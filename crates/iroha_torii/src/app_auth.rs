//! Canonical request signing helpers for app-facing HTTP endpoints.
//!
//! Clients may optionally attach:
//! - `X-Iroha-Account`: exact canonical lowercase `0x` account-address hex or
//!   an active canonical ASCII account alias that authorises the request. The
//!   ASCII hex spelling transports the same account identified as I105 in data
//!   models and signed request bodies without relying on Unicode HTTP fields.
//! - `X-Iroha-Signature`: base64 signature over the canonical request bytes plus
//!   freshness metadata.
//! - `X-Iroha-Timestamp-Ms`: unix timestamp in milliseconds included in the
//!   signed payload.
//! - `X-Iroha-Nonce`: caller-chosen nonce included in the signed payload.
//! - `X-Iroha-Witness`: base64 Norito witness for multisig-controlled accounts.
//!
//! The canonical request bytes are:
//! ```text
//! <UPPERCASE_METHOD>\n
//! <path>\n
//! <sorted_query_string>\n
//! <hex_sha256(body)>\n
//! <timestamp_ms>\n
//! <nonce>
//! ```
//! - Query parameters are parsed, percent-decoded (treating `+` as space), sorted
//!   by `(key, value)`, then re-encoded using `application/x-www-form-urlencoded`
//!   rules. Authenticated V1 requests accept at most 64 decoded query pairs and
//!   64 KiB of raw query text, a 32-byte method token, and a 64 KiB
//!   percent-encoded path. Authentication headers are singletons.
//! - Account identities and aliases carried by authenticated V1 requests are
//!   capped at 36 KiB before canonical parsing; larger controllers use witnesses.
//! - The body hash is computed over the raw request body bytes.
//! - Canonical witnesses use strict padded base64, canonical Norito, a 1 MiB
//!   encoded ceiling, and at most 64 signature entries.
//! - Freshness validation rejects stale timestamps and replayed nonces.
//!   Timestamp headers use exact unsigned decimal spelling with no sign,
//!   padding, or surrounding whitespace.
//! - Nonce retention must exceed the full timestamp-skew window. A saturated
//!   cache rejects new requests and never evicts live replay evidence.
//! - `X-Iroha-Account` only identifies a caller when paired with a valid
//!   signature or witness; bare account headers are rejected on caller-scoped
//!   read paths.
//!
//! Some endpoints carry the same auth envelope inside a JSON body instead of HTTP headers. Those
//! callers provide `account_id`, `timestamp_ms`, `nonce`, and exactly one proof field in the body,
//! while the canonical message hashes the endpoint-defined unsigned body bytes.
use crate::bounded_replay_cache::{InsertError as ReplayInsertError, ReplayCache};
use axum::http::HeaderMap;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use iroha_config::parameters::{actual::AppApi as AppApiConfig, defaults};
use iroha_core::{
    sns::resolve_active_account_alias,
    state::{State as CoreState, WorldReadOnly},
};
use iroha_crypto::{Algorithm, Hash, PublicKey, Signature};
use iroha_data_model::{
    NetworkId, ValidationFail,
    account::{AccountController, AccountId, address::AccountAddress, rekey::AccountAlias},
    alias_setup::AccountAliasName,
    query::error::QueryExecutionFail,
    soracloud::{
        CANONICAL_REQUEST_WITNESS_VERSION_V1, CanonicalRequestSignatureWitnessV1,
        CanonicalRequestWitnessV1,
    },
};
#[cfg(feature = "app_api")]
use iroha_torii_shared::FeeQuoteRequest;
use iroha_torii_shared::canonical_request_form::{
    CANONICAL_REQUEST_MAX_QUERY_PAIRS_V1, CanonicalFormError, CanonicalRequestExactWriter,
    CanonicalRequestFormPlan, canonical_request_decimal_len, canonical_request_query_pair_count,
    write_canonical_request_decimal,
};
use norito::codec::{Decode, Encode};
use sha2::{Digest as _, Sha256};
use std::{
    fmt,
    num::NonZeroUsize,
    sync::{Arc, OnceLock, RwLock},
    time::Duration,
};
/// Header carrying the authorising account id.
pub const HEADER_ACCOUNT: &str = "X-Iroha-Account";
/// Header carrying the base64-encoded signature over the canonical request bytes.
pub const HEADER_SIGNATURE: &str = "X-Iroha-Signature";
/// Header carrying the unix timestamp in milliseconds for freshness checks.
pub const HEADER_TIMESTAMP_MS: &str = "X-Iroha-Timestamp-Ms";
/// Header carrying the caller-chosen replay nonce.
pub const HEADER_NONCE: &str = "X-Iroha-Nonce";
/// Header carrying the base64 Norito-encoded multisig witness.
pub const HEADER_WITNESS: &str = "X-Iroha-Witness";
#[cfg(test)]
const ACCOUNT_BODY_CONTEXT: &str = "account_id";
/// Maximum raw query bytes covered by one canonical V1 request.
///
/// This matches the complete HTTP/1 parser-buffer ceiling and also protects
/// direct in-process verifier callers that do not pass through that transport.
pub(crate) const CANONICAL_REQUEST_MAX_RAW_QUERY_BYTES_V1: usize = 64 * 1024;
/// Maximum method token bytes accepted by the in-process V1 verifier.
const CANONICAL_REQUEST_MAX_METHOD_BYTES_V1: usize = 32;
/// Maximum percent-encoded path bytes covered by one canonical V1 request.
///
/// Network listeners impose a finite HTTP-head envelope, but `http::Uri` can also be constructed
/// directly from an arbitrarily large `PathAndQuery`. This explicit protocol ceiling protects
/// in-process verifier callers before the canonical message destination is allocated.
const CANONICAL_REQUEST_MAX_PATH_BYTES_V1: usize = 64 * 1024;
/// Maximum bytes in a canonical account identity or alias carried by V1 auth.
///
/// This covers the worst-case UTF-8 I105 spelling for every supported V1
/// single-key controller after the grouped base conversion. Larger multisig
/// controllers authenticate with the separately bounded witness form instead.
pub(crate) const CANONICAL_REQUEST_MAX_ACCOUNT_LITERAL_BYTES_V1: usize = 36 * 1024;
/// Maximum bytes in the catalog-free ASCII alias exception accepted by auth.
///
/// An account alias contains at most three [`iroha_model_base::name::Name`] segments plus the `@`
/// and optional `.` separators. Apply this structural ceiling before normalization or catalog
/// lookup; the wider account limit is reserved for canonical controller hex.
const CANONICAL_REQUEST_MAX_ALIAS_LITERAL_BYTES_V1: usize =
    3 * iroha_model_base::name::MAX_NAME_BYTES + 2;
/// Maximum number of signatures carried by one canonical V1 witness.
const CANONICAL_REQUEST_WITNESS_MAX_SIGNATURES_V1: usize = 64;
/// Maximum decoded size of one canonical V1 witness (768 KiB).
///
/// Canonical base64 expands this to exactly 1 MiB, the transport's maximum complete HTTP-head
/// envelope. The explicit ceiling also protects direct in-process verifier callers which bypass the
/// HTTP parser, while the outer routed-read admission owns the overlapping header, decoded frame,
/// and verification scratch high-water.
pub(crate) const CANONICAL_REQUEST_WITNESS_MAX_DECODED_BYTES_V1: usize = 3 * 1024 * 1024 / 4;
/// Largest detached signature payload supported by the canonical V1 verifier.
pub(crate) const CANONICAL_REQUEST_MAX_SIGNATURE_BYTES_V1: usize =
    Algorithm::MlDsa.signature_payload_len();
/// HTTP request types used for canonical signing.
pub use axum::http::{Method, Uri};
#[cfg(test)]
use iroha_data_model::query::ItemKindTag;
#[cfg(test)]
use iroha_data_model::query::Query;
#[cfg(test)]
use iroha_data_model::query::QueryRequest;
#[cfg(test)]
use iroha_data_model::query::QueryWithParams;
#[cfg(test)]
use iroha_data_model::query::dsl::CompoundPredicate;
#[cfg(test)]
use iroha_data_model::query::dsl::HasProjection;
#[cfg(test)]
use iroha_data_model::query::dsl::PredicateMarker;
#[cfg(test)]
use iroha_data_model::query::dsl::SelectorMarker;
#[cfg(test)]
use iroha_data_model::query::dsl::SelectorTuple;
#[cfg(test)]
use iroha_data_model::query::parameters::QueryParams;
#[cfg(test)]
use std::sync::Mutex;
/// Canonical request freshness configuration.
#[derive(Debug, Clone, Copy)]
pub struct CanonicalRequestAuthConfig {
    /// Maximum allowed clock skew for signed requests.
    pub max_clock_skew: Duration,
    /// TTL for nonces retained for replay detection; must exceed twice `max_clock_skew`.
    pub nonce_ttl: Duration,
    /// Maximum number of nonce entries held in memory for replay detection.
    pub replay_cache_capacity: NonZeroUsize,
}
/// Invalid relationship between canonical-request freshness and replay retention.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CanonicalRequestAuthConfigError;
impl fmt::Display for CanonicalRequestAuthConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "canonical request nonce TTL must be greater than twice the maximum clock skew",
        )
    }
}
impl std::error::Error for CanonicalRequestAuthConfigError {}
impl CanonicalRequestAuthConfig {
    /// Validate that a nonce cannot expire while its signed timestamp remains admissible.
    pub fn validate(self) -> Result<(), CanonicalRequestAuthConfigError> {
        let replay_window = self
            .max_clock_skew
            .checked_mul(2)
            .ok_or(CanonicalRequestAuthConfigError)?;
        if self.nonce_ttl <= replay_window {
            return Err(CanonicalRequestAuthConfigError);
        }
        Ok(())
    }
}
impl Default for CanonicalRequestAuthConfig {
    fn default() -> Self {
        Self {
            max_clock_skew: Duration::from_secs(defaults::torii::app_auth::MAX_CLOCK_SKEW_SECS),
            nonce_ttl: Duration::from_secs(defaults::torii::app_auth::NONCE_TTL_SECS),
            replay_cache_capacity: NonZeroUsize::new(
                defaults::torii::app_auth::REPLAY_CACHE_CAPACITY,
            )
            .expect("default app-auth replay cache capacity must be non-zero"),
        }
    }
}
impl From<&AppApiConfig> for CanonicalRequestAuthConfig {
    fn from(value: &AppApiConfig) -> Self {
        Self {
            max_clock_skew: value.request_signature_max_clock_skew,
            nonce_ttl: value.request_signature_nonce_ttl,
            replay_cache_capacity: value.request_signature_replay_cache_capacity,
        }
    }
}
#[derive(Debug)]
struct CanonicalRequestAuthRuntime {
    config: CanonicalRequestAuthConfig,
    replay_cache: Arc<ReplayCache>,
}
impl CanonicalRequestAuthRuntime {
    fn new(config: CanonicalRequestAuthConfig) -> Self {
        debug_assert!(config.validate().is_ok());
        Self {
            config,
            replay_cache: Arc::new(ReplayCache::new(
                config.nonce_ttl,
                config.replay_cache_capacity,
            )),
        }
    }
}
fn auth_runtime() -> &'static RwLock<CanonicalRequestAuthRuntime> {
    static STATE: OnceLock<RwLock<CanonicalRequestAuthRuntime>> = OnceLock::new();
    STATE.get_or_init(|| RwLock::new(CanonicalRequestAuthRuntime::new(Default::default())))
}
fn auth_runtime_snapshot() -> (CanonicalRequestAuthConfig, Arc<ReplayCache>) {
    let guard = auth_runtime()
        .read()
        .expect("canonical request auth config lock");
    (guard.config, guard.replay_cache.clone())
}
/// Configure app-facing canonical request freshness enforcement.
///
/// # Errors
///
/// Returns an error when nonce retention is too short to cover the complete
/// accepted timestamp-skew window.
pub fn configure(
    config: CanonicalRequestAuthConfig,
) -> Result<(), CanonicalRequestAuthConfigError> {
    config.validate()?;
    let mut guard = auth_runtime()
        .write()
        .expect("canonical request auth config lock");
    guard.config = config;
    guard
        .replay_cache
        .configure(config.nonce_ttl, config.replay_cache_capacity);
    Ok(())
}
/// Authenticated canonical request identity.
///
/// The supplied codec context bounds verification; it does not own these result graphs.
/// Callers must retain their original physical owner until consumption or an exactly paid
/// transfer. TODO: close general helper-return and HTTP-extension ownership before treating
/// this raw result type as a complete request-lifetime allocation certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedCanonicalRequest {
    /// Account declared in the canonical request authentication material.
    pub account: AccountId,
    /// Exact account controller key that verified the request signature.
    pub signer: PublicKey,
    /// Full signer set that satisfied the request authorisation.
    pub verified_signers: Vec<PublicKey>,
}
#[cfg(test)]
#[derive(Debug, Clone, Copy)]
pub(crate) enum CanonicalRequestBodyProof<'a> {
    SignatureBase64(&'a str),
}
#[cfg(test)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct CanonicalRequestBodyAuth<'a> {
    pub(crate) account_id: &'a str,
    pub(crate) timestamp_ms: u64,
    pub(crate) nonce: &'a str,
    pub(crate) proof: CanonicalRequestBodyProof<'a>,
}

/// Validate `raw` against the V1 query limits and plan its canonical form.
fn canonical_request_form_plan(raw: &str) -> Result<CanonicalRequestFormPlan<'_>, crate::Error> {
    validate_canonical_request_raw_query(raw)?;
    CanonicalRequestFormPlan::new(raw).map_err(|error| match error {
        CanonicalFormError::TooManyPairs => canonical_request_pair_limit_error(),
        CanonicalFormError::Capacity => canonical_request_capacity_error(),
    })
}
/// Canonicalise a raw query string by decoding, sorting, and re-encoding.
#[cfg(test)]
fn canonical_query_string(raw: Option<&str>) -> Result<String, crate::Error> {
    let plan = canonical_request_form_plan(raw.unwrap_or_default())?;
    let mut output = allocate_exact_canonical_auth_bytes(plan.encoded_bytes())?;
    let mut writer = CanonicalRequestExactWriter::new(&mut output);
    plan.write_to(&mut writer);
    debug_assert_eq!(writer.offset(), plan.encoded_bytes());
    String::from_utf8(output.into_vec()).map_err(|_| {
        crate::Error::Query(ValidationFail::NotPermitted(
            "canonical request query is not valid UTF-8".to_owned(),
        ))
    })
}

fn validate_canonical_request_query(uri: &Uri) -> Result<(), crate::Error> {
    validate_canonical_request_raw_query(uri.query().unwrap_or_default())
}

fn validate_canonical_request_target(method: &Method, uri: &Uri) -> Result<(), crate::Error> {
    if method.as_str().len() > CANONICAL_REQUEST_MAX_METHOD_BYTES_V1 {
        return Err(crate::Error::Query(ValidationFail::NotPermitted(format!(
            "canonical request method exceeds the V1 limit of {CANONICAL_REQUEST_MAX_METHOD_BYTES_V1} bytes"
        ))));
    }
    if uri.path().len() > CANONICAL_REQUEST_MAX_PATH_BYTES_V1 {
        return Err(crate::Error::Query(ValidationFail::NotPermitted(format!(
            "canonical request path exceeds the V1 limit of {CANONICAL_REQUEST_MAX_PATH_BYTES_V1} bytes"
        ))));
    }
    validate_canonical_request_query(uri)
}

fn validate_canonical_request_raw_query(raw: &str) -> Result<(), crate::Error> {
    if raw.len() > CANONICAL_REQUEST_MAX_RAW_QUERY_BYTES_V1 {
        return Err(crate::Error::Query(ValidationFail::NotPermitted(format!(
            "canonical request query exceeds the V1 limit of {CANONICAL_REQUEST_MAX_RAW_QUERY_BYTES_V1} raw bytes"
        ))));
    }
    // `form_urlencoded::parse` ignores empty `&`-delimited components. Count
    // the same lexical units without percent-decoding source-sized strings.
    if canonical_request_query_pair_count(raw) > CANONICAL_REQUEST_MAX_QUERY_PAIRS_V1 {
        return Err(canonical_request_pair_limit_error());
    }
    Ok(())
}

fn canonical_request_pair_limit_error() -> crate::Error {
    crate::Error::Query(ValidationFail::NotPermitted(format!(
        "canonical request query exceeds the V1 limit of {CANONICAL_REQUEST_MAX_QUERY_PAIRS_V1} pairs"
    )))
}

fn canonical_request_capacity_error() -> crate::Error {
    crate::Error::Query(ValidationFail::QueryFailed(
        QueryExecutionFail::CapacityLimit,
    ))
}

fn admitted_signer_list(count: usize) -> Result<Vec<PublicKey>, crate::Error> {
    let layout = std::alloc::Layout::array::<PublicKey>(count)
        .map_err(|_| canonical_request_capacity_error())?;
    norito::core::reserve_decode_allocation(layout.size())
        .map_err(|_| canonical_request_capacity_error())?;
    let mut signers = Vec::new();
    signers
        .try_reserve_exact(count)
        .map_err(|_| canonical_request_capacity_error())?;
    Ok(signers)
}

fn bounded_canonical_request_message_with_network(
    network_id: Option<&NetworkId>,
    method: &Method,
    uri: &Uri,
    body: &[u8],
    freshness: Option<(u64, &str)>,
) -> Result<Box<[u8]>, crate::Error> {
    const DOMAIN: &[u8] = b"iroha.app.request.network.v1\0";
    const HEX: &[u8; 16] = b"0123456789abcdef";
    validate_canonical_request_target(method, uri)?;
    if let Some((_, nonce)) = freshness
        && !canonical_request_nonce_is_valid(nonce)
    {
        return Err(crate::Error::Query(ValidationFail::NotPermitted(
            "invalid canonical request nonce".to_owned(),
        )));
    }
    let query = canonical_request_form_plan(uri.query().unwrap_or_default())?;
    let freshness_bytes = if let Some((timestamp_ms, nonce)) = freshness {
        1_usize
            .checked_add(canonical_request_decimal_len(timestamp_ms))
            .and_then(|length| length.checked_add(1))
            .and_then(|length| length.checked_add(nonce.len()))
            .ok_or_else(canonical_request_capacity_error)?
    } else {
        0
    };
    let network_prefix_bytes = if let Some(network_id) = network_id {
        DOMAIN
            .len()
            .checked_add(network_id.as_bytes().len())
            .ok_or_else(canonical_request_capacity_error)?
    } else {
        0
    };
    let total_bytes = network_prefix_bytes
        .checked_add(method.as_str().len())
        .and_then(|length| length.checked_add(1))
        .and_then(|length| length.checked_add(uri.path().len()))
        .and_then(|length| length.checked_add(1))
        .and_then(|length| length.checked_add(query.encoded_bytes()))
        .and_then(|length| length.checked_add(1 + 64))
        .and_then(|length| length.checked_add(freshness_bytes))
        .ok_or_else(canonical_request_capacity_error)?;
    let mut output = allocate_exact_canonical_auth_bytes(total_bytes)?;
    let mut writer = CanonicalRequestExactWriter::new(&mut output);
    if let Some(network_id) = network_id {
        writer.extend(DOMAIN);
        writer.extend(network_id.as_bytes());
    }
    for byte in method.as_str().bytes() {
        writer.push(byte.to_ascii_uppercase());
    }
    writer.push(b'\n');
    writer.extend(uri.path().as_bytes());
    writer.push(b'\n');
    query.write_to(&mut writer);
    writer.push(b'\n');
    let body_hash = Sha256::digest(body);
    for byte in body_hash {
        writer.push(HEX[usize::from(byte >> 4)]);
        writer.push(HEX[usize::from(byte & 0x0f)]);
    }
    if let Some((timestamp_ms, nonce)) = freshness {
        writer.push(b'\n');
        write_canonical_request_decimal(timestamp_ms, &mut writer);
        writer.push(b'\n');
        writer.extend(nonce.as_bytes());
    }
    debug_assert_eq!(writer.offset(), total_bytes);
    Ok(output)
}

fn bounded_canonical_request_message(
    method: &Method,
    uri: &Uri,
    body: &[u8],
) -> Result<Box<[u8]>, crate::Error> {
    bounded_canonical_request_message_with_network(None, method, uri, body, None)
}

fn bounded_canonical_network_request_message(
    network_id: &NetworkId,
    method: &Method,
    uri: &Uri,
    body: &[u8],
    freshness: Option<(u64, &str)>,
) -> Result<Box<[u8]>, crate::Error> {
    bounded_canonical_request_message_with_network(Some(network_id), method, uri, body, freshness)
}

fn bounded_canonical_network_request_hash(
    network_id: &NetworkId,
    method: &Method,
    uri: &Uri,
    body: &[u8],
) -> Result<Hash, crate::Error> {
    let message = bounded_canonical_network_request_message(network_id, method, uri, body, None)?;
    Ok(Hash::new(&message))
}

fn validate_canonical_request_singleton_headers(headers: &HeaderMap) -> Result<(), crate::Error> {
    for name in [
        HEADER_ACCOUNT,
        HEADER_SIGNATURE,
        HEADER_TIMESTAMP_MS,
        HEADER_NONCE,
        HEADER_WITNESS,
    ] {
        let mut values = headers.get_all(name).iter();
        let _ = values.next();
        if values.next().is_some() {
            return Err(crate::Error::Query(ValidationFail::NotPermitted(format!(
                "canonical request header `{name}` must appear at most once"
            ))));
        }
    }
    Ok(())
}

fn canonical_request_account_literal_fits_v1(value: &str) -> bool {
    value.len() <= CANONICAL_REQUEST_MAX_ACCOUNT_LITERAL_BYTES_V1
}
/// Construct canonical request bytes for signing.
///
/// # Errors
/// Returns an error when the V1 method, path, or query limits are exceeded or
/// when the exact destination cannot be allocated.
pub fn canonical_request_message(
    method: &Method,
    uri: &Uri,
    body: &[u8],
) -> Result<Vec<u8>, crate::Error> {
    bounded_canonical_request_message(method, uri, body).map(|message| message.into_vec())
}
/// Construct exact-network canonical request bytes for signing.
///
/// # Errors
/// Returns an error when the V1 target limits are exceeded or the exact
/// destination cannot be allocated.
pub fn canonical_network_request_message(
    network_id: &NetworkId,
    method: &Method,
    uri: &Uri,
    body: &[u8],
) -> Result<Vec<u8>, crate::Error> {
    bounded_canonical_network_request_message(network_id, method, uri, body, None)
        .map(|message| message.into_vec())
}
/// Hash an exact-network canonical request for a multisig witness.
///
/// # Errors
/// Returns an error when canonical request construction fails.
pub fn canonical_network_request_hash(
    network_id: &NetworkId,
    method: &Method,
    uri: &Uri,
    body: &[u8],
) -> Result<Hash, crate::Error> {
    bounded_canonical_network_request_hash(network_id, method, uri, body)
}
/// Construct exact-network canonical request bytes with freshness metadata.
///
/// # Errors
/// Returns an error when the V1 target or nonce limits are exceeded or the
/// exact destination cannot be allocated.
pub fn canonical_network_request_signature_message(
    network_id: &NetworkId,
    method: &Method,
    uri: &Uri,
    body: &[u8],
    timestamp_ms: u64,
    nonce: &str,
) -> Result<Vec<u8>, crate::Error> {
    bounded_canonical_network_request_message(
        network_id,
        method,
        uri,
        body,
        Some((timestamp_ms, nonce)),
    )
    .map(|message| message.into_vec())
}
/// Encode a signature payload for use in `X-Iroha-Signature` headers.
///
/// # Errors
/// Returns an error for an invalid or excessive V1 signature payload, or when
/// the exact base64 destination cannot be allocated.
pub fn signature_header_value(signature: &Signature) -> Result<String, norito::Error> {
    let payload = signature.payload();
    if payload.is_empty()
        || payload.len() > CANONICAL_REQUEST_MAX_SIGNATURE_BYTES_V1
        || payload.iter().all(|byte| *byte == 0)
    {
        return Err(norito::Error::Message(
            "invalid canonical request signature".to_owned(),
        ));
    }
    encode_bounded_canonical_base64_value(
        payload,
        CANONICAL_REQUEST_MAX_SIGNATURE_BYTES_V1,
        "canonical request signature",
    )
}
/// Wire-identical wrapper that rejects an excessive witness signature count
/// before the decoder reserves the source-controlled vector.
#[derive(Default)]
struct BoundedCanonicalRequestWitnessSignaturesV1(
    Vec<BoundedCanonicalRequestSignatureWitnessWireV1>,
);

/// Wire-identical detached signature wrapper with a pre-allocation byte cap.
struct BoundedCanonicalRequestSignatureV1(Signature);

impl norito::core::SerializePayload for BoundedCanonicalRequestSignatureV1 {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::core::Error> {
        norito::core::SerializePayload::serialize(&self.0, writer)
    }

    fn encoded_len_hint(&self) -> Option<usize> {
        norito::core::SerializePayload::encoded_len_hint(&self.0)
    }

    fn encoded_len_exact(&self) -> Option<usize> {
        norito::core::SerializePayload::encoded_len_exact(&self.0)
    }
}

impl<'de> norito::core::DeserializePayload<'de> for BoundedCanonicalRequestSignatureV1 {
    fn deserialize(archived: &'de norito::core::Archived<Self>) -> Self {
        Self::try_deserialize(archived).expect("bounded canonical request signature decode")
    }

    fn try_deserialize(
        archived: &'de norito::core::Archived<Self>,
    ) -> Result<Self, norito::core::Error> {
        let bytes =
            norito::core::payload_slice_from_ptr(core::ptr::from_ref(archived).cast::<u8>())?;
        let (signature, used) = <Self as norito::core::DecodeFromSlice>::decode_from_slice(bytes)?;
        if used != bytes.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        Ok(signature)
    }
}

impl<'a> norito::core::DecodeFromSlice<'a> for BoundedCanonicalRequestSignatureV1 {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let (signature_bytes, _) = norito::core::inspect_seq_len_slice(bytes)?;
        if signature_bytes > CANONICAL_REQUEST_MAX_SIGNATURE_BYTES_V1 {
            return Err(norito::core::Error::SequenceLengthExceeded {
                length: u64::try_from(signature_bytes).unwrap_or(u64::MAX),
                limit: CANONICAL_REQUEST_MAX_SIGNATURE_BYTES_V1 as u64,
            });
        }
        let (signature, used) =
            <Signature as norito::core::DecodeFromSlice>::decode_from_slice(bytes)?;
        Ok((Self(signature), used))
    }
}

#[derive(Encode, Decode)]
struct BoundedCanonicalRequestSignatureWitnessWireV1 {
    signer: PublicKey,
    signature: BoundedCanonicalRequestSignatureV1,
}

impl From<BoundedCanonicalRequestSignatureWitnessWireV1> for CanonicalRequestSignatureWitnessV1 {
    fn from(value: BoundedCanonicalRequestSignatureWitnessWireV1) -> Self {
        Self {
            signer: value.signer,
            signature: value.signature.0,
        }
    }
}

impl norito::core::SerializePayload for BoundedCanonicalRequestWitnessSignaturesV1 {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::core::Error> {
        norito::core::SerializePayload::serialize(&self.0, writer)
    }

    fn encoded_len_hint(&self) -> Option<usize> {
        norito::core::SerializePayload::encoded_len_hint(&self.0)
    }

    fn encoded_len_exact(&self) -> Option<usize> {
        norito::core::SerializePayload::encoded_len_exact(&self.0)
    }
}

impl<'de> norito::core::DeserializePayload<'de> for BoundedCanonicalRequestWitnessSignaturesV1 {
    fn deserialize(archived: &'de norito::core::Archived<Self>) -> Self {
        Self::try_deserialize(archived).expect("bounded canonical request witness decode")
    }

    fn try_deserialize(
        archived: &'de norito::core::Archived<Self>,
    ) -> Result<Self, norito::core::Error> {
        let bytes =
            norito::core::payload_slice_from_ptr(core::ptr::from_ref(archived).cast::<u8>())?;
        let (signatures, used) = <Self as norito::core::DecodeFromSlice>::decode_from_slice(bytes)?;
        if used != bytes.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        Ok(signatures)
    }
}

impl<'a> norito::core::DecodeFromSlice<'a> for BoundedCanonicalRequestWitnessSignaturesV1 {
    fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
        let (signature_count, _) = norito::core::inspect_seq_len_slice(bytes)?;
        if signature_count > CANONICAL_REQUEST_WITNESS_MAX_SIGNATURES_V1 {
            return Err(norito::core::Error::SequenceLengthExceeded {
                length: u64::try_from(signature_count).unwrap_or(u64::MAX),
                limit: CANONICAL_REQUEST_WITNESS_MAX_SIGNATURES_V1 as u64,
            });
        }
        let (signatures, used) = <Vec<BoundedCanonicalRequestSignatureWitnessWireV1> as norito::core::DecodeFromSlice>::decode_from_slice(bytes)?;
        Ok((Self(signatures), used))
    }
}

// The public field is a `Vec`, which Norito's packed derive classifies as
// self-delimiting. Preserve that exact field-bitset identity while the private
// wrapper checks cardinality and signature payloads before owning them.
mod bounded_signatures_wire {
    pub(super) type Vec = super::BoundedCanonicalRequestWitnessSignaturesV1;
}

// The final type segment is intentionally named `String`. Norito's packed
// struct derive classifies that syntactic wire type as self-delimiting, which
// preserves the public witness field bitset while this private wrapper rejects
// an excessive nonce before allocating its owned text.
mod bounded_nonce_wire {
    pub(super) struct String(pub(super) std::string::String);

    impl norito::core::SerializePayload for String {
        fn serialize(
            &self,
            writer: &mut norito::core::Encoder<'_>,
        ) -> Result<(), norito::core::Error> {
            norito::core::SerializePayload::serialize(&self.0, writer)
        }

        fn encoded_len_hint(&self) -> Option<usize> {
            norito::core::SerializePayload::encoded_len_hint(&self.0)
        }

        fn encoded_len_exact(&self) -> Option<usize> {
            norito::core::SerializePayload::encoded_len_exact(&self.0)
        }
    }

    impl<'de> norito::core::DeserializePayload<'de> for String {
        fn deserialize(archived: &'de norito::core::Archived<Self>) -> Self {
            Self::try_deserialize(archived).expect("bounded canonical request nonce decode")
        }

        fn try_deserialize(
            archived: &'de norito::core::Archived<Self>,
        ) -> Result<Self, norito::core::Error> {
            let bytes =
                norito::core::payload_slice_from_ptr(core::ptr::from_ref(archived).cast::<u8>())?;
            let (nonce, _) = <Self as norito::core::DecodeFromSlice>::decode_from_slice(bytes)?;
            // This self-delimiting field is decoded from the remaining packed
            // witness suffix. `DecodeFromSlice` records the exact prefix it
            // consumed so the outer derive can advance to the following hash.
            Ok(nonce)
        }
    }

    impl<'a> norito::core::DecodeFromSlice<'a> for String {
        fn decode_from_slice(bytes: &'a [u8]) -> Result<(Self, usize), norito::core::Error> {
            let (nonce_bytes, header_bytes) = norito::core::inspect_len_from_slice(bytes)?;
            if nonce_bytes == 0 || nonce_bytes > 256 {
                return Err(norito::core::Error::SequenceLengthExceeded {
                    length: u64::try_from(nonce_bytes).unwrap_or(u64::MAX),
                    limit: 256,
                });
            }
            let end = header_bytes
                .checked_add(nonce_bytes)
                .ok_or(norito::core::Error::LengthMismatch)?;
            let nonce = bytes
                .get(header_bytes..end)
                .ok_or(norito::core::Error::LengthMismatch)?;
            if !nonce.iter().all(|byte| (0x21..=0x7e).contains(byte)) {
                return Err(norito::core::Error::Message(
                    "canonical request nonce is not printable ASCII".to_owned(),
                ));
            }
            let (nonce, used) =
                <std::string::String as norito::core::DecodeFromSlice>::decode_from_slice(bytes)?;
            Ok((Self(nonce), used))
        }
    }
}

#[derive(Encode, Decode)]
struct BoundedCanonicalRequestWitnessWireV1 {
    schema_version: u16,
    subject_account: AccountId,
    timestamp_ms: u64,
    nonce: bounded_nonce_wire::String,
    canonical_request_hash: Hash,
    #[norito(default)]
    signatures: bounded_signatures_wire::Vec,
}

/// Canonical witness decoder with the public V1 schema identity and bounded
/// signature-vector wire implementation.
#[derive(norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_torii::app_auth::BoundedCanonicalRequestWitnessV1",
    frame = "iroha_data_model::soracloud::CanonicalRequestWitnessV1"
)]
struct BoundedCanonicalRequestWitnessV1(BoundedCanonicalRequestWitnessWireV1);

impl norito::core::SerializePayload for BoundedCanonicalRequestWitnessV1 {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::core::Error> {
        norito::core::SerializePayload::serialize(&self.0, writer)
    }

    fn encoded_len_hint(&self) -> Option<usize> {
        norito::core::SerializePayload::encoded_len_hint(&self.0)
    }

    fn encoded_len_exact(&self) -> Option<usize> {
        norito::core::SerializePayload::encoded_len_exact(&self.0)
    }
}

impl<'de> norito::core::DeserializePayload<'de> for BoundedCanonicalRequestWitnessV1 {
    fn deserialize(archived: &'de norito::core::Archived<Self>) -> Self {
        Self::try_deserialize(archived).expect("bounded canonical request witness decode")
    }

    fn try_deserialize(
        archived: &'de norito::core::Archived<Self>,
    ) -> Result<Self, norito::core::Error> {
        <BoundedCanonicalRequestWitnessWireV1 as norito::core::DeserializePayload<'de>>::try_deserialize(
            archived.cast::<BoundedCanonicalRequestWitnessWireV1>(),
        )
        .map(Self)
    }
}

impl TryFrom<BoundedCanonicalRequestWitnessV1> for CanonicalRequestWitnessV1 {
    type Error = norito::core::Error;

    fn try_from(value: BoundedCanonicalRequestWitnessV1) -> Result<Self, Self::Error> {
        let value = value.0;
        let layout = std::alloc::Layout::array::<CanonicalRequestSignatureWitnessV1>(
            value.signatures.0.len(),
        )
        .map_err(|_| norito::core::Error::LengthMismatch)?;
        norito::core::reserve_decode_allocation(layout.size())?;
        let mut signatures = Vec::new();
        signatures
            .try_reserve_exact(value.signatures.0.len())
            .map_err(|_| norito::core::Error::AllocationFailed {
                bytes: u64::try_from(
                    value
                        .signatures
                        .0
                        .len()
                        .saturating_mul(std::mem::size_of::<CanonicalRequestSignatureWitnessV1>()),
                )
                .unwrap_or(u64::MAX),
            })?;
        signatures.extend(value.signatures.0.into_iter().map(Into::into));
        Ok(Self {
            schema_version: value.schema_version,
            subject_account: value.subject_account,
            timestamp_ms: value.timestamp_ms,
            nonce: value.nonce.0,
            canonical_request_hash: value.canonical_request_hash,
            signatures,
        })
    }
}
/// Construct the signed payload for a canonical request witness.
///
/// The payload binds the witness to the subject account, freshness fields, and
/// reconstructed canonical request hash. Individual signatures are supplied
/// separately in [`CanonicalRequestWitnessV1::signatures`].
///
/// # Errors
/// Returns [`norito::Error`] when witness encoding fails.
pub fn canonical_request_witness_message(
    witness: &CanonicalRequestWitnessV1,
) -> Result<Vec<u8>, norito::Error> {
    validate_canonical_request_witness_for_encoding(witness)?;
    iroha_torii_shared::canonical_request_witness::encode_signing_message(
        witness,
        CANONICAL_REQUEST_WITNESS_MAX_DECODED_BYTES_V1,
    )
    .map_err(|error| match error {
        norito::core::BoundedEncodeError::FrameTooLarge {
            encoded_bytes,
            max_bytes,
        } => norito::Error::ArchiveLengthExceeded {
            length: u64::try_from(encoded_bytes).unwrap_or(u64::MAX),
            limit: u64::try_from(max_bytes).unwrap_or(u64::MAX),
        },
        norito::core::BoundedEncodeError::AllocationFailed { bytes } => {
            norito::Error::AllocationFailed {
                bytes: u64::try_from(bytes).unwrap_or(u64::MAX),
            }
        }
        norito::core::BoundedEncodeError::Serialization(error) => error,
    })
}
/// Encode a multisig witness payload for use in `X-Iroha-Witness` headers.
///
/// # Errors
/// Returns [`norito::Error`] when witness encoding fails.
#[cfg(test)]
pub fn witness_header_value(witness: &CanonicalRequestWitnessV1) -> Result<String, norito::Error> {
    validate_canonical_request_witness_for_encoding(witness)?;
    let _flags = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    let bytes =
        norito::core::to_bytes_bounded(witness, CANONICAL_REQUEST_WITNESS_MAX_DECODED_BYTES_V1)
            .map_err(bounded_witness_encode_error)?;
    encode_bounded_canonical_base64_value(
        &bytes,
        CANONICAL_REQUEST_WITNESS_MAX_DECODED_BYTES_V1,
        "canonical request witness",
    )
}

fn encode_bounded_canonical_base64_value(
    bytes: &[u8],
    maximum_decoded_bytes: usize,
    _context: &'static str,
) -> Result<String, norito::Error> {
    if bytes.len() > maximum_decoded_bytes {
        return Err(norito::Error::ArchiveLengthExceeded {
            length: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            limit: u64::try_from(maximum_decoded_bytes).unwrap_or(u64::MAX),
        });
    }
    let encoded_len = canonical_padded_base64_len(bytes.len());
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(encoded_len)
        .map_err(|_| norito::Error::AllocationFailed {
            bytes: u64::try_from(encoded_len).unwrap_or(u64::MAX),
        })?;
    encoded.resize(encoded_len, 0);
    let written = BASE64_STANDARD
        .encode_slice(bytes, &mut encoded)
        .map_err(|_| norito::Error::LengthMismatch)?;
    if written != encoded_len {
        return Err(norito::Error::LengthMismatch);
    }
    String::from_utf8(encoded).map_err(|_| norito::Error::InvalidUtf8)
}

#[cfg(test)]
fn bounded_witness_encode_error(error: norito::core::BoundedEncodeError) -> norito::Error {
    match error {
        norito::core::BoundedEncodeError::FrameTooLarge {
            encoded_bytes,
            max_bytes,
        } => norito::Error::ArchiveLengthExceeded {
            length: u64::try_from(encoded_bytes).unwrap_or(u64::MAX),
            limit: u64::try_from(max_bytes).unwrap_or(u64::MAX),
        },
        norito::core::BoundedEncodeError::AllocationFailed { bytes } => {
            norito::Error::AllocationFailed {
                bytes: u64::try_from(bytes).unwrap_or(u64::MAX),
            }
        }
        norito::core::BoundedEncodeError::Serialization(error) => error,
    }
}

fn validate_canonical_request_witness_for_encoding(
    witness: &CanonicalRequestWitnessV1,
) -> Result<(), norito::Error> {
    if witness.schema_version != CANONICAL_REQUEST_WITNESS_VERSION_V1 {
        return Err(norito::Error::Message(
            "unsupported canonical request witness schema version".to_owned(),
        ));
    }
    if !canonical_request_nonce_is_valid(&witness.nonce) {
        return Err(norito::Error::Message(
            "invalid canonical request witness nonce".to_owned(),
        ));
    }
    if witness.signatures.len() > CANONICAL_REQUEST_WITNESS_MAX_SIGNATURES_V1 {
        return Err(norito::Error::SequenceLengthExceeded {
            length: u64::try_from(witness.signatures.len()).unwrap_or(u64::MAX),
            limit: CANONICAL_REQUEST_WITNESS_MAX_SIGNATURES_V1 as u64,
        });
    }
    for signature in &witness.signatures {
        let payload = signature.signature.payload();
        if payload.is_empty()
            || payload.len() > CANONICAL_REQUEST_MAX_SIGNATURE_BYTES_V1
            || payload.iter().all(|byte| *byte == 0)
        {
            return Err(norito::Error::Message(
                "invalid canonical request witness signature".to_owned(),
            ));
        }
    }
    Ok(())
}

fn canonical_request_nonce_is_valid(nonce: &str) -> bool {
    !nonce.is_empty()
        && nonce.len() <= 256
        && nonce.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

/// Preflight the exact wire values of a canonical-request authentication proof.
///
/// This deliberately stops before account resolution, freshness checks, replay
/// admission, and cryptographic verification. It is used by internal forwarders
/// to reject values that the authoritative route verifier cannot parse.
#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_canonical_request_auth_wire_values(
    account: Option<&str>,
    signature: Option<&str>,
    timestamp_ms: Option<&str>,
    nonce: Option<&str>,
    witness: Option<&str>,
) -> Result<(), crate::Error> {
    if let Some(account) = account {
        validate_canonical_account_header_literal(account)?;
    }
    if let Some(signature) = signature {
        let signature = decode_signature_bytes_value(signature, "X-Iroha-Signature")?;
        if signature.is_empty() || signature.iter().all(|byte| *byte == 0) {
            return Err(crate::Error::Query(ValidationFail::NotPermitted(
                "invalid X-Iroha-Signature payload".to_owned(),
            )));
        }
    }
    if let Some(timestamp_ms) = timestamp_ms {
        let _ = parse_canonical_timestamp_ms(timestamp_ms)?;
    }
    if let Some(nonce) = nonce
        && !canonical_request_nonce_is_valid(nonce)
    {
        return Err(crate::Error::Query(ValidationFail::NotPermitted(
            "invalid X-Iroha-Nonce value".to_owned(),
        )));
    }
    if let Some(witness) = witness {
        let witness = decode_witness_value(witness, "X-Iroha-Witness")?;
        validate_canonical_request_witness_for_encoding(&witness).map_err(|_| {
            crate::Error::Query(ValidationFail::NotPermitted(
                "invalid X-Iroha-Witness payload".to_owned(),
            ))
        })?;
    }
    Ok(())
}

fn validate_canonical_account_header_literal(account_literal: &str) -> Result<(), crate::Error> {
    fn invalid_account_header() -> crate::Error {
        crate::Error::Query(ValidationFail::NotPermitted(
            "invalid X-Iroha-Account value".to_owned(),
        ))
    }

    if account_literal.is_empty()
        || !canonical_request_account_literal_fits_v1(account_literal)
        || !account_literal.is_ascii()
    {
        return Err(invalid_account_header());
    }
    if account_literal.starts_with("0x") {
        parse_canonical_account_header_address(account_literal)?;
        return Ok(());
    }
    if account_literal.len() > CANONICAL_REQUEST_MAX_ALIAS_LITERAL_BYTES_V1 {
        return Err(invalid_account_header());
    }
    let alias = account_literal
        .parse::<AccountAliasName>()
        .map_err(|_| invalid_account_header())?;
    if alias.canonical_text() != account_literal {
        return Err(invalid_account_header());
    }
    Ok(())
}

fn parse_required_header_exact_text<'a>(
    headers: &'a HeaderMap,
    name: &'static str,
) -> Result<&'a str, crate::Error> {
    let value = headers.get(name).ok_or_else(|| {
        crate::Error::Query(ValidationFail::NotPermitted(format!(
            "missing required canonical request header `{name}`"
        )))
    })?;
    let value = std::str::from_utf8(value.as_bytes()).map_err(|_| {
        crate::Error::Query(ValidationFail::NotPermitted(format!(
            "invalid canonical request header `{name}`"
        )))
    })?;
    if value.is_empty() {
        Err(crate::Error::Query(ValidationFail::NotPermitted(format!(
            "invalid canonical request header `{name}`"
        ))))
    } else {
        Ok(value)
    }
}

fn parse_canonical_timestamp_ms(value: &str) -> Result<u64, crate::Error> {
    let encoded = value.as_bytes();
    if encoded.is_empty()
        || encoded.len() > 20
        || !encoded.iter().all(u8::is_ascii_digit)
        || (encoded.len() > 1 && encoded[0] == b'0')
    {
        return Err(crate::Error::Query(ValidationFail::NotPermitted(
            "invalid X-Iroha-Timestamp-Ms value".to_owned(),
        )));
    }
    value.parse::<u64>().map_err(|_| {
        crate::Error::Query(ValidationFail::NotPermitted(
            "invalid X-Iroha-Timestamp-Ms value".to_owned(),
        ))
    })
}

fn parse_account_header_value(
    state: &Arc<CoreState>,
    account_literal: &str,
    context: &norito::core::DecodeBudgetContext,
) -> Result<AccountId, crate::Error> {
    context.with(|| {
        fn invalid_account_header() -> crate::Error {
            crate::Error::Query(ValidationFail::NotPermitted(
                "invalid X-Iroha-Account value".to_owned(),
            ))
        }
        if account_literal.is_empty() || account_literal.trim() != account_literal {
            return Err(invalid_account_header());
        }
        if !canonical_request_account_literal_fits_v1(account_literal) {
            return Err(invalid_account_header());
        }
        if account_literal.starts_with("0x") {
            return parse_canonical_account_header_address(account_literal);
        }
        // HTTP field values do not provide a portable Unicode text carrier. App
        // authentication therefore uses canonical lowercase account-address hex
        // for account identities and retains one deliberately narrower alias
        // exception: resolve the exact active ASCII alias only to establish which
        // controller must verify the request signature. User-directed alias lookup
        // remains permissioned independently.
        if !account_literal.is_ascii() {
            return Err(invalid_account_header());
        }
        if account_literal.len() > CANONICAL_REQUEST_MAX_ALIAS_LITERAL_BYTES_V1 {
            return Err(invalid_account_header());
        }
        state
            .try_with_authorization_view(context, |view| {
                let alias = AccountAlias::from_literal(account_literal, view.catalog())
                    .map_err(|_| invalid_account_header())?;
                let canonical = alias
                    .to_literal(view.catalog())
                    .map_err(|_| invalid_account_header())?;
                if canonical != account_literal {
                    return Err(invalid_account_header());
                }
                resolve_active_account_alias(
                    view.world(),
                    view.catalog(),
                    &alias,
                    view.ledger_time_ms(),
                )
                .map_err(|error| {
                    if error.deferral().is_some() {
                        canonical_request_capacity_error()
                    } else {
                        crate::Error::Query(ValidationFail::InternalError(error.to_string()))
                    }
                })?
                .ok_or_else(invalid_account_header)
            })
            .map_err(authorization_view_error)?
    })
}

pub(crate) fn authorization_view_error(error: iroha_core::state::StateViewError) -> crate::Error {
    match error {
        iroha_core::state::StateViewError::Busy(_) => canonical_request_capacity_error(),
        error => crate::Error::Query(ValidationFail::InternalError(error.to_string())),
    }
}

fn parse_canonical_account_header_address(
    account_literal: &str,
) -> Result<AccountId, crate::Error> {
    fn invalid_account_header() -> crate::Error {
        crate::Error::Query(ValidationFail::NotPermitted(
            "invalid X-Iroha-Account value".to_owned(),
        ))
    }
    let encoded = account_literal
        .strip_prefix("0x")
        .ok_or_else(invalid_account_header)?;
    if encoded.is_empty()
        || encoded.len() % 2 != 0
        || !encoded
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err(invalid_account_header());
    }
    let mut canonical = allocate_exact_canonical_auth_bytes(encoded.len() / 2)?;
    for (destination, pair) in canonical.iter_mut().zip(encoded.as_bytes().chunks_exact(2)) {
        let nibble = |byte| match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => unreachable!("canonical account-header hex was preflighted"),
        };
        *destination = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
    AccountAddress::from_canonical_bytes(&canonical)
        .and_then(|address| {
            let account = address.to_account_id()?;
            if account.to_canonical_hex()?.as_bytes() != account_literal.as_bytes() {
                return Err(iroha_data_model::account::address::AccountAddressError::InvalidLength);
            }
            Ok(account)
        })
        .map_err(|error| {
            if error.is_decode_resource_limit() {
                crate::Error::Query(ValidationFail::QueryFailed(
                    QueryExecutionFail::CapacityLimit,
                ))
            } else {
                invalid_account_header()
            }
        })
}
#[cfg(test)]
fn parse_account_body_value(
    state: &Arc<CoreState>,
    account_literal: &str,
) -> Result<AccountId, crate::Error> {
    parse_account_literal_value(
        state,
        account_literal,
        ACCOUNT_BODY_CONTEXT,
        "invalid account_id value",
    )
}
#[cfg(test)]
fn parse_account_literal_value(
    state: &Arc<CoreState>,
    account_literal: &str,
    context: &'static str,
    invalid_message: &'static str,
) -> Result<AccountId, crate::Error> {
    if account_literal.is_empty()
        || account_literal.trim() != account_literal
        || !canonical_request_account_literal_fits_v1(account_literal)
    {
        return Err(crate::Error::Query(ValidationFail::NotPermitted(
            invalid_message.to_owned(),
        )));
    }
    crate::routing::parse_account_literal_with_state(
        state.as_ref(),
        account_literal,
        &crate::routing::MaybeTelemetry::disabled(),
        context,
    )
    .map(|(account_id, _)| account_id)
    .map_err(|_| crate::Error::Query(ValidationFail::NotPermitted(invalid_message.to_owned())))
}
fn validate_freshness(
    config: &CanonicalRequestAuthConfig,
    timestamp_ms: u64,
    nonce: &str,
    nonce_context: &'static str,
) -> Result<(), crate::Error> {
    let delta_ms = crate::utils::unix_now_ms().abs_diff(timestamp_ms);
    let max_skew_ms: u64 = config
        .max_clock_skew
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX);
    if delta_ms > max_skew_ms {
        return Err(crate::Error::Query(ValidationFail::NotPermitted(
            "request timestamp outside allowed skew window".to_owned(),
        )));
    }
    if !canonical_request_nonce_is_valid(nonce) {
        return Err(crate::Error::Query(ValidationFail::NotPermitted(format!(
            "invalid {nonce_context} value"
        ))));
    }
    Ok(())
}

const fn canonical_padded_base64_len(decoded_bytes: usize) -> usize {
    (decoded_bytes.saturating_add(2) / 3).saturating_mul(4)
}

pub(crate) fn decode_bounded_canonical_base64_value(
    encoded: &str,
    maximum_decoded_bytes: usize,
    context: &'static str,
) -> Result<Box<[u8]>, crate::Error> {
    let maximum_encoded_bytes = canonical_padded_base64_len(maximum_decoded_bytes);
    if encoded.len() > maximum_encoded_bytes {
        return Err(crate::Error::Query(ValidationFail::NotPermitted(format!(
            "{context} exceeds the V1 limit of {maximum_decoded_bytes} decoded bytes"
        ))));
    }
    let padding = if encoded.ends_with("==") {
        2
    } else if encoded.ends_with('=') {
        1
    } else {
        0
    };
    let Some(decoded_bytes) = encoded
        .len()
        .checked_div(4)
        .and_then(|groups| groups.checked_mul(3))
        .and_then(|bytes| bytes.checked_sub(padding))
        .filter(|_| encoded.len() % 4 == 0)
    else {
        return Err(crate::Error::Query(ValidationFail::NotPermitted(format!(
            "invalid base64 in {context}"
        ))));
    };
    if decoded_bytes > maximum_decoded_bytes {
        return Err(crate::Error::Query(ValidationFail::NotPermitted(format!(
            "{context} exceeds the V1 limit of {maximum_decoded_bytes} decoded bytes"
        ))));
    }
    let mut decoded = allocate_exact_canonical_auth_bytes(decoded_bytes)?;
    // `STANDARD` requires canonical RFC 4648 padding and rejects non-zero
    // trailing pad bits, so re-encoding the complete decoded value would only
    // add another source-sized allocation.
    let written = BASE64_STANDARD
        .decode_slice(encoded, decoded.as_mut())
        .map_err(|_| {
            crate::Error::Query(ValidationFail::NotPermitted(format!(
                "invalid base64 in {context}"
            )))
        })?;
    if written != decoded_bytes {
        return Err(crate::Error::Query(ValidationFail::NotPermitted(format!(
            "invalid base64 in {context}"
        ))));
    }
    Ok(decoded)
}

#[allow(unsafe_code)]
fn allocate_exact_canonical_auth_bytes(length: usize) -> Result<Box<[u8]>, crate::Error> {
    if length == 0 {
        return Ok(Vec::new().into_boxed_slice());
    }
    let layout = std::alloc::Layout::array::<u8>(length).map_err(|_| {
        crate::Error::Query(ValidationFail::QueryFailed(
            iroha_data_model::query::error::QueryExecutionFail::CapacityLimit,
        ))
    })?;
    norito::core::reserve_decode_allocation(layout.size())
        .map_err(|_| canonical_request_capacity_error())?;
    // SAFETY: `layout` describes exactly `length` initialized bytes. A null
    // result is mapped to a recoverable capacity failure before ownership is
    // constructed.
    let allocation = unsafe { std::alloc::alloc_zeroed(layout) };
    if allocation.is_null() {
        return Err(crate::Error::Query(ValidationFail::QueryFailed(
            iroha_data_model::query::error::QueryExecutionFail::CapacityLimit,
        )));
    }
    let slice = std::ptr::slice_from_raw_parts_mut(allocation, length);
    // SAFETY: the allocation owns exactly the layout of this boxed slice.
    Ok(unsafe { Box::from_raw(slice) })
}

fn decode_signature_bytes_value(
    signature_b64: &str,
    context: &'static str,
) -> Result<Box<[u8]>, crate::Error> {
    decode_bounded_canonical_base64_value(
        signature_b64,
        CANONICAL_REQUEST_MAX_SIGNATURE_BYTES_V1,
        context,
    )
}
fn checked_app_auth_signature_from_bytes(
    signature_bytes: &[u8],
    signer: &PublicKey,
    signature_context: &'static str,
) -> Result<Signature, crate::Error> {
    match signer.try_algorithm() {
        Ok(Algorithm::Ed25519) => {
            iroha_crypto::ed25519_parse_signature(signature_bytes).map_err(|err| {
                crate::Error::Query(ValidationFail::NotPermitted(format!(
                    "invalid {signature_context}: Ed25519 signature failed admission: {err}"
                )))
            })
        }
        Ok(Algorithm::MlDsa) => {
            iroha_crypto::mldsa65_parse_signature(signature_bytes).map_err(|err| {
                crate::Error::Query(ValidationFail::NotPermitted(format!(
                    "invalid {signature_context}: ML-DSA signature failed admission: {err}"
                )))
            })
        }
        _ => Signature::try_from_bytes_for_admission(signature_bytes).map_err(|_| {
            crate::Error::Query(ValidationFail::NotPermitted(format!(
                "invalid {signature_context}"
            )))
        }),
    }
}
fn verify_app_auth_signature(
    signature: &Signature,
    signer: &PublicKey,
    message: &[u8],
    signature_context: &'static str,
) -> Result<(), crate::Error> {
    validate_app_auth_signature_for_signer(signature, signer, signature_context)?;
    iroha_crypto::verify_signature_for_admission(signature, signer, message).map_err(|_| {
        crate::Error::Query(ValidationFail::NotPermitted(
            "query signature failed verification".to_owned(),
        ))
    })
}
fn validate_app_auth_signature_for_signer(
    signature: &Signature,
    signer: &PublicKey,
    signature_context: &'static str,
) -> Result<(), crate::Error> {
    match signer.try_algorithm() {
        Ok(Algorithm::Ed25519) => iroha_crypto::ed25519_parse_signature(signature.payload())
            .map(|_| ())
            .map_err(|err| {
                crate::Error::Query(ValidationFail::NotPermitted(format!(
                    "invalid {signature_context}: Ed25519 signature failed admission: {err}"
                )))
            }),
        Ok(Algorithm::MlDsa) => iroha_crypto::mldsa65_parse_signature(signature.payload())
            .map(|_| ())
            .map_err(|err| {
                crate::Error::Query(ValidationFail::NotPermitted(format!(
                    "invalid {signature_context}: ML-DSA signature failed admission: {err}"
                )))
            }),
        _ => Ok(()),
    }
}
fn decode_witness_value(
    witness_b64: &str,
    context: &'static str,
) -> Result<CanonicalRequestWitnessV1, crate::Error> {
    let witness_bytes = decode_bounded_canonical_base64_value(
        witness_b64,
        CANONICAL_REQUEST_WITNESS_MAX_DECODED_BYTES_V1,
        context,
    )?;
    let limits = norito::DecodeLimits::new(
        CANONICAL_REQUEST_WITNESS_MAX_DECODED_BYTES_V1,
        CANONICAL_REQUEST_WITNESS_MAX_DECODED_BYTES_V1,
        CANONICAL_REQUEST_WITNESS_MAX_DECODED_BYTES_V1,
        CANONICAL_REQUEST_WITNESS_MAX_DECODED_BYTES_V1.saturating_mul(2),
        norito::core::MAX_VALUE_NESTING_DEPTH,
    );
    let witness = norito::decode_canonical_with_limits::<BoundedCanonicalRequestWitnessV1>(
        &witness_bytes,
        limits,
    )
    .and_then(CanonicalRequestWitnessV1::try_from)
    .map_err(|error| {
        if norito::core::decode_error_matches_active_limits(&error) {
            canonical_request_capacity_error()
        } else {
            crate::Error::Query(ValidationFail::NotPermitted(format!(
                "invalid {context} payload"
            )))
        }
    })?;
    if witness.schema_version != CANONICAL_REQUEST_WITNESS_VERSION_V1 {
        return Err(crate::Error::Query(ValidationFail::NotPermitted(format!(
            "unsupported {context} schema_version `{}`",
            witness.schema_version
        ))));
    }
    Ok(witness)
}
#[cfg(test)]
fn verify_single_signature_authorization(
    state: &Arc<CoreState>,
    account: &AccountId,
    signature_bytes: &[u8],
    message: &[u8],
    signature_context: &'static str,
    context: &norito::core::DecodeBudgetContext,
) -> Result<PublicKey, crate::Error> {
    state
        .try_with_authorization_view(context, |view| {
            let world = view.world();
            let account_entry = world.account(account).map_err(|_| {
                crate::Error::Query(ValidationFail::NotPermitted(
                    "canonical request account is not registered".to_owned(),
                ))
            })?;
            match account_entry.id.controller() {
                AccountController::Single(pk) => {
                    let signature = checked_app_auth_signature_from_bytes(
                        signature_bytes,
                        pk,
                        signature_context,
                    )?;
                    verify_app_auth_signature(&signature, pk, message, signature_context)?;
                    pk.try_clone_for_admission()
                        .map_err(|_| canonical_request_capacity_error())
                }
                AccountController::Multisig(_) => {
                    Err(crate::Error::Query(ValidationFail::NotPermitted(
                        "multisig accounts must use X-Iroha-Witness".to_owned(),
                    )))
                }
            }
        })
        .map_err(authorization_view_error)?
}
fn verify_multisig_witness_authorization(
    state: &Arc<CoreState>,
    account: &AccountId,
    witness: &CanonicalRequestWitnessV1,
    witness_context: &'static str,
    signature_context: &'static str,
    context: &norito::core::DecodeBudgetContext,
) -> Result<Vec<PublicKey>, crate::Error> {
    let message = canonical_request_witness_message(witness).map_err(|_| {
        crate::Error::Query(ValidationFail::NotPermitted(format!(
            "invalid {witness_context} payload"
        )))
    })?;
    state.try_with_authorization_view(context, |view| {
        let world = view.world();
    let account_entry = world.account(account).map_err(|_| {
        crate::Error::Query(ValidationFail::NotPermitted(
            "canonical request account is not registered".to_owned(),
        ))
    })?;
    match account_entry.id.controller() {
        AccountController::Single(_) => Err(crate::Error::Query(ValidationFail::NotPermitted(
            "single-signature accounts must use X-Iroha-Signature".to_owned(),
        ))),
        AccountController::Multisig(policy) => {
            if witness.signatures.is_empty() {
                return Err(crate::Error::Query(ValidationFail::NotPermitted(format!(
                    "{witness_context} must include at least one signature"
                ))));
            }
            if witness.signatures.len() > policy.members().len() {
                return Err(crate::Error::Query(ValidationFail::NotPermitted(format!(
                    "{witness_context} includes more signatures than the account multisig policy has members"
                ))));
            }
            let mut total_weight = 0_u32;
            let mut verified_signers = admitted_signer_list(witness.signatures.len())?;
            for CanonicalRequestSignatureWitnessV1 { signer, signature } in &witness.signatures {
                if verified_signers.iter().any(|verified| verified == signer) {
                    return Err(crate::Error::Query(ValidationFail::NotPermitted(format!(
                        "{witness_context} contains duplicate signer keys"
                    ))));
                }
                let Some(member) = policy
                    .members()
                    .iter()
                    .find(|member| member.public_key() == signer)
                else {
                    return Err(crate::Error::Query(ValidationFail::NotPermitted(format!(
                        "{witness_context} includes a signer outside the account multisig policy"
                    ))));
                };
                verify_app_auth_signature(signature, signer, &message, signature_context)?;
                total_weight = total_weight.saturating_add(u32::from(member.weight()));
                verified_signers.push(
                    signer
                        .try_clone_for_admission()
                        .map_err(|_| canonical_request_capacity_error())?,
                );
            }
            if total_weight < u32::from(policy.threshold()) {
                return Err(crate::Error::Query(ValidationFail::NotPermitted(format!(
                    "{witness_context} signatures do not satisfy multisig threshold"
                ))));
            }
            Ok(verified_signers)
        }
    }

    }).map_err(authorization_view_error)?
}
#[cfg(test)]
fn validate_expected_account(
    expected_account: Option<&AccountId>,
    account: &AccountId,
) -> Result<(), crate::Error> {
    if let Some(expected) = expected_account
        && expected != account
    {
        return Err(crate::Error::Query(ValidationFail::NotPermitted(
            "signed account does not match request path".to_owned(),
        )));
    }
    Ok(())
}
fn check_replay(
    account: &AccountId,
    nonce: &str,
    replay_cache: &ReplayCache,
    minimum_ttl: Duration,
) -> Result<(), crate::Error> {
    const DOMAIN: &[u8] = b"iroha:app-auth:replay:v1\0";
    let replay_key = Hash::new_from_writer(|mut writer| {
        writer.write_all(DOMAIN)?;
        norito::core::write_canonical_to_writer(account, &mut writer)
            .map_err(std::io::Error::other)?;
        writer.write_all(nonce.as_bytes())
    })
    .map_err(|_| {
        crate::Error::Query(ValidationFail::QueryFailed(
            iroha_data_model::query::error::QueryExecutionFail::CapacityLimit,
        ))
    })?;
    match replay_cache.check_and_insert_digest_with_minimum_ttl(replay_key, minimum_ttl) {
        Ok(()) => Ok(()),
        Err(ReplayInsertError::Replay) => Err(crate::Error::Query(ValidationFail::NotPermitted(
            "request nonce already used".to_owned(),
        ))),
        Err(ReplayInsertError::Capacity | ReplayInsertError::LifetimeOverflow) => {
            Err(crate::Error::Query(ValidationFail::QueryFailed(
                iroha_data_model::query::error::QueryExecutionFail::CapacityLimit,
            )))
        }
    }
}

fn finish_verified_canonical_request(
    account: AccountId,
    signer: PublicKey,
    verified_signers: Vec<PublicKey>,
    nonce: &str,
    replay_cache: &ReplayCache,
    minimum_ttl: Duration,
) -> Result<VerifiedCanonicalRequest, crate::Error> {
    // Every source-sized clone and container reservation is complete before
    // this call. Publishing replay evidence is therefore the final fallible
    // admission step and cannot burn a valid nonce for a result-allocation
    // failure.
    check_replay(&account, nonce, replay_cache, minimum_ttl)?;
    Ok(VerifiedCanonicalRequest {
        account,
        signer,
        verified_signers,
    })
}
/// Validate an iterable query against the executor on behalf of `authority`.
#[cfg(test)]
pub fn validate_iter_query_for_authority<Q>(
    state: &Arc<CoreState>,
    authority: &AccountId,
    query: Q,
) -> Result<(), crate::Error>
where
    Q: Query + 'static,
    Q::Item: HasProjection<PredicateMarker>
        + HasProjection<SelectorMarker, AtomType = ()>
        + ItemKindTag
        + Send
        + Sync,
    Q: norito::codec::Encode,
{
    use iroha_core::smartcontracts::isi::query::{
        QueryLimits, validate_fresh_query_for_client_world_parts,
    };
    let iter = QueryWithParams {
        query: (),
        query_payload: norito::codec::Encode::encode(&query),
        item: query.query_item_kind(),
        predicate_bytes: norito::codec::Encode::encode(&CompoundPredicate::<Q::Item>::PASS),
        selector_bytes: norito::codec::Encode::encode(&SelectorTuple::<Q::Item>::default()),
        params: QueryParams::default(),
    };
    let request = QueryRequest::Start(iter);
    let limits = QueryLimits::new(crate::routing::app_query_limits().max_fetch_size);
    let world = state.world_view();
    let latest_block = state.latest_block_header_fast();
    validate_fresh_query_for_client_world_parts(
        request,
        authority,
        &world,
        latest_block,
        limits,
        &state.ivm_execution_budget(),
    )
    .map_err(crate::Error::Query)
}
#[cfg(test)]
pub(crate) fn verify_canonical_body_request(
    state: &Arc<CoreState>,
    auth: CanonicalRequestBodyAuth<'_>,
    method: &Method,
    uri: &Uri,
    unsigned_body: &[u8],
    expected_account: Option<&AccountId>,
    context: &norito::core::DecodeBudgetContext,
) -> Result<VerifiedCanonicalRequest, crate::Error> {
    context.with(|| {
        validate_canonical_request_target(method, uri)?;
        let account = parse_account_body_value(state, auth.account_id)?;
        validate_expected_account(expected_account, &account)?;
        let (auth_config, replay_cache) = auth_runtime_snapshot();
        validate_freshness(&auth_config, auth.timestamp_ms, auth.nonce, "nonce")?;
        match auth.proof {
            CanonicalRequestBodyProof::SignatureBase64(signature_b64) => {
                let signature_bytes =
                    decode_signature_bytes_value(signature_b64, "signature_base64")?;
                let message = bounded_canonical_network_request_message(
                    state.network_id_ref(),
                    method,
                    uri,
                    unsigned_body,
                    Some((auth.timestamp_ms, auth.nonce)),
                )?;
                let signer = verify_single_signature_authorization(
                    state,
                    &account,
                    &signature_bytes,
                    &message,
                    "signature_base64 payload",
                    context,
                )?;
                let primary_signer = signer
                    .try_clone_for_admission()
                    .map_err(|_| canonical_request_capacity_error())?;
                let mut verified_signers = admitted_signer_list(1)?;
                verified_signers.push(signer);
                finish_verified_canonical_request(
                    account,
                    primary_signer,
                    verified_signers,
                    auth.nonce,
                    &replay_cache,
                    auth_config.nonce_ttl,
                )
            }
        }
    })
}
/// Verify optional exact-network canonical request headers.
///
/// Returns `Ok(Some(identity))` when a signature is present and valid, `Ok(None)` when
/// no signing headers are provided, and an error when headers are malformed or verification fails.
#[cfg(test)]
pub fn verify_canonical_request(
    state: &Arc<CoreState>,
    headers: &HeaderMap,
    method: &Method,
    uri: &Uri,
    body: &[u8],
    expected_account: Option<&AccountId>,
    context: &norito::core::DecodeBudgetContext,
) -> Result<Option<VerifiedCanonicalRequest>, crate::Error> {
    verify_canonical_request_for_network(
        state,
        headers,
        method,
        uri,
        body,
        CanonicalRequestVerificationScope {
            expected_account,
            purpose: CanonicalRequestPurpose::General,
        },
        state.network_id_ref(),
        context,
    )
}
/// Verify required canonical request headers against an exact network identity.
///
/// A signature produced for a different genesis-derived [`NetworkId`] cannot
/// authenticate on this network even when every HTTP field and body byte is identical.
/// `context` is the caller's original cumulative owner and is installed only synchronously.
pub fn verify_canonical_network_request(
    state: &Arc<CoreState>,
    network_id: &NetworkId,
    headers: &HeaderMap,
    method: &Method,
    uri: &Uri,
    body: &[u8],
    expected_account: Option<&AccountId>,
    context: &norito::core::DecodeBudgetContext,
) -> Result<Option<VerifiedCanonicalRequest>, crate::Error> {
    if network_id != state.network_id_ref() {
        return Err(crate::Error::Query(ValidationFail::NotPermitted(
            "request verifier NetworkId does not match Core state".to_owned(),
        )));
    }
    verify_canonical_request_for_network(
        state,
        headers,
        method,
        uri,
        body,
        CanonicalRequestVerificationScope {
            expected_account,
            purpose: CanonicalRequestPurpose::General,
        },
        network_id,
        context,
    )
}
#[derive(Clone, Copy)]
enum CanonicalRequestPurpose {
    General,
    #[cfg(feature = "app_api")]
    FeeQuote,
}
#[derive(Clone, Copy)]
struct CanonicalRequestVerificationScope<'a> {
    expected_account: Option<&'a AccountId>,
    purpose: CanonicalRequestPurpose,
}
fn validate_verified_request_purpose(
    purpose: CanonicalRequestPurpose,
    _method: &Method,
    _uri: &Uri,
    _body: &[u8],
    _account: &AccountId,
    _verified_signers: &[PublicKey],
) -> Result<(), crate::Error> {
    match purpose {
        CanonicalRequestPurpose::General => Ok(()),
        #[cfg(feature = "app_api")]
        CanonicalRequestPurpose::FeeQuote => Ok(()),
    }
}
fn verify_canonical_request_for_network(
    state: &Arc<CoreState>,
    headers: &HeaderMap,
    method: &Method,
    uri: &Uri,
    body: &[u8],
    scope: CanonicalRequestVerificationScope<'_>,
    network_id: &NetworkId,
    context: &norito::core::DecodeBudgetContext,
) -> Result<Option<VerifiedCanonicalRequest>, crate::Error> {
    context.with(|| {

    // Axum routes query-bearing fee-quote URIs to the same handler. Reject them before any
    // authentication can commit replay state or bypass the endpoint-specific signer policy.
    if uri.path() == "/v1/fees/quote" && uri.query().is_some() {
        return Err(crate::Error::Query(ValidationFail::NotPermitted(
            "fee quote requests must not contain query parameters".to_owned(),
        )));
    }
    validate_canonical_request_singleton_headers(headers)?;
    let account_hdr = headers.get(HEADER_ACCOUNT);
    let signature_hdr = headers.get(HEADER_SIGNATURE);
    let timestamp_hdr = headers.get(HEADER_TIMESTAMP_MS);
    let nonce_hdr = headers.get(HEADER_NONCE);
    let witness_hdr = headers.get(HEADER_WITNESS);
    let all_missing = account_hdr.is_none()
        && signature_hdr.is_none()
        && timestamp_hdr.is_none()
        && nonce_hdr.is_none()
        && witness_hdr.is_none();
    if all_missing {
        return Ok(None);
    }
    if witness_hdr.is_some() {
        if signature_hdr.is_some() || timestamp_hdr.is_some() || nonce_hdr.is_some() {
            return Err(crate::Error::Query(ValidationFail::NotPermitted(
                "X-Iroha-Witness must not be combined with X-Iroha-Signature, X-Iroha-Timestamp-Ms, or X-Iroha-Nonce".to_owned(),
            )));
        }
        validate_canonical_request_target(method, uri)?;
        let witness_b64 = parse_required_header_exact_text(headers, HEADER_WITNESS)?;
        let witness = decode_witness_value(witness_b64, "X-Iroha-Witness")?;
        let explicit_account = if account_hdr.is_some() {
            let account_literal = parse_required_header_exact_text(headers, HEADER_ACCOUNT)?;
            let account = parse_account_header_value(state, account_literal, context)?;
            if account != witness.subject_account {
                return Err(crate::Error::Query(ValidationFail::NotPermitted(
                    "X-Iroha-Account does not match X-Iroha-Witness subject_account".to_owned(),
                )));
            }
            Some(account)
        } else {
            None
        };
        let account = explicit_account
            .as_ref()
            .unwrap_or(&witness.subject_account);
        if let Some(expected) = scope.expected_account
            && expected != account
        {
            return Err(crate::Error::Query(ValidationFail::NotPermitted(
                "signed account does not match request path".to_owned(),
            )));
        }
        let (auth_config, replay_cache) = auth_runtime_snapshot();
        validate_freshness(
            &auth_config,
            witness.timestamp_ms,
            &witness.nonce,
            "X-Iroha-Nonce",
        )?;
        let expected_hash = bounded_canonical_network_request_hash(network_id, method, uri, body)?;
        if witness.canonical_request_hash != expected_hash {
            return Err(crate::Error::Query(ValidationFail::NotPermitted(
                "X-Iroha-Witness canonical request hash mismatch".to_owned(),
            )));
        }
        let verified_signers = verify_multisig_witness_authorization(
            state,
            account,
            &witness,
            "X-Iroha-Witness",
            "X-Iroha-Witness signature payload",
         context)?;
        validate_verified_request_purpose(
            scope.purpose,
            method,
            uri,
            body,
            account,
            &verified_signers,
        )?;
        let signer = verified_signers
            .first()
            .expect("non-empty witness signer set")
            .try_clone_for_admission()
            .map_err(|_| canonical_request_capacity_error())?;
        let account = explicit_account.unwrap_or(witness.subject_account);
        return Ok(Some(finish_verified_canonical_request(
            account,
            signer,
            verified_signers,
            &witness.nonce,
            &replay_cache,
            auth_config.nonce_ttl,
        )?));
    }
    if account_hdr.is_none()
        || signature_hdr.is_none()
        || timestamp_hdr.is_none()
        || nonce_hdr.is_none()
    {
        return Err(crate::Error::Query(ValidationFail::NotPermitted(
            "X-Iroha-Account, X-Iroha-Signature, X-Iroha-Timestamp-Ms, and X-Iroha-Nonce must be set together".to_owned(),
        )));
    };
    validate_canonical_request_target(method, uri)?;
    let account_literal = parse_required_header_exact_text(headers, HEADER_ACCOUNT)?;
    let account = parse_account_header_value(state, account_literal, context)?;
    if let Some(expected) = scope.expected_account
        && expected != &account
    {
        return Err(crate::Error::Query(ValidationFail::NotPermitted(
            "signed account does not match request path".to_owned(),
        )));
    }
    let timestamp_ms = parse_canonical_timestamp_ms(parse_required_header_exact_text(
        headers,
        HEADER_TIMESTAMP_MS,
    )?)?;
    let nonce = parse_required_header_exact_text(headers, HEADER_NONCE)?;
    let (auth_config, replay_cache) = auth_runtime_snapshot();
    validate_freshness(&auth_config, timestamp_ms, nonce, "X-Iroha-Nonce")?;
    let signature_b64 = parse_required_header_exact_text(headers, HEADER_SIGNATURE)?;
    let signature_bytes = decode_signature_bytes_value(signature_b64, "X-Iroha-Signature")?;
    let message = bounded_canonical_network_request_message(
        network_id,
        method,
        uri,
        body,
        Some((timestamp_ms, nonce)),
    )?;
    let signer = state.try_with_authorization_view(context, |view| {
        let world = view.world();
    let account_entry = world.account(&account).map_err(|_| {
        crate::Error::Query(ValidationFail::NotPermitted(
            "canonical request account is not registered".to_owned(),
        ))
    })?;
    let signer = match account_entry.id.controller() {
        AccountController::Single(pk) => {
            let signature = checked_app_auth_signature_from_bytes(
                &signature_bytes,
                pk,
                "X-Iroha-Signature payload",
            )?;
            verify_app_auth_signature(&signature, pk, &message, "X-Iroha-Signature payload")?;
            pk.try_clone_for_admission()
                .map_err(|_| canonical_request_capacity_error())?
        }
        AccountController::Multisig(_) => {
            return Err(crate::Error::Query(ValidationFail::NotPermitted(
                "multisig accounts must use X-Iroha-Witness".to_owned(),
            )));
        }
    };
        Ok::<_, crate::Error>(signer)
    }).map_err(authorization_view_error)??;
    let primary_signer = signer
        .try_clone_for_admission()
        .map_err(|_| canonical_request_capacity_error())?;
    let mut verified_signers = admitted_signer_list(1)?;
    verified_signers.push(signer);
    validate_verified_request_purpose(
        scope.purpose,
        method,
        uri,
        body,
        &account,
        &verified_signers,
    )?;
    Ok(Some(finish_verified_canonical_request(
        account,
        primary_signer,
        verified_signers,
        nonce,
        &replay_cache,
        auth_config.nonce_ttl,
    )?))

    })
}
/// Verify canonical request headers for the fee-quote endpoint.
///
/// Normal world-state-backed authentication always takes precedence. When the exact canonical
/// single-key account named by `X-Iroha-Account` is not registered yet, this endpoint alone may
/// authenticate it from the key embedded in its account id, provided the quoted payload's first
/// instruction self-registers that same authority. Aliases, multisig controllers, and other
/// endpoints never enter this fallback.
#[cfg(feature = "app_api")]
pub(crate) fn verify_fee_quote_canonical_request(
    state: &Arc<CoreState>,
    headers: &HeaderMap,
    method: &Method,
    uri: &Uri,
    body: &[u8],
    context: &norito::core::DecodeBudgetContext,
) -> Result<Option<VerifiedCanonicalRequest>, crate::Error> {
    context.with(|| {
        let normal_error = match verify_canonical_request_for_network(
            state,
            headers,
            method,
            uri,
            body,
            CanonicalRequestVerificationScope {
                expected_account: None,
                purpose: CanonicalRequestPurpose::FeeQuote,
            },
            state.network_id_ref(),
            context,
        ) {
            Ok(verified) => return Ok(verified),
            Err(error) => error,
        };
        if method != Method::POST || uri.path() != "/v1/fees/quote" || uri.query().is_some() {
            return Err(normal_error);
        }
        if headers.get(HEADER_WITNESS).is_some() {
            return Err(normal_error);
        }
        let account_literal = match parse_required_header_exact_text(headers, HEADER_ACCOUNT) {
            Ok(account_literal) => account_literal,
            Err(_) => return Err(normal_error),
        };
        if !canonical_request_account_literal_fits_v1(account_literal) {
            return Err(normal_error);
        }
        let account = match parse_canonical_account_header_address(account_literal) {
            Ok(account) => account,
            Err(_) => return Err(normal_error),
        };
        let signer = match account.controller() {
            AccountController::Single(signer) => signer
                .try_clone_for_admission()
                .map_err(|_| canonical_request_capacity_error())?,
            AccountController::Multisig(_) => return Err(normal_error),
        };
        // A materialised account must always use its world-state controller and normal account
        // authentication, even when the request body happens to contain a registration instruction.
        if state
            .try_with_authorization_view(context, |view| view.world().account(&account).is_ok())
            .map_err(authorization_view_error)?
        {
            return Err(normal_error);
        }
        let timestamp_ms = parse_canonical_timestamp_ms(parse_required_header_exact_text(
            headers,
            HEADER_TIMESTAMP_MS,
        )?)?;
        let nonce = parse_required_header_exact_text(headers, HEADER_NONCE)?;
        let (auth_config, replay_cache) = auth_runtime_snapshot();
        validate_freshness(&auth_config, timestamp_ms, nonce, "X-Iroha-Nonce")?;
        let signature_b64 = parse_required_header_exact_text(headers, HEADER_SIGNATURE)?;
        let signature_bytes = decode_signature_bytes_value(signature_b64, "X-Iroha-Signature")?;
        let signature = checked_app_auth_signature_from_bytes(
            &signature_bytes,
            &signer,
            "X-Iroha-Signature payload",
        )?;
        let message = bounded_canonical_network_request_message(
            state.network_id_ref(),
            method,
            uri,
            body,
            Some((timestamp_ms, nonce)),
        )?;
        verify_app_auth_signature(&signature, &signer, &message, "X-Iroha-Signature payload")?;
        // Decode only after proving the raw request bytes. Malformed bodies therefore cannot bypass
        // authentication, and they do not qualify an absent authority for this endpoint exception.
        let request: FeeQuoteRequest = match norito::json::from_slice(body) {
            Ok(request) => request,
            Err(_) => return Err(normal_error),
        };
        if request.payload.authority != account
            || !iroha_core::tx::executable_self_registers_authority(
                &request.payload.instructions,
                &account,
            )
        {
            return Err(normal_error);
        }
        let primary_signer = signer
            .try_clone_for_admission()
            .map_err(|_| canonical_request_capacity_error())?;
        let mut verified_signers = admitted_signer_list(1)?;
        verified_signers.push(signer);
        Ok(Some(finish_verified_canonical_request(
            account,
            primary_signer,
            verified_signers,
            nonce,
            &replay_cache,
            auth_config.nonce_ttl,
        )?))
    })
}
#[cfg(all(test, feature = "app_api"))]
mod tests {
    fn standalone_auth_context() -> norito::core::DecodeBudgetContext {
        norito::core::DecodeBudgetContext::new(norito::canonical_decode_limits(48 * 1024 * 1024))
    }
    use super::*;
    use axum::http::Uri;
    use iroha_core::{
        kura::Kura,
        query::store::LiveQueryStore,
        state::{State, World},
    };
    use iroha_crypto::{Algorithm, HashOf, KeyPair};
    use iroha_data_model::{
        Registrable,
        account::{Account, AccountAddress, MultisigMember, MultisigPolicy},
        block::BlockHeader,
        domain::Domain,
        isi::Register,
        transaction::{FeePaymentIntent, TransactionBuilder},
    };
    use iroha_model_base::domain::DomainId;
    use iroha_test_samples::{ALICE_ID, ALICE_KEYPAIR};
    use mv::storage::StorageReadOnly;
    use nonzero_ext::nonzero;
    const TEST_ACCOUNT_I105: &str = "sorauﾛ1NﾗhBUd2BﾂｦﾄiﾔﾆﾂﾇKSﾃaﾘﾒﾓQﾗrﾒoﾘﾅnｳﾘbQｳQJﾆLJ5HSE";
    const ED25519_SMALL_ORDER_POINT: [u8; ed25519_dalek::PUBLIC_KEY_LENGTH] = [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];
    const ED25519_NONCANONICAL_IDENTITY: [u8; ed25519_dalek::PUBLIC_KEY_LENGTH] = [
        0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ];
    fn minimal_state_with_account(account: &AccountId) -> Arc<State> {
        let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
        let domain = Domain::new(domain_id.clone()).build(account);
        let account_value = Account::new(account.clone()).build(account);
        Arc::new(State::new_for_testing(
            World::with([domain], [account_value], []),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        ))
    }
    fn minimal_state_with_account_and_network_id(
        account: &AccountId,
        network_id: NetworkId,
    ) -> Arc<State> {
        let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
        let domain = Domain::new(domain_id.clone()).build(account);
        let account_value = Account::new(account.clone()).build(account);
        Arc::new(State::new_with_chain_and_network_id_for_testing(
            World::with([domain], [account_value], []),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
            "app-auth-tests".parse().expect("test chain name"),
            network_id,
        ))
    }
    fn minimal_state_without_accounts() -> Arc<State> {
        Arc::new(State::new_for_testing(
            World::default(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        ))
    }
    fn minimal_state_without_accounts_for_network(network_id: NetworkId) -> Arc<State> {
        Arc::new(State::new_with_chain_and_network_id_for_testing(
            World::default(),
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
            "app-auth-tests".parse().expect("test chain name"),
            network_id,
        ))
    }
    fn fee_quote_body(authority: &AccountId, account_to_register: &AccountId) -> Vec<u8> {
        let payload = TransactionBuilder::new(
            test_network_id(0x30),
            authority.clone(),
            FeePaymentIntent::authority(Vec::new(), None),
        )
        .with_instructions([Register::account(Account::new(account_to_register.clone()))])
        .into_payload()
        .expect("build self-registering fee quote payload");
        norito::json::to_vec(&FeeQuoteRequest { payload }).expect("encode fee quote request")
    }
    fn signed_headers_for_test(
        network_id: &NetworkId,
        account: &AccountId,
        key_pair: &KeyPair,
        method: &Method,
        uri: &Uri,
        body: &[u8],
        nonce: &'static str,
    ) -> HeaderMap {
        let timestamp_ms = crate::utils::unix_now_ms();
        let message = canonical_network_request_signature_message(
            network_id,
            method,
            uri,
            body,
            timestamp_ms,
            nonce,
        )
        .expect("canonical test request is within V1 limits");
        let signature = checked_signature(key_pair.private_key(), &message);
        let mut headers = HeaderMap::new();
        headers.insert(
            HEADER_ACCOUNT,
            account
                .to_canonical_hex()
                .expect("canonical account header")
                .parse()
                .expect("valid account header"),
        );
        headers.insert(
            HEADER_SIGNATURE,
            signature_header_value(&signature)
                .expect("encode valid signature header")
                .parse()
                .expect("valid signature header"),
        );
        headers.insert(
            HEADER_TIMESTAMP_MS,
            timestamp_ms
                .to_string()
                .parse()
                .expect("valid timestamp header"),
        );
        headers.insert(HEADER_NONCE, nonce.parse().expect("valid nonce header"));
        headers
    }
    fn test_network_id(seed: u8) -> NetworkId {
        NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
            Hash::prehashed([seed; Hash::LENGTH]),
        ))
    }
    fn signed_network_headers_for_test(
        network_id: &NetworkId,
        account: &AccountId,
        key_pair: &KeyPair,
        method: &Method,
        uri: &Uri,
        body: &[u8],
        nonce: &'static str,
    ) -> HeaderMap {
        let timestamp_ms = crate::utils::unix_now_ms();
        let message = canonical_network_request_signature_message(
            network_id,
            method,
            uri,
            body,
            timestamp_ms,
            nonce,
        )
        .expect("canonical test request is within V1 limits");
        let signature = checked_signature(key_pair.private_key(), &message);
        let mut headers = HeaderMap::new();
        headers.insert(
            HEADER_ACCOUNT,
            account
                .to_canonical_hex()
                .expect("canonical account header")
                .parse()
                .expect("valid account header"),
        );
        headers.insert(
            HEADER_SIGNATURE,
            signature_header_value(&signature)
                .expect("encode valid signature header")
                .parse()
                .expect("valid signature header"),
        );
        headers.insert(
            HEADER_TIMESTAMP_MS,
            timestamp_ms
                .to_string()
                .parse()
                .expect("valid timestamp header"),
        );
        headers.insert(HEADER_NONCE, nonce.parse().expect("valid nonce header"));
        headers
    }
    fn assert_missing_account_rejection(error: crate::Error) {
        match error {
            crate::Error::Query(ValidationFail::NotPermitted(message)) => {
                assert_eq!(message, "canonical request account is not registered")
            }
            other => panic!("expected missing-account authentication rejection, got {other:?}"),
        }
    }
    fn bind_account_alias_for_test(state: &Arc<State>, account_id: &AccountId, alias: &str) {
        let dataspace_catalog = state.nexus_snapshot().dataspace_catalog.clone();
        let label =
            iroha_data_model::account::rekey::AccountAlias::from_literal(alias, &dataspace_catalog)
                .expect("valid account alias");
        let selector = iroha_core::sns::selector_for_account_alias(&label, &dataspace_catalog)
            .expect("account alias selector");
        let account_address =
            AccountAddress::from_account_id(account_id).expect("address from account id");
        let record = iroha_data_model::sns::NameRecordV1::new(
            selector.clone(),
            account_id.clone(),
            vec![iroha_data_model::sns::NameControllerV1::account(
                &account_address,
            )],
            0,
            0,
            u64::MAX,
            u64::MAX,
            u64::MAX,
            iroha_model_base::metadata::Metadata::default(),
        );
        let header = iroha_data_model::block::BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut tx = block.transaction();
        let world = tx.world_mut_for_testing();
        world
            .account_aliases_mut_for_testing()
            .insert(label.clone(), account_id.clone());
        let mut labels = world
            .account_aliases_by_account_mut_for_testing()
            .get(account_id)
            .cloned()
            .unwrap_or_default();
        labels.insert(label.clone());
        world
            .account_aliases_by_account_mut_for_testing()
            .insert(account_id.clone(), labels);
        world.replace_account_rekey_record_for_testing(
            iroha_data_model::account::rekey::AccountRekeyRecord::new(label, account_id.clone()),
        );
        world.smart_contract_state_mut_for_testing().insert(
            iroha_core::sns::record_storage_key(&selector),
            norito::codec::Encode::encode(&record),
        );
        tx.apply();
        block
            .commit_world_overlay_for_testing()
            .expect("commit account alias for test");
    }
    #[cfg(test)]
    fn test_guard(config: CanonicalRequestAuthConfig) -> impl Drop {
        static TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        struct Guard {
            _lock: std::sync::MutexGuard<'static, ()>,
        }
        impl Drop for Guard {
            fn drop(&mut self) {
                configure(CanonicalRequestAuthConfig::default()).expect("default app-auth config");
            }
        }
        let guard = TEST_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        configure(config).expect("valid app-auth test config");
        Guard { _lock: guard }
    }
    #[cfg(test)]
    fn checked_signature(private_key: &iroha_crypto::PrivateKey, payload: &[u8]) -> Signature {
        Signature::try_new(private_key, payload).expect("test fixture signing should succeed")
    }
    fn noncanonical_standard_base64_pad_bit_alias(encoded: &str) -> String {
        assert!(
            encoded.ends_with("=="),
            "64-byte signatures encode with == padding"
        );
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut bytes = encoded.as_bytes().to_vec();
        let index = bytes.len() - 3;
        let value = ALPHABET
            .iter()
            .position(|byte| *byte == bytes[index])
            .expect("standard base64 alphabet");
        bytes[index] = ALPHABET[value ^ 0x01];
        String::from_utf8(bytes).expect("base64 alias remains ASCII")
    }
    fn checked_app_auth_key_fixture() -> KeyPair {
        KeyPair::try_random().expect("generate checked app auth fixture key")
    }
    #[test]
    fn app_auth_fixture_uses_checked_default_key_generation() {
        let key_pair = checked_app_auth_key_fixture();
        let actual = key_pair
            .public_key()
            .try_algorithm()
            .expect("app auth fixture key advertises a valid algorithm");
        assert_eq!(actual, Algorithm::default());
    }
    #[test]
    fn iterable_validation_preserves_escrow_seller_discriminant() {
        let state = minimal_state_with_account(&ALICE_ID);
        let query = iroha_data_model::query::escrow::prelude::FindAssetEscrowsBySeller {
            seller: ALICE_ID.clone(),
        };
        validate_iter_query_for_authority(&state, &ALICE_ID, query)
            .expect("the seller-specific tag must retain same-account query authorization");
    }
    #[test]
    fn checked_app_auth_signature_from_bytes_rejects_malformed_ed25519_r_before_wrapping() {
        let valid_signature = checked_signature(
            ALICE_KEYPAIR.private_key(),
            b"app-auth checked signature admission helper",
        );
        for (label, replacement_r) in [
            ("small-order", ED25519_SMALL_ORDER_POINT),
            ("noncanonical", ED25519_NONCANONICAL_IDENTITY),
        ] {
            let mut payload = valid_signature.payload().to_vec();
            payload[..ed25519_dalek::PUBLIC_KEY_LENGTH].copy_from_slice(&replacement_r);
            let err = checked_app_auth_signature_from_bytes(
                &payload,
                ALICE_KEYPAIR.public_key(),
                "helper signature payload",
            )
            .expect_err("malformed Ed25519 R must fail before opaque signature wrapping");
            match err {
                crate::Error::Query(ValidationFail::NotPermitted(msg)) => {
                    assert!(
                        msg.contains("helper signature payload")
                            && msg.contains("Ed25519 signature failed admission"),
                        "{label} signature failed with unexpected error: {msg}"
                    );
                }
                other => panic!("unexpected error: {other:?}"),
            }
        }
    }
    #[test]
    fn checked_app_auth_signature_from_bytes_rejects_malformed_mldsa_signature_lengths_before_wrapping()
     {
        let key_pair = KeyPair::try_random_with_algorithm(Algorithm::MlDsa)
            .expect("generate checked app auth ML-DSA fixture key");
        let valid_signature = checked_signature(
            key_pair.private_key(),
            b"app-auth checked ML-DSA signature admission helper",
        );
        let mut extended = valid_signature.payload().to_vec();
        extended.push(0);
        for (label, payload) in [
            (
                "truncated",
                valid_signature.payload()[..valid_signature.payload().len() - 1].to_vec(),
            ),
            ("extended", extended),
        ] {
            let err = checked_app_auth_signature_from_bytes(
                &payload,
                key_pair.public_key(),
                "helper ML-DSA signature payload",
            )
            .expect_err("malformed ML-DSA length must fail before opaque signature wrapping");
            match err {
                crate::Error::Query(ValidationFail::NotPermitted(msg)) => {
                    assert!(
                        msg.contains("helper ML-DSA signature payload")
                            && msg.contains("ML-DSA signature failed admission"),
                        "{label} signature failed with unexpected error: {msg}"
                    );
                }
                other => panic!("unexpected error: {other:?}"),
            }
        }
    }
    #[test]
    fn validate_app_auth_signature_for_signer_rejects_malformed_mldsa_signature_lengths() {
        let key_pair = KeyPair::try_random_with_algorithm(Algorithm::MlDsa)
            .expect("generate checked app auth ML-DSA validation fixture key");
        let valid_signature = checked_signature(
            key_pair.private_key(),
            b"app-auth wrapped ML-DSA signature admission helper",
        );
        let mut extended = valid_signature.payload().to_vec();
        extended.push(0);
        for (label, payload) in [
            (
                "truncated",
                valid_signature.payload()[..valid_signature.payload().len() - 1].to_vec(),
            ),
            ("extended", extended),
        ] {
            let signature = Signature::from_bytes(&payload);
            let err = validate_app_auth_signature_for_signer(
                &signature,
                key_pair.public_key(),
                "wrapped ML-DSA signature payload",
            )
            .expect_err("malformed wrapped ML-DSA length must fail admission");
            match err {
                crate::Error::Query(ValidationFail::NotPermitted(msg)) => {
                    assert!(
                        msg.contains("wrapped ML-DSA signature payload")
                            && msg.contains("ML-DSA signature failed admission"),
                        "{label} signature failed with unexpected error: {msg}"
                    );
                }
                other => panic!("unexpected error: {other:?}"),
            }
        }
    }
    #[test]
    fn canonical_query_sorting_is_stable() {
        let raw = "b=2&a=3&b=1&space=a+b";
        let canonical = canonical_query_string(Some(raw)).expect("query is within V1 limits");
        assert_eq!(canonical, "a=3&b=1&b=2&space=a+b");
    }

    #[test]
    fn public_canonical_message_matches_independent_lossy_form_wire_oracle() {
        let network_id = test_network_id(0x7b);
        let method = Method::POST;
        let raw = "b=%FF&a=%E2%82%AC&literal=%GG&space=a+b&&empty";
        let uri: Uri = format!("/v1/contracts/view?{raw}")
            .parse()
            .expect("canonical form corpus URI");
        let timestamp_ms = 1_902_345_678_901_u64;
        let nonce = "bounded-message-parity";
        let expected = canonical_network_request_signature_message(
            &network_id,
            &method,
            &uri,
            b"wire body",
            timestamp_ms,
            nonce,
        )
        .expect("canonical test request is within V1 limits");
        let mut oracle = b"iroha.app.request.network.v1\0".to_vec();
        oracle.extend_from_slice(network_id.as_bytes());
        oracle.extend_from_slice(
            b"POST\n/v1/contracts/view\na=%E2%82%AC&b=%EF%BF%BD&empty=&literal=%25GG&space=a+b\n6119ee2a454af16109eb044507a4dcaa39ae21297562f996e8d0dea6de66094c\n1902345678901\nbounded-message-parity",
        );
        assert_eq!(expected, oracle);
    }
    #[test]
    fn canonical_query_pair_limit_accepts_exact_and_rejects_plus_one() {
        let exact_query = std::iter::repeat_n("key=value", CANONICAL_REQUEST_MAX_QUERY_PAIRS_V1)
            .collect::<Vec<_>>()
            .join("&");
        let exact_uri: Uri = format!("/v1/test?{exact_query}")
            .parse()
            .expect("exact URI");
        validate_canonical_request_query(&exact_uri)
            .expect("the exact V1 query-pair limit must be accepted");
        canonical_request_message(&Method::GET, &exact_uri, &[])
            .expect("the public builder accepts the exact query-pair limit");

        let excessive_query = format!("{exact_query}&key=value");
        let excessive_uri: Uri = format!("/v1/test?{excessive_query}")
            .parse()
            .expect("plus-one URI");
        let error = validate_canonical_request_query(&excessive_uri)
            .expect_err("one pair beyond the V1 limit must be rejected");
        assert!(matches!(
            error,
            crate::Error::Query(ValidationFail::NotPermitted(message))
                if message.contains("64 pairs")
        ));
        assert!(canonical_request_message(&Method::GET, &excessive_uri, &[]).is_err());
    }

    #[test]
    fn canonical_query_raw_byte_limit_accepts_exact_and_rejects_plus_one() {
        let exact = "x".repeat(CANONICAL_REQUEST_MAX_RAW_QUERY_BYTES_V1);
        validate_canonical_request_raw_query(&exact)
            .expect("the exact V1 raw-query byte limit must be accepted");
        let exact_uri = Uri::builder()
            .path_and_query(
                http::uri::PathAndQuery::try_from(format!("/v1/test?{exact}"))
                    .expect("exact path-and-query"),
            )
            .build()
            .expect("exact URI");
        canonical_request_message(&Method::GET, &exact_uri, &[])
            .expect("the public builder accepts the exact raw-query limit");

        let excessive = format!("{exact}x");
        let error = validate_canonical_request_raw_query(&excessive)
            .expect_err("one raw query byte beyond the V1 limit must be rejected");
        assert!(matches!(
            error,
            crate::Error::Query(ValidationFail::NotPermitted(message))
                if message.contains("65536 raw bytes")
        ));
        let excessive_uri = Uri::builder()
            .path_and_query(
                http::uri::PathAndQuery::try_from(format!("/v1/test?{excessive}"))
                    .expect("plus-one path-and-query"),
            )
            .build()
            .expect("plus-one URI");
        assert!(canonical_request_message(&Method::GET, &excessive_uri, &[]).is_err());
    }

    #[test]
    fn canonical_method_limit_accepts_exact_and_rejects_plus_one() {
        let uri: Uri = "/v1/test".parse().expect("test URI");
        let exact = Method::from_bytes(&vec![b'A'; CANONICAL_REQUEST_MAX_METHOD_BYTES_V1])
            .expect("exact method token");
        validate_canonical_request_target(&exact, &uri)
            .expect("the exact V1 method limit must be accepted");
        canonical_request_message(&exact, &uri, &[])
            .expect("the public builder accepts the exact method limit");

        let excessive = Method::from_bytes(&vec![b'A'; CANONICAL_REQUEST_MAX_METHOD_BYTES_V1 + 1])
            .expect("plus-one method token");
        let error = validate_canonical_request_target(&excessive, &uri)
            .expect_err("one method byte beyond the V1 limit must be rejected");
        assert!(matches!(
            error,
            crate::Error::Query(ValidationFail::NotPermitted(message))
                if message.contains("32 bytes")
        ));
        assert!(canonical_request_message(&excessive, &uri, &[]).is_err());
    }

    #[test]
    fn canonical_path_limit_accepts_exact_and_rejects_programmatic_plus_one() {
        use axum::http::uri::PathAndQuery;

        fn uri_with_path_bytes(bytes: usize) -> Uri {
            let path = format!("/{}", "x".repeat(bytes - 1));
            Uri::builder()
                .path_and_query(PathAndQuery::try_from(path).expect("valid path and query"))
                .build()
                .expect("programmatic URI")
        }

        let method = Method::GET;
        let exact = uri_with_path_bytes(CANONICAL_REQUEST_MAX_PATH_BYTES_V1);
        validate_canonical_request_target(&method, &exact)
            .expect("the exact V1 path limit must be accepted");
        canonical_request_message(&method, &exact, &[])
            .expect("the public builder accepts the exact path limit");

        let excessive = uri_with_path_bytes(CANONICAL_REQUEST_MAX_PATH_BYTES_V1 + 1);
        let error = validate_canonical_request_target(&method, &excessive)
            .expect_err("one programmatic path byte beyond the V1 limit must be rejected");
        assert!(matches!(
            error,
            crate::Error::Query(ValidationFail::NotPermitted(message))
                if message.contains("65536 bytes")
        ));
        let network_id = test_network_id(0x7c);
        assert!(canonical_request_message(&method, &excessive, &[]).is_err());
        assert!(canonical_network_request_message(&network_id, &method, &excessive, &[]).is_err());
        assert!(canonical_network_request_hash(&network_id, &method, &excessive, &[]).is_err());
    }

    #[test]
    fn canonical_auth_singleton_headers_reject_duplicates() {
        let mut headers = HeaderMap::new();
        headers.append(HEADER_ACCOUNT, "first".parse().expect("header"));
        validate_canonical_request_singleton_headers(&headers)
            .expect("one auth header value is canonical");
        headers.append(HEADER_ACCOUNT, "second".parse().expect("header"));
        let error = validate_canonical_request_singleton_headers(&headers)
            .expect_err("duplicate auth header must be rejected");
        assert!(matches!(
            error,
            crate::Error::Query(ValidationFail::NotPermitted(message))
                if message.contains(HEADER_ACCOUNT) && message.contains("at most once")
        ));
    }

    #[test]
    fn canonical_account_literal_limit_rejects_plus_one_before_parsing() {
        let exact = "a".repeat(CANONICAL_REQUEST_MAX_ACCOUNT_LITERAL_BYTES_V1);
        assert!(canonical_request_account_literal_fits_v1(&exact));
        let excessive = format!("{exact}a");
        assert!(!canonical_request_account_literal_fits_v1(&excessive));

        let maximum_single_canonical_bytes = 1 + 4 + iroha_crypto::MAX_PUBLIC_KEY_PAYLOAD_BYTES;
        let maximum_i105_symbols = maximum_single_canonical_bytes
            .checked_mul(4)
            .expect("protocol key ceiling fits")
            .div_ceil(3)
            + 6;
        let maximum_i105_utf8_bytes = 6 + maximum_i105_symbols * 3;
        assert!(
            maximum_i105_utf8_bytes <= CANONICAL_REQUEST_MAX_ACCOUNT_LITERAL_BYTES_V1,
            "the direct V1 cap must admit every supported single-key I105 spelling"
        );
    }

    #[test]
    fn canonical_account_header_obeys_original_cumulative_codec_owner() {
        let account = ALICE_ID.clone();
        let state = minimal_state_with_account(&account);
        let literal = account.to_canonical_hex().unwrap();
        let owner = crate::history_producer::HistoryProducerOwner::for_test();
        let before = owner.allocation_context().consumed_allocated_bytes();
        let first =
            parse_account_header_value(&state, &literal, owner.allocation_context()).unwrap();
        let after = owner.allocation_context().consumed_allocated_bytes();
        assert_eq!(first, account);
        assert!(after > before);
        parse_account_header_value(&state, &literal, owner.allocation_context()).unwrap();
        assert!(owner.allocation_context().consumed_allocated_bytes() > after);
        let refused =
            norito::core::DecodeBudgetContext::new(norito::DecodeLimits::new(1, 1, 1, 1, 1));
        assert!(matches!(
            parse_account_header_value(&state, &literal, &refused),
            Err(crate::Error::Query(ValidationFail::QueryFailed(
                QueryExecutionFail::CapacityLimit
            )))
        ));
    }

    #[test]
    fn canonical_account_alias_limit_precedes_the_wider_controller_hex_limit() {
        let excessive = format!(
            "{}@d",
            "a".repeat(CANONICAL_REQUEST_MAX_ALIAS_LITERAL_BYTES_V1)
        );
        assert!(
            excessive.len() < CANONICAL_REQUEST_MAX_ACCOUNT_LITERAL_BYTES_V1,
            "the alias ceiling must be narrower than the controller-hex ceiling"
        );
        let error = validate_canonical_account_header_literal(&excessive)
            .expect_err("an oversized catalog-free alias must be rejected before parsing");
        assert!(matches!(
            error,
            crate::Error::Query(ValidationFail::NotPermitted(message))
                if message == "invalid X-Iroha-Account value"
        ));
    }

    #[test]
    fn canonical_timestamp_accepts_only_exact_unsigned_decimal() {
        assert_eq!(
            parse_canonical_timestamp_ms("0").expect("canonical zero"),
            0
        );
        assert_eq!(
            parse_canonical_timestamp_ms("18446744073709551615").expect("canonical u64 maximum"),
            u64::MAX
        );
        for invalid in [
            "",
            "+1",
            "-1",
            "00",
            "01",
            " 1",
            "1 ",
            "18446744073709551616",
        ] {
            assert!(
                parse_canonical_timestamp_ms(invalid).is_err(),
                "alternate timestamp spelling {invalid:?} must be rejected"
            );
        }
    }

    #[test]
    fn canonical_nonce_accepts_only_one_to_256_printable_ascii_bytes() {
        let config = CanonicalRequestAuthConfig::default();
        let timestamp_ms = crate::utils::unix_now_ms();
        let exact = "!".repeat(256);
        validate_freshness(&config, timestamp_ms, &exact, "nonce")
            .expect("256 printable ASCII bytes are accepted");
        let network_id = test_network_id(0x7d);
        let uri: Uri = "/v1/test".parse().expect("test URI");
        canonical_network_request_signature_message(
            &network_id,
            &Method::GET,
            &uri,
            &[],
            timestamp_ms,
            &exact,
        )
        .expect("the public builder accepts the exact nonce limit");
        for invalid in [
            String::new(),
            "!".repeat(257),
            "embedded space".to_owned(),
            "control\u{7f}".to_owned(),
            "non-ascii-λ".to_owned(),
        ] {
            let error = validate_freshness(&config, timestamp_ms, &invalid, "nonce")
                .expect_err("non-canonical nonce must be rejected");
            assert!(matches!(
                error,
                crate::Error::Query(ValidationFail::NotPermitted(message))
                    if message.contains("invalid nonce")
            ));
            assert!(
                canonical_network_request_signature_message(
                    &network_id,
                    &Method::GET,
                    &uri,
                    &[],
                    timestamp_ms,
                    &invalid,
                )
                .is_err(),
                "the public builder must reject nonce {invalid:?}",
            );
        }
    }

    #[test]
    fn bounded_base64_decode_accepts_exact_bytes_and_rejects_plus_one() {
        assert_eq!(
            canonical_padded_base64_len(CANONICAL_REQUEST_WITNESS_MAX_DECODED_BYTES_V1),
            1024 * 1024
        );
        let exact = BASE64_STANDARD.encode([0x11, 0x22, 0x33]);
        let decoded = decode_bounded_canonical_base64_value(&exact, 3, "test base64")
            .expect("exact decoded byte limit");
        assert_eq!(decoded.as_ref(), &[0x11, 0x22, 0x33]);

        let excessive = BASE64_STANDARD.encode([0x11, 0x22, 0x33, 0x44]);
        let error = decode_bounded_canonical_base64_value(&excessive, 3, "test base64")
            .expect_err("one decoded byte beyond the limit must fail before allocation");
        assert!(matches!(
            error,
            crate::Error::Query(ValidationFail::NotPermitted(message))
                if message.contains("3 decoded bytes")
        ));
    }
    #[test]
    fn signature_header_builder_accepts_v1_max_and_rejects_invalid_or_plus_one() {
        let exact_payload = vec![0x11; CANONICAL_REQUEST_MAX_SIGNATURE_BYTES_V1];
        let exact = Signature::from_bytes(&exact_payload);
        let encoded = signature_header_value(&exact).expect("exact V1 signature byte limit");
        assert_eq!(
            encoded.len(),
            canonical_padded_base64_len(CANONICAL_REQUEST_MAX_SIGNATURE_BYTES_V1)
        );

        assert!(signature_header_value(&Signature::from_bytes(&[])).is_err());
        assert!(signature_header_value(&Signature::from_bytes(&[0; 64])).is_err());
        let excessive_payload = vec![0x11; CANONICAL_REQUEST_MAX_SIGNATURE_BYTES_V1 + 1];
        let excessive = Signature::from_bytes(&excessive_payload);
        assert!(signature_header_value(&excessive).is_err());
    }
    #[test]
    fn borrowed_witness_signature_payload_preserves_owned_wire_bytes() {
        let mut witness = CanonicalRequestWitnessV1 {
            schema_version: CANONICAL_REQUEST_WITNESS_VERSION_V1,
            subject_account: ALICE_ID.clone(),
            timestamp_ms: 42,
            nonce: "borrowed-wire-parity".to_owned(),
            canonical_request_hash: Hash::new(b"borrowed witness payload parity"),
            signatures: Vec::new(),
        };
        let sdk =
            iroha::client::canonical_request_witness_message(&witness).expect("SDK signing frame");
        let server = canonical_request_witness_message(&witness).expect("server signing frame");
        let captured = include_bytes!(
            "../../iroha_torii_shared/tests/fixtures/canonical_request_witness_sdk_v1.bin"
        );
        assert_eq!(sdk, captured);
        assert_eq!(server, sdk);
        let sdk_signature = checked_signature(ALICE_KEYPAIR.private_key(), &sdk);
        sdk_signature
            .verify(ALICE_KEYPAIR.public_key(), &server)
            .expect("SDK signature must verify against server bytes");
        let server_signature = checked_signature(ALICE_KEYPAIR.private_key(), &server);
        server_signature
            .verify(ALICE_KEYPAIR.public_key(), &sdk)
            .expect("server signature must verify against SDK bytes");
        let rejected = include_bytes!(
            "../../iroha_torii_shared/tests/fixtures/rejected_canonical_request_witness_torii_v1.bin"
        );
        assert_eq!(
            norito::core::from_bytes_view(captured)
                .expect("captured SDK archive")
                .as_bytes(),
            norito::core::from_bytes_view(rejected)
                .expect("conflicting Torii archive")
                .as_bytes()
        );
        assert_ne!(server, rejected);
        let rejected_signature = checked_signature(ALICE_KEYPAIR.private_key(), rejected);
        assert!(
            rejected_signature
                .verify(ALICE_KEYPAIR.public_key(), &server)
                .is_err()
        );
        assert!(
            sdk_signature
                .verify(ALICE_KEYPAIR.public_key(), rejected)
                .is_err()
        );
        witness.signatures.push(CanonicalRequestSignatureWitnessV1 {
            signer: ALICE_KEYPAIR.public_key().clone(),
            signature: sdk_signature,
        });
        let flags = norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
        let _flags = norito::core::DecodeFlagsGuard::enter(flags);
        assert_eq!(
            canonical_request_witness_message(&witness).expect("server frame excludes signatures"),
            sdk
        );
        assert_eq!(
            iroha::client::canonical_request_witness_message(&witness)
                .expect("SDK frame excludes signatures"),
            sdk
        );
        assert_eq!(norito::core::effective_decode_flags(), Some(flags));
    }

    #[test]
    fn public_witness_builders_ignore_ambient_noncanonical_layout_flags() {
        let signature = checked_signature(ALICE_KEYPAIR.private_key(), b"witness layout fixture");
        let witness = CanonicalRequestWitnessV1 {
            schema_version: CANONICAL_REQUEST_WITNESS_VERSION_V1,
            subject_account: ALICE_ID.clone(),
            timestamp_ms: 42,
            nonce: "ambient-layout".to_owned(),
            canonical_request_hash: Hash::new(b"ambient witness layout"),
            signatures: vec![CanonicalRequestSignatureWitnessV1 {
                signer: ALICE_KEYPAIR.public_key().clone(),
                signature,
            }],
        };
        let canonical_message =
            canonical_request_witness_message(&witness).expect("canonical witness message");
        let canonical_header = witness_header_value(&witness).expect("canonical witness header");

        let flags = norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
        let _flags = norito::core::DecodeFlagsGuard::enter(flags);
        assert_eq!(
            canonical_request_witness_message(&witness).expect("guarded witness message"),
            canonical_message
        );
        assert_eq!(
            witness_header_value(&witness).expect("guarded witness header"),
            canonical_header
        );
    }

    #[test]
    fn bounded_witness_frame_identity_matches_original_observations() {
        use norito::NoritoSchema as _;
        let source =
            include_str!("../tests/fixtures/bounded_request_witness_frame_identity.v1.json");
        assert_eq!(
            hex::encode(iroha_crypto::sha256(source)),
            "8c5690e66b6689d38a488650aa7502cb7dcd6e964662f93617640a378ac4375f"
        );
        let fixture: norito::json::Value =
            norito::json::from_str(source).expect("original observation");
        assert_eq!(
            BoundedCanonicalRequestWitnessV1::nominal_name(),
            fixture["nominal"].as_str().unwrap()
        );
        assert_eq!(
            BoundedCanonicalRequestWitnessV1::frame_name(),
            fixture["root_nominal"].as_str().unwrap()
        );
        fn typed_contract<T: norito::NoritoSerialize + for<'de> norito::NoritoDeserialize<'de>>()
        -> [u8; 16] {
            norito::schema::identity::frame_hash::<T>()
        }
        let hash = typed_contract::<BoundedCanonicalRequestWitnessV1>();
        for direction in [
            "serialize_hash",
            "deserialize_hash",
            "root_serialize_hash",
            "root_deserialize_hash",
        ] {
            assert_eq!(hex::encode(hash), fixture[direction].as_str().unwrap());
        }
        assert_eq!(fixture["frames"].as_array().unwrap().len(), 1);
        for row in fixture["frames"].as_array().unwrap() {
            let flags = u8::try_from(row["flags"].as_u64().unwrap()).expect("recorded flags");
            let bytes =
                hex::decode(row["frame_hex"].as_str().unwrap()).expect("captured complete frame");
            let header = norito::core::Header::read(&bytes[..]).expect("captured header");
            assert_eq!(header.schema, hash);
            assert_eq!(header.flags, flags);
            assert_eq!(flags, norito::core::default_encode_flags());
            let _flags = norito::core::DecodeFlagsGuard::enter(flags);
            let limits = norito::DecodeLimits::new(
                CANONICAL_REQUEST_WITNESS_MAX_DECODED_BYTES_V1,
                CANONICAL_REQUEST_WITNESS_MAX_DECODED_BYTES_V1,
                CANONICAL_REQUEST_WITNESS_MAX_DECODED_BYTES_V1,
                CANONICAL_REQUEST_WITNESS_MAX_DECODED_BYTES_V1.saturating_mul(2),
                norito::core::MAX_VALUE_NESTING_DEPTH,
            );
            let bounded: BoundedCanonicalRequestWitnessV1 =
                norito::decode_from_bytes_with_limits(&bytes, limits)
                    .expect("original frame bounded decode");
            assert_eq!(norito::to_bytes(&bounded).expect("bounded frame"), bytes);
            let public = CanonicalRequestWitnessV1::try_from(bounded).expect("bounded conversion");
            assert_eq!(norito::to_bytes(&public).expect("public frame"), bytes);
            norito::decode_canonical::<BoundedCanonicalRequestWitnessV1>(&bytes)
                .expect("canonical frame");
        }
    }
    #[test]
    fn bounded_witness_wrapper_preserves_public_noncompact_wire() {
        let signature =
            checked_signature(ALICE_KEYPAIR.private_key(), b"noncompact witness fixture");
        let witness = CanonicalRequestWitnessV1 {
            schema_version: CANONICAL_REQUEST_WITNESS_VERSION_V1,
            subject_account: ALICE_ID.clone(),
            timestamp_ms: 42,
            nonce: "noncompact-layout".to_owned(),
            canonical_request_hash: Hash::new(b"noncompact witness layout"),
            signatures: vec![CanonicalRequestSignatureWitnessV1 {
                signer: ALICE_KEYPAIR.public_key().clone(),
                signature: signature.clone(),
            }],
        };
        let bounded = BoundedCanonicalRequestWitnessV1(BoundedCanonicalRequestWitnessWireV1 {
            schema_version: witness.schema_version,
            subject_account: witness.subject_account.clone(),
            timestamp_ms: witness.timestamp_ms,
            nonce: bounded_nonce_wire::String(witness.nonce.clone()),
            canonical_request_hash: witness.canonical_request_hash,
            signatures: BoundedCanonicalRequestWitnessSignaturesV1(vec![
                BoundedCanonicalRequestSignatureWitnessWireV1 {
                    signer: ALICE_KEYPAIR.public_key().clone(),
                    signature: BoundedCanonicalRequestSignatureV1(signature),
                },
            ]),
        });
        let _flags = norito::core::DecodeFlagsGuard::enter(0);
        let public_bytes = norito::to_bytes(&witness).expect("encode public noncompact witness");
        let bounded_bytes = norito::to_bytes(&bounded).expect("encode bounded noncompact witness");
        assert_eq!(bounded_bytes, public_bytes);

        let header = norito::core::Header::read(std::io::Cursor::new(&public_bytes))
            .expect("read noncompact witness header");
        assert_eq!(header.flags, 0);
        let limits = norito::DecodeLimits::new(
            CANONICAL_REQUEST_WITNESS_MAX_DECODED_BYTES_V1,
            CANONICAL_REQUEST_WITNESS_MAX_DECODED_BYTES_V1,
            CANONICAL_REQUEST_WITNESS_MAX_DECODED_BYTES_V1,
            CANONICAL_REQUEST_WITNESS_MAX_DECODED_BYTES_V1.saturating_mul(2),
            norito::core::MAX_VALUE_NESTING_DEPTH,
        );
        let decoded: BoundedCanonicalRequestWitnessV1 =
            norito::decode_from_bytes_with_limits(&public_bytes, limits)
                .expect("decode public noncompact witness through bounded wrapper");
        assert_eq!(
            CanonicalRequestWitnessV1::try_from(decoded)
                .expect("convert bounded noncompact witness"),
            witness
        );
    }
    #[test]
    fn canonical_message_includes_body_hash() {
        let uri: Uri = format!("/v1/accounts/{TEST_ACCOUNT_I105}/assets?limit=5")
            .parse()
            .expect("uri");
        let msg = canonical_request_message(&Method::GET, &uri, b"{\"foo\":1}")
            .expect("canonical test request is within V1 limits");
        let rendered = String::from_utf8(msg).expect("utf8");
        assert!(rendered.contains(&format!("/v1/accounts/{TEST_ACCOUNT_I105}/assets")));
        assert!(rendered.contains("limit=5"));
        assert!(
            rendered.ends_with("37a76343c8e3c695feeaadfe52329673ff129c65f99f55ae6056c9254f4c481d")
        );
    }
    #[test]
    fn exact_network_auth_rejects_wrong_network_path_body_and_replay() {
        let _guard = test_guard(CanonicalRequestAuthConfig::default());
        let account = ALICE_ID.clone();
        let network_id = test_network_id(0x31);
        let state = minimal_state_with_account_and_network_id(&account, network_id);
        let wrong_network_id = test_network_id(0x32);
        let method = Method::POST;
        let uri: Uri = "/v1/subscriptions".parse().expect("subscription URI");
        let body = br#"{"payload_public_key":"self-declared-only"}"#;
        let headers = signed_network_headers_for_test(
            &network_id,
            &account,
            &ALICE_KEYPAIR,
            &method,
            &uri,
            body,
            "exact-network-replay",
        );
        verify_canonical_network_request(
            &state,
            &wrong_network_id,
            &headers,
            &method,
            &uri,
            body,
            None,
            &standalone_auth_context(),
        )
        .expect_err("a request signed for a different genesis lineage must fail");
        let wrong_uri: Uri = "/v1/subscriptions/plans"
            .parse()
            .expect("subscription plan URI");
        verify_canonical_network_request(
            &state,
            &network_id,
            &headers,
            &method,
            &wrong_uri,
            body,
            None,
            &standalone_auth_context(),
        )
        .expect_err("a signature for another subscription path must fail");
        verify_canonical_network_request(
            &state,
            &network_id,
            &headers,
            &method,
            &uri,
            br#"{"payload_public_key":"tampered"}"#,
            None,
            &standalone_auth_context(),
        )
        .expect_err("a signature for another subscription body must fail");
        let verified = verify_canonical_network_request(
            &state,
            &network_id,
            &headers,
            &method,
            &uri,
            body,
            None,
            &standalone_auth_context(),
        )
        .expect("exact-network request verification")
        .expect("signed identity");
        assert_eq!(verified.account, account);
        let replay = verify_canonical_network_request(
            &state,
            &network_id,
            &headers,
            &method,
            &uri,
            body,
            None,
            &standalone_auth_context(),
        )
        .expect_err("an accepted exact-network nonce must be one-shot");
        assert!(matches!(
            replay,
            crate::Error::Query(ValidationFail::NotPermitted(message))
                if message == "request nonce already used"
        ));
    }
    #[test]
    fn exact_network_auth_rejects_self_declared_unregistered_principal() {
        let _guard = test_guard(CanonicalRequestAuthConfig::default());
        let key_pair = checked_app_auth_key_fixture();
        let self_declared = AccountId::new(key_pair.public_key().clone());
        let network_id = test_network_id(0x41);
        let state = minimal_state_without_accounts_for_network(network_id);
        let method = Method::POST;
        let uri: Uri = "/v1/da/ingest".parse().expect("DA ingest URI");
        let body = br#"{"payload_signature":"validity-does-not-establish-eligibility"}"#;
        let headers = signed_network_headers_for_test(
            &network_id,
            &self_declared,
            &key_pair,
            &method,
            &uri,
            body,
            "unregistered-self-declared-principal",
        );
        let error = verify_canonical_network_request(
            &state,
            &network_id,
            &headers,
            &method,
            &uri,
            body,
            None,
            &standalone_auth_context(),
        )
        .expect_err("a payload-declared key is not an eligible on-ledger principal");
        assert_missing_account_rejection(error);
    }
    #[test]
    fn fee_quote_auth_accepts_exact_absent_self_registration_and_rejects_replay() {
        let _guard = test_guard(CanonicalRequestAuthConfig::default());
        let key_pair = checked_app_auth_key_fixture();
        let authority = AccountId::new(key_pair.public_key().clone());
        let state = minimal_state_without_accounts();
        let method = Method::POST;
        let uri: Uri = "/v1/fees/quote".parse().expect("fee quote uri");
        let body = fee_quote_body(&authority, &authority);
        let headers = signed_headers_for_test(
            state.network_id_ref(),
            &authority,
            &key_pair,
            &method,
            &uri,
            &body,
            "fee-quote-self-register-success",
        );
        let verified = verify_fee_quote_canonical_request(
            &state,
            &headers,
            &method,
            &uri,
            &body,
            &standalone_auth_context(),
        )
        .expect("self-registering authority should authenticate")
        .expect("signed request identity");
        assert_eq!(verified.account, authority);
        assert_eq!(verified.signer, key_pair.public_key().clone());
        assert_eq!(
            verified.verified_signers,
            vec![key_pair.public_key().clone()]
        );
        let replay = verify_fee_quote_canonical_request(
            &state,
            &headers,
            &method,
            &uri,
            &body,
            &standalone_auth_context(),
        )
        .expect_err("accepted fallback must use the canonical replay cache");
        assert!(matches!(
            replay,
            crate::Error::Query(ValidationFail::NotPermitted(message))
                if message == "request nonce already used"
        ));
    }
    #[test]
    fn fee_quote_auth_fallback_is_limited_to_the_exact_self_registering_request() {
        let _guard = test_guard(CanonicalRequestAuthConfig::default());
        let key_pair = checked_app_auth_key_fixture();
        let authority = AccountId::new(key_pair.public_key().clone());
        let other_key_pair = checked_app_auth_key_fixture();
        let other = AccountId::new(other_key_pair.public_key().clone());
        let state = minimal_state_without_accounts();
        let method = Method::POST;
        let quote_uri: Uri = "/v1/fees/quote".parse().expect("fee quote uri");
        let registers_other = fee_quote_body(&authority, &other);
        let headers = signed_headers_for_test(
            state.network_id_ref(),
            &authority,
            &key_pair,
            &method,
            &quote_uri,
            &registers_other,
            "fee-quote-registers-other",
        );
        let error = verify_fee_quote_canonical_request(
            &state,
            &headers,
            &method,
            &quote_uri,
            &registers_other,
            &standalone_auth_context(),
        )
        .expect_err("registration of another account must not qualify");
        assert_missing_account_rejection(error);
        let mismatched_authority = fee_quote_body(&other, &other);
        let headers = signed_headers_for_test(
            state.network_id_ref(),
            &authority,
            &key_pair,
            &method,
            &quote_uri,
            &mismatched_authority,
            "fee-quote-mismatched-payload-authority",
        );
        let error = verify_fee_quote_canonical_request(
            &state,
            &headers,
            &method,
            &quote_uri,
            &mismatched_authority,
            &standalone_auth_context(),
        )
        .expect_err("header and payload authorities must match");
        assert_missing_account_rejection(error);
        let multisig_policy = MultisigPolicy::new(
            1,
            vec![MultisigMember::new(key_pair.public_key().clone(), 1).expect("multisig member")],
        )
        .expect("multisig policy");
        let multisig_authority = AccountId::new_multisig(multisig_policy);
        let multisig_body = fee_quote_body(&multisig_authority, &multisig_authority);
        let headers = signed_headers_for_test(
            state.network_id_ref(),
            &multisig_authority,
            &key_pair,
            &method,
            &quote_uri,
            &multisig_body,
            "fee-quote-absent-multisig",
        );
        let error = verify_fee_quote_canonical_request(
            &state,
            &headers,
            &method,
            &quote_uri,
            &multisig_body,
            &standalone_auth_context(),
        )
        .expect_err("absent multisig authority must require a materialised WSV policy");
        assert_missing_account_rejection(error);
        let correct_body = fee_quote_body(&authority, &authority);
        let canonical_i105 = authority.canonical_i105().expect("canonical I105 fixture");
        let mut non_header_wire = signed_headers_for_test(
            state.network_id_ref(),
            &authority,
            &key_pair,
            &method,
            &quote_uri,
            &correct_body,
            "fee-quote-i105-header-rejected",
        );
        for invalid_account in [&canonical_i105, "absent@universal"] {
            non_header_wire.insert(
                HEADER_ACCOUNT,
                axum::http::HeaderValue::from_str(invalid_account)
                    .expect("non-fallback account header fixture"),
            );
            let error = verify_fee_quote_canonical_request(
                &state,
                &non_header_wire,
                &method,
                &quote_uri,
                &correct_body,
                &standalone_auth_context(),
            )
            .expect_err("fee-quote fallback must require canonical account-address hex");
            assert!(matches!(
                error,
                crate::Error::Query(ValidationFail::NotPermitted(message))
                    if message == "invalid X-Iroha-Account value"
            ));
        }
        let wrong_key_headers = signed_headers_for_test(
            state.network_id_ref(),
            &authority,
            &other_key_pair,
            &method,
            &quote_uri,
            &correct_body,
            "fee-quote-wrong-embedded-controller",
        );
        let error = verify_fee_quote_canonical_request(
            &state,
            &wrong_key_headers,
            &method,
            &quote_uri,
            &correct_body,
            &standalone_auth_context(),
        )
        .expect_err("embedded authority controller must verify the request");
        assert!(matches!(
            error,
            crate::Error::Query(ValidationFail::NotPermitted(message))
                if message == "query signature failed verification"
        ));
        let other_uri: Uri = "/v1/fee-sponsor-programs/by-id"
            .parse()
            .expect("other signed endpoint uri");
        let headers = signed_headers_for_test(
            state.network_id_ref(),
            &authority,
            &key_pair,
            &method,
            &other_uri,
            &correct_body,
            "fee-quote-fallback-other-endpoint",
        );
        let error = verify_fee_quote_canonical_request(
            &state,
            &headers,
            &method,
            &other_uri,
            &correct_body,
            &standalone_auth_context(),
        )
        .expect_err("fallback must not broaden another endpoint");
        assert_missing_account_rejection(error);
        let malformed_body = b"{";
        let headers = signed_headers_for_test(
            state.network_id_ref(),
            &authority,
            &key_pair,
            &method,
            &quote_uri,
            malformed_body,
            "fee-quote-malformed-body-auth-first",
        );
        let error = verify_fee_quote_canonical_request(
            &state,
            &headers,
            &method,
            &quote_uri,
            malformed_body,
            &standalone_auth_context(),
        )
        .expect_err("malformed body must not qualify an absent account");
        assert_missing_account_rejection(error);
    }
    #[test]
    fn fee_quote_auth_never_bypasses_a_registered_account_controller() {
        let _guard = test_guard(CanonicalRequestAuthConfig::default());
        let key_pair = checked_app_auth_key_fixture();
        let authority = AccountId::new(key_pair.public_key().clone());
        let wrong_key_pair = checked_app_auth_key_fixture();
        let state = minimal_state_with_account(&authority);
        let method = Method::POST;
        let uri: Uri = "/v1/fees/quote".parse().expect("fee quote uri");
        let body = fee_quote_body(&authority, &authority);
        let headers = signed_headers_for_test(
            state.network_id_ref(),
            &authority,
            &wrong_key_pair,
            &method,
            &uri,
            &body,
            "fee-quote-registered-controller-wins",
        );
        let error = verify_fee_quote_canonical_request(
            &state,
            &headers,
            &method,
            &uri,
            &body,
            &standalone_auth_context(),
        )
        .expect_err("registered controller verification must not fall back");
        assert!(matches!(
            error,
            crate::Error::Query(ValidationFail::NotPermitted(message))
                if message == "query signature failed verification"
        ));
    }
    #[test]
    fn verify_accepts_valid_signature() {
        let _guard = test_guard(CanonicalRequestAuthConfig::default());
        let account = ALICE_ID.clone();
        let state = minimal_state_with_account(&account);
        let method = Method::GET;
        let uri: Uri = format!("/v1/accounts/{TEST_ACCOUNT_I105}/assets?limit=10")
            .parse()
            .expect("uri");
        let timestamp_ms = crate::utils::unix_now_ms();
        let nonce = "accept-valid-signature";
        let message = canonical_network_request_signature_message(
            state.network_id_ref(),
            &method,
            &uri,
            &[],
            timestamp_ms,
            nonce,
        )
        .expect("canonical test request is within V1 limits");
        let signature = checked_signature(ALICE_KEYPAIR.private_key(), &message);
        let account_literal = account.to_canonical_hex().expect("account header hex");
        let mut headers = HeaderMap::new();
        headers.insert(
            HEADER_ACCOUNT,
            axum::http::HeaderValue::from_str(&account_literal).unwrap(),
        );
        headers.insert(
            HEADER_SIGNATURE,
            axum::http::HeaderValue::from_str(&BASE64_STANDARD.encode(signature.payload()))
                .unwrap(),
        );
        headers.insert(
            HEADER_TIMESTAMP_MS,
            axum::http::HeaderValue::from_str(&timestamp_ms.to_string()).unwrap(),
        );
        headers.insert(HEADER_NONCE, axum::http::HeaderValue::from_static(nonce));
        let verified = verify_canonical_request(
            &state,
            &headers,
            &method,
            &uri,
            &[],
            Some(&account),
            &standalone_auth_context(),
        )
        .expect("verify");
        assert_eq!(
            verified,
            Some(VerifiedCanonicalRequest {
                account,
                signer: ALICE_KEYPAIR.public_key().clone(),
                verified_signers: vec![ALICE_KEYPAIR.public_key().clone()],
            })
        );
    }
    #[test]
    fn verify_rejects_noncanonical_signature_header_base64_text() {
        let _guard = test_guard(CanonicalRequestAuthConfig::default());
        let account = ALICE_ID.clone();
        let state = minimal_state_with_account(&account);
        let method = Method::GET;
        let uri: Uri = format!("/v1/accounts/{TEST_ACCOUNT_I105}/assets?limit=10")
            .parse()
            .expect("uri");
        let timestamp_ms = crate::utils::unix_now_ms();
        let nonce = "reject-noncanonical-signature-header";
        let message = canonical_network_request_signature_message(
            state.network_id_ref(),
            &method,
            &uri,
            &[],
            timestamp_ms,
            nonce,
        )
        .expect("canonical test request is within V1 limits");
        let signature = checked_signature(ALICE_KEYPAIR.private_key(), &message);
        let account_literal = account.to_canonical_hex().expect("account header hex");
        for signature_b64 in [
            format!(" {} ", BASE64_STANDARD.encode(signature.payload())),
            noncanonical_standard_base64_pad_bit_alias(
                &BASE64_STANDARD.encode(signature.payload()),
            ),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(
                HEADER_ACCOUNT,
                axum::http::HeaderValue::from_str(&account_literal).unwrap(),
            );
            headers.insert(
                HEADER_SIGNATURE,
                axum::http::HeaderValue::from_str(&signature_b64).unwrap(),
            );
            headers.insert(
                HEADER_TIMESTAMP_MS,
                axum::http::HeaderValue::from_str(&timestamp_ms.to_string()).unwrap(),
            );
            headers.insert(HEADER_NONCE, axum::http::HeaderValue::from_static(nonce));
            let err = verify_canonical_request(
                &state,
                &headers,
                &method,
                &uri,
                &[],
                Some(&account),
                &standalone_auth_context(),
            )
            .expect_err("noncanonical signature header text must fail before verification");
            match err {
                crate::Error::Query(ValidationFail::NotPermitted(msg)) => {
                    assert!(
                        msg.contains("base64") && msg.contains("X-Iroha-Signature"),
                        "unexpected noncanonical signature header rejection: {msg}"
                    );
                }
                other => panic!("unexpected error: {other:?}"),
            }
        }
    }
    #[test]
    fn verify_accepts_alias_account_header_and_returns_canonical_i105_account() {
        let _guard = test_guard(CanonicalRequestAuthConfig::default());
        let account = ALICE_ID.clone();
        let state = minimal_state_with_account(&account);
        bind_account_alias_for_test(&state, &account, "wallet@universal");
        let method = Method::GET;
        let uri: Uri = format!("/v1/accounts/{TEST_ACCOUNT_I105}/assets?limit=10")
            .parse()
            .expect("uri");
        let timestamp_ms = crate::utils::unix_now_ms();
        let nonce = "accept-alias-account-header";
        let message = canonical_network_request_signature_message(
            state.network_id_ref(),
            &method,
            &uri,
            &[],
            timestamp_ms,
            nonce,
        )
        .expect("canonical test request is within V1 limits");
        let signature = checked_signature(ALICE_KEYPAIR.private_key(), &message);
        let mut headers = HeaderMap::new();
        headers.insert(
            HEADER_ACCOUNT,
            axum::http::HeaderValue::from_static("wallet@universal"),
        );
        headers.insert(
            HEADER_SIGNATURE,
            axum::http::HeaderValue::from_str(&BASE64_STANDARD.encode(signature.payload()))
                .unwrap(),
        );
        headers.insert(
            HEADER_TIMESTAMP_MS,
            axum::http::HeaderValue::from_str(&timestamp_ms.to_string()).unwrap(),
        );
        headers.insert(HEADER_NONCE, axum::http::HeaderValue::from_static(nonce));
        let verified = verify_canonical_request(
            &state,
            &headers,
            &method,
            &uri,
            &[],
            Some(&account),
            &standalone_auth_context(),
        )
        .expect("verify");
        assert_eq!(
            verified,
            Some(VerifiedCanonicalRequest {
                account,
                signer: ALICE_KEYPAIR.public_key().clone(),
                verified_signers: vec![ALICE_KEYPAIR.public_key().clone()],
            })
        );
    }
    #[test]
    fn account_header_uses_ascii_canonical_address_hex() {
        let account = ALICE_ID.clone();
        let state = minimal_state_with_account(&account);
        let canonical = account.to_canonical_hex().expect("canonical account hex");
        assert!(canonical.is_ascii());
        assert_eq!(
            parse_account_header_value(&state, &canonical, &standalone_auth_context())
                .expect("canonical account header"),
            account
        );

        let mut forged_class = canonical.clone().into_bytes();
        let first_header_byte = u8::from_str_radix(
            std::str::from_utf8(&forged_class[2..4]).expect("canonical header hex"),
            16,
        )
        .expect("canonical header byte");
        let forged_header = format!("{:02x}", first_header_byte | 0b1000);
        forged_class[2..4].copy_from_slice(forged_header.as_bytes());
        let uppercase_payload = format!("0x{}", canonical[2..].to_ascii_uppercase());
        assert_ne!(uppercase_payload, canonical);
        for invalid in [
            account
                .canonical_i105()
                .expect("canonical I105 data spelling"),
            canonical.replacen("0x", "0X", 1),
            uppercase_payload,
            canonical[..canonical.len() - 1].to_owned(),
            String::from_utf8(forged_class).expect("forged lowercase header hex"),
        ] {
            parse_account_header_value(&state, &invalid, &standalone_auth_context())
                .expect_err("non-ASCII or noncanonical account header must fail closed");
        }
    }
    #[test]
    fn account_header_alias_requires_an_exact_active_ascii_binding() {
        let account = ALICE_ID.clone();
        let state = minimal_state_with_account(&account);
        bind_account_alias_for_test(&state, &account, "wallet@universal");
        assert_eq!(
            parse_account_header_value(&state, "wallet@universal", &standalone_auth_context())
                .expect("active alias"),
            account
        );
        for invalid in [
            " wallet@universal",
            "wallet@universal ",
            "Wallet@universal",
            "wallet@UNIVERSAL",
            "wallet",
            "wállét@universal",
            "missing@universal",
        ] {
            parse_account_header_value(&state, invalid, &standalone_auth_context())
                .expect_err("noncanonical or inactive account header alias must fail closed");
        }
    }
    #[test]
    fn verify_rejects_wrong_signature() {
        let _guard = test_guard(CanonicalRequestAuthConfig::default());
        let account = ALICE_ID.clone();
        let state = minimal_state_with_account(&account);
        let method = Method::GET;
        let uri: Uri = format!("/v1/accounts/{TEST_ACCOUNT_I105}/assets?limit=1")
            .parse()
            .expect("uri");
        let timestamp_ms = crate::utils::unix_now_ms();
        let nonce = "wrong-signature";
        let bad_sig = checked_signature(checked_app_auth_key_fixture().private_key(), b"forged");
        let account_literal = account.to_canonical_hex().expect("account header hex");
        let mut headers = HeaderMap::new();
        headers.insert(
            HEADER_ACCOUNT,
            axum::http::HeaderValue::from_str(&account_literal).unwrap(),
        );
        headers.insert(
            HEADER_SIGNATURE,
            axum::http::HeaderValue::from_str(&BASE64_STANDARD.encode(bad_sig.payload())).unwrap(),
        );
        headers.insert(
            HEADER_TIMESTAMP_MS,
            axum::http::HeaderValue::from_str(&timestamp_ms.to_string()).unwrap(),
        );
        headers.insert(HEADER_NONCE, axum::http::HeaderValue::from_static(nonce));
        let err = verify_canonical_request(
            &state,
            &headers,
            &method,
            &uri,
            &[],
            None,
            &standalone_auth_context(),
        )
        .expect_err("must fail");
        match err {
            crate::Error::Query(ValidationFail::NotPermitted(msg)) => {
                assert!(msg.contains("signature"))
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
    #[test]
    fn verify_rejects_all_zero_signature_payload_before_backend() {
        let _guard = test_guard(CanonicalRequestAuthConfig::default());
        let account = ALICE_ID.clone();
        let state = minimal_state_with_account(&account);
        let method = Method::GET;
        let uri: Uri = format!("/v1/accounts/{TEST_ACCOUNT_I105}/assets?limit=1")
            .parse()
            .expect("uri");
        let timestamp_ms = crate::utils::unix_now_ms();
        let nonce = "all-zero-signature";
        let account_literal = account.to_canonical_hex().expect("account header hex");
        let mut headers = HeaderMap::new();
        headers.insert(
            HEADER_ACCOUNT,
            axum::http::HeaderValue::from_str(&account_literal).unwrap(),
        );
        headers.insert(
            HEADER_SIGNATURE,
            axum::http::HeaderValue::from_str(&BASE64_STANDARD.encode([0u8; 64])).unwrap(),
        );
        headers.insert(
            HEADER_TIMESTAMP_MS,
            axum::http::HeaderValue::from_str(&timestamp_ms.to_string()).unwrap(),
        );
        headers.insert(HEADER_NONCE, axum::http::HeaderValue::from_static(nonce));
        let err = verify_canonical_request(
            &state,
            &headers,
            &method,
            &uri,
            &[],
            None,
            &standalone_auth_context(),
        )
        .expect_err("inert signature payload must fail");
        match err {
            crate::Error::Query(ValidationFail::NotPermitted(msg)) => {
                assert!(
                    msg.contains("X-Iroha-Signature payload"),
                    "unexpected all-zero signature rejection: {msg}"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
    #[test]
    fn verify_rejects_malformed_ed25519_signature_payload_before_backend() {
        let _guard = test_guard(CanonicalRequestAuthConfig::default());
        let account = ALICE_ID.clone();
        let state = minimal_state_with_account(&account);
        let method = Method::GET;
        let uri: Uri = format!("/v1/accounts/{TEST_ACCOUNT_I105}/assets?limit=1")
            .parse()
            .expect("uri");
        let timestamp_ms = crate::utils::unix_now_ms();
        let message = canonical_network_request_signature_message(
            state.network_id_ref(),
            &method,
            &uri,
            &[],
            timestamp_ms,
            "invalid-r",
        )
        .expect("canonical test request is within V1 limits");
        let valid_signature = checked_signature(ALICE_KEYPAIR.private_key(), &message);
        let account_literal = account.to_canonical_hex().expect("account header hex");
        for (label, replacement_r, expected) in [
            (
                "small-order",
                ED25519_SMALL_ORDER_POINT,
                "Ed25519 signature failed admission",
            ),
            (
                "noncanonical",
                ED25519_NONCANONICAL_IDENTITY,
                "Ed25519 signature failed admission",
            ),
        ] {
            let nonce = format!("invalid-r-{label}");
            let mut payload = valid_signature.payload().to_vec();
            payload[..ed25519_dalek::PUBLIC_KEY_LENGTH].copy_from_slice(&replacement_r);
            let mut headers = HeaderMap::new();
            headers.insert(
                HEADER_ACCOUNT,
                axum::http::HeaderValue::from_str(&account_literal).unwrap(),
            );
            headers.insert(
                HEADER_SIGNATURE,
                axum::http::HeaderValue::from_str(&BASE64_STANDARD.encode(&payload)).unwrap(),
            );
            headers.insert(
                HEADER_TIMESTAMP_MS,
                axum::http::HeaderValue::from_str(&timestamp_ms.to_string()).unwrap(),
            );
            headers.insert(
                HEADER_NONCE,
                axum::http::HeaderValue::from_str(&nonce).unwrap(),
            );
            let err = verify_canonical_request(
                &state,
                &headers,
                &method,
                &uri,
                &[],
                None,
                &standalone_auth_context(),
            )
            .expect_err("malformed Ed25519 signature R must fail before backend verify");
            match err {
                crate::Error::Query(ValidationFail::NotPermitted(msg)) => {
                    assert!(
                        msg.contains("X-Iroha-Signature payload") && msg.contains(expected),
                        "{label} signature failed with unexpected error: {msg}"
                    );
                }
                other => panic!("unexpected error: {other:?}"),
            }
        }
    }
    #[test]
    fn body_auth_rejects_noncanonical_signature_base64_text() {
        let _guard = test_guard(CanonicalRequestAuthConfig::default());
        let account = ALICE_ID.clone();
        let state = minimal_state_with_account(&account);
        let method = Method::POST;
        let uri: Uri = "/v1/transactions".parse().expect("uri");
        let unsigned_body = br#"{"request":"refill"}"#;
        let timestamp_ms = crate::utils::unix_now_ms();
        let nonce = "body-auth-noncanonical-base64";
        let message = canonical_network_request_signature_message(
            state.network_id_ref(),
            &method,
            &uri,
            unsigned_body,
            timestamp_ms,
            nonce,
        )
        .expect("canonical test request is within V1 limits");
        let signature = checked_signature(ALICE_KEYPAIR.private_key(), &message);
        let account_literal = account.canonical_i105().expect("i105 account");
        for signature_b64 in [
            format!(" {} ", BASE64_STANDARD.encode(signature.payload())),
            noncanonical_standard_base64_pad_bit_alias(
                &BASE64_STANDARD.encode(signature.payload()),
            ),
        ] {
            let auth = CanonicalRequestBodyAuth {
                account_id: &account_literal,
                timestamp_ms,
                nonce,
                proof: CanonicalRequestBodyProof::SignatureBase64(&signature_b64),
            };
            let err = verify_canonical_body_request(
                &state,
                auth,
                &method,
                &uri,
                unsigned_body,
                Some(&account),
                &standalone_auth_context(),
            )
            .expect_err("noncanonical body signature base64 must fail before verification");
            match err {
                crate::Error::Query(ValidationFail::NotPermitted(msg)) => {
                    assert!(
                        msg.contains("base64") && msg.contains("signature_base64"),
                        "unexpected noncanonical body signature rejection: {msg}"
                    );
                }
                other => panic!("unexpected error: {other:?}"),
            }
        }
    }
    #[test]
    fn body_auth_rejects_malformed_ed25519_signature_payload_before_backend() {
        let _guard = test_guard(CanonicalRequestAuthConfig::default());
        let account = ALICE_ID.clone();
        let state = minimal_state_with_account(&account);
        let method = Method::POST;
        let uri: Uri = "/v1/transactions".parse().expect("uri");
        let unsigned_body = br#"{"request":"refill"}"#;
        let timestamp_ms = crate::utils::unix_now_ms();
        let nonce = "body-auth-invalid-r";
        let message = canonical_network_request_signature_message(
            state.network_id_ref(),
            &method,
            &uri,
            unsigned_body,
            timestamp_ms,
            nonce,
        )
        .expect("canonical test request is within V1 limits");
        let valid_signature = checked_signature(ALICE_KEYPAIR.private_key(), &message);
        let account_literal = account.canonical_i105().expect("i105 account");
        for (label, replacement_r, expected) in [
            (
                "small-order",
                ED25519_SMALL_ORDER_POINT,
                "Ed25519 signature failed admission",
            ),
            (
                "noncanonical",
                ED25519_NONCANONICAL_IDENTITY,
                "Ed25519 signature failed admission",
            ),
        ] {
            let mut payload = valid_signature.payload().to_vec();
            payload[..ed25519_dalek::PUBLIC_KEY_LENGTH].copy_from_slice(&replacement_r);
            let signature_b64 = BASE64_STANDARD.encode(&payload);
            let auth = CanonicalRequestBodyAuth {
                account_id: &account_literal,
                timestamp_ms,
                nonce,
                proof: CanonicalRequestBodyProof::SignatureBase64(&signature_b64),
            };
            let err = verify_canonical_body_request(
                &state,
                auth,
                &method,
                &uri,
                unsigned_body,
                Some(&account),
                &standalone_auth_context(),
            )
            .expect_err("body malformed Ed25519 signature R must fail before backend verify");
            match err {
                crate::Error::Query(ValidationFail::NotPermitted(msg)) => {
                    assert!(
                        msg.contains("signature_base64 payload") && msg.contains(expected),
                        "{label} body signature failed with unexpected error: {msg}"
                    );
                }
                other => panic!("unexpected error: {other:?}"),
            }
        }
    }
    #[tokio::test]
    async fn verify_rejects_mismatched_path_account() {
        let _guard = test_guard(CanonicalRequestAuthConfig::default());
        let account = ALICE_ID.clone();
        let other: AccountId = AccountId::new(checked_app_auth_key_fixture().public_key().clone());
        let state = minimal_state_with_account(&account);
        let method = Method::GET;
        let uri: Uri = format!("/v1/accounts/{TEST_ACCOUNT_I105}/assets?limit=1")
            .parse()
            .expect("uri");
        let timestamp_ms = crate::utils::unix_now_ms();
        let nonce = "mismatched-path-account";
        let message = canonical_network_request_signature_message(
            state.network_id_ref(),
            &method,
            &uri,
            &[],
            timestamp_ms,
            nonce,
        )
        .expect("canonical test request is within V1 limits");
        let signature = checked_signature(ALICE_KEYPAIR.private_key(), &message);
        let account_literal = account.to_canonical_hex().expect("account header hex");
        let mut headers = HeaderMap::new();
        headers.insert(
            HEADER_ACCOUNT,
            axum::http::HeaderValue::from_str(&account_literal).unwrap(),
        );
        headers.insert(
            HEADER_SIGNATURE,
            axum::http::HeaderValue::from_str(&BASE64_STANDARD.encode(signature.payload()))
                .unwrap(),
        );
        headers.insert(
            HEADER_TIMESTAMP_MS,
            axum::http::HeaderValue::from_str(&timestamp_ms.to_string()).unwrap(),
        );
        headers.insert(HEADER_NONCE, axum::http::HeaderValue::from_static(nonce));
        let err = verify_canonical_request(
            &state,
            &headers,
            &method,
            &uri,
            &[],
            Some(&other),
            &standalone_auth_context(),
        )
        .unwrap_err();
        match err {
            crate::Error::Query(ValidationFail::NotPermitted(msg)) => {
                assert!(msg.contains("signed account does not match request path"))
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
    #[test]
    fn verify_rejects_missing_freshness_headers() {
        let _guard = test_guard(CanonicalRequestAuthConfig::default());
        let account = ALICE_ID.clone();
        let state = minimal_state_with_account(&account);
        let method = Method::GET;
        let uri: Uri = format!("/v1/accounts/{TEST_ACCOUNT_I105}/assets?limit=1")
            .parse()
            .expect("uri");
        let message = canonical_request_message(&method, &uri, &[])
            .expect("canonical test request is within V1 limits");
        let signature = checked_signature(ALICE_KEYPAIR.private_key(), &message);
        let account_literal = account.to_canonical_hex().expect("account header hex");
        let mut headers = HeaderMap::new();
        headers.insert(
            HEADER_ACCOUNT,
            axum::http::HeaderValue::from_str(&account_literal).unwrap(),
        );
        headers.insert(
            HEADER_SIGNATURE,
            axum::http::HeaderValue::from_str(&BASE64_STANDARD.encode(signature.payload()))
                .unwrap(),
        );
        let err = verify_canonical_request(
            &state,
            &headers,
            &method,
            &uri,
            &[],
            None,
            &standalone_auth_context(),
        )
        .expect_err("freshness headers must be required");
        match err {
            crate::Error::Query(ValidationFail::NotPermitted(msg)) => {
                assert!(msg.contains("must be set together"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
    #[test]
    fn verify_rejects_replayed_nonce() {
        let _guard = test_guard(CanonicalRequestAuthConfig::default());
        let account = ALICE_ID.clone();
        let state = minimal_state_with_account(&account);
        let method = Method::GET;
        let uri: Uri = format!("/v1/accounts/{TEST_ACCOUNT_I105}/assets?limit=1")
            .parse()
            .expect("uri");
        let timestamp_ms = crate::utils::unix_now_ms();
        let nonce = "replayed-nonce";
        let message = canonical_network_request_signature_message(
            state.network_id_ref(),
            &method,
            &uri,
            &[],
            timestamp_ms,
            nonce,
        )
        .expect("canonical test request is within V1 limits");
        let signature = checked_signature(ALICE_KEYPAIR.private_key(), &message);
        let account_literal = account.to_canonical_hex().expect("account header hex");
        let mut headers = HeaderMap::new();
        headers.insert(
            HEADER_ACCOUNT,
            axum::http::HeaderValue::from_str(&account_literal).unwrap(),
        );
        headers.insert(
            HEADER_SIGNATURE,
            axum::http::HeaderValue::from_str(&BASE64_STANDARD.encode(signature.payload()))
                .unwrap(),
        );
        headers.insert(
            HEADER_TIMESTAMP_MS,
            axum::http::HeaderValue::from_str(&timestamp_ms.to_string()).unwrap(),
        );
        headers.insert(HEADER_NONCE, axum::http::HeaderValue::from_static(nonce));
        verify_canonical_request(
            &state,
            &headers,
            &method,
            &uri,
            &[],
            None,
            &standalone_auth_context(),
        )
        .expect("first request must pass");
        let err = verify_canonical_request(
            &state,
            &headers,
            &method,
            &uri,
            &[],
            None,
            &standalone_auth_context(),
        )
        .expect_err("replay must fail");
        match err {
            crate::Error::Query(ValidationFail::NotPermitted(msg)) => {
                assert!(msg.contains("nonce already used"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
    #[test]
    fn replay_cache_capacity_fails_closed_without_evicting_live_nonces() {
        let cache = ReplayCache::new(Duration::from_secs(300), nonzero!(2_usize));
        let account = ALICE_ID.clone();
        let ttl = Duration::from_secs(300);
        check_replay(&account, "protected-a", &cache, ttl).expect("first nonce");
        check_replay(&account, "protected-b", &cache, ttl).expect("second nonce");
        let saturated =
            check_replay(&account, "overflow", &cache, ttl).expect_err("full cache must reject");
        assert!(matches!(
            saturated,
            crate::Error::Query(ValidationFail::QueryFailed(
                iroha_data_model::query::error::QueryExecutionFail::CapacityLimit
            ))
        ));
        let replay = check_replay(&account, "protected-a", &cache, ttl)
            .expect_err("capacity pressure must preserve the first nonce");
        match replay {
            crate::Error::Query(ValidationFail::NotPermitted(message)) => {
                assert!(message.contains("nonce already used"));
            }
            other => panic!("unexpected replay error: {other:?}"),
        }
    }
    #[test]
    fn app_auth_config_rejects_short_nonce_retention() {
        let config = CanonicalRequestAuthConfig {
            max_clock_skew: Duration::from_secs(60),
            nonce_ttl: Duration::from_secs(120),
            replay_cache_capacity: nonzero!(8_usize),
        };
        assert_eq!(config.validate(), Err(CanonicalRequestAuthConfigError));
    }
    #[test]
    fn configure_preserves_replay_cache_entries() {
        let _guard = test_guard(CanonicalRequestAuthConfig::default());
        let account = ALICE_ID.clone();
        let state = minimal_state_with_account(&account);
        let method = Method::GET;
        let uri: Uri = format!("/v1/accounts/{TEST_ACCOUNT_I105}/assets?limit=1")
            .parse()
            .expect("uri");
        let timestamp_ms = crate::utils::unix_now_ms();
        let nonce = format!("configure-preserves-replay-cache-{timestamp_ms}");
        let message = canonical_network_request_signature_message(
            state.network_id_ref(),
            &method,
            &uri,
            &[],
            timestamp_ms,
            &nonce,
        )
        .expect("canonical test request is within V1 limits");
        let signature = checked_signature(ALICE_KEYPAIR.private_key(), &message);
        let account_literal = account.to_canonical_hex().expect("account header hex");
        let mut headers = HeaderMap::new();
        headers.insert(
            HEADER_ACCOUNT,
            axum::http::HeaderValue::from_str(&account_literal).unwrap(),
        );
        headers.insert(
            HEADER_SIGNATURE,
            axum::http::HeaderValue::from_str(&BASE64_STANDARD.encode(signature.payload()))
                .unwrap(),
        );
        headers.insert(
            HEADER_TIMESTAMP_MS,
            axum::http::HeaderValue::from_str(&timestamp_ms.to_string()).unwrap(),
        );
        headers.insert(
            HEADER_NONCE,
            axum::http::HeaderValue::from_str(&nonce).unwrap(),
        );
        verify_canonical_request(
            &state,
            &headers,
            &method,
            &uri,
            &[],
            None,
            &standalone_auth_context(),
        )
        .expect("first request must pass");
        configure(CanonicalRequestAuthConfig {
            max_clock_skew: Duration::from_secs(120),
            ..CanonicalRequestAuthConfig::default()
        })
        .expect("valid reconfigured app-auth window");
        let err = verify_canonical_request(
            &state,
            &headers,
            &method,
            &uri,
            &[],
            None,
            &standalone_auth_context(),
        )
        .expect_err("replay must still fail after reconfigure");
        match err {
            crate::Error::Query(ValidationFail::NotPermitted(msg)) => {
                assert!(msg.contains("nonce already used"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
    #[test]
    fn verify_rejects_stale_timestamp() {
        let _guard = test_guard(CanonicalRequestAuthConfig {
            max_clock_skew: Duration::from_secs(1),
            nonce_ttl: Duration::from_secs(300),
            replay_cache_capacity: nonzero!(128usize),
        });
        let account = ALICE_ID.clone();
        let state = minimal_state_with_account(&account);
        let method = Method::GET;
        let uri: Uri = format!("/v1/accounts/{TEST_ACCOUNT_I105}/assets?limit=1")
            .parse()
            .expect("uri");
        let timestamp_ms = 1;
        let nonce = "stale-timestamp";
        let message = canonical_network_request_signature_message(
            state.network_id_ref(),
            &method,
            &uri,
            &[],
            timestamp_ms,
            nonce,
        )
        .expect("canonical test request is within V1 limits");
        let signature = checked_signature(ALICE_KEYPAIR.private_key(), &message);
        let account_literal = account.to_canonical_hex().expect("account header hex");
        let mut headers = HeaderMap::new();
        headers.insert(
            HEADER_ACCOUNT,
            axum::http::HeaderValue::from_str(&account_literal).unwrap(),
        );
        headers.insert(
            HEADER_SIGNATURE,
            axum::http::HeaderValue::from_str(&BASE64_STANDARD.encode(signature.payload()))
                .unwrap(),
        );
        headers.insert(
            HEADER_TIMESTAMP_MS,
            axum::http::HeaderValue::from_static("1"),
        );
        headers.insert(HEADER_NONCE, axum::http::HeaderValue::from_static(nonce));
        let err = verify_canonical_request(
            &state,
            &headers,
            &method,
            &uri,
            &[],
            None,
            &standalone_auth_context(),
        )
        .expect_err("stale request must fail");
        match err {
            crate::Error::Query(ValidationFail::NotPermitted(msg)) => {
                assert!(msg.contains("timestamp outside allowed skew"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
    #[test]
    fn verify_rejects_multisig_account_signature() {
        let _guard = test_guard(CanonicalRequestAuthConfig::default());
        let signer_one = checked_app_auth_key_fixture();
        let signer_two = checked_app_auth_key_fixture();
        let policy = MultisigPolicy::new(
            2,
            vec![
                MultisigMember::new(signer_one.public_key().clone(), 1).expect("member"),
                MultisigMember::new(signer_two.public_key().clone(), 1).expect("member"),
            ],
        )
        .expect("policy");
        let account = AccountId::new_multisig(policy);
        let state = minimal_state_with_account(&account);
        let method = Method::GET;
        let uri: Uri = format!("/v1/accounts/{TEST_ACCOUNT_I105}/assets?limit=1")
            .parse()
            .expect("uri");
        let timestamp_ms = crate::utils::unix_now_ms();
        let nonce = "multisig-http-auth";
        let message = canonical_network_request_signature_message(
            state.network_id_ref(),
            &method,
            &uri,
            &[],
            timestamp_ms,
            nonce,
        )
        .expect("canonical test request is within V1 limits");
        let signature = checked_signature(signer_one.private_key(), &message);
        let account_literal = account.to_canonical_hex().expect("account header hex");
        let mut headers = HeaderMap::new();
        headers.insert(
            HEADER_ACCOUNT,
            axum::http::HeaderValue::from_str(&account_literal).unwrap(),
        );
        headers.insert(
            HEADER_SIGNATURE,
            axum::http::HeaderValue::from_str(&BASE64_STANDARD.encode(signature.payload()))
                .unwrap(),
        );
        headers.insert(
            HEADER_TIMESTAMP_MS,
            axum::http::HeaderValue::from_str(&timestamp_ms.to_string()).unwrap(),
        );
        headers.insert(HEADER_NONCE, axum::http::HeaderValue::from_static(nonce));
        let err = verify_canonical_request(
            &state,
            &headers,
            &method,
            &uri,
            &[],
            None,
            &standalone_auth_context(),
        )
        .expect_err("multisig app-auth must fail closed");
        match err {
            crate::Error::Query(ValidationFail::NotPermitted(msg)) => {
                assert!(msg.contains("X-Iroha-Witness"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
    fn multisig_witness(
        network_id: &NetworkId,
        account: &AccountId,
        method: &Method,
        uri: &Uri,
        body: &[u8],
        timestamp_ms: u64,
        nonce: &str,
        signers: &[&KeyPair],
    ) -> CanonicalRequestWitnessV1 {
        let mut witness = CanonicalRequestWitnessV1 {
            schema_version: CANONICAL_REQUEST_WITNESS_VERSION_V1,
            subject_account: account.clone(),
            timestamp_ms,
            nonce: nonce.to_owned(),
            canonical_request_hash: canonical_network_request_hash(network_id, method, uri, body)
                .expect("canonical test request is within V1 limits"),
            signatures: Vec::new(),
        };
        let message = canonical_request_witness_message(&witness).expect("witness payload");
        witness.signatures = signers
            .iter()
            .map(|signer| CanonicalRequestSignatureWitnessV1 {
                signer: signer.public_key().clone(),
                signature: checked_signature(signer.private_key(), &message),
            })
            .collect();
        witness
    }
    fn witness_headers(account: &AccountId, witness: &CanonicalRequestWitnessV1) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            HEADER_ACCOUNT,
            axum::http::HeaderValue::from_str(
                &account.to_canonical_hex().expect("account header hex"),
            )
            .expect("valid account header"),
        );
        headers.insert(
            HEADER_WITNESS,
            axum::http::HeaderValue::from_str(
                &witness_header_value(witness).expect("encode witness header"),
            )
            .expect("valid witness header"),
        );
        headers
    }

    fn unchecked_witness_header_fixture(witness: &CanonicalRequestWitnessV1) -> String {
        BASE64_STANDARD.encode(norito::to_bytes(witness).expect("encode raw witness fixture"))
    }

    #[test]
    fn bounded_witness_decode_accepts_exact_signature_count_and_rejects_plus_one() {
        let signature = checked_signature(
            ALICE_KEYPAIR.private_key(),
            b"bounded witness signature count fixture",
        );
        let entry = CanonicalRequestSignatureWitnessV1 {
            signer: ALICE_KEYPAIR.public_key().clone(),
            signature,
        };
        let mut witness = CanonicalRequestWitnessV1 {
            schema_version: CANONICAL_REQUEST_WITNESS_VERSION_V1,
            subject_account: ALICE_ID.clone(),
            timestamp_ms: 42,
            nonce: "bounded-witness-signature-count".to_owned(),
            canonical_request_hash: Hash::new(b"bounded witness signature count"),
            signatures: vec![entry.clone(); CANONICAL_REQUEST_WITNESS_MAX_SIGNATURES_V1],
        };
        let exact = witness_header_value(&witness).expect("encode exact-count witness");
        let decoded = decode_witness_value(&exact, "test witness")
            .expect("the exact V1 witness signature limit must decode");
        assert_eq!(
            decoded.signatures.len(),
            CANONICAL_REQUEST_WITNESS_MAX_SIGNATURES_V1
        );

        witness.signatures.push(entry);
        assert!(
            witness_header_value(&witness).is_err(),
            "the public witness encoder must reject a plus-one signature count"
        );
        let excessive = unchecked_witness_header_fixture(&witness);
        let error = decode_witness_value(&excessive, "test witness")
            .expect_err("one signature beyond the V1 limit must fail before vector allocation");
        assert!(matches!(
            error,
            crate::Error::Query(ValidationFail::NotPermitted(message))
                if message == "invalid test witness payload"
        ));
    }

    #[test]
    fn bounded_witness_decode_caps_nonce_before_owned_string_allocation() {
        let witness_with_nonce = |nonce: String| CanonicalRequestWitnessV1 {
            schema_version: CANONICAL_REQUEST_WITNESS_VERSION_V1,
            subject_account: ALICE_ID.clone(),
            timestamp_ms: 42,
            nonce,
            canonical_request_hash: Hash::new(b"bounded witness nonce"),
            signatures: Vec::new(),
        };

        let exact = witness_header_value(&witness_with_nonce("!".repeat(256)))
            .expect("encode exact nonce witness");
        let decoded = decode_witness_value(&exact, "test witness")
            .expect("the exact V1 witness nonce limit must decode");
        assert_eq!(decoded.nonce.len(), 256);

        for invalid in ["!".repeat(257), "not printable".to_owned()] {
            let witness = witness_with_nonce(invalid);
            assert!(
                witness_header_value(&witness).is_err(),
                "the public witness encoder must reject a non-canonical nonce"
            );
            let encoded = unchecked_witness_header_fixture(&witness);
            let error = decode_witness_value(&encoded, "test witness")
                .expect_err("invalid nonce must fail before owned String decode");
            assert!(matches!(
                error,
                crate::Error::Query(ValidationFail::NotPermitted(message))
                    if message == "invalid test witness payload"
            ));
        }
    }

    #[test]
    fn bounded_witness_decode_accepts_exact_signature_bytes_and_rejects_plus_one() {
        let witness_with_signature_bytes = |signature_bytes| CanonicalRequestWitnessV1 {
            schema_version: CANONICAL_REQUEST_WITNESS_VERSION_V1,
            subject_account: ALICE_ID.clone(),
            timestamp_ms: 42,
            nonce: "bounded-witness-signature-bytes".to_owned(),
            canonical_request_hash: Hash::new(b"bounded witness signature bytes"),
            signatures: vec![CanonicalRequestSignatureWitnessV1 {
                signer: ALICE_KEYPAIR.public_key().clone(),
                signature: Signature::from_bytes(&vec![0x5a; signature_bytes]),
            }],
        };

        let exact = witness_header_value(&witness_with_signature_bytes(
            CANONICAL_REQUEST_MAX_SIGNATURE_BYTES_V1,
        ))
        .expect("encode exact signature-byte witness");
        let decoded = decode_witness_value(&exact, "test witness")
            .expect("the exact V1 signature byte limit must decode");
        assert_eq!(
            decoded.signatures[0].signature.payload().len(),
            CANONICAL_REQUEST_MAX_SIGNATURE_BYTES_V1
        );

        let excessive_witness =
            witness_with_signature_bytes(CANONICAL_REQUEST_MAX_SIGNATURE_BYTES_V1 + 1);
        assert!(
            witness_header_value(&excessive_witness).is_err(),
            "the public witness encoder must reject a plus-one signature payload"
        );
        let excessive = unchecked_witness_header_fixture(&excessive_witness);
        let error = decode_witness_value(&excessive, "test witness")
            .expect_err("one signature byte beyond the V1 limit must fail before allocation");
        assert!(matches!(
            error,
            crate::Error::Query(ValidationFail::NotPermitted(message))
                if message == "invalid test witness payload"
        ));
    }
    #[test]
    fn verify_accepts_valid_multisig_witness() {
        let _guard = test_guard(CanonicalRequestAuthConfig::default());
        let signer_one = checked_app_auth_key_fixture();
        let signer_two = checked_app_auth_key_fixture();
        let policy = MultisigPolicy::new(
            2,
            vec![
                MultisigMember::new(signer_one.public_key().clone(), 1).expect("member"),
                MultisigMember::new(signer_two.public_key().clone(), 1).expect("member"),
            ],
        )
        .expect("policy");
        let account = AccountId::new_multisig(policy);
        let state = minimal_state_with_account(&account);
        let method = Method::POST;
        let uri: Uri = "/v1/soracloud/deploy?view=full".parse().expect("uri");
        let timestamp_ms = crate::utils::unix_now_ms();
        let nonce = "valid-multisig-witness";
        let witness = multisig_witness(
            state.network_id_ref(),
            &account,
            &method,
            &uri,
            b"{\"deploy\":true}",
            timestamp_ms,
            nonce,
            &[&signer_one, &signer_two],
        );
        let headers = witness_headers(&account, &witness);
        let verified = verify_canonical_request(
            &state,
            &headers,
            &method,
            &uri,
            b"{\"deploy\":true}",
            None,
            &standalone_auth_context(),
        )
        .expect("verify")
        .expect("witness auth must be present");
        assert_eq!(verified.account, account);
        assert_eq!(verified.signer, signer_one.public_key().clone());
        assert_eq!(
            verified.verified_signers,
            vec![
                signer_one.public_key().clone(),
                signer_two.public_key().clone()
            ]
        );
    }
    #[test]
    fn verify_accepts_sdk_signed_multisig_witness_and_rejects_conflicting_frame() {
        let _guard = test_guard(CanonicalRequestAuthConfig::default());
        let signer = checked_app_auth_key_fixture();
        let policy = MultisigPolicy::new(
            1,
            vec![MultisigMember::new(signer.public_key().clone(), 1).expect("member")],
        )
        .expect("policy");
        let account = AccountId::new_multisig(policy);
        let state = minimal_state_with_account(&account);
        let method = Method::POST;
        let uri: Uri = "/v1/soracloud/deploy?view=full".parse().expect("uri");
        let body = b"{\"deploy\":true}";
        let mut witness = CanonicalRequestWitnessV1 {
            schema_version: CANONICAL_REQUEST_WITNESS_VERSION_V1,
            subject_account: account.clone(),
            timestamp_ms: crate::utils::unix_now_ms(),
            nonce: "sdk-signed-witness".to_owned(),
            canonical_request_hash: canonical_network_request_hash(
                state.network_id_ref(),
                &method,
                &uri,
                body,
            )
            .expect("canonical request"),
            signatures: Vec::new(),
        };
        let sdk =
            iroha::client::canonical_request_witness_message(&witness).expect("SDK signing frame");
        assert_eq!(
            canonical_request_witness_message(&witness).expect("server frame"),
            sdk
        );
        let mut conflicting_frame = sdk.clone();
        // The historical Torii frame differs only in this Norito header field.
        let schema_offset = norito::core::MAGIC.len() + 2;
        let rejected_schema: [u8; 16] = hex::decode("5f285eb4475d17f4f8f7971788dae774")
            .expect("captured conflicting root")
            .try_into()
            .expect("16-byte root");
        conflicting_frame[schema_offset..schema_offset + rejected_schema.len()]
            .copy_from_slice(&rejected_schema);
        assert_eq!(
            norito::core::Header::read(&conflicting_frame[..])
                .expect("header")
                .schema,
            rejected_schema
        );
        witness.signatures.push(CanonicalRequestSignatureWitnessV1 {
            signer: signer.public_key().clone(),
            signature: checked_signature(signer.private_key(), &conflicting_frame),
        });
        let rejected_headers = witness_headers(&account, &witness);
        let rejected_error = verify_canonical_request(
            &state,
            &rejected_headers,
            &method,
            &uri,
            body,
            None,
            &standalone_auth_context(),
        )
        .expect_err("a signature over the conflicting root must fail");
        assert!(matches!(
            rejected_error,
            crate::Error::Query(ValidationFail::NotPermitted(message))
                if message == "query signature failed verification"
        ));
        witness.signatures[0].signature = checked_signature(signer.private_key(), &sdk);
        let mut headers = witness_headers(&account, &witness);
        headers.insert(
            HEADER_WITNESS,
            iroha::client::canonical_request_witness_header_value(&witness)
                .expect("SDK witness header")
                .parse()
                .expect("HTTP header"),
        );
        let verified = verify_canonical_request(
            &state,
            &headers,
            &method,
            &uri,
            body,
            None,
            &standalone_auth_context(),
        )
        .expect("SDK-produced witness must verify")
        .expect("witness auth is present");
        assert_eq!(verified.account, account);
        assert_eq!(verified.signer, signer.public_key().clone());
        assert_eq!(verified.verified_signers, vec![signer.public_key().clone()]);
        assert!(
            verify_canonical_request(
                &state,
                &headers,
                &method,
                &uri,
                body,
                None,
                &standalone_auth_context()
            )
            .is_err(),
            "successful SDK witness must retain replay protection"
        );
    }
    #[test]
    fn verify_rejects_malformed_multisig_witness_signature_r_before_backend() {
        let _guard = test_guard(CanonicalRequestAuthConfig::default());
        let signer_one = checked_app_auth_key_fixture();
        let policy = MultisigPolicy::new(
            1,
            vec![MultisigMember::new(signer_one.public_key().clone(), 1).expect("member")],
        )
        .expect("policy");
        let account = AccountId::new_multisig(policy);
        let state = minimal_state_with_account(&account);
        let method = Method::POST;
        let uri: Uri = "/v1/soracloud/deploy?view=full".parse().expect("uri");
        let timestamp_ms = crate::utils::unix_now_ms();
        let nonce = "invalid-r-multisig-witness";
        for (label, replacement_r, expected) in [
            (
                "small-order",
                ED25519_SMALL_ORDER_POINT,
                "Ed25519 signature failed admission",
            ),
            (
                "noncanonical",
                ED25519_NONCANONICAL_IDENTITY,
                "Ed25519 signature failed admission",
            ),
        ] {
            let mut witness = multisig_witness(
                state.network_id_ref(),
                &account,
                &method,
                &uri,
                b"{\"deploy\":true}",
                timestamp_ms,
                nonce,
                &[&signer_one],
            );
            let mut payload = witness.signatures[0].signature.payload().to_vec();
            payload[..ed25519_dalek::PUBLIC_KEY_LENGTH].copy_from_slice(&replacement_r);
            witness.signatures[0].signature = Signature::from_bytes(&payload);
            let headers = witness_headers(&account, &witness);
            let err = verify_canonical_request(
                &state,
                &headers,
                &method,
                &uri,
                b"{\"deploy\":true}",
                None,
                &standalone_auth_context(),
            )
            .expect_err("malformed witness signature R must fail before backend verify");
            match err {
                crate::Error::Query(ValidationFail::NotPermitted(msg)) => {
                    assert!(
                        msg.contains("X-Iroha-Witness signature payload") && msg.contains(expected),
                        "{label} witness signature failed with unexpected error: {msg}"
                    );
                }
                other => panic!("unexpected error: {other:?}"),
            }
        }
    }
    #[test]
    fn verify_rejects_duplicate_multisig_witness_signers() {
        let _guard = test_guard(CanonicalRequestAuthConfig::default());
        let signer_one = checked_app_auth_key_fixture();
        let signer_two = checked_app_auth_key_fixture();
        let policy = MultisigPolicy::new(
            2,
            vec![
                MultisigMember::new(signer_one.public_key().clone(), 1).expect("member"),
                MultisigMember::new(signer_two.public_key().clone(), 1).expect("member"),
            ],
        )
        .expect("policy");
        let account = AccountId::new_multisig(policy);
        let state = minimal_state_with_account(&account);
        let method = Method::POST;
        let uri: Uri = "/v1/soracloud/deploy".parse().expect("uri");
        let timestamp_ms = crate::utils::unix_now_ms();
        let witness = multisig_witness(
            state.network_id_ref(),
            &account,
            &method,
            &uri,
            b"{}",
            timestamp_ms,
            "duplicate-multisig-witness",
            &[&signer_one],
        );
        let mut duplicate = witness.clone();
        duplicate.signatures.push(duplicate.signatures[0].clone());
        let headers = witness_headers(&account, &duplicate);
        let err = verify_canonical_request(
            &state,
            &headers,
            &method,
            &uri,
            b"{}",
            None,
            &standalone_auth_context(),
        )
        .expect_err("duplicate witness signers must fail");
        match err {
            crate::Error::Query(ValidationFail::NotPermitted(msg)) => {
                assert!(msg.contains("duplicate signer"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
    #[test]
    fn verify_rejects_multisig_witness_below_threshold() {
        let _guard = test_guard(CanonicalRequestAuthConfig::default());
        let signer_one = checked_app_auth_key_fixture();
        let signer_two = checked_app_auth_key_fixture();
        let signer_three = checked_app_auth_key_fixture();
        let policy = MultisigPolicy::new(
            3,
            vec![
                MultisigMember::new(signer_one.public_key().clone(), 1).expect("member"),
                MultisigMember::new(signer_two.public_key().clone(), 1).expect("member"),
                MultisigMember::new(signer_three.public_key().clone(), 1).expect("member"),
            ],
        )
        .expect("policy");
        let account = AccountId::new_multisig(policy);
        let state = minimal_state_with_account(&account);
        let method = Method::POST;
        let uri: Uri = "/v1/soracloud/deploy".parse().expect("uri");
        let witness = multisig_witness(
            state.network_id_ref(),
            &account,
            &method,
            &uri,
            b"{}",
            crate::utils::unix_now_ms(),
            "threshold-multisig-witness",
            &[&signer_one, &signer_two],
        );
        let headers = witness_headers(&account, &witness);
        let err = verify_canonical_request(
            &state,
            &headers,
            &method,
            &uri,
            b"{}",
            None,
            &standalone_auth_context(),
        )
        .expect_err("threshold failure must reject witness");
        match err {
            crate::Error::Query(ValidationFail::NotPermitted(msg)) => {
                assert!(msg.contains("threshold"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
    #[test]
    fn verify_rejects_replayed_multisig_witness_nonce() {
        let _guard = test_guard(CanonicalRequestAuthConfig::default());
        let signer_one = checked_app_auth_key_fixture();
        let signer_two = checked_app_auth_key_fixture();
        let policy = MultisigPolicy::new(
            2,
            vec![
                MultisigMember::new(signer_one.public_key().clone(), 1).expect("member"),
                MultisigMember::new(signer_two.public_key().clone(), 1).expect("member"),
            ],
        )
        .expect("policy");
        let account = AccountId::new_multisig(policy);
        let state = minimal_state_with_account(&account);
        let method = Method::POST;
        let uri: Uri = "/v1/soracloud/deploy".parse().expect("uri");
        let witness = multisig_witness(
            state.network_id_ref(),
            &account,
            &method,
            &uri,
            b"{}",
            crate::utils::unix_now_ms(),
            "replayed-multisig-witness",
            &[&signer_one, &signer_two],
        );
        let headers = witness_headers(&account, &witness);
        verify_canonical_request(
            &state,
            &headers,
            &method,
            &uri,
            b"{}",
            None,
            &standalone_auth_context(),
        )
        .expect("first multisig witness must pass");
        let err = verify_canonical_request(
            &state,
            &headers,
            &method,
            &uri,
            b"{}",
            None,
            &standalone_auth_context(),
        )
        .expect_err("replayed multisig witness must fail");
        match err {
            crate::Error::Query(ValidationFail::NotPermitted(msg)) => {
                assert!(msg.contains("nonce already used"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
