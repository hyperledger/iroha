//! Signature-based operator authentication for Torii operator endpoints.
//!
//! This middleware is intended for internet-exposed deployments where operator endpoints are
//! reachable but must be authenticated. Requests must include the following headers:
//! - `x-iroha-operator-public-key`: operator public key (Iroha multihash string).
//! - `x-iroha-operator-timestamp-ms`: unix timestamp in milliseconds.
//! - `x-iroha-operator-nonce`: caller-chosen nonce (unique per request).
//! - `x-iroha-operator-signature`: base64 signature over the exact-network canonical request
//!   bytes plus `timestamp-ms` and `nonce`.
//! - `x-iroha-torii-proxy-target-peer-id`: receiver identity for internal Torii-proxy requests.
//!
//! Operator signature bytes use a route-specific domain, the exact genesis-derived
//! `NetworkId`, and then `crate::canonical_request_message`:
//! ```text
//! iroha.operator.http-request.network.v1\0 || <network_id[32]> ||
//! <UPPERCASE_METHOD>\n
//! <path>\n
//! <sorted_query_string>\n
//! <hex_sha256(body)>\n
//! <timestamp_ms>\n
//! <nonce>
//! ```
//!
//! Replay protection is enforced via a bounded in-memory nonce cache. Capacity
//! pressure rejects new requests and never evicts a live nonce.
use crate::{
    JsonBody, SharedAppState,
    app_auth::{CANONICAL_REQUEST_MAX_SIGNATURE_BYTES_V1, decode_bounded_canonical_base64_value},
    bounded_replay_cache::{InsertError as ReplayInsertError, ReplayCache},
    canonical_request_message, json_entry, json_object,
};
use axum::{
    body::Body,
    extract::{Request, State},
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{CACHE_CONTROL, WWW_AUTHENTICATE},
    },
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::Engine as _;
#[cfg(all(test, feature = "app_api"))]
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use iroha_config::parameters::actual::ToriiOperatorSignatures;
use iroha_crypto::{Algorithm, Hash, KeyPair, PublicKey, Signature};
use iroha_data_model::NetworkId;
use iroha_model_base::peer::PeerId;
use rand::{rand_core::TryCryptoRng, rngs::OsRng};
#[cfg(test)]
use std::num::NonZeroUsize;
use std::{collections::HashSet, fmt, time::Duration};
const HEADER_OPERATOR_PUBLIC_KEY: &str = "x-iroha-operator-public-key";
const HEADER_OPERATOR_TIMESTAMP_MS: &str = "x-iroha-operator-timestamp-ms";
const HEADER_OPERATOR_NONCE: &str = "x-iroha-operator-nonce";
const HEADER_OPERATOR_SIGNATURE: &str = "x-iroha-operator-signature";
const HEADER_TORII_PROXY_TARGET_PEER_ID: &str = "x-iroha-torii-proxy-target-peer-id";
const OPERATOR_SIGNATURE_DOMAIN_V1: &[u8] = b"iroha.operator.http-request.network.v1\0";
const TORII_PROXY_SIGNATURE_DOMAIN_V1: &[u8] = b"iroha.torii-proxy.http-request.network.v1\0";
const OPERATOR_REPLAY_KEY_DOMAIN_V1: &[u8] = b"iroha:torii:operator-replay:v1\0";
fn validate_operator_signature_for_public_key(
    signature: &Signature,
    public_key: &PublicKey,
) -> Result<(), OperatorSignatureError> {
    if !matches!(public_key.try_algorithm(), Ok(Algorithm::Ed25519)) {
        return Ok(());
    }
    validate_operator_ed25519_signature_payload(signature.payload())
}
fn validate_operator_ed25519_signature_payload(
    signature: &[u8],
) -> Result<(), OperatorSignatureError> {
    if signature.len() != ed25519_dalek::SIGNATURE_LENGTH {
        return Err(OperatorSignatureError::invalid_header(
            HEADER_OPERATOR_SIGNATURE,
        ));
    }
    let r_bytes: [u8; ed25519_dalek::PUBLIC_KEY_LENGTH] = signature
        .get(..ed25519_dalek::PUBLIC_KEY_LENGTH)
        .ok_or_else(|| OperatorSignatureError::invalid_header(HEADER_OPERATOR_SIGNATURE))?
        .try_into()
        .map_err(|_| OperatorSignatureError::invalid_header(HEADER_OPERATOR_SIGNATURE))?;
    if !operator_ed25519_compressed_y_is_canonical(&r_bytes) {
        return Err(OperatorSignatureError::invalid_header(
            HEADER_OPERATOR_SIGNATURE,
        ));
    }
    let r_point = ed25519_dalek::VerifyingKey::from_bytes(&r_bytes)
        .map_err(|_| OperatorSignatureError::invalid_header(HEADER_OPERATOR_SIGNATURE))?;
    if r_point.is_weak() {
        return Err(OperatorSignatureError::invalid_header(
            HEADER_OPERATOR_SIGNATURE,
        ));
    }
    Ok(())
}
fn parse_operator_signature_for_public_key(
    signature_bytes: &[u8],
    public_key: &PublicKey,
) -> Result<Signature, OperatorSignatureError> {
    let algorithm = public_key
        .try_algorithm()
        .map_err(|_| OperatorSignatureError::invalid_header(HEADER_OPERATOR_PUBLIC_KEY))?;
    if signature_bytes.len() != algorithm.signature_payload_len() {
        return Err(OperatorSignatureError::invalid_header(
            HEADER_OPERATOR_SIGNATURE,
        ));
    }
    match algorithm {
        Algorithm::Ed25519 => iroha_crypto::ed25519_parse_signature(signature_bytes)
            .map_err(|_| OperatorSignatureError::invalid_header(HEADER_OPERATOR_SIGNATURE)),
        Algorithm::MlDsa => iroha_crypto::mldsa65_parse_signature(signature_bytes)
            .map_err(|_| OperatorSignatureError::invalid_header(HEADER_OPERATOR_SIGNATURE)),
        _ => Signature::try_from_bytes_for_admission(signature_bytes)
            .map_err(|_| OperatorSignatureError::invalid_header(HEADER_OPERATOR_SIGNATURE)),
    }
}
fn operator_ed25519_compressed_y_is_canonical(
    bytes: &[u8; ed25519_dalek::PUBLIC_KEY_LENGTH],
) -> bool {
    const ED25519_FIELD_MODULUS_LE: [u8; ed25519_dalek::PUBLIC_KEY_LENGTH] = [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ];
    let mut y = *bytes;
    y[ed25519_dalek::PUBLIC_KEY_LENGTH - 1] &= 0x7f;
    for idx in (0..ed25519_dalek::PUBLIC_KEY_LENGTH).rev() {
        match y[idx].cmp(&ED25519_FIELD_MODULUS_LE[idx]) {
            std::cmp::Ordering::Less => return true,
            std::cmp::Ordering::Greater => return false,
            std::cmp::Ordering::Equal => {}
        }
    }
    false
}
/// Failure to construct or verify an exact-network operator request signature.
#[derive(Debug, Clone)]
pub struct OperatorSignatureError {
    status: StatusCode,
    code: &'static str,
    message: String,
}
impl OperatorSignatureError {
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }
    fn missing_header(name: &'static str) -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "operator_signature_missing",
            format!("missing required operator signature header `{name}`"),
        )
    }
    fn invalid_header(name: &'static str) -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "operator_signature_invalid",
            format!("invalid operator signature header `{name}`"),
        )
    }
    fn key_not_allowed() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            "operator_key_not_allowed",
            "operator public key is not allow-listed",
        )
    }
    fn skew_exceeded() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "operator_signature_skew",
            "operator request timestamp outside allowed skew window",
        )
    }
    fn replay() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "operator_signature_replay",
            "operator request nonce was already used",
        )
    }
    fn replay_cache_unavailable() -> Self {
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "operator_signature_replay_cache_unavailable",
            "operator request replay protection is at capacity",
        )
    }
    fn bad_signature() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "operator_signature_bad",
            "operator signature failed verification",
        )
    }
    fn payload_too_large() -> Self {
        Self::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "operator_signature_body_too_large",
            "operator request body exceeds configured maximum",
        )
    }
    fn body_read_timeout() -> Self {
        Self::new(
            StatusCode::REQUEST_TIMEOUT,
            "operator_signature_body_timeout",
            "operator request body was not received before the configured deadline",
        )
    }
    fn random_nonce(message: impl Into<String>) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "operator_signature_nonce_rng",
            format!("operator signature nonce RNG failed: {}", message.into()),
        )
    }
    fn signing(message: impl Into<String>) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "operator_signature_signing",
            format!("operator signature signing failed: {}", message.into()),
        )
    }
    fn canonical_request(error: crate::Error) -> Self {
        let (status, code) = match &error {
            crate::Error::Query(iroha_data_model::ValidationFail::NotPermitted(_)) => (
                StatusCode::BAD_REQUEST,
                "operator_signature_canonical_request_invalid",
            ),
            _ => (
                StatusCode::SERVICE_UNAVAILABLE,
                "operator_signature_canonical_request_unavailable",
            ),
        };
        Self::new(status, code, error.to_string())
    }
    fn canonical_allocation(bytes: usize) -> Self {
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "operator_signature_canonical_request_unavailable",
            format!("unable to allocate {bytes} canonical request bytes"),
        )
    }
    fn torii_proxy_target_mismatch() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            "torii_proxy_target_mismatch",
            "Torii proxy request target does not match the receiving peer",
        )
    }
    fn torii_proxy_receiver_unavailable() -> Self {
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "torii_proxy_receiver_unavailable",
            "Torii proxy receiver identity is unavailable",
        )
    }
}
impl fmt::Display for OperatorSignatureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}
impl std::error::Error for OperatorSignatureError {}
impl IntoResponse for OperatorSignatureError {
    fn into_response(self) -> Response {
        let payload = json_object(vec![
            json_entry("code", self.code),
            json_entry("message", self.message),
        ]);
        let mut resp = JsonBody(payload).into_response();
        *resp.status_mut() = self.status;
        if self.status == StatusCode::UNAUTHORIZED {
            resp.headers_mut().insert(
                WWW_AUTHENTICATE,
                HeaderValue::from_static("IrohaOperatorSignature realm=\"torii\""),
            );
        }
        resp
    }
}
/// Signature-based operator authentication state.
pub struct OperatorSignatures {
    network_id: NetworkId,
    enabled: bool,
    allow_node_key: bool,
    allowed_public_keys: HashSet<PublicKey>,
    node_public_key: PublicKey,
    max_clock_skew: Duration,
    operator_replay_cache: ReplayCache,
    identity_bound_replay_cache: ReplayCache,
    torii_proxy_replay_cache: ReplayCache,
    max_body_bytes: usize,
    body_read_timeout: Duration,
}
/// Invalid operator-signature freshness, replay, or body-read deadline configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OperatorSignatureConfigError;
impl fmt::Display for OperatorSignatureConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "operator signature body-read timeout must be non-zero and nonce TTL must exceed \
             twice the maximum clock skew",
        )
    }
}
impl std::error::Error for OperatorSignatureConfigError {}
/// Public key whose request signature was authenticated by an operator-format middleware.
///
/// Identity-bound routes receive this extension without receiving operator
/// admission; their handler must still bind the key to its governed role.
#[derive(Clone, Debug)]
pub struct AuthenticatedOperatorPublicKey(pub PublicKey);
/// Route-local operator authentication state with an exact body limit.
#[derive(Clone)]
pub struct BoundedOperatorAccessState {
    /// Shared Torii state used for operator authentication and replay protection.
    pub(crate) app: SharedAppState,
    /// Maximum body bytes authentication may buffer for this route.
    pub(crate) max_body_bytes: usize,
}
impl OperatorSignatures {
    /// Build operator-signature authentication with a replay-safe freshness window.
    ///
    /// # Errors
    ///
    /// Returns an error when the body-read timeout is zero or nonce retention
    /// does not cover the complete accepted timestamp-skew window.
    pub fn new(
        config: ToriiOperatorSignatures,
        node_public_key: PublicKey,
        network_id: NetworkId,
        max_body_bytes: u64,
        _telemetry: crate::routing::MaybeTelemetry,
    ) -> Result<Self, OperatorSignatureConfigError> {
        let replay_window = config
            .max_clock_skew
            .checked_mul(2)
            .ok_or(OperatorSignatureConfigError)?;
        if config.nonce_ttl <= replay_window {
            return Err(OperatorSignatureConfigError);
        }
        if config.body_read_timeout.is_zero() {
            return Err(OperatorSignatureConfigError);
        }
        let max_body_bytes = usize::try_from(max_body_bytes).unwrap_or(usize::MAX);
        let body_read_timeout = config.body_read_timeout;
        let nonce_ttl = config.nonce_ttl;
        let replay_cache_capacity = config.replay_cache_capacity;
        let allowed_public_keys = config.allowed_public_keys.into_iter().collect();
        Ok(Self {
            network_id,
            enabled: config.enabled,
            allow_node_key: config.allow_node_key,
            allowed_public_keys,
            node_public_key,
            max_clock_skew: config.max_clock_skew,
            operator_replay_cache: ReplayCache::new(nonce_ttl, replay_cache_capacity),
            identity_bound_replay_cache: ReplayCache::new(nonce_ttl, replay_cache_capacity),
            torii_proxy_replay_cache: ReplayCache::new(nonce_ttl, replay_cache_capacity),
            max_body_bytes,
            body_read_timeout,
        })
    }
    pub(crate) fn is_enabled(&self) -> bool {
        self.enabled
    }
    /// Return the canonical Ed25519 key payloads trusted by operator policy.
    ///
    /// PoR verdict authentication reuses this configured trust root rather than trusting keys
    /// embedded by the submitter. Non-Ed25519 operator keys are intentionally excluded because
    /// first-release PoR artefacts require Ed25519 signatures.
    pub(crate) fn trusted_ed25519_key_bytes(&self) -> Vec<Vec<u8>> {
        let mut keys = self
            .allowed_public_keys
            .iter()
            .chain(self.allow_node_key.then_some(&self.node_public_key))
            .filter_map(|key| {
                let (algorithm, bytes) = key.to_bytes();
                (algorithm == iroha_crypto::Algorithm::Ed25519).then(|| bytes.to_vec())
            })
            .collect::<Vec<_>>();
        keys.sort_unstable();
        keys.dedup();
        keys
    }
    fn is_key_allowed(&self, public_key: &PublicKey) -> bool {
        if self.allow_node_key && public_key == &self.node_public_key {
            return true;
        }
        self.allowed_public_keys.contains(public_key)
    }
    fn parse_required_header<'a>(
        headers: &'a HeaderMap,
        name: &'static str,
    ) -> Result<&'a str, OperatorSignatureError> {
        let mut values = headers.get_all(name).iter();
        let value = values
            .next()
            .ok_or_else(|| OperatorSignatureError::missing_header(name))?;
        if values.next().is_some() {
            return Err(OperatorSignatureError::invalid_header(name));
        }
        let value = value
            .to_str()
            .map_err(|_| OperatorSignatureError::invalid_header(name))?;
        if value.is_empty() || value.trim() != value {
            return Err(OperatorSignatureError::invalid_header(name));
        }
        Ok(value)
    }
    fn parse_canonical_timestamp(value: &str) -> Result<u64, OperatorSignatureError> {
        if !value.bytes().all(|byte| byte.is_ascii_digit())
            || (value.len() > 1 && value.starts_with('0'))
        {
            return Err(OperatorSignatureError::invalid_header(
                HEADER_OPERATOR_TIMESTAMP_MS,
            ));
        }
        value
            .parse::<u64>()
            .map_err(|_| OperatorSignatureError::invalid_header(HEADER_OPERATOR_TIMESTAMP_MS))
    }
    fn parse_public_key_literal(value: &str) -> Result<PublicKey, OperatorSignatureError> {
        PublicKey::from_canonical_str_for_decode(value)
            .map_err(|_| OperatorSignatureError::invalid_header(HEADER_OPERATOR_PUBLIC_KEY))
    }
    fn request_public_key(headers: &HeaderMap) -> Result<PublicKey, OperatorSignatureError> {
        Self::parse_public_key_literal(Self::parse_required_header(
            headers,
            HEADER_OPERATOR_PUBLIC_KEY,
        )?)
    }
    fn decode_signature_header(
        headers: &HeaderMap,
        public_key: &PublicKey,
    ) -> Result<Box<[u8]>, OperatorSignatureError> {
        let maximum_bytes = public_key
            .try_algorithm()
            .map_err(|_| OperatorSignatureError::invalid_header(HEADER_OPERATOR_PUBLIC_KEY))?
            .signature_payload_len()
            .min(CANONICAL_REQUEST_MAX_SIGNATURE_BYTES_V1);
        decode_bounded_canonical_base64_value(
            Self::parse_required_header(headers, HEADER_OPERATOR_SIGNATURE)?,
            maximum_bytes,
            "operator signature",
        )
        .map_err(|_| OperatorSignatureError::invalid_header(HEADER_OPERATOR_SIGNATURE))
    }
    fn validate_freshness(
        &self,
        timestamp_ms: u64,
        nonce: &str,
    ) -> Result<(), OperatorSignatureError> {
        let now_ms = crate::utils::unix_now_ms();
        let delta_ms = now_ms.abs_diff(timestamp_ms);
        let max_skew_ms: u64 = self
            .max_clock_skew
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX);
        if delta_ms > max_skew_ms {
            return Err(OperatorSignatureError::skew_exceeded());
        }
        if nonce.is_empty()
            || nonce.len() > 256
            || !nonce.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
        {
            return Err(OperatorSignatureError::invalid_header(
                HEADER_OPERATOR_NONCE,
            ));
        }
        Ok(())
    }
    fn admit_nonce(
        replay_cache: &ReplayCache,
        nonce: &str,
        public_key: &PublicKey,
    ) -> Result<(), OperatorSignatureError> {
        let (algorithm, payload) = public_key
            .try_to_bytes()
            .map_err(|_| OperatorSignatureError::invalid_header(HEADER_OPERATOR_PUBLIC_KEY))?;
        let algorithm = [algorithm as u8];
        let replay_key = Hash::new_from_chunks(&[
            OPERATOR_REPLAY_KEY_DOMAIN_V1,
            &algorithm,
            payload,
            b"\0",
            nonce.as_bytes(),
        ]);
        match replay_cache.check_and_insert_digest(replay_key) {
            Ok(()) => Ok(()),
            Err(ReplayInsertError::Replay) => Err(OperatorSignatureError::replay()),
            Err(ReplayInsertError::Capacity | ReplayInsertError::LifetimeOverflow) => {
                Err(OperatorSignatureError::replay_cache_unavailable())
            }
        }
    }
    fn operator_request_message(
        network_id: &NetworkId,
        method: &crate::Method,
        uri: &crate::Uri,
        body: &[u8],
        timestamp_ms: u64,
        nonce: &str,
    ) -> Result<Vec<u8>, OperatorSignatureError> {
        let canonical_request = canonical_request_message(method, uri, body)
            .map_err(OperatorSignatureError::canonical_request)?;
        let capacity = OPERATOR_SIGNATURE_DOMAIN_V1
            .len()
            .checked_add(network_id.as_bytes().len())
            .and_then(|bytes| bytes.checked_add(canonical_request.len()))
            .and_then(|bytes| bytes.checked_add(nonce.len()))
            .and_then(|bytes| bytes.checked_add(32))
            .ok_or_else(|| OperatorSignatureError::canonical_allocation(usize::MAX))?;
        let mut msg = Vec::new();
        msg.try_reserve_exact(capacity)
            .map_err(|_| OperatorSignatureError::canonical_allocation(capacity))?;
        msg.extend_from_slice(OPERATOR_SIGNATURE_DOMAIN_V1);
        msg.extend_from_slice(network_id.as_bytes());
        msg.extend_from_slice(&canonical_request);
        msg.extend_from_slice(b"\n");
        msg.extend_from_slice(timestamp_ms.to_string().as_bytes());
        msg.extend_from_slice(b"\n");
        msg.extend_from_slice(nonce.as_bytes());
        Ok(msg)
    }
    fn authorize_bytes_with_policy(
        &self,
        headers: &HeaderMap,
        method: &crate::Method,
        uri: &crate::Uri,
        body: &[u8],
        require_allowlisted_key: bool,
    ) -> Result<(), OperatorSignatureError> {
        let public_key_literal = Self::parse_required_header(headers, HEADER_OPERATOR_PUBLIC_KEY)?;
        let public_key = Self::parse_public_key_literal(public_key_literal)?;
        if require_allowlisted_key && !self.is_key_allowed(&public_key) {
            return Err(OperatorSignatureError::key_not_allowed());
        }
        let timestamp_str = Self::parse_required_header(headers, HEADER_OPERATOR_TIMESTAMP_MS)?;
        let timestamp_ms = Self::parse_canonical_timestamp(timestamp_str)?;
        let nonce = Self::parse_required_header(headers, HEADER_OPERATOR_NONCE)?;
        let signature_bytes = Self::decode_signature_header(headers, &public_key)?;
        let signature = parse_operator_signature_for_public_key(&signature_bytes, &public_key)?;
        validate_operator_signature_for_public_key(&signature, &public_key)?;
        self.validate_freshness(timestamp_ms, nonce)?;
        let msg = Self::operator_request_message(
            &self.network_id,
            method,
            uri,
            body,
            timestamp_ms,
            nonce,
        )?;
        signature
            .verify(&public_key, &msg)
            .map_err(|_| OperatorSignatureError::bad_signature())?;
        // Admit the nonce only after authenticating the request. `check_and_insert` is atomic for
        // a replay key, so concurrently verified requests using the same nonce still have exactly
        // one winner without letting unauthenticated traffic consume or evict cache entries.
        let replay_cache = if require_allowlisted_key {
            &self.operator_replay_cache
        } else {
            &self.identity_bound_replay_cache
        };
        Self::admit_nonce(replay_cache, nonce, &public_key)?;
        Ok(())
    }
    fn authorize_bytes(
        &self,
        headers: &HeaderMap,
        method: &crate::Method,
        uri: &crate::Uri,
        body: &[u8],
    ) -> Result<(), OperatorSignatureError> {
        self.authorize_bytes_with_policy(headers, method, uri, body, true)
    }
    fn authorize_request(
        &self,
        req: &axum::http::Request<Body>,
        body_bytes: &[u8],
    ) -> Result<(), OperatorSignatureError> {
        if body_bytes.len() > self.max_body_bytes {
            return Err(OperatorSignatureError::payload_too_large());
        }
        self.authorize_bytes(req.headers(), req.method(), req.uri(), body_bytes)
    }
    fn authorize_request_for_bound_key(
        &self,
        req: &axum::http::Request<Body>,
        body_bytes: &[u8],
    ) -> Result<(), OperatorSignatureError> {
        if body_bytes.len() > self.max_body_bytes {
            return Err(OperatorSignatureError::payload_too_large());
        }
        self.authorize_bytes_with_policy(req.headers(), req.method(), req.uri(), body_bytes, false)
    }
    fn torii_proxy_target_peer_id(headers: &HeaderMap) -> Result<PeerId, OperatorSignatureError> {
        PublicKey::from_canonical_str_for_decode(Self::parse_required_header(
            headers,
            HEADER_TORII_PROXY_TARGET_PEER_ID,
        )?)
        .map(PeerId::new)
        .map_err(|_| OperatorSignatureError::invalid_header(HEADER_TORII_PROXY_TARGET_PEER_ID))
    }
    fn torii_proxy_request_message(
        network_id: &NetworkId,
        method: &crate::Method,
        uri: &crate::Uri,
        body: &[u8],
        timestamp_ms: u64,
        nonce: &str,
        target_peer_id: &PeerId,
    ) -> Result<Vec<u8>, OperatorSignatureError> {
        let canonical_request = canonical_request_message(method, uri, body)
            .map_err(OperatorSignatureError::canonical_request)?;
        let target_peer_id = target_peer_id
            .public_key()
            .try_to_multihash_string()
            .map_err(|_| OperatorSignatureError::canonical_allocation(usize::MAX))?;
        let capacity = TORII_PROXY_SIGNATURE_DOMAIN_V1
            .len()
            .checked_add(network_id.as_bytes().len())
            .and_then(|bytes| bytes.checked_add(target_peer_id.len()))
            .and_then(|bytes| bytes.checked_add(canonical_request.len()))
            .and_then(|bytes| bytes.checked_add(nonce.len()))
            .and_then(|bytes| bytes.checked_add(32))
            .ok_or_else(|| OperatorSignatureError::canonical_allocation(usize::MAX))?;
        let mut message = Vec::new();
        message
            .try_reserve_exact(capacity)
            .map_err(|_| OperatorSignatureError::canonical_allocation(capacity))?;
        message.extend_from_slice(TORII_PROXY_SIGNATURE_DOMAIN_V1);
        message.extend_from_slice(network_id.as_bytes());
        // `NetworkId` is fixed-width, so the following canonical peer-id bytes
        // cannot be re-framed across network boundaries.
        message.extend_from_slice(target_peer_id.as_bytes());
        message.push(b'\n');
        message.extend_from_slice(&canonical_request);
        message.push(b'\n');
        message.extend_from_slice(timestamp_ms.to_string().as_bytes());
        message.push(b'\n');
        message.extend_from_slice(nonce.as_bytes());
        Ok(message)
    }
    fn authorize_torii_proxy_bytes(
        &self,
        headers: &HeaderMap,
        method: &crate::Method,
        uri: &crate::Uri,
        body: &[u8],
        receiver_peer_id: &PeerId,
    ) -> Result<(), OperatorSignatureError> {
        let public_key_literal = Self::parse_required_header(headers, HEADER_OPERATOR_PUBLIC_KEY)?;
        let public_key = Self::parse_public_key_literal(public_key_literal)?;
        let target_peer_id = Self::torii_proxy_target_peer_id(headers)?;
        if &target_peer_id != receiver_peer_id {
            return Err(OperatorSignatureError::torii_proxy_target_mismatch());
        }
        let timestamp_str = Self::parse_required_header(headers, HEADER_OPERATOR_TIMESTAMP_MS)?;
        let timestamp_ms = Self::parse_canonical_timestamp(timestamp_str)?;
        let nonce = Self::parse_required_header(headers, HEADER_OPERATOR_NONCE)?;
        let signature_bytes = Self::decode_signature_header(headers, &public_key)?;
        let signature = parse_operator_signature_for_public_key(&signature_bytes, &public_key)?;
        validate_operator_signature_for_public_key(&signature, &public_key)?;
        self.validate_freshness(timestamp_ms, nonce)?;
        let message = Self::torii_proxy_request_message(
            &self.network_id,
            method,
            uri,
            body,
            timestamp_ms,
            nonce,
            &target_peer_id,
        )?;
        signature
            .verify(&public_key, &message)
            .map_err(|_| OperatorSignatureError::bad_signature())?;
        Self::admit_nonce(&self.torii_proxy_replay_cache, nonce, &public_key)?;
        Ok(())
    }
    fn authorize_torii_proxy_request(
        &self,
        req: &axum::http::Request<Body>,
        body_bytes: &[u8],
        receiver_peer_id: &PeerId,
        max_body_bytes: usize,
    ) -> Result<(), OperatorSignatureError> {
        if body_bytes.len() > max_body_bytes {
            return Err(OperatorSignatureError::payload_too_large());
        }
        self.authorize_torii_proxy_bytes(
            req.headers(),
            req.method(),
            req.uri(),
            body_bytes,
            receiver_peer_id,
        )
    }
}
async fn collect_operator_signature_body(
    body: Body,
    max_body_bytes: usize,
    body_read_timeout: Duration,
) -> Result<axum::body::Bytes, OperatorSignatureError> {
    match tokio::time::timeout(
        body_read_timeout,
        axum::body::to_bytes(body, max_body_bytes),
    )
    .await
    {
        Ok(Ok(bytes)) => Ok(bytes),
        Ok(Err(_)) => Err(OperatorSignatureError::payload_too_large()),
        Err(_) => Err(OperatorSignatureError::body_read_timeout()),
    }
}
/// Build operator signature headers for an internal Torii request.
///
/// # Errors
///
/// Returns an error if nonce generation, request-message construction, signing,
/// or encoding the signature headers fails.
pub fn signed_request_headers(
    key_pair: &KeyPair,
    network_id: &NetworkId,
    method: &crate::Method,
    uri: &crate::Uri,
    body: &[u8],
) -> Result<HeaderMap, OperatorSignatureError> {
    signed_request_headers_with_rng(key_pair, network_id, method, uri, body, &mut OsRng)
}
fn signed_request_headers_with_rng<R: TryCryptoRng>(
    key_pair: &KeyPair,
    network_id: &NetworkId,
    method: &crate::Method,
    uri: &crate::Uri,
    body: &[u8],
    rng: &mut R,
) -> Result<HeaderMap, OperatorSignatureError> {
    let timestamp_ms = crate::utils::unix_now_ms();
    let nonce = operator_signature_nonce_with_rng(rng)?;
    let msg = OperatorSignatures::operator_request_message(
        network_id,
        method,
        uri,
        body,
        timestamp_ms,
        &nonce,
    )?;
    let signature = Signature::try_new(key_pair.private_key(), &msg)
        .map_err(|error| OperatorSignatureError::signing(error.to_string()))?;
    operator_signature_headers(key_pair, timestamp_ms, &nonce, &signature)
}
/// Build route-specific signature headers for an internal Torii-proxy request.
///
/// The signature has its own protocol domain and binds the intended receiver peer. The sender key
/// is deliberately not checked against the privileged operator allow-list: the proxy handler
/// remains responsible for binding this authenticated peer identity to the request's authoritative
/// route.
///
/// # Errors
///
/// Returns an error if nonce generation, route-bound message construction, signing,
/// or encoding the signature headers fails.
pub fn signed_torii_proxy_request_headers(
    sender_key_pair: &KeyPair,
    network_id: &NetworkId,
    target_peer_id: &PeerId,
    method: &crate::Method,
    uri: &crate::Uri,
    body: &[u8],
) -> Result<HeaderMap, OperatorSignatureError> {
    signed_torii_proxy_request_headers_with_rng(
        sender_key_pair,
        network_id,
        target_peer_id,
        method,
        uri,
        body,
        &mut OsRng,
    )
}
fn signed_torii_proxy_request_headers_with_rng<R: TryCryptoRng>(
    sender_key_pair: &KeyPair,
    network_id: &NetworkId,
    target_peer_id: &PeerId,
    method: &crate::Method,
    uri: &crate::Uri,
    body: &[u8],
    rng: &mut R,
) -> Result<HeaderMap, OperatorSignatureError> {
    let timestamp_ms = crate::utils::unix_now_ms();
    let nonce = operator_signature_nonce_with_rng(rng)?;
    let message = OperatorSignatures::torii_proxy_request_message(
        network_id,
        method,
        uri,
        body,
        timestamp_ms,
        &nonce,
        target_peer_id,
    )?;
    let signature = Signature::try_new(sender_key_pair.private_key(), &message)
        .map_err(|error| OperatorSignatureError::signing(error.to_string()))?;
    let mut headers =
        operator_signature_headers(sender_key_pair, timestamp_ms, &nonce, &signature)?;
    let target_peer_id = target_peer_id
        .public_key()
        .try_to_multihash_string()
        .map_err(|_| OperatorSignatureError::canonical_allocation(usize::MAX))?;
    headers.insert(
        HEADER_TORII_PROXY_TARGET_PEER_ID,
        HeaderValue::from_str(&target_peer_id).map_err(|_| {
            OperatorSignatureError::invalid_header(HEADER_TORII_PROXY_TARGET_PEER_ID)
        })?,
    );
    Ok(headers)
}
fn operator_signature_nonce_with_rng<R: TryCryptoRng>(
    rng: &mut R,
) -> Result<String, OperatorSignatureError> {
    let mut nonce_bytes = [0u8; 12];
    rng.try_fill_bytes(&mut nonce_bytes)
        .map_err(|error| OperatorSignatureError::random_nonce(error.to_string()))?;
    const ENCODED_LEN: usize = 16;
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(ENCODED_LEN)
        .map_err(|_| OperatorSignatureError::canonical_allocation(ENCODED_LEN))?;
    encoded.resize(ENCODED_LEN, 0);
    let written = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode_slice(nonce_bytes, &mut encoded)
        .map_err(|_| OperatorSignatureError::signing("nonce base64 length mismatch"))?;
    if written != ENCODED_LEN {
        return Err(OperatorSignatureError::signing(
            "nonce base64 length mismatch",
        ));
    }
    String::from_utf8(encoded)
        .map_err(|_| OperatorSignatureError::signing("nonce base64 is not UTF-8"))
}
fn operator_signature_headers(
    key_pair: &KeyPair,
    timestamp_ms: u64,
    nonce: &str,
    signature: &Signature,
) -> Result<HeaderMap, OperatorSignatureError> {
    let mut headers = HeaderMap::new();
    let public_key = key_pair
        .public_key()
        .try_to_multihash_string()
        .map_err(|error| OperatorSignatureError::signing(error.to_string()))?;
    headers.insert(
        HEADER_OPERATOR_PUBLIC_KEY,
        HeaderValue::from_str(&public_key)
            .map_err(|_| OperatorSignatureError::invalid_header(HEADER_OPERATOR_PUBLIC_KEY))?,
    );
    headers.insert(
        HEADER_OPERATOR_TIMESTAMP_MS,
        HeaderValue::from(timestamp_ms),
    );
    headers.insert(
        HEADER_OPERATOR_NONCE,
        HeaderValue::from_str(nonce)
            .map_err(|_| OperatorSignatureError::invalid_header(HEADER_OPERATOR_NONCE))?,
    );
    headers.insert(
        HEADER_OPERATOR_SIGNATURE,
        HeaderValue::from_str(
            &crate::signature_header_value(signature)
                .map_err(|error| OperatorSignatureError::signing(error.to_string()))?,
        )
        .map_err(|_| OperatorSignatureError::invalid_header(HEADER_OPERATOR_SIGNATURE))?,
    );
    Ok(headers)
}
pub async fn enforce_operator_access(
    State(app): State<SharedAppState>,
    req: Request,
    next: Next,
) -> Response {
    let max_body_bytes = app.operator_signatures.max_body_bytes;
    private_operator_response(enforce_operator_access_inner(app, req, next, max_body_bytes).await)
}
/// Enforce operator authentication while buffering no more than the route-specific body limit.
pub async fn enforce_bounded_operator_access(
    State(state): State<BoundedOperatorAccessState>,
    req: Request,
    next: Next,
) -> Response {
    let max_body_bytes = state
        .max_body_bytes
        .min(state.app.operator_signatures.max_body_bytes);
    private_operator_response(
        enforce_operator_access_inner(state.app, req, next, max_body_bytes).await,
    )
}
fn private_operator_response(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("private, no-store"));
    response
}
async fn enforce_operator_access_inner(
    app: SharedAppState,
    req: Request,
    next: Next,
    max_body_bytes: usize,
) -> Response {
    if !app.operator_signatures.is_enabled() {
        return OperatorSignatureError::new(
            StatusCode::FORBIDDEN,
            "operator_access_disabled",
            "operator signature authentication is disabled",
        )
        .into_response();
    }
    // WebAuthn/mTLS can strengthen operator authentication, but a replayable
    // session or bootstrap token must never replace the exact request signature
    // promised by `AuthenticationPolicy::OperatorSignature`.
    if app.operator_auth.is_enabled() {
        let remote_ip = req
            .extensions()
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
            .map(|connect_info| connect_info.0.ip());
        if let Err(err) = app
            .operator_auth
            .authorize_operator_endpoint(req.headers(), remote_ip)
            .await
        {
            return err.into_response();
        }
    }
    let (parts, body) = req.into_parts();
    let body_bytes = match collect_operator_signature_body(
        body,
        max_body_bytes,
        app.operator_signatures.body_read_timeout,
    )
    .await
    {
        Ok(bytes) => bytes,
        Err(error) => return error.into_response(),
    };
    let mut req = axum::http::Request::from_parts(parts, Body::from(body_bytes.clone()));
    if let Err(err) = app.operator_signatures.authorize_request(&req, &body_bytes) {
        return err.into_response();
    }
    let authenticated_public_key = match OperatorSignatures::request_public_key(req.headers()) {
        Ok(public_key) => public_key,
        Err(error) => return error.into_response(),
    };
    req.extensions_mut()
        .insert(AuthenticatedOperatorPublicKey(authenticated_public_key));
    next.run(req).await
}
/// Verify a canonical signed request without applying the operator allow-list.
///
/// Route handlers using this middleware must bind the authenticated header key to an
/// authoritative identity before mutating state. This is used for SoraFS provider submissions,
/// whose admitted advert key is dynamic and therefore cannot be copied into the static operator
/// allow-list. Freshness, signature verification, body binding, and replay protection are still
/// enforced here before the request reaches the handler.
pub async fn enforce_identity_bound_signature(
    State(app): State<SharedAppState>,
    req: Request,
    next: Next,
) -> Response {
    let (parts, body) = req.into_parts();
    let body_bytes = match collect_operator_signature_body(
        body,
        app.operator_signatures.max_body_bytes,
        app.operator_signatures.body_read_timeout,
    )
    .await
    {
        Ok(bytes) => bytes,
        Err(error) => return error.into_response(),
    };
    let mut req = axum::http::Request::from_parts(parts, Body::from(body_bytes.clone()));
    if let Err(error) = app
        .operator_signatures
        .authorize_request_for_bound_key(&req, &body_bytes)
    {
        return error.into_response();
    }
    let authenticated_public_key = match OperatorSignatures::request_public_key(req.headers()) {
        Ok(public_key) => public_key,
        Err(error) => return error.into_response(),
    };
    req.extensions_mut()
        .insert(AuthenticatedOperatorPublicKey(authenticated_public_key));
    next.run(req).await
}
fn torii_proxy_receiver_peer_id(app: &SharedAppState) -> Option<PeerId> {
    #[cfg(any(feature = "app_api", feature = "connect"))]
    {
        app.local_peer_id.clone()
    }
    #[cfg(not(any(feature = "app_api", feature = "connect")))]
    {
        let _ = app;
        None
    }
}
/// Verify the route-specific internal Torii-proxy signature.
///
/// This guard accepts any cryptographically valid peer key, binds the request to this receiver,
/// and uses a replay cache isolated from both privileged operator and generic identity-bound
/// traffic. The handler must still authorize the authenticated peer for the routed request.
pub async fn enforce_torii_proxy_peer_signature(
    State(app): State<SharedAppState>,
    req: Request,
    next: Next,
) -> Response {
    let Some(receiver_peer_id) = torii_proxy_receiver_peer_id(&app) else {
        return OperatorSignatureError::torii_proxy_receiver_unavailable().into_response();
    };
    // The peer signature itself needs the complete raw body. Hold the peer
    // receiver working-set permit through handler completion. Local quorum
    // collectors and public signed-query ingress have separate reservations.
    let proxy_memory_permit = match crate::try_acquire_torii_proxy_receiver_memory(&app) {
        Ok(permit) => permit,
        Err(response) => return response,
    };
    let ingress_envelope = app.torii_proxy_http_ingress_envelope;
    let decode_limits = match ingress_envelope.decode_limits() {
        Ok(limits) => limits,
        Err(response) => return response,
    };
    let (parts, body) = req.into_parts();
    // This route wraps a configured-size inner request, so its canonical
    // signed envelope has a separate protocol-bounded framing allowance.
    let max_body_bytes = ingress_envelope.body_bytes;
    let body_bytes = match collect_operator_signature_body(
        body,
        max_body_bytes,
        app.operator_signatures.body_read_timeout,
    )
    .await
    {
        Ok(bytes) => bytes,
        Err(error) => return error.into_response(),
    };
    let mut req = axum::http::Request::from_parts(parts, Body::from(body_bytes.clone()));
    if let Err(error) = app.operator_signatures.authorize_torii_proxy_request(
        &req,
        &body_bytes,
        &receiver_peer_id,
        max_body_bytes,
    ) {
        return error.into_response();
    }
    let authenticated_public_key = match OperatorSignatures::request_public_key(req.headers()) {
        Ok(public_key) => public_key,
        Err(error) => return error.into_response(),
    };
    req.extensions_mut()
        .insert(AuthenticatedOperatorPublicKey(authenticated_public_key));
    req.extensions_mut().insert(proxy_memory_permit.clone());
    req.extensions_mut()
        .insert(crate::utils::extractors::NoritoIngressLimits {
            max_body_bytes,
            decode_limits,
        });
    // `Body` owns the sole shared Bytes allocation from here; do not keep an
    // additional signature-verification handle live across handler execution.
    drop(body_bytes);
    let response = next.run(req).await;
    let (parts, body) = response.into_parts();
    // A slow authenticated peer can retain the returned body after handler
    // completion. Capture the permit in the body itself so the next bridge
    // request is not admitted until this response is drained or dropped.
    use http_body_util::BodyExt as _;
    let guarded_body = body.map_frame(move |frame| {
        let _permit = &proxy_memory_permit;
        frame
    });
    Response::from_parts(parts, Body::new(guarded_body))
}
#[cfg(all(test, feature = "app_api"))]
mod tests {
    use super::*;
    use axum::routing::{get, post};
    use iroha_config::parameters::actual::{
        OperatorWebAuthnAlgorithm, OperatorWebAuthnConfig, ToriiOperatorAuth,
    };
    use iroha_crypto::{Algorithm, KeyPair};
    use rand::rand_core::{TryCryptoRng, TryRngCore};
    use std::{
        sync::{Arc, Barrier},
        thread,
    };
    use tower::ServiceExt as _;
    use url::Url;
    struct FailingOperatorNonceRng;
    #[derive(Debug)]
    struct FailingOperatorNonceRngError;
    impl fmt::Display for FailingOperatorNonceRngError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("failing operator nonce RNG")
        }
    }
    impl TryRngCore for FailingOperatorNonceRng {
        type Error = FailingOperatorNonceRngError;
        fn try_next_u32(&mut self) -> std::result::Result<u32, Self::Error> {
            Err(FailingOperatorNonceRngError)
        }
        fn try_next_u64(&mut self) -> std::result::Result<u64, Self::Error> {
            Err(FailingOperatorNonceRngError)
        }
        fn try_fill_bytes(&mut self, _dst: &mut [u8]) -> std::result::Result<(), Self::Error> {
            Err(FailingOperatorNonceRngError)
        }
    }
    impl TryCryptoRng for FailingOperatorNonceRng {}
    fn checked_ed25519_keypair() -> KeyPair {
        KeyPair::try_random_with_algorithm(Algorithm::Ed25519)
            .expect("generate checked operator signature fixture keypair")
    }
    fn checked_mldsa_keypair() -> KeyPair {
        KeyPair::try_from_seed(b"torii-operator-signature-mldsa".to_vec(), Algorithm::MlDsa)
            .expect("generate checked ML-DSA operator signature fixture keypair")
    }
    fn test_network_id() -> NetworkId {
        crate::signed_query_test_network_id()
    }
    fn foreign_network_id() -> NetworkId {
        NetworkId::from_genesis_hash(
            iroha_crypto::HashOf::<iroha_data_model::block::BlockHeader>::from_untyped_unchecked(
                iroha_crypto::Hash::prehashed([0xFE; 32]),
            ),
        )
    }
    fn bootstrap_token_operator_auth(
        token: &str,
        data_dir: &std::path::Path,
    ) -> crate::operator_auth::OperatorAuth {
        let config = ToriiOperatorAuth {
            enabled: true,
            tokens: vec![token.to_owned()],
            rate_per_minute: None,
            burst: None,
            webauthn: Some(OperatorWebAuthnConfig {
                rp_id: "example.com".to_owned(),
                rp_name: "Iroha Operator".to_owned(),
                origins: vec![Url::parse("https://example.com").expect("operator origin")],
                user_id: b"operator".to_vec(),
                user_name: "operator".to_owned(),
                user_display_name: "Operator".to_owned(),
                challenge_ttl: Duration::from_secs(120),
                session_ttl: Duration::from_secs(600),
                require_user_verification: true,
                allowed_algorithms: vec![OperatorWebAuthnAlgorithm::Es256],
            }),
            ..Default::default()
        };
        crate::operator_auth::OperatorAuth::new(
            config,
            data_dir.to_path_buf(),
            crate::routing::MaybeTelemetry::disabled(),
        )
        .expect("valid bootstrap operator-auth fixture")
    }
    fn operator_signatures_with_capacity(
        key_pair: &KeyPair,
        capacity: usize,
    ) -> OperatorSignatures {
        let cfg = ToriiOperatorSignatures {
            enabled: true,
            allow_node_key: true,
            body_read_timeout: Duration::from_secs(10),
            allowed_public_keys: Vec::new(),
            max_clock_skew: Duration::from_secs(60),
            nonce_ttl: Duration::from_secs(300),
            replay_cache_capacity: NonZeroUsize::new(capacity).expect("non-zero test capacity"),
        };
        OperatorSignatures::new(
            cfg,
            key_pair.public_key().clone(),
            test_network_id(),
            1024,
            crate::routing::MaybeTelemetry::disabled(),
        )
        .expect("valid operator-signature test config")
    }
    #[test]
    fn unauthorized_operator_errors_advertise_the_signature_scheme() {
        let response =
            OperatorSignatureError::missing_header(HEADER_OPERATOR_SIGNATURE).into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get(WWW_AUTHENTICATE),
            Some(&HeaderValue::from_static(
                "IrohaOperatorSignature realm=\"torii\""
            ))
        );
    }
    #[test]
    fn operator_signature_headers_require_exact_singleton_text() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HEADER_OPERATOR_NONCE,
            HeaderValue::from_static("canonical-nonce"),
        );
        assert_eq!(
            OperatorSignatures::parse_required_header(&headers, HEADER_OPERATOR_NONCE)
                .expect("one exact header"),
            "canonical-nonce"
        );
        headers.append(
            HEADER_OPERATOR_NONCE,
            HeaderValue::from_static("second-nonce"),
        );
        assert_eq!(
            OperatorSignatures::parse_required_header(&headers, HEADER_OPERATOR_NONCE)
                .expect_err("duplicate singleton header must fail")
                .code,
            "operator_signature_invalid"
        );

        let mut padded = HeaderMap::new();
        padded.insert(
            HEADER_OPERATOR_NONCE,
            HeaderValue::from_static(" padded-nonce "),
        );
        assert_eq!(
            OperatorSignatures::parse_required_header(&padded, HEADER_OPERATOR_NONCE)
                .expect_err("surrounding whitespace is non-canonical")
                .code,
            "operator_signature_invalid"
        );
    }
    #[test]
    fn operator_timestamp_text_is_canonical_unsigned_decimal() {
        assert_eq!(
            OperatorSignatures::parse_canonical_timestamp("0").expect("canonical zero"),
            0
        );
        assert_eq!(
            OperatorSignatures::parse_canonical_timestamp(&u64::MAX.to_string())
                .expect("canonical u64 maximum"),
            u64::MAX
        );
        for invalid in ["", "+1", "01", " 1", "1 ", "-1"] {
            assert!(
                OperatorSignatures::parse_canonical_timestamp(invalid).is_err(),
                "timestamp {invalid:?} must fail closed"
            );
        }
    }
    #[test]
    fn operator_signature_base64_is_bounded_by_the_selected_algorithm() {
        let key_pair = checked_ed25519_keypair();
        let mut headers = HeaderMap::new();
        let exact = BASE64_STANDARD.encode([0x11_u8; 64]);
        headers.insert(
            HEADER_OPERATOR_SIGNATURE,
            HeaderValue::from_str(&exact).expect("exact signature header"),
        );
        let decoded = OperatorSignatures::decode_signature_header(&headers, key_pair.public_key())
            .expect("exact Ed25519 signature byte limit");
        assert_eq!(decoded.as_ref(), &[0x11_u8; 64]);

        let excessive = BASE64_STANDARD.encode([0x11_u8; 65]);
        headers.insert(
            HEADER_OPERATOR_SIGNATURE,
            HeaderValue::from_str(&excessive).expect("plus-one signature header"),
        );
        assert!(
            OperatorSignatures::decode_signature_header(&headers, key_pair.public_key()).is_err()
        );
    }
    #[test]
    fn operator_signatures_reject_short_nonce_retention() {
        let key_pair = checked_ed25519_keypair();
        let config = ToriiOperatorSignatures {
            max_clock_skew: Duration::from_secs(60),
            nonce_ttl: Duration::from_secs(120),
            ..Default::default()
        };
        let error = match OperatorSignatures::new(
            config,
            key_pair.public_key().clone(),
            test_network_id(),
            1024,
            crate::routing::MaybeTelemetry::disabled(),
        ) {
            Ok(_) => panic!("nonce retention must cover the full skew window"),
            Err(error) => error,
        };
        assert_eq!(error, OperatorSignatureConfigError);
    }
    #[test]
    fn operator_signatures_reject_zero_body_read_timeout() {
        let key_pair = checked_ed25519_keypair();
        let config = ToriiOperatorSignatures {
            body_read_timeout: Duration::ZERO,
            ..Default::default()
        };
        let error = match OperatorSignatures::new(
            config,
            key_pair.public_key().clone(),
            test_network_id(),
            1024,
            crate::routing::MaybeTelemetry::disabled(),
        ) {
            Ok(_) => panic!("signature body reads require a positive deadline"),
            Err(error) => error,
        };
        assert_eq!(error, OperatorSignatureConfigError);
    }
    fn signed_headers_with_nonce(
        key_pair: &KeyPair,
        method: &crate::Method,
        uri: &crate::Uri,
        body: &[u8],
        timestamp_ms: u64,
        nonce: &str,
    ) -> HeaderMap {
        let message = OperatorSignatures::operator_request_message(
            &test_network_id(),
            method,
            uri,
            body,
            timestamp_ms,
            nonce,
        )
        .expect("canonical operator test request is within V1 limits");
        let signature = Signature::try_new(key_pair.private_key(), &message)
            .expect("checked operator signature fixture");
        operator_signature_headers(key_pair, timestamp_ms, nonce, &signature)
            .expect("valid operator signature headers")
    }
    fn signed_torii_proxy_headers_with_nonce(
        sender_key_pair: &KeyPair,
        target_peer_id: &PeerId,
        method: &crate::Method,
        uri: &crate::Uri,
        body: &[u8],
        timestamp_ms: u64,
        nonce: &str,
    ) -> HeaderMap {
        let message = OperatorSignatures::torii_proxy_request_message(
            &test_network_id(),
            method,
            uri,
            body,
            timestamp_ms,
            nonce,
            target_peer_id,
        )
        .expect("canonical proxy test request is within V1 limits");
        let signature = Signature::try_new(sender_key_pair.private_key(), &message)
            .expect("checked Torii proxy signature fixture");
        let mut headers =
            operator_signature_headers(sender_key_pair, timestamp_ms, nonce, &signature)
                .expect("valid Torii proxy signature headers");
        headers.insert(
            HEADER_TORII_PROXY_TARGET_PEER_ID,
            target_peer_id
                .to_string()
                .parse()
                .expect("Torii proxy target header"),
        );
        headers
    }
    const ED25519_SMALL_ORDER_POINT: [u8; ed25519_dalek::PUBLIC_KEY_LENGTH] = [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];
    const ED25519_NONCANONICAL_IDENTITY: [u8; ed25519_dalek::PUBLIC_KEY_LENGTH] = [
        0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ];
    #[test]
    fn operator_signatures_rejects_replay() {
        let key_pair = checked_ed25519_keypair();
        let cfg = ToriiOperatorSignatures {
            enabled: true,
            allow_node_key: true,
            body_read_timeout: Duration::from_secs(10),
            allowed_public_keys: Vec::new(),
            max_clock_skew: Duration::from_secs(60),
            nonce_ttl: Duration::from_secs(300),
            replay_cache_capacity: NonZeroUsize::new(64).unwrap(),
        };
        let auth = OperatorSignatures::new(
            cfg,
            key_pair.public_key().clone(),
            test_network_id(),
            1024,
            crate::routing::MaybeTelemetry::disabled(),
        )
        .expect("valid operator-signature test config");
        let uri: crate::Uri = "/v1/configuration".parse().unwrap();
        let body = b"{}";
        let ts = crate::utils::unix_now_ms();
        let nonce = "nonce-1";
        let msg = OperatorSignatures::operator_request_message(
            &test_network_id(),
            &crate::Method::POST,
            &uri,
            body,
            ts,
            nonce,
        )
        .expect("canonical operator test request is within V1 limits");
        let signature = Signature::try_new(key_pair.private_key(), &msg)
            .expect("checked operator replay fixture signature");
        signature
            .verify(key_pair.public_key(), &msg)
            .expect("checked operator replay fixture signature verifies");
        let mut headers = HeaderMap::new();
        headers.insert(
            HEADER_OPERATOR_PUBLIC_KEY,
            key_pair
                .public_key()
                .to_string()
                .parse()
                .expect("public key header"),
        );
        headers.insert(
            HEADER_OPERATOR_TIMESTAMP_MS,
            ts.to_string().parse().expect("timestamp header"),
        );
        headers.insert(HEADER_OPERATOR_NONCE, nonce.parse().expect("nonce header"));
        headers.insert(
            HEADER_OPERATOR_SIGNATURE,
            BASE64_STANDARD
                .encode(signature.payload())
                .parse()
                .expect("signature header"),
        );
        auth.authorize_bytes(&headers, &crate::Method::POST, &uri, body)
            .expect("first use ok");
        let replay = auth
            .authorize_bytes(&headers, &crate::Method::POST, &uri, body)
            .expect_err("the identical signed request must be rejected as replay");
        assert_eq!(replay.code, "operator_signature_replay");
        headers.insert(
            HEADER_OPERATOR_PUBLIC_KEY,
            format!("ed25519:{}", key_pair.public_key())
                .parse()
                .expect("algorithm-prefixed public key header"),
        );
        let err = auth
            .authorize_bytes(&headers, &crate::Method::POST, &uri, body)
            .expect_err("retired key spelling must be rejected before replay lookup");
        assert_eq!(err.code, "operator_signature_invalid");
    }
    #[test]
    fn operator_and_proxy_signatures_reject_foreign_exact_network() {
        let key_pair = checked_ed25519_keypair();
        let auth = operator_signatures_with_capacity(&key_pair, 8);
        let uri: crate::Uri = "/v1/internal/torii/proxy".parse().expect("proxy URI");
        let body = b"canonical-norito-request";
        let timestamp_ms = crate::utils::unix_now_ms();
        let operator_message = OperatorSignatures::operator_request_message(
            &foreign_network_id(),
            &crate::Method::POST,
            &uri,
            body,
            timestamp_ms,
            "foreign-network-operator",
        )
        .expect("canonical operator test request is within V1 limits");
        let operator_signature = Signature::try_new(key_pair.private_key(), &operator_message)
            .expect("foreign-network operator signature");
        let operator_headers = operator_signature_headers(
            &key_pair,
            timestamp_ms,
            "foreign-network-operator",
            &operator_signature,
        )
        .expect("valid foreign-network operator headers");
        let operator_error = auth
            .authorize_bytes(&operator_headers, &crate::Method::POST, &uri, body)
            .expect_err("same route and label on another genesis must fail operator admission");
        assert_eq!(operator_error.code, "operator_signature_bad");
        let receiver = PeerId::from(checked_ed25519_keypair().public_key().clone());
        let proxy_message = OperatorSignatures::torii_proxy_request_message(
            &foreign_network_id(),
            &crate::Method::POST,
            &uri,
            body,
            timestamp_ms,
            "foreign-network-proxy",
            &receiver,
        )
        .expect("canonical proxy test request is within V1 limits");
        let proxy_signature = Signature::try_new(key_pair.private_key(), &proxy_message)
            .expect("foreign-network proxy signature");
        let mut proxy_headers = operator_signature_headers(
            &key_pair,
            timestamp_ms,
            "foreign-network-proxy",
            &proxy_signature,
        )
        .expect("valid foreign-network proxy headers");
        proxy_headers.insert(
            HEADER_TORII_PROXY_TARGET_PEER_ID,
            receiver.to_string().parse().expect("proxy target header"),
        );
        let proxy_error = auth
            .authorize_torii_proxy_bytes(
                &proxy_headers,
                &crate::Method::POST,
                &uri,
                body,
                &receiver,
            )
            .expect_err("same proxy target on another genesis must fail admission");
        assert_eq!(proxy_error.code, "operator_signature_bad");
    }
    #[test]
    fn torii_proxy_signatures_accept_unlisted_peer_keys_without_operator_privileges() {
        let operator = checked_ed25519_keypair();
        let remote_peer = checked_ed25519_keypair();
        let receiver = PeerId::from(checked_ed25519_keypair().public_key().clone());
        let auth = operator_signatures_with_capacity(&operator, 8);
        let uri: crate::Uri = "/v1/internal/torii/proxy".parse().expect("Torii proxy URI");
        let body = b"canonical-norito-request";
        let headers = signed_torii_proxy_headers_with_nonce(
            &remote_peer,
            &receiver,
            &crate::Method::POST,
            &uri,
            body,
            crate::utils::unix_now_ms(),
            "unlisted-remote-peer",
        );
        let operator_error = auth
            .authorize_bytes(&headers, &crate::Method::POST, &uri, body)
            .expect_err("remote peer key must not gain privileged operator access");
        assert_eq!(operator_error.code, "operator_key_not_allowed");
        auth.authorize_torii_proxy_bytes(&headers, &crate::Method::POST, &uri, body, &receiver)
            .expect("the proxy crypto layer accepts an unlisted peer for handler authorization");
    }
    #[test]
    fn torii_proxy_signatures_reject_wrong_or_tampered_target() {
        let operator = checked_ed25519_keypair();
        let remote_peer = checked_ed25519_keypair();
        let signed_target = PeerId::from(checked_ed25519_keypair().public_key().clone());
        let receiver = PeerId::from(checked_ed25519_keypair().public_key().clone());
        let auth = operator_signatures_with_capacity(&operator, 8);
        let uri: crate::Uri = "/v1/internal/torii/proxy".parse().expect("Torii proxy URI");
        let body = b"canonical-norito-request";
        let timestamp_ms = crate::utils::unix_now_ms();
        let headers = signed_torii_proxy_headers_with_nonce(
            &remote_peer,
            &signed_target,
            &crate::Method::POST,
            &uri,
            body,
            timestamp_ms,
            "wrong-proxy-target",
        );
        let wrong_target = auth
            .authorize_torii_proxy_bytes(&headers, &crate::Method::POST, &uri, body, &receiver)
            .expect_err("a request signed for another receiver must fail");
        assert_eq!(wrong_target.code, "torii_proxy_target_mismatch");
        let mut tampered_headers = headers;
        tampered_headers.insert(
            HEADER_TORII_PROXY_TARGET_PEER_ID,
            receiver
                .to_string()
                .parse()
                .expect("tampered Torii proxy target header"),
        );
        let tampered_target = auth
            .authorize_torii_proxy_bytes(
                &tampered_headers,
                &crate::Method::POST,
                &uri,
                body,
                &receiver,
            )
            .expect_err("the receiver target must be covered by the signature");
        assert_eq!(tampered_target.code, "operator_signature_bad");
    }
    #[test]
    fn torii_proxy_signatures_bind_canonical_request_freshness_and_reject_replay() {
        let operator = checked_ed25519_keypair();
        let remote_peer = checked_ed25519_keypair();
        let receiver = PeerId::from(checked_ed25519_keypair().public_key().clone());
        let auth = operator_signatures_with_capacity(&operator, 8);
        let uri: crate::Uri = "/v1/internal/torii/proxy".parse().expect("Torii proxy URI");
        let other_uri: crate::Uri = "/v1/internal/torii/proxy/alias"
            .parse()
            .expect("tampered Torii proxy URI");
        let body = b"canonical-norito-request";
        let timestamp_ms = crate::utils::unix_now_ms();
        let headers = signed_torii_proxy_headers_with_nonce(
            &remote_peer,
            &receiver,
            &crate::Method::POST,
            &uri,
            body,
            timestamp_ms,
            "path-body-replay",
        );
        let wrong_method = auth
            .authorize_torii_proxy_bytes(&headers, &crate::Method::PUT, &uri, body, &receiver)
            .expect_err("the signature must bind the exact method");
        assert_eq!(wrong_method.code, "operator_signature_bad");
        let wrong_path = auth
            .authorize_torii_proxy_bytes(
                &headers,
                &crate::Method::POST,
                &other_uri,
                body,
                &receiver,
            )
            .expect_err("the signature must bind the exact route path");
        assert_eq!(wrong_path.code, "operator_signature_bad");
        let wrong_body = auth
            .authorize_torii_proxy_bytes(
                &headers,
                &crate::Method::POST,
                &uri,
                b"tampered-norito-request",
                &receiver,
            )
            .expect_err("the signature must bind the exact body");
        assert_eq!(wrong_body.code, "operator_signature_bad");
        let mut wrong_timestamp_headers = headers.clone();
        wrong_timestamp_headers.insert(
            HEADER_OPERATOR_TIMESTAMP_MS,
            timestamp_ms
                .saturating_add(1)
                .to_string()
                .parse()
                .expect("tampered timestamp header"),
        );
        let wrong_timestamp = auth
            .authorize_torii_proxy_bytes(
                &wrong_timestamp_headers,
                &crate::Method::POST,
                &uri,
                body,
                &receiver,
            )
            .expect_err("the signature must bind the exact timestamp");
        assert_eq!(wrong_timestamp.code, "operator_signature_bad");
        let mut wrong_nonce_headers = headers.clone();
        wrong_nonce_headers.insert(
            HEADER_OPERATOR_NONCE,
            HeaderValue::from_static("tampered-proxy-nonce"),
        );
        let wrong_nonce = auth
            .authorize_torii_proxy_bytes(
                &wrong_nonce_headers,
                &crate::Method::POST,
                &uri,
                body,
                &receiver,
            )
            .expect_err("the signature must bind the exact nonce");
        assert_eq!(wrong_nonce.code, "operator_signature_bad");
        auth.authorize_torii_proxy_bytes(&headers, &crate::Method::POST, &uri, body, &receiver)
            .expect("failed verification must not consume the authenticated nonce");
        let replay = auth
            .authorize_torii_proxy_bytes(&headers, &crate::Method::POST, &uri, body, &receiver)
            .expect_err("an authenticated Torii proxy nonce must be single-use");
        assert_eq!(replay.code, "operator_signature_replay");
    }
    #[test]
    fn operator_identity_bound_and_torii_proxy_replay_caches_are_partitioned() {
        let signer = checked_ed25519_keypair();
        let receiver = PeerId::from(checked_ed25519_keypair().public_key().clone());
        let auth = operator_signatures_with_capacity(&signer, 8);
        let uri: crate::Uri = "/v1/internal/torii/proxy".parse().expect("Torii proxy URI");
        let body = b"canonical-norito-request";
        let timestamp_ms = crate::utils::unix_now_ms();
        let nonce = "partitioned-replay-claim";
        let generic_headers = signed_headers_with_nonce(
            &signer,
            &crate::Method::POST,
            &uri,
            body,
            timestamp_ms,
            nonce,
        );
        let proxy_headers = signed_torii_proxy_headers_with_nonce(
            &signer,
            &receiver,
            &crate::Method::POST,
            &uri,
            body,
            timestamp_ms,
            nonce,
        );
        auth.authorize_bytes(&generic_headers, &crate::Method::POST, &uri, body)
            .expect("privileged operator replay partition admits its first use");
        auth.authorize_bytes_with_policy(&generic_headers, &crate::Method::POST, &uri, body, false)
            .expect("generic identity-bound replay partition admits its independent first use");
        auth.authorize_torii_proxy_bytes(
            &proxy_headers,
            &crate::Method::POST,
            &uri,
            body,
            &receiver,
        )
        .expect("Torii proxy replay partition admits its independent first use");
        assert_eq!(
            auth.authorize_bytes(&generic_headers, &crate::Method::POST, &uri, body)
                .expect_err("operator partition must reject its own replay")
                .code,
            "operator_signature_replay"
        );
        assert_eq!(
            auth.authorize_bytes_with_policy(
                &generic_headers,
                &crate::Method::POST,
                &uri,
                body,
                false,
            )
            .expect_err("identity-bound partition must reject its own replay")
            .code,
            "operator_signature_replay"
        );
        assert_eq!(
            auth.authorize_torii_proxy_bytes(
                &proxy_headers,
                &crate::Method::POST,
                &uri,
                body,
                &receiver,
            )
            .expect_err("Torii proxy partition must reject its own replay")
            .code,
            "operator_signature_replay"
        );
    }
    #[tokio::test]
    async fn torii_proxy_middleware_exposes_authenticated_unlisted_peer_identity() {
        let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests();
        let receiver_key_pair = checked_ed25519_keypair();
        let receiver = PeerId::from(receiver_key_pair.public_key().clone());
        Arc::get_mut(&mut app)
            .expect("unique test app state")
            .local_peer_id = Some(receiver.clone());
        let remote_peer = checked_ed25519_keypair();
        let expected_remote_public_key = remote_peer.public_key().clone();
        let body = b"canonical-norito-request";
        let uri: crate::Uri = "/v1/internal/torii/proxy".parse().expect("Torii proxy URI");
        let headers = signed_torii_proxy_request_headers(
            &remote_peer,
            app.state.network_id_ref(),
            &receiver,
            &crate::Method::POST,
            &uri,
            body,
        )
        .expect("Torii proxy signature headers");
        let proxy_layer = axum::middleware::from_fn_with_state::<
            _,
            _,
            (axum::extract::State<SharedAppState>, axum::extract::Request),
        >(app.clone(), enforce_torii_proxy_peer_signature);
        let router = axum::Router::new()
            .route(
                uri.path(),
                post(
                    move |axum::Extension(authenticated): axum::Extension<
                        AuthenticatedOperatorPublicKey,
                    >| {
                        let expected_remote_public_key = expected_remote_public_key.clone();
                        async move {
                            if authenticated.0 == expected_remote_public_key {
                                StatusCode::OK
                            } else {
                                StatusCode::FORBIDDEN
                            }
                        }
                    },
                )
                .layer(proxy_layer),
            )
            .with_state(app);
        let mut request = axum::http::Request::builder()
            .method(crate::Method::POST)
            .uri(uri)
            .body(Body::from(body.to_vec()))
            .expect("Torii proxy request");
        request.headers_mut().extend(headers);
        let response = router
            .oneshot(request)
            .await
            .expect("Torii proxy middleware response");
        assert_eq!(response.status(), StatusCode::OK);
    }
    #[tokio::test]
    async fn stalled_signature_body_returns_fixed_timeout_error() {
        let stalled = futures::stream::pending::<
            std::result::Result<axum::body::Bytes, std::convert::Infallible>,
        >();
        let error = tokio::time::timeout(
            Duration::from_secs(1),
            collect_operator_signature_body(
                Body::from_stream(stalled),
                1024,
                Duration::from_millis(20),
            ),
        )
        .await
        .expect("configured signature-body deadline must complete")
        .expect_err("a stalled signature body must be rejected");
        assert_eq!(error.status, StatusCode::REQUEST_TIMEOUT);
        assert_eq!(error.code, "operator_signature_body_timeout");
    }
    #[tokio::test]
    async fn stalled_torii_proxy_body_timeout_releases_peer_receiver_lane() {
        let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests();
        let receiver_key_pair = checked_ed25519_keypair();
        {
            let state = Arc::get_mut(&mut app).expect("unique test app state");
            state.local_peer_id = Some(PeerId::from(receiver_key_pair.public_key().clone()));
            Arc::get_mut(&mut state.operator_signatures)
                .expect("unique operator-signature state")
                .body_read_timeout = Duration::from_millis(100);
        }
        let local_collector = crate::try_acquire_torii_proxy_memory(&app).unwrap();
        assert_eq!(app.torii_proxy_memory_inflight.available_permits(), 0);
        assert_eq!(
            app.torii_proxy_receiver_memory_inflight.available_permits(),
            1
        );
        let uri: crate::Uri = "/v1/internal/torii/proxy".parse().expect("Torii proxy URI");
        let proxy_layer = axum::middleware::from_fn_with_state::<
            _,
            _,
            (axum::extract::State<SharedAppState>, axum::extract::Request),
        >(app.clone(), enforce_torii_proxy_peer_signature);
        let router = axum::Router::new()
            .route(
                uri.path(),
                post(|| async { StatusCode::NO_CONTENT }).layer(proxy_layer),
            )
            .with_state(app.clone());
        let (body_polled_tx, body_polled_rx) = tokio::sync::oneshot::channel();
        let stalled = futures::stream::once(async move {
            let _ = body_polled_tx.send(());
            std::future::pending::<
                std::result::Result<axum::body::Bytes, std::convert::Infallible>,
            >()
            .await
        });
        let request = axum::http::Request::builder()
            .method(crate::Method::POST)
            .uri(uri)
            .body(Body::from_stream(stalled))
            .expect("stalled Torii proxy request");
        let response_task = tokio::spawn(async move {
            router
                .oneshot(request)
                .await
                .expect("Torii proxy middleware response")
        });
        tokio::time::timeout(Duration::from_secs(1), body_polled_rx)
            .await
            .expect("stalled body must be polled after acquiring proxy admission")
            .expect("body poll signal");
        assert_eq!(
            app.torii_proxy_receiver_memory_inflight.available_permits(),
            0,
            "the stalled body must own the peer receiver lane until its deadline"
        );
        let response = tokio::time::timeout(Duration::from_secs(1), response_task)
            .await
            .expect("configured proxy body deadline must complete")
            .expect("proxy middleware task must complete");
        assert_eq!(response.status(), StatusCode::REQUEST_TIMEOUT);
        let response_body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .expect("bounded timeout response body");
        assert!(
            std::str::from_utf8(&response_body)
                .expect("timeout response is UTF-8 JSON")
                .contains("\"code\":\"operator_signature_body_timeout\"")
        );
        assert_eq!(
            app.torii_proxy_receiver_memory_inflight.available_permits(),
            1,
            "timing out a stalled peer body must release the peer receiver lane"
        );
        assert_eq!(app.torii_proxy_memory_inflight.available_permits(), 0);
        drop(local_collector);
        assert_eq!(app.torii_proxy_memory_inflight.available_permits(), 1);
    }
    #[test]
    fn bad_signature_does_not_consume_its_claimed_nonce() {
        let key_pair = checked_ed25519_keypair();
        let auth = operator_signatures_with_capacity(&key_pair, 1);
        let uri: crate::Uri = "/v1/configuration".parse().unwrap();
        let body = b"{}";
        let timestamp_ms = crate::utils::unix_now_ms();
        let nonce = "nonce-after-bad-signature";
        let valid_headers = signed_headers_with_nonce(
            &key_pair,
            &crate::Method::POST,
            &uri,
            body,
            timestamp_ms,
            nonce,
        );
        let mut invalid_headers = signed_headers_with_nonce(
            &key_pair,
            &crate::Method::POST,
            &uri,
            body,
            timestamp_ms,
            "nonce-that-was-actually-signed",
        );
        invalid_headers.insert(
            HEADER_OPERATOR_NONCE,
            nonce.parse().expect("claimed nonce header"),
        );
        let error = auth
            .authorize_bytes(&invalid_headers, &crate::Method::POST, &uri, body)
            .expect_err("mismatched signature must fail");
        assert_eq!(error.code, "operator_signature_bad");
        auth.authorize_bytes(&valid_headers, &crate::Method::POST, &uri, body)
            .expect("bad signature must not consume the nonce");
        let replay = auth
            .authorize_bytes(&valid_headers, &crate::Method::POST, &uri, body)
            .expect_err("authenticated nonce must remain replay-protected");
        assert_eq!(replay.code, "operator_signature_replay");
    }
    #[test]
    fn bad_signatures_cannot_poison_replay_cache_capacity() {
        let key_pair = checked_ed25519_keypair();
        let auth = operator_signatures_with_capacity(&key_pair, 2);
        let uri: crate::Uri = "/v1/configuration".parse().unwrap();
        let body = b"{}";
        let timestamp_ms = crate::utils::unix_now_ms();
        let protected_headers: Vec<_> = ["protected-nonce-a", "protected-nonce-b"]
            .into_iter()
            .map(|nonce| {
                signed_headers_with_nonce(
                    &key_pair,
                    &crate::Method::POST,
                    &uri,
                    body,
                    timestamp_ms,
                    nonce,
                )
            })
            .collect();
        for headers in &protected_headers {
            auth.authorize_bytes(headers, &crate::Method::POST, &uri, body)
                .expect("initial authenticated nonce use");
        }
        for index in 0..32 {
            let mut poison_headers = signed_headers_with_nonce(
                &key_pair,
                &crate::Method::POST,
                &uri,
                body,
                timestamp_ms,
                "different-signed-nonce",
            );
            poison_headers.insert(
                HEADER_OPERATOR_NONCE,
                format!("poison-nonce-{index}")
                    .parse()
                    .expect("poison nonce header"),
            );
            let error = auth
                .authorize_bytes(&poison_headers, &crate::Method::POST, &uri, body)
                .expect_err("poisoning request must fail signature verification");
            assert_eq!(error.code, "operator_signature_bad");
        }
        for headers in &protected_headers {
            let replay = auth
                .authorize_bytes(headers, &crate::Method::POST, &uri, body)
                .expect_err("invalid traffic must not evict authenticated replay protection");
            assert_eq!(replay.code, "operator_signature_replay");
        }
    }
    #[test]
    fn authenticated_capacity_pressure_preserves_live_operator_nonces() {
        let key_pair = checked_ed25519_keypair();
        let auth = operator_signatures_with_capacity(&key_pair, 2);
        let uri: crate::Uri = "/v1/configuration".parse().expect("valid URI");
        let body = b"{}";
        let timestamp_ms = crate::utils::unix_now_ms();
        let protected_headers = ["protected-a", "protected-b"].map(|nonce| {
            signed_headers_with_nonce(
                &key_pair,
                &crate::Method::POST,
                &uri,
                body,
                timestamp_ms,
                nonce,
            )
        });
        for headers in &protected_headers {
            auth.authorize_bytes(headers, &crate::Method::POST, &uri, body)
                .expect("initial authenticated nonce use");
        }
        let overflow = signed_headers_with_nonce(
            &key_pair,
            &crate::Method::POST,
            &uri,
            body,
            timestamp_ms,
            "overflow",
        );
        let error = auth
            .authorize_bytes(&overflow, &crate::Method::POST, &uri, body)
            .expect_err("full replay cache must reject a new nonce");
        assert_eq!(error.code, "operator_signature_replay_cache_unavailable");
        assert_eq!(error.status, StatusCode::SERVICE_UNAVAILABLE);
        for headers in &protected_headers {
            let replay = auth
                .authorize_bytes(headers, &crate::Method::POST, &uri, body)
                .expect_err("capacity pressure must preserve authenticated nonces");
            assert_eq!(replay.code, "operator_signature_replay");
        }
    }
    #[test]
    fn concurrent_valid_requests_with_same_nonce_have_one_winner() {
        const WORKERS: usize = 16;
        let key_pair = checked_ed25519_keypair();
        let auth = operator_signatures_with_capacity(&key_pair, 64);
        let uri: crate::Uri = "/v1/configuration".parse().unwrap();
        let body = b"{}";
        let headers = signed_headers_with_nonce(
            &key_pair,
            &crate::Method::POST,
            &uri,
            body,
            crate::utils::unix_now_ms(),
            "concurrent-shared-nonce",
        );
        let barrier = Arc::new(Barrier::new(WORKERS));
        let results = thread::scope(|scope| {
            let mut handles = Vec::with_capacity(WORKERS);
            for _ in 0..WORKERS {
                let barrier = Arc::clone(&barrier);
                let headers = headers.clone();
                let auth = &auth;
                let uri = &uri;
                handles.push(scope.spawn(move || {
                    barrier.wait();
                    auth.authorize_bytes(&headers, &crate::Method::POST, uri, body)
                        .map_err(|error| error.code)
                }));
            }
            handles
                .into_iter()
                .map(|handle| handle.join().expect("authorization worker"))
                .collect::<Vec<_>>()
        });
        let mut accepted = 0;
        let mut replayed = 0;
        for result in results {
            match result {
                Ok(()) => accepted += 1,
                Err("operator_signature_replay") => replayed += 1,
                Err(code) => panic!("unexpected concurrent authorization error: {code}"),
            }
        }
        assert_eq!(accepted, 1);
        assert_eq!(replayed, WORKERS - 1);
    }
    #[test]
    fn operator_signatures_accepts_valid_signature() {
        let key_pair = checked_ed25519_keypair();
        let cfg = ToriiOperatorSignatures {
            enabled: true,
            allow_node_key: false,
            body_read_timeout: Duration::from_secs(10),
            allowed_public_keys: vec![key_pair.public_key().clone()],
            max_clock_skew: Duration::from_secs(60),
            nonce_ttl: Duration::from_secs(300),
            replay_cache_capacity: NonZeroUsize::new(64).unwrap(),
        };
        let auth = OperatorSignatures::new(
            cfg,
            checked_ed25519_keypair().public_key().clone(),
            test_network_id(),
            1024,
            crate::routing::MaybeTelemetry::disabled(),
        )
        .expect("valid operator-signature test config");
        let uri: crate::Uri = "/v1/configuration?b=2&a=1".parse().unwrap();
        let body = b"{\"foo\":1}";
        let headers = signed_request_headers(
            &key_pair,
            &test_network_id(),
            &crate::Method::POST,
            &uri,
            body,
        )
        .expect("operator signature headers");
        auth.authorize_bytes(&headers, &crate::Method::POST, &uri, body)
            .expect("valid signature");
    }
    #[test]
    fn operator_signatures_accepts_valid_mldsa_signature() {
        let key_pair = checked_mldsa_keypair();
        let cfg = ToriiOperatorSignatures {
            enabled: true,
            allow_node_key: false,
            body_read_timeout: Duration::from_secs(10),
            allowed_public_keys: vec![key_pair.public_key().clone()],
            max_clock_skew: Duration::from_secs(60),
            nonce_ttl: Duration::from_secs(300),
            replay_cache_capacity: NonZeroUsize::new(64).unwrap(),
        };
        let auth = OperatorSignatures::new(
            cfg,
            checked_ed25519_keypair().public_key().clone(),
            test_network_id(),
            1024,
            crate::routing::MaybeTelemetry::disabled(),
        )
        .expect("valid operator-signature test config");
        let uri: crate::Uri = "/v1/configuration?b=2&a=1".parse().unwrap();
        let body = b"{\"foo\":1}";
        let headers = signed_request_headers(
            &key_pair,
            &test_network_id(),
            &crate::Method::POST,
            &uri,
            body,
        )
        .expect("ML-DSA operator signature headers");
        auth.authorize_bytes(&headers, &crate::Method::POST, &uri, body)
            .expect("valid ML-DSA signature");
    }
    #[test]
    fn operator_signatures_reject_all_zero_signature_header() {
        let key_pair = checked_ed25519_keypair();
        let cfg = ToriiOperatorSignatures {
            enabled: true,
            allow_node_key: false,
            body_read_timeout: Duration::from_secs(10),
            allowed_public_keys: vec![key_pair.public_key().clone()],
            max_clock_skew: Duration::from_secs(60),
            nonce_ttl: Duration::from_secs(300),
            replay_cache_capacity: NonZeroUsize::new(64).unwrap(),
        };
        let auth = OperatorSignatures::new(
            cfg,
            checked_ed25519_keypair().public_key().clone(),
            test_network_id(),
            1024,
            crate::routing::MaybeTelemetry::disabled(),
        )
        .expect("valid operator-signature test config");
        let uri: crate::Uri = "/v1/configuration?b=2&a=1".parse().unwrap();
        let body = b"{\"foo\":1}";
        let mut headers = signed_request_headers(
            &key_pair,
            &test_network_id(),
            &crate::Method::POST,
            &uri,
            body,
        )
        .expect("operator signature headers");
        headers.insert(
            HEADER_OPERATOR_SIGNATURE,
            BASE64_STANDARD
                .encode([0u8; 64])
                .parse()
                .expect("all-zero signature header"),
        );
        let error = auth
            .authorize_bytes(&headers, &crate::Method::POST, &uri, body)
            .expect_err("all-zero signature header must fail");
        assert_eq!(error.code, "operator_signature_invalid");
    }
    #[test]
    fn operator_signatures_reject_malformed_ed25519_signature_r_before_backend() {
        let key_pair = checked_ed25519_keypair();
        let cfg = ToriiOperatorSignatures {
            enabled: true,
            allow_node_key: false,
            body_read_timeout: Duration::from_secs(10),
            allowed_public_keys: vec![key_pair.public_key().clone()],
            max_clock_skew: Duration::from_secs(60),
            nonce_ttl: Duration::from_secs(300),
            replay_cache_capacity: NonZeroUsize::new(64).unwrap(),
        };
        let auth = OperatorSignatures::new(
            cfg,
            checked_ed25519_keypair().public_key().clone(),
            test_network_id(),
            1024,
            crate::routing::MaybeTelemetry::disabled(),
        )
        .expect("valid operator-signature test config");
        let uri: crate::Uri = "/v1/configuration?b=2&a=1".parse().unwrap();
        let body = b"{\"foo\":1}";
        for (label, replacement_r) in [
            ("small-order", ED25519_SMALL_ORDER_POINT),
            ("noncanonical", ED25519_NONCANONICAL_IDENTITY),
        ] {
            let mut headers = signed_request_headers(
                &key_pair,
                &test_network_id(),
                &crate::Method::POST,
                &uri,
                body,
            )
            .expect("operator signature headers");
            let signature_str = headers
                .get(HEADER_OPERATOR_SIGNATURE)
                .expect("signature header")
                .to_str()
                .expect("signature header is text");
            let mut signature_bytes = BASE64_STANDARD
                .decode(signature_str)
                .expect("decode generated signature");
            signature_bytes[..ed25519_dalek::PUBLIC_KEY_LENGTH].copy_from_slice(&replacement_r);
            headers.insert(
                HEADER_OPERATOR_SIGNATURE,
                BASE64_STANDARD
                    .encode(signature_bytes)
                    .parse()
                    .expect("malformed signature header"),
            );
            let error = auth
                .authorize_bytes(&headers, &crate::Method::POST, &uri, body)
                .expect_err("malformed signature header must fail");
            assert_eq!(
                error.code, "operator_signature_invalid",
                "{label} signature R must fail at header admission"
            );
        }
    }
    #[test]
    fn operator_signatures_reject_malformed_mldsa_signature_lengths() {
        let key_pair = checked_mldsa_keypair();
        let cfg = ToriiOperatorSignatures {
            enabled: true,
            allow_node_key: false,
            body_read_timeout: Duration::from_secs(10),
            allowed_public_keys: vec![key_pair.public_key().clone()],
            max_clock_skew: Duration::from_secs(60),
            nonce_ttl: Duration::from_secs(300),
            replay_cache_capacity: NonZeroUsize::new(64).unwrap(),
        };
        let auth = OperatorSignatures::new(
            cfg,
            checked_ed25519_keypair().public_key().clone(),
            test_network_id(),
            1024,
            crate::routing::MaybeTelemetry::disabled(),
        )
        .expect("valid operator-signature test config");
        let uri: crate::Uri = "/v1/configuration?b=2&a=1".parse().unwrap();
        let body = b"{\"foo\":1}";
        for label in ["short", "overlong"] {
            let mut headers = signed_request_headers(
                &key_pair,
                &test_network_id(),
                &crate::Method::POST,
                &uri,
                body,
            )
            .expect("ML-DSA operator signature headers");
            let signature_str = headers
                .get(HEADER_OPERATOR_SIGNATURE)
                .expect("signature header")
                .to_str()
                .expect("signature header is text");
            let mut signature_bytes = BASE64_STANDARD
                .decode(signature_str)
                .expect("decode generated ML-DSA signature");
            match label {
                "short" => {
                    signature_bytes
                        .pop()
                        .expect("ML-DSA fixture signature is non-empty");
                }
                "overlong" => signature_bytes.push(0xA5),
                _ => unreachable!("covered labels"),
            }
            headers.insert(
                HEADER_OPERATOR_SIGNATURE,
                BASE64_STANDARD
                    .encode(signature_bytes)
                    .parse()
                    .expect("malformed ML-DSA signature header"),
            );
            let error = auth
                .authorize_bytes(&headers, &crate::Method::POST, &uri, body)
                .expect_err("malformed ML-DSA operator signature header must fail");
            assert_eq!(
                error.code, "operator_signature_invalid",
                "{label} ML-DSA signature length must fail at header admission"
            );
        }
    }
    #[test]
    fn signed_request_headers_authorize_successfully() {
        let key_pair = checked_ed25519_keypair();
        let cfg = ToriiOperatorSignatures {
            enabled: true,
            allow_node_key: true,
            body_read_timeout: Duration::from_secs(10),
            allowed_public_keys: Vec::new(),
            max_clock_skew: Duration::from_secs(60),
            nonce_ttl: Duration::from_secs(300),
            replay_cache_capacity: NonZeroUsize::new(64).unwrap(),
        };
        let auth = OperatorSignatures::new(
            cfg,
            key_pair.public_key().clone(),
            test_network_id(),
            1024,
            crate::routing::MaybeTelemetry::disabled(),
        )
        .expect("valid operator-signature test config");
        let uri: crate::Uri = iroha_torii_shared::route_catalog::core::CONFIGURATION_GET
            .path()
            .parse()
            .unwrap();
        let headers = signed_request_headers(
            &key_pair,
            &test_network_id(),
            &crate::Method::GET,
            &uri,
            &[],
        )
        .expect("operator signature headers");
        auth.authorize_bytes(&headers, &crate::Method::GET, &uri, &[])
            .expect("generated headers should verify");
    }
    #[test]
    fn signed_request_headers_reports_nonce_rng_failure() {
        let key_pair = checked_ed25519_keypair();
        let uri: crate::Uri = iroha_torii_shared::route_catalog::core::CONFIGURATION_GET
            .path()
            .parse()
            .expect("configuration URI");
        let mut rng = FailingOperatorNonceRng;
        let error = signed_request_headers_with_rng(
            &key_pair,
            &test_network_id(),
            &crate::Method::GET,
            &uri,
            &[],
            &mut rng,
        )
        .expect_err("RNG failure must be reported");
        assert_eq!(error.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(error.code, "operator_signature_nonce_rng");
        assert!(
            error
                .message
                .contains("operator signature nonce RNG failed")
        );
        assert!(error.message.contains("failing operator nonce RNG"));
    }
    #[test]
    fn operator_signature_signing_error_is_internal() {
        let error = OperatorSignatureError::signing("backend rejected message");
        assert_eq!(error.status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(error.code, "operator_signature_signing");
        assert!(error.message.contains("backend rejected message"));
    }
    #[tokio::test]
    async fn operator_middleware_marks_successful_responses_private_and_no_store() {
        let app = crate::tests_runtime_handlers::mk_app_state_for_tests();
        assert!(app.operator_signatures.is_enabled());
        assert!(!app.operator_auth.is_enabled());
        let uri: crate::Uri = "/status".parse().expect("operator test URI");
        let headers = signed_request_headers(
            &app.da_receipt_signer,
            app.state.network_id_ref(),
            &crate::Method::GET,
            &uri,
            &[],
        )
        .expect("valid operator signature headers");
        let operator_layer = axum::middleware::from_fn_with_state::<
            _,
            _,
            (axum::extract::State<SharedAppState>, axum::extract::Request),
        >(app.clone(), enforce_operator_access);
        let router = axum::Router::new()
            .route("/status", get(|| async { "ok" }))
            .route_layer(operator_layer);
        let mut request = axum::http::Request::builder()
            .uri(uri)
            .body(Body::empty())
            .expect("request");
        request.headers_mut().extend(headers);

        let response = router.oneshot(request).await.expect("router response");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CACHE_CONTROL),
            Some(&HeaderValue::from_static("private, no-store")),
        );
    }
    #[tokio::test]
    async fn operator_middleware_requires_signature_even_when_bootstrap_token_is_valid() {
        let mut app = crate::tests_runtime_handlers::mk_app_state_for_tests();
        assert!(app.operator_signatures.is_enabled());
        assert!(!app.operator_auth.is_enabled());
        let tempdir = tempfile::tempdir().expect("operator auth tempdir");
        const BOOTSTRAP_TOKEN: &str = "bootstrap-token-for-operator-tests-01";
        let operator_auth = bootstrap_token_operator_auth(BOOTSTRAP_TOKEN, tempdir.path());
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-iroha-operator-token",
            HeaderValue::from_static(BOOTSTRAP_TOKEN),
        );
        operator_auth
            .authorize_bootstrap(&headers, None, "register_options")
            .await
            .expect("fixture token is valid for first-credential bootstrap");
        let node_public_key = app.da_receipt_signer.public_key().clone();
        let network_id = *app.state.network_id_ref();
        let telemetry = app.telemetry.clone();
        let cfg = ToriiOperatorSignatures {
            enabled: false,
            ..Default::default()
        };
        let app_mut = Arc::get_mut(&mut app).expect("unique app state required");
        app_mut.operator_auth = Arc::new(operator_auth);
        app_mut.operator_signatures = Arc::new(
            OperatorSignatures::new(
                cfg,
                node_public_key,
                network_id,
                iroha_config::parameters::defaults::torii::MAX_CONTENT_LEN.get(),
                telemetry,
            )
            .expect("valid operator-signature test config"),
        );
        assert!(!app.operator_signatures.is_enabled());
        assert!(app.operator_auth.is_enabled());
        let operator_layer = axum::middleware::from_fn_with_state::<
            _,
            _,
            (axum::extract::State<SharedAppState>, axum::extract::Request),
        >(app.clone(), enforce_operator_access);
        let router = axum::Router::new()
            .route("/status", get(|| async { "ok" }))
            .route_layer(operator_layer);
        let mut request = axum::http::Request::builder()
            .uri("/status")
            .body(Body::empty())
            .expect("request");
        request.headers_mut().extend(headers);
        let response = router.oneshot(request).await.expect("router response");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response.headers().get(CACHE_CONTROL),
            Some(&HeaderValue::from_static("private, no-store")),
        );
    }
}
