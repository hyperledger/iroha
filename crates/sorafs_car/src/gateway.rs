//! HTTP gateway integration for the multi-source orchestrator.
//!
//! This module bridges the generic scheduling logic in [`multi_fetch`] with the
//! chunk-range endpoints served by Torii gateways. Callers provide the manifest
//! context together with per-provider connection details (base URL + stream
//! token) and receive a ready-to-use set of [`FetchProvider`] definitions plus
//! an async fetcher that issues chunk requests with the correct headers.
use crate::multi_fetch::{
    AttemptFailure, ChunkResponse, FetchOptions, FetchOutcome, FetchProvider, FetchRequest,
    MultiSourceError, PolicyBlockEvidence, ProviderMetadata, RangeCapability, StreamBudget,
    TransportHint,
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ed25519_dalek::VerifyingKey;
use hex::FromHexError;
use norito::json::{self, Value};
use rand::{rand_core::TryRngCore as _, rngs::OsRng};
use reqwest::{
    Client, StatusCode, Url,
    header::{HeaderMap, HeaderName, HeaderValue, InvalidHeaderValue},
};
use sorafs_manifest::{
    BLAKE3_256_MULTIHASH_CODE, MAX_MANIFEST_ROOT_CID_BYTES, ManifestV1,
    STREAM_TOKEN_MAX_BASE64_BYTES_V1, STREAM_TOKEN_MAX_TTL_SECS_V1, STREAM_TOKEN_MAX_WIRE_BYTES_V1,
    StreamTokenV1, decode_manifest_v1_canonical, validate_manifest_root_cid,
};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt,
    future::Future,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    num::NonZeroUsize,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
mod generated_local;
mod generated_tls;
pub use generated_local::{
    AuthenticatedGeneratedLocalProviderTransportV1, GeneratedLocalProviderTransportErrorV1,
    GeneratedLocalProviderTransportV1, GeneratedLocalPublicationHttpClientV1,
    GeneratedLocalPublicationTransportErrorV1, GeneratedLocalPublicationTransportV1,
};
mod source;
pub use source::{GatewaySourceErrorV1, GatewaySourceLimitsV1, GatewayVerifiedPayloadV1};
const HEADER_SORA_NONCE: &str = "x-sorafs-nonce";
const HEADER_SORA_CHUNKER: &str = "x-sorafs-chunker";
const HEADER_SORA_STREAM_TOKEN: &str = "x-sorafs-stream-token";
const HEADER_SORA_MANIFEST_ENVELOPE: &str = "x-sorafs-manifest-envelope";
const HEADER_SORA_CLIENT: &str = "x-sorafs-client";
const HEADER_SORA_REQ_BLINDED_CID: &str = "sora-req-blinded-cid";
const HEADER_SORA_REQ_SALT_EPOCH: &str = "sora-req-salt-epoch";
const HEADER_SORA_REQ_NONCE: &str = "sora-req-nonce";
const HEADER_SORA_CACHE_VERSION: &str = "sora-cache-version";
/// Exact V1 gateway compliance denial code.
pub(crate) const GATEWAY_COMPLIANCE_DENIED_CODE: &str = "gateway_compliance_denied";
/// Baseline governed-catalog decision source.
pub(crate) const GATEWAY_COMPLIANCE_SOURCE_BASELINE: &str = "baseline";
/// Legal or safety hold decision source.
pub(crate) const GATEWAY_COMPLIANCE_SOURCE_LEGAL_SAFETY_HOLD: &str = "legal_safety_hold";
const MAX_GATEWAY_PROVIDERS: usize = 256;
const MAX_DNS_ADDRESSES_PER_HOST: usize = 16;
const MAX_PROVIDER_NAME_BYTES: usize = 128;
const MAX_CHUNKER_HANDLE_BYTES: usize = 128;
const MAX_MANIFEST_ENVELOPE_BASE64_BYTES: usize = 64 * 1024;
const MAX_CLIENT_ID_BYTES: usize = 128;
const MAX_CACHE_VERSION_BYTES: usize = 128;
const MAX_GATEWAY_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_GATEWAY_ERROR_BODY_BYTES: usize = 4 * 1024;
const MAX_STREAM_TOKEN_ID_BYTES: usize = 128;
const STREAM_TOKEN_CLOCK_SKEW_SECS: u64 = 60;
const GATEWAY_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const GATEWAY_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// HTTP request issued by the gateway fetcher.
pub(crate) struct HttpRequest {
    pub url: Url,
    pub headers: HeaderMap,
    pub max_response_bytes: usize,
}
/// HTTP response returned by the engine.
#[derive(Clone)]
pub(crate) struct HttpResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}
/// Evidence returned by a gateway when a request is blocked by policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GatewayFailureEvidence {
    /// Status code observed on the wire.
    pub observed_status: StatusCode,
    /// Exact canonical policy-denial code from the response body.
    pub code: String,
    /// Governed decision source (`baseline` or `legal_safety_hold`).
    pub source: String,
    /// Lowercase hexadecimal digest of the active governed catalog.
    pub catalog_digest_hex: String,
}
pub(crate) type HttpFuture = Pin<Box<dyn Future<Output = Result<HttpResponse, HttpError>> + Send>>;
/// Minimal async HTTP client abstraction used by the fetcher.
pub(crate) trait HttpEngine: Send + Sync {
    fn get(&self, request: HttpRequest) -> HttpFuture;
}
/// Errors surfaced by HTTP engines.
#[derive(Debug)]
pub(crate) enum HttpError {
    Transport(reqwest::Error),
    Body(reqwest::Error),
    ResponseTooLarge {
        limit: usize,
    },
    #[cfg(test)]
    TestEngine(String),
}
struct ReqwestEngine {
    client: Client,
}
impl ReqwestEngine {
    fn new(client: Client) -> Self {
        Self { client }
    }
}
impl HttpEngine for ReqwestEngine {
    fn get(&self, request: HttpRequest) -> HttpFuture {
        let client = self.client.clone();
        Box::pin(async move {
            let max_response_bytes = request.max_response_bytes.min(MAX_GATEWAY_RESPONSE_BYTES);
            let mut builder = client.get(request.url);
            builder = builder.headers(request.headers);
            let mut response = builder.send().await.map_err(HttpError::Transport)?;
            let status = response.status();
            let headers = response.headers().clone();
            if response
                .content_length()
                .is_some_and(|length| length > max_response_bytes as u64)
            {
                return Err(HttpError::ResponseTooLarge {
                    limit: max_response_bytes,
                });
            }
            let initial_capacity = response
                .content_length()
                .and_then(|length| usize::try_from(length).ok())
                .unwrap_or(0)
                .min(max_response_bytes);
            let mut body = Vec::with_capacity(initial_capacity);
            while let Some(chunk) = response.chunk().await.map_err(HttpError::Body)? {
                let next_len =
                    body.len()
                        .checked_add(chunk.len())
                        .ok_or(HttpError::ResponseTooLarge {
                            limit: max_response_bytes,
                        })?;
                if next_len > max_response_bytes {
                    return Err(HttpError::ResponseTooLarge {
                        limit: max_response_bytes,
                    });
                }
                body.extend_from_slice(&chunk);
            }
            Ok(HttpResponse {
                status,
                headers,
                body,
            })
        })
    }
}
/// Provider configuration required to contact a Torii gateway.
#[derive(Debug, Clone)]
pub struct GatewayProviderInput {
    /// Human-friendly alias used in orchestrator reports.
    pub name: String,
    /// Hex-encoded 32-byte provider identifier.
    pub provider_id_hex: String,
    /// Hex-encoded Ed25519 key that must verify the supplied stream token.
    pub gateway_public_key_hex: String,
    /// Base URL for the provider's Torii gateway.
    ///
    /// The request paths required by this module are appended to the base URL,
    /// so callers may omit a trailing slash.
    pub base_url: String,
    /// Base64-encoded [`StreamTokenV1`] authorising chunk access.
    pub stream_token_b64: String,
    /// Optional admin endpoint exposing `/privacy/events` for relay telemetry.
    pub privacy_events_url: Option<String>,
}
impl GatewayProviderInput {
    /// Parse one operator provider specification of comma-separated `key=value` pairs.
    ///
    /// Required keys are `name`, `provider-id`, `gateway-key`, `base-url` and `stream-token`;
    /// `privacy-url` is optional. Hex identifiers must be 32 bytes and are normalised to lower
    /// case. `flag` names the command-line flag in error messages.
    ///
    /// # Errors
    ///
    /// Returns a human-readable message for malformed pairs, unknown keys, empty values,
    /// non-canonical hex identifiers or missing required keys.
    pub fn parse_spec(value: &str, flag: &str) -> Result<Self, String> {
        fn non_empty(flag: &str, key: &str, value: &str) -> Result<String, String> {
            if value.is_empty() {
                return Err(format!("{flag} {key} must not be empty"));
            }
            Ok(value.to_owned())
        }
        fn hex32(flag: &str, key: &str, value: &str) -> Result<String, String> {
            if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(format!("{flag} {key} must be 32-byte hex"));
            }
            Ok(value.to_ascii_lowercase())
        }
        fn required(flag: &str, entry: &str, value: Option<String>) -> Result<String, String> {
            value.ok_or_else(|| format!("{flag} requires {entry}"))
        }

        let mut name = None;
        let mut provider_id_hex = None;
        let mut gateway_public_key_hex = None;
        let mut base_url = None;
        let mut stream_token_b64 = None;
        let mut privacy_events_url = None;
        for pair in value
            .split(',')
            .map(str::trim)
            .filter(|pair| !pair.is_empty())
        {
            let (key, val) = pair
                .split_once('=')
                .ok_or_else(|| format!("{flag} expects comma-separated key=value pairs"))?;
            let val = val.trim();
            match key {
                "name" => name = Some(non_empty(flag, key, val)?),
                "provider-id" => provider_id_hex = Some(hex32(flag, key, val)?),
                "gateway-key" => gateway_public_key_hex = Some(hex32(flag, key, val)?),
                "base-url" => base_url = Some(non_empty(flag, key, val)?),
                "stream-token" => stream_token_b64 = Some(non_empty(flag, key, val)?),
                "privacy-url" => privacy_events_url = Some(non_empty(flag, key, val)?),
                other => {
                    return Err(format!(
                        "unknown {flag} key `{other}`; expected name, provider-id, gateway-key, base-url, stream-token, privacy-url"
                    ));
                }
            }
        }
        Ok(Self {
            name: required(flag, "name=<alias>", name)?,
            provider_id_hex: required(flag, "provider-id=<hex>", provider_id_hex)?,
            gateway_public_key_hex: required(flag, "gateway-key=<hex>", gateway_public_key_hex)?,
            base_url: required(flag, "base-url=<https://...>", base_url)?,
            stream_token_b64: required(flag, "stream-token=<base64>", stream_token_b64)?,
            privacy_events_url,
        })
    }
}
/// Shared manifest context supplied to the gateway fetcher.
#[derive(Debug, Clone)]
pub struct GatewayFetchConfig {
    /// Hex-encoded manifest identifier used in the chunk endpoints.
    pub manifest_id_hex: String,
    /// Chunker handle advertised by the manifest (e.g. `sorafs.sf1@1.0.0`).
    pub chunker_handle: String,
    /// Optional governance envelope to satisfy gateway policy checks.
    pub manifest_envelope_b64: Option<String>,
    /// Optional client label for rate limiting / audit purposes.
    pub client_id: Option<String>,
    /// Optional exact manifest root CID: lowercase hex of the canonical 36-byte
    /// CIDv1 dag-cbor/BLAKE3-256 value. The stream token must authorise this CID.
    pub expected_manifest_cid_hex: Option<String>,
    /// Optional canonical blinded CID (base64url, no padding) passed via `Sora-Req-Blinded-CID`.
    pub blinded_cid_b64: Option<String>,
    /// Optional salt epoch associated with `blinded_cid_b64`.
    pub salt_epoch: Option<u32>,
    /// Optional cache version to enforce on successful gateway responses.
    pub expected_cache_version: Option<String>,
}
impl GatewayFetchConfig {
    /// Normalise the manifest identifier for routing.
    fn manifest_id_normalised(&self) -> String {
        self.manifest_id_hex.trim().to_ascii_lowercase()
    }
}
/// Container bundling orchestrator providers with the HTTP fetcher.
#[derive(Clone)]
pub struct GatewayFetchContext {
    providers: Arc<[FetchProvider]>,
    fetcher: GatewayFetcher,
}
impl std::fmt::Debug for GatewayFetchContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayFetchContext")
            .field("providers_len", &self.providers.len())
            .field("fetcher", &"<opaque>")
            .finish()
    }
}
impl GatewayFetchContext {
    /// Build a gateway fetch context from the supplied manifest and provider inputs.
    ///
    /// # Errors
    ///
    /// Returns [`GatewayBuildError`] when provider identifiers, stream tokens, or headers are
    /// malformed, or when the stream token metadata is inconsistent with the manifest context.
    pub fn new(
        config: GatewayFetchConfig,
        providers: impl IntoIterator<Item = GatewayProviderInput>,
    ) -> Result<Self, GatewayBuildError> {
        Self::new_with_timeouts(
            config,
            providers,
            GATEWAY_CONNECT_TIMEOUT,
            GATEWAY_REQUEST_TIMEOUT,
        )
    }
    /// Build a gateway fetch context with explicit connect and whole-request timeouts.
    ///
    /// This is intended for clients whose platform configuration owns a tighter
    /// end-to-end network bound than the generic gateway defaults.
    ///
    /// # Errors
    ///
    /// Returns [`GatewayBuildError`] when either timeout is zero, the connect
    /// timeout exceeds the request timeout, or the provider context is invalid.
    pub fn new_with_timeouts(
        config: GatewayFetchConfig,
        providers: impl IntoIterator<Item = GatewayProviderInput>,
        connect_timeout: Duration,
        request_timeout: Duration,
    ) -> Result<Self, GatewayBuildError> {
        Self::build_with_tls_roots(config, providers, connect_timeout, request_timeout, None)
    }
    /// Construct a provider source with an explicit, independently authenticated TLS root set.
    ///
    /// The supplied DER roots replace platform roots; no implicit trust fallback is used.
    /// At most four roots of at most 16 KiB each are accepted. Endpoint DNS names and pinned
    /// public-address resolution are still verified by the ordinary gateway transport.
    pub fn new_with_pinned_tls_roots(
        config: GatewayFetchConfig,
        providers: impl IntoIterator<Item = GatewayProviderInput>,
        connect_timeout: Duration,
        request_timeout: Duration,
        tls_roots_der: &[Vec<u8>],
    ) -> Result<Self, GatewayBuildError> {
        Self::build_with_tls_roots(
            config,
            providers,
            connect_timeout,
            request_timeout,
            Some(tls_roots_der),
        )
    }
    /// Construct the one exact generated-local provider transport after a native proof join.
    ///
    /// Uses only its original CA, original hostname and loopback socket. Platform roots,
    /// DNS lookup, proxies, redirects and unrelated privacy endpoints are unavailable.
    /// # Errors
    /// Refuses a different provider/origin, invalid TLS material, timeout or stream token.
    pub fn new_with_generated_local_transport(
        config: GatewayFetchConfig,
        provider: GatewayProviderInput,
        connect_timeout: Duration,
        request_timeout: Duration,
        selected: &AuthenticatedGeneratedLocalProviderTransportV1,
    ) -> Result<Self, GatewayBuildError> {
        selected.validate_input(&provider)?;
        let client = selected.async_http_client(connect_timeout, request_timeout)?;
        Self::build_with_selected_engine(
            config,
            [provider],
            Arc::new(ReqwestEngine::new(client)),
            Some(selected),
        )
    }
    fn build_with_tls_roots(
        config: GatewayFetchConfig,
        providers: impl IntoIterator<Item = GatewayProviderInput>,
        connect_timeout: Duration,
        request_timeout: Duration,
        tls_roots_der: Option<&[Vec<u8>]>,
    ) -> Result<Self, GatewayBuildError> {
        if connect_timeout.is_zero()
            || request_timeout.is_zero()
            || connect_timeout > request_timeout
        {
            return Err(GatewayBuildError::InvalidTimeouts);
        }
        let tls_roots = tls_roots_der
            .map(|roots| {
                if roots.is_empty() || roots.len() > 4 {
                    return Err(GatewayBuildError::InvalidPinnedTlsRoots);
                }
                roots
                    .iter()
                    .map(|der| {
                        if der.is_empty() || der.len() > 16 * 1024 {
                            return Err(GatewayBuildError::InvalidPinnedTlsRoots);
                        }
                        reqwest::Certificate::from_der(der)
                            .map_err(|_| GatewayBuildError::InvalidPinnedTlsRoots)
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?;
        let mut inputs = Vec::new();
        for input in providers {
            if inputs.len() >= MAX_GATEWAY_PROVIDERS {
                return Err(GatewayBuildError::TooManyProviders {
                    maximum: MAX_GATEWAY_PROVIDERS,
                });
            }
            inputs.push(input);
        }
        if inputs.is_empty() {
            return Err(GatewayBuildError::NoProviders);
        }
        let mut resolved_hosts = BTreeMap::<String, Vec<SocketAddr>>::new();
        for input in &inputs {
            let base_url = parse_base_url(&input.base_url).map_err(|source| {
                GatewayBuildError::InvalidBaseUrl {
                    provider_id: input.provider_id_hex.clone(),
                    source,
                }
            })?;
            resolve_public_host(&base_url, &mut resolved_hosts)?;
            if let Some(raw) = input.privacy_events_url.as_deref() {
                let privacy_url = parse_privacy_url(raw).map_err(|source| {
                    GatewayBuildError::InvalidPrivacyUrl {
                        provider_id: input.provider_id_hex.clone(),
                        source,
                    }
                })?;
                resolve_public_host(&privacy_url, &mut resolved_hosts)?;
            }
        }
        let mut client_builder = Client::builder()
            .no_proxy()
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(connect_timeout)
            .timeout(request_timeout);
        if let Some(roots) = tls_roots {
            client_builder = client_builder.tls_built_in_root_certs(false);
            for root in roots {
                client_builder = client_builder.add_root_certificate(root);
            }
        }
        for (host, addresses) in &resolved_hosts {
            client_builder = client_builder.resolve_to_addrs(host, addresses);
        }
        let client = client_builder
            .build()
            .map_err(GatewayBuildError::ClientBuild)?;
        Self::build_with_engine(config, inputs, Arc::new(ReqwestEngine::new(client)))
    }
    pub(crate) fn build_with_engine(
        config: GatewayFetchConfig,
        providers: impl IntoIterator<Item = GatewayProviderInput>,
        engine: Arc<dyn HttpEngine>,
    ) -> Result<Self, GatewayBuildError> {
        Self::build_with_selected_engine(config, providers, engine, None)
    }
    fn build_with_selected_engine(
        config: GatewayFetchConfig,
        providers: impl IntoIterator<Item = GatewayProviderInput>,
        engine: Arc<dyn HttpEngine>,
        selected: Option<&AuthenticatedGeneratedLocalProviderTransportV1>,
    ) -> Result<Self, GatewayBuildError> {
        let config = NormalisedConfig::from_config(config)?;
        let mut provider_map = HashMap::new();
        let mut provider_ids = HashSet::new();
        let mut fetch_providers = Vec::new();
        for (index, input) in providers.into_iter().enumerate() {
            if index >= MAX_GATEWAY_PROVIDERS {
                return Err(GatewayBuildError::TooManyProviders {
                    maximum: MAX_GATEWAY_PROVIDERS,
                });
            }
            let descriptor = ProviderDescriptor::from_input(
                &config,
                input,
                &mut provider_map,
                &mut provider_ids,
                selected,
            )?;
            fetch_providers.push(descriptor.provider.clone());
        }
        if fetch_providers.is_empty() {
            return Err(GatewayBuildError::NoProviders);
        }
        let fetcher = GatewayFetcher {
            inner: Arc::new(GatewayFetcherInner {
                manifest_id_hex: config.manifest_id.clone(),
                chunker_header: config.chunker_header.clone(),
                manifest_envelope: config.manifest_envelope.clone(),
                client_header: config.client_header.clone(),
                blinded_header: config.blinded_header.clone(),
                salt_epoch_header: config.salt_epoch_header.clone(),
                cache_version: config.cache_version.clone(),
                engine,
                providers: provider_map,
            }),
        };
        Ok(Self {
            providers: fetch_providers.into(),
            fetcher,
        })
    }
    /// Clone all provider descriptors for orchestrator scheduling.
    #[must_use]
    pub fn providers(&self) -> Vec<FetchProvider> {
        self.providers.to_vec()
    }
    /// Fetcher reference used to issue chunk requests.
    #[must_use]
    pub fn fetcher(&self) -> GatewayFetcher {
        self.fetcher.clone()
    }
    /// Convenience wrapper executing the orchestration end-to-end.
    pub async fn execute_plan(
        &self,
        plan: &crate::CarBuildPlan,
        options: FetchOptions,
    ) -> Result<FetchOutcome, MultiSourceError> {
        let fetcher = self.fetcher.clone();
        let providers = self.providers();
        crate::multi_fetch::fetch_plan_parallel(
            plan,
            providers,
            move |request| {
                let fetcher = fetcher.clone();
                async move { fetcher.fetch(request).await }
            },
            options,
        )
        .await
    }
    /// Fetch the manifest payload for this context using the configured providers.
    pub async fn fetch_manifest(&self) -> Result<GatewayFetchedManifest, GatewayManifestError> {
        self.fetcher.fetch_manifest().await
    }
}
/// Cloneable async fetcher issuing chunk requests to Torii gateways.
#[derive(Clone)]
pub struct GatewayFetcher {
    inner: Arc<GatewayFetcherInner>,
}
impl GatewayFetcher {
    /// Issue a single chunk request for the provided fetch metadata.
    pub async fn fetch(&self, request: FetchRequest) -> Result<ChunkResponse, GatewayFetchError> {
        self.inner.fetch(request).await
    }
    /// Expose the fetcher as a closure compatible with [`fetch_plan_parallel`].
    pub fn as_closure(
        &self,
    ) -> impl Fn(FetchRequest) -> GatewayFetchFuture + Send + Sync + Clone + 'static {
        let fetcher = self.clone();
        move |request| {
            let fetcher = fetcher.clone();
            Box::pin(async move { fetcher.fetch(request).await })
        }
    }
    /// Fetch the manifest payload associated with this context.
    pub async fn fetch_manifest(&self) -> Result<GatewayFetchedManifest, GatewayManifestError> {
        self.inner.fetch_manifest().await
    }
}
/// Future returned by the gateway fetcher closure.
pub type GatewayFetchFuture =
    Pin<Box<dyn Future<Output = Result<ChunkResponse, GatewayFetchError>> + Send>>;
struct GatewayFetcherInner {
    engine: Arc<dyn HttpEngine>,
    manifest_id_hex: String,
    chunker_header: HeaderValue,
    manifest_envelope: Option<HeaderValue>,
    client_header: Option<HeaderValue>,
    blinded_header: Option<HeaderValue>,
    salt_epoch_header: Option<HeaderValue>,
    cache_version: Option<String>,
    providers: HashMap<String, Arc<ProviderRuntime>>,
}
impl GatewayFetcherInner {
    async fn fetch(&self, request: FetchRequest) -> Result<ChunkResponse, GatewayFetchError> {
        let provider_alias = request.provider.id().as_str().to_string();
        let provider = self
            .providers
            .get(&provider_alias)
            .ok_or_else(|| GatewayFetchError::UnknownProvider {
                provider: provider_alias.clone(),
            })?
            .clone();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| GatewayFetchError::SystemClockBeforeUnixEpoch)?
            .as_secs();
        if now >= provider.ttl_epoch {
            return Err(GatewayFetchError::ExpiredStreamToken {
                provider: provider_alias,
            });
        }
        let digest_hex = hex::encode(request.spec.digest);
        let url = provider
            .base_url
            .join(&format!(
                "v1/sorafs/storage/chunk/{}/{}",
                self.manifest_id_hex, digest_hex
            ))
            .map_err(|source| GatewayFetchError::UrlJoin {
                provider: provider_alias.clone(),
                source,
            })?;
        let nonce = provider.next_nonce(request.spec.chunk_index).map_err(|_| {
            GatewayFetchError::NonceExhausted {
                provider: provider_alias.clone(),
            }
        })?;
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static(HEADER_SORA_CHUNKER),
            self.chunker_header.clone(),
        );
        headers.insert(
            HeaderName::from_static(HEADER_SORA_NONCE),
            header_value(&nonce).map_err(|source| GatewayFetchError::InvalidRequestHeader {
                provider: provider_alias.clone(),
                header: "X-SoraFS-Nonce",
                source,
            })?,
        );
        headers.insert(
            HeaderName::from_static(HEADER_SORA_STREAM_TOKEN),
            provider.stream_token.clone(),
        );
        if let Some(value) = &self.manifest_envelope {
            headers.insert(
                HeaderName::from_static(HEADER_SORA_MANIFEST_ENVELOPE),
                value.clone(),
            );
        }
        if let Some(value) = &self.client_header {
            headers.insert(HeaderName::from_static(HEADER_SORA_CLIENT), value.clone());
        }
        if let Some(value) = &self.blinded_header {
            headers.insert(
                HeaderName::from_static(HEADER_SORA_REQ_BLINDED_CID),
                value.clone(),
            );
            if let Some(epoch) = &self.salt_epoch_header {
                headers.insert(
                    HeaderName::from_static(HEADER_SORA_REQ_SALT_EPOCH),
                    epoch.clone(),
                );
            }
            headers.insert(
                HeaderName::from_static(HEADER_SORA_REQ_NONCE),
                header_value(&nonce).map_err(|source| GatewayFetchError::InvalidRequestHeader {
                    provider: provider_alias.clone(),
                    header: "Sora-Req-Nonce",
                    source,
                })?,
            );
        }
        let max_response_bytes = usize::try_from(request.spec.length)
            .unwrap_or(usize::MAX)
            .saturating_add(MAX_GATEWAY_ERROR_BODY_BYTES)
            .min(MAX_GATEWAY_RESPONSE_BYTES);
        let response = self
            .engine
            .get(HttpRequest {
                url,
                headers,
                max_response_bytes,
            })
            .await
            .map_err(|error| match error {
                HttpError::Transport(source) => GatewayFetchError::Request {
                    provider: provider_alias.clone(),
                    source,
                },
                HttpError::Body(source) => GatewayFetchError::RequestBody {
                    provider: provider_alias.clone(),
                    source,
                },
                HttpError::ResponseTooLarge { limit } => GatewayFetchError::ResponseTooLarge {
                    provider: provider_alias.clone(),
                    limit,
                },
                #[cfg(test)]
                HttpError::TestEngine(message) => GatewayFetchError::TestEngine {
                    provider: provider_alias.clone(),
                    message,
                },
            })?;
        if !response.status.is_success() {
            if response.status == StatusCode::TOO_MANY_REQUESTS {
                return Err(GatewayFetchError::RateLimited {
                    provider: provider_alias,
                    retry_after: retry_after_delay(
                        response.headers.get(reqwest::header::RETRY_AFTER),
                        SystemTime::now(),
                    ),
                });
            }
            if let Some(evidence) = extract_failure_evidence(&response) {
                return Err(GatewayFetchError::PolicyBlocked {
                    provider: provider_alias,
                    evidence,
                });
            }
            let body = if response.body.is_empty() {
                None
            } else {
                Some(truncate(&String::from_utf8_lossy(&response.body), 512))
            };
            return Err(GatewayFetchError::UnexpectedStatus {
                provider: provider_alias,
                status: response.status,
                body,
            });
        }
        let cache_version = observed_cache_version(&response.headers);
        if let Some(expected) = &self.cache_version
            && cache_version.as_deref() != Some(expected.as_str())
        {
            return Err(GatewayFetchError::CacheVersionMismatch {
                provider: provider_alias,
                expected: expected.clone(),
                observed: cache_version,
                status: response.status,
            });
        }
        Ok(ChunkResponse::new(response.body))
    }
    async fn fetch_manifest(&self) -> Result<GatewayFetchedManifest, GatewayManifestError> {
        if self.providers.is_empty() {
            return Err(GatewayManifestError::NoProviders);
        }
        let manifest_path = format!("v1/sorafs/storage/manifest/{}", self.manifest_id_hex);
        let mut last_error: Option<GatewayManifestError> = None;
        for (alias, runtime) in &self.providers {
            let url = match runtime.base_url.join(&manifest_path) {
                Ok(url) => url,
                Err(err) => {
                    last_error = Some(GatewayManifestError::Request {
                        provider: alias.clone(),
                        error: format!("failed to join manifest URL: {err}"),
                    });
                    continue;
                }
            };
            let mut headers = HeaderMap::new();
            if let Some(envelope) = &self.manifest_envelope {
                headers.insert(
                    HeaderName::from_static(HEADER_SORA_MANIFEST_ENVELOPE),
                    envelope.clone(),
                );
            }
            if let Some(client) = &self.client_header {
                headers.insert(HeaderName::from_static(HEADER_SORA_CLIENT), client.clone());
            }
            if let Some(blinded) = &self.blinded_header {
                headers.insert(
                    HeaderName::from_static(HEADER_SORA_REQ_BLINDED_CID),
                    blinded.clone(),
                );
                if let Some(epoch) = &self.salt_epoch_header {
                    headers.insert(
                        HeaderName::from_static(HEADER_SORA_REQ_SALT_EPOCH),
                        epoch.clone(),
                    );
                }
            }
            let response = match self
                .engine
                .get(HttpRequest {
                    url,
                    headers,
                    max_response_bytes: MAX_GATEWAY_RESPONSE_BYTES,
                })
                .await
            {
                Ok(response) => response,
                Err(err) => {
                    let error = match err {
                        HttpError::Transport(source) => format!("request failed: {source}"),
                        HttpError::Body(source) => format!("body read failed: {source}"),
                        HttpError::ResponseTooLarge { limit } => {
                            format!("response exceeded {limit}-byte limit")
                        }
                        #[cfg(test)]
                        HttpError::TestEngine(message) => message,
                    };
                    last_error = Some(GatewayManifestError::Request {
                        provider: alias.clone(),
                        error,
                    });
                    continue;
                }
            };
            if !response.status.is_success() {
                if let Some(evidence) = extract_failure_evidence(&response) {
                    let detail = format!(
                        "gateway blocked request (status={}, code={}, source={}, catalog_digest_hex={})",
                        evidence.observed_status,
                        evidence.code,
                        evidence.source,
                        evidence.catalog_digest_hex
                    );
                    last_error = Some(GatewayManifestError::Status {
                        provider: alias.clone(),
                        status: evidence.observed_status,
                        body: Some(detail),
                    });
                    continue;
                }
                let body = if response.body.is_empty() {
                    None
                } else {
                    Some(truncate(&String::from_utf8_lossy(&response.body), 512))
                };
                last_error = Some(GatewayManifestError::Status {
                    provider: alias.clone(),
                    status: response.status,
                    body,
                });
                continue;
            }
            let cache_version = observed_cache_version(&response.headers);
            if let Some(expected) = &self.cache_version
                && cache_version.as_deref() != Some(expected.as_str())
            {
                last_error = Some(GatewayManifestError::CacheVersionMismatch {
                    provider: alias.clone(),
                    expected: expected.clone(),
                    observed: cache_version.clone(),
                    status: response.status,
                });
                continue;
            }
            match parse_manifest_response(
                alias,
                &self.manifest_id_hex,
                &response.body,
                cache_version.clone(),
            ) {
                Ok(manifest) => return Ok(manifest),
                Err(err) => last_error = Some(err),
            }
        }
        Err(last_error.unwrap_or(GatewayManifestError::NoProviders))
    }
}
fn header_value(value: impl AsRef<str>) -> Result<HeaderValue, InvalidHeaderValue> {
    HeaderValue::from_str(value.as_ref())
}
fn truncate(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_string();
    }
    let mut truncated = text.chars().take(max).collect::<String>();
    truncated.push('…');
    truncated
}
fn observed_cache_version(headers: &HeaderMap) -> Option<String> {
    headers
        .get(HEADER_SORA_CACHE_VERSION)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty() && value.len() <= MAX_CACHE_VERSION_BYTES)
        .map(ToOwned::to_owned)
}
/// Convert an HTTP retry hint to a bounded duration once; the scheduler then uses monotonic time.
/// Both delay-seconds and HTTP-date follow RFC 9110 section 10.2.3:
/// <https://www.rfc-editor.org/rfc/rfc9110.html#name-retry-after>.
fn retry_after_delay(value: Option<&HeaderValue>, now: SystemTime) -> Duration {
    const MINIMUM: Duration = Duration::from_secs(1);
    const MAXIMUM: Duration = Duration::from_secs(86_400);
    let Some(value) = value.and_then(|value| value.to_str().ok()) else {
        return MINIMUM;
    };
    if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
        // An overflowing but syntactically valid delay is still a long cooldown.
        return Duration::from_secs(value.parse::<u64>().unwrap_or(u64::MAX))
            .clamp(MINIMUM, MAXIMUM);
    }
    httpdate::parse_http_date(value)
        .ok()
        .and_then(|date| date.duration_since(now).ok())
        .unwrap_or(MINIMUM)
        .clamp(MINIMUM, MAXIMUM)
}

fn extract_failure_evidence(response: &HttpResponse) -> Option<GatewayFailureEvidence> {
    // Obsolete local-evidence headers make an otherwise valid body noncanonical.
    if response.status != StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS
        || response.headers.contains_key("sora-moderation-token")
        || response.headers.contains_key("sora-denylist-version")
    {
        return None;
    }
    let value = json::from_slice::<Value>(&response.body).ok()?;
    let object = value.as_object()?;
    if object.len() != 3 {
        return None;
    }
    let code = object.get("error")?.as_str()?;
    let source = object.get("source")?.as_str()?;
    let catalog_digest_hex = object.get("catalog_digest_hex")?.as_str()?;
    if code != GATEWAY_COMPLIANCE_DENIED_CODE
        || !is_canonical_gateway_compliance_source(source)
        || !is_canonical_catalog_digest_hex(catalog_digest_hex)
    {
        return None;
    }
    Some(GatewayFailureEvidence {
        observed_status: response.status,
        code: code.to_owned(),
        source: source.to_owned(),
        catalog_digest_hex: catalog_digest_hex.to_owned(),
    })
}
/// Return whether a governed decision source can deny a request in V1.
pub(crate) fn is_canonical_gateway_compliance_source(source: &str) -> bool {
    source == GATEWAY_COMPLIANCE_SOURCE_BASELINE
        || source == GATEWAY_COMPLIANCE_SOURCE_LEGAL_SAFETY_HOLD
}
/// Return whether a catalog digest is exact lowercase 32-byte hexadecimal text.
pub(crate) fn is_canonical_catalog_digest_hex(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
#[derive(Debug)]
struct ProviderRuntime {
    base_url: Url,
    stream_token: HeaderValue,
    token_id: String,
    ttl_epoch: u64,
    nonce_prefix: [u8; 16],
    nonce: AtomicU64,
    _privacy_events_url: Option<Url>,
}
impl ProviderRuntime {
    fn next_nonce(&self, chunk_index: usize) -> Result<String, NonceExhausted> {
        let counter = self
            .nonce
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .map_err(|_| NonceExhausted)?;
        Ok(format!(
            "{}-{}-{chunk_index}-{counter}",
            self.token_id,
            hex::encode(self.nonce_prefix)
        ))
    }
}
#[derive(Debug, Clone, Copy)]
struct NonceExhausted;
#[derive(Debug)]
struct ProviderDescriptor {
    provider: FetchProvider,
}
#[derive(Debug)]
struct NormalisedConfig {
    manifest_id: String,
    chunker_handle: String,
    chunker_header: HeaderValue,
    manifest_envelope: Option<HeaderValue>,
    client_header: Option<HeaderValue>,
    expected_manifest_cid_hex: Option<String>,
    blinded_header: Option<HeaderValue>,
    salt_epoch_header: Option<HeaderValue>,
    cache_version: Option<String>,
}
impl NormalisedConfig {
    fn from_config(config: GatewayFetchConfig) -> Result<Self, GatewayBuildError> {
        let manifest_id = config.manifest_id_normalised();
        if manifest_id.len() != 64 || !manifest_id.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(GatewayBuildError::InvalidManifestId { manifest_id });
        }
        let GatewayFetchConfig {
            manifest_id_hex: _,
            chunker_handle,
            manifest_envelope_b64,
            client_id,
            expected_manifest_cid_hex,
            blinded_cid_b64,
            salt_epoch,
            expected_cache_version,
        } = config;
        let chunker_handle = chunker_handle.trim().to_string();
        if chunker_handle.is_empty() || chunker_handle.len() > MAX_CHUNKER_HANDLE_BYTES {
            return Err(GatewayBuildError::EmptyChunkerHandle);
        }
        let chunker_header = HeaderValue::from_str(&chunker_handle).map_err(|_| {
            GatewayBuildError::InvalidHeader {
                header: HEADER_SORA_CHUNKER,
                reason: "chunker handle contains invalid ASCII",
            }
        })?;
        let manifest_envelope = if let Some(value) = manifest_envelope_b64 {
            let trimmed = value.trim();
            if trimmed != value
                || trimmed.is_empty()
                || trimmed.len() > MAX_MANIFEST_ENVELOPE_BASE64_BYTES
            {
                return Err(GatewayBuildError::InvalidHeader {
                    header: HEADER_SORA_MANIFEST_ENVELOPE,
                    reason: "manifest envelope must be non-empty and within the size limit",
                });
            }
            let decoded = STANDARD.decode(trimmed.as_bytes()).map_err(|_| {
                GatewayBuildError::InvalidHeader {
                    header: HEADER_SORA_MANIFEST_ENVELOPE,
                    reason: "manifest envelope must contain valid base64",
                }
            })?;
            if decoded.is_empty() {
                return Err(GatewayBuildError::InvalidHeader {
                    header: HEADER_SORA_MANIFEST_ENVELOPE,
                    reason: "manifest envelope must not be empty",
                });
            }
            if STANDARD.encode(&decoded) != trimmed {
                return Err(GatewayBuildError::InvalidHeader {
                    header: HEADER_SORA_MANIFEST_ENVELOPE,
                    reason: "manifest envelope must use canonical base64",
                });
            }
            Some(
                HeaderValue::from_str(trimmed).map_err(|_| GatewayBuildError::InvalidHeader {
                    header: HEADER_SORA_MANIFEST_ENVELOPE,
                    reason: "manifest envelope must contain valid ASCII",
                })?,
            )
        } else {
            None
        };
        let client_header = if let Some(id) = client_id {
            let trimmed = id.trim();
            if trimmed.is_empty() || trimmed.len() > MAX_CLIENT_ID_BYTES {
                return Err(GatewayBuildError::InvalidHeader {
                    header: HEADER_SORA_CLIENT,
                    reason: "client identifier must be non-empty and within the size limit",
                });
            }
            Some(
                HeaderValue::from_str(trimmed).map_err(|_| GatewayBuildError::InvalidHeader {
                    header: HEADER_SORA_CLIENT,
                    reason: "client identifier must contain valid ASCII",
                })?,
            )
        } else {
            None
        };
        let expected_manifest_cid_hex = match expected_manifest_cid_hex {
            Some(cid) => {
                if cid.len() != MAX_MANIFEST_ROOT_CID_BYTES * 2
                    || !cid
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                {
                    return Err(GatewayBuildError::InvalidExpectedManifestCid);
                }
                let bytes =
                    hex::decode(&cid).map_err(|_| GatewayBuildError::InvalidExpectedManifestCid)?;
                validate_manifest_root_cid(
                    &bytes,
                    sorafs_manifest::chunker_registry::MANIFEST_DAG_CODEC,
                    BLAKE3_256_MULTIHASH_CODE,
                )
                .map_err(|_| GatewayBuildError::InvalidExpectedManifestCid)?;
                Some(cid)
            }
            None => None,
        };
        let (blinded_header, salt_epoch_header) = match (blinded_cid_b64, salt_epoch) {
            (Some(blinded), Some(epoch)) => {
                let trimmed = blinded.trim();
                if trimmed != blinded || trimmed.is_empty() {
                    return Err(GatewayBuildError::InvalidHeader {
                        header: HEADER_SORA_REQ_BLINDED_CID,
                        reason: "value must not be empty",
                    });
                }
                let decoded = URL_SAFE_NO_PAD.decode(trimmed.as_bytes()).map_err(|_| {
                    GatewayBuildError::InvalidHeader {
                        header: HEADER_SORA_REQ_BLINDED_CID,
                        reason: "value must be URL-safe base64 without padding",
                    }
                })?;
                if decoded.len() != 32 {
                    return Err(GatewayBuildError::InvalidHeader {
                        header: HEADER_SORA_REQ_BLINDED_CID,
                        reason: "decoded value must be 32 bytes",
                    });
                }
                if URL_SAFE_NO_PAD.encode(&decoded) != trimmed {
                    return Err(GatewayBuildError::InvalidHeader {
                        header: HEADER_SORA_REQ_BLINDED_CID,
                        reason: "value must use canonical URL-safe base64 without padding",
                    });
                }
                let header = HeaderValue::from_str(trimmed).map_err(|_| {
                    GatewayBuildError::InvalidHeader {
                        header: HEADER_SORA_REQ_BLINDED_CID,
                        reason: "value must contain valid ASCII",
                    }
                })?;
                let epoch_string = epoch.to_string();
                let epoch_header = HeaderValue::from_str(&epoch_string).map_err(|_| {
                    GatewayBuildError::InvalidHeader {
                        header: HEADER_SORA_REQ_SALT_EPOCH,
                        reason: "epoch must be ASCII digits",
                    }
                })?;
                (Some(header), Some(epoch_header))
            }
            (Some(_), None) => return Err(GatewayBuildError::MissingSaltEpoch),
            (None, Some(_)) => return Err(GatewayBuildError::SaltEpochWithoutBlindedCid),
            (None, None) => (None, None),
        };
        let cache_version = if let Some(version) = expected_cache_version {
            let trimmed = version.trim();
            if trimmed.is_empty() || trimmed.len() > MAX_CACHE_VERSION_BYTES {
                return Err(GatewayBuildError::InvalidHeader {
                    header: HEADER_SORA_CACHE_VERSION,
                    reason: "expected cache version must be non-empty and within the size limit",
                });
            }
            Some(trimmed.to_string())
        } else {
            None
        };
        Ok(Self {
            manifest_id,
            chunker_handle,
            chunker_header,
            manifest_envelope,
            client_header,
            expected_manifest_cid_hex,
            blinded_header,
            salt_epoch_header,
            cache_version,
        })
    }
}
impl ProviderDescriptor {
    fn from_input(
        config: &NormalisedConfig,
        input: GatewayProviderInput,
        providers: &mut HashMap<String, Arc<ProviderRuntime>>,
        provider_ids: &mut HashSet<[u8; 32]>,
        selected: Option<&AuthenticatedGeneratedLocalProviderTransportV1>,
    ) -> Result<Self, GatewayBuildError> {
        if input.name.is_empty()
            || input.name.len() > MAX_PROVIDER_NAME_BYTES
            || !input.name.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-')
            })
        {
            return Err(GatewayBuildError::InvalidProviderName);
        }
        if providers.contains_key(&input.name) {
            return Err(GatewayBuildError::DuplicateProvider {
                provider_id: input.name.clone(),
            });
        }
        let provider_id_hex = input.provider_id_hex.clone();
        let provider_id = decode_provider_id(&provider_id_hex).map_err(|source| {
            GatewayBuildError::InvalidProviderId {
                provider_id: provider_id_hex.clone(),
                source,
            }
        })?;
        if provider_id.iter().all(|byte| *byte == 0) {
            return Err(GatewayBuildError::ZeroProviderId);
        }
        if !provider_ids.insert(provider_id) {
            return Err(GatewayBuildError::DuplicateProviderId { provider_id_hex });
        }
        let gateway_public_key = decode_gateway_public_key(&input.gateway_public_key_hex)?;
        let base_url = match selected {
            Some(local) => local.validate_input(&input)?,
            None => parse_base_url(&input.base_url).map_err(|source| {
                GatewayBuildError::InvalidBaseUrl {
                    provider_id: provider_id_hex.clone(),
                    source,
                }
            })?,
        };
        let privacy_events_url = match input.privacy_events_url.as_ref() {
            Some(raw) => Some(parse_privacy_url(raw).map_err(|source| {
                GatewayBuildError::InvalidPrivacyUrl {
                    provider_id: provider_id_hex.clone(),
                    source,
                }
            })?),
            None => None,
        };
        let token = match decode_stream_token(&input.stream_token_b64) {
            Ok(token) => token,
            Err(source) => {
                return Err(GatewayBuildError::InvalidStreamToken {
                    provider_id: provider_id_hex.into_boxed_str(),
                    source,
                });
            }
        };
        token.verify(&gateway_public_key).map_err(|source| {
            GatewayBuildError::InvalidStreamTokenSignature {
                provider_id: provider_id_hex.clone(),
                source,
            }
        })?;
        if token.body.issued_at >= token.body.ttl_epoch
            || token.body.ttl_epoch - token.body.issued_at > STREAM_TOKEN_MAX_TTL_SECS_V1
        {
            return Err(GatewayBuildError::InvalidStreamTokenLifetime {
                provider_id: provider_id_hex.clone(),
            });
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| GatewayBuildError::SystemClockBeforeUnixEpoch)?
            .as_secs();
        if now >= token.body.ttl_epoch {
            return Err(GatewayBuildError::ExpiredStreamToken {
                provider_id: provider_id_hex.clone(),
            });
        }
        if token.body.issued_at > now.saturating_add(STREAM_TOKEN_CLOCK_SKEW_SECS) {
            return Err(GatewayBuildError::FutureStreamToken {
                provider_id: provider_id_hex.clone(),
            });
        }
        if token.body.token_id.is_empty()
            || token.body.token_id.len() > MAX_STREAM_TOKEN_ID_BYTES
            || !token
                .body
                .token_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(GatewayBuildError::InvalidStreamTokenId {
                provider_id: provider_id_hex.clone(),
            });
        }
        if validate_manifest_root_cid(
            &token.body.manifest_cid,
            sorafs_manifest::chunker_registry::MANIFEST_DAG_CODEC,
            BLAKE3_256_MULTIHASH_CODE,
        )
        .is_err()
        {
            return Err(GatewayBuildError::InvalidStreamTokenManifestCid {
                provider_id: provider_id_hex.clone(),
            });
        }
        if token.body.token_pk_version == 0
            || token.body.rate_limit_bytes == 0
            || token.body.requests_per_minute == 0
        {
            return Err(GatewayBuildError::InvalidStreamTokenBudget {
                provider_id: provider_id_hex.clone(),
            });
        }
        if token.body.provider_id != provider_id {
            return Err(GatewayBuildError::ProviderIdMismatch {
                provider_id: provider_id_hex.clone(),
                token_provider_id: hex::encode(token.body.provider_id),
            });
        }
        if token.body.profile_handle != config.chunker_handle {
            return Err(GatewayBuildError::ProfileMismatch {
                provider_id: provider_id_hex.clone(),
                token_profile: token.body.profile_handle.clone(),
                expected: config.chunker_handle.clone(),
            });
        }
        if let Some(expected_cid) = &config.expected_manifest_cid_hex {
            let token_cid = hex::encode(token.body.manifest_cid.as_slice());
            if token_cid != *expected_cid {
                return Err(GatewayBuildError::ManifestCidMismatch {
                    provider_id: provider_id_hex.clone(),
                    expected: expected_cid.clone(),
                    actual: token_cid,
                });
            }
        }
        let max_streams = usize::from(token.body.max_streams);
        let capacity = NonZeroUsize::new(max_streams).ok_or_else(|| {
            GatewayBuildError::ZeroStreamCapacity {
                provider_id: provider_id_hex.clone(),
            }
        })?;
        let mut metadata = ProviderMetadata::new();
        metadata.provider_id = Some(provider_id_hex.clone());
        metadata.profile_id = Some(config.chunker_handle.clone());
        metadata.max_streams = Some(token.body.max_streams);
        metadata.requests_per_minute = Some(token.body.requests_per_minute);
        metadata
            .capability_names
            .push("chunk_range_fetch".to_string());
        metadata.transport_hints.push(TransportHint {
            protocol: "torii-http-range".to_string(),
            protocol_id: 1,
            priority: 0,
        });
        metadata.privacy_events_url = privacy_events_url.as_ref().map(ToString::to_string);
        metadata.stream_budget = Some(StreamBudget {
            max_in_flight: token.body.max_streams,
            max_bytes_per_sec: token.body.rate_limit_bytes,
            burst_bytes: None,
        });
        metadata.range_capability = Some(RangeCapability {
            max_chunk_span: u32::MAX,
            min_granularity: 1,
            supports_sparse_offsets: true,
            requires_alignment: false,
            supports_merkle_proof: true,
        });
        metadata.profile_aliases.push(input.name.clone());
        let provider = FetchProvider::new(input.name.clone())
            .with_max_concurrent_chunks(capacity)
            .with_metadata(metadata);
        let mut nonce_prefix = [0u8; 16];
        let mut rng = OsRng;
        rng.try_fill_bytes(&mut nonce_prefix)
            .map_err(|source| GatewayBuildError::RandomBytes {
                message: source.to_string(),
            })?;
        if nonce_prefix.iter().all(|byte| *byte == 0) {
            return Err(GatewayBuildError::RandomBytes {
                message: "operating system returned an all-zero nonce prefix".to_owned(),
            });
        }
        let runtime = ProviderRuntime {
            base_url,
            stream_token: HeaderValue::from_str(input.stream_token_b64.trim()).map_err(|_| {
                GatewayBuildError::InvalidHeader {
                    header: HEADER_SORA_STREAM_TOKEN,
                    reason: "stream token must contain valid ASCII",
                }
            })?,
            token_id: token.body.token_id.clone(),
            ttl_epoch: token.body.ttl_epoch,
            nonce_prefix,
            nonce: AtomicU64::new(0),
            _privacy_events_url: privacy_events_url,
        };
        providers.insert(input.name, Arc::new(runtime));
        Ok(Self { provider })
    }
}
fn decode_provider_id(value: &str) -> Result<[u8; 32], ProviderIdDecodeError> {
    let decoded = hex::decode(value).map_err(ProviderIdDecodeError::InvalidHex)?;
    let actual = decoded.len();
    if actual != 32 {
        return Err(ProviderIdDecodeError::InvalidLength { actual });
    }
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(ProviderIdDecodeError::NonCanonical);
    }
    decoded
        .try_into()
        .map_err(|_| ProviderIdDecodeError::InvalidLength { actual })
}
fn decode_gateway_public_key(value: &str) -> Result<VerifyingKey, GatewayBuildError> {
    let trimmed = value.trim();
    if trimmed != value
        || trimmed.len() != 64
        || !trimmed
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(GatewayBuildError::InvalidGatewayPublicKey);
    }
    let decoded = hex::decode(trimmed).map_err(|_| GatewayBuildError::InvalidGatewayPublicKey)?;
    let bytes: [u8; 32] = decoded
        .try_into()
        .map_err(|_| GatewayBuildError::InvalidGatewayPublicKey)?;
    let key =
        VerifyingKey::from_bytes(&bytes).map_err(|_| GatewayBuildError::InvalidGatewayPublicKey)?;
    if key.is_weak() {
        return Err(GatewayBuildError::InvalidGatewayPublicKey);
    }
    Ok(key)
}
fn parse_base_url(value: &str) -> Result<Url, GatewayUrlError> {
    let url = parse_gateway_url(value)?;
    if url.path() != "/" {
        return Err(GatewayUrlError::InvalidPath);
    }
    Ok(url)
}
fn parse_privacy_url(value: &str) -> Result<Url, GatewayUrlError> {
    let url = parse_gateway_url(value)?;
    if url.path() != "/privacy/events" {
        return Err(GatewayUrlError::InvalidPath);
    }
    Ok(url)
}
fn parse_gateway_url(value: &str) -> Result<Url, GatewayUrlError> {
    if value != value.trim() || value.len() > 2_048 {
        return Err(GatewayUrlError::NonCanonical);
    }
    let url = Url::parse(value).map_err(GatewayUrlError::Parse)?;
    let canonical = url.as_str();
    let omitted_root_slash = canonical
        .strip_suffix('/')
        .is_some_and(|without_slash| value == without_slash && url.path() == "/");
    if value != canonical && !omitted_root_slash {
        return Err(GatewayUrlError::NonCanonical);
    }
    if url.scheme() != "https" {
        return Err(GatewayUrlError::InsecureScheme);
    }
    if url.port_or_known_default().is_none_or(|port| port == 0) {
        return Err(GatewayUrlError::ZeroPort);
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(GatewayUrlError::Credentials);
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(GatewayUrlError::QueryOrFragment);
    }
    let host = url.host().ok_or(GatewayUrlError::MissingHost)?;
    match host {
        url::Host::Ipv4(address) if !is_public_ip(IpAddr::V4(address)) => {
            return Err(GatewayUrlError::NonPublicAddress);
        }
        url::Host::Ipv6(address) if !is_public_ip(IpAddr::V6(address)) => {
            return Err(GatewayUrlError::NonPublicAddress);
        }
        url::Host::Domain(name) if name == "localhost" || name.ends_with(".localhost") => {
            return Err(GatewayUrlError::NonPublicAddress);
        }
        _ => {}
    }
    Ok(url)
}
fn is_public_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let [first, second, third, _] = address.octets();
            !address.is_private()
                && !address.is_loopback()
                && !address.is_link_local()
                && !address.is_broadcast()
                && !address.is_documentation()
                && !address.is_unspecified()
                && !address.is_multicast()
                && first != 0
                && !(first == 100 && (64..=127).contains(&second))
                && !(first == 192 && second == 0 && third == 0)
                && !(first == 192 && second == 88 && third == 99)
                && !(first == 198 && (18..=19).contains(&second))
                && first < 240
        }
        IpAddr::V6(address) => {
            let segments = address.segments();
            let global_unicast = segments[0] & 0xe000 == 0x2000;
            let documentation = (segments[0] == 0x2001 && segments[1] == 0x0db8)
                || (segments[0] == 0x3fff && segments[1] & 0xf000 == 0);
            let special_purpose = segments[0] == 0x2001 && segments[1] <= 0x01ff;
            let six_to_four = segments[0] == 0x2002;
            global_unicast
                && !documentation
                && !special_purpose
                && !six_to_four
                && !address.is_loopback()
                && !address.is_unspecified()
                && !address.is_multicast()
        }
    }
}
fn resolve_public_host(
    url: &Url,
    resolved_hosts: &mut BTreeMap<String, Vec<SocketAddr>>,
) -> Result<(), GatewayBuildError> {
    let host = url
        .host_str()
        .ok_or(GatewayBuildError::GatewayDnsResolution)?;
    if url
        .host()
        .is_some_and(|host| matches!(host, url::Host::Ipv4(_) | url::Host::Ipv6(_)))
    {
        return Ok(());
    }
    if resolved_hosts.contains_key(host) {
        return Ok(());
    }
    let port = url.port_or_known_default().unwrap_or(443);
    let mut addresses = (host, port)
        .to_socket_addrs()
        .map_err(|_| GatewayBuildError::GatewayDnsResolution)?
        .collect::<Vec<_>>();
    addresses.sort_unstable();
    addresses.dedup();
    if addresses.is_empty()
        || addresses.len() > MAX_DNS_ADDRESSES_PER_HOST
        || addresses.iter().any(|address| !is_public_ip(address.ip()))
    {
        return Err(GatewayBuildError::GatewayDnsResolution);
    }
    resolved_hosts.insert(host.to_owned(), addresses);
    Ok(())
}
#[derive(Debug, Error)]
pub enum GatewayUrlError {
    #[error("URL parse failed: {0}")]
    Parse(#[source] url::ParseError),
    #[error("URL must be canonical and at most 2048 bytes")]
    NonCanonical,
    #[error("URL must use HTTPS")]
    InsecureScheme,
    #[error("URL must use a nonzero HTTPS port")]
    ZeroPort,
    #[error("URL credentials are forbidden")]
    Credentials,
    #[error("URL query strings and fragments are forbidden")]
    QueryOrFragment,
    #[error("URL host is required")]
    MissingHost,
    #[error("literal URL host is not globally routable")]
    NonPublicAddress,
    #[error("URL path is not the required canonical endpoint")]
    InvalidPath,
}
fn decode_stream_token(value: &str) -> Result<StreamTokenV1, StreamTokenDecodeError> {
    let trimmed = value.trim();
    if trimmed != value {
        return Err(StreamTokenDecodeError::NonCanonicalBase64);
    }
    if trimmed.len() > STREAM_TOKEN_MAX_BASE64_BYTES_V1 {
        return Err(StreamTokenDecodeError::Oversized);
    }
    let bytes = STANDARD
        .decode(trimmed.as_bytes())
        .map_err(StreamTokenDecodeError::InvalidBase64)?;
    if bytes.len() > STREAM_TOKEN_MAX_WIRE_BYTES_V1 {
        return Err(StreamTokenDecodeError::Oversized);
    }
    if STANDARD.encode(&bytes) != trimmed {
        return Err(StreamTokenDecodeError::NonCanonicalBase64);
    }
    let limits = norito::DecodeLimits::new(
        STREAM_TOKEN_MAX_WIRE_BYTES_V1,
        bytes.len(),
        STREAM_TOKEN_MAX_WIRE_BYTES_V1.saturating_mul(2),
        STREAM_TOKEN_MAX_WIRE_BYTES_V1.saturating_mul(4),
        32,
    );
    norito::decode_canonical_with_limits(&bytes, limits).map_err(|error| match error {
        norito::Error::NonCanonicalEncoding => StreamTokenDecodeError::NonCanonicalPayload,
        other => StreamTokenDecodeError::InvalidPayload(other),
    })
}
/// Errors emitted while constructing the gateway fetcher.
#[derive(Debug, Error)]
pub enum GatewayBuildError {
    #[error("failed to construct HTTP client: {0}")]
    ClientBuild(reqwest::Error),
    #[error("gateway timeouts must be nonzero and connect must not exceed request")]
    InvalidTimeouts,
    /// Explicit source trust roots were empty, excessive or invalid DER.
    #[error("gateway pinned TLS roots are invalid")]
    InvalidPinnedTlsRoots,
    /// Provider inputs differ from the exact original joined local transport.
    #[error("gateway inputs do not match the selected generated-local transport")]
    InvalidGeneratedLocalTransport,
    #[error("failed to obtain secure random bytes for gateway nonces: {message}")]
    RandomBytes { message: String },
    #[error("gateway DNS resolution returned no exclusively public addresses")]
    GatewayDnsResolution,
    #[error("too many gateway providers; maximum is {maximum}")]
    TooManyProviders { maximum: usize },
    #[error("at least one gateway provider is required")]
    NoProviders,
    #[error("provider name is empty, oversized, or noncanonical")]
    InvalidProviderName,
    #[error("manifest identifier must be a 32-byte hex string: {manifest_id}")]
    InvalidManifestId { manifest_id: String },
    #[error("chunker handle must not be empty")]
    EmptyChunkerHandle,
    #[error("expected manifest CID must be canonical lowercase hex of CIDv1 dag-cbor/BLAKE3-256")]
    InvalidExpectedManifestCid,
    #[error("invalid {header} header: {reason}")]
    InvalidHeader {
        header: &'static str,
        reason: &'static str,
    },
    #[error("Sora-Req-Salt-Epoch must be provided when Sora-Req-Blinded-CID is set")]
    MissingSaltEpoch,
    #[error("Sora-Req-Salt-Epoch cannot be supplied without Sora-Req-Blinded-CID")]
    SaltEpochWithoutBlindedCid,
    #[error("duplicate provider identifier `{provider_id}`")]
    DuplicateProvider { provider_id: String },
    #[error("provider identifier `{provider_id}` must be 32-byte hex: {source}")]
    InvalidProviderId {
        provider_id: String,
        #[source]
        source: ProviderIdDecodeError,
    },
    #[error("provider identifier must not be all zero")]
    ZeroProviderId,
    #[error("provider identifier `{provider_id_hex}` is configured more than once")]
    DuplicateProviderId { provider_id_hex: String },
    #[error("gateway public key must be canonical strong 32-byte Ed25519 hex")]
    InvalidGatewayPublicKey,
    #[error(
        "stream token provider id `{token_provider_id}` does not match provider `{provider_id}`"
    )]
    ProviderIdMismatch {
        provider_id: String,
        token_provider_id: String,
    },
    #[error("provider `{provider_id}` URL parse error: {source}")]
    InvalidBaseUrl {
        provider_id: String,
        source: GatewayUrlError,
    },
    #[error("provider `{provider_id}` privacy events URL parse error: {source}")]
    InvalidPrivacyUrl {
        provider_id: String,
        source: GatewayUrlError,
    },
    #[error("provider `{provider_id}` stream token decode error: {source}")]
    InvalidStreamToken {
        provider_id: Box<str>,
        source: StreamTokenDecodeError,
    },
    #[error("provider `{provider_id}` stream token signature is invalid: {source}")]
    InvalidStreamTokenSignature {
        provider_id: String,
        #[source]
        source: sorafs_manifest::StreamTokenError,
    },
    #[error("provider `{provider_id}` stream token lifetime is inverted")]
    InvalidStreamTokenLifetime { provider_id: String },
    #[error("provider `{provider_id}` stream token is expired")]
    ExpiredStreamToken { provider_id: String },
    #[error("provider `{provider_id}` stream token was issued too far in the future")]
    FutureStreamToken { provider_id: String },
    #[error("provider `{provider_id}` stream token id is noncanonical")]
    InvalidStreamTokenId { provider_id: String },
    #[error("provider `{provider_id}` stream token manifest CID is empty or oversized")]
    InvalidStreamTokenManifestCid { provider_id: String },
    #[error("provider `{provider_id}` stream token contains a zero key version or budget")]
    InvalidStreamTokenBudget { provider_id: String },
    #[error("system clock is before the Unix epoch")]
    SystemClockBeforeUnixEpoch,
    #[error("provider `{provider_id}` stream token declares zero max_streams")]
    ZeroStreamCapacity { provider_id: String },
    #[error(
        "provider `{provider_id}` stream token profile `{token_profile}` \
         does not match expected chunker handle `{expected}`"
    )]
    ProfileMismatch {
        provider_id: String,
        token_profile: String,
        expected: String,
    },
    #[error(
        "provider `{provider_id}` stream token manifest CID mismatch (expected {expected}, got {actual})"
    )]
    ManifestCidMismatch {
        provider_id: String,
        expected: String,
        actual: String,
    },
}
/// Errors returned when decoding a fixed-width gateway provider identifier.
#[derive(Debug, Clone, Copy, Error)]
pub enum ProviderIdDecodeError {
    /// The identifier was not valid hexadecimal text.
    #[error("invalid hexadecimal encoding: {0}")]
    InvalidHex(#[source] FromHexError),
    /// The decoded identifier was not exactly 32 bytes.
    #[error("decoded length is {actual} bytes, expected 32")]
    InvalidLength {
        /// Actual decoded byte length.
        actual: usize,
    },
    /// The identifier used uppercase hexadecimal or surrounding whitespace.
    #[error("identifier must be canonical lowercase hexadecimal without whitespace")]
    NonCanonical,
}
/// Errors surfaced while fetching manifests from gateways.
#[derive(Debug, Error)]
pub enum GatewayManifestError {
    /// No providers were registered with the fetch context.
    #[error("no providers configured for manifest fetch")]
    NoProviders,
    /// HTTP request failed (transport or body read error).
    #[error("provider `{provider}` manifest request failed: {error}")]
    Request { provider: String, error: String },
    /// Manifest endpoint returned a non-success status.
    #[error("provider `{provider}` manifest request returned status {status}: {body:?}")]
    Status {
        provider: String,
        status: StatusCode,
        body: Option<String>,
    },
    /// Gateway did not advertise the expected cache version.
    #[error(
        "provider `{provider}` manifest response advertised cache version {observed:?} but expected {expected} (status {status})"
    )]
    CacheVersionMismatch {
        provider: String,
        expected: String,
        observed: Option<String>,
        status: StatusCode,
    },
    /// Manifest response was missing a required field.
    #[error("provider `{provider}` manifest response missing `{field}`")]
    MissingField {
        provider: String,
        field: &'static str,
    },
    /// Manifest payload failed to decode from Base64.
    #[error("provider `{provider}` manifest payload base64 decode failed: {error}")]
    Base64 { provider: String, error: String },
    /// Manifest payload failed to decode as Norito.
    #[error("provider `{provider}` manifest decode failed: {error}")]
    Decode { provider: String, error: String },
    /// Manifest digest provided by the gateway did not match the decoded payload.
    #[error("provider `{provider}` manifest digest mismatch (expected {expected}, got {actual})")]
    DigestMismatch {
        provider: String,
        expected: String,
        actual: String,
    },
    /// The valid manifest returned by the gateway was not the manifest addressed by the request.
    #[error("provider `{provider}` returned manifest {actual} for requested manifest {expected}")]
    ManifestIdMismatch {
        provider: String,
        expected: String,
        actual: String,
    },
}
/// Parsed manifest details fetched from a gateway endpoint.
#[derive(Debug, Clone)]
pub struct GatewayFetchedManifest {
    /// Raw manifest payload as returned by the gateway.
    pub manifest_bytes: Vec<u8>,
    /// Decoded Norito manifest.
    pub manifest: ManifestV1,
    /// Canonical manifest digest advertised by the gateway.
    pub manifest_digest: blake3::Hash,
    /// BLAKE3 digest of the payload captured during ingestion.
    pub payload_digest: blake3::Hash,
    /// Total content length recorded for the manifest.
    pub content_length: u64,
    /// Number of chunks recorded by the gateway.
    pub chunk_count: u64,
    /// Chunking profile handle stored alongside the manifest.
    pub chunk_profile_handle: String,
    /// Cache version advertised by the gateway response.
    pub cache_version: Option<String>,
}
fn parse_manifest_response(
    provider: &str,
    expected_manifest_id_hex: &str,
    body: &[u8],
    cache_version: Option<String>,
) -> Result<GatewayFetchedManifest, GatewayManifestError> {
    let value: Value = json::from_slice(body).map_err(|err| GatewayManifestError::Decode {
        provider: provider.to_string(),
        error: err.to_string(),
    })?;
    let manifest_b64 = value
        .get("manifest_b64")
        .and_then(Value::as_str)
        .ok_or_else(|| GatewayManifestError::MissingField {
            provider: provider.to_string(),
            field: "manifest_b64",
        })?;
    if manifest_b64.len() > MAX_GATEWAY_RESPONSE_BYTES {
        return Err(GatewayManifestError::Decode {
            provider: provider.to_string(),
            error: "manifest_b64 exceeds the gateway response limit".to_owned(),
        });
    }
    let manifest_bytes =
        STANDARD
            .decode(manifest_b64.as_bytes())
            .map_err(|err| GatewayManifestError::Base64 {
                provider: provider.to_string(),
                error: err.to_string(),
            })?;
    if STANDARD.encode(&manifest_bytes) != manifest_b64 {
        return Err(GatewayManifestError::Decode {
            provider: provider.to_string(),
            error: "manifest_b64 must use canonical standard base64".to_owned(),
        });
    }
    let manifest: ManifestV1 = decode_manifest_v1_canonical(&manifest_bytes).map_err(|err| {
        GatewayManifestError::Decode {
            provider: provider.to_string(),
            error: err.to_string(),
        }
    })?;
    let manifest_digest_hex = value
        .get("manifest_digest_hex")
        .and_then(Value::as_str)
        .ok_or_else(|| GatewayManifestError::MissingField {
            provider: provider.to_string(),
            field: "manifest_digest_hex",
        })?;
    if manifest_digest_hex.len() != 64
        || !manifest_digest_hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(GatewayManifestError::Decode {
            provider: provider.to_string(),
            error: "manifest_digest_hex must be canonical lowercase 32-byte hex".to_owned(),
        });
    }
    let computed_digest = manifest
        .digest()
        .map_err(|err| GatewayManifestError::Decode {
            provider: provider.to_string(),
            error: err.to_string(),
        })?;
    let computed_digest_hex = hex::encode(computed_digest.as_bytes());
    if manifest_digest_hex != computed_digest_hex {
        return Err(GatewayManifestError::DigestMismatch {
            provider: provider.to_string(),
            expected: manifest_digest_hex.to_owned(),
            actual: computed_digest_hex,
        });
    }
    if computed_digest_hex != expected_manifest_id_hex {
        return Err(GatewayManifestError::ManifestIdMismatch {
            provider: provider.to_string(),
            expected: expected_manifest_id_hex.to_owned(),
            actual: computed_digest_hex,
        });
    }
    let payload_digest_hex = value
        .get("payload_digest_hex")
        .and_then(Value::as_str)
        .ok_or_else(|| GatewayManifestError::MissingField {
            provider: provider.to_string(),
            field: "payload_digest_hex",
        })?;
    if payload_digest_hex.len() != 64
        || !payload_digest_hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(GatewayManifestError::Decode {
            provider: provider.to_string(),
            error: "payload_digest_hex must be canonical lowercase 32-byte hex".to_owned(),
        });
    }
    let payload_bytes =
        hex::decode(payload_digest_hex).map_err(|err| GatewayManifestError::Decode {
            provider: provider.to_string(),
            error: format!("payload_digest_hex decode failed: {err}"),
        })?;
    if payload_bytes.len() != 32 {
        return Err(GatewayManifestError::Decode {
            provider: provider.to_string(),
            error: "payload_digest_hex must decode to 32 bytes".into(),
        });
    }
    let mut payload_digest_bytes = [0u8; 32];
    payload_digest_bytes.copy_from_slice(&payload_bytes);
    let payload_digest = blake3::Hash::from_bytes(payload_digest_bytes);
    let content_length = value
        .get("content_length")
        .and_then(Value::as_u64)
        .ok_or_else(|| GatewayManifestError::MissingField {
            provider: provider.to_string(),
            field: "content_length",
        })?;
    if content_length != manifest.content_length {
        return Err(GatewayManifestError::Decode {
            provider: provider.to_string(),
            error: "content_length does not match the decoded manifest".to_owned(),
        });
    }
    let chunk_count = value
        .get("chunk_count")
        .and_then(Value::as_u64)
        .ok_or_else(|| GatewayManifestError::MissingField {
            provider: provider.to_string(),
            field: "chunk_count",
        })?;
    let chunk_profile_handle = value
        .get("chunk_profile_handle")
        .and_then(Value::as_str)
        .ok_or_else(|| GatewayManifestError::MissingField {
            provider: provider.to_string(),
            field: "chunk_profile_handle",
        })?
        .to_string();
    let manifest_profile_handle = format!(
        "{}.{}@{}",
        manifest.chunking.namespace, manifest.chunking.name, manifest.chunking.semver
    );
    if chunk_profile_handle != manifest_profile_handle {
        return Err(GatewayManifestError::Decode {
            provider: provider.to_string(),
            error: "chunk_profile_handle does not match the decoded manifest".to_owned(),
        });
    }
    Ok(GatewayFetchedManifest {
        manifest_bytes,
        manifest,
        manifest_digest: computed_digest,
        payload_digest,
        content_length,
        chunk_count,
        chunk_profile_handle,
        cache_version,
    })
}
/// Errors encountered while fetching chunks from a gateway.
#[derive(Debug, Error)]
pub enum GatewayFetchError {
    /// A healthy gateway deferred admission; this is not a provider-health failure.
    #[error("provider `{provider}` rate limited the request; retry after {retry_after:?}")]
    RateLimited {
        /// Provider that returned HTTP 429.
        provider: String,
        /// Minimum delay before another request to this provider.
        retry_after: Duration,
    },
    #[error("no configuration registered for provider `{provider}`")]
    UnknownProvider { provider: String },
    #[error("provider `{provider}` stream token expired before request dispatch")]
    ExpiredStreamToken { provider: String },
    #[error("system clock is before the Unix epoch")]
    SystemClockBeforeUnixEpoch,
    #[error("provider `{provider}` exhausted its request nonce space")]
    NonceExhausted { provider: String },
    #[error("failed to construct {header} request header for provider `{provider}`: {source}")]
    InvalidRequestHeader {
        provider: String,
        header: &'static str,
        #[source]
        source: InvalidHeaderValue,
    },
    #[error("failed to join chunk URL for provider `{provider}`: {source}")]
    UrlJoin {
        provider: String,
        source: url::ParseError,
    },
    #[error("request to provider `{provider}` failed: {source}")]
    Request {
        provider: String,
        #[source]
        source: reqwest::Error,
    },
    #[error(
        "provider `{provider}` cache version mismatch (expected {expected}, observed {observed:?}) with status {status}"
    )]
    CacheVersionMismatch {
        provider: String,
        expected: String,
        observed: Option<String>,
        status: StatusCode,
    },
    #[error("failed to read response from provider `{provider}`: {source}")]
    RequestBody {
        provider: String,
        #[source]
        source: reqwest::Error,
    },
    #[error("provider `{provider}` response exceeds the {limit}-byte safety limit")]
    ResponseTooLarge { provider: String, limit: usize },
    #[error(
        "provider `{provider}` blocked request (status={status}, code={code}, source={decision_source}, catalog_digest_hex={catalog_digest_hex})",
        status = .evidence.observed_status,
        code = .evidence.code,
        decision_source = .evidence.source,
        catalog_digest_hex = .evidence.catalog_digest_hex,
    )]
    PolicyBlocked {
        provider: String,
        evidence: GatewayFailureEvidence,
    },
    #[error("provider `{provider}` returned unexpected status {status}: {body:?}")]
    UnexpectedStatus {
        provider: String,
        status: StatusCode,
        body: Option<String>,
    },
    #[cfg(test)]
    #[error("provider `{provider}` test-engine error: {message}")]
    TestEngine { provider: String, message: String },
}
impl From<GatewayFetchError> for AttemptFailure {
    fn from(error: GatewayFetchError) -> Self {
        Self::from(&error)
    }
}
impl From<&GatewayFetchError> for AttemptFailure {
    fn from(error: &GatewayFetchError) -> Self {
        let message = error.to_string();
        let policy_block = match &error {
            GatewayFetchError::PolicyBlocked { evidence, .. } => {
                Some(PolicyBlockEvidence::from(evidence))
            }
            _ => None,
        };
        AttemptFailure::Provider {
            message,
            policy_block,
        }
    }
}
impl From<&GatewayFailureEvidence> for PolicyBlockEvidence {
    fn from(evidence: &GatewayFailureEvidence) -> Self {
        PolicyBlockEvidence {
            observed_status: evidence.observed_status,
            code: evidence.code.clone(),
            source: evidence.source.clone(),
            catalog_digest_hex: evidence.catalog_digest_hex.clone(),
        }
    }
}
/// Stream token decoding errors surfaced during configuration.
#[derive(Debug, Error)]
pub enum StreamTokenDecodeError {
    #[error("stream token exceeds the maximum encoded size")]
    Oversized,
    #[error("stream token must use canonical base64 without surrounding whitespace")]
    NonCanonicalBase64,
    #[error("stream token is not valid base64")]
    InvalidBase64(base64::DecodeError),
    #[error("stream token payload is not valid Norito")]
    InvalidPayload(norito::Error),
    #[error("stream token payload is not the exact canonical Norito encoding")]
    NonCanonicalPayload,
}
impl fmt::Display for GatewayFetcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GatewayFetcher(providers={})",
            self.inner.providers.len()
        )
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use sorafs_chunker::ChunkProfile;
    use sorafs_manifest::StreamTokenBodyV1;
    use std::{
        collections::HashMap,
        sync::{Arc, Mutex},
    };
    #[test]
    fn request_header_value_rejects_control_characters_without_panicking() {
        assert!(header_value("valid-nonce").is_ok());
        assert!(header_value("invalid\nnonce").is_err());
        assert!(header_value("invalid\0nonce").is_err());
    }
    use crate::{CarBuildPlan, ChunkFetchSpec, multi_fetch::FetchProvider};
    #[test]
    fn retry_after_accepts_seconds_and_http_dates_with_bounded_delays() {
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let header = |value: &str| HeaderValue::from_str(value).unwrap();
        assert_eq!(retry_after_delay(None, now), Duration::from_secs(1));
        for (value, seconds) in [
            ("0", 1),
            ("1", 1),
            ("60", 60),
            ("86400", 86_400),
            ("86401", 86_400),
            ("18446744073709551615", 86_400),
            ("18446744073709551616", 86_400),
            ("", 1),
            ("+60", 1),
            ("-60", 1),
            ("1.5", 1),
            ("not-a-date", 1),
        ] {
            assert_eq!(
                retry_after_delay(Some(&header(value)), now),
                Duration::from_secs(seconds),
                "{value}"
            );
        }
        for (date, expected) in [
            (now - Duration::from_secs(60), Duration::from_secs(1)),
            (now, Duration::from_secs(1)),
            (now + Duration::from_secs(60), Duration::from_secs(60)),
            (
                now + Duration::from_secs(86_401),
                Duration::from_secs(86_400),
            ),
        ] {
            let value = header(&httpdate::fmt_http_date(date));
            assert_eq!(retry_after_delay(Some(&value), now), expected);
        }
        let value = header(&httpdate::fmt_http_date(now + Duration::from_secs(2)));
        assert_eq!(
            retry_after_delay(Some(&value), now + Duration::from_millis(500)),
            Duration::from_millis(1500)
        );
        assert_eq!(
            retry_after_delay(Some(&HeaderValue::from_bytes(&[0xff]).unwrap()), now),
            Duration::from_secs(1)
        );
    }
    fn sample_payload(len: usize) -> Vec<u8> {
        (0..len).map(|idx| (idx % 251) as u8).collect()
    }
    fn sample_stream_token(
        manifest_cid_hex: &str,
        provider_id_hex: &str,
        profile: &str,
        max_streams: u16,
    ) -> StreamTokenV1 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_secs();
        StreamTokenV1::sign(
            StreamTokenBodyV1 {
                token_id: "0123456789abcdef0123456789abcdef".to_string(),
                manifest_cid: hex::decode(manifest_cid_hex).expect("cid hex"),
                provider_id: {
                    let mut bytes = [0u8; 32];
                    bytes.copy_from_slice(&hex::decode(provider_id_hex).expect("provider hex"));
                    bytes
                },
                profile_handle: profile.to_string(),
                max_streams,
                ttl_epoch: now + STREAM_TOKEN_MAX_TTL_SECS_V1,
                rate_limit_bytes: 8 * 1024 * 1024,
                issued_at: now,
                requests_per_minute: 120,
                token_pk_version: 1,
            },
            &gateway_signing_key(),
        )
        .expect("sign sample stream token")
    }
    fn encode_token_b64(token: &StreamTokenV1) -> String {
        let bytes = norito::encode_canonical(token).expect("encode token");
        STANDARD.encode(bytes)
    }
    fn plan_for_payload(payload: &[u8]) -> CarBuildPlan {
        CarBuildPlan::single_file_with_profile(payload, ChunkProfile::DEFAULT).expect("build plan")
    }
    fn manifest_id_from_payload(payload: &[u8]) -> String {
        hex::encode(blake3::hash(payload).as_bytes())
    }
    fn sample_manifest_cid_hex() -> String {
        hex::encode(sorafs_manifest::canonical_manifest_root_cid([0x11; 32]))
    }
    fn manifest_root_cid_for_payload(payload: &[u8]) -> String {
        let plan = plan_for_payload(payload);
        let stats = crate::CarWriter::new(&plan, payload)
            .expect("native CAR writer")
            .write_to(std::io::sink())
            .expect("native CAR root");
        hex::encode(&stats.root_cids[0])
    }
    fn provider_id_hex() -> String {
        "ab".repeat(32)
    }
    fn gateway_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[0x42; 32])
    }
    fn gateway_public_key_hex() -> String {
        hex::encode(gateway_signing_key().verifying_key().to_bytes())
    }
    fn chunker_handle() -> String {
        "sorafs.sf1@1.0.0".to_string()
    }
    fn gateway_config(manifest_id_hex: &str, chunker_handle: &str) -> GatewayFetchConfig {
        GatewayFetchConfig {
            manifest_id_hex: manifest_id_hex.to_owned(),
            chunker_handle: chunker_handle.to_owned(),
            manifest_envelope_b64: None,
            client_id: None,
            expected_manifest_cid_hex: None,
            blinded_cid_b64: None,
            salt_epoch: None,
            expected_cache_version: None,
        }
    }
    fn gateway_provider_input(token: &StreamTokenV1) -> GatewayProviderInput {
        GatewayProviderInput {
            name: "alpha".to_owned(),
            provider_id_hex: hex::encode(token.body.provider_id),
            gateway_public_key_hex: gateway_public_key_hex(),
            base_url: "https://gateway.example/".to_owned(),
            stream_token_b64: encode_token_b64(token),
            privacy_events_url: None,
        }
    }
    fn fixture_manifest_response() -> Value {
        let manifest_bytes =
            include_bytes!("../../../fixtures/sorafs_manifest/ci_sample/manifest.to").to_vec();
        let manifest: ManifestV1 =
            norito::decode_from_bytes(&manifest_bytes).expect("fixture manifest");
        let digest = manifest.digest().expect("manifest digest");
        let profile = format!(
            "{}.{}@{}",
            manifest.chunking.namespace, manifest.chunking.name, manifest.chunking.semver
        );
        let mut object = norito::json::Map::new();
        object.insert(
            "manifest_b64".to_owned(),
            Value::String(STANDARD.encode(manifest_bytes)),
        );
        object.insert(
            "manifest_digest_hex".to_owned(),
            Value::String(hex::encode(digest.as_bytes())),
        );
        object.insert(
            "payload_digest_hex".to_owned(),
            Value::String("11".repeat(32)),
        );
        object.insert(
            "content_length".to_owned(),
            Value::from(manifest.content_length),
        );
        object.insert("chunk_count".to_owned(), Value::from(1_u64));
        object.insert("chunk_profile_handle".to_owned(), Value::String(profile));
        Value::Object(object)
    }
    #[test]
    fn manifest_response_requires_canonical_manifest_bound_metadata() {
        let canonical = fixture_manifest_response();
        let expected_manifest_id = canonical
            .get("manifest_digest_hex")
            .and_then(Value::as_str)
            .expect("manifest digest")
            .to_owned();
        let body = json::to_vec(&canonical).expect("response JSON");
        parse_manifest_response("alpha", &expected_manifest_id, &body, None)
            .expect("canonical response");
        assert!(matches!(
            parse_manifest_response("alpha", &"ff".repeat(32), &body, None),
            Err(GatewayManifestError::ManifestIdMismatch { .. })
        ));
        for (field, replacement) in [
            (
                "manifest_digest_hex",
                Value::String(
                    canonical
                        .get("manifest_digest_hex")
                        .and_then(Value::as_str)
                        .expect("digest")
                        .to_ascii_uppercase(),
                ),
            ),
            ("content_length", Value::from(0_u64)),
            (
                "chunk_profile_handle",
                Value::String("sorafs.other@1.0.0".to_owned()),
            ),
        ] {
            let mut tampered = canonical.clone();
            tampered
                .as_object_mut()
                .expect("object")
                .insert(field.to_owned(), replacement);
            let body = json::to_vec(&tampered).expect("response JSON");
            assert!(
                parse_manifest_response("alpha", &expected_manifest_id, &body, None).is_err(),
                "tampered {field} must be rejected"
            );
        }
        let mut trailing = canonical.clone();
        let mut manifest_bytes = STANDARD
            .decode(
                canonical
                    .get("manifest_b64")
                    .and_then(Value::as_str)
                    .expect("manifest base64"),
            )
            .expect("decode fixture manifest");
        manifest_bytes.push(0xA5);
        trailing.as_object_mut().expect("object").insert(
            "manifest_b64".to_owned(),
            Value::String(STANDARD.encode(manifest_bytes)),
        );
        let body = json::to_vec(&trailing).expect("response JSON");
        assert!(matches!(
            parse_manifest_response("alpha", &expected_manifest_id, &body, None),
            Err(GatewayManifestError::Decode { .. })
        ));
        let mut oversized = canonical;
        oversized.as_object_mut().expect("object").insert(
            "manifest_b64".to_owned(),
            Value::String(
                STANDARD.encode(vec![0_u8; sorafs_manifest::MAX_MANIFEST_ENCODED_BYTES + 1]),
            ),
        );
        let body = json::to_vec(&oversized).expect("response JSON");
        assert!(matches!(
            parse_manifest_response("alpha", &expected_manifest_id, &body, None),
            Err(GatewayManifestError::Decode { .. })
        ));
    }
    fn build_test_context(
        config: GatewayFetchConfig,
        providers: impl IntoIterator<Item = GatewayProviderInput>,
    ) -> Result<GatewayFetchContext, GatewayBuildError> {
        GatewayFetchContext::build_with_engine(
            config,
            providers,
            Arc::new(MockHttpEngine::new(HashMap::new())),
        )
    }
    #[test]
    fn manifest_envelope_rejects_invalid_base64() {
        let config = GatewayFetchConfig {
            manifest_id_hex: manifest_id_from_payload(&[1, 2, 3, 4]),
            chunker_handle: chunker_handle(),
            manifest_envelope_b64: Some("!!not-base64!!".to_string()),
            client_id: None,
            expected_manifest_cid_hex: None,
            blinded_cid_b64: None,
            salt_epoch: None,
            expected_cache_version: None,
        };
        let err = NormalisedConfig::from_config(config).expect_err("manifest envelope should fail");
        match err {
            GatewayBuildError::InvalidHeader { header, reason } => {
                assert_eq!(header, HEADER_SORA_MANIFEST_ENVELOPE);
                assert_eq!(reason, "manifest envelope must contain valid base64");
            }
            other => panic!("unexpected error: {other}"),
        }
    }
    #[test]
    fn provider_id_mismatch_is_rejected() {
        let payload = sample_payload(1024);
        let manifest_id_hex = manifest_id_from_payload(&payload);
        let manifest_cid_hex = manifest_root_cid_for_payload(&payload);
        let provider_id = provider_id_hex();
        let token_provider_id = "cd".repeat(32);
        let chunker = chunker_handle();
        let token = sample_stream_token(&manifest_cid_hex, &token_provider_id, &chunker, 2);
        let token_b64 = encode_token_b64(&token);
        let config = GatewayFetchConfig {
            manifest_id_hex: manifest_id_hex.clone(),
            chunker_handle: chunker,
            manifest_envelope_b64: None,
            client_id: None,
            expected_manifest_cid_hex: None,
            blinded_cid_b64: None,
            salt_epoch: None,
            expected_cache_version: None,
        };
        let input = GatewayProviderInput {
            name: "provider-1".to_string(),
            provider_id_hex: provider_id.clone(),
            gateway_public_key_hex: gateway_public_key_hex(),
            base_url: "https://example.invalid".to_string(),
            stream_token_b64: token_b64,
            privacy_events_url: None,
        };
        let err = GatewayFetchContext::build_with_engine(
            config,
            vec![input],
            Arc::new(MockHttpEngine::new(HashMap::new())),
        )
        .expect_err("should fail");
        match err {
            GatewayBuildError::ProviderIdMismatch {
                provider_id: found,
                token_provider_id: token_id,
            } => {
                assert_eq!(found, provider_id);
                assert_eq!(token_id, token_provider_id);
            }
            other => panic!("unexpected error: {other}"),
        }
    }
    #[test]
    fn provider_id_decoder_rejects_wrong_digest_sizes_without_panicking() {
        for actual in [0usize, 1, 31, 33, 64] {
            let encoded = "ab".repeat(actual);
            let outcome = std::panic::catch_unwind(|| decode_provider_id(&encoded));
            let result = outcome.expect("wrong provider-id length must not panic");
            assert!(matches!(
                result,
                Err(ProviderIdDecodeError::InvalidLength { actual: found }) if found == actual
            ));
        }
        let outcome = std::panic::catch_unwind(|| decode_provider_id("not-hex"));
        let result = outcome.expect("invalid provider-id hex must not panic");
        assert!(matches!(result, Err(ProviderIdDecodeError::InvalidHex(_))));
        assert!(matches!(
            decode_provider_id(&"AB".repeat(32)),
            Err(ProviderIdDecodeError::NonCanonical)
        ));
        assert!(matches!(
            decode_provider_id(&format!(" {}", "ab".repeat(32))),
            Err(ProviderIdDecodeError::InvalidHex(_))
        ));
    }
    #[test]
    fn gateway_context_requires_at_least_one_provider() {
        let config = gateway_config(&"11".repeat(32), &chunker_handle());
        assert!(matches!(
            build_test_context(config, []),
            Err(GatewayBuildError::NoProviders)
        ));
    }
    #[test]
    fn gateway_context_rejects_invalid_explicit_timeouts_before_network_access() {
        let config = gateway_config(&"11".repeat(32), &chunker_handle());
        assert!(matches!(
            GatewayFetchContext::new_with_timeouts(
                config.clone(),
                [],
                Duration::ZERO,
                Duration::from_secs(1),
            ),
            Err(GatewayBuildError::InvalidTimeouts)
        ));
        assert!(matches!(
            GatewayFetchContext::new_with_timeouts(
                config,
                [],
                Duration::from_secs(2),
                Duration::from_secs(1),
            ),
            Err(GatewayBuildError::InvalidTimeouts)
        ));
    }
    #[test]
    fn provider_configuration_rejects_duplicate_canonical_provider_ids() {
        let manifest_id = "11".repeat(32);
        let profile = chunker_handle();
        let token =
            sample_stream_token(&sample_manifest_cid_hex(), &provider_id_hex(), &profile, 2);
        let first = gateway_provider_input(&token);
        let mut second = first.clone();
        second.name = "beta".to_owned();
        assert!(matches!(
            build_test_context(gateway_config(&manifest_id, &profile), [first, second]),
            Err(GatewayBuildError::DuplicateProviderId { .. })
        ));
    }
    #[test]
    fn provider_configuration_rejects_invalid_signature_and_key() {
        let manifest_id = "11".repeat(32);
        let profile = chunker_handle();
        let mut token =
            sample_stream_token(&sample_manifest_cid_hex(), &provider_id_hex(), &profile, 2);
        token.body.max_streams = 3;
        assert!(matches!(
            build_test_context(
                gateway_config(&manifest_id, &profile),
                [gateway_provider_input(&token)]
            ),
            Err(GatewayBuildError::InvalidStreamTokenSignature { .. })
        ));
        let token =
            sample_stream_token(&sample_manifest_cid_hex(), &provider_id_hex(), &profile, 2);
        let mut wrong_key = gateway_provider_input(&token);
        wrong_key.gateway_public_key_hex = hex::encode(
            SigningKey::from_bytes(&[0x43; 32])
                .verifying_key()
                .to_bytes(),
        );
        assert!(matches!(
            build_test_context(gateway_config(&manifest_id, &profile), [wrong_key]),
            Err(GatewayBuildError::InvalidStreamTokenSignature { .. })
        ));
        let mut weak_key = gateway_provider_input(&token);
        weak_key.gateway_public_key_hex = "00".repeat(32);
        assert!(matches!(
            build_test_context(gateway_config(&manifest_id, &profile), [weak_key]),
            Err(GatewayBuildError::InvalidGatewayPublicKey)
        ));
    }
    #[test]
    fn provider_nonces_are_process_unique_and_fail_closed_on_counter_exhaustion() {
        let manifest_id = "11".repeat(32);
        let profile = chunker_handle();
        let token =
            sample_stream_token(&sample_manifest_cid_hex(), &provider_id_hex(), &profile, 2);
        let context = build_test_context(
            gateway_config(&manifest_id, &profile),
            [gateway_provider_input(&token)],
        )
        .expect("context");
        let runtime = context
            .fetcher
            .inner
            .providers
            .get("alpha")
            .expect("provider runtime");
        let first = runtime.next_nonce(7).expect("first nonce");
        let second = runtime.next_nonce(7).expect("second nonce");
        assert_ne!(first, second);
        assert!(first.ends_with("-7-0"));
        assert!(second.ends_with("-7-1"));
        assert_eq!(first.split('-').nth_back(2).map(str::len), Some(32));
        runtime.nonce.store(u64::MAX, Ordering::Relaxed);
        assert!(runtime.next_nonce(7).is_err());
    }
    #[test]
    fn provider_configuration_rejects_invalid_token_lifetimes() {
        let manifest_id = "11".repeat(32);
        let profile = chunker_handle();
        let sample =
            sample_stream_token(&sample_manifest_cid_hex(), &provider_id_hex(), &profile, 2);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_secs();
        let mut maximum_body = sample.body.clone();
        maximum_body.issued_at = now;
        maximum_body.ttl_epoch = now + STREAM_TOKEN_MAX_TTL_SECS_V1;
        let maximum = StreamTokenV1::sign(maximum_body, &gateway_signing_key()).expect("sign");
        build_test_context(
            gateway_config(&manifest_id, &profile),
            [gateway_provider_input(&maximum)],
        )
        .expect("the exact maximum token lifetime is accepted");
        let mut boundary_expired_body = sample.body.clone();
        boundary_expired_body.issued_at = now.saturating_sub(1);
        boundary_expired_body.ttl_epoch = now;
        let boundary_expired =
            StreamTokenV1::sign(boundary_expired_body, &gateway_signing_key()).expect("sign");
        assert!(matches!(
            build_test_context(
                gateway_config(&manifest_id, &profile),
                [gateway_provider_input(&boundary_expired)]
            ),
            Err(GatewayBuildError::ExpiredStreamToken { .. })
        ));
        let mut expired_body = sample.body.clone();
        expired_body.issued_at = now.saturating_sub(120);
        expired_body.ttl_epoch = now.saturating_sub(1);
        let expired = StreamTokenV1::sign(expired_body, &gateway_signing_key()).expect("sign");
        assert!(matches!(
            build_test_context(
                gateway_config(&manifest_id, &profile),
                [gateway_provider_input(&expired)]
            ),
            Err(GatewayBuildError::ExpiredStreamToken { .. })
        ));
        let mut future_body = sample.body.clone();
        // Keep the rejection outside the allowed skew even if the wall clock crosses a
        // second boundary while the real signature/context checks execute.
        future_body.issued_at = now.saturating_add(STREAM_TOKEN_CLOCK_SKEW_SECS + 60);
        future_body.ttl_epoch = future_body.issued_at.saturating_add(60);
        let future = StreamTokenV1::sign(future_body, &gateway_signing_key()).expect("sign");
        assert!(matches!(
            build_test_context(
                gateway_config(&manifest_id, &profile),
                [gateway_provider_input(&future)]
            ),
            Err(GatewayBuildError::FutureStreamToken { .. })
        ));
        let mut inverted_body = sample.body;
        inverted_body.issued_at = now;
        inverted_body.ttl_epoch = now;
        let inverted = StreamTokenV1::sign(inverted_body, &gateway_signing_key()).expect("sign");
        assert!(matches!(
            build_test_context(
                gateway_config(&manifest_id, &profile),
                [gateway_provider_input(&inverted)]
            ),
            Err(GatewayBuildError::InvalidStreamTokenLifetime { .. })
        ));
        let sample =
            sample_stream_token(&sample_manifest_cid_hex(), &provider_id_hex(), &profile, 2);
        let mut oversized_lifetime_body = sample.body;
        oversized_lifetime_body.issued_at = now;
        oversized_lifetime_body.ttl_epoch = now + STREAM_TOKEN_MAX_TTL_SECS_V1 + 1;
        let oversized_lifetime =
            StreamTokenV1::sign(oversized_lifetime_body, &gateway_signing_key()).expect("sign");
        assert!(matches!(
            build_test_context(
                gateway_config(&manifest_id, &profile),
                [gateway_provider_input(&oversized_lifetime)]
            ),
            Err(GatewayBuildError::InvalidStreamTokenLifetime { .. })
        ));
    }
    #[test]
    fn provider_configuration_rejects_unbounded_or_noncanonical_token_fields() {
        let manifest_id = "11".repeat(32);
        let profile = chunker_handle();
        let sample =
            sample_stream_token(&sample_manifest_cid_hex(), &provider_id_hex(), &profile, 2);
        let mut empty_id_body = sample.body.clone();
        empty_id_body.token_id.clear();
        let empty_id = StreamTokenV1::sign(empty_id_body, &gateway_signing_key()).expect("sign");
        assert!(matches!(
            build_test_context(
                gateway_config(&manifest_id, &profile),
                [gateway_provider_input(&empty_id)]
            ),
            Err(GatewayBuildError::InvalidStreamTokenId { .. })
        ));
        let mut oversized_cid_body = sample.body.clone();
        oversized_cid_body.manifest_cid = vec![0x42; MAX_MANIFEST_ROOT_CID_BYTES + 1];
        let oversized_cid =
            StreamTokenV1::sign(oversized_cid_body, &gateway_signing_key()).expect("sign");
        assert!(matches!(
            build_test_context(
                gateway_config(&manifest_id, &profile),
                [gateway_provider_input(&oversized_cid)]
            ),
            Err(GatewayBuildError::InvalidStreamTokenManifestCid { .. })
        ));
        for mutate in [
            |body: &mut StreamTokenBodyV1| body.token_pk_version = 0,
            |body: &mut StreamTokenBodyV1| body.rate_limit_bytes = 0,
            |body: &mut StreamTokenBodyV1| body.requests_per_minute = 0,
        ] {
            let mut zero_budget_body = sample.body.clone();
            mutate(&mut zero_budget_body);
            let zero_budget =
                StreamTokenV1::sign(zero_budget_body, &gateway_signing_key()).expect("sign");
            assert!(matches!(
                build_test_context(
                    gateway_config(&manifest_id, &profile),
                    [gateway_provider_input(&zero_budget)]
                ),
                Err(GatewayBuildError::InvalidStreamTokenBudget { .. })
            ));
        }
        let mut spaced_profile_body = sample.body;
        spaced_profile_body.profile_handle = format!(" {profile}");
        let spaced_profile =
            StreamTokenV1::sign(spaced_profile_body, &gateway_signing_key()).expect("sign");
        assert!(matches!(
            build_test_context(
                gateway_config(&manifest_id, &profile),
                [gateway_provider_input(&spaced_profile)]
            ),
            Err(GatewayBuildError::ProfileMismatch { .. })
        ));
    }
    #[test]
    fn gateway_urls_reject_downgrades_ambiguity_and_nonpublic_literals() {
        for invalid in [
            "http://gateway.example/",
            "https://user@gateway.example/",
            "https://gateway.example:0/",
            "https://localhost:444/",
            "https://provider.localhost:444/",
            "https://gateway.example:443/",
            "HTTPS://gateway.example/",
            "https://Gateway.Example/",
            "https://gateway.example/path",
            "https://gateway.example/?query=1",
            "https://gateway.example/#fragment",
            " https://gateway.example/",
            "https://127.0.0.1/",
            "https://10.0.0.1/",
            "https://169.254.169.254/",
            "https://192.0.2.1/",
            "https://192.88.99.1/",
            "https://[::1]/",
            "https://[fc00::1]/",
            "https://[fe80::1]/",
            "https://[2001:100::1]/",
            "https://[2001:db8::1]/",
            "https://[3fff::1]/",
            "https://[::ffff:127.0.0.1]/",
        ] {
            assert!(
                parse_base_url(invalid).is_err(),
                "unsafe gateway URL was accepted: {invalid}"
            );
        }
        assert!(parse_base_url("https://gateway.example/").is_ok());
        assert!(parse_base_url("https://8.8.8.8/").is_ok());
        for origin in ["https://gateway.example:444/", "https://8.8.8.8:8443/"] {
            let parsed = parse_base_url(origin).unwrap();
            assert_eq!(parsed.as_str(), origin);
            assert_ne!(parsed.port_or_known_default(), Some(443));
        }
        assert!(parse_privacy_url("https://gateway.example/privacy/events").is_ok());
        assert!(parse_privacy_url("https://gateway.example/").is_err());
    }
    #[test]
    fn token_and_header_inputs_are_bounded_and_canonical() {
        let token = sample_stream_token(
            &sample_manifest_cid_hex(),
            &provider_id_hex(),
            &chunker_handle(),
            2,
        );
        let encoded = encode_token_b64(&token);
        assert!(matches!(
            decode_stream_token(&format!(" {encoded}")),
            Err(StreamTokenDecodeError::NonCanonicalBase64)
        ));
        let mut trailing_payload = norito::encode_canonical(&token).expect("canonical token");
        trailing_payload.push(0xA5);
        assert!(matches!(
            decode_stream_token(&STANDARD.encode(trailing_payload)),
            Err(StreamTokenDecodeError::NonCanonicalPayload)
                | Err(StreamTokenDecodeError::InvalidPayload(_))
        ));
        assert!(matches!(
            decode_stream_token(&"A".repeat(STREAM_TOKEN_MAX_BASE64_BYTES_V1 + 1)),
            Err(StreamTokenDecodeError::Oversized)
        ));
        let exact_wire = STANDARD.encode(vec![0_u8; STREAM_TOKEN_MAX_WIRE_BYTES_V1]);
        assert!(matches!(
            decode_stream_token(&exact_wire),
            Err(StreamTokenDecodeError::InvalidPayload(_))
        ));
        let oversized_wire = STANDARD.encode(vec![0_u8; STREAM_TOKEN_MAX_WIRE_BYTES_V1 + 1]);
        assert!(matches!(
            decode_stream_token(&oversized_wire),
            Err(StreamTokenDecodeError::Oversized)
        ));
        let mut config = gateway_config(&"11".repeat(32), &chunker_handle());
        config.expected_manifest_cid_hex = Some("AB".repeat(32));
        assert!(matches!(
            NormalisedConfig::from_config(config),
            Err(GatewayBuildError::InvalidExpectedManifestCid)
        ));
        let mut config = gateway_config(&"11".repeat(32), &chunker_handle());
        config.client_id = Some("x".repeat(MAX_CLIENT_ID_BYTES + 1));
        assert!(matches!(
            NormalisedConfig::from_config(config),
            Err(GatewayBuildError::InvalidHeader {
                header: HEADER_SORA_CLIENT,
                ..
            })
        ));
    }
    #[test]
    fn expected_manifest_cid_accepts_actual_native_root_and_fixture() {
        let fixture = decode_manifest_v1_canonical(include_bytes!(
            "../../../fixtures/sorafs_manifest/ci_sample/manifest.to"
        ))
        .expect("canonical native fixture");
        for cid in [
            hex::encode(&fixture.root_cid),
            manifest_root_cid_for_payload(&sample_payload(8192)),
        ] {
            assert_eq!(cid.len(), MAX_MANIFEST_ROOT_CID_BYTES * 2);
            let mut config = gateway_config(&"11".repeat(32), &chunker_handle());
            config.expected_manifest_cid_hex = Some(cid.clone());
            let token = sample_stream_token(&cid, &provider_id_hex(), &chunker_handle(), 2);
            build_test_context(config.clone(), [gateway_provider_input(&token)])
                .expect("native root and matching signed token");
            let different_token = sample_stream_token(
                &hex::encode(sorafs_manifest::canonical_manifest_root_cid([0x99; 32])),
                &provider_id_hex(),
                &chunker_handle(),
                2,
            );
            assert!(matches!(
                build_test_context(config, [gateway_provider_input(&different_token)]),
                Err(GatewayBuildError::ManifestCidMismatch { .. })
            ));
        }
    }
    #[test]
    fn expected_manifest_cid_rejects_hashes_noncanonical_and_other_cid_formats() {
        let root = sorafs_manifest::canonical_manifest_root_cid([0xab; 32]);
        let mut invalid_cids = vec![
            "ab".repeat(32),
            hex::encode(&root).to_ascii_uppercase(),
            format!(" {}", hex::encode(&root)),
            format!("{}00", hex::encode(&root)),
            hex::encode(&root[..root.len() - 1]),
            hex::encode(sorafs_manifest::canonical_manifest_root_cid([0; 32])),
        ];
        for (offset, value) in [(0, 0), (1, 0x55), (2, 0x12), (3, 31)] {
            let mut malformed = root.clone();
            malformed[offset] = value;
            invalid_cids.push(hex::encode(malformed));
        }
        let mut nonminimal = vec![0x81, 0x00];
        nonminimal.extend_from_slice(&root[1..]);
        invalid_cids.push(hex::encode(nonminimal));
        for cid in invalid_cids {
            let mut config = gateway_config(&"11".repeat(32), &chunker_handle());
            config.expected_manifest_cid_hex = Some(cid);
            assert!(matches!(
                NormalisedConfig::from_config(config),
                Err(GatewayBuildError::InvalidExpectedManifestCid)
            ));
        }
    }
    #[test]
    fn signed_stream_token_requires_canonical_cid_without_optional_expectation() {
        let root = sorafs_manifest::canonical_manifest_root_cid([0xab; 32]);
        for cid in [vec![0xab; 32], vec![0; 36], {
            let mut different_codec = root;
            different_codec[1] = 0x55;
            different_codec
        }] {
            let token =
                sample_stream_token(&hex::encode(cid), &provider_id_hex(), &chunker_handle(), 2);
            assert!(matches!(
                build_test_context(
                    gateway_config(&"11".repeat(32), &chunker_handle()),
                    [gateway_provider_input(&token)],
                ),
                Err(GatewayBuildError::InvalidStreamTokenManifestCid { .. })
            ));
        }
    }
    #[tokio::test(flavor = "multi_thread")]
    async fn gateway_fetcher_serves_chunk_successfully() {
        let payload = sample_payload(8 * 1024);
        let plan = plan_for_payload(&payload);
        let manifest_id_hex = manifest_id_from_payload(&payload);
        let manifest_cid_hex = manifest_root_cid_for_payload(&payload);
        let provider_id = provider_id_hex();
        let chunker_handle = chunker_handle();
        let token = sample_stream_token(&manifest_cid_hex, &provider_id, &chunker_handle, 4);
        let token_b64 = encode_token_b64(&token);
        let path = format!(
            "/v1/sorafs/storage/chunk/{}/{}",
            manifest_id_hex,
            hex::encode(
                plan.try_chunk_fetch_specs().expect("valid CAR plan")[0]
                    .digest
                    .as_slice()
            )
        );
        let mut responses = HashMap::new();
        responses.insert(
            path.clone(),
            HttpResponse {
                status: StatusCode::OK,
                headers: HeaderMap::new(),
                body: payload
                    [0..plan.try_chunk_fetch_specs().expect("valid CAR plan")[0].length as usize]
                    .to_vec(),
            },
        );
        let engine = Arc::new(MockHttpEngine::new(responses));
        let config = GatewayFetchConfig {
            manifest_id_hex: manifest_id_hex.clone(),
            chunker_handle: chunker_handle.clone(),
            manifest_envelope_b64: Some("ZW52ZWxvcGU=".to_string()),
            client_id: Some("orchestrator".to_string()),
            expected_manifest_cid_hex: Some(manifest_cid_hex),
            blinded_cid_b64: None,
            salt_epoch: None,
            expected_cache_version: None,
        };
        let provider_input = GatewayProviderInput {
            name: "alpha".to_string(),
            provider_id_hex: provider_id.clone(),
            gateway_public_key_hex: gateway_public_key_hex(),
            base_url: "https://gateway.example/".to_string(),
            stream_token_b64: token_b64.clone(),
            privacy_events_url: None,
        };
        let context =
            GatewayFetchContext::build_with_engine(config, [provider_input], engine.clone())
                .expect("context");
        let outcome = context
            .execute_plan(&plan, FetchOptions::default())
            .await
            .expect("fetch outcome");
        assert_eq!(
            outcome.chunks.len(),
            plan.try_chunk_fetch_specs().expect("valid CAR plan").len()
        );
        assert_eq!(
            outcome.chunks[0],
            payload[0..plan.try_chunk_fetch_specs().expect("valid CAR plan")[0].length as usize]
        );
        let requests = engine.recorded();
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        assert_eq!(request.path, path);
        assert_eq!(
            request.max_response_bytes,
            usize::try_from(plan.chunks[0].length)
                .expect("chunk length fits usize")
                .saturating_add(MAX_GATEWAY_ERROR_BODY_BYTES)
        );
        assert_eq!(
            request
                .headers
                .get(HEADER_SORA_STREAM_TOKEN)
                .and_then(|value| value.to_str().ok()),
            Some(token_b64.as_str())
        );
        assert_eq!(
            request
                .headers
                .get(HEADER_SORA_CHUNKER)
                .and_then(|value| value.to_str().ok()),
            Some(chunker_handle.as_str())
        );
        assert!(request.headers.contains_key(HEADER_SORA_NONCE));
        assert_eq!(
            request
                .headers
                .get(HEADER_SORA_MANIFEST_ENVELOPE)
                .and_then(|value| value.to_str().ok()),
            Some("ZW52ZWxvcGU=")
        );
        assert_eq!(
            request
                .headers
                .get(HEADER_SORA_CLIENT)
                .and_then(|value| value.to_str().ok()),
            Some("orchestrator")
        );
    }
    #[tokio::test]
    async fn gateway_fetcher_rechecks_token_expiry_before_dispatch() {
        let payload = sample_payload(1024);
        let plan = plan_for_payload(&payload);
        let manifest_id = manifest_id_from_payload(&payload);
        let profile = chunker_handle();
        let token =
            sample_stream_token(&sample_manifest_cid_hex(), &provider_id_hex(), &profile, 2);
        let mut context = build_test_context(
            gateway_config(&manifest_id, &profile),
            [gateway_provider_input(&token)],
        )
        .expect("context");
        let inner = Arc::get_mut(&mut context.fetcher.inner).expect("unique fetcher");
        let runtime = Arc::get_mut(inner.providers.get_mut("alpha").expect("provider runtime"))
            .expect("unique provider runtime");
        runtime.ttl_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_secs();
        let request = FetchRequest {
            provider: Arc::new(context.providers()[0].clone()),
            spec: plan.try_chunk_fetch_specs().expect("valid CAR plan")[0].clone(),
            attempt: 1,
        };
        assert!(matches!(
            context.fetcher().fetch(request).await,
            Err(GatewayFetchError::ExpiredStreamToken { .. })
        ));
    }
    #[tokio::test(flavor = "multi_thread")]
    async fn gateway_fetcher_sets_blinded_headers() {
        let payload = sample_payload(2048);
        let plan = plan_for_payload(&payload);
        let manifest_id_hex = manifest_id_from_payload(&payload);
        let manifest_cid_hex = manifest_root_cid_for_payload(&payload);
        let provider_id = provider_id_hex();
        let chunker_handle = chunker_handle();
        let token = sample_stream_token(&manifest_cid_hex, &provider_id, &chunker_handle, 2);
        let token_b64 = encode_token_b64(&token);
        let blinded_b64 = URL_SAFE_NO_PAD.encode([0u8; 32]);
        let salt_epoch = 42u32;
        let path = format!(
            "/v1/sorafs/storage/chunk/{}/{}",
            manifest_id_hex,
            hex::encode(
                plan.try_chunk_fetch_specs().expect("valid CAR plan")[0]
                    .digest
                    .as_slice()
            )
        );
        let mut responses = HashMap::new();
        responses.insert(
            path.clone(),
            HttpResponse {
                status: StatusCode::OK,
                headers: HeaderMap::new(),
                body: payload
                    [0..plan.try_chunk_fetch_specs().expect("valid CAR plan")[0].length as usize]
                    .to_vec(),
            },
        );
        let engine = Arc::new(MockHttpEngine::new(responses));
        let config = GatewayFetchConfig {
            manifest_id_hex: manifest_id_hex.clone(),
            chunker_handle: chunker_handle.clone(),
            manifest_envelope_b64: None,
            client_id: None,
            expected_manifest_cid_hex: Some(manifest_cid_hex.clone()),
            blinded_cid_b64: Some(blinded_b64.clone()),
            salt_epoch: Some(salt_epoch),
            expected_cache_version: None,
        };
        let provider_input = GatewayProviderInput {
            name: "alpha".to_string(),
            provider_id_hex: provider_id.clone(),
            gateway_public_key_hex: gateway_public_key_hex(),
            base_url: "https://gateway.example/".to_string(),
            stream_token_b64: token_b64,
            privacy_events_url: None,
        };
        let context =
            GatewayFetchContext::build_with_engine(config, [provider_input], engine.clone())
                .expect("context");
        context
            .execute_plan(&plan, FetchOptions::default())
            .await
            .expect("fetch outcome");
        let requests = engine.recorded();
        assert_eq!(requests.len(), 1);
        let request = &requests[0];
        let epoch_value = salt_epoch.to_string();
        assert_eq!(request.path, path);
        assert_eq!(
            request
                .headers
                .get(HeaderName::from_static(HEADER_SORA_REQ_BLINDED_CID))
                .and_then(|value| value.to_str().ok()),
            Some(blinded_b64.as_str())
        );
        assert_eq!(
            request
                .headers
                .get(HeaderName::from_static(HEADER_SORA_REQ_SALT_EPOCH))
                .and_then(|value| value.to_str().ok()),
            Some(epoch_value.as_str())
        );
        let req_nonce = request
            .headers
            .get(HeaderName::from_static(HEADER_SORA_REQ_NONCE))
            .and_then(|value| value.to_str().ok());
        let sorafs_nonce = request
            .headers
            .get(HeaderName::from_static(HEADER_SORA_NONCE))
            .and_then(|value| value.to_str().ok());
        assert_eq!(req_nonce, sorafs_nonce);
    }
    async fn assert_gateway_rate_limit(hint: Option<HeaderValue>, expected: Duration) {
        let payload = sample_payload(1024);
        let plan = plan_for_payload(&payload);
        let manifest_id_hex = manifest_id_from_payload(&payload);
        let manifest_cid_hex = manifest_root_cid_for_payload(&payload);
        let provider_id = provider_id_hex();
        let chunker_handle = chunker_handle();
        let token = sample_stream_token(&manifest_cid_hex, &provider_id, &chunker_handle, 2);
        let token_b64 = encode_token_b64(&token);
        let path = format!(
            "/v1/sorafs/storage/chunk/{}/{}",
            manifest_id_hex,
            hex::encode(
                plan.try_chunk_fetch_specs().expect("valid CAR plan")[0]
                    .digest
                    .as_slice()
            )
        );
        let mut headers = HeaderMap::new();
        if let Some(hint) = hint {
            headers.insert(reqwest::header::RETRY_AFTER, hint);
        }
        let mut responses = HashMap::new();
        responses.insert(
            path.clone(),
            HttpResponse {
                status: StatusCode::TOO_MANY_REQUESTS,
                headers,
                body: br#"{"error":"stream_token_rate_limited"}"#.to_vec(),
            },
        );
        let engine = Arc::new(MockHttpEngine::new(responses));
        let config = GatewayFetchConfig {
            manifest_id_hex: manifest_id_hex.clone(),
            chunker_handle: chunker_handle.clone(),
            manifest_envelope_b64: None,
            client_id: None,
            expected_manifest_cid_hex: Some(manifest_cid_hex.clone()),
            blinded_cid_b64: None,
            salt_epoch: None,
            expected_cache_version: None,
        };
        let provider_input = GatewayProviderInput {
            name: "alpha".to_string(),
            provider_id_hex: provider_id.clone(),
            gateway_public_key_hex: gateway_public_key_hex(),
            base_url: "https://gateway.example/".to_string(),
            stream_token_b64: token_b64.clone(),
            privacy_events_url: None,
        };
        let context =
            GatewayFetchContext::build_with_engine(config, [provider_input], engine.clone())
                .expect("context");
        let fetcher = context.fetcher();
        let provider: FetchProvider = context.providers()[0].clone();
        let spec: ChunkFetchSpec = plan.try_chunk_fetch_specs().expect("valid CAR plan")[0].clone();
        let request = FetchRequest {
            provider: Arc::new(provider),
            spec,
            attempt: 1,
        };
        let error = fetcher.fetch(request).await.expect_err("should fail");
        match error {
            GatewayFetchError::RateLimited {
                provider,
                retry_after,
            } => {
                assert_eq!(provider, "alpha");
                assert_eq!(retry_after, expected);
            }
            other => panic!("unexpected error {other:?}"),
        }
        let recorded = engine.recorded();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].path, path);
    }
    #[tokio::test(flavor = "multi_thread")]
    async fn gateway_fetcher_types_rate_limit_without_retry_after_as_one_second() {
        assert_gateway_rate_limit(None, Duration::from_secs(1)).await;
    }
    #[tokio::test(flavor = "multi_thread")]
    async fn gateway_fetcher_preserves_numeric_retry_after() {
        assert_gateway_rate_limit(
            Some(HeaderValue::from_static("60")),
            Duration::from_secs(60),
        )
        .await;
    }
    #[tokio::test(flavor = "multi_thread")]
    async fn gateway_fetcher_preserves_and_bounds_http_date_retry_after() {
        let date = SystemTime::now() + Duration::from_secs(2 * 86_400);
        let hint = HeaderValue::from_str(&httpdate::fmt_http_date(date)).unwrap();
        assert_gateway_rate_limit(Some(hint), Duration::from_secs(86_400)).await;
    }
    #[tokio::test(flavor = "multi_thread")]
    async fn gateway_fetcher_surfaces_policy_block_evidence() {
        const CATALOG_DIGEST_HEX: &str =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let payload = sample_payload(2048);
        let plan = plan_for_payload(&payload);
        let manifest_id_hex = manifest_id_from_payload(&payload);
        let manifest_cid_hex = manifest_root_cid_for_payload(&payload);
        let provider_id = provider_id_hex();
        let chunker_handle = chunker_handle();
        let token = sample_stream_token(&manifest_cid_hex, &provider_id, &chunker_handle, 2);
        let token_b64 = encode_token_b64(&token);
        let path = format!(
            "/v1/sorafs/storage/chunk/{}/{}",
            manifest_id_hex,
            hex::encode(
                plan.try_chunk_fetch_specs().expect("valid CAR plan")[0]
                    .digest
                    .as_slice()
            )
        );
        let mut responses = HashMap::new();
        responses.insert(
            path.clone(),
            HttpResponse {
                status: StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS,
                headers: HeaderMap::new(),
                body: format!(
                    r#"{{"error":"gateway_compliance_denied","source":"legal_safety_hold","catalog_digest_hex":"{CATALOG_DIGEST_HEX}"}}"#
                )
                .into_bytes(),
            },
        );
        let engine = Arc::new(MockHttpEngine::new(responses));
        let config = GatewayFetchConfig {
            manifest_id_hex: manifest_id_hex.clone(),
            chunker_handle: chunker_handle.clone(),
            manifest_envelope_b64: None,
            client_id: None,
            expected_manifest_cid_hex: Some(manifest_cid_hex.clone()),
            blinded_cid_b64: None,
            salt_epoch: None,
            expected_cache_version: None,
        };
        let provider_input = GatewayProviderInput {
            name: "alpha".to_string(),
            provider_id_hex: provider_id.clone(),
            gateway_public_key_hex: gateway_public_key_hex(),
            base_url: "https://gateway.example/".to_string(),
            stream_token_b64: token_b64,
            privacy_events_url: None,
        };
        let context =
            GatewayFetchContext::build_with_engine(config, [provider_input], engine.clone())
                .expect("context");
        let request = FetchRequest {
            provider: Arc::new(context.providers()[0].clone()),
            spec: plan.try_chunk_fetch_specs().expect("valid CAR plan")[0].clone(),
            attempt: 1,
        };
        let error = context
            .fetcher()
            .fetch(request)
            .await
            .expect_err("should be blocked");
        match error {
            GatewayFetchError::PolicyBlocked { evidence, .. } => {
                assert_eq!(
                    evidence.observed_status,
                    StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS
                );
                assert_eq!(evidence.code, GATEWAY_COMPLIANCE_DENIED_CODE);
                assert_eq!(evidence.source, GATEWAY_COMPLIANCE_SOURCE_LEGAL_SAFETY_HOLD);
                assert_eq!(evidence.catalog_digest_hex, CATALOG_DIGEST_HEX);
            }
            other => panic!("unexpected error {other:?}"),
        }
    }
    #[tokio::test(flavor = "multi_thread")]
    async fn gateway_fetcher_rejects_cache_version_mismatch() {
        let payload = sample_payload(512);
        let plan = plan_for_payload(&payload);
        let manifest_id_hex = manifest_id_from_payload(&payload);
        let manifest_cid_hex = manifest_root_cid_for_payload(&payload);
        let provider_id = provider_id_hex();
        let chunker_handle = chunker_handle();
        let token = sample_stream_token(&manifest_cid_hex, &provider_id, &chunker_handle, 1);
        let token_b64 = encode_token_b64(&token);
        let path = format!(
            "/v1/sorafs/storage/chunk/{}/{}",
            manifest_id_hex,
            hex::encode(
                plan.try_chunk_fetch_specs().expect("valid CAR plan")[0]
                    .digest
                    .as_slice()
            )
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static(HEADER_SORA_CACHE_VERSION),
            HeaderValue::from_static("cache-v1"),
        );
        let mut responses = HashMap::new();
        responses.insert(
            path.clone(),
            HttpResponse {
                status: StatusCode::OK,
                headers,
                body: payload
                    [0..plan.try_chunk_fetch_specs().expect("valid CAR plan")[0].length as usize]
                    .to_vec(),
            },
        );
        let engine = Arc::new(MockHttpEngine::new(responses));
        let config = GatewayFetchConfig {
            manifest_id_hex: manifest_id_hex.clone(),
            chunker_handle: chunker_handle.clone(),
            manifest_envelope_b64: None,
            client_id: None,
            expected_manifest_cid_hex: Some(manifest_cid_hex.clone()),
            blinded_cid_b64: None,
            salt_epoch: None,
            expected_cache_version: Some("cache-v2".to_string()),
        };
        let provider_input = GatewayProviderInput {
            name: "alpha".to_string(),
            provider_id_hex: provider_id.clone(),
            gateway_public_key_hex: gateway_public_key_hex(),
            base_url: "https://gateway.example/".to_string(),
            stream_token_b64: token_b64,
            privacy_events_url: None,
        };
        let context =
            GatewayFetchContext::build_with_engine(config, [provider_input], engine.clone())
                .expect("context");
        let request = FetchRequest {
            provider: Arc::new(context.providers()[0].clone()),
            spec: plan.try_chunk_fetch_specs().expect("valid CAR plan")[0].clone(),
            attempt: 1,
        };
        let err = context
            .fetcher()
            .fetch(request)
            .await
            .expect_err("should fail");
        match err {
            GatewayFetchError::CacheVersionMismatch {
                expected,
                observed,
                status,
                ..
            } => {
                assert_eq!(expected, "cache-v2");
                assert_eq!(observed.as_deref(), Some("cache-v1"));
                assert_eq!(status, StatusCode::OK);
            }
            other => panic!("unexpected error {other:?}"),
        }
        let recorded = engine.recorded();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].path, path);
    }
    #[tokio::test(flavor = "multi_thread")]
    async fn canonical_policy_denial_precedes_success_cache_validation() {
        const CATALOG_DIGEST_HEX: &str =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let payload = sample_payload(1024);
        let plan = plan_for_payload(&payload);
        let manifest_id_hex = manifest_id_from_payload(&payload);
        let manifest_cid_hex = manifest_root_cid_for_payload(&payload);
        let provider_id = provider_id_hex();
        let chunker_handle = chunker_handle();
        let token = sample_stream_token(&manifest_cid_hex, &provider_id, &chunker_handle, 1);
        let token_b64 = encode_token_b64(&token);
        let chunk_digest_hex = hex::encode(
            plan.try_chunk_fetch_specs().expect("valid CAR plan")[0]
                .digest
                .as_slice(),
        );
        let path = format!(
            "/v1/sorafs/storage/chunk/{}/{}",
            manifest_id_hex, chunk_digest_hex
        );
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static(HEADER_SORA_CACHE_VERSION),
            HeaderValue::from_static("stale-cache"),
        );
        let mut responses = HashMap::new();
        responses.insert(
            path.clone(),
            HttpResponse {
                status: StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS,
                headers,
                body: format!(
                    r#"{{"error":"gateway_compliance_denied","source":"baseline","catalog_digest_hex":"{CATALOG_DIGEST_HEX}"}}"#
                )
                .into_bytes(),
            },
        );
        let engine = Arc::new(MockHttpEngine::new(responses));
        let config = GatewayFetchConfig {
            manifest_id_hex: manifest_id_hex.clone(),
            chunker_handle: chunker_handle.clone(),
            manifest_envelope_b64: None,
            client_id: None,
            expected_manifest_cid_hex: Some(manifest_cid_hex.clone()),
            blinded_cid_b64: None,
            salt_epoch: None,
            expected_cache_version: Some("expected-cache".to_string()),
        };
        let provider_input = GatewayProviderInput {
            name: "alpha".to_string(),
            provider_id_hex: provider_id.clone(),
            gateway_public_key_hex: gateway_public_key_hex(),
            base_url: "https://gateway.example/".to_string(),
            stream_token_b64: token_b64,
            privacy_events_url: None,
        };
        let context = GatewayFetchContext::build_with_engine(config, [provider_input], engine)
            .expect("context");
        let request = FetchRequest {
            provider: Arc::new(context.providers()[0].clone()),
            spec: plan.try_chunk_fetch_specs().expect("valid CAR plan")[0].clone(),
            attempt: 1,
        };
        let err = context.fetcher().fetch(request).await.expect_err("blocked");
        match err {
            GatewayFetchError::PolicyBlocked { evidence, .. } => {
                assert_eq!(evidence.catalog_digest_hex, CATALOG_DIGEST_HEX);
            }
            other => panic!("unexpected error {other:?}"),
        }
    }
    #[test]
    fn failure_evidence_accepts_exact_canonical_denials() {
        const CATALOG_DIGEST_HEX: &str =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        for source in [
            GATEWAY_COMPLIANCE_SOURCE_BASELINE,
            GATEWAY_COMPLIANCE_SOURCE_LEGAL_SAFETY_HOLD,
        ] {
            let response = HttpResponse {
                status: StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS,
                headers: HeaderMap::new(),
                body: format!(
                    r#"{{"error":"gateway_compliance_denied","source":"{source}","catalog_digest_hex":"{CATALOG_DIGEST_HEX}"}}"#
                )
                .into_bytes(),
            };
            let evidence = extract_failure_evidence(&response).expect("canonical evidence");
            assert_eq!(evidence.observed_status, response.status);
            assert_eq!(evidence.code, GATEWAY_COMPLIANCE_DENIED_CODE);
            assert_eq!(evidence.source, source);
            assert_eq!(evidence.catalog_digest_hex, CATALOG_DIGEST_HEX);
        }
    }
    #[test]
    fn failure_evidence_rejects_noncanonical_status_body_and_sources() {
        const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let uppercase_digest = DIGEST.to_ascii_uppercase();
        let malformed_digest = format!("{}g", &DIGEST[..63]);
        let cases = [
            (
                "legacy code",
                StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS,
                r#"{"error":"denylisted","source":"baseline","catalog_digest_hex":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}"#.to_owned(),
            ),
            (
                "rewritten forbidden status",
                StatusCode::FORBIDDEN,
                format!(
                    r#"{{"error":"gateway_compliance_denied","source":"baseline","catalog_digest_hex":"{DIGEST}"}}"#
                ),
            ),
            (
                "missing code",
                StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS,
                format!(r#"{{"source":"baseline","catalog_digest_hex":"{DIGEST}"}}"#),
            ),
            (
                "missing source",
                StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS,
                format!(
                    r#"{{"error":"gateway_compliance_denied","catalog_digest_hex":"{DIGEST}"}}"#
                ),
            ),
            (
                "missing digest",
                StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS,
                r#"{"error":"gateway_compliance_denied","source":"baseline"}"#.to_owned(),
            ),
            (
                "unknown source",
                StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS,
                format!(
                    r#"{{"error":"gateway_compliance_denied","source":"unknown","catalog_digest_hex":"{DIGEST}"}}"#
                ),
            ),
            (
                "allow source no_match",
                StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS,
                format!(
                    r#"{{"error":"gateway_compliance_denied","source":"no_match","catalog_digest_hex":"{DIGEST}"}}"#
                ),
            ),
            (
                "allow source accepted_appeal",
                StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS,
                format!(
                    r#"{{"error":"gateway_compliance_denied","source":"accepted_appeal","catalog_digest_hex":"{DIGEST}"}}"#
                ),
            ),
            (
                "uppercase digest",
                StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS,
                format!(
                    r#"{{"error":"gateway_compliance_denied","source":"baseline","catalog_digest_hex":"{uppercase_digest}"}}"#
                ),
            ),
            (
                "malformed digest",
                StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS,
                format!(
                    r#"{{"error":"gateway_compliance_denied","source":"baseline","catalog_digest_hex":"{malformed_digest}"}}"#
                ),
            ),
            (
                "short digest",
                StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS,
                r#"{"error":"gateway_compliance_denied","source":"baseline","catalog_digest_hex":"abcd"}"#.to_owned(),
            ),
            (
                "extra legacy message",
                StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS,
                format!(
                    r#"{{"error":"gateway_compliance_denied","source":"baseline","catalog_digest_hex":"{DIGEST}","message":"blocked"}}"#
                ),
            ),
        ];
        for (label, status, body) in cases {
            let response = HttpResponse {
                status,
                headers: HeaderMap::new(),
                body: body.into_bytes(),
            };
            assert!(
                extract_failure_evidence(&response).is_none(),
                "{label} unexpectedly produced policy evidence"
            );
        }
    }
    #[test]
    fn legacy_headers_alone_do_not_create_policy_evidence() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("sora-denylist-version"),
            HeaderValue::from_static("legacy-v1"),
        );
        headers.insert(
            HeaderName::from_static("sora-moderation-token"),
            HeaderValue::from_static("dG9rZW4="),
        );
        let response = HttpResponse {
            status: StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS,
            headers,
            body: Vec::new(),
        };
        assert!(extract_failure_evidence(&response).is_none());
    }
    #[test]
    fn legacy_token_headers_invalidate_canonical_body_evidence() {
        const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        for (header, value) in [
            ("sora-moderation-token", "dG9rZW4="),
            ("sora-denylist-version", "legacy-v1"),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(
                HeaderName::from_static(header),
                HeaderValue::from_static(value),
            );
            let response = HttpResponse {
                status: StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS,
                headers,
                body: format!(
                    r#"{{"error":"gateway_compliance_denied","source":"baseline","catalog_digest_hex":"{DIGEST}"}}"#
                )
                .into_bytes(),
            };
            assert!(
                extract_failure_evidence(&response).is_none(),
                "legacy header {header} unexpectedly preserved policy evidence"
            );
        }
    }
    #[derive(Clone)]
    struct RecordedRequest {
        path: String,
        headers: HeaderMap,
        max_response_bytes: usize,
    }
    struct MockHttpEngine {
        responses: HashMap<String, HttpResponse>,
        recorded: Mutex<Vec<RecordedRequest>>,
    }
    impl MockHttpEngine {
        fn new(responses: HashMap<String, HttpResponse>) -> Self {
            Self {
                responses,
                recorded: Mutex::new(Vec::new()),
            }
        }
        fn recorded(&self) -> Vec<RecordedRequest> {
            self.recorded.lock().unwrap().clone()
        }
    }
    impl HttpEngine for MockHttpEngine {
        fn get(&self, request: HttpRequest) -> HttpFuture {
            let path = request.url.path().to_string();
            let headers = request.headers.clone();
            self.recorded.lock().unwrap().push(RecordedRequest {
                path: path.clone(),
                headers,
                max_response_bytes: request.max_response_bytes,
            });
            let maybe = self.responses.get(&path).cloned();
            let error_message = format!("no test response for {path}");
            Box::pin(
                async move { maybe.ok_or_else(|| HttpError::TestEngine(error_message.clone())) },
            )
        }
    }
    #[test]
    fn attempt_failure_preserves_policy_block_evidence() {
        let evidence = GatewayFailureEvidence {
            observed_status: StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS,
            code: GATEWAY_COMPLIANCE_DENIED_CODE.to_owned(),
            source: GATEWAY_COMPLIANCE_SOURCE_BASELINE.to_owned(),
            catalog_digest_hex: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_owned(),
        };
        let error = GatewayFetchError::PolicyBlocked {
            provider: "alpha".to_string(),
            evidence: evidence.clone(),
        };
        let failure = AttemptFailure::from(error);
        match failure {
            AttemptFailure::Provider {
                policy_block: Some(policy),
                message,
            } => {
                assert!(message.contains(GATEWAY_COMPLIANCE_DENIED_CODE));
                assert_eq!(policy.code, evidence.code);
                assert_eq!(policy.source, evidence.source);
                assert_eq!(policy.catalog_digest_hex, evidence.catalog_digest_hex);
                assert_eq!(policy.observed_status, evidence.observed_status);
            }
            other => panic!("unexpected attempt failure: {other:?}"),
        }
    }
    include!("gateway/canonical_token_tests.rs");
    include!("gateway/retrieval_quota_tests.rs");
    #[test]
    fn provider_spec_parses_canonical_keys_and_normalises_hex() {
        let provider_id = "AB".repeat(32);
        let gateway_key = "CD".repeat(32);
        let spec = GatewayProviderInput::parse_spec(
            &format!(
                "name=alpha, provider-id={provider_id}, gateway-key={gateway_key}, base-url=https://alpha.example/, stream-token=dG9rZW4=, privacy-url=https://admin.example/"
            ),
            "--provider",
        )
        .expect("valid gateway provider specification");
        assert_eq!(spec.name, "alpha");
        assert_eq!(spec.provider_id_hex, provider_id.to_ascii_lowercase());
        assert_eq!(
            spec.gateway_public_key_hex,
            gateway_key.to_ascii_lowercase()
        );
        assert_eq!(spec.base_url, "https://alpha.example/");
        assert_eq!(spec.stream_token_b64, "dG9rZW4=");
        assert_eq!(
            spec.privacy_events_url.as_deref(),
            Some("https://admin.example/")
        );
    }

    #[test]
    fn provider_spec_rejects_aliases_missing_keys_and_bad_hex() {
        let provider_id = "11".repeat(32);
        let gateway_key = "22".repeat(32);
        let alias = GatewayProviderInput::parse_spec(
            &format!(
                "name=alpha,provider_id={provider_id},gateway-key={gateway_key},base-url=https://a/,stream-token=dA=="
            ),
            "--gateway-provider",
        )
        .expect_err("snake_case aliases are not accepted");
        assert!(alias.contains("unknown --gateway-provider key `provider_id`"));
        let missing = GatewayProviderInput::parse_spec(
            &format!("name=alpha,provider-id={provider_id},base-url=https://a/,stream-token=dA=="),
            "--provider",
        )
        .expect_err("gateway key is required");
        assert!(missing.contains("--provider requires gateway-key=<hex>"));
        let bad_hex = GatewayProviderInput::parse_spec(
            &format!(
                "name=alpha,provider-id={provider_id},gateway-key=not-hex,base-url=https://a/,stream-token=dA=="
            ),
            "--provider",
        )
        .expect_err("gateway key must be hex");
        assert!(bad_hex.contains("--provider gateway-key must be 32-byte hex"));
        let malformed =
            GatewayProviderInput::parse_spec("name", "--provider").expect_err("pairs need `=`");
        assert!(malformed.contains("comma-separated key=value pairs"));
    }
}
