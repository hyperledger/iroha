//! Admission-bound HTTP Routing V1 projections for SoraFS.
//!
//! The routing view is deliberately derived from committed pin-registry state and the validated
//! provider-advert cache for every request. It is not a second content-ownership database: approved
//! manifests and completed replication orders remain the sole authority, while adverts only supply
//! current peer connectivity metadata.
use crate::{SharedAppState, sorafs::ProviderAdvertCache};
use axum::{
    body::Body,
    extract::{Path, RawQuery, State},
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{
            ACCEPT, ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN, CACHE_CONTROL,
            CONTENT_TYPE, LAST_MODIFIED, VARY,
        },
    },
    response::Response,
};
use iroha_core::state::{StateView, WorldReadOnly};
use iroha_data_model::sorafs::pin_registry::ManifestRootCid;
use iroha_logger::{debug, warn};
use mv::storage::StorageReadOnly;
use norito::json::{self, Map, Value};
use sorafs_manifest::{
    AdvertEndpoint, AdvertValidationError, EndpointKind, ProviderAdvertV1, TransportProtocol,
};
pub(crate) use sorafs_orchestrator::routing_authority::RoutingAuthorityCache;
use sorafs_orchestrator::routing_authority::{
    FinalizedStateIdentityV1, RoutingAuthorityError, RoutingAuthoritySource,
    build_routing_authority_projection,
};
use std::collections::{BTreeMap, BTreeSet};
use time::{Month, OffsetDateTime, Weekday};
use url::{Host as UrlHost, Url};
const JSON_RESULT_LIMIT: usize = 100;
const NDJSON_RESULT_LIMIT: usize = 1_024;
const MAX_PATH_IDENTIFIER_BYTES: usize = 256;
const MAX_RAW_QUERY_BYTES: usize = 2_048;
const MAX_FILTER_VALUE_BYTES: usize = 1_024;
const MAX_FILTER_TERMS: usize = 32;
const MAX_FILTER_TERM_BYTES: usize = 63;
const MAX_ACCEPT_BYTES: usize = 1_024;
const MAX_ACCEPT_RANGES: usize = 32;
const MAX_ENDPOINT_BYTES: usize = 512;
const POSITIVE_CACHE_TTL_SECS: u64 = 300;
const NEGATIVE_CACHE_TTL_SECS: u64 = 15;
const STALE_CACHE_TTL_SECS: u64 = 86_400;
const CONTENT_TYPE_JSON: &str = "application/json";
const CONTENT_TYPE_NDJSON: &str = "application/x-ndjson";
const PROTOCOL_TORII_HTTP_RANGE: &str = "transport-sorafs-http-range";
const PROTOCOL_QUIC_STREAM: &str = "transport-sorafs-quic-stream";
const PROTOCOL_SORANET_RELAY: &str = "transport-sorafs-soranet-relay";
const PROTOCOL_VENDOR: &str = "transport-sorafs-vendor";
/// Serve `GET /routing/v1/providers/{cid}`.
pub(crate) async fn handle_get_routing_providers(
    State(state): State<SharedAppState>,
    Path(cid): Path<String>,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
) -> Response {
    let representation = match negotiate_representation(&headers) {
        Ok(value) => value,
        Err(error) => return routing_error_response(error),
    };
    let filters = match RoutingFilters::parse(raw_query.as_deref()) {
        Ok(value) => value,
        Err(error) => return routing_error_response(error),
    };
    let content_cid = match parse_content_cid(&cid) {
        Ok(value) => value,
        Err(error) => return routing_error_response(error),
    };
    let now = unix_now_secs();
    let (authority, cache_outcome) = state
        .sorafs_routing_authority_cache
        .get_or_rebuild(|| CommittedRoutingAuthoritySource::new(state.state.view()))
        .await;
    state
        .telemetry
        .with_metrics(|metrics| metrics.inc_sorafs_routing_authority_cache(cache_outcome.label()));
    let authority = match authority {
        Ok(value) => value,
        Err(error) => return routing_error_response(map_authority_error(error)),
    };
    let Some(cache) = state.sorafs_cache() else {
        return routing_error_response(RoutingError::DiscoveryUnavailable);
    };
    let mut cache_guard = cache.write().await;
    cache_guard.prune_stale(now);
    let cache_guard = tokio::sync::RwLockWriteGuard::downgrade(cache_guard);
    let provider_ids = authority
        .providers_for_content(&content_cid)
        .cloned()
        .unwrap_or_default();
    let peers = match resolve_authorized_peers(&provider_ids, &cache_guard, now, &filters) {
        Ok(value) => value,
        Err(error) => return routing_error_response(error),
    };
    drop(cache_guard);
    debug!(
        route = "providers",
        representation = representation.label(),
        result_count = peers.len(),
        "served admission-bound delegated-routing result"
    );
    routing_success_response("Providers", peers, representation, now)
}
/// Serve `GET /routing/v1/peers/{peer_id}`.
pub(crate) async fn handle_get_routing_peers(
    State(state): State<SharedAppState>,
    Path(peer_id): Path<String>,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
) -> Response {
    let representation = match negotiate_representation(&headers) {
        Ok(value) => value,
        Err(error) => return routing_error_response(error),
    };
    let filters = match RoutingFilters::parse(raw_query.as_deref()) {
        Ok(value) => value,
        Err(error) => return routing_error_response(error),
    };
    let canonical_peer_id = match parse_peer_id(&peer_id) {
        Ok(value) => value,
        Err(error) => return routing_error_response(error),
    };
    let now = unix_now_secs();
    let (authority, cache_outcome) = state
        .sorafs_routing_authority_cache
        .get_or_rebuild(|| CommittedRoutingAuthoritySource::new(state.state.view()))
        .await;
    state
        .telemetry
        .with_metrics(|metrics| metrics.inc_sorafs_routing_authority_cache(cache_outcome.label()));
    let authority = match authority {
        Ok(value) => value,
        Err(error) => return routing_error_response(map_authority_error(error)),
    };
    let Some(cache) = state.sorafs_cache() else {
        return routing_error_response(RoutingError::DiscoveryUnavailable);
    };
    let mut cache_guard = cache.write().await;
    cache_guard.prune_stale(now);
    let cache_guard = tokio::sync::RwLockWriteGuard::downgrade(cache_guard);
    let mut peers =
        match resolve_authorized_peers(authority.all_providers(), &cache_guard, now, &filters) {
            Ok(value) => value,
            Err(error) => return routing_error_response(error),
        };
    peers.retain(|peer| peer.id == canonical_peer_id);
    drop(cache_guard);
    debug!(
        route = "peers",
        representation = representation.label(),
        result_count = peers.len(),
        "served admission-bound delegated-routing result"
    );
    routing_success_response("Peers", peers, representation, now)
}
struct CommittedRoutingAuthoritySource<'state> {
    state_view: StateView<'state>,
}
impl<'state> CommittedRoutingAuthoritySource<'state> {
    fn new(state_view: StateView<'state>) -> Self {
        Self { state_view }
    }
}
impl RoutingAuthoritySource for CommittedRoutingAuthoritySource<'_> {
    fn finalized_identity(&self) -> Result<FinalizedStateIdentityV1, RoutingAuthorityError> {
        let height = u64::try_from(self.state_view.height())
            .map_err(|_| RoutingAuthorityError::InvalidFinalizedIdentity)?;
        let block_hash = self
            .state_view
            .latest_block_hash()
            .map(|hash| *hash.as_ref());
        FinalizedStateIdentityV1::new(height, block_hash)
    }
    fn build_projection(
        &self,
        identity: FinalizedStateIdentityV1,
    ) -> Result<
        sorafs_orchestrator::routing_authority::RoutingAuthorityProjection,
        RoutingAuthorityError,
    > {
        build_routing_authority_projection(
            identity,
            self.state_view.world().pin_manifests().iter(),
            self.state_view.world().replication_orders().iter(),
        )
    }
}
const fn map_authority_error(error: RoutingAuthorityError) -> RoutingError {
    match error {
        RoutingAuthorityError::CapacityExceeded => RoutingError::AuthorityCapacityExceeded,
        RoutingAuthorityError::InvalidFinalizedIdentity
        | RoutingAuthorityError::StaleFinalizedIdentity
        | RoutingAuthorityError::FinalizedFork
        | RoutingAuthorityError::Corrupt => RoutingError::AuthorityCorrupt,
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Representation {
    Json,
    Ndjson,
}
impl Representation {
    const fn label(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Ndjson => "ndjson",
        }
    }
    const fn result_limit(self) -> usize {
        match self {
            Self::Json => JSON_RESULT_LIMIT,
            Self::Ndjson => NDJSON_RESULT_LIMIT,
        }
    }
}
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct RoutingFilters {
    addrs: Option<AddressFilters>,
    protocols: Option<BTreeSet<String>>,
}
impl RoutingFilters {
    fn parse(raw_query: Option<&str>) -> Result<Self, RoutingError> {
        let Some(raw_query) = raw_query else {
            return Ok(Self::default());
        };
        if raw_query.len() > MAX_RAW_QUERY_BYTES {
            return Err(RoutingError::QueryTooLarge);
        }
        if raw_query.is_empty() {
            return Err(RoutingError::MalformedQuery);
        }
        let mut addrs = None;
        let mut protocols = None;
        let mut pairs = 0usize;
        for pair in raw_query.split('&') {
            if pair.is_empty() {
                return Err(RoutingError::MalformedQuery);
            }
            let Some((key, value)) = pair.split_once('=') else {
                return Err(RoutingError::MalformedQuery);
            };
            if key.is_empty() || value.contains('=') {
                return Err(RoutingError::MalformedQuery);
            }
            if key.bytes().any(|byte| matches!(byte, b'%' | b'+')) || value.contains('%') {
                return Err(RoutingError::NonCanonicalQueryEncoding);
            }
            pairs = pairs.saturating_add(1);
            if pairs > 2 {
                return Err(RoutingError::TooManyQueryParameters);
            }
            match key {
                "filter-addrs" => {
                    if addrs.is_some() {
                        return Err(RoutingError::DuplicateQueryParameter);
                    }
                    addrs = Some(AddressFilters::parse(value)?);
                }
                "filter-protocols" => {
                    if protocols.is_some() {
                        return Err(RoutingError::DuplicateQueryParameter);
                    }
                    protocols = Some(parse_protocol_filters(value)?);
                }
                _ => return Err(RoutingError::UnknownQueryParameter),
            }
        }
        Ok(Self { addrs, protocols })
    }
    fn apply(&self, mut peer: RoutingPeer) -> Option<RoutingPeer> {
        if let Some(filters) = &self.addrs {
            if peer.addrs.is_empty() {
                if !filters.positive.contains("unknown") {
                    return None;
                }
            } else {
                peer.addrs.retain(|address| filters.matches(address));
                if peer.addrs.is_empty() {
                    return None;
                }
            }
        }
        if let Some(filters) = &self.protocols {
            let matches = if peer.protocols.is_empty() {
                filters.contains("unknown")
            } else {
                peer.protocols
                    .iter()
                    .any(|protocol| filters.contains(&protocol.to_ascii_lowercase()))
            };
            if !matches {
                return None;
            }
        }
        Some(peer)
    }
}
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct AddressFilters {
    positive: BTreeSet<String>,
    negative: BTreeSet<String>,
}
impl AddressFilters {
    fn parse(value: &str) -> Result<Self, RoutingError> {
        if value.is_empty() {
            return Err(RoutingError::EmptyFilter);
        }
        if value.len() > MAX_FILTER_VALUE_BYTES {
            return Err(RoutingError::FilterTooLarge);
        }
        let mut result = Self::default();
        for (index, raw_term) in value.split(',').enumerate() {
            if index >= MAX_FILTER_TERMS {
                return Err(RoutingError::TooManyFilters);
            }
            let (negative, term) = raw_term
                .strip_prefix('!')
                .map_or((false, raw_term), |term| (true, term));
            let canonical = canonical_filter_term(term, FilterKind::Address)?;
            if negative && canonical == "unknown" {
                return Err(RoutingError::InvalidFilter);
            }
            if result.positive.contains(&canonical) || result.negative.contains(&canonical) {
                return Err(RoutingError::DuplicateFilter);
            }
            let inserted = if negative {
                result.negative.insert(canonical)
            } else {
                result.positive.insert(canonical)
            };
            if !inserted {
                return Err(RoutingError::DuplicateFilter);
            }
        }
        if result.positive.is_empty() && result.negative.is_empty() {
            return Err(RoutingError::EmptyFilter);
        }
        Ok(result)
    }
    fn matches(&self, address: &str) -> bool {
        let components = multiaddr_protocol_components(address);
        if self
            .negative
            .iter()
            .any(|filter| components.contains(filter.as_str()))
        {
            return false;
        }
        self.positive.is_empty()
            || self
                .positive
                .iter()
                .filter(|filter| filter.as_str() != "unknown")
                .any(|filter| components.contains(filter.as_str()))
    }
}
#[derive(Debug, Clone, Copy)]
enum FilterKind {
    Address,
    Protocol,
}
fn parse_protocol_filters(value: &str) -> Result<BTreeSet<String>, RoutingError> {
    if value.is_empty() {
        return Err(RoutingError::EmptyFilter);
    }
    if value.len() > MAX_FILTER_VALUE_BYTES {
        return Err(RoutingError::FilterTooLarge);
    }
    let mut result = BTreeSet::new();
    for (index, raw_term) in value.split(',').enumerate() {
        if index >= MAX_FILTER_TERMS {
            return Err(RoutingError::TooManyFilters);
        }
        if raw_term.starts_with('!') {
            return Err(RoutingError::InvalidFilter);
        }
        let canonical = canonical_filter_term(raw_term, FilterKind::Protocol)?;
        if !result.insert(canonical) {
            return Err(RoutingError::DuplicateFilter);
        }
    }
    if result.is_empty() {
        return Err(RoutingError::EmptyFilter);
    }
    Ok(result)
}
fn canonical_filter_term(term: &str, kind: FilterKind) -> Result<String, RoutingError> {
    if term.is_empty() || term.len() > MAX_FILTER_TERM_BYTES || !term.is_ascii() {
        return Err(RoutingError::InvalidFilter);
    }
    let canonical = term.to_ascii_lowercase();
    let valid = match kind {
        FilterKind::Address => canonical
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'),
        FilterKind::Protocol => canonical.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'-' | b'.' | b'_' | b'+')
        }),
    };
    if !valid
        || !canonical
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        || !canonical
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
    {
        return Err(RoutingError::InvalidFilter);
    }
    Ok(canonical)
}
fn multiaddr_protocol_components(address: &str) -> BTreeSet<&str> {
    let mut result = BTreeSet::new();
    let mut components = address.split('/').filter(|component| !component.is_empty());
    while let Some(protocol) = components.next() {
        result.insert(protocol);
        if matches!(
            protocol,
            "dns" | "dns4" | "dns6" | "dnsaddr" | "ip4" | "ip6" | "tcp" | "udp" | "p2p"
        ) {
            let _ = components.next();
        }
    }
    result
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct RoutingPeer {
    provider_id: [u8; 32],
    id: String,
    addrs: Vec<String>,
    protocols: Vec<String>,
    issued_at: u64,
    expires_at: u64,
}
impl RoutingPeer {
    fn from_advert(advert: &ProviderAdvertV1, now: u64) -> Result<Option<Self>, RoutingError> {
        if now >= advert.expires_at {
            return Ok(None);
        }
        advert
            .validate_with_body(now)
            .map_err(|error| match error {
                AdvertValidationError::TooManyEndpoints { .. } => {
                    RoutingError::AdvertCapacityExceeded
                }
                _ => RoutingError::AdvertCorrupt,
            })?;
        let public_key: [u8; 32] = advert
            .signature
            .public_key
            .as_slice()
            .try_into()
            .map_err(|_| RoutingError::AdvertCorrupt)?;
        let id = peer_id_from_ed25519_key(public_key);
        let mut addrs = BTreeSet::new();
        for endpoint in &advert.body.endpoints {
            if let Some(address) = endpoint_multiaddr(endpoint) {
                addrs.insert(address);
            }
        }
        let protocols = advert
            .body
            .transport_hints
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(|hint| transport_protocol_name(hint.protocol).to_owned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        Ok(Some(Self {
            provider_id: advert.body.provider_id,
            id,
            addrs: addrs.into_iter().collect(),
            protocols,
            issued_at: advert.issued_at,
            expires_at: advert.expires_at,
        }))
    }
    fn into_json(self) -> Value {
        let mut map = Map::new();
        map.insert("Schema".into(), Value::String("peer".to_owned()));
        map.insert("ID".into(), Value::String(self.id));
        map.insert(
            "Addrs".into(),
            Value::Array(self.addrs.into_iter().map(Value::String).collect()),
        );
        map.insert(
            "Protocols".into(),
            Value::Array(self.protocols.into_iter().map(Value::String).collect()),
        );
        Value::Object(map)
    }
}
fn resolve_authorized_peers(
    provider_ids: &BTreeSet<[u8; 32]>,
    cache: &ProviderAdvertCache,
    now: u64,
    filters: &RoutingFilters,
) -> Result<Vec<RoutingPeer>, RoutingError> {
    resolve_advert_peers(
        provider_ids.iter().filter_map(|provider_id| {
            cache
                .record_by_provider(provider_id)
                .map(|record| (*provider_id, record.advert()))
        }),
        now,
        filters,
    )
}
fn resolve_advert_peers<'a, I>(
    adverts: I,
    now: u64,
    filters: &RoutingFilters,
) -> Result<Vec<RoutingPeer>, RoutingError>
where
    I: IntoIterator<Item = ([u8; 32], &'a ProviderAdvertV1)>,
{
    let mut by_peer_id: BTreeMap<String, RoutingPeer> = BTreeMap::new();
    for (provider_id, advert) in adverts {
        let Some(peer) = RoutingPeer::from_advert(advert, now)? else {
            continue;
        };
        if peer.provider_id != provider_id {
            return Err(RoutingError::AdvertCorrupt);
        }
        if let Some(existing) = by_peer_id.get(&peer.id)
            && existing.provider_id != peer.provider_id
        {
            // A signing key reused by distinct governed provider identities is
            // ambiguous and must not be merged into invented ownership.
            return Err(RoutingError::PeerIdentityEquivocation);
        }
        by_peer_id.insert(peer.id.clone(), peer);
    }
    Ok(by_peer_id
        .into_values()
        .filter_map(|peer| filters.apply(peer))
        .collect())
}
fn endpoint_multiaddr(endpoint: &AdvertEndpoint) -> Option<String> {
    let raw = endpoint.host_pattern.as_str();
    if raw.is_empty()
        || raw != raw.trim()
        || raw.len() > MAX_ENDPOINT_BYTES
        || !raw.is_ascii()
        || raw.bytes().any(|byte| byte.is_ascii_control())
        || raw.contains(['\\', '%', '*'])
    {
        return None;
    }
    let candidate = if raw.contains("://") {
        raw.to_owned()
    } else {
        format!("https://{raw}")
    };
    let url = Url::parse(&candidate).ok()?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
        || url.port() == Some(0)
    {
        return None;
    }
    let scheme_valid = match endpoint.kind {
        EndpointKind::Torii | EndpointKind::NoritoRpc => url.scheme() == "https",
        EndpointKind::Quic => matches!(url.scheme(), "https" | "quic"),
    };
    if !scheme_valid {
        return None;
    }
    let port = url.port().unwrap_or(443);
    let host = match url.host()? {
        UrlHost::Domain(domain) => {
            if domain.is_empty()
                || domain.ends_with('.')
                || domain.split('.').any(|label| {
                    label.is_empty()
                        || label.len() > 63
                        || label.starts_with('-')
                        || label.ends_with('-')
                        || !label
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                })
            {
                return None;
            }
            format!("/dns/{}", domain.to_ascii_lowercase())
        }
        UrlHost::Ipv4(address) => format!("/ip4/{address}"),
        UrlHost::Ipv6(address) => format!("/ip6/{address}"),
    };
    let suffix = match endpoint.kind {
        EndpointKind::Torii => format!("/tcp/{port}/tls/http"),
        EndpointKind::Quic => format!("/udp/{port}/quic-v1"),
        EndpointKind::NoritoRpc => format!("/tcp/{port}/tls"),
    };
    Some(format!("{host}{suffix}"))
}
const fn transport_protocol_name(protocol: TransportProtocol) -> &'static str {
    match protocol {
        TransportProtocol::ToriiHttpRange => PROTOCOL_TORII_HTTP_RANGE,
        TransportProtocol::QuicStream => PROTOCOL_QUIC_STREAM,
        TransportProtocol::SoraNetRelay => PROTOCOL_SORANET_RELAY,
        TransportProtocol::VendorReserved => PROTOCOL_VENDOR,
    }
}
fn routing_success_response(
    wrapper: &'static str,
    mut peers: Vec<RoutingPeer>,
    representation: Representation,
    now: u64,
) -> Response {
    let result_limit = representation.result_limit();
    peers.truncate(result_limit);
    let has_results = !peers.is_empty();
    let last_modified = peers.iter().map(|peer| peer.issued_at).max().unwrap_or(now);
    let max_age = if has_results {
        peers
            .iter()
            .map(|peer| peer.expires_at.saturating_sub(now))
            .min()
            .unwrap_or(POSITIVE_CACHE_TTL_SECS)
            .min(POSITIVE_CACHE_TTL_SECS)
    } else {
        NEGATIVE_CACHE_TTL_SECS
    };
    let (content_type, body) = match representation {
        Representation::Json => {
            let mut map = Map::new();
            map.insert(
                wrapper.into(),
                Value::Array(peers.into_iter().map(RoutingPeer::into_json).collect()),
            );
            let body = json::to_json(&Value::Object(map)).unwrap_or_else(|_| "{}".to_owned());
            (CONTENT_TYPE_JSON, body)
        }
        Representation::Ndjson => {
            let mut body = String::new();
            for peer in peers {
                let Ok(line) = json::to_json(&peer.into_json()) else {
                    continue;
                };
                body.push_str(&line);
                body.push('\n');
            }
            (CONTENT_TYPE_NDJSON, body)
        }
    };
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = StatusCode::OK;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
        .headers_mut()
        .insert(VARY, HeaderValue::from_static("Accept"));
    response
        .headers_mut()
        .insert(ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
    response.headers_mut().insert(
        ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET, OPTIONS"),
    );
    let cache_control = format!(
        "public, max-age={max_age}, stale-while-revalidate={STALE_CACHE_TTL_SECS}, stale-if-error={STALE_CACHE_TTL_SECS}"
    );
    if let Ok(value) = HeaderValue::from_str(&cache_control) {
        response.headers_mut().insert(CACHE_CONTROL, value);
    }
    if let Ok(value) = HeaderValue::from_str(&http_date(last_modified)) {
        response.headers_mut().insert(LAST_MODIFIED, value);
    }
    response
}
fn routing_error_response(error: RoutingError) -> Response {
    let status = error.status();
    warn!(
        route_family = "delegated_routing",
        reason = error.reason_label(),
        status = status.as_u16(),
        "rejected delegated-routing request"
    );
    let mut map = Map::new();
    map.insert(
        "Code".into(),
        json::to_value(&status.as_u16()).unwrap_or(Value::Null),
    );
    map.insert("Message".into(), Value::String(error.message().to_owned()));
    let body = json::to_json(&Value::Object(map)).unwrap_or_else(|_| "{}".to_owned());
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(CONTENT_TYPE_JSON));
    response
        .headers_mut()
        .insert(VARY, HeaderValue::from_static("Accept"));
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
    response.headers_mut().insert(
        ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("GET, OPTIONS"),
    );
    response
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RoutingError {
    IdentifierTooLarge,
    InvalidContentCid,
    InvalidPeerId,
    QueryTooLarge,
    MalformedQuery,
    NonCanonicalQueryEncoding,
    TooManyQueryParameters,
    UnknownQueryParameter,
    DuplicateQueryParameter,
    EmptyFilter,
    FilterTooLarge,
    TooManyFilters,
    InvalidFilter,
    DuplicateFilter,
    InvalidAccept,
    NotAcceptable,
    DiscoveryUnavailable,
    AuthorityCapacityExceeded,
    AuthorityCorrupt,
    AdvertCapacityExceeded,
    AdvertCorrupt,
    PeerIdentityEquivocation,
}
impl RoutingError {
    const fn status(self) -> StatusCode {
        match self {
            Self::IdentifierTooLarge
            | Self::InvalidContentCid
            | Self::InvalidPeerId
            | Self::QueryTooLarge
            | Self::MalformedQuery
            | Self::NonCanonicalQueryEncoding
            | Self::TooManyQueryParameters
            | Self::UnknownQueryParameter
            | Self::DuplicateQueryParameter
            | Self::EmptyFilter
            | Self::FilterTooLarge
            | Self::TooManyFilters
            | Self::InvalidFilter
            | Self::DuplicateFilter
            | Self::InvalidAccept => StatusCode::UNPROCESSABLE_ENTITY,
            Self::NotAcceptable => StatusCode::NOT_ACCEPTABLE,
            Self::DiscoveryUnavailable
            | Self::AuthorityCapacityExceeded
            | Self::AuthorityCorrupt
            | Self::AdvertCapacityExceeded
            | Self::AdvertCorrupt
            | Self::PeerIdentityEquivocation => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
    const fn reason_label(self) -> &'static str {
        match self {
            Self::IdentifierTooLarge => "identifier_too_large",
            Self::InvalidContentCid => "invalid_content_cid",
            Self::InvalidPeerId => "invalid_peer_id",
            Self::QueryTooLarge => "query_too_large",
            Self::MalformedQuery => "malformed_query",
            Self::NonCanonicalQueryEncoding => "non_canonical_query_encoding",
            Self::TooManyQueryParameters => "too_many_query_parameters",
            Self::UnknownQueryParameter => "unknown_query_parameter",
            Self::DuplicateQueryParameter => "duplicate_query_parameter",
            Self::EmptyFilter => "empty_filter",
            Self::FilterTooLarge => "filter_too_large",
            Self::TooManyFilters => "too_many_filters",
            Self::InvalidFilter => "invalid_filter",
            Self::DuplicateFilter => "duplicate_filter",
            Self::InvalidAccept => "invalid_accept",
            Self::NotAcceptable => "not_acceptable",
            Self::DiscoveryUnavailable => "discovery_unavailable",
            Self::AuthorityCapacityExceeded => "authority_capacity_exceeded",
            Self::AuthorityCorrupt => "authority_corrupt",
            Self::AdvertCapacityExceeded => "advert_capacity_exceeded",
            Self::AdvertCorrupt => "advert_corrupt",
            Self::PeerIdentityEquivocation => "peer_identity_equivocation",
        }
    }
    const fn message(self) -> &'static str {
        match self {
            Self::IdentifierTooLarge => "path identifier exceeds the first-release size limit",
            Self::InvalidContentCid => "content identifier is not a canonical SoraFS CIDv1",
            Self::InvalidPeerId => "peer identifier is not a canonical libp2p peer ID",
            Self::QueryTooLarge => "routing query exceeds the first-release size limit",
            Self::MalformedQuery => {
                "routing query must contain non-empty name=value parameters separated by &"
            }
            Self::NonCanonicalQueryEncoding => {
                "routing query must use literal parameter names and filter values"
            }
            Self::TooManyQueryParameters => "routing query contains too many parameters",
            Self::UnknownQueryParameter => "routing query contains an unsupported parameter",
            Self::DuplicateQueryParameter => "routing query repeats a parameter",
            Self::EmptyFilter => "routing filter must not be empty",
            Self::FilterTooLarge => "routing filter exceeds the first-release size limit",
            Self::TooManyFilters => "routing filter contains too many terms",
            Self::InvalidFilter => "routing filter contains an invalid term",
            Self::DuplicateFilter => "routing filter repeats a case-insensitive term",
            Self::InvalidAccept => "Accept header is malformed or exceeds its size limit",
            Self::NotAcceptable => "requested response media type is not supported",
            Self::DiscoveryUnavailable => "SoraFS provider discovery is unavailable",
            Self::AuthorityCapacityExceeded => "routing authority snapshot exceeds safety limits",
            Self::AuthorityCorrupt => "routing authority snapshot failed canonical validation",
            Self::AdvertCapacityExceeded => "provider advert exceeds routing safety limits",
            Self::AdvertCorrupt => "provider advert failed routing validation",
            Self::PeerIdentityEquivocation => "provider adverts reuse a peer identity",
        }
    }
}
fn negotiate_representation(headers: &HeaderMap) -> Result<Representation, RoutingError> {
    let values = headers.get_all(ACCEPT);
    let mut saw_header = false;
    let mut total_bytes = 0usize;
    let mut ranges = Vec::new();
    for value in values.iter() {
        saw_header = true;
        let value = value.to_str().map_err(|_| RoutingError::InvalidAccept)?;
        total_bytes = total_bytes.saturating_add(value.len());
        if total_bytes > MAX_ACCEPT_BYTES {
            return Err(RoutingError::InvalidAccept);
        }
        for raw_range in value.split(',') {
            if ranges.len() == MAX_ACCEPT_RANGES {
                return Err(RoutingError::InvalidAccept);
            }
            ranges.push(parse_accept_range(raw_range)?);
        }
    }
    if !saw_header {
        return Ok(Representation::Json);
    }
    let (json_quality, json_specificity) = accept_quality_for(&ranges, CONTENT_TYPE_JSON);
    let (ndjson_quality, ndjson_specificity) = accept_quality_for(&ranges, CONTENT_TYPE_NDJSON);
    if ndjson_quality > 0
        && (ndjson_quality > json_quality
            || (ndjson_quality == json_quality && ndjson_specificity > json_specificity))
    {
        return Ok(Representation::Ndjson);
    }
    if json_quality > 0 {
        return Ok(Representation::Json);
    }
    if ndjson_quality > 0 {
        return Ok(Representation::Ndjson);
    }
    Err(RoutingError::NotAcceptable)
}
fn accept_quality_for(ranges: &[(String, u16)], target: &str) -> (u16, u8) {
    let mut selected = (0u16, 0u8);
    let mut matched = false;
    for (media_type, quality) in ranges {
        let specificity = if media_type == target {
            Some(2)
        } else if media_type == "application/*" {
            Some(1)
        } else if media_type == "*/*" {
            Some(0)
        } else {
            None
        };
        let Some(specificity) = specificity else {
            continue;
        };
        if !matched
            || specificity > selected.1
            || (specificity == selected.1 && *quality > selected.0)
        {
            selected = (*quality, specificity);
            matched = true;
        }
    }
    selected
}
fn parse_accept_range(raw: &str) -> Result<(String, u16), RoutingError> {
    let mut parts = raw.split(';');
    let media_type = parts
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(RoutingError::InvalidAccept)?
        .to_ascii_lowercase();
    if !media_type.is_ascii() || !media_type.contains('/') {
        return Err(RoutingError::InvalidAccept);
    }
    let mut quality = 1_000;
    let mut saw_quality = false;
    for parameter in parts {
        let parameter = parameter.trim();
        if parameter.is_empty() {
            return Err(RoutingError::InvalidAccept);
        }
        let quality_value = parameter
            .split_once('=')
            .filter(|(name, _)| name.trim().eq_ignore_ascii_case("q"))
            .map(|(_, value)| value.trim());
        if let Some(raw_quality) = quality_value {
            if saw_quality {
                return Err(RoutingError::InvalidAccept);
            }
            quality = parse_quality(raw_quality)?;
            saw_quality = true;
        }
    }
    Ok((media_type, quality))
}
fn parse_quality(value: &str) -> Result<u16, RoutingError> {
    if value == "0" || value == "0." {
        return Ok(0);
    }
    if value == "1" || value == "1." {
        return Ok(1_000);
    }
    let Some((whole, fraction)) = value.split_once('.') else {
        return Err(RoutingError::InvalidAccept);
    };
    if fraction.is_empty()
        || fraction.len() > 3
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(RoutingError::InvalidAccept);
    }
    match whole {
        "0" => {
            let mut padded = fraction.to_owned();
            while padded.len() < 3 {
                padded.push('0');
            }
            padded.parse().map_err(|_| RoutingError::InvalidAccept)
        }
        "1" if fraction.bytes().all(|byte| byte == b'0') => Ok(1_000),
        _ => Err(RoutingError::InvalidAccept),
    }
}
fn parse_content_cid(value: &str) -> Result<ManifestRootCid, RoutingError> {
    if value.len() > MAX_PATH_IDENTIFIER_BYTES {
        return Err(RoutingError::IdentifierTooLarge);
    }
    if value.is_empty() || !value.is_ascii() {
        return Err(RoutingError::InvalidContentCid);
    }
    let (prefix, payload) = value.split_at(1);
    let bytes = match prefix {
        "b" => {
            let decoded = decode_base32_lower(payload).ok_or(RoutingError::InvalidContentCid)?;
            if format!("b{}", encode_base32_lower(&decoded)) != value {
                return Err(RoutingError::InvalidContentCid);
            }
            decoded
        }
        "k" => {
            let decoded = decode_base36_lower(payload).ok_or(RoutingError::InvalidContentCid)?;
            if format!("k{}", encode_base36_lower(&decoded)) != value {
                return Err(RoutingError::InvalidContentCid);
            }
            decoded
        }
        "z" => {
            let decoded = decode_base58btc(payload).ok_or(RoutingError::InvalidContentCid)?;
            if format!("z{}", encode_base58btc(&decoded)) != value {
                return Err(RoutingError::InvalidContentCid);
            }
            decoded
        }
        _ => return Err(RoutingError::InvalidContentCid),
    };
    ManifestRootCid::try_from_slice(&bytes).map_err(|_| RoutingError::InvalidContentCid)
}
fn peer_id_from_ed25519_key(public_key: [u8; 32]) -> String {
    // libp2p public-key protobuf: field 1 (Ed25519 enum), field 2 (32 bytes).
    let mut multihash = Vec::with_capacity(38);
    multihash.extend_from_slice(&[0x00, 0x24, 0x08, 0x01, 0x12, 0x20]);
    multihash.extend_from_slice(&public_key);
    canonical_peer_id_from_multihash(&multihash)
}
fn parse_peer_id(value: &str) -> Result<String, RoutingError> {
    if value.is_empty() || value.len() > MAX_PATH_IDENTIFIER_BYTES {
        return Err(if value.len() > MAX_PATH_IDENTIFIER_BYTES {
            RoutingError::IdentifierTooLarge
        } else {
            RoutingError::InvalidPeerId
        });
    }
    let payload = value.strip_prefix('b').ok_or(RoutingError::InvalidPeerId)?;
    let cid = decode_base32_lower(payload).ok_or(RoutingError::InvalidPeerId)?;
    if format!("b{}", encode_base32_lower(&cid)) != value {
        return Err(RoutingError::InvalidPeerId);
    }
    let multihash = peer_multihash_from_cid(&cid)?;
    validate_peer_multihash(&multihash)?;
    if canonical_peer_id_from_multihash(&multihash) != value {
        return Err(RoutingError::InvalidPeerId);
    }
    Ok(value.to_owned())
}
fn peer_multihash_from_cid(cid: &[u8]) -> Result<Vec<u8>, RoutingError> {
    if cid.len() < 3 || cid[0] != 1 || cid[1] != 0x72 {
        return Err(RoutingError::InvalidPeerId);
    }
    Ok(cid[2..].to_vec())
}
fn validate_peer_multihash(multihash: &[u8]) -> Result<(), RoutingError> {
    let (code, code_len) = decode_uvarint(multihash).ok_or(RoutingError::InvalidPeerId)?;
    let (digest_len, len_len) =
        decode_uvarint(&multihash[code_len..]).ok_or(RoutingError::InvalidPeerId)?;
    let digest_len = usize::try_from(digest_len).map_err(|_| RoutingError::InvalidPeerId)?;
    let digest_offset = code_len.saturating_add(len_len);
    if digest_len == 0
        || digest_len > 42
        || digest_offset.checked_add(digest_len) != Some(multihash.len())
        || multihash[digest_offset..].iter().all(|byte| *byte == 0)
    {
        return Err(RoutingError::InvalidPeerId);
    }
    match code {
        0x00 => {}
        0x12 if digest_len == 32 => {}
        _ => return Err(RoutingError::InvalidPeerId),
    }
    Ok(())
}
fn canonical_peer_id_from_multihash(multihash: &[u8]) -> String {
    let mut cid = Vec::with_capacity(multihash.len() + 2);
    cid.extend_from_slice(&[1, 0x72]);
    cid.extend_from_slice(multihash);
    format!("b{}", encode_base32_lower(&cid))
}
fn decode_uvarint(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0u64;
    for (index, byte) in bytes.iter().copied().take(10).enumerate() {
        let shift = index.checked_mul(7)?;
        if shift == 63 && byte > 1 {
            return None;
        }
        value |= u64::from(byte & 0x7f).checked_shl(u32::try_from(shift).ok()?)?;
        if byte & 0x80 == 0 {
            let used = index + 1;
            if encode_uvarint(value).len() != used {
                return None;
            }
            return Some((value, used));
        }
    }
    None
}
fn encode_uvarint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
    out
}
fn encode_base32_lower(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::with_capacity(bytes.len().saturating_mul(8).div_ceil(5));
    let mut accumulator = 0u32;
    let mut bits = 0u8;
    for byte in bytes {
        accumulator = (accumulator << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let index = ((accumulator >> bits) & 0x1f) as usize;
            out.push(char::from(ALPHABET[index]));
        }
    }
    if bits > 0 {
        let index = ((accumulator << (5 - bits)) & 0x1f) as usize;
        out.push(char::from(ALPHABET[index]));
    }
    out
}
fn decode_base32_lower(value: &str) -> Option<Vec<u8>> {
    if value.is_empty() || !value.is_ascii() {
        return None;
    }
    let mut out = Vec::with_capacity(value.len().saturating_mul(5) / 8);
    let mut accumulator = 0u32;
    let mut bits = 0u8;
    for byte in value.bytes() {
        let digit = match byte {
            b'a'..=b'z' => byte - b'a',
            b'2'..=b'7' => byte - b'2' + 26,
            _ => return None,
        };
        accumulator = (accumulator << 5) | u32::from(digit);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((accumulator >> bits) & 0xff) as u8);
        }
    }
    if bits > 0 && accumulator & ((1u32 << bits) - 1) != 0 {
        return None;
    }
    Some(out)
}
fn encode_base58btc(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    if bytes.is_empty() {
        return String::new();
    }
    let leading_zeroes = bytes.iter().take_while(|byte| **byte == 0).count();
    let mut digits = vec![0u8];
    for byte in bytes {
        let mut carry = u32::from(*byte);
        for digit in digits.iter_mut().rev() {
            carry += u32::from(*digit) << 8;
            *digit = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.insert(0, (carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = String::with_capacity(leading_zeroes + digits.len());
    out.extend(std::iter::repeat_n('1', leading_zeroes));
    let skip = usize::from(digits.first() == Some(&0));
    for digit in digits.into_iter().skip(skip) {
        out.push(char::from(ALPHABET[usize::from(digit)]));
    }
    out
}
fn decode_base58btc(value: &str) -> Option<Vec<u8>> {
    if value.is_empty() || !value.is_ascii() {
        return None;
    }
    let leading_zeroes = value.bytes().take_while(|byte| *byte == b'1').count();
    let mut bytes = vec![0u8];
    for character in value.bytes() {
        let digit = base58_digit(character)?;
        let mut carry = u32::from(digit);
        for byte in bytes.iter_mut().rev() {
            carry += u32::from(*byte) * 58;
            *byte = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let skip = usize::from(bytes.first() == Some(&0));
    let mut out = vec![0u8; leading_zeroes];
    out.extend(bytes.into_iter().skip(skip));
    Some(out)
}
fn base58_digit(byte: u8) -> Option<u8> {
    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    ALPHABET
        .iter()
        .position(|candidate| *candidate == byte)
        .and_then(|index| u8::try_from(index).ok())
}
fn encode_base36_lower(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    if bytes.is_empty() {
        return String::new();
    }
    let leading_zeroes = bytes.iter().take_while(|byte| **byte == 0).count();
    let mut digits = vec![0u8];
    for byte in bytes {
        let mut carry = u32::from(*byte);
        for digit in digits.iter_mut().rev() {
            carry += u32::from(*digit) << 8;
            *digit = (carry % 36) as u8;
            carry /= 36;
        }
        while carry > 0 {
            digits.insert(0, (carry % 36) as u8);
            carry /= 36;
        }
    }
    let mut out = String::with_capacity(leading_zeroes + digits.len());
    out.extend(std::iter::repeat_n('0', leading_zeroes));
    let skip = usize::from(digits.first() == Some(&0));
    for digit in digits.into_iter().skip(skip) {
        out.push(char::from(ALPHABET[usize::from(digit)]));
    }
    out
}
fn decode_base36_lower(value: &str) -> Option<Vec<u8>> {
    if value.is_empty() || !value.is_ascii() {
        return None;
    }
    let leading_zeroes = value.bytes().take_while(|byte| *byte == b'0').count();
    let mut bytes = vec![0u8];
    for character in value.bytes() {
        let digit = match character {
            b'0'..=b'9' => character - b'0',
            b'a'..=b'z' => character - b'a' + 10,
            _ => return None,
        };
        let mut carry = u32::from(digit);
        for byte in bytes.iter_mut().rev() {
            carry += u32::from(*byte) * 36;
            *byte = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let skip = usize::from(bytes.first() == Some(&0));
    let mut out = vec![0u8; leading_zeroes];
    out.extend(bytes.into_iter().skip(skip));
    Some(out)
}
fn http_date(timestamp: u64) -> String {
    let datetime = i64::try_from(timestamp)
        .ok()
        .and_then(|timestamp| OffsetDateTime::from_unix_timestamp(timestamp).ok())
        .unwrap_or(OffsetDateTime::UNIX_EPOCH);
    let weekday = match datetime.weekday() {
        Weekday::Monday => "Mon",
        Weekday::Tuesday => "Tue",
        Weekday::Wednesday => "Wed",
        Weekday::Thursday => "Thu",
        Weekday::Friday => "Fri",
        Weekday::Saturday => "Sat",
        Weekday::Sunday => "Sun",
    };
    let month = match datetime.month() {
        Month::January => "Jan",
        Month::February => "Feb",
        Month::March => "Mar",
        Month::April => "Apr",
        Month::May => "May",
        Month::June => "Jun",
        Month::July => "Jul",
        Month::August => "Aug",
        Month::September => "Sep",
        Month::October => "Oct",
        Month::November => "Nov",
        Month::December => "Dec",
    };
    format!(
        "{weekday}, {:02} {month} {:04} {:02}:{:02}:{:02} GMT",
        datetime.day(),
        datetime.year(),
        datetime.hour(),
        datetime.minute(),
        datetime.second()
    )
}
fn unix_now_secs() -> u64 {
    u64::try_from(OffsetDateTime::now_utc().unix_timestamp()).unwrap_or(0)
}
#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header;
    use http_body_util::BodyExt as _;
    use sorafs_manifest::{
        AdvertSignature, AvailabilityTier, CapabilityTlv, CapabilityType, PathDiversityPolicy,
        ProviderAdvertBodyV1, ProviderCapabilityRangeV1, QosHints, RendezvousTopic,
        SignatureAlgorithm, StreamBudgetV1, TransportHintV1,
    };
    use std::sync::Arc;
    const NOW: u64 = 1_700_000_100;
    fn sample_cid(seed: u8) -> ManifestRootCid {
        ManifestRootCid::from_blake3_digest([seed.max(1); 32]).expect("canonical root CID")
    }
    fn sample_advert(
        provider_id: [u8; 32],
        key_seed: u8,
        with_protocols: bool,
    ) -> ProviderAdvertV1 {
        let (capabilities, stream_budget, transport_hints) = if with_protocols {
            (
                vec![
                    CapabilityTlv {
                        cap_type: CapabilityType::ToriiGateway,
                        payload: Vec::new(),
                    },
                    CapabilityTlv {
                        cap_type: CapabilityType::ChunkRangeFetch,
                        payload: ProviderCapabilityRangeV1::default()
                            .to_bytes()
                            .expect("encode range capability"),
                    },
                ],
                Some(StreamBudgetV1 {
                    max_in_flight: 2,
                    max_bytes_per_sec: 1_000,
                    burst_bytes: Some(500),
                }),
                Some(vec![
                    TransportHintV1 {
                        protocol: TransportProtocol::ToriiHttpRange,
                        priority: 0,
                    },
                    TransportHintV1 {
                        protocol: TransportProtocol::QuicStream,
                        priority: 1,
                    },
                ]),
            )
        } else {
            (
                vec![CapabilityTlv {
                    cap_type: CapabilityType::ToriiGateway,
                    payload: Vec::new(),
                }],
                None,
                None,
            )
        };
        let body = ProviderAdvertBodyV1 {
            provider_id,
            profile_id: "sorafs.sf1@1.0.0".to_owned(),
            profile_aliases: Some(vec!["sorafs.sf1@1.0.0".to_owned(), "sorafs-sf1".to_owned()]),
            stake: sorafs_manifest::StakePointer {
                pool_id: [provider_id[0].wrapping_add(1).max(1); 32],
                stake_amount: "1".parse().expect("canonical stake quantity"),
            },
            qos: QosHints {
                availability: AvailabilityTier::Hot,
                max_retrieval_latency_ms: 1,
                max_concurrent_streams: 1,
            },
            capabilities,
            endpoints: vec![
                AdvertEndpoint {
                    kind: EndpointKind::Torii,
                    host_pattern: format!("provider-{}.example:8443", provider_id[0]),
                    metadata: Vec::new(),
                },
                AdvertEndpoint {
                    kind: EndpointKind::Quic,
                    host_pattern: format!("provider-{}.example", provider_id[0]),
                    metadata: Vec::new(),
                },
            ],
            rendezvous_topics: vec![RendezvousTopic {
                topic: "sorafs.sf1.primary".to_owned(),
                region: "global".to_owned(),
            }],
            path_policy: PathDiversityPolicy {
                min_guard_weight: 1,
                max_same_asn_per_path: 1,
                max_same_pool_per_path: 1,
            },
            notes: None,
            stream_budget,
            transport_hints,
        };
        let advert = ProviderAdvertV1 {
            version: sorafs_manifest::PROVIDER_ADVERT_VERSION_V1,
            network_id: [0xA1; 32],
            issued_at: NOW.saturating_sub(10),
            expires_at: NOW.saturating_add(600),
            body,
            signature: AdvertSignature {
                algorithm: SignatureAlgorithm::Ed25519,
                public_key: vec![key_seed.max(1); 32],
                signature: vec![1; 64],
            },
            signature_strict: true,
            allow_unknown_capabilities: false,
        };
        advert
            .validate_with_body(NOW)
            .expect("test advert body must validate");
        advert
    }
    fn sample_peer(seed: u8) -> RoutingPeer {
        RoutingPeer {
            provider_id: [seed.max(1); 32],
            id: peer_id_from_ed25519_key([seed.max(1); 32]),
            addrs: vec![format!("/dns/provider-{seed}.example/tcp/443/tls/http")],
            protocols: vec![
                PROTOCOL_QUIC_STREAM.to_owned(),
                PROTOCOL_TORII_HTTP_RANGE.to_owned(),
            ],
            issued_at: NOW.saturating_sub(u64::from(seed)),
            expires_at: NOW.saturating_add(600),
        }
    }
    #[test]
    fn content_cid_accepts_canonical_multibases_and_rejects_identity_or_alias_encodings() {
        let cid = sample_cid(0xA5);
        let bytes = cid.as_bytes();
        for encoded in [
            format!("b{}", encode_base32_lower(bytes)),
            format!("k{}", encode_base36_lower(bytes)),
            format!("z{}", encode_base58btc(bytes)),
        ] {
            assert_eq!(parse_content_cid(&encoded), Ok(cid));
        }
        let uppercase = format!("B{}", encode_base32_lower(bytes).to_ascii_uppercase());
        assert_eq!(
            parse_content_cid(&uppercase),
            Err(RoutingError::InvalidContentCid)
        );
        let mut identity_cid = bytes.to_vec();
        identity_cid[2] = 0;
        assert_eq!(
            parse_content_cid(&format!("b{}", encode_base32_lower(&identity_cid))),
            Err(RoutingError::InvalidContentCid)
        );
        assert_eq!(
            parse_content_cid(&"b".repeat(MAX_PATH_IDENTIFIER_BYTES + 1)),
            Err(RoutingError::IdentifierTooLarge)
        );
        assert_eq!(
            parse_content_cid("not-a-cid"),
            Err(RoutingError::InvalidContentCid)
        );
    }
    #[test]
    fn non_ascii_content_cid_returns_client_error_and_follow_up_still_parses() {
        let error = parse_content_cid("é").expect_err("non-ASCII CID must be rejected");
        let response = routing_error_response(error);
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let cid = sample_cid(0xA6);
        let encoded = format!("b{}", encode_base32_lower(cid.as_bytes()));
        assert_eq!(parse_content_cid(&encoded), Ok(cid));
    }
    #[test]
    fn base_encodings_round_trip_leading_zeroes_and_reject_noncanonical_tail_bits() {
        for bytes in [
            Vec::new(),
            vec![0],
            vec![0, 0, 1],
            vec![1, 2, 3, 4, 5, 0xff],
        ] {
            let base32 = encode_base32_lower(&bytes);
            if bytes.is_empty() {
                assert!(decode_base32_lower(&base32).is_none());
            } else {
                assert_eq!(
                    decode_base32_lower(&base32).as_deref(),
                    Some(bytes.as_slice())
                );
            }
            let base36 = encode_base36_lower(&bytes);
            if bytes.is_empty() {
                assert!(decode_base36_lower(&base36).is_none());
            } else {
                assert_eq!(
                    decode_base36_lower(&base36).as_deref(),
                    Some(bytes.as_slice())
                );
            }
            let base58 = encode_base58btc(&bytes);
            if bytes.is_empty() {
                assert!(decode_base58btc(&base58).is_none());
            } else {
                assert_eq!(decode_base58btc(&base58).as_deref(), Some(bytes.as_slice()));
            }
        }
        assert!(
            decode_base32_lower("ab").is_none(),
            "non-zero pad bits must fail"
        );
    }
    #[test]
    fn peer_id_parser_accepts_only_canonical_base32_cid_v1() {
        let canonical = peer_id_from_ed25519_key([0xA5; 32]);
        assert_eq!(parse_peer_id(&canonical), Ok(canonical.clone()));
        let cid = decode_base32_lower(&canonical[1..]).expect("decode canonical peer CID");
        let multihash = &cid[2..];
        let legacy = encode_base58btc(multihash);
        assert_eq!(parse_peer_id(&legacy), Err(RoutingError::InvalidPeerId));
        let base36 = format!("k{}", encode_base36_lower(&cid));
        assert_eq!(parse_peer_id(&base36), Err(RoutingError::InvalidPeerId));
        assert_eq!(
            parse_peer_id(&canonical.to_ascii_uppercase()),
            Err(RoutingError::InvalidPeerId)
        );
    }
    #[test]
    fn peer_id_parser_rejects_malformed_noncanonical_and_oversized_inputs() {
        for invalid in ["", "b", "kZZ", "0OIl", "znot-a-peer"] {
            assert!(matches!(
                parse_peer_id(invalid),
                Err(RoutingError::InvalidPeerId)
            ));
        }
        let mut oversized_identity = vec![0, 43];
        oversized_identity.extend([1; 43]);
        assert_eq!(
            parse_peer_id(&encode_base58btc(&oversized_identity)),
            Err(RoutingError::InvalidPeerId)
        );
        assert_eq!(
            parse_peer_id(&"1".repeat(MAX_PATH_IDENTIFIER_BYTES + 1)),
            Err(RoutingError::IdentifierTooLarge)
        );
        assert!(
            decode_uvarint(&[0x80, 0]).is_none(),
            "overlong varint must fail"
        );
    }
    #[test]
    fn query_parser_rejects_non_literal_malformed_and_unsupported_parameters() {
        assert_eq!(RoutingFilters::parse(None), Ok(RoutingFilters::default()));
        for query in [
            "",
            "&",
            "filter-addrs",
            "=tcp",
            "filter-addrs=tcp=udp",
            "filter-addrs=tcp&",
            "&filter-addrs=tcp",
            "filter-addrs=tcp&&filter-protocols=transport-a",
        ] {
            assert_eq!(
                RoutingFilters::parse(Some(query)),
                Err(RoutingError::MalformedQuery),
                "query {query:?} must be rejected as malformed"
            );
        }
        for query in [
            "filter%2Daddrs=tcp",
            "%66ilter-addrs=tcp",
            "filter+addrs=tcp",
            "filter-addrs=tcp%2Cudp",
            "filter-addrs=%FF",
        ] {
            assert_eq!(
                RoutingFilters::parse(Some(query)),
                Err(RoutingError::NonCanonicalQueryEncoding),
                "query {query:?} must not acquire an encoded alias"
            );
        }
        for (query, expected) in [
            (
                "filter-addrs=tcp&filter-addrs=udp",
                RoutingError::DuplicateQueryParameter,
            ),
            ("FILTER-ADDRS=tcp", RoutingError::UnknownQueryParameter),
            ("filter-addrs=tcp&x=1", RoutingError::UnknownQueryParameter),
            ("filter-addrs=TCP,tcp", RoutingError::DuplicateFilter),
            ("filter-addrs=tcp,!TCP", RoutingError::DuplicateFilter),
            (
                "filter-protocols=transport-sorafs-quic-stream,TRANSPORT-SORAFS-QUIC-STREAM",
                RoutingError::DuplicateFilter,
            ),
            ("filter-protocols=!transport-a", RoutingError::InvalidFilter),
            ("filter-addrs=!unknown", RoutingError::InvalidFilter),
            ("filter-addrs=", RoutingError::EmptyFilter),
        ] {
            assert_eq!(RoutingFilters::parse(Some(query)), Err(expected));
        }
        assert_eq!(
            RoutingFilters::parse(Some(
                "filter-addrs=tcp&filter-protocols=transport-a&extra=value"
            )),
            Err(RoutingError::TooManyQueryParameters)
        );
        let oversized = format!("filter-addrs={}", "a".repeat(MAX_FILTER_VALUE_BYTES + 1));
        assert_eq!(
            RoutingFilters::parse(Some(&oversized)),
            Err(RoutingError::FilterTooLarge)
        );
        let oversized_query = "x".repeat(MAX_RAW_QUERY_BYTES + 1);
        assert_eq!(
            RoutingFilters::parse(Some(&oversized_query)),
            Err(RoutingError::QueryTooLarge)
        );
    }
    #[test]
    fn query_parser_preserves_literal_plus_in_protocol_filter_terms() {
        let filters = RoutingFilters::parse(Some("filter-protocols=transport-a+b"))
            .expect("literal plus is part of the protocol filter grammar");
        assert_eq!(
            filters.protocols,
            Some(BTreeSet::from(["transport-a+b".to_owned()]))
        );
    }
    #[test]
    fn address_filters_apply_positive_negative_unknown_and_case_insensitive_semantics() {
        let filters = RoutingFilters::parse(Some("filter-addrs=TCP,!IP6")).unwrap();
        let peer = RoutingPeer {
            addrs: vec![
                "/ip6/2001:db8::1/tcp/443/tls/http".to_owned(),
                "/dns/example.test/tcp/443/tls/http".to_owned(),
                "/dns/example.test/udp/443/quic-v1".to_owned(),
            ],
            ..sample_peer(1)
        };
        let filtered = filters.apply(peer).expect("one TCP address survives");
        assert_eq!(filtered.addrs, vec!["/dns/example.test/tcp/443/tls/http"]);
        let unknown = RoutingPeer {
            addrs: Vec::new(),
            ..sample_peer(2)
        };
        assert!(filters.apply(unknown.clone()).is_none());
        let unknown_filter = RoutingFilters::parse(Some("filter-addrs=unknown")).unwrap();
        assert!(unknown_filter.apply(unknown).is_some());
        assert!(unknown_filter.apply(sample_peer(3)).is_none());
    }
    #[test]
    fn address_filter_never_confuses_a_host_value_for_a_protocol() {
        let filters = AddressFilters::parse("tcp").unwrap();
        assert!(!filters.matches("/dns/tcp/udp/443/quic-v1"));
        assert!(filters.matches("/dns/example.test/tcp/443/tls/http"));
    }
    #[test]
    fn protocol_filters_preserve_full_protocol_set_and_handle_unknown() {
        let filters =
            RoutingFilters::parse(Some("filter-protocols=TRANSPORT-SORAFS-HTTP-RANGE")).unwrap();
        let peer = sample_peer(4);
        let expected = peer.protocols.clone();
        assert_eq!(filters.apply(peer).unwrap().protocols, expected);
        let unknown = RoutingPeer {
            protocols: Vec::new(),
            ..sample_peer(5)
        };
        assert!(filters.apply(unknown.clone()).is_none());
        let unknown_filter = RoutingFilters::parse(Some("filter-protocols=unknown")).unwrap();
        assert!(unknown_filter.apply(unknown).is_some());
    }
    #[test]
    fn accept_negotiation_defaults_to_json_and_honors_quality_without_q_zero_bypass() {
        let headers = HeaderMap::new();
        assert_eq!(negotiate_representation(&headers), Ok(Representation::Json));
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static(CONTENT_TYPE_NDJSON));
        assert_eq!(
            negotiate_representation(&headers),
            Ok(Representation::Ndjson)
        );
        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/x-ndjson, */*"),
        );
        assert_eq!(
            negotiate_representation(&headers),
            Ok(Representation::Ndjson),
            "an exact NDJSON request outranks an equal wildcard"
        );
        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/x-ndjson;Q=0, application/json;q=0.5"),
        );
        assert_eq!(negotiate_representation(&headers), Ok(Representation::Json));
        headers.insert(ACCEPT, HeaderValue::from_static("text/plain"));
        assert_eq!(
            negotiate_representation(&headers),
            Err(RoutingError::NotAcceptable)
        );
        headers.insert(ACCEPT, HeaderValue::from_static("application/json;q=1.1"));
        assert_eq!(
            negotiate_representation(&headers),
            Err(RoutingError::InvalidAccept)
        );
    }
    #[test]
    fn expired_adverts_and_unassigned_or_missing_adverts_never_publish_routes() {
        let provider = [0x71; 32];
        let mut expired = sample_advert(provider, 1, false);
        expired.expires_at = NOW;
        assert!(
            resolve_advert_peers([(provider, &expired)], NOW, &RoutingFilters::default())
                .unwrap()
                .is_empty()
        );
        assert!(
            resolve_advert_peers(std::iter::empty(), NOW, &RoutingFilters::default())
                .unwrap()
                .is_empty()
        );
        let advert = sample_advert(provider, 1, false);
        assert_eq!(
            resolve_advert_peers([([0x72; 32], &advert)], NOW, &RoutingFilters::default()),
            Err(RoutingError::AdvertCorrupt)
        );
    }
    #[test]
    fn peer_key_reuse_is_rejected_as_equivocation() {
        let first = sample_advert([0x81; 32], 9, false);
        let second = sample_advert([0x82; 32], 9, false);
        assert_eq!(
            resolve_advert_peers(
                [([0x81; 32], &first), ([0x82; 32], &second)],
                NOW,
                &RoutingFilters::default()
            ),
            Err(RoutingError::PeerIdentityEquivocation)
        );
    }
    #[test]
    fn peer_results_are_deterministic_across_advert_iteration_order() {
        let first = sample_advert([0x91; 32], 3, true);
        let second = sample_advert([0x92; 32], 2, true);
        let forward = resolve_advert_peers(
            [([0x91; 32], &first), ([0x92; 32], &second)],
            NOW,
            &RoutingFilters::default(),
        )
        .unwrap();
        let reverse = resolve_advert_peers(
            [([0x92; 32], &second), ([0x91; 32], &first)],
            NOW,
            &RoutingFilters::default(),
        )
        .unwrap();
        assert_eq!(forward, reverse);
        assert!(forward.windows(2).all(|pair| pair[0].id < pair[1].id));
        assert!(forward.iter().all(|peer| {
            peer.addrs.windows(2).all(|pair| pair[0] < pair[1])
                && peer.protocols.windows(2).all(|pair| pair[0] < pair[1])
        }));
    }
    #[test]
    fn endpoint_projection_is_canonical_and_unsafe_endpoints_become_unknown() {
        let endpoint = |kind, host_pattern: &str| AdvertEndpoint {
            kind,
            host_pattern: host_pattern.to_owned(),
            metadata: Vec::new(),
        };
        assert_eq!(
            endpoint_multiaddr(&endpoint(EndpointKind::Torii, "EXAMPLE.test:8443")),
            Some("/dns/example.test/tcp/8443/tls/http".to_owned())
        );
        assert_eq!(
            endpoint_multiaddr(&endpoint(EndpointKind::Quic, "https://[2001:db8::1]:4443")),
            Some("/ip6/2001:db8::1/udp/4443/quic-v1".to_owned())
        );
        for invalid in [
            "http://example.test",
            "https://user@example.test",
            "https://example.test/path",
            "*.example.test",
            "example.test%2f@evil.test",
            " example.test",
        ] {
            assert!(endpoint_multiaddr(&endpoint(EndpointKind::Torii, invalid)).is_none());
        }
    }
    #[tokio::test]
    async fn response_negotiation_emits_bounded_json_and_ndjson_with_cache_headers() {
        let peers = (1..=105).map(sample_peer).collect::<Vec<_>>();
        let response = routing_success_response("Providers", peers, Representation::Json, NOW);
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[CONTENT_TYPE], CONTENT_TYPE_JSON);
        assert_eq!(response.headers()[VARY], "Accept");
        assert_eq!(response.headers()[ACCESS_CONTROL_ALLOW_ORIGIN], "*");
        assert!(
            response.headers()[CACHE_CONTROL]
                .to_str()
                .unwrap()
                .contains("max-age=300")
        );
        assert!(response.headers().contains_key(LAST_MODIFIED));
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let value: Value = json::from_slice(&body).unwrap();
        assert_eq!(
            value
                .get("Providers")
                .and_then(Value::as_array)
                .map(Vec::len),
            Some(JSON_RESULT_LIMIT)
        );
        let response = routing_success_response(
            "Peers",
            vec![sample_peer(1), sample_peer(2)],
            Representation::Ndjson,
            NOW,
        );
        assert_eq!(response.headers()[CONTENT_TYPE], CONTENT_TYPE_NDJSON);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let lines = std::str::from_utf8(&body)
            .unwrap()
            .lines()
            .collect::<Vec<_>>();
        assert_eq!(lines.len(), 2);
        for line in lines {
            let value: Value = json::from_str(line).unwrap();
            assert_eq!(value.get("Schema").and_then(Value::as_str), Some("peer"));
        }
    }
    #[tokio::test]
    async fn empty_results_use_short_negative_cache_ttl_and_spec_error_shape() {
        let response = routing_success_response("Providers", Vec::new(), Representation::Json, NOW);
        assert!(
            response.headers()[CACHE_CONTROL]
                .to_str()
                .unwrap()
                .contains("max-age=15")
        );
        let response = routing_error_response(RoutingError::InvalidContentCid);
        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let value: Value = json::from_slice(&body).unwrap();
        assert_eq!(value.get("Code").and_then(Value::as_u64), Some(422));
        assert!(value.get("Message").and_then(Value::as_str).is_some());
    }
    #[test]
    fn http_date_uses_imf_fixdate() {
        assert_eq!(http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(http_date(784_111_777), "Sun, 06 Nov 1994 08:49:37 GMT");
    }
    #[test]
    fn advert_endpoint_bound_preserves_canonical_validation() {
        use sorafs_manifest::provider_advert::PROVIDER_ADVERT_ENDPOINTS_MAX_V1;

        let mut advert = sample_advert([0xA1; 32], 1, false);
        advert.body.endpoints = (0..PROVIDER_ADVERT_ENDPOINTS_MAX_V1)
            .map(|index| AdvertEndpoint {
                kind: EndpointKind::Torii,
                host_pattern: format!("provider-{index}.example"),
                metadata: Vec::new(),
            })
            .collect();
        let peer = RoutingPeer::from_advert(&advert, NOW)
            .expect("advert at the canonical endpoint limit validates")
            .expect("unexpired advert");
        assert_eq!(peer.addrs.len(), PROVIDER_ADVERT_ENDPOINTS_MAX_V1);
        advert.body.endpoints.push(AdvertEndpoint {
            kind: EndpointKind::Torii,
            host_pattern: "one-too-many.example".to_owned(),
            metadata: Vec::new(),
        });
        assert_eq!(
            RoutingPeer::from_advert(&advert, NOW),
            Err(RoutingError::AdvertCapacityExceeded)
        );
        advert.body.endpoints.pop();
        advert.body.endpoints[0].host_pattern.clear();
        assert_eq!(
            RoutingPeer::from_advert(&advert, NOW),
            Err(RoutingError::AdvertCorrupt),
            "an in-budget advert must still pass canonical body validation"
        );
    }
    #[test]
    fn empty_cache_is_deny_all_for_authorized_provider_ids() {
        let cache = ProviderAdvertCache::new(
            [CapabilityType::ToriiGateway],
            Arc::new(crate::sorafs::AdmissionRegistry::empty([0xA1; 32])),
        );
        assert!(
            resolve_authorized_peers(
                &BTreeSet::from([[0xB1; 32]]),
                &cache,
                NOW,
                &RoutingFilters::default()
            )
            .unwrap()
            .is_empty()
        );
    }
    #[test]
    fn error_responses_never_reflect_attacker_controlled_identifiers() {
        let response = routing_error_response(RoutingError::InvalidPeerId);
        assert_eq!(response.headers()[header::CONTENT_TYPE], CONTENT_TYPE_JSON);
        assert!(!RoutingError::InvalidPeerId.message().contains("attacker"));
    }
}
