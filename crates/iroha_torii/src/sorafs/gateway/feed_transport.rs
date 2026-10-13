//! Production HTTPS transport for governed SoraFS compliance feeds.
//!
//! The controller validates URL policy, public DNS answers, redirects, and configured trust pins.
//! This transport enforces the runtime side of that contract: a bounded system resolver, exact
//! address pinning, authenticated HTTPS, explicit content encodings, and bounded response
//! buffering. Construction also seals the canonical trust inventory into the runtime identity that
//! the controller verifies at startup and around feed use.
use super::compliance::{
    GatewayComplianceContentEncoding, GatewayComplianceError, GatewayComplianceFeedTransport,
    GatewayComplianceFeedTransportIdentityV1, GatewayComplianceFeedTransportProbeError,
    GatewayComplianceFetchRequest, GatewayComplianceFetchResponse,
};
use http::{
    HeaderMap, HeaderName,
    header::{CONTENT_ENCODING, CONTENT_LENGTH, LOCATION},
};
use iroha_config::parameters::defaults::sorafs::gateway::compliance::{
    GATEWAY_COMPLIANCE_FEED_TRANSPORT_HANDLE_V1, GATEWAY_COMPLIANCE_FEED_TRANSPORT_REVISION_V1,
};
use reqwest::{redirect::Policy, tls::TlsInfo};
use sha2::{Digest as _, Sha256};
use sorafs_manifest::gateway_compliance::{
    MAX_GATEWAY_COMPLIANCE_CATALOG_BYTES_V1, gateway_compliance_feed_transport_policy_digest,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    io::Read,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs as _},
    sync::{
        Arc, Mutex,
        mpsc::{self, Receiver, SyncSender, TrySendError},
    },
    thread,
    time::{Duration, Instant},
};
use url::Host;
use x509_parser::parse_x509_certificate;
const RESOLVER_WORKERS: usize = 4;
const RESOLVER_QUEUE_CAPACITY: usize = 16;
const MAX_RESOLVED_ADDRESSES: usize = 64;
const MAX_PINNED_ADDRESSES: usize = 32;
const MAX_DNS_HOSTNAME_BYTES: usize = 253;
const MAX_FEED_URL_BYTES: usize = 2_048;
const MAX_REDIRECT_LOCATION_BYTES: usize = 2_048;
const MAX_RESPONSE_HEADER_COUNT: usize = 64;
const MAX_RESPONSE_HEADER_BYTES: usize = 32 * 1_024;
const READ_BUFFER_BYTES: usize = 8 * 1_024;
const MAX_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_TOTAL_TIMEOUT: Duration = Duration::from_secs(120);
type Resolver = dyn Fn(&str) -> Result<Vec<IpAddr>, ResolveFailure> + Send + Sync + 'static;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResolveFailure {
    Deadline,
    Lookup,
    ProviderPanic,
    TooManyAddresses,
}
struct ResolveJob {
    hostname: String,
    deadline: Instant,
    reply: SyncSender<Result<Vec<IpAddr>, ResolveFailure>>,
}
struct ResolverPool {
    sender: SyncSender<ResolveJob>,
    worker_count: usize,
    queue_capacity: usize,
}
impl fmt::Debug for ResolverPool {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolverPool")
            .field("worker_count", &self.worker_count)
            .field("queue_capacity", &self.queue_capacity)
            .finish_non_exhaustive()
    }
}
impl ResolverPool {
    fn new() -> Result<Self, GatewayComplianceError> {
        Self::new_with(
            RESOLVER_WORKERS,
            RESOLVER_QUEUE_CAPACITY,
            Arc::new(resolve_system_hostname),
        )
    }
    fn new_with(
        worker_count: usize,
        queue_capacity: usize,
        resolver: Arc<Resolver>,
    ) -> Result<Self, GatewayComplianceError> {
        if worker_count == 0 || queue_capacity == 0 {
            return Err(GatewayComplianceError::InvalidPolicy(
                "gateway compliance resolver bounds are invalid".into(),
            ));
        }
        let (sender, receiver) = mpsc::sync_channel(queue_capacity);
        let receiver = Arc::new(Mutex::new(receiver));
        for worker_index in 0..worker_count {
            let receiver = Arc::clone(&receiver);
            let resolver = Arc::clone(&resolver);
            // Dropping a `JoinHandle` intentionally detaches the fixed worker;
            // channel disconnection still stops idle workers when the
            // transport is dropped.
            let _worker = thread::Builder::new()
                .name(format!("sorafs-compliance-dns-{worker_index}"))
                .spawn(move || resolver_worker(receiver, resolver))
                .map_err(|_| {
                    GatewayComplianceError::InvalidFeed("DNS resolver initialization failed".into())
                })?;
        }
        Ok(Self {
            sender,
            worker_count,
            queue_capacity,
        })
    }
    fn resolve(
        &self,
        hostname: &str,
        timeout: Duration,
    ) -> Result<Vec<IpAddr>, GatewayComplianceError> {
        validate_dns_hostname(hostname)?;
        if timeout.is_zero() || timeout > MAX_CONNECT_TIMEOUT {
            return Err(GatewayComplianceError::InvalidPolicy(
                "invalid compliance DNS resolution deadline".into(),
            ));
        }
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(GatewayComplianceError::FetchTimeout)?;
        let (reply, result) = mpsc::sync_channel(1);
        let job = ResolveJob {
            hostname: hostname.to_owned(),
            deadline,
            reply,
        };
        match self.sender.try_send(job) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                return Err(GatewayComplianceError::FetchTimeout);
            }
            Err(TrySendError::Disconnected(_)) => {
                return Err(GatewayComplianceError::InvalidFeed(
                    "DNS resolver unavailable".into(),
                ));
            }
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(GatewayComplianceError::FetchTimeout)?;
        match result.recv_timeout(remaining) {
            Ok(Ok(addresses)) => {
                if addresses.is_empty() || addresses.len() > MAX_RESOLVED_ADDRESSES {
                    Err(GatewayComplianceError::UnsafeAddressSet {
                        found: addresses.len(),
                        maximum: MAX_RESOLVED_ADDRESSES,
                    })
                } else if addresses.iter().any(|address| !is_public_ip(*address)) {
                    Err(GatewayComplianceError::NonPublicAddress)
                } else {
                    Ok(addresses)
                }
            }
            Ok(Err(ResolveFailure::TooManyAddresses)) => {
                Err(GatewayComplianceError::ResourceLimit {
                    resource: "resolved compliance feed addresses",
                    found: MAX_RESOLVED_ADDRESSES.saturating_add(1),
                    maximum: MAX_RESOLVED_ADDRESSES,
                })
            }
            Ok(Err(ResolveFailure::Lookup)) => Err(GatewayComplianceError::InvalidFeed(
                "DNS resolution failed".into(),
            )),
            Ok(Err(ResolveFailure::ProviderPanic)) => Err(GatewayComplianceError::InvalidFeed(
                "DNS resolver provider panicked".into(),
            )),
            Ok(Err(ResolveFailure::Deadline)) => Err(GatewayComplianceError::FetchTimeout),
            Err(mpsc::RecvTimeoutError::Timeout) => Err(GatewayComplianceError::FetchTimeout),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(GatewayComplianceError::InvalidFeed(
                "DNS resolver unavailable".into(),
            )),
        }
    }
}
fn resolver_worker(receiver: Arc<Mutex<Receiver<ResolveJob>>>, resolver: Arc<Resolver>) {
    loop {
        let job = {
            let Ok(receiver) = receiver.lock() else {
                return;
            };
            receiver.recv()
        };
        let Ok(job) = job else {
            return;
        };
        let result = if Instant::now() >= job.deadline {
            Err(ResolveFailure::Deadline)
        } else {
            iroha_panic_hook::catch_unwind_suppressed(|| resolver(&job.hostname))
                .unwrap_or(Err(ResolveFailure::ProviderPanic))
        };
        let _ = job.reply.try_send(result);
    }
}
fn resolve_system_hostname(hostname: &str) -> Result<Vec<IpAddr>, ResolveFailure> {
    let socket_addresses = (hostname, 443)
        .to_socket_addrs()
        .map_err(|_| ResolveFailure::Lookup)?;
    let mut addresses = BTreeSet::new();
    for socket_address in socket_addresses {
        let address = socket_address.ip();
        if !addresses.contains(&address) && addresses.len() == MAX_RESOLVED_ADDRESSES {
            return Err(ResolveFailure::TooManyAddresses);
        }
        addresses.insert(address);
    }
    Ok(addresses.into_iter().collect())
}
/// Credential-free, address-pinned production HTTPS transport.
///
/// Construction creates a fixed-size system-resolver pool. A timed-out system lookup may occupy one
/// worker until the operating system returns, but the worker count and pending queue are fixed, so
/// timeouts cannot create an unbounded population of lingering resolver threads or jobs.
pub struct ProductionGatewayComplianceFeedTransport {
    resolver: ResolverPool,
    accepted_spki_sha256_by_hostname: BTreeMap<String, BTreeSet<[u8; 32]>>,
    identity: GatewayComplianceFeedTransportIdentityV1,
}
impl fmt::Debug for ProductionGatewayComplianceFeedTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProductionGatewayComplianceFeedTransport")
            .field("resolver", &self.resolver)
            .field(
                "trusted_hostname_count",
                &self.accepted_spki_sha256_by_hostname.len(),
            )
            .field("provider_handle", &self.identity.provider_handle)
            .field("revision", &self.identity.revision)
            .finish()
    }
}
impl ProductionGatewayComplianceFeedTransport {
    /// Create the standard no-secret production transport from resolved trust
    /// pins keyed by canonical DNS hostname. An empty inventory is a qualified deny-all
    /// external transport; catalog authorization and activation remain in the controller.
    ///
    /// # Errors
    ///
    /// Returns an error if the trust inventory is invalid or the bounded
    /// resolver workers cannot be created.
    pub fn try_new(
        accepted_spki_sha256_by_hostname: BTreeMap<String, BTreeSet<[u8; 32]>>,
    ) -> Result<Self, GatewayComplianceError> {
        for (hostname, pins) in &accepted_spki_sha256_by_hostname {
            validate_dns_hostname(hostname)?;
            if pins.is_empty() || pins.iter().any(|pin| pin.iter().all(|byte| *byte == 0)) {
                return Err(GatewayComplianceError::InvalidPolicy(
                    "invalid compliance HTTPS trust-pin inventory".into(),
                ));
            }
        }
        let identity = GatewayComplianceFeedTransportIdentityV1 {
            provider_handle: GATEWAY_COMPLIANCE_FEED_TRANSPORT_HANDLE_V1.to_owned(),
            revision: GATEWAY_COMPLIANCE_FEED_TRANSPORT_REVISION_V1,
            policy_digest: gateway_compliance_feed_transport_policy_digest(
                &accepted_spki_sha256_by_hostname,
            )?,
            test_marked: false,
        };
        Ok(Self {
            resolver: ResolverPool::new()?,
            accepted_spki_sha256_by_hostname,
            identity,
        })
    }
    fn require_configured_host(&self, hostname: &str) -> Result<(), GatewayComplianceError> {
        if self.accepted_spki_sha256_by_hostname.contains_key(hostname) {
            Ok(())
        } else {
            Err(GatewayComplianceError::TrustPinMismatch)
        }
    }
    fn verify_spki(
        &self,
        hostname: &str,
        peer_spki_sha256: [u8; 32],
    ) -> Result<(), GatewayComplianceError> {
        if self
            .accepted_spki_sha256_by_hostname
            .get(hostname)
            .is_some_and(|pins| pins.contains(&peer_spki_sha256))
        {
            Ok(())
        } else {
            Err(GatewayComplianceError::TrustPinMismatch)
        }
    }
}
impl GatewayComplianceFeedTransport for ProductionGatewayComplianceFeedTransport {
    fn qualification(
        &self,
    ) -> Result<GatewayComplianceFeedTransportIdentityV1, GatewayComplianceFeedTransportProbeError>
    {
        Ok(self.identity.clone())
    }
    fn resolve(
        &self,
        hostname: &str,
        timeout: Duration,
    ) -> Result<Vec<IpAddr>, GatewayComplianceError> {
        self.require_configured_host(hostname)?;
        self.resolver.resolve(hostname, timeout)
    }
    fn fetch(
        &self,
        request: &GatewayComplianceFetchRequest,
    ) -> Result<GatewayComplianceFetchResponse, GatewayComplianceError> {
        fetch_pinned(self, request)
    }
}
fn fetch_pinned(
    transport: &ProductionGatewayComplianceFeedTransport,
    request: &GatewayComplianceFetchRequest,
) -> Result<GatewayComplianceFetchResponse, GatewayComplianceError> {
    let started = Instant::now();
    let (hostname, port) = validate_fetch_request(request)?;
    // Refuse unconfigured hosts before allocating client/address state or opening any socket.
    // In particular, an explicitly empty inventory can never be an outbound transport.
    transport.require_configured_host(hostname)?;
    let socket_addresses: Vec<_> = request
        .pinned_addresses
        .iter()
        .copied()
        .map(|address| SocketAddr::new(address, port))
        .collect();
    let remaining = remaining_time(started, request.total_timeout)?;
    let max_response_header_bytes = u32::try_from(MAX_RESPONSE_HEADER_BYTES).map_err(|_| {
        GatewayComplianceError::InvalidPolicy(
            "compliance response header bound is not representable".into(),
        )
    })?;
    let client = reqwest::blocking::Client::builder()
        // Reqwest has no cookie store unless one is explicitly installed. The
        // production transport also starts with no caller-supplied headers, so
        // feed requests cannot inherit credentials from daemon state.
        .default_headers(HeaderMap::new())
        .https_only(true)
        .use_rustls_tls()
        .redirect(Policy::none())
        .no_proxy()
        .referer(false)
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
        .http2_max_header_list_size(max_response_header_bytes)
        .tls_info(true)
        .connect_timeout(request.connect_timeout.min(remaining))
        .timeout(remaining)
        .resolve_to_addrs(hostname, &socket_addresses)
        .build()
        .map_err(|_| {
            GatewayComplianceError::InvalidFeed("HTTPS transport initialization failed".into())
        })?;
    let remaining = remaining_time(started, request.total_timeout)?;
    let mut response = client
        .get(request.url.clone())
        .timeout(remaining)
        .send()
        .map_err(map_reqwest_error)?;
    let connected_address = response
        .remote_addr()
        .map(|address| address.ip())
        .ok_or_else(|| {
            GatewayComplianceError::InvalidFeed(
                "HTTPS transport omitted the connected peer address".into(),
            )
        })?;
    if !request.pinned_addresses.contains(&connected_address) {
        return Err(GatewayComplianceError::DnsRebinding);
    }
    let peer_spki_sha256 = response
        .extensions()
        .get::<TlsInfo>()
        .and_then(TlsInfo::peer_certificate)
        .ok_or_else(|| {
            GatewayComplianceError::InvalidFeed(
                "HTTPS transport omitted the peer certificate".into(),
            )
        })
        .and_then(spki_sha256)?;
    transport.verify_spki(hostname, peer_spki_sha256)?;
    validate_response_headers(response.headers())?;
    let status = response.status().as_u16();
    let content_encoding = parse_content_encoding(response.headers())?;
    let redirect_location = parse_redirect_location(response.headers())?;
    let content_length = parse_content_length(response.headers(), request.max_encoded_bytes)?;
    remaining_time(started, request.total_timeout)?;
    let body = read_body_bounded(
        &mut response,
        request.max_encoded_bytes,
        content_length,
        started,
        request.total_timeout,
    )?;
    let elapsed = started.elapsed();
    if elapsed >= request.total_timeout {
        return Err(GatewayComplianceError::FetchTimeout);
    }
    Ok(GatewayComplianceFetchResponse {
        status,
        redirect_location,
        connected_address,
        peer_spki_sha256,
        content_encoding,
        body,
        elapsed,
    })
}
fn validate_fetch_request(
    request: &GatewayComplianceFetchRequest,
) -> Result<(&str, u16), GatewayComplianceError> {
    if request.url.scheme() != "https"
        || request.url.as_str().len() > MAX_FEED_URL_BYTES
        || !request.url.username().is_empty()
        || request.url.password().is_some()
        || request.url.query().is_some()
        || request.url.fragment().is_some()
        || request.url.port().is_some_and(|port| port != 443)
    {
        return Err(GatewayComplianceError::UnsafeUrl(
            "transport requires credential-free HTTPS without query or fragment".into(),
        ));
    }
    let hostname = match request.url.host() {
        Some(Host::Domain(hostname)) => hostname,
        _ => {
            return Err(GatewayComplianceError::UnsafeUrl(
                "transport requires a DNS hostname".into(),
            ));
        }
    };
    validate_dns_hostname(hostname)?;
    if request.pinned_addresses.is_empty()
        || request.pinned_addresses.len() > MAX_PINNED_ADDRESSES
        || request
            .pinned_addresses
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
    {
        return Err(GatewayComplianceError::UnsafeAddressSet {
            found: request.pinned_addresses.len(),
            maximum: MAX_PINNED_ADDRESSES,
        });
    }
    if request
        .pinned_addresses
        .iter()
        .any(|address| !is_public_ip(*address))
    {
        return Err(GatewayComplianceError::NonPublicAddress);
    }
    if request.connect_timeout.is_zero()
        || request.total_timeout.is_zero()
        || request.connect_timeout > request.total_timeout
        || request.connect_timeout > MAX_CONNECT_TIMEOUT
        || request.total_timeout > MAX_TOTAL_TIMEOUT
        || request.max_encoded_bytes == 0
        || request.max_encoded_bytes > MAX_GATEWAY_COMPLIANCE_CATALOG_BYTES_V1
    {
        return Err(GatewayComplianceError::InvalidPolicy(
            "invalid compliance HTTPS transport bounds".into(),
        ));
    }
    Ok((hostname, 443))
}
fn validate_dns_hostname(hostname: &str) -> Result<(), GatewayComplianceError> {
    if hostname.is_empty()
        || hostname.len() > MAX_DNS_HOSTNAME_BYTES
        || !hostname.is_ascii()
        || !hostname.contains('.')
        || hostname.ends_with('.')
        || hostname == "localhost"
        || matches!(
            hostname.rsplit_once('.'),
            Some((_, "localhost" | "local" | "internal" | "onion"))
        )
        || hostname.parse::<IpAddr>().is_ok()
        || hostname.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return Err(GatewayComplianceError::UnsafeUrl(
            "DNS hostname is not canonical".into(),
        ));
    }
    for label in hostname.split('.') {
        if label.is_empty()
            || label.len() > 63
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || !label
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            || !label
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
        {
            return Err(GatewayComplianceError::UnsafeUrl(
                "DNS hostname is not canonical".into(),
            ));
        }
    }
    Ok(())
}
fn is_public_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => is_public_ipv4(address),
        IpAddr::V6(address) => is_public_ipv6(address),
    }
}
fn is_public_ipv4(address: Ipv4Addr) -> bool {
    let [a, b, c, _] = address.octets();
    !(address.is_private()
        || address.is_loopback()
        || address.is_link_local()
        || address.is_multicast()
        || address.is_broadcast()
        || address.is_documentation()
        || address.is_unspecified()
        || a == 0
        || a >= 240
        || (a == 100 && (64..=127).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 88 && c == 99)
        || (a == 198 && (18..=19).contains(&b)))
}
fn is_public_ipv6(address: Ipv6Addr) -> bool {
    let segments = address.segments();
    let documentation = segments[0] == 0x2001 && segments[1] == 0x0db8;
    let documentation_v2 = segments[0] == 0x3fff && (segments[1] & 0xf000) == 0;
    let orchid = segments[0] == 0x2001 && (segments[1] & 0xfff0) == 0x0010;
    let orchid_v2 = segments[0] == 0x2001 && (segments[1] & 0xfff0) == 0x0020;
    let benchmark = segments[0] == 0x2001 && segments[1] == 0x0002 && segments[2] == 0;
    let transition = (segments[0] == 0x2001 && segments[1] == 0)
        || segments[0] == 0x2002
        || address.to_ipv4_mapped().is_some();
    !((segments[0] & 0xe000) != 0x2000
        || address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        || (segments[0] & 0xfe00) == 0xfc00
        || (segments[0] & 0xffc0) == 0xfe80
        || documentation
        || documentation_v2
        || orchid
        || orchid_v2
        || benchmark
        || transition)
}
fn remaining_time(
    started: Instant,
    total_timeout: Duration,
) -> Result<Duration, GatewayComplianceError> {
    total_timeout
        .checked_sub(started.elapsed())
        .filter(|remaining| !remaining.is_zero())
        .ok_or(GatewayComplianceError::FetchTimeout)
}
fn map_reqwest_error(error: reqwest::Error) -> GatewayComplianceError {
    if error.is_timeout() {
        GatewayComplianceError::FetchTimeout
    } else {
        GatewayComplianceError::InvalidFeed("authenticated HTTPS request failed".into())
    }
}
fn parse_content_encoding(
    headers: &HeaderMap,
) -> Result<GatewayComplianceContentEncoding, GatewayComplianceError> {
    let mut values = headers.get_all(CONTENT_ENCODING).iter();
    let value = values.next();
    if values.next().is_some() {
        return Err(GatewayComplianceError::InvalidFeed(
            "multiple Content-Encoding headers are not allowed".into(),
        ));
    }
    let Some(value) = value else {
        return Ok(GatewayComplianceContentEncoding::Identity);
    };
    let value = value.to_str().map_err(|_| {
        GatewayComplianceError::InvalidFeed("invalid Content-Encoding header".into())
    })?;
    if value.eq_ignore_ascii_case("identity") {
        Ok(GatewayComplianceContentEncoding::Identity)
    } else if value.eq_ignore_ascii_case("gzip") {
        Ok(GatewayComplianceContentEncoding::Gzip)
    } else if value.eq_ignore_ascii_case("zstd") {
        Ok(GatewayComplianceContentEncoding::Zstd)
    } else {
        Err(GatewayComplianceError::InvalidFeed(
            "unsupported Content-Encoding header".into(),
        ))
    }
}
fn validate_response_headers(headers: &HeaderMap) -> Result<(), GatewayComplianceError> {
    if headers.len() > MAX_RESPONSE_HEADER_COUNT {
        return Err(GatewayComplianceError::ResourceLimit {
            resource: "compliance feed response headers",
            found: headers.len(),
            maximum: MAX_RESPONSE_HEADER_COUNT,
        });
    }
    let bytes = headers.iter().try_fold(0_usize, |total, (name, value)| {
        total
            .checked_add(name.as_str().len())
            .and_then(|total| total.checked_add(value.as_bytes().len()))
            .ok_or(GatewayComplianceError::ResourceLimit {
                resource: "compliance feed response header bytes",
                found: MAX_RESPONSE_HEADER_BYTES.saturating_add(1),
                maximum: MAX_RESPONSE_HEADER_BYTES,
            })
    })?;
    if bytes > MAX_RESPONSE_HEADER_BYTES {
        return Err(GatewayComplianceError::ResourceLimit {
            resource: "compliance feed response header bytes",
            found: bytes,
            maximum: MAX_RESPONSE_HEADER_BYTES,
        });
    }
    Ok(())
}
fn parse_redirect_location(headers: &HeaderMap) -> Result<Option<String>, GatewayComplianceError> {
    parse_single_header(headers, &LOCATION, MAX_REDIRECT_LOCATION_BYTES, "Location")
}
fn parse_single_header(
    headers: &HeaderMap,
    name: &HeaderName,
    max_bytes: usize,
    label: &'static str,
) -> Result<Option<String>, GatewayComplianceError> {
    let mut values = headers.get_all(name).iter();
    let value = values.next();
    if values.next().is_some() {
        return Err(GatewayComplianceError::InvalidFeed(format!(
            "multiple {label} headers are not allowed"
        )));
    }
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value
        .to_str()
        .map_err(|_| GatewayComplianceError::InvalidFeed(format!("invalid {label} header")))?;
    if value.is_empty() || value.len() > max_bytes {
        return Err(GatewayComplianceError::InvalidFeed(format!(
            "invalid {label} header"
        )));
    }
    Ok(Some(value.to_owned()))
}
fn parse_content_length(
    headers: &HeaderMap,
    maximum: usize,
) -> Result<Option<usize>, GatewayComplianceError> {
    let mut values = headers.get_all(CONTENT_LENGTH).iter();
    let value = values.next();
    if values.next().is_some() {
        return Err(GatewayComplianceError::InvalidFeed(
            "multiple Content-Length headers are not allowed".into(),
        ));
    }
    let Some(value) = value else {
        return Ok(None);
    };
    let raw = value
        .to_str()
        .map_err(|_| GatewayComplianceError::InvalidFeed("invalid Content-Length header".into()))?;
    if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(GatewayComplianceError::InvalidFeed(
            "invalid Content-Length header".into(),
        ));
    }
    let length = raw
        .parse::<u64>()
        .map_err(|_| GatewayComplianceError::InvalidFeed("invalid Content-Length header".into()))?;
    let length = usize::try_from(length).map_err(|_| GatewayComplianceError::ResourceLimit {
        resource: "encoded feed bytes",
        found: maximum.saturating_add(1),
        maximum,
    })?;
    if length > maximum {
        return Err(GatewayComplianceError::ResourceLimit {
            resource: "encoded feed bytes",
            found: maximum.saturating_add(1),
            maximum,
        });
    }
    Ok(Some(length))
}
fn read_body_bounded(
    reader: &mut impl Read,
    maximum: usize,
    content_length: Option<usize>,
    started: Instant,
    total_timeout: Duration,
) -> Result<Vec<u8>, GatewayComplianceError> {
    let mut body = Vec::new();
    let initial_capacity = content_length.unwrap_or(READ_BUFFER_BYTES).min(maximum);
    body.try_reserve_exact(initial_capacity).map_err(|_| {
        GatewayComplianceError::InvalidFeed("HTTPS response body allocation failed".into())
    })?;
    let mut buffer = [0_u8; READ_BUFFER_BYTES];
    loop {
        remaining_time(started, total_timeout)?;
        let remaining_capacity = maximum.saturating_sub(body.len());
        let declared_remaining =
            content_length.map_or(usize::MAX, |length| length.saturating_sub(body.len()));
        let read_limit = buffer
            .len()
            .min(remaining_capacity.saturating_add(1))
            .min(declared_remaining.saturating_add(1));
        let read = reader.read(&mut buffer[..read_limit]).map_err(|_| {
            if started.elapsed() >= total_timeout {
                GatewayComplianceError::FetchTimeout
            } else {
                GatewayComplianceError::InvalidFeed("HTTPS response body read failed".into())
            }
        })?;
        if read == 0 {
            if content_length.is_some_and(|length| body.len() != length) {
                return Err(GatewayComplianceError::InvalidFeed(
                    "HTTPS response body was truncated".into(),
                ));
            }
            return Ok(body);
        }
        if read > remaining_capacity {
            return Err(GatewayComplianceError::ResourceLimit {
                resource: "encoded feed bytes",
                found: maximum.saturating_add(1),
                maximum,
            });
        }
        body.try_reserve_exact(read).map_err(|_| {
            GatewayComplianceError::InvalidFeed("HTTPS response body allocation failed".into())
        })?;
        body.extend_from_slice(&buffer[..read]);
        if content_length.is_some_and(|length| body.len() > length) {
            return Err(GatewayComplianceError::InvalidFeed(
                "HTTPS response body length does not match Content-Length".into(),
            ));
        }
    }
}
fn spki_sha256(certificate_der: &[u8]) -> Result<[u8; 32], GatewayComplianceError> {
    let (remainder, certificate) = parse_x509_certificate(certificate_der).map_err(|_| {
        GatewayComplianceError::InvalidFeed("invalid HTTPS peer certificate".into())
    })?;
    if !remainder.is_empty() {
        return Err(GatewayComplianceError::InvalidFeed(
            "invalid HTTPS peer certificate".into(),
        ));
    }
    Ok(Sha256::digest(certificate.public_key().raw).into())
}
#[cfg(test)]
mod tests {
    use super::*;
    use http::{
        HeaderMap, HeaderValue,
        header::{CONTENT_ENCODING, CONTENT_LENGTH, LOCATION},
    };
    use rcgen::generate_simple_self_signed;
    use sha2::Sha256;
    use std::{
        collections::{BTreeMap, BTreeSet},
        io::Cursor,
        net::{IpAddr, Ipv4Addr},
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
            mpsc,
        },
        thread,
        time::{Duration, Instant},
    };
    use x509_parser::parse_x509_certificate;
    #[test]
    fn canonical_dns_hostname_validation_is_strict() {
        for valid in ["feed.example", "a-b.c0.example"] {
            validate_dns_hostname(valid).expect("valid canonical DNS hostname");
        }
        for invalid in [
            "",
            "Feed.example",
            "feed.example.",
            "-feed.example",
            "feed-.example",
            "feed..example",
            "feed_example",
        ] {
            assert!(
                validate_dns_hostname(invalid).is_err(),
                "{invalid:?} must be rejected"
            );
        }
    }
    #[test]
    fn content_encoding_accepts_only_one_supported_token() {
        let mut headers = HeaderMap::new();
        assert_eq!(
            parse_content_encoding(&headers).expect("identity by omission"),
            GatewayComplianceContentEncoding::Identity
        );
        headers.insert(CONTENT_ENCODING, HeaderValue::from_static("GZip"));
        assert_eq!(
            parse_content_encoding(&headers).expect("case-insensitive gzip"),
            GatewayComplianceContentEncoding::Gzip
        );
        headers.insert(CONTENT_ENCODING, HeaderValue::from_static("br"));
        assert!(parse_content_encoding(&headers).is_err());
        headers.insert(CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        headers.append(CONTENT_ENCODING, HeaderValue::from_static("zstd"));
        assert!(parse_content_encoding(&headers).is_err());
    }
    #[test]
    fn response_header_bounds_are_checked_before_body_allocation() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_LENGTH, HeaderValue::from_static("9"));
        assert!(matches!(
            parse_content_length(&headers, 8),
            Err(GatewayComplianceError::ResourceLimit { .. })
        ));
        headers.insert(LOCATION, HeaderValue::from_static("/next"));
        assert_eq!(
            parse_redirect_location(&headers).expect("valid location"),
            Some("/next".to_owned())
        );
        headers.append(LOCATION, HeaderValue::from_static("/other"));
        assert!(parse_redirect_location(&headers).is_err());
        let mut excessive_count = HeaderMap::new();
        for _ in 0..=MAX_RESPONSE_HEADER_COUNT {
            excessive_count.append("x-feed-test", HeaderValue::from_static("a"));
        }
        assert!(matches!(
            validate_response_headers(&excessive_count),
            Err(GatewayComplianceError::ResourceLimit { .. })
        ));
        let mut excessive_bytes = HeaderMap::new();
        excessive_bytes.insert(
            "x-feed-test",
            HeaderValue::from_bytes(&vec![b'a'; MAX_RESPONSE_HEADER_BYTES])
                .expect("large valid header value"),
        );
        assert!(matches!(
            validate_response_headers(&excessive_bytes),
            Err(GatewayComplianceError::ResourceLimit { .. })
        ));
    }
    #[test]
    fn fetch_request_requires_canonical_https_and_address_inventory() {
        let request = GatewayComplianceFetchRequest {
            url: url::Url::parse("https://feed.example/catalog").expect("URL"),
            pinned_addresses: vec![
                IpAddr::V4(Ipv4Addr::new(93, 184, 216, 35)),
                IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            ],
            connect_timeout: Duration::from_secs(1),
            total_timeout: Duration::from_secs(2),
            max_encoded_bytes: 1_024,
        };
        assert!(validate_fetch_request(&request).is_err());
        let mut canonical = request;
        canonical.pinned_addresses.sort_unstable();
        validate_fetch_request(&canonical).expect("canonical request");
        canonical.url =
            url::Url::parse("https://user@feed.example/catalog").expect("credential URL");
        assert!(validate_fetch_request(&canonical).is_err());
    }
    #[test]
    fn body_reader_accepts_exact_limit_and_rejects_one_extra_byte() {
        let started = Instant::now();
        assert_eq!(
            read_body_bounded(
                &mut Cursor::new([1_u8, 2, 3, 4]),
                4,
                None,
                started,
                Duration::from_secs(1),
            )
            .expect("body at limit"),
            vec![1, 2, 3, 4]
        );
        let error = read_body_bounded(
            &mut Cursor::new([1_u8, 2, 3, 4, 5]),
            4,
            None,
            Instant::now(),
            Duration::from_secs(1),
        )
        .expect_err("body above limit");
        assert!(matches!(
            error,
            GatewayComplianceError::ResourceLimit { .. }
        ));
        assert!(
            read_body_bounded(
                &mut Cursor::new([1_u8, 2, 3]),
                4,
                Some(4),
                Instant::now(),
                Duration::from_secs(1),
            )
            .is_err()
        );
        assert!(
            read_body_bounded(
                &mut Cursor::new([1_u8, 2, 3, 4, 5]),
                8,
                Some(4),
                Instant::now(),
                Duration::from_secs(1),
            )
            .is_err()
        );
    }
    #[test]
    fn leaf_certificate_spki_digest_hashes_exact_der_spki() {
        let certified =
            generate_simple_self_signed(vec!["feed.example".to_owned()]).expect("certificate");
        let certificate_der = certified.cert.der().as_ref();
        let digest = spki_sha256(certificate_der).expect("SPKI digest");
        let (_, certificate) =
            parse_x509_certificate(certificate_der).expect("parse generated certificate");
        let expected: [u8; 32] = Sha256::digest(certificate.public_key().raw).into();
        assert_eq!(digest, expected);
        let transport = ProductionGatewayComplianceFeedTransport::try_new(BTreeMap::from([(
            "feed.example".to_owned(),
            BTreeSet::from([digest]),
        )]))
        .expect("production transport");
        let identity = transport.qualification().expect("transport identity");
        assert_eq!(
            identity.provider_handle,
            GATEWAY_COMPLIANCE_FEED_TRANSPORT_HANDLE_V1
        );
        assert_eq!(
            identity.revision,
            GATEWAY_COMPLIANCE_FEED_TRANSPORT_REVISION_V1
        );
        assert!(!identity.test_marked);
        assert_eq!(
            identity.policy_digest,
            gateway_compliance_feed_transport_policy_digest(&BTreeMap::from([(
                "feed.example".to_owned(),
                BTreeSet::from([digest]),
            )]))
            .expect("transport policy digest")
        );
        transport
            .verify_spki("feed.example", digest)
            .expect("configured SPKI");
        assert!(transport.verify_spki("feed.example", [0x55; 32]).is_err());
        let mut non_canonical = certificate_der.to_vec();
        non_canonical.push(0);
        assert!(spki_sha256(&non_canonical).is_err());
    }
    #[test]
    fn resolver_timeout_leaves_only_bounded_worker_and_queue_work() {
        let calls = Arc::new(AtomicUsize::new(0));
        let resolver_calls = Arc::clone(&calls);
        let (entered_sender, entered_receiver) = mpsc::sync_channel(1);
        let (release_sender, release_receiver) = mpsc::sync_channel(1);
        let release_receiver = Arc::new(Mutex::new(release_receiver));
        let resolver_release = Arc::clone(&release_receiver);
        let resolver: Arc<Resolver> = Arc::new(move |_| {
            let call_index = resolver_calls.fetch_add(1, Ordering::Relaxed);
            if call_index == 0 {
                entered_sender
                    .send(())
                    .expect("signal first resolver entry");
                resolver_release
                    .lock()
                    .expect("resolver release mutex")
                    .recv_timeout(Duration::from_secs(10))
                    .expect("release first resolver");
            }
            Ok(vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))])
        });
        let pool = Arc::new(ResolverPool::new_with(1, 1, resolver).expect("bounded resolver"));
        let first_pool = Arc::clone(&pool);
        let first =
            thread::spawn(move || first_pool.resolve("feed.example", Duration::from_secs(10)));
        entered_receiver
            .recv_timeout(Duration::from_secs(5))
            .expect("first resolver started");
        let (expired_reply, expired_result) = mpsc::sync_channel(1);
        let expired_deadline = Instant::now()
            .checked_add(Duration::from_millis(5))
            .expect("expired-job deadline");
        assert!(
            pool.sender
                .try_send(ResolveJob {
                    hostname: "feed.example".to_owned(),
                    deadline: expired_deadline,
                    reply: expired_reply,
                })
                .is_ok(),
            "queue expiring resolver job"
        );
        assert!(matches!(
            expired_result.recv_timeout(Duration::from_millis(20)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        assert!(matches!(
            pool.resolve("feed.example", Duration::from_millis(5)),
            Err(GatewayComplianceError::FetchTimeout)
        ));
        release_sender.send(()).expect("release resolver");
        first
            .join()
            .expect("first resolver thread")
            .expect("first resolver result");
        assert!(matches!(
            expired_result.recv_timeout(Duration::from_secs(1)),
            Ok(Err(ResolveFailure::Deadline))
        ));
        pool.resolve("feed.example", Duration::from_secs(1))
            .expect("post-timeout resolver probe");
        assert_eq!(
            calls.load(Ordering::Relaxed),
            2,
            "expired queued jobs must be discarded before system resolution"
        );
    }
    #[test]
    fn resolver_provider_panic_is_suppressed_and_worker_recovers() {
        let calls = Arc::new(AtomicUsize::new(0));
        let resolver_calls = Arc::clone(&calls);
        let resolver: Arc<Resolver> = Arc::new(move |_| {
            let call_index = resolver_calls.fetch_add(1, Ordering::Relaxed);
            assert!(
                iroha_panic_hook::is_suppressed(),
                "resolver provider panic must not trigger the process panic hook"
            );
            assert!(call_index != 0, "injected resolver provider panic");
            Ok(vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))])
        });
        let pool = ResolverPool::new_with(1, 1, resolver).expect("bounded resolver");

        assert!(matches!(
            pool.resolve("feed.example", Duration::from_secs(1)),
            Err(GatewayComplianceError::InvalidFeed(message))
                if message == "DNS resolver provider panicked"
        ));
        assert_eq!(
            pool.resolve("feed.example", Duration::from_secs(1))
                .expect("resolver worker must survive the provider panic"),
            vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]
        );
        assert_eq!(calls.load(Ordering::Relaxed), 2);
    }
    #[test]
    fn empty_and_nonempty_transports_refuse_unknown_hosts_before_resolver_or_http() {
        for inventory in [
            BTreeMap::new(),
            BTreeMap::from([("configured.example".to_owned(), BTreeSet::from([[7; 32]]))]),
        ] {
            let mut transport =
                ProductionGatewayComplianceFeedTransport::try_new(inventory.clone()).unwrap();
            let identity = transport.qualification().unwrap();
            assert!(!identity.test_marked);
            assert_eq!(
                identity.policy_digest,
                gateway_compliance_feed_transport_policy_digest(&inventory).unwrap()
            );
            let calls = Arc::new(AtomicUsize::new(0));
            let counted = Arc::clone(&calls);
            transport.resolver = ResolverPool::new_with(
                1,
                1,
                Arc::new(move |_| {
                    counted.fetch_add(1, Ordering::SeqCst);
                    Ok(vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))])
                }),
            )
            .unwrap();
            assert!(matches!(
                transport.resolve("unconfigured.example", Duration::from_secs(1)),
                Err(GatewayComplianceError::TrustPinMismatch)
            ));
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            let request = GatewayComplianceFetchRequest {
                url: url::Url::parse("https://unconfigured.example/catalog").unwrap(),
                pinned_addresses: vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
                connect_timeout: Duration::from_millis(1),
                total_timeout: Duration::from_millis(1),
                max_encoded_bytes: 1024,
            };
            validate_fetch_request(&request).unwrap();
            // The production fetch boundary returns the inventory refusal before constructing
            // a reqwest client or socket, rather than a connection/DNS/timeout failure.
            assert!(matches!(
                transport.fetch(&request),
                Err(GatewayComplianceError::TrustPinMismatch)
            ));
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            if !inventory.is_empty() {
                assert_eq!(
                    transport
                        .resolve("configured.example", Duration::from_secs(1))
                        .unwrap(),
                    request.pinned_addresses
                );
                assert_eq!(calls.load(Ordering::SeqCst), 1);
                transport
                    .verify_spki("configured.example", [7; 32])
                    .unwrap();
                assert!(matches!(
                    transport.verify_spki("configured.example", [8; 32]),
                    Err(GatewayComplianceError::TrustPinMismatch)
                ));
            }
        }
    }
}
