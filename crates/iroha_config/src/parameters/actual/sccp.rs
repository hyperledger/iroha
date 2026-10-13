//! Runtime view of the node-local SCCP configuration (`specs/sccp.md` §4.13.4).
//!
//! `[sccp.keeper]` configures the in-node keeper and its keeper key, and
//! `[sccp.light_client_keeper]` the keeper's light-client advance duty. Every default works
//! without operator input: the keeper-key directory derives from `kura.store_dir`, and an
//! empty endpoint list resolves to the compiled public list in
//! [`defaults::sccp::endpoints`]. The endpoint syntax checks are public so that the RPC and
//! wallet crates apply exactly the same rules to their own endpoint lists. Configuration
//! parsing checks syntax only; owner-only file checks of the key directory and secret-header
//! files happen at runtime in the keeper and the RPC crate.

use core::{fmt, str::FromStr};
use std::{
    net::{Ipv4Addr, SocketAddrV4},
    num::NonZeroUsize,
    path::{Path, PathBuf},
    time::Duration,
};

use iroha_config_base::{ParameterOrigin, WithOrigin};
use url::{Host, Url};

use crate::parameters::defaults;

/// Node-local SCCP components (`[sccp]`).
#[derive(Debug, Clone)]
pub struct SccpNode {
    /// In-node keeper and its keeper key (`[sccp.keeper]`, §4.13.4).
    pub keeper: SccpKeeper,
    /// The keeper's light-client advance duty (`[sccp.light_client_keeper]`, §4.13.4).
    pub light_client_keeper: SccpLightClientKeeper,
}

impl SccpNode {
    /// Complete default configuration for a node whose Kura store lives in `kura_store_dir`.
    pub fn defaults_for_kura_store_dir(kura_store_dir: &WithOrigin<PathBuf>) -> Self {
        Self {
            keeper: SccpKeeper::defaults_for_kura_store_dir(kura_store_dir),
            light_client_keeper: SccpLightClientKeeper::default(),
        }
    }
}

impl Default for SccpNode {
    fn default() -> Self {
        Self::defaults_for_kura_store_dir(&WithOrigin::new(
            PathBuf::from(defaults::kura::STORE_DIR),
            ParameterOrigin::custom("default kura.store_dir".to_owned()),
        ))
    }
}

/// In-node keeper (`[sccp.keeper]`, §4.13.4).
///
/// The keeper is its own supervised task. It signs with a node-local Ed25519 keeper key that it
/// generates on first start; the key is neither registered nor funded, because every
/// transaction the keeper submits is fee-exempt on success (§4.19).
#[derive(Debug, Clone)]
pub struct SccpKeeper {
    /// Whether the keeper runs. When the key directory is unusable the keeper stays inert and
    /// reports `sccp_keeper_unconfigured`; the node itself never aborts.
    pub enabled: bool,
    /// Keeper-key directory: `<kura.store_dir>/sccp/keeper-key` unless configured. The
    /// directory is created `0700` and holds the keeper key as one owner-only `0600` file;
    /// symlinks and other modes are refused at runtime. Resolve it with
    /// [`Self::key_dir_path`].
    pub key_dir: WithOrigin<PathBuf>,
    /// Whether the keeper submits due keepalives (§4.7.4).
    pub keepalive: bool,
    /// Keepalive stagger per canonical committee index (nonzero).
    pub keepalive_stagger: Duration,
    /// Whether the keeper watches the registered destinations; it uses the endpoints of
    /// [`SccpLightClientKeeper`].
    pub watch: bool,
}

impl SccpKeeper {
    /// Default keeper configuration for a node whose Kura store lives in `kura_store_dir`.
    pub fn defaults_for_kura_store_dir(kura_store_dir: &WithOrigin<PathBuf>) -> Self {
        Self {
            enabled: defaults::sccp::keeper::ENABLED,
            key_dir: derived_keeper_key_dir(kura_store_dir),
            keepalive: defaults::sccp::keeper::KEEPALIVE,
            keepalive_stagger: Duration::from_millis(defaults::sccp::keeper::KEEPALIVE_STAGGER_MS),
            watch: defaults::sccp::keeper::WATCH,
        }
    }

    /// Keeper-key directory resolved against the configuration file that set it.
    pub fn key_dir_path(&self) -> PathBuf {
        self.key_dir.resolve_relative_path()
    }
}

/// Default keeper-key directory `<kura.store_dir>/sccp/keeper-key`, derived like the default
/// snapshot store directory.
pub fn derived_keeper_key_dir(kura_store_dir: &WithOrigin<PathBuf>) -> WithOrigin<PathBuf> {
    WithOrigin::new(
        kura_store_dir
            .resolve_relative_path()
            .join(Path::new(defaults::sccp::keeper::KEY_DIR_UNDER_KURA_STORE)),
        ParameterOrigin::custom(
            "derived from kura.store_dir because sccp.keeper.key_dir was empty".to_owned(),
        ),
    )
}

/// The keeper's light-client advance duty (`[sccp.light_client_keeper]`, §4.13.4).
///
/// The duty is effective while [`SccpKeeper`] runs. It advances stale light clients with
/// proof-carrying advances built from public RPC endpoints and submits them fee-exempt from the
/// keeper key's account. Its submissions are verified like anyone's, so a lying endpoint can
/// only cause rejected advances.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SccpLightClientKeeper {
    /// Whether the keeper advances stale light clients; effective only while [`SccpKeeper`] is
    /// enabled.
    pub enabled: bool,
    /// Staleness after which a light client is advanced; `None` means `ws_bound_ms / 4` of
    /// each light client. Use [`Self::advance_after_for`].
    pub advance_after: Option<Duration>,
    /// Cadence at which each network's local light-client state is checked (nonzero). The
    /// keeper adds up to a quarter of jitter, and doubles the wait after each consecutive failed
    /// poll of a network up to 64 × this interval.
    pub poll_interval: Duration,
    /// Total wall-clock time of one RPC attempt (connecting, sending and reading the whole
    /// answer) before failing over to the next endpoint (nonzero).
    pub request_timeout: Duration,
    /// Wall-clock budget of one network's poll, covering every RPC request of one advance build
    /// (nonzero). No request starts and no failover backoff sleeps past it.
    pub poll_budget: Duration,
    /// Largest encoded advance the keeper submits. Advances are stepped to fit it; one that
    /// still does not fit is dropped with a warning. The on-chain per-instruction bounds still
    /// apply.
    pub max_advance_bytes: NonZeroUsize,
    /// Effective endpoint lists per chain (configured lists, or the compiled defaults).
    pub endpoints: SccpLightClientKeeperEndpoints,
    /// Per-endpoint secret headers whose values are read from owner-only files at runtime.
    pub secret_headers: Vec<SccpSecretHeader>,
}

impl SccpLightClientKeeper {
    /// Staleness after which the keeper advances a light client with the given
    /// weak-subjectivity bound.
    pub fn advance_after_for(&self, ws_bound_ms: u64) -> Duration {
        self.advance_after
            .unwrap_or_else(|| Duration::from_millis(ws_bound_ms / 4))
    }
}

impl Default for SccpLightClientKeeper {
    fn default() -> Self {
        let advance_after_ms = defaults::sccp::light_client_keeper::ADVANCE_AFTER_MS;
        Self {
            enabled: defaults::sccp::light_client_keeper::ENABLED,
            advance_after: (advance_after_ms != 0)
                .then_some(Duration::from_millis(advance_after_ms)),
            poll_interval: Duration::from_millis(
                defaults::sccp::light_client_keeper::POLL_INTERVAL_MS,
            ),
            request_timeout: Duration::from_millis(
                defaults::sccp::light_client_keeper::REQUEST_TIMEOUT_MS,
            ),
            poll_budget: Duration::from_millis(defaults::sccp::light_client_keeper::POLL_BUDGET_MS),
            max_advance_bytes: NonZeroUsize::new(
                defaults::sccp::light_client_keeper::MAX_ADVANCE_BYTES,
            )
            .expect("default SCCP advance bound is nonzero"),
            endpoints: SccpLightClientKeeperEndpoints::compiled_defaults(),
            secret_headers: Vec::new(),
        }
    }
}

/// Effective keeper endpoint lists per chain (`[sccp.light_client_keeper.endpoints]`).
///
/// Each list is tried in order with failover. HTTP endpoints use `https`, or `http` for
/// loopback hosts only.
#[derive(Clone, PartialEq, Eq)]
pub struct SccpLightClientKeeperEndpoints {
    /// Ethereum execution-layer JSON-RPC endpoints.
    pub ethereum_execution: Vec<Url>,
    /// Ethereum beacon API endpoints serving the light-client routes.
    pub ethereum_beacon: Vec<Url>,
    /// BNB Smart Chain JSON-RPC endpoints.
    pub bsc: Vec<Url>,
    /// TON liteservers reached over ADNL-TCP.
    pub ton_liteservers: Vec<SccpTonLiteserver>,
}

impl SccpLightClientKeeperEndpoints {
    /// The compiled default public endpoint lists of [`defaults::sccp::endpoints`].
    pub fn compiled_defaults() -> Self {
        Self {
            ethereum_execution: compiled_http_endpoints(
                defaults::sccp::endpoints::ETHEREUM_EXECUTION,
            ),
            ethereum_beacon: compiled_http_endpoints(defaults::sccp::endpoints::ETHEREUM_BEACON),
            bsc: compiled_http_endpoints(defaults::sccp::endpoints::BSC),
            ton_liteservers: compiled_ton_liteservers(defaults::sccp::endpoints::TON_LITESERVERS),
        }
    }
}

impl Default for SccpLightClientKeeperEndpoints {
    fn default() -> Self {
        Self::compiled_defaults()
    }
}

impl fmt::Debug for SccpLightClientKeeperEndpoints {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fn urls(list: &[Url]) -> Vec<&str> {
            list.iter().map(Url::as_str).collect()
        }
        formatter
            .debug_struct("SccpLightClientKeeperEndpoints")
            .field("ethereum_execution", &urls(&self.ethereum_execution))
            .field("ethereum_beacon", &urls(&self.ethereum_beacon))
            .field("bsc", &urls(&self.bsc))
            .field("ton_liteservers", &self.ton_liteservers)
            .finish()
    }
}

/// Parses a compiled default HTTP endpoint list.
///
/// # Panics
/// If a compiled entry violates [`parse_sccp_http_endpoint`]; unit tests keep every compiled
/// entry valid.
pub fn compiled_http_endpoints(entries: &[&str]) -> Vec<Url> {
    entries
        .iter()
        .map(|entry| {
            parse_sccp_http_endpoint(entry).expect("compiled SCCP endpoint is a valid endpoint")
        })
        .collect()
}

/// Parses a compiled default TON liteserver list.
///
/// # Panics
/// If a compiled entry is not a canonical `<ipv4>:<port>:<base64 key>` entry; unit tests keep
/// every compiled entry valid.
pub fn compiled_ton_liteservers(entries: &[&str]) -> Vec<SccpTonLiteserver> {
    entries
        .iter()
        .map(|entry| entry.parse().expect("compiled TON liteserver is canonical"))
        .collect()
}

/// A TON liteserver: IPv4 socket address and ed25519 ADNL public key.
///
/// The configuration spelling is `<ipv4>:<port>:<base64 ed25519 public key>`, as in the
/// `liteservers` array of `global-config.json` with the signed-integer IP in dotted form.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SccpTonLiteserver {
    /// Liteserver TCP address.
    pub address: SocketAddrV4,
    /// Liteserver ed25519 ADNL public key.
    pub public_key: [u8; 32],
}

impl FromStr for SccpTonLiteserver {
    type Err = SccpEndpointError;

    fn from_str(entry: &str) -> Result<Self, Self::Err> {
        let mut parts = entry.split(':');
        let (Some(ip), Some(port), Some(key), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(SccpEndpointError::new(
                "a TON liteserver must be `<ipv4>:<port>:<base64 ed25519 public key>`",
            ));
        };
        let ip = Ipv4Addr::from_str(ip).map_err(|_| {
            SccpEndpointError::new("a TON liteserver address must be a dotted IPv4 address")
        })?;
        if ip.is_unspecified() || ip.is_broadcast() || ip.is_multicast() {
            return Err(SccpEndpointError::new(
                "a TON liteserver address must be a unicast IPv4 address",
            ));
        }
        let port = parse_canonical_port(port).ok_or_else(|| {
            SccpEndpointError::new(
                "a TON liteserver port must be a decimal 1..=65535 without leading zeros",
            )
        })?;
        let public_key = decode_base64_key(key).ok_or_else(|| {
            SccpEndpointError::new(
                "a TON liteserver key must be 32 bytes in canonical padded standard base64",
            )
        })?;
        Ok(Self {
            address: SocketAddrV4::new(ip, port),
            public_key,
        })
    }
}

impl fmt::Display for SccpTonLiteserver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}:{}:{}",
            self.address.ip(),
            self.address.port(),
            encode_base64_key(&self.public_key)
        )
    }
}

impl fmt::Debug for SccpTonLiteserver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.to_string(), formatter)
    }
}

/// A secret request header for one HTTP endpoint
/// (`[[sccp.light_client_keeper.secret_headers]]`).
///
/// The value is never part of the configuration: it is read at runtime from `value_file`,
/// which must be an owner-only regular file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SccpSecretHeader {
    /// Endpoint the header is sent to, compared exactly after URL normalization.
    pub endpoint: Url,
    /// Lowercase HTTP header name.
    pub header: String,
    /// File holding the header value, resolved against the configuration file.
    pub value_file: PathBuf,
}

/// Reason an SCCP endpoint, liteserver or secret-header entry was rejected.
///
/// Messages never echo the rejected value, because endpoint URLs may embed credentials.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct SccpEndpointError {
    message: String,
}

impl SccpEndpointError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// Parses one SCCP HTTP endpoint: an absolute `https` URL, or `http` for a loopback host
/// (`localhost`, `127.0.0.0/8` or `::1`), without embedded credentials or a fragment.
///
/// # Errors
/// If the URL is malformed or violates one of the rules above.
pub fn parse_sccp_http_endpoint(raw: &str) -> Result<Url, SccpEndpointError> {
    if raw.is_empty() || raw.trim() != raw {
        return Err(SccpEndpointError::new(
            "an endpoint URL must be non-empty and carry no surrounding whitespace",
        ));
    }
    let url = Url::parse(raw)
        .map_err(|error| SccpEndpointError::new(format!("invalid endpoint URL: {error}")))?;
    match url.scheme() {
        "https" => {}
        "http" if is_loopback_host(&url) => {}
        "http" => {
            return Err(SccpEndpointError::new(
                "an endpoint URL must use https; http is accepted for loopback hosts only",
            ));
        }
        _ => {
            return Err(SccpEndpointError::new("an endpoint URL must use https"));
        }
    }
    if url.host().is_none() {
        return Err(SccpEndpointError::new("an endpoint URL must name a host"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(SccpEndpointError::new(
            "an endpoint URL must not embed credentials; use secret_headers",
        ));
    }
    if url.fragment().is_some() {
        return Err(SccpEndpointError::new(
            "an endpoint URL must not carry a fragment",
        ));
    }
    Ok(url)
}

/// Header names a secret header must not replace, because the RPC client owns them.
pub const SCCP_RESERVED_SECRET_HEADER_NAMES: &[&str] = &[
    "connection",
    "content-length",
    "content-type",
    "expect",
    "host",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Longest accepted secret-header name.
pub const SCCP_MAX_SECRET_HEADER_NAME_BYTES: usize = 128;

/// Parses a secret-header name: an RFC 9110 token of at most
/// [`SCCP_MAX_SECRET_HEADER_NAME_BYTES`] bytes that is not reserved, returned lowercase.
///
/// # Errors
/// If the name is empty, too long, not a token, or reserved.
pub fn parse_sccp_secret_header_name(raw: &str) -> Result<String, SccpEndpointError> {
    if raw.is_empty() || raw.len() > SCCP_MAX_SECRET_HEADER_NAME_BYTES {
        return Err(SccpEndpointError::new(format!(
            "a secret header name must have 1..={SCCP_MAX_SECRET_HEADER_NAME_BYTES} bytes"
        )));
    }
    if !raw.bytes().all(is_header_token_byte) {
        return Err(SccpEndpointError::new(
            "a secret header name must be an HTTP token",
        ));
    }
    let name = raw.to_ascii_lowercase();
    if SCCP_RESERVED_SECRET_HEADER_NAMES.contains(&name.as_str()) {
        return Err(SccpEndpointError::new(
            "a secret header name must not replace a header the RPC client sets",
        ));
    }
    Ok(name)
}

fn is_header_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

fn is_loopback_host(url: &Url) -> bool {
    match url.host() {
        Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    }
}

fn parse_canonical_port(text: &str) -> Option<u16> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) || text.starts_with('0') {
        return None;
    }
    text.parse().ok()
}

const BASE64_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Canonical padded standard base64 length of a 32-byte key.
const BASE64_KEY_LEN: usize = 44;

fn base64_value(symbol: u8) -> Option<u32> {
    BASE64_ALPHABET
        .iter()
        .position(|candidate| *candidate == symbol)
        .and_then(|index| u32::try_from(index).ok())
}

fn decode_base64_key(text: &str) -> Option<[u8; 32]> {
    let bytes = text.as_bytes();
    if bytes.len() != BASE64_KEY_LEN || bytes[BASE64_KEY_LEN - 1] != b'=' {
        return None;
    }
    let mut key = [0_u8; 32];
    let mut written = 0;
    let mut accumulator = 0_u32;
    let mut pending_bits = 0_u32;
    for symbol in &bytes[..BASE64_KEY_LEN - 1] {
        accumulator = (accumulator << 6) | base64_value(*symbol)?;
        pending_bits += 6;
        if pending_bits >= 8 {
            pending_bits -= 8;
            *key.get_mut(written)? = u8::try_from(accumulator >> pending_bits).ok()?;
            written += 1;
            accumulator &= (1 << pending_bits) - 1;
        }
    }
    // 43 symbols carry 258 bits: 32 bytes plus two padding bits that must be zero.
    (written == key.len() && accumulator == 0).then_some(key)
}

fn encode_base64_key(key: &[u8; 32]) -> String {
    let mut out = String::with_capacity(BASE64_KEY_LEN);
    for chunk in key.chunks(3) {
        let mut group = [0_u8; 3];
        group[..chunk.len()].copy_from_slice(chunk);
        let triple =
            (usize::from(group[0]) << 16) | (usize::from(group[1]) << 8) | usize::from(group[2]);
        let symbols = chunk.len() + 1;
        for index in 0..4 {
            if index < symbols {
                let value = (triple >> (18 - 6 * index)) & 0x3f;
                out.push(char::from(BASE64_ALPHABET[value]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sccp_compiled_endpoints_parse_and_round_trip() {
        let endpoints = SccpLightClientKeeperEndpoints::compiled_defaults();
        for (list, compiled) in [
            (
                &endpoints.ethereum_execution,
                defaults::sccp::endpoints::ETHEREUM_EXECUTION,
            ),
            (
                &endpoints.ethereum_beacon,
                defaults::sccp::endpoints::ETHEREUM_BEACON,
            ),
            (&endpoints.bsc, defaults::sccp::endpoints::BSC),
        ] {
            assert!(!list.is_empty());
            assert_eq!(list.len(), compiled.len());
            for url in list {
                assert_eq!(url.scheme(), "https");
            }
        }
        assert_eq!(
            endpoints.ton_liteservers.len(),
            defaults::sccp::endpoints::TON_LITESERVERS.len()
        );
        for (server, entry) in endpoints
            .ton_liteservers
            .iter()
            .zip(defaults::sccp::endpoints::TON_LITESERVERS)
        {
            assert_eq!(&server.to_string(), entry, "compiled entry is canonical");
        }
    }

    #[test]
    fn sccp_compiled_endpoint_lists_are_unique() {
        let endpoints = SccpLightClientKeeperEndpoints::compiled_defaults();
        for list in [
            &endpoints.ethereum_execution,
            &endpoints.ethereum_beacon,
            &endpoints.bsc,
        ] {
            let unique: std::collections::BTreeSet<_> = list.iter().map(Url::as_str).collect();
            assert_eq!(unique.len(), list.len());
        }
        let unique: std::collections::BTreeSet<_> = endpoints
            .ton_liteservers
            .iter()
            .map(|server| server.address)
            .collect();
        assert_eq!(unique.len(), endpoints.ton_liteservers.len());
    }

    #[test]
    fn sccp_http_endpoint_rules() {
        for accepted in [
            "https://rpc.example.org",
            "https://rpc.example.org:8545/v1/path?network=mainnet",
            "http://localhost:8545",
            "http://127.0.0.1:8545",
            "http://127.3.2.1",
            "http://[::1]:5052",
        ] {
            parse_sccp_http_endpoint(accepted).expect(accepted);
        }
        for rejected in [
            "",
            " https://rpc.example.org",
            "rpc.example.org",
            "http://rpc.example.org",
            "http://10.0.0.1:8545",
            "ws://127.0.0.1:8546",
            "ftp://rpc.example.org",
            "https://user:secret@rpc.example.org",
            "https://rpc.example.org/#fragment",
        ] {
            assert!(
                parse_sccp_http_endpoint(rejected).is_err(),
                "{rejected} must be rejected"
            );
        }
    }

    #[test]
    fn sccp_endpoint_errors_do_not_echo_values() {
        let error = parse_sccp_http_endpoint("https://user:hunter2@rpc.example.org")
            .expect_err("credentials are rejected");
        assert!(!error.to_string().contains("hunter2"));
    }

    #[test]
    fn sccp_ton_liteserver_parsing() {
        let entry = "5.9.10.47:19949:n4VDnSCUuSpjnCyUk9e3QOOd6o0ItSWYbTnW3Wnn8wk=";
        let server: SccpTonLiteserver = entry.parse().expect("canonical entry");
        assert_eq!(
            server.address,
            SocketAddrV4::new(Ipv4Addr::new(5, 9, 10, 47), 19949)
        );
        assert_eq!(server.public_key[0], 0x9f);
        assert_eq!(server.to_string(), entry);
        assert_eq!(format!("{server:?}"), format!("{entry:?}"));
        for rejected in [
            "",
            "5.9.10.47:19949",
            "5.9.10.47:19949:n4VDnSCUuSpjnCyUk9e3QOOd6o0ItSWYbTnW3Wnn8wk=:extra",
            "84478511:19949:n4VDnSCUuSpjnCyUk9e3QOOd6o0ItSWYbTnW3Wnn8wk=",
            "example.org:19949:n4VDnSCUuSpjnCyUk9e3QOOd6o0ItSWYbTnW3Wnn8wk=",
            "0.0.0.0:19949:n4VDnSCUuSpjnCyUk9e3QOOd6o0ItSWYbTnW3Wnn8wk=",
            "224.0.0.1:19949:n4VDnSCUuSpjnCyUk9e3QOOd6o0ItSWYbTnW3Wnn8wk=",
            "5.9.10.47:0:n4VDnSCUuSpjnCyUk9e3QOOd6o0ItSWYbTnW3Wnn8wk=",
            "5.9.10.47:019949:n4VDnSCUuSpjnCyUk9e3QOOd6o0ItSWYbTnW3Wnn8wk=",
            "5.9.10.47:+1994:n4VDnSCUuSpjnCyUk9e3QOOd6o0ItSWYbTnW3Wnn8wk=",
            "5.9.10.47:65536:n4VDnSCUuSpjnCyUk9e3QOOd6o0ItSWYbTnW3Wnn8wk=",
            "5.9.10.47:19949:n4VDnSCUuSpjnCyUk9e3QOOd6o0ItSWYbTnW3Wnn8wk",
            "5.9.10.47:19949:n4VDnSCUuSpjnCyUk9e3QOOd6o0ItSWYbTnW3Wnn8wl=",
            "5.9.10.47:19949:n4VDnSCUuSpjnCyUk9e3QOOd6o0ItSWYbTnW3Wnn8w==",
            "5.9.10.47:19949:n4VDnSCUuSpjnCyUk9e3QOOd6o0ItSWYbTnW3Wnn8w_=",
        ] {
            assert!(
                rejected.parse::<SccpTonLiteserver>().is_err(),
                "{rejected} must be rejected"
            );
        }
    }

    #[test]
    fn sccp_base64_key_round_trip() {
        for fill in [0_u8, 0x5a, 0xff] {
            let mut key = [fill; 32];
            key[31] = 0x01;
            let text = encode_base64_key(&key);
            assert_eq!(text.len(), BASE64_KEY_LEN);
            assert_eq!(decode_base64_key(&text), Some(key));
        }
    }

    #[test]
    fn sccp_secret_header_names() {
        assert_eq!(
            parse_sccp_secret_header_name("X-Api-Key").expect("token"),
            "x-api-key"
        );
        for rejected in [
            "",
            "x api key",
            "x-api-key:",
            "Host",
            "Content-Length",
            "té",
        ] {
            assert!(
                parse_sccp_secret_header_name(rejected).is_err(),
                "{rejected} must be rejected"
            );
        }
        assert!(
            parse_sccp_secret_header_name(&"x".repeat(SCCP_MAX_SECRET_HEADER_NAME_BYTES + 1))
                .is_err()
        );
    }

    #[test]
    fn sccp_default_key_dir_derives_from_kura_store_dir() {
        let kura = WithOrigin::new(
            PathBuf::from("/var/lib/iroha"),
            ParameterOrigin::custom("test".to_owned()),
        );
        let keeper = SccpKeeper::defaults_for_kura_store_dir(&kura);
        assert_eq!(
            keeper.key_dir_path(),
            PathBuf::from("/var/lib/iroha/sccp/keeper-key")
        );
        assert_eq!(
            derived_keeper_key_dir(&kura).into_value(),
            keeper.key_dir_path()
        );
        let node = SccpNode::default();
        assert_eq!(
            node.keeper.key_dir_path(),
            PathBuf::from(defaults::kura::STORE_DIR).join("sccp/keeper-key")
        );
        assert!(node.keeper.enabled);
        assert!(node.keeper.keepalive);
        assert_eq!(node.keeper.keepalive_stagger, Duration::from_secs(15));
        assert!(node.keeper.watch);
        assert_eq!(node.light_client_keeper, SccpLightClientKeeper::default());
    }

    #[test]
    fn sccp_keeper_advance_after_defaults_to_quarter_ws_bound() {
        let mut keeper = SccpLightClientKeeper::default();
        assert_eq!(keeper.advance_after, None);
        assert_eq!(
            keeper.advance_after_for(86_400_000),
            Duration::from_millis(21_600_000)
        );
        keeper.advance_after = Some(Duration::from_secs(5));
        assert_eq!(keeper.advance_after_for(86_400_000), Duration::from_secs(5));
    }

    #[test]
    fn sccp_keeper_defaults_match_spec() {
        let keeper = SccpLightClientKeeper::default();
        assert!(keeper.enabled);
        assert_eq!(keeper.poll_interval, Duration::from_secs(60));
        assert_eq!(keeper.request_timeout, Duration::from_secs(10));
        assert_eq!(keeper.poll_budget, Duration::from_secs(120));
        assert_eq!(keeper.max_advance_bytes.get(), 262_144);
        assert!(keeper.secret_headers.is_empty());
        assert_eq!(
            keeper.endpoints,
            SccpLightClientKeeperEndpoints::compiled_defaults()
        );
    }
}
