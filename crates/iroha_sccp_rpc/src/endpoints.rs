//! SCCP public-RPC endpoint lists (spec §4.13.4, §8).
//!
//! An [`EndpointSet`] is one chain's ordered list of HTTP endpoints: the list
//! configured under `[sccp.light_client_keeper.endpoints]` (or a client
//! config), or the compiled default public list that `iroha_config` exposes in
//! `defaults::sccp::endpoints`. Each endpoint may carry secret request headers
//! whose values live in owner-only files.
//!
//! Requests run through [`run_with_failover`]: a request starts at the
//! preferred endpoint and tries every endpoint once, in round-robin order, per
//! round. An endpoint that fails with a failover error
//! ([`RpcError::is_failover`]) hands the request to the next one; the endpoint
//! that answers becomes the preferred endpoint of later requests. An endpoint
//! that answers with something that discredits it
//! ([`RpcError::discredits_endpoint`]: an HTTP 404 or other non-failover
//! status, a JSON-RPC or API error, malformed data) has its answer returned,
//! and later requests start at the next endpoint. When a whole round fails,
//! the next round starts after an exponential backoff whose jitter is derived
//! from a caller-provided seed, so retries are deterministic in tests and
//! spread out across nodes. Callers that find an endpoint's data unusable
//! after verification move on with [`EndpointSet::rotate_preferred`].
//!
//! Lists start at their first endpoint unless seeded
//! ([`EndpointSet::with_seeded_start`], [`start_index`]): the in-node keeper
//! seeds its lists, so validators sharing the compiled public lists start at
//! different endpoints instead of all hitting the first one at once.
//!
//! A [`PollBudget`] bounds the wall-clock time of a caller's whole poll: no
//! attempt starts and no backoff sleeps past its deadline, and each attempt's
//! own deadline is clipped to it.
//!
//! Secret header values are read lazily, at every attempt, from files that
//! must be regular, non-symlink and owner-only (mode `0600` or stricter). The
//! read buffer is zeroized after use and values are never logged or printed.

use std::{
    fmt,
    fs::{self, File},
    io::{self, Read as _},
    num::NonZeroU32,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use iroha_config::parameters::{
    actual::{
        SccpLightClientKeeper, SccpLightClientKeeperEndpoints, SccpSecretHeader,
        compiled_http_endpoints, parse_sccp_http_endpoint, parse_sccp_secret_header_name,
    },
    defaults,
};
use reqwest::{
    Url,
    header::{HeaderName, HeaderValue},
};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::http::{AttemptFailure, RpcError};

/// Largest accepted secret header value file.
pub const MAX_SECRET_HEADER_VALUE_BYTES: usize = 8 * 1024;
/// Default number of failover rounds of one request.
pub const DEFAULT_FAILOVER_ROUNDS: u32 = 3;
/// Default backoff before the second round.
pub const DEFAULT_BACKOFF_BASE: Duration = Duration::from_millis(250);
/// Default longest backoff between rounds.
pub const DEFAULT_BACKOFF_MAX: Duration = Duration::from_secs(8);

/// The HTTP endpoint lists of `[sccp.light_client_keeper.endpoints]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HttpEndpointKind {
    /// Ethereum execution-layer JSON-RPC.
    EthereumExecution,
    /// Ethereum beacon API (light-client routes).
    EthereumBeacon,
    /// BNB Smart Chain JSON-RPC.
    Bsc,
}

impl HttpEndpointKind {
    /// Every HTTP endpoint list.
    pub const ALL: [Self; 3] = [Self::EthereumExecution, Self::EthereumBeacon, Self::Bsc];

    /// Configuration key of the list.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EthereumExecution => "ethereum_execution",
            Self::EthereumBeacon => "ethereum_beacon",
            Self::Bsc => "bsc",
        }
    }

    /// The compiled default public endpoints of the list.
    pub const fn compiled_default_urls(self) -> &'static [&'static str] {
        match self {
            Self::EthereumExecution => defaults::sccp::endpoints::ETHEREUM_EXECUTION,
            Self::EthereumBeacon => defaults::sccp::endpoints::ETHEREUM_BEACON,
            Self::Bsc => defaults::sccp::endpoints::BSC,
        }
    }

    /// The effective configured list of this kind.
    pub fn configured(self, endpoints: &SccpLightClientKeeperEndpoints) -> &[Url] {
        match self {
            Self::EthereumExecution => &endpoints.ethereum_execution,
            Self::EthereumBeacon => &endpoints.ethereum_beacon,
            Self::Bsc => &endpoints.bsc,
        }
    }
}

/// Why an endpoint list or a secret-header entry was rejected.
///
/// Messages never echo URLs or header values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointError {
    message: String,
}

impl EndpointError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for EndpointError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for EndpointError {}

/// Why a secret header value file was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretFileError {
    /// The value file.
    pub path: PathBuf,
    /// What is wrong with it.
    pub problem: SecretFileProblem,
}

/// What is wrong with a secret header value file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretFileProblem {
    /// Inspecting, opening or reading failed.
    Io {
        /// Kind of the I/O error.
        kind: io::ErrorKind,
        /// OS error code, when there is one.
        raw_os_error: Option<i32>,
    },
    /// The path is a symbolic link.
    Symlink,
    /// The path is not a regular file.
    NotRegularFile,
    /// Group or other permission bits, owner execute, or the setuid, setgid or
    /// sticky bit are set.
    Permissions {
        /// The file's permission bits.
        mode: u32,
    },
    /// The file was replaced between inspection and opening.
    Replaced,
    /// The value exceeds [`MAX_SECRET_HEADER_VALUE_BYTES`].
    TooLarge,
    /// The value is empty (after one trailing line break).
    Empty,
    /// The value contains bytes an HTTP header value cannot carry.
    InvalidValue,
    /// Owner-only files cannot be checked on this platform.
    Unsupported,
}

impl fmt::Display for SecretFileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let path = self.path.display();
        match self.problem {
            SecretFileProblem::Io { kind, .. } => {
                write!(formatter, "`{path}` is unreadable: {kind}")
            }
            SecretFileProblem::Symlink => {
                write!(
                    formatter,
                    "`{path}` is a symbolic link; use the file itself"
                )
            }
            SecretFileProblem::NotRegularFile => {
                write!(formatter, "`{path}` is not a regular file")
            }
            SecretFileProblem::Permissions { mode } => write!(
                formatter,
                "`{path}` has mode {:04o}; it must be owner-only (0600 or stricter)",
                mode & 0o7777
            ),
            SecretFileProblem::Replaced => {
                write!(formatter, "`{path}` changed while it was being opened")
            }
            SecretFileProblem::TooLarge => write!(
                formatter,
                "`{path}` exceeds {MAX_SECRET_HEADER_VALUE_BYTES} bytes"
            ),
            SecretFileProblem::Empty => write!(formatter, "`{path}` holds an empty value"),
            SecretFileProblem::InvalidValue => write!(
                formatter,
                "`{path}` holds bytes that an HTTP header value cannot carry"
            ),
            SecretFileProblem::Unsupported => write!(
                formatter,
                "`{path}` cannot be checked for owner-only access on this platform"
            ),
        }
    }
}

impl std::error::Error for SecretFileError {}

/// A secret request header whose value is read from an owner-only file.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretHeaderSource {
    name: HeaderName,
    value_file: PathBuf,
}

impl fmt::Debug for SecretHeaderSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretHeaderSource")
            .field("name", &self.name.as_str())
            .field("value_file", &self.value_file)
            .finish()
    }
}

impl SecretHeaderSource {
    /// A secret header `name` (an HTTP token the client does not own itself)
    /// read from `value_file`. The file is not touched until a request is sent.
    ///
    /// # Errors
    /// If `name` is not an acceptable header name.
    pub fn new(name: &str, value_file: impl Into<PathBuf>) -> Result<Self, EndpointError> {
        let name = parse_sccp_secret_header_name(name)
            .map_err(|error| EndpointError::new(error.to_string()))?;
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| EndpointError::new("a secret header name must be an HTTP token"))?;
        Ok(Self {
            name,
            value_file: value_file.into(),
        })
    }

    /// The lowercase header name.
    pub fn name(&self) -> &HeaderName {
        &self.name
    }

    /// The owner-only value file.
    pub fn value_file(&self) -> &Path {
        &self.value_file
    }

    /// Reads the value file now and returns a sensitive header value.
    ///
    /// The file must be a regular file (not a symlink) with mode `0600` or
    /// stricter. One trailing line break is removed. The read buffer is
    /// zeroized before returning; the returned value is marked sensitive so the
    /// HTTP stack never prints it.
    ///
    /// # Errors
    /// [`SecretFileError`] describing the refusal, never the value.
    pub fn header_value(&self) -> Result<HeaderValue, SecretFileError> {
        let refuse = |problem| SecretFileError {
            path: self.value_file.clone(),
            problem,
        };
        let secret = read_owner_only_file(&self.value_file).map_err(refuse)?;
        let value = strip_line_break(&secret);
        if value.is_empty() {
            return Err(refuse(SecretFileProblem::Empty));
        }
        let mut header =
            HeaderValue::from_bytes(value).map_err(|_| refuse(SecretFileProblem::InvalidValue))?;
        header.set_sensitive(true);
        Ok(header)
    }
}

/// Removes one trailing `\n` or `\r\n`.
fn strip_line_break(value: &[u8]) -> &[u8] {
    let value = value.strip_suffix(b"\n").unwrap_or(value);
    value.strip_suffix(b"\r").unwrap_or(value)
}

/// Permission bits a secret header value file must not carry: setuid, setgid,
/// sticky, owner execute and every group or other bit. What remains is `0600`
/// or stricter.
#[cfg(unix)]
const OWNER_ONLY_FORBIDDEN_MODE_BITS: u32 = 0o7177;

/// Reads an owner-only regular file into a zeroizing buffer.
#[cfg(unix)]
fn read_owner_only_file(path: &Path) -> Result<Zeroizing<Vec<u8>>, SecretFileProblem> {
    use std::os::unix::fs::MetadataExt as _;

    fn check(metadata: &fs::Metadata) -> Result<(), SecretFileProblem> {
        if metadata.file_type().is_symlink() {
            return Err(SecretFileProblem::Symlink);
        }
        if !metadata.is_file() {
            return Err(SecretFileProblem::NotRegularFile);
        }
        let mode = metadata.mode();
        if mode & OWNER_ONLY_FORBIDDEN_MODE_BITS != 0 {
            return Err(SecretFileProblem::Permissions { mode });
        }
        Ok(())
    }

    let io_problem = |error: io::Error| SecretFileProblem::Io {
        kind: error.kind(),
        raw_os_error: error.raw_os_error(),
    };
    let before = fs::symlink_metadata(path).map_err(io_problem)?;
    check(&before)?;
    let mut file = File::open(path).map_err(io_problem)?;
    let opened = file.metadata().map_err(io_problem)?;
    if opened.dev() != before.dev() || opened.ino() != before.ino() {
        return Err(SecretFileProblem::Replaced);
    }
    check(&opened)?;
    // A fixed buffer is never reallocated, so no unzeroized copy is left behind.
    let mut buffer = Zeroizing::new(vec![0_u8; MAX_SECRET_HEADER_VALUE_BYTES + 1]);
    let mut filled = 0;
    loop {
        let read = file.read(&mut buffer[filled..]).map_err(io_problem)?;
        if read == 0 {
            break;
        }
        filled += read;
        if filled > MAX_SECRET_HEADER_VALUE_BYTES {
            return Err(SecretFileProblem::TooLarge);
        }
    }
    buffer.truncate(filled);
    Ok(buffer)
}

/// Owner-only files cannot be checked without Unix permissions.
#[cfg(not(unix))]
fn read_owner_only_file(_path: &Path) -> Result<Zeroizing<Vec<u8>>, SecretFileProblem> {
    Err(SecretFileProblem::Unsupported)
}

/// One HTTP endpoint and its secret headers.
#[derive(Clone, PartialEq, Eq)]
pub struct Endpoint {
    url: Url,
    origin: String,
    secret_headers: Vec<SecretHeaderSource>,
}

impl fmt::Debug for Endpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: Vec<&str> = self
            .secret_headers
            .iter()
            .map(|header| header.name.as_str())
            .collect();
        formatter
            .debug_struct("Endpoint")
            .field("origin", &self.origin)
            .field("secret_headers", &names)
            .finish_non_exhaustive()
    }
}

impl Endpoint {
    fn new(url: Url) -> Self {
        let origin = url.origin().ascii_serialization();
        Self {
            url,
            origin,
            secret_headers: Vec::new(),
        }
    }

    /// The endpoint URL. It may embed provider keys in its path or query, so it
    /// must not be logged; use [`Self::origin`].
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// `scheme://host[:port]`, safe to log.
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// Secret headers sent with every request to this endpoint.
    pub fn secret_headers(&self) -> &[SecretHeaderSource] {
        &self.secret_headers
    }

    /// The URL of `path_and_query` below this endpoint: the path is appended
    /// to the endpoint's own path and the queries are joined, so
    /// `https://host/key?x=1` with `/wallet/getnowblock` becomes
    /// `https://host/key/wallet/getnowblock?x=1`. An empty path addresses the
    /// endpoint URL itself (JSON-RPC).
    ///
    /// # Errors
    /// [`RpcError::InvalidRequest`] if a non-empty path does not start with `/`
    /// or carries a fragment.
    pub fn request_url(&self, path_and_query: &str) -> Result<Url, RpcError> {
        if path_and_query.is_empty() {
            return Ok(self.url.clone());
        }
        if !path_and_query.starts_with('/') || path_and_query.contains('#') {
            return Err(RpcError::InvalidRequest(
                "a request path must start with `/` and carry no fragment".to_owned(),
            ));
        }
        let (path, query) = path_and_query
            .split_once('?')
            .map_or((path_and_query, None), |(path, query)| (path, Some(query)));
        let mut url = self.url.clone();
        let joined_path = format!("{}{path}", self.url.path().trim_end_matches('/'));
        url.set_path(&joined_path);
        let joined_query = match (self.url.query(), query) {
            (Some(base), Some(extra)) if !base.is_empty() && !extra.is_empty() => {
                Some(format!("{base}&{extra}"))
            }
            (Some(base), _) if !base.is_empty() => Some(base.to_owned()),
            (_, Some(extra)) if !extra.is_empty() => Some(extra.to_owned()),
            _ => None,
        };
        url.set_query(joined_query.as_deref());
        Ok(url)
    }
}

/// One chain's ordered endpoint list with a preferred (last answering)
/// endpoint.
pub struct EndpointSet {
    endpoints: Vec<Endpoint>,
    preferred: AtomicUsize,
}

impl Clone for EndpointSet {
    fn clone(&self) -> Self {
        Self {
            endpoints: self.endpoints.clone(),
            preferred: AtomicUsize::new(self.preferred()),
        }
    }
}

impl fmt::Debug for EndpointSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EndpointSet")
            .field("endpoints", &self.endpoints)
            .field("preferred", &self.preferred())
            .finish()
    }
}

impl EndpointSet {
    /// A list of `urls`, each re-checked with the configuration rules
    /// (`https`, or `http` for loopback hosts; no credentials; no fragment),
    /// with the entries of `secret_headers` whose endpoint equals one of the
    /// URLs attached to it. Entries for other endpoints are ignored, so one
    /// secret-header table can serve every chain.
    ///
    /// # Errors
    /// If the list is empty, longer than the configuration allows, holds a
    /// duplicate or an invalid URL, or a secret header is invalid or repeated
    /// for one endpoint.
    pub fn new(
        urls: impl IntoIterator<Item = Url>,
        secret_headers: &[SccpSecretHeader],
    ) -> Result<Self, EndpointError> {
        let mut endpoints: Vec<Endpoint> = Vec::new();
        for url in urls {
            let url = parse_sccp_http_endpoint(url.as_str())
                .map_err(|error| EndpointError::new(error.to_string()))?;
            if endpoints.iter().any(|endpoint| endpoint.url == url) {
                return Err(EndpointError::new("an endpoint list repeats an endpoint"));
            }
            endpoints.push(Endpoint::new(url));
        }
        if endpoints.is_empty() {
            return Err(EndpointError::new("an endpoint list must not be empty"));
        }
        if endpoints.len() > defaults::sccp::light_client_keeper::MAX_ENDPOINTS_PER_LIST {
            return Err(EndpointError::new(format!(
                "an endpoint list holds at most {} endpoints",
                defaults::sccp::light_client_keeper::MAX_ENDPOINTS_PER_LIST
            )));
        }
        if secret_headers.len() > defaults::sccp::light_client_keeper::MAX_SECRET_HEADERS {
            return Err(EndpointError::new(format!(
                "at most {} secret headers are accepted",
                defaults::sccp::light_client_keeper::MAX_SECRET_HEADERS
            )));
        }
        for entry in secret_headers {
            let Some(endpoint) = endpoints
                .iter_mut()
                .find(|endpoint| endpoint.url == entry.endpoint)
            else {
                continue;
            };
            let source = SecretHeaderSource::new(&entry.header, entry.value_file.clone())?;
            if endpoint
                .secret_headers
                .iter()
                .any(|existing| existing.name == source.name)
            {
                return Err(EndpointError::new(
                    "a secret header is configured twice for one endpoint",
                ));
            }
            endpoint.secret_headers.push(source);
        }
        Ok(Self {
            endpoints,
            preferred: AtomicUsize::new(0),
        })
    }

    /// Parses `urls` and builds the list as [`Self::new`] does.
    ///
    /// # Errors
    /// As [`Self::new`], or if an entry is not a URL.
    pub fn parse(
        urls: &[&str],
        secret_headers: &[SccpSecretHeader],
    ) -> Result<Self, EndpointError> {
        let urls = urls
            .iter()
            .map(|raw| {
                parse_sccp_http_endpoint(raw).map_err(|error| EndpointError::new(error.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(urls, secret_headers)
    }

    /// The compiled default public list of `kind`, without secret headers.
    pub fn compiled_defaults(kind: HttpEndpointKind) -> Self {
        let endpoints = compiled_http_endpoints(kind.compiled_default_urls())
            .into_iter()
            .map(Endpoint::new)
            .collect();
        Self {
            endpoints,
            preferred: AtomicUsize::new(0),
        }
    }

    /// The keeper's effective list of `kind` (configured, or the compiled
    /// defaults when the configured list was empty) with its secret headers.
    ///
    /// # Errors
    /// As [`Self::new`].
    pub fn from_keeper_config(
        keeper: &SccpLightClientKeeper,
        kind: HttpEndpointKind,
    ) -> Result<Self, EndpointError> {
        Self::new(
            kind.configured(&keeper.endpoints).iter().cloned(),
            &keeper.secret_headers,
        )
    }

    /// Number of endpoints (at least one).
    pub fn len(&self) -> usize {
        self.endpoints.len()
    }

    /// Always `false`: a list holds at least one endpoint.
    pub fn is_empty(&self) -> bool {
        self.endpoints.is_empty()
    }

    /// The endpoints in configured order.
    pub fn endpoints(&self) -> &[Endpoint] {
        &self.endpoints
    }

    /// Index of the endpoint the next request starts at.
    pub fn preferred(&self) -> usize {
        self.preferred.load(Ordering::Relaxed) % self.endpoints.len().max(1)
    }

    /// The endpoint the next request starts at.
    pub fn preferred_endpoint(&self) -> &Endpoint {
        &self.endpoints[self.preferred()]
    }

    /// The same list with requests starting at [`start_index`]`(seed, len)`
    /// instead of the first endpoint, so callers with different seeds (the
    /// keepers of different validators) spread over a shared list.
    #[must_use]
    pub fn with_seeded_start(self, seed: u64) -> Self {
        self.set_preferred(start_index(seed, self.len()));
        self
    }

    /// Moves the preferred endpoint to the next one, for callers whose
    /// verification rejected the data of the current one (the preferred
    /// endpoint is the one that answered last).
    pub fn rotate_preferred(&self) {
        self.rotate_past(self.preferred());
    }

    /// Makes the endpoint after `index` the preferred one.
    fn rotate_past(&self, index: usize) {
        self.set_preferred((index + 1) % self.endpoints.len().max(1));
    }

    fn set_preferred(&self, index: usize) {
        self.preferred.store(index, Ordering::Relaxed);
    }
}

/// Domain separator of [`start_index`].
const START_INDEX_DOMAIN: u64 = 0x5343_4350_5354_4152;
/// Domain separator of [`endpoint_seed`].
const ENDPOINT_SEED_DOMAIN: &[u8] = b"iroha-sccp-rpc/endpoint-seed/v1";

/// A seed for start indices and backoff jitter derived from caller bytes,
/// such as the node's peer id: the first eight bytes, little-endian, of
/// `SHA-256("iroha-sccp-rpc/endpoint-seed/v1" ‖ bytes)`. Equal bytes give
/// equal seeds on every platform.
pub fn endpoint_seed(bytes: &[u8]) -> u64 {
    let digest = Sha256::new()
        .chain_update(ENDPOINT_SEED_DOMAIN)
        .chain_update(bytes)
        .finalize();
    let mut word = [0_u8; 8];
    word.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(word)
}

/// The index a list of `len` entries starts at for `seed`: a fixed,
/// platform-independent mix of the seed reduced modulo `len` (zero for an
/// empty list).
pub fn start_index(seed: u64, len: usize) -> usize {
    let Ok(len64) = u64::try_from(len) else {
        return 0;
    };
    if len64 == 0 {
        return 0;
    }
    usize::try_from(splitmix64(seed ^ START_INDEX_DOMAIN) % len64).unwrap_or(0)
}

/// A wall-clock budget for a caller's poll, shared by every transport and
/// liteclient that carries a clone of it.
///
/// While a deadline is set, failover starts no attempt and sleeps no backoff
/// past it, and each attempt's own deadline is clipped to it; the request then
/// ends with a budget error that lists the failed attempts. Without a
/// deadline, requests are bounded by their per-attempt timeouts and failover
/// rounds only.
#[derive(Debug, Clone, Default)]
pub struct PollBudget {
    deadline: Arc<Mutex<Option<Instant>>>,
}

impl PollBudget {
    /// A budget without a deadline.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the deadline to `duration` from now until the returned guard is
    /// dropped. A duration too large for the clock leaves no deadline.
    pub fn start(&self, duration: Duration) -> PollBudgetGuard {
        self.set_deadline(Instant::now().checked_add(duration));
        PollBudgetGuard {
            budget: self.clone(),
        }
    }

    /// Sets (or, with `None`, clears) the deadline.
    pub fn set_deadline(&self, deadline: Option<Instant>) {
        *self.deadline.lock().unwrap_or_else(PoisonError::into_inner) = deadline;
    }

    /// The current deadline, if any.
    pub fn deadline(&self) -> Option<Instant> {
        *self.deadline.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Clears its [`PollBudget`]'s deadline when dropped.
#[derive(Debug)]
#[must_use = "the budget ends when the guard is dropped"]
pub struct PollBudgetGuard {
    budget: PollBudget,
}

impl Drop for PollBudgetGuard {
    fn drop(&mut self) {
        self.budget.set_deadline(None);
    }
}

/// The deadline of one attempt starting at `now`: `timeout` from now, or the
/// poll `budget` deadline when that comes first. Every byte of the attempt
/// (connecting, sending, reading the whole answer) must arrive before it.
pub fn attempt_deadline(now: Instant, timeout: Duration, budget: Option<Instant>) -> Instant {
    match (now.checked_add(timeout), budget) {
        (Some(own), Some(budget)) => own.min(budget),
        (Some(own), None) => own,
        (None, Some(budget)) => budget,
        // A timeout beyond the clock's range: as far as the clock goes.
        (None, None) => now
            .checked_add(Duration::from_secs(u64::from(u32::MAX)))
            .unwrap_or(now),
    }
}

/// Whether a poll with `deadline` leaves room for work that ends at `until`
/// (`None`: beyond the clock's range).
pub(crate) fn within_budget(deadline: Option<Instant>, until: Option<Instant>) -> bool {
    match (deadline, until) {
        (None, _) => true,
        (Some(deadline), Some(until)) => until < deadline,
        (Some(_), None) => false,
    }
}

/// Exponential backoff between failover rounds, with jitter derived from a
/// seed.
///
/// Round `r` (zero-based, counting failed rounds) waits a duration in
/// `[d/2, d]` where `d = min(base · 2^r, max)`; the point in that range is a
/// deterministic function of `(seed, r)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Backoff {
    base: Duration,
    max: Duration,
    seed: u64,
}

impl Backoff {
    /// A backoff starting at `base` and capped at `max` (raised to `base` if
    /// smaller), with jitter seeded by `seed`.
    pub fn new(base: Duration, max: Duration, seed: u64) -> Self {
        Self {
            base,
            max: max.max(base),
            seed,
        }
    }

    /// The initial delay.
    pub fn base(&self) -> Duration {
        self.base
    }

    /// The longest delay.
    pub fn max(&self) -> Duration {
        self.max
    }

    /// The jitter seed.
    pub fn seed(&self) -> u64 {
        self.seed
    }

    /// The delay after `failed_rounds + 1` failed rounds.
    pub fn delay(&self, failed_rounds: u32) -> Duration {
        let factor = 1_u32.checked_shl(failed_rounds.min(31)).unwrap_or(u32::MAX);
        let ceiling = self.base.saturating_mul(factor).min(self.max);
        let nanos = u64::try_from(ceiling.as_nanos()).unwrap_or(u64::MAX);
        let floor = nanos / 2;
        let span = nanos - floor;
        let jitter = if span == 0 {
            0
        } else {
            splitmix64(self.seed ^ u64::from(failed_rounds).wrapping_mul(0x9E37_79B9_7F4A_7C15))
                % span.saturating_add(1)
        };
        Duration::from_nanos(floor + jitter)
    }
}

/// `SplitMix64` finalizer: a fixed, platform-independent mixing function.
fn splitmix64(seed: u64) -> u64 {
    let mut z = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// How often a request goes around its endpoint list and how long it waits in
/// between.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailoverPolicy {
    /// Rounds over the whole list before giving up.
    pub rounds: NonZeroU32,
    /// Backoff between failed rounds.
    pub backoff: Backoff,
}

impl FailoverPolicy {
    /// A policy of `rounds` rounds with `backoff` in between.
    pub fn new(rounds: NonZeroU32, backoff: Backoff) -> Self {
        Self { rounds, backoff }
    }

    /// The default policy ([`DEFAULT_FAILOVER_ROUNDS`] rounds,
    /// [`DEFAULT_BACKOFF_BASE`]..[`DEFAULT_BACKOFF_MAX`]) with jitter seeded by
    /// `seed`.
    pub fn with_seed(seed: u64) -> Self {
        Self {
            rounds: NonZeroU32::new(DEFAULT_FAILOVER_ROUNDS).unwrap_or(NonZeroU32::MIN),
            backoff: Backoff::new(DEFAULT_BACKOFF_BASE, DEFAULT_BACKOFF_MAX, seed),
        }
    }

    /// The wait before round `failed_rounds + 1`: the backoff delay, or the
    /// endpoints' longest `Retry-After` of the failed round when that is longer
    /// (capped at the backoff maximum).
    pub fn round_delay(&self, failed_rounds: u32, retry_after: Option<Duration>) -> Duration {
        let delay = self.backoff.delay(failed_rounds);
        retry_after.map_or(delay, |requested| {
            delay.max(requested.min(self.backoff.max()))
        })
    }
}

impl Default for FailoverPolicy {
    fn default() -> Self {
        Self::with_seed(0)
    }
}

/// Waits between failover rounds.
pub trait Sleeper: Send + Sync {
    /// Blocks the calling thread for `duration`.
    fn sleep(&self, duration: Duration);
}

/// [`Sleeper`] backed by [`std::thread::sleep`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ThreadSleeper;

impl Sleeper for ThreadSleeper {
    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

/// Runs `attempt` against the endpoints of `endpoints` with failover, within
/// the poll `deadline` when one is given.
///
/// Each round tries every endpoint once, starting at the preferred endpoint
/// and going round-robin. A failover error ([`RpcError::is_failover`]) moves to
/// the next endpoint; any other result is returned at once. A success makes its
/// endpoint the preferred one; an error that discredits its endpoint
/// ([`RpcError::discredits_endpoint`]) makes the next endpoint the preferred
/// one. After a fully failed round the next one starts after
/// [`FailoverPolicy::round_delay`]. No attempt starts, and no backoff is slept,
/// past `deadline`.
///
/// # Errors
/// The first non-failover error; [`RpcError::BudgetExhausted`] with the failed
/// attempts when `deadline` passes first; or [`RpcError::Exhausted`] with every
/// failed attempt once all rounds failed.
pub fn run_with_failover<T>(
    endpoints: &EndpointSet,
    policy: &FailoverPolicy,
    sleeper: &dyn Sleeper,
    deadline: Option<Instant>,
    mut attempt: impl FnMut(&Endpoint) -> Result<T, RpcError>,
) -> Result<T, RpcError> {
    let count = endpoints.len();
    let mut failures = Vec::new();
    let mut retry_after = None;
    for round in 0..policy.rounds.get() {
        if round > 0 {
            let delay = policy.round_delay(round - 1, retry_after);
            if !within_budget(deadline, Instant::now().checked_add(delay)) {
                return Err(RpcError::BudgetExhausted { failures });
            }
            sleeper.sleep(delay);
            retry_after = None;
        }
        let start = endpoints.preferred();
        for offset in 0..count {
            if !within_budget(deadline, Some(Instant::now())) {
                return Err(RpcError::BudgetExhausted { failures });
            }
            let index = (start + offset) % count;
            let endpoint = &endpoints.endpoints[index];
            match attempt(endpoint) {
                Ok(value) => {
                    endpoints.set_preferred(index);
                    return Ok(value);
                }
                Err(error) if error.is_failover() => {
                    retry_after = retry_after.max(error.retry_after());
                    failures.push(AttemptFailure {
                        endpoint: endpoint.origin().to_owned(),
                        round,
                        error,
                    });
                }
                Err(error) => {
                    if error.discredits_endpoint() {
                        endpoints.rotate_past(index);
                    }
                    return Err(error);
                }
            }
        }
    }
    Err(RpcError::Exhausted { failures })
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    fn url(text: &str) -> Url {
        parse_sccp_http_endpoint(text).expect("test URL")
    }

    fn header(endpoint: &str, name: &str, file: &str) -> SccpSecretHeader {
        SccpSecretHeader {
            endpoint: url(endpoint),
            header: name.to_owned(),
            value_file: PathBuf::from(file),
        }
    }

    #[derive(Default)]
    struct RecordingSleeper(Mutex<Vec<Duration>>);

    impl Sleeper for RecordingSleeper {
        fn sleep(&self, duration: Duration) {
            self.0.lock().expect("lock").push(duration);
        }
    }

    fn timeout(endpoint: &Endpoint) -> RpcError {
        RpcError::Timeout {
            endpoint: endpoint.origin().to_owned(),
        }
    }

    #[test]
    fn compiled_defaults_cover_every_http_list() {
        for kind in HttpEndpointKind::ALL {
            let set = EndpointSet::compiled_defaults(kind);
            assert_eq!(set.len(), kind.compiled_default_urls().len());
            assert!(!set.is_empty());
            for endpoint in set.endpoints() {
                assert_eq!(endpoint.url().scheme(), "https");
                assert!(endpoint.secret_headers().is_empty());
            }
            assert!(!kind.as_str().is_empty());
        }
        assert_eq!(
            HttpEndpointKind::ALL.map(HttpEndpointKind::as_str),
            ["ethereum_execution", "ethereum_beacon", "bsc"],
            "the HTTP endpoint kinds are execution, beacon and BSC"
        );
        let keeper = SccpLightClientKeeper::default();
        let from_config =
            EndpointSet::from_keeper_config(&keeper, HttpEndpointKind::Bsc).expect("defaults");
        assert_eq!(
            from_config.endpoints(),
            EndpointSet::compiled_defaults(HttpEndpointKind::Bsc).endpoints()
        );
    }

    #[test]
    fn endpoint_lists_are_validated() {
        assert!(EndpointSet::parse(&[], &[]).is_err());
        assert!(EndpointSet::parse(&["http://rpc.example.org"], &[]).is_err());
        assert!(
            EndpointSet::parse(&["https://a.example.org", "https://a.example.org"], &[]).is_err()
        );
        let too_many: Vec<String> = (0
            ..=defaults::sccp::light_client_keeper::MAX_ENDPOINTS_PER_LIST)
            .map(|index| format!("https://rpc{index}.example.org"))
            .collect();
        let too_many: Vec<&str> = too_many.iter().map(String::as_str).collect();
        assert!(EndpointSet::parse(&too_many, &[]).is_err());
        let set = EndpointSet::parse(&["https://a.example.org", "http://127.0.0.1:8545"], &[])
            .expect("valid list");
        assert_eq!(set.len(), 2);
        assert_eq!(set.endpoints()[1].origin(), "http://127.0.0.1:8545");
    }

    #[test]
    fn secret_headers_attach_to_their_endpoint_only() {
        let headers = [
            header("https://a.example.org/key", "X-Api-Key", "/k1"),
            header("https://other.example.org", "x-api-key", "/k2"),
        ];
        let set = EndpointSet::parse(
            &["https://a.example.org/key", "https://b.example.org"],
            &headers,
        )
        .expect("list");
        assert_eq!(set.endpoints()[0].secret_headers().len(), 1);
        assert_eq!(
            set.endpoints()[0].secret_headers()[0].name().as_str(),
            "x-api-key"
        );
        assert_eq!(
            set.endpoints()[0].secret_headers()[0].value_file(),
            Path::new("/k1")
        );
        assert!(set.endpoints()[1].secret_headers().is_empty());

        let repeated = [
            header("https://a.example.org", "x-api-key", "/k1"),
            header("https://a.example.org", "X-API-KEY", "/k2"),
        ];
        assert!(EndpointSet::parse(&["https://a.example.org"], &repeated).is_err());
        let reserved = [header("https://a.example.org", "host", "/k1")];
        assert!(EndpointSet::parse(&["https://a.example.org"], &reserved).is_err());
    }

    #[test]
    fn debug_output_hides_paths_and_values() {
        let headers = [header(
            "https://a.example.org/v3/secretkey",
            "x-api-key",
            "/k1",
        )];
        let set =
            EndpointSet::parse(&["https://a.example.org/v3/secretkey"], &headers).expect("list");
        let debug = format!("{set:?}");
        assert!(debug.contains("https://a.example.org"));
        assert!(!debug.contains("secretkey"));
        assert!(debug.contains("x-api-key"));
    }

    #[test]
    fn request_urls_join_paths_and_queries() {
        let plain = Endpoint::new(url("https://rpc.example.org"));
        assert_eq!(
            plain
                .request_url("/eth/v1/beacon/light_client/finality_update")
                .expect("url")
                .as_str(),
            "https://rpc.example.org/eth/v1/beacon/light_client/finality_update"
        );
        assert_eq!(
            plain.request_url("").expect("url").as_str(),
            "https://rpc.example.org/"
        );
        let keyed = Endpoint::new(url("https://rpc.example.org/v2/key/?network=main"));
        assert_eq!(
            keyed
                .request_url("/eth/v1/beacon/light_client/updates?start_period=1&count=2")
                .expect("url")
                .as_str(),
            "https://rpc.example.org/v2/key/eth/v1/beacon/light_client/updates?network=main&start_period=1&count=2"
        );
        assert_eq!(keyed.origin(), "https://rpc.example.org");
        assert!(plain.request_url("eth").is_err());
        assert!(plain.request_url("/a#b").is_err());
    }

    #[test]
    fn backoff_is_deterministic_bounded_and_seeded() {
        let backoff = Backoff::new(Duration::from_millis(100), Duration::from_secs(1), 42);
        for round in 0..40 {
            let delay = backoff.delay(round);
            let ceiling = Duration::from_millis(100)
                .saturating_mul(1_u32.checked_shl(round.min(31)).unwrap_or(u32::MAX))
                .min(Duration::from_secs(1));
            assert!(
                delay >= ceiling / 2 && delay <= ceiling,
                "round {round}: {delay:?}"
            );
            assert_eq!(delay, backoff.delay(round));
        }
        let other = Backoff::new(Duration::from_millis(100), Duration::from_secs(1), 43);
        assert!((0..8).any(|round| backoff.delay(round) != other.delay(round)));
        let zero = Backoff::new(Duration::ZERO, Duration::ZERO, 1);
        assert_eq!(zero.delay(3), Duration::ZERO);
        assert_eq!(
            Backoff::new(Duration::from_secs(2), Duration::from_secs(1), 0).max(),
            Duration::from_secs(2)
        );
        assert_ne!(splitmix64(0), splitmix64(1));
    }

    #[test]
    fn round_delay_honours_retry_after_up_to_the_cap() {
        let policy = FailoverPolicy::new(
            NonZeroU32::new(3).expect("nonzero"),
            Backoff::new(Duration::from_millis(10), Duration::from_secs(5), 7),
        );
        assert_eq!(policy.round_delay(0, None), policy.backoff.delay(0));
        assert_eq!(
            policy.round_delay(0, Some(Duration::from_secs(2))),
            Duration::from_secs(2)
        );
        assert_eq!(
            policy.round_delay(0, Some(Duration::from_secs(60))),
            Duration::from_secs(5)
        );
        assert_eq!(
            FailoverPolicy::default().rounds.get(),
            DEFAULT_FAILOVER_ROUNDS
        );
        assert_eq!(FailoverPolicy::with_seed(9).backoff.seed(), 9);
        assert_eq!(
            FailoverPolicy::with_seed(9).backoff.base(),
            DEFAULT_BACKOFF_BASE
        );
    }

    #[test]
    fn failover_walks_round_robin_and_sticks_to_the_answering_endpoint() {
        let set = EndpointSet::parse(
            &[
                "https://a.example.org",
                "https://b.example.org",
                "https://c.example.org",
            ],
            &[],
        )
        .expect("list");
        let sleeper = RecordingSleeper::default();
        let policy = FailoverPolicy::default();
        let mut visited = Vec::new();
        let answer = run_with_failover(&set, &policy, &sleeper, None, |endpoint| {
            visited.push(endpoint.origin().to_owned());
            if endpoint.origin() == "https://c.example.org" {
                Ok(3)
            } else {
                Err(timeout(endpoint))
            }
        })
        .expect("third endpoint answers");
        assert_eq!(answer, 3);
        assert_eq!(
            visited,
            [
                "https://a.example.org",
                "https://b.example.org",
                "https://c.example.org"
            ]
        );
        assert_eq!(set.preferred(), 2);
        assert!(sleeper.0.lock().expect("lock").is_empty());

        // A failure of the preferred endpoint wraps around the list in order.
        let mut wrapped = Vec::new();
        let answer = run_with_failover(&set, &policy, &sleeper, None, |endpoint| {
            wrapped.push(endpoint.origin().to_owned());
            if endpoint.origin() == "https://b.example.org" {
                Ok(2)
            } else {
                Err(timeout(endpoint))
            }
        })
        .expect("second endpoint answers");
        assert_eq!(answer, 2);
        assert_eq!(
            wrapped,
            [
                "https://c.example.org",
                "https://a.example.org",
                "https://b.example.org"
            ]
        );
        assert_eq!(set.preferred(), 1);
        set.set_preferred(2);

        let mut first = None;
        run_with_failover(&set, &policy, &sleeper, None, |endpoint| {
            first.get_or_insert_with(|| endpoint.origin().to_owned());
            Ok(())
        })
        .expect("answer");
        assert_eq!(first.as_deref(), Some("https://c.example.org"));
        set.rotate_preferred();
        assert_eq!(set.preferred(), 0);
        assert_eq!(set.preferred_endpoint().origin(), "https://a.example.org");
        assert_eq!(set.clone().preferred(), 0);
    }

    #[test]
    fn failover_exhausts_rounds_with_seeded_backoff() {
        let set = EndpointSet::parse(&["https://a.example.org", "https://b.example.org"], &[])
            .expect("list");
        let sleeper = RecordingSleeper::default();
        let policy = FailoverPolicy::new(
            NonZeroU32::new(3).expect("nonzero"),
            Backoff::new(Duration::from_millis(50), Duration::from_secs(1), 11),
        );
        let error = run_with_failover(&set, &policy, &sleeper, None, |endpoint| -> Result<(), _> {
            Err(timeout(endpoint))
        })
        .expect_err("every attempt fails");
        let RpcError::Exhausted { failures } = &error else {
            panic!("unexpected {error:?}");
        };
        assert_eq!(failures.len(), 6);
        assert_eq!(failures[5].round, 2);
        assert!(matches!(error.last_failure(), RpcError::Timeout { .. }));
        assert_eq!(
            *sleeper.0.lock().expect("lock"),
            vec![policy.backoff.delay(0), policy.backoff.delay(1)]
        );
    }

    #[test]
    fn failover_returns_answers_at_once() {
        let set = EndpointSet::parse(&["https://a.example.org", "https://b.example.org"], &[])
            .expect("list");
        let mut attempts = 0;
        let error = run_with_failover(
            &set,
            &FailoverPolicy::default(),
            &RecordingSleeper::default(),
            None,
            |endpoint| -> Result<(), _> {
                attempts += 1;
                Err(RpcError::Status {
                    endpoint: endpoint.origin().to_owned(),
                    status: 404,
                    retry_after: None,
                    message: None,
                })
            },
        )
        .expect_err("404 is an answer");
        assert_eq!(attempts, 1);
        assert!(matches!(error, RpcError::Status { status: 404, .. }));
        // The answering endpoint is discredited: the next request starts at
        // the next one.
        assert_eq!(set.preferred(), 1);
    }

    #[test]
    fn discrediting_answers_rotate_past_the_answering_endpoint() {
        let set = EndpointSet::parse(
            &[
                "https://a.example.org",
                "https://b.example.org",
                "https://c.example.org",
            ],
            &[],
        )
        .expect("list");
        let sleeper = RecordingSleeper::default();
        let policy = FailoverPolicy::default();
        // `a` times out, `b` answers with malformed data: `b` is returned and
        // the next request starts at `c`.
        let error = run_with_failover(&set, &policy, &sleeper, None, |endpoint| -> Result<(), _> {
            if endpoint.origin() == "https://a.example.org" {
                Err(timeout(endpoint))
            } else {
                Err(crate::http::invalid_response("bad hex"))
            }
        })
        .expect_err("malformed data");
        assert!(matches!(error, RpcError::InvalidResponse { .. }));
        assert_eq!(set.preferred(), 2);
        // A request error raised before anything was sent discredits nobody.
        let error = run_with_failover(&set, &policy, &sleeper, None, |_| -> Result<(), _> {
            Err(RpcError::InvalidRequest("bad argument".to_owned()))
        })
        .expect_err("invalid request");
        assert!(matches!(error, RpcError::InvalidRequest(_)));
        assert_eq!(set.preferred(), 2);
        // Wrapping: a discredited last endpoint hands over to the first.
        let _ = run_with_failover(&set, &policy, &sleeper, None, |endpoint| -> Result<(), _> {
            Err(RpcError::JsonRpc {
                endpoint: endpoint.origin().to_owned(),
                code: -32000,
                message: "header not found".to_owned(),
                data: None,
            })
        });
        assert_eq!(set.preferred(), 0);
        set.rotate_preferred();
        assert_eq!(set.preferred(), 1);
    }

    #[test]
    fn seeded_starts_spread_over_the_list_and_are_deterministic() {
        const LEN: usize = 5;
        const SEEDS: u64 = 5_000;
        let mut counts = [0_u64; LEN];
        for seed in 0..SEEDS {
            let index = start_index(seed, LEN);
            assert!(index < LEN);
            assert_eq!(index, start_index(seed, LEN), "deterministic");
            counts[index] += 1;
        }
        // Each index gets about a fifth of the seeds.
        for count in counts {
            assert!(
                (SEEDS / 5 * 8 / 10..=SEEDS / 5 * 12 / 10).contains(&count),
                "{counts:?}"
            );
        }
        assert_eq!(start_index(7, 0), 0);
        assert_eq!(start_index(7, 1), 0);

        // Peer ids spread too, and seeds are stable across runs.
        let mut peers = [0_u64; LEN];
        for peer in 0_u32..1_000 {
            let seed = endpoint_seed(&peer.to_le_bytes());
            assert_eq!(seed, endpoint_seed(&peer.to_le_bytes()));
            peers[start_index(seed, LEN)] += 1;
        }
        assert!(peers.iter().all(|count| *count > 120), "{peers:?}");
        assert_ne!(endpoint_seed(b"peer-a"), endpoint_seed(b"peer-b"));
        assert_eq!(
            endpoint_seed(b""),
            u64::from_le_bytes(
                <Sha256 as sha2::Digest>::digest(ENDPOINT_SEED_DOMAIN)[..8]
                    .try_into()
                    .expect("eight bytes")
            )
        );

        let urls: Vec<String> = (0..LEN)
            .map(|index| format!("https://rpc{index}.example.org"))
            .collect();
        let urls: Vec<&str> = urls.iter().map(String::as_str).collect();
        let plain = EndpointSet::parse(&urls, &[]).expect("list");
        assert_eq!(plain.preferred(), 0, "explicit lists keep their order");
        let seeded = plain.clone().with_seeded_start(42);
        assert_eq!(seeded.preferred(), start_index(42, LEN));
        let mut first = None;
        run_with_failover(
            &seeded,
            &FailoverPolicy::default(),
            &RecordingSleeper::default(),
            None,
            |endpoint| {
                first.get_or_insert_with(|| endpoint.origin().to_owned());
                Ok(())
            },
        )
        .expect("answer");
        assert_eq!(
            first.as_deref(),
            Some(urls[start_index(42, LEN)]),
            "the first request starts at the seeded index"
        );
    }

    #[test]
    fn spent_budgets_stop_failover_before_the_next_attempt() {
        let set = EndpointSet::parse(&["https://a.example.org", "https://b.example.org"], &[])
            .expect("list");
        let sleeper = RecordingSleeper::default();
        let policy = FailoverPolicy::new(
            NonZeroU32::new(3).expect("nonzero"),
            Backoff::new(Duration::from_millis(50), Duration::from_secs(1), 11),
        );
        // A deadline already passed: nothing is attempted.
        let mut attempts = 0;
        let error = run_with_failover(
            &set,
            &policy,
            &sleeper,
            Some(Instant::now()),
            |_| -> Result<(), _> {
                attempts += 1;
                Ok(())
            },
        )
        .expect_err("spent budget");
        assert_eq!(attempts, 0);
        assert!(matches!(&error, RpcError::BudgetExhausted { failures } if failures.is_empty()));
        assert!(!error.is_failover());

        // A deadline that passes during the first attempt stops the request
        // there, with that attempt listed.
        let deadline = Instant::now() + Duration::from_millis(20);
        let mut attempts = 0;
        let error = run_with_failover(&set, &policy, &sleeper, Some(deadline), |endpoint| {
            attempts += 1;
            std::thread::sleep(Duration::from_millis(30));
            Err::<(), _>(timeout(endpoint))
        })
        .expect_err("budget runs out");
        assert_eq!(attempts, 1);
        let RpcError::BudgetExhausted { failures } = &error else {
            panic!("unexpected {error:?}");
        };
        assert_eq!(failures.len(), 1);
        assert!(matches!(error.last_failure(), RpcError::Timeout { .. }));
        assert!(error.to_string().contains("budget"), "{error}");

        // A backoff that would sleep past the deadline is not slept.
        let deadline = Instant::now() + Duration::from_secs(60);
        let long = FailoverPolicy::new(
            NonZeroU32::new(2).expect("nonzero"),
            Backoff::new(Duration::from_secs(120), Duration::from_secs(120), 1),
        );
        let error = run_with_failover(&set, &long, &sleeper, Some(deadline), |endpoint| {
            Err::<(), _>(timeout(endpoint))
        })
        .expect_err("no room for the backoff");
        assert!(matches!(&error, RpcError::BudgetExhausted { failures } if failures.len() == 2));
        assert!(sleeper.0.lock().expect("lock").is_empty(), "nothing slept");
    }

    #[test]
    fn poll_budgets_are_shared_and_end_with_their_guard() {
        let budget = PollBudget::new();
        assert_eq!(budget.deadline(), None);
        let shared = budget.clone();
        {
            let _guard = budget.start(Duration::from_secs(5));
            let deadline = shared.deadline().expect("deadline set through a clone");
            assert!(deadline > Instant::now());
            assert!(deadline <= Instant::now() + Duration::from_secs(5));
        }
        assert_eq!(
            shared.deadline(),
            None,
            "dropping the guard ends the budget"
        );
        let at = Instant::now();
        budget.set_deadline(Some(at));
        assert_eq!(shared.deadline(), Some(at));
        budget.set_deadline(None);

        let now = Instant::now();
        let second = Duration::from_secs(1);
        assert_eq!(attempt_deadline(now, second, None), now + second);
        assert_eq!(
            attempt_deadline(now, second, Some(now + 2 * second)),
            now + second
        );
        assert_eq!(
            attempt_deadline(now, 3 * second, Some(now + second)),
            now + second
        );
        assert!(within_budget(None, None));
        assert!(within_budget(Some(now + second), Some(now)));
        assert!(!within_budget(Some(now), Some(now)));
        assert!(!within_budget(Some(now), None));
    }

    #[test]
    fn line_breaks_are_stripped_once() {
        assert_eq!(strip_line_break(b"key\n"), b"key");
        assert_eq!(strip_line_break(b"key\r\n"), b"key");
        assert_eq!(strip_line_break(b"key\n\n"), b"key\n");
        assert_eq!(strip_line_break(b"key"), b"key");
    }

    #[cfg(unix)]
    #[test]
    fn secret_files_must_be_owner_only_regular_files() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let dir = std::env::temp_dir().join(format!(
            "iroha_sccp_rpc_secret_unit_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_nanos())
        ));
        fs::create_dir_all(&dir).expect("temp dir");
        let file = dir.join("key");
        fs::write(&file, b"s3cret\n").expect("write");
        let source = SecretHeaderSource::new("x-api-key", &file).expect("source");

        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).expect("chmod");
        let value = source.header_value().expect("owner-only file");
        assert_eq!(value.as_bytes(), b"s3cret");
        assert!(value.is_sensitive());
        fs::set_permissions(&file, fs::Permissions::from_mode(0o400)).expect("chmod");
        assert!(source.header_value().is_ok());

        for mode in [0o640, 0o604, 0o700, 0o660, 0o4600, 0o2600, 0o1600] {
            // Some platforms refuse or silently drop special bits for
            // unprivileged users; only modes that actually stick are checked.
            if fs::set_permissions(&file, fs::Permissions::from_mode(mode)).is_err() {
                continue;
            }
            let applied = fs::metadata(&file).expect("metadata").permissions().mode() & 0o7777;
            if applied != mode {
                continue;
            }
            let error = source.header_value().expect_err("refused mode");
            assert!(
                matches!(error.problem, SecretFileProblem::Permissions { .. }),
                "{mode:o}"
            );
            assert!(!error.to_string().contains("s3cret"));
        }
        assert_eq!(OWNER_ONLY_FORBIDDEN_MODE_BITS & 0o600, 0);
        assert_eq!(OWNER_ONLY_FORBIDDEN_MODE_BITS | 0o600, 0o7777);
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).expect("chmod");

        let link = dir.join("link");
        symlink(&file, &link).expect("symlink");
        let linked = SecretHeaderSource::new("x-api-key", &link).expect("source");
        assert_eq!(
            linked.header_value().expect_err("symlink").problem,
            SecretFileProblem::Symlink
        );
        let directory = SecretHeaderSource::new("x-api-key", &dir).expect("source");
        assert!(matches!(
            directory.header_value().expect_err("directory").problem,
            SecretFileProblem::NotRegularFile | SecretFileProblem::Permissions { .. }
        ));
        let missing = SecretHeaderSource::new("x-api-key", dir.join("missing")).expect("source");
        assert!(matches!(
            missing.header_value().expect_err("missing").problem,
            SecretFileProblem::Io {
                kind: io::ErrorKind::NotFound,
                ..
            }
        ));

        fs::write(&file, b"\n").expect("write");
        assert_eq!(
            source.header_value().expect_err("empty").problem,
            SecretFileProblem::Empty
        );
        fs::write(&file, b"bad\x01value").expect("write");
        assert_eq!(
            source.header_value().expect_err("control byte").problem,
            SecretFileProblem::InvalidValue
        );
        fs::write(&file, vec![b'a'; MAX_SECRET_HEADER_VALUE_BYTES + 1]).expect("write");
        assert_eq!(
            source.header_value().expect_err("too large").problem,
            SecretFileProblem::TooLarge
        );
        fs::remove_dir_all(&dir).expect("cleanup");
    }
}
