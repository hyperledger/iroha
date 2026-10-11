//! Blocking HTTP transport for SCCP RPC (spec §4.13.4, §8).
//!
//! [`HttpTransport`] is a `reqwest` blocking client over rustls bound to one
//! [`EndpointSet`]. Every request runs through [`run_with_failover`]. Errors
//! that mean "this endpoint cannot serve this request now" move on to the
//! next endpoint: transport errors, timeouts, HTTP 401, 403, 406, 408, 429
//! and 5xx, JSON-RPC rate-limit and method-unsupported error objects (also
//! inside a batch), a JSON-RPC batch refused as a whole, a success body that
//! is not JSON where JSON was asked for, a body over its route's byte cap or
//! JSON decode limits, and unusable secret headers. Every fully failed round backs
//! off exponentially with seeded jitter. Answers about the request itself (a
//! missing block, bad parameters, a revert, malformed hex) are returned at
//! once, and the next request starts at the next endpoint
//! ([`RpcError::discredits_endpoint`]).
//!
//! Every attempt has one wall-clock deadline for connecting, sending and
//! reading the whole body: [`HttpConfig::request_timeout`] from its start, or
//! the caller's [`PollBudget`] deadline when that comes first. A body that
//! trickles in is cut off at the deadline, not merely between reads.
//!
//! Bodies are bounded by their route's byte cap (see [`crate::limits`]),
//! clipped to [`HttpConfig::max_response_bytes`]. JSON bodies are parsed with
//! `norito::json` inside the attempt, under value, depth and allocation limits
//! derived from that cap, so the typed decoders of the clients run inside the
//! attempt too and their verdicts drive failover and rotation.
//!
//! The client follows no redirects (a redirect could carry an endpoint's secret
//! headers to another host), ignores proxy environment variables (runtime
//! behaviour comes from configuration only), and never puts endpoint paths,
//! queries or secret header values into errors: endpoints are named by their
//! origin only, because many providers embed API keys in the URL path.
//!
//! Nothing here verifies what an endpoint returns. Envelope checks (a JSON-RPC
//! `id` that answers the request, strict hex) only reject malformed replies;
//! evidence is verified by `iroha_sccp`.
//!
//! A blocking client owns an internal runtime thread and waits for it both
//! while it is built and on every request, so async callers (the irohad
//! keeper) build and drive transports on blocking threads (`spawn_blocking`),
//! never on an async worker thread.

use std::{
    error::Error as StdError,
    fmt, io,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use iroha_config::parameters::{actual::SccpLightClientKeeper, defaults};
use norito::json::{Map, Value};
use reqwest::{
    Method,
    blocking::{Client, Response},
    header::{ACCEPT, CONTENT_TYPE, HeaderMap, RETRY_AFTER},
    redirect,
};

use crate::{
    endpoints::{
        Endpoint, EndpointError, EndpointSet, FailoverPolicy, HttpEndpointKind, PollBudget,
        SecretFileError, Sleeper, ThreadSleeper, attempt_deadline, run_with_failover,
    },
    limits::{
        JsonBodyError, JsonLimits, http_response_cap, json_rpc_batch_response_cap,
        json_rpc_response_cap, parse_json,
    },
};

/// Default ceiling on one response body (64 MiB). Each route has a smaller
/// cap of its own ([`crate::limits`]); the ceiling bounds the routes without
/// one, such as a full `eth_getBlockReceipts`.
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;
/// Most calls accepted in one JSON-RPC batch.
pub const MAX_JSON_RPC_BATCH: usize = 100;
/// JSON-RPC error codes that rate-limited endpoints answer with HTTP 200:
/// EIP-1474 `-32005` ("limit exceeded") and the `429` some providers copy
/// from HTTP. They fail over like HTTP 429.
pub const JSON_RPC_RATE_LIMIT_CODES: [i64; 2] = [-32005, 429];
/// JSON-RPC error codes of an endpoint that does not serve the called method:
/// JSON-RPC 2.0 `-32601` ("method not found") and EIP-1474 `-32004` ("method
/// not supported"). Public endpoints differ in the methods they serve
/// (`eth_getProof`, `eth_getBlockReceipts`), so these fail over as well.
pub const JSON_RPC_UNSUPPORTED_CODES: [i64; 2] = [-32601, -32004];
/// HTTP statuses that fail over: 401 and 403 (the endpoint refuses this client,
/// for example a missing, invalid or exhausted API key, or a provider that
/// signals rate limits with 403), 406, 408 and 429. [`is_failover_status`]
/// adds every 5xx.
pub const FAILOVER_CLIENT_STATUSES: [u16; 5] = [401, 403, 406, 408, 429];
/// `application/json`.
pub const MEDIA_TYPE_JSON: &str = "application/json";

/// Longest endpoint-supplied message kept in an error.
const ERROR_MESSAGE_LIMIT: usize = 256;
/// Largest error body read to extract a message.
const ERROR_BODY_LIMIT: usize = 16 * 1024;
/// Bytes read from a body at a time; the attempt deadline is checked between
/// reads.
const READ_CHUNK_BYTES: usize = 64 * 1024;
/// Longest transport error description kept in an error.
const TRANSPORT_DETAIL_LIMIT: usize = 512;
/// `User-Agent` of every request.
const USER_AGENT: &str = concat!("iroha-sccp-rpc/", env!("CARGO_PKG_VERSION"));

/// Transport limits of one [`HttpTransport`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpConfig {
    /// Total wall-clock time of one request attempt (connecting, sending and
    /// reading the whole body) before failing over to the next endpoint.
    pub request_timeout: Duration,
    /// Ceiling on every response body; each route's own cap is clipped to it
    /// ([`crate::limits`]). Larger bodies are refused unread or cut off.
    pub max_response_bytes: usize,
}

impl HttpConfig {
    /// Limits for the in-node keeper: its `request_timeout` and the default
    /// response ceiling.
    pub fn from_keeper_config(keeper: &SccpLightClientKeeper) -> Self {
        Self {
            request_timeout: keeper.request_timeout,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
        }
    }

    /// The same limits with another response bound.
    #[must_use]
    pub fn with_max_response_bytes(mut self, max_response_bytes: usize) -> Self {
        self.max_response_bytes = max_response_bytes;
        self
    }
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_millis(
                defaults::sccp::light_client_keeper::REQUEST_TIMEOUT_MS,
            ),
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
        }
    }
}

/// Why an RPC request failed.
///
/// Endpoints are named by their origin (`scheme://host[:port]`) only; paths,
/// queries and secret header values never appear.
#[derive(Debug)]
pub enum RpcError {
    /// The endpoint list or a secret-header entry is invalid.
    Endpoint(EndpointError),
    /// A caller argument is outside what the request accepts.
    InvalidRequest(String),
    /// The HTTP client could not be built.
    Client(String),
    /// Connecting, TLS, sending or reading failed.
    Transport {
        /// Endpoint origin.
        endpoint: String,
        /// Error chain, without the request URL.
        detail: String,
    },
    /// The attempt passed its deadline ([`HttpConfig::request_timeout`] or
    /// the poll budget).
    Timeout {
        /// Endpoint origin.
        endpoint: String,
    },
    /// The endpoint answered with a non-success HTTP status.
    Status {
        /// Endpoint origin.
        endpoint: String,
        /// HTTP status code.
        status: u16,
        /// `Retry-After` in seconds, when present.
        retry_after: Option<Duration>,
        /// Sanitized message from the error body, when one was found.
        message: Option<String>,
    },
    /// The body exceeds its route's byte cap (at most
    /// [`HttpConfig::max_response_bytes`]); this fails over.
    ResponseTooLarge {
        /// Endpoint origin.
        endpoint: String,
        /// The byte cap.
        limit: usize,
    },
    /// The JSON body exceeds the value, nesting or allocation limits derived
    /// from its route's byte cap ([`crate::limits::JsonLimits`]); this fails
    /// over.
    ResponseTooComplex {
        /// Endpoint origin.
        endpoint: String,
        /// Which limit was hit, without echoing the body.
        detail: String,
    },
    /// A secret header of the endpoint could not be loaded; the request was not
    /// sent.
    SecretHeader {
        /// Endpoint origin.
        endpoint: String,
        /// Why the owner-only file was refused.
        error: SecretFileError,
    },
    /// A success response that should carry JSON does not (for example a CDN
    /// or captcha HTML page, or a truncated body); the endpoint did not serve
    /// the request, so this fails over.
    NotJson {
        /// Endpoint origin.
        endpoint: String,
        /// Media type of the response, when present.
        content_type: Option<String>,
        /// Why the body is not JSON.
        detail: String,
    },
    /// The response is malformed: a broken envelope, a missing field, or
    /// non-canonical hex.
    InvalidResponse {
        /// What is wrong, without echoing large values.
        detail: String,
    },
    /// A JSON-RPC error object.
    JsonRpc {
        /// Endpoint origin.
        endpoint: String,
        /// JSON-RPC error code.
        code: i64,
        /// Sanitized error message.
        message: String,
        /// Optional `data` member.
        data: Option<Value>,
    },
    /// A JSON-RPC batch was answered with one error object for the whole
    /// batch: the endpoint does not serve batches, or not this one. This fails
    /// over; a caller that sees it for every endpoint can send the calls one by
    /// one.
    BatchRejected {
        /// The error object, as an [`RpcError::JsonRpc`].
        error: Box<RpcError>,
    },
    /// Every attempt of every round failed with a failover error.
    Exhausted {
        /// Each failed attempt, in order.
        failures: Vec<AttemptFailure>,
    },
    /// The caller's [`PollBudget`] ran out before an attempt answered.
    BudgetExhausted {
        /// Each failed attempt, in order.
        failures: Vec<AttemptFailure>,
    },
}

impl RpcError {
    /// Whether this error moves the request to the next endpoint because the
    /// endpoint cannot serve it now: transport failures, timeouts, failover
    /// HTTP statuses ([`is_failover_status`]), JSON-RPC rate limits
    /// ([`JSON_RPC_RATE_LIMIT_CODES`]) and unsupported methods
    /// ([`JSON_RPC_UNSUPPORTED_CODES`]), rejected batches, success bodies that
    /// are not JSON, bodies over their byte cap or JSON decode limits, and
    /// unusable secret headers. Every other error is an answer about the
    /// request (for example HTTP 404 for an unknown beacon block, JSON-RPC
    /// `-32000` "header not found", `-32602` bad parameters or a code-3
    /// revert) and is returned at once.
    pub fn is_failover(&self) -> bool {
        match self {
            Self::Transport { .. }
            | Self::Timeout { .. }
            | Self::SecretHeader { .. }
            | Self::NotJson { .. }
            | Self::ResponseTooLarge { .. }
            | Self::ResponseTooComplex { .. }
            | Self::BatchRejected { .. } => true,
            Self::Status { status, .. } => is_failover_status(*status),
            Self::JsonRpc { code, .. } => {
                JSON_RPC_RATE_LIMIT_CODES.contains(code)
                    || JSON_RPC_UNSUPPORTED_CODES.contains(code)
            }
            _ => false,
        }
    }

    /// Whether this answer is a reason to start the next request at another
    /// endpoint: a non-failover HTTP status (404 included), a JSON-RPC error
    /// object or a malformed response. The answer itself is still returned;
    /// only the preferred endpoint moves on. Errors raised before anything was
    /// sent and failover errors discredit nobody.
    pub fn discredits_endpoint(&self) -> bool {
        !self.is_failover()
            && matches!(
                self,
                Self::Status { .. } | Self::JsonRpc { .. } | Self::InvalidResponse { .. }
            )
    }

    /// The `Retry-After` delay the endpoint asked for, if any.
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::Status { retry_after, .. } => *retry_after,
            _ => None,
        }
    }

    /// The last failure of an exhausted request (or of one whose budget ran
    /// out), or `self`.
    pub fn last_failure(&self) -> &Self {
        match self {
            Self::Exhausted { failures } | Self::BudgetExhausted { failures } => {
                failures.last().map_or(self, |last| &last.error)
            }
            _ => self,
        }
    }
}

impl fmt::Display for RpcError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Endpoint(error) => write!(formatter, "invalid SCCP endpoint list: {error}"),
            Self::InvalidRequest(detail) => write!(formatter, "invalid RPC request: {detail}"),
            Self::Client(detail) => write!(formatter, "HTTP client setup failed: {detail}"),
            Self::Transport { endpoint, detail } => {
                write!(formatter, "{endpoint}: transport error: {detail}")
            }
            Self::Timeout { endpoint } => write!(formatter, "{endpoint}: request timed out"),
            Self::Status {
                endpoint,
                status,
                message,
                ..
            } => match message {
                Some(message) => write!(formatter, "{endpoint}: HTTP {status}: {message}"),
                None => write!(formatter, "{endpoint}: HTTP {status}"),
            },
            Self::ResponseTooLarge { endpoint, limit } => {
                write!(formatter, "{endpoint}: response exceeds {limit} bytes")
            }
            Self::ResponseTooComplex { endpoint, detail } => {
                write!(
                    formatter,
                    "{endpoint}: response exceeds the JSON decode limits: {detail}"
                )
            }
            Self::SecretHeader { endpoint, error } => {
                write!(formatter, "{endpoint}: secret header refused: {error}")
            }
            Self::NotJson {
                endpoint,
                content_type,
                detail,
            } => write!(
                formatter,
                "{endpoint}: expected a JSON body, got {} ({detail})",
                content_type.as_deref().unwrap_or("no content type")
            ),
            Self::InvalidResponse { detail } => write!(formatter, "invalid RPC response: {detail}"),
            Self::JsonRpc {
                endpoint,
                code,
                message,
                ..
            } => write!(formatter, "{endpoint}: JSON-RPC error {code}: {message}"),
            Self::BatchRejected { error } => {
                write!(formatter, "JSON-RPC batch rejected: {error}")
            }
            Self::Exhausted { failures } => {
                write!(
                    formatter,
                    "all endpoints failed after {} attempt(s)",
                    failures.len()
                )?;
                for failure in failures {
                    write!(formatter, "; {failure}")?;
                }
                Ok(())
            }
            Self::BudgetExhausted { failures } => {
                write!(
                    formatter,
                    "the poll budget ran out after {} failed attempt(s)",
                    failures.len()
                )?;
                for failure in failures {
                    write!(formatter, "; {failure}")?;
                }
                Ok(())
            }
        }
    }
}

impl StdError for RpcError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Endpoint(error) => Some(error),
            Self::SecretHeader { error, .. } => Some(error),
            Self::BatchRejected { error } => Some(error.as_ref()),
            _ => None,
        }
    }
}

/// Whether an HTTP status fails over: [`FAILOVER_CLIENT_STATUSES`] and every
/// 5xx. Other statuses (400, 404, 405, 413, …) answer the request itself.
pub fn is_failover_status(status: u16) -> bool {
    FAILOVER_CLIENT_STATUSES.contains(&status) || (500..=599).contains(&status)
}

impl From<EndpointError> for RpcError {
    fn from(error: EndpointError) -> Self {
        Self::Endpoint(error)
    }
}

/// One failed attempt of a request that failed over.
#[derive(Debug)]
pub struct AttemptFailure {
    /// Origin of the endpoint that failed.
    pub endpoint: String,
    /// Zero-based failover round.
    pub round: u32,
    /// The failover error.
    pub error: RpcError,
}

impl fmt::Display for AttemptFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "round {}: {}", self.round, self.error)
    }
}

/// A successful (2xx) HTTP response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    /// Origin of the endpoint that answered.
    pub endpoint: String,
    /// HTTP status code (2xx).
    pub status: u16,
    /// `Content-Type` header, when present and ASCII.
    pub content_type: Option<String>,
    /// Response body, at most `cap` bytes.
    pub body: Vec<u8>,
    /// The byte cap the body was read under: its route's cap clipped to
    /// [`HttpConfig::max_response_bytes`]. [`Self::json`] derives its decode
    /// limits from it.
    pub cap: usize,
}

impl HttpResponse {
    /// Parses the body as JSON within [`JsonLimits::for_cap`]`(self.cap)`.
    ///
    /// # Errors
    /// [`RpcError::NotJson`] if the body is not UTF-8 JSON, and
    /// [`RpcError::ResponseTooComplex`] if it exceeds the decode limits (both
    /// failover errors).
    pub fn json(&self) -> Result<Value, RpcError> {
        parse_json(&self.body, JsonLimits::for_cap(self.cap)).map_err(|error| match error {
            JsonBodyError::Malformed(detail) => RpcError::NotJson {
                endpoint: self.endpoint.clone(),
                content_type: self.media_type(),
                detail: sanitize_detail(&format!("the response body is not JSON: {detail}")),
            },
            JsonBodyError::TooComplex(detail) => RpcError::ResponseTooComplex {
                endpoint: self.endpoint.clone(),
                detail: sanitize_detail(&detail),
            },
        })
    }

    /// The media type of `Content-Type`, lowercase and without parameters.
    pub fn media_type(&self) -> Option<String> {
        self.content_type.as_deref().map(media_type_of)
    }
}

/// One call of a JSON-RPC batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonRpcCall {
    /// Method name.
    pub method: String,
    /// Positional parameters.
    pub params: Vec<Value>,
}

impl JsonRpcCall {
    /// A call of `method` with positional `params`.
    pub fn new(method: impl Into<String>, params: Vec<Value>) -> Self {
        Self {
            method: method.into(),
            params,
        }
    }
}

/// What one attempt sends.
struct RequestSpec<'a> {
    method: Method,
    path: &'a str,
    accept: &'a str,
    body: Option<(&'static str, &'a [u8])>,
    /// The route's byte cap; `None` for the transport ceiling.
    cap: Option<usize>,
}

/// Blocking HTTP client bound to one endpoint list with failover.
pub struct HttpTransport {
    client: Client,
    endpoints: EndpointSet,
    config: HttpConfig,
    policy: FailoverPolicy,
    sleeper: Arc<dyn Sleeper>,
    budget: PollBudget,
    next_id: AtomicU64,
}

impl fmt::Debug for HttpTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpTransport")
            .field("endpoints", &self.endpoints)
            .field("config", &self.config)
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl HttpTransport {
    /// A transport over `endpoints` with the given limits and failover policy,
    /// sleeping between failed rounds with [`ThreadSleeper`], without a poll
    /// budget. Requests start at the list's preferred endpoint (the first one,
    /// unless the list was seeded).
    ///
    /// Call it off async worker threads: building the blocking client starts
    /// its internal runtime thread and blocks until that thread runs, which
    /// panics on a Tokio worker thread in debug builds.
    ///
    /// # Errors
    /// [`RpcError::Client`] if the TLS client cannot be built.
    pub fn new(
        endpoints: EndpointSet,
        config: HttpConfig,
        policy: FailoverPolicy,
    ) -> Result<Self, RpcError> {
        if config.request_timeout.is_zero() {
            return Err(RpcError::InvalidRequest(
                "the request timeout must be nonzero".to_owned(),
            ));
        }
        if config.max_response_bytes == 0 {
            return Err(RpcError::InvalidRequest(
                "the response bound must be nonzero".to_owned(),
            ));
        }
        // Each request also carries the remaining time of its attempt
        // deadline, which bounds the whole exchange, body included.
        let client = Client::builder()
            .use_rustls_tls()
            .timeout(config.request_timeout)
            .connect_timeout(config.request_timeout)
            .redirect(redirect::Policy::none())
            .no_proxy()
            .user_agent(USER_AGENT)
            .build()
            .map_err(|error| RpcError::Client(describe_reqwest_error(error)))?;
        Ok(Self {
            client,
            endpoints,
            config,
            policy,
            sleeper: Arc::new(ThreadSleeper),
            budget: PollBudget::new(),
            next_id: AtomicU64::new(1),
        })
    }

    /// The keeper's transport for one chain: its configured (or compiled
    /// default) endpoints and secret headers, its request timeout, and the
    /// default failover policy. `seed` (for example
    /// [`endpoint_seed`](crate::endpoints::endpoint_seed) of the node's peer
    /// id) seeds both the backoff jitter and the starting endpoint, so
    /// validators sharing a compiled list start at different endpoints. Like
    /// [`Self::new`], call it off async worker threads.
    ///
    /// # Errors
    /// [`RpcError::Endpoint`] if the configured list is unusable, or
    /// [`RpcError::Client`] if the TLS client cannot be built.
    pub fn from_keeper_config(
        keeper: &SccpLightClientKeeper,
        kind: HttpEndpointKind,
        seed: u64,
    ) -> Result<Self, RpcError> {
        let endpoints = EndpointSet::from_keeper_config(keeper, kind)?.with_seeded_start(seed);
        Self::new(
            endpoints,
            HttpConfig::from_keeper_config(keeper),
            FailoverPolicy::with_seed(seed),
        )
    }

    /// Replaces the sleeper used between failed rounds (tests record delays
    /// instead of sleeping).
    #[must_use]
    pub fn with_sleeper(mut self, sleeper: Arc<dyn Sleeper>) -> Self {
        self.sleeper = sleeper;
        self
    }

    /// Bounds every request by `budget`: the caller starts a deadline on it
    /// for each poll ([`PollBudget::start`]) and shares one budget across all
    /// of its transports and liteclients.
    #[must_use]
    pub fn with_budget(mut self, budget: PollBudget) -> Self {
        self.budget = budget;
        self
    }

    /// The endpoint list.
    pub fn endpoints(&self) -> &EndpointSet {
        &self.endpoints
    }

    /// The transport limits.
    pub fn config(&self) -> HttpConfig {
        self.config
    }

    /// The failover policy.
    pub fn policy(&self) -> FailoverPolicy {
        self.policy
    }

    /// The poll budget.
    pub fn budget(&self) -> &PollBudget {
        &self.budget
    }

    /// Moves the next request to the endpoint after the one that answered
    /// last, for callers whose verification (`iroha_sccp`, or admission on
    /// Taira) rejected that endpoint's data. The builders' `rotate_endpoints`
    /// calls it, and the keeper does so after a build that failed on the data
    /// it was served.
    // TODO(WP9): the keeper does not observe on-chain rejections of its
    // submitted advances, and the wallet and CLI do not rotate after a local
    // verification failure yet.
    pub fn rotate_preferred(&self) {
        self.endpoints.rotate_preferred();
    }

    /// `GET path` with the given `Accept` header; the body is bounded by the
    /// route's cap ([`crate::limits::http_response_cap`]).
    ///
    /// # Errors
    /// Any [`RpcError`]; failover errors only after every round failed.
    pub fn get(&self, path: &str, accept: &str) -> Result<HttpResponse, RpcError> {
        self.execute_then(
            &RequestSpec {
                method: Method::GET,
                path,
                accept,
                body: None,
                cap: http_response_cap(path),
            },
            Ok,
        )
    }

    /// `POST path` with a body of the given content type; the answer is
    /// bounded by the route's cap ([`crate::limits::http_response_cap`]).
    ///
    /// # Errors
    /// Any [`RpcError`]; failover errors only after every round failed.
    pub fn post(
        &self,
        path: &str,
        content_type: &'static str,
        body: &[u8],
        accept: &str,
    ) -> Result<HttpResponse, RpcError> {
        self.execute_then(
            &RequestSpec {
                method: Method::POST,
                path,
                accept,
                body: Some((content_type, body)),
                cap: http_response_cap(path),
            },
            Ok,
        )
    }

    /// `GET path` and parse the body as JSON inside the attempt, so an
    /// endpoint whose success body is not JSON fails over.
    ///
    /// # Errors
    /// Any [`RpcError`].
    pub fn get_json(&self, path: &str) -> Result<Value, RpcError> {
        self.get_json_then(path, Ok)
    }

    /// `GET path`, then parse the body as JSON and pass it to `decode`, both
    /// inside the attempt: a failover error from either moves on to the next
    /// endpoint, and an error that discredits the endpoint
    /// ([`RpcError::discredits_endpoint`], such as malformed data) moves later
    /// requests on.
    ///
    /// # Errors
    /// Any [`RpcError`], including those of `decode`.
    pub fn get_json_then<T>(
        &self,
        path: &str,
        decode: impl Fn(Value) -> Result<T, RpcError>,
    ) -> Result<T, RpcError> {
        let spec = RequestSpec {
            method: Method::GET,
            path,
            accept: MEDIA_TYPE_JSON,
            body: None,
            cap: http_response_cap(path),
        };
        self.execute_then(&spec, |response| decode(response.json()?))
    }

    /// One JSON-RPC 2.0 call against the endpoint URL itself; returns `result`
    /// (which may be `null`).
    ///
    /// # Errors
    /// [`RpcError::JsonRpc`] for an error object, [`RpcError::InvalidResponse`]
    /// for a malformed envelope or an `id` that does not answer the request,
    /// or any transport error.
    pub fn json_rpc(&self, method: &str, params: Vec<Value>) -> Result<Value, RpcError> {
        self.json_rpc_then(method, params, Ok)
    }

    /// One JSON-RPC 2.0 call whose `result` is passed to `decode` inside the
    /// attempt (see [`Self::get_json_then`]); the answer is bounded by the
    /// method's cap ([`crate::limits::json_rpc_response_cap`]).
    ///
    /// # Errors
    /// As [`Self::json_rpc`], and the errors of `decode`.
    pub fn json_rpc_then<T>(
        &self,
        method: &str,
        params: Vec<Value>,
        decode: impl Fn(Value) -> Result<T, RpcError>,
    ) -> Result<T, RpcError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let body = encode_json(&json_rpc_request(id, method, params))?;
        // Decoding runs inside the attempt, so a body that is not JSON, a
        // rate-limit error object or an unsupported method fails over like
        // HTTP 429.
        self.execute_then(
            &json_rpc_spec(&body, json_rpc_response_cap(method)),
            |response| {
                decode(decode_json_rpc_response(
                    response.json()?,
                    Some(id),
                    &response.endpoint,
                )?)
            },
        )
    }

    /// One JSON-RPC 2.0 batch of 1..=[`MAX_JSON_RPC_BATCH`] calls; returns one
    /// result per call, in call order.
    ///
    /// A batch fails over as a whole when the endpoint refuses it with one
    /// error object ([`RpcError::BatchRejected`]) or rate-limits or does not
    /// serve any of its calls; other per-call errors are returned in place.
    ///
    /// # Errors
    /// [`RpcError::InvalidRequest`] for an empty or oversized batch;
    /// [`RpcError::InvalidResponse`] if the answers do not match the calls one
    /// to one; or any transport error, after every round failed for failover
    /// errors.
    pub fn json_rpc_batch(
        &self,
        calls: Vec<JsonRpcCall>,
    ) -> Result<Vec<Result<Value, RpcError>>, RpcError> {
        self.json_rpc_batch_then(calls, Ok)
    }

    /// [`Self::json_rpc_batch`] whose per-call results are passed to `decode`
    /// inside the attempt (see [`Self::get_json_then`]); the answer is bounded
    /// by the sum of the calls' caps
    /// ([`crate::limits::json_rpc_batch_response_cap`]).
    ///
    /// # Errors
    /// As [`Self::json_rpc_batch`], and the errors of `decode`.
    pub fn json_rpc_batch_then<T>(
        &self,
        calls: Vec<JsonRpcCall>,
        decode: impl Fn(Vec<Result<Value, RpcError>>) -> Result<T, RpcError>,
    ) -> Result<T, RpcError> {
        if calls.is_empty() || calls.len() > MAX_JSON_RPC_BATCH {
            return Err(RpcError::InvalidRequest(format!(
                "a JSON-RPC batch carries 1..={MAX_JSON_RPC_BATCH} calls"
            )));
        }
        let count = calls.len();
        let cap = json_rpc_batch_response_cap(calls.iter().map(|call| call.method.as_str()));
        let first_id = self
            .next_id
            .fetch_add(u64::try_from(count).unwrap_or(u64::MAX), Ordering::Relaxed);
        let requests = calls
            .into_iter()
            .zip(first_id..)
            .map(|(call, id)| json_rpc_request(id, &call.method, call.params))
            .collect();
        let body = encode_json(&Value::Array(requests))?;
        self.execute_then(&json_rpc_spec(&body, cap), |response| {
            let results =
                decode_json_rpc_batch(response.json()?, first_id, count, &response.endpoint)?;
            decode(fail_over_unserved_batch(results)?)
        })
    }

    /// Sends `spec` with failover and decodes each successful response inside
    /// its attempt, so failover errors raised by `decode` move on as well.
    fn execute_then<T>(
        &self,
        spec: &RequestSpec<'_>,
        decode: impl Fn(HttpResponse) -> Result<T, RpcError>,
    ) -> Result<T, RpcError> {
        let cap = spec.cap.map_or(self.config.max_response_bytes, |cap| {
            cap.min(self.config.max_response_bytes)
        });
        run_with_failover(
            &self.endpoints,
            &self.policy,
            self.sleeper.as_ref(),
            self.budget.deadline(),
            |endpoint| decode(self.send_once(endpoint, spec, cap)?),
        )
    }

    /// One attempt against `endpoint`, bounded by one deadline and a body of
    /// at most `cap` bytes.
    fn send_once(
        &self,
        endpoint: &Endpoint,
        spec: &RequestSpec<'_>,
        cap: usize,
    ) -> Result<HttpResponse, RpcError> {
        let origin = endpoint.origin();
        let started = Instant::now();
        let deadline =
            attempt_deadline(started, self.config.request_timeout, self.budget.deadline());
        let timeout = || RpcError::Timeout {
            endpoint: origin.to_owned(),
        };
        let left = deadline.saturating_duration_since(started);
        if left.is_zero() {
            return Err(timeout());
        }
        let url = endpoint.request_url(spec.path)?;
        let mut request = self
            .client
            .request(spec.method.clone(), url)
            .timeout(left)
            .header(ACCEPT, spec.accept);
        if let Some((content_type, body)) = spec.body {
            request = request
                .header(CONTENT_TYPE, content_type)
                .body(body.to_vec());
        }
        for secret in endpoint.secret_headers() {
            // The owner-only file is read now and its buffer zeroized on return;
            // the header value is marked sensitive and never printed.
            let value = secret
                .header_value()
                .map_err(|error| RpcError::SecretHeader {
                    endpoint: origin.to_owned(),
                    error,
                })?;
            request = request.header(secret.name().clone(), value);
        }
        let response = request.send().map_err(|error| send_error(origin, error))?;
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let content_type = header_text(&headers, CONTENT_TYPE.as_str());
        if !(200..300).contains(&status) {
            let body = read_error_body(response, deadline);
            return Err(RpcError::Status {
                endpoint: origin.to_owned(),
                status,
                retry_after: retry_after(&headers),
                message: body.and_then(|body| error_message(content_type.as_deref(), &body)),
            });
        }
        let body = read_body(response, cap, origin, deadline)?;
        Ok(HttpResponse {
            endpoint: origin.to_owned(),
            status,
            content_type,
            body,
            cap,
        })
    }
}

/// A JSON-RPC POST of `body` to the endpoint URL itself, answered within
/// `cap` bytes (`None`: the transport ceiling).
fn json_rpc_spec(body: &[u8], cap: Option<usize>) -> RequestSpec<'_> {
    RequestSpec {
        method: Method::POST,
        path: "",
        accept: MEDIA_TYPE_JSON,
        body: Some((MEDIA_TYPE_JSON, body)),
        cap,
    }
}

/// Turns a batch answer in which the endpoint rate-limited some calls or does
/// not serve their method into a failover error, so the whole batch moves to
/// the next endpoint.
fn fail_over_unserved_batch(
    mut results: Vec<Result<Value, RpcError>>,
) -> Result<Vec<Result<Value, RpcError>>, RpcError> {
    if let Some(index) = results
        .iter()
        .position(|result| result.as_ref().is_err_and(RpcError::is_failover))
        && let Err(error) = results.swap_remove(index)
    {
        return Err(error);
    }
    Ok(results)
}

fn json_rpc_request(id: u64, method: &str, params: Vec<Value>) -> Value {
    let mut map = Map::new();
    map.insert("jsonrpc".to_owned(), Value::from("2.0"));
    map.insert("id".to_owned(), Value::from(id));
    map.insert("method".to_owned(), Value::from(method));
    map.insert("params".to_owned(), Value::Array(params));
    Value::Object(map)
}

/// Serializes a request body.
pub(crate) fn encode_json(value: &Value) -> Result<Vec<u8>, RpcError> {
    norito::json::to_vec(value)
        .map_err(|error| RpcError::InvalidRequest(format!("request is not encodable: {error}")))
}

/// Decodes one JSON-RPC response object answering request `expected_id`
/// (`None` for an object answering a whole batch, which must be an error).
fn decode_json_rpc_response(
    value: Value,
    expected_id: Option<u64>,
    endpoint: &str,
) -> Result<Value, RpcError> {
    let Value::Object(mut map) = value else {
        return Err(invalid_response("a JSON-RPC response is not an object"));
    };
    if map.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(invalid_response(
            "a JSON-RPC response lacks \"jsonrpc\": \"2.0\"",
        ));
    }
    let id = map.remove("id").unwrap_or(Value::Null);
    let error = map.remove("error").filter(|error| !error.is_null());
    let result = map.remove("result");
    match (error, result) {
        (Some(error), None) => {
            // Errors raised before the request was read carry a null id.
            if !id.is_null() && id.as_u64() != expected_id {
                return Err(invalid_response(
                    "a JSON-RPC error answers another request id",
                ));
            }
            Err(decode_json_rpc_error(error, endpoint))
        }
        (None, Some(result)) => {
            if expected_id.is_none() || id.as_u64() != expected_id {
                return Err(invalid_response(
                    "a JSON-RPC result answers another request id",
                ));
            }
            Ok(result)
        }
        _ => Err(invalid_response(
            "a JSON-RPC response must carry exactly one of result and error",
        )),
    }
}

fn decode_json_rpc_error(error: Value, endpoint: &str) -> RpcError {
    let Value::Object(mut map) = error else {
        return invalid_response("a JSON-RPC error is not an object");
    };
    let Some(code) = map.get("code").and_then(Value::as_i64) else {
        return invalid_response("a JSON-RPC error lacks an integer code");
    };
    let Some(message) = map.get("message").and_then(Value::as_str) else {
        return invalid_response("a JSON-RPC error lacks a message");
    };
    RpcError::JsonRpc {
        endpoint: endpoint.to_owned(),
        code,
        message: sanitize_message(message),
        data: map.remove("data").filter(|data| !data.is_null()),
    }
}

fn decode_json_rpc_batch(
    value: Value,
    first_id: u64,
    count: usize,
    endpoint: &str,
) -> Result<Vec<Result<Value, RpcError>>, RpcError> {
    let items = match value {
        Value::Array(items) => items,
        // One error object for the whole batch: the endpoint refused the batch.
        object @ Value::Object(_) => {
            return Err(match decode_json_rpc_response(object, None, endpoint) {
                Err(error @ RpcError::JsonRpc { .. }) => RpcError::BatchRejected {
                    error: Box::new(error),
                },
                Err(error) => error,
                Ok(_) => invalid_response("a JSON-RPC batch was answered with one result"),
            });
        }
        _ => return Err(invalid_response("a JSON-RPC batch answer is not an array")),
    };
    if items.len() != count {
        return Err(invalid_response(format!(
            "a JSON-RPC batch of {count} calls was answered with {} responses",
            items.len()
        )));
    }
    let mut slots: Vec<Option<Result<Value, RpcError>>> = (0..count).map(|_| None).collect();
    for item in items {
        let id = item
            .get("id")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid_response("a JSON-RPC batch response lacks a numeric id"))?;
        let slot = id
            .checked_sub(first_id)
            .and_then(|offset| usize::try_from(offset).ok())
            .and_then(|index| slots.get_mut(index))
            .ok_or_else(|| invalid_response("a JSON-RPC batch response answers an unknown id"))?;
        if slot.is_some() {
            return Err(invalid_response(
                "a JSON-RPC batch answers one request twice",
            ));
        }
        *slot = Some(decode_json_rpc_response(item, Some(id), endpoint));
    }
    slots
        .into_iter()
        .map(|slot| slot.ok_or_else(|| invalid_response("a JSON-RPC batch misses an answer")))
        .collect()
}

fn send_error(endpoint: &str, error: reqwest::Error) -> RpcError {
    if error.is_timeout() {
        RpcError::Timeout {
            endpoint: endpoint.to_owned(),
        }
    } else {
        RpcError::Transport {
            endpoint: endpoint.to_owned(),
            detail: describe_reqwest_error(error),
        }
    }
}

/// The error chain of a `reqwest` error without the request URL.
fn describe_reqwest_error(error: reqwest::Error) -> String {
    let error = error.without_url();
    let mut detail = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        detail.push_str(": ");
        detail.push_str(&cause.to_string());
        source = cause.source();
    }
    sanitize_detail(&detail)
}

fn read_error(endpoint: &str, error: io::Error) -> RpcError {
    if error.kind() == io::ErrorKind::TimedOut {
        return RpcError::Timeout {
            endpoint: endpoint.to_owned(),
        };
    }
    let kind = error.kind();
    error.into_inner().map_or_else(
        || RpcError::Transport {
            endpoint: endpoint.to_owned(),
            detail: format!("reading the body failed: {kind}"),
        },
        |inner| match inner.downcast::<reqwest::Error>() {
            Ok(reqwest_error) => send_error(endpoint, *reqwest_error),
            Err(other) => RpcError::Transport {
                endpoint: endpoint.to_owned(),
                detail: sanitize_detail(&other.to_string()),
            },
        },
    )
}

/// Reads a success body of at most `limit` bytes, all of it before
/// `deadline`.
fn read_body(
    mut response: Response,
    limit: usize,
    endpoint: &str,
    deadline: Instant,
) -> Result<Vec<u8>, RpcError> {
    let limit_u64 = u64::try_from(limit).unwrap_or(u64::MAX);
    if response
        .content_length()
        .is_some_and(|length| length > limit_u64)
    {
        return Err(RpcError::ResponseTooLarge {
            endpoint: endpoint.to_owned(),
            limit,
        });
    }
    // An announced length (within the limit) sizes the buffer once.
    let announced = response
        .content_length()
        .and_then(|length| usize::try_from(length).ok())
        .unwrap_or(0);
    read_until(&mut response, limit, announced, deadline).map_err(|failure| match failure {
        BodyReadFailure::TooLarge => RpcError::ResponseTooLarge {
            endpoint: endpoint.to_owned(),
            limit,
        },
        BodyReadFailure::Deadline => RpcError::Timeout {
            endpoint: endpoint.to_owned(),
        },
        BodyReadFailure::Io(error) => read_error(endpoint, error),
    })
}

/// Reads up to [`ERROR_BODY_LIMIT`] bytes of an error body before
/// `deadline`; `None` if that fails.
fn read_error_body(mut response: Response, deadline: Instant) -> Option<Vec<u8>> {
    // The message is best effort: a longer, late or broken error body has none.
    read_until(&mut response, ERROR_BODY_LIMIT, 0, deadline).ok()
}

/// Why [`read_until`] stopped.
#[derive(Debug)]
enum BodyReadFailure {
    /// More than the limit arrived.
    TooLarge,
    /// The deadline passed before the body ended.
    Deadline,
    /// Reading failed.
    Io(io::Error),
}

/// Reads `reader` to its end in chunks, refusing more than `limit` bytes and
/// checking `deadline` before every read, so a body that trickles in slowly
/// still ends at the deadline. `expected` bytes (at most `limit`) are
/// reserved up front.
fn read_until(
    reader: &mut impl io::Read,
    limit: usize,
    expected: usize,
    deadline: Instant,
) -> Result<Vec<u8>, BodyReadFailure> {
    let mut body = Vec::with_capacity(expected.min(limit));
    let mut chunk = vec![0_u8; READ_CHUNK_BYTES.min(limit.saturating_add(1)).max(1)];
    loop {
        if Instant::now() >= deadline {
            return Err(BodyReadFailure::Deadline);
        }
        match reader.read(&mut chunk) {
            Ok(0) => return Ok(body),
            Ok(read) => {
                if body.len().saturating_add(read) > limit {
                    return Err(BodyReadFailure::TooLarge);
                }
                body.extend_from_slice(&chunk[..read]);
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(BodyReadFailure::Io(error)),
        }
    }
}

fn header_text(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.trim().to_owned())
}

/// `Retry-After` in delta-seconds; HTTP dates are ignored.
fn retry_after(headers: &HeaderMap) -> Option<Duration> {
    let text = header_text(headers, RETRY_AFTER.as_str())?;
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok().map(Duration::from_secs)
}

/// Lowercase media type of a `Content-Type` value, without parameters.
fn media_type_of(content_type: &str) -> String {
    content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
}

/// Extracts a message from an error body: the `message` or `error` member of
/// a JSON object, or a `text/plain` body.
fn error_message(content_type: Option<&str>, body: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(body).ok()?;
    if let Ok(Value::Object(map)) = parse_json(body, JsonLimits::for_cap(ERROR_BODY_LIMIT)) {
        let message = map.get("message").and_then(Value::as_str).or_else(|| {
            map.get("error").and_then(|error| {
                error
                    .as_str()
                    .or_else(|| error.get("message").and_then(Value::as_str))
            })
        })?;
        return Some(sanitize_message(message));
    }
    let is_plain = content_type.is_some_and(|value| media_type_of(value) == "text/plain");
    (is_plain && !text.trim().is_empty()).then(|| sanitize_message(text.trim()))
}

/// Replaces control characters and bounds the length of endpoint-supplied text.
pub(crate) fn sanitize_message(message: &str) -> String {
    bounded_printable(message, ERROR_MESSAGE_LIMIT)
}

fn sanitize_detail(detail: &str) -> String {
    bounded_printable(detail, TRANSPORT_DETAIL_LIMIT)
}

fn bounded_printable(text: &str, limit: usize) -> String {
    let mut out: String = text
        .chars()
        .take(limit)
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect();
    if text.chars().nth(limit).is_some() {
        out.push('…');
    }
    out
}

/// An [`RpcError::InvalidResponse`].
pub(crate) fn invalid_response(detail: impl Into<String>) -> RpcError {
    RpcError::InvalidResponse {
        detail: detail.into(),
    }
}

/// The object `value`, or an error naming `what`.
pub(crate) fn expect_object<'a>(value: &'a Value, what: &str) -> Result<&'a Map, RpcError> {
    value
        .as_object()
        .ok_or_else(|| invalid_response(format!("{what} is not an object")))
}

/// Member `key` of `map`, absent or `null` meaning `None`.
pub(crate) fn optional<'a>(map: &'a Map, key: &str) -> Option<&'a Value> {
    map.get(key).filter(|value| !value.is_null())
}

/// Member `key` of `map`, which must be present and not `null`.
pub(crate) fn required<'a>(map: &'a Map, key: &str, what: &str) -> Result<&'a Value, RpcError> {
    optional(map, key).ok_or_else(|| invalid_response(format!("{what} lacks `{key}`")))
}

/// String member `key` of `map`.
pub(crate) fn required_str<'a>(map: &'a Map, key: &str, what: &str) -> Result<&'a str, RpcError> {
    required(map, key, what)?
        .as_str()
        .ok_or_else(|| invalid_response(format!("{what}.{key} is not a string")))
}

/// Optional string member `key` of `map`.
pub(crate) fn optional_str<'a>(
    map: &'a Map,
    key: &str,
    what: &str,
) -> Result<Option<&'a str>, RpcError> {
    optional(map, key)
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| invalid_response(format!("{what}.{key} is not a string")))
        })
        .transpose()
}

/// Array member `key` of `map`.
pub(crate) fn required_array<'a>(
    map: &'a Map,
    key: &str,
    what: &str,
) -> Result<&'a [Value], RpcError> {
    required(map, key, what)?
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| invalid_response(format!("{what}.{key} is not an array")))
}

/// Optional array member `key` of `map`; absent or `null` is empty.
pub(crate) fn optional_array<'a>(
    map: &'a Map,
    key: &str,
    what: &str,
) -> Result<&'a [Value], RpcError> {
    optional(map, key).map_or(Ok(&[][..]), |value| {
        value
            .as_array()
            .map(Vec::as_slice)
            .ok_or_else(|| invalid_response(format!("{what}.{key} is not an array")))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Value {
        norito::json::parse_value(text).expect("test JSON")
    }

    #[test]
    fn json_rpc_result_must_answer_the_request_id() {
        let ok = parse(r#"{"jsonrpc":"2.0","id":7,"result":"0x1"}"#);
        assert_eq!(
            decode_json_rpc_response(ok.clone(), Some(7), "e").expect("result"),
            Value::from("0x1")
        );
        assert!(matches!(
            decode_json_rpc_response(ok, Some(8), "e"),
            Err(RpcError::InvalidResponse { .. })
        ));
        let null_result = parse(r#"{"jsonrpc":"2.0","id":3,"result":null}"#);
        assert_eq!(
            decode_json_rpc_response(null_result, Some(3), "e").expect("null result"),
            Value::Null
        );
    }

    #[test]
    fn json_rpc_envelope_is_strict() {
        for text in [
            r#"{"id":1,"result":"0x1"}"#,
            r#"{"jsonrpc":"1.0","id":1,"result":"0x1"}"#,
            r#"{"jsonrpc":"2.0","id":1}"#,
            r#"{"jsonrpc":"2.0","id":1,"result":"0x1","error":{"code":1,"message":"x"}}"#,
            r#"{"jsonrpc":"2.0","id":"1","result":"0x1"}"#,
            r"[1]",
        ] {
            assert!(
                matches!(
                    decode_json_rpc_response(parse(text), Some(1), "e"),
                    Err(RpcError::InvalidResponse { .. })
                ),
                "{text} must be rejected"
            );
        }
    }

    #[test]
    fn json_rpc_errors_decode_with_sanitized_messages() {
        let error = decode_json_rpc_response(
            parse(r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"bad\nrequest","data":"0x"}}"#),
            Some(4),
            "https://rpc.example.org",
        )
        .expect_err("error object");
        match error {
            RpcError::JsonRpc {
                endpoint,
                code,
                message,
                data,
            } => {
                assert_eq!(endpoint, "https://rpc.example.org");
                assert_eq!(code, -32600);
                assert_eq!(message, "bad request");
                assert_eq!(data, Some(Value::from("0x")));
            }
            other => panic!("unexpected {other:?}"),
        }
        let malformed = decode_json_rpc_response(
            parse(r#"{"jsonrpc":"2.0","id":4,"error":{"message":"no code"}}"#),
            Some(4),
            "e",
        );
        assert!(matches!(malformed, Err(RpcError::InvalidResponse { .. })));
    }

    #[test]
    fn json_rpc_batches_match_answers_to_calls() {
        let answers = parse(
            r#"[{"jsonrpc":"2.0","id":11,"result":"b"},{"jsonrpc":"2.0","id":10,"result":"a"}]"#,
        );
        let results = decode_json_rpc_batch(answers, 10, 2, "e").expect("batch");
        assert_eq!(results[0].as_ref().expect("a"), &Value::from("a"));
        assert_eq!(results[1].as_ref().expect("b"), &Value::from("b"));

        for (text, count) in [
            (r#"[{"jsonrpc":"2.0","id":10,"result":"a"}]"#, 2),
            (
                r#"[{"jsonrpc":"2.0","id":10,"result":"a"},{"jsonrpc":"2.0","id":10,"result":"a"}]"#,
                2,
            ),
            (r#"[{"jsonrpc":"2.0","id":12,"result":"a"}]"#, 1),
            (r#""nope""#, 1),
        ] {
            assert!(
                decode_json_rpc_batch(parse(text), 10, count, "e").is_err(),
                "{text} must be rejected"
            );
        }
        let whole = decode_json_rpc_batch(
            parse(
                r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"batch unsupported"}}"#,
            ),
            10,
            1,
            "e",
        );
        match whole {
            Err(RpcError::BatchRejected { error }) => {
                assert!(matches!(*error, RpcError::JsonRpc { code: -32600, .. }));
            }
            other => panic!("unexpected {other:?}"),
        }
        let malformed_whole = decode_json_rpc_batch(
            parse(r#"{"jsonrpc":"2.0","id":null,"error":{"message":"no code"}}"#),
            10,
            1,
            "e",
        );
        assert!(matches!(
            malformed_whole,
            Err(RpcError::InvalidResponse { .. })
        ));
    }

    #[test]
    fn failover_classification() {
        let status = |status| RpcError::Status {
            endpoint: "e".to_owned(),
            status,
            retry_after: None,
            message: None,
        };
        for code in [401, 403, 406, 408, 429, 500, 502, 503, 525, 599] {
            assert!(status(code).is_failover(), "{code}");
            assert!(is_failover_status(code), "{code}");
        }
        for code in [300, 400, 404, 405, 413, 418, 600] {
            assert!(!status(code).is_failover(), "{code}");
            assert!(!is_failover_status(code), "{code}");
        }
        assert!(
            RpcError::Timeout {
                endpoint: "e".to_owned()
            }
            .is_failover()
        );
        // Malformed envelopes and hex are answers; a body that is not JSON at
        // all means the endpoint did not serve the request.
        assert!(!invalid_response("x").is_failover());
        assert!(
            RpcError::NotJson {
                endpoint: "e".to_owned(),
                content_type: Some("text/html".to_owned()),
                detail: "x".to_owned(),
            }
            .is_failover()
        );
        let json_rpc = |code| RpcError::JsonRpc {
            endpoint: "e".to_owned(),
            code,
            message: String::new(),
            data: None,
        };
        for code in [-32000, -32602, -32600, -32603, -32700, 3] {
            assert!(!json_rpc(code).is_failover(), "{code}");
        }
        for code in JSON_RPC_RATE_LIMIT_CODES
            .into_iter()
            .chain(JSON_RPC_UNSUPPORTED_CODES)
        {
            assert!(json_rpc(code).is_failover(), "{code}");
        }
        assert!(
            RpcError::BatchRejected {
                error: Box::new(json_rpc(-32600)),
            }
            .is_failover()
        );
        // Bodies over their cap or decode limits fail over.
        assert!(
            RpcError::ResponseTooLarge {
                endpoint: "e".to_owned(),
                limit: 1,
            }
            .is_failover()
        );
        assert!(
            RpcError::ResponseTooComplex {
                endpoint: "e".to_owned(),
                detail: "x".to_owned(),
            }
            .is_failover()
        );
        assert!(
            !RpcError::BudgetExhausted {
                failures: Vec::new()
            }
            .is_failover()
        );
    }

    #[test]
    fn answers_discredit_their_endpoint_and_failovers_do_not() {
        let status = |status| RpcError::Status {
            endpoint: "e".to_owned(),
            status,
            retry_after: None,
            message: None,
        };
        let json_rpc = |code| RpcError::JsonRpc {
            endpoint: "e".to_owned(),
            code,
            message: String::new(),
            data: None,
        };
        for discrediting in [
            status(404),
            status(400),
            json_rpc(-32000),
            json_rpc(3),
            invalid_response("bad hex"),
        ] {
            assert!(discrediting.discredits_endpoint(), "{discrediting:?}");
        }
        for neutral in [
            status(429),
            status(503),
            json_rpc(-32005),
            json_rpc(-32601),
            RpcError::Timeout {
                endpoint: "e".to_owned(),
            },
            RpcError::InvalidRequest("x".to_owned()),
            RpcError::Exhausted {
                failures: Vec::new(),
            },
            RpcError::BudgetExhausted {
                failures: Vec::new(),
            },
        ] {
            assert!(!neutral.discredits_endpoint(), "{neutral:?}");
        }
    }

    #[test]
    fn body_reads_stop_at_the_limit_and_the_deadline() {
        /// Delivers one byte per read, sleeping before each.
        struct Drip(usize);
        impl io::Read for Drip {
            fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                if self.0 == 0 {
                    return Ok(0);
                }
                std::thread::sleep(Duration::from_millis(5));
                self.0 -= 1;
                buffer[0] = b'x';
                Ok(1)
            }
        }
        /// Fails every read.
        struct Broken;
        impl io::Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("reset"))
            }
        }
        let later = Instant::now() + Duration::from_secs(60);
        assert_eq!(
            read_until(&mut &b"abcdef"[..], 6, 6, later).expect("at the limit"),
            b"abcdef"
        );
        assert!(matches!(
            read_until(&mut &b"abcdefg"[..], 6, 0, later),
            Err(BodyReadFailure::TooLarge)
        ));
        assert!(matches!(
            read_until(&mut &b"abc"[..], 6, 0, Instant::now()),
            Err(BodyReadFailure::Deadline)
        ));
        let started = Instant::now();
        let deadline = started + Duration::from_millis(50);
        assert!(matches!(
            read_until(&mut Drip(1_000), 10_000, 1_000_000, deadline),
            Err(BodyReadFailure::Deadline)
        ));
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(matches!(
            read_until(&mut Broken, 10, 0, later),
            Err(BodyReadFailure::Io(_))
        ));
    }

    #[test]
    fn unserved_batch_calls_fail_the_batch_over() {
        let error_code = |code: i64| RpcError::JsonRpc {
            endpoint: "e".to_owned(),
            code,
            message: "m".to_owned(),
            data: None,
        };
        let kept = fail_over_unserved_batch(vec![Ok(Value::from("0x1")), Err(error_code(-32000))])
            .expect("answers only");
        assert_eq!(kept.len(), 2);
        assert!(matches!(
            kept[1],
            Err(RpcError::JsonRpc { code: -32000, .. })
        ));
        for code in [-32005, 429, -32601, -32004] {
            let error = fail_over_unserved_batch(vec![
                Ok(Value::from("0x1")),
                Err(error_code(-32000)),
                Err(error_code(code)),
            ])
            .expect_err("unserved call");
            assert!(
                matches!(error, RpcError::JsonRpc { code: found, .. } if found == code),
                "{code}"
            );
            assert!(error.is_failover());
        }
    }

    #[test]
    fn unserved_errors_display_and_chain_their_cause() {
        let not_json = RpcError::NotJson {
            endpoint: "https://rpc.example.org".to_owned(),
            content_type: Some("text/html".to_owned()),
            detail: "the response body is not JSON".to_owned(),
        };
        assert_eq!(
            not_json.to_string(),
            "https://rpc.example.org: expected a JSON body, got text/html (the response body \
             is not JSON)"
        );
        assert!(not_json.source().is_none());
        let rejected = RpcError::BatchRejected {
            error: Box::new(RpcError::JsonRpc {
                endpoint: "https://rpc.example.org".to_owned(),
                code: -32600,
                message: "batch requests are not supported".to_owned(),
                data: None,
            }),
        };
        assert_eq!(
            rejected.to_string(),
            "JSON-RPC batch rejected: https://rpc.example.org: JSON-RPC error -32600: batch \
             requests are not supported"
        );
        assert!(
            rejected
                .source()
                .is_some_and(|cause| cause.to_string().contains("-32600"))
        );
        assert_eq!(rejected.retry_after(), None);
    }

    #[test]
    fn json_rpc_requests_post_json_to_the_endpoint_url() {
        let spec = json_rpc_spec(b"{}", Some(7));
        assert_eq!(spec.method, Method::POST);
        assert_eq!(spec.path, "");
        assert_eq!(spec.accept, MEDIA_TYPE_JSON);
        assert_eq!(spec.body, Some((MEDIA_TYPE_JSON, &b"{}"[..])));
        assert_eq!(spec.cap, Some(7));
        assert_eq!(json_rpc_spec(b"{}", None).cap, None);
    }

    #[test]
    fn error_bodies_yield_bounded_messages() {
        assert_eq!(
            error_message(
                Some("application/json"),
                br#"{"code":404,"message":"LC bootstrap unavailable"}"#
            ),
            Some("LC bootstrap unavailable".to_owned())
        );
        // The `Error` member of the removed TRON HTTP API is not read.
        assert_eq!(error_message(None, br#"{"Error":"class x : y"}"#), None);
        assert_eq!(
            error_message(None, br#"{"error":{"code":-1,"message":"m"}}"#),
            Some("m".to_owned())
        );
        assert_eq!(
            error_message(Some("text/plain; charset=utf-8"), b"error code: 525\n"),
            Some("error code: 525".to_owned())
        );
        assert_eq!(error_message(Some("text/html"), b"<html></html>"), None);
        let long = "x".repeat(ERROR_MESSAGE_LIMIT + 10);
        let bounded = sanitize_message(&long);
        assert_eq!(bounded.chars().count(), ERROR_MESSAGE_LIMIT + 1);
        assert!(bounded.ends_with('…'));
    }

    #[test]
    fn media_types_and_retry_after() {
        assert_eq!(
            media_type_of("Application/Octet-Stream; charset=binary"),
            "application/octet-stream"
        );
        let mut headers = HeaderMap::new();
        headers.insert(RETRY_AFTER, "3".parse().expect("header"));
        assert_eq!(retry_after(&headers), Some(Duration::from_secs(3)));
        headers.insert(
            RETRY_AFTER,
            "Wed, 21 Oct 2015 07:28:00 GMT".parse().expect("header"),
        );
        assert_eq!(retry_after(&headers), None);
    }

    #[test]
    fn json_rpc_requests_are_well_formed() {
        let body = encode_json(&json_rpc_request(9, "eth_chainId", Vec::new())).expect("encode");
        let value = parse(std::str::from_utf8(&body).expect("utf8"));
        assert_eq!(value.get("jsonrpc").and_then(Value::as_str), Some("2.0"));
        assert_eq!(value.get("id").and_then(Value::as_u64), Some(9));
        assert_eq!(
            value.get("method").and_then(Value::as_str),
            Some("eth_chainId")
        );
        assert_eq!(
            value.get("params").and_then(Value::as_array).map(Vec::len),
            Some(0)
        );
    }

    #[test]
    fn field_helpers_report_missing_and_mistyped_members() {
        let value = parse(r#"{"a":"x","b":null,"c":[1],"d":1}"#);
        let map = expect_object(&value, "obj").expect("object");
        assert_eq!(required_str(map, "a", "obj").expect("a"), "x");
        assert!(required(map, "b", "obj").is_err());
        assert_eq!(optional_str(map, "b", "obj").expect("b"), None);
        assert!(optional_str(map, "d", "obj").is_err());
        assert_eq!(required_array(map, "c", "obj").expect("c").len(), 1);
        assert!(
            optional_array(map, "missing", "obj")
                .expect("empty")
                .is_empty()
        );
        assert!(required_array(map, "a", "obj").is_err());
        assert!(expect_object(&Value::Null, "obj").is_err());
    }

    #[test]
    fn responses_expose_media_type_and_json() {
        let response = HttpResponse {
            endpoint: "https://rpc.example.org".to_owned(),
            status: 200,
            content_type: Some("Application/JSON; charset=utf-8".to_owned()),
            body: br#"{"a":1}"#.to_vec(),
            cap: 1024,
        };
        assert_eq!(response.media_type().as_deref(), Some("application/json"));
        assert_eq!(
            response
                .json()
                .expect("json")
                .get("a")
                .and_then(Value::as_u64),
            Some(1)
        );
        let html = HttpResponse {
            content_type: Some("text/html; charset=utf-8".to_owned()),
            body: b"<html>Just a moment...</html>".to_vec(),
            ..response.clone()
        };
        let error = html.json().expect_err("HTML is not JSON");
        assert!(error.is_failover());
        assert!(
            matches!(
                &error,
                RpcError::NotJson { endpoint, content_type: Some(media), .. }
                    if endpoint == "https://rpc.example.org" && media == "text/html"
            ),
            "{error:?}"
        );
        let binary = HttpResponse {
            content_type: None,
            body: vec![0xff],
            ..response.clone()
        };
        assert_eq!(binary.media_type(), None);
        assert!(matches!(
            binary.json(),
            Err(RpcError::NotJson {
                content_type: None,
                ..
            })
        ));
        let truncated = HttpResponse {
            body: b"{".to_vec(),
            ..response.clone()
        };
        let error = truncated.json().expect_err("truncated");
        assert!(
            matches!(&error, RpcError::NotJson { detail, .. } if detail.starts_with("the response body is not JSON")),
            "{error:?}"
        );
        assert_eq!(
            HttpResponse {
                body: b"[1]".to_vec(),
                ..response.clone()
            }
            .json()
            .expect("JSON"),
            parse("[1]")
        );
        // The decode limits derive from the cap the body was read under: 64
        // bytes allow eight values.
        let crowded = HttpResponse {
            body: b"[0,0,0,0,0,0,0,0,0,0]".to_vec(),
            cap: 64,
            ..response
        };
        let error = crowded.json().expect_err("too many values for the cap");
        assert!(
            matches!(&error, RpcError::ResponseTooComplex { endpoint, .. } if endpoint == "https://rpc.example.org"),
            "{error:?}"
        );
        assert!(error.is_failover());
        assert!(error.to_string().contains("JSON decode limits"));
    }

    #[test]
    fn transports_validate_limits_and_follow_keeper_config() {
        let endpoints =
            EndpointSet::parse(&["https://rpc.example.org/v2/secret-key"], &[]).expect("list");
        let zero_timeout = HttpConfig {
            request_timeout: Duration::ZERO,
            ..HttpConfig::default()
        };
        assert!(matches!(
            HttpTransport::new(endpoints.clone(), zero_timeout, FailoverPolicy::default()),
            Err(RpcError::InvalidRequest(_))
        ));
        let zero_bound = HttpConfig::default().with_max_response_bytes(0);
        assert!(matches!(
            HttpTransport::new(endpoints.clone(), zero_bound, FailoverPolicy::default()),
            Err(RpcError::InvalidRequest(_))
        ));
        let transport =
            HttpTransport::new(endpoints, HttpConfig::default(), FailoverPolicy::default())
                .expect("transport");
        assert!(!format!("{transport:?}").contains("secret-key"));

        let keeper = SccpLightClientKeeper {
            request_timeout: Duration::from_millis(2_500),
            ..SccpLightClientKeeper::default()
        };
        let transport = HttpTransport::from_keeper_config(&keeper, HttpEndpointKind::Bsc, 5)
            .expect("keeper transport");
        assert_eq!(
            transport.endpoints().endpoints(),
            EndpointSet::compiled_defaults(HttpEndpointKind::Bsc).endpoints()
        );
        // The keeper's lists start at the seeded index.
        assert_eq!(
            transport.endpoints().preferred(),
            crate::endpoints::start_index(5, transport.endpoints().len())
        );
        assert_eq!(transport.budget().deadline(), None);
        let budget = PollBudget::new();
        let transport = transport.with_budget(budget.clone());
        let _guard = budget.start(Duration::from_secs(1));
        assert!(transport.budget().deadline().is_some());
        assert_eq!(
            transport.config().request_timeout,
            Duration::from_millis(2_500)
        );
        assert_eq!(transport.policy(), FailoverPolicy::with_seed(5));
    }

    #[test]
    fn errors_name_endpoints_by_origin_and_list_every_failed_attempt() {
        let error = RpcError::Exhausted {
            failures: vec![
                AttemptFailure {
                    endpoint: "https://a.example.org".to_owned(),
                    round: 0,
                    error: RpcError::Timeout {
                        endpoint: "https://a.example.org".to_owned(),
                    },
                },
                AttemptFailure {
                    endpoint: "https://b.example.org".to_owned(),
                    round: 0,
                    error: RpcError::Status {
                        endpoint: "https://b.example.org".to_owned(),
                        status: 429,
                        retry_after: Some(Duration::from_secs(2)),
                        message: Some("slow down".to_owned()),
                    },
                },
            ],
        };
        assert_eq!(
            error.to_string(),
            "all endpoints failed after 2 attempt(s); round 0: https://a.example.org: request \
             timed out; round 0: https://b.example.org: HTTP 429: slow down"
        );
        assert!(!error.is_failover());
        assert_eq!(error.retry_after(), None);
        assert_eq!(
            error.last_failure().retry_after(),
            Some(Duration::from_secs(2))
        );
        let endpoint_error =
            RpcError::from(EndpointSet::parse(&[], &[]).expect_err("an empty list is refused"));
        assert!(endpoint_error.source().is_some());
        assert!(!endpoint_error.is_failover());
    }

    #[test]
    fn http_config_follows_keeper_config() {
        let keeper = SccpLightClientKeeper {
            request_timeout: Duration::from_millis(1_500),
            ..SccpLightClientKeeper::default()
        };
        let config = HttpConfig::from_keeper_config(&keeper);
        assert_eq!(config.request_timeout, Duration::from_millis(1_500));
        assert_eq!(config.max_response_bytes, DEFAULT_MAX_RESPONSE_BYTES);
        assert_eq!(config.with_max_response_bytes(7).max_response_bytes, 7);
        assert_eq!(
            HttpConfig::default().request_timeout,
            Duration::from_secs(10)
        );
    }
}
