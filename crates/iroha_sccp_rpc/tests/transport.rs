//! Transport tests for `iroha_sccp_rpc`.
//!
//! An in-process `TcpListener` mock HTTP server replays responses recorded from
//! public mainnet endpoints (`fixtures/sccp/rpc/transport`) and synthetic
//! failures. Nothing here touches the network.

use std::{
    collections::VecDeque,
    fmt::Write as _,
    fs,
    io::{BufRead as _, BufReader, Read as _, Write as _},
    net::{SocketAddr, TcpListener, TcpStream},
    num::NonZeroU32,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use iroha_config::parameters::actual::SccpSecretHeader;
use iroha_sccp_rpc::{
    beacon::{BeaconBlockId, BeaconClient},
    endpoints::{
        Backoff, EndpointSet, FailoverPolicy, PollBudget, SecretFileProblem, Sleeper, start_index,
    },
    evm::{BlockId, BlockTag, EvmCallRequest, EvmClient, U256},
    http::{HttpConfig, HttpTransport, JsonRpcCall, RpcError},
    limits::{JsonLimits, SMALL_RESPONSE_BYTES},
};
use norito::json::Value;

// ---------------------------------------------------------------------------
// Mock HTTP server
// ---------------------------------------------------------------------------

/// One scripted reply.
#[derive(Clone)]
enum Reply {
    /// Answer with a status, headers and body.
    Respond {
        status: u16,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        /// Rewrite JSON-RPC ids to the ids of the request.
        rewrite_ids: bool,
        /// Omit `Content-Length`; the body ends when the connection closes.
        close_delimited: bool,
    },
    /// Read the request, then stay silent for the duration and close.
    Stall(Duration),
    /// Answer 200 with the headers at once (`Content-Length` included), then
    /// write the body one byte per interval.
    Drip { body: Vec<u8>, interval: Duration },
}

impl Reply {
    fn status(status: u16, content_type: &str, body: &[u8]) -> Self {
        Self::Respond {
            status,
            headers: vec![("Content-Type".to_owned(), content_type.to_owned())],
            body: body.to_vec(),
            rewrite_ids: false,
            close_delimited: false,
        }
    }

    fn json(body: &str) -> Self {
        Self::status(200, "application/json", body.as_bytes())
    }

    /// A JSON-RPC result whose id is rewritten to the request id.
    fn rpc_result(result: &str) -> Self {
        Self::Respond {
            status: 200,
            headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
            body: format!(r#"{{"jsonrpc":"2.0","id":0,"result":{result}}}"#).into_bytes(),
            rewrite_ids: true,
            close_delimited: false,
        }
    }

    /// A JSON-RPC error object whose id (or ids, for a batch answer) is
    /// rewritten to the request id.
    fn rpc_errors(body: &str) -> Self {
        Self::Respond {
            status: 200,
            headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
            body: body.as_bytes().to_vec(),
            rewrite_ids: true,
            close_delimited: false,
        }
    }

    fn with_header(mut self, name: &str, value: &str) -> Self {
        if let Self::Respond { headers, .. } = &mut self {
            headers.push((name.to_owned(), value.to_owned()));
        }
        self
    }

    fn close_delimited(mut self) -> Self {
        if let Self::Respond {
            close_delimited, ..
        } = &mut self
        {
            *close_delimited = true;
        }
        self
    }
}

/// One request the server received.
#[derive(Debug, Clone)]
struct Recorded {
    /// Position among every request received by any mock server of the test
    /// binary; requests of one test are sequential, so this orders them.
    sequence: u64,
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

/// Next [`Recorded::sequence`].
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

impl Recorded {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    fn json(&self) -> Value {
        norito::json::parse_value(std::str::from_utf8(&self.body).expect("utf8 request"))
            .expect("JSON request")
    }
}

#[derive(Default)]
struct State {
    replies: VecDeque<Reply>,
    requests: Vec<Recorded>,
}

struct MockServer {
    address: SocketAddr,
    state: Arc<Mutex<State>>,
    stop: Arc<AtomicBool>,
    accept: Option<JoinHandle<()>>,
}

impl MockServer {
    fn start(replies: Vec<Reply>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock server");
        let address = listener.local_addr().expect("mock address");
        let state = Arc::new(Mutex::new(State {
            replies: replies.into(),
            requests: Vec::new(),
        }));
        let stop = Arc::new(AtomicBool::new(false));
        let accept = {
            let state = Arc::clone(&state);
            let stop = Arc::clone(&stop);
            thread::spawn(move || {
                for stream in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(stream) = stream else { continue };
                    let state = Arc::clone(&state);
                    thread::spawn(move || serve(stream, &state));
                }
            })
        };
        Self {
            address,
            state,
            stop,
            accept: Some(accept),
        }
    }

    fn url(&self) -> String {
        format!("http://{}", self.address)
    }

    fn requests(&self) -> Vec<Recorded> {
        self.state.lock().expect("mock state").requests.clone()
    }

    fn request_count(&self) -> usize {
        self.state.lock().expect("mock state").requests.len()
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.address);
        if let Some(accept) = self.accept.take() {
            let _ = accept.join();
        }
    }
}

fn read_request(stream: &TcpStream) -> Option<Recorded> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_owned();
    let target = parts.next()?.to_owned();
    let mut headers = Vec::new();
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).ok()?;
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        let (name, value) = header.split_once(':')?;
        headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
    }
    let length = headers
        .iter()
        .find(|(name, _)| name == "content-length")
        .and_then(|(_, value)| value.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = vec![0_u8; length];
    reader.read_exact(&mut body).ok()?;
    Some(Recorded {
        sequence: SEQUENCE.fetch_add(1, Ordering::SeqCst),
        method,
        target,
        headers,
        body,
    })
}

fn serve(mut stream: TcpStream, state: &Mutex<State>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let Some(request) = read_request(&stream) else {
        return;
    };
    let reply = {
        let mut state = state.lock().expect("mock state");
        state.requests.push(request.clone());
        state
            .replies
            .pop_front()
            .unwrap_or_else(|| Reply::status(500, "text/plain", b"unscripted request"))
    };
    match reply {
        Reply::Stall(duration) => thread::sleep(duration),
        Reply::Drip { body, interval } => {
            let head = format!(
                "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                body.len()
            );
            if stream.write_all(head.as_bytes()).is_err() {
                return;
            }
            for byte in body {
                if stream.write_all(&[byte]).is_err() || stream.flush().is_err() {
                    return;
                }
                thread::sleep(interval);
            }
        }
        Reply::Respond {
            status,
            headers,
            body,
            rewrite_ids,
            close_delimited,
        } => {
            let body = if rewrite_ids {
                rewrite_json_rpc_ids(&request.body, &body)
            } else {
                body
            };
            let mut head = format!(
                "HTTP/1.1 {status} {}\r\nConnection: close\r\n",
                reason(status)
            );
            if !close_delimited {
                write!(head, "Content-Length: {}\r\n", body.len()).expect("format head");
            }
            for (name, value) in headers {
                write!(head, "{name}: {value}\r\n").expect("format head");
            }
            head.push_str("\r\n");
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(&body);
            let _ = stream.flush();
        }
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        429 => "Too Many Requests",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

/// Sets the `id` of each JSON-RPC answer to the id of the matching request.
fn rewrite_json_rpc_ids(request: &[u8], response: &[u8]) -> Vec<u8> {
    let request = norito::json::parse_value(std::str::from_utf8(request).expect("utf8"))
        .expect("JSON-RPC request");
    let mut response = norito::json::parse_value(std::str::from_utf8(response).expect("utf8"))
        .expect("JSON-RPC response");
    match (&request, &mut response) {
        (Value::Object(call), Value::Object(answer)) => {
            answer.insert(
                "id".to_owned(),
                call.get("id").cloned().expect("request id"),
            );
        }
        (Value::Array(calls), Value::Array(answers)) => {
            for (call, answer) in calls.iter().zip(answers.iter_mut()) {
                if let Value::Object(answer) = answer {
                    answer.insert(
                        "id".to_owned(),
                        call.get("id").cloned().expect("request id"),
                    );
                }
            }
        }
        _ => panic!("mismatched JSON-RPC shapes"),
    }
    norito::json::to_vec(&response).expect("encode response")
}

// ---------------------------------------------------------------------------
// Recorded fixtures
// ---------------------------------------------------------------------------

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/sccp/rpc/transport")
}

fn index() -> &'static Value {
    static INDEX: OnceLock<Value> = OnceLock::new();
    INDEX.get_or_init(|| {
        let text = fs::read_to_string(fixtures_dir().join("recorded.json")).expect("index");
        norito::json::parse_value(&text).expect("index JSON")
    })
}

fn exchange(name: &str) -> &'static Value {
    index()
        .get("exchanges")
        .and_then(|exchanges| exchanges.get(name))
        .unwrap_or_else(|| panic!("no recorded exchange `{name}`"))
}

fn fixture_bytes(name: &str) -> Vec<u8> {
    let file = exchange(name)
        .get("body")
        .and_then(Value::as_str)
        .expect("body file");
    fs::read(fixtures_dir().join(file)).expect("fixture body")
}

fn fixture_json(name: &str) -> Value {
    norito::json::parse_value(std::str::from_utf8(&fixture_bytes(name)).expect("utf8"))
        .expect("fixture JSON")
}

/// The recorded reply of `name`, with JSON-RPC ids rewritten for replay.
fn recorded(name: &str) -> Reply {
    let entry = exchange(name);
    let status = entry
        .get("status")
        .and_then(Value::as_u64)
        .and_then(|status| u16::try_from(status).ok())
        .expect("status");
    let content_type = entry
        .get("content_type")
        .and_then(Value::as_str)
        .expect("content type");
    let headers = vec![("Content-Type".to_owned(), content_type.to_owned())];
    let request = entry.get("request").expect("request");
    let rewrite_ids = request.get("json_rpc").is_some() || request.get("json_rpc_batch").is_some();
    Reply::Respond {
        status,
        headers,
        body: fixture_bytes(name),
        rewrite_ids,
        close_delimited: false,
    }
}

// ---------------------------------------------------------------------------
// Transports
// ---------------------------------------------------------------------------

#[derive(Default)]
struct RecordingSleeper(Mutex<Vec<Duration>>);

impl RecordingSleeper {
    fn delays(&self) -> Vec<Duration> {
        self.0.lock().expect("sleeper").clone()
    }
}

impl Sleeper for RecordingSleeper {
    fn sleep(&self, duration: Duration) {
        self.0.lock().expect("sleeper").push(duration);
    }
}

fn policy(rounds: u32) -> FailoverPolicy {
    FailoverPolicy::new(
        NonZeroU32::new(rounds).expect("rounds"),
        Backoff::new(Duration::from_millis(100), Duration::from_secs(2), 0x5ccf),
    )
}

fn config(timeout: Duration) -> HttpConfig {
    HttpConfig {
        request_timeout: timeout,
        ..HttpConfig::default()
    }
}

fn transport_with(
    set: EndpointSet,
    config: HttpConfig,
    rounds: u32,
) -> (HttpTransport, Arc<RecordingSleeper>) {
    let sleeper = Arc::new(RecordingSleeper::default());
    let transport = HttpTransport::new(set, config, policy(rounds))
        .expect("transport")
        .with_sleeper(sleeper.clone());
    (transport, sleeper)
}

fn transport(servers: &[&MockServer], rounds: u32) -> (HttpTransport, Arc<RecordingSleeper>) {
    let urls: Vec<String> = servers.iter().map(|server| server.url()).collect();
    let urls: Vec<&str> = urls.iter().map(String::as_str).collect();
    let set = EndpointSet::parse(&urls, &[]).expect("endpoints");
    transport_with(set, config(Duration::from_secs(5)), rounds)
}

fn evm(server: &MockServer) -> EvmClient {
    EvmClient::new(transport(&[server], 1).0)
}

#[test]
fn destination_log_discovery_bounds_queries_and_rejects_foreign_or_unpositioned_answers() {
    let log = norito::json!({
        "address":(format!("0x{}", "11".repeat(20))),
        "topics":[(format!("0x{}", "22".repeat(32)))],
        "data":"0x1234", "blockNumber":"0x10", "logIndex":"0x1",
        "blockHash":(format!("0x{}", "33".repeat(32))), "removed":false,
    });
    let body = norito::json::to_json(&vec![log.clone()]).unwrap();
    let server = MockServer::start(vec![Reply::rpc_result(&body)]);
    let client = evm(&server);
    assert!(
        client
            .destination_logs([0x11; 20], 1, 2_049, &[[0x22; 32]])
            .is_err()
    );
    assert!(
        client
            .destination_logs([0x11; 20], 2, 1, &[[0x22; 32]])
            .is_err()
    );
    assert!(client.destination_logs([0x11; 20], 1, 16, &[]).is_err());
    assert_eq!(server.request_count(), 0);
    let result = client
        .destination_logs([0x11; 20], 1, 16, &[[0x22; 32]])
        .unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].block_number, Some(16));
    for (field, value) in [
        ("address", Value::from(format!("0x{}", "44".repeat(20)))),
        ("blockNumber", Value::from("0x11")),
        ("logIndex", Value::Null),
        ("blockHash", Value::Null),
        (
            "topics",
            Value::Array(vec![Value::from(format!("0x{}", "55".repeat(32)))]),
        ),
    ] {
        let mut bad = log.clone();
        bad.as_object_mut().unwrap().insert(field.into(), value);
        let body = norito::json::to_json(&vec![bad]).unwrap();
        let server = MockServer::start(vec![Reply::rpc_result(&body)]);
        assert!(
            evm(&server)
                .destination_logs([0x11; 20], 1, 16, &[[0x22; 32]])
                .is_err(),
            "{field}"
        );
    }
}

fn beacon(server: &MockServer) -> BeaconClient {
    BeaconClient::new(transport(&[server], 1).0)
}

fn hex32(text: &str) -> [u8; 32] {
    let mut out = [0_u8; 32];
    hex::decode_to_slice(text.trim_start_matches("0x"), &mut out).expect("32-byte hex");
    out
}

fn hex20(text: &str) -> [u8; 20] {
    let mut out = [0_u8; 20];
    hex::decode_to_slice(text.trim_start_matches("0x"), &mut out).expect("20-byte hex");
    out
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos());
        let path = std::env::temp_dir().join(format!(
            "iroha_sccp_rpc_{label}_{}_{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("temp dir");
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

// ---------------------------------------------------------------------------
// Failover, backoff and limits
// ---------------------------------------------------------------------------

#[test]
fn failover_skips_5xx_and_429_in_round_robin_order_and_sticks() {
    let a = MockServer::start(vec![Reply::status(525, "text/plain", b"error code: 525")]);
    let b = MockServer::start(vec![
        Reply::status(429, "text/plain", b"slow down").with_header("Retry-After", "1"),
    ]);
    let c = MockServer::start(vec![
        recorded("evm/eth_chainId"),
        recorded("evm/eth_blockNumber"),
    ]);
    let (transport, sleeper) = transport(&[&a, &b, &c], 3);
    let client = EvmClient::new(transport);

    assert_eq!(client.chain_id().expect("third endpoint answers"), 1);
    assert_eq!(
        (a.request_count(), b.request_count(), c.request_count()),
        (1, 1, 1)
    );
    let order = [&a, &b, &c].map(|server| server.requests()[0].sequence);
    assert!(
        order[0] < order[1] && order[1] < order[2],
        "tried in list order"
    );
    assert!(sleeper.delays().is_empty(), "no backoff inside a round");
    assert_eq!(client.transport().endpoints().preferred(), 2);

    assert_eq!(client.block_number().expect("sticky endpoint"), 0x18d_af53);
    assert_eq!(
        (a.request_count(), b.request_count(), c.request_count()),
        (1, 1, 2)
    );
}

#[test]
fn failed_rounds_back_off_with_seeded_jitter_until_exhausted() {
    let server = MockServer::start(vec![
        Reply::status(503, "text/plain", b"busy"),
        Reply::status(502, "text/plain", b"bad gateway"),
        Reply::status(500, "application/json", br#"{"message":"internal"}"#),
    ]);
    let (transport, sleeper) = transport(&[&server], 3);
    let error = EvmClient::new(transport)
        .chain_id()
        .expect_err("all rounds fail");
    let RpcError::Exhausted { failures } = &error else {
        panic!("unexpected {error:?}");
    };
    assert_eq!(failures.len(), 3);
    assert_eq!(
        failures
            .iter()
            .map(|failure| failure.round)
            .collect::<Vec<_>>(),
        vec![0, 1, 2]
    );
    assert!(matches!(
        error.last_failure(),
        RpcError::Status { status: 500, message: Some(message), .. } if message == "internal"
    ));
    let policy = policy(3);
    assert_eq!(
        sleeper.delays(),
        vec![policy.round_delay(0, None), policy.round_delay(1, None)]
    );
    assert_eq!(
        sleeper.delays(),
        vec![policy.backoff.delay(0), policy.backoff.delay(1)]
    );
    assert_eq!(server.request_count(), 3);
    assert!(
        error
            .to_string()
            .contains("all endpoints failed after 3 attempt(s)")
    );
}

#[test]
fn retry_after_of_429_extends_the_backoff() {
    let server = MockServer::start(vec![
        Reply::status(429, "text/plain", b"rate limited").with_header("Retry-After", "1"),
        recorded("evm/eth_chainId"),
    ]);
    let (transport, sleeper) = transport(&[&server], 2);
    assert_eq!(
        EvmClient::new(transport).chain_id().expect("second round"),
        1
    );
    let delays = sleeper.delays();
    assert_eq!(delays, vec![Duration::from_secs(1)]);
    assert!(delays[0] >= policy(2).backoff.delay(0));
}

#[test]
fn timeouts_and_refused_connections_fail_over() {
    let stalled = MockServer::start(vec![Reply::Stall(Duration::from_millis(1_500))]);
    let refused = {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        format!("http://{}", listener.local_addr().expect("address"))
    };
    let answering = MockServer::start(vec![recorded("evm/eth_chainId")]);
    let set =
        EndpointSet::parse(&[&stalled.url(), &refused, &answering.url()], &[]).expect("endpoints");
    let (transport, _) = transport_with(set, config(Duration::from_millis(300)), 1);
    let client = EvmClient::new(transport);
    assert_eq!(client.chain_id().expect("third endpoint answers"), 1);
    assert_eq!(stalled.request_count(), 1);
    assert_eq!(answering.request_count(), 1);

    let lonely = MockServer::start(vec![Reply::Stall(Duration::from_millis(1_500))]);
    let set = EndpointSet::parse(&[&lonely.url()], &[]).expect("endpoints");
    let (transport, _) = transport_with(set, config(Duration::from_millis(300)), 1);
    let error = EvmClient::new(transport).chain_id().expect_err("timeout");
    assert!(
        matches!(error.last_failure(), RpcError::Timeout { .. }),
        "{error:?}"
    );
}

#[test]
fn client_errors_and_json_rpc_errors_are_answers_not_failover() {
    let a = MockServer::start(vec![Reply::status(
        405,
        "text/html",
        b"<html><body><h1>405 Method Not Allowed</h1></body></html>",
    )]);
    let b = MockServer::start(Vec::new());
    let (transport, _) = transport(&[&a, &b], 3);
    let error = transport
        .post(
            "/eth/v1/beacon/headers/finalized",
            "application/json",
            br#"{"id":"finalized"}"#,
            "application/json",
        )
        .expect_err("405");
    assert!(
        matches!(
            error,
            RpcError::Status {
                status: 405,
                message: None,
                ..
            }
        ),
        "{error:?}"
    );
    assert_eq!(b.request_count(), 0);

    let a = MockServer::start(vec![recorded("evm/eth_getProof_window_error")]);
    let b = MockServer::start(Vec::new());
    let client = EvmClient::new(transport_pair(&a, &b));
    let error = client
        .proof(
            &hex20("0x0000F90827F1C53a10cb7A02335B175320002935"),
            &[hex32(&format!("{:0>64}", "1b75"))],
            BlockId::from(0x18d_af08),
        )
        .expect_err("proof window error");
    match error {
        RpcError::JsonRpc { code, message, .. } => {
            assert_eq!(code, -32602);
            assert_eq!(
                message,
                "distance to target block exceeds maximum proof window"
            );
        }
        other => panic!("unexpected {other:?}"),
    }
    assert_eq!(b.request_count(), 0);
}

fn transport_pair(a: &MockServer, b: &MockServer) -> HttpTransport {
    transport(&[a, b], 3).0
}

#[test]
fn responses_above_the_size_limit_fail_over() {
    let big = vec![b'x'; 2_000];
    let server = MockServer::start(vec![
        Reply::status(200, "application/octet-stream", &big),
        Reply::status(200, "application/octet-stream", &big).close_delimited(),
        Reply::status(200, "application/octet-stream", &big[..1_000]).close_delimited(),
    ]);
    let set = EndpointSet::parse(&[&server.url()], &[]).expect("endpoints");
    let limits = config(Duration::from_secs(5)).with_max_response_bytes(1_000);
    let (transport, _) = transport_with(set, limits, 1);
    // Announced (`Content-Length`) or counted while reading, an oversized
    // body is a failover error; the only endpoint exhausts the request.
    for _ in 0..2 {
        let error = transport
            .get("/blob", "application/octet-stream")
            .expect_err("too large");
        assert!(
            matches!(
                error.last_failure(),
                RpcError::ResponseTooLarge { limit: 1_000, .. }
            ),
            "{error:?}"
        );
        assert!(matches!(error, RpcError::Exhausted { .. }), "{error:?}");
    }
    let response = transport
        .get("/blob", "application/octet-stream")
        .expect("at the limit");
    assert_eq!(response.body.len(), 1_000);
    assert_eq!(response.cap, 1_000);
    assert_eq!(server.request_count(), 3);

    // An oversized answer moves the request to the next endpoint. The cap of
    // `eth_chainId` is its route's, far below the transport ceiling.
    let padded = format!(
        r#"{{"jsonrpc":"2.0","id":0,"result":"0x1","pad":"{}"}}"#,
        "x".repeat(SMALL_RESPONSE_BYTES)
    );
    let oversized = MockServer::start(vec![Reply::rpc_errors(&padded)]);
    let answering = MockServer::start(vec![recorded("evm/eth_chainId")]);
    let client = EvmClient::new(transport_pair(&oversized, &answering));
    assert_eq!(client.chain_id().expect("second endpoint"), 1);
    assert_eq!(
        (oversized.request_count(), answering.request_count()),
        (1, 1)
    );
}

// ---------------------------------------------------------------------------
// Decode limits, deadlines, budgets, rotation and seeding
// ---------------------------------------------------------------------------

#[test]
fn element_heavy_bodies_fail_over_instead_of_allocating() {
    // Within the 64 KiB byte cap of `eth_chainId`, but at 2 bytes per value
    // against a floor of 8: refused by the allocation-free preflight.
    let zeros = format!("[{}0]", "0,".repeat(20_000));
    assert!(zeros.len() < SMALL_RESPONSE_BYTES);
    // Within the value floor (17 bytes per object), but every object
    // allocates a B-tree leaf of several hundred bytes: refused by the decode
    // budget before the tree outgrows 6 × 64 KiB.
    let objects = format!(
        "[{}{{\"aaaaaaaaaa\":0}}]",
        "{\"aaaaaaaaaa\":0},".repeat(3_000)
    );
    assert!(objects.len() < SMALL_RESPONSE_BYTES);
    let limits = JsonLimits::for_cap(SMALL_RESPONSE_BYTES);
    assert!(3_000 * 2 + 3 < limits.values);
    assert!(3_000 * 600 > limits.allocated_bytes);

    for heavy_result in [zeros, objects] {
        let heavy = MockServer::start(vec![Reply::rpc_result(&heavy_result)]);
        let answering = MockServer::start(vec![recorded("evm/eth_chainId")]);
        let (single, sleeper) = transport(&[&heavy, &answering], 2);
        let client = EvmClient::new(single);
        assert_eq!(client.chain_id().expect("second endpoint"), 1);
        assert_eq!((heavy.request_count(), answering.request_count()), (1, 1));
        assert!(sleeper.delays().is_empty(), "no backoff inside a round");
        assert_eq!(client.transport().endpoints().preferred(), 1);

        let lonely = MockServer::start(vec![Reply::rpc_result(&heavy_result)]);
        let error = evm(&lonely).chain_id().expect_err("only a heavy body");
        assert!(
            matches!(error.last_failure(), RpcError::ResponseTooComplex { .. }),
            "{error:?}"
        );
        assert!(error.last_failure().is_failover());
    }
}

#[test]
fn slow_drip_bodies_hit_the_total_deadline() {
    // Every read returns within 50 ms, but the whole body would take 10 s:
    // the attempt ends at its 500 ms total deadline and fails over.
    let drip = || Reply::Drip {
        body: format!(
            r#"{{"jsonrpc":"2.0","id":1,"result":"0x1","pad":"{}"}}"#,
            "x".repeat(150)
        )
        .into_bytes(),
        interval: Duration::from_millis(50),
    };
    let dripping = MockServer::start(vec![drip()]);
    let answering = MockServer::start(vec![recorded("evm/eth_chainId")]);
    let set = EndpointSet::parse(&[&dripping.url(), &answering.url()], &[]).expect("endpoints");
    let (transport, _) = transport_with(set, config(Duration::from_millis(500)), 1);
    let started = Instant::now();
    assert_eq!(
        EvmClient::new(transport)
            .chain_id()
            .expect("second endpoint"),
        1
    );
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(answering.request_count(), 1);

    let lonely = MockServer::start(vec![drip()]);
    let set = EndpointSet::parse(&[&lonely.url()], &[]).expect("endpoints");
    let (transport, _) = transport_with(set, config(Duration::from_millis(500)), 1);
    let started = Instant::now();
    let error = EvmClient::new(transport)
        .chain_id()
        .expect_err("dripping body");
    assert!(
        matches!(error.last_failure(), RpcError::Timeout { .. }),
        "{error:?}"
    );
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[test]
fn poll_budgets_bound_the_whole_request() {
    let stalled = MockServer::start(vec![Reply::Stall(Duration::from_secs(3))]);
    let answering = MockServer::start(vec![recorded("evm/eth_chainId")]);
    let set = EndpointSet::parse(&[&stalled.url(), &answering.url()], &[]).expect("endpoints");
    let budget = PollBudget::new();
    let (transport, sleeper) = transport_with(set, config(Duration::from_secs(5)), 3);
    let client = EvmClient::new(transport.with_budget(budget.clone()));
    {
        let _poll = budget.start(Duration::from_millis(300));
        let started = Instant::now();
        let error = client.chain_id().expect_err("budget runs out");
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
        let RpcError::BudgetExhausted { failures } = &error else {
            panic!("unexpected {error:?}");
        };
        assert_eq!(failures.len(), 1);
        assert!(matches!(failures[0].error, RpcError::Timeout { .. }));
        assert!(!error.is_failover());
        assert_eq!(answering.request_count(), 0, "no attempt past the budget");
        assert!(sleeper.delays().is_empty());
    }
    // The next poll has no deadline until it starts one.
    assert_eq!(client.transport().budget().deadline(), None);
    assert_eq!(client.chain_id().expect("unscripted 500 fails over"), 1);
    assert_eq!(answering.request_count(), 1);
}

#[test]
fn not_found_and_bad_data_rotate_the_next_request() {
    // A 404 is an answer about the request: returned at once, and the next
    // request starts at the next endpoint.
    let a = MockServer::start(vec![Reply::status(
        404,
        "application/json",
        br#"{"code":404,"message":"No block found for id '42'"}"#,
    )]);
    let b = MockServer::start(vec![recorded("beacon/headers_finalized")]);
    let client = BeaconClient::new(transport_pair(&a, &b));
    let error = client
        .header(&BeaconBlockId::slot(42))
        .expect_err("unknown slot");
    assert!(
        matches!(error, RpcError::Status { status: 404, .. }),
        "{error:?}"
    );
    assert_eq!(b.request_count(), 0);
    assert_eq!(client.transport().endpoints().preferred(), 1);
    assert_eq!(
        client.finalized_header().expect("next endpoint").slot,
        15_301_120
    );
    assert_eq!((a.request_count(), b.request_count()), (1, 1));

    // Malformed data decoded inside the attempt discredits its endpoint too.
    let a = MockServer::start(vec![
        Reply::rpc_result(r#""0x01""#),
        recorded("evm/eth_chainId"),
    ]);
    let b = MockServer::start(vec![recorded("evm/eth_chainId")]);
    let client = EvmClient::new(transport_pair(&a, &b));
    let error = client.chain_id().expect_err("non-canonical quantity");
    assert!(
        matches!(error, RpcError::InvalidResponse { .. }),
        "{error:?}"
    );
    assert_eq!(b.request_count(), 0);
    assert_eq!(client.chain_id().expect("next endpoint"), 1);
    assert_eq!((a.request_count(), b.request_count()), (1, 1));

    // Callers whose verification rejects data rotate explicitly.
    assert_eq!(client.transport().endpoints().preferred(), 1);
    client.transport().rotate_preferred();
    assert_eq!(client.chain_id().expect("rotated back"), 1);
    assert_eq!((a.request_count(), b.request_count()), (2, 1));
}

#[test]
fn seeded_lists_spread_the_first_request() {
    let servers: Vec<MockServer> = (0..4)
        .map(|_| MockServer::start(vec![recorded("evm/eth_chainId")]))
        .collect();
    let urls: Vec<String> = servers.iter().map(MockServer::url).collect();
    let urls: Vec<&str> = urls.iter().map(String::as_str).collect();
    // One seed per start index (the seeds spread over every index).
    let mut seeds = [None; 4];
    for seed in 0_u64..256 {
        seeds[start_index(seed, 4)].get_or_insert(seed);
    }
    for (index, seed) in seeds.into_iter().enumerate() {
        let seed = seed.expect("every index is some seed's start");
        let set = EndpointSet::parse(&urls, &[])
            .expect("endpoints")
            .with_seeded_start(seed);
        let (transport, _) = transport_with(set, config(Duration::from_secs(5)), 1);
        assert_eq!(EvmClient::new(transport).chain_id().expect("chain id"), 1);
        assert_eq!(servers[index].request_count(), 1, "seed {seed}");
    }
    assert!(servers.iter().all(|server| server.request_count() == 1));
}

#[test]
fn json_rpc_rate_limits_fail_over_like_http_429() {
    let limited = MockServer::start(vec![Reply::json(
        r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32005,"message":"daily request count exceeded, request rate limited"}}"#,
    )]);
    let answering = MockServer::start(vec![recorded("evm/eth_chainId")]);
    let (single, sleeper) = transport(&[&limited, &answering], 2);
    let client = EvmClient::new(single);
    assert_eq!(client.chain_id().expect("second endpoint"), 1);
    assert_eq!((limited.request_count(), answering.request_count()), (1, 1));
    assert!(sleeper.delays().is_empty(), "no backoff inside a round");
    assert_eq!(client.transport().endpoints().preferred(), 1);

    // One rate-limited call moves the whole batch to the next endpoint.
    let limited = MockServer::start(vec![Reply::rpc_errors(
        r#"[{"jsonrpc":"2.0","id":0,"result":"0x18daf58"},{"jsonrpc":"2.0","id":0,"error":{"code":429,"message":"Too Many Requests"}}]"#,
    )]);
    let answering = MockServer::start(vec![recorded("evm/batch_blockNumber_getProof")]);
    let (batch, _) = transport(&[&limited, &answering], 1);
    let results = batch
        .json_rpc_batch(head_and_proof_batch())
        .expect("second endpoint answers the batch");
    assert!(results.iter().all(Result::is_ok));
    assert_eq!((limited.request_count(), answering.request_count()), (1, 1));
}

/// The calls of the recorded `evm/batch_blockNumber_getProof` exchange.
fn head_and_proof_batch() -> Vec<JsonRpcCall> {
    vec![
        JsonRpcCall::new("eth_blockNumber", Vec::new()),
        JsonRpcCall::new(
            "eth_getProof",
            vec![
                Value::from("0x0000F90827F1C53a10cb7A02335B175320002935"),
                Value::Array(vec![Value::from(format!("0x{:0>64}", "1b75"))]),
                Value::from("latest"),
            ],
        ),
    ]
}

#[test]
fn unsupported_methods_fail_over_to_an_endpoint_that_serves_them() {
    let history = hex20("0x0000F90827F1C53a10cb7A02335B175320002935");
    let slot = hex32(&format!("{:0>64}", "1b75"));
    let unsupported = MockServer::start(vec![Reply::rpc_errors(
        r#"{"jsonrpc":"2.0","id":0,"error":{"code":-32601,"message":"the method eth_getProof does not exist/is not available"}}"#,
    )]);
    let serving = MockServer::start(vec![
        recorded("evm/eth_getProof"),
        recorded("evm/eth_chainId"),
    ]);
    let (single, sleeper) = transport(&[&unsupported, &serving], 2);
    let client = EvmClient::new(single);
    let proof = client
        .proof(&history, &[slot], BlockId::from(BlockTag::Latest))
        .expect("second endpoint serves eth_getProof");
    assert_eq!(proof.address, history);
    assert_eq!(
        (unsupported.request_count(), serving.request_count()),
        (1, 1)
    );
    assert!(sleeper.delays().is_empty(), "no backoff inside a round");
    // The serving endpoint is preferred from now on.
    assert_eq!(client.transport().endpoints().preferred(), 1);
    assert_eq!(client.chain_id().expect("preferred endpoint"), 1);
    assert_eq!(
        (unsupported.request_count(), serving.request_count()),
        (1, 2)
    );

    // EIP-1474 "method not supported" inside a batch moves the whole batch.
    let unsupported = MockServer::start(vec![Reply::rpc_errors(
        r#"[{"jsonrpc":"2.0","id":0,"result":"0x18daf58"},{"jsonrpc":"2.0","id":0,"error":{"code":-32004,"message":"method not supported"}}]"#,
    )]);
    let serving = MockServer::start(vec![recorded("evm/batch_blockNumber_getProof")]);
    let (batch, _) = transport(&[&unsupported, &serving], 1);
    let results = batch
        .json_rpc_batch(head_and_proof_batch())
        .expect("second endpoint serves the batch");
    assert!(results.iter().all(Result::is_ok));
    assert_eq!(
        (unsupported.request_count(), serving.request_count()),
        (1, 1)
    );

    // An endpoint refusing the whole batch with one error object hands it on;
    // when every endpoint refuses, the caller learns why from the failures.
    let refusing = MockServer::start(vec![Reply::json(
        r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"batch requests are not supported"}}"#,
    )]);
    let serving = MockServer::start(vec![recorded("evm/batch_blockNumber_getProof")]);
    let (batch, _) = transport(&[&refusing, &serving], 1);
    let results = batch
        .json_rpc_batch(head_and_proof_batch())
        .expect("second endpoint serves the batch");
    assert_eq!(results.len(), 2);
    assert_eq!((refusing.request_count(), serving.request_count()), (1, 1));
    let refusing = MockServer::start(vec![Reply::json(
        r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"batch requests are not supported"}}"#,
    )]);
    let (batch, _) = transport(&[&refusing], 1);
    let error = batch
        .json_rpc_batch(head_and_proof_batch())
        .expect_err("every endpoint refuses");
    assert!(
        matches!(
            error.last_failure(),
            RpcError::BatchRejected { error: inner } if matches!(**inner, RpcError::JsonRpc { code: -32600, .. })
        ),
        "{error:?}"
    );
}

#[test]
fn refused_credentials_fail_over() {
    let forbidden = MockServer::start(vec![Reply::status(
        403,
        "application/json",
        br#"{"message":"request rate exceeded, the query server is suspended"}"#,
    )]);
    let unauthorized = MockServer::start(vec![Reply::status(
        401,
        "application/json",
        br#"{"message":"invalid API key"}"#,
    )]);
    let answering = MockServer::start(vec![recorded("evm/eth_blockNumber")]);
    let (keyed_transport, sleeper) = transport(&[&forbidden, &unauthorized, &answering], 1);
    let client = EvmClient::new(keyed_transport);
    let head = client.block_number().expect("third endpoint answers");
    assert_eq!(head, 0x18d_af53);
    let order = [&forbidden, &unauthorized, &answering].map(|server| server.requests()[0].sequence);
    assert!(
        order[0] < order[1] && order[1] < order[2],
        "tried in list order"
    );
    assert!(sleeper.delays().is_empty(), "no backoff inside a round");
    assert_eq!(client.transport().endpoints().preferred(), 2);

    let forbidden = MockServer::start(vec![Reply::status(
        403,
        "application/json",
        br#"{"message":"forbidden"}"#,
    )]);
    let (lonely, _) = transport(&[&forbidden], 1);
    let error = EvmClient::new(lonely)
        .block_number()
        .expect_err("the only endpoint refuses");
    assert!(
        matches!(
            error.last_failure(),
            RpcError::Status { status: 403, message: Some(message), .. } if message == "forbidden"
        ),
        "{error:?}"
    );
}

#[test]
fn success_bodies_that_are_not_json_fail_over() {
    let page = || {
        Reply::status(
            200,
            "text/html; charset=utf-8",
            b"<!DOCTYPE html><html><title>Just a moment...</title></html>",
        )
    };

    let html = MockServer::start(vec![page()]);
    let answering = MockServer::start(vec![recorded("evm/eth_chainId")]);
    let client = EvmClient::new(transport_pair(&html, &answering));
    assert_eq!(client.chain_id().expect("second endpoint"), 1);
    assert_eq!((html.request_count(), answering.request_count()), (1, 1));
    assert_eq!(client.transport().endpoints().preferred(), 1);
    assert_eq!(
        answering.requests()[0].header("content-type"),
        Some("application/json")
    );

    let html = MockServer::start(vec![page()]);
    let answering = MockServer::start(vec![recorded("beacon/headers_finalized")]);
    let client = BeaconClient::new(transport_pair(&html, &answering));
    assert_eq!(
        client.finalized_header().expect("second endpoint").slot,
        15_301_120
    );
    assert_eq!((html.request_count(), answering.request_count()), (1, 1));

    let truncated = MockServer::start(vec![Reply::json(r#"{"data":{"root":"0xfe"#)]);
    let (transport, _) = transport(&[&truncated], 1);
    let error = transport
        .get_json("/eth/v1/beacon/headers/finalized")
        .expect_err("only a truncated body");
    assert!(
        matches!(
            error.last_failure(),
            RpcError::NotJson { content_type: Some(media), .. } if media == "application/json"
        ),
        "{error:?}"
    );
}

#[test]
fn json_rpc_ids_must_answer_the_request() {
    let server = MockServer::start(vec![Reply::json(
        r#"{"jsonrpc":"2.0","id":999,"result":"0x1"}"#,
    )]);
    let error = evm(&server).chain_id().expect_err("foreign id");
    assert!(
        matches!(error, RpcError::InvalidResponse { .. }),
        "{error:?}"
    );
}

#[test]
fn malformed_hex_is_rejected_without_failover() {
    for (reply, call) in [
        (r#""0x01""#, 0),
        (r#""0x""#, 0),
        (r#""1""#, 0),
        (r#""0xzz""#, 1),
        (r#""0xabc""#, 2),
        (r#""0x1234""#, 3),
        (r"1", 1),
    ] {
        let a = MockServer::start(vec![Reply::rpc_result(reply)]);
        let b = MockServer::start(Vec::new());
        let client = EvmClient::new(transport_pair(&a, &b));
        let result = match call {
            0 => client.chain_id().map(drop),
            1 => client.block_number().map(drop),
            2 => client
                .code(&[0; 20], BlockId::from(BlockTag::Latest))
                .map(drop),
            _ => client.send_raw_transaction(&[2, 0xc0]).map(drop),
        };
        let error = result.expect_err(reply);
        assert!(
            matches!(error, RpcError::InvalidResponse { .. }),
            "{reply}: {error:?}"
        );
        assert_eq!(b.request_count(), 0, "{reply}");
    }

    let mut block = fixture_json("evm/eth_getBlockByNumber_hashes");
    let result = block
        .get_mut("result")
        .and_then(Value::as_object_mut)
        .expect("block");
    result.insert(
        "miner".to_owned(),
        Value::from(format!("0x{}", "11".repeat(19))),
    );
    let server = MockServer::start(vec![Reply::Respond {
        status: 200,
        headers: Vec::new(),
        body: norito::json::to_vec(&block).expect("encode"),
        rewrite_ids: true,
        close_delimited: false,
    }]);
    let error = evm(&server)
        .block_by_number(BlockTag::Number(0x18d_af08))
        .expect_err("short miner");
    assert!(error.to_string().contains("block.miner"), "{error}");
}

// ---------------------------------------------------------------------------
// Secret headers
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn secret_file(dir: &TempDir, name: &str, contents: &[u8], mode: u32) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    let path = dir.0.join(name);
    fs::write(&path, contents).expect("write secret");
    fs::set_permissions(&path, fs::Permissions::from_mode(mode)).expect("chmod");
    path
}

#[cfg(unix)]
fn with_secret(server: &MockServer, value_file: PathBuf) -> EndpointSet {
    let url = iroha_config::parameters::actual::parse_sccp_http_endpoint(&server.url())
        .expect("endpoint");
    EndpointSet::new(
        [url.clone()],
        &[SccpSecretHeader {
            endpoint: url,
            header: "X-Api-Key".to_owned(),
            value_file,
        }],
    )
    .expect("endpoints")
}

#[cfg(unix)]
#[test]
fn secret_headers_are_read_from_owner_only_files_and_never_printed() {
    let dir = TempDir::new("secret_ok");
    let file = secret_file(&dir, "key", b"top-secret-value\n", 0o600);
    let server = MockServer::start(vec![recorded("evm/eth_chainId")]);
    let (transport, _) = transport_with(
        with_secret(&server, file),
        config(Duration::from_secs(5)),
        1,
    );
    assert!(!format!("{transport:?}").contains("top-secret-value"));
    assert_eq!(EvmClient::new(transport).chain_id().expect("chain id"), 1);
    let request = &server.requests()[0];
    assert_eq!(request.header("x-api-key"), Some("top-secret-value"));
    assert_eq!(request.header("content-type"), Some("application/json"));
    assert_eq!(request.method, "POST");
}

#[cfg(unix)]
#[test]
fn insecure_secret_header_files_are_refused_before_sending() {
    use std::os::unix::fs::symlink;

    let dir = TempDir::new("secret_refused");
    let readable = secret_file(&dir, "readable", b"top-secret-value", 0o644);
    let owner_only = secret_file(&dir, "owner-only", b"top-secret-value", 0o600);
    let link = dir.0.join("link");
    symlink(&owner_only, &link).expect("symlink");

    for (value_file, expected) in [
        (readable, "permissions"),
        (link, "symlink"),
        (dir.0.join("missing"), "missing"),
    ] {
        let server = MockServer::start(vec![recorded("evm/eth_chainId")]);
        let (transport, _) = transport_with(
            with_secret(&server, value_file),
            config(Duration::from_secs(5)),
            1,
        );
        let error = EvmClient::new(transport).chain_id().expect_err(expected);
        assert_eq!(server.request_count(), 0, "{expected}: nothing is sent");
        let RpcError::SecretHeader { error: refusal, .. } = error.last_failure() else {
            panic!("{expected}: unexpected {error:?}");
        };
        match expected {
            "permissions" => assert!(matches!(
                refusal.problem,
                SecretFileProblem::Permissions { mode } if mode & 0o777 == 0o644
            )),
            "symlink" => assert_eq!(refusal.problem, SecretFileProblem::Symlink),
            _ => assert!(matches!(refusal.problem, SecretFileProblem::Io { .. })),
        }
        let printed = format!("{error} {error:?}");
        assert!(
            !printed.contains("top-secret-value"),
            "{expected}: {printed}"
        );
    }
}

#[cfg(unix)]
#[test]
fn an_endpoint_with_a_refused_secret_fails_over_to_the_next() {
    let dir = TempDir::new("secret_failover");
    let readable = secret_file(&dir, "readable", b"top-secret-value", 0o640);
    let guarded = MockServer::start(vec![recorded("evm/eth_chainId")]);
    let open = MockServer::start(vec![recorded("evm/eth_chainId")]);
    let guarded_url = iroha_config::parameters::actual::parse_sccp_http_endpoint(&guarded.url())
        .expect("endpoint");
    let open_url =
        iroha_config::parameters::actual::parse_sccp_http_endpoint(&open.url()).expect("endpoint");
    let set = EndpointSet::new(
        [guarded_url.clone(), open_url],
        &[SccpSecretHeader {
            endpoint: guarded_url,
            header: "x-api-key".to_owned(),
            value_file: readable,
        }],
    )
    .expect("endpoints");
    let (transport, _) = transport_with(set, config(Duration::from_secs(5)), 1);
    assert_eq!(
        EvmClient::new(transport)
            .chain_id()
            .expect("second endpoint"),
        1
    );
    assert_eq!(guarded.request_count(), 0);
    assert_eq!(open.request_count(), 1);
    assert_eq!(open.requests()[0].header("x-api-key"), None);
}

// ---------------------------------------------------------------------------
// EVM JSON-RPC
// ---------------------------------------------------------------------------

fn rpc_call(request: &Recorded) -> (String, Vec<Value>) {
    let call = request.json();
    (
        call.get("method")
            .and_then(Value::as_str)
            .expect("method")
            .to_owned(),
        call.get("params")
            .and_then(Value::as_array)
            .expect("params")
            .clone(),
    )
}

#[test]
fn evm_chain_ids_and_head() {
    let server = MockServer::start(vec![
        recorded("evm/eth_chainId"),
        recorded("evm/eth_blockNumber"),
        recorded("bsc/eth_chainId"),
    ]);
    let client = evm(&server);
    assert_eq!(client.chain_id().expect("ethereum"), 1);
    assert_eq!(client.block_number().expect("head"), 0x18d_af53);
    assert_eq!(client.chain_id().expect("bsc"), 56);
    let (method, params) = rpc_call(&server.requests()[1]);
    assert_eq!(method, "eth_blockNumber");
    assert!(params.is_empty());
    assert_eq!(
        server.requests()[0].header("accept"),
        Some("application/json")
    );
}

#[test]
fn evm_blocks_carry_every_header_field_through_prague() {
    let server = MockServer::start(vec![recorded("evm/eth_getBlockByNumber_hashes")]);
    let block = evm(&server)
        .block_by_number(BlockTag::Number(0x18d_af08))
        .expect("block")
        .expect("known block");
    let (method, params) = rpc_call(&server.requests()[0]);
    assert_eq!(method, "eth_getBlockByNumber");
    assert_eq!(params, vec![Value::from("0x18daf08"), Value::from(false)]);

    let header = &block.header;
    assert_eq!(
        header.hash,
        hex32("0x4168ab54c50c21f13c2fc36b285fc7666824d3acb7879f56945b73d07338a942")
    );
    assert_eq!(header.number, 0x18d_af08);
    assert_eq!(
        header.beneficiary,
        hex20("0x4838b106fce9647bdf1e7877bf73ce8b0bad5f97")
    );
    assert!(header.difficulty.is_zero());
    assert_eq!(header.gas_limit, 0x393_8700);
    assert_eq!(header.timestamp, 0x6ab7_e84b);
    assert_eq!(header.extra_data, b"Titan (titanbuilder.xyz)");
    assert_eq!(header.nonce, [0; 8]);
    assert_eq!(header.base_fee_per_gas, Some(U256::from(0x4e8_b783_u64)));
    assert!(header.withdrawals_root.is_some());
    assert_eq!(header.blob_gas_used, Some(0x60000));
    assert_eq!(header.excess_blob_gas, Some(0xac1_6b73));
    assert!(header.parent_beacon_block_root.is_some());
    assert_eq!(
        header.requests_hash,
        Some(hex32(
            "0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ))
    );
    assert_eq!(block.transactions.len(), 320);
    assert!(block.uncles.is_empty());
    assert_eq!(block.size, Some(0x23d52));
    assert!(block.raw.get("withdrawals").is_some());
}

#[test]
fn evm_block_receipts_match_block_hashes() {
    let server = MockServer::start(vec![
        recorded("evm/eth_getBlockByNumber_hashes"),
        recorded("evm/eth_getBlockReceipts"),
        recorded("evm/eth_getTransactionReceipt"),
        recorded("evm/eth_getTransactionReceipt_null"),
        recorded("evm/eth_getBlockByNumber_null"),
    ]);
    let client = evm(&server);
    let block = client
        .block_by_number(BlockTag::Number(0x18d_af08))
        .expect("block")
        .expect("known block");

    let receipts = client
        .block_receipts(BlockId::from(0x18d_af08))
        .expect("receipts")
        .expect("known block");
    assert_eq!(receipts.len(), 4);
    assert_eq!(
        receipts
            .iter()
            .map(|receipt| receipt.tx_type)
            .collect::<Vec<_>>(),
        vec![0, 3, 4, 2]
    );
    assert_eq!(receipts[0].transaction_index, 32);
    for receipt in &receipts {
        let index = usize::try_from(receipt.transaction_index).expect("index");
        assert_eq!(receipt.transaction_hash, block.transactions[index]);
        assert_eq!(receipt.block_hash, block.header.hash);
        assert!(!receipt.logs.is_empty());
    }
    assert_eq!(receipts[1].blob_gas_used.map(|used| used > 0), Some(true));

    let hash = hex32("0xe5bb91ca521805fde8fb1165b49fd18eb741779b34fe53b18614ee0e63605dc6");
    let receipt = client
        .transaction_receipt(&hash)
        .expect("receipt")
        .expect("known receipt");
    assert_eq!(receipt.transaction_hash, hash);
    assert_eq!(receipt.status, Some(1));
    assert_eq!(receipt.logs.len(), 21);
    assert_eq!(
        receipt.logs[0].address,
        hex20("0x9008d19f58aabd9ed0d60971565aa8510560ab41")
    );
    assert_eq!(client.transaction_receipt(&[0; 32]).expect("unknown"), None);
    assert_eq!(
        client
            .block_by_number(BlockTag::Number(0xffff_ffff))
            .expect("unknown block"),
        None
    );
    let (_, params) = rpc_call(&server.requests()[1]);
    assert_eq!(params, vec![Value::from("0x18daf08")]);
}

#[test]
fn evm_proofs_must_answer_the_requested_slots() {
    let history = hex20("0x0000F90827F1C53a10cb7A02335B175320002935");
    let slot = hex32(&format!("{:0>64}", "1b75"));
    let server = MockServer::start(vec![
        recorded("evm/eth_getProof"),
        recorded("evm/eth_getProof"),
    ]);
    let client = evm(&server);
    let proof = client
        .proof(&history, &[slot], BlockId::from(BlockTag::Latest))
        .expect("proof");
    assert_eq!(proof.address, history);
    assert_eq!(proof.nonce, 1);
    assert_eq!(proof.account_proof.len(), 8);
    assert_eq!(proof.storage_proof[0].key, slot);
    assert_eq!(proof.storage_proof[0].proof.len(), 5);
    // EIP-2935 stores the hash of block 0x18daf08 in slot 0x18daf08 % 8191.
    assert_eq!(
        proof.storage_proof[0].value.to_be_bytes(),
        hex32("0x4168ab54c50c21f13c2fc36b285fc7666824d3acb7879f56945b73d07338a942")
    );
    let (method, params) = rpc_call(&server.requests()[0]);
    assert_eq!(method, "eth_getProof");
    assert_eq!(params[2], Value::from("latest"));

    let other_slot = hex32(&format!("{:0>64}", "1b76"));
    let error = client
        .proof(&history, &[other_slot], BlockId::from(BlockTag::Latest))
        .expect_err("foreign slot");
    assert!(
        matches!(error, RpcError::InvalidResponse { .. }),
        "{error:?}"
    );
}

#[test]
fn evm_state_reads_and_fee_data() {
    let server = MockServer::start(vec![
        recorded("evm/eth_getCode"),
        recorded("evm/eth_call"),
        recorded("evm/eth_estimateGas"),
        recorded("evm/eth_getTransactionCount"),
        recorded("evm/eth_maxPriorityFeePerGas"),
    ]);
    let client = evm(&server);
    let history = hex20("0x0000F90827F1C53a10cb7A02335B175320002935");
    let code = client
        .code(&history, BlockId::from(0x18d_af08))
        .expect("code");
    assert_eq!(code.len(), 83);
    assert_eq!(&code[..2], &[0x33, 0x73]);

    let weth = hex20("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2");
    let symbol = EvmCallRequest::new(weth, vec![0x95, 0xd8, 0x9b, 0x41]);
    let output = client
        .call(&symbol, BlockId::from(0x18d_af08))
        .expect("call");
    assert_eq!(output.len(), 96);
    assert_eq!(&output[64..68], b"WETH");
    assert_eq!(client.estimate_gas(&symbol).expect("gas"), 0x605b);
    let miner = hex20("0x4838b106fce9647bdf1e7877bf73ce8b0bad5f97");
    assert_eq!(
        client
            .transaction_count(&miner, BlockId::from(0x18d_af08))
            .expect("nonce"),
        0x0058_f449
    );
    assert_eq!(client.max_priority_fee_per_gas().expect("tip"), U256::ZERO);

    let (method, params) = rpc_call(&server.requests()[1]);
    assert_eq!(method, "eth_call");
    assert_eq!(
        params[0].get("data").and_then(Value::as_str),
        Some("0x95d89b41")
    );
    assert_eq!(server.request_count(), 5);
}

#[test]
fn evm_raw_transaction_submission() {
    let hash = format!("0x{}", "ab".repeat(32));
    let server = MockServer::start(vec![
        recorded("evm/eth_sendRawTransaction_error"),
        Reply::rpc_result(&format!(r#""{hash}""#)),
    ]);
    let client = evm(&server);
    let error = client
        .send_raw_transaction(&[0x02, 0xc0])
        .expect_err("rejected");
    assert!(
        matches!(error, RpcError::JsonRpc { code: -32600, .. }),
        "{error:?}"
    );
    assert_eq!(
        client
            .send_raw_transaction(&[0x02, 0xc1, 0x80])
            .expect("accepted"),
        [0xab; 32]
    );
    let (method, params) = rpc_call(&server.requests()[1]);
    assert_eq!(method, "eth_sendRawTransaction");
    assert_eq!(params, vec![Value::from("0x02c180")]);
    assert!(client.send_raw_transaction(&[]).is_err());
}

#[test]
fn evm_batches_match_answers_to_calls() {
    let server = MockServer::start(vec![recorded("evm/batch_blockNumber_getProof")]);
    let (transport, _) = transport(&[&server], 1);
    let results = transport
        .json_rpc_batch(vec![
            JsonRpcCall::new("eth_blockNumber", Vec::new()),
            JsonRpcCall::new(
                "eth_getProof",
                vec![
                    Value::from("0x0000F90827F1C53a10cb7A02335B175320002935"),
                    Value::Array(vec![Value::from(format!("0x{:0>64}", "1b75"))]),
                    Value::from("latest"),
                ],
            ),
        ])
        .expect("batch");
    assert_eq!(results.len(), 2);
    assert_eq!(
        results[0].as_ref().expect("head"),
        &Value::from("0x18daf58")
    );
    assert!(
        results[1]
            .as_ref()
            .expect("proof")
            .get("accountProof")
            .is_some()
    );
    assert!(server.requests()[0].json().as_array().is_some());
    assert!(transport.json_rpc_batch(Vec::new()).is_err());
}

#[test]
fn evm_block_batches_parse_every_block() {
    let block = fixture_json("evm/eth_getBlockByNumber_hashes");
    let missing = fixture_json("evm/eth_getBlockByNumber_null");
    let server = MockServer::start(vec![Reply::Respond {
        status: 200,
        headers: Vec::new(),
        body: norito::json::to_vec(&Value::Array(vec![block, missing])).expect("encode"),
        rewrite_ids: true,
        close_delimited: false,
    }]);
    let blocks = evm(&server)
        .blocks_by_number(&[0x18d_af08, 0xffff_ffff])
        .expect("batch");
    assert_eq!(blocks.len(), 2);
    assert_eq!(
        blocks[0].as_ref().map(|block| block.header.number),
        Some(0x18d_af08)
    );
    assert!(blocks[1].is_none());
}

#[test]
fn bsc_blocks_parse_with_chain_specific_fields_kept_raw() {
    let server = MockServer::start(vec![recorded("bsc/eth_getBlockByNumber_finalized")]);
    let block = evm(&server)
        .block_by_number(BlockTag::Finalized)
        .expect("block")
        .expect("known block");
    assert_eq!(block.header.number, 0x766_abbf);
    assert_eq!(block.header.difficulty, U256::from(2_u64));
    assert_eq!(block.header.base_fee_per_gas, Some(U256::ZERO));
    assert_eq!(block.header.parent_beacon_block_root, Some([0; 32]));
    assert!(block.header.requests_hash.is_some());
    assert!(block.header.extra_data.len() > 32);
    assert_eq!(
        block.raw.get("milliTimestamp").and_then(Value::as_str),
        Some("0x1a0de72724a")
    );
    let (_, params) = rpc_call(&server.requests()[0]);
    assert_eq!(params[0], Value::from("finalized"));
}

// ---------------------------------------------------------------------------
// Beacon API
// ---------------------------------------------------------------------------

#[test]
fn beacon_headers_are_read_as_json() {
    let server = MockServer::start(vec![
        recorded("beacon/headers_finalized"),
        Reply::status(
            404,
            "application/json",
            br#"{"code":404,"message":"No block found for id '42'"}"#,
        ),
    ]);
    let client = beacon(&server);
    let header = client.finalized_header().expect("finalized header");
    assert_eq!(
        header.root,
        hex32("0xfea1d5a9a843e3afece8bdf7cfe4e0701d9b6282af51715834783170128f6ecd")
    );
    assert_eq!(header.slot, 15_301_120);
    assert_eq!(header.proposer_index, 2_175_118);
    assert!(header.canonical);
    assert_eq!(header.execution_optimistic, Some(false));
    assert_eq!(header.finalized, Some(false));
    assert_eq!(
        server.requests()[0].target,
        "/eth/v1/beacon/headers/finalized"
    );
    assert_eq!(
        server.requests()[0].header("accept"),
        Some("application/json")
    );

    let error = client
        .header(&BeaconBlockId::slot(42))
        .expect_err("unknown slot");
    assert!(
        matches!(
            &error,
            RpcError::Status { status: 404, message: Some(message), .. }
                if message == "No block found for id '42'"
        ),
        "{error:?}"
    );
    assert_eq!(server.requests()[1].target, "/eth/v1/beacon/headers/42");
}

fn receipt_visit_fixture() -> (Value, Vec<Value>) {
    let mut block = fixture_json("evm/eth_getBlockByNumber_hashes")
        .get("result")
        .unwrap()
        .clone();
    let mut receipts = fixture_json("evm/eth_getBlockReceipts")
        .get("result")
        .unwrap()
        .as_array()
        .unwrap()[..2]
        .to_vec();
    let hashes = receipts
        .iter()
        .map(|receipt| receipt.get("transactionHash").unwrap().clone())
        .collect();
    let fields = block.as_object_mut().unwrap();
    fields.insert("transactions".into(), Value::Array(hashes));
    fields.insert("gasUsed".into(), Value::from("0xa410"));
    for (index, receipt) in receipts.iter_mut().enumerate() {
        let fields = receipt.as_object_mut().unwrap();
        fields.insert(
            "transactionIndex".into(),
            Value::from(format!("0x{index:x}")),
        );
        fields.insert("gasUsed".into(), Value::from("0x5208"));
        fields.insert(
            "cumulativeGasUsed".into(),
            Value::from(format!("0x{:x}", 21_000 * (index + 1))),
        );
    }
    (block, receipts)
}

#[test]
fn per_transaction_receipt_visit_does_not_require_the_aggregate_json_to_fit() {
    let (block, receipts) = receipt_visit_fixture();
    let encoded: Vec<_> = receipts
        .iter()
        .map(|receipt| norito::json::to_json(receipt).unwrap())
        .collect();
    let block_json = norito::json::to_json(&block).unwrap();
    let cap = encoded
        .iter()
        .map(String::len)
        .chain([block_json.len()])
        .max()
        .unwrap()
        + 100;
    assert!(norito::json::to_vec(&receipts).unwrap().len() > cap);
    let server = MockServer::start(
        std::iter::once(Reply::rpc_result(&block_json))
            .chain(encoded.iter().map(|body| Reply::rpc_result(body)))
            .collect(),
    );
    let endpoints = EndpointSet::parse(&[server.url().as_str()], &[]).unwrap();
    let client = EvmClient::new(
        transport_with(
            endpoints,
            config(Duration::from_secs(5)).with_max_response_bytes(cap),
            1,
        )
        .0,
    );
    let block = client
        .block_by_number(BlockTag::Number(0x18d_af08))
        .unwrap()
        .unwrap();
    let mut entries = Vec::new();
    client
        .visit_block_receipts(&block, |receipt| {
            entries.push(iroha_sccp_rpc::builders::ethereum::receipt_rlp(receipt));
            Ok(())
        })
        .unwrap();
    assert_eq!(entries.len(), 2);
    assert!(entries.iter().all(|entry| !entry.is_empty()));
    let requests = server.requests();
    assert_eq!(requests.len(), 3);
    for request in &requests[1..] {
        let request = norito::json::from_slice::<Value>(&request.body).unwrap();
        assert_eq!(
            request.get("method").and_then(Value::as_str),
            Some("eth_getTransactionReceipt")
        );
    }
}

#[test]
fn receipt_visit_refuses_missing_reordered_foreign_and_incomplete_block_answers() {
    for case in 0..5 {
        let (mut block, mut receipts) = receipt_visit_fixture();
        match case {
            0 => receipts[1] = Value::Null,
            1 => {
                receipts[1]
                    .as_object_mut()
                    .unwrap()
                    .insert("transactionIndex".into(), Value::from("0x0"));
            }
            2 => {
                receipts[1].as_object_mut().unwrap().insert(
                    "blockHash".into(),
                    Value::from(format!("0x{}", "11".repeat(32))),
                );
            }
            3 => {
                receipts[1]
                    .as_object_mut()
                    .unwrap()
                    .insert("cumulativeGasUsed".into(), Value::from("0xa411"));
            }
            _ => {
                block
                    .as_object_mut()
                    .unwrap()
                    .insert("gasUsed".into(), Value::from("0xa411"));
            }
        }
        let replies = std::iter::once(Reply::rpc_result(&norito::json::to_json(&block).unwrap()))
            .chain(
                receipts
                    .iter()
                    .map(|receipt| Reply::rpc_result(&norito::json::to_json(receipt).unwrap())),
            )
            .collect();
        let server = MockServer::start(replies);
        let client = evm(&server);
        let block = client
            .block_by_number(BlockTag::Number(0x18d_af08))
            .unwrap()
            .unwrap();
        assert!(
            client.visit_block_receipts(&block, |_| Ok(())).is_err(),
            "case {case}"
        );
    }
}

#[test]
fn receipt_visit_stops_before_the_next_request_on_visitor_refusal() {
    let (block, receipts) = receipt_visit_fixture();
    let server = MockServer::start(vec![
        Reply::rpc_result(&norito::json::to_json(&block).unwrap()),
        Reply::rpc_result(&norito::json::to_json(&receipts[0]).unwrap()),
    ]);
    let client = evm(&server);
    let block = client
        .block_by_number(BlockTag::Number(0x18d_af08))
        .unwrap()
        .unwrap();
    assert!(
        matches!(client.visit_block_receipts(&block, |_| Err(RpcError::InvalidRequest("original visitor refusal".into()))),Err(RpcError::InvalidRequest(message)) if message=="original visitor refusal")
    );
    assert_eq!(server.requests().len(), 2);
}

fn receipt_proof_block(mut block: Value, receipts: &[Value]) -> Value {
    let server = MockServer::start(
        receipts
            .iter()
            .map(|receipt| Reply::rpc_result(&norito::json::to_json(receipt).unwrap()))
            .collect(),
    );
    let client = evm(&server);
    let entries: Vec<_> = receipts
        .iter()
        .enumerate()
        .map(|(index, receipt)| {
            let hash = hex32(receipt.get("transactionHash").unwrap().as_str().unwrap());
            let receipt = client.transaction_receipt(&hash).unwrap().unwrap();
            (
                iroha_sccp::ethereum_source::rlp_encode_u64(index as u64),
                iroha_sccp_rpc::builders::ethereum::receipt_rlp(&receipt),
            )
        })
        .collect();
    let root = iroha_sccp::ethereum_source::mpt_root(&entries).unwrap();
    block.as_object_mut().unwrap().insert(
        "receiptsRoot".into(),
        Value::from(iroha_sccp_rpc::evm::format_data(&root)),
    );
    block
}

#[test]
fn streamed_receipt_proof_authenticates_root_and_rejects_substituted_receipts() {
    let (block, receipts) = receipt_visit_fixture();
    let block = receipt_proof_block(block, &receipts);
    for changed in [false, true] {
        let mut receipts = receipts.clone();
        if changed {
            receipts[1]
                .as_object_mut()
                .unwrap()
                .insert("status".into(), Value::from("0x0"));
        }
        let server = MockServer::start(
            std::iter::once(Reply::rpc_result(&norito::json::to_json(&block).unwrap()))
                .chain(
                    receipts
                        .iter()
                        .map(|receipt| Reply::rpc_result(&norito::json::to_json(receipt).unwrap())),
                )
                .collect(),
        );
        let client = evm(&server);
        let block = client
            .block_by_number(BlockTag::Number(0x18d_af08))
            .unwrap()
            .unwrap();
        let result = client.block_receipt_proof(&block, 0, 1_048_576);
        if changed {
            assert!(result.is_err());
        } else {
            let proof = result.unwrap();
            assert!(!proof.nodes.is_empty());
            assert!(proof.nodes.iter().map(Vec::len).sum::<usize>() < 1_048_576);
        }
    }
}

#[test]
fn streamed_receipt_enforces_the_whole_body_and_selected_proof_budgets() {
    let (block, receipts) = receipt_visit_fixture();
    let block = receipt_proof_block(block, &receipts);
    let block_json = norito::json::to_json(&block).unwrap();
    let cap = block_json.len() + 1_024;
    let mut padded = receipts[0].clone();
    padded
        .as_object_mut()
        .unwrap()
        .insert("ignored_padding".into(), Value::from("x".repeat(cap * 2)));
    let server = MockServer::start(vec![
        Reply::rpc_result(&block_json),
        // No Content-Length: the streaming reader itself must enforce the bound.
        Reply::rpc_result(&norito::json::to_json(&padded).unwrap()).close_delimited(),
    ]);
    let set = EndpointSet::parse(&[&server.url()], &[]).unwrap();
    let mut cfg = config(Duration::from_secs(5));
    cfg.max_response_bytes = cap;
    let (transport, _) = transport_with(set, cfg, 1);
    let client = EvmClient::new(transport);
    let block = client
        .block_by_number(BlockTag::Number(0x18d_af08))
        .unwrap()
        .unwrap();
    let error = client
        .block_receipt_proof(&block, 0, 1_048_576)
        .unwrap_err();
    assert!(
        matches!(error.last_failure(), RpcError::ResponseTooLarge { limit, .. } if *limit == cap),
        "{error:?}"
    );
    assert_eq!(server.request_count(), 2);

    let server = MockServer::start(vec![
        Reply::rpc_result(&block_json),
        Reply::rpc_result(&norito::json::to_json(&receipts[0]).unwrap()),
    ]);
    let client = evm(&server);
    let block = client
        .block_by_number(BlockTag::Number(0x18d_af08))
        .unwrap()
        .unwrap();
    let error = client.block_receipt_proof(&block, 0, 256).unwrap_err();
    assert!(
        matches!(error.last_failure(), RpcError::InvalidResponse { .. }),
        "{error:?}"
    );
    // The selected receipt cannot fit its proof: never fetch unrelated receipts.
    assert_eq!(server.request_count(), 2);
}

#[test]
fn streamed_receipt_slow_body_preserves_the_total_attempt_deadline() {
    let (block, receipts) = receipt_visit_fixture();
    let block = receipt_proof_block(block, &receipts);
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":2,"result":{}}}"#,
        norito::json::to_json(&receipts[0]).unwrap()
    )
    .into_bytes();
    let server = MockServer::start(vec![
        Reply::rpc_result(&norito::json::to_json(&block).unwrap()),
        Reply::Drip {
            body,
            interval: Duration::from_millis(20),
        },
    ]);
    let set = EndpointSet::parse(&[&server.url()], &[]).unwrap();
    let (transport, _) = transport_with(set, config(Duration::from_millis(500)), 1);
    let client = EvmClient::new(transport);
    let block = client
        .block_by_number(BlockTag::Number(0x18d_af08))
        .unwrap()
        .unwrap();
    let started = Instant::now();
    let error = client
        .block_receipt_proof(&block, 0, 1_048_576)
        .unwrap_err();
    assert!(
        matches!(error.last_failure(), RpcError::Timeout { .. }),
        "{error:?}"
    );
    assert!(started.elapsed() < Duration::from_secs(3));
    assert_eq!(server.request_count(), 2);
}

#[test]
fn unrelated_receipt_above_the_old_route_cap_retains_only_its_leaf_hash() {
    let (mut block, mut receipts) = receipt_visit_fixture();
    let data_bytes = 9 * 1024 * 1024;
    let fields = receipts[1].as_object_mut().unwrap();
    let mut log = fields.get("logs").unwrap().as_array().unwrap()[0].clone();
    log.as_object_mut().unwrap().insert(
        "data".into(),
        Value::from(format!("0x{}", "aa".repeat(data_bytes))),
    );
    fields.insert("logs".into(), Value::Array(vec![log]));
    let gas = 21_000 + 375 + u64::try_from(data_bytes).unwrap() * 8;
    fields.insert("gasUsed".into(), Value::from(format!("0x{gas:x}")));
    fields.insert(
        "cumulativeGasUsed".into(),
        Value::from(format!("0x{:x}", gas + 21_000)),
    );
    block.as_object_mut().unwrap().insert(
        "gasUsed".into(),
        Value::from(format!("0x{:x}", gas + 21_000)),
    );
    block.as_object_mut().unwrap().insert(
        "gasLimit".into(),
        Value::from(format!("0x{:x}", gas + 21_000)),
    );
    // Independent consensus receipt codec supplies the oracle; no streaming parser is
    // used to manufacture its own expected root.
    let entries: Vec<_> = receipts
        .iter()
        .enumerate()
        .map(|(index, receipt)| {
            let status = receipt.get("status").and_then(Value::as_str).unwrap() == "0x1";
            let cumulative = iroha_sccp_rpc::evm::parse_quantity_u64(
                receipt.get("cumulativeGasUsed").unwrap().as_str().unwrap(),
            )
            .unwrap();
            let logs = receipt
                .get("logs")
                .unwrap()
                .as_array()
                .unwrap()
                .iter()
                .map(|log| iroha_sccp::ethereum_source::EthereumLogV1 {
                    address: hex20(log.get("address").unwrap().as_str().unwrap()),
                    topics: log
                        .get("topics")
                        .unwrap()
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|topic| hex32(topic.as_str().unwrap()))
                        .collect(),
                    data: iroha_sccp_rpc::evm::parse_data(
                        log.get("data").unwrap().as_str().unwrap(),
                    )
                    .unwrap(),
                })
                .collect();
            let bloom = iroha_sccp_rpc::evm::parse_data_array::<256>(
                receipt.get("logsBloom").unwrap().as_str().unwrap(),
            )
            .unwrap();
            let tx_type = u8::try_from(
                iroha_sccp_rpc::evm::parse_quantity_u64(
                    receipt.get("type").unwrap().as_str().unwrap(),
                )
                .unwrap(),
            )
            .expect("fixture receipt type fits one byte");
            let bytes = iroha_sccp::ethereum_source::encode_receipt(
                &iroha_sccp::ethereum_source::EthereumReceiptV1 {
                    tx_type,
                    success: status,
                    cumulative_gas_used: cumulative,
                    logs,
                },
                &bloom,
            );
            (
                iroha_sccp::ethereum_source::rlp_encode_u64(index as u64),
                bytes,
            )
        })
        .collect();
    let root = iroha_sccp::ethereum_source::mpt_root(&entries).unwrap();
    block.as_object_mut().unwrap().insert(
        "receiptsRoot".into(),
        Value::from(iroha_sccp_rpc::evm::format_data(&root)),
    );
    let large = norito::json::to_json(&receipts[1]).unwrap();
    assert!(large.len() > iroha_sccp_rpc::limits::EVM_RECEIPT_RESPONSE_BYTES);
    let server = MockServer::start(vec![
        Reply::rpc_result(&norito::json::to_json(&block).unwrap()),
        Reply::rpc_result(&norito::json::to_json(&receipts[0]).unwrap()),
        Reply::rpc_result(&large),
    ]);
    let client = evm(&server);
    let block = client
        .block_by_number(BlockTag::Number(0x18d_af08))
        .unwrap()
        .unwrap();
    let proof = client.block_receipt_proof(&block, 0, 1_048_576).unwrap();
    assert_eq!(
        Some(proof.clone()),
        iroha_sccp::ethereum_source::mpt_proof(
            &entries,
            &iroha_sccp::ethereum_source::rlp_encode_u64(0)
        )
    );
    assert!(proof.nodes.iter().map(Vec::len).sum::<usize>() < 1_048_576);
}
