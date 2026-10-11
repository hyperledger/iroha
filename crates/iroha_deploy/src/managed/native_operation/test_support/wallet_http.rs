//! Bounded original wallet transport fixture; accepted codec quotes and 503 are not native evidence.
//! The parser is also used by the separate real native quote/funding server.

use iroha_data_model::transaction::SignedTransaction;
use std::{
    io::{self, Read as _, Write as _},
    net::{Ipv4Addr, TcpListener, TcpStream},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

pub(in crate::managed) struct WalletHttpRequest {
    pub(in crate::managed) method: String,
    pub(in crate::managed) target: url::Url,
    pub(in crate::managed) body: Vec<u8>,
}

/// The real wallet HTTP client talks to canonical quote/status DTO owners, never a proof stub.
pub(in crate::managed) struct WalletHttp {
    stop: Arc<AtomicBool>,
    pub(in crate::managed) requests: Arc<Mutex<Vec<WalletHttpRequest>>>,
    worker: Option<JoinHandle<io::Result<()>>>,
}
impl WalletHttp {
    pub(in crate::managed) fn start_config(
        config: &iroha::config::Config,
        journal: PathBuf,
    ) -> Self {
        let endpoint = &config.torii_api_url;
        assert_eq!(endpoint.host_str(), Some("127.0.0.1"));
        assert_eq!(endpoint.scheme(), "http");
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, endpoint.port().unwrap())).unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let worker_stop = Arc::clone(&stop);
        let worker_requests = Arc::clone(&requests);
        let worker = thread::spawn(move || {
            while !worker_stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut socket, _)) => {
                        let request = wallet_request(&mut socket)?;
                        let (status, body) = wallet_response(&request, &journal);
                        let mut seen = worker_requests.lock().unwrap();
                        if seen.len() >= 64 {
                            return Err(io::Error::other("wallet HTTP request cap exceeded"));
                        }
                        seen.push(request);
                        drop(seen);
                        write!(
                            socket,
                            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        )?;
                        socket.write_all(&body)?;
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => return Err(error),
                }
            }
            Ok(())
        });
        Self {
            stop,
            requests,
            worker: Some(worker),
        }
    }
    pub(in crate::managed) fn finish(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.worker.take().unwrap().join().unwrap().unwrap();
    }
}
impl Drop for WalletHttp {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(worker) = self.worker.take() {
            match worker.join() {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    // Retain the original fixture failure even when the caller is unwinding.
                    // Causes here are fixed parser/cap messages or OS errors, never request data.
                    struct BoundedCause<'a> {
                        bytes: &'a mut [u8],
                        length: usize,
                    }
                    impl std::fmt::Write for BoundedCause<'_> {
                        fn write_str(&mut self, value: &str) -> std::fmt::Result {
                            let mut length = value.len().min(self.bytes.len() - self.length);
                            while !value.is_char_boundary(length) {
                                length -= 1;
                            }
                            self.bytes[self.length..self.length + length]
                                .copy_from_slice(&value.as_bytes()[..length]);
                            self.length += length;
                            if length < value.len() {
                                return Err(std::fmt::Error);
                            }
                            Ok(())
                        }
                    }
                    let mut bytes = [0; 512];
                    let mut cause = BoundedCause {
                        bytes: &mut bytes,
                        length: 0,
                    };
                    let _ = std::fmt::write(&mut cause, format_args!("{error}"));
                    let text = std::str::from_utf8(&cause.bytes[..cause.length])
                        .unwrap_or("invalid fixture error text");
                    let _ = writeln!(
                        io::stderr().lock(),
                        "wallet HTTP fixture worker failed: kind={:?} raw_os={:?} cause={text}",
                        error.kind(),
                        error.raw_os_error(),
                    );
                }
                Err(_) => {
                    let _ = writeln!(io::stderr().lock(), "wallet HTTP fixture worker panicked");
                }
            }
        }
    }
}

pub(in crate::managed) fn wallet_request(socket: &mut TcpStream) -> io::Result<WalletHttpRequest> {
    const MAX_HEADER: usize = 16 * 1024;
    const MAX_BODY: usize = 128 * 1024;
    // Darwin can inherit nonblocking mode from the listener; this parser owns bounded reads.
    socket.set_nonblocking(false)?;
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    socket.set_write_timeout(Some(Duration::from_secs(2)))?;
    let mut bytes = Vec::new();
    let header_end = loop {
        let mut chunk = [0; 4096];
        let read = socket.read(&mut chunk)?;
        if read == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        bytes.extend_from_slice(&chunk[..read]);
        if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            if end + 4 <= MAX_HEADER {
                break end + 4;
            }
        }
        if bytes.len() >= MAX_HEADER {
            return Err(io::Error::other("wallet HTTP header exceeds bound"));
        }
    };
    let header = std::str::from_utf8(&bytes[..header_end])
        .map_err(|_| io::Error::other("invalid wallet HTTP header"))?;
    let mut lines = header.split("\r\n");
    let fields: Vec<_> = lines.next().unwrap().split(' ').collect();
    if fields.len() != 3 || fields[2] != "HTTP/1.1" {
        return Err(io::Error::other("invalid wallet HTTP request line"));
    }
    let method = fields[0].to_owned();
    let target = url::Url::parse(&format!("http://127.0.0.1{}", fields[1]))
        .map_err(|_| io::Error::other("invalid wallet HTTP request target"))?;
    let mut content_length = None;
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| io::Error::other("invalid wallet HTTP header field"))?;
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(io::Error::other("unexpected wallet HTTP streaming body"));
        }
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(io::Error::other("duplicate wallet HTTP length"));
            }
            content_length = Some(
                value
                    .trim()
                    .parse::<usize>()
                    .map_err(|_| io::Error::other("invalid wallet HTTP body length"))?,
            );
        }
    }
    let length = content_length.unwrap_or(0);
    if length > MAX_BODY || bytes.len() > header_end + length {
        return Err(io::Error::other("wallet HTTP body exceeds bound"));
    }
    let mut body = bytes.split_off(header_end);
    let retained = body.len();
    body.resize(length, 0);
    socket.read_exact(&mut body[retained..])?;
    Ok(WalletHttpRequest {
        method,
        target,
        body,
    })
}

fn wallet_response(
    request: &WalletHttpRequest,
    journal: &std::path::Path,
) -> (&'static str, Vec<u8>) {
    use iroha_torii_shared::{
        ErrorDetails, ErrorEnvelope, FeeQuoteDecision, FeeQuoteObservation, FeeQuoteRequest,
        FeeQuoteResponse, PIPELINE_TRANSACTION_STATUS_NOT_FOUND_CODE,
        PipelineTransactionStatusNotFoundV1, route_catalog,
    };
    match (request.method.as_str(), request.target.path()) {
        ("GET", "/v1/node/capabilities") => (
            "200 OK",
            norito::json::to_vec(&norito::json!({
                "data_model_version": (iroha_data_model::DATA_MODEL_VERSION),
                "signed_transaction_schema_hash_hex":
                    (hex::encode(norito::schema::identity::frame_hash::<SignedTransaction>()))
            }))
            .unwrap(),
        ),
        ("POST", "/v1/fees/quote") => {
            let quote: FeeQuoteRequest = norito::json::from_slice(&request.body).unwrap();
            let response = FeeQuoteResponse {
                intent: quote.payload.fee_payment_intent().clone(),
                observation: FeeQuoteObservation {
                    ledger_time_ms: 1,
                    next_block_height: 1,
                    route_dataspace_id: iroha_model_base::topology::DataSpaceId::UNIVERSAL,
                },
                components: Vec::new(),
                capacities: Vec::new(),
                decision: FeeQuoteDecision::Accepted {
                    debit_source: iroha_data_model::nexus::FeeDebitSource::Account(
                        quote.payload.authority().clone(),
                    ),
                    program_revision: None,
                },
            };
            ("200 OK", norito::json::to_vec(&response).unwrap())
        }
        ("GET", "/v1/pipeline/transactions/status") => {
            let hash = request
                .target
                .query_pairs()
                .find(|(key, _)| key == "hash")
                .unwrap()
                .1
                .parse::<iroha_crypto::HashOf<SignedTransaction>>()
                .unwrap();
            let response = ErrorEnvelope::new(
                PIPELINE_TRANSACTION_STATUS_NOT_FOUND_CODE,
                "Missing status.",
            )
            .with_details(ErrorDetails {
                pipeline_transaction_status_not_found: Some(
                    PipelineTransactionStatusNotFoundV1::new(&hash, "global"),
                ),
                ..ErrorDetails::default()
            });
            ("404 Not Found", norito::json::to_vec(&response).unwrap())
        }
        ("POST", path) if path == route_catalog::pipeline::TRANSACTION.path() => {
            assert!(journal.join("operation.json").is_file());
            assert!(
                journal.join("submission.json").is_file(),
                "the actual wallet must durably mark its attempt before HTTP dispatch"
            );
            ("503 Service Unavailable", b"unavailable".to_vec())
        }
        (method, path) => panic!("unexpected reserve wallet HTTP request {method} {path}"),
    }
}

#[cfg(target_os = "macos")]
#[test]
fn wallet_request_restores_blocking_mode_before_bounded_http_reads() {
    use std::os::fd::AsRawFd as _;

    fn flags(socket: &TcpStream) -> io::Result<libc::c_int> {
        #[expect(
            unsafe_code,
            reason = "F_GETFL only reads status flags from this live test-owned socket descriptor"
        )]
        let flags = unsafe { libc::fcntl(socket.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(flags)
        }
    }

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    // Queue the whole request first, so the old parser can consume it without any timing race.
    client
        .write_all(b"POST /v1/fees/quote?scope=global HTTP/1.1\r\nContent-Length: 4\r\n\r\nnull")
        .unwrap();
    let (mut socket, _) = listener.accept().unwrap();
    socket.set_nonblocking(true).unwrap();
    assert_ne!(flags(&socket).unwrap() & libc::O_NONBLOCK, 0);

    let request = wallet_request(&mut socket).unwrap();

    assert_eq!(flags(&socket).unwrap() & libc::O_NONBLOCK, 0);
    assert_eq!(socket.read_timeout().unwrap(), Some(Duration::from_secs(2)));
    assert_eq!(
        socket.write_timeout().unwrap(),
        Some(Duration::from_secs(2))
    );
    assert_eq!(request.method, "POST");
    assert_eq!(
        request.target.as_str(),
        "http://127.0.0.1/v1/fees/quote?scope=global"
    );
    assert_eq!(request.body.as_slice(), b"null");
}
