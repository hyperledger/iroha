//! Shared finite test transports and original generated-profile native execution fixtures.
//! Refusal/codec transports remain separate from actual State-derived fee and proof evidence.

use super::*;
use crate::managed::PreparedLocalnet;
use std::{
    io::{self, Read as _, Write as _},
    net::{Ipv4Addr, TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
};

pub(crate) struct Request {
    pub(crate) peer: usize,
    pub(crate) method: String,
    pub(crate) path: String,
}

pub(crate) struct UnavailablePeers {
    stop: Arc<AtomicBool>,
    pub(crate) requests: Arc<Mutex<Vec<Request>>>,
    workers: Vec<JoinHandle<io::Result<()>>>,
}

impl UnavailablePeers {
    pub(crate) fn start(prepared: &PreparedLocalnet) -> Self {
        let listeners: Vec<_> = prepared
            .peers
            .iter()
            .map(|peer| {
                let url: url::Url = peer.torii_url.parse().unwrap();
                assert_eq!(url.host_str(), Some("127.0.0.1"));
                assert_eq!(url.scheme(), "http");
                let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, url.port().unwrap()))
                    .expect("bind exactly the generated peer endpoint");
                listener.set_nonblocking(true).unwrap();
                listener
            })
            .collect();
        let capabilities = norito::json::to_vec(&norito::json!({
            "data_model_version": (iroha_data_model::DATA_MODEL_VERSION),
            "signed_transaction_schema_hash_hex":
                (hex::encode(norito::schema::identity::frame_hash::<SignedTransaction>()))
        }))
        .unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let workers = listeners
            .into_iter()
            .enumerate()
            .map(|(peer, listener)| {
                let stop = Arc::clone(&stop);
                let requests = Arc::clone(&requests);
                let capabilities = capabilities.clone();
                thread::spawn(move || {
                    while !stop.load(Ordering::SeqCst) {
                        match listener.accept() {
                            Ok((mut socket, _)) => {
                                // macOS can inherit the listener's nonblocking flag.
                                // request_line retains bounded blocking reads/writes.
                                socket.set_nonblocking(false)?;
                                let (method, path) = request_line(&mut socket)?;
                                let success = method == "GET" && path == "/v1/node/capabilities";
                                let mut seen = requests.lock().unwrap();
                                if seen.len() >= 32 {
                                    return Err(io::Error::other("HTTP fixture request cap exceeded"));
                                }
                                seen.push(Request { peer, method, path });
                                drop(seen);
                                let (status, body): (&str, &[u8]) = if success {
                                    ("200 OK", &capabilities)
                                } else {
                                    ("503 Service Unavailable", b"unavailable")
                                };
                                write!(
                                    socket,
                                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                    body.len()
                                )?;
                                socket.write_all(body)?;
                            }
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                                thread::sleep(Duration::from_millis(5));
                            }
                            Err(error) => return Err(error),
                        }
                    }
                    Ok(())
                })
            })
            .collect();
        Self {
            stop,
            requests,
            workers,
        }
    }

    pub(crate) fn finish(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        for worker in self.workers.drain(..) {
            worker
                .join()
                .expect("HTTP fixture worker panicked")
                .unwrap();
        }
    }
}

impl Drop for UnavailablePeers {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

fn request_line(socket: &mut TcpStream) -> io::Result<(String, String)> {
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    socket.set_write_timeout(Some(Duration::from_secs(2)))?;
    let mut bytes = [0; 8192];
    let mut length = 0;
    loop {
        if length == bytes.len() {
            return Err(io::Error::other("HTTP fixture header exceeds bound"));
        }
        let read = socket.read(&mut bytes[length..])?;
        if read == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        length += read;
        if bytes[..length].windows(4).any(|part| part == b"\r\n\r\n") {
            break;
        }
    }
    let line_end = bytes[..length]
        .windows(2)
        .position(|part| part == b"\r\n")
        .ok_or_else(|| io::Error::other("missing HTTP request line"))?;
    let line = std::str::from_utf8(&bytes[..line_end])
        .map_err(|_| io::Error::other("invalid HTTP request line"))?;
    let fields: Vec<_> = line.split(' ').collect();
    if fields.len() != 3 || fields[2] != "HTTP/1.1" {
        return Err(io::Error::other("invalid HTTP request line"));
    }
    Ok((fields[0].into(), fields[1].into()))
}

#[path = "test_support/native_fixture.rs"]
pub(in crate::managed) mod native_fixture;
#[path = "test_support/wallet_http.rs"]
pub(in crate::managed) mod wallet_http;

#[path = "test_support/provider_profile_tests.rs"]
mod provider_profile_tests;

#[path = "test_support/gateway_setup_native_tests.rs"]
pub(in crate::managed) mod gateway_setup_native_tests;

#[path = "test_support/preparation.rs"]
pub(in crate::managed) mod preparation;

/// Select one explicit original provider slot for a component fixture.
pub(in crate::managed) fn provider_id(
    prepared: &PreparedLocalnet,
    slot: usize,
) -> iroha_data_model::sorafs::capacity::ProviderId {
    prepared
        .stream_token_authorities()
        .unwrap()
        .unwrap()
        .providers[slot]
        .provider_id
}

#[path = "test_support/musubi_namespace_tests.rs"]
mod musubi_namespace_tests;

#[path = "test_support/amx_registration_native_tests.rs"]
mod amx_registration_native_tests;
pub(crate) use amx_registration_native_tests::with_signed_amx_preparation;

/// Exercise the shared post-carrier decision against an actual native fixture's authenticated
/// frontier and its owner's real bounded SDK proof reader. No paid wallet or source is replaced.
pub(in crate::managed) fn assert_optional_current<T>(
    peers: &UnavailablePeers,
    frontier: &FinalityVerifier,
    read: impl Fn(&FinalityVerifier) -> Result<T>,
) {
    let before = peers.requests.lock().unwrap().len();
    assert!(optional_current(false, Some(frontier), &read).is_none());
    assert_eq!(
        peers.requests.lock().unwrap().len(),
        before,
        "unrequested current reporting must not fetch a World proof after native carrier replay",
    );
    assert!(optional_current(true, None, &read).is_none());
    assert_eq!(peers.requests.lock().unwrap().len(), before);
    assert!(optional_current(true, Some(frontier), read).is_none());
    // Isolate this explicit read window from the caller's subsequent offline-recovery census.
    // An enabled current read reaches the real proof endpoint and fails closed on its 503;
    // removing the false guard fails above on these same concrete HTTP requests.
    let requests = peers.requests.lock().unwrap().split_off(before);
    assert!(requests.iter().all(|request| request.method == "GET"));
    assert!(
        requests
            .iter()
            .any(|request| request.path != "/v1/node/capabilities")
    );
}
