//! Real SDK HTTP decoding keeps the caller's cumulative native admission and peer order.

use super::*;
use crate::verify::http::{HttpFinalityError, HttpFinalitySource};
use iroha::client::Client;
use norito::core::DecodeBudgetContext;
use std::{io::Read as _, net::TcpStream, sync::Condvar, time::Instant};

const ORIGINAL_CHALLENGE: [u8; 32] = [91; 32];
const RETRY_CHALLENGE: [u8; 32] = [92; 32];

#[test]
fn http_finality_batch_preserves_cumulative_native_decode_admission_and_retry() {
    with_generated_chain(4, check_http_admission);
}

#[inline(never)]
fn check_http_admission(native: &NativeFixture, authority: &ServiceAuthority) {
    let selected = native
        .validators
        .iter()
        .rev()
        .map(|(key, _)| PeerId::new(key.public_key().clone()))
        .collect::<Vec<_>>();
    let (mut server, clients) = AttestationHttp::start(native, authority, &selected);
    let source = HttpFinalitySource::new(
        authority.config.network_id,
        NonZeroU64::new(native.chain.height()).unwrap(),
        clients.iter().map(|(_, client)| client.clone()).collect(),
        clients,
        Instant::now() + Duration::from_secs(60),
    )
    .unwrap();

    // All four real requests must reach their independent endpoint before any first
    // attestation response is released. Capability probes are warmed outside admission.
    let warm = source.latest_attestations(&selected, &ORIGINAL_CHALLENGE);
    for (peer, result) in selected.iter().zip(warm) {
        let actual = result.unwrap();
        actual.attestation().verify().unwrap();
        assert_eq!(&actual.attestation().body.node_id, peer);
        assert_eq!(actual.attestation().body.challenge, ORIGINAL_CHALLENGE);
        assert_eq!(
            actual.attestation().body.network_id,
            authority.config.network_id
        );
        assert_eq!(actual.attestation().body.status.applied_height, 4);
    }
    assert_eq!(*server.first_round.0.lock().unwrap(), selected.len());

    // Calibrate one complete physical SDK response, including both native proof decodes.
    // The HTTP fixture retains its actual immutable native bytes, so the serial replay
    // below has exactly the same producer input and no cold capability-probe variability.
    let calibration = DecodeBudgetContext::new(limits(usize::MAX));
    calibration
        .with(|| source.latest_attestation(&selected[0], &ORIGINAL_CHALLENGE))
        .unwrap();
    let one_read = usize::try_from(calibration.consumed_allocated_bytes()).unwrap();
    assert!(one_read > 1);

    for cap in [0, 1, one_read] {
        server.requests.lock().unwrap().clear();
        let serial_budget = DecodeBudgetContext::new(limits(cap));
        let serial = serial_budget.with(|| {
            selected
                .iter()
                .map(|peer| source.latest_attestation(peer, &ORIGINAL_CHALLENGE))
                .collect::<Vec<_>>()
        });
        let serial_order = server.requests.lock().unwrap().clone();
        let expected_order = (0..selected.len())
            .map(|slot| (slot, ORIGINAL_CHALLENGE))
            .collect::<Vec<_>>();
        assert_eq!(serial_order, expected_order);
        assert_eq!(serial.len(), selected.len());
        if cap == one_read {
            assert!(
                serial[0].is_ok(),
                "one complete original response is admitted"
            );
            assert!(serial[1..].iter().all(|result| result.is_err()));
        } else {
            assert!(serial.iter().all(|result| result.is_err()));
        }

        server.requests.lock().unwrap().clear();
        let batch_budget = DecodeBudgetContext::new(limits(cap));
        let batch =
            batch_budget.with(|| source.latest_attestations(&selected, &ORIGINAL_CHALLENGE));
        assert_eq!(batch.len(), serial.len());
        for (actual, expected) in batch.into_iter().zip(serial) {
            match (actual, expected) {
                (Ok(actual), Ok(expected)) => {
                    assert_eq!(actual.attestation(), expected.attestation());
                }
                (Err(actual), Err(expected)) => {
                    assert_eq!(actual, expected);
                    assert_eq!(actual, HttpFinalityError::Read);
                }
                _ => panic!("HTTP batch changed the original caller's decode admission"),
            }
        }
        assert_eq!(
            batch_budget.consumed_allocated_bytes(),
            serial_budget.consumed_allocated_bytes()
        );
        assert_eq!(*server.requests.lock().unwrap(), expected_order);
    }

    // A refused owner cannot poison the source or erase independently selected peers.
    assert!(!norito::core::decode_limits_active());
    for (peer, result) in selected
        .iter()
        .zip(source.latest_attestations(&selected, &RETRY_CHALLENGE))
    {
        let actual = result.unwrap();
        actual.attestation().verify().unwrap();
        assert_eq!(&actual.attestation().body.node_id, peer);
        assert_eq!(actual.attestation().body.challenge, RETRY_CHALLENGE);
    }
    server.finish();
}

fn limits(allocated: usize) -> norito::DecodeLimits {
    norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, allocated, 64)
}

type RequestLog = Arc<Mutex<Vec<(usize, [u8; 32])>>>;
type FirstRound = Arc<(Mutex<usize>, Condvar)>;

// Only complete statements from the genuine native State producer cross into these
// finite transport threads. No key, authority, proof stub or fabricated verdict does.
struct AttestationHttp {
    stop: Arc<AtomicBool>,
    requests: RequestLog,
    first_round: FirstRound,
    workers: Vec<JoinHandle<io::Result<()>>>,
}

impl AttestationHttp {
    fn start(
        native: &NativeFixture,
        authority: &ServiceAuthority,
        peers: &[PeerId],
    ) -> (Self, Vec<(PeerId, Client)>) {
        let capabilities = norito::json::to_vec(&norito::json!({
            "data_model_version": (iroha_data_model::DATA_MODEL_VERSION),
            "signed_transaction_schema_hash_hex":
                (hex::encode(norito::schema::identity::frame_hash::<SignedTransaction>()))
        }))
        .unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let first_round = Arc::new((Mutex::new(0), Condvar::new()));
        // Install the join owner before producing or admitting any subsequent endpoint.
        let mut server = Self {
            stop,
            requests,
            first_round,
            workers: Vec::new(),
        };
        let mut clients = Vec::new();
        for (slot, peer) in peers.iter().enumerate() {
            let original = native
                .latest_attestation(peer, &ORIGINAL_CHALLENGE)
                .unwrap();
            let retry = native.latest_attestation(peer, &RETRY_CHALLENGE).unwrap();
            original.attestation().verify().unwrap();
            retry.attestation().verify().unwrap();
            let bodies = [
                norito::encode_canonical(original.attestation()).unwrap(),
                norito::encode_canonical(retry.attestation()).unwrap(),
            ];
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            listener.set_nonblocking(true).unwrap();
            let mut config = authority.config.clone();
            config.torii_api_url = format!("http://{}/", listener.local_addr().unwrap())
                .parse()
                .unwrap();
            clients.push((peer.clone(), Client::builder(config).build().unwrap()));
            let stop = Arc::clone(&server.stop);
            let requests = Arc::clone(&server.requests);
            let first_round = Arc::clone(&server.first_round);
            let capabilities = capabilities.clone();
            let members = peers.len();
            let route = iroha_torii_shared::route_catalog::sumeragi::BRIDGE_FINALITY_ATTESTATION
                .path()
                .replace("{height}", &native.chain.height().to_string());
            server.workers.push(thread::spawn(move || {
                let mut read_count = 0;
                let mut first = true;
                while !stop.load(Ordering::SeqCst) {
                    let mut socket = match listener.accept() {
                        Ok((socket, _)) => socket,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(2));
                            continue;
                        }
                        Err(error) => return Err(error),
                    };
                    read_count += 1;
                    if read_count > 16 {
                        return Err(io::Error::other("native attestation HTTP request cap"));
                    }
                    let (target, challenge) = request(&mut socket)?;
                    let (content_type, body) = if target == "/v1/node/capabilities" {
                        ("application/json", capabilities.as_slice())
                    } else if target == route {
                        let index = match challenge {
                            Some(ORIGINAL_CHALLENGE) => 0,
                            Some(RETRY_CHALLENGE) => 1,
                            _ => return Err(io::Error::other("unexpected native challenge")),
                        };
                        requests.lock().unwrap().push((slot, challenge.unwrap()));
                        if first {
                            first = false;
                            join_first_round(&first_round, members)?;
                        }
                        ("application/x-norito", bodies[index].as_slice())
                    } else {
                        return Err(io::Error::other("unexpected native HTTP route"));
                    };
                    write!(
                        socket,
                        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    )?;
                    socket.write_all(body)?;
                }
                Ok(())
            }));
        }
        (server, clients)
    }

    fn close(&mut self) -> Vec<thread::Result<io::Result<()>>> {
        self.stop.store(true, Ordering::SeqCst);
        self.workers.drain(..).map(JoinHandle::join).collect()
    }

    fn finish(&mut self) {
        // Join every worker before surfacing any one transport failure.
        let results = self.close();
        for result in results {
            result.unwrap().unwrap();
        }
    }
}

impl Drop for AttestationHttp {
    fn drop(&mut self) {
        // Preserve the original assertion during unwind while still joining every read.
        let _ = self.close();
    }
}

fn join_first_round(round: &FirstRound, members: usize) -> io::Result<()> {
    let (count, changed) = round.as_ref();
    let mut arrived = count.lock().unwrap();
    *arrived += 1;
    changed.notify_all();
    let deadline = Instant::now() + Duration::from_secs(3);
    while *arrived < members {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::other("independent HTTP reads did not overlap"));
        }
        arrived = changed.wait_timeout(arrived, remaining).unwrap().0;
    }
    Ok(())
}

fn request(socket: &mut TcpStream) -> io::Result<(String, Option<[u8; 32]>)> {
    socket.set_nonblocking(false)?;
    socket.set_read_timeout(Some(Duration::from_secs(2)))?;
    socket.set_write_timeout(Some(Duration::from_secs(2)))?;
    let mut bytes = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(2);
    while !bytes.ends_with(b"\r\n\r\n") {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::other("native HTTP header deadline"));
        }
        socket.set_read_timeout(Some(remaining))?;
        if bytes.len() == 16 * 1024 {
            return Err(io::Error::other("native HTTP header cap"));
        }
        let mut byte = [0; 1];
        socket.read_exact(&mut byte)?;
        bytes.push(byte[0]);
    }
    let header =
        std::str::from_utf8(&bytes).map_err(|_| io::Error::other("invalid native HTTP header"))?;
    let mut lines = header.split("\r\n");
    let mut first = lines.next().unwrap().split_whitespace();
    if first.next() != Some("GET") {
        return Err(io::Error::other("native fixture permits reads only"));
    }
    let target = first
        .next()
        .ok_or_else(|| io::Error::other("native HTTP request target absent"))?
        .to_owned();
    let mut challenge = None;
    for line in lines {
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("x-iroha-finality-challenge")
        {
            if challenge.is_some() {
                return Err(io::Error::other("duplicate native challenge"));
            }
            challenge = Some(
                hex::decode(value.trim())
                    .ok()
                    .and_then(|bytes| bytes.try_into().ok())
                    .ok_or_else(|| io::Error::other("invalid native challenge"))?,
            );
        }
    }
    Ok((target, challenge))
}
