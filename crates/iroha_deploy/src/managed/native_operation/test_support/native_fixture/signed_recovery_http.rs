//! Exact committed-wallet recovery over HTTP and genuine challenge-bound native finality.
//! These finite component transports never provide signing or finality acceptance substitutes.

use super::*;
use iroha_core::state::WorldReadOnly as _;
use iroha_data_model::query::{
    CommittedTransaction, CommittedTxFilters, Query, QueryWithParams,
    dsl::{CompoundPredicate, SelectorTuple},
    parameters::QueryParams,
    transaction::prelude::FindTransactions,
};
use iroha_torii_shared::{
    PipelineTransactionDetailsResponse, PipelineTransactionStatus,
    PipelineTransactionStatusResponse,
    bridge_attestation::{FinalityAttestationFailure, FinalityAttestationFailureReason},
    bridge_finality::BridgeFinalityAttestationTipMismatchV1,
    route_catalog,
};
use norito::codec::Encode as _;
use std::{collections::BTreeSet, io::Read as _, net::TcpStream, time::Instant};

/// One actual transport request; no query body or signing material is retained here.
#[derive(Debug)]
pub(in crate::managed) struct Request {
    /// Original prepared endpoint index.
    pub(in crate::managed) peer: usize,
    /// Exact HTTP method.
    pub(in crate::managed) method: String,
    /// Route without its query string.
    pub(in crate::managed) path: String,
    /// Challenge supplied by the actual finality reader, when present.
    pub(in crate::managed) challenge: Option<[u8; 32]>,
    /// Whether exact wallet status and committed details preceded this request.
    pub(in crate::managed) after_details: bool,
    /// Actual HTTP response status.
    pub(in crate::managed) status: u16,
}

struct StopOnDrop<'a>(&'a AtomicBool);
impl Drop for StopOnDrop<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// Run one original recovery against its four selected endpoints, joining every worker.
/// Finality is refused until the exact committed wallet details have been requested.
pub(in crate::managed) fn with_recovery_http<T>(
    native: &NativeFixture,
    prepared: &PreparedLocalnet,
    signed: &SignedTransaction,
    permit_finality: bool,
    action: impl FnOnce(&Mutex<Vec<Request>>) -> T,
) -> T {
    let state = native.chain.state();
    let height = state
        .committed_entrypoint_height(&signed.hash_as_entrypoint())
        .expect("the exact signed wallet transaction was genuinely committed");
    let carrier = state
        .read_finalized_execution_carrier(height, 1_000_000, 64 * 1024 * 1024)
        .unwrap();
    let indices = carrier
        .block()
        .network_entrypoints()
        .enumerate()
        .filter_map(|(index, entrypoint)| {
            (entrypoint.hash() == signed.hash_as_entrypoint()).then_some(index)
        })
        .collect::<Vec<_>>();
    assert_eq!(indices.len(), 1);
    let transaction = carrier
        .transaction_at(u32::try_from(indices[0]).unwrap(), 64 * 1024 * 1024)
        .unwrap();
    let iroha_data_model::transaction::TransactionEntrypoint::External(committed) =
        transaction.entrypoint()
    else {
        panic!("wallet recovery requires the original external input");
    };
    assert_eq!(
        committed.encode_wire_v1().unwrap(),
        signed.encode_wire_v1().unwrap()
    );
    assert!(transaction.result().is_ok());
    let details = PipelineTransactionDetailsResponse {
        hash: signed.hash_as_entrypoint().to_string(),
        transaction,
    };
    drop(carrier);
    assert_eq!(prepared.peers.len(), 4);
    let listeners = prepared
        .peers
        .iter()
        .map(|peer| {
            let endpoint: url::Url = peer.torii_url.parse().unwrap();
            assert_eq!(endpoint.scheme(), "http");
            assert_eq!(endpoint.host_str(), Some("127.0.0.1"));
            let bytes = iroha_fs::read_private(&peer.config_path, 1024 * 1024).unwrap();
            let fingerprint = Hash::new(bytes.as_slice());
            let matches = native
                .validators
                .iter()
                .filter(|(_, original)| *original == fingerprint)
                .map(|(key, _)| PeerId::new(key.public_key().clone()))
                .collect::<Vec<_>>();
            assert_eq!(
                matches.len(),
                1,
                "endpoint belongs to exactly one original validator"
            );
            let listener =
                TcpListener::bind((Ipv4Addr::LOCALHOST, endpoint.port().unwrap())).unwrap();
            listener.set_nonblocking(true).unwrap();
            (listener, matches.into_iter().next().unwrap())
        })
        .collect::<Vec<_>>();
    let stop = AtomicBool::new(false);
    let status_seen = AtomicBool::new(false);
    let details_seen = AtomicBool::new(false);
    let requests = Mutex::new(Vec::new());
    thread::scope(|scope| {
        // This guard drops before automatic scoped joins if action or a spawn unwinds.
        let stopping = StopOnDrop(&stop);
        let workers = listeners.into_iter().enumerate().map(|(peer, (listener, node))| {
            let stop = &stop;
            let status_seen = &status_seen;
            let details_seen = &details_seen;
            let requests = &requests;
            let details = &details;
            scope.spawn(move || -> io::Result<()> {
                let mut count = 0;
                while !stop.load(Ordering::SeqCst) {
                    let mut socket = match listener.accept() {
                        Ok((socket, _)) => socket,
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(2));
                            continue;
                        }
                        Err(error) => return Err(error),
                    };
                    count += 1;
                    if count > 64 {
                        return Err(io::Error::other("recovery HTTP request cap exceeded"));
                    }
                    let (request, challenge) = request(&mut socket)?;
                    let after_details = details_seen.load(Ordering::SeqCst);
                    let (status, content_type, body) = response(
                        native, signed, details, height.get() as u64, &node, &request, challenge,
                        permit_finality && after_details, status_seen, details_seen,
                    )?;
                    requests.lock().unwrap().push(Request {
                        peer, method: request.method, path: request.target.path().into(),
                        challenge, after_details, status,
                    });
                    let reason = match status { 200 => "OK", 409 => "Conflict", _ => "Service Unavailable" };
                    write!(socket, "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n", body.len())?;
                    socket.write_all(&body)?;
                }
                Ok(())
            })
        }).collect::<Vec<_>>();
        let result = action(&requests);
        drop(stopping);
        let results = workers
            .into_iter()
            .map(|worker| worker.join())
            .collect::<Vec<_>>();
        for result in results {
            result.unwrap().unwrap();
        }
        result
    })
}

/// Assert actual wallet-first ordering and independent finality with no new paid work.
pub(in crate::managed) fn assert_recovery_reads(
    requests: &Mutex<Vec<Request>>,
    permit_finality: bool,
) {
    let requests = requests.lock().unwrap();
    let reads = requests
        .iter()
        .filter(|read| read.path != "/v1/node/capabilities")
        .collect::<Vec<_>>();
    assert!(reads.len() >= 3);
    assert_eq!(
        (reads[0].method.as_str(), reads[0].path.as_str()),
        ("GET", "/v1/pipeline/transactions/status")
    );
    assert_eq!(
        (reads[1].method.as_str(), reads[1].path.as_str()),
        ("POST", route_catalog::pipeline::TRANSACTION_DETAILS.path())
    );
    assert!(reads[2..].iter().all(|read| read.method == "GET"
        && read.path.starts_with("/v1/bridge/finality/")
        && read.after_details));
    if permit_finality {
        let attestations = reads
            .iter()
            .filter(|read| {
                read.status == 200 && read.path.starts_with("/v1/bridge/finality/attestation/")
            })
            .collect::<Vec<_>>();
        assert_eq!(
            attestations.len(),
            4,
            "one complete native attestation round"
        );
        assert_eq!(
            attestations
                .iter()
                .map(|read| read.peer)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([0, 1, 2, 3])
        );
        let challenges = attestations
            .iter()
            .map(|read| read.challenge.expect("actual challenge header"))
            .collect::<BTreeSet<_>>();
        assert_eq!(challenges.len(), 1);
        assert!(!challenges.contains(&[0; 32]));
    } else {
        assert_eq!(reads.len() - 2, 4, "one bounded unavailable observation");
        assert_eq!(
            reads[2..]
                .iter()
                .map(|read| read.peer)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([0, 1, 2, 3]),
            "a 503 is not retried on the same peer"
        );
        assert!(reads[2..].iter().all(|read| read.status == 503));
    }
}

fn response(
    native: &NativeFixture,
    signed: &SignedTransaction,
    details: &PipelineTransactionDetailsResponse,
    committed_height: u64,
    node: &PeerId,
    request: &WalletHttpRequest,
    challenge: Option<[u8; 32]>,
    permit_finality: bool,
    status_seen: &AtomicBool,
    details_seen: &AtomicBool,
) -> io::Result<(u16, &'static str, Vec<u8>)> {
    let path = request.target.path();
    if request.method == "GET" && path == "/v1/node/capabilities" {
        return Ok((200, "application/json", norito::json::to_vec(&norito::json!({
            "data_model_version": (iroha_data_model::DATA_MODEL_VERSION),
            "signed_transaction_schema_hash_hex": (hex::encode(norito::schema::identity::frame_hash::<SignedTransaction>()))
        })).unwrap()));
    }
    if request.method == "GET" && path == "/v1/pipeline/transactions/status" {
        let query = request
            .target
            .query_pairs()
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(query.len(), 2);
        assert_eq!(
            query
                .get("hash")
                .unwrap()
                .parse::<iroha_crypto::HashOf<SignedTransaction>>()
                .unwrap(),
            signed.hash()
        );
        assert_eq!(
            query.get("scope").map(|value| value.as_ref()),
            Some("global")
        );
        status_seen.store(true, Ordering::SeqCst);
        return Ok((
            200,
            "application/json",
            norito::json::to_vec(&PipelineTransactionStatusResponse::new(
                hex::encode(signed.hash().as_ref()),
                PipelineTransactionStatus {
                    kind: "Applied".into(),
                    block_height: Some(committed_height),
                },
                "global".into(),
                "state".into(),
            ))
            .unwrap(),
        ));
    }
    if request.method == "POST" && path == route_catalog::pipeline::TRANSACTION_DETAILS.path() {
        assert!(status_seen.load(Ordering::SeqCst));
        let query = SignedQuery::decode_all_versioned(&request.body).unwrap();
        query.verify_signature().unwrap();
        assert_eq!(query.authority(), signed.authority());
        assert_eq!(query.payload.network_id(), native.chain.network_id());
        let QueryRequest::Start(actual) = query.request() else {
            panic!("exact committed transaction query required");
        };
        let selected = FindTransactions::new();
        let predicate = CompoundPredicate::from_filters(CommittedTxFilters {
            entry_eq: Some(signed.hash_as_entrypoint()),
            ..CommittedTxFilters::default()
        });
        let expected = QueryWithParams {
            query: (),
            query_payload: selected.dyn_encode(),
            item: selected.query_item_kind(),
            predicate_bytes: predicate.encode(),
            selector_bytes: SelectorTuple::<CommittedTransaction>::default().encode(),
            params: QueryParams::default(),
        };
        assert_eq!(actual.parts(), expected.parts());
        assert_eq!(actual.params(), expected.params());
        let view = native.chain.state().view();
        view.world().account(signed.authority()).unwrap();
        // The dedicated details route permits this exact committed input's owner. It does
        // not require the unrelated generic FindTransactions permission. These finite
        // request expectations do not qualify Torii's separate ingress replay admission.
        let now = now_ms().unwrap();
        assert!(query.payload.creation_time_ms <= now);
        assert!(
            query
                .payload
                .creation_time_ms
                .checked_add(query.payload.time_to_live_ms.get())
                .is_some_and(|expires| now < expires)
        );
        assert_ne!(query.payload.nonce, [0; 32]);
        assert!(
            !details_seen.load(Ordering::SeqCst),
            "one exact wallet details read"
        );
        let bytes = norito::encode_canonical(details).unwrap();
        details_seen.store(true, Ordering::SeqCst);
        return Ok((200, "application/x-norito", bytes));
    }
    if request.method != "GET" || !path.starts_with("/v1/bridge/finality/") {
        return Err(io::Error::other(
            "recovery transport forbids paid work and current-state queries",
        ));
    }
    if !permit_finality {
        if let Some(height) = path.strip_prefix("/v1/bridge/finality/attestation/") {
            let height = height.parse().map_err(io::Error::other)?;
            let challenge = challenge
                .filter(|challenge| *challenge != [0; 32])
                .ok_or_else(|| io::Error::other("fresh nonzero challenge required"))?;
            let failure = FinalityAttestationFailure {
                challenge,
                height,
                reason: FinalityAttestationFailureReason::FinalityUnavailable,
                tip_mismatch: None,
            };
            return Ok((
                503,
                "application/x-norito",
                norito::encode_canonical(&failure.into_error_envelope()).unwrap(),
            ));
        }
        return Ok((
            503,
            "application/x-norito",
            b"finality unavailable".to_vec(),
        ));
    }
    if let Some(height) = path.strip_prefix("/v1/bridge/finality/attestation/") {
        let height: u64 = height.parse().map_err(io::Error::other)?;
        let challenge = challenge
            .filter(|challenge| *challenge != [0; 32])
            .ok_or_else(|| io::Error::other("fresh nonzero challenge required"))?;
        if height != native.chain.height() {
            let failure = FinalityAttestationFailure {
                challenge,
                height,
                reason: FinalityAttestationFailureReason::TipChanged,
                tip_mismatch: Some(BridgeFinalityAttestationTipMismatchV1 {
                    requested_height: height,
                    applied_height: native.chain.height(),
                    status_height: native.chain.height(),
                    challenge,
                    node_id: node.clone(),
                    network_id: native.chain.network_id(),
                }),
            };
            return Ok((
                409,
                "application/x-norito",
                norito::encode_canonical(&failure.into_error_envelope()).unwrap(),
            ));
        }
        let statement = native.latest_attestation(node, &challenge)?;
        return Ok((
            200,
            "application/x-norito",
            norito::encode_canonical(statement.attestation()).unwrap(),
        ));
    }
    let height = path
        .strip_prefix("/v1/bridge/finality/")
        .unwrap()
        .parse::<u64>()
        .map_err(io::Error::other)?;
    let height = NonZeroU64::new(height).ok_or_else(|| io::Error::other("zero proof height"))?;
    let proof = native.finality_proof(height)?;
    Ok((
        200,
        "application/x-norito",
        norito::encode_canonical(&proof).unwrap(),
    ))
}

fn request(socket: &mut TcpStream) -> io::Result<(WalletHttpRequest, Option<[u8; 32]>)> {
    socket.set_nonblocking(false)?;
    socket.set_write_timeout(Some(Duration::from_secs(2)))?;
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() || header.len() == 16 * 1024 {
            return Err(io::Error::other("recovery HTTP header bound exceeded"));
        }
        socket.set_read_timeout(Some(remaining))?;
        let mut byte = [0];
        socket.read_exact(&mut byte)?;
        header.push(byte[0]);
    }
    let header = std::str::from_utf8(&header).map_err(io::Error::other)?;
    let mut lines = header.split("\r\n");
    let fields = lines.next().unwrap().split_whitespace().collect::<Vec<_>>();
    if fields.len() != 3 || fields[2] != "HTTP/1.1" {
        return Err(io::Error::other("invalid request line"));
    }
    let target =
        url::Url::parse(&format!("http://127.0.0.1{}", fields[1])).map_err(io::Error::other)?;
    let mut length = None;
    let mut challenge = None;
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| io::Error::other("invalid request header"))?;
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(io::Error::other("streaming request forbidden"));
        }
        if name.eq_ignore_ascii_case("content-length") {
            if length.is_some() {
                return Err(io::Error::other("duplicate request length"));
            }
            length = Some(value.trim().parse::<usize>().map_err(io::Error::other)?);
        }
        if name.eq_ignore_ascii_case("x-iroha-finality-challenge") {
            if challenge.is_some() {
                return Err(io::Error::other("duplicate challenge"));
            }
            challenge = Some(
                hex::decode(value.trim())
                    .map_err(io::Error::other)?
                    .try_into()
                    .map_err(|_| io::Error::other("invalid challenge width"))?,
            );
        }
    }
    let length = length.unwrap_or(0);
    if length > 128 * 1024 {
        return Err(io::Error::other("request body bound exceeded"));
    }
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(io::Error::other("request body deadline"));
    }
    socket.set_read_timeout(Some(remaining))?;
    let mut body = vec![0; length];
    socket.read_exact(&mut body)?;
    Ok((
        WalletHttpRequest {
            method: fields[0].into(),
            target,
            body,
        },
        challenge,
    ))
}
