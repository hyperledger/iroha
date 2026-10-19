//! Full receipt adapter tests with a certified native World cut and local RPC transcripts.

use super::*;
use iroha::{
    data_model::{
        sccp::light_client::{
            SccpLcCheckpointDataV1, SccpLcCheckpointOriginV1, SccpLcCheckpointV1, SccpLcHeadV1,
            SccpLcPointV1, SccpLightClientParamsV1, SccpLightClientV1,
        },
        sumeragi_finality::{
            WorldStateElementKindV1, WorldStateSnapshotEntryV1, world_state_value_hash_v1,
        },
        testing::native_finality::NativeFinalityFixture,
    },
    http::{HttpTransport, Response, TransportFuture, TransportRequest},
};
use iroha_sccp::{
    api::{
        SccpBlockRefV1, SccpCertificateV1, SccpFinalityConstantsV1, SccpLcCheckpointCoverV1,
        SccpLcCheckpointEntryV1, SccpLcProfileStatusV1, SccpLightClientDetailV1,
        SccpMessageProofBundleV1, SccpReadLimitsV1,
    },
    ethereum_source::{
        mpt_proof, mpt_root, rlp_encode_bytes, rlp_encode_list, rlp_encode_u64,
        rlp_encode_uint_bytes,
    },
    light_client::profile::{SCCP_LC_PROFILE_NETWORKS_V1, SccpLcProfileCatalogV1},
    v1::{
        evm_abi::FinalizedLogV1,
        hashes::{keccak256, word_u64},
        payload::SccpTransferPayloadV1,
        proof::DestinationV1,
    },
};
use iroha_sccp_rpc::{
    builders::ethereum::{header_rlp, receipt_rlp},
    evm::{BlockId, EvmHeader, EvmLog, EvmReceipt, U256, format_data, format_quantity},
};
use iroha_sccp_wallet::pure::evm::{Eip1559TransactionV1, EvmSigningKey};
use norito::{json, json::Value};
use std::{
    collections::VecDeque,
    io::{BufRead as _, Write as _},
    net::TcpListener,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

const NETWORK: SccpNetworkV1 = SccpNetworkV1::EthereumMainnet;
const CONTRACT: [u8; 20] = [0x31; 20];
const CODE_HASH: [u8; 32] = [0x32; 32];

#[derive(Debug)]
struct NativeReads(Mutex<VecDeque<(String, u16, Vec<u8>)>>);
impl HttpTransport for NativeReads {
    fn send_blocking(&self, request: TransportRequest) -> Result<Response<Vec<u8>>> {
        let (expected, status, body) = self
            .0
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected native read");
        assert_eq!(request.method, iroha::http::Method::GET);
        let path = request.url.path().to_owned()
            + &request
                .url
                .query()
                .map(|s| format!("?{s}"))
                .unwrap_or_default();
        assert_eq!(path, expected);
        Ok(Response::builder()
            .status(status)
            .header("content-type", "application/json")
            .body(body)
            .unwrap())
    }
    fn send(&self, request: TransportRequest) -> TransportFuture<'_> {
        Box::pin(async move { self.send_blocking(request) })
    }
}

struct RpcRead {
    method: &'static str,
    params: Value,
    result: Value,
}
struct RpcMock {
    url: String,
    pending: Arc<Mutex<VecDeque<RpcRead>>>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}
impl RpcMock {
    fn new(reads: Vec<RpcRead>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let pending = Arc::new(Mutex::new(VecDeque::from(reads)));
        let stop = Arc::new(AtomicBool::new(false));
        let queue = Arc::clone(&pending);
        let stopped = Arc::clone(&stop);
        let worker = std::thread::spawn(move || {
            let until = Instant::now() + Duration::from_secs(10);
            while !stopped.load(Ordering::Acquire) && Instant::now() < until {
                let (mut stream, _) = match listener.accept() {
                    Ok(stream) => stream,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(e) => panic!("local RPC listener: {e}"),
                };
                Self::configure_stream(&stream);
                let mut input = std::io::BufReader::new(&mut stream);
                let mut line = String::new();
                input.read_line(&mut line).unwrap();
                assert!(line.starts_with("POST / HTTP/1.1"));
                let mut length = None;
                loop {
                    line.clear();
                    assert!(input.read_line(&mut line).unwrap() > 0);
                    if line == "\r\n" {
                        break;
                    }
                    if let Some(n) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        length = Some(n.trim().parse::<usize>().unwrap());
                    }
                }
                let length = length.expect("bounded JSON-RPC body");
                assert!(length < 8192);
                let mut body = vec![0; length];
                input.read_exact(&mut body).unwrap();
                let request: Value = norito::json::from_slice(&body).unwrap();
                let expected = queue
                    .lock()
                    .unwrap()
                    .pop_front()
                    .expect("unexpected EVM RPC");
                assert_eq!(request["method"].as_str(), Some(expected.method));
                assert_eq!(request["params"], expected.params);
                let body = norito::json::to_vec(&json!({"jsonrpc":"2.0", "id": (request["id"].clone()), "result": (expected.result)})).unwrap();
                write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
                stream.write_all(&body).unwrap();
            }
        });
        Self {
            url,
            pending,
            stop,
            worker: Some(worker),
        }
    }
    fn configure_stream(stream: &std::net::TcpStream) {
        // Accepted sockets can inherit the listener's nonblocking mode. The
        // listener polls for shutdown; request parsing uses bounded blocking I/O.
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
    }
    fn assert_drained(&self) {
        assert!(self.pending.lock().unwrap().is_empty());
    }
}
impl Drop for RpcMock {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let outcome = worker.join();
            if !std::thread::panicking() {
                outcome.unwrap();
            }
        }
    }
}

#[cfg(unix)]
#[test]
fn rpc_mock_normalizes_accepted_socket_mode_without_changing_io_deadlines() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let _client = std::net::TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (stream, _) = listener.accept().unwrap();
    // Force the inherited mode on every Unix host, including hosts whose
    // accept implementation creates a blocking socket by default.
    stream.set_nonblocking(true).unwrap();
    assert!(
        rustix::fs::fcntl_getfl(&stream)
            .unwrap()
            .contains(rustix::fs::OFlags::NONBLOCK)
    );
    RpcMock::configure_stream(&stream);
    assert!(
        !rustix::fs::fcntl_getfl(&stream)
            .unwrap()
            .contains(rustix::fs::OFlags::NONBLOCK),
        "accepted RPC sockets must block within the original I/O deadline"
    );
    assert!(
        rustix::fs::fcntl_getfl(&listener)
            .unwrap()
            .contains(rustix::fs::OFlags::NONBLOCK),
        "the listener must still poll for shutdown"
    );
    assert_eq!(stream.read_timeout().unwrap(), Some(Duration::from_secs(2)));
    assert_eq!(
        stream.write_timeout().unwrap(),
        Some(Duration::from_secs(2))
    );
}

fn rpc(method: &'static str, params: Value, result: Value) -> RpcRead {
    RpcRead {
        method,
        params,
        result,
    }
}
fn hex_nodes(nodes: &[Vec<u8>]) -> Vec<String> {
    nodes.iter().map(|n| format_data(n)).collect()
}

struct Fixture {
    origin: AuthenticatedOrigin,
    raw: Vec<u8>,
    receipt: EvmReceipt,
    block: Value,
    proof: Value,
    checkpoint: SccpLcCheckpointV1,
    light_client: SccpLightClientV1,
    bundle: SccpMessageProofBundleV1,
}
impl Fixture {
    fn new(success: bool, consumed: bool) -> Self {
        let (bundle, calldata) = message_bundle();
        let payload = SccpTransferPayloadV1::decode(&bundle.payload).unwrap();
        let event = FinalizedLogV1 {
            message_id: bundle.message_id,
            nonce: payload.nonce,
            token_amount: payload.amount,
            recipient: payload.recipient.bytes.as_slice().try_into().unwrap(),
        };
        let slot = keccak256(&[&word_u64(payload.nonce >> 8), &word_u64(4)]);
        let storage_key = keccak256(&[&slot]);
        let bit = if consumed {
            payload.nonce & 255
        } else {
            (payload.nonce + 1) & 255
        };
        let mut word = [0u8; 32];
        word[31 - bit as usize / 8] = 1 << (bit % 8);
        let storage = vec![(storage_key.to_vec(), rlp_encode_uint_bytes(&word))];
        let storage_root = mpt_root(&storage).unwrap();
        let account_key = keccak256(&[&CONTRACT]);
        let accounts = vec![(
            account_key.to_vec(),
            rlp_encode_list(&[
                rlp_encode_u64(1),
                rlp_encode_u64(0),
                rlp_encode_bytes(&storage_root),
                rlp_encode_bytes(&CODE_HASH),
            ]),
        )];
        let raw =
            Eip1559TransactionV1::contract_call(NETWORK, CONTRACT, calldata, 7, 1, 2, 100_000)
                .unwrap()
                .sign(&EvmSigningKey::from_secret([7; 32]).unwrap())
                .unwrap()
                .raw();
        let hash = keccak256(&[&raw]);
        let (topics, data) = event.encode();
        let mut receipt = EvmReceipt {
            tx_type: 2,
            status: Some(u8::from(success)),
            state_root: None,
            cumulative_gas_used: 21_000,
            logs_bloom: [0; 256],
            logs: if success {
                vec![EvmLog {
                    address: CONTRACT,
                    topics,
                    data,
                    log_index: Some(0),
                    transaction_index: Some(0),
                    transaction_hash: Some(hash),
                    block_hash: None,
                    block_number: Some(10),
                    removed: false,
                }]
            } else {
                vec![]
            },
            transaction_hash: hash,
            transaction_index: 0,
            block_hash: [0; 32],
            block_number: 10,
            gas_used: 21_000,
            effective_gas_price: None,
            from: None,
            to: Some(CONTRACT),
            contract_address: None,
            blob_gas_used: None,
            blob_gas_price: None,
        };
        let mut header = EvmHeader {
            hash: [0; 32],
            parent_hash: [1; 32],
            ommers_hash: [2; 32],
            beneficiary: [3; 20],
            state_root: mpt_root(&accounts).unwrap(),
            transactions_root: mpt_root(&[(rlp_encode_u64(0), raw.clone())]).unwrap(),
            receipts_root: mpt_root(&[(rlp_encode_u64(0), receipt_rlp(&receipt))]).unwrap(),
            logs_bloom: [0; 256],
            difficulty: U256::ZERO,
            number: 10,
            gas_limit: 1_000_000,
            gas_used: 21_000,
            timestamp: 1_700_000_000,
            extra_data: vec![],
            mix_hash: [4; 32],
            nonce: [0; 8],
            base_fee_per_gas: Some(U256::ZERO),
            withdrawals_root: None,
            blob_gas_used: None,
            excess_blob_gas: None,
            parent_beacon_block_root: None,
            requests_hash: None,
        };
        header.hash = keccak256(&[&header_rlp(&header)]);
        receipt.block_hash = header.hash;
        for log in &mut receipt.logs {
            log.block_hash = Some(header.hash);
        }
        let checkpoint = SccpLcCheckpointV1 {
            data: SccpLcCheckpointDataV1 {
                source_height: header.number,
                block_hash: header.hash,
                state_root: Some(header.state_root),
                receipts_or_tx_root: header.receipts_root,
                source_time_ms: header.timestamp * 1000,
            },
            recorded_at_taira_ms: header.timestamp * 1000 + 1,
            origin: SccpLcCheckpointOriginV1::Advance,
        };
        let light_client = SccpLightClientV1 {
            params: SccpLightClientParamsV1::defaults_for(NETWORK).unwrap(),
            head: SccpLcHeadV1 {
                latest_set_id: 9,
                latest_finalized: SccpLcPointV1 {
                    source_height: 10,
                    block_hash: header.hash,
                    source_time_ms: checkpoint.data.source_time_ms,
                },
                last_progress_taira_ms: checkpoint.recorded_at_taira_ms,
            },
            frozen: None,
            state_hash: [8; 32],
        };
        let mut snapshot = WorldStateSnapshotV1 {
            schema_hash: Hash::new(b"receipt adapter native cut"),
            entries: vec![
                WorldStateSnapshotEntryV1 {
                    field_id: "world.sccp_light_clients".into(),
                    kind: WorldStateElementKindV1::Table,
                    key_hash: Some(world_state_value_hash_v1(&NETWORK).unwrap()),
                    value_hash: world_state_value_hash_v1(&light_client).unwrap(),
                },
                WorldStateSnapshotEntryV1 {
                    field_id: "world.sccp_light_client_checkpoints".into(),
                    kind: WorldStateElementKindV1::Table,
                    key_hash: Some(world_state_value_hash_v1(&(NETWORK, 10u64)).unwrap()),
                    value_hash: world_state_value_hash_v1(&checkpoint).unwrap(),
                },
            ],
        };
        snapshot.entries.sort_by(|a, b| a.field_id.cmp(&b.field_id));
        let mut native = NativeFinalityFixture::new();
        let block = native.block_with_submitted_work(native.next_header());
        let certificate = native.certify_with_world_root(block, snapshot.root().unwrap());
        let tip = native
            .verifier()
            .verify_retained_decision(&certificate)
            .unwrap();
        let origin = AuthenticatedOrigin {
            network: *native.network_id().as_bytes(),
            instance: native.verifier().instance().0,
            world: snapshot.authenticate(&tip).unwrap(),
            element_count: snapshot.entries.len(),
            verifier: native.verifier(),
        };
        origin.verify_retained_block(&certificate).unwrap();
        let proof = json!({"address": (format_data(&CONTRACT)), "balance":"0x0", "nonce":"0x1", "codeHash": (format_data(&CODE_HASH)), "storageHash": (format_data(&storage_root)), "accountProof": (hex_nodes(&mpt_proof(&accounts, &account_key).unwrap().nodes)), "storageProof": [{"key": (format_data(&slot)), "value": (U256::from_be_bytes(word).to_quantity()), "proof": (hex_nodes(&mpt_proof(&storage, &storage_key).unwrap().nodes))}]});
        Self {
            origin,
            raw,
            receipt,
            block: block_json(&header, hash),
            proof,
            checkpoint,
            light_client,
            bundle,
        }
    }
    fn native(
        &self,
        checkpoint_status: u16,
        forge: bool,
    ) -> (iroha::blocking::Client, Arc<NativeReads>) {
        let active = SccpLcProfileCatalogV1::compiled().genesis();
        let profiles = SCCP_LC_PROFILE_NETWORKS_V1
            .into_iter()
            .map(|network| {
                let p = active.get(network).unwrap();
                SccpLcProfileStatusV1 {
                    network,
                    version: p.version,
                    profile_hash: p.profile_hash,
                    activation_height: None,
                    proposal_id: None,
                    supported_until_ms: None,
                }
            })
            .collect();
        let caps = SccpCapabilitiesV1 {
            network_id: self.origin.network,
            consensus_instance: self.origin.instance,
            finality: SccpFinalityConstantsV1::current(),
            current_generation: None,
            coalition_slashable_floor: None,
            liability_clock: 0,
            forgery_max_generation: None,
            pause_panel_ids: None,
            parliament_binding_ballot_available: false,
            reconciliation_available: false,
            parameters: None,
            committed_height: self.origin.height(),
            light_client_profiles: profiles,
            chain_id: "fixture".into(),
            profiles: vec![],
            profiles_policy_hash: active.policy_hash(),
            limits: SccpReadLimitsV1::v1(),
            path_templates: vec![],
        };
        let detail = SccpLightClientDetailV1 {
            light_client: self.light_client,
            usable: true,
            weak_subjectivity_deadline_ms: None,
            supported_until_ms: None,
            sets: Default::default(),
            checkpoints: Default::default(),
        };
        let mut checkpoint = self.checkpoint;
        if forge {
            checkpoint.data.block_hash[0] ^= 1;
        }
        let cover = SccpLcCheckpointCoverV1 {
            network: NETWORK,
            covering: 10,
            head: self.light_client.head.latest_finalized,
            nearest: SccpLcCheckpointEntryV1 {
                checkpoint,
                permanent: true,
            },
            nearest_permanent: None,
        };
        let path = format!("/v1/sccp/light-clients/{}", NETWORK.profile_key());
        let reads = Arc::new(NativeReads(Mutex::new(VecDeque::from([
            (path.clone(), 200, norito::json::to_vec(&detail).unwrap()),
            (
                "/v1/sccp/capabilities".into(),
                200,
                norito::json::to_vec(&caps).unwrap(),
            ),
            (
                format!("{path}/checkpoints?covering=10"),
                checkpoint_status,
                norito::json::to_vec(&cover).unwrap(),
            ),
        ]))));
        let client =
            iroha::blocking::Client::with_http_transport(crate::fallback_config(), reads.clone())
                .unwrap();
        (client, reads)
    }
    fn rpc_reads(&self, include_proofs: bool, finalized: bool) -> Vec<RpcRead> {
        let hash = format_data(&self.receipt.transaction_hash);
        let mut reads = vec![
            rpc("eth_chainId", json!([]), json!("0x1")),
            rpc(
                "eth_getTransactionReceipt",
                json!([(hash.clone())]),
                receipt_json(&self.receipt),
            ),
        ];
        if include_proofs {
            let mut account_proof = self.proof.clone();
            account_proof
                .as_object_mut()
                .unwrap()
                .insert("storageProof".into(), json!([]));
            reads.extend([
                rpc(
                    "eth_getBlockByNumber",
                    json!(["0xa", false]),
                    self.block.clone(),
                ),
                rpc(
                    "eth_getRawTransactionByHash",
                    json!([(hash.clone())]),
                    json!((format_data(&self.raw))),
                ),
                rpc(
                    "eth_getTransactionReceipt",
                    json!([(hash)]),
                    receipt_json(&self.receipt),
                ),
                rpc(
                    "eth_getProof",
                    json!([
                        (format_data(&CONTRACT)),
                        [],
                        (BlockId::Hash(self.receipt.block_hash).to_state_param())
                    ]),
                    account_proof,
                ),
            ]);
        }
        if finalized {
            let payload = SccpTransferPayloadV1::decode(&self.bundle.payload).unwrap();
            let slot = keccak256(&[&word_u64(payload.nonce >> 8), &word_u64(4)]);
            reads.push(rpc(
                "eth_getProof",
                json!([
                    (format_data(&CONTRACT)),
                    [(format_data(&slot))],
                    (BlockId::Hash(self.receipt.block_hash).to_state_param())
                ]),
                self.proof.clone(),
            ));
        }
        reads
    }
}

fn destination(server: &RpcMock) -> crate::sccp::evm::EvmDestination {
    let mut config = iroha_sccp_wallet::config::SccpClientConfig::from_user(
        Default::default(),
        Path::new("unused-fixture-journal"),
    )
    .unwrap();
    config.request_timeout = Duration::from_secs(2);
    crate::sccp::evm::EvmDestination::connect(
        &config,
        &server.url,
        NETWORK,
        CONTRACT,
        DestinationV1 {
            network: NETWORK,
            route_revision: 1,
            destination_word: [3; 32],
        },
        CODE_HASH,
    )
    .unwrap()
}

fn block_json(h: &EvmHeader, hash: [u8; 32]) -> Value {
    json!({"hash":(format_data(&h.hash)),"parentHash":(format_data(&h.parent_hash)),"sha3Uncles":(format_data(&h.ommers_hash)),"miner":(format_data(&h.beneficiary)),"stateRoot":(format_data(&h.state_root)),"transactionsRoot":(format_data(&h.transactions_root)),"receiptsRoot":(format_data(&h.receipts_root)),"logsBloom":(format_data(&h.logs_bloom)),"difficulty":"0x0","number":(format_quantity(h.number)),"gasLimit":(format_quantity(h.gas_limit)),"gasUsed":(format_quantity(h.gas_used)),"timestamp":(format_quantity(h.timestamp)),"extraData":"0x","mixHash":(format_data(&h.mix_hash)),"nonce":(format_data(&h.nonce)),"baseFeePerGas":"0x0","transactions":[(format_data(&hash))],"uncles":[]})
}
fn receipt_json(r: &EvmReceipt) -> Value {
    let logs:Vec<_>=r.logs.iter().map(|log|json!({"address":(format_data(&log.address)),"topics":(log.topics.iter().map(|t|format_data(t)).collect::<Vec<_>>()),"data":(format_data(&log.data)),"logIndex":"0x0","transactionIndex":"0x0","transactionHash":(format_data(&r.transaction_hash)),"blockHash":(format_data(&r.block_hash)),"blockNumber":"0xa","removed":false})).collect();
    json!({"type":"0x2","status":(format_quantity(u64::from(r.status.unwrap()))),"cumulativeGasUsed":(format_quantity(r.cumulative_gas_used)),"logsBloom":(format_data(&r.logs_bloom)),"logs":(logs),"transactionHash":(format_data(&r.transaction_hash)),"transactionIndex":"0x0","blockHash":(format_data(&r.block_hash)),"blockNumber":"0xa","gasUsed":(format_quantity(r.gas_used))})
}

fn message_bundle() -> (SccpMessageProofBundleV1, Vec<u8>) {
    // Retained published certificate material, not an invented opaque authority.
    // These adapter tests do not repeat the prior journal's bundle verification.
    let fixture: Value = norito::json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/sccp/evm_calldata_v1.json"
    )))
    .unwrap();
    let scenario = &fixture["scenario"];
    let payload = &scenario["payloads"][1];
    let cert = &scenario["certificate_100"];
    fn bytes(v: &Value) -> Vec<u8> {
        hex::decode(v.as_str().unwrap().strip_prefix("0x").unwrap()).unwrap()
    }
    let certificate = SccpCertificateV1 {
        height: 100,
        qc: bytes(&cert["qc"]).try_into().unwrap(),
        aggregate_signature: bytes(&cert["aggregate_signature"]).try_into().unwrap(),
        header: bytes(&cert["header"]).try_into().unwrap(),
        committee: cert["committee"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| bytes(v).try_into().unwrap())
            .collect(),
    };
    certificate.check_shape().unwrap();
    use iroha_sccp::v1::{
        control::{ControlLeafV1, control_leaf},
        hashes::transfer_leaf,
        merkle::PromoteOddTree,
    };
    let dest: [u8; 32] = bytes(&scenario["destination"]["destination_word"])
        .try_into()
        .unwrap();
    let taira: [u8; 32] = bytes(&scenario["taira_network_id"]).try_into().unwrap();
    let control = &scenario["control"];
    let control = ControlLeafV1 {
        route_revision: 1,
        control_nonce: control["control_nonce"].as_u64().unwrap(),
        track: u8::try_from(control["track"].as_u64().unwrap()).unwrap(),
        parliament_paused: u8::from(control["parliament_paused"].as_bool().unwrap()),
        fast_pause_until_ms: control["fast_pause_until_ms"].as_u64().unwrap(),
        certificate_id: bytes(&control["certificate_id"]).try_into().unwrap(),
        effect_hash: bytes(&control["effect_hash"]).try_into().unwrap(),
    };
    let tree = PromoteOddTree::block(&[
        transfer_leaf(
            &bytes(&scenario["payloads"][1]["message_id"])
                .try_into()
                .unwrap(),
            &dest,
        ),
        transfer_leaf(
            &bytes(&scenario["payloads"][2]["message_id"])
                .try_into()
                .unwrap(),
            &dest,
        ),
        control_leaf(&taira, NETWORK, &dest, &control).unwrap(),
    ])
    .unwrap();
    assert_eq!(tree.root().as_slice(), bytes(&scenario["block_100_root"]));
    let calldata = bytes(
        &fixture["calls"]
            .as_array()
            .unwrap()
            .iter()
            .find(|call| call["label"].as_str() == Some("finalize_direct"))
            .unwrap()["calldata"],
    );
    (
        SccpMessageProofBundleV1 {
            message_id: bytes(&payload["message_id"]).try_into().unwrap(),
            payload: bytes(&payload["payload"]),
            deadline_ms: scenario["deadline_ms"].as_u64().unwrap(),
            leaf_index: 0,
            path: tree.path(0).unwrap(),
            block: SccpBlockRefV1 {
                height: 100,
                sccp_root: bytes(&scenario["block_100_root"]).try_into().unwrap(),
                message_count: 3,
                history_index: 0,
                history_path: vec![],
            },
            certificate,
        },
        calldata,
    )
}

#[test]
fn receipt_adapter_authenticates_original_success_failure_and_finalized_state() {
    for success in [false, true] {
        let f = Fixture::new(success, true);
        let (native, reads) = f.native(200, false);
        let rpc = RpcMock::new(f.rpc_reads(true, success));
        let destination = destination(&rpc);
        let transport = destination.transport();
        let (deadline, _guard) = transport.receipt_budget(Duration::from_secs(5)).unwrap();
        let (receipt, evidence) = transport
            .receipt(&native, &f.origin, &f.raw)
            .unwrap()
            .unwrap();
        assert_eq!(receipt.status, Some(u8::from(success)));
        assert_eq!(receipt.block_hash, f.receipt.block_hash);
        assert_eq!(receipt.transaction_hash, keccak256(&[&f.raw]));
        let labels: Vec<_> = evidence.iter().map(|e| e.label.as_str()).collect();
        assert_eq!(
            labels,
            vec![
                "taira.evm_receipt_authority",
                "taira.evm_receipt_profile",
                "taira.evm_receipt_light_client",
                "taira.evm_receipt_checkpoint",
                "evm.original_transaction.proof",
                "evm.original_receipt.proof",
                "evm.original_call_target.proof",
                "evm.receipt.ancestry.0.rlp"
            ]
        );
        if success {
            let effect = transport.confirm_finalized(&receipt, &f.bundle).unwrap();
            assert_eq!(
                effect.iter().map(|e| e.label.as_str()).collect::<Vec<_>>(),
                vec![
                    "evm.finalized.account.proof",
                    "evm.finalized.consumed.proof",
                    "evm.finalized.consumed.locator"
                ]
            );
        } else {
            assert!(transport.confirm_finalized(&receipt, &f.bundle).is_err());
        }
        transport.require_receipt_deadline(deadline).unwrap();
        assert!(reads.0.lock().unwrap().is_empty());
        rpc.assert_drained();
    }
}

#[test]
fn receipt_adapter_requires_call_target_proof_for_success_and_failure() {
    for success in [false, true] {
        let mut f = Fixture::new(success, true);
        f.proof
            .as_object_mut()
            .unwrap()
            .insert("accountProof".into(), json!([]));
        let (native, reads) = f.native(200, false);
        let rpc = RpcMock::new(f.rpc_reads(true, false));
        let destination = destination(&rpc);
        let transport = destination.transport();
        let (_deadline, _guard) = transport.receipt_budget(Duration::from_secs(5)).unwrap();
        assert!(transport.receipt(&native, &f.origin, &f.raw).is_err());
        assert!(reads.0.lock().unwrap().is_empty());
        rpc.assert_drained();
    }
}

#[test]
fn receipt_adapter_waits_for_missing_checkpoint_and_rejects_forged_native_row() {
    for (status, forge) in [(404, false), (410, false), (200, true)] {
        let f = Fixture::new(true, true);
        let (native, reads) = f.native(status, forge);
        let rpc = RpcMock::new(f.rpc_reads(false, false));
        let destination = destination(&rpc);
        let transport = destination.transport();
        let (_deadline, _guard) = transport.receipt_budget(Duration::from_secs(5)).unwrap();
        let result = transport.receipt(&native, &f.origin, &f.raw);
        if forge {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap().is_none());
        }
        assert!(reads.0.lock().unwrap().is_empty());
        rpc.assert_drained();
    }
}

#[test]
fn receipt_adapter_rejects_finalized_event_without_authenticated_consumed_bit() {
    let f = Fixture::new(true, false);
    let (native, reads) = f.native(200, false);
    let rpc = RpcMock::new(f.rpc_reads(true, true));
    let destination = destination(&rpc);
    let transport = destination.transport();
    let (_deadline, _guard) = transport.receipt_budget(Duration::from_secs(5)).unwrap();
    let (receipt, _) = transport
        .receipt(&native, &f.origin, &f.raw)
        .unwrap()
        .unwrap();
    assert!(transport.confirm_finalized(&receipt, &f.bundle).is_err());
    assert!(reads.0.lock().unwrap().is_empty());
    rpc.assert_drained();
}
