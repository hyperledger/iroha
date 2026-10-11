use axum::{
    Router,
    body::{Body, Bytes},
    extract::{
        State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, HeaderValue, Response, StatusCode, Uri, header},
    response::IntoResponse,
    routing::{get, post},
};
use color_eyre::{Result, eyre::eyre};
use iroha_crypto::{Hash, HashOf};
use iroha_data_model::{
    block::{
        SignedBlock,
        consensus::SumeragiDiagnosticsStatus,
        execution_output::{ExecutionOutputV1, NetworkExecutionOutputV1},
        output_budget::ExecutionOutputLimits,
        stream::{BlockMessage, BlockSubscriptionRequest},
    },
    events::{
        EventBox,
        pipeline::{PipelineEventBox, TransactionEvent, TransactionStatus},
        stream::{EventMessage, EventSubscriptionRequest},
    },
    sumeragi::SumeragiStatus,
    transaction::{FeePaymentIntent, TransactionBuilder},
};
use iroha_model_base::{topology::DataSpaceId, topology::LaneId};
use iroha_torii_shared::status::{
    CryptoStatus, DiagnosticTraceStatus, GovernanceManifestAdmissionCounters,
    GovernanceManifestQuorumCounters, GovernanceProposalCounters,
    GovernanceProtectedNamespaceCounters, GovernanceStatus, Status as TelemetryStatus,
    TxGossipSnapshot, Uptime,
};
use iroha_torii_shared::{NORITO_V1_WEBSOCKET_SUBPROTOCOL, route_catalog as torii_routes};
use norito::json::{self, Value};
use parking_lot::Mutex;
use std::{fs, net::SocketAddr, num::NonZeroU64, path::Path, sync::Arc, time::Duration};
use tokio::{
    net::TcpListener,
    sync::{broadcast, oneshot},
    task::JoinHandle,
};
#[path = "mock_stream_auth.rs"]
mod stream_auth;
use stream_auth::StreamAuthority;
fn canonical_block_stream_message() -> Vec<u8> {
    let signer = mochi_core::development_signing_authorities()
        .first()
        .expect("development signer must exist");
    let mut transaction = TransactionBuilder::new_genesis(
        signer.account_id().clone(),
        FeePaymentIntent::authority(Vec::new(), None),
    );
    transaction.set_creation_time(Duration::from_secs(42));
    let transaction = transaction
        .with_instructions(std::iter::empty::<iroha_data_model::isi::InstructionBox>())
        .sign(signer.key_pair().private_key());
    let mut block = SignedBlock::genesis(
        vec![transaction],
        signer.key_pair().private_key(),
        None,
        None,
    );
    block
        .set_execution_outputs(
            vec![ExecutionOutputV1::Network(NetworkExecutionOutputV1 {
                input_index: 0,
                result: Ok(iroha_data_model::transaction::DataTriggerSequence::default()).into(),
                completions: Vec::new(),
            })],
            1,
            Default::default(),
            Vec::new(),
            Default::default(),
            Default::default(),
            &ExecutionOutputLimits {
                max_outputs: 1,
                max_output_bytes: 64 * 1024,
                max_total_output_bytes: 64 * 1024,
                max_executed_wire_bytes: 1024 * 1024,
            },
        )
        .expect("attach canonical successful mock block result");
    let final_signature = iroha_data_model::block::BlockSignature::new(
        0,
        iroha_crypto::SignatureOf::try_from_hash(signer.key_pair().private_key(), block.hash())
            .expect("sign result-bearing mock block"),
    );
    block
        .replace_signatures(
            iroha_data_model::block::BlockSignatures::try_from_iter([final_signature])
                .expect("single finalized block signature"),
        )
        .expect("replace result-bearing mock-block signature");
    {
        let mut final_signatures = block.signatures();
        let final_signature = final_signatures
            .next()
            .expect("result-bearing mock-block signature");
        assert_eq!(final_signature.index(), 0);
        assert!(final_signatures.next().is_none());
        final_signature
            .signature()
            .verify_hash(signer.key_pair().public_key(), block.hash())
            .expect("verify result-bearing mock-block signature");
    }
    norito::to_bytes(&BlockMessage(block)).expect("canonical block message must encode")
}
fn canonical_event_stream_message() -> Vec<u8> {
    let event = EventMessage::new(EventBox::Pipeline(PipelineEventBox::Transaction(
        TransactionEvent {
            hash: HashOf::from_untyped_unchecked(Hash::new(b"mochi-mock-transaction")),
            block_height: Some(NonZeroU64::MIN),
            lane_id: LaneId::new(0),
            dataspace_id: DataSpaceId::new(0),
            status: TransactionStatus::Approved,
        },
    )));
    norito::to_bytes(&event).expect("canonical event message must encode")
}
/// Deterministic payloads served by the mock Torii instance.
#[derive(Clone, Debug)]
pub struct MockToriiData {
    /// Snapshot returned from `GET /status`.
    pub status: TelemetryStatus,
    /// Snapshot returned from `GET /v1/sumeragi/status`.
    pub sumeragi: SumeragiStatus,
    /// Snapshot returned from `GET /v1/sumeragi/diagnostics`.
    pub sumeragi_diagnostics: SumeragiDiagnosticsStatus,
    /// JSON payload returned from `GET /v1/configuration`.
    pub configuration: Value,
    /// Prometheus metrics payload returned from `GET /metrics`.
    pub metrics: String,
    /// Raw bytes returned from `POST /v1/query`.
    pub query_response: Vec<u8>,
    /// Binary `BlockMessage` frame broadcast on `/v1/blocks/stream`.
    pub block_frame: Vec<u8>,
    /// Binary `EventMessage` frame broadcast on `/v1/events/ws`.
    pub event_frame: Vec<u8>,
}
impl Default for MockToriiData {
    fn default() -> Self {
        let governance = GovernanceStatus {
            proposals: GovernanceProposalCounters::default(),
            protected_namespace: GovernanceProtectedNamespaceCounters::default(),
            manifest_admission: GovernanceManifestAdmissionCounters::default(),
            manifest_quorum: GovernanceManifestQuorumCounters::default(),
            recent_manifest_activations: Vec::new(),
            sealed_lanes_total: 0,
            sealed_lane_aliases: Vec::new(),
            citizens_total: 0,
        };
        let status = TelemetryStatus {
            build: Default::default(),
            observed_at_ms: 0,
            peers: 2,
            blocks: 5,
            blocks_non_empty: 3,
            commit_time_ms: 42,
            txs_approved: 7,
            txs_rejected: 1,
            last_rejection_at_ms: None,
            txs_rejected_recent_5m: 0,
            uptime: Uptime(Duration::from_secs(123)),
            view_changes: 0,
            queue_size: 4,
            queue_queued: 4,
            queue_inflight: 0,
            last_block_committed_at_ms: 0,
            last_non_empty_block_committed_at_ms: 0,
            time_since_last_block_ms: 0,
            time_since_last_non_empty_block_ms: 0,
            crypto: CryptoStatus {
                sm_helpers_available: true,
                sm_openssl_preview_enabled: false,
                trace: DiagnosticTraceStatus::default(),
            },
            nexus: None,
            stack: Default::default(),
            sumeragi: None,
            governance,
            teu_lane_commit: Vec::new(),
            teu_dataspace_backlog: Vec::new(),
            dataspace_catalog: Vec::new(),
            tx_gossip: TxGossipSnapshot::default(),
            taikai_ingest: Vec::new(),
            taikai_alias_rotations: Vec::new(),
            da_receipt_cursors: Vec::new(),
        };
        let sumeragi = SumeragiStatus {
            protocol_version: iroha_data_model::sumeragi::PROTOCOL_VERSION,
            config_fingerprint: Hash::new(b"mochi-mock-config"),
            beacon_horizon: None,
            instance: [0x41; 32],
            height: 10,
            view: 4,
            stage: 0,
            leader: None,
            proxy_tail: None,
            high_qc_view: None,
            level: 0,
            start_level: 0,
            t_retx_ms: 100,
            committed_height: 9,
            applied_height: 9,
            awaiting: false,
            signer: None,
            unanchored: false,
            abstaining: true,
            halted: None,
            footprint: Default::default(),
        };
        let sumeragi_diagnostics = SumeragiDiagnosticsStatus {
            tx_queue_depth: 4,
            tx_queue_capacity: 1024,
            tx_queue_retained_bytes: 0,
            tx_queue_max_retained_bytes: 1,
            tx_queue_saturated: false,
            tx_queue_saturated_by_count: false,
            tx_queue_saturated_by_bytes: false,
            tx_queue_saturated_by_age: false,
            tx_queue_oldest_queued_age_ms: 0,
            npos: None,
            lane_governance_sealed_total: 0,
            lane_governance_sealed_aliases: Vec::new(),
            lane_governance: Vec::new(),
        };
        let configuration = norito::json!({
            "torii": {
                "address": "127.0.0.1:5555",
                "public_address": "127.0.0.1:5555"
            },
            "network": {
                "address": "127.0.0.1:1337"
            }
        });
        Self {
            status,
            sumeragi,
            sumeragi_diagnostics,
            configuration,
            metrics: "iroha_blocks_total 5\n".to_owned(),
            query_response: vec![0x13, 0x37],
            block_frame: canonical_block_stream_message(),
            event_frame: canonical_event_stream_message(),
        }
    }
}
impl MockToriiData {
    /// Load deterministic HTTP fixtures and pair them with stream messages encoded from the
    /// current Torii DTO schema.
    pub fn from_fixture_dir(dir: impl AsRef<Path>) -> Result<Self> {
        let dir = dir.as_ref();
        let read_bytes = |path: &Path| -> Result<Vec<u8>> {
            fs::read(path).map_err(|err| eyre!("failed to read {}: {err}", path.display()))
        };
        let read_string = |path: &Path| -> Result<String> {
            fs::read_to_string(path)
                .map_err(|err| eyre!("failed to read {}: {err}", path.display()))
        };
        let status_path = dir.join("status.json");
        let status_bytes = read_bytes(&status_path)?;
        let status: TelemetryStatus = norito::json::from_slice(&status_bytes).map_err(|err| {
            eyre!(
                "failed to decode Torii status fixture {}: {err}",
                status_path.display()
            )
        })?;
        let sumeragi_path = dir.join("sumeragi.json");
        let sumeragi_bytes = read_bytes(&sumeragi_path)?;
        let sumeragi: SumeragiStatus =
            norito::json::from_slice(&sumeragi_bytes).map_err(|err| {
                eyre!(
                    "failed to decode Sumeragi status fixture {}: {err}",
                    sumeragi_path.display()
                )
            })?;
        let sumeragi_diagnostics_path = dir.join("sumeragi_diagnostics.json");
        let sumeragi_diagnostics_bytes = read_bytes(&sumeragi_diagnostics_path)?;
        let sumeragi_diagnostics: SumeragiDiagnosticsStatus =
            norito::json::from_slice(&sumeragi_diagnostics_bytes).map_err(|err| {
                eyre!(
                    "failed to decode Sumeragi diagnostics fixture {}: {err}",
                    sumeragi_diagnostics_path.display()
                )
            })?;
        let configuration_path = dir.join("configuration.json");
        let configuration_bytes = read_bytes(&configuration_path)?;
        let configuration: Value =
            norito::json::from_slice(&configuration_bytes).map_err(|err| {
                eyre!(
                    "failed to decode configuration fixture {}: {err}",
                    configuration_path.display()
                )
            })?;
        let metrics_path = dir.join("metrics.prom");
        let metrics = read_string(&metrics_path)?;
        let query_path = dir.join("query.bin");
        let query_response = read_bytes(&query_path)?;
        Ok(Self {
            status,
            sumeragi,
            sumeragi_diagnostics,
            configuration,
            metrics,
            query_response,
            block_frame: canonical_block_stream_message(),
            event_frame: canonical_event_stream_message(),
        })
    }
}
#[derive(Clone)]
struct MockToriiBytes {
    status_bytes: Vec<u8>,
    sumeragi_bytes: Vec<u8>,
    sumeragi_diagnostics_bytes: Vec<u8>,
    configuration_bytes: Vec<u8>,
    metrics: String,
    query_response: Vec<u8>,
}
#[derive(Clone)]
struct AppState {
    stream_authority: Option<Arc<StreamAuthority>>,
    bytes: Arc<Mutex<MockToriiBytes>>,
    block_tx: broadcast::Sender<MockToriiFrame>,
    event_tx: broadcast::Sender<MockToriiFrame>,
    default_block_frame: Arc<Mutex<Vec<u8>>>,
    default_event_frame: Arc<Mutex<Vec<u8>>>,
}
/// Builder for spawning a [`MockTorii`] server with deterministic fixtures.
#[derive(Debug, Clone)]
pub struct MockToriiBuilder {
    addr: SocketAddr,
    data: MockToriiData,
    stream_authority: Option<Arc<StreamAuthority>>,
}
impl MockToriiBuilder {
    /// Create a new builder bound to the provided socket address.
    #[must_use]
    pub fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            data: MockToriiData::default(),
            stream_authority: None,
        }
    }
    /// Require canonical signatures from this exact account and genesis network.
    #[must_use]
    pub fn stream_reader(mut self, reader: &iroha::client::AccountClient) -> Self {
        self.stream_authority = Some(Arc::new(StreamAuthority::new(reader)));
        self
    }
    /// Override the initial block WebSocket frame.
    #[must_use]
    pub fn block_frame(mut self, frame: Vec<u8>) -> Self {
        self.data.block_frame = frame;
        self
    }
    /// Override the initial event WebSocket frame.
    #[must_use]
    pub fn event_frame(mut self, frame: Vec<u8>) -> Self {
        self.data.event_frame = frame;
        self
    }
    /// Populate the builder with fixtures loaded from `dir`.
    pub fn fixture_dir(mut self, dir: impl AsRef<Path>) -> Result<Self> {
        self.data = MockToriiData::from_fixture_dir(dir)?;
        Ok(self)
    }
    /// Spawn the mock server and return a handle for driving it.
    pub async fn spawn(self) -> Result<MockTorii> {
        MockTorii::spawn(self.addr, self.data, self.stream_authority).await
    }
}
/// Frames that can be pushed onto the mock Torii WebSocket feeds.
#[derive(Clone, Debug)]
pub enum MockToriiFrame {
    /// UTF-8 frame delivered as a text message.
    Text(String),
    /// Binary frame delivered verbatim.
    Binary(Vec<u8>),
    /// Close signal propagated to connected clients.
    Close,
}
impl MockToriiFrame {
    fn into_message(self) -> Message {
        match self {
            Self::Text(text) => Message::Text(text.into()),
            Self::Binary(bytes) => Message::Binary(Bytes::from(bytes)),
            Self::Close => Message::Close(None),
        }
    }
}
/// Running mock Torii instance.
pub struct MockTorii {
    addr: SocketAddr,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
    state: AppState,
}
impl MockTorii {
    /// Number of authenticated, non-replayed stream upgrades accepted by the mock.
    pub fn authenticated_stream_count(&self) -> usize {
        self.state
            .stream_authority
            .as_ref()
            .map_or(0, |authority| authority.accepted())
    }
    async fn spawn(
        addr: SocketAddr,
        data: MockToriiData,
        stream_authority: Option<Arc<StreamAuthority>>,
    ) -> Result<Self> {
        let bytes = MockToriiBytes {
            status_bytes: norito::to_bytes(&data.status)?,
            sumeragi_bytes: norito::to_bytes(&data.sumeragi)?,
            sumeragi_diagnostics_bytes: norito::to_bytes(&data.sumeragi_diagnostics)?,
            configuration_bytes: json::to_vec_pretty(&data.configuration)?,
            metrics: data.metrics,
            query_response: data.query_response,
        };
        let bytes = Arc::new(Mutex::new(bytes));
        let default_block_frame = Arc::new(Mutex::new(data.block_frame));
        let default_event_frame = Arc::new(Mutex::new(data.event_frame));
        let (block_tx, _) = broadcast::channel(32);
        let (event_tx, _) = broadcast::channel(32);
        let state = AppState {
            stream_authority,
            bytes,
            block_tx,
            event_tx,
            default_block_frame,
            default_event_frame,
        };
        let listener = TcpListener::bind(addr).await?;
        let addr = listener.local_addr()?;
        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let router = Router::new()
            .route("/status", get(handle_status))
            .route("/v1/sumeragi/status", get(handle_sumeragi_status))
            .route("/v1/sumeragi/diagnostics", get(handle_sumeragi_diagnostics))
            .route(
                torii_routes::core::CONFIGURATION_GET.path(),
                get(handle_configuration),
            )
            .route("/metrics", get(handle_metrics))
            .route(
                torii_routes::pipeline::TRANSACTION.path(),
                post(handle_transaction),
            )
            .route(torii_routes::pipeline::QUERY.path(), post(handle_query))
            .route(
                torii_routes::streaming::BLOCKS_WS.path(),
                get(handle_block_stream),
            )
            .route(
                torii_routes::streaming::SUBSCRIPTION_WS.path(),
                get(handle_event_stream),
            )
            .with_state(state.clone());
        let server =
            axum::serve(listener, router.into_make_service()).with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            });
        let task = tokio::spawn(async move {
            if let Err(err) = server.await {
                eprintln!("mock Torii server error: {err}");
            }
        });
        Ok(Self {
            addr,
            shutdown: Some(shutdown_tx),
            task: Some(task),
            state,
        })
    }
    /// Socket address the server listens on.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }
    /// Broadcast a frame on the `/v1/events/ws` feed.
    pub fn broadcast_event(&self, frame: MockToriiFrame) {
        if let MockToriiFrame::Binary(bytes) = &frame {
            let mut guard = self.state.default_event_frame.lock();
            *guard = bytes.clone();
        }
        let _ = self.state.event_tx.send(frame);
    }
    /// Signal the server to shut down and wait for completion.
    pub async fn shutdown(mut self) -> Result<()> {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(task) = self.task.take() {
            task.await
                .map_err(|err| eyre!("mock Torii task aborted: {err}"))?;
        }
        Ok(())
    }
}
impl Drop for MockTorii {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}
async fn handle_status(State(state): State<AppState>) -> impl IntoResponse {
    let bytes = state.bytes.lock().status_bytes.clone();
    binary_response(bytes, "application/norito")
}
async fn handle_sumeragi_status(State(state): State<AppState>) -> impl IntoResponse {
    let bytes = state.bytes.lock().sumeragi_bytes.clone();
    binary_response(bytes, "application/norito")
}
async fn handle_sumeragi_diagnostics(State(state): State<AppState>) -> impl IntoResponse {
    let bytes = state.bytes.lock().sumeragi_diagnostics_bytes.clone();
    binary_response(bytes, "application/norito")
}
async fn handle_configuration(State(state): State<AppState>) -> impl IntoResponse {
    let bytes = state.bytes.lock().configuration_bytes.clone();
    binary_response(bytes, "application/json")
}
async fn handle_metrics(State(state): State<AppState>) -> impl IntoResponse {
    let metrics = state.bytes.lock().metrics.clone();
    Response::builder()
        .status(StatusCode::OK)
        .header(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; charset=utf-8"),
        )
        .body(Body::from(metrics))
        .expect("metrics response")
}
async fn handle_transaction() -> impl IntoResponse {
    StatusCode::ACCEPTED
}
async fn handle_query(State(state): State<AppState>) -> impl IntoResponse {
    let bytes = state.bytes.lock().query_response.clone();
    binary_response(bytes, "application/octet-stream")
}
async fn handle_block_stream(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
    ws: WebSocketUpgrade,
) -> axum::response::Response {
    let Some(authority) = &state.stream_authority else {
        return StatusCode::FORBIDDEN.into_response();
    };
    if let Err(status) = authority.verify(&headers, &uri) {
        return status.into_response();
    }
    ws.protocols([NORITO_V1_WEBSOCKET_SUBPROTOCOL])
        .on_upgrade(move |socket| block_stream(socket, state))
}

async fn handle_event_stream(
    State(state): State<AppState>,
    headers: HeaderMap,
    uri: Uri,
    ws: WebSocketUpgrade,
) -> axum::response::Response {
    let Some(authority) = &state.stream_authority else {
        return StatusCode::FORBIDDEN.into_response();
    };
    if let Err(status) = authority.verify(&headers, &uri) {
        return status.into_response();
    }
    ws.protocols([NORITO_V1_WEBSOCKET_SUBPROTOCOL])
        .on_upgrade(move |socket| event_stream(socket, state))
}

async fn block_stream(mut socket: WebSocket, state: AppState) {
    let Some(Ok(Message::Binary(request))) = socket.recv().await else {
        return;
    };
    if norito::decode_from_bytes::<BlockSubscriptionRequest>(&request).is_err() {
        return;
    }
    let mut rx = state.block_tx.subscribe();
    if let Err(err) = send_default_frame(&mut socket, &state.default_block_frame).await {
        eprintln!("failed to send default block frame: {err}");
        return;
    }
    while let Ok(frame) = rx.recv().await {
        if send_frame(&mut socket, frame).await.is_err() {
            break;
        }
    }
}
async fn event_stream(mut socket: WebSocket, state: AppState) {
    let Some(Ok(Message::Binary(request))) = socket.recv().await else {
        return;
    };
    let Ok(request) = norito::decode_from_bytes::<EventSubscriptionRequest>(&request) else {
        return;
    };
    if request.filters.is_empty() {
        return;
    }
    let mut rx = state.event_tx.subscribe();
    if let Err(err) = send_default_frame(&mut socket, &state.default_event_frame).await {
        eprintln!("failed to send default event frame: {err}");
        return;
    }
    while let Ok(frame) = rx.recv().await {
        if send_frame(&mut socket, frame).await.is_err() {
            break;
        }
    }
}
async fn send_default_frame(
    socket: &mut WebSocket,
    storage: &Arc<Mutex<Vec<u8>>>,
) -> std::result::Result<(), axum::Error> {
    let bytes = storage.lock().clone();
    if bytes.is_empty() {
        return Ok(());
    }
    send_frame(socket, MockToriiFrame::Binary(bytes)).await
}
async fn send_frame(
    socket: &mut WebSocket,
    frame: MockToriiFrame,
) -> std::result::Result<(), axum::Error> {
    socket.send(frame.into_message()).await
}
fn binary_response(body: Vec<u8>, content_type: &'static str) -> Response<Body> {
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, HeaderValue::from_static(content_type))
        .body(Body::from(body))
        .expect("binary response")
}
#[cfg(test)]
mod tests {
    use super::*;
    mod replay_fixture_owner;
    #[test]
    fn default_data_uses_fixtures() {
        let data = MockToriiData::default();
        let block_message: BlockMessage = norito::decode_from_bytes(&data.block_frame)
            .expect("default block frame must be a canonical BlockMessage");
        assert_eq!(block_message.0.header().height(), NonZeroU64::MIN);
        assert_eq!(block_message.0.external_entrypoint_count(), 1);
        assert_eq!(block_message.0.signatures().len(), 1);
        assert_eq!(block_message.0.committed_fragment_count(), Some(1));
        block_message
            .0
            .validate_proposal_commitments()
            .expect("mock block proposal commitments must be canonical");
        block_message
            .0
            .validate_output_merkle_cache()
            .expect("mock block output Merkle cache must be canonical");
        assert_eq!(
            block_message.0.output_merkle_commitment(),
            block_message
                .0
                .output_hashes()
                .collect::<iroha_crypto::MerkleTree<_>>()
                .commitment()
        );
        let event_message: EventMessage = norito::decode_from_bytes(&data.event_frame)
            .expect("default event frame must be a canonical EventMessage");
        assert!(matches!(
            EventBox::from(event_message),
            EventBox::Pipeline(PipelineEventBox::Transaction(TransactionEvent {
                block_height: Some(height),
                status: TransactionStatus::Approved,
                ..
            })) if height == NonZeroU64::MIN
        ));
    }
}
