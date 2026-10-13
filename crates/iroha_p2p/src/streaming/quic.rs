#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::too_many_lines,
    clippy::missing_errors_doc,
    clippy::ignored_unit_patterns,
    clippy::unused_async
)]
use bytes::Bytes;
use norito::{
    decode_from_bytes,
    streaming::{
        self, CapabilityAck, CapabilityReport, ControlFrame, TransportCapabilities,
        TransportCapabilitiesFrame, TransportCapabilityError, TransportCapabilityResolution,
    },
    to_bytes,
};
use quinn::{
    self, ClientConfig, ConnectError, Connection, ConnectionError, Endpoint, IdleTimeout,
    ReadExactError, RecvStream, SendDatagramError, SendStream, ServerConfig, TransportConfig,
    VarInt,
    crypto::rustls::{
        QuicClientConfig as QuinnRustlsClientConfig, QuicServerConfig as QuinnRustlsServerConfig,
    },
};
use rustls::{client::danger::ServerCertVerifier, pki_types::PrivatePkcs8KeyDer};
use std::{
    collections::VecDeque,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, AtomicUsize, Ordering},
    },
    time::Duration,
};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::{sync::Notify, task::JoinHandle};
const CONTROL_STREAM_PREFACE: &[u8; 5] = b"NSC/1";
const MEDIA_STREAM_PREFACE: &[u8; 5] = b"NSM/1";
const CONTROL_TYPE_PUBLISHER_TO_VIEWER: u8 = 0x01;
const CONTROL_TYPE_VIEWER_TO_PUBLISHER: u8 = 0x02;
const MAX_CONTROL_FRAME_LEN: usize = 512 * 1024;
const MAX_MEDIA_DATA_FRAMES_PER_WINDOW: usize = 12;
const MAX_MEDIA_PARITY_FRAMES_PER_WINDOW: usize = 6;
const MAX_MEDIA_FRAMES_PER_WINDOW: usize =
    MAX_MEDIA_DATA_FRAMES_PER_WINDOW + MAX_MEDIA_PARITY_FRAMES_PER_WINDOW;
const MAX_MEDIA_FRAME_LEN: usize = 4 * 1024 * 1024;
const MAX_MEDIA_WINDOW_LEN: usize = 16 * 1024 * 1024;
const MAX_MEDIA_WINDOW_TRANSFER_TIME: Duration = Duration::from_secs(30);
const MAX_CONCURRENT_UNI_STREAMS: u32 = 16;
const CONTROL_STREAM_PRIORITY: i32 = 256;
const MEDIA_STREAM_PRIORITY: i32 = 128;
const MAX_DATAGRAM_INBOX_ENTRIES: usize = 256;
const DATAGRAM_NEGOTIATING: usize = usize::MAX;
const DATAGRAM_PROTOCOL_ERROR_CODE: u32 = 0x4e53_4301;
const MEDIA_PROTOCOL_ERROR_CODE: u32 = 0x4e53_4302;
const QUIC_DEPENDENCY_BLOCK_REASON: &str = "streaming QUIC is unavailable pending transport requalification of locked quinn-proto 0.11.18; dependency memory and panic fixes alone do not establish authenticated transport, resource, or interoperability qualification";
const SETUP_PENDING: u8 = 0;
const SETUP_COMPLETE: u8 = 1;
const SETUP_TIMED_OUT: u8 = 2;
const ALPN: &[u8] = b"nsc/1";
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// Fingerprint that pins one streaming server certificate.
pub type CertificateFingerprint = [u8; iroha_crypto::Hash::LENGTH];
/// Result type used by the streaming QUIC helpers.
pub type Result<T> = core::result::Result<T, Error>;
/// Errors produced by the streaming QUIC transport helpers.
#[derive(Debug, Error)]
pub enum Error {
    /// Multiaddr string could not be parsed.
    #[error("invalid NSC multiaddr: {0}")]
    InvalidMultiaddr(String),
    /// Multiaddr did not advertise a UDP port.
    #[error("multiaddr is missing UDP segment")]
    MissingPort,
    /// Multiaddr contained an unsupported protocol component.
    #[error("unsupported multiaddr protocol '{0}'")]
    UnsupportedProtocol(String),
    /// I/O failure.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// QUIC connection failure.
    #[error("QUIC connection error: {0}")]
    Connection(#[from] ConnectionError),
    /// QUIC connect-time failure.
    #[error("QUIC connect error: {0}")]
    Connect(#[from] ConnectError),
    /// Failed to send a datagram.
    #[error("failed to send datagram: {0}")]
    SendDatagram(#[from] SendDatagramError),
    /// Norito codec failure.
    #[error("Norito codec error: {0}")]
    Norito(#[from] norito::Error),
    /// Control-stream preface was missing or malformed.
    #[error("control stream preface mismatch")]
    BadPreface,
    /// Remote advertised an unexpected control-stream direction.
    #[error("unexpected control stream direction (expected {expected:?}, found {found:?})")]
    WrongDirection {
        /// Expected direction marker.
        expected: ControlStreamDirection,
        /// Marker advertised by the peer.
        found: ControlStreamDirection,
    },
    /// Control frame exceeded the configured maximum length.
    #[error("control frame length {len} exceeds maximum {max}")]
    FrameTooLarge {
        /// Reported frame length.
        len: usize,
        /// Maximum allowed frame length.
        max: usize,
    },
    /// Transport capability negotiation failed.
    #[error("transport capability negotiation failed: {0}")]
    TransportCapability(TransportCapabilityError),
    /// Control stream ended unexpectedly.
    #[error("control stream closed by peer")]
    ControlStreamClosed,
    /// TLS client configuration failure.
    #[error("TLS client configuration error: {0}")]
    TlsClient(String),
    /// TLS server configuration failure.
    #[error("TLS server configuration error: {0}")]
    TlsServer(String),
    /// Transport configuration failure.
    #[error("transport configuration error: {0}")]
    TransportConfig(String),
    /// Datagrams larger than the negotiated bound were rejected.
    #[error("datagram size {len} exceeds negotiated maximum {max}")]
    DatagramTooLarge {
        /// Attempted datagram size.
        len: usize,
        /// Negotiated limit.
        max: usize,
    },
    /// Peer delivered an unexpected control frame while a specific response was required.
    #[error("protocol violation: {0}")]
    ProtocolViolation(String),
    /// Streaming transport setup exceeded its single absolute pre-authentication deadline.
    #[error("streaming setup exceeded its pre-authentication deadline")]
    SetupTimeout,
    /// A media segment window violated deterministic framing or resource limits.
    #[error("invalid media segment window: {0}")]
    InvalidMediaWindow(String),
}
/// Direction of the dedicated QUIC control stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlStreamDirection {
    /// Publisher → Viewer control flow.
    PublisherToViewer,
    /// Viewer → Publisher control flow.
    ViewerToPublisher,
}
impl ControlStreamDirection {
    const fn marker(self) -> u8 {
        match self {
            Self::PublisherToViewer => CONTROL_TYPE_PUBLISHER_TO_VIEWER,
            Self::ViewerToPublisher => CONTROL_TYPE_VIEWER_TO_PUBLISHER,
        }
    }
    fn from_marker(marker: u8) -> Option<Self> {
        match marker {
            CONTROL_TYPE_PUBLISHER_TO_VIEWER => Some(Self::PublisherToViewer),
            CONTROL_TYPE_VIEWER_TO_PUBLISHER => Some(Self::ViewerToPublisher),
            _ => None,
        }
    }
    const fn opposite(self) -> Self {
        match self {
            Self::PublisherToViewer => Self::ViewerToPublisher,
            Self::ViewerToPublisher => Self::PublisherToViewer,
        }
    }
}
/// Local endpoint role (publisher or viewer).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndpointRole {
    /// Publisher side of the session.
    Publisher,
    /// Viewer side of the session.
    Viewer,
}
impl EndpointRole {
    const fn outgoing_direction(self) -> ControlStreamDirection {
        match self {
            Self::Publisher => ControlStreamDirection::PublisherToViewer,
            Self::Viewer => ControlStreamDirection::ViewerToPublisher,
        }
    }
    const fn incoming_direction(self) -> ControlStreamDirection {
        self.outgoing_direction().opposite()
    }
}
/// Transport tuning knobs shared by viewers and publishers.
#[derive(Clone, Copy, Debug)]
pub struct TransportConfigSettings {
    /// Maximum QUIC DATAGRAM payload size (after AEAD).
    ///
    /// Shipping defaults remain zero pending complete transport requalification.
    pub max_datagram_size: usize,
    /// Total receive buffer reserved for datagrams.
    ///
    /// Shipping defaults remain zero pending complete transport requalification.
    pub datagram_receive_buffer: usize,
    /// Total send buffer reserved for datagrams.
    ///
    /// Shipping defaults remain zero pending complete transport requalification.
    pub datagram_send_buffer: usize,
    /// Idle timeout advertised at the transport layer.
    pub idle_timeout: Duration,
}
impl Default for TransportConfigSettings {
    fn default() -> Self {
        Self {
            max_datagram_size: 0,
            datagram_receive_buffer: 0,
            datagram_send_buffer: 0,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
        }
    }
}

/// One encrypted media or parity chunk carried by the stream fallback.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MediaChunk {
    /// Manifest-assigned chunk identifier.
    pub chunk_id: u16,
    /// Whether this frame carries a parity shard rather than source media.
    pub is_parity: bool,
    /// Encrypted chunk payload committed by the segment manifest.
    pub payload: Bytes,
}

/// One complete segment window received through the stream fallback.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MediaSegmentWindow {
    /// Monotonic manifest segment number.
    pub segment_number: u64,
    /// Source chunks followed by parity shards in strictly increasing chunk-id order.
    pub chunks: Vec<MediaChunk>,
}
/// Listener for incoming viewer connections.
#[derive(Clone)]
pub struct StreamingServer {
    endpoint: Endpoint,
    settings: TransportConfigSettings,
    certificate_fingerprint: CertificateFingerprint,
}
impl StreamingServer {
    /// Bind a QUIC listener on `addr` using the provided transport settings.
    pub async fn bind(addr: SocketAddr, settings: TransportConfigSettings) -> Result<Self> {
        validate_shipping_quic_dependency()?;
        Self::bind_for_requalification(addr, settings).await
    }

    async fn bind_for_requalification(
        addr: SocketAddr,
        settings: TransportConfigSettings,
    ) -> Result<Self> {
        let transport = build_transport_config(settings)?;
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(["nsc.local".to_owned()])
                .map_err(|e| Error::TlsServer(e.to_string()))?;
        let cert_der = cert.der().clone().into_owned();
        let certificate_fingerprint = crate::transport::certificate_fingerprint(cert_der.as_ref());
        let priv_key = PrivatePkcs8KeyDer::from(signing_key.serialize_der());
        let mut rustls_config =
            rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_no_client_auth()
                .with_single_cert(vec![cert_der], priv_key.into())
                .map_err(|e| Error::TlsServer(e.to_string()))?;
        rustls_config.max_early_data_size = 0;
        rustls_config.alpn_protocols = vec![ALPN.to_vec()];
        let rustls_config = Arc::new(rustls_config);
        let crypto = QuinnRustlsServerConfig::try_from(rustls_config)
            .map_err(|e| Error::TlsServer(e.to_string()))?;
        let mut server_config = ServerConfig::with_crypto(Arc::new(crypto));
        server_config.transport_config(transport);
        let endpoint = Endpoint::server(server_config, addr)?;
        Ok(Self {
            endpoint,
            settings,
            certificate_fingerprint,
        })
    }
    /// Retrieve the socket address the server is listening on.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.endpoint.local_addr().map_err(Error::from)
    }
    /// Return the fingerprint clients must obtain through an authenticated channel.
    #[must_use]
    pub const fn certificate_fingerprint(&self) -> CertificateFingerprint {
        self.certificate_fingerprint
    }
    /// Accept the next inbound streaming connection.
    pub async fn accept(&self) -> Result<StreamingConnection> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or_else(|| Error::ProtocolViolation("listener closed".into()))?;
        let deadline = setup_deadline(self.settings)?;
        let connecting = incoming
            .accept()
            .map_err(|e| std::io::Error::other(format!("listener accept failed: {e}")))?;
        let connection = deadline
            .run(None, connecting)
            .await
            .map_err(|_| Error::SetupTimeout)??;
        StreamingConnection::new_with_deadline(
            connection,
            EndpointRole::Publisher,
            self.settings,
            deadline,
        )
        .await
    }
    /// Close the listener and wait for active connections to drain.
    pub async fn shutdown(&self) {
        self.endpoint.close(VarInt::from_u32(0), &[]);
        self.endpoint.wait_idle().await;
    }
}
/// Viewer-side QUIC connector.
pub struct StreamingClient {
    endpoint: Endpoint,
    connection: StreamingConnection,
}
impl StreamingClient {
    /// Connect to the remote publisher described by `multiaddr`.
    ///
    /// `expected_certificate_fingerprint` must come from an authenticated manifest, directory, or
    /// operator configuration. Requiring it here keeps transport authentication fail-closed even
    /// before streaming `KeyUpdate` frames establish end-to-end content keys.
    pub async fn connect(
        multiaddr: &str,
        expected_certificate_fingerprint: CertificateFingerprint,
        settings: TransportConfigSettings,
    ) -> Result<Self> {
        validate_shipping_quic_dependency()?;
        Self::connect_for_requalification(multiaddr, expected_certificate_fingerprint, settings)
            .await
    }

    async fn connect_for_requalification(
        multiaddr: &str,
        expected_certificate_fingerprint: CertificateFingerprint,
        settings: TransportConfigSettings,
    ) -> Result<Self> {
        let parsed = parse_multiaddr(multiaddr)?;
        // Validate transport policy before binding a UDP socket.
        let transport = build_transport_config(settings)?;
        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())?;
        let verifier: Arc<dyn ServerCertVerifier> = Arc::new(
            crate::transport::CertificateKeyProofVerifier::pinned(expected_certificate_fingerprint),
        );
        let mut tls_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        tls_config.enable_early_data = false;
        tls_config.alpn_protocols = vec![ALPN.to_vec()];
        let tls_config = Arc::new(tls_config);
        let crypto = QuinnRustlsClientConfig::try_from(Arc::clone(&tls_config))
            .map_err(|e| Error::TlsClient(e.to_string()))?;
        let mut client_config = ClientConfig::new(Arc::new(crypto));
        client_config.transport_config(transport);
        endpoint.set_default_client_config(client_config);
        let server_addr = SocketAddr::new(parsed.host, parsed.port);
        let deadline = setup_deadline(settings)?;
        let connecting = endpoint.connect(server_addr, &parsed.server_name)?;
        let connection = deadline
            .run(None, connecting)
            .await
            .map_err(|_| Error::SetupTimeout)??;
        let connection = StreamingConnection::new_with_deadline(
            connection,
            EndpointRole::Viewer,
            settings,
            deadline,
        )
        .await?;
        Ok(Self {
            endpoint,
            connection,
        })
    }
    /// Access the underlying connection mutably.
    pub fn connection(&mut self) -> &mut StreamingConnection {
        &mut self.connection
    }
    /// Close the connection and wait for idle shutdown.
    pub async fn close(self) {
        self.connection.close();
        self.endpoint.close(VarInt::from_u32(0), &[]);
        self.endpoint.wait_idle().await;
    }
}

fn setup_deadline(settings: TransportConfigSettings) -> Result<crate::preauth::PreauthDeadline> {
    crate::preauth::PreauthDeadline::from_now(settings.idle_timeout).ok_or_else(|| {
        Error::TransportConfig("streaming setup timeout cannot be represented".into())
    })
}

fn validate_shipping_quic_dependency() -> Result<()> {
    Err(Error::TransportConfig(
        QUIC_DEPENDENCY_BLOCK_REASON.to_owned(),
    ))
}

#[derive(Clone, Debug)]
enum DatagramTerminal {
    Connection(ConnectionError),
    Protocol(String),
}

impl DatagramTerminal {
    fn into_error(self) -> Error {
        match self {
            Self::Connection(error) => Error::Connection(error),
            Self::Protocol(reason) => Error::ProtocolViolation(reason),
        }
    }
}

#[derive(Debug)]
struct DatagramInboxState {
    frames: VecDeque<Bytes>,
    bytes: usize,
    terminal: Option<DatagramTerminal>,
    policy: usize,
}

impl Default for DatagramInboxState {
    fn default() -> Self {
        Self {
            frames: VecDeque::new(),
            bytes: 0,
            terminal: None,
            policy: DATAGRAM_NEGOTIATING,
        }
    }
}

#[derive(Debug)]
struct DatagramInbox {
    state: Mutex<DatagramInboxState>,
    notify: Notify,
    max_bytes: usize,
}

impl DatagramInbox {
    fn new(max_bytes: usize) -> Self {
        Self {
            state: Mutex::new(DatagramInboxState::default()),
            notify: Notify::new(),
            max_bytes,
        }
    }

    fn admit(&self, frame: Bytes, configured_max: usize) -> core::result::Result<(), String> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.terminal.is_some() {
            return Err("DATAGRAM session is already terminal".to_owned());
        }
        let max_datagram = if state.policy == DATAGRAM_NEGOTIATING {
            configured_max
        } else {
            state.policy
        };
        if max_datagram == 0 {
            return Err("peer sent a DATAGRAM while delivery was disabled".to_owned());
        }
        if frame.len() > max_datagram {
            return Err(format!(
                "peer sent datagram of {} bytes above negotiated maximum {max_datagram}",
                frame.len()
            ));
        }
        if state.frames.len() == MAX_DATAGRAM_INBOX_ENTRIES
            || frame.len() > self.max_bytes.saturating_sub(state.bytes)
        {
            // QUIC DATAGRAM delivery is unreliable. Dropping a newest frame
            // keeps both count and bytes bounded without backpressuring the
            // eager transport drain.
            return Ok(());
        }
        // Quinn's decoded DATAGRAM is a slice of a packet-sized allocation.
        // Copying here makes the application inbox's byte and entry limits
        // bound the buffers it actually retains instead of pinning that packet.
        let retained_frame = Bytes::copy_from_slice(&frame);
        drop(frame);
        state.bytes += retained_frame.len();
        state.frames.push_back(retained_frame);
        drop(state);
        self.notify.notify_one();
        Ok(())
    }

    fn fail(&self, terminal: DatagramTerminal) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.terminal.is_none() {
            state.frames.clear();
            state.bytes = 0;
            state.terminal = Some(terminal);
        }
        drop(state);
        self.notify.notify_waiters();
    }

    fn apply_policy(&self, max_datagram: usize) -> Option<String> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.policy = max_datagram;
        let violation = state.frames.iter().find_map(|frame| {
            if max_datagram == 0 {
                Some("peer sent a DATAGRAM while delivery was disabled".to_owned())
            } else if frame.len() > max_datagram {
                Some(format!(
                    "peer sent datagram of {} bytes above negotiated maximum {max_datagram}",
                    frame.len()
                ))
            } else {
                None
            }
        });
        if let Some(reason) = violation.as_ref() {
            state.frames.clear();
            state.bytes = 0;
            state.terminal = Some(DatagramTerminal::Protocol(reason.clone()));
        }
        drop(state);
        self.notify.notify_waiters();
        violation
    }

    fn has_protocol_terminal(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .terminal
            .as_ref()
            .is_some_and(|terminal| matches!(terminal, DatagramTerminal::Protocol(_)))
    }

    async fn recv(&self) -> Result<Bytes> {
        loop {
            let notified = self.notify.notified();
            let outcome = {
                let mut state = self
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                state.terminal.clone().map_or_else(|| {
                    let max_datagram = state.policy;
                    if max_datagram == DATAGRAM_NEGOTIATING {
                        None
                    } else if max_datagram == 0 {
                        Some(Err(Error::ProtocolViolation(
                            "DATAGRAM delivery is disabled for this session".into(),
                        )))
                    } else {
                        state.frames.pop_front().map(|frame| {
                        state.bytes = state.bytes.saturating_sub(frame.len());
                        if frame.len() > max_datagram {
                            let reason = format!(
                                "peer sent datagram of {} bytes above negotiated maximum {max_datagram}",
                                frame.len()
                            );
                            state.frames.clear();
                            state.bytes = 0;
                            state.terminal =
                                Some(DatagramTerminal::Protocol(reason.clone()));
                            Err(Error::ProtocolViolation(reason))
                        } else {
                            Ok(frame)
                        }
                    })
                    }
                }, |terminal| Some(Err(terminal.into_error())))
            };
            if let Some(outcome) = outcome {
                return outcome;
            }
            notified.await;
        }
    }
}

fn spawn_datagram_pump(
    connection: Connection,
    inbox: Arc<DatagramInbox>,
    configured_max: usize,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let frame = match connection.read_datagram().await {
                Ok(frame) => frame,
                Err(error) => {
                    inbox.fail(DatagramTerminal::Connection(error));
                    return;
                }
            };
            if frame.is_empty() {
                let reason = "peer sent a zero-length QUIC DATAGRAM".to_owned();
                inbox.fail(DatagramTerminal::Protocol(reason));
                connection.close(
                    VarInt::from_u32(DATAGRAM_PROTOCOL_ERROR_CODE),
                    b"zero-length DATAGRAM",
                );
                let mut drained = 0_u32;
                while connection.read_datagram().await.is_ok() {
                    drained = drained.wrapping_add(1);
                    if drained % 64 == 0 {
                        tokio::task::yield_now().await;
                    }
                }
                return;
            }
            if let Err(reason) = inbox.admit(frame, configured_max) {
                inbox.fail(DatagramTerminal::Protocol(reason));
                connection.close(
                    VarInt::from_u32(DATAGRAM_PROTOCOL_ERROR_CODE),
                    b"invalid DATAGRAM",
                );
                while connection.read_datagram().await.is_ok() {
                    tokio::task::yield_now().await;
                }
                return;
            }
        }
    })
}

#[derive(Clone, Copy, Debug)]
struct PendingCapabilityAck {
    stream_id: streaming::Hash,
    protocol_version: u16,
    dplpmtud: bool,
    resolution: TransportCapabilityResolution,
}

/// Active streaming session over QUIC.
pub struct StreamingConnection {
    role: EndpointRole,
    connection: Connection,
    control_send: ControlStreamWriter,
    control_recv: ControlStreamReader,
    configured_max_datagram: usize,
    max_datagram: Arc<AtomicUsize>,
    datagram_inbox: Arc<DatagramInbox>,
    datagram_task: JoinHandle<()>,
    setup_deadline: Option<crate::preauth::PreauthDeadline>,
    setup_state: Arc<AtomicU8>,
    setup_watchdog: JoinHandle<()>,
    pending_publisher_ack: Option<PendingCapabilityAck>,
    media_window_timeout: Duration,
    last_sent_media_segment: Option<u64>,
    last_received_media_segment: Option<u64>,
}
impl StreamingConnection {
    #[cfg(test)]
    async fn new(
        connection: Connection,
        role: EndpointRole,
        settings: TransportConfigSettings,
    ) -> Result<Self> {
        let deadline = setup_deadline(settings)?;
        Self::new_with_deadline(connection, role, settings, deadline).await
    }

    async fn new_with_deadline(
        connection: Connection,
        role: EndpointRole,
        settings: TransportConfigSettings,
        deadline: crate::preauth::PreauthDeadline,
    ) -> Result<Self> {
        let max_datagram = Arc::new(AtomicUsize::new(DATAGRAM_NEGOTIATING));
        let datagram_inbox = Arc::new(DatagramInbox::new(settings.datagram_receive_buffer));
        // Drain Quinn continuously before the control stream is authenticated.
        // The bounded application inbox counts entries as well as bytes and
        // closes the connection on the first empty DATAGRAM.
        // Locked quinn-proto 0.11.18 independently charges fixed per-entry
        // overhead before this pump polls. TODO: Complete whole-transport
        // qualification before enabling the shipping endpoint constructors.
        let datagram_task = spawn_datagram_pump(
            connection.clone(),
            Arc::clone(&datagram_inbox),
            settings.max_datagram_size,
        );
        let setup = deadline
            .run(None, async {
                let send = connection
                    .open_uni()
                    .await
                    .map_err(|e| Error::Io(std::io::Error::from(e)))?;
                let control_send =
                    ControlStreamWriter::new(send, role.outgoing_direction()).await?;
                // QUIC streams are created implicitly when the first frame is sent. If we wait on
                // `accept_uni()` before writing anything to our outgoing stream, both endpoints can
                // deadlock waiting for the other side to "open" its control stream.
                let recv = connection.accept_uni().await?;
                let control_recv =
                    ControlStreamReader::new(recv, role.incoming_direction()).await?;
                Ok::<_, Error>((control_send, control_recv))
            })
            .await;
        let (control_send, control_recv) = match setup {
            Ok(Ok(streams)) => streams,
            Ok(Err(error)) => {
                datagram_task.abort();
                return Err(error);
            }
            Err(_) => {
                connection.close(VarInt::from_u32(0), b"setup timeout");
                datagram_task.abort();
                return Err(Error::SetupTimeout);
            }
        };
        let setup_state = Arc::new(AtomicU8::new(SETUP_PENDING));
        let watchdog_state = Arc::clone(&setup_state);
        let watchdog_connection = connection.clone();
        let setup_watchdog = tokio::spawn(async move {
            deadline.wait().await;
            if watchdog_state
                .compare_exchange(
                    SETUP_PENDING,
                    SETUP_TIMED_OUT,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                watchdog_connection.close(VarInt::from_u32(0), b"setup timeout");
            }
        });
        Ok(Self {
            role,
            connection,
            control_send,
            control_recv,
            configured_max_datagram: settings.max_datagram_size,
            max_datagram,
            datagram_inbox,
            datagram_task,
            setup_deadline: Some(deadline),
            setup_state,
            setup_watchdog,
            pending_publisher_ack: None,
            media_window_timeout: settings.idle_timeout.min(MAX_MEDIA_WINDOW_TRANSFER_TIME),
            last_sent_media_segment: None,
            last_received_media_segment: None,
        })
    }
    /// Return the local role.
    pub const fn role(&self) -> EndpointRole {
        self.role
    }
    /// Send a control frame to the peer.
    pub async fn send_control_frame(&mut self, frame: &ControlFrame) -> Result<()> {
        let completes_setup = if matches!(self.role, EndpointRole::Publisher) {
            if let ControlFrame::CapabilityAck(ack) = frame {
                let pending = self.pending_publisher_ack.ok_or_else(|| {
                    Error::ProtocolViolation(
                        "publisher sent a capability ack without a pending report".into(),
                    )
                })?;
                validate_capability_ack_binding(
                    ack,
                    pending.stream_id,
                    pending.protocol_version,
                    pending.dplpmtud,
                    pending.resolution,
                )?;
                true
            } else {
                false
            }
        } else {
            false
        };
        let result = if let Some(deadline) = self.setup_deadline {
            if let Ok(result) = deadline
                .run(None, self.control_send.send_frame(frame))
                .await
            {
                result
            } else {
                self.connection.close(VarInt::from_u32(0), b"setup timeout");
                return Err(Error::SetupTimeout);
            }
        } else {
            self.control_send.send_frame(frame).await
        };
        result?;
        if completes_setup {
            self.pending_publisher_ack = None;
            self.finish_setup()?;
        }
        Ok(())
    }
    /// Receive the next control frame from the peer.
    pub async fn next_control_frame(&mut self) -> Result<ControlFrame> {
        if let Some(deadline) = self.setup_deadline {
            if let Ok(result) = deadline.run(None, self.control_recv.next_frame()).await {
                result
            } else {
                self.connection.close(VarInt::from_u32(0), b"setup timeout");
                Err(Error::SetupTimeout)
            }
        } else {
            self.control_recv.next_frame().await
        }
    }
    /// Send a datagram payload.
    pub async fn send_datagram(&self, payload: &[u8]) -> Result<()> {
        if payload.is_empty() {
            return Err(Error::ProtocolViolation(
                "zero-length QUIC DATAGRAMs are forbidden".into(),
            ));
        }
        let max_datagram = self.max_datagram.load(Ordering::Acquire);
        if max_datagram == DATAGRAM_NEGOTIATING {
            return Err(Error::ProtocolViolation(
                "DATAGRAM capability negotiation is incomplete".into(),
            ));
        }
        if payload.len() > max_datagram {
            return Err(Error::DatagramTooLarge {
                len: payload.len(),
                max: max_datagram,
            });
        }
        self.connection
            .send_datagram(Bytes::copy_from_slice(payload))?;
        Ok(())
    }
    /// Receive the next datagram payload.
    pub async fn recv_datagram(&self) -> Result<Bytes> {
        let result = self.datagram_inbox.recv().await;
        if result.is_err() && self.datagram_inbox.has_protocol_terminal() {
            self.connection.close(
                VarInt::from_u32(DATAGRAM_PROTOCOL_ERROR_CODE),
                b"invalid DATAGRAM",
            );
        }
        result
    }
    /// Return the negotiated DATAGRAM payload limit for this session.
    pub fn max_datagram_size(&self) -> usize {
        match self.max_datagram.load(Ordering::Acquire) {
            DATAGRAM_NEGOTIATING => 0,
            limit => limit,
        }
    }
    /// Return `true` if DATAGRAM delivery is enabled for this session.
    pub fn datagram_enabled(&self) -> bool {
        let limit = self.max_datagram.load(Ordering::Acquire);
        limit != DATAGRAM_NEGOTIATING && limit > 0
    }
    /// Send one deterministic media segment window on its own unidirectional stream.
    ///
    /// This is the reliable fallback selected when capability negotiation disables DATAGRAM
    /// delivery. Windows must be sent by the publisher in strictly increasing segment order.
    pub async fn send_media_window(
        &mut self,
        segment_number: u64,
        chunks: &[MediaChunk],
    ) -> Result<()> {
        self.ensure_stream_fallback(EndpointRole::Publisher)?;
        validate_media_window(segment_number, self.last_sent_media_segment, chunks)?;

        let deadline = media_window_deadline(self.media_window_timeout)?;
        let result = tokio::time::timeout_at(deadline, async {
            let mut stream = self
                .connection
                .open_uni()
                .await
                .map_err(|error| Error::Io(std::io::Error::from(error)))?;
            write_media_window(&mut stream, segment_number, chunks).await
        })
        .await
        .unwrap_or_else(|_| Err(media_window_timeout_error()));
        if result.is_err() {
            self.close_invalid_media_stream();
        }
        result?;
        self.last_sent_media_segment = Some(segment_number);
        Ok(())
    }
    /// Receive the next deterministic media segment window from a unidirectional stream.
    ///
    /// The viewer validates framing, bounded lengths, chunk ordering, and monotonic segment
    /// numbers before returning any payloads to the caller.
    pub async fn recv_media_window(&mut self) -> Result<MediaSegmentWindow> {
        self.ensure_stream_fallback(EndpointRole::Viewer)?;
        let deadline = media_window_deadline(self.media_window_timeout)?;
        let result = tokio::time::timeout_at(deadline, async {
            let stream = self.connection.accept_uni().await?;
            read_media_window(stream, self.last_received_media_segment).await
        })
        .await
        .unwrap_or_else(|_| Err(media_window_timeout_error()));
        match result {
            Ok(window) => {
                self.last_received_media_segment = Some(window.segment_number);
                Ok(window)
            }
            Err(error) => {
                self.close_invalid_media_stream();
                Err(error)
            }
        }
    }
    /// Close the underlying QUIC connection.
    pub fn close(&self) {
        self.connection.close(VarInt::from_u32(0), &[]);
    }
    /// Wait for the underlying QUIC connection to close.
    pub async fn closed(&self) -> ConnectionError {
        self.connection.closed().await
    }
    fn ensure_stream_fallback(&self, required_role: EndpointRole) -> Result<()> {
        if self.role != required_role {
            return Err(Error::InvalidMediaWindow(format!(
                "the {required_role:?} role is required"
            )));
        }
        if self.setup_state.load(Ordering::Acquire) != SETUP_COMPLETE {
            return Err(Error::InvalidMediaWindow(
                "transport capability negotiation is incomplete".into(),
            ));
        }
        if self.datagram_enabled() {
            return Err(Error::InvalidMediaWindow(
                "stream fallback cannot be used when DATAGRAM delivery is negotiated".into(),
            ));
        }
        Ok(())
    }
    fn close_invalid_media_stream(&self) {
        self.connection.close(
            VarInt::from_u32(MEDIA_PROTOCOL_ERROR_CODE),
            b"invalid media stream",
        );
    }
    fn finish_setup(&mut self) -> Result<()> {
        let Some(deadline) = self.setup_deadline else {
            return Err(Error::ProtocolViolation(
                "streaming setup was already completed".into(),
            ));
        };
        match self.setup_state.compare_exchange(
            SETUP_PENDING,
            SETUP_COMPLETE,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {}
            Err(SETUP_TIMED_OUT) => {
                self.connection.close(VarInt::from_u32(0), b"setup timeout");
                return Err(Error::SetupTimeout);
            }
            Err(_) => {
                return Err(Error::ProtocolViolation(
                    "streaming setup was already completed".into(),
                ));
            }
        }
        // The compare-exchange is the logical completion instant. A task that
        // was descheduled across the deadline must not win merely because the
        // watchdog has not yet been polled.
        if deadline.has_elapsed() {
            self.setup_state.store(SETUP_TIMED_OUT, Ordering::Release);
            self.connection.close(VarInt::from_u32(0), b"setup timeout");
            return Err(Error::SetupTimeout);
        }
        self.setup_deadline = None;
        self.setup_watchdog.abort();
        Ok(())
    }
    fn normalize_local_transport_capabilities(
        &self,
        mut capabilities: TransportCapabilities,
    ) -> TransportCapabilities {
        if capabilities.supports_datagram && self.configured_max_datagram > 0 {
            let configured = u16::try_from(self.configured_max_datagram).unwrap_or(u16::MAX);
            capabilities.max_segment_datagram_size =
                capabilities.max_segment_datagram_size.min(configured);
        } else {
            capabilities.supports_datagram = false;
            capabilities.max_segment_datagram_size = 0;
        }
        capabilities
    }
    fn apply_transport_resolution(
        &mut self,
        resolution: TransportCapabilityResolution,
    ) -> Result<()> {
        let negotiated = if resolution.use_datagram {
            usize::from(resolution.max_segment_datagram_size)
        } else {
            0
        };
        let max_datagram = negotiated;
        debug_assert!(max_datagram <= self.configured_max_datagram);
        if let Some(reason) = self.datagram_inbox.apply_policy(max_datagram) {
            self.connection.close(
                VarInt::from_u32(DATAGRAM_PROTOCOL_ERROR_CODE),
                b"invalid DATAGRAM",
            );
            return Err(Error::ProtocolViolation(reason));
        }
        self.max_datagram.store(max_datagram, Ordering::Release);
        Ok(())
    }
}

fn media_window_deadline(timeout: Duration) -> Result<tokio::time::Instant> {
    tokio::time::Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| Error::TransportConfig("media window deadline cannot be represented".into()))
}

fn media_window_timeout_error() -> Error {
    Error::InvalidMediaWindow("media stream exceeded its absolute transfer deadline".into())
}

fn validate_media_segment_number(segment_number: u64, previous_segment: Option<u64>) -> Result<()> {
    if let Some(previous) = previous_segment
        && segment_number <= previous
    {
        return Err(Error::InvalidMediaWindow(format!(
            "segment number {segment_number} must be greater than previously completed segment {previous}"
        )));
    }
    Ok(())
}

#[derive(Default)]
struct MediaWindowValidator {
    data_frames: usize,
    parity_frames: usize,
    parity_started: bool,
    previous_chunk: Option<u16>,
    payload_bytes: usize,
}

impl MediaWindowValidator {
    fn admit(&mut self, chunk_id: u16, is_parity: bool, payload_len: usize) -> Result<()> {
        if payload_len == 0 {
            return Err(Error::InvalidMediaWindow(format!(
                "chunk {chunk_id} has an empty payload"
            )));
        }
        if payload_len > MAX_MEDIA_FRAME_LEN {
            return Err(Error::InvalidMediaWindow(format!(
                "chunk {chunk_id} payload is {payload_len} bytes; maximum is {MAX_MEDIA_FRAME_LEN}"
            )));
        }
        self.payload_bytes = self
            .payload_bytes
            .checked_add(payload_len)
            .ok_or_else(|| Error::InvalidMediaWindow("payload byte count overflow".into()))?;
        if self.payload_bytes > MAX_MEDIA_WINDOW_LEN {
            return Err(Error::InvalidMediaWindow(format!(
                "segment payload is {} bytes; maximum is {MAX_MEDIA_WINDOW_LEN}",
                self.payload_bytes
            )));
        }
        if self
            .previous_chunk
            .is_some_and(|previous| chunk_id <= previous)
        {
            return Err(Error::InvalidMediaWindow(format!(
                "chunk id {chunk_id} is not strictly greater than its predecessor"
            )));
        }
        self.previous_chunk = Some(chunk_id);
        if is_parity {
            if self.data_frames == 0 {
                return Err(Error::InvalidMediaWindow(
                    "source chunks must precede every parity shard".into(),
                ));
            }
            self.parity_started = true;
            self.parity_frames += 1;
            if self.parity_frames > MAX_MEDIA_PARITY_FRAMES_PER_WINDOW {
                return Err(Error::InvalidMediaWindow(format!(
                    "segment window contains {} parity frames; maximum is {MAX_MEDIA_PARITY_FRAMES_PER_WINDOW}",
                    self.parity_frames
                )));
            }
        } else {
            if self.parity_started {
                return Err(Error::InvalidMediaWindow(
                    "source chunks must precede every parity shard".into(),
                ));
            }
            self.data_frames += 1;
            if self.data_frames > MAX_MEDIA_DATA_FRAMES_PER_WINDOW {
                return Err(Error::InvalidMediaWindow(format!(
                    "segment window contains {} source frames; maximum is {MAX_MEDIA_DATA_FRAMES_PER_WINDOW}",
                    self.data_frames
                )));
            }
        }
        Ok(())
    }

    fn finish(self) -> Result<()> {
        if self.data_frames == 0 {
            return Err(Error::InvalidMediaWindow(
                "a segment window must contain at least one source chunk".into(),
            ));
        }
        Ok(())
    }
}

fn validate_media_window(
    segment_number: u64,
    previous_segment: Option<u64>,
    chunks: &[MediaChunk],
) -> Result<()> {
    validate_media_segment_number(segment_number, previous_segment)?;
    if chunks.is_empty() {
        return Err(Error::InvalidMediaWindow(
            "a segment window must contain at least one source chunk".into(),
        ));
    }
    if chunks.len() > MAX_MEDIA_FRAMES_PER_WINDOW {
        return Err(Error::InvalidMediaWindow(format!(
            "segment window contains {} frames; maximum is {MAX_MEDIA_FRAMES_PER_WINDOW}",
            chunks.len()
        )));
    }

    let mut validator = MediaWindowValidator::default();
    for chunk in chunks {
        validator.admit(chunk.chunk_id, chunk.is_parity, chunk.payload.len())?;
    }
    validator.finish()
}

async fn write_media_window(
    stream: &mut SendStream,
    segment_number: u64,
    chunks: &[MediaChunk],
) -> Result<()> {
    stream
        .set_priority(MEDIA_STREAM_PRIORITY)
        .map_err(|error| Error::Io(std::io::Error::other(error)))?;
    stream
        .write_all(MEDIA_STREAM_PREFACE)
        .await
        .map_err(|error| Error::Io(std::io::Error::from(error)))?;
    stream
        .write_all(&segment_number.to_le_bytes())
        .await
        .map_err(|error| Error::Io(std::io::Error::from(error)))?;
    let frame_count = u16::try_from(chunks.len()).expect("media frame limit fits u16");
    stream
        .write_all(&frame_count.to_le_bytes())
        .await
        .map_err(|error| Error::Io(std::io::Error::from(error)))?;
    for chunk in chunks {
        stream
            .write_all(&chunk.chunk_id.to_le_bytes())
            .await
            .map_err(|error| Error::Io(std::io::Error::from(error)))?;
        stream
            .write_all(&[u8::from(chunk.is_parity)])
            .await
            .map_err(|error| Error::Io(std::io::Error::from(error)))?;
        let payload_len = u32::try_from(chunk.payload.len()).expect("media frame limit fits u32");
        stream
            .write_all(&payload_len.to_le_bytes())
            .await
            .map_err(|error| Error::Io(std::io::Error::from(error)))?;
        stream
            .write_all(&chunk.payload)
            .await
            .map_err(|error| Error::Io(std::io::Error::from(error)))?;
    }
    stream
        .finish()
        .map_err(|error| Error::Io(std::io::Error::other(error)))?;
    Ok(())
}

async fn read_media_exact(stream: &mut RecvStream, buffer: &mut [u8]) -> Result<()> {
    match stream.read_exact(buffer).await {
        Ok(()) => Ok(()),
        Err(ReadExactError::FinishedEarly(_)) => Err(Error::InvalidMediaWindow(
            "media stream ended before its declared payload".into(),
        )),
        Err(ReadExactError::ReadError(error)) => Err(Error::Io(std::io::Error::from(error))),
    }
}

async fn read_media_window(
    mut stream: RecvStream,
    previous_segment: Option<u64>,
) -> Result<MediaSegmentWindow> {
    let mut preface = [0_u8; MEDIA_STREAM_PREFACE.len()];
    read_media_exact(&mut stream, &mut preface).await?;
    if preface != *MEDIA_STREAM_PREFACE {
        return Err(Error::InvalidMediaWindow(
            "media stream preface mismatch".into(),
        ));
    }
    let mut segment_bytes = [0_u8; 8];
    read_media_exact(&mut stream, &mut segment_bytes).await?;
    let segment_number = u64::from_le_bytes(segment_bytes);
    validate_media_segment_number(segment_number, previous_segment)?;
    let mut count_bytes = [0_u8; 2];
    read_media_exact(&mut stream, &mut count_bytes).await?;
    let frame_count = usize::from(u16::from_le_bytes(count_bytes));
    if frame_count == 0 || frame_count > MAX_MEDIA_FRAMES_PER_WINDOW {
        return Err(Error::InvalidMediaWindow(format!(
            "media stream declared {frame_count} frames; expected 1..={MAX_MEDIA_FRAMES_PER_WINDOW}"
        )));
    }

    let mut chunks = Vec::with_capacity(frame_count);
    let mut validator = MediaWindowValidator::default();
    for _ in 0..frame_count {
        let mut chunk_id_bytes = [0_u8; 2];
        read_media_exact(&mut stream, &mut chunk_id_bytes).await?;
        let chunk_id = u16::from_le_bytes(chunk_id_bytes);
        let mut parity_byte = [0_u8; 1];
        read_media_exact(&mut stream, &mut parity_byte).await?;
        let is_parity = match parity_byte[0] {
            0 => false,
            1 => true,
            value => {
                return Err(Error::InvalidMediaWindow(format!(
                    "chunk {chunk_id} uses reserved parity flag {value}"
                )));
            }
        };
        let mut payload_len_bytes = [0_u8; 4];
        read_media_exact(&mut stream, &mut payload_len_bytes).await?;
        let payload_len = usize::try_from(u32::from_le_bytes(payload_len_bytes))
            .expect("u32 payload length fits supported platforms");
        validator.admit(chunk_id, is_parity, payload_len)?;
        let mut payload = Vec::new();
        payload.try_reserve_exact(payload_len).map_err(|_| {
            Error::InvalidMediaWindow(format!(
                "unable to reserve {payload_len} bytes for chunk {chunk_id}"
            ))
        })?;
        payload.resize(payload_len, 0);
        read_media_exact(&mut stream, &mut payload).await?;
        chunks.push(MediaChunk {
            chunk_id,
            is_parity,
            payload: Bytes::from(payload),
        });
    }
    validator.finish()?;
    if stream
        .read_chunk(1, true)
        .await
        .map_err(|error| Error::Io(std::io::Error::from(error)))?
        .is_some()
    {
        return Err(Error::InvalidMediaWindow(
            "media stream contains bytes after its declared frames".into(),
        ));
    }
    Ok(MediaSegmentWindow {
        segment_number,
        chunks,
    })
}

impl Drop for StreamingConnection {
    fn drop(&mut self) {
        self.datagram_task.abort();
        self.setup_watchdog.abort();
    }
}
/// Capability negotiation helpers.
#[derive(Clone, Copy, Debug, Default)]
pub struct CapabilityNegotiation;
impl CapabilityNegotiation {
    /// Perform viewer-side negotiation: send `report` and await `CapabilityAck`.
    pub async fn viewer_handshake<F>(
        conn: &mut StreamingConnection,
        capabilities: TransportCapabilities,
        report: CapabilityReport,
        record: F,
    ) -> Result<(CapabilityAck, TransportCapabilityResolution)>
    where
        F: FnOnce(&TransportCapabilityResolution),
    {
        validate_capability_report(&report)?;
        let mut record = Some(record);
        let local_frame = TransportCapabilitiesFrame {
            endpoint_role: streaming::CapabilityRole::Viewer,
            capabilities: conn.normalize_local_transport_capabilities(capabilities),
        };
        conn.send_control_frame(&ControlFrame::TransportCapabilities(local_frame.clone()))
            .await?;
        let remote_caps = loop {
            let response = conn.next_control_frame().await?;
            match response {
                ControlFrame::TransportCapabilities(frame) => {
                    if frame.endpoint_role != streaming::CapabilityRole::Publisher {
                        return Err(Error::ProtocolViolation(format!(
                            "expected publisher capabilities, received {role:?}",
                            role = frame.endpoint_role
                        )));
                    }
                    break frame;
                }
                ControlFrame::Error(err) => {
                    return Err(Error::ProtocolViolation(format!(
                        "peer reported error: {err:?}"
                    )));
                }
                other => {
                    return Err(Error::ProtocolViolation(format!(
                        "expected TransportCapabilities, received {other:?}"
                    )));
                }
            }
        };
        let mut resolution = streaming::resolve_transport_capabilities(
            &local_frame.capabilities,
            &remote_caps.capabilities,
        )
        .map_err(Error::TransportCapability)?;
        if resolution.use_datagram {
            if report.max_datagram_size == 0 {
                return Err(Error::ProtocolViolation(
                    "viewer capability report advertised zero datagram size".into(),
                ));
            }
            resolution.max_segment_datagram_size = resolution
                .max_segment_datagram_size
                .min(report.max_datagram_size);
        }
        let expected_stream_id = report.stream_id;
        let expected_version = report.protocol_version;
        let expected_dplpmtud = report.dplpmtud;
        conn.send_control_frame(&ControlFrame::CapabilityReport(report))
            .await?;
        loop {
            let response = conn.next_control_frame().await?;
            match response {
                ControlFrame::CapabilityAck(ack) => {
                    validate_capability_ack_binding(
                        &ack,
                        expected_stream_id,
                        expected_version,
                        expected_dplpmtud,
                        resolution,
                    )?;
                    conn.apply_transport_resolution(resolution)?;
                    conn.finish_setup()?;
                    if let Some(callback) = record.take() {
                        callback(&resolution);
                    }
                    return Ok((ack, resolution));
                }
                ControlFrame::Error(err) => {
                    return Err(Error::ProtocolViolation(format!(
                        "peer reported error: {err:?}"
                    )));
                }
                other => {
                    return Err(Error::ProtocolViolation(format!(
                        "expected CapabilityAck, received {other:?}"
                    )));
                }
            }
        }
    }
    /// Await the viewer's capability report (publisher side).
    pub async fn publisher_handshake<F>(
        conn: &mut StreamingConnection,
        capabilities: TransportCapabilities,
        record: F,
    ) -> Result<(CapabilityReport, TransportCapabilityResolution)>
    where
        F: FnOnce(&TransportCapabilityResolution),
    {
        let mut record = Some(record);
        let viewer_caps = match conn.next_control_frame().await? {
            ControlFrame::TransportCapabilities(frame) => {
                if frame.endpoint_role != streaming::CapabilityRole::Viewer {
                    return Err(Error::ProtocolViolation(format!(
                        "expected viewer capabilities, received {role:?}",
                        role = frame.endpoint_role
                    )));
                }
                frame
            }
            ControlFrame::Error(err) => {
                return Err(Error::ProtocolViolation(format!(
                    "peer reported error: {err:?}"
                )));
            }
            other => {
                return Err(Error::ProtocolViolation(format!(
                    "expected TransportCapabilities, received {other:?}"
                )));
            }
        };
        let local_frame = TransportCapabilitiesFrame {
            endpoint_role: streaming::CapabilityRole::Publisher,
            capabilities: conn.normalize_local_transport_capabilities(capabilities),
        };
        conn.send_control_frame(&ControlFrame::TransportCapabilities(local_frame.clone()))
            .await?;
        let mut resolution = streaming::resolve_transport_capabilities(
            &local_frame.capabilities,
            &viewer_caps.capabilities,
        )
        .map_err(Error::TransportCapability)?;
        loop {
            let frame = conn.next_control_frame().await?;
            match frame {
                ControlFrame::CapabilityReport(report) => {
                    validate_capability_report(&report)?;
                    if resolution.use_datagram {
                        if report.max_datagram_size == 0 {
                            return Err(Error::ProtocolViolation(
                                "viewer capability report advertised zero datagram size".into(),
                            ));
                        }
                        resolution.max_segment_datagram_size = resolution
                            .max_segment_datagram_size
                            .min(report.max_datagram_size);
                    }
                    conn.apply_transport_resolution(resolution)?;
                    conn.pending_publisher_ack = Some(PendingCapabilityAck {
                        stream_id: report.stream_id,
                        protocol_version: report.protocol_version,
                        dplpmtud: report.dplpmtud,
                        resolution,
                    });
                    if let Some(callback) = record.take() {
                        callback(&resolution);
                    }
                    return Ok((report, resolution));
                }
                ControlFrame::Error(err) => {
                    return Err(Error::ProtocolViolation(format!(
                        "peer reported error: {err:?}"
                    )));
                }
                other => {
                    return Err(Error::ProtocolViolation(format!(
                        "expected CapabilityReport, received {other:?}"
                    )));
                }
            }
        }
    }
}
fn validate_capability_report(report: &CapabilityReport) -> Result<()> {
    if report.endpoint_role != streaming::CapabilityRole::Viewer {
        return Err(Error::ProtocolViolation(format!(
            "expected viewer capability report, received {role:?}",
            role = report.endpoint_role
        )));
    }
    if report.protocol_version == 0 {
        return Err(Error::ProtocolViolation(
            "capability report advertised zero protocol version".into(),
        ));
    }
    Ok(())
}
fn validate_capability_ack_binding(
    ack: &CapabilityAck,
    expected_stream_id: streaming::Hash,
    expected_version: u16,
    expected_dplpmtud: bool,
    resolution: TransportCapabilityResolution,
) -> Result<()> {
    if ack.stream_id != expected_stream_id {
        return Err(Error::ProtocolViolation(
            "capability ack stream_id does not match report".into(),
        ));
    }
    if ack.accepted_version != expected_version {
        return Err(Error::ProtocolViolation(format!(
            "capability ack accepted_version={} but report used {}",
            ack.accepted_version, expected_version
        )));
    }
    if ack.max_datagram_size != resolution.max_segment_datagram_size {
        return Err(Error::ProtocolViolation(format!(
            "capability ack reported max_datagram_size={} but negotiated {}",
            ack.max_datagram_size, resolution.max_segment_datagram_size
        )));
    }
    if ack.dplpmtud != expected_dplpmtud {
        return Err(Error::ProtocolViolation(format!(
            "capability ack dplpmtud={} but report used {}",
            ack.dplpmtud, expected_dplpmtud
        )));
    }
    Ok(())
}
struct ControlStreamWriter {
    stream: SendStream,
}
impl ControlStreamWriter {
    async fn new(mut stream: SendStream, direction: ControlStreamDirection) -> Result<Self> {
        stream
            .set_priority(CONTROL_STREAM_PRIORITY)
            .map_err(|error| Error::Io(std::io::Error::other(error)))?;
        stream
            .write_all(CONTROL_STREAM_PREFACE)
            .await
            .map_err(|e| Error::Io(std::io::Error::from(e)))?;
        stream
            .write_u8(direction.marker())
            .await
            .map_err(|e| Error::Io(std::io::Error::from(e)))?;
        stream
            .flush()
            .await
            .map_err(|e| Error::Io(std::io::Error::from(e)))?;
        Ok(Self { stream })
    }
    async fn send_frame(&mut self, frame: &ControlFrame) -> Result<()> {
        let bytes = to_bytes(frame)?;
        if bytes.len() > MAX_CONTROL_FRAME_LEN {
            return Err(Error::FrameTooLarge {
                len: bytes.len(),
                max: MAX_CONTROL_FRAME_LEN,
            });
        }
        self.stream
            .write_u32_le(bytes.len() as u32)
            .await
            .map_err(|e| Error::Io(std::io::Error::from(e)))?;
        self.stream
            .write_all(&bytes)
            .await
            .map_err(|e| Error::Io(std::io::Error::from(e)))?;
        self.stream
            .flush()
            .await
            .map_err(|e| Error::Io(std::io::Error::from(e)))?;
        Ok(())
    }
}
struct ControlStreamReader {
    stream: RecvStream,
}
impl ControlStreamReader {
    async fn new(mut stream: RecvStream, expected: ControlStreamDirection) -> Result<Self> {
        let mut preface = [0u8; CONTROL_STREAM_PREFACE.len()];
        match stream.read_exact(&mut preface).await {
            Ok(()) => {}
            Err(ReadExactError::FinishedEarly(_)) => return Err(Error::ControlStreamClosed),
            Err(ReadExactError::ReadError(e)) => return Err(Error::Io(std::io::Error::from(e))),
        }
        if preface != *CONTROL_STREAM_PREFACE {
            return Err(Error::BadPreface);
        }
        let marker = match stream.read_u8().await {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(Error::ControlStreamClosed);
            }
            Err(e) => return Err(Error::Io(e)),
        };
        let found = ControlStreamDirection::from_marker(marker).ok_or(Error::BadPreface)?;
        if found != expected {
            return Err(Error::WrongDirection { expected, found });
        }
        Ok(Self { stream })
    }
    async fn next_frame(&mut self) -> Result<ControlFrame> {
        let mut len_buf = [0u8; 4];
        match self.stream.read_exact(&mut len_buf).await {
            Ok(()) => {}
            Err(ReadExactError::FinishedEarly(_)) => return Err(Error::ControlStreamClosed),
            Err(ReadExactError::ReadError(e)) => return Err(Error::Io(std::io::Error::from(e))),
        }
        let len = u32::from_le_bytes(len_buf) as usize;
        if len > MAX_CONTROL_FRAME_LEN {
            return Err(Error::FrameTooLarge {
                len,
                max: MAX_CONTROL_FRAME_LEN,
            });
        }
        let mut buf = vec![0u8; len];
        match self.stream.read_exact(&mut buf).await {
            Ok(()) => {}
            Err(ReadExactError::FinishedEarly(_)) => return Err(Error::ControlStreamClosed),
            Err(ReadExactError::ReadError(e)) => return Err(Error::Io(std::io::Error::from(e))),
        }
        let frame = decode_control_frame(buf.as_slice())?;
        Ok(frame)
    }
}

fn decode_control_frame(bytes: &[u8]) -> Result<ControlFrame> {
    // `decode_from_bytes` derives a cumulative allocation budget from the
    // complete wire frame. This is intentionally narrower than the ambient
    // archive limit used by `deserialize_from`, while preserving supported
    // Norito compression and layout flags.
    Ok(decode_from_bytes(bytes)?)
}
#[derive(Debug)]
struct ParsedMultiaddr {
    host: IpAddr,
    port: u16,
    server_name: String,
}
fn parse_multiaddr(addr: &str) -> Result<ParsedMultiaddr> {
    let trimmed = addr.trim();
    if trimmed.is_empty() {
        return Err(Error::InvalidMultiaddr(addr.into()));
    }
    let mut parts = trimmed.trim_matches('/').split('/');
    let proto = parts
        .next()
        .ok_or_else(|| Error::InvalidMultiaddr(addr.into()))?;
    match proto {
        "ip4" => {
            let host = parts
                .next()
                .ok_or_else(|| Error::InvalidMultiaddr(addr.into()))?;
            let ip: Ipv4Addr = host
                .parse()
                .map_err(|_| Error::InvalidMultiaddr(addr.into()))?;
            let port = parse_port(&mut parts, addr)?;
            Ok(ParsedMultiaddr {
                host: IpAddr::V4(ip),
                port,
                // Use a stable SNI value. Streaming authenticates the self-signed
                // certificate by fingerprint, so SNI is advisory but must still be
                // syntactically valid for the QUIC stack.
                server_name: "nsc.local".to_string(),
            })
        }
        "ip6" => {
            let host = parts
                .next()
                .ok_or_else(|| Error::InvalidMultiaddr(addr.into()))?;
            let ip: Ipv6Addr = host
                .parse()
                .map_err(|_| Error::InvalidMultiaddr(addr.into()))?;
            let port = parse_port(&mut parts, addr)?;
            Ok(ParsedMultiaddr {
                host: IpAddr::V6(ip),
                port,
                server_name: "nsc.local".to_string(),
            })
        }
        other => Err(Error::UnsupportedProtocol(other.into())),
    }
}
fn parse_port<'a, I>(parts: &mut I, original: &str) -> Result<u16>
where
    I: Iterator<Item = &'a str>,
{
    let transport = parts.next().ok_or_else(|| Error::MissingPort)?;
    if transport != "udp" {
        return Err(Error::UnsupportedProtocol(transport.into()));
    }
    let port_str = parts.next().ok_or_else(|| Error::MissingPort)?;
    let port: u16 = port_str
        .parse()
        .map_err(|_| Error::InvalidMultiaddr(original.into()))?;
    if let Some(extra) = parts.next() {
        if extra != "quic" {
            return Err(Error::UnsupportedProtocol(extra.into()));
        }
        if let Some(rem) = parts.next() {
            return Err(Error::UnsupportedProtocol(rem.into()));
        }
    }
    Ok(port)
}

fn build_transport_config(settings: TransportConfigSettings) -> Result<Arc<TransportConfig>> {
    let datagrams_enabled = settings.max_datagram_size != 0
        || settings.datagram_receive_buffer != 0
        || settings.datagram_send_buffer != 0;
    if datagrams_enabled {
        if settings.max_datagram_size == 0 || u16::try_from(settings.max_datagram_size).is_err() {
            return Err(Error::TransportConfig(
                "DATAGRAM payload limit must be between 1 and u16::MAX".into(),
            ));
        }
        // Quinn charges one private Datagram (a Bytes value) per queue entry.
        let minimum_buffer = settings
            .max_datagram_size
            .checked_add(core::mem::size_of::<Bytes>())
            .ok_or_else(|| {
                Error::TransportConfig("DATAGRAM buffer geometry overflows usize".into())
            })?;
        if settings.datagram_receive_buffer < minimum_buffer
            || settings.datagram_send_buffer < minimum_buffer
        {
            return Err(Error::TransportConfig(format!(
                "DATAGRAM receive and send buffers must each hold a {minimum_buffer}-byte entry"
            )));
        }
    }
    let mut transport = TransportConfig::default();
    // Quinn defaults to zero concurrent streams, which makes `open_uni()`/`accept_uni()` hang
    // indefinitely. Streaming sessions always use at least one uni stream in each direction for
    // control frames.
    // Each endpoint permanently consumes one unidirectional stream for control. The remaining 15
    // bound the number of unfinished per-segment media streams a peer can hold concurrently.
    transport.max_concurrent_uni_streams(VarInt::from_u32(MAX_CONCURRENT_UNI_STREAMS));
    // The protocol has no bidirectional stream role. Advertising any credit would let a peer
    // retain streams that the application never accepts or validates.
    transport.max_concurrent_bidi_streams(VarInt::from_u32(0));
    // Disabled settings omit DATAGRAM support. Explicit bounded settings
    // remain available to private requalification; public constructors still
    // reject every QUIC endpoint before binding.
    transport.datagram_receive_buffer_size(
        datagrams_enabled.then_some(settings.datagram_receive_buffer),
    );
    transport.datagram_send_buffer_size(settings.datagram_send_buffer);
    transport.keep_alive_interval(Some(settings.idle_timeout / 2));
    let idle = IdleTimeout::try_from(settings.idle_timeout)
        .map_err(|e| Error::TransportConfig(e.to_string()))?;
    transport.max_idle_timeout(Some(idle));
    Ok(Arc::new(transport))
}
#[cfg(all(test, feature = "quic"))]
mod tests {
    use super::*;
    use iroha_crypto::streaming::StreamingSession;
    use norito::streaming::{
        AudioCapability, CapabilityAck, CapabilityFlags, CapabilityReport, CapabilityRole,
        ChunkDescriptor, EncryptionSuite, EntropyMode, FecScheme, FeedbackHintFrame, Hash,
        ManifestAnnounceFrame, ManifestV1, ProfileId, ReceiverReport, Resolution, StreamMetadata,
        TransportCapabilities,
    };
    use std::future::Future;
    use tokio::time::{Duration as TokioDuration, sleep, timeout};
    const TEST_TIMEOUT: TokioDuration = TokioDuration::from_secs(10);
    async fn within<T>(label: &'static str, fut: impl Future<Output = T>) -> T {
        timeout(TEST_TIMEOUT, fut)
            .await
            .unwrap_or_else(|_| panic!("{label} timed out"))
    }
    fn hash(byte: u8) -> Hash {
        [byte; 32]
    }
    fn manifest() -> ManifestAnnounceFrame {
        ManifestAnnounceFrame {
            manifest: ManifestV1 {
                stream_id: hash(1),
                protocol_version: 1,
                segment_number: 10,
                published_at: 1_701_234_567,
                profile: ProfileId::BASELINE,
                entropy_mode: EntropyMode::RansBundled,
                entropy_tables_checksum: None,
                da_endpoint: "/ip4/127.0.0.1/udp/9000/quic".into(),
                chunk_root: hash(2),
                content_key_id: 5,
                nonce_salt: hash(3),
                chunk_descriptors: vec![ChunkDescriptor {
                    chunk_id: 0,
                    offset: 0,
                    length: 3,
                    commitment: hash(4),
                    parity: false,
                }],
                transport_capabilities_hash: [0; 32],
                encryption_suite: EncryptionSuite::X25519ChaCha20Poly1305(hash(5)),
                fec_suite: FecScheme::Rs12_10,
                privacy_routes: Vec::new(),
                neural_bundle: None,
                audio_summary: None,
                public_metadata: StreamMetadata {
                    title: "NSC Test Stream".into(),
                    description: Some("integration harness".into()),
                    access_policy_id: Some(hash(6)),
                    tags: vec!["test".into(), "nsc".into()],
                },
                capabilities: CapabilityFlags::from_bits(0b101),
                signature: [0xAA; 64],
            },
        }
    }
    fn capability_report(protocol_version: u16) -> CapabilityReport {
        CapabilityReport {
            stream_id: hash(11),
            endpoint_role: CapabilityRole::Viewer,
            protocol_version,
            max_resolution: Resolution::R1080p,
            hdr_supported: false,
            capture_hdr: false,
            neural_bundles: vec!["bundle-v1".into()],
            audio_caps: AudioCapability {
                sample_rates: vec![48_000],
                ambisonics: false,
                max_channels: 2,
            },
            feature_bits: CapabilityFlags::from_bits(0b10),
            max_datagram_size: 1_024,
            dplpmtud: false,
        }
    }
    fn capability_ack(report: &CapabilityReport, max_datagram_size: u16) -> CapabilityAck {
        CapabilityAck {
            stream_id: report.stream_id,
            accepted_version: report.protocol_version,
            negotiated_features: report.feature_bits,
            max_datagram_size,
            dplpmtud: report.dplpmtud,
        }
    }
    fn capability_resolution() -> TransportCapabilityResolution {
        let capabilities = TransportCapabilities {
            max_segment_datagram_size: 1_024,
            ..TransportCapabilities::kyber768_default()
        };
        norito::streaming::resolve_transport_capabilities(&capabilities, &capabilities)
            .expect("default capabilities resolve")
    }
    #[test]
    fn control_frame_decode_uses_wire_derived_allocation_budget() {
        const DECLARED_EXPANSION: u64 = 63 * 1024 * 1024;
        const EXPECTED_WIRE_DERIVED_LIMIT: u64 = (MAX_CONTROL_FRAME_LEN as u64) * 64 + 64 * 1024;
        let frame = ControlFrame::CapabilityReport(capability_report(1));
        let encoded =
            norito::to_compressed_bytes(&frame, Some(norito::CompressionConfig::default()))
                .expect("compress control frame");
        assert!(matches!(
            decode_control_frame(&encoded).expect("valid compressed control frame"),
            ControlFrame::CapabilityReport(_)
        ));

        let mut forged = encoded;
        forged.resize(MAX_CONTROL_FRAME_LEN, 0);
        let length_offset = 4 + 1 + 1 + 16 + 1;
        forged[length_offset..length_offset + 8].copy_from_slice(&DECLARED_EXPANSION.to_le_bytes());
        let error = decode_control_frame(&forged)
            .expect_err("attacker-declared expansion must exceed the wire-derived budget");
        assert!(
            matches!(
                &error,
                Error::Norito(norito::Error::TotalAllocationExceeded { attempted, limit })
                    if *attempted == DECLARED_EXPANSION
                        && *limit == EXPECTED_WIRE_DERIVED_LIMIT
            ),
            "unexpected error: {error:?}"
        );
    }
    #[test]
    fn shipping_streaming_transport_disables_quinn_datagram_queues() {
        let settings = TransportConfigSettings::default();
        assert_eq!(settings.max_datagram_size, 0);
        assert_eq!(settings.datagram_receive_buffer, 0);
        assert_eq!(settings.datagram_send_buffer, 0);
        build_transport_config(settings)
            .expect("dormant stream-only QUIC transport must remain testable");

        for enabled in [
            TransportConfigSettings {
                max_datagram_size: 1,
                ..settings
            },
            TransportConfigSettings {
                datagram_receive_buffer: 1,
                ..settings
            },
            TransportConfigSettings {
                datagram_send_buffer: 1,
                ..settings
            },
        ] {
            let error = build_transport_config(enabled)
                .expect_err("each incomplete DATAGRAM configuration must fail closed");
            let Error::TransportConfig(reason) = error else {
                panic!("unexpected error: {error:?}");
            };
            assert!(reason.contains("DATAGRAM"));
        }
    }
    #[test]
    fn requalification_datagram_geometry_accepts_exact_entry_and_rejects_incomplete_buffers() {
        let payload = 1_200;
        let minimum_buffer = payload + core::mem::size_of::<Bytes>();
        let settings = TransportConfigSettings {
            max_datagram_size: payload,
            datagram_receive_buffer: minimum_buffer,
            datagram_send_buffer: minimum_buffer,
            ..TransportConfigSettings::default()
        };
        build_transport_config(settings).expect("an exact fixed-overhead DATAGRAM entry fits");
        for invalid in [
            TransportConfigSettings {
                datagram_receive_buffer: minimum_buffer - 1,
                ..settings
            },
            TransportConfigSettings {
                datagram_send_buffer: minimum_buffer - 1,
                ..settings
            },
            TransportConfigSettings {
                max_datagram_size: 0,
                ..settings
            },
            TransportConfigSettings {
                max_datagram_size: usize::from(u16::MAX) + 1,
                ..settings
            },
            TransportConfigSettings {
                max_datagram_size: usize::MAX,
                ..settings
            },
        ] {
            assert!(matches!(
                build_transport_config(invalid),
                Err(Error::TransportConfig(_))
            ));
        }
        // Valid private geometry never opens the public shipping transport.
        assert!(matches!(
            validate_shipping_quic_dependency(),
            Err(Error::TransportConfig(_))
        ));
    }
    #[tokio::test]
    async fn public_streaming_endpoints_reject_unqualified_quinn_before_binding() {
        let settings = TransportConfigSettings::default();
        let server_error = match StreamingServer::bind(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            settings,
        )
        .await
        {
            Ok(_) => panic!("public server must reject unqualified Quinn"),
            Err(error) => error,
        };
        let client_error = match StreamingClient::connect(
            "/ip4/127.0.0.1/udp/9/quic",
            [0; iroha_crypto::Hash::LENGTH],
            settings,
        )
        .await
        {
            Ok(_) => panic!("public client must reject unqualified Quinn"),
            Err(error) => error,
        };
        for error in [server_error, client_error] {
            let Error::TransportConfig(reason) = error else {
                panic!("unexpected error: {error:?}");
            };
            assert!(reason.contains("quinn-proto 0.11.18"));
            assert!(reason.contains("transport requalification"));
            assert!(reason.contains("requalification"));
        }
    }
    #[test]
    fn media_window_validation_enforces_deterministic_order_and_bounds() {
        let source = MediaChunk {
            chunk_id: 1,
            is_parity: false,
            payload: Bytes::from_static(b"source"),
        };
        let parity = MediaChunk {
            chunk_id: 2,
            is_parity: true,
            payload: Bytes::from_static(b"parity"),
        };
        validate_media_window(9, Some(8), &[source.clone(), parity.clone()])
            .expect("ordered bounded window");

        for (chunks, expected) in [
            (
                vec![
                    source.clone(),
                    MediaChunk {
                        chunk_id: 0,
                        ..source.clone()
                    },
                ],
                "strictly greater",
            ),
            (vec![source.clone(), source.clone()], "strictly greater"),
            (
                vec![
                    parity.clone(),
                    MediaChunk {
                        chunk_id: 3,
                        ..source.clone()
                    },
                ],
                "source chunks must precede",
            ),
            (
                vec![MediaChunk {
                    payload: Bytes::new(),
                    ..source.clone()
                }],
                "empty payload",
            ),
        ] {
            let error = validate_media_window(9, Some(8), &chunks)
                .expect_err("malformed window must be rejected");
            assert!(error.to_string().contains(expected), "{error}");
        }

        let too_many = (0..=MAX_MEDIA_FRAMES_PER_WINDOW)
            .map(|chunk_id| MediaChunk {
                chunk_id: u16::try_from(chunk_id).expect("small fixture id"),
                is_parity: false,
                payload: Bytes::from_static(b"x"),
            })
            .collect::<Vec<_>>();
        let error = validate_media_window(9, Some(8), &too_many)
            .expect_err("frame count must be bounded before per-frame validation");
        assert!(error.to_string().contains("maximum is 18"));

        let error = validate_media_window(8, Some(8), &[source])
            .expect_err("segment numbers must increase monotonically");
        assert!(error.to_string().contains("previously completed segment 8"));
    }
    #[tokio::test]
    async fn datagram_inbox_bounds_count_and_bytes_and_revalidates_policy() {
        let inbox = DatagramInbox::new(MAX_DATAGRAM_INBOX_ENTRIES + 32);
        for _ in 0..(MAX_DATAGRAM_INBOX_ENTRIES + 32) {
            inbox
                .admit(Bytes::from_static(&[1]), 8)
                .expect("configured pre-negotiation DATAGRAM");
        }
        {
            let state = inbox.state.lock().expect("inbox state");
            assert_eq!(state.frames.len(), MAX_DATAGRAM_INBOX_ENTRIES);
            assert_eq!(state.bytes, MAX_DATAGRAM_INBOX_ENTRIES);
        }

        let inbox = DatagramInbox::new(8);
        inbox
            .admit(Bytes::from_static(&[1, 2, 3, 4]), 8)
            .expect("first DATAGRAM");
        inbox
            .admit(Bytes::from_static(&[5, 6, 7, 8]), 8)
            .expect("second DATAGRAM");
        inbox
            .admit(Bytes::from_static(&[9]), 8)
            .expect("unreliable inbox may drop at its byte bound");
        {
            let state = inbox.state.lock().expect("inbox state");
            assert_eq!(state.frames.len(), 2);
            assert_eq!(state.bytes, 8);
        }
        assert!(inbox.apply_policy(0).is_some());
        assert!(matches!(
            inbox.recv().await,
            Err(Error::ProtocolViolation(_))
        ));

        let disabled = DatagramInbox::new(8);
        assert!(disabled.apply_policy(0).is_none());
        assert!(
            disabled
                .admit(Bytes::from_static(&[1]), 8)
                .expect_err("policy update and admission share one lock")
                .contains("disabled")
        );
        let bounded = DatagramInbox::new(8);
        assert!(bounded.apply_policy(4).is_none());
        assert!(bounded.admit(Bytes::from_static(&[1, 2, 3, 4]), 8).is_ok());
        assert!(
            bounded
                .admit(Bytes::from_static(&[1, 2, 3, 4, 5]), 8)
                .expect_err("post-negotiation admission must use the negotiated bound")
                .contains("above negotiated maximum 4")
        );
    }
    #[test]
    fn datagram_inbox_compacts_packet_backing_before_retention() {
        struct TrackedOwner {
            bytes: Vec<u8>,
            dropped: Arc<std::sync::atomic::AtomicBool>,
        }
        impl AsRef<[u8]> for TrackedOwner {
            fn as_ref(&self) -> &[u8] {
                &self.bytes
            }
        }
        impl Drop for TrackedOwner {
            fn drop(&mut self) {
                self.dropped
                    .store(true, std::sync::atomic::Ordering::Release);
            }
        }

        let dropped = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let packet = Bytes::from_owner(TrackedOwner {
            bytes: vec![0_u8; 64 * 1024],
            dropped: Arc::clone(&dropped),
        });
        let payload = packet.slice(23..27);
        drop(packet);
        let inbox = DatagramInbox::new(4);
        inbox.admit(payload, 4).expect("small DATAGRAM is retained");

        assert!(dropped.load(std::sync::atomic::Ordering::Acquire));
        let state = inbox.state.lock().expect("inbox state");
        assert_eq!(
            state.frames.front().map(Bytes::as_ref),
            Some(&[0, 0, 0, 0][..])
        );
        assert_eq!(state.bytes, 4);
    }
    #[test]
    fn streaming_certificate_pin_rejects_another_certificate() {
        let rcgen::CertifiedKey { cert, .. } =
            rcgen::generate_simple_self_signed(["nsc.local".to_owned()])
                .expect("generate certificate");
        let cert_der = cert.der().clone().into_owned();
        let fingerprint = crate::transport::certificate_fingerprint(cert_der.as_ref());
        let server_name =
            rustls::pki_types::ServerName::try_from("nsc.local").expect("valid server name");
        let now = rustls::pki_types::UnixTime::since_unix_epoch(Duration::ZERO);
        let verifier = crate::transport::CertificateKeyProofVerifier::pinned(fingerprint);
        verifier
            .verify_server_cert(&cert_der, &[], &server_name, &[], now)
            .expect("matching certificate fingerprint");
        let mut wrong_fingerprint = fingerprint;
        wrong_fingerprint[0] ^= 1;
        let verifier = crate::transport::CertificateKeyProofVerifier::pinned(wrong_fingerprint);
        let error = verifier
            .verify_server_cert(&cert_der, &[], &server_name, &[], now)
            .expect_err("different certificate fingerprint must fail closed");
        assert!(error.to_string().contains("fingerprint mismatch"));
    }
    #[tokio::test]
    async fn accept_rejects_client_that_never_opens_control_stream() {
        let settings = TransportConfigSettings {
            idle_timeout: TokioDuration::from_millis(100),
            ..TransportConfigSettings::default()
        };
        let server = match StreamingServer::bind_for_requalification(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            settings,
        )
        .await
        {
            Ok(server) => server,
            Err(Error::Io(err)) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("quic test skipped: {err}");
                return;
            }
            Err(error) => panic!("server bind failed: {error:?}"),
        };
        let listen_addr = server.local_addr().expect("listen addr");
        let fingerprint = server.certificate_fingerprint();
        let raw_client = async move {
            let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).expect("endpoint");
            let verifier: Arc<dyn ServerCertVerifier> = Arc::new(
                crate::transport::CertificateKeyProofVerifier::pinned(fingerprint),
            );
            let mut tls_config = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth();
            tls_config.alpn_protocols = vec![ALPN.to_vec()];
            let crypto = QuinnRustlsClientConfig::try_from(Arc::new(tls_config))
                .expect("QUIC client config");
            let mut client_config = ClientConfig::new(Arc::new(crypto));
            client_config.transport_config(build_transport_config(settings).expect("transport"));
            endpoint.set_default_client_config(client_config);
            let connection = endpoint
                .connect(listen_addr, "nsc.local")
                .expect("connect start")
                .await
                .expect("QUIC handshake");
            // Keep the transport alive beyond the setup deadline without ever
            // opening the required viewer-to-publisher control stream.
            sleep(TokioDuration::from_millis(250)).await;
            connection.close(VarInt::from_u32(0), &[]);
            endpoint.close(VarInt::from_u32(0), &[]);
        };
        let (accepted, ()) =
            tokio::join!(within("server setup deadline", server.accept()), raw_client);
        assert!(matches!(accepted, Err(Error::SetupTimeout)));
        within("server.shutdown", server.shutdown()).await;
    }
    #[tokio::test]
    async fn setup_watchdog_closes_an_active_connection_between_api_calls() {
        let settings = TransportConfigSettings {
            idle_timeout: TokioDuration::from_millis(150),
            ..TransportConfigSettings::default()
        };
        let server = match StreamingServer::bind_for_requalification(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            settings,
        )
        .await
        {
            Ok(server) => server,
            Err(Error::Io(err)) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("quic test skipped: {err}");
                return;
            }
            Err(error) => panic!("server bind failed: {error:?}"),
        };
        let listen_addr = server.local_addr().expect("listen addr");
        let fingerprint = server.certificate_fingerprint();
        let multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic", listen_addr.port());
        let (accepted, connected) = tokio::join!(
            within("server.accept", server.accept()),
            within(
                "client.connect",
                StreamingClient::connect_for_requalification(&multiaddr, fingerprint, settings)
            )
        );
        let publisher = accepted.expect("publisher control streams");
        let mut client = connected.expect("viewer control streams");
        let raw_connection = client.connection().connection.clone();
        let transport_activity = tokio::spawn(async move {
            loop {
                if raw_connection
                    .send_datagram(Bytes::from_static(&[1]))
                    .is_err()
                {
                    break;
                }
                sleep(TokioDuration::from_millis(20)).await;
            }
        });

        within("setup watchdog close", publisher.closed()).await;
        transport_activity.abort();
        within("client.close", client.close()).await;
        within("server.shutdown", server.shutdown()).await;
    }
    #[test]
    fn capability_report_zero_protocol_version_rejected() {
        let report = capability_report(0);
        let err = validate_capability_report(&report).expect_err("zero protocol version rejected");
        match err {
            Error::ProtocolViolation(reason) => {
                assert!(reason.contains("zero protocol version"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
    #[test]
    fn capability_report_non_viewer_role_rejected() {
        let mut report = capability_report(1);
        report.endpoint_role = CapabilityRole::Publisher;
        let err = validate_capability_report(&report).expect_err("non-viewer report role rejected");
        match err {
            Error::ProtocolViolation(reason) => {
                assert!(reason.contains("expected viewer capability report"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
    #[test]
    fn capability_ack_binding_rejects_mismatched_report_echo() {
        let report = capability_report(3);
        let resolution = capability_resolution();
        let valid_ack = capability_ack(&report, resolution.max_segment_datagram_size);
        validate_capability_ack_binding(
            &valid_ack,
            report.stream_id,
            report.protocol_version,
            report.dplpmtud,
            resolution,
        )
        .expect("matching ack accepted");
        let mut wrong_stream = valid_ack.clone();
        wrong_stream.stream_id = hash(12);
        let err = validate_capability_ack_binding(
            &wrong_stream,
            report.stream_id,
            report.protocol_version,
            report.dplpmtud,
            resolution,
        )
        .expect_err("stream id mismatch rejected");
        match err {
            Error::ProtocolViolation(reason) => assert!(reason.contains("stream_id")),
            other => panic!("unexpected error: {other:?}"),
        }
        let mut wrong_version = valid_ack.clone();
        wrong_version.accepted_version = 2;
        let err = validate_capability_ack_binding(
            &wrong_version,
            report.stream_id,
            report.protocol_version,
            report.dplpmtud,
            resolution,
        )
        .expect_err("version mismatch rejected");
        match err {
            Error::ProtocolViolation(reason) => assert!(reason.contains("accepted_version")),
            other => panic!("unexpected error: {other:?}"),
        }
        let mut wrong_datagram = valid_ack;
        wrong_datagram.max_datagram_size = resolution.max_segment_datagram_size - 1;
        let err = validate_capability_ack_binding(
            &wrong_datagram,
            report.stream_id,
            report.protocol_version,
            report.dplpmtud,
            resolution,
        )
        .expect_err("datagram mismatch rejected");
        match err {
            Error::ProtocolViolation(reason) => assert!(reason.contains("max_datagram_size")),
            other => panic!("unexpected error: {other:?}"),
        }
        let mut wrong_dplpmtud = capability_ack(&report, resolution.max_segment_datagram_size);
        wrong_dplpmtud.dplpmtud = !report.dplpmtud;
        let err = validate_capability_ack_binding(
            &wrong_dplpmtud,
            report.stream_id,
            report.protocol_version,
            report.dplpmtud,
            resolution,
        )
        .expect_err("dplpmtud mismatch rejected");
        match err {
            Error::ProtocolViolation(reason) => assert!(reason.contains("dplpmtud")),
            other => panic!("unexpected error: {other:?}"),
        }
    }
    #[tokio::test]
    async fn capability_negotiation_and_datagram_roundtrip() {
        let settings = TransportConfigSettings {
            max_datagram_size: 1_200,
            datagram_receive_buffer: 64 * 1024,
            datagram_send_buffer: 64 * 1024,
            ..TransportConfigSettings::default()
        };
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = StreamingServer::bind_for_requalification(server_addr, settings)
            .await
            .expect("real loopback QUIC listener is required for DATAGRAM qualification");
        let listen_addr = server.local_addr().expect("listen addr");
        let server_certificate_fingerprint = server.certificate_fingerprint();
        let (datagram_read_tx, datagram_read_rx) = tokio::sync::oneshot::channel();
        let server_task = {
            let server = server.clone();
            async move {
                let incoming = within("endpoint.accept", server.endpoint.accept())
                    .await
                    .expect("incoming");
                let connecting = incoming.accept().expect("incoming.accept");
                let connection = within("server.handshake", connecting)
                    .await
                    .expect("handshake");
                let mut conn = within(
                    "server.streaming_conn",
                    StreamingConnection::new(connection, EndpointRole::Publisher, settings),
                )
                .await
                .expect("streaming conn");
                let publisher_caps = TransportCapabilities {
                    max_segment_datagram_size: settings.max_datagram_size as u16,
                    ..TransportCapabilities::kyber768_default()
                };
                let (report, transport_resolution) = within(
                    "publisher_handshake",
                    CapabilityNegotiation::publisher_handshake(
                        &mut conn,
                        publisher_caps.clone(),
                        |_| {},
                    ),
                )
                .await
                .expect("report");
                assert!(transport_resolution.use_datagram);
                assert_eq!(
                    transport_resolution.max_segment_datagram_size,
                    settings.max_datagram_size as u16
                );
                assert_eq!(report.endpoint_role, CapabilityRole::Viewer);
                let ack = CapabilityAck {
                    stream_id: report.stream_id,
                    accepted_version: report.protocol_version,
                    negotiated_features: CapabilityFlags::from_bits(
                        report.feature_bits.bits() | 0b1,
                    ),
                    max_datagram_size: transport_resolution.max_segment_datagram_size,
                    dplpmtud: report.dplpmtud,
                };
                let ack_frame = ControlFrame::CapabilityAck(ack.clone());
                within("send_ack", conn.send_control_frame(&ack_frame))
                    .await
                    .expect("ack");
                let announce = manifest();
                let transport_hash = transport_resolution.capabilities_hash();
                let mut manifest_with_hash = announce.clone();
                manifest_with_hash.manifest.transport_capabilities_hash = transport_hash;
                within(
                    "send_manifest_announce",
                    conn.send_control_frame(&ControlFrame::ManifestAnnounce(Box::new(
                        manifest_with_hash.clone(),
                    ))),
                )
                .await
                .expect("announce");
                let chunk = vec![0xDE, 0xAD, 0xBE, 0xEF];
                within("send_datagram", conn.send_datagram(&chunk))
                    .await
                    .expect("datagram");
                datagram_read_rx.await.expect("viewer read datagram");
                for _ in 0..1_024 {
                    conn.connection
                        .send_datagram(Bytes::new())
                        .expect("raw peer can queue an empty DATAGRAM burst");
                }
                let _ = within("wait_empty_datagram_close", conn.closed()).await;
            }
        };
        let viewer_task = async {
            let multiaddr = format!("/ip4/127.0.0.1/udp/{}/quic", listen_addr.port());
            let parsed = parse_multiaddr(&multiaddr).expect("multiaddr");
            let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap()).expect("endpoint");
            let verifier: Arc<dyn ServerCertVerifier> =
                Arc::new(crate::transport::CertificateKeyProofVerifier::pinned(
                    server_certificate_fingerprint,
                ));
            let mut tls_config = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth();
            tls_config.enable_early_data = false;
            tls_config.alpn_protocols = vec![ALPN.to_vec()];
            let tls_config = Arc::new(tls_config);
            let crypto =
                QuinnRustlsClientConfig::try_from(Arc::clone(&tls_config)).expect("tls config");
            let mut client_config = ClientConfig::new(Arc::new(crypto));
            let transport = build_transport_config(settings).expect("transport");
            client_config.transport_config(transport);
            endpoint.set_default_client_config(client_config);
            let server_addr = SocketAddr::new(parsed.host, parsed.port);
            let connecting = endpoint
                .connect(server_addr, &parsed.server_name)
                .expect("connect start");
            let connection = within("client.handshake", connecting)
                .await
                .expect("handshake");
            let connection = within(
                "client.streaming_conn",
                StreamingConnection::new(connection, EndpointRole::Viewer, settings),
            )
            .await
            .expect("streaming conn");
            let mut client = StreamingClient {
                endpoint,
                connection,
            };
            let recorded_hash = Arc::new(std::sync::Mutex::new(None));
            let max_size =
                u16::try_from(settings.max_datagram_size).expect("max_datagram_size fits u16");
            let report = CapabilityReport {
                stream_id: hash(9),
                endpoint_role: CapabilityRole::Viewer,
                protocol_version: 1,
                max_resolution: norito::streaming::Resolution::R1080p,
                hdr_supported: false,
                capture_hdr: false,
                neural_bundles: vec!["bundle-v1".into()],
                audio_caps: AudioCapability {
                    sample_rates: vec![48_000],
                    ambisonics: false,
                    max_channels: 2,
                },
                feature_bits: CapabilityFlags::from_bits(0b10),
                max_datagram_size: max_size,
                dplpmtud: false,
            };
            let viewer_caps = TransportCapabilities {
                max_segment_datagram_size: max_size,
                ..TransportCapabilities::kyber768_default()
            };
            let recorded_clone = Arc::clone(&recorded_hash);
            let (ack, transport_resolution) = within(
                "viewer_handshake",
                CapabilityNegotiation::viewer_handshake(
                    client.connection(),
                    viewer_caps,
                    report,
                    move |resolution| {
                        *recorded_clone.lock().expect("recorded hash lock") =
                            Some(resolution.capabilities_hash());
                    },
                ),
            )
            .await
            .unwrap();
            assert_eq!(ack.accepted_version, 1);
            assert!(transport_resolution.use_datagram);
            assert_eq!(transport_resolution.max_segment_datagram_size, max_size);
            assert_eq!(
                *recorded_hash.lock().expect("recorded hash checked"),
                Some(transport_resolution.capabilities_hash())
            );
            let frame = within(
                "next_control_frame",
                client.connection().next_control_frame(),
            )
            .await
            .unwrap();
            match frame {
                ControlFrame::ManifestAnnounce(frame) => {
                    assert_eq!(frame.manifest.stream_id, hash(1));
                    assert_eq!(
                        frame.manifest.transport_capabilities_hash,
                        transport_resolution.capabilities_hash()
                    );
                }
                other => panic!("unexpected frame: {other:?}"),
            }
            let chunk = within("recv_datagram", client.connection().recv_datagram())
                .await
                .unwrap();
            assert_eq!(chunk.as_ref(), &[0xDE, 0xAD, 0xBE, 0xEF]);
            datagram_read_tx.send(()).expect("notify publisher");
            let error = within("reject_empty_datagram", client.connection().recv_datagram())
                .await
                .expect_err("empty DATAGRAM must close the session");
            match error {
                Error::ProtocolViolation(reason) => {
                    assert!(
                        reason.contains("zero-length"),
                        "unexpected reason: {reason}"
                    );
                }
                other => panic!("unexpected error: {other:?}"),
            }
            within("client.close", client.close()).await;
        };
        tokio::join!(server_task, viewer_task);
        within("server.shutdown", server.shutdown()).await;
    }
    #[tokio::test]
    async fn feedback_frames_roundtrip_over_quic() {
        let settings = TransportConfigSettings::default();
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = match StreamingServer::bind_for_requalification(server_addr, settings).await {
            Ok(server) => server,
            Err(Error::Io(err)) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("quic test skipped: {err}");
                return;
            }
            Err(err) => panic!("server bind failed: {err:?}"),
        };
        let listen_addr = server.local_addr().expect("listen addr");
        let server_certificate_fingerprint = server.certificate_fingerprint();
        let server_task = {
            let server = server.clone();
            async move {
                let mut conn = within("server.accept", server.accept())
                    .await
                    .expect("accept");
                let mut session = StreamingSession::new(CapabilityRole::Publisher);
                let publisher_caps = TransportCapabilities::kyber768_default();
                let (report, resolution) = within(
                    "publisher_handshake",
                    CapabilityNegotiation::publisher_handshake(
                        &mut conn,
                        publisher_caps.clone(),
                        |_| {},
                    ),
                )
                .await
                .expect("handshake");
                session
                    .record_transport_capabilities(resolution.clone())
                    .expect("negotiated transport capabilities are valid");
                let ack = CapabilityAck {
                    stream_id: report.stream_id,
                    accepted_version: report.protocol_version,
                    negotiated_features: report.feature_bits,
                    max_datagram_size: resolution.max_segment_datagram_size,
                    dplpmtud: report.dplpmtud,
                };
                within(
                    "send_ack",
                    conn.send_control_frame(&ControlFrame::CapabilityAck(ack)),
                )
                .await
                .expect("ack");
                let mut received_hint = false;
                let mut received_report = false;
                while !(received_hint && received_report) {
                    match within("server.next_control_frame", conn.next_control_frame())
                        .await
                        .expect("frame")
                    {
                        ControlFrame::FeedbackHint(hint) => {
                            session
                                .process_feedback_hint(&hint)
                                .expect("feedback hint stream id matches session");
                            received_hint = true;
                        }
                        ControlFrame::ReceiverReport(report) => {
                            let parity = session
                                .process_receiver_report(&report)
                                .expect("receiver report stream id matches session");
                            assert_eq!(parity, 2);
                            received_report = true;
                        }
                        ControlFrame::CapabilityReport(_) => {
                            // Viewer may resend capability report during handshake; ignore.
                        }
                        other => panic!("unexpected frame: {other:?}"),
                    }
                }
                assert_eq!(session.latest_feedback_parity(), Some(2));
                conn.close();
            }
        };
        let viewer_task = async move {
            let mut client = within(
                "client.connect",
                StreamingClient::connect_for_requalification(
                    &format!("/ip4/127.0.0.1/udp/{}/quic", listen_addr.port()),
                    server_certificate_fingerprint,
                    settings,
                ),
            )
            .await
            .expect("client");
            let report = CapabilityReport {
                stream_id: hash(11),
                endpoint_role: CapabilityRole::Viewer,
                protocol_version: 1,
                max_resolution: Resolution::R1080p,
                hdr_supported: false,
                capture_hdr: false,
                neural_bundles: vec!["bundle-v1".into()],
                audio_caps: AudioCapability {
                    sample_rates: vec![48_000],
                    ambisonics: false,
                    max_channels: 2,
                },
                feature_bits: CapabilityFlags::from_bits(0b10),
                max_datagram_size: settings.max_datagram_size as u16,
                dplpmtud: false,
            };
            let viewer_caps = TransportCapabilities {
                max_segment_datagram_size: settings.max_datagram_size as u16,
                ..TransportCapabilities::kyber768_default()
            };
            let (_ack, _resolution) = within(
                "viewer_handshake",
                CapabilityNegotiation::viewer_handshake(
                    client.connection(),
                    viewer_caps,
                    report,
                    |_| {},
                ),
            )
            .await
            .expect("viewer handshake");
            let hint = FeedbackHintFrame {
                stream_id: hash(11),
                loss_ewma_q16: (0.08_f64 * 65536.0).round() as u32,
                latency_gradient_q16: 0,
                observed_rtt_ms: 30,
                report_interval_ms: 250,
                parity_chunks: 0,
            };
            let recv_report = ReceiverReport {
                stream_id: hint.stream_id,
                latest_segment: 12,
                layer_mask: 0,
                measured_throughput_kbps: 1_250,
                rtt_ms: 33,
                loss_percent_x100: 700,
                decoder_buffer_ms: 90,
                active_resolution: Resolution::R1080p,
                hdr_active: false,
                ecn_ce_count: 0,
                jitter_ms: 5,
                delivered_sequence: 900,
                parity_applied: 1,
                fec_budget: 1,
                sync_diagnostics: None,
            };
            within(
                "send_hint",
                client
                    .connection()
                    .send_control_frame(&ControlFrame::FeedbackHint(hint)),
            )
            .await
            .expect("send hint");
            within(
                "send_report",
                client
                    .connection()
                    .send_control_frame(&ControlFrame::ReceiverReport(recv_report)),
            )
            .await
            .expect("send report");
            // Wait for the publisher to process frames and close the connection before we tear down
            // our endpoint. Closing immediately can race with stream delivery and spuriously abort
            // the server-side receive loop.
            let _ = within("wait_server_close", client.connection().closed()).await;
            within("client.close", client.close()).await;
        };
        tokio::join!(server_task, viewer_task);
        within("server.shutdown", server.shutdown()).await;
    }
    #[tokio::test]
    async fn mtu_negotiation_clamps_asymmetric_local_limits_on_the_wire() {
        let server_settings = TransportConfigSettings {
            max_datagram_size: 1_200,
            datagram_receive_buffer: 64 * 1024,
            datagram_send_buffer: 64 * 1024,
            ..TransportConfigSettings::default()
        };
        let viewer_settings = TransportConfigSettings {
            max_datagram_size: 800,
            datagram_receive_buffer: 64 * 1024,
            datagram_send_buffer: 64 * 1024,
            ..TransportConfigSettings::default()
        };
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = StreamingServer::bind_for_requalification(server_addr, server_settings)
            .await
            .expect("real loopback QUIC listener is required for MTU qualification");
        let listen_addr = server.local_addr().expect("listen addr");
        let server_certificate_fingerprint = server.certificate_fingerprint();
        let (datagram_received_tx, datagram_received_rx) = tokio::sync::oneshot::channel();
        let server_task = {
            let server = server.clone();
            async move {
                let mut conn = within("server.accept", server.accept())
                    .await
                    .expect("accept");
                let mut publisher_caps = TransportCapabilities::kyber768_default();
                publisher_caps.max_segment_datagram_size = 1_350;
                let (report, resolution) = within(
                    "publisher_handshake",
                    CapabilityNegotiation::publisher_handshake(&mut conn, publisher_caps, |_| {}),
                )
                .await
                .expect("handshake");
                assert!(resolution.use_datagram);
                assert_eq!(resolution.max_segment_datagram_size, 800);
                assert_eq!(conn.max_datagram_size(), 800);
                assert!(conn.datagram_enabled());
                let ack = CapabilityAck {
                    stream_id: report.stream_id,
                    accepted_version: report.protocol_version,
                    negotiated_features: CapabilityFlags::from_bits(
                        report.feature_bits.bits() | 0b1,
                    ),
                    max_datagram_size: resolution.max_segment_datagram_size,
                    dplpmtud: report.dplpmtud,
                };
                within(
                    "send_ack",
                    conn.send_control_frame(&ControlFrame::CapabilityAck(ack)),
                )
                .await
                .expect("ack");
                let datagram = within("receive_negotiated_datagram", conn.recv_datagram())
                    .await
                    .expect("negotiated DATAGRAM delivery");
                assert_eq!(datagram.len(), 800);
                datagram_received_tx
                    .send(())
                    .expect("viewer still waits for DATAGRAM receipt");
            }
        };
        let viewer_task = async move {
            let mut client = within(
                "client.connect",
                StreamingClient::connect_for_requalification(
                    &format!("/ip4/127.0.0.1/udp/{}/quic", listen_addr.port()),
                    server_certificate_fingerprint,
                    viewer_settings,
                ),
            )
            .await
            .expect("client");
            let mut viewer_caps = TransportCapabilities::kyber768_default();
            viewer_caps.max_segment_datagram_size = 1_350;
            let report = CapabilityReport {
                stream_id: hash(7),
                endpoint_role: CapabilityRole::Viewer,
                protocol_version: 1,
                max_resolution: norito::streaming::Resolution::R1080p,
                hdr_supported: true,
                capture_hdr: true,
                neural_bundles: vec!["bundle-v2".into()],
                audio_caps: AudioCapability {
                    sample_rates: vec![48_000, 96_000],
                    ambisonics: false,
                    max_channels: 2,
                },
                feature_bits: CapabilityFlags::from_bits(0b11),
                max_datagram_size: 1_350,
                dplpmtud: true,
            };
            let (ack, resolution) = within(
                "viewer_handshake",
                CapabilityNegotiation::viewer_handshake(
                    client.connection(),
                    viewer_caps,
                    report,
                    |_| {},
                ),
            )
            .await
            .expect("handshake");
            assert!(resolution.use_datagram);
            assert_eq!(resolution.max_segment_datagram_size, 800);
            assert_eq!(ack.max_datagram_size, 800);
            assert_eq!(client.connection().max_datagram_size(), 800);
            assert!(client.connection().datagram_enabled());
            let payload = vec![0_u8; 801];
            let err = within(
                "send_oversized_datagram",
                client.connection().send_datagram(&payload),
            )
            .await
            .unwrap_err();
            match err {
                Error::DatagramTooLarge { max, .. } => assert_eq!(max, 800),
                other => panic!("unexpected error: {other:?}"),
            }
            within(
                "send_maximum_datagram",
                client.connection().send_datagram(&vec![0_u8; 800]),
            )
            .await
            .expect("maximum negotiated DATAGRAM size must be accepted");
            within("wait_datagram_receipt", datagram_received_rx)
                .await
                .expect("server received maximum-sized DATAGRAM");
            within("client.close", client.close()).await;
        };
        tokio::join!(server_task, viewer_task);
        within("server.shutdown", server.shutdown()).await;
    }
    #[tokio::test]
    async fn datagram_disabled_sets_zero_limit() {
        let settings = TransportConfigSettings::default();
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let server = match StreamingServer::bind_for_requalification(server_addr, settings).await {
            Ok(server) => server,
            Err(Error::Io(err)) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("quic test skipped: {err}");
                return;
            }
            Err(err) => panic!("server bind failed: {err:?}"),
        };
        let listen_addr = server.local_addr().expect("listen addr");
        let server_certificate_fingerprint = server.certificate_fingerprint();
        let server_task = {
            let server = server.clone();
            async move {
                let mut conn = within("server.accept", server.accept())
                    .await
                    .expect("accept");
                let mut publisher_caps = TransportCapabilities::kyber768_default();
                publisher_caps.supports_datagram = false;
                let (report, resolution) = within(
                    "publisher_handshake",
                    CapabilityNegotiation::publisher_handshake(&mut conn, publisher_caps, |_| {}),
                )
                .await
                .expect("handshake");
                assert!(!resolution.use_datagram);
                assert_eq!(resolution.max_segment_datagram_size, 0);
                assert_eq!(conn.max_datagram_size(), 0);
                assert!(!conn.datagram_enabled());
                let ack = CapabilityAck {
                    stream_id: report.stream_id,
                    accepted_version: report.protocol_version,
                    negotiated_features: CapabilityFlags::from_bits(report.feature_bits.bits()),
                    max_datagram_size: 0,
                    dplpmtud: report.dplpmtud,
                };
                within(
                    "send_ack",
                    conn.send_control_frame(&ControlFrame::CapabilityAck(ack)),
                )
                .await
                .expect("ack");
                within(
                    "send_media_window",
                    conn.send_media_window(
                        42,
                        &[
                            MediaChunk {
                                chunk_id: 3,
                                is_parity: false,
                                payload: Bytes::from_static(b"encrypted-source-a"),
                            },
                            MediaChunk {
                                chunk_id: 4,
                                is_parity: false,
                                payload: Bytes::from_static(b"encrypted-source-b"),
                            },
                            MediaChunk {
                                chunk_id: 5,
                                is_parity: true,
                                payload: Bytes::from_static(b"encrypted-parity"),
                            },
                        ],
                    ),
                )
                .await
                .expect("stream fallback media window");
                let mut unfinished =
                    within("open unfinished media stream", conn.connection.open_uni())
                        .await
                        .expect("open unfinished media stream");
                unfinished
                    .set_priority(MEDIA_STREAM_PRIORITY)
                    .expect("set unfinished stream priority");
                unfinished
                    .write_all(MEDIA_STREAM_PREFACE)
                    .await
                    .expect("unfinished stream preface");
                unfinished
                    .write_all(&43_u64.to_le_bytes())
                    .await
                    .expect("unfinished segment number");
                unfinished
                    .write_all(&1_u16.to_le_bytes())
                    .await
                    .expect("unfinished frame count");
                unfinished
                    .write_all(&6_u16.to_le_bytes())
                    .await
                    .expect("unfinished chunk id");
                unfinished
                    .write_all(&[0])
                    .await
                    .expect("unfinished parity flag");
                unfinished
                    .write_all(&1_u32.to_le_bytes())
                    .await
                    .expect("unfinished payload length");
                let _ = within("wait_client_close", conn.closed()).await;
                drop(unfinished);
            }
        };
        let viewer_task = async move {
            let mut client = within(
                "client.connect",
                StreamingClient::connect_for_requalification(
                    &format!("/ip4/127.0.0.1/udp/{}/quic", listen_addr.port()),
                    server_certificate_fingerprint,
                    settings,
                ),
            )
            .await
            .expect("client");
            let mut viewer_caps = TransportCapabilities::kyber768_default();
            viewer_caps.max_segment_datagram_size = 1024;
            let report = CapabilityReport {
                stream_id: hash(8),
                endpoint_role: CapabilityRole::Viewer,
                protocol_version: 1,
                max_resolution: norito::streaming::Resolution::R720p,
                hdr_supported: false,
                capture_hdr: false,
                neural_bundles: vec![],
                audio_caps: AudioCapability {
                    sample_rates: vec![48_000],
                    ambisonics: false,
                    max_channels: 2,
                },
                feature_bits: CapabilityFlags::from_bits(0b01),
                max_datagram_size: 1200,
                dplpmtud: false,
            };
            let (ack, resolution) = within(
                "viewer_handshake",
                CapabilityNegotiation::viewer_handshake(
                    client.connection(),
                    viewer_caps,
                    report,
                    |_| {},
                ),
            )
            .await
            .expect("handshake");
            assert!(!resolution.use_datagram);
            assert_eq!(resolution.max_segment_datagram_size, 0);
            assert_eq!(ack.max_datagram_size, 0);
            assert_eq!(client.connection().max_datagram_size(), 0);
            assert!(!client.connection().datagram_enabled());
            let media = within("recv_media_window", client.connection().recv_media_window())
                .await
                .expect("stream fallback media window");
            assert_eq!(media.segment_number, 42);
            assert_eq!(
                media.chunks,
                vec![
                    MediaChunk {
                        chunk_id: 3,
                        is_parity: false,
                        payload: Bytes::from_static(b"encrypted-source-a"),
                    },
                    MediaChunk {
                        chunk_id: 4,
                        is_parity: false,
                        payload: Bytes::from_static(b"encrypted-source-b"),
                    },
                    MediaChunk {
                        chunk_id: 5,
                        is_parity: true,
                        payload: Bytes::from_static(b"encrypted-parity"),
                    },
                ]
            );
            let payload = vec![0_u8; 1];
            let err = within("send_datagram", client.connection().send_datagram(&payload))
                .await
                .unwrap_err();
            match err {
                Error::DatagramTooLarge { max, .. } => assert_eq!(max, 0),
                other => panic!("unexpected error: {other:?}"),
            }
            let error = client
                .connection()
                .connection
                .send_datagram(Bytes::from_static(&[1]))
                .expect_err("the local transport must disable DATAGRAM sends");
            assert!(matches!(error, SendDatagramError::Disabled));
            client.connection().media_window_timeout = TokioDuration::from_millis(50);
            let error = within(
                "unfinished media stream deadline",
                client.connection().recv_media_window(),
            )
            .await
            .expect_err("an unfinished media stream must hit its absolute deadline");
            assert!(error.to_string().contains("absolute transfer deadline"));
            within("client.close", client.close()).await;
        };
        tokio::join!(server_task, viewer_task);
        within("server.shutdown", server.shutdown()).await;
    }
}
