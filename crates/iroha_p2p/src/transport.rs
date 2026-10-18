//! Authenticated peer transport and handshake support.
//!
//! Stock nodes use mandatory TLS 1.3 over TCP, with optional QUIC using the
//! same application identity and channel-binding invariants. No plaintext or
//! legacy Noise peer transport is selectable in the first release.
use rustls::{
    DigitallySignedStruct, Error as RustlsError, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
static SELF_SIGNED_SIGNATURE_ALGORITHMS: std::sync::LazyLock<
    rustls::crypto::WebPkiSupportedAlgorithms,
> = std::sync::LazyLock::new(|| {
    rustls::crypto::ring::default_provider().signature_verification_algorithms
});
const MAX_CONNECT_RESPONSE_HEADER_BYTES: usize = 8_192;
/// Exact ALPN negotiated by Iroha's raw TLS and QUIC P2P transports.
pub const P2P_ALPN: &[u8] = b"iroha-p2p/1";
/// Certificate verifier for self-signed transport certificates.
///
/// An unpinned verifier deliberately leaves naming and trust-root validation to the application
/// identity layer, but still verifies TLS `CertificateVerify`. That proof of possession is required
/// before a certificate fingerprint can serve as a channel binding: accepting a signature produced
/// by an unrelated key would let an attacker replay another node's certificate bytes. A pinned
/// verifier additionally authenticates the exact leaf fingerprint at the transport layer.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CertificateKeyProofVerifier {
    expected_fingerprint: Option<[u8; iroha_crypto::Hash::LENGTH]>,
}
impl CertificateKeyProofVerifier {
    /// Verify certificate-key possession while deferring identity to the signed P2P handshake.
    pub(crate) const fn unpinned() -> Self {
        Self {
            expected_fingerprint: None,
        }
    }
    /// Verify certificate-key possession and require one exact certificate fingerprint.
    pub(crate) const fn pinned(expected_fingerprint: [u8; iroha_crypto::Hash::LENGTH]) -> Self {
        Self {
            expected_fingerprint: Some(expected_fingerprint),
        }
    }
}
impl ServerCertVerifier for CertificateKeyProofVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, RustlsError> {
        if let Some(expected) = self.expected_fingerprint {
            let actual = certificate_fingerprint(end_entity.as_ref());
            if actual != expected {
                return Err(RustlsError::General(
                    "transport certificate fingerprint mismatch".to_owned(),
                ));
            }
        }
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &SELF_SIGNED_SIGNATURE_ALGORITHMS,
        )
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &SELF_SIGNED_SIGNATURE_ALGORITHMS,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        SELF_SIGNED_SIGNATURE_ALGORITHMS.supported_schemes()
    }
}
#[cfg(feature = "quic")]
pub mod quic {
    #![allow(clippy::missing_errors_doc)]
    //! QUIC transport integration (feature-gated, optional).
    //!
    //! This module provides a QUIC dialer that can be reused across many outbound dials.
    //! Self-signed certificates are accepted because peer identity is enforced by the signed
    //! application handshake, but TLS still verifies that the server owns the certificate key. The
    //! signed handshake binds the presented certificate fingerprint to the active session. ALPN is
    //! fixed.
    /// ALPN negotiated for Iroha P2P QUIC connections.
    pub use super::P2P_ALPN;
    use quinn::{
        ClientConfig, Connection, Endpoint, TransportConfig, VarInt,
        crypto::rustls::QuicClientConfig as QuinnRustlsClientConfig,
    };
    use rustls::client::danger::ServerCertVerifier;
    use std::{io, sync::Arc, time::Duration};
    /// Number of bidirectional streams used by one Iroha P2P QUIC session.
    pub const P2P_BIDI_STREAMS_PER_CONNECTION: u32 = 2;
    /// Smallest per-direction flow-control allocation used by the budget split.
    pub const FLOW_CONTROL_GRANULE_BYTES: usize = 64 * 1024;
    const QUIC_DEPENDENCY_BLOCK_REASON: &str = "QUIC transport is unavailable pending transport requalification of locked quinn-proto 0.11.18; dependency memory and panic fixes alone do not establish authenticated transport, resource, or interoperability qualification";
    const FLOW_CONTROL_DIRECTIONS_PER_CONNECTION: usize = 4;
    // Quinn's endpoint configuration expresses the maximum UDP payload as a
    // `u16`, and its receive path additionally caps one datagram at 64 KiB.
    // The first datagram retained by `Incoming` is explicitly excluded from
    // both configured incoming-buffer limits, so reserve a whole granule for it.
    const INCOMING_FIRST_PACKET_RESERVE_BYTES: usize = FLOW_CONTROL_GRANULE_BYTES;
    /// Inputs used to derive bounded QUIC flow-control credit.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct FlowControlConfig {
        /// Largest encrypted P2P frame body accepted on a stream.
        pub max_encrypted_frame_bytes: usize,
        /// Process-wide upper bound on simultaneously active P2P connections.
        pub max_total_connections: usize,
        /// Process-wide byte budget shared by QUIC send and receive flow control.
        pub process_budget_bytes: usize,
    }
    impl Default for FlowControlConfig {
        fn default() -> Self {
            Self {
                max_encrypted_frame_bytes: crate::MAX_ENCRYPTED_FRAME_BYTES,
                max_total_connections: 1,
                process_budget_bytes: FLOW_CONTROL_DIRECTIONS_PER_CONNECTION
                    * FLOW_CONTROL_GRANULE_BYTES,
            }
        }
    }
    /// Checked QUIC flow-control limits shared by client and server endpoints.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    #[expect(
        clippy::struct_field_names,
        reason = "field names expose byte units at the public QUIC configuration boundary"
    )]
    pub struct FlowControlGeometry {
        /// Credit granted to each individual stream.
        pub stream_receive_window_bytes: u64,
        /// Aggregate receive credit granted to one connection.
        pub connection_receive_window_bytes: u64,
        /// Aggregate send credit retained for one connection.
        pub connection_send_window_bytes: u64,
    }
    /// Checked endpoint-side admission and datagram buffer geometry.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct EndpointBufferGeometry {
        /// Quinn `Incoming` records allowed before the application accepts them.
        pub max_incoming: usize,
        /// Bytes buffered after the first packet for one pending `Incoming`.
        pub incoming_buffer_size_bytes: u64,
        /// Aggregate post-first-packet bytes for all pending `Incoming` records.
        pub incoming_buffer_size_total_bytes: u64,
        /// Payload-byte reserve for the first packet retained by one `Incoming`.
        pub incoming_first_packet_reserve_bytes: usize,
        /// Aggregate first-packet reserve across all admitted `Incoming` records.
        pub incoming_first_packet_reserve_total_bytes: usize,
        /// Configured QUIC datagram buffers retained per active connection.
        pub datagram_buffer_bytes_per_connection: usize,
        /// Checked aggregate datagram buffer geometry for all connections.
        pub datagram_buffer_bytes_total: usize,
        /// Checked aggregate stream flow-control geometry for all connections.
        pub flow_control_buffer_bytes_total: usize,
        /// Combined flow-control, pending-Incoming payload, and datagram buffer bound.
        pub endpoint_buffer_bytes_total: usize,
    }
    /// Derive bounded Quinn endpoint admission and datagram buffer limits.
    ///
    /// Pending handshakes get one flow-control granule after their first packet, plus a separate
    /// granule for the first packet that Quinn excludes from both incoming-buffer limits. Since
    /// [`flow_control_geometry`] requires four such granules per active connection, each aggregate
    /// pending region fits within one quarter of the same minimum process geometry. Datagram
    /// buffers are separately configured, but their per-connection sum and aggregate multiplication
    /// are still checked explicitly. Locked Quinn separately charges payload bytes
    /// and fixed per-entry overhead in its DATAGRAM buffers. Shipping constructors still reject QUIC pending
    /// transport requalification with locked quinn-proto 0.11.18. Pending-`Incoming` object metadata is
    /// count-bounded by `max_incoming`, but is not part of this payload/flow-credit byte geometry.
    pub fn endpoint_buffer_geometry(
        flow_control: FlowControlConfig,
        max_incoming: usize,
        datagram_receive_buffer: Option<usize>,
        datagram_send_buffer: usize,
    ) -> io::Result<EndpointBufferGeometry> {
        let flow_geometry = flow_control_geometry(flow_control)?;
        if max_incoming == 0 || max_incoming > flow_control.max_total_connections {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "QUIC max_incoming ({max_incoming}) must be between 1 and max_total_connections ({})",
                    flow_control.max_total_connections
                ),
            ));
        }
        let incoming_buffer_size_total = max_incoming
            .checked_mul(FLOW_CONTROL_GRANULE_BYTES)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "QUIC aggregate Incoming buffer geometry overflows usize",
                )
            })?;
        let incoming_buffer_size_bytes =
            u64::try_from(FLOW_CONTROL_GRANULE_BYTES).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "QUIC per-Incoming buffer does not fit u64",
                )
            })?;
        let incoming_buffer_size_total_bytes =
            u64::try_from(incoming_buffer_size_total).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "QUIC aggregate Incoming buffer does not fit u64",
                )
            })?;
        let incoming_first_packet_reserve_total_bytes = max_incoming
            .checked_mul(INCOMING_FIRST_PACKET_RESERVE_BYTES)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "QUIC aggregate Incoming first-packet reserve overflows usize",
                )
            })?;
        let datagram_buffer_bytes_per_connection = datagram_receive_buffer
            .unwrap_or(0)
            .checked_add(datagram_send_buffer)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "QUIC per-connection datagram buffer geometry overflows usize",
                )
            })?;
        let datagram_buffer_bytes_total = datagram_buffer_bytes_per_connection
            .checked_mul(flow_control.max_total_connections)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "QUIC aggregate datagram buffer geometry overflows usize",
                )
            })?;
        let flow_control_buffer_bytes_per_connection = flow_geometry
            .connection_receive_window_bytes
            .checked_add(flow_geometry.connection_send_window_bytes)
            .and_then(|bytes| usize::try_from(bytes).ok())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "QUIC per-connection flow-control buffer geometry overflows usize",
                )
            })?;
        let flow_control_buffer_bytes_total = flow_control_buffer_bytes_per_connection
            .checked_mul(flow_control.max_total_connections)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "QUIC aggregate flow-control buffer geometry overflows usize",
                )
            })?;
        let endpoint_buffer_bytes_total = flow_control_buffer_bytes_total
            .checked_add(incoming_buffer_size_total)
            .and_then(|bytes| bytes.checked_add(incoming_first_packet_reserve_total_bytes))
            .and_then(|bytes| bytes.checked_add(datagram_buffer_bytes_total))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "QUIC combined endpoint buffer geometry overflows usize",
                )
            })?;
        Ok(EndpointBufferGeometry {
            max_incoming,
            incoming_buffer_size_bytes,
            incoming_buffer_size_total_bytes,
            incoming_first_packet_reserve_bytes: INCOMING_FIRST_PACKET_RESERVE_BYTES,
            incoming_first_packet_reserve_total_bytes,
            datagram_buffer_bytes_per_connection,
            datagram_buffer_bytes_total,
            flow_control_buffer_bytes_total,
            endpoint_buffer_bytes_total,
        })
    }
    /// Derive the per-connection QUIC flow-control geometry from a process budget.
    ///
    /// A connection has two receive streams and may retain the same aggregate amount for sending.
    /// Consequently, `4 * max_total_connections * W` is bounded by `process_budget_bytes`, where
    /// `W` is the stream window. Large frames do not require equally large static credit: QUIC
    /// replenishes the window as the application consumes stream bytes.
    pub fn flow_control_geometry(cfg: FlowControlConfig) -> io::Result<FlowControlGeometry> {
        if cfg.max_encrypted_frame_bytes == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "QUIC max encrypted frame bytes must be non-zero",
            ));
        }
        if cfg.max_total_connections == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "QUIC max total connections must be non-zero",
            ));
        }
        let minimum_budget = cfg
            .max_total_connections
            .checked_mul(FLOW_CONTROL_DIRECTIONS_PER_CONNECTION)
            .and_then(|value| value.checked_mul(FLOW_CONTROL_GRANULE_BYTES))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "QUIC minimum flow-control budget overflows usize",
                )
            })?;
        if cfg.process_budget_bytes < minimum_budget {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "QUIC process flow-control budget ({}) must be at least {} bytes for {} connections",
                    cfg.process_budget_bytes, minimum_budget, cfg.max_total_connections
                ),
            ));
        }
        let complete_frame_bytes = cfg
            .max_encrypted_frame_bytes
            .checked_add(crate::P2P_FRAME_LENGTH_PREFIX_BYTES)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "QUIC complete encrypted-frame length overflows usize",
                )
            })?;
        let denominator = cfg
            .max_total_connections
            .checked_mul(FLOW_CONTROL_DIRECTIONS_PER_CONNECTION)
            .expect("minimum-budget calculation already checked this product");
        let budget_share = cfg.process_budget_bytes / denominator;
        let rounded_budget_share =
            (budget_share / FLOW_CONTROL_GRANULE_BYTES) * FLOW_CONTROL_GRANULE_BYTES;
        let stream_window = complete_frame_bytes.min(rounded_budget_share);
        let connection_window = stream_window.checked_mul(2).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "QUIC per-connection flow-control window overflows usize",
            )
        })?;
        let stream_receive_window_bytes = u64::try_from(stream_window).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "QUIC stream flow-control window does not fit u64",
            )
        })?;
        let connection_window_bytes = u64::try_from(connection_window).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "QUIC connection flow-control window does not fit u64",
            )
        })?;
        VarInt::from_u64(stream_receive_window_bytes)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
        VarInt::from_u64(connection_window_bytes)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
        Ok(FlowControlGeometry {
            stream_receive_window_bytes,
            connection_receive_window_bytes: connection_window_bytes,
            connection_send_window_bytes: connection_window_bytes,
        })
    }
    /// Apply the protocol stream count and checked flow-control geometry.
    pub fn configure_flow_control(
        transport: &mut TransportConfig,
        cfg: FlowControlConfig,
    ) -> io::Result<FlowControlGeometry> {
        let geometry = flow_control_geometry(cfg)?;
        let stream_receive_window = VarInt::from_u64(geometry.stream_receive_window_bytes)
            .expect("flow-control geometry validated the stream window");
        let connection_receive_window = VarInt::from_u64(geometry.connection_receive_window_bytes)
            .expect("flow-control geometry validated the connection window");
        transport
            .max_concurrent_bidi_streams(VarInt::from_u32(P2P_BIDI_STREAMS_PER_CONNECTION))
            .max_concurrent_uni_streams(VarInt::from_u32(0))
            .stream_receive_window(stream_receive_window)
            .receive_window(connection_receive_window)
            .send_window(geometry.connection_send_window_bytes);
        Ok(geometry)
    }
    /// QUIC transport tuning for outbound dials.
    #[derive(Clone, Copy, Debug)]
    pub struct DialerConfig {
        /// QUIC idle timeout (transport-level), if set.
        pub max_idle_timeout: Option<Duration>,
        /// QUIC keep-alive interval, if set.
        pub keep_alive_interval: Option<Duration>,
        /// Receive buffer reserved for QUIC datagrams on each connection (bytes).
        ///
        /// This must be `None` while the locked Quinn release lacks fixed
        /// per-entry receive accounting; any `Some` value is rejected.
        pub datagram_receive_buffer: Option<usize>,
        /// Send buffer reserved for QUIC datagrams on each connection (bytes).
        ///
        /// This must be zero while DATAGRAM receive support is fail-closed.
        pub datagram_send_buffer: usize,
        /// Checked process-wide flow-control geometry inputs.
        pub flow_control: FlowControlConfig,
    }
    impl Default for DialerConfig {
        fn default() -> Self {
            Self {
                max_idle_timeout: None,
                // A small keep-alive keeps common NAT mappings fresh and reduces idle drops.
                keep_alive_interval: Some(Duration::from_secs(10)),
                datagram_receive_buffer: None,
                datagram_send_buffer: 0,
                flow_control: FlowControlConfig::default(),
            }
        }
    }
    /// Reusable outbound QUIC dialer.
    #[derive(Clone, Debug)]
    pub struct Dialer {
        endpoint: Endpoint,
    }
    impl Dialer {
        /// Create a QUIC dialer bound to `bind_addr` (usually `0.0.0.0:0`).
        pub fn bind(bind_addr: std::net::SocketAddr, cfg: DialerConfig) -> io::Result<Self> {
            // Validate before creating the UDP socket so rejected shipping
            // QUIC has no externally observable transport side effect.
            let transport = build_transport_config(cfg)?;
            let mut endpoint = Endpoint::client(bind_addr)?;
            let verifier: Arc<dyn ServerCertVerifier> =
                Arc::new(super::CertificateKeyProofVerifier::unpinned());
            let mut tls = rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth();
            // Application authentication happens after the transport
            // handshake; replayable 0-RTT bytes must never enter that path.
            tls.enable_early_data = false;
            tls.alpn_protocols = vec![P2P_ALPN.to_vec()];
            let tls = Arc::new(tls);
            let crypto = QuinnRustlsClientConfig::try_from(tls)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
            let mut client = ClientConfig::new(Arc::new(crypto));
            client.transport_config(transport);
            endpoint.set_default_client_config(client);
            Ok(Self { endpoint })
        }
        /// Connect to `remote` and return an established connection.
        pub async fn connect(
            &self,
            remote: std::net::SocketAddr,
            server_name: &str,
        ) -> io::Result<Connection> {
            let connecting = self
                .endpoint
                .connect(remote, server_name)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
            connecting
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))
        }
    }
    fn build_transport_config(_cfg: DialerConfig) -> io::Result<Arc<TransportConfig>> {
        // This is called before `Endpoint::client`, so the rejected transport
        // cannot create a UDP socket or emit packets.
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            QUIC_DEPENDENCY_BLOCK_REASON,
        ))
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        const MIB: usize = 1024 * 1024;
        #[test]
        fn core_profile_flow_control_stays_within_process_budget() {
            let cfg = FlowControlConfig {
                max_encrypted_frame_bytes: 16 * MIB,
                max_total_connections: 120,
                process_budget_bytes: 128 * MIB,
            };
            let geometry = flow_control_geometry(cfg).expect("valid core geometry");
            assert_eq!(geometry.stream_receive_window_bytes, 256 * 1024);
            assert_eq!(geometry.connection_receive_window_bytes, 512 * 1024);
            assert_eq!(geometry.connection_send_window_bytes, 512 * 1024);
            let total = usize::try_from(
                geometry
                    .connection_receive_window_bytes
                    .checked_add(geometry.connection_send_window_bytes)
                    .expect("small connection budget"),
            )
            .expect("connection budget fits usize")
            .checked_mul(cfg.max_total_connections)
            .expect("small process budget");
            assert!(total <= cfg.process_budget_bytes);
        }
        #[test]
        fn public_dialer_rejects_unqualified_quinn_before_binding() {
            let unbindable: std::net::SocketAddr = "192.0.2.1:0".parse().unwrap();
            for cfg in [
                DialerConfig::default(),
                DialerConfig {
                    datagram_receive_buffer: Some(0),
                    ..DialerConfig::default()
                },
                DialerConfig {
                    datagram_receive_buffer: Some(1),
                    ..DialerConfig::default()
                },
                DialerConfig {
                    datagram_send_buffer: 1,
                    ..DialerConfig::default()
                },
            ] {
                let error = Dialer::bind(unbindable, cfg)
                    .expect_err("unqualified Quinn must fail before the UDP bind");
                assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
                let reason = error.to_string();
                assert!(reason.contains("quinn-proto 0.11.18"));
                assert!(reason.contains("transport requalification"));
                assert!(reason.contains("requalification"));
            }
        }
        #[test]
        fn home_profile_uses_larger_window_under_same_process_budget() {
            let geometry = flow_control_geometry(FlowControlConfig {
                max_encrypted_frame_bytes: 16 * MIB,
                max_total_connections: 32,
                process_budget_bytes: 128 * MIB,
            })
            .expect("valid home geometry");
            assert_eq!(geometry.stream_receive_window_bytes, MIB as u64);
            assert_eq!(geometry.connection_receive_window_bytes, (2 * MIB) as u64);
            assert_eq!(geometry.connection_send_window_bytes, (2 * MIB) as u64);
        }
        #[test]
        fn budget_one_byte_below_minimum_is_rejected() {
            let connections = 7;
            let minimum =
                connections * FLOW_CONTROL_DIRECTIONS_PER_CONNECTION * FLOW_CONTROL_GRANULE_BYTES;
            let error = flow_control_geometry(FlowControlConfig {
                max_encrypted_frame_bytes: MIB,
                max_total_connections: connections,
                process_budget_bytes: minimum - 1,
            })
            .expect_err("undersized process budget must fail closed");
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert!(error.to_string().contains("must be at least"));
        }
        #[test]
        fn small_frame_window_includes_stream_length_prefix() {
            let geometry = flow_control_geometry(FlowControlConfig {
                max_encrypted_frame_bytes: 4096,
                max_total_connections: 1,
                process_budget_bytes: 4 * FLOW_CONTROL_GRANULE_BYTES,
            })
            .expect("valid small-frame geometry");
            assert_eq!(
                geometry.stream_receive_window_bytes,
                (4096 + crate::P2P_FRAME_LENGTH_PREFIX_BYTES) as u64
            );
        }
        #[test]
        fn zero_connections_and_arithmetic_overflow_are_rejected() {
            let zero_connections = flow_control_geometry(FlowControlConfig {
                max_encrypted_frame_bytes: 1,
                max_total_connections: 0,
                process_budget_bytes: usize::MAX,
            })
            .expect_err("zero connections must fail closed");
            assert_eq!(zero_connections.kind(), io::ErrorKind::InvalidInput);
            let overflow = flow_control_geometry(FlowControlConfig {
                max_encrypted_frame_bytes: 1,
                max_total_connections: usize::MAX,
                process_budget_bytes: usize::MAX,
            })
            .expect_err("minimum budget multiplication must be checked");
            assert_eq!(overflow.kind(), io::ErrorKind::InvalidInput);
        }
        #[test]
        fn endpoint_buffers_follow_connection_cap_with_checked_aggregates() {
            let cfg = FlowControlConfig {
                max_encrypted_frame_bytes: MIB,
                max_total_connections: 4,
                process_budget_bytes: 4 * 4 * FLOW_CONTROL_GRANULE_BYTES,
            };
            let geometry = endpoint_buffer_geometry(cfg, 2, Some(1024), 2048)
                .expect("small endpoint geometry must fit");
            assert_eq!(geometry.max_incoming, 2);
            assert_eq!(
                geometry.incoming_buffer_size_bytes,
                FLOW_CONTROL_GRANULE_BYTES as u64
            );
            assert_eq!(
                geometry.incoming_buffer_size_total_bytes,
                (2 * FLOW_CONTROL_GRANULE_BYTES) as u64
            );
            assert_eq!(
                geometry.incoming_first_packet_reserve_bytes,
                FLOW_CONTROL_GRANULE_BYTES
            );
            assert_eq!(
                geometry.incoming_first_packet_reserve_total_bytes,
                2 * FLOW_CONTROL_GRANULE_BYTES
            );
            assert_eq!(geometry.datagram_buffer_bytes_per_connection, 3072);
            assert_eq!(geometry.datagram_buffer_bytes_total, 12_288);
            assert_eq!(geometry.flow_control_buffer_bytes_total, 1_048_576);
            assert_eq!(geometry.endpoint_buffer_bytes_total, 1_323_008);
        }
        #[test]
        fn cap_one_and_datagram_overflow_fail_closed() {
            let cap_one = FlowControlConfig {
                max_encrypted_frame_bytes: MIB,
                max_total_connections: 1,
                process_budget_bytes: 4 * FLOW_CONTROL_GRANULE_BYTES,
            };
            let geometry = endpoint_buffer_geometry(cap_one, 1, None, 0)
                .expect("cap-one endpoint geometry must be valid");
            assert_eq!(geometry.max_incoming, 1);
            assert_eq!(
                geometry.incoming_buffer_size_total_bytes,
                geometry.incoming_buffer_size_bytes
            );
            assert_eq!(
                geometry.endpoint_buffer_bytes_total,
                6 * FLOW_CONTROL_GRANULE_BYTES
            );
            let excessive_incoming = endpoint_buffer_geometry(cap_one, 2, None, 0)
                .expect_err("Incoming cap may not exceed total connection geometry");
            assert_eq!(excessive_incoming.kind(), io::ErrorKind::InvalidInput);
            let overflow = endpoint_buffer_geometry(
                FlowControlConfig {
                    max_encrypted_frame_bytes: 1,
                    max_total_connections: 2,
                    process_budget_bytes: 8 * FLOW_CONTROL_GRANULE_BYTES,
                },
                2,
                Some(usize::MAX),
                1,
            )
            .expect_err("per-connection datagram addition must be checked");
            assert_eq!(overflow.kind(), io::ErrorKind::InvalidInput);
            let aggregate_overflow = endpoint_buffer_geometry(
                FlowControlConfig {
                    max_encrypted_frame_bytes: 1,
                    max_total_connections: 2,
                    process_budget_bytes: 8 * FLOW_CONTROL_GRANULE_BYTES,
                },
                2,
                Some(usize::MAX / 2 + 1),
                0,
            )
            .expect_err("aggregate datagram multiplication must be checked");
            assert_eq!(aggregate_overflow.kind(), io::ErrorKind::InvalidInput);
        }
        #[test]
        fn incoming_first_packet_reserve_is_checked_in_combined_endpoint_geometry() {
            let combined_overflow = endpoint_buffer_geometry(
                FlowControlConfig {
                    max_encrypted_frame_bytes: usize::MAX / 8,
                    max_total_connections: 2,
                    process_budget_bytes: usize::MAX,
                },
                2,
                None,
                2 * FLOW_CONTROL_GRANULE_BYTES,
            )
            .expect_err("first-packet reserve must participate in checked endpoint total");
            assert_eq!(combined_overflow.kind(), io::ErrorKind::InvalidInput);
            assert!(combined_overflow.to_string().contains("combined endpoint"));
        }
    }
}
/// QUIC dialer handle type.
#[cfg(feature = "quic")]
pub type QuicDialer = quic::Dialer;
/// Stub QUIC dialer type when QUIC support is not compiled in.
#[cfg(not(feature = "quic"))]
pub type QuicDialer = ();
/// QUIC connection handle type.
#[cfg(feature = "quic")]
pub type QuicConnection = quinn::Connection;
/// Stub QUIC connection handle type when QUIC support is not compiled in.
#[cfg(not(feature = "quic"))]
pub type QuicConnection = ();
/// Compute the stable certificate fingerprint used for transport channel binding.
#[must_use]
pub fn certificate_fingerprint(cert_der: &[u8]) -> crate::peer::TransportBinding {
    iroha_crypto::Hash::new(cert_der).into()
}
/// Extract the peer certificate fingerprint from an established TLS client session.
///
/// # Errors
///
/// Returns an error when the peer does not present a certificate or when the
/// certificate chain is empty.
pub fn tls_peer_certificate_fingerprint<S>(
    tls: &tokio_rustls::client::TlsStream<S>,
) -> std::io::Result<crate::peer::TransportBinding> {
    let (_, session) = tls.get_ref();
    let certs = session.peer_certificates().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "tls peer did not present a certificate",
        )
    })?;
    let cert = certs.first().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "tls peer certificate chain is empty",
        )
    })?;
    Ok(certificate_fingerprint(cert.as_ref()))
}
/// Extract the peer certificate fingerprint from an established QUIC session.
///
/// # Errors
///
/// Returns an error when the peer does not present an identity, when the
/// identity is not encoded as a certificate chain, or when the chain is empty.
#[cfg(feature = "quic")]
pub fn quic_peer_certificate_fingerprint(
    connection: &quinn::Connection,
) -> std::io::Result<crate::peer::TransportBinding> {
    let identity = connection.peer_identity().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "quic peer did not present an identity",
        )
    })?;
    let certs = identity
        .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "unexpected quic peer identity type",
            )
        })?;
    let cert = certs.first().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "quic peer certificate chain is empty",
        )
    })?;
    Ok(certificate_fingerprint(cert.as_ref()))
}
pub mod tls {
    //! Mandatory first-release TLS-over-TCP transport.
    //!
    //! Wraps a TCP stream with TLS 1.3 using rustls. Self-signed certificates are accepted after
    //! TLS proves possession of their private key; peer identity is then enforced by the
    //! application handshake signature bound to the presented certificate fingerprint.
    use rustls::{ClientConfig, client::danger::ServerCertVerifier, pki_types::ServerName};
    use std::sync::Arc;
    use tokio::io::{AsyncRead, AsyncWrite};
    use tokio_rustls::{TlsConnector, client::TlsStream};
    const HTTPS_PROXY_ALPN: &[u8] = b"http/1.1";

    fn server_name(host: &str) -> tokio::io::Result<ServerName<'static>> {
        ServerName::try_from(host).map_or_else(
            |_| {
                host.parse::<std::net::IpAddr>()
                    .map(|ip| ServerName::IpAddress(ip.into()))
                    .map_err(|_| {
                        tokio::io::Error::new(tokio::io::ErrorKind::InvalidInput, "invalid SNI")
                    })
            },
            |name| Ok(name.to_owned()),
        )
    }

    fn require_alpn<S>(
        tls: &TlsStream<S>,
        expected: &[u8],
        profile: &str,
    ) -> tokio::io::Result<()> {
        let negotiated = tls.get_ref().1.alpn_protocol();
        if negotiated == Some(expected) {
            Ok(())
        } else {
            Err(tokio::io::Error::new(
                tokio::io::ErrorKind::InvalidData,
                format!("{profile} did not negotiate its required ALPN"),
            ))
        }
    }

    async fn connect_with_profile<S>(
        host: &str,
        tcp: S,
        verifier: Arc<dyn ServerCertVerifier>,
        alpn: &[u8],
        profile: &str,
    ) -> tokio::io::Result<TlsStream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        config.alpn_protocols = vec![alpn.to_vec()];
        let connector = TlsConnector::from(Arc::new(config));
        let tls = connector.connect(server_name(host)?, tcp).await?;
        require_alpn(&tls, alpn, profile)?;
        Ok(tls)
    }

    /// Upgrade an already-connected raw P2P TCP stream to TLS 1.3.
    ///
    /// This profile offers and requires the exact [`super::P2P_ALPN`] protocol.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid server names, TLS handshake failures, or a
    /// missing or different negotiated ALPN.
    pub async fn connect_tls<S>(host: &str, tcp: S) -> tokio::io::Result<TlsStream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let verifier: Arc<dyn ServerCertVerifier> =
            Arc::new(super::CertificateKeyProofVerifier::unpinned());
        connect_with_profile(host, tcp, verifier, super::P2P_ALPN, "raw P2P TLS").await
    }

    /// Upgrade an already-connected HTTPS proxy stream to pinned TLS 1.3.
    ///
    /// This profile offers and requires HTTP/1.1 ALPN. The exact end-entity
    /// certificate pin is mandatory so CONNECT credentials cannot be captured by
    /// an unauthenticated proxy.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid server names, TLS handshake or certificate
    /// pin failures, or a missing or different negotiated ALPN.
    pub async fn connect_https_proxy_tls_pinned<S>(
        host: &str,
        tcp: S,
        expected_cert_der: Arc<[u8]>,
    ) -> tokio::io::Result<TlsStream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let expected_fingerprint = super::certificate_fingerprint(expected_cert_der.as_ref());
        let verifier: Arc<dyn ServerCertVerifier> = Arc::new(
            super::CertificateKeyProofVerifier::pinned(expected_fingerprint),
        );
        connect_with_profile(host, tcp, verifier, HTTPS_PROXY_ALPN, "HTTPS proxy TLS").await
    }
}
use crate::sampler::LogSampler;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use iroha_primitives::addr::{SocketAddr, SocketAddrHost};
use socket2::{SockRef, TcpKeepalive};
use std::sync::{Arc, Mutex, OnceLock};
use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt, Result},
    net::TcpStream,
};
fn clear_sensitive_vec(bytes: &mut Vec<u8>) {
    bytes.resize(bytes.capacity(), 0);
    bytes.fill(0);
    std::hint::black_box(bytes.as_mut_slice());
    bytes.clear();
}

fn clear_sensitive_string(value: &mut String) {
    let mut bytes = std::mem::take(value).into_bytes();
    clear_sensitive_vec(&mut bytes);
}

struct SensitiveBytes {
    bytes: Vec<u8>,
}
impl SensitiveBytes {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
        }
    }
    fn from_vec(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
    fn extend_from_slice(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }
    fn reserve(&mut self, additional: usize) {
        self.bytes.reserve(additional);
    }
    fn as_slice(&self) -> &[u8] {
        self.bytes.as_slice()
    }
    fn len(&self) -> usize {
        self.bytes.len()
    }
    fn ends_with(&self, suffix: &[u8]) -> bool {
        self.bytes.ends_with(suffix)
    }
    fn clear(&mut self) {
        clear_sensitive_vec(&mut self.bytes);
    }
}
impl std::fmt::Debug for SensitiveBytes {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SensitiveBytes")
            .field("bytes", &"[REDACTED]")
            .field("len", &self.bytes.len())
            .finish()
    }
}
impl Drop for SensitiveBytes {
    fn drop(&mut self) {
        self.clear();
    }
}

struct ProxyCredentials {
    user_pass: String,
    username_len: usize,
}
impl ProxyCredentials {
    fn new(username: &str, password: &str) -> Self {
        let mut user_pass = String::with_capacity(username.len() + 1 + password.len());
        user_pass.push_str(username);
        user_pass.push(':');
        user_pass.push_str(password);
        Self {
            user_pass,
            username_len: username.len(),
        }
    }
    fn username(&self) -> &str {
        self.user_pass.get(..self.username_len).unwrap_or_default()
    }
    fn password(&self) -> &str {
        self.user_pass
            .get(self.username_len.saturating_add(1)..)
            .unwrap_or_default()
    }
    fn clear(&mut self) {
        clear_sensitive_string(&mut self.user_pass);
        self.username_len = 0;
    }
}
impl std::fmt::Debug for ProxyCredentials {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProxyCredentials")
            .field("username", &"[REDACTED]")
            .field("password", &"[REDACTED]")
            .finish()
    }
}
impl Drop for ProxyCredentials {
    fn drop(&mut self) {
        self.clear();
    }
}

#[derive(Clone, Eq, PartialEq)]
enum NoProxyEntry {
    Any,
    Ip(std::net::IpAddr),
    Domain(String),
}

/// Outbound proxy configuration for TCP-based dials (HTTP CONNECT / SOCKS5).
#[derive(Clone, Default)]
pub struct ProxyPolicy {
    proxy: Option<Proxy>,
    no_proxy: Vec<NoProxyEntry>,
}
impl std::fmt::Debug for ProxyPolicy {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProxyPolicy")
            .field("proxy", &self.proxy)
            .field("no_proxy_count", &self.no_proxy.len())
            .finish()
    }
}
impl ProxyPolicy {
    /// Disable proxying entirely.
    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            proxy: None,
            no_proxy: Vec::new(),
        }
    }
    /// Build a proxy policy from config values.
    ///
    /// # Errors
    /// Returns an error if `proxy_url` or a no-proxy entry cannot be parsed, or
    /// if credentials are configured for a plaintext proxy transport.
    pub fn from_config(proxy_url: Option<String>, no_proxy: Vec<String>) -> io::Result<Self> {
        let proxy = if let Some(mut raw) = proxy_url {
            let parsed = parse_proxy_value(&raw);
            clear_sensitive_string(&mut raw);
            Some(parsed.map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?)
        } else {
            None
        };
        let no_proxy = normalize_no_proxy(no_proxy)?;
        Ok(Self { proxy, no_proxy })
    }
    pub(crate) fn is_configured(&self) -> bool {
        self.proxy.is_some()
    }
    pub(crate) fn has_no_proxy_entries(&self) -> bool {
        !self.no_proxy.is_empty()
    }
    pub(crate) fn uses_https_proxy(&self) -> bool {
        self.proxy
            .as_ref()
            .is_some_and(|proxy| proxy.kind == ProxyKind::HttpConnectTls)
    }
    fn should_bypass_proxy(&self, target_host: &str) -> bool {
        let target_host = target_host.trim();
        let unbracketed = target_host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(target_host);
        let target_ip = unbracketed
            .parse::<std::net::IpAddr>()
            .ok()
            .map(canonical_proxy_ip);
        let target_domain = if target_ip.is_none() {
            normalize_dns_name(unbracketed).ok()
        } else {
            None
        };
        self.no_proxy.iter().any(|entry| match entry {
            NoProxyEntry::Any => true,
            NoProxyEntry::Ip(expected) => target_ip == Some(*expected),
            NoProxyEntry::Domain(suffix) => target_domain.as_ref().is_some_and(|host| {
                host == suffix
                    || host
                        .strip_suffix(suffix)
                        .is_some_and(|prefix| prefix.ends_with('.'))
            }),
        })
    }
    fn pick_proxy_for_target(&self, target: &SocketAddr) -> Option<&Proxy> {
        let proxy = self.proxy.as_ref()?;
        // Resolve target host string for NO_PROXY checks
        match target {
            SocketAddr::Host(h) => {
                let host = h.host.as_ref();
                if self.should_bypass_proxy(host) {
                    None
                } else {
                    Some(proxy)
                }
            }
            SocketAddr::Ipv4(v4) => {
                let host = format!("{}.{}.{}.{}", v4.ip[0], v4.ip[1], v4.ip[2], v4.ip[3]);
                if self.should_bypass_proxy(&host) {
                    None
                } else {
                    Some(proxy)
                }
            }
            SocketAddr::Ipv6(v6) => {
                // Represent as canonical without brackets.
                let host = v6.ip.to_string();
                if self.should_bypass_proxy(&host) {
                    None
                } else {
                    Some(proxy)
                }
            }
        }
    }
}

fn canonical_proxy_ip(address: std::net::IpAddr) -> std::net::IpAddr {
    match address {
        std::net::IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map_or(std::net::IpAddr::V6(address), std::net::IpAddr::V4),
        address => address,
    }
}

fn normalize_dns_name(raw: &str) -> io::Result<String> {
    let name = raw.strip_suffix('.').unwrap_or(raw);
    if name.is_empty() || name.len() > 253 || !name.is_ascii() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "no-proxy DNS name is empty, non-ASCII, or too long",
        ));
    }
    if name.split('.').any(|label| {
        label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    }) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "no-proxy DNS name contains an invalid label",
        ));
    }
    Ok(name.to_ascii_lowercase())
}

fn normalize_no_proxy(list: Vec<String>) -> io::Result<Vec<NoProxyEntry>> {
    let mut normalized = Vec::with_capacity(list.len());
    for raw in list {
        let entry = raw.trim();
        if entry.is_empty() {
            continue;
        }
        if entry == "*" {
            normalized.push(NoProxyEntry::Any);
            continue;
        }
        let entry = entry.strip_prefix('.').unwrap_or(entry);
        let unbracketed = match (entry.strip_prefix('['), entry.strip_suffix(']')) {
            (Some(_), None) | (None, Some(_)) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "no-proxy IP literal has mismatched brackets",
                ));
            }
            (Some(without_open), Some(_)) => without_open.strip_suffix(']').unwrap_or(without_open),
            (None, None) => entry,
        };
        if let Ok(ip) = unbracketed.parse::<std::net::IpAddr>() {
            normalized.push(NoProxyEntry::Ip(canonical_proxy_ip(ip)));
        } else {
            normalized.push(NoProxyEntry::Domain(normalize_dns_name(entry)?));
        }
    }
    Ok(normalized)
}
/// TCP socket options applied to outbound dials.
#[derive(Clone)]
pub struct TcpConnectOptions {
    /// Proxy policy for this dial.
    pub proxy: ProxyPolicy,
    /// Operator admission policy for peer, proxy, and resolved dial targets.
    pub(crate) outbound_dial_policy: Arc<crate::dial_policy::OutboundDialPolicy>,
    /// Whether to verify TLS certificates when connecting to an `https://` proxy.
    ///
    /// This must be `true` for HTTPS proxies. `false` is rejected before dialing.
    /// This does not affect raw P2P TLS-over-TCP.
    pub proxy_tls_verify: bool,
    /// Optional DER-encoded (base64 decoded) end-entity certificate to pin when connecting to an `https://` proxy.
    ///
    /// Required when the proxy URL uses the `https://` scheme.
    pub proxy_tls_pinned_cert_der: Option<std::sync::Arc<[u8]>>,
    /// Whether to enable `TCP_NODELAY` for reduced latency.
    pub tcp_nodelay: bool,
    /// Optional keepalive idle time. When `None`, keepalive is disabled.
    pub tcp_keepalive: Option<std::time::Duration>,
}
impl std::fmt::Debug for TcpConnectOptions {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TcpConnectOptions")
            .field("proxy", &self.proxy)
            .field("proxy_tls_verify", &self.proxy_tls_verify)
            .field(
                "proxy_tls_pin_present",
                &self.proxy_tls_pinned_cert_der.is_some(),
            )
            .field(
                "proxy_tls_pin_len",
                &self
                    .proxy_tls_pinned_cert_der
                    .as_ref()
                    .map_or(0, |pin| pin.len()),
            )
            .field("tcp_nodelay", &self.tcp_nodelay)
            .field("tcp_keepalive", &self.tcp_keepalive)
            .finish_non_exhaustive()
    }
}
impl Default for TcpConnectOptions {
    fn default() -> Self {
        Self {
            proxy: ProxyPolicy::disabled(),
            outbound_dial_policy: Arc::new(crate::dial_policy::OutboundDialPolicy::default()),
            proxy_tls_verify: true,
            proxy_tls_pinned_cert_der: None,
            tcp_nodelay: true,
            tcp_keepalive: None,
        }
    }
}

fn proxy_socket_addr(proxy: &Proxy) -> SocketAddr {
    proxy.host.parse::<std::net::IpAddr>().map_or_else(
        |_| {
            SocketAddr::Host(SocketAddrHost {
                host: proxy.host.clone().into(),
                port: proxy.port,
            })
        },
        |ip| std::net::SocketAddr::new(ip, proxy.port).into(),
    )
}

async fn resolve_checked(
    target: &SocketAddr,
    policy: &crate::dial_policy::OutboundDialPolicy,
) -> Result<Vec<std::net::SocketAddr>> {
    policy.check_target(target)?;
    match target {
        SocketAddr::Ipv4(address) => policy
            .check_resolved_targets(std::iter::once(std::net::SocketAddr::V4((*address).into()))),
        SocketAddr::Ipv6(address) => policy
            .check_resolved_targets(std::iter::once(std::net::SocketAddr::V6((*address).into()))),
        SocketAddr::Host(address) => policy.check_resolved_targets(
            tokio::net::lookup_host((address.host.as_ref(), address.port)).await?,
        ),
    }
}

async fn connect_checked(
    target: &SocketAddr,
    policy: &crate::dial_policy::OutboundDialPolicy,
) -> Result<TcpStream> {
    let candidates = resolve_checked(target, policy).await?;
    let mut last_error = None;
    for candidate in candidates {
        match TcpStream::connect(candidate).await {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "outbound dial target had no admitted addresses",
        )
    }))
}
/// TCP-like outbound substrate returned by [`connect`].
///
/// Most substrate dials return a plain [`TcpStream`] which the peer dialer must
/// immediately upgrade to TLS 1.3. When tunnelling through an `https://` proxy,
/// the connection to the proxy is already wrapped in TLS before the independent
/// end-to-end P2P TLS session is established.
pub enum TcpConnectStream {
    /// Raw substrate stream which is not itself an admitted P2P transport.
    Plain(TcpStream),
    /// TLS-wrapped stream to the proxy (`https://` proxies only).
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProxyKind {
    HttpConnect,
    HttpConnectTls,
    Socks5,
}
#[derive(Clone)]
struct Proxy {
    kind: ProxyKind,
    host: String,
    port: u16,
    auth: Option<Arc<ProxyCredentials>>,
}
impl std::fmt::Debug for Proxy {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Proxy")
            .field("kind", &self.kind)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("auth_present", &self.auth.is_some())
            .finish()
    }
}
fn parse_proxy_value(raw: &str) -> std::result::Result<Proxy, String> {
    let mut s = raw;
    let mut kind = ProxyKind::HttpConnect;
    if let Some(rest) = s.strip_prefix("http://") {
        s = rest;
    } else if let Some(rest) = s.strip_prefix("https://") {
        s = rest;
        kind = ProxyKind::HttpConnectTls;
    } else if let Some(rest) = s.strip_prefix("socks5://") {
        s = rest;
        kind = ProxyKind::Socks5;
    } else if let Some(rest) = s.strip_prefix("socks5h://") {
        // `socks5h` indicates remote DNS resolution. When the target is a hostname,
        // we already forward it as a domain name, so this behaves the same as `socks5`.
        s = rest;
        kind = ProxyKind::Socks5;
    }
    // Strip credentials if present
    let mut auth = None;
    if let Some(at) = s.rfind('@') {
        let (creds, host_part) = s.split_at(at);
        s = host_part.get(1..).unwrap_or_default(); // skip '@'
        if !creds.is_empty() {
            if kind != ProxyKind::HttpConnectTls {
                return Err(
                    "proxy credentials require a pinned https:// proxy transport".to_owned(),
                );
            }
            let mut parts = creds.splitn(2, ':');
            let user = parts.next().unwrap_or("");
            let pass = parts.next().unwrap_or("");
            auth = Some(Arc::new(ProxyCredentials::new(user, pass)));
        }
    }
    let (host, port_str) = if let Some(rest) = s.strip_prefix('[') {
        let (host, rest) = rest
            .split_once(']')
            .ok_or_else(|| "proxy URL has unterminated IPv6 host".to_string())?;
        let port_str = rest
            .strip_prefix(':')
            .ok_or_else(|| "proxy URL missing port".to_string())?;
        (host, port_str)
    } else {
        // If the host contains multiple ':' characters, treat it as an IPv6 literal missing brackets.
        // Require bracketed form to avoid ambiguity with the port delimiter.
        if s.matches(':').count() > 1 {
            return Err("proxy URL has ambiguous IPv6 host; use [addr]:port".to_string());
        }
        s.rsplit_once(':')
            .ok_or_else(|| "proxy URL missing port".to_string())?
    };
    if host.is_empty() {
        return Err("proxy URL missing host".to_string());
    }
    let host = host.parse::<std::net::IpAddr>().map_or_else(
        |_| normalize_dns_name(host).map_err(|_| "proxy URL has invalid host".to_owned()),
        |address| Ok(canonical_proxy_ip(address).to_string()),
    )?;
    let port: u16 = port_str
        .parse()
        .map_err(|_| "proxy URL has invalid port".to_string())?;
    Ok(Proxy {
        kind,
        host,
        port,
        auth,
    })
}
// ---- TCP socket option helpers ----
fn http_connect_authority(target: &SocketAddr) -> Result<String> {
    match target {
        SocketAddr::Ipv4(addr) => Ok(format!("{}:{}", addr.ip, addr.port)),
        SocketAddr::Ipv6(addr) => Ok(format!("[{}]:{}", addr.ip, addr.port)),
        SocketAddr::Host(addr) => {
            let rooted = addr.host.ends_with('.');
            let host = normalize_dns_name(addr.host.as_ref())?;
            let root = if rooted { "." } else { "" };
            Ok(format!("{host}{root}:{}", addr.port))
        }
    }
}

fn build_connect_request(target: &SocketAddr, proxy: &Proxy) -> Result<SensitiveBytes> {
    let target = http_connect_authority(target)?;
    let prefix =
        format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nConnection: keep-alive\r\n");
    let mut headers = SensitiveBytes::from_vec(prefix.into_bytes());
    if let Some(credentials) = &proxy.auth {
        let mut user_pass = SensitiveBytes::with_capacity(credentials.user_pass.len());
        user_pass.extend_from_slice(credentials.username().as_bytes());
        user_pass.extend_from_slice(b":");
        user_pass.extend_from_slice(credentials.password().as_bytes());
        let mut authorization =
            SensitiveBytes::from_vec(BASE64_STANDARD.encode(user_pass.as_slice()).into_bytes());
        user_pass.clear();
        headers.reserve(b"Proxy-Authorization: Basic ".len() + authorization.as_slice().len() + 4);
        headers.extend_from_slice(b"Proxy-Authorization: Basic ");
        headers.extend_from_slice(authorization.as_slice());
        headers.extend_from_slice(b"\r\n");
        authorization.clear();
    }
    headers.extend_from_slice(b"\r\n");
    Ok(headers)
}
async fn socks5_negotiate_method<S>(stream: &mut S, proxy: &Proxy) -> Result<u8>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    debug_assert!(proxy.auth.is_none());
    let methods = [0x00];
    let methods_len = u8::try_from(methods.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "SOCKS5 method list too long"))?;
    let mut greeting = Vec::with_capacity(2 + methods.len());
    greeting.push(0x05);
    greeting.push(methods_len);
    greeting.extend_from_slice(&methods);
    stream.write_all(&greeting).await?;
    stream.flush().await?;
    let mut choice = [0u8; 2];
    stream.read_exact(&mut choice).await?;
    if choice[0] != 0x05 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SOCKS5 bad version",
        ));
    }
    match choice[1] {
        0x00 => Ok(choice[1]),
        0xFF => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SOCKS5 no acceptable auth methods",
        )),
        m => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("SOCKS5 unsupported auth method {m}"),
        )),
    }
}
fn socks5_build_connect_request(target: &SocketAddr) -> Result<Vec<u8>> {
    let mut req = Vec::with_capacity(32);
    req.push(0x05); // version
    req.push(0x01); // CMD=CONNECT
    req.push(0x00); // RSV
    match target {
        SocketAddr::Ipv4(v4) => {
            req.push(0x01); // ATYP=IPv4
            let ip: std::net::Ipv4Addr = v4.ip.into();
            req.extend_from_slice(&ip.octets());
            req.extend_from_slice(&v4.port.to_be_bytes());
        }
        SocketAddr::Ipv6(v6) => {
            req.push(0x04); // ATYP=IPv6
            let ip: std::net::Ipv6Addr = v6.ip.into();
            req.extend_from_slice(&ip.octets());
            req.extend_from_slice(&v6.port.to_be_bytes());
        }
        SocketAddr::Host(host) => {
            let name = host.host.as_ref();
            let name_len = u8::try_from(name.len()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "SOCKS5 target hostname too long",
                )
            })?;
            req.push(0x03); // ATYP=DOMAIN
            req.push(name_len);
            req.extend_from_slice(name.as_bytes());
            req.extend_from_slice(&host.port.to_be_bytes());
        }
    }
    Ok(req)
}
async fn socks5_read_connect_reply<S>(stream: &mut S) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    // Reply: VER, REP, RSV, ATYP, BND.ADDR, BND.PORT.
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "SOCKS5 bad reply version",
        ));
    }
    if head[1] != 0x00 {
        return Err(io::Error::other(format!(
            "SOCKS5 connect failed (rep={})",
            head[1]
        )));
    }
    match head[3] {
        0x01 => {
            let mut bnd = [0u8; 4];
            stream.read_exact(&mut bnd).await?;
        }
        0x04 => {
            let mut bnd = [0u8; 16];
            stream.read_exact(&mut bnd).await?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut bnd = vec![0u8; len[0] as usize];
            stream.read_exact(&mut bnd).await?;
        }
        atyp => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("SOCKS5 bad reply ATYP {atyp}"),
            ));
        }
    }
    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await?;
    Ok(())
}
async fn socks5_connect<S>(stream: &mut S, proxy: &Proxy, target: &SocketAddr) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    // RFC 1928: SOCKS5 version/method negotiation.
    socks5_negotiate_method(stream, proxy).await?;
    let req = socks5_build_connect_request(target)?;
    stream.write_all(&req).await?;
    stream.flush().await?;
    socks5_read_connect_reply(stream).await
}
async fn http_connect_tunnel<S>(
    stream: &mut S,
    proxy: &Proxy,
    target: &SocketAddr,
    proxy_endpoint: &str,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    // Construct and validate the complete authority before writing any proxy
    // bytes. `SocketAddrHost` is Norito-decodable and therefore must not be
    // interpolated directly into HTTP syntax.
    let mut req = build_connect_request(target, proxy)?;
    let write_result = stream.write_all(req.as_slice()).await;
    req.clear();
    write_result?;
    let mut response = SensitiveBytes::with_capacity(MAX_CONNECT_RESPONSE_HEADER_BYTES);
    let read_result = async {
        // Read exactly through CRLFCRLF. Chunked reads can consume tunneled P2P
        // bytes and make them unavailable to the caller.
        loop {
            if response.len() == MAX_CONNECT_RESPONSE_HEADER_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "proxy CONNECT response header exceeds 8192 bytes",
                ));
            }
            let mut byte = [0u8; 1];
            match stream.read_exact(&mut byte).await {
                Ok(_) => response.extend_from_slice(&byte),
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "proxy CONNECT response ended before CRLFCRLF",
                    ));
                }
                Err(error) => return Err(error),
            }
            if response.ends_with(b"\r\n\r\n") {
                return validate_http_connect_response(response.as_slice());
            }
        }
    }
    .await;
    response.clear();
    if let Err(error) = read_result {
        static PROXY_CONNECT_SAMPLER: OnceLock<Mutex<LogSampler>> = OnceLock::new();
        let sampler = PROXY_CONNECT_SAMPLER.get_or_init(|| Mutex::new(LogSampler::new()));
        if let Ok(mut sampler) = sampler.lock()
            && let Some(suppressed) = sampler.should_log(tokio::time::Duration::from_millis(500))
        {
            iroha_logger::warn!(
                kind = ?error.kind(),
                proxy = %proxy_endpoint,
                target = %target,
                suppressed,
                "HTTP CONNECT proxy response rejected"
            );
        }
        return Err(error);
    }
    Ok(())
}

fn validate_http_connect_response(response: &[u8]) -> Result<()> {
    const STATUS: &[u8] = b"HTTP/1.1 200";
    if !response.ends_with(b"\r\n\r\n") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "proxy CONNECT response is missing CRLFCRLF",
        ));
    }
    if response
        .windows(2)
        .any(|pair| pair[0] == b'\r' && pair[1] != b'\n')
        || response
            .iter()
            .enumerate()
            .any(|(index, byte)| *byte == b'\n' && (index == 0 || response[index - 1] != b'\r'))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "proxy CONNECT response contains malformed line endings",
        ));
    }
    let mut lines = response[..response.len() - 2].split(|byte| *byte == b'\n');
    let status_line = lines
        .next()
        .and_then(|line| line.strip_suffix(b"\r"))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "proxy CONNECT response has no status line",
            )
        })?;
    if !status_line.starts_with(STATUS)
        || status_line
            .get(STATUS.len())
            .is_some_and(|byte| *byte != b' ')
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "proxy CONNECT did not return exact HTTP/1.1 200 status",
        ));
    }
    if status_line.iter().any(|byte| !(0x20..=0x7e).contains(byte)) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "proxy CONNECT status line contains control or non-ASCII bytes",
        ));
    }
    for line in lines {
        // Splitting a CRLF-terminated header block on LF yields one final
        // empty slice after the terminating line. It is framing, not a
        // malformed header.
        if line.is_empty() {
            continue;
        }
        let line = line.strip_suffix(b"\r").ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "proxy CONNECT response contains a malformed header line",
            )
        })?;
        let colon = line.iter().position(|byte| *byte == b':').ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "proxy CONNECT response header is missing a colon",
            )
        })?;
        if colon == 0
            || !line[..colon].iter().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(
                        *byte,
                        b'!' | b'#'
                            | b'$'
                            | b'%'
                            | b'&'
                            | b'\''
                            | b'*'
                            | b'+'
                            | b'-'
                            | b'.'
                            | b'^'
                            | b'_'
                            | b'`'
                            | b'|'
                            | b'~'
                    )
            })
            || line[colon + 1..]
                .iter()
                .any(|byte| !(0x20..=0x7e).contains(byte))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "proxy CONNECT response contains an invalid header",
            ));
        }
    }
    Ok(())
}
/// Connect to a peer using the default transport (TCP).
///
/// When the `quic` feature is enabled, this remains a placeholder and
/// will be upgraded to a proper QUIC transport in a future change.
///
/// # Errors
///
/// Returns an `io::Error` if TCP connect fails, proxy handshake fails, or I/O operations error.
pub async fn connect(addr: &SocketAddr, opts: &TcpConnectOptions) -> Result<TcpConnectStream> {
    // Validate the logical destination before resolving or connecting to a
    // proxy. Every concrete address is checked again immediately before dial.
    opts.outbound_dial_policy.check_target(addr)?;
    let configured_https_proxy_pin: Option<Arc<[u8]>> =
        if let Some(proxy) = opts.proxy.proxy.as_ref() {
            if proxy.auth.is_some() && proxy.kind != ProxyKind::HttpConnectTls {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "proxy credentials require a pinned https:// proxy transport",
                ));
            }
            if proxy.kind == ProxyKind::HttpConnectTls {
                if !opts.proxy_tls_verify {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "HTTPS proxy certificate verification cannot be disabled",
                    ));
                }
                let pin = opts.proxy_tls_pinned_cert_der.clone().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "HTTPS proxy requires an exact configured leaf certificate pin",
                    )
                })?;
                if pin.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "HTTPS proxy leaf certificate pin cannot be empty",
                    ));
                }
                Some(pin)
            } else {
                None
            }
        } else {
            None
        };
    // If a proxy is configured and the target is not in NO_PROXY, tunnel via HTTP CONNECT.
    if let Some(proxy) = opts.proxy.pick_proxy_for_target(addr) {
        let proxy_addr = proxy_socket_addr(proxy);
        let proxy_endpoint = if proxy.host.contains(':') {
            format!("[{}]:{}", proxy.host, proxy.port)
        } else {
            format!("{}:{}", proxy.host, proxy.port)
        };
        // A CIDR policy cannot be delegated to a remote resolver. Resolve the
        // peer exactly once before opening the proxy connection and send the
        // proxy an admitted numeric endpoint. The end-to-end P2P TLS layer
        // still authenticates the original name.
        let resolved_target = if opts.outbound_dial_policy.has_ip_constraints()
            && matches!(addr, SocketAddr::Host(_))
        {
            Some(
                resolve_checked(addr, &opts.outbound_dial_policy)
                    .await?
                    .into_iter()
                    .next()
                    .expect("non-empty checked resolution")
                    .into(),
            )
        } else {
            None
        };
        let tunnel_target = resolved_target.as_ref().unwrap_or(addr);
        let mut stream = match connect_checked(&proxy_addr, &opts.outbound_dial_policy).await {
            Ok(s) => s,
            Err(e) => {
                static PROXY_CONNECT_SAMPLER: OnceLock<Mutex<LogSampler>> = OnceLock::new();
                let sampler = PROXY_CONNECT_SAMPLER.get_or_init(|| Mutex::new(LogSampler::new()));
                if let Ok(mut s) = sampler.lock()
                    && let Some(supp) = s.should_log(tokio::time::Duration::from_millis(500))
                {
                    iroha_logger::warn!(%e, proxy=%proxy_endpoint, suppressed=supp, "Failed to connect to proxy");
                }
                return Err(e);
            }
        };
        apply_tcp_socket_options(&stream, opts.tcp_nodelay, opts.tcp_keepalive);
        match proxy.kind {
            ProxyKind::HttpConnect => {
                http_connect_tunnel(&mut stream, proxy, tunnel_target, &proxy_endpoint).await?;
            }
            ProxyKind::HttpConnectTls => {
                let pinned =
                    configured_https_proxy_pin.expect("HTTPS proxy pin validated before dial");
                let mut tls = crate::transport::tls::connect_https_proxy_tls_pinned(
                    &proxy.host,
                    stream,
                    pinned,
                )
                .await?;
                http_connect_tunnel(&mut tls, proxy, tunnel_target, &proxy_endpoint).await?;
                return Ok(TcpConnectStream::Tls(Box::new(tls)));
            }
            ProxyKind::Socks5 => {
                socks5_connect(&mut stream, proxy, tunnel_target).await?;
            }
        }
        Ok(TcpConnectStream::Plain(stream))
    } else {
        match connect_checked(addr, &opts.outbound_dial_policy).await {
            Ok(stream) => {
                apply_tcp_socket_options(&stream, opts.tcp_nodelay, opts.tcp_keepalive);
                Ok(TcpConnectStream::Plain(stream))
            }
            Err(e) => {
                static DIRECT_CONNECT_SAMPLER: OnceLock<Mutex<LogSampler>> = OnceLock::new();
                let sampler = DIRECT_CONNECT_SAMPLER.get_or_init(|| Mutex::new(LogSampler::new()));
                if let Ok(mut s) = sampler.lock()
                    && let Some(supp) = s.should_log(tokio::time::Duration::from_millis(500))
                {
                    iroha_logger::warn!(%e, target=%addr.to_string(), suppressed=supp, "TCP connect failed");
                }
                Err(e)
            }
        }
    }
}
pub(crate) fn apply_tcp_socket_options(
    stream: &TcpStream,
    tcp_nodelay: bool,
    tcp_keepalive: Option<std::time::Duration>,
) {
    let sock_ref = SockRef::from(stream);
    apply_tcp_socket_options_sockref(&sock_ref, tcp_nodelay, tcp_keepalive);
}
fn apply_tcp_socket_options_sockref(
    sock_ref: &SockRef<'_>,
    tcp_nodelay: bool,
    tcp_keepalive: Option<std::time::Duration>,
) {
    let _ = sock_ref.set_tcp_nodelay(tcp_nodelay);
    if let Some(idle) = tcp_keepalive {
        // Best-effort: keepalive knobs vary across OSes. Socket2 provides a safe wrapper.
        let keepalive = TcpKeepalive::new().with_time(idle);
        let _ = sock_ref.set_tcp_keepalive(&keepalive);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test(flavor = "current_thread")]
    async fn connect_failure_sampling_limits_logs() {
        let mut sampler = crate::sampler::LogSampler::new();
        let mut logged = 0u32;
        for _ in 0..1000 {
            if sampler
                .should_log(tokio::time::Duration::from_millis(500))
                .is_some()
            {
                logged += 1;
            }
        }
        assert!(logged <= 1, "sampler should limit logs within the window");
        // After the period elapses, the sampler should emit again
        tokio::time::pause();
        tokio::time::advance(tokio::time::Duration::from_millis(600)).await;
        assert!(
            sampler
                .should_log(tokio::time::Duration::from_millis(500))
                .is_some()
        );
    }
    #[test]
    fn parse_proxy_extracts_auth_and_host() {
        let proxy = parse_proxy_value("https://user:pass@example.com:8443").expect("proxy parsed");
        assert_eq!(proxy.kind, ProxyKind::HttpConnectTls);
        assert_eq!(proxy.host, "example.com");
        assert_eq!(proxy.port, 8443);
        let credentials = proxy.auth.as_deref().expect("credentials");
        assert_eq!(credentials.username(), "user");
        assert_eq!(credentials.password(), "pass");
    }
    #[test]
    fn parse_proxy_rejects_credentials_on_plaintext_transports() {
        for value in [
            "http://user:pass@proxy.example:8080",
            "user:pass@proxy.example:8080",
            "socks5://user:pass@proxy.example:1080",
            "socks5h://user:pass@proxy.example:1080",
        ] {
            let error = parse_proxy_value(value).expect_err("plaintext credentials must fail");
            assert_eq!(
                error,
                "proxy credentials require a pinned https:// proxy transport"
            );
            assert!(!error.contains("user"));
            assert!(!error.contains("pass"));
        }
    }
    #[test]
    fn proxy_parse_errors_do_not_echo_credentials() {
        let error = ProxyPolicy::from_config(
            Some("https://UNIQUE_USER:UNIQUE_PASSWORD@proxy.example:not-a-port".to_owned()),
            Vec::new(),
        )
        .expect_err("invalid port must fail");
        let text = error.to_string();
        assert_eq!(text, "proxy URL has invalid port");
        assert!(!text.contains("UNIQUE_USER"));
        assert!(!text.contains("UNIQUE_PASSWORD"));
    }
    #[test]
    fn parse_proxy_accepts_socks5_scheme() {
        let proxy = parse_proxy_value("socks5://proxy.example.com:1080").expect("proxy parsed");
        assert_eq!(proxy.kind, ProxyKind::Socks5);
        assert_eq!(proxy.host, "proxy.example.com");
        assert_eq!(proxy.port, 1080);
        assert!(proxy.auth.is_none());
    }
    #[test]
    fn parse_proxy_accepts_https_scheme() {
        let proxy = parse_proxy_value("https://proxy.example.com:8443").expect("proxy parsed");
        assert_eq!(proxy.kind, ProxyKind::HttpConnectTls);
        assert_eq!(proxy.host, "proxy.example.com");
        assert_eq!(proxy.port, 8443);
    }
    #[test]
    fn parse_proxy_rejects_invalid_host_syntax_before_dial() {
        for value in [
            "http://bad..example:8080",
            "http://bad_example:8080",
            "http://-bad.example:8080",
            "http://bad-.example:8080",
            "http://proxy.example\r\nInjected:8080",
        ] {
            let error = parse_proxy_value(value).expect_err("invalid proxy host must fail");
            assert_eq!(error, "proxy URL has invalid host", "value: {value:?}");
        }

        let proxy = parse_proxy_value("http://PROXY.Example.:8080")
            .expect("valid proxy host is normalized");
        assert_eq!(proxy.host, "proxy.example");
    }
    #[test]
    fn connect_request_includes_basic_auth_when_present() {
        use iroha_primitives::addr::{SocketAddrHost, socket_addr};

        let proxy = Proxy {
            kind: ProxyKind::HttpConnectTls,
            host: "example.com".into(),
            port: 8443,
            auth: Some(Arc::new(ProxyCredentials::new("user", "pass"))),
        };
        let target = SocketAddr::Host(SocketAddrHost {
            host: "DEST.example.".into(),
            port: 443,
        });
        let mut req = build_connect_request(&target, &proxy).expect("valid CONNECT authority");
        let request = std::str::from_utf8(req.as_slice()).expect("ASCII request");
        assert!(request.starts_with("CONNECT dest.example.:443 HTTP/1.1\r\n"));
        assert!(request.contains("Proxy-Authorization: Basic dXNlcjpwYXNz"));
        req.clear();
        assert!(req.as_slice().is_empty());
        let proxy_no_auth = Proxy {
            kind: ProxyKind::HttpConnect,
            host: "example.com".into(),
            port: 8080,
            auth: None,
        };
        let req = build_connect_request(&socket_addr!(192.0.2.1:443), &proxy_no_auth)
            .expect("valid IPv4 CONNECT authority");
        assert!(
            !std::str::from_utf8(req.as_slice())
                .expect("ASCII request")
                .contains("Proxy-Authorization")
        );
    }
    #[test]
    fn connect_request_formats_canonical_typed_authorities() {
        use iroha_primitives::addr::{SocketAddrHost, socket_addr};

        let proxy = Proxy {
            kind: ProxyKind::HttpConnect,
            host: "proxy.example".into(),
            port: 8080,
            auth: None,
        };
        let targets = [
            (
                SocketAddr::Host(SocketAddrHost {
                    host: "DEST.Example.".into(),
                    port: 443,
                }),
                "CONNECT dest.example.:443 HTTP/1.1\r\nHost: dest.example.:443\r\n",
            ),
            (
                socket_addr!([2001:db8::1]:8443),
                "CONNECT [2001:db8::1]:8443 HTTP/1.1\r\nHost: [2001:db8::1]:8443\r\n",
            ),
        ];

        for (target, expected_prefix) in targets {
            let request = build_connect_request(&target, &proxy).expect("valid CONNECT authority");
            let request = std::str::from_utf8(request.as_slice()).expect("ASCII request");
            assert!(request.starts_with(expected_prefix), "request: {request:?}");
        }
    }
    #[test]
    fn connect_authority_rejects_invalid_host_syntax() {
        use iroha_primitives::addr::SocketAddrHost;

        for host in [
            "good.example\r\nX-Injected: yes",
            "good.example\rX-Injected: yes",
            "good.example\nX-Injected: yes",
            "good.example\tX-Injected",
            "good.example\0X-Injected",
            "good.example:80",
            "good.example/extra",
            "münchen.example",
            "good_example",
            "-bad.example",
            "bad-.example",
            "bad..example",
        ] {
            let target = SocketAddr::Host(SocketAddrHost {
                host: host.into(),
                port: 443,
            });
            assert!(
                http_connect_authority(&target).is_err(),
                "host {host:?} must be rejected"
            );
        }

        let target = SocketAddr::Host(SocketAddrHost {
            host: format!("{}.example", "a".repeat(254)).into(),
            port: 443,
        });
        assert!(http_connect_authority(&target).is_err());
    }
    #[tokio::test]
    async fn invalid_connect_authority_is_rejected_before_any_proxy_bytes() {
        use iroha_primitives::addr::SocketAddrHost;

        let proxy = Proxy {
            kind: ProxyKind::HttpConnectTls,
            host: "proxy.example".to_owned(),
            port: 8080,
            auth: Some(Arc::new(ProxyCredentials::new("user", "pass"))),
        };
        let target = SocketAddr::Host(SocketAddrHost {
            host: "victim.example\r\nX-Injected: yes".into(),
            port: 443,
        });
        let (mut client, mut server) = tokio::io::duplex(256);
        let error = http_connect_tunnel(&mut client, &proxy, &target, "proxy.example:8080")
            .await
            .expect_err("invalid authority must fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        drop(client);
        let mut written = Vec::new();
        server
            .read_to_end(&mut written)
            .await
            .expect("read proxy bytes");
        assert!(written.is_empty());
    }
    #[test]
    fn proxy_credentials_clear_and_debug_are_redacted() {
        let mut credentials = ProxyCredentials::new("UNIQUE_PROXY_USER", "UNIQUE_PROXY_PASSWORD");
        let debug = format!("{credentials:?}");
        assert_eq!(
            debug,
            "ProxyCredentials { username: \"[REDACTED]\", password: \"[REDACTED]\" }"
        );
        credentials.clear();
        assert!(credentials.user_pass.is_empty());
        assert_eq!(credentials.user_pass.capacity(), 0);
        assert_eq!(credentials.username_len, 0);
    }
    #[test]
    fn cloned_proxy_policy_shares_redacted_credentials_and_options_hide_pin() {
        let policy = ProxyPolicy::from_config(
            Some("https://UNIQUE_PROXY_USER:UNIQUE_PROXY_PASSWORD@proxy.example:8443".to_owned()),
            vec![".Example.COM".to_owned(), "127.0.0.1".to_owned()],
        )
        .expect("policy");
        let clone = policy.clone();
        let original_credentials = policy
            .proxy
            .as_ref()
            .and_then(|proxy| proxy.auth.as_ref())
            .expect("credentials");
        let cloned_credentials = clone
            .proxy
            .as_ref()
            .and_then(|proxy| proxy.auth.as_ref())
            .expect("credentials");
        assert!(Arc::ptr_eq(original_credentials, cloned_credentials));

        let opts = TcpConnectOptions {
            proxy: policy,
            outbound_dial_policy: Arc::new(crate::dial_policy::OutboundDialPolicy::default()),
            proxy_tls_verify: true,
            proxy_tls_pinned_cert_der: Some(Arc::from(b"UNIQUE_PROXY_PIN_MATERIAL".to_vec())),
            tcp_nodelay: true,
            tcp_keepalive: None,
        };
        let debug = format!("{opts:?}");
        assert_eq!(
            debug,
            "TcpConnectOptions { proxy: ProxyPolicy { proxy: Some(Proxy { kind: HttpConnectTls, host: \"proxy.example\", port: 8443, auth_present: true }), no_proxy_count: 2 }, proxy_tls_verify: true, proxy_tls_pin_present: true, proxy_tls_pin_len: 25, tcp_nodelay: true, tcp_keepalive: None, .. }"
        );
        for secret in [
            "UNIQUE_PROXY_USER",
            "UNIQUE_PROXY_PASSWORD",
            "UNIQUE_PROXY_PIN_MATERIAL",
        ] {
            assert!(!debug.contains(secret), "Debug leaked {secret}");
        }
    }
    #[test]
    fn no_proxy_matches_only_exact_ip_or_dns_label_boundary() {
        let policy = ProxyPolicy::from_config(
            None,
            vec![
                ".Example.COM".to_owned(),
                "192.0.2.1".to_owned(),
                "[2001:db8::1]".to_owned(),
            ],
        )
        .expect("no-proxy policy");
        assert!(policy.should_bypass_proxy("example.com"));
        assert!(policy.should_bypass_proxy("Api.Example.Com."));
        assert!(!policy.should_bypass_proxy("notexample.com"));
        assert!(!policy.should_bypass_proxy("example.com.attacker"));
        assert!(policy.should_bypass_proxy("192.0.2.1"));
        assert!(!policy.should_bypass_proxy("1192.0.2.1"));
        assert!(policy.should_bypass_proxy("2001:0db8:0:0:0:0:0:1"));
        assert!(!policy.should_bypass_proxy("2001:db8::2"));
        assert!(
            policy.should_bypass_proxy("::ffff:192.0.2.1"),
            "IPv4-mapped spelling must not leak an IPv4 no-proxy target through the proxy"
        );

        let mapped = ProxyPolicy::from_config(None, vec!["::ffff:192.0.2.2".to_owned()])
            .expect("mapped no-proxy policy");
        assert!(
            mapped.should_bypass_proxy("192.0.2.2"),
            "mapped no-proxy entries must match canonical IPv4 targets"
        );

        let wildcard = ProxyPolicy::from_config(None, vec!["*".to_owned()]).expect("wildcard");
        assert!(wildcard.should_bypass_proxy("anything.example"));
    }
    #[test]
    fn no_proxy_rejects_invalid_suffixes() {
        for invalid in ["..example.com", "exa_mple.com", "[2001:db8::1", "例.test"] {
            let error = ProxyPolicy::from_config(None, vec![invalid.to_owned()])
                .expect_err("invalid no-proxy entry");
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        }
    }
    #[tokio::test(flavor = "current_thread")]
    async fn outbound_policy_rejects_literal_before_opening_tcp_connection() {
        use tokio::net::TcpListener;

        let listener = match TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
            Err(error) => panic!("bind: {error:?}"),
        };
        let endpoint = listener.local_addr().expect("listener address");
        let opts = TcpConnectOptions {
            outbound_dial_policy: Arc::new(
                crate::dial_policy::OutboundDialPolicy::from_config(
                    Vec::new(),
                    vec!["127.0.0.0/8".to_owned()],
                    Vec::new(),
                    Vec::new(),
                )
                .expect("policy"),
            ),
            ..TcpConnectOptions::default()
        };
        let target = std::net::SocketAddr::new(endpoint.ip(), endpoint.port()).into();
        let error = match connect(&target, &opts).await {
            Err(error) => error,
            Ok(_) => panic!("denied target must fail closed"),
        };
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(25), listener.accept())
                .await
                .is_err(),
            "a denied literal must not open a TCP connection"
        );
    }
    #[tokio::test(flavor = "current_thread")]
    async fn outbound_policy_rechecks_every_dns_result_before_connecting() {
        use iroha_primitives::addr::SocketAddrHost;
        use tokio::net::TcpListener;

        let listener = match TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
            Err(error) => panic!("bind: {error:?}"),
        };
        let endpoint = listener.local_addr().expect("listener address");
        let opts = TcpConnectOptions {
            outbound_dial_policy: Arc::new(
                crate::dial_policy::OutboundDialPolicy::from_config(
                    Vec::new(),
                    vec!["127.0.0.0/8".to_owned(), "::1/128".to_owned()],
                    Vec::new(),
                    Vec::new(),
                )
                .expect("policy"),
            ),
            ..TcpConnectOptions::default()
        };
        let target = SocketAddr::Host(SocketAddrHost {
            host: "localhost".into(),
            port: endpoint.port(),
        });
        let error = match connect(&target, &opts).await {
            Err(error) => error,
            Ok(_) => panic!("denied DNS result must fail closed"),
        };
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(25), listener.accept())
                .await
                .is_err(),
            "a denied DNS result must not open a TCP connection"
        );
    }
    #[tokio::test(flavor = "current_thread")]
    async fn outbound_policy_applies_to_proxy_endpoint_before_connecting() {
        use iroha_primitives::addr::socket_addr;
        use tokio::net::TcpListener;

        let listener = match TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
            Err(error) => panic!("bind: {error:?}"),
        };
        let endpoint = listener.local_addr().expect("proxy address");
        let opts = TcpConnectOptions {
            proxy: ProxyPolicy::from_config(
                Some(format!("http://{}:{}", endpoint.ip(), endpoint.port())),
                Vec::new(),
            )
            .expect("proxy policy"),
            outbound_dial_policy: Arc::new(
                crate::dial_policy::OutboundDialPolicy::from_config(
                    Vec::new(),
                    vec!["127.0.0.0/8".to_owned()],
                    Vec::new(),
                    Vec::new(),
                )
                .expect("dial policy"),
            ),
            ..TcpConnectOptions::default()
        };
        let error = match connect(&socket_addr!(192.0.2.1:443), &opts).await {
            Err(error) => error,
            Ok(_) => panic!("denied proxy endpoint must fail closed"),
        };
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(25), listener.accept())
                .await
                .is_err(),
            "a denied proxy endpoint must not open a TCP connection"
        );
    }
    #[test]
    fn connect_response_parser_requires_exact_bounded_http11_success() {
        for valid in [
            b"HTTP/1.1 200\r\n\r\n".as_slice(),
            b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: test\r\n\r\n".as_slice(),
        ] {
            validate_http_connect_response(valid).expect("exact HTTP/1.1 200 must pass");
        }
        for invalid in [
            b"HTTP/1.0 200 OK\r\n\r\n".as_slice(),
            b"HTTP/1.1 2000 Not Really\r\n\r\n".as_slice(),
            b"HTTP/1.1 204 No Content\r\n\r\n".as_slice(),
            b"HTTP/1.1 200 OK\n\n".as_slice(),
            b"HTTP/1.1 200 OK\r\nBadHeader\r\n\r\n".as_slice(),
            b"HTTP/1.1 200 OK\r\nX-Test: bad\x01value\r\n\r\n".as_slice(),
            b"HTTP/1.1 200 OK\r\nX-Test: value\r\n".as_slice(),
        ] {
            validate_http_connect_response(invalid).expect_err("malformed response must fail");
        }
    }
    #[tokio::test]
    async fn connect_tunnel_stops_exactly_after_header_and_rejects_eof_or_oversize() {
        use iroha_primitives::addr::socket_addr;
        let proxy = Proxy {
            kind: ProxyKind::HttpConnect,
            host: "proxy.example".to_owned(),
            port: 8080,
            auth: None,
        };
        let target = socket_addr!(192.0.2.1:443);
        let (mut client, mut server) = tokio::io::duplex(16_384);
        let server_task = tokio::spawn(async move {
            let mut request = Vec::new();
            loop {
                let mut byte = [0u8; 1];
                server.read_exact(&mut byte).await.expect("CONNECT request");
                request.push(byte[0]);
                if request.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            server
                .write_all(b"HTTP/1.1 200 OK\r\nX: y\r\n\r\nPOST_HEADER")
                .await
                .expect("response");
        });
        http_connect_tunnel(&mut client, &proxy, &target, "proxy.example:8080")
            .await
            .expect("valid CONNECT response");
        let mut tunnel_bytes = [0u8; 11];
        client
            .read_exact(&mut tunnel_bytes)
            .await
            .expect("post-header bytes must remain readable");
        assert_eq!(&tunnel_bytes, b"POST_HEADER");
        server_task.await.expect("server task");

        for response in [b"HTTP/1.1 200 OK\r\nIncomplete".to_vec(), vec![b'A'; 8192]] {
            let (mut client, mut server) = tokio::io::duplex(16_384);
            let server_task = tokio::spawn(async move {
                let mut request = Vec::new();
                loop {
                    let mut byte = [0u8; 1];
                    server.read_exact(&mut byte).await.expect("CONNECT request");
                    request.push(byte[0]);
                    if request.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                server.write_all(&response).await.expect("response");
            });
            http_connect_tunnel(&mut client, &proxy, &target, "proxy.example:8080")
                .await
                .expect_err("unterminated response must fail");
            server_task.await.expect("server task");
        }
    }
    #[tokio::test(flavor = "current_thread")]
    async fn plaintext_proxy_credentials_are_rejected_before_any_proxy_bytes() {
        use iroha_primitives::addr::socket_addr;
        use tokio::net::TcpListener;

        for kind in [ProxyKind::HttpConnect, ProxyKind::Socks5] {
            let listener = match TcpListener::bind("127.0.0.1:0").await {
                Ok(listener) => listener,
                Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
                Err(error) => panic!("bind: {error:?}"),
            };
            let endpoint = listener.local_addr().expect("proxy address");
            let opts = TcpConnectOptions {
                proxy: ProxyPolicy {
                    proxy: Some(Proxy {
                        kind,
                        host: endpoint.ip().to_string(),
                        port: endpoint.port(),
                        auth: Some(Arc::new(ProxyCredentials::new("user", "password"))),
                    }),
                    no_proxy: Vec::new(),
                },
                ..TcpConnectOptions::default()
            };
            let error = match connect(&socket_addr!(192.0.2.1:443), &opts).await {
                Err(error) => error,
                Ok(_) => panic!("plaintext proxy credentials must fail closed"),
            };
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(25), listener.accept())
                    .await
                    .is_err(),
                "rejected plaintext proxy credentials must not even open the proxy channel"
            );
        }
    }
    #[tokio::test(flavor = "current_thread")]
    async fn unverified_or_unpinned_https_proxy_is_rejected_before_connect_auth() {
        use iroha_primitives::addr::socket_addr;
        use tokio::net::TcpListener;

        for (verify, pin) in [(false, None), (true, None)] {
            let listener = match TcpListener::bind("127.0.0.1:0").await {
                Ok(listener) => listener,
                Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return,
                Err(error) => panic!("bind: {error:?}"),
            };
            let endpoint = listener.local_addr().expect("proxy address");
            let proxy_url = format!(
                "https://UNIQUE_USER:UNIQUE_PASSWORD@{}:{}",
                endpoint.ip(),
                endpoint.port()
            );
            let opts = TcpConnectOptions {
                proxy: ProxyPolicy::from_config(Some(proxy_url), Vec::new()).expect("proxy policy"),
                proxy_tls_verify: verify,
                proxy_tls_pinned_cert_der: pin,
                ..TcpConnectOptions::default()
            };
            let error = match connect(&socket_addr!(192.0.2.1:443), &opts).await {
                Err(error) => error,
                Ok(_) => panic!("unverified or unpinned HTTPS proxy must fail closed"),
            };
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(25), listener.accept())
                    .await
                    .is_err(),
                "rejected HTTPS proxy settings must not send CONNECT or authorization bytes"
            );
        }
    }
    #[test]
    fn apply_tcp_socket_options_enables_keepalive_when_configured() {
        use socket2::{Domain, Protocol, Socket, Type};
        // Binding/listening is prohibited in some sandbox environments. Keep this test local
        // to socket options and avoid requiring a live TCP connection.
        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).expect("socket");
        let sock_ref = SockRef::from(&socket);
        apply_tcp_socket_options_sockref(
            &sock_ref,
            true,
            Some(std::time::Duration::from_secs(123)),
        );
        let enabled = SockRef::from(&socket).keepalive().expect("read keepalive");
        assert!(enabled, "SO_KEEPALIVE was not enabled");
    }
    #[tokio::test(flavor = "current_thread")]
    async fn socks5_connect_no_auth_ipv4_target_roundtrips() {
        use iroha_primitives::addr::socket_addr;
        let (mut client, mut server) = tokio::io::duplex(1024);
        let proxy = Proxy {
            kind: ProxyKind::Socks5,
            host: "proxy.example.com".into(),
            port: 1080,
            auth: None,
        };
        let target = socket_addr!(1.2.3.4:1234);
        let client_fut = async { socks5_connect(&mut client, &proxy, &target).await };
        let server_fut = async move {
            // Greeting
            let mut head = [0u8; 2];
            server.read_exact(&mut head).await?;
            assert_eq!(head[0], 0x05, "VER");
            let n_methods = head[1] as usize;
            let mut methods = vec![0u8; n_methods];
            server.read_exact(&mut methods).await?;
            assert!(
                methods.contains(&0x00),
                "client must advertise NO AUTH method"
            );
            // Choose no-auth
            server.write_all(&[0x05, 0x00]).await?;
            // CONNECT request
            let mut req = [0u8; 4];
            server.read_exact(&mut req).await?;
            assert_eq!(req[0], 0x05, "VER");
            assert_eq!(req[1], 0x01, "CMD=CONNECT");
            assert_eq!(req[2], 0x00, "RSV");
            assert_eq!(req[3], 0x01, "ATYP=IPv4");
            let mut ip = [0u8; 4];
            server.read_exact(&mut ip).await?;
            let mut port = [0u8; 2];
            server.read_exact(&mut port).await?;
            assert_eq!(ip, [1, 2, 3, 4]);
            assert_eq!(u16::from_be_bytes(port), 1234);
            // Reply: success, bind 0.0.0.0:0
            server
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            Ok::<_, io::Error>(())
        };
        let (client_res, server_res) = tokio::join!(client_fut, server_fut);
        client_res.expect("client should succeed");
        server_res.expect("server should complete");
    }
    #[tokio::test(flavor = "current_thread")]
    async fn socks5_connect_uses_domain_type_for_hostname_targets() {
        use iroha_primitives::addr::SocketAddrHost;
        let (mut client, mut server) = tokio::io::duplex(1024);
        let proxy = Proxy {
            kind: ProxyKind::Socks5,
            host: "proxy.example.com".into(),
            port: 1080,
            auth: None,
        };
        let target = SocketAddr::Host(SocketAddrHost {
            host: "example.com".into(),
            port: 9999,
        });
        let client_fut = async { socks5_connect(&mut client, &proxy, &target).await };
        let server_fut = async move {
            // Greeting, choose no-auth
            let mut head = [0u8; 2];
            server.read_exact(&mut head).await?;
            let mut methods = vec![0u8; head[1] as usize];
            server.read_exact(&mut methods).await?;
            server.write_all(&[0x05, 0x00]).await?;
            // CONNECT request: DOMAIN
            let mut req = [0u8; 4];
            server.read_exact(&mut req).await?;
            assert_eq!(req[0], 0x05);
            assert_eq!(req[1], 0x01);
            assert_eq!(req[2], 0x00);
            assert_eq!(req[3], 0x03, "ATYP=DOMAIN");
            let mut len = [0u8; 1];
            server.read_exact(&mut len).await?;
            let mut name = vec![0u8; len[0] as usize];
            server.read_exact(&mut name).await?;
            let mut port = [0u8; 2];
            server.read_exact(&mut port).await?;
            assert_eq!(name, b"example.com");
            assert_eq!(u16::from_be_bytes(port), 9999);
            server
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            Ok::<_, io::Error>(())
        };
        let (client_res, server_res) = tokio::join!(client_fut, server_fut);
        client_res.expect("client should succeed");
        server_res.expect("server should complete");
    }
    async fn spawn_test_tls_server(
        alpn_protocols: Vec<Vec<u8>>,
        connections: usize,
    ) -> Option<(std::net::SocketAddr, Arc<[u8]>, tokio::task::JoinHandle<()>)> {
        use tokio::net::TcpListener;
        use tokio_rustls::TlsAcceptor;

        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(["test.local".to_owned()])
                .expect("generate test certificate");
        let cert_chain = vec![rustls::pki_types::CertificateDer::from(
            cert.der().as_ref().to_vec(),
        )];
        let private_key = rustls::pki_types::PrivateKeyDer::from(
            rustls::pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der()),
        );
        let mut server_config =
            rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_no_client_auth()
                .with_single_cert(cert_chain, private_key)
                .expect("test TLS server config");
        server_config.alpn_protocols = alpn_protocols;
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = match TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => return None,
            Err(error) => panic!("bind: {error:?}"),
        };
        let addr = listener.local_addr().expect("test TLS address");
        let server = tokio::spawn(async move {
            for _ in 0..connections {
                let (tcp, _) = listener.accept().await.expect("accept test TLS client");
                let _ = acceptor.accept(tcp).await;
            }
        });
        Some((addr, Arc::from(cert.der().as_ref().to_vec()), server))
    }
    #[tokio::test(flavor = "current_thread")]
    async fn raw_p2p_tls_requires_tls13_and_exact_alpn() {
        use tokio::net::TcpStream;

        for (server_alpn, should_succeed) in [
            (vec![P2P_ALPN.to_vec()], true),
            (Vec::new(), false),
            (vec![b"http/1.1".to_vec()], false),
        ] {
            let Some((addr, _cert, server)) = spawn_test_tls_server(server_alpn, 1).await else {
                return;
            };
            let tcp = TcpStream::connect(addr)
                .await
                .expect("connect test TLS server");
            let result = crate::transport::tls::connect_tls("test.local", tcp).await;
            if should_succeed {
                assert!(result.is_ok(), "exact raw P2P TLS profile must succeed");
            } else {
                assert!(
                    result.is_err(),
                    "raw P2P TLS profile accepted an invalid protocol negotiation"
                );
            }
            if let Ok(tls) = result {
                assert_eq!(tls.get_ref().1.alpn_protocol(), Some(P2P_ALPN));
            }
            server.await.expect("test TLS server task");
        }
    }
    #[tokio::test(flavor = "current_thread")]
    async fn self_signed_tls_rejects_certificate_signed_by_another_key() {
        use rustls::{
            server::{ClientHello, ResolvesServerCert},
            sign::CertifiedKey,
        };
        use std::sync::Arc;
        use tokio::net::{TcpListener, TcpStream};
        use tokio_rustls::TlsAcceptor;
        #[derive(Debug)]
        struct FixedCertificate(Arc<CertifiedKey>);
        impl ResolvesServerCert for FixedCertificate {
            fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
                Some(Arc::clone(&self.0))
            }
        }
        let rcgen::CertifiedKey { cert, .. } =
            rcgen::generate_simple_self_signed(["iroha-tls".to_owned()])
                .expect("generate advertised certificate");
        let rcgen::CertifiedKey {
            signing_key: unrelated_key,
            ..
        } = rcgen::generate_simple_self_signed(["attacker.local".to_owned()])
            .expect("generate unrelated key");
        let unrelated_key = rustls::pki_types::PrivateKeyDer::from(
            rustls::pki_types::PrivatePkcs8KeyDer::from(unrelated_key.serialize_der()),
        );
        let unrelated_key = rustls::crypto::ring::sign::any_supported_type(&unrelated_key)
            .expect("parse unrelated signing key");
        let advertised_cert = rustls::pki_types::CertificateDer::from(cert.der().as_ref().to_vec());
        let certified_key = CertifiedKey::new(vec![advertised_cert], unrelated_key);
        let mut server_cfg =
            rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(FixedCertificate(Arc::new(certified_key))));
        server_cfg.alpn_protocols = vec![P2P_ALPN.to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(server_cfg));
        let listener = match TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(error) => panic!("bind: {error:?}"),
        };
        let addr = listener.local_addr().expect("local addr");
        let server = async move {
            let (tcp, _) = listener.accept().await.expect("accept");
            acceptor.accept(tcp).await
        };
        let client = async move {
            let tcp = TcpStream::connect(addr).await.expect("connect");
            crate::transport::tls::connect_tls("iroha-tls", tcp).await
        };
        let (client_result, _server_result) = tokio::join!(client, server);
        assert!(
            client_result.is_err(),
            "TLS CertificateVerify must reject a replayed certificate without its private key"
        );
    }
    #[test]
    fn tcp_connect_stream_keeps_proxy_tls_state_off_stack() {
        const {
            assert!(
                std::mem::size_of::<TcpConnectStream>()
                    <= std::mem::size_of::<TcpStream>() + std::mem::size_of::<usize>()
            );
        }
    }
    #[tokio::test(flavor = "current_thread")]
    async fn boxed_https_proxy_stream_preserves_nested_p2p_tls_and_payload() {
        use iroha_primitives::addr::socket_addr;
        use tokio::net::TcpListener;
        use tokio_rustls::TlsAcceptor;

        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(["test.local".to_owned()])
                .expect("generate test certificate");
        let pinned: Arc<[u8]> = Arc::from(cert.der().as_ref());
        let expected_binding = certificate_fingerprint(pinned.as_ref());
        let mut config =
            rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_no_client_auth()
                .with_single_cert(
                    vec![rustls::pki_types::CertificateDer::from(pinned.to_vec())],
                    rustls::pki_types::PrivateKeyDer::from(
                        rustls::pki_types::PrivatePkcs8KeyDer::from(signing_key.serialize_der()),
                    ),
                )
                .expect("test TLS server config");
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let proxy_acceptor = TlsAcceptor::from(Arc::new(config.clone()));
        config.alpn_protocols = vec![P2P_ALPN.to_vec()];
        let peer_acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind proxy");
        let endpoint = listener.local_addr().expect("proxy address");
        let opts = TcpConnectOptions {
            proxy: ProxyPolicy::from_config(Some(format!("https://{endpoint}")), Vec::new())
                .expect("proxy policy"),
            proxy_tls_pinned_cert_der: Some(pinned),
            ..TcpConnectOptions::default()
        };
        let server = async move {
            let (tcp, _) = listener.accept().await.expect("accept proxy client");
            let mut proxy = proxy_acceptor.accept(tcp).await.expect("proxy TLS");
            assert_eq!(
                proxy.get_ref().1.alpn_protocol(),
                Some(b"http/1.1".as_slice())
            );
            let expected = b"CONNECT 192.0.2.1:443 HTTP/1.1\r\nHost: 192.0.2.1:443\r\nConnection: keep-alive\r\n\r\n";
            let mut request = vec![0; expected.len()];
            proxy
                .read_exact(&mut request)
                .await
                .expect("CONNECT request");
            assert_eq!(request, expected);
            proxy
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .expect("CONNECT response");
            proxy.flush().await.expect("flush CONNECT");
            let mut peer = peer_acceptor.accept(proxy).await.expect("nested P2P TLS");
            assert_eq!(peer.get_ref().1.alpn_protocol(), Some(P2P_ALPN));
            let mut payload = [0; 4];
            peer.read_exact(&mut payload)
                .await
                .expect("authenticated request");
            assert_eq!(&payload, b"ping");
            peer.write_all(b"pong")
                .await
                .expect("authenticated response");
            peer.flush().await.expect("flush response");
        };
        let client = async {
            let stream = connect(&socket_addr!(192.0.2.1:443), &opts)
                .await
                .expect("CONNECT tunnel");
            let TcpConnectStream::Tls(proxy) = stream else {
                panic!("HTTPS proxy must retain its TLS transport");
            };
            assert_eq!(
                proxy.get_ref().1.alpn_protocol(),
                Some(b"http/1.1".as_slice())
            );
            let mut peer = tls::connect_tls("test.local", proxy)
                .await
                .expect("nested P2P TLS");
            assert_eq!(peer.get_ref().1.alpn_protocol(), Some(P2P_ALPN));
            assert_eq!(
                tls_peer_certificate_fingerprint(&peer).unwrap(),
                expected_binding
            );
            peer.write_all(b"ping")
                .await
                .expect("authenticated request");
            peer.flush().await.expect("flush request");
            let mut payload = [0; 4];
            peer.read_exact(&mut payload)
                .await
                .expect("authenticated response");
            assert_eq!(&payload, b"pong");
        };
        tokio::join!(client, server);
    }
    #[tokio::test(flavor = "current_thread")]
    async fn https_proxy_tls_pinning_accepts_only_matching_cert() {
        use tokio::net::TcpStream;

        let Some((addr, pinned, server)) =
            spawn_test_tls_server(vec![b"http/1.1".to_vec()], 2).await
        else {
            return;
        };
        // Pinning should accept the exact end-entity certificate.
        let tcp = TcpStream::connect(addr).await.expect("connect");
        let verified = crate::transport::tls::connect_https_proxy_tls_pinned(
            "test.local",
            tcp,
            Arc::clone(&pinned),
        )
        .await;
        assert!(
            verified.is_ok(),
            "pinned TLS should accept the pinned certificate"
        );
        // A mismatched pin should be rejected.
        let tcp = TcpStream::connect(addr).await.expect("connect");
        let mut wrong = pinned.as_ref().to_vec();
        wrong[0] = wrong[0].wrapping_add(1);
        let wrong = Arc::<[u8]>::from(wrong);
        let verified =
            crate::transport::tls::connect_https_proxy_tls_pinned("test.local", tcp, wrong).await;
        assert!(
            verified.is_err(),
            "pinned TLS should reject mismatched certificates"
        );
        let _ = server.await;
    }
}
