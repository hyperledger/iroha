//! Eager, bounded QUIC DATAGRAM ingress for peer connections.

use super::*;
use futures::FutureExt;

const QUIC_DATAGRAM_INBOX_CAPACITY: usize = 256;
const QUIC_DATAGRAM_PREAUTH_DRAIN_LIMIT: usize = 256;

/// QUIC application error used for malformed production P2P DATAGRAMs.
const QUIC_DATAGRAM_PROTOCOL_ERROR_CODE: u32 = 0x4952_4f44;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum QuicDatagramDisposition {
    DropPreauth,
    Queue,
    Reject(&'static str),
}

enum QuicDatagramPumpEvent {
    Activate(QuicDatagramActivation),
    Datagram(Result<bytes::Bytes, quinn::ConnectionError>),
}

enum PreauthDrainError {
    Connection(String),
    Protocol(&'static str),
}

fn classify_quic_datagram(
    payload_len: usize,
    authenticated: bool,
    max_payload_bytes: usize,
) -> QuicDatagramDisposition {
    if payload_len == 0 {
        return QuicDatagramDisposition::Reject("zero-length QUIC DATAGRAM");
    }
    if payload_len > max_payload_bytes {
        return QuicDatagramDisposition::Reject("oversized QUIC DATAGRAM");
    }
    if authenticated {
        QuicDatagramDisposition::Queue
    } else {
        QuicDatagramDisposition::DropPreauth
    }
}

fn quic_datagram_queue_charge(payload_len: usize) -> Option<usize> {
    payload_len.checked_add(core::mem::size_of::<RetainedQuicDatagram>())
}

fn compact_quic_datagram(payload: &bytes::Bytes) -> bytes::Bytes {
    // Quinn returns a slice of its decoded packet buffer. Retaining that slice
    // can pin the entire packet even when the application payload is tiny, so
    // detach it before charging and queueing application-owned memory.
    bytes::Bytes::copy_from_slice(payload)
}

fn drain_ready_preauth_datagrams(
    connection: &quinn::Connection,
    max_payload_bytes: usize,
) -> Result<(), PreauthDrainError> {
    for drained in 0..=QUIC_DATAGRAM_PREAUTH_DRAIN_LIMIT {
        let Some(datagram) = connection.read_datagram().now_or_never() else {
            return Ok(());
        };
        let datagram =
            datagram.map_err(|error| PreauthDrainError::Connection(error.to_string()))?;
        if drained == QUIC_DATAGRAM_PREAUTH_DRAIN_LIMIT {
            return Err(PreauthDrainError::Protocol(
                "pre-authentication QUIC DATAGRAM backlog exceeds 256 entries",
            ));
        }
        match classify_quic_datagram(datagram.len(), false, max_payload_bytes) {
            QuicDatagramDisposition::DropPreauth => {}
            QuicDatagramDisposition::Reject(reason) => {
                return Err(PreauthDrainError::Protocol(reason));
            }
            QuicDatagramDisposition::Queue => unreachable!("pre-auth DATAGRAM cannot be queued"),
        }
    }
    unreachable!("bounded pre-auth drain loop always returns")
}

#[derive(Debug)]
pub(super) struct RetainedQuicDatagram {
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "shipping transport rejects QUIC before activation; qualification tests exercise the retained datagram path"
        )
    )]
    pub(super) payload: bytes::Bytes,
    _lease: SharedByteLease,
}

struct QuicDatagramActivation {
    byte_budget: InboundSourceByteBudget,
    acknowledged: oneshot::Sender<()>,
}

/// Eager, bounded QUIC DATAGRAM drain retained across application authentication.
///
/// Unauthenticated payloads are discarded, while authenticated payloads enter
/// a fixed-count inbox whose per-entry size is capped by configuration.
pub struct QuicDatagramIngress {
    inbox: mpsc::Receiver<RetainedQuicDatagram>,
    terminal: watch::Receiver<Option<Arc<str>>>,
    activation: Option<oneshot::Sender<QuicDatagramActivation>>,
    task: tokio::task::JoinHandle<()>,
}

impl QuicDatagramIngress {
    /// Start draining Quinn immediately after transport establishment.
    pub(crate) fn spawn(connection: &quinn::Connection, max_payload_bytes: usize) -> Self {
        let (inbox_tx, inbox) = mpsc::channel(QUIC_DATAGRAM_INBOX_CAPACITY);
        let (terminal_tx, terminal) = watch::channel(None::<Arc<str>>);
        let (activation_tx, mut activation_rx) = oneshot::channel::<QuicDatagramActivation>();
        let task_connection = connection.clone();
        // Locked quinn-proto 0.11.18 charges fixed per-entry overhead before
        // this pump polls. TODO: Complete transport qualification before
        // enabling the shipping QUIC endpoint constructors.
        let task = tokio::spawn(async move {
            let mut frames_since_yield = 0_u8;
            let mut byte_budget: Option<InboundSourceByteBudget> = None;
            loop {
                let event = if byte_budget.is_some() {
                    QuicDatagramPumpEvent::Datagram(task_connection.read_datagram().await)
                } else {
                    match activation_rx.try_recv() {
                        Ok(activation) => QuicDatagramPumpEvent::Activate(activation),
                        Err(oneshot::error::TryRecvError::Closed) => return,
                        Err(oneshot::error::TryRecvError::Empty) => {
                            tokio::select! {
                                biased;
                                datagram = task_connection.read_datagram() => {
                                    QuicDatagramPumpEvent::Datagram(datagram)
                                }
                                activation = &mut activation_rx => {
                                    let Ok(activation) = activation else {
                                        return;
                                    };
                                    QuicDatagramPumpEvent::Activate(activation)
                                }
                            }
                        }
                    }
                };

                match event {
                    QuicDatagramPumpEvent::Activate(activation) => {
                        // The first `Pending` observation after draining ready
                        // frames is the authentication linearization point.
                        // A bounded flood fails closed instead of starving the
                        // activation or promoting queued pre-auth traffic.
                        match drain_ready_preauth_datagrams(&task_connection, max_payload_bytes) {
                            Ok(()) => {}
                            Err(PreauthDrainError::Connection(reason)) => {
                                terminal_tx.send_replace(Some(
                                    format!("QUIC DATAGRAM receive failed: {reason}").into(),
                                ));
                                return;
                            }
                            Err(PreauthDrainError::Protocol(reason)) => {
                                terminal_tx.send_replace(Some(Arc::from(reason)));
                                task_connection.close(
                                    quinn::VarInt::from_u32(QUIC_DATAGRAM_PROTOCOL_ERROR_CODE),
                                    b"invalid pre-auth DATAGRAM",
                                );
                                while task_connection.read_datagram().await.is_ok() {
                                    tokio::task::yield_now().await;
                                }
                                return;
                            }
                        }
                        byte_budget = Some(activation.byte_budget);
                        if activation.acknowledged.send(()).is_err() {
                            return;
                        }
                    }
                    QuicDatagramPumpEvent::Datagram(datagram) => {
                        let datagram = match datagram {
                            Ok(datagram) => datagram,
                            Err(error) => {
                                terminal_tx.send_replace(Some(
                                    format!("QUIC DATAGRAM receive failed: {error}").into(),
                                ));
                                return;
                            }
                        };
                        let mut rejection = None;
                        match classify_quic_datagram(
                            datagram.len(),
                            byte_budget.is_some(),
                            max_payload_bytes,
                        ) {
                            QuicDatagramDisposition::DropPreauth => {}
                            QuicDatagramDisposition::Queue => match inbox_tx.try_reserve() {
                                Ok(permit) => {
                                    if let Some(charge) = quic_datagram_queue_charge(datagram.len())
                                    {
                                        if let Some(lease) = byte_budget
                                            .as_ref()
                                            .and_then(|budget| budget.try_reserve(charge))
                                        {
                                            permit.send(RetainedQuicDatagram {
                                                payload: compact_quic_datagram(&datagram),
                                                _lease: lease,
                                            });
                                        }
                                    } else {
                                        rejection = Some("QUIC DATAGRAM queue charge overflow");
                                    }
                                }
                                Err(mpsc::error::TrySendError::Full(())) => {}
                                Err(mpsc::error::TrySendError::Closed(())) => return,
                            },
                            QuicDatagramDisposition::Reject(reason) => rejection = Some(reason),
                        }
                        if let Some(reason) = rejection {
                            terminal_tx.send_replace(Some(Arc::from(reason)));
                            task_connection.close(
                                quinn::VarInt::from_u32(QUIC_DATAGRAM_PROTOCOL_ERROR_CODE),
                                b"invalid DATAGRAM",
                            );
                            while task_connection.read_datagram().await.is_ok() {
                                tokio::task::yield_now().await;
                            }
                            return;
                        }
                        frames_since_yield = frames_since_yield.wrapping_add(1);
                        if frames_since_yield == 0 {
                            tokio::task::yield_now().await;
                        }
                    }
                }
            }
        });
        Self {
            inbox,
            terminal,
            activation: Some(activation_tx),
            task,
        }
    }

    /// Serialize application authentication with the drain's observation order.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "shipping transport rejects QUIC before activation; qualification tests exercise the retained datagram path"
        )
    )]
    pub(super) async fn authenticate(
        &mut self,
        byte_budget: InboundSourceByteBudget,
    ) -> Result<(), Error> {
        let Some(activation) = self.activation.take() else {
            return Err(std::io::Error::other("QUIC DATAGRAM ingress activated twice").into());
        };
        let (acknowledged, acknowledgement) = oneshot::channel();
        activation
            .send(QuicDatagramActivation {
                byte_budget,
                acknowledged,
            })
            .map_err(|_| std::io::Error::other("QUIC DATAGRAM drain stopped before activation"))?;
        acknowledgement
            .await
            .map_err(|_| std::io::Error::other("QUIC DATAGRAM activation was not acknowledged"))?;
        Ok(())
    }

    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "shipping transport rejects QUIC before activation; qualification tests exercise the retained datagram path"
        )
    )]
    pub(super) async fn recv(&mut self) -> Result<RetainedQuicDatagram, Error> {
        loop {
            if let Some(reason) = self.terminal.borrow().clone() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    reason.to_string(),
                )
                .into());
            }
            tokio::select! {
                biased;
                changed = self.terminal.changed() => {
                    if changed.is_err() {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::ConnectionAborted,
                            "QUIC DATAGRAM drain stopped",
                        ).into());
                    }
                }
                datagram = self.inbox.recv() => {
                    return datagram.ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::ConnectionAborted,
                            "QUIC DATAGRAM inbox closed",
                        ).into()
                    });
                }
            }
        }
    }
}

impl Drop for QuicDatagramIngress {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quinn::{ClientConfig, Endpoint, ServerConfig, TransportConfig};
    use rustls::pki_types::PrivatePkcs8KeyDer;

    async fn connection_pair()
    -> std::io::Result<(Endpoint, Endpoint, quinn::Connection, quinn::Connection)> {
        use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};

        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(["iroha-quic".to_owned()])
                .map_err(std::io::Error::other)?;
        let private_key = PrivatePkcs8KeyDer::from(signing_key.serialize_der());
        let mut tls =
            rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_no_client_auth()
                .with_single_cert(vec![cert.der().clone().into_owned()], private_key.into())
                .map_err(std::io::Error::other)?;
        tls.max_early_data_size = 0;
        tls.alpn_protocols = vec![crate::transport::quic::P2P_ALPN.to_vec()];
        let crypto = QuicServerConfig::try_from(Arc::new(tls)).map_err(std::io::Error::other)?;
        let mut server_config = ServerConfig::with_crypto(Arc::new(crypto));
        let mut server_transport = TransportConfig::default();
        server_transport
            .datagram_receive_buffer_size(Some(64 * 1024))
            .datagram_send_buffer_size(64 * 1024);
        server_config.transport_config(Arc::new(server_transport));
        let endpoint =
            Endpoint::server(server_config, "127.0.0.1:0".parse().expect("test address"))?;
        let server_addr = endpoint.local_addr()?;
        let mut client_endpoint = Endpoint::client("127.0.0.1:0".parse().expect("test address"))?;
        let verifier: Arc<dyn rustls::client::danger::ServerCertVerifier> =
            Arc::new(crate::transport::CertificateKeyProofVerifier::unpinned());
        let mut client_tls = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        client_tls.enable_early_data = false;
        client_tls.alpn_protocols = vec![crate::transport::quic::P2P_ALPN.to_vec()];
        let client_crypto =
            QuicClientConfig::try_from(Arc::new(client_tls)).map_err(std::io::Error::other)?;
        let mut client_config = ClientConfig::new(Arc::new(client_crypto));
        let mut client_transport = TransportConfig::default();
        client_transport
            .datagram_receive_buffer_size(Some(64 * 1024))
            .datagram_send_buffer_size(64 * 1024);
        client_config.transport_config(Arc::new(client_transport));
        client_endpoint.set_default_client_config(client_config);
        let accepted = async {
            let incoming = endpoint
                .accept()
                .await
                .ok_or_else(|| std::io::Error::other("test endpoint closed"))?;
            let connecting = incoming.accept().map_err(std::io::Error::other)?;
            connecting.await.map_err(std::io::Error::other)
        };
        let connected = async {
            client_endpoint
                .connect(server_addr, "iroha-quic")
                .map_err(std::io::Error::other)?
                .await
                .map_err(std::io::Error::other)
        };
        let (server, client) = tokio::try_join!(accepted, connected)?;
        Ok((endpoint, client_endpoint, server, client))
    }

    #[test]
    fn datagram_policy_drops_preauth_and_rejects_unbudgeted_shapes() {
        assert_eq!(
            classify_quic_datagram(1, false, 32),
            QuicDatagramDisposition::DropPreauth
        );
        assert_eq!(
            classify_quic_datagram(1, true, 32),
            QuicDatagramDisposition::Queue
        );
        assert!(matches!(
            classify_quic_datagram(0, false, 32),
            QuicDatagramDisposition::Reject(_)
        ));
        assert!(matches!(
            classify_quic_datagram(33, true, 32),
            QuicDatagramDisposition::Reject(_)
        ));
        assert_eq!(
            quic_datagram_queue_charge(32),
            Some(32 + core::mem::size_of::<RetainedQuicDatagram>())
        );
        assert_eq!(quic_datagram_queue_charge(usize::MAX), None);
    }

    #[test]
    fn compact_datagram_releases_packet_sized_backing_owner() {
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
        let packet = bytes::Bytes::from_owner(TrackedOwner {
            bytes: vec![0_u8; 64 * 1024],
            dropped: Arc::clone(&dropped),
        });
        let payload = packet.slice(17..21);
        drop(packet);
        let compact = compact_quic_datagram(&payload);
        drop(payload);
        assert!(dropped.load(std::sync::atomic::Ordering::Acquire));
        assert_eq!(compact.as_ref(), &[0, 0, 0, 0]);
    }

    #[tokio::test]
    async fn full_datagram_inbox_rejects_before_another_entry_is_charged() {
        let (inbox_tx, mut inbox) = mpsc::channel(1);
        let charge = quic_datagram_queue_charge(1).expect("small charge");
        let budget = SharedByteBudget::new(charge * 2, 0).expect("test byte budget");

        let first_lease = budget.try_reserve(charge, false).expect("first entry fits");
        inbox_tx
            .try_send(RetainedQuicDatagram {
                payload: bytes::Bytes::from_static(&[1]),
                _lease: first_lease,
            })
            .expect("first entry fills inbox");

        assert!(matches!(
            inbox_tx.try_reserve(),
            Err(mpsc::error::TrySendError::Full(()))
        ));
        assert_eq!(budget.retained_total(), charge);

        drop(inbox.recv().await.expect("queued entry"));
        assert_eq!(budget.retained_total(), 0);
    }

    #[tokio::test]
    async fn ingress_terminal_preempts_buffered_frames_and_drop_aborts_task() {
        let (inbox_tx, inbox) = mpsc::channel(1);
        let (terminal_tx, terminal) = watch::channel(None::<Arc<str>>);
        let (activation_tx, activation_rx) = oneshot::channel::<QuicDatagramActivation>();
        let task = tokio::spawn(async move {
            let activation = activation_rx.await.expect("activation request");
            activation
                .acknowledged
                .send(())
                .expect("activation caller remains alive");
            std::future::pending::<()>().await;
        });
        let abort_handle = task.abort_handle();
        let mut ingress = QuicDatagramIngress {
            inbox,
            terminal,
            activation: Some(activation_tx),
            task,
        };
        let budget = SharedByteBudget::new(1024, 0).expect("test byte budget");
        ingress
            .authenticate(InboundSourceByteBudget::shared_only(Arc::clone(&budget)))
            .await
            .expect("activate ingress");
        let charge = quic_datagram_queue_charge(6).expect("small charge");
        let lease = budget.try_reserve(charge, false).expect("test byte lease");
        inbox_tx
            .send(RetainedQuicDatagram {
                payload: bytes::Bytes::from_static(b"queued"),
                _lease: lease,
            })
            .await
            .expect("test inbox open");
        terminal_tx.send_replace(Some(Arc::from("terminal violation")));
        let error = ingress
            .recv()
            .await
            .expect_err("terminal state must beat buffered frames");
        assert!(matches!(error, Error::Io(_)));
        drop(ingress);
        tokio::task::yield_now().await;
        assert!(abort_handle.is_finished());
        assert_eq!(budget.retained_total(), 0);
    }

    #[tokio::test]
    async fn preauth_datagram_does_not_cross_activation_boundary() {
        let pair = tokio::time::timeout(Duration::from_secs(5), connection_pair()).await;
        let (_server_endpoint, _client_endpoint, server, client) = match pair {
            Ok(Ok(pair)) => pair,
            Ok(Err(error)) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("QUIC test skipped: {error}");
                return;
            }
            Ok(Err(error)) => panic!("QUIC pair failed: {error}"),
            Err(error) => panic!("QUIC pair timed out: {error}"),
        };

        let received_before = server.stats().frame_rx.datagram;
        client
            .send_datagram(bytes::Bytes::from_static(b"preauth"))
            .expect("queue pre-authentication DATAGRAM");
        tokio::time::timeout(Duration::from_secs(2), async {
            while server.stats().frame_rx.datagram == received_before {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("server transport must queue pre-authentication DATAGRAM");

        // Both the activation and the dependency-owned DATAGRAM are ready when
        // the pump is first scheduled. The pump must drain the latter under
        // pre-authentication policy before acknowledging the boundary.
        let mut ingress = QuicDatagramIngress::spawn(&server, 32);
        let budget = SharedByteBudget::new(1024, 0).expect("test byte budget");
        ingress
            .authenticate(InboundSourceByteBudget::shared_only(budget))
            .await
            .expect("activate ingress after draining pre-authentication traffic");

        client
            .send_datagram(bytes::Bytes::from_static(b"postauth"))
            .expect("queue authenticated DATAGRAM");
        let retained = tokio::time::timeout(Duration::from_secs(2), ingress.recv())
            .await
            .expect("authenticated DATAGRAM must arrive")
            .expect("authenticated DATAGRAM must be retained");
        assert_eq!(retained.payload.as_ref(), b"postauth");
    }

    #[tokio::test]
    async fn empty_datagram_is_rejected_before_application_authentication() {
        let pair = tokio::time::timeout(Duration::from_secs(5), connection_pair()).await;
        let (_server_endpoint, _client_endpoint, server, client) = match pair {
            Ok(Ok(pair)) => pair,
            Ok(Err(error)) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("QUIC test skipped: {error}");
                return;
            }
            Ok(Err(error)) => panic!("QUIC pair failed: {error}"),
            Err(error) => panic!("QUIC pair timed out: {error}"),
        };
        let mut ingress = QuicDatagramIngress::spawn(&server, 32);
        client
            .send_datagram(bytes::Bytes::new())
            .expect("empty DATAGRAM reaches the peer transport");
        let error = tokio::time::timeout(Duration::from_secs(2), ingress.recv())
            .await
            .expect("eager drain must observe the DATAGRAM")
            .expect_err("empty DATAGRAM must be terminal before authentication");
        let Error::Io(error) = error else {
            panic!("unexpected error: {error}");
        };
        assert!(error.to_string().contains("zero-length"));
        tokio::time::timeout(Duration::from_secs(2), client.closed())
            .await
            .expect("protocol close must reach the sender");
    }
}
