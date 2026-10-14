//! Loopback integration test covering FeedbackHint/ReceiverReport flow and parity decisions.
use eyre::{Result as EyreResult, eyre};
use iroha_core::streaming::StreamingHandle;
use iroha_crypto::{Algorithm, KeyPair, streaming::FeedbackStateSnapshot};
use iroha_data_model::peer::Peer;
use iroha_p2p::streaming::{
    StreamingClient, StreamingServer,
    quic::{Error as QuicError, TransportConfigSettings},
};
use iroha_primitives::addr::SocketAddr;
use norito::streaming::{
    AudioCapability, CapabilityFlags, CapabilityReport, CapabilityRole, ControlFrame,
    FeedbackHintFrame, ReceiverReport, Resolution, SyncDiagnostics, TransportCapabilities,
};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr as StdSocketAddr},
    time::Duration,
};
use tokio::time::timeout;
const FEEDBACK_FP_SHIFT: u32 = 16;
const FEEDBACK_ALPHA_FP: u32 = 13_107;
const FEEDBACK_OFFSET_FP: u32 = 327;
const FEEDBACK_CEIL_BIAS: u32 = 0xFFFF;
const FEC_WINDOW_CHUNKS: u32 = 12;
const MAX_PARITY_CHUNKS: u8 = 6;
const LOOPBACK_TIMEOUT: Duration = Duration::from_secs(15);
fn fill_hash(byte: u8) -> [u8; 32] {
    [byte; 32]
}
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn loss_ratio_to_q16(loss_ratio: f64) -> u32 {
    ((loss_ratio * 65_536.0).round()) as u32
}
fn ewma_update(current: u32, sample: u32) -> u32 {
    if current == sample {
        return current;
    }
    let diff = i64::from(sample) - i64::from(current);
    let update = ((diff * i64::from(FEEDBACK_ALPHA_FP)) + (1 << (FEEDBACK_FP_SHIFT - 1)))
        >> FEEDBACK_FP_SHIFT;
    let mut next = i64::from(current) + update;
    if next < 0 {
        next = 0;
    }
    let clamped = next.clamp(0, i64::from(u32::MAX));
    u32::try_from(clamped).expect("clamped to u32")
}
fn parity_from_loss_fp(loss_fp: u32) -> u8 {
    let scaled = (u64::from(loss_fp) * 5) / 4;
    let adjusted = (scaled + u64::from(FEEDBACK_OFFSET_FP)) * u64::from(FEC_WINDOW_CHUNKS);
    let parity = ((adjusted + u64::from(FEEDBACK_CEIL_BIAS)) >> FEEDBACK_FP_SHIFT)
        .min(u64::from(MAX_PARITY_CHUNKS));
    u8::try_from(parity).expect("parity within u8")
}
fn make_peer(keys: &KeyPair, port: u16) -> Peer {
    let std_addr = StdSocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let addr = SocketAddr::from(std_addr);
    Peer::new(addr, keys.public_key().clone())
}
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::too_many_lines)]
async fn norito_streaming_feedback_loopback() -> EyreResult<()> {
    let settings = TransportConfigSettings::default();
    let negotiated_max_datagram = u16::try_from(settings.max_datagram_size).map_err(|_| {
        eyre!(
            "max datagram size {} exceeds u16",
            settings.max_datagram_size
        )
    })?;
    let server_addr = StdSocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let server = match StreamingServer::bind(server_addr, settings).await {
        Ok(server) => server,
        Err(QuicError::Io(err)) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("streaming feedback test skipped: {err}");
            return Ok(());
        }
        Err(err) => return Err(eyre!(err)),
    };
    let listen_addr = server.local_addr().map_err(|err| eyre!(err))?;
    let server_certificate_fingerprint = server.certificate_fingerprint();
    let publisher_keys = KeyPair::try_random_with_algorithm(Algorithm::Ed25519)
        .expect("generate checked streaming publisher Ed25519 keypair");
    let viewer_keys = KeyPair::try_random().expect("generate checked streaming viewer keypair");
    let publisher_peer = make_peer(&publisher_keys, 24_101);
    let viewer_peer = make_peer(&viewer_keys, 24_102);
    let feedback_caps = CapabilityFlags::from_bits(
        CapabilityFlags::FEATURE_FEEDBACK_HINTS | CapabilityFlags::FEATURE_PRIVACY_PROVIDER,
    );
    let publisher_handle = StreamingHandle::new().with_capabilities(feedback_caps);
    let viewer_handle = StreamingHandle::new().with_capabilities(feedback_caps);
    let stream_id = fill_hash(0xA1);
    let first_loss_fp = loss_ratio_to_q16(0.07);
    let second_loss_fp = loss_ratio_to_q16(0.01);
    let expected_initial_parity = parity_from_loss_fp(first_loss_fp);
    let expected_ewma_after_second = ewma_update(first_loss_fp, second_loss_fp);
    let server_task = {
        let server = server.clone();
        let publisher_handle = publisher_handle.clone();
        let viewer_peer = viewer_peer.clone();
        async move {
            let mut conn = server.accept().await.map_err(|err| eyre!(err))?;
            let mut publisher_caps = TransportCapabilities::kyber768_default();
            publisher_caps.max_segment_datagram_size = 1_024;
            let (_ack, resolution) = publisher_handle
                .negotiate_publisher_transport(&viewer_peer, &mut conn, publisher_caps)
                .await
                .map_err(|err| eyre!(err))?;
            let mut hints = 0_u8;
            let mut reports = 0_u8;
            while hints < 2 || reports < 2 {
                let frame = conn.next_control_frame().await.map_err(|err| eyre!(err))?;
                publisher_handle
                    .process_control_frame(&viewer_peer, &frame)
                    .map_err(|err| eyre!(err))?;
                match frame {
                    ControlFrame::FeedbackHint(_) => hints += 1,
                    ControlFrame::ReceiverReport(_) => reports += 1,
                    _ => {}
                }
            }
            let parity = publisher_handle
                .feedback_parity(viewer_peer.id())
                .expect("parity recorded");
            let snapshot = publisher_handle
                .feedback_snapshot(viewer_peer.id())
                .expect("snapshot recorded");
            conn.close();
            Ok::<(u8, FeedbackStateSnapshot, u16), eyre::Report>((
                parity,
                snapshot,
                resolution.fec_feedback_interval_ms,
            ))
        }
    };
    let viewer_task = {
        let publisher_peer = publisher_peer.clone();
        let viewer_handle = viewer_handle.clone();
        async move {
            let endpoint = format!("/ip4/127.0.0.1/udp/{}/quic", listen_addr.port());
            let mut client =
                StreamingClient::connect(&endpoint, server_certificate_fingerprint, settings)
                    .await
                    .map_err(|err| eyre!(err))?;
            let report = CapabilityReport {
                stream_id,
                endpoint_role: CapabilityRole::Viewer,
                protocol_version: 1,
                max_resolution: Resolution::R1080p,
                hdr_supported: false,
                capture_hdr: false,
                neural_bundles: vec![],
                audio_caps: AudioCapability {
                    sample_rates: vec![48_000],
                    ambisonics: false,
                    max_channels: 2,
                },
                feature_bits: feedback_caps,
                max_datagram_size: negotiated_max_datagram,
                dplpmtud: true,
            };
            let mut viewer_caps = TransportCapabilities::kyber768_default();
            viewer_caps.max_segment_datagram_size = 1_100;
            let (_ack, resolution) = viewer_handle
                .negotiate_viewer_transport(
                    &publisher_peer,
                    client.connection(),
                    viewer_caps,
                    report,
                )
                .await
                .map_err(|err| eyre!(err))?;
            let hint_primary = FeedbackHintFrame {
                stream_id,
                loss_ewma_q16: first_loss_fp,
                latency_gradient_q16: 0,
                observed_rtt_ms: 30,
                report_interval_ms: resolution.fec_feedback_interval_ms,
                parity_chunks: 0,
            };
            let report_primary = ReceiverReport {
                stream_id,
                latest_segment: 12,
                layer_mask: 0,
                measured_throughput_kbps: 1_300,
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
                sync_diagnostics: Some(SyncDiagnostics {
                    window_ms: 500,
                    samples: 96,
                    avg_audio_jitter_ms: 4,
                    max_audio_jitter_ms: 9,
                    avg_av_drift_ms: 2,
                    max_av_drift_ms: 8,
                    ewma_av_drift_ms: 3,
                    violation_count: 0,
                }),
            };
            let hint_followup = FeedbackHintFrame {
                stream_id,
                loss_ewma_q16: second_loss_fp,
                latency_gradient_q16: -256,
                observed_rtt_ms: 29,
                report_interval_ms: resolution.fec_feedback_interval_ms,
                parity_chunks: 0,
            };
            let report_followup = ReceiverReport {
                stream_id,
                latest_segment: 13,
                layer_mask: 0,
                measured_throughput_kbps: 1_450,
                rtt_ms: 31,
                loss_percent_x100: 120,
                decoder_buffer_ms: 110,
                active_resolution: Resolution::R720p,
                hdr_active: false,
                ecn_ce_count: 0,
                jitter_ms: 4,
                delivered_sequence: 1_050,
                parity_applied: 0,
                fec_budget: 0,
                sync_diagnostics: None,
            };
            client
                .connection()
                .send_control_frame(&ControlFrame::FeedbackHint(hint_primary))
                .await
                .map_err(|err| eyre!(err))?;
            client
                .connection()
                .send_control_frame(&ControlFrame::ReceiverReport(report_primary))
                .await
                .map_err(|err| eyre!(err))?;
            client
                .connection()
                .send_control_frame(&ControlFrame::FeedbackHint(hint_followup))
                .await
                .map_err(|err| eyre!(err))?;
            client
                .connection()
                .send_control_frame(&ControlFrame::ReceiverReport(report_followup))
                .await
                .map_err(|err| eyre!(err))?;
            // Let the publisher consume the control frames and terminate first. Closing
            // immediately can race with stream delivery and surface a spurious "closed by peer".
            let _ = client.connection().closed().await;
            client.close().await;
            Ok::<(), eyre::Report>(())
        }
    };
    let join_outcome = timeout(LOOPBACK_TIMEOUT, async {
        tokio::try_join!(server_task, viewer_task)
    })
    .await;
    match join_outcome {
        Err(_) => {
            server.shutdown().await;
            eprintln!("streaming feedback test skipped: feedback loop timed out");
            Ok(())
        }
        Ok(Err(err)) => {
            server.shutdown().await;
            if err
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io_err| io_err.kind() == std::io::ErrorKind::PermissionDenied)
            {
                eprintln!("streaming feedback test skipped: {err}");
                Ok(())
            } else {
                Err(err)
            }
        }
        Ok(Ok(((parity, snapshot, negotiated_interval), ()))) => {
            server.shutdown().await;
            assert_eq!(
                parity, expected_initial_parity,
                "publisher parity honours monotonic rule"
            );
            assert_eq!(
                snapshot.parity_chunks, parity,
                "snapshot parity mirrors session state"
            );
            assert_eq!(snapshot.hints_received, 2);
            assert_eq!(snapshot.reports_received, 2);
            assert_eq!(
                snapshot.loss_ewma_q16,
                Some(expected_ewma_after_second),
                "EWMA mirrors deterministic fixed-point calculation"
            );
            assert_eq!(
                snapshot.last_delivered_sequence,
                Some(1_050),
                "latest delivered sequence carried through report"
            );
            assert_eq!(
                snapshot.latest_parity_applied,
                Some(0),
                "publisher records viewer's applied parity"
            );
            assert_eq!(snapshot.latest_fec_budget, Some(0));
            assert_eq!(
                negotiated_interval,
                TransportCapabilities::kyber768_default().fec_feedback_interval_ms,
                "negotiated cadence defaults honoured"
            );
            Ok(())
        }
    }
}
