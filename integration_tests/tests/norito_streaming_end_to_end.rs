//! End-to-end Norito Streaming harness covering manifest + chunk delivery.
use crate::streaming::{
    self, StreamingTestVector, baseline_test_vector, make_peer, manifest_announce_for_viewer,
    streaming_handle, test_keypairs,
};
use eyre::{Result as EyreResult, eyre};
use iroha_core::streaming::StreamingProcessError;
use iroha_data_model::peer::Peer;
use iroha_p2p::streaming::{StreamingClient, StreamingServer, quic::TransportConfigSettings};
use norito::streaming::{
    CapabilityReport, CapabilityRole, ChunkAcknowledgeFrame, ControlFrame, TransportCapabilities,
};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr as StdSocketAddr},
    time::Duration,
};
use tokio::time::{sleep, timeout};
const ROUNDTRIP_TIMEOUT: Duration = Duration::from_secs(15);
#[tokio::test(flavor = "multi_thread")]
#[ignore = "shipping QUIC endpoint admission remains unavailable pending complete transport qualification"]
async fn norito_streaming_end_to_end_roundtrip() -> EyreResult<()> {
    let vector = baseline_test_vector();
    let snapshot = vector
        .snapshot_json()
        .map_err(|err| eyre!("snapshot encode failed: {err}"))?;
    let expected_snapshot =
        include_str!("../fixtures/norito_streaming/rans/baseline.json").replace("\r\n", "\n");
    assert_eq!(
        snapshot.trim_end(),
        expected_snapshot.trim_end(),
        "baseline streaming vector must match golden fixture"
    );
    let settings = TransportConfigSettings::default();
    let server_addr = StdSocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let server = StreamingServer::bind(server_addr, settings)
        .await
        .map_err(|err| eyre!(err))?;
    let listen_addr = server.local_addr().map_err(|err| eyre!(err))?;
    let server_certificate_fingerprint = server.certificate_fingerprint();
    let (publisher_keys, viewer_keys) = test_keypairs();
    let publisher_peer = make_peer(&publisher_keys, 26_100);
    let viewer_peer = make_peer(&viewer_keys, 26_101);
    let publisher_handle = streaming_handle();
    let viewer_handle = streaming_handle();
    let server_task = run_publisher(
        server.clone(),
        publisher_handle.clone(),
        viewer_peer.clone(),
        vector.clone(),
    );
    let viewer_task = run_viewer(
        listen_addr.port(),
        server_certificate_fingerprint,
        settings,
        publisher_peer.clone(),
        viewer_handle.clone(),
        vector.clone(),
    );
    let join_outcome = Box::pin(timeout(ROUNDTRIP_TIMEOUT, async {
        tokio::try_join!(server_task, viewer_task)
    }))
    .await;
    let (manifest_wire_bytes, (received_manifest, received_chunks)) = match join_outcome {
        Err(_) => {
            server.shutdown().await;
            return Err(eyre!("streaming end-to-end roundtrip timed out"));
        }
        Ok(Err(err)) => {
            server.shutdown().await;
            return Err(err);
        }
        Ok(Ok(result)) => result,
    };
    // Ensure the manifest observed by the viewer matches the publisher output.
    let expected_manifest_bytes = StreamingTestVector::manifest_wire_bytes(&received_manifest)
        .map_err(|err| eyre!("encode manifest: {err}"))?;
    assert_eq!(
        manifest_wire_bytes, expected_manifest_bytes,
        "publisher and viewer must agree on manifest bytes"
    );
    // Verify chunk payload integrity.
    assert_eq!(
        received_chunks.len(),
        vector.chunk_payloads.len(),
        "viewer must receive expected number of chunks"
    );
    for (idx, chunk) in received_chunks.iter().enumerate() {
        assert_eq!(
            chunk, &vector.chunk_payloads[idx],
            "chunk {idx} payload matches fixture"
        );
    }
    server.shutdown().await;
    Ok(())
}
async fn run_publisher(
    server: StreamingServer,
    handle: iroha_core::streaming::StreamingHandle,
    viewer_peer: Peer,
    vector: StreamingTestVector,
) -> EyreResult<Vec<u8>> {
    let mut conn = server.accept().await.map_err(|err| eyre!(err))?;
    let max_chunk = vector.max_chunk_len();
    let max_size =
        u16::try_from(max_chunk).map_err(|_| eyre!("chunk length {max_chunk} exceeds u16::MAX"))?;
    let mut publisher_caps = TransportCapabilities::kyber768_default();
    publisher_caps.max_segment_datagram_size = max_size;
    let StreamingTestVector {
        manifest,
        chunk_payloads,
        ..
    } = vector;
    let segment_number = manifest.segment_number;
    let expected_chunk_ids: Vec<u16> = manifest
        .chunk_descriptors
        .iter()
        .map(|descriptor| descriptor.chunk_id)
        .collect();
    assert_eq!(
        expected_chunk_ids.len(),
        chunk_payloads.len(),
        "chunk descriptors and payloads must align"
    );
    let (_ack, _resolution) = handle
        .negotiate_publisher_transport(&viewer_peer, &mut conn, publisher_caps)
        .await
        .map_err(|err| eyre!(err))?;
    let manifest_frame =
        manifest_announce_for_viewer(&handle, &viewer_peer, manifest).map_err(eyre_manifest)?;
    let manifest_wire = manifest_frame.manifest.clone();
    conn.send_control_frame(&ControlFrame::ManifestAnnounce(Box::new(manifest_frame)))
        .await
        .map_err(|err| eyre!(err))?;
    for chunk in &chunk_payloads {
        conn.send_datagram(chunk).await.map_err(|err| eyre!(err))?;
    }
    for expected_chunk_id in &expected_chunk_ids {
        let frame = timeout(ROUNDTRIP_TIMEOUT, conn.next_control_frame())
            .await
            .map_err(|_| {
                eyre!("timed out while awaiting chunk {expected_chunk_id} acknowledgement")
            })?
            .map_err(|err| eyre!(err))?;
        let acknowledge = if let ControlFrame::ChunkAcknowledge(frame) = frame {
            frame
        } else {
            return Err(eyre!(
                "unexpected control frame while awaiting acknowledgements: {frame:?}"
            ));
        };
        if acknowledge.segment != segment_number {
            return Err(eyre!(
                "chunk acknowledgement for unexpected segment: expected {segment_number}, found {}",
                acknowledge.segment
            ));
        }
        if acknowledge.chunk_id != *expected_chunk_id {
            return Err(eyre!(
                "chunk acknowledgement reported unexpected chunk id: expected {expected_chunk_id}, found {}",
                acknowledge.chunk_id
            ));
        }
    }
    // Allow the viewer to drain frames prior to shutdown.
    sleep(Duration::from_millis(25)).await;
    conn.close();
    StreamingTestVector::manifest_wire_bytes(&manifest_wire)
        .map_err(|err| eyre!("encode manifest: {err}"))
}
async fn run_viewer(
    port: u16,
    server_certificate_fingerprint: iroha_p2p::streaming::quic::CertificateFingerprint,
    settings: TransportConfigSettings,
    publisher_peer: Peer,
    handle: iroha_core::streaming::StreamingHandle,
    vector: StreamingTestVector,
) -> EyreResult<(norito::streaming::ManifestV1, Vec<Vec<u8>>)> {
    let endpoint = format!("/ip4/127.0.0.1/udp/{port}/quic");
    let mut client = StreamingClient::connect(&endpoint, server_certificate_fingerprint, settings)
        .await
        .map_err(|err| eyre!(err))?;
    let max_chunk = vector.max_chunk_len();
    let max_size =
        u16::try_from(max_chunk).map_err(|_| eyre!("chunk length {max_chunk} exceeds u16::MAX"))?;
    let report = CapabilityReport {
        stream_id: vector.manifest.stream_id,
        endpoint_role: CapabilityRole::Viewer,
        protocol_version: 1,
        max_resolution: norito::streaming::Resolution::R1080p,
        hdr_supported: false,
        capture_hdr: false,
        neural_bundles: Vec::new(),
        audio_caps: norito::streaming::AudioCapability {
            sample_rates: vec![48_000],
            ambisonics: false,
            max_channels: 2,
        },
        feature_bits: streaming::BASE_CAPABILITIES,
        max_datagram_size: max_size,
        dplpmtud: true,
    };
    let mut viewer_caps = TransportCapabilities::kyber768_default();
    viewer_caps.max_segment_datagram_size = max_size;
    let (_ack, _resolution) = handle
        .negotiate_viewer_transport(&publisher_peer, client.connection(), viewer_caps, report)
        .await
        .map_err(|err| eyre!(err))?;
    let manifest = loop {
        let frame = {
            let conn = client.connection();
            conn.next_control_frame().await.map_err(|err| eyre!(err))?
        };
        handle
            .process_control_frame(&publisher_peer, &frame)
            .map_err(eyre_manifest)?;
        if let ControlFrame::ManifestAnnounce(frame) = frame {
            break frame.manifest;
        }
    };
    let mut chunks = Vec::with_capacity(vector.chunk_payloads.len());
    for (idx, descriptor) in manifest.chunk_descriptors.iter().enumerate() {
        let datagram = {
            let conn = client.connection();
            timeout(ROUNDTRIP_TIMEOUT, conn.recv_datagram())
                .await
                .map_err(|_| eyre!("timed out while awaiting chunk payload {idx}"))?
                .map_err(|err| eyre!(err))?
        };
        chunks.push(datagram.to_vec());
        let acknowledgement = ControlFrame::ChunkAcknowledge(ChunkAcknowledgeFrame {
            segment: manifest.segment_number,
            chunk_id: descriptor.chunk_id,
        });
        client
            .connection()
            .send_control_frame(&acknowledgement)
            .await
            .map_err(|err| eyre!(err))?;
    }
    // Keep the viewer endpoint alive until the publisher closes so all chunk
    // acknowledgements are delivered before connection teardown.
    let _ = client.connection().closed().await;
    client.close().await;
    Ok((manifest, chunks))
}
fn eyre_manifest(err: StreamingProcessError) -> eyre::Report {
    eyre::Report::new(err)
}
