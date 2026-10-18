//! Negative-path coverage for the Norito Streaming integration harness.
use crate::streaming;
use iroha_config::parameters::actual;
use iroha_core::streaming::{KeyUpdateSpec, StreamingProcessError};
use iroha_crypto::{Algorithm, KeyPair};
use norito::streaming::{
    BUNDLED_RANS_GPU_BUILD_AVAILABLE, CapabilityFlags, CapabilityRole, ControlFrame,
    EncryptionSuite, EntropyMode, FecScheme, ManifestV1, Multiaddr, PrivacyCapabilities,
    PrivacyRelay, PrivacyRoute, StreamMetadata,
    codec::{BaselineManifestParams, ManifestError},
};
#[test]
fn manifest_chunk_root_mismatch_detected() {
    let (_config, segment, _frames) = streaming::baseline_segment(2);
    let stream_id = [0xAA; 32];
    let manifest = segment.build_manifest(BaselineManifestParams {
        stream_id,
        protocol_version: 1,
        published_at: 1_704_000_000,
        da_endpoint: Multiaddr::from("/dns/publisher.example/quic"),
        privacy_routes: vec![PrivacyRoute {
            route_id: [0xBB; 32],
            entry: PrivacyRelay {
                relay_id: [0xBC; 32],
                endpoint: Multiaddr::from("/dns/entry.relay/quic"),
                key_fingerprint: [0xBD; 32],
                capabilities: PrivacyCapabilities::from_bits(0b001),
            },
            exit: PrivacyRelay {
                relay_id: [0xBE; 32],
                endpoint: Multiaddr::from("/dns/exit.relay/quic"),
                key_fingerprint: [0xBF; 32],
                capabilities: PrivacyCapabilities::from_bits(0b010),
            },
            ticket_entry: vec![1, 2, 3],
            ticket_exit: vec![4, 5, 6],
            expiry_segment: 42,
            soranet: None,
        }],
        public_metadata: StreamMetadata {
            title: "Negative Manifest Test".into(),
            description: Some("Tampered chunk root should be rejected.".into()),
            access_policy_id: None,
            tags: vec!["nsc".into(), "negative".into()],
        },
        capabilities: streaming::BASE_CAPABILITIES,
        signature: [0xAB; 64],
        fec_suite: FecScheme::Rs12_10,
        neural_bundle: None,
        transport_capabilities_hash: [0xAC; 32],
    });
    let mut tampered_manifest: ManifestV1 = manifest.clone();
    tampered_manifest.chunk_root[0] ^= 0xFF;
    let err = segment
        .verify_manifest(&tampered_manifest)
        .expect_err("tampered chunk root must fail verification");
    assert!(
        matches!(err, ManifestError::ChunkRootMismatch),
        "expected chunk root mismatch, found {err:?}"
    );
}
#[test]
fn key_update_signature_mismatch_rejected() {
    let publisher_keys = KeyPair::try_random_with_algorithm(Algorithm::Ed25519)
        .expect("generate checked streaming publisher Ed25519 keypair");
    let viewer_keys = KeyPair::try_random().expect("generate checked streaming viewer keypair");
    let publisher_peer = streaming::make_peer(&publisher_keys, 27_100);
    let viewer_peer = streaming::make_peer(&viewer_keys, 27_101);
    let publisher_handle = streaming::streaming_handle();
    let viewer_handle = streaming::streaming_handle();
    let suite = EncryptionSuite::X25519ChaCha20Poly1305([0x11; 32]);
    let session_id = [0x22; 32];
    let update = publisher_handle
        .build_key_update(
            &viewer_peer,
            CapabilityRole::Publisher,
            &KeyUpdateSpec {
                session_id,
                suite: &suite,
                protocol_version: 1,
                key_counter: 1,
            },
            publisher_keys.private_key(),
        )
        .expect("publisher key update");
    let mut tampered_update = update.clone();
    tampered_update.signature[0] ^= 0x01;
    let result = viewer_handle
        .process_control_frame(&publisher_peer, &ControlFrame::KeyUpdate(tampered_update));
    assert!(
        matches!(result, Err(StreamingProcessError::Handshake(_))),
        "tampered signature must map to handshake error: {result:?}"
    );
    // Ensure the untampered update still succeeds to avoid false positives.
    viewer_handle
        .process_control_frame(&publisher_peer, &ControlFrame::KeyUpdate(update))
        .expect("valid key update must be accepted");
}
#[test]
fn bundled_manifest_requires_negotiated_flag() {
    let vector = streaming::baseline_test_vector();
    let mut manifest = vector.manifest.clone();
    manifest.entropy_mode = EntropyMode::RansBundled;
    let handle = streaming::bundled_streaming_handle(2);
    manifest.entropy_tables_checksum = Some(handle.bundle_tables_checksum());
    let (_publisher_keys, viewer_keys) = streaming::test_keypairs();
    let viewer_peer = streaming::make_peer(&viewer_keys, 27_201);
    let base_flags = streaming::BASE_CAPABILITIES;
    let negotiated = base_flags.remove(CapabilityFlags::FEATURE_ENTROPY_BUNDLED);
    let resolution = streaming::seed_viewer_negotiation(
        &handle,
        &viewer_peer,
        negotiated,
        vector.max_chunk_len(),
    );
    manifest.transport_capabilities_hash = resolution.capabilities_hash();
    let err = handle
        .validate_manifest_transport_capabilities(viewer_peer.id(), &manifest)
        .expect_err("bundled manifest must fail without negotiated entropy bit");
    assert!(matches!(
        err,
        StreamingProcessError::ManifestEntropyModeNotNegotiated { .. }
    ));
}
#[test]
fn bundled_manifest_checksum_mismatch_detected() {
    let vector = streaming::baseline_test_vector();
    let mut manifest = vector.manifest.clone();
    manifest.entropy_mode = EntropyMode::RansBundled;
    let handle = streaming::bundled_streaming_handle(3);
    manifest.entropy_tables_checksum = Some(handle.bundle_tables_checksum());
    let (_publisher_keys, viewer_keys) = streaming::test_keypairs();
    let viewer_peer = streaming::make_peer(&viewer_keys, 27_202);
    let negotiated = streaming::BASE_CAPABILITIES;
    let resolution = streaming::seed_viewer_negotiation(
        &handle,
        &viewer_peer,
        negotiated,
        vector.max_chunk_len(),
    );
    manifest.transport_capabilities_hash = resolution.capabilities_hash();
    manifest
        .entropy_tables_checksum
        .as_mut()
        .expect("checksum must be present")[0] ^= 0xFF;
    let err = handle
        .validate_manifest_transport_capabilities(viewer_peer.id(), &manifest)
        .expect_err("tampered checksum must be rejected");
    assert!(matches!(
        err,
        StreamingProcessError::ManifestEntropyTablesMismatch { .. }
    ));
}
#[test]
fn gpu_bundled_manifest_requires_negotiated_acceleration_flag() {
    if !BUNDLED_RANS_GPU_BUILD_AVAILABLE {
        eprintln!(
            "skipping gpu_bundled_manifest_requires_negotiated_acceleration_flag: GPU bundle acceleration unavailable"
        );
        return;
    }
    let vector = streaming::bundled_test_vector();
    let mut manifest = vector.manifest.clone();
    manifest.entropy_mode = EntropyMode::RansBundled;
    manifest.capabilities = manifest
        .capabilities
        .insert(CapabilityFlags::FEATURE_ENTROPY_BUNDLED)
        .insert(CapabilityFlags::FEATURE_BUNDLE_ACCEL_GPU);
    let handle = streaming::bundled_streaming_handle_with_accel(3, actual::BundleAcceleration::Gpu);
    manifest.entropy_tables_checksum = Some(handle.bundle_tables_checksum());
    let (_publisher_keys, viewer_keys) = streaming::test_keypairs();
    let viewer_peer = streaming::make_peer(&viewer_keys, 27_205);
    let negotiated =
        streaming::BASE_CAPABILITIES.insert(CapabilityFlags::FEATURE_BUNDLE_ACCEL_CPU_SIMD);
    let resolution = streaming::seed_viewer_negotiation(
        &handle,
        &viewer_peer,
        negotiated,
        vector.max_chunk_len(),
    );
    manifest.transport_capabilities_hash = resolution.capabilities_hash();
    let err = handle
        .validate_manifest_transport_capabilities(viewer_peer.id(), &manifest)
        .expect_err("GPU handle must reject viewers lacking the GPU acceleration bit");
    assert!(matches!(
        err,
        StreamingProcessError::ManifestAccelerationNotNegotiated { .. }
    ));
}
#[test]
fn bundled_vector_requires_entropy_negotiation() {
    let vector = streaming::bundled_test_vector();
    let handle = streaming::bundled_streaming_handle(4);
    let (_publisher_keys, viewer_keys) = streaming::test_keypairs();
    let viewer_peer = streaming::make_peer(&viewer_keys, 27_250);
    let negotiated = streaming::BASE_CAPABILITIES.remove(CapabilityFlags::FEATURE_ENTROPY_BUNDLED);
    streaming::seed_viewer_negotiation(&handle, &viewer_peer, negotiated, vector.max_chunk_len());
    let mut manifest = vector.manifest.clone();
    let err = handle
        .apply_manifest_transport_capabilities(viewer_peer.id(), &mut manifest)
        .expect_err("bundled manifest must reject viewers lacking negotiation");
    assert!(matches!(
        err,
        StreamingProcessError::ManifestEntropyModeNotNegotiated { .. }
    ));
}
#[test]
fn bundled_vector_applies_after_entropy_negotiation() {
    let vector = streaming::bundled_test_vector();
    let handle = streaming::bundled_streaming_handle(4);
    let (_publisher_keys, viewer_keys) = streaming::test_keypairs();
    let viewer_peer = streaming::make_peer(&viewer_keys, 27_251);
    let negotiated = streaming::BASE_CAPABILITIES;
    let resolution = streaming::seed_viewer_negotiation(
        &handle,
        &viewer_peer,
        negotiated,
        vector.max_chunk_len(),
    );
    let mut manifest = vector.manifest.clone();
    handle
        .apply_manifest_transport_capabilities(viewer_peer.id(), &mut manifest)
        .expect("bundled manifest should apply after negotiation");
    assert_eq!(
        manifest.transport_capabilities_hash,
        resolution.capabilities_hash(),
        "transport hash must reflect negotiated capabilities"
    );
    assert_eq!(
        manifest.entropy_tables_checksum,
        Some(handle.bundle_tables_checksum()),
        "bundled manifest must carry the configured table checksum"
    );
    assert!(
        manifest
            .capabilities
            .contains(CapabilityFlags::FEATURE_ENTROPY_BUNDLED),
        "bundled manifest must advertise the entropy capability"
    );
    handle
        .validate_manifest_transport_capabilities(viewer_peer.id(), &manifest)
        .expect("validated manifest must pass when flags match");
}
#[test]
fn cpu_accelerated_bundled_manifest_advertises_acceleration_bit() {
    let vector = streaming::bundled_test_vector();
    let handle =
        streaming::bundled_streaming_handle_with_accel(4, actual::BundleAcceleration::CpuSimd);
    let (_publisher_keys, viewer_keys) = streaming::test_keypairs();
    let viewer_peer = streaming::make_peer(&viewer_keys, 27_252);
    let negotiated =
        streaming::BASE_CAPABILITIES.insert(CapabilityFlags::FEATURE_BUNDLE_ACCEL_CPU_SIMD);
    let resolution = streaming::seed_viewer_negotiation(
        &handle,
        &viewer_peer,
        negotiated,
        vector.max_chunk_len(),
    );
    let mut manifest = vector.manifest.clone();
    handle
        .apply_manifest_transport_capabilities(viewer_peer.id(), &mut manifest)
        .expect("bundled manifest should apply after CPU acceleration negotiation");
    assert!(
        manifest
            .capabilities
            .contains(CapabilityFlags::FEATURE_ENTROPY_BUNDLED),
        "entropy capability bit must remain advertised for bundled manifests"
    );
    assert!(
        manifest
            .capabilities
            .contains(CapabilityFlags::FEATURE_BUNDLE_ACCEL_CPU_SIMD),
        "CPU-accelerated manifests must advertise FEATURE_BUNDLE_ACCEL_CPU_SIMD"
    );
    assert_eq!(
        manifest.transport_capabilities_hash,
        resolution.capabilities_hash(),
        "transport hash must reflect the negotiated CPU acceleration bits"
    );
}
#[test]
fn gpu_accelerated_bundled_manifest_advertises_acceleration_bit() {
    if !BUNDLED_RANS_GPU_BUILD_AVAILABLE {
        eprintln!(
            "skipping gpu_accelerated_bundled_manifest_advertises_acceleration_bit: GPU bundle acceleration unavailable"
        );
        return;
    }
    let vector = streaming::bundled_test_vector();
    let handle = streaming::bundled_streaming_handle_with_accel(4, actual::BundleAcceleration::Gpu);
    let (_publisher_keys, viewer_keys) = streaming::test_keypairs();
    let viewer_peer = streaming::make_peer(&viewer_keys, 27_253);
    let negotiated = streaming::BASE_CAPABILITIES.insert(CapabilityFlags::FEATURE_BUNDLE_ACCEL_GPU);
    let resolution = streaming::seed_viewer_negotiation(
        &handle,
        &viewer_peer,
        negotiated,
        vector.max_chunk_len(),
    );
    let mut manifest = vector.manifest.clone();
    handle
        .apply_manifest_transport_capabilities(viewer_peer.id(), &mut manifest)
        .expect("bundled manifest should apply after GPU acceleration negotiation");
    assert!(
        manifest
            .capabilities
            .contains(CapabilityFlags::FEATURE_ENTROPY_BUNDLED),
        "entropy capability bit must remain advertised for bundled manifests"
    );
    assert!(
        manifest
            .capabilities
            .contains(CapabilityFlags::FEATURE_BUNDLE_ACCEL_GPU),
        "GPU-accelerated manifests must advertise FEATURE_BUNDLE_ACCEL_GPU"
    );
    assert_eq!(
        manifest.transport_capabilities_hash,
        resolution.capabilities_hash(),
        "transport hash must reflect the negotiated GPU acceleration bits"
    );
}
