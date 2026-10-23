#[cfg(feature = "quic")]
#[test]
fn publisher_rejects_missing_bundle_acceleration_support() {
    use norito::streaming::{AudioCapability, CapabilityReport, Resolution};
    let mut handle = StreamingHandle::new();
    let mut codec = actual::StreamingCodec::from_defaults();
    codec.entropy_mode = EntropyMode::RansBundled;
    codec.bundle_width = 2;
    codec.bundle_accel = actual::BundleAcceleration::CpuSimd;
    codec.rans_tables_path = repo_rans_tables_path();
    handle
        .apply_codec_config(&codec)
        .expect("bundle tables should load");
    let report = CapabilityReport {
        stream_id: hash_with(0xDE),
        endpoint_role: CapabilityRole::Viewer,
        protocol_version: 1,
        max_resolution: Resolution::R720p,
        hdr_supported: false,
        capture_hdr: false,
        neural_bundles: Vec::new(),
        audio_caps: AudioCapability {
            sample_rates: vec![48_000],
            ambisonics: false,
            max_channels: 2,
        },
        feature_bits: CapabilityFlags::from_bits(CapabilityFlags::FEATURE_ENTROPY_BUNDLED),
        max_datagram_size: 900,
        dplpmtud: false,
    };
    let resolution = sample_resolution();
    let err = handle
        .build_capability_ack(&report, resolution)
        .expect_err("publisher should reject viewers lacking bundle acceleration support");
    assert!(matches!(
        err,
        StreamingProcessError::BundledAccelerationUnsupported { .. }
    ));
}
#[test]
fn snapshot_decode_tolerates_misaligned_plaintext() {
    let key_pair = checked_random_keypair();
    let peer = make_peer(&key_pair, 16001);
    let resolution = sample_resolution();
    let snapshot = StreamingSessionSnapshot {
        role: CapabilityRole::Viewer,
        session_id: hash_with(0x99),
        key_counter: 3,
        suite: EncryptionSuite::X25519ChaCha20Poly1305(hash_with(0x42)),
        kem_suite_id: 1, // ML-KEM-768 default for streaming snapshots.
        sts_root: hash_with(0x11),
        latest_gck: Some(vec![0xAA, 0xBB, 0xCC]),
        last_content_key_id: Some(7),
        last_content_key_valid_from: Some(1_702_000_000),
        cadence: Some(SessionCadenceSnapshot {
            started_at_ms: 1_701_000_000,
            total_payload_bytes: 4_096,
        }),
        transport_capabilities: Some(TransportCapabilityResolutionSnapshot::from(&resolution)),
        negotiated_capabilities: Some(CapabilityFlags::from_bits(0b101)),
        kyber_remote_public: Some(vec![0x55, 0x66, 0x77]),
        kyber_remote_fingerprint: Some(hash_with(0x22)),
        kyber_local_public: None,
        kyber_local_fingerprint: None,
    };
    let entry = StreamingSnapshotEntry {
        role: CapabilityRole::Viewer,
        peer: peer.id().clone(),
        snapshot,
    };
    let file = StreamingSnapshotFile {
        version: SNAPSHOT_VERSION,
        entries: vec![entry],
    };
    let plaintext = norito_core::to_bytes(&file).expect("canonical snapshot encode");
    let decoded = super::decode_snapshot_plaintext(&plaintext).expect("aligned decode succeeds");
    assert_eq!(decoded, file);
    let align = norito_core::archived_payload_align::<StreamingSnapshotFile>();
    assert!(align > 1, "expected archived snapshot alignment > 1");
    let mut envelope = vec![0u8; align - 1 + plaintext.len()];
    envelope[align - 1..align - 1 + plaintext.len()].copy_from_slice(&plaintext);
    let misaligned_slice = &envelope[align - 1..align - 1 + plaintext.len()];
    assert_eq!(misaligned_slice, plaintext.as_slice());
    assert_ne!(
        (misaligned_slice.as_ptr() as usize) % align,
        0,
        "test failed to craft a misaligned view"
    );
    let decoded =
        super::decode_snapshot_plaintext(misaligned_slice).expect("misaligned decode succeeds");
    assert_eq!(decoded, file);
}
#[test]
fn snapshot_file_bounds_reject_entry_count_and_variable_blobs() {
    let entry = sample_snapshot_entry(16_101);
    let oversized_entries = StreamingSnapshotFile {
        version: SNAPSHOT_VERSION,
        entries: vec![entry.clone(); SNAPSHOT_MAX_ENTRIES_V1 + 1],
    };
    let err = validate_snapshot_file_bounds(&oversized_entries)
        .expect_err("entry max plus one must be rejected");
    assert!(matches!(
        err,
        StreamingSnapshotError::ResourceLimitExceeded {
            resource: "entries",
            observed,
            limit,
        } if observed == (SNAPSHOT_MAX_ENTRIES_V1 + 1) as u64
            && limit == SNAPSHOT_MAX_ENTRIES_V1 as u64
    ));
    let mut oversized_key = entry;
    oversized_key.snapshot.kyber_remote_public =
        Some(vec![0x44; SNAPSHOT_MAX_KEM_PUBLIC_KEY_BYTES_V1 + 1]);
    let err = validate_snapshot_file_bounds(&StreamingSnapshotFile {
        version: SNAPSHOT_VERSION,
        entries: vec![oversized_key],
    })
    .expect_err("ML-KEM max plus one must be rejected");
    assert!(matches!(
        err,
        StreamingSnapshotError::ResourceLimitExceeded {
            resource: "remote ML-KEM public key bytes",
            observed,
            limit,
        } if observed == (SNAPSHOT_MAX_KEM_PUBLIC_KEY_BYTES_V1 + 1) as u64
            && limit == SNAPSHOT_MAX_KEM_PUBLIC_KEY_BYTES_V1 as u64
    ));
}
#[test]
fn snapshot_load_falls_back_from_corrupt_temp_without_buffering_both_candidates() {
    let dir = tempdir().expect("create temp dir");
    let path = dir.path().join("sessions.norito");
    let tmp_path = snapshot_temp_path(&path);
    let material = StreamingKeyMaterial::new(checked_random_ed25519_keypair())
        .expect("streaming key material");
    let key = snapshot_session_key(&material);
    let encryptor = SymmetricEncryptor::<ChaCha20Poly1305>::new_from_session_key(&key)
        .expect("snapshot encryptor");
    let plaintext = norito_core::to_bytes(&StreamingSnapshotFile {
        version: SNAPSHOT_VERSION,
        entries: Vec::new(),
    })
    .expect("encode empty snapshot");
    let main_bytes = encryptor
        .encrypt_easy(SNAPSHOT_AAD, plaintext.as_slice())
        .expect("encrypt main snapshot");
    fs::write(&path, &main_bytes).expect("write main snapshot");
    fs::write(&tmp_path, [0xFF; 8]).expect("write corrupt temp snapshot");
    let handle = StreamingHandle::new()
        .with_snapshot_encryption_key(&key)
        .expect("configure snapshot encryption key");
    handle
        .load_snapshots_from_path(&path)
        .expect("valid main snapshot must survive a corrupt temp candidate");
    assert_eq!(fs::read(&path).expect("read main snapshot"), main_bytes);
    assert!(tmp_path.exists(), "corrupt temp candidate is not promoted");
}
#[test]
fn snapshot_persist_roundtrip() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let snapshot_path = dir.path().join("sessions.norito");
    let publisher_keys = checked_random_ed25519_keypair();
    let viewer_keys = checked_random_keypair();
    let publisher_peer = make_peer(&publisher_keys, 17001);
    let viewer_peer = make_peer(&viewer_keys, 17002);
    let session_id = hash_with(0x55);
    let suite = EncryptionSuite::X25519ChaCha20Poly1305(hash_with(0x66));
    let resolution = sample_resolution();
    let material = StreamingKeyMaterial::new(publisher_keys.clone())
        .expect("publisher material requires ed25519");
    let publisher_key = snapshot_session_key(&material);
    let publisher_handle = StreamingHandle::with_key_material(material.clone())
        .with_snapshot_path(snapshot_path.clone())
        .with_snapshot_encryption_key(&publisher_key)
        .expect("configure snapshot encryption key");
    let viewer_key = snapshot_session_key(&material);
    let viewer_handle = StreamingHandle::new()
        .with_snapshot_encryption_key(&viewer_key)
        .expect("configure viewer snapshot encryption key");
    let publisher_update = publisher_handle
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
    let publisher_frame = ControlFrame::KeyUpdate(publisher_update.clone());
    viewer_handle
        .process_control_frame(&publisher_peer, &publisher_frame)
        .expect("viewer processes key update");
    let viewer_update = viewer_handle
        .build_key_update(
            &publisher_peer,
            CapabilityRole::Viewer,
            &KeyUpdateSpec {
                session_id,
                suite: &suite,
                protocol_version: 1,
                key_counter: 2,
            },
            viewer_keys.private_key(),
        )
        .expect("viewer key update");
    let viewer_frame = ControlFrame::KeyUpdate(viewer_update);
    publisher_handle
        .process_control_frame(&viewer_peer, &viewer_frame)
        .expect("publisher processes viewer key update");
    publisher_handle
        .record_transport_capabilities(&viewer_peer, CapabilityRole::Publisher, resolution)
        .expect("publisher records capabilities");
    viewer_handle
        .record_transport_capabilities(&publisher_peer, CapabilityRole::Viewer, resolution)
        .expect("viewer records capabilities");
    let negotiated = CapabilityFlags::from_bits(CapabilityFlags::FEATURE_ENTROPY_BUNDLED | 0b101);
    publisher_handle
        .record_negotiated_capabilities(&viewer_peer, CapabilityRole::Publisher, negotiated)
        .expect("publisher records features");
    viewer_handle
        .record_negotiated_capabilities(&publisher_peer, CapabilityRole::Viewer, negotiated)
        .expect("viewer records features");
    publisher_handle
        .persist_snapshots()
        .expect("persist streaming snapshots");
    assert!(snapshot_path.exists(), "snapshot file should exist");
    let restored_key = snapshot_session_key(&material);
    let restored_handle = StreamingHandle::with_key_material(material)
        .with_snapshot_path(snapshot_path.clone())
        .with_snapshot_encryption_key(&restored_key)
        .expect("configure restored snapshot encryption key");
    restored_handle
        .load_snapshots_from_path(&snapshot_path)
        .expect("load streaming snapshots");
    assert!(
        restored_handle.transport_keys(viewer_peer.id()).is_some(),
        "restored handle should retain transport keys"
    );
    assert_eq!(
        restored_handle.transport_capabilities_hash(viewer_peer.id()),
        Some(resolution.capabilities_hash()),
        "restored handle retains transport capability hash"
    );
}
#[test]
fn snapshot_load_promotes_temp_file() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let snapshot_path = dir.path().join("sessions.norito");
    let publisher_keys = checked_random_ed25519_keypair();
    let viewer_keys = checked_random_keypair();
    let publisher_peer = make_peer(&publisher_keys, 18001);
    let viewer_peer = make_peer(&viewer_keys, 18002);
    let session_id = hash_with(0x5A);
    let suite = EncryptionSuite::X25519ChaCha20Poly1305(hash_with(0x6B));
    let resolution = sample_resolution();
    let material = StreamingKeyMaterial::new(publisher_keys.clone())
        .expect("publisher material requires ed25519");
    let publisher_key = snapshot_session_key(&material);
    let publisher_handle = StreamingHandle::with_key_material(material.clone())
        .with_snapshot_path(snapshot_path.clone())
        .with_snapshot_encryption_key(&publisher_key)
        .expect("configure snapshot encryption key");
    let viewer_key = snapshot_session_key(&material);
    let viewer_handle = StreamingHandle::new()
        .with_snapshot_encryption_key(&viewer_key)
        .expect("configure viewer snapshot encryption key");
    let publisher_update = publisher_handle
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
    let publisher_frame = ControlFrame::KeyUpdate(publisher_update);
    viewer_handle
        .process_control_frame(&publisher_peer, &publisher_frame)
        .expect("viewer processes key update");
    let viewer_update = viewer_handle
        .build_key_update(
            &publisher_peer,
            CapabilityRole::Viewer,
            &KeyUpdateSpec {
                session_id,
                suite: &suite,
                protocol_version: 1,
                key_counter: 2,
            },
            viewer_keys.private_key(),
        )
        .expect("viewer key update");
    let viewer_frame = ControlFrame::KeyUpdate(viewer_update);
    publisher_handle
        .process_control_frame(&viewer_peer, &viewer_frame)
        .expect("publisher processes viewer key update");
    publisher_handle
        .record_transport_capabilities(&viewer_peer, CapabilityRole::Publisher, resolution)
        .expect("publisher records capabilities");
    viewer_handle
        .record_transport_capabilities(&publisher_peer, CapabilityRole::Viewer, resolution)
        .expect("viewer records capabilities");
    let negotiated = CapabilityFlags::from_bits(CapabilityFlags::FEATURE_ENTROPY_BUNDLED | 0b101);
    publisher_handle
        .record_negotiated_capabilities(&viewer_peer, CapabilityRole::Publisher, negotiated)
        .expect("publisher records features");
    viewer_handle
        .record_negotiated_capabilities(&publisher_peer, CapabilityRole::Viewer, negotiated)
        .expect("viewer records features");
    publisher_handle
        .persist_snapshots()
        .expect("persist streaming snapshots");
    let tmp_path = snapshot_temp_path(&snapshot_path);
    fs::rename(&snapshot_path, &tmp_path).expect("move snapshot to temp");
    let restored_key = snapshot_session_key(&material);
    let restored_handle = StreamingHandle::with_key_material(material)
        .with_snapshot_path(snapshot_path.clone())
        .with_snapshot_encryption_key(&restored_key)
        .expect("configure restored snapshot encryption key");
    restored_handle
        .load_snapshots_from_path(&snapshot_path)
        .expect("load streaming snapshots from temp");
    assert!(snapshot_path.exists(), "snapshot file should be promoted");
    assert!(!tmp_path.exists(), "temp snapshot file should be removed");
    assert!(
        restored_handle.transport_keys(viewer_peer.id()).is_some(),
        "restored handle should retain transport keys"
    );
}
#[test]
fn snapshot_session_key_derivation_is_deterministic() {
    let key_pair = checked_random_ed25519_keypair();
    let material = StreamingKeyMaterial::new(key_pair.clone()).expect("material created");
    let first = snapshot_session_key(&material);
    let second = snapshot_session_key(&material);
    assert_eq!(first.payload(), second.payload());
    let other_pair = checked_random_ed25519_keypair();
    let other_material = StreamingKeyMaterial::new(other_pair).expect("material created");
    let other = snapshot_session_key(&other_material);
    assert_ne!(first.payload(), other.payload());
}
#[test]
fn apply_crypto_capabilities_reports_actual_backend_independent_of_chain_admission() {
    let mut handle = StreamingHandle::new().with_capabilities(CapabilityFlags::from_bits(0b1));
    handle.apply_crypto_capabilities();
    assert_eq!(
        handle
            .capabilities()
            .contains(CapabilityFlags::FEATURE_SM_TRANSACTIONS),
        Algorithm::Sm2
            .require_implementation(iroha_crypto::CryptoOperation::VerifySignature)
            .is_ok(),
    );
}
