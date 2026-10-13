#[test]
fn pipeline_sidecar_roundtrip() {
    let (_temp_dir, _config, kura, block_hash, sidecar) = default_pipeline_sidecar_fixture();
    kura.write_pipeline_metadata(&sidecar);
    let got = kura.read_pipeline_metadata(1).expect("sidecar exists");
    assert_eq!(got.height, 1);
    assert_eq!(got.block_hash, block_hash);
    assert_eq!(got.dag.key_count, 0);
    assert_eq!(got.format_label(), "pipeline.recovery");
}
#[test]
fn fast_pipeline_read_leaves_recovery_artifacts_byte_exact() {
    let (_temp_dir, mut config, kura, block_hash, sidecar) = default_pipeline_sidecar_fixture();
    kura.write_pipeline_metadata(&sidecar);

    let mut pipeline_dir = kura.store_dir().expect("pipeline store dir");
    pipeline_dir.push(PIPELINE_DIR_NAME);
    let data_path = pipeline_dir.join(PIPELINE_SIDECARS_DATA_FILE);
    let index_path = pipeline_dir.join(PIPELINE_SIDECARS_INDEX_FILE);
    let temp_data_path = data_path.with_extension("norito.tmp");
    let temp_index_path = index_path.with_extension("index.tmp");
    let staged = PipelineRecoverySidecar::new(
        1,
        block_hash,
        PipelineDagSnapshot {
            fingerprint: [0xA5; 32],
            key_count: 7,
        },
        Vec::new(),
    )
    .encode_framed()
    .expect("encode staged recovery sidecar");
    fs::write(&temp_data_path, &staged).expect("write staged recovery payload");
    let mut staged_index = SidecarIndexLayout::base_header(1).to_vec();
    staged_index.extend_from_slice(
        &SidecarIndexEntry {
            offset: 0,
            len: u64::try_from(staged.len()).unwrap(),
        }
        .to_bytes(),
    );
    fs::write(&temp_index_path, &staged_index).expect("write staged recovery index");

    let paths = [&data_path, &index_path, &temp_data_path, &temp_index_path];
    let before = paths
        .iter()
        .map(fs::read)
        .collect::<std::io::Result<Vec<_>>>()
        .expect("snapshot pipeline files before Fast read");
    drop(kura);

    config.init_mode = InitMode::Fast;
    let (fast, _) =
        Kura::open_test_kura_with_configured_lane_config(&config, &RuntimeLaneConfig::default())
            .expect("open emergency Fast Kura");
    let got = fast
        .read_pipeline_metadata(1)
        .expect("Fast may read the stable sidecar without recovery");
    assert_eq!(got.dag.fingerprint, sidecar.dag.fingerprint);
    let after = paths
        .iter()
        .map(fs::read)
        .collect::<std::io::Result<Vec<_>>>()
        .expect("snapshot pipeline files after Fast read");
    assert_eq!(
        after, before,
        "Fast read must not promote or rewrite recovery files"
    );
}
#[test]
fn framed_pipeline_sidecar_boundaries_are_canonical_and_ambient_independent() {
    let block_hash = HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
        b"canonical framed sidecar boundary",
    ));
    let pipeline = PipelineRecoverySidecar::new(
        1,
        block_hash,
        PipelineDagSnapshot {
            fingerprint: [0xA5; 32],
            key_count: 1,
        },
        Vec::new(),
    );
    let canonical_pipeline =
        norito::encode_canonical(&pipeline).expect("encode canonical pipeline sidecar");
    assert_eq!(
        pipeline.encode_framed().expect("frame pipeline sidecar"),
        canonical_pipeline
    );
    let alternate_flags =
        norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
    let alternate_pipeline = {
        let _alternate = norito::core::DecodeFlagsGuard::enter(alternate_flags);
        norito::to_bytes(&pipeline).expect("encode alternate-layout pipeline sidecar")
    };
    assert_ne!(alternate_pipeline, canonical_pipeline);
    assert!(
        norito::decode_canonical::<PipelineRecoverySidecar>(&alternate_pipeline).is_err(),
        "durable pipeline sidecars must reject alternate layouts"
    );
    let _ambient = norito::core::DecodeFlagsGuard::enter(alternate_flags);
    assert_eq!(
        pipeline
            .encode_framed()
            .expect("frame pipeline sidecar under alternate ambient layout"),
        canonical_pipeline
    );
}
#[test]
fn bound_progress_intent_identity_is_canonical_and_ambient_independent() {
    let payload = b"bound progress canonical payload";
    let mut new_index_bytes = SidecarIndexLayout::base_header(1).to_vec();
    new_index_bytes.extend_from_slice(
        &SidecarIndexEntry {
            offset: 0,
            len: u64::try_from(payload.len()).expect("payload length fits u64"),
        }
        .to_bytes(),
    );
    let intent = BoundProgressAppendIntentV1 {
        version: BOUND_PROGRESS_APPEND_INTENT_VERSION,
        namespace_components: vec!["blocks".to_owned(), "lane".to_owned()],
        data_file: "progress.data".to_owned(),
        index_file: "progress.index".to_owned(),
        height: 1,
        pair_was_present: false,
        old_data_len: 0,
        new_data_len: u64::try_from(payload.len()).expect("payload length fits u64"),
        payload_hash: BoundProgressAppendIntentV1::payload_digest(payload),
        old_index_len: 0,
        new_index_len: u64::try_from(new_index_bytes.len()).unwrap(),
        index_write_offset: 0,
        old_index_bytes: Vec::new(),
        new_index_bytes,
        integrity_hash: Hash::prehashed([0; Hash::LENGTH]),
    }
    .seal();
    let canonical = norito::encode_canonical(&intent).expect("encode canonical progress intent");
    let alternate_flags =
        norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
    let alternate = {
        let _alternate = norito::core::DecodeFlagsGuard::enter(alternate_flags);
        norito::to_bytes(&intent).expect("encode alternate-layout progress intent")
    };
    assert_ne!(alternate, canonical);
    assert!(
        norito::decode_canonical::<BoundProgressAppendIntentV1>(&alternate).is_err(),
        "durable progress intents must reject alternate layouts"
    );
    let integrity_hash = intent.integrity_hash;
    let _ambient = norito::core::DecodeFlagsGuard::enter(alternate_flags);
    assert_eq!(
        intent.computed_integrity_hash(),
        Some(integrity_hash),
        "intent identity must ignore ambient layout"
    );
    assert_eq!(
        norito::encode_canonical(&intent).expect("encode intent under alternate ambient layout"),
        canonical
    );
}
#[test]
fn pipeline_sidecar_exact_candidate_read_preserves_canonical_authority() {
    let (_temp_dir, _config, kura) = kura_root_fixture(BLOCKS_IN_MEMORY);
    let mut blocks = NativeBlocks::new();
    let candidate = blocks.next();
    let height = candidate.header().height().get();
    let block_hash = candidate.hash();
    let sidecar = PipelineRecoverySidecar::new(
        height,
        block_hash,
        PipelineDagSnapshot {
            fingerprint: [0xA5; 32],
            key_count: 1,
        },
        Vec::new(),
    );
    kura.write_pipeline_metadata(&sidecar);
    let exact = kura
        .read_pipeline_metadata_for_block(height, block_hash)
        .expect("an exact candidate may reuse its pre-canonical sidecar");
    assert_eq!(exact.block_hash, block_hash);
    let competing_hash = HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(
        b"competing pipeline sidecar candidate",
    ));
    assert!(
        kura.read_pipeline_metadata_for_block(height, competing_hash)
            .is_none(),
        "a competing candidate must not reuse the sidecar"
    );
    assert!(
        kura.read_pipeline_metadata(height).is_none(),
        "an exact candidate read must not confer canonical authority"
    );
    kura.store_block(candidate)
        .expect("store the exact candidate as canonical");
    let canonical = kura
        .read_pipeline_metadata(height)
        .expect("the sidecar becomes canonically readable only after block storage");
    assert_eq!(canonical.block_hash, block_hash);
}
#[test]
fn pipeline_sidecar_canonical_boundary_rejects_missing_current_fields() {
    #[derive(norito::NoritoSchema)]
    #[norito_schema(
        name = "iroha_core::kura::tests::pipeline_sidecar_canonical_boundary_rejects_missing_current_fields::PreReleasePipelineRecoverySidecar"
    )]
    #[derive(Debug, Clone, Encode, Decode)]
    struct PreReleasePipelineRecoverySidecar {
        format: PipelineRecoveryFormat,
        height: u64,
        block_hash: HashOf<BlockHeader>,
        dag: PipelineDagSnapshot,
        txs: Vec<PipelineTxSnapshot>,
        #[norito(default)]
        proofs: Vec<PipelineProofSnapshot>,
    }
    let block_hash =
        HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(b"pre-release-pipeline-sidecar"));
    let pre_release = PreReleasePipelineRecoverySidecar {
        format: PipelineRecoveryFormat::Current,
        height: 1,
        block_hash,
        dag: PipelineDagSnapshot {
            fingerprint: [0u8; 32],
            key_count: 0,
        },
        txs: Vec::new(),
        proofs: Vec::new(),
    };
    let current = PipelineRecoverySidecar::new(
        pre_release.height,
        pre_release.block_hash,
        pre_release.dag,
        pre_release.txs.clone(),
    );
    let bytes = frame_kura_test_payload(&current, &pre_release);
    assert_kura_test_payload_rejected::<PipelineRecoverySidecar>(&bytes);
    assert!(
        norito::decode_from_bytes::<PipelineRecoverySidecar>(&bytes).is_err(),
        "first-release decoding must require every current sidecar field"
    );
    assert!(
        norito::decode_canonical::<PipelineRecoverySidecar>(&bytes).is_err(),
        "the durable V1 boundary must reject a byte layout missing current fields"
    );
}
#[test]
fn pipeline_tx_snapshot_compact_omits_keys_and_preserves_counts() {
    let hash = HashOf::<TransactionEntrypoint>::from_untyped_unchecked(Hash::new(
        b"compact-pipeline-tx-snapshot",
    ));
    let snapshot = PipelineTxSnapshot::compact(hash, usize::MAX, 7);
    assert!(snapshot.reads.is_empty());
    assert!(snapshot.writes.is_empty());
    assert_eq!(snapshot.read_count(), u32::MAX);
    assert_eq!(snapshot.write_count(), 7);
}
#[test]
fn pipeline_tx_snapshot_counts_are_explicit_not_inferred_from_samples() {
    let hash = HashOf::<TransactionEntrypoint>::from_untyped_unchecked(Hash::new(
        b"explicit-pipeline-tx-snapshot",
    ));
    let snapshot = PipelineTxSnapshot {
        hash,
        reads: vec!["state:alpha".to_owned(), "state:beta".to_owned()],
        writes: vec!["state:gamma".to_owned()],
        read_count: 0,
        write_count: 0,
    };
    assert_eq!(snapshot.read_count(), 0);
    assert_eq!(snapshot.write_count(), 0);
}
#[test]
fn pipeline_tx_snapshot_rejects_pre_release_bytes_without_counts() {
    #[derive(norito::NoritoSchema)]
    #[norito_schema(
        name = "iroha_core::kura::tests::pipeline_tx_snapshot_rejects_pre_release_bytes_without_counts::PreReleasePipelineTxSnapshot"
    )]
    #[derive(Debug, Clone, Encode, Decode)]
    struct PreReleasePipelineTxSnapshot {
        hash: HashOf<TransactionEntrypoint>,
        reads: Vec<String>,
        writes: Vec<String>,
    }
    let pre_release = PreReleasePipelineTxSnapshot {
        hash: HashOf::<TransactionEntrypoint>::from_untyped_unchecked(Hash::new(
            b"pre-release-pipeline-tx-snapshot",
        )),
        reads: vec!["state:alpha".to_owned()],
        writes: vec!["state:beta".to_owned()],
    };
    let current = PipelineTxSnapshot {
        hash: pre_release.hash,
        reads: pre_release.reads.clone(),
        writes: pre_release.writes.clone(),
        read_count: 1,
        write_count: 1,
    };
    let bytes = frame_kura_test_payload(&current, &pre_release);
    assert_kura_test_payload_rejected::<PipelineTxSnapshot>(&bytes);
    assert!(
        norito::decode_from_bytes::<PipelineTxSnapshot>(&bytes).is_err(),
        "V1 decoding must require explicit read and write counts"
    );
}
#[test]
fn pipeline_sidecar_enqueue_flushes() {
    let (_temp_dir, _config, kura, block_hash, sidecar) = default_pipeline_sidecar_fixture();
    assert_eq!(
        kura.enqueue_pipeline_metadata(sidecar),
        PipelineSidecarEnqueueResult::Enqueued { queue_depth: 1 }
    );
    assert!(kura.read_pipeline_metadata(1).is_none());
    kura.flush_pipeline_sidecars();
    let got = kura.read_pipeline_metadata(1).expect("sidecar exists");
    assert_eq!(got.height, 1);
    assert_eq!(got.block_hash, block_hash);
}
#[test]
fn sidecar_queues_reject_unauthorized_output_and_flush_without_draining() {
    let (_temp_dir, _config, kura, block_hash, sidecar) = default_pipeline_sidecar_fixture();

    kura.canonical_storage_poisoned
        .store(true, Ordering::Release);
    assert_eq!(
        kura.enqueue_pipeline_metadata(sidecar.clone()),
        PipelineSidecarEnqueueResult::RejectedUnauthorized
    );
    assert_eq!(
        kura.enqueue_fastpq_proof_snapshot(sample_fastpq_snapshot(1, block_hash, 8)),
        FastpqProofEnqueueResult::RejectedUnauthorized
    );
    assert!(kura.pipeline_sidecar_queue.lock().is_empty());
    assert!(kura.fastpq_proof_queue.lock().is_empty());

    kura.canonical_storage_poisoned
        .store(false, Ordering::Release);
    assert_eq!(
        kura.enqueue_pipeline_metadata(sidecar),
        PipelineSidecarEnqueueResult::Enqueued { queue_depth: 1 }
    );
    assert_eq!(
        kura.enqueue_fastpq_proof_snapshot(sample_fastpq_snapshot(1, block_hash, 8)),
        FastpqProofEnqueueResult::Enqueued { queue_depth: 1 }
    );
    kura.canonical_storage_poisoned
        .store(true, Ordering::Release);
    assert_eq!(kura.flush_pipeline_sidecars(), 0);
    assert_eq!(kura.flush_fastpq_proof_snapshots(), 0);
    assert_eq!(kura.pipeline_sidecar_queue.lock().len(), 1);
    assert_eq!(kura.fastpq_proof_queue.lock().len(), 1);
}
#[test]
fn pipeline_sidecar_enqueue_coalesces_writer_notifications() {
    let kura = Kura::blank_kura_for_testing();
    let first_hash =
        HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(b"pipeline-sidecar-first"));
    let second_hash =
        HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(b"pipeline-sidecar-second"));
    let snapshot = PipelineDagSnapshot {
        fingerprint: [0u8; 32],
        key_count: 0,
    };
    let first = PipelineRecoverySidecar::new(1, first_hash, snapshot.clone(), Vec::new());
    let second = PipelineRecoverySidecar::new(2, second_hash, snapshot, Vec::new());
    assert_eq!(
        kura.enqueue_pipeline_metadata(first),
        PipelineSidecarEnqueueResult::Enqueued { queue_depth: 1 }
    );
    assert_eq!(
        kura.enqueue_pipeline_metadata(second),
        PipelineSidecarEnqueueResult::Enqueued { queue_depth: 2 }
    );
    assert_eq!(kura.pipeline_sidecar_queue.lock().len(), 2);
    let rx_guard = kura.block_notify_rx.lock();
    let rx = rx_guard
        .as_ref()
        .expect("writer receiver should be present");
    assert_eq!(rx.try_recv(), Ok(BlockNotify::NewBlock));
    assert!(matches!(rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
}
#[test]
fn pipeline_sidecar_enqueue_rejects_queue_overflow() {
    let kura = Kura::blank_kura_for_testing();
    kura.set_pipeline_sidecar_queue_cap_for_testing(1);
    let first_hash =
        HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(b"pipeline-sidecar-cap-first"));
    let second_hash =
        HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(b"pipeline-sidecar-cap-second"));
    let snapshot = PipelineDagSnapshot {
        fingerprint: [0u8; 32],
        key_count: 0,
    };
    let first = PipelineRecoverySidecar::new(1, first_hash, snapshot.clone(), Vec::new());
    let second = PipelineRecoverySidecar::new(2, second_hash, snapshot, Vec::new());
    assert_eq!(
        kura.enqueue_pipeline_metadata(first),
        PipelineSidecarEnqueueResult::Enqueued { queue_depth: 1 }
    );
    assert_eq!(
        kura.enqueue_pipeline_metadata(second),
        PipelineSidecarEnqueueResult::RejectedQueueFull { cap: 1 }
    );
    let queue = kura.pipeline_sidecar_queue.lock();
    assert_eq!(queue.len(), 1);
    assert_eq!(queue[0].height, 1);
}
fn sample_fastpq_snapshot(
    height: u64,
    block_hash: HashOf<BlockHeader>,
    proof_len: usize,
) -> FastpqProofSnapshot {
    use iroha_data_model::fastpq::{
        FastpqArtifactIdentityDescriptionV1, FastpqCommitmentDescriptionV1,
        FastpqOrderedCompactAirCommitmentsV1, FastpqProofKindV1,
    };
    let proof = vec![0x7a; proof_len];
    FastpqProofSnapshot {
        height,
        block_hash,
        entry_hash: Hash::new(format!("fastpq-entry-{height}-{proof_len}").into_bytes()),
        batch_index: 0,
        transition_count: 0,
        public_inputs: iroha_data_model::fastpq::FastpqPublicInputs {
            dsid: [0; 16],
            slot: 0,
            old_root: [0; 32],
            new_root: [0; 32],
            perm_root: [0; 32],
            tx_set_hash: [0; 32],
        },
        ordering_hash: [0; 32],
        artifact_identity: FastpqArtifactIdentityDescriptionV1 {
            proof_kind: FastpqProofKindV1::OrdinaryCompact,
            profile_id: fastpq_prover::offline_compact::quantity_profile_id(),
            public_statement_digest: Hash::new(b"snapshot public statement").into(),
            artifact_digest: Hash::new(&proof).into(),
            inner_bundle_digest: Hash::new(b"snapshot inner bundle").into(),
            artifact_bytes: proof_len as u64,
            commitments: FastpqCommitmentDescriptionV1::OrderedCompactAir(
                FastpqOrderedCompactAirCommitmentsV1 {
                    segment_count: 1,
                    segment_air_row_roots: vec![
                        iroha_data_model::fastpq::FastpqCommitmentV1::from_bytes([0x41; 32]),
                    ],
                },
            ),
        },
    }
}
#[test]
fn fastpq_snapshot_from_statement_retains_identity_without_statement_payload() {
    let block_hash =
        HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(b"canonical snapshot constructor"));
    let expected = sample_fastpq_snapshot(1, block_hash, 128 * 1024);
    let statement = iroha_data_model::fastpq::FastpqPublicTransferStatementV1 {
        public_inputs: expected.public_inputs,
        ordering_hash: [0x39; 32],
        transitions: vec![iroha_data_model::fastpq::FastpqStateTransition {
            key: b"source-key".to_vec(),
            pre_value: vec![1; 32 * 1024],
            post_value: vec![2; 32 * 1024],
            operation: iroha_data_model::fastpq::FastpqOperationKind::Transfer,
        }],
        transcripts: Vec::new(),
    };
    let actual = FastpqProofSnapshot::from_statement(
        1,
        block_hash,
        expected.entry_hash,
        0,
        &statement,
        expected.artifact_identity.clone(),
    );
    assert_eq!(actual.public_inputs, statement.public_inputs);
    assert_eq!(actual.ordering_hash, statement.ordering_hash);
    assert_eq!(actual.transition_count, 1);
    assert_eq!(actual.artifact_identity, expected.artifact_identity);
    assert!(norito::encode_canonical(&actual).unwrap().len() < 2048);
    assert!(actual.same_attachment(&expected));
    let mut other = expected;
    other.artifact_identity.artifact_digest[0] ^= 1;
    assert!(!actual.same_attachment(&other));
}
#[test]
fn consensus_sidecar_enqueues_do_not_wait_for_unrelated_prune_lock_holder() {
    let kura = Kura::blank_kura_for_testing();
    let block_hash =
        HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(b"non-prune writer lock"));
    let pipeline = PipelineRecoverySidecar::new(
        1,
        block_hash,
        PipelineDagSnapshot {
            fingerprint: [0x41; 32],
            key_count: 1,
        },
        Vec::new(),
    );
    let fastpq = sample_fastpq_snapshot(1, block_hash, 8);
    // The writer loop holds this lock while flushing sidecars and enforcing the storage
    // budget. Consensus enqueues must remain memory-only and must not wait for that I/O.
    let prune_guard = kura.prune_lock.lock();
    assert!(!kura.prune_in_progress.load(Ordering::Acquire));
    let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
    let (result_tx, result_rx) = std::sync::mpsc::sync_channel(1);
    let enqueue_kura = Arc::clone(&kura);
    let enqueuer = thread::spawn(move || {
        started_tx.send(()).expect("announce enqueue start");
        let pipeline_result = enqueue_kura.enqueue_pipeline_metadata(pipeline);
        let fastpq_result = enqueue_kura.enqueue_fastpq_proof_snapshot(fastpq);
        result_tx
            .send((pipeline_result, fastpq_result))
            .expect("report enqueue results");
    });
    started_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("enqueue worker started");
    let results = result_rx.recv_timeout(Duration::from_secs(2));
    drop(prune_guard);
    enqueuer.join().expect("enqueue worker");
    let (pipeline_result, fastpq_result) =
        results.expect("memory-only enqueues must not wait behind prune_lock");
    assert_eq!(
        pipeline_result,
        PipelineSidecarEnqueueResult::Enqueued { queue_depth: 1 }
    );
    assert_eq!(
        fastpq_result,
        FastpqProofEnqueueResult::Enqueued { queue_depth: 1 }
    );
    assert_eq!(kura.pipeline_sidecar_queue.lock().len(), 1);
    assert_eq!(kura.fastpq_proof_queue.lock().len(), 1);
}
#[test]
fn fastpq_snapshot_json_identity_is_canonical_under_every_ambient_layout() {
    use base64::Engine as _;
    let block_hash =
        HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(b"codec-only snapshot"));
    let snapshot = sample_fastpq_snapshot(1, block_hash, 8);
    let canonical = norito::encode_canonical(&snapshot.artifact_identity).unwrap();
    let expected_base64 = base64::engine::general_purpose::STANDARD.encode(&canonical);
    let expected = snapshot.to_json_value();
    for flags in
        (u8::MIN..=u8::MAX).filter(|&flags| norito::core::validate_header_flags(flags).is_ok())
    {
        let _ambient = norito::core::DecodeFlagsGuard::enter(flags);
        let json = snapshot.to_json_value();
        assert_eq!(json, expected);
        assert_eq!(
            json.get("artifact_identity")
                .and_then(|value| value.as_str()),
            Some(expected_base64.as_str())
        );
        assert_eq!(norito::core::effective_decode_flags(), Some(flags));
    }
    assert!(expected.get("batch").is_none());
    assert!(expected.get("proof").is_none());
    assert!(expected.get("trace_commitment").is_none());
}
#[test]
fn fastpq_proof_snapshot_merges_into_pipeline_sidecar() {
    let (_temp_dir, _config, kura, block_hash, sidecar) = default_pipeline_sidecar_fixture();
    kura.write_pipeline_metadata(&sidecar);
    let mut snapshot = sample_fastpq_snapshot(1, block_hash, 12);
    snapshot.entry_hash = Hash::prehashed([0x11; 32]);
    assert!(matches!(
        kura.enqueue_fastpq_proof_snapshot(snapshot.clone()),
        FastpqProofEnqueueResult::Enqueued { .. }
    ));
    assert_eq!(kura.flush_fastpq_proof_snapshots(), 1);
    let got = kura.read_pipeline_metadata(1).expect("sidecar exists");
    let compact = snapshot.clone();
    assert_eq!(got.fastpq_proofs, vec![compact.clone()]);
    assert_eq!(
        got.fastpq_proofs[0].artifact_identity,
        snapshot.artifact_identity
    );
    assert_eq!(kura.fastpq_proofs_for_block(1), vec![compact]);
    let duplicate = got.fastpq_proofs[0].clone();
    assert!(matches!(
        kura.enqueue_fastpq_proof_snapshot(duplicate),
        FastpqProofEnqueueResult::Enqueued { .. }
    ));
    assert_eq!(kura.flush_fastpq_proof_snapshots(), 1);
    let got = kura.read_pipeline_metadata(1).expect("sidecar exists");
    assert_eq!(got.fastpq_proofs.len(), 1);
}
#[test]
fn fastpq_proof_snapshot_persists_compact_metadata_only() {
    let (_temp_dir, _config, kura) = unwrapped_kura_fixture();
    let block_hash = store_dummy_blocks(&kura, 1)[0];
    kura.write_pipeline_metadata(&PipelineRecoverySidecar::new(
        1,
        block_hash,
        PipelineDagSnapshot {
            fingerprint: [0u8; 32],
            key_count: 0,
        },
        Vec::new(),
    ));
    let mut snapshot = sample_fastpq_snapshot(1, block_hash, 128 * 1024);
    snapshot.transition_count = 1;
    assert!(matches!(
        kura.enqueue_fastpq_proof_snapshot(snapshot.clone()),
        FastpqProofEnqueueResult::Enqueued { .. }
    ));
    assert_eq!(kura.flush_fastpq_proof_snapshots(), 1);
    let got = kura.read_pipeline_metadata(1).expect("sidecar exists");
    let persisted = got.fastpq_proofs.first().expect("proof summary persisted");
    assert_eq!(persisted.artifact_identity, snapshot.artifact_identity);
    assert_eq!(persisted.transition_count, 1);
    assert_eq!(persisted.public_inputs, snapshot.public_inputs);
    assert_eq!(persisted.ordering_hash, snapshot.ordering_hash);
    let bytes = norito::encode_canonical(persisted).unwrap();
    assert!(
        bytes.len() < 2048,
        "artifact contents are never stored in recovery metadata"
    );
    let mut different_size = persisted.clone();
    different_size.artifact_identity.artifact_bytes = 8;
    assert_eq!(
        bytes.len(),
        norito::encode_canonical(&different_size).unwrap().len()
    );
}
#[test]
fn fastpq_proof_snapshots_for_same_block_flush_as_single_sidecar_update() {
    let (_temp_dir, _config, kura, block_hash, sidecar) = default_pipeline_sidecar_fixture();
    let base_payload_len = sidecar.encode_framed().expect("encode sidecar").len() as u64;
    kura.write_pipeline_metadata(&sidecar);
    let snapshot1 = sample_fastpq_snapshot(1, block_hash, 8);
    let snapshot2 = sample_fastpq_snapshot(1, block_hash, 9);
    assert!(matches!(
        kura.enqueue_fastpq_proof_snapshot(snapshot1),
        FastpqProofEnqueueResult::Enqueued { .. }
    ));
    assert!(matches!(
        kura.enqueue_fastpq_proof_snapshot(snapshot2),
        FastpqProofEnqueueResult::Enqueued { .. }
    ));
    assert_eq!(kura.flush_fastpq_proof_snapshots(), 2);
    let got = kura.read_pipeline_metadata(1).expect("sidecar exists");
    assert_eq!(got.fastpq_proofs.len(), 2);
    let updated_payload_len = got.encode_framed().expect("encode updated sidecar").len() as u64;
    let mut pipeline_dir = kura.store_dir().expect("pipeline store dir");
    pipeline_dir.push(PIPELINE_DIR_NAME);
    let data_len = fs::metadata(pipeline_dir.join(PIPELINE_SIDECARS_DATA_FILE))
        .expect("sidecar data metadata")
        .len();
    assert_eq!(
        data_len,
        base_payload_len + updated_payload_len,
        "proof attachments for one block should not append an intermediate sidecar copy"
    );
}
#[test]
fn fastpq_proof_snapshot_rejects_queue_overflow() {
    let kura = Kura::blank_kura_for_testing();
    kura.set_fastpq_proof_sidecar_limits_for_testing(1, usize::MAX, 2);
    let block_hash = HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(b"block"));
    assert!(matches!(
        kura.enqueue_fastpq_proof_snapshot(sample_fastpq_snapshot(1, block_hash, 8)),
        FastpqProofEnqueueResult::Enqueued { queue_depth: 1 }
    ));
    assert_eq!(
        kura.enqueue_fastpq_proof_snapshot(sample_fastpq_snapshot(1, block_hash, 9)),
        FastpqProofEnqueueResult::RejectedQueueFull { cap: 1 }
    );
    assert_eq!(kura.fastpq_proof_queue.lock().len(), 1);
}

#[test]
fn fastpq_proof_snapshot_rolls_back_when_shutdown_arrives_during_enqueue() {
    use std::cell::Cell;

    let kura = Kura::blank_kura_for_testing();
    let block_hash = HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(b"block"));
    let cancellation_checks = Cell::new(0usize);

    let result =
        kura.enqueue_fastpq_proof_snapshot_unless(sample_fastpq_snapshot(1, block_hash, 8), || {
            let check = cancellation_checks.get();
            cancellation_checks.set(check.saturating_add(1));
            check == 1
        });

    assert_eq!(result, FastpqProofEnqueueResult::RejectedShutdown);
    assert_eq!(cancellation_checks.get(), 2);
    assert!(
        kura.fastpq_proof_queue.lock().is_empty(),
        "shutdown observed after insertion must roll the snapshot back"
    );
}

#[test]
fn fastpq_proof_snapshot_rejects_oversized_snapshot() {
    let kura = Kura::blank_kura_for_testing();
    kura.set_fastpq_proof_sidecar_limits_for_testing(8, 1, 2);
    let block_hash = HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(b"block"));
    match kura.enqueue_fastpq_proof_snapshot(sample_fastpq_snapshot(1, block_hash, 8)) {
        FastpqProofEnqueueResult::RejectedTooLarge { actual, max } => {
            assert!(actual > max);
            assert_eq!(max, 1);
        }
        result => panic!("expected oversized rejection, got {result:?}"),
    }
    assert!(kura.fastpq_proof_queue.lock().is_empty());
}
#[test]
fn fastpq_proof_snapshot_retries_missing_sidecar_until_limit() {
    let kura = Kura::blank_kura_for_testing();
    kura.set_fastpq_proof_sidecar_limits_for_testing(8, usize::MAX, 2);
    let block_hash = HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(b"block"));
    assert!(matches!(
        kura.enqueue_fastpq_proof_snapshot(sample_fastpq_snapshot(1, block_hash, 8)),
        FastpqProofEnqueueResult::Enqueued { .. }
    ));
    assert_eq!(kura.flush_fastpq_proof_snapshots(), 0);
    assert_eq!(kura.fastpq_proof_queue.lock().len(), 1);
    assert_eq!(kura.flush_fastpq_proof_snapshots(), 0);
    assert!(kura.fastpq_proof_queue.lock().is_empty());
}

#[test]
fn fastpq_retry_requeue_respects_cap_during_concurrent_enqueue() {
    let kura = Kura::blank_kura_for_testing();
    kura.set_fastpq_proof_sidecar_limits_for_testing(1, usize::MAX, 2);
    let block_hash = HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(b"block"));
    let retry_snapshot = sample_fastpq_snapshot(1, block_hash, 8);
    let concurrent_snapshot = sample_fastpq_snapshot(1, block_hash, 9);
    let concurrent_entry_hash = concurrent_snapshot.entry_hash;
    assert!(matches!(
        kura.enqueue_fastpq_proof_snapshot(retry_snapshot),
        FastpqProofEnqueueResult::Enqueued { queue_depth: 1 }
    ));

    // Hold the disk-mutation lock so the flusher drains the queue and then pauses before it can
    // discover that the pipeline sidecar is absent. A concurrent enqueue can fill the newly empty
    // queue in that window.
    let sidecar_guard = kura.sidecar_lock.lock();
    let flush_kura = Arc::clone(&kura);
    let flusher = thread::spawn(move || flush_kura.flush_fastpq_proof_snapshots());
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let drained = loop {
        if kura.fastpq_proof_queue.lock().is_empty() {
            break true;
        }
        if std::time::Instant::now() >= deadline {
            break false;
        }
        thread::yield_now();
    };
    if !drained {
        drop(sidecar_guard);
        flusher.join().expect("flusher joins after lock release");
        panic!("FASTPQ flusher did not drain its initial queue");
    }
    assert!(matches!(
        kura.enqueue_fastpq_proof_snapshot(concurrent_snapshot),
        FastpqProofEnqueueResult::Enqueued { queue_depth: 1 }
    ));
    drop(sidecar_guard);
    assert_eq!(
        flusher.join().expect("FASTPQ flusher joins"),
        0,
        "missing pipeline sidecar cannot persist a proof"
    );

    let queue = kura.fastpq_proof_queue.lock();
    assert_eq!(queue.len(), 1, "retry merge must preserve the queue cap");
    assert_eq!(
        queue.front().map(|queued| queued.snapshot.entry_hash),
        Some(concurrent_entry_hash),
        "an already accepted concurrent enqueue keeps its queue position"
    );
}
#[test]
fn pipeline_sidecar_promotes_temp_index_on_read() {
    let (_temp_dir, _config, kura, block_hash, sidecar) = default_pipeline_sidecar_fixture();
    let payload = sidecar.encode_framed().expect("encode sidecar");
    let mut pipeline_dir = kura.store_dir().expect("pipeline store dir");
    pipeline_dir.push(PIPELINE_DIR_NAME);
    fs::create_dir_all(&pipeline_dir).expect("create pipeline dir");
    let data_path = pipeline_dir.join(PIPELINE_SIDECARS_DATA_FILE);
    let index_path = pipeline_dir.join(PIPELINE_SIDECARS_INDEX_FILE);
    fs::write(&data_path, &payload).expect("write sidecar data");
    std::fs::File::create(&index_path).expect("create empty index");
    let temp_index_path = index_path.with_extension("index.tmp");
    let entry = SidecarIndexEntry {
        offset: 0,
        len: payload.len() as u64,
    }
    .to_bytes();
    let mut temp = std::fs::File::create(&temp_index_path).expect("create temp index");
    temp.write_all(&SidecarIndexLayout::base_header(1))
        .expect("write V1 index header");
    temp.write_all(&entry).expect("write temp index entry");
    temp.flush().expect("flush temp index");
    temp.sync_data().expect("sync temp index");
    let got = kura.read_pipeline_metadata(1).expect("sidecar exists");
    assert_eq!(got.block_hash, block_hash);
    assert!(!temp_index_path.exists(), "temp index should be promoted");
    let index_len = std::fs::metadata(&index_path)
        .expect("index metadata")
        .len();
    assert_eq!(
        index_len,
        INDEXED_SIDECAR_BASE_HEADER_SIZE_U64 + PIPELINE_INDEX_ENTRY_SIZE_U64
    );
}
#[test]
fn indexed_sidecar_recovery_promotes_canonical_header_only_rewrite() {
    let temp_dir = TempDir::new().expect("create sidecar directory");
    let data_path = temp_dir.path().join(PIPELINE_SIDECARS_DATA_FILE);
    let index_path = temp_dir.path().join(PIPELINE_SIDECARS_INDEX_FILE);
    let payload = norito::to_bytes(&DummySidecar { height: 1 }).expect("encode initial sidecar");
    assert!(Kura::append_indexed_sidecar(
        &data_path,
        &index_path,
        1,
        &payload,
        "header-only rewrite recovery test",
        FsyncMode::Batched,
        None,
    ));
    let temp_data_path = data_path.with_extension("norito.tmp");
    let temp_index_path = index_path.with_extension("index.tmp");
    fs::write(&temp_data_path, []).expect("stage empty compacted data");
    let expected_header = SidecarIndexLayout::base_header(2);
    fs::write(&temp_index_path, expected_header).expect("stage header-only V1 index");
    assert!(Kura::recover_indexed_sidecar_artifacts(
        &data_path,
        &index_path,
        "header-only rewrite recovery test",
    ));
    assert!(fs::read(&data_path).expect("read promoted data").is_empty());
    assert_eq!(
        fs::read(&index_path).expect("read promoted index"),
        expected_header
    );
    assert!(!temp_data_path.exists() && !temp_index_path.exists());
    let mut index = std::fs::File::open(&index_path).expect("open promoted index");
    let layout = SidecarIndexLayout::read_from(
        &mut index,
        fs::metadata(&index_path).expect("index metadata").len(),
    )
    .expect("decode header-only V1 layout");
    assert_eq!(layout.base_height, 2);
    assert_eq!(layout.entry_count, 0);
}
#[test]
fn pipeline_sidecar_promotes_temp_index_after_data_promotion_crash() {
    let (_temp_dir, _config, kura) = unwrapped_kura_fixture();
    let hashes = store_dummy_blocks(&kura, 2);
    let sidecar = PipelineRecoverySidecar::new(
        1,
        hashes[0],
        PipelineDagSnapshot {
            fingerprint: [0u8; 32],
            key_count: 0,
        },
        Vec::new(),
    );
    let payload = sidecar.encode_framed().expect("encode sidecar");
    let temp_sidecar = PipelineRecoverySidecar::new(
        1,
        hashes[0],
        PipelineDagSnapshot {
            fingerprint: [1u8; 32],
            key_count: 1,
        },
        Vec::new(),
    );
    let temp_payload = temp_sidecar.encode_framed().expect("encode temp sidecar");
    let mut pipeline_dir = kura.store_dir().expect("pipeline store dir");
    pipeline_dir.push(PIPELINE_DIR_NAME);
    fs::create_dir_all(&pipeline_dir).expect("create pipeline dir");
    let data_path = pipeline_dir.join(PIPELINE_SIDECARS_DATA_FILE);
    let index_path = pipeline_dir.join(PIPELINE_SIDECARS_INDEX_FILE);
    let temp_index_path = index_path.with_extension("index.tmp");
    let mut data_file = std::fs::File::create(&data_path).expect("create sidecar data");
    data_file.write_all(&payload).expect("write sidecar data");
    let temp_offset = payload.len() as u64;
    data_file
        .write_all(&temp_payload)
        .expect("write temp sidecar data");
    data_file.flush().expect("flush sidecar data");
    data_file.sync_data().expect("sync sidecar data");
    let entry = SidecarIndexEntry {
        offset: 0,
        len: payload.len() as u64,
    }
    .to_bytes();
    let mut index = std::fs::File::create(&index_path).expect("create sidecar index");
    index
        .write_all(&SidecarIndexLayout::base_header(1))
        .expect("write V1 index header");
    index.write_all(&entry).expect("write sidecar index");
    index.flush().expect("flush sidecar index");
    index.sync_data().expect("sync sidecar index");
    let temp_entry = SidecarIndexEntry {
        offset: temp_offset,
        len: temp_payload.len() as u64,
    }
    .to_bytes();
    let mut temp_index = std::fs::File::create(&temp_index_path).expect("create temp index");
    temp_index
        .write_all(&SidecarIndexLayout::base_header(1))
        .expect("write temp V1 index header");
    temp_index.write_all(&temp_entry).expect("write temp index");
    temp_index.flush().expect("flush temp index");
    temp_index.sync_data().expect("sync temp index");
    let got = kura.read_pipeline_metadata(1).expect("sidecar exists");
    assert_eq!(got.block_hash, hashes[0]);
    assert_eq!(got.dag.fingerprint, [1u8; 32]);
    assert!(
        !temp_index_path.exists(),
        "temp index is the recovery marker after data was already promoted"
    );
    let mut buf = [0u8; PIPELINE_INDEX_ENTRY_SIZE];
    let mut index_file = std::fs::File::open(&index_path).expect("open sidecar index");
    index_file
        .seek(SeekFrom::Start(INDEXED_SIDECAR_BASE_HEADER_SIZE_U64))
        .expect("seek past V1 header");
    index_file.read_exact(&mut buf).expect("read sidecar index");
    let entry = SidecarIndexEntry::from_bytes(buf);
    assert_eq!(entry.offset, temp_offset);
    assert_eq!(entry.len, temp_payload.len() as u64);
}
#[test]
fn pipeline_sidecar_recovers_temp_data_before_temp_index() {
    let (_temp_dir, _config, kura) = unwrapped_kura_fixture();
    let block_hash = store_dummy_blocks(&kura, 1)[0];
    let old_sidecar = PipelineRecoverySidecar::new(
        1,
        block_hash,
        PipelineDagSnapshot {
            fingerprint: [0u8; 32],
            key_count: 0,
        },
        Vec::new(),
    );
    kura.write_pipeline_metadata(&old_sidecar);
    let recovered_sidecar = PipelineRecoverySidecar::new(
        1,
        block_hash,
        PipelineDagSnapshot {
            fingerprint: [2u8; 32],
            key_count: 2,
        },
        Vec::new(),
    );
    let recovered_payload = recovered_sidecar
        .encode_framed()
        .expect("encode recovered sidecar");
    let mut pipeline_dir = kura.store_dir().expect("pipeline store dir");
    pipeline_dir.push(PIPELINE_DIR_NAME);
    let data_path = pipeline_dir.join(PIPELINE_SIDECARS_DATA_FILE);
    let index_path = pipeline_dir.join(PIPELINE_SIDECARS_INDEX_FILE);
    let temp_data_path = data_path.with_extension("norito.tmp");
    let temp_index_path = index_path.with_extension("index.tmp");
    let mut temp_data = std::fs::File::create(&temp_data_path).expect("create temp data");
    temp_data
        .write_all(&recovered_payload)
        .expect("write temp data");
    temp_data.flush().expect("flush temp data");
    temp_data.sync_data().expect("sync temp data");
    let entry = SidecarIndexEntry {
        offset: 0,
        len: recovered_payload.len() as u64,
    }
    .to_bytes();
    let mut temp_index = std::fs::File::create(&temp_index_path).expect("create temp index");
    temp_index
        .write_all(&SidecarIndexLayout::base_header(1))
        .expect("write temp V1 index header");
    temp_index.write_all(&entry).expect("write temp index");
    temp_index.flush().expect("flush temp index");
    temp_index.sync_data().expect("sync temp index");
    let got = kura.read_pipeline_metadata(1).expect("recovered sidecar");
    assert_eq!(got.dag.fingerprint, [2u8; 32]);
    assert!(!temp_data_path.exists(), "temp data should be promoted");
    assert!(!temp_index_path.exists(), "temp index should be promoted");
    assert_eq!(
        std::fs::read(&data_path).expect("read promoted data"),
        recovered_payload
    );
}
#[test]
fn pipeline_sidecar_recovery_sync_failure_does_not_expose_new_data_with_old_index() {
    let kura = Kura::blank_kura_for_testing();
    let block_hash = store_dummy_blocks(&kura, 1)[0];
    let old_sidecar = PipelineRecoverySidecar::new(
        1,
        block_hash,
        PipelineDagSnapshot {
            fingerprint: [3u8; 32],
            key_count: 3,
        },
        Vec::new(),
    );
    kura.write_pipeline_metadata(&old_sidecar);
    let new_sidecar = PipelineRecoverySidecar::new(
        1,
        block_hash,
        PipelineDagSnapshot {
            fingerprint: [4u8; 32],
            key_count: 4,
        },
        Vec::new(),
    );
    let new_payload = new_sidecar.encode_framed().expect("encode new sidecar");
    let mut pipeline_dir = kura.store_dir().expect("pipeline store dir");
    pipeline_dir.push(PIPELINE_DIR_NAME);
    let data_path = pipeline_dir.join(PIPELINE_SIDECARS_DATA_FILE);
    let index_path = pipeline_dir.join(PIPELINE_SIDECARS_INDEX_FILE);
    let old_index = std::fs::read(&index_path).expect("read old index");
    let temp_data_path = data_path.with_extension("norito.tmp");
    let temp_index_path = index_path.with_extension("index.tmp");
    let mut temp_data = std::fs::File::create(&temp_data_path).expect("create temp data");
    temp_data
        .write_all(&new_payload)
        .expect("write new temp data");
    temp_data.flush().expect("flush new temp data");
    temp_data.sync_data().expect("sync new temp data");
    let new_entry = SidecarIndexEntry {
        offset: 0,
        len: new_payload.len() as u64,
    }
    .to_bytes();
    let mut temp_index = std::fs::File::create(&temp_index_path).expect("create temp index");
    temp_index
        .write_all(&SidecarIndexLayout::base_header(1))
        .expect("write new temp V1 index header");
    temp_index
        .write_all(&new_entry)
        .expect("write new temp index");
    temp_index.flush().expect("flush new temp index");
    temp_index.sync_data().expect("sync new temp index");
    sync_dir(&pipeline_dir).expect("sync recovery markers");
    fail_next_sidecar_promotion_dir_sync_for_tests();
    assert!(
        kura.read_pipeline_metadata(1).is_none(),
        "a failed data-promotion sync must fail closed before the old index can expose new data"
    );
    assert_eq!(
        std::fs::read(&index_path).expect("read unpromoted index"),
        old_index,
        "index must remain unpublished when the data-promotion barrier fails"
    );
    assert!(
        temp_index_path.exists(),
        "durable temp index must remain as the recovery marker"
    );
    let recovered = kura
        .read_pipeline_metadata(1)
        .expect("retry should finish index promotion");
    assert_eq!(recovered.dag.fingerprint, [4u8; 32]);
    assert!(
        !temp_index_path.exists(),
        "retry must consume recovery marker"
    );
}
#[test]
fn pipeline_sidecar_prune_marker_sync_failure_keeps_main_pair_unchanged() {
    let kura = Kura::blank_kura_for_testing();
    let hashes = store_dummy_blocks(&kura, 2);
    let mut pipeline_dir = kura.store_dir().expect("pipeline store dir");
    pipeline_dir.push(PIPELINE_DIR_NAME);
    std::fs::create_dir_all(&pipeline_dir).expect("create pipeline dir");
    let data_path = pipeline_dir.join(PIPELINE_SIDECARS_DATA_FILE);
    let index_path = pipeline_dir.join(PIPELINE_SIDECARS_INDEX_FILE);
    for (index, block_hash) in hashes.into_iter().enumerate() {
        let height = (index + 1) as u64;
        let sidecar = PipelineRecoverySidecar::new(
            height,
            block_hash,
            PipelineDagSnapshot {
                fingerprint: [u8::try_from(height).expect("fixture value fits u8"); 32],
                key_count: u32::try_from(height).expect("test height fits u32"),
            },
            Vec::new(),
        );
        let payload = sidecar.encode_framed().expect("encode sidecar");
        assert!(Kura::append_indexed_sidecar(
            &data_path,
            &index_path,
            height,
            &payload,
            "pipeline sidecar test",
            FsyncMode::Always,
            None,
        ));
    }
    let old_data = std::fs::read(&data_path).expect("read old data");
    let old_index = std::fs::read(&index_path).expect("read old index");
    fail_next_sidecar_temp_marker_dir_sync_for_tests();
    assert!(
        !Kura::prune_indexed_sidecars(
            &data_path,
            &index_path,
            NonZeroUsize::new(1).expect("non-zero retention"),
            "pipeline sidecar test",
        ),
        "prune must reject a temp recovery marker that was not directory-synced"
    );
    assert_eq!(
        std::fs::read(&data_path).expect("read unchanged data"),
        old_data,
        "new data must not be promoted before the recovery marker is durable"
    );
    assert_eq!(
        std::fs::read(&index_path).expect("read unchanged index"),
        old_index,
        "index must remain paired with the old data after marker sync failure"
    );
    assert!(data_path.with_extension("norito.tmp").exists());
    assert!(index_path.with_extension("index.tmp").exists());
    assert!(Kura::recover_indexed_sidecar_artifacts(
        &data_path,
        &index_path,
        "pipeline sidecar test",
    ));
    assert!(
        Kura::read_indexed_sidecar_from_paths::<PipelineRecoverySidecar, _>(
            1,
            &data_path,
            &index_path,
            norito::decode_from_bytes::<PipelineRecoverySidecar>,
            "pipeline sidecar test",
        )
        .is_none(),
        "pruned height must remain absent after recovery"
    );
    let retained = Kura::read_indexed_sidecar_from_paths::<PipelineRecoverySidecar, _>(
        2,
        &data_path,
        &index_path,
        norito::decode_from_bytes::<PipelineRecoverySidecar>,
        "pipeline sidecar test",
    )
    .expect("retained height after recovery");
    assert_eq!(retained.dag.fingerprint, [2u8; 32]);
}
#[test]
fn pipeline_sidecar_fails_closed_on_corrupt_temp_index() {
    let (_temp_dir, _config, kura, _block_hash, sidecar) = default_pipeline_sidecar_fixture();
    kura.write_pipeline_metadata(&sidecar);
    let mut pipeline_dir = kura.store_dir().expect("pipeline store dir");
    pipeline_dir.push(PIPELINE_DIR_NAME);
    let index_path = pipeline_dir.join(PIPELINE_SIDECARS_INDEX_FILE);
    let temp_index_path = index_path.with_extension("index.tmp");
    std::fs::write(&temp_index_path, [0u8; 3]).expect("write corrupt temp index");
    assert!(
        kura.read_pipeline_metadata(1).is_none(),
        "ambiguous recovery state must not expose the old data/index pair"
    );
    assert!(
        temp_index_path.exists(),
        "corrupt temp index should not be promoted"
    );
}
#[test]
fn pipeline_sidecar_fails_closed_on_orphaned_temp_data() {
    let (_temp_dir, _config, kura) = unwrapped_kura_fixture();
    let hashes = store_dummy_blocks(&kura, 2);
    let sidecar = PipelineRecoverySidecar::new(
        1,
        hashes[0],
        PipelineDagSnapshot {
            fingerprint: [0u8; 32],
            key_count: 0,
        },
        Vec::new(),
    );
    kura.write_pipeline_metadata(&sidecar);
    let temp_sidecar = PipelineRecoverySidecar::new(
        1,
        hashes[1],
        PipelineDagSnapshot {
            fingerprint: [1u8; 32],
            key_count: 1,
        },
        Vec::new(),
    );
    let payload = temp_sidecar.encode_framed().expect("encode temp sidecar");
    let mut pipeline_dir = kura.store_dir().expect("pipeline store dir");
    pipeline_dir.push(PIPELINE_DIR_NAME);
    let data_path = pipeline_dir.join(PIPELINE_SIDECARS_DATA_FILE);
    let temp_data_path = data_path.with_extension("norito.tmp");
    fs::write(&temp_data_path, &payload).expect("write temp data");
    assert!(
        kura.read_pipeline_metadata(1).is_none(),
        "temp data without a recovery index is ambiguous and must fail closed"
    );
}
#[test]
fn pipeline_sidecar_rejects_height_mismatch() {
    let (_temp_dir, _config, kura) = unwrapped_kura_fixture();
    let mut pipeline_dir = kura.store_dir().expect("pipeline store dir");
    pipeline_dir.push(PIPELINE_DIR_NAME);
    std::fs::create_dir_all(&pipeline_dir).expect("create pipeline dir");
    let data_path = pipeline_dir.join(PIPELINE_SIDECARS_DATA_FILE);
    let index_path = pipeline_dir.join(PIPELINE_SIDECARS_INDEX_FILE);
    let block_hash = HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([0xBB; 32]));
    let sidecar = PipelineRecoverySidecar::new(
        2,
        block_hash,
        PipelineDagSnapshot {
            fingerprint: [0x12; 32],
            key_count: 1,
        },
        Vec::new(),
    );
    let payload = sidecar.encode_framed().expect("encode sidecar");
    assert!(
        Kura::append_indexed_sidecar(
            &data_path,
            &index_path,
            1,
            &payload,
            "pipeline sidecar",
            FsyncMode::Batched,
            None,
        ),
        "append mismatched sidecar"
    );
    assert!(
        kura.read_pipeline_metadata(1).is_none(),
        "height mismatch should be rejected"
    );
}
#[test]
fn sidecar_fsync_mode_tracks_kura_config() {
    let (_temp_dir, kura) = unwrapped_inline_kura_fixture_with_fsync(FsyncMode::Always);
    assert_eq!(kura.sidecar_fsync_mode(), FsyncMode::Always);
}
#[test]
fn pipeline_sidecar_rejects_block_hash_mismatch() {
    let (_temp_dir, _config, kura) = unwrapped_kura_fixture();
    let mut blocks = NativeBlocks::new();
    let block = blocks.next();
    let expected_hash = block.hash();
    kura.store_block(block).expect("store block");
    let mismatch_hash = HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([0xCC; 32]));
    assert_ne!(expected_hash, mismatch_hash, "mismatch hash must differ");
    let sidecar = PipelineRecoverySidecar::new(
        1,
        mismatch_hash,
        PipelineDagSnapshot {
            fingerprint: [0x34; 32],
            key_count: 7,
        },
        Vec::new(),
    );
    kura.write_pipeline_metadata(&sidecar);
    assert!(
        kura.read_pipeline_metadata(1).is_none(),
        "block hash mismatch should be rejected"
    );
}
#[test]
fn pipeline_sidecars_append_to_single_store() {
    let (_temp_dir, _config, kura) = unwrapped_kura_fixture();
    let hashes = store_dummy_blocks(&kura, 2);
    let dag = PipelineDagSnapshot {
        fingerprint: [1u8; 32],
        key_count: 1,
    };
    let sidecar1 = PipelineRecoverySidecar::new(1, hashes[0], dag, Vec::new());
    let sidecar2 = PipelineRecoverySidecar::new(2, hashes[1], dag, Vec::new());
    kura.write_pipeline_metadata(&sidecar1);
    kura.write_pipeline_metadata(&sidecar2);
    let mut pipeline_dir = kura.store_dir().expect("pipeline store dir");
    pipeline_dir.push(PIPELINE_DIR_NAME);
    let data_path = pipeline_dir.join(PIPELINE_SIDECARS_DATA_FILE);
    let index_path = pipeline_dir.join(PIPELINE_SIDECARS_INDEX_FILE);
    assert!(data_path.is_file(), "pipeline sidecar data file missing");
    assert!(index_path.is_file(), "pipeline sidecar index file missing");
    let index_len = std::fs::metadata(&index_path)
        .expect("index metadata")
        .len();
    assert_eq!(
        index_len,
        INDEXED_SIDECAR_BASE_HEADER_SIZE_U64 + 2 * PIPELINE_INDEX_ENTRY_SIZE_U64,
        "expected two index entries"
    );
    assert!(
        !pipeline_dir.join("block_1.norito").exists(),
        "per-block sidecar should not be created in aggregated layout"
    );
    let got = kura.read_pipeline_metadata(2).expect("sidecar exists");
    assert_eq!(got.height, 2);
    assert_eq!(got.dag.key_count, 1);
}
#[test]
fn pipeline_sidecar_overwrite_updates_entry() {
    let temp_dir = TempDir::new().unwrap();
    let data_path = temp_dir.path().join(PIPELINE_SIDECARS_DATA_FILE);
    let index_path = temp_dir.path().join(PIPELINE_SIDECARS_INDEX_FILE);
    let payload1 = norito::to_bytes(&DummySidecar { height: 1 }).expect("encode dummy sidecar 1");
    assert!(
        Kura::append_indexed_sidecar(
            &data_path,
            &index_path,
            1,
            &payload1,
            "dummy sidecar",
            FsyncMode::Batched,
            None,
        ),
        "append height 1 must succeed"
    );
    let payload2 = norito::to_bytes(&DummySidecar { height: 2 }).expect("encode dummy sidecar 2");
    assert!(
        Kura::append_indexed_sidecar(
            &data_path,
            &index_path,
            1,
            &payload2,
            "dummy sidecar",
            FsyncMode::Batched,
            None,
        ),
        "overwrite height 1 must succeed"
    );
    let index_len = fs::metadata(&index_path).expect("index metadata").len();
    assert_eq!(
        index_len,
        INDEXED_SIDECAR_BASE_HEADER_SIZE_U64 + PIPELINE_INDEX_ENTRY_SIZE_U64,
        "expected single index entry"
    );
    let mut index = std::fs::File::open(&index_path).expect("index exists");
    let mut buf = [0u8; PIPELINE_INDEX_ENTRY_SIZE];
    index
        .seek(SeekFrom::Start(INDEXED_SIDECAR_BASE_HEADER_SIZE_U64))
        .expect("seek past V1 header");
    index.read_exact(&mut buf).expect("read index entry");
    let entry = SidecarIndexEntry::from_bytes(buf);
    assert!(entry.len > 0);
    let mut data = std::fs::File::open(&data_path).expect("data exists");
    let len = usize::try_from(entry.len).expect("len fits in usize");
    let mut payload = vec![0u8; len];
    data.seek(SeekFrom::Start(entry.offset))
        .expect("seek to payload");
    data.read_exact(&mut payload).expect("read payload");
    let decoded: DummySidecar = norito::decode_from_bytes(&payload).expect("decode dummy sidecar");
    assert_eq!(decoded.height, 2);
}
#[test]
fn pipeline_sidecar_rejects_overlapping_offsets() {
    let (_temp_dir, _config, kura) = unwrapped_kura_fixture();
    let mut pipeline_dir = kura.store_dir().expect("pipeline store dir");
    pipeline_dir.push(PIPELINE_DIR_NAME);
    std::fs::create_dir_all(&pipeline_dir).expect("create pipeline dir");
    let data_path = pipeline_dir.join(PIPELINE_SIDECARS_DATA_FILE);
    let index_path = pipeline_dir.join(PIPELINE_SIDECARS_INDEX_FILE);
    let sidecar1 = PipelineRecoverySidecar::new(
        1,
        HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([0x11; 32])),
        PipelineDagSnapshot {
            fingerprint: [0x10; 32],
            key_count: 0,
        },
        Vec::new(),
    );
    let sidecar2 = PipelineRecoverySidecar::new(
        2,
        HashOf::<BlockHeader>::from_untyped_unchecked(Hash::prehashed([0x22; 32])),
        PipelineDagSnapshot {
            fingerprint: [0x20; 32],
            key_count: 0,
        },
        Vec::new(),
    );
    let payload1 = sidecar1.encode_framed().expect("encode sidecar1");
    let payload2 = sidecar2.encode_framed().expect("encode sidecar2");
    assert_eq!(payload1.len(), payload2.len(), "payload lengths must match");
    fs::write(&data_path, &payload2).expect("write payload data");
    let entry1 = SidecarIndexEntry {
        offset: 0,
        len: payload1.len() as u64,
    };
    let entry2 = SidecarIndexEntry {
        offset: 0,
        len: payload2.len() as u64,
    };
    let mut index = std::fs::File::create(&index_path).expect("create index");
    index
        .write_all(&SidecarIndexLayout::base_header(1))
        .expect("write V1 index header");
    index.write_all(&entry1.to_bytes()).expect("write entry1");
    index.write_all(&entry2.to_bytes()).expect("write entry2");
    assert!(
        kura.read_pipeline_metadata(2).is_none(),
        "overlapping offsets should be rejected"
    );
}
#[test]
fn pipeline_sidecar_allows_out_of_order_offsets() {
    let (_temp_dir, _config, kura) = unwrapped_kura_fixture();
    let mut pipeline_dir = kura.store_dir().expect("pipeline store dir");
    pipeline_dir.push(PIPELINE_DIR_NAME);
    std::fs::create_dir_all(&pipeline_dir).expect("create pipeline dir");
    let data_path = pipeline_dir.join(PIPELINE_SIDECARS_DATA_FILE);
    let index_path = pipeline_dir.join(PIPELINE_SIDECARS_INDEX_FILE);
    let hashes = store_dummy_blocks(&kura, 2);
    let sidecar1 = PipelineRecoverySidecar::new(
        1,
        hashes[0],
        PipelineDagSnapshot {
            fingerprint: [0x30; 32],
            key_count: 0,
        },
        Vec::new(),
    );
    let sidecar2 = PipelineRecoverySidecar::new(
        2,
        hashes[1],
        PipelineDagSnapshot {
            fingerprint: [0x40; 32],
            key_count: 0,
        },
        Vec::new(),
    );
    let payload1 = sidecar1.encode_framed().expect("encode sidecar1");
    let payload2 = sidecar2.encode_framed().expect("encode sidecar2");
    let mut data = std::fs::File::create(&data_path).expect("create data file");
    data.write_all(&payload2).expect("write payload2");
    data.write_all(&payload1).expect("write payload1");
    let entry1 = SidecarIndexEntry {
        offset: payload2.len() as u64,
        len: payload1.len() as u64,
    };
    let entry2 = SidecarIndexEntry {
        offset: 0,
        len: payload2.len() as u64,
    };
    let mut index = std::fs::File::create(&index_path).expect("create index");
    index
        .write_all(&SidecarIndexLayout::base_header(1))
        .expect("write V1 index header");
    index.write_all(&entry1.to_bytes()).expect("write entry1");
    index.write_all(&entry2.to_bytes()).expect("write entry2");
    let got = kura.read_pipeline_metadata(2).expect("sidecar exists");
    assert_eq!(got.height, 2);
    assert_eq!(got.block_hash, sidecar2.block_hash);
}
#[test]
fn pipeline_sidecar_allows_misaligned_index() {
    let (_temp_dir, _config, kura) = unwrapped_kura_fixture();
    let mut pipeline_dir = kura.store_dir().expect("pipeline store dir");
    pipeline_dir.push(PIPELINE_DIR_NAME);
    std::fs::create_dir_all(&pipeline_dir).expect("create pipeline dir");
    let data_path = pipeline_dir.join(PIPELINE_SIDECARS_DATA_FILE);
    let index_path = pipeline_dir.join(PIPELINE_SIDECARS_INDEX_FILE);
    let block_hash = store_dummy_blocks(&kura, 1)[0];
    let sidecar = PipelineRecoverySidecar::new(
        1,
        block_hash,
        PipelineDagSnapshot {
            fingerprint: [0x44; 32],
            key_count: 0,
        },
        Vec::new(),
    );
    let payload = sidecar.encode_framed().expect("encode sidecar");
    fs::write(&data_path, &payload).expect("write payload");
    let entry = SidecarIndexEntry {
        offset: 0,
        len: payload.len() as u64,
    };
    let mut index = std::fs::File::create(&index_path).expect("create index");
    index
        .write_all(&SidecarIndexLayout::base_header(1))
        .expect("write V1 index header");
    index.write_all(&entry.to_bytes()).expect("write entry");
    index.write_all(&[0u8; 3]).expect("write padding");
    let got = kura.read_pipeline_metadata(1).expect("sidecar exists");
    assert_eq!(got.height, 1);
    assert_eq!(got.block_hash, sidecar.block_hash);
}
#[test]
fn sidecar_reader_rejects_oversized_payloads() {
    let temp_dir = TempDir::new().unwrap();
    let store_root = temp_dir.path().join("kura");
    let config = kura_config_for_path(&store_root, BLOCKS_IN_MEMORY);
    let kura =
        Kura::open_test_kura_with_configured_lane_config(&config, &RuntimeLaneConfig::default())
            .unwrap()
            .0;
    let mut dir = kura.store_dir().expect("store dir");
    dir.push(PIPELINE_DIR_NAME);
    std::fs::create_dir_all(&dir).expect("create pipeline dir");
    let data_path = dir.join(PIPELINE_SIDECARS_DATA_FILE);
    let index_path = dir.join(PIPELINE_SIDECARS_INDEX_FILE);
    let pipeline_limit = u64::try_from(MAX_PIPELINE_RECOVERY_SIDECAR_BYTES).unwrap_or(u64::MAX);
    std::fs::File::create(&data_path)
        .and_then(|file| file.set_len(pipeline_limit + 1))
        .expect("create sparse oversized sidecar data file");
    let entry = SidecarIndexEntry {
        offset: 0,
        len: pipeline_limit + 1,
    }
    .to_bytes();
    let mut index_bytes = SidecarIndexLayout::base_header(1).to_vec();
    index_bytes.extend_from_slice(&entry);
    std::fs::write(&index_path, index_bytes).expect("write oversized index entry");
    let decoder_called = std::cell::Cell::new(false);
    assert!(
        Kura::read_indexed_sidecar_from_paths_with_recovery_and_limit::<(), _>(
            1,
            &data_path,
            &index_path,
            |_| {
                decoder_called.set(true);
                Ok(())
            },
            "pipeline sidecar",
            false,
            pipeline_limit,
        )
        .is_none()
    );
    assert!(
        !decoder_called.get(),
        "oversized payload must not be decoded"
    );
    assert!(kura.read_pipeline_metadata(1).is_none());
}
#[cfg(unix)]
#[test]
fn read_only_sidecar_reader_rejects_symlinks_and_fifos() {
    use std::os::unix::fs::symlink;

    let dir = TempDir::new().expect("sidecar path fixtures");
    let data_path = dir.path().join("pipeline.data");
    let index_path = dir.path().join("pipeline.index");
    let target_path = dir.path().join("pipeline.target");
    std::fs::write(&target_path, []).expect("write symlink target");
    std::fs::write(&index_path, []).expect("write regular sidecar index");
    symlink(&target_path, &data_path).expect("create sidecar data symlink");
    assert!(
        Kura::read_indexed_sidecar_from_paths_with_recovery_and_limit::<(), _>(
            1,
            &data_path,
            &index_path,
            |_| panic!("symlink payload must not be decoded"),
            "pipeline sidecar",
            false,
            1024,
        )
        .is_none()
    );

    std::fs::remove_file(&data_path).expect("remove sidecar data symlink");
    std::fs::write(&data_path, []).expect("write regular sidecar data");
    std::fs::remove_file(&index_path).expect("remove regular sidecar index");
    let status = std::process::Command::new("mkfifo")
        .arg(&index_path)
        .status()
        .expect("invoke mkfifo for sidecar regression");
    assert!(status.success(), "mkfifo must create the sidecar fixture");
    assert!(
        Kura::read_indexed_sidecar_from_paths_with_recovery_and_limit::<(), _>(
            1,
            &data_path,
            &index_path,
            |_| panic!("FIFO payload must not be decoded"),
            "pipeline sidecar",
            false,
            1024,
        )
        .is_none()
    );
}
#[test]
fn pipeline_sidecar_ignores_invalid_prev_entry() {
    let (_temp_dir, _config, kura) = unwrapped_kura_fixture();
    let mut pipeline_dir = kura.store_dir().expect("pipeline store dir");
    pipeline_dir.push(PIPELINE_DIR_NAME);
    std::fs::create_dir_all(&pipeline_dir).expect("create pipeline dir");
    let data_path = pipeline_dir.join(PIPELINE_SIDECARS_DATA_FILE);
    let index_path = pipeline_dir.join(PIPELINE_SIDECARS_INDEX_FILE);
    let hashes = store_dummy_blocks(&kura, 2);
    let sidecar2 = PipelineRecoverySidecar::new(
        2,
        hashes[1],
        PipelineDagSnapshot {
            fingerprint: [0x66; 32],
            key_count: 0,
        },
        Vec::new(),
    );
    let payload2 = sidecar2.encode_framed().expect("encode sidecar2");
    fs::write(&data_path, &payload2).expect("write payload2");
    let bogus_prev = SidecarIndexEntry {
        offset: 0,
        len: payload2.len() as u64 + 10,
    };
    let entry2 = SidecarIndexEntry {
        offset: 0,
        len: payload2.len() as u64,
    };
    let mut index = std::fs::File::create(&index_path).expect("create index");
    index
        .write_all(&SidecarIndexLayout::base_header(1))
        .expect("write V1 index header");
    index
        .write_all(&bogus_prev.to_bytes())
        .expect("write bogus entry");
    index.write_all(&entry2.to_bytes()).expect("write entry2");
    let got = kura.read_pipeline_metadata(2).expect("sidecar exists");
    assert_eq!(got.height, 2);
    assert_eq!(got.block_hash, sidecar2.block_hash);
}
#[test]
fn sidecar_append_truncates_misaligned_index() {
    let temp_dir = TempDir::new().unwrap();
    let data_path = temp_dir.path().join(PIPELINE_SIDECARS_DATA_FILE);
    let index_path = temp_dir.path().join(PIPELINE_SIDECARS_INDEX_FILE);
    let payload1 = norito::to_bytes(&DummySidecar { height: 1 }).expect("encode dummy sidecar 1");
    let payload2 = norito::to_bytes(&DummySidecar { height: 2 }).expect("encode dummy sidecar 2");
    fs::write(&data_path, &payload1).expect("write payload1");
    let entry1 = SidecarIndexEntry {
        offset: 0,
        len: payload1.len() as u64,
    };
    let mut index = std::fs::File::create(&index_path).expect("create index");
    index
        .write_all(&SidecarIndexLayout::base_header(1))
        .expect("write V1 index header");
    index.write_all(&entry1.to_bytes()).expect("write entry1");
    index.write_all(&[0u8; 3]).expect("write padding");
    assert!(
        Kura::append_indexed_sidecar(
            &data_path,
            &index_path,
            2,
            &payload2,
            "dummy sidecar",
            FsyncMode::Batched,
            None,
        ),
        "append should succeed and truncate misaligned index"
    );
    let index_len = fs::metadata(&index_path).expect("index metadata").len();
    assert_eq!(
        index_len,
        INDEXED_SIDECAR_BASE_HEADER_SIZE_U64 + 2 * PIPELINE_INDEX_ENTRY_SIZE_U64,
        "expected aligned index after append"
    );
    let mut index = std::fs::File::open(&index_path).expect("index exists");
    let mut buf = [0u8; PIPELINE_INDEX_ENTRY_SIZE];
    index
        .seek(SeekFrom::Start(INDEXED_SIDECAR_BASE_HEADER_SIZE_U64))
        .expect("seek past V1 header");
    index.read_exact(&mut buf).expect("read entry1");
    let entry1 = SidecarIndexEntry::from_bytes(buf);
    index.read_exact(&mut buf).expect("read entry2");
    let entry2 = SidecarIndexEntry::from_bytes(buf);
    assert_eq!(entry1.offset, 0);
    assert_eq!(entry1.len, payload1.len() as u64);
    assert_eq!(entry2.offset, payload1.len() as u64);
    assert_eq!(entry2.len, payload2.len() as u64);
}
#[test]
fn sidecar_prune_truncates_misaligned_index() {
    let temp_dir = TempDir::new().unwrap();
    let data_path = temp_dir.path().join(PIPELINE_SIDECARS_DATA_FILE);
    let index_path = temp_dir.path().join(PIPELINE_SIDECARS_INDEX_FILE);
    let retention = NonZeroUsize::new(2).expect("non-zero retention");
    let payloads = (1_u64..=3)
        .map(|height| norito::to_bytes(&DummySidecar { height }).expect("encode dummy sidecar"))
        .collect::<Vec<_>>();
    let mut entries = Vec::new();
    let mut data = std::fs::File::create(&data_path).expect("create data");
    let mut offset = 0u64;
    for payload in &payloads {
        data.write_all(payload).expect("write payload");
        entries.push(SidecarIndexEntry {
            offset,
            len: payload.len() as u64,
        });
        offset = offset.saturating_add(payload.len() as u64);
    }
    let mut index = std::fs::File::create(&index_path).expect("create index");
    index
        .write_all(&SidecarIndexLayout::base_header(1))
        .expect("write V1 index header");
    for entry in &entries {
        index.write_all(&entry.to_bytes()).expect("write entry");
    }
    index.write_all(&[0u8; 3]).expect("write padding");
    assert!(
        Kura::prune_indexed_sidecars(&data_path, &index_path, retention, "dummy sidecar"),
        "prune should tolerate misaligned index"
    );
    let index_len = fs::metadata(&index_path).expect("index metadata").len();
    assert_eq!(
        index_len,
        INDEXED_SIDECAR_BASE_HEADER_SIZE_U64 + 3 * PIPELINE_INDEX_ENTRY_SIZE_U64,
        "expected aligned index after prune"
    );
    let mut index = std::fs::File::open(&index_path).expect("index exists");
    let mut buf = [0u8; PIPELINE_INDEX_ENTRY_SIZE];
    index
        .seek(SeekFrom::Start(INDEXED_SIDECAR_BASE_HEADER_SIZE_U64))
        .expect("seek past V1 header");
    let mut pruned_entries = Vec::new();
    for _ in 0..3 {
        index.read_exact(&mut buf).expect("read entry");
        pruned_entries.push(SidecarIndexEntry::from_bytes(buf));
    }
    assert_eq!(pruned_entries[0].len, 0);
    assert!(pruned_entries[1].len > 0);
    assert!(pruned_entries[2].len > 0);
    assert_eq!(pruned_entries[1].offset, 0);
    assert_eq!(pruned_entries[2].offset, pruned_entries[1].len);
    let mut data = std::fs::File::open(&data_path).expect("data exists");
    for (idx, expected_height) in [2_u64, 3_u64].into_iter().enumerate() {
        let entry = &pruned_entries[idx + 1];
        let len = usize::try_from(entry.len).expect("len fits in usize");
        let mut payload = vec![0u8; len];
        data.seek(SeekFrom::Start(entry.offset))
            .expect("seek to payload");
        data.read_exact(&mut payload).expect("read payload");
        let decoded: DummySidecar =
            norito::decode_from_bytes(&payload).expect("decode dummy sidecar");
        assert_eq!(decoded.height, expected_height);
    }
}
#[test]
fn sidecar_prune_skips_entries_past_data_len() {
    let temp_dir = TempDir::new().unwrap();
    let data_path = temp_dir.path().join(PIPELINE_SIDECARS_DATA_FILE);
    let index_path = temp_dir.path().join(PIPELINE_SIDECARS_INDEX_FILE);
    let retention = NonZeroUsize::new(1).expect("non-zero retention");
    let payload1 = norito::to_bytes(&DummySidecar { height: 1 }).expect("encode sidecar");
    fs::write(&data_path, &payload1).expect("write payload");
    let entry1 = SidecarIndexEntry {
        offset: 0,
        len: payload1.len() as u64,
    };
    let entry2 = SidecarIndexEntry {
        offset: payload1.len() as u64 + 8,
        len: 4,
    };
    let mut index = std::fs::File::create(&index_path).expect("create index");
    index
        .write_all(&SidecarIndexLayout::base_header(1))
        .expect("write V1 index header");
    index.write_all(&entry1.to_bytes()).expect("write entry1");
    index.write_all(&entry2.to_bytes()).expect("write entry2");
    assert!(
        Kura::prune_indexed_sidecars(&data_path, &index_path, retention, "dummy sidecar"),
        "prune should drop invalid entries"
    );
    let mut index = std::fs::File::open(&index_path).expect("index exists");
    let mut buf = [0u8; PIPELINE_INDEX_ENTRY_SIZE];
    index
        .seek(SeekFrom::Start(INDEXED_SIDECAR_BASE_HEADER_SIZE_U64))
        .expect("seek past V1 header");
    index.read_exact(&mut buf).expect("read entry1");
    let entry1 = SidecarIndexEntry::from_bytes(buf);
    index.read_exact(&mut buf).expect("read entry2");
    let entry2 = SidecarIndexEntry::from_bytes(buf);
    assert_eq!(entry1.len, 0);
    assert_eq!(entry2.len, 0);
    assert_eq!(
        fs::metadata(&data_path).expect("data metadata").len(),
        0,
        "invalid kept entry should be dropped from data file"
    );
}
#[test]
fn sidecar_retention_window_advances_base_and_bounds_index() {
    let temp_dir = TempDir::new().expect("temporary sidecar directory");
    let data_path = temp_dir.path().join("bounded-history-dummy.norito");
    let index_path = temp_dir.path().join("bounded-history-dummy.index");
    let retention = NonZeroUsize::new(2).expect("non-zero Native evidence retention");
    for height in 41_u64..=44 {
        let payload =
            norito::to_bytes(&DummySidecar { height }).expect("encode dummy Native evidence");
        assert!(Kura::append_indexed_sidecar(
            &data_path,
            &index_path,
            height,
            &payload,
            "dummy bounded evidence",
            FsyncMode::Always,
            None,
        ));
        assert!(Kura::prune_indexed_sidecars_to_retention_window(
            &data_path,
            &index_path,
            retention,
            "dummy bounded evidence",
        ));
    }
    let mut index = std::fs::File::open(&index_path).expect("open compact Native index");
    let index_len = index.metadata().expect("compact index metadata").len();
    let layout = SidecarIndexLayout::read_from(&mut index, index_len)
        .expect("decode compact Native index layout");
    assert_eq!(layout.base_height, 43);
    assert_eq!(layout.entry_count, retention.get() as u64);
    assert_eq!(
        index_len,
        INDEXED_SIDECAR_BASE_HEADER_SIZE_U64
            + u64::try_from(retention.get()).expect("retention fits u64")
                * PIPELINE_INDEX_ENTRY_SIZE_U64,
        "Sidecar retention must bound historical index slots as well as payload bytes"
    );
    for height in 41_u64..=42 {
        assert!(
            Kura::read_indexed_sidecar_from_paths(
                height,
                &data_path,
                &index_path,
                norito::decode_from_bytes::<DummySidecar>,
                "dummy bounded evidence",
            )
            .is_none(),
            "height {height} must be outside the retained sidecar window"
        );
    }
    for height in 43_u64..=44 {
        assert_eq!(
            Kura::read_indexed_sidecar_from_paths(
                height,
                &data_path,
                &index_path,
                norito::decode_from_bytes::<DummySidecar>,
                "dummy bounded evidence",
            ),
            Some(DummySidecar { height }),
        );
    }
}
#[test]
fn terminal_frontier_compaction_retains_every_later_pending_slot() {
    let temp_dir = TempDir::new().expect("temporary sidecar directory");
    let data_path = temp_dir.path().join("terminal-history.norito");
    let index_path = temp_dir.path().join("terminal-history.index");
    let retention = NonZeroUsize::new(32).expect("non-zero terminal retention");
    for height in 1_u64..=600 {
        let payload =
            norito::to_bytes(&DummySidecar { height }).expect("encode dummy lane history");
        assert!(Kura::append_indexed_sidecar(
            &data_path,
            &index_path,
            height,
            &payload,
            "dummy terminal lane history",
            FsyncMode::Always,
            None,
        ));
    }
    assert!(Kura::prune_indexed_sidecars_through_terminal_frontier(
        &data_path,
        &index_path,
        550,
        retention,
        "dummy terminal lane history",
    ));
    let mut index = std::fs::File::open(&index_path).expect("open compact terminal index");
    let index_len = index
        .metadata()
        .expect("compact terminal index metadata")
        .len();
    let layout = SidecarIndexLayout::read_from(&mut index, index_len)
        .expect("decode compact terminal index layout");
    assert_eq!(layout.base_height, 519);
    assert_eq!(layout.entry_count, 82);
    assert!(
        Kura::read_indexed_sidecar_from_paths(
            518,
            &data_path,
            &index_path,
            norito::decode_from_bytes::<DummySidecar>,
            "dummy terminal lane history",
        )
        .is_none()
    );
    for height in [519_u64, 550, 551, 600] {
        assert_eq!(
            Kura::read_indexed_sidecar_from_paths(
                height,
                &data_path,
                &index_path,
                norito::decode_from_bytes::<DummySidecar>,
                "dummy terminal lane history",
            ),
            Some(DummySidecar { height }),
            "terminal diagnostics and every post-frontier slot must survive"
        );
    }
}
#[test]
fn terminal_frontier_compaction_retains_sparse_required_evidence() {
    let temp_dir = TempDir::new().expect("temporary sidecar directory");
    let data_path = temp_dir.path().join("terminal-required.norito");
    let index_path = temp_dir.path().join("terminal-required.index");
    for height in 1_u64..=600 {
        let payload =
            norito::to_bytes(&DummySidecar { height }).expect("encode dummy lane history");
        assert!(Kura::append_indexed_sidecar(
            &data_path,
            &index_path,
            height,
            &payload,
            "dummy required terminal history",
            FsyncMode::Always,
            None,
        ));
    }
    let required_heights = BTreeSet::from([7_u64, 400]);
    assert!(
        Kura::prune_indexed_sidecars_through_terminal_frontier_with_required_heights(
            &data_path,
            &index_path,
            550,
            NonZeroUsize::new(32).expect("non-zero terminal retention"),
            &required_heights,
            "dummy required terminal history",
        )
    );
    let mut index = std::fs::File::open(&index_path).expect("open required terminal index");
    let index_len = index
        .metadata()
        .expect("required terminal index metadata")
        .len();
    let layout = SidecarIndexLayout::read_from(&mut index, index_len)
        .expect("decode required terminal index layout");
    assert_eq!(layout.base_height, 7);
    assert_eq!(layout.entry_count, 594);
    for height in [7_u64, 400, 519, 550, 551, 600] {
        assert_eq!(
            Kura::read_indexed_sidecar_from_paths(
                height,
                &data_path,
                &index_path,
                norito::decode_from_bytes::<DummySidecar>,
                "dummy required terminal history",
            ),
            Some(DummySidecar { height }),
            "required evidence and the policy window must survive compaction",
        );
    }
    for height in [6_u64, 8, 399, 401, 518] {
        assert!(
            Kura::read_indexed_sidecar_from_paths::<DummySidecar, _>(
                height,
                &data_path,
                &index_path,
                norito::decode_from_bytes::<DummySidecar>,
                "dummy required terminal history",
            )
            .is_none(),
            "an unrequired height outside the policy window must be pruned",
        );
    }
}
#[test]
fn terminal_frontier_compaction_missing_required_evidence_is_byte_exact() {
    let temp_dir = TempDir::new().expect("temporary sidecar directory");
    let data_path = temp_dir.path().join("terminal-required-missing.norito");
    let index_path = temp_dir.path().join("terminal-required-missing.index");
    for height in 1_u64..=10 {
        let payload =
            norito::to_bytes(&DummySidecar { height }).expect("encode dummy lane history");
        assert!(Kura::append_indexed_sidecar(
            &data_path,
            &index_path,
            height,
            &payload,
            "dummy missing required terminal history",
            FsyncMode::Always,
            None,
        ));
    }
    let original_data = fs::read(&data_path).expect("read original required data");
    let original_index = fs::read(&index_path).expect("read original required index");
    assert!(
        !Kura::prune_indexed_sidecars_through_terminal_frontier_with_required_heights(
            &data_path,
            &index_path,
            10,
            NonZeroUsize::new(1).expect("non-zero terminal retention"),
            &BTreeSet::from([11_u64]),
            "dummy missing required terminal history",
        ),
        "compaction must fail before replacing a pair that lacks required evidence",
    );
    assert_eq!(
        fs::read(&data_path).expect("read preserved required data"),
        original_data,
    );
    assert_eq!(
        fs::read(&index_path).expect("read preserved required index"),
        original_index,
    );
    assert!(!data_path.with_extension("norito.tmp").exists());
    assert!(!index_path.with_extension("index.tmp").exists());
}
#[test]
fn terminal_evidence_recovery_rejects_temp_pair_that_omits_required_height() {
    let temp_dir = TempDir::new().expect("temporary sidecar directory");
    let data_path = temp_dir.path().join("terminal-required-recovery.norito");
    let index_path = temp_dir.path().join("terminal-required-recovery.index");
    for height in 1_u64..=3 {
        let payload =
            norito::to_bytes(&DummySidecar { height }).expect("encode dummy lane history");
        assert!(Kura::append_indexed_sidecar(
            &data_path,
            &index_path,
            height,
            &payload,
            "dummy required recovery history",
            FsyncMode::Always,
            None,
        ));
    }
    let original_data = fs::read(&data_path).expect("read original recovery data");
    let original_index = fs::read(&index_path).expect("read original recovery index");
    let retained_payload =
        norito::to_bytes(&DummySidecar { height: 3 }).expect("encode temp retained payload");
    let temp_data_path = data_path.with_extension("norito.tmp");
    let temp_index_path = index_path.with_extension("index.tmp");
    fs::write(&temp_data_path, &retained_payload).expect("write compacted temp data");
    let mut temp_index = std::fs::File::create(&temp_index_path).expect("create compacted index");
    temp_index
        .write_all(&SidecarIndexLayout::base_header(3))
        .expect("write compacted index header");
    temp_index
        .write_all(
            &SidecarIndexEntry {
                offset: 0,
                len: u64::try_from(retained_payload.len()).expect("payload length fits u64"),
            }
            .to_bytes(),
        )
        .expect("write compacted index entry");
    temp_index.flush().expect("flush compacted index");
    temp_index.sync_data().expect("sync compacted index");

    assert!(
        !Kura::recover_indexed_sidecar_artifacts_with_required_heights(
            &data_path,
            &index_path,
            &BTreeSet::from([1_u64]),
            "dummy required recovery history",
        ),
        "recovery must not promote a crash temp that omits required evidence",
    );
    assert_eq!(
        fs::read(&data_path).expect("read unchanged recovery data"),
        original_data,
    );
    assert_eq!(
        fs::read(&index_path).expect("read unchanged recovery index"),
        original_index,
    );
    assert!(temp_data_path.exists() && temp_index_path.exists());
}
#[test]
fn terminal_frontier_compaction_fails_before_replacing_malformed_pending_slot() {
    let temp_dir = TempDir::new().expect("temporary sidecar directory");
    let data_path = temp_dir.path().join("terminal-malformed.norito");
    let index_path = temp_dir.path().join("terminal-malformed.index");
    for height in 1_u64..=3 {
        let payload =
            norito::to_bytes(&DummySidecar { height }).expect("encode dummy lane history");
        assert!(Kura::append_indexed_sidecar(
            &data_path,
            &index_path,
            height,
            &payload,
            "dummy malformed terminal history",
            FsyncMode::Always,
            None,
        ));
    }
    let mut index = std::fs::OpenOptions::new()
        .write(true)
        .open(&index_path)
        .expect("open terminal index for corruption");
    index
        .seek(SeekFrom::Start(
            INDEXED_SIDECAR_BASE_HEADER_SIZE_U64 + 2 * PIPELINE_INDEX_ENTRY_SIZE_U64 + 8_u64,
        ))
        .expect("seek to pending entry length");
    index
        .write_all(&STRICT_INIT_MAX_BLOCK_BYTES.saturating_add(1).to_le_bytes())
        .expect("forge oversized pending entry");
    index.sync_all().expect("sync forged pending entry");
    drop(index);
    let corrupted_index = std::fs::read(&index_path).expect("read forged index");
    let original_data = std::fs::read(&data_path).expect("read original data");
    assert!(
        !Kura::prune_indexed_sidecars_through_terminal_frontier(
            &data_path,
            &index_path,
            2,
            NonZeroUsize::new(1).expect("non-zero retention"),
            "dummy malformed terminal history",
        ),
        "terminal compaction must fail closed instead of dropping a later pending slot"
    );
    assert_eq!(
        std::fs::read(&index_path).expect("read preserved forged index"),
        corrupted_index
    );
    assert_eq!(
        std::fs::read(&data_path).expect("read preserved data"),
        original_data
    );
    assert!(!data_path.with_extension("norito.tmp").exists());
    assert!(!index_path.with_extension("index.tmp").exists());
}
