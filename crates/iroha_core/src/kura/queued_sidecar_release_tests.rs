use super::*;
use std::{
    cell::Cell,
    collections::BTreeMap,
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Wake, Waker},
};

thread_local! {
    static UNWIND_AFTER_FENCE: Cell<Option<usize>> = const { Cell::new(None) };
}

// Test-only acquired-prefix unwind, never a production runtime switch.
pub(super) fn fence_boundary(stage: usize) {
    if UNWIND_AFTER_FENCE.with(|fault| {
        if fault.get() == Some(stage) {
            fault.set(None);
            true
        } else {
            false
        }
    }) {
        std::panic::resume_unwind(Box::new("original queued sidecar fence unwind"));
    }
}

struct Probe {
    kura: Arc<Kura>,
    pipeline_count: usize,
    proofs: Vec<(FastpqProofSnapshot, usize)>,
    calls: AtomicUsize,
    violations: AtomicUsize,
    reentered: AtomicUsize,
}

impl Wake for Probe {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        let physical_free = self
            .kura
            .publication_fences_for_test()
            .iter()
            .all(|(_, fence)| fence.try_lock().is_some());
        let store_free = self.kura.block_store.try_lock().is_some();
        let pipeline_matches = self
            .kura
            .pipeline_sidecar_queue
            .try_lock()
            .is_some_and(|queue| queue.len() == self.pipeline_count);
        let proofs_match = self
            .kura
            .fastpq_proof_queue
            .try_lock()
            .is_some_and(|queue| {
                queue
                    .iter()
                    .map(|item| (&item.snapshot, item.retries))
                    .eq(self
                        .proofs
                        .iter()
                        .map(|(snapshot, retries)| (snapshot, *retries)))
            });
        let mut valid = physical_free && store_free && pipeline_matches && proofs_match;
        if physical_free && store_free {
            let result = self.kura.try_publication_lease();
            if matches!(result, Err(KuraPublicationPreparationError::Busy { .. })) {
                valid = false;
            } else {
                self.reentered.fetch_add(1, Ordering::SeqCst);
            }
            drop(result);
        }
        if !valid {
            self.violations.fetch_add(1, Ordering::SeqCst);
        }
        self.calls.fetch_add(1, Ordering::SeqCst);
    }
}

fn observe_original_release<T>(
    kura: &Arc<Kura>,
    fence: usize,
    pipeline_count: usize,
    proofs: Vec<(FastpqProofSnapshot, usize)>,
    run: impl FnOnce() -> T,
) -> T {
    let budget = kura.transaction_history_budget();
    let mut registration = crate::unit_test_support::release_registration(&budget);
    let original = kura.publication_fences_for_test()[fence]
        .1
        .observe_release();
    let mut wait = original.wait_for_release(&mut registration);
    let probe = Arc::new(Probe {
        kura: Arc::clone(kura),
        pipeline_count,
        proofs,
        calls: AtomicUsize::new(0),
        violations: AtomicUsize::new(0),
        reentered: AtomicUsize::new(0),
    });
    let waker = Waker::from(Arc::clone(&probe));
    assert!(
        Pin::new(&mut wait)
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    drop(kura.publication_fences_for_test()[2].1.lock());
    assert_eq!(
        probe.calls.load(Ordering::SeqCst),
        0,
        "unrelated physical release"
    );
    assert!(
        Pin::new(&mut wait)
            .poll(&mut Context::from_waker(&waker))
            .is_pending()
    );
    let result = run();
    assert_eq!(
        probe.calls.load(Ordering::SeqCst),
        1,
        "one original physical release"
    );
    assert_eq!(
        probe.violations.load(Ordering::SeqCst),
        0,
        "original queued sidecar notice must follow outer fences and finalized queues"
    );
    assert_eq!(probe.reentered.load(Ordering::SeqCst), 1);
    assert!(
        Pin::new(&mut wait)
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
    );
    drop(wait);
    assert!(registration.belongs_to(&budget));
    let reserved = budget.reserved_bytes();
    let charge = iroha_allocation::release::ReleaseRegistration::allocation_layout().size();
    assert!(reserved >= charge);
    drop(registration);
    assert_eq!(budget.reserved_bytes(), reserved - charge);
    result
}

fn fixture() -> (Arc<Kura>, PipelineRecoverySidecar, FastpqProofSnapshot) {
    use iroha_data_model::fastpq::{
        FastpqArtifactIdentityDescriptionV1, FastpqCommitmentDescriptionV1,
        FastpqOrderedCompactAirCommitmentsV1, FastpqProofKindV1,
    };
    let kura = Kura::blank_kura_for_testing();
    kura.set_fastpq_proof_sidecar_limits_for_testing(8, usize::MAX, 2);
    let block_hash =
        HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(b"retained diagnostic block"));
    let sidecar = PipelineRecoverySidecar::new(
        1,
        block_hash,
        PipelineDagSnapshot {
            fingerprint: [0x33; 32],
            key_count: 0,
        },
        Vec::new(),
    );
    let snapshot = FastpqProofSnapshot {
        height: 1,
        block_hash,
        entry_hash: Hash::new(b"retained diagnostic entry"),
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
            public_statement_digest: Hash::new(b"public statement").into(),
            artifact_digest: Hash::new(b"artifact bytes").into(),
            inner_bundle_digest: Hash::new(b"inner bundle").into(),
            artifact_bytes: 14,
            commitments: FastpqCommitmentDescriptionV1::OrderedCompactAir(
                FastpqOrderedCompactAirCommitmentsV1 {
                    segment_count: 1,
                    segment_air_row_roots: vec![
                        iroha_data_model::fastpq::FastpqCommitmentV1::from_bytes([0x41; 32]),
                    ],
                },
            ),
        },
    };
    (kura, sidecar, snapshot)
}

fn directory(kura: &Kura) -> PathBuf {
    kura.store_dir().unwrap().join(PIPELINE_DIR_NAME)
}

fn inventory(kura: &Kura) -> BTreeMap<PathBuf, Vec<u8>> {
    let directory = directory(kura);
    if !directory.exists() {
        return BTreeMap::new();
    }
    if directory.is_file() {
        let bytes = std::fs::read(&directory).unwrap();
        return BTreeMap::from([(directory, bytes)]);
    }
    std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            let bytes = std::fs::read(&path).unwrap();
            (path, bytes)
        })
        .collect()
}

fn assert_exact_sidecar(kura: &Kura, sidecar: &PipelineRecoverySidecar) {
    let payload = sidecar.encode_framed().unwrap();
    assert_eq!(
        kura.read_pipeline_metadata_payload(1)
            .unwrap()
            .encode_framed()
            .unwrap(),
        payload
    );
    let mut index = SidecarIndexLayout::base_header(1).to_vec();
    index.extend_from_slice(
        &SidecarIndexEntry {
            offset: 0,
            len: u64::try_from(payload.len()).unwrap(),
        }
        .to_bytes(),
    );
    assert_eq!(
        inventory(kura),
        BTreeMap::from([
            (directory(kura).join(PIPELINE_SIDECARS_DATA_FILE), payload),
            (directory(kura).join(PIPELINE_SIDECARS_INDEX_FILE), index),
        ])
    );
}

fn enqueue_pipeline(kura: &Kura, sidecar: PipelineRecoverySidecar) {
    assert_eq!(
        kura.enqueue_pipeline_metadata(sidecar),
        PipelineSidecarEnqueueResult::Enqueued { queue_depth: 1 }
    );
}

fn enqueue_proof(kura: &Kura, snapshot: FastpqProofSnapshot) {
    assert_eq!(
        kura.enqueue_fastpq_proof_snapshot(snapshot),
        FastpqProofEnqueueResult::Enqueued { queue_depth: 1 }
    );
}

fn drain_real_writer(kura: &Kura) {
    let shutdown = ShutdownSignal::new();
    shutdown.send();
    kura.receive_blocks_loop(&shutdown);
}

#[test]
fn original_direct_pipeline_success_notifies_after_outer_prune() {
    let (kura, sidecar, _) = fixture();
    observe_original_release(&kura, 3, 0, vec![], || {
        kura.write_pipeline_metadata(&sidecar)
    });
    assert_exact_sidecar(&kura, &sidecar);
}

#[test]
fn original_direct_pipeline_io_refusal_retains_exact_bytes() {
    let (kura, sidecar, _) = fixture();
    std::fs::write(directory(&kura), b"original namespace blocker").unwrap();
    let before = inventory(&kura);
    assert_eq!(
        std::fs::create_dir_all(directory(&kura))
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::AlreadyExists
    );
    observe_original_release(&kura, 3, 0, vec![], || {
        kura.write_pipeline_metadata(&sidecar)
    });
    assert_eq!(inventory(&kura), before);
    assert!(kura.read_pipeline_metadata_payload(1).is_none());
}

#[test]
fn original_queued_pipeline_writer_notifies_after_outer_prune() {
    let (kura, sidecar, _) = fixture();
    enqueue_pipeline(&kura, sidecar.clone());
    observe_original_release(&kura, 3, 0, vec![], || drain_real_writer(&kura));
    assert!(kura.pipeline_sidecar_queue.lock().is_empty());
    assert_exact_sidecar(&kura, &sidecar);
}

#[test]
fn original_queued_fastpq_writer_notifies_after_attachment_publication() {
    let (kura, mut sidecar, snapshot) = fixture();
    kura.write_pipeline_metadata(&sidecar);
    enqueue_proof(&kura, snapshot.clone());
    observe_original_release(&kura, 3, 0, vec![], || drain_real_writer(&kura));
    sidecar.fastpq_proofs.push(snapshot);
    assert!(kura.fastpq_proof_queue.lock().is_empty());
    assert_eq!(
        kura.read_pipeline_metadata_payload(1)
            .unwrap()
            .encode_framed()
            .unwrap(),
        sidecar.encode_framed().unwrap()
    );
    let before = inventory(&kura);
    // An exact duplicate attachment is written logically, without changing physical bytes.
    let snapshot = sidecar.fastpq_proofs[0].clone();
    enqueue_proof(&kura, snapshot);
    assert_eq!(
        kura.flush_fastpq_proof_snapshots(&mut kura.sidecar_lock.defer_notifications()),
        1
    );
    assert_eq!(inventory(&kura), before);
}

#[test]
fn original_queued_fastpq_retry_and_exhaustion_finalize_before_notice() {
    for (blocked_directory, max_retries) in [(false, 2), (true, 2), (false, 1)] {
        let (kura, _, snapshot) = fixture();
        kura.set_fastpq_proof_sidecar_limits_for_testing(8, usize::MAX, max_retries);
        if blocked_directory {
            std::fs::write(directory(&kura), b"original retry blocker").unwrap();
        }
        let before = inventory(&kura);
        enqueue_proof(&kura, snapshot.clone());
        let expected = if max_retries == 1 {
            vec![]
        } else {
            vec![(snapshot.clone(), 1)]
        };
        observe_original_release(&kura, 3, 0, expected.clone(), || drain_real_writer(&kura));
        assert_eq!(
            kura.fastpq_proof_queue
                .lock()
                .iter()
                .map(|item| (item.snapshot.clone(), item.retries))
                .collect::<Vec<_>>(),
            expected
        );
        assert_eq!(inventory(&kura), before);
    }
}

#[test]
fn original_queued_fastpq_hash_refusal_retains_exact_bytes() {
    let (kura, sidecar, mut snapshot) = fixture();
    kura.write_pipeline_metadata(&sidecar);
    let before = inventory(&kura);
    snapshot.block_hash =
        HashOf::<BlockHeader>::from_untyped_unchecked(Hash::new(b"different candidate"));
    enqueue_proof(&kura, snapshot);
    observe_original_release(&kura, 3, 0, vec![], || drain_real_writer(&kura));
    assert!(kura.fastpq_proof_queue.lock().is_empty());
    assert_eq!(inventory(&kura), before);
    assert_exact_sidecar(&kura, &sidecar);
}

#[test]
fn original_standalone_fastpq_flush_notifies_after_retry_queue_finalizes() {
    let (kura, _, snapshot) = fixture();
    enqueue_proof(&kura, snapshot.clone());
    let written = observe_original_release(&kura, 3, 0, vec![(snapshot.clone(), 1)], || {
        kura.flush_fastpq_proof_snapshots(&mut kura.sidecar_lock.defer_notifications())
    });
    assert_eq!(written, 0);
    let queue = kura.fastpq_proof_queue.lock();
    assert_eq!(queue.len(), 1);
    assert_eq!(queue[0].snapshot, snapshot);
    assert_eq!(queue[0].retries, 1);
    assert!(inventory(&kura).is_empty());
}

#[test]
fn original_queued_sidecar_unwind_notifies_after_each_acquired_prefix() {
    for mode in 0..3 {
        for stage in [1, if mode == 2 { 3 } else { 2 }] {
            let (kura, sidecar, snapshot) = fixture();
            if mode == 1 {
                enqueue_pipeline(&kura, sidecar.clone());
            }
            if mode == 2 {
                enqueue_proof(&kura, snapshot.clone());
            }
            let before = inventory(&kura);
            let pipeline_count = usize::from(mode == 1 && stage == 1);
            let proofs = if mode == 2 && stage == 1 {
                vec![(snapshot, 0)]
            } else {
                vec![]
            };
            let fence = if stage == 1 { 0 } else { 3 };
            observe_original_release(&kura, fence, pipeline_count, proofs, || {
                UNWIND_AFTER_FENCE.with(|fault| fault.set(Some(stage)));
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    if mode == 0 {
                        kura.write_pipeline_metadata(&sidecar);
                    } else {
                        drain_real_writer(&kura);
                    }
                }));
                UNWIND_AFTER_FENCE.with(|fault| fault.set(None));
                let error = result.expect_err("unwind after original acquired sidecar fence");
                assert_eq!(
                    error.downcast_ref::<&'static str>(),
                    Some(&"original queued sidecar fence unwind")
                );
            });
            assert_eq!(inventory(&kura), before);
        }
    }
}
