//! Complete real-registry gathers, source ownership and exact integer failures.

use std::{
    collections::BTreeMap,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use super::*;
use crate::kura::{PipelineDagSnapshot, PipelineRecoverySidecar};
use iroha_crypto::{Hash, HashOf};

fn owner_fixture() -> Arc<Kura> {
    let kura = Kura::blank_kura_for_testing();
    kura.reconcile_physical_resource_inventory().unwrap();
    kura.reconcile_resident_resource_inventory().unwrap();
    assert!(kura.resource_inventory_snapshot().is_ok());
    kura
}

fn samples(metrics: &Metrics) -> BTreeMap<String, u64> {
    let text = metrics.try_to_string().expect("real registry exposition");
    let mut result = BTreeMap::new();
    for line in text.lines().filter(|line| line.starts_with(PREFIX)) {
        let (key, value) = line.split_once(' ').expect("metric sample");
        let value = value.parse::<u64>().expect("exact integral decimal sample");
        assert!(
            result.insert(key.to_owned(), value).is_none(),
            "duplicate sample: {key}"
        );
    }
    result
}

fn scalar(rows: &BTreeMap<String, u64>, name: &str) -> u64 {
    rows[&format!("{PREFIX}{name}")]
}

fn component(rows: &BTreeMap<String, u64>, name: &str, family: &str) -> u64 {
    rows[&format!("{PREFIX}{name}{{family=\"{family}\"}}")]
}

fn unavailable(rows: &BTreeMap<String, u64>, reason: &str) {
    assert_eq!(
        rows.len(),
        2,
        "no stale numeric vector may survive: {rows:?}"
    );
    assert_eq!(scalar(rows, "available"), 0);
    assert_eq!(rows[&format!("{PREFIX}status{{reason=\"{reason}\"}}")], 1);
}

fn assert_complete(rows: &BTreeMap<String, u64>) {
    // Independent expected inventory: do not derive the expected label set from
    // the production mapper which this assertion protects.
    let names = [
        "resident_canonical",
        "resident_transaction",
        "resident_frontier",
        "resident_queue",
        "canonical_index",
        "canonical_hashes",
        "pipeline_index",
        "query_marker_records",
        "evidence_key_records",
        "storage_bytes",
    ];
    assert_eq!(names.len(), 10);
    assert_eq!(rows.len(), 10 * 5 + 10);
    assert_eq!(scalar(rows, "available"), 1);
    assert_eq!(rows[&format!("{PREFIX}status{{reason=\"available\"}}")], 1);
    for field in [
        "resident_associations",
        "persisted_entries",
        "index_bytes",
        "temporary_index_bytes",
        "storage_bytes",
    ] {
        let total = names
            .iter()
            .map(|family| component(rows, field, family))
            .sum::<u64>();
        assert_eq!(
            total,
            scalar(rows, &format!("{field}_sum")),
            "field={field}"
        );
    }
    assert_eq!(
        scalar(rows, "represented_entries"),
        scalar(rows, "resident_associations_sum") + scalar(rows, "persisted_entries_sum")
    );
}

#[test]
fn resource_gather_registers_exact_inventory_and_reads_source_once() {
    let kura = owner_fixture();
    let metrics = Metrics::default();
    let collector = ResourceCollector::new(Arc::downgrade(&kura)).unwrap();
    assert_eq!(collector.desc().len(), 15);
    assert_eq!(collector.source_reads.load(Ordering::Relaxed), 0);
    metrics
        .register_collector(Box::new(collector.clone()))
        .unwrap();
    assert_eq!(collector.source_reads.load(Ordering::Relaxed), 0);
    let expected = kura.resource_inventory_snapshot().unwrap();
    for count in 1..=2 {
        let rows = samples(&metrics);
        assert_complete(&rows);
        assert_eq!(scalar(&rows, "generation"), expected.generation);
        assert_eq!(scalar(&rows, "fault_count"), expected.fault_count);
        assert_eq!(
            scalar(&rows, "storage_bytes_sum"),
            expected.total.storage_bytes
        );
        assert_eq!(collector.source_reads.load(Ordering::Relaxed), count);
    }
}

#[test]
fn resource_gather_tracks_actual_sidecar_bytes_and_resident_queue_memberships() {
    let kura = owner_fixture();
    let key = &iroha_test_samples::SAMPLE_GENESIS_ACCOUNT_KEYPAIR;
    let mut block: iroha_data_model::block::SignedBlock =
        crate::block::ValidBlock::new_dummy_and_modify_header(key.private_key(), |header| {
            header.set_height(std::num::NonZeroU64::new(1).unwrap());
        })
        .into();
    crate::kura::tests::install_network_index_test_outputs(&mut block, Vec::new());
    let signature =
        iroha_crypto::SignatureOf::try_from_hash(key.private_key(), block.header().hash()).unwrap();
    block
        .replace_signatures(
            iroha_data_model::block::BlockSignatures::try_from_iter([
                iroha_data_model::block::BlockSignature::new(0, signature),
            ])
            .expect("at most 31 block signatures"),
        )
        .unwrap();
    let block_hash = block.hash();
    kura.store_block(crate::block::reserve_block_for_tests().initialize(block))
        .unwrap();
    assert_eq!(
        kura.get_durable_block_hash(std::num::NonZeroUsize::new(1).unwrap()),
        Some(block_hash)
    );
    let metrics = Metrics::default();
    kura.register_resource_telemetry(&metrics).unwrap();
    let before = samples(&metrics);
    assert_complete(&before);
    let sidecar = PipelineRecoverySidecar::new(
        1,
        block_hash,
        PipelineDagSnapshot {
            fingerprint: [9; 32],
            key_count: 7,
        },
        Vec::new(),
    );
    let encoded = sidecar.encode_framed().unwrap();
    kura.write_pipeline_metadata(&sidecar);
    assert_eq!(
        kura.read_pipeline_metadata(1)
            .unwrap()
            .encode_framed()
            .unwrap(),
        encoded
    );
    let written = samples(&metrics);
    assert_complete(&written);
    assert_eq!(
        component(&written, "persisted_entries", "pipeline_index"),
        1
    );
    assert_eq!(
        component(&written, "index_bytes", "pipeline_index"),
        32 + 16
    );
    assert_eq!(
        scalar(&written, "storage_bytes_sum") - scalar(&before, "storage_bytes_sum"),
        u64::try_from(encoded.len()).unwrap() + 32 + 16
    );
    kura.pipeline_sidecar_queue
        .lock()
        .push_back(sidecar.clone());
    let queued = samples(&metrics);
    assert_complete(&queued);
    assert_eq!(
        component(&queued, "resident_associations", "resident_queue"),
        component(&written, "resident_associations", "resident_queue") + 1
    );
    assert_eq!(
        scalar(&queued, "storage_bytes_sum"),
        scalar(&written, "storage_bytes_sum")
    );
    assert_eq!(
        kura.pipeline_sidecar_queue
            .lock()
            .pop_front()
            .unwrap()
            .height,
        1
    );
    let drained = samples(&metrics);
    assert_complete(&drained);
    assert_eq!(
        scalar(&drained, "resident_associations_sum"),
        scalar(&written, "resident_associations_sum")
    );
    kura.write_pipeline_metadata(&sidecar);
    let retried = samples(&metrics);
    assert_complete(&retried);
    assert_eq!(
        scalar(&retried, "storage_bytes_sum"),
        scalar(&written, "storage_bytes_sum")
    );
    assert_eq!(
        scalar(&retried, "persisted_entries_sum"),
        scalar(&written, "persisted_entries_sum")
    );
}

#[test]
fn resource_gather_rejects_empty_and_expired_sources_without_retaining_owner() {
    let metrics = Metrics::default();
    metrics
        .register_collector(Box::new(ResourceCollector::new(Weak::new()).unwrap()))
        .unwrap();
    unavailable(&samples(&metrics), "owner_unavailable");
    let kura = owner_fixture();
    let weak = Arc::downgrade(&kura);
    let metrics = Metrics::default();
    kura.register_resource_telemetry(&metrics).unwrap();
    assert_complete(&samples(&metrics));
    drop(kura);
    assert!(
        weak.upgrade().is_none(),
        "registry must not keep Kura alive"
    );
    unavailable(&samples(&metrics), "owner_unavailable");
}

#[test]
fn resource_gather_registration_rejects_duplicate_owner_and_leaves_original_explicit() {
    let first = owner_fixture();
    let second = owner_fixture();
    let metrics = Metrics::default();
    first.register_resource_telemetry(&metrics).unwrap();
    assert_complete(&samples(&metrics));
    assert!(matches!(
        second.register_resource_telemetry(&metrics),
        Err(CollectorRegistrationError::AlreadyReg)
    ));
    drop(first);
    unavailable(&samples(&metrics), "owner_unavailable");
    assert!(
        second.resource_inventory_snapshot().is_ok(),
        "second owner must not replace the expired original"
    );
}

#[test]
fn resource_gather_omits_previous_vector_for_every_inventory_failure() {
    for (reason, label) in [
        (Unavailable::Unregistered, "unregistered"),
        (Unavailable::Busy, "busy"),
        (Unavailable::Interrupted, "interrupted"),
        (Unavailable::Arithmetic, "arithmetic"),
        (Unavailable::GenerationChanged, "generation_changed"),
        (Unavailable::OwnerMismatch, "owner_mismatch"),
        (Unavailable::InvalidInventory, "invalid_inventory"),
    ] {
        let kura = owner_fixture();
        let metrics = Metrics::default();
        kura.register_resource_telemetry(&metrics).unwrap();
        assert_complete(&samples(&metrics));
        kura.resource_inventory
            .invalidate(Family::ResidentCanonical.mask(), reason);
        assert_eq!(kura.resource_inventory_snapshot().unwrap_err(), reason);
        unavailable(&samples(&metrics), label);
    }
}

#[test]
fn resource_gather_uses_recovery_wrapper_and_never_repairs_unavailable_inventory() {
    let kura = owner_fixture();
    let metrics = Metrics::default();
    kura.register_resource_telemetry(&metrics).unwrap();
    assert_complete(&samples(&metrics));
    let generation = kura.resource_inventory_snapshot().unwrap().generation;
    kura.prune_in_progress.store(true, Ordering::Release);
    assert_eq!(
        kura.resource_inventory.try_snapshot().unwrap().generation,
        generation
    );
    unavailable(&samples(&metrics), "busy");
    kura.prune_in_progress.store(false, Ordering::Release);
    kura.canonical_storage_poisoned
        .store(true, Ordering::Release);
    unavailable(&samples(&metrics), "invalid_inventory");
    assert!(kura.canonical_storage_poisoned.load(Ordering::Acquire));
    assert_eq!(
        kura.resource_inventory.try_snapshot().unwrap().generation,
        generation
    );
}

#[test]
fn resource_gather_does_not_wait_for_storage_owner_locks() {
    let kura = owner_fixture();
    let metrics = Arc::new(Metrics::default());
    kura.register_resource_telemetry(&metrics).unwrap();
    assert_complete(&samples(&metrics));
    let prune = kura.prune_lock.lock();
    let canonical = kura.canonical_chain_lock.lock();
    let writer = kura.block_store_write_lock.lock();
    let store = kura.block_store.lock();
    let sidecar = kura.sidecar_lock.lock();
    let (tx, rx) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        tx.send(samples(&metrics)).unwrap();
    });
    let observed = rx.recv_timeout(std::time::Duration::from_secs(5));
    // Release locks before asserting, so a regression cannot strand the worker.
    drop(sidecar);
    drop(store);
    drop(writer);
    drop(canonical);
    drop(prune);
    worker.join().unwrap();
    assert_complete(&observed.expect("resource gather must not acquire storage owner locks"));
}

struct ProjectionCollector {
    collector: ResourceCollector,
    observation: Arc<Mutex<Snapshot>>,
}
impl Collector for ProjectionCollector {
    fn desc(&self) -> Vec<&CollectorDesc> {
        self.collector.desc()
    }
    fn collect(&self) -> Vec<proto::MetricFamily> {
        self.collector
            .project(Ok(&self.observation.lock().unwrap()))
    }
}
fn projection_fixture() -> (Metrics, Arc<Mutex<Snapshot>>, Snapshot) {
    let kura = owner_fixture();
    let baseline = kura.resource_inventory_snapshot().unwrap();
    let observation = Arc::new(Mutex::new(baseline));
    let metrics = Metrics::default();
    metrics
        .register_collector(Box::new(ProjectionCollector {
            collector: ResourceCollector::new(Weak::new()).unwrap(),
            observation: observation.clone(),
        }))
        .unwrap();
    assert_complete(&samples(&metrics));
    (metrics, observation, baseline)
}
fn set_usage_field(usage: &mut Usage, column: usize, value: u64) {
    match column {
        0 => usage.resident_associations = value,
        1 => usage.persisted_entries = value,
        2 => usage.index_bytes = value,
        3 => usage.temporary_index_bytes = value,
        4 => usage.storage_bytes = value,
        _ => panic!("test field out of range"),
    }
}

#[test]
fn resource_gather_preserves_exact_integer_boundary_through_prometheus_text() {
    let (metrics, observation, baseline) = projection_fixture();
    for value in [MAX_EXACT_INTEGER - 1, MAX_EXACT_INTEGER] {
        for column in 0..5 {
            let mut expected = baseline;
            expected.components.fill(Usage::default());
            expected.total = Usage::default();
            set_usage_field(&mut expected.components[0], column, value);
            set_usage_field(&mut expected.total, column, value);
            expected.generation = value;
            expected.fault_count = value;
            *observation.lock().unwrap() = expected;
            let rows = samples(&metrics);
            assert_complete(&rows);
            assert_eq!(scalar(&rows, "generation"), value);
            assert_eq!(scalar(&rows, "fault_count"), value);
            assert_eq!(
                component(&rows, SPECS[4 + column].0, "resident_canonical"),
                value
            );
            assert_eq!(scalar(&rows, SPECS[9 + column].0), value);
        }
    }
}

#[test]
fn resource_gather_rejects_unrepresentable_fields_and_derived_total_without_stale_values() {
    let (metrics, observation, baseline) = projection_fixture();
    for target in 0..13 {
        *observation.lock().unwrap() = baseline;
        assert_complete(&samples(&metrics));
        let mut rejected = baseline;
        match target {
            0..=4 => set_usage_field(&mut rejected.components[0], target, MAX_EXACT_INTEGER + 1),
            5..=9 => set_usage_field(&mut rejected.total, target - 5, MAX_EXACT_INTEGER + 1),
            10 => rejected.generation = MAX_EXACT_INTEGER + 1,
            11 => rejected.fault_count = MAX_EXACT_INTEGER + 1,
            12 => {
                rejected.total.resident_associations = MAX_EXACT_INTEGER;
                rejected.total.persisted_entries = 1;
            }
            _ => unreachable!(),
        }
        *observation.lock().unwrap() = rejected;
        unavailable(&samples(&metrics), "numeric_range");
    }
    let mut overflow = baseline;
    overflow.total.resident_associations = u64::MAX;
    overflow.total.persisted_entries = 1;
    *observation.lock().unwrap() = overflow;
    unavailable(&samples(&metrics), "arithmetic");
}

#[test]
fn resource_concurrent_gathers_keep_whole_vectors_and_one_source_read_each() {
    let kura = owner_fixture();
    let collector = ResourceCollector::new(Arc::downgrade(&kura)).unwrap();
    // Each registry has its own unrelated exposition locks. Sharing one registry
    // would serialize these callers before reaching the source being tested.
    let registries = (0..4)
        .map(|_| {
            let metrics = Arc::new(Metrics::default());
            metrics
                .register_collector(Box::new(collector.clone()))
                .unwrap();
            metrics
        })
        .collect::<Vec<_>>();
    let running = Arc::new(AtomicBool::new(true));
    let writer_owner = kura.clone();
    let writer_running = running.clone();
    let sidecar = PipelineRecoverySidecar::new(
        1,
        HashOf::from_untyped_unchecked(Hash::new(b"concurrent resource queue")),
        PipelineDagSnapshot {
            fingerprint: [3; 32],
            key_count: 1,
        },
        Vec::new(),
    );
    let writer = std::thread::spawn(move || {
        while writer_running.load(Ordering::Acquire) {
            writer_owner
                .pipeline_sidecar_queue
                .lock()
                .push_back(sidecar.clone());
            std::thread::yield_now();
            assert!(
                writer_owner
                    .pipeline_sidecar_queue
                    .lock()
                    .pop_front()
                    .is_some()
            );
        }
    });
    // Start every reader before joining any of them so their gathers can overlap.
    let mut workers = Vec::with_capacity(registries.len());
    for registry in &registries {
        let metrics = registry.clone();
        workers.push(std::thread::spawn(move || {
            for _ in 0..8 {
                let rows = samples(&metrics);
                if scalar(&rows, "available") == 1 {
                    assert_complete(&rows);
                } else {
                    unavailable(&rows, "busy");
                }
            }
        }));
    }
    let results = workers
        .into_iter()
        .map(std::thread::JoinHandle::join)
        .collect::<Vec<_>>();
    running.store(false, Ordering::Release);
    writer.join().unwrap();
    for result in results {
        result.unwrap();
    }
    assert_eq!(collector.source_reads.load(Ordering::Relaxed), 32);
    assert_complete(&samples(&registries[0]));
    assert_eq!(collector.source_reads.load(Ordering::Relaxed), 33);
}

#[test]
fn integer_projection_preserves_every_checked_boundary() {
    for value in [
        0,
        1,
        u64::from(u32::MAX),
        1_u64 << 32,
        MAX_EXACT_INTEGER - 1,
        MAX_EXACT_INTEGER,
    ] {
        assert_eq!(integer_projection(value).to_string(), value.to_string());
    }
}
