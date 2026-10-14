//! Benchmarks for production WSV state commit and derived-index paths.

#[cfg(feature = "bench")]
use core::num::NonZeroU64;
#[cfg(feature = "bench")]
use criterion::{BatchSize, Criterion};
#[cfg(feature = "bench")]
use iroha_core::{
    da::{LaneEpoch, receipts::DaReceiptCursorIndex},
    kura::Kura,
    query::store::LiveQueryStore,
    state::{State, World},
};
#[cfg(feature = "bench")]
use iroha_crypto::{Hash, Signature};
#[cfg(feature = "bench")]
use iroha_data_model::{
    da::{
        commitment::{DaCommitmentRecord, DaProofScheme, RetentionClass},
        types::{BlobDigest, StorageTicketId},
    },
    sorafs::pin_registry::ManifestDigest,
};
#[cfg(feature = "bench")]
use iroha_model_base::topology::LaneId;
#[cfg(feature = "bench")]
use std::{hint::black_box, time::Duration};
#[cfg(feature = "bench")]
fn bench_state_write_lock_heavy_world_commit(c: &mut Criterion) {
    let mut group = c.benchmark_group("state_write_lock_heavy_world_commit");
    group.sample_size(10);
    group.warm_up_time(Duration::from_millis(100));
    for account_count in [128_usize, 2_048] {
        group.bench_function(format!("accounts_{account_count}"), |b| {
            b.iter_batched(
                || {
                    let kura = Kura::blank_kura_for_testing();
                    let query = LiveQueryStore::start_test();
                    State::new_for_testing(World::default(), kura, query)
                },
                |state| {
                    let elapsed = state
                        .commit_heavy_world_accounts_for_bench(
                            NonZeroU64::new(1).expect("non-zero block height"),
                            account_count,
                        )
                        .expect("commit heavy world account benchmark block");
                    assert!(elapsed > Duration::ZERO);
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}
#[cfg(feature = "bench")]
fn receipt_cursor_record(lane_id: LaneId, sequence: u64) -> DaCommitmentRecord {
    DaCommitmentRecord::new(
        lane_id,
        1,
        sequence,
        BlobDigest::new([0xAA; 32]),
        ManifestDigest::new([0xBB; 32]),
        DaProofScheme::MerkleSha256,
        Hash::prehashed([0xCC; 32]),
        None,
        RetentionClass::default(),
        StorageTicketId::new([0xDD; 32]),
        Signature::try_from_bytes(&[0x33; 64])
            .expect("checked DA receipt cursor benchmark signature"),
    )
}
#[cfg(feature = "bench")]
fn bench_da_receipt_cursor_sparse_bundle_commit(c: &mut Criterion) {
    let mut group = c.benchmark_group("da_receipt_cursor_sparse_bundle_commit");
    group.sample_size(20);
    group.warm_up_time(Duration::from_millis(100));
    for cursor_count in [128_u32, 2_048] {
        let mut base = DaReceiptCursorIndex::default();
        for lane in 0..cursor_count {
            base.record(LaneEpoch::new(LaneId::new(lane), 1), 1, 1)
                .expect("seed DA receipt cursor benchmark index");
        }
        let record = receipt_cursor_record(LaneId::new(cursor_count - 1), 2);
        group.bench_function(format!("indexed_lane_epochs_{cursor_count}"), |b| {
            b.iter_batched(
                || base.clone(),
                |mut cursors| {
                    black_box(
                        cursors
                            .record_bundle(2, std::slice::from_ref(&record))
                            .expect("commit DA receipt cursor benchmark bundle"),
                    );
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}
/// Entry point for the benchmark binary.
#[cfg(feature = "bench")]
fn main() {
    let mut c = Criterion::default().configure_from_args();
    bench_state_write_lock_heavy_world_commit(&mut c);
    bench_da_receipt_cursor_sparse_bundle_commit(&mut c);
    c.final_summary();
}
/// Entry point used when benchmark-only helpers are not compiled.
#[cfg(not(feature = "bench"))]
fn main() {}
