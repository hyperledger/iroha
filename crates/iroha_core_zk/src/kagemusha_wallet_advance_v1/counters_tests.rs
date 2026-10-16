//! Storage counters: exact counts per durable-store primitive and provider bracket, thread
//! isolation, and the provider unit costs recorded for the storage baseline.

use super::{EventV1, KagemushaWalletStorageCountersV1 as Counters, count};
use crate::kagemusha_wallet_advance_v1::{
    KagemushaWalletAnchorPolicyV1 as Policy, KagemushaWalletCustodyDirV1 as Dir,
    KagemushaWalletEntryNameV1 as Name, KagemushaWalletFsV1, KagemushaWalletProviderV1,
    KagemushaWalletPublishOutcomeV1 as Outcome, KagemushaWalletRemoveOutcomeV1 as Removed,
    KagemushaWalletSlotIdV1, KagemushaWalletStdFsV1, kagemusha_wallet_prepare_root_v1,
    test_support::{
        FakePlatformV1, TestOwnerV1, advance_request, bootstrapped_device, bootstrapped_provider,
        next_capsule, released, sim_store, wallet_fixture,
    },
};
use iroha_data_model::kagemusha::KagemushaWalletRecoveryCapsuleV1;

fn name(text: &str) -> Name {
    Name::new(text).expect("name")
}

#[test]
fn durable_store_counts_each_primitive_and_sync_class() {
    let (_fs, store) = sim_store();
    kagemusha_wallet_prepare_root_v1(&store).expect("root");
    let dir = Dir::root();
    let (outcome, c) = Counters::observe(|| store.write_new(&dir, &name("a.bin"), b"one"));
    assert_eq!(outcome, Outcome::Published);
    assert_eq!(
        (
            c.write_new,
            c.staged_syncs,
            c.publish_syncs,
            c.fsync_class_calls()
        ),
        (1, 1, 1, 2)
    );
    let (outcome, c) = Counters::observe(|| store.rewrite_same(&dir, &name("a.bin"), b"one"));
    assert_eq!(outcome, Outcome::Published);
    assert_eq!(
        (
            c.rewrite_same,
            c.replace_exact,
            c.reads,
            c.fsync_class_calls()
        ),
        (1, 0, 1, 2)
    );
    let (outcome, c) =
        Counters::observe(|| store.replace_exact(&dir, &name("a.bin"), b"one", b"two"));
    assert_eq!(outcome, Outcome::Published);
    assert_eq!(
        (
            c.rewrite_same,
            c.replace_exact,
            c.staged_syncs,
            c.publish_syncs
        ),
        (0, 1, 1, 1)
    );
    let (outcomes, c) = Counters::observe(|| {
        store.write_new_pair(&dir, (&name("b.bin"), b"x"), (&name("c.bin"), b"y"))
    });
    assert_eq!(outcomes, [Outcome::Published; 2]);
    assert_eq!(
        (
            c.write_new,
            c.staged_syncs,
            c.publish_syncs,
            c.fsync_class_calls()
        ),
        (2, 2, 1, 3),
        "a pair shares one parent sync"
    );
    let (synced, c) = Counters::observe(|| store.sync_file(&dir, &name("a.bin")));
    synced.expect("file sync");
    assert_eq!((c.file_syncs, c.fsync_class_calls()), (1, 1));
    let (synced, c) = Counters::observe(|| store.sync_dir(&dir));
    synced.expect("directory sync");
    assert_eq!((c.dir_syncs, c.fsync_class_calls()), (1, 1));
    let (removed, c) = Counters::observe(|| store.remove_file(&dir, &name("b.bin")));
    assert_eq!(removed, Removed::Removed);
    assert_eq!((c.removals, c.dir_syncs, c.fsync_class_calls()), (1, 1, 1));
    let (_, c) = Counters::observe(|| {
        store.read(&dir, &name("c.bin"), 1);
        store.list(&dir)
    });
    assert_eq!((c.reads, c.listings, c.fsync_class_calls()), (1, 1, 0));
}

#[test]
fn durable_store_counts_a_batch_as_one_publication_sync() {
    use crate::kagemusha_wallet_advance_v1::{
        KagemushaWalletBatchActionV1 as Action, KagemushaWalletBatchEntryV1 as Entry,
    };
    let (_fs, store) = sim_store();
    kagemusha_wallet_prepare_root_v1(&store).expect("root");
    let dir = Dir::root();
    // Both copies of two archive records.
    let names = ["w-1.rec", "w-1.rec.r", "w-2.rec", "w-2.rec.r"].map(name);
    let batch = |action: Action| {
        names
            .iter()
            .map(|name| Entry {
                name,
                bytes: b"record copy",
                action,
            })
            .collect::<Vec<_>>()
    };
    let (outcome, c) = Counters::observe(|| store.publish_batch(&dir, &batch(Action::New)));
    assert_eq!(outcome, Outcome::Published);
    assert_eq!(
        (
            c.batch_publishes,
            c.batch_names,
            c.write_new,
            c.rewrite_same,
            c.reads,
            c.staged_syncs,
            c.publish_syncs,
            c.fsync_class_calls()
        ),
        (1, 4, 4, 0, 0, 4, 1, 5),
        "four copies share one parent sync"
    );
    let (outcome, c) = Counters::observe(|| store.publish_batch(&dir, &batch(Action::Replace)));
    assert_eq!(outcome, Outcome::Published);
    assert_eq!(
        (
            c.batch_publishes,
            c.batch_names,
            c.write_new,
            c.rewrite_same,
            c.reads,
            c.staged_syncs,
            c.publish_syncs,
            c.fsync_class_calls()
        ),
        (1, 4, 0, 4, 0, 4, 1, 5),
        "an exact retry adopts every copy on a fresh inode behind one parent sync"
    );
    let fields = c.fields();
    assert!(fields.contains(&("batch_publishes", 1)) && fields.contains(&("batch_names", 4)));
    // The same copies published one name at a time: a staged and a parent sync each.
    let ((), single) = Counters::observe(|| {
        for copy in ["v-1.rec", "v-1.rec.r", "v-2.rec", "v-2.rec.r"] {
            assert_eq!(
                store.write_new(&dir, &name(copy), b"record copy"),
                Outcome::Published
            );
        }
    });
    assert_eq!(
        (
            single.write_new,
            single.batch_names,
            single.fsync_class_calls()
        ),
        (4, 0, 8)
    );
}

#[test]
fn counters_are_per_thread_nest_and_survive_an_unwinding_observation() {
    let before = Counters::current();
    let other = std::thread::spawn(|| {
        let (_fs, store) = sim_store();
        kagemusha_wallet_prepare_root_v1(&store).expect("root");
        Counters::current()
    })
    .join()
    .expect("other thread");
    assert!(other.fsync_class_calls() > 0);
    assert_eq!(
        Counters::current(),
        before,
        "another thread's storage work is never attributed here"
    );
    let ((), outer) = Counters::observe(|| {
        count(EventV1::Read);
        let ((), inner) = Counters::observe(|| count(EventV1::Read));
        assert_eq!(inner.reads, 1);
        let unwound = std::panic::catch_unwind(|| {
            Counters::observe(|| {
                count(EventV1::Read);
                panic!("injected observation unwind");
            })
        });
        assert!(unwound.is_err());
    });
    assert_eq!(
        outer.reads, 3,
        "inner and unwound work stays in the enclosing observation"
    );
    assert_eq!(Counters::current().reads, before.reads + 3);
}

fn advance_next(
    provider: &mut KagemushaWalletProviderV1<impl KagemushaWalletFsV1, FakePlatformV1>,
    slot: &KagemushaWalletSlotIdV1,
    seed: u8,
    previous: &KagemushaWalletRecoveryCapsuleV1,
) -> KagemushaWalletRecoveryCapsuleV1 {
    let current = provider.status(slot).expect("status");
    let capsule = next_capsule(&wallet_fixture(seed), previous);
    let request = advance_request(current.marker().expect("marker"), &capsule);
    released(
        provider
            .advance(slot, &TestOwnerV1, &request)
            .expect("advance"),
    );
    capsule
}

#[test]
fn every_protected_storage_probe_and_reconciliation_is_counted() {
    for policy in [Policy::NotRequired, Policy::Keychain] {
        let (device, _, slot, boot) = bootstrapped_device(policy, 0x5a);
        let probes = || device.platform.with(|state| state.storage_calls);
        let platform_before = probes();
        let ((), c) = Counters::observe(|| {
            let mut provider = device.open();
            provider.status(&slot).expect("full reconcile");
            provider.status(&slot).expect("cached reconcile");
            provider
                .with_archive(&slot, |archive| archive.write_record(&[3; 32], b"record"))
                .expect("put");
            provider
                .with_archive(&slot, |archive| archive.read_record(&[3; 32], 6))
                .expect("get");
            provider
                .publish_archive_checkpoint(&slot, [0; 32], b"manifest")
                .expect("publish");
            provider.archive_checkpoint(&slot).expect("checkpoint");
            advance_next(&mut provider, &slot, 0x5a, &boot);
        });
        assert_eq!(
            c.storage_probes,
            u64::try_from(probes() - platform_before).unwrap(),
            "{policy:?}: every storage_state upcall is counted"
        );
        assert!(c.full_reconciles >= 1 && c.reconciles > c.full_reconciles);
        assert_eq!((c.archive_puts, c.archive_gets), (1, 1));
    }
}

#[test]
fn archive_record_access_counts_two_copies_and_their_syncs() {
    let (device, _, slot, _) = bootstrapped_device(Policy::NotRequired, 0x5b);
    let mut provider = device.open();
    provider.status(&slot).expect("full reconcile");
    let (written, put) = Counters::observe(|| {
        provider.with_archive(&slot, |archive| archive.write_record(&[4; 32], b"record"))
    });
    written.expect("put");
    assert_eq!(
        (
            put.archive_puts,
            put.archive_gets,
            put.write_new,
            put.rewrite_same,
            put.staged_syncs,
            put.publish_syncs,
            put.fsync_class_calls(),
            put.reconciles,
            put.full_reconciles,
        ),
        (1, 0, 2, 0, 2, 2, 4, 1, 0),
        "a new record publishes two copies, each with a staged and a parent sync"
    );
    let (written, retry) = Counters::observe(|| {
        provider.with_archive(&slot, |archive| archive.write_record(&[4; 32], b"record"))
    });
    written.expect("exact retry");
    assert_eq!(
        (
            retry.archive_puts,
            retry.archive_put_memo_hits,
            retry.write_new,
            retry.rewrite_same,
            retry.fsync_class_calls()
        ),
        (1, 1, 0, 0, 0),
        "an exact retry of bytes this process published durably is answered by the write memo"
    );
    let (read, get) = Counters::observe(|| {
        provider.with_archive(&slot, |archive| archive.read_record(&[4; 32], 6))
    });
    assert_eq!(read.expect("get").as_deref(), Some(b"record".as_slice()));
    assert_eq!(
        (
            get.archive_gets,
            get.archive_puts,
            get.fsync_class_calls(),
            get.reconciles
        ),
        (1, 0, 0, 1)
    );
    assert_eq!(
        get.storage_probes, put.storage_probes,
        "both accesses use the same protected-storage brackets"
    );
    // Another process has no memo: it adopts the visible identical copies on fresh inodes.
    drop(provider);
    let mut provider = device.open();
    provider.status(&slot).expect("full reconcile");
    let (written, adopted) = Counters::observe(|| {
        provider.with_archive(&slot, |archive| archive.write_record(&[4; 32], b"record"))
    });
    written.expect("adopt");
    assert_eq!(
        (
            adopted.archive_put_memo_hits,
            adopted.write_new,
            adopted.rewrite_same,
            adopted.fsync_class_calls()
        ),
        (0, 0, 2, 4)
    );
}

fn json_line(source: &str, policy: Policy, fs: &str, operation: &str, c: &Counters) -> String {
    let fields = c
        .fields()
        .iter()
        .map(|(name, value)| format!("\"{name}\":{value}"))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "STORAGE-BASELINE {{\"source\":\"{source}\",\"policy\":\"{policy:?}\",\"fs\":\"{fs}\",\
         \"operation\":\"{operation}\",\"fsync_class_calls\":{},\"fsync_class_nanos\":{},{fields}}}",
        c.fsync_class_calls(),
        c.fsync_class_nanos(),
    )
}

fn provider_unit_costs<F: KagemushaWalletFsV1 + Clone>(fs: F, label: &str, policy: Policy) {
    let seed = 0x5c;
    let mut recorded = Vec::new();
    let mut line = |operation: &str, c: &Counters| {
        println!(
            "{}",
            json_line("provider-unit", policy, label, operation, c)
        );
        recorded.push((operation.to_owned(), *c));
    };
    let ((mut provider, platform, slot, boot), c) =
        Counters::observe(|| bootstrapped_provider(fs.clone(), policy, seed));
    line("open_enroll_bootstrap", &c);
    let mut previous = boot;
    for ordinal in 0..3 {
        let (capsule, c) =
            Counters::observe(|| advance_next(&mut provider, &slot, seed, &previous));
        line(&format!("status_and_advance_{ordinal}"), &c);
        previous = capsule;
    }
    let (_, c) = Counters::observe(|| provider.status(&slot).expect("cached"));
    line("status_cached_no_checkpoint", &c);
    let mut checkpoint = [0; 32];
    for ordinal in 0..2_u8 {
        let manifest = vec![ordinal; 1_024];
        let (digest, c) = Counters::observe(|| {
            provider
                .publish_archive_checkpoint(&slot, checkpoint, &manifest)
                .expect("publish")
        });
        line(&format!("publish_archive_checkpoint_{ordinal}"), &c);
        checkpoint = digest;
    }
    let (_, c) = Counters::observe(|| provider.status(&slot).expect("cached"));
    line("status_cached", &c);
    let (_, c) = Counters::observe(|| provider.archive_checkpoint(&slot).expect("read"));
    line("archive_checkpoint_read", &c);
    let (capsule, c) = Counters::observe(|| advance_next(&mut provider, &slot, seed, &previous));
    line("status_and_advance_with_checkpoint", &c);
    drop(capsule);
    let record = vec![7; 160];
    for (operation, key) in [("archive_put_new", [8; 32]), ("archive_put_retry", [8; 32])] {
        let (_, c) = Counters::observe(|| {
            provider
                .with_archive(&slot, |archive| archive.write_record(&key, &record))
                .expect("put")
        });
        line(operation, &c);
    }
    for (operation, key) in [("archive_get_hit", [8; 32]), ("archive_get_miss", [9; 32])] {
        let (_, c) = Counters::observe(|| {
            provider
                .with_archive(&slot, |archive| archive.read_record(&key, 512))
                .expect("get")
        });
        line(operation, &c);
    }
    drop(provider);
    let (reopened, c) = Counters::observe(|| {
        <KagemushaWalletProviderV1<F, FakePlatformV1>>::open(
            fs.clone(),
            platform.clone(),
            crate::kagemusha_wallet_advance_v1::test_support::SCHEME,
            crate::kagemusha_wallet_advance_v1::test_support::test_options(),
        )
    });
    line("reopen", &c);
    let mut reopened = reopened.expect("reopen");
    let (_, c) = Counters::observe(|| reopened.status(&slot));
    line("status_full_after_reopen", &c);
    let unit = |operation: &str| {
        recorded
            .iter()
            .find(|(name, _)| name == operation)
            .map(|(_, c)| *c)
            .expect("recorded unit")
    };
    // Baseline unit costs: storage optimizations update these counts.
    let advance = unit("status_and_advance_with_checkpoint");
    assert_eq!(
        (
            advance.fsync_class_calls(),
            advance.write_new,
            advance.removals
        ),
        (12, 6, 2),
        "Advance A8 removes no definitively absent completion copy"
    );
    // Both checkpoint copies share one directory sync (staged 2 + directory 1), then the
    // marker (staged 1 + directory 1) and the retirement of the old one (directory 1).
    let publication = unit("publish_archive_checkpoint_1");
    assert_eq!(
        (
            publication.fsync_class_calls(),
            publication.batch_publishes,
            publication.batch_names,
            publication.staged_syncs,
            publication.publish_syncs,
            publication.dir_syncs,
        ),
        (6, 1, 2, 3, 2, 1)
    );
    let cached = unit("status_cached");
    assert_eq!((cached.fsync_class_calls(), cached.storage_probes), (0, 10));
    let put = unit("archive_put_new");
    assert_eq!(
        (put.fsync_class_calls(), put.storage_probes, put.reconciles),
        (4, 11, 1)
    );
    let retry = unit("archive_put_retry");
    assert_eq!(
        (
            retry.fsync_class_calls(),
            retry.archive_put_memo_hits,
            retry.storage_probes,
            retry.reconciles
        ),
        (0, 1, 11, 1),
        "an exact retry keeps the with_archive bracket and skips the rewrite"
    );
    let get = unit("archive_get_hit");
    assert_eq!(
        (get.fsync_class_calls(), get.storage_probes, get.reconciles),
        (0, 11, 1)
    );
    let full = unit("status_full_after_reopen");
    assert_eq!((full.fsync_class_calls(), full.full_reconciles), (16, 1));
}

/// Unit costs of provider operations for the storage baseline (simulator counts; host
/// `std::fs` counts with real sync latency). Run with `--nocapture` to record the lines.
#[test]
fn storage_baseline_provider_unit_costs() {
    for policy in [Policy::NotRequired, Policy::Keychain] {
        let (fs, _) = sim_store();
        provider_unit_costs(fs, "sim", policy);
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path().join("custody");
        assert_eq!(
            KagemushaWalletStdFsV1::create_root(&root),
            Outcome::Published
        );
        provider_unit_costs(
            KagemushaWalletStdFsV1::open(&root).expect("std root"),
            "std",
            policy,
        );
    }
}
