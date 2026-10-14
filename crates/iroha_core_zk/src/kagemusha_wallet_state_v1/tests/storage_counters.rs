//! Storage counters of the shared coordinator over a real provider archive.
//!
//! Proofs are the explicit mocks of this module and `TestCustody` keeps the monetary head. The
//! archive is an actual `ProviderArchive` of a bootstrapped provider over the simulator
//! (counts) or a host `std::fs` root (counts and real sync latency). Every custody call that
//! has no monetary effect (status, lookup, archive checkpoint read and publication, resources)
//! is also issued to that provider, so its storage work is counted on this thread; Advance and
//! collection calls are counted by kind only, and their provider unit costs are measured by
//! `kagemusha_wallet_advance_v1::counters` tests. Lines prefixed `STORAGE-BASELINE` record the
//! measurement when run with `--nocapture`.

use super::*;
use crate::kagemusha_wallet_advance_v1::{
    KagemushaWalletAnchorPolicyV1 as Policy, KagemushaWalletFsV1, KagemushaWalletStdFsV1,
    KagemushaWalletStorageCountersV1 as Counters,
    test_support::{FakePlatformV1, bootstrapped_provider},
};

#[derive(Debug, Default, Clone, Copy)]
struct Calls {
    status: u64,
    lookup: u64,
    advance: u64,
    checkpoint: u64,
    publish: u64,
    collect: u64,
    prune: u64,
    resources: u64,
}

impl Calls {
    fn since(self, before: Self) -> Self {
        Self {
            status: self.status - before.status,
            lookup: self.lookup - before.lookup,
            advance: self.advance - before.advance,
            checkpoint: self.checkpoint - before.checkpoint,
            publish: self.publish - before.publish,
            collect: self.collect - before.collect,
            prune: self.prune - before.prune,
            resources: self.resources - before.resources,
        }
    }
}

struct ShadowCustody<F: KagemushaWalletFsV1> {
    test: TestCustody,
    real: AdvanceHandle<F, FakePlatformV1>,
    real_checkpoint: [u8; 32],
    calls: Calls,
}

impl<F: KagemushaWalletFsV1> Custody for ShadowCustody<F> {
    fn archive_checkpoint(&mut self) -> Result<Option<([u8; 32], Vec<u8>)>, ProviderError> {
        self.calls.checkpoint += 1;
        self.real
            .archive_checkpoint()
            .expect("provider checkpoint read");
        self.test.archive_checkpoint()
    }
    fn publish_archive_checkpoint(
        &mut self,
        expected: [u8; 32],
        bytes: &[u8],
    ) -> Result<[u8; 32], ProviderError> {
        self.calls.publish += 1;
        let digest = self.test.publish_archive_checkpoint(expected, bytes)?;
        self.real_checkpoint = self
            .real
            .publish_archive_checkpoint(self.real_checkpoint, bytes)
            .expect("provider checkpoint publication");
        Ok(digest)
    }
    fn status(&mut self) -> Result<SlotStatus, ProviderError> {
        self.calls.status += 1;
        self.real.status().expect("provider status");
        self.test.status()
    }
    fn lookup(
        &mut self,
        operation_id: &[u8; 32],
    ) -> Result<Lookup<KagemushaWalletCompletionRecordV1>, ProviderError> {
        self.calls.lookup += 1;
        self.real.lookup(operation_id).expect("provider lookup");
        self.test.lookup(operation_id)
    }
    fn collect_capsule(
        &mut self,
        generation: u128,
        capsule: [u8; 32],
    ) -> Result<(), ProviderError> {
        self.calls.collect += 1;
        self.test.collect_capsule(generation, capsule)
    }
    fn prune_completion(
        &mut self,
        operation: [u8; 32],
        kind: u8,
    ) -> Result<crate::kagemusha_wallet_advance_v1::KagemushaWalletTombstoneV1, ProviderError> {
        self.calls.prune += 1;
        self.test.prune_completion(operation, kind)
    }
    fn advance(
        &mut self,
        owner: &TransitionOwner,
        request: &AdvanceRequest<KagemushaWalletRecoveryCapsuleV1>,
    ) -> Result<AdvanceOutcome<KagemushaWalletCompletionRecordV1>, ProviderError> {
        self.calls.advance += 1;
        self.test.advance(owner, request)
    }
    fn runtime_resources(
        &mut self,
    ) -> Result<crate::kagemusha_wallet_capacity_v1::KagemushaWalletRuntimeResourcesV1, ProviderError>
    {
        self.calls.resources += 1;
        self.real.runtime_resources().expect("provider resources");
        self.test.runtime_resources()
    }
}

type ShadowWallet<F> =
    Coordinator<ShadowCustody<F>, ProviderArchive<F, FakePlatformV1>, TestProofs>;

struct Recorder {
    policy: Policy,
    fs: &'static str,
    lines: Vec<(String, Counters, Calls)>,
}

impl Recorder {
    fn record<F: KagemushaWalletFsV1, T>(
        &mut self,
        w: &mut ShadowWallet<F>,
        operation: &str,
        run: impl FnOnce(&mut ShadowWallet<F>) -> T,
    ) -> T {
        let before = w.custody.calls;
        let (value, counters) = Counters::observe(|| run(w));
        self.emit(operation, counters, w.custody.calls.since(before));
        value
    }

    fn emit(&mut self, operation: &str, counters: Counters, calls: Calls) {
        let fields = counters
            .fields()
            .iter()
            .map(|(name, value)| format!("\"{name}\":{value}"))
            .collect::<Vec<_>>()
            .join(",");
        println!(
            "STORAGE-BASELINE {{\"source\":\"coordinator\",\"policy\":\"{:?}\",\"fs\":\"{}\",\
             \"operation\":\"{operation}\",\"fsync_class_calls\":{},\"fsync_class_nanos\":{},\
             \"custody_status\":{},\"custody_lookup\":{},\"custody_advance\":{},\
             \"custody_checkpoint_read\":{},\"custody_checkpoint_publish\":{},\
             \"custody_collect\":{},\"custody_prune\":{},\"custody_resources\":{},{fields}}}",
            self.policy,
            self.fs,
            counters.fsync_class_calls(),
            counters.fsync_class_nanos(),
            calls.status,
            calls.lookup,
            calls.advance,
            calls.checkpoint,
            calls.publish,
            calls.collect,
            calls.prune,
            calls.resources,
        );
        self.lines.push((operation.to_owned(), counters, calls));
    }

    fn fold<F: KagemushaWalletFsV1>(&mut self, w: &mut ShadowWallet<F>, operation: &str) {
        for turn in 0..8 {
            let status = self.record(w, &format!("{operation}_fold_turn_{turn}"), |w| {
                w.fold_once().expect("fold turn")
            });
            match status {
                FoldStatus::Checkpoint { .. } => {}
                FoldStatus::Folded(_) => return,
                other => panic!("{operation}: unexpected fold status {other:?}"),
            }
        }
        panic!("{operation}: fold did not finish");
    }
}

fn rebind(value: &mut FrozenTransition, mut c: KagemushaWalletRecoveryBodyV1) {
    c.statement.successor = c.successor_state.commitment().unwrap();
    c.operation_id = c.statement.operation_id(&c.wallet_id).unwrap();
    c.output = KagemushaWalletOutputDescriptorV1::for_transition(
        &c.statement,
        &c.proof_digest().unwrap(),
        &c.payment_digest,
    )
    .unwrap();
    value.capsule = seal_body(c);
    value.validate().unwrap();
}

fn bind_lineage<F: KagemushaWalletFsV1>(w: &mut ShadowWallet<F>, value: &mut FrozenTransition) {
    let step = w.released_steps().unwrap().pop().unwrap();
    let lineage = w.read_fold(&step).unwrap().unwrap().record.lineage;
    let mut c = value.capsule.body().clone();
    c.predecessor_lineage = KagemushaWalletLineageSlotV1::Present {
        lineage: lineage.clone(),
    };
    c.statement.lineage_burned_total = lineage.public.burned_total;
    c.statement.lineage_pending_outgoing_root = lineage.public.pending_outgoing_root;
    c.successor_state.core.burned_total = c.statement.lineage_burned_total;
    rebind(value, c);
}

/// Bootstrap, Receive, policy refresh, Send, Load and Unload, each followed by its fold turns,
/// then a snapshot; returns every recorded operation.
fn coordinator_run<F: KagemushaWalletFsV1>(
    fs: F,
    label: &'static str,
    policy: Policy,
) -> Vec<(String, Counters, Calls)> {
    let mut recorder = Recorder {
        policy,
        fs: label,
        lines: Vec::new(),
    };
    let c = credential();
    let (provider, _platform, slot, _) = bootstrapped_provider(fs, policy, 0x5d);
    let real = AdvanceHandle::new(provider, slot);
    let archive = real.archive(c.body.scheme_id, c.body.wallet_id);
    let custody = ShadowCustody {
        test: TestCustody::new(),
        real,
        real_checkpoint: [0; 32],
        calls: Calls::default(),
    };
    let (w, open) = Counters::observe(|| {
        Coordinator::new(
            custody,
            archive,
            TestProofs::default(),
            c.body.scheme_id,
            c.body.wallet_id,
        )
        .expect("wallet")
    });
    let mut w = w;
    let opened = w.custody.calls;
    recorder.emit("coordinator_open", open, opened);
    w.scheduler().set_activity(true, false);
    let template: KagemushaWalletPaymentV1 = fixture("KagemushaWalletPaymentV1");

    let boot = bootstrap();
    recorder.record(&mut w, "bootstrap_commit", |w| {
        w.commit(boot.clone()).expect("Bootstrap")
    });
    recorder.fold(&mut w, "bootstrap");

    let receive = frozen(
        Some(&boot),
        KagemushaWalletEffectV1::Receive {
            credit_id: received_credit(),
            payer_wallet_id: [0x88; 32],
            amount: template.request.body.amount,
        },
    );
    recorder.record(&mut w, "receive_commit", |w| {
        w.commit(receive.clone()).expect("Receive")
    });
    recorder.fold(&mut w, "receive");

    let mut policy_step = frozen(
        Some(&receive),
        KagemushaWalletEffectV1::RefreshPolicy {
            update_kind: KagemushaWalletPolicyUpdateKindV1::SchemePolicy,
            update: template.request.body.scheme_policy,
            accepted_time_floor_ms: receive
                .capsule
                .body()
                .successor_state
                .core
                .accepted_time_floor_ms,
        },
    );
    let mut body = policy_step.capsule.body().clone();
    body.successor_state.core.policy_epoch = template.request.body.policy_epoch;
    body.successor_state.rest.scheme_policy = template.request.body.scheme_policy;
    rebind(&mut policy_step, body);
    recorder.record(&mut w, "refresh_policy_commit", |w| {
        w.commit(policy_step.clone()).expect("RefreshPolicy")
    });
    recorder.fold(&mut w, "refresh_policy");

    let mut pending = KagemushaWalletIndexedTreeV1::new();
    pending
        .insert(template.digests().unwrap().credit_id, field(42))
        .unwrap();
    let mut send = frozen(Some(&policy_step), template.send.statement.effect);
    bind_lineage(&mut w, &mut send);
    let mut body = send.capsule.body().clone();
    body.successor_state.core.pending_outgoing_root = pending.root();
    body.successor_state.core.policy_epoch = template.request.body.policy_epoch;
    body.successor_state.rest.scheme_policy = template.request.body.scheme_policy;
    rebind(&mut send, body);
    let sent = recorder.record(&mut w, "send_commit", |w| {
        w.commit(send.clone()).expect("Send")
    });
    assert!(matches!(sent, Completion::Complete(_)));
    recorder.fold(&mut w, "send");

    let mut load = frozen(
        Some(&send),
        KagemushaWalletEffectV1::Load {
            receipt_digest: field(98),
            load_ordinal: 0,
            amount: 1,
            online_charge: 0,
        },
    );
    let mut body = load.capsule.body().clone();
    body.successor_state.core.pending_outgoing_root = pending.root();
    rebind(&mut load, body);
    recorder.record(&mut w, "load_commit", |w| {
        w.commit(load.clone()).expect("Load")
    });
    recorder.fold(&mut w, "load");

    let mut unload = frozen(
        Some(&load),
        KagemushaWalletEffectV1::Unload {
            nullifier: kagemusha_wallet_unload_nullifier_v1(&w.scheme_id, &w.wallet_id, 0),
            redeem_ordinal: 0,
            amount: 1,
            online_charge: 0,
            charge_quote: [0; 32],
        },
    );
    bind_lineage(&mut w, &mut unload);
    recorder.record(&mut w, "unload_commit", |w| {
        w.commit(unload.clone()).expect("Unload")
    });
    recorder.fold(&mut w, "unload");

    recorder.record(&mut w, "snapshot", |w| w.snapshot().expect("snapshot"));
    recorder.record(&mut w, "send_exact_retry", |w| {
        w.retry(&send.capsule.body().operation_id)
            .expect("retry")
            .expect("retained Send")
    });
    recorder.lines
}

fn std_root() -> (tempfile::TempDir, KagemushaWalletStdFsV1) {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().join("custody");
    assert_eq!(
        KagemushaWalletStdFsV1::create_root(&root),
        crate::kagemusha_wallet_advance_v1::KagemushaWalletPublishOutcomeV1::Published
    );
    let fs = KagemushaWalletStdFsV1::open(&root).expect("std root");
    (temp, fs)
}

#[test]
fn coordinator_storage_counts_are_deterministic_and_filesystem_independent() {
    let simulated = coordinator_run(SimFs::new(), "sim", Policy::NotRequired);
    let again = coordinator_run(SimFs::new(), "sim", Policy::NotRequired);
    let (_temp, fs) = std_root();
    let native = coordinator_run(fs, "std", Policy::NotRequired);
    let counts = |lines: &[(String, Counters, Calls)]| {
        lines
            .iter()
            .map(|(operation, c, _)| {
                let mut c = *c;
                c.staged_sync_nanos = 0;
                c.publish_sync_nanos = 0;
                c.dir_sync_nanos = 0;
                c.file_sync_nanos = 0;
                (operation.clone(), c)
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(counts(&simulated), counts(&again));
    assert_eq!(
        counts(&simulated),
        counts(&native),
        "the simulator and std::fs run the same store primitives"
    );
    let operation = |name: &str| {
        simulated
            .iter()
            .find(|(operation, _, _)| operation == name)
            .map(|(_, c, calls)| (*c, *calls))
            .unwrap_or_else(|| panic!("{name} recorded"))
    };
    for name in [
        "bootstrap_commit",
        "receive_commit",
        "refresh_policy_commit",
        "send_commit",
        "load_commit",
        "unload_commit",
    ] {
        let (c, calls) = operation(name);
        assert_eq!((calls.advance, calls.publish), (1, 1), "{name}");
        assert!(c.index_node_saves > 0, "{name}");
    }
    let (receive, _) = operation("receive_fold_turn_1");
    assert_eq!(
        receive.map_inserts, 1,
        "folding a Receive inserts its credit into the persistent credit tree"
    );
    // Baseline per operation (Android policy): fsync-class calls, provider archive puts and
    // protected-storage probes, Advance excluded. Storage optimizations update this table.
    const BASELINE: [(&str, u64, u64, u64); 21] = [
        ("coordinator_open", 0, 0, 31),
        ("bootstrap_commit", 35, 7, 229),
        ("bootstrap_fold_turn_0", 11, 1, 263),
        ("bootstrap_fold_turn_1", 27, 5, 373),
        ("receive_commit", 23, 4, 273),
        ("receive_fold_turn_0", 11, 1, 197),
        ("receive_fold_turn_1", 1_407, 350, 13_650),
        ("refresh_policy_commit", 19, 3, 295),
        ("refresh_policy_fold_turn_0", 11, 1, 219),
        ("refresh_policy_fold_turn_1", 27, 5, 318),
        ("send_commit", 35, 7, 350),
        ("send_fold_turn_0", 11, 1, 230),
        ("send_fold_turn_1", 35, 7, 384),
        ("load_commit", 19, 3, 328),
        ("load_fold_turn_0", 11, 1, 241),
        ("load_fold_turn_1", 27, 5, 340),
        ("unload_commit", 23, 4, 317),
        ("unload_fold_turn_0", 11, 1, 230),
        ("unload_fold_turn_1", 35, 7, 384),
        ("snapshot", 0, 0, 194),
        ("send_exact_retry", 0, 0, 66),
    ];
    let actual = simulated
        .iter()
        .map(|(operation, c, _)| {
            (
                operation.as_str(),
                c.fsync_class_calls(),
                c.archive_puts,
                c.storage_probes,
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(actual, BASELINE);
}

/// Coordinator storage baseline for both anchor policies (Android: none; iOS: Keychain).
#[test]
fn storage_baseline_coordinator_operations() {
    for policy in [Policy::NotRequired, Policy::Keychain] {
        coordinator_run(SimFs::new(), "sim", policy);
        let (_temp, fs) = std_root();
        coordinator_run(fs, "std", policy);
    }
}

/// Persistent-map insertion through the provider archive, the unit of the Pending and Fee map
/// drafts, into maps of 0 and 10 entries (the simulator slows down with thousands of
/// archive files); depth at 10, 100 and 1,000 entries uses an in-memory store.
#[test]
fn storage_baseline_persistent_map_insertion() {
    for policy in [Policy::NotRequired, Policy::Keychain] {
        let c = credential();
        let (provider, _platform, slot, _) = bootstrapped_provider(SimFs::new(), policy, 0x5e);
        let mut handle = AdvanceHandle::new(provider, slot);
        Custody::status(&mut handle).expect("verified slot");
        let mut archive = handle.archive(c.body.scheme_id, c.body.wallet_id);
        let mut map = map_tree::PersistentMapV1::default();
        let mut inserted = 0_u32;
        for size in [0_u32, 10] {
            while inserted < size {
                inserted += 1;
                let mut key = field(0);
                key[..4].copy_from_slice(&inserted.to_le_bytes());
                key[4] = 1;
                map.insert(&mut archive, key, field(7)).expect("insert");
            }
            let mut key = field(0);
            key[..4].copy_from_slice(&(size + 1_000).to_le_bytes());
            key[4] = 2;
            let mut next = map.clone();
            let (_, insertion) = Counters::observe(|| {
                next.insert(&mut archive, key, field(9))
                    .expect("measured insert")
            });
            let (_, membership) =
                Counters::observe(|| next.membership(&mut archive, &key).expect("member"));
            for (operation, counters) in [
                (format!("map_insert_at_{size}"), insertion),
                (format!("map_membership_at_{size}"), membership),
            ] {
                let fields = counters
                    .fields()
                    .iter()
                    .map(|(name, value)| format!("\"{name}\":{value}"))
                    .collect::<Vec<_>>()
                    .join(",");
                println!(
                    "STORAGE-BASELINE {{\"source\":\"map\",\"policy\":\"{policy:?}\",\
                     \"fs\":\"sim\",\"operation\":\"{operation}\",\"fsync_class_calls\":{},\
                     \"fsync_class_nanos\":{},{fields}}}",
                    counters.fsync_class_calls(),
                    counters.fsync_class_nanos(),
                );
            }
            assert_eq!(insertion.map_inserts, 1);
            assert_eq!(
                insertion.archive_puts, insertion.index_node_saves,
                "every saved index node is one provider archive put"
            );
            assert_eq!(
                insertion.fsync_class_calls(),
                4 * insertion.archive_puts,
                "each put publishes two copies with a staged and a parent sync"
            );
            if policy == Policy::NotRequired {
                // Baseline: fsync-class calls, provider archive puts and storage probes of one
                // insertion into a map of `size` entries.
                let expected = if size == 0 {
                    (1_376, 344, 13_343)
                } else {
                    (1_884, 471, 23_100)
                };
                assert_eq!(
                    (
                        insertion.fsync_class_calls(),
                        insertion.archive_puts,
                        insertion.storage_probes
                    ),
                    expected
                );
            }
        }
    }
    let mut store = MemoryArchive::new();
    let mut map = map_tree::PersistentMapV1::default();
    for count in 1_u32..=1_000 {
        let mut key = field(0);
        key[..4].copy_from_slice(&count.to_le_bytes());
        key[4] = 3;
        let (_, c) = Counters::observe(|| map.insert(&mut store, key, field(7)).unwrap());
        if matches!(count, 10 | 100 | 1_000) {
            println!(
                "STORAGE-BASELINE {{\"source\":\"map-depth\",\"policy\":\"none\",\"fs\":\"memory\",\
                 \"operation\":\"map_insert_after_{count}\",\"index_node_loads\":{},\
                 \"index_node_saves\":{},\"index_walks\":{},\"index_max_depth\":{}}}",
                c.index_node_loads, c.index_node_saves, c.index_walks, c.index_max_depth,
            );
        }
    }
}
