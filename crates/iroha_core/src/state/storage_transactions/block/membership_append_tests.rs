//! Real-file replay, original preparation and charged owner failure controls.

use super::super::{TransactionsStorage, key_digest};
use super::*;
use iroha_crypto::HashOf;
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    num::NonZeroUsize,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::Arc,
};

struct FileIo {
    file: File,
    start: u64,
    end: u64,
    reads: usize,
    writes: usize,
    syncs: usize,
    completed: Option<u64>,
    cut: Option<usize>,
    panic_write: bool,
    fail_read: Option<usize>,
    fail_sync: bool,
}
impl FileIo {
    fn new(records: u64) -> Self {
        Self {
            file: tempfile::tempfile().unwrap(),
            start: 0,
            end: records * RECORD_BYTES,
            reads: 0,
            writes: 0,
            syncs: 0,
            completed: None,
            cut: None,
            panic_write: false,
            fail_read: None,
            fail_sync: false,
        }
    }
    fn bytes(&mut self) -> Vec<u8> {
        self.file.rewind().unwrap();
        let mut bytes = Vec::new();
        self.file.read_to_end(&mut bytes).unwrap();
        bytes
    }
}
impl AppendIo for FileIo {
    fn generation(&self) -> NonZeroU64 {
        NonZeroU64::new(7).unwrap()
    }
    fn start_offset(&self) -> u64 {
        self.start
    }
    fn reserved_end(&self) -> u64 {
        self.end
    }
    fn read_exact(
        &mut self,
        offset: u64,
        bytes: &mut [u8],
    ) -> Result<(), MembershipAppendStoreError> {
        self.reads += 1;
        if self.fail_read == Some(self.reads) {
            return Err(io::Error::from(io::ErrorKind::Other).into());
        }
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.read_exact(bytes)?;
        Ok(())
    }
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> Result<usize, MembershipAppendStoreError> {
        assert!(self.completed.is_none());
        assert!(offset >= self.start && offset + bytes.len() as u64 <= self.end);
        self.writes += 1;
        self.file.seek(SeekFrom::Start(offset))?;
        let n = self.cut.map_or(bytes.len(), |cut| cut.min(bytes.len()));
        self.file.write_all(&bytes[..n])?;
        if let Some(cut) = self.cut.as_mut() {
            *cut -= n;
            if *cut == 0 {
                assert!(!self.panic_write, "injected ambiguous write unwind");
                return Err(io::Error::from(io::ErrorKind::StorageFull).into());
            }
        }
        Ok(n)
    }
    fn sync_data(&mut self) -> Result<(), MembershipAppendStoreError> {
        self.syncs += 1;
        self.file.sync_data()?;
        if self.fail_sync {
            return Err(io::Error::from(io::ErrorKind::Other).into());
        }
        Ok(())
    }
    fn complete(&mut self, end: u64) -> Result<(), MembershipAppendStoreError> {
        assert_eq!(self.file.metadata().unwrap().len(), end);
        if let Some(previous) = self.completed {
            assert_eq!(previous, end);
        }
        self.completed = Some(end);
        Ok(())
    }
}
fn store(records: u64) -> ReplayStore<FileIo> {
    ReplayStore::new(FileIo::new(records), MembershipRecordCodec::new().unwrap()).unwrap()
}
fn key(n: u64) -> Key {
    HashOf::from_untyped_unchecked(Hash::new(n.to_le_bytes()))
}
fn height(n: usize) -> Value {
    NonZeroUsize::new(n).unwrap()
}
fn records() -> [MembershipRecord; 3] {
    let location =
        |n| MembershipLocation::new(NonZeroU64::new(7).unwrap(), n * RECORD_BYTES).unwrap();
    let leaf = MerkleMapNode::Leaf {
        key: key_digest(&key(1)),
        value: MerkleMapValueRef {
            hash: canonical_height_digest(1),
            location: location(0),
        },
    };
    [
        MembershipRecord::Height(NonZeroU64::new(1).unwrap()),
        MembershipRecord::Node(leaf),
        MembershipRecord::Node(MerkleMapNode::Branch {
            bit: 0,
            prefix: [0; 32],
            left: MerkleMapNodeRef {
                hash: leaf.hash(),
                location: location(1),
            },
            right: MerkleMapNodeRef {
                hash: Hash::new(b"other-child"),
                location: location(1),
            },
        }),
    ]
}
fn cold(
    storage: &TransactionsStorage,
    store: &mut ReplayStore<FileIo>,
) -> CommittedMembershipRoot<MembershipLocation> {
    storage
        .block()
        .capture_committed_root(100_000, store, &mut Workspace::new())
        .unwrap()
}
fn attempt(
    prepared: &PreparedTransactionsBlock<'_>,
    baseline: &CommittedMembershipRoot<MembershipLocation>,
    mut store: ReplayStore<FileIo>,
) -> AppendInner<FileIo> {
    store.io.start = store.complete;
    store.cursor = store.complete;
    AppendInner {
        preparation: prepared.next_identity.clone(),
        baseline: baseline.clone(),
        workspace: Workspace::new(),
        store,
        root: None,
    }
}

#[test]
fn every_record_byte_cut_and_ambiguous_unwind_reuses_only_the_original_slot() {
    for record_index in 0..3 {
        for cut in 0..=FRAME_BYTES {
            for unwind in [false, true] {
                let mut s = store(3);
                let values = records();
                for value in &values[..record_index] {
                    s.append(*value).unwrap();
                }
                let prefix = s.io.bytes();
                let original_complete = s.complete;
                for _ in 0..3 {
                    s.restart().unwrap();
                    for value in &values[..record_index] {
                        s.append(*value).unwrap();
                    }
                    s.io.cut = Some(cut);
                    s.io.panic_write = unwind;
                    let outcome = catch_unwind(AssertUnwindSafe(|| s.append(values[record_index])));
                    assert!(if unwind {
                        outcome.is_err()
                    } else {
                        outcome.unwrap().is_err()
                    });
                    assert_eq!(s.complete, original_complete);
                    assert!(s.pending.is_some());
                    let bytes = s.io.bytes();
                    assert_eq!(&bytes[..prefix.len()], prefix);
                    assert_eq!(bytes.len(), prefix.len() + cut);
                }
                s.io.cut = None;
                s.io.panic_write = false;
                s.restart().unwrap();
                for value in &values[..=record_index] {
                    s.append(*value).unwrap();
                }
                assert_eq!(s.complete, (record_index as u64 + 1) * RECORD_BYTES);
                assert!(s.pending.is_none());
                s.seal().unwrap();
                s.sync().unwrap();
                assert_eq!(s.io.completed, Some(s.complete));
            }
        }
    }
}

#[test]
fn replay_mismatch_corruption_and_shorter_completion_never_rewrite_acknowledged_bytes() {
    let mut s = store(3);
    for record in records() {
        s.append(record).unwrap();
    }
    let before = s.io.bytes();
    let writes = s.io.writes;
    s.restart().unwrap();
    assert!(matches!(
        s.append(MembershipRecord::Height(NonZeroU64::new(2).unwrap())),
        Err(MembershipAppendStoreError::ReplayMismatch)
    ));
    assert_eq!(s.io.writes, writes);
    assert_eq!(s.io.bytes(), before);
    s.restart().unwrap();
    s.append(records()[0]).unwrap();
    assert!(matches!(
        s.seal(),
        Err(MembershipAppendStoreError::IncompleteReplay)
    ));
    s.io.file.seek(SeekFrom::Start(RECORD_BYTES + 50)).unwrap();
    s.io.file.write_all(&[0xff]).unwrap();
    assert!(matches!(
        s.append(records()[1]),
        Err(MembershipAppendStoreError::ReplayMismatch)
    ));
    assert_eq!(s.io.writes, writes);
    s.io.file.set_len(RECORD_BYTES).unwrap();
    assert!(
        matches!(s.append(records()[1]), Err(MembershipAppendStoreError::Io(e)) if e.kind()==io::ErrorKind::UnexpectedEof)
    );
    assert_eq!(s.io.writes, writes);
}

#[test]
fn pending_mismatch_capacity_and_future_references_refuse_before_new_io() {
    let mut s = store(1);
    s.io.cut = Some(17);
    assert!(s.append(records()[0]).is_err());
    let writes = s.io.writes;
    assert!(matches!(
        s.append(MembershipRecord::Height(NonZeroU64::new(2).unwrap())),
        Err(MembershipAppendStoreError::ReplayMismatch)
    ));
    assert_eq!(s.io.writes, writes);
    s.io.cut = None;
    let loc = s.append(records()[0]).unwrap();
    assert_eq!(loc, MembershipLocation::new(s.io.generation(), 0).unwrap());
    assert!(matches!(
        s.append(records()[0]),
        Err(MembershipAppendStoreError::Capacity)
    ));
    let mut future = store(3);
    assert!(matches!(
        future.append(records()[1]),
        Err(MembershipAppendStoreError::Record(
            RecordError::OutsideReadableExtent
        ))
    ));
    assert_eq!(future.io.writes, 0);
    assert!(matches!(
        future.write_height(Hash::new(b"wrong"), 1),
        Err(MembershipAppendStoreError::HeightHashMismatch)
    ));
    assert!(matches!(
        future.write_height(canonical_height_digest(0), 0),
        Err(MembershipAppendStoreError::Record(
            RecordError::InvalidHeight
        ))
    ));
    assert_eq!(future.io.writes, 0);
}

#[test]
fn sync_uncertainty_retains_the_sealed_candidate_and_never_replays_writes() {
    let mut s = store(3);
    assert!(s.sync().is_err());
    for record in records() {
        s.append(record).unwrap();
    }
    s.seal().unwrap();
    let writes = s.io.writes;
    s.io.fail_sync = true;
    for _ in 0..8 {
        assert!(s.sync().is_err());
        assert!(!s.durable);
        assert!(s.io.completed.is_none());
    }
    s.io.fail_sync = false;
    s.sync().unwrap();
    assert!(s.durable);
    assert_eq!(s.io.syncs, 9);
    s.sync().unwrap();
    assert_eq!(s.io.syncs, 9);
    assert_eq!(s.io.writes, writes);
    assert!(matches!(
        s.restart(),
        Err(MembershipAppendStoreError::Sealed)
    ));
    assert!(matches!(
        s.append(records()[0]),
        Err(MembershipAppendStoreError::Sealed)
    ));
}

#[test]
fn original_preparation_replays_net_changes_with_old_and_rollback_roots_intact() {
    let storage = TransactionsStorage::new();
    let mut block = storage.block();
    block.insert_block([key(1), key(2)].into_iter().collect(), height(1));
    block.commit().unwrap();
    let mut block = storage.block();
    block.insert_block([key(2), key(3)].into_iter().collect(), height(2));
    block.commit().unwrap();
    let mut disk = store(2048);
    let baseline = cold(&storage, &mut disk);
    let old_bytes = disk.io.bytes();
    let mut block = storage.block_and_revert();
    block.insert_block([key(1), key(4)].into_iter().collect(), height(2));
    let prepared = block.prepare_commit().unwrap();
    let mut owned = attempt(&prepared, &baseline, disk);
    // Fail after some new record output, then replay the same actual HashSets.
    owned.store.io.cut = Some(FRAME_BYTES + 29);
    assert!(owned.prepare(&prepared).is_err());
    let retained_high_water = owned.store.complete;
    for _ in 0..4 {
        owned.store.io.cut = Some(29);
        assert!(owned.prepare(&prepared).is_err());
        assert_eq!(owned.store.complete, retained_high_water);
        assert_eq!(&owned.store.io.bytes()[..old_bytes.len()], old_bytes);
    }
    owned.store.io.cut = None;
    owned.prepare(&prepared).unwrap();
    let after = &owned.root.as_ref().unwrap().after;
    assert_eq!(
        after.read(&key(1), &mut owned.store).unwrap(),
        Some(height(2))
    );
    assert_eq!(
        after.read(&key(2), &mut owned.store).unwrap(),
        Some(height(1))
    );
    assert_eq!(after.read(&key(3), &mut owned.store).unwrap(), None);
    assert_eq!(
        after.read(&key(4), &mut owned.store).unwrap(),
        Some(height(2))
    );
    assert_eq!(
        baseline.read(&key(2), &mut owned.store).unwrap(),
        Some(height(2))
    );
    assert_eq!(
        baseline
            .read_predecessor(&key(2), &mut owned.store)
            .unwrap(),
        Some(height(1))
    );
    let before_sync = owned.store.io.writes;
    owned.prepare(&prepared).unwrap();
    owned.store.sync().unwrap();
    assert_eq!(owned.store.io.writes, before_sync);
    assert_eq!(&owned.store.io.bytes()[..old_bytes.len()], old_bytes);
}

#[test]
fn every_original_preparation_read_failure_retains_the_same_file_and_prefix() {
    let storage = TransactionsStorage::new();
    let mut block = storage.block();
    block.insert_block([key(1), key(2)].into_iter().collect(), height(1));
    block.commit().unwrap();
    let mut disk = store(2048);
    let baseline = cold(&storage, &mut disk);
    let old_bytes = disk.io.bytes();
    let mut block = storage.block();
    block.insert_block([key(3), key(4)].into_iter().collect(), height(2));
    let prepared = block.prepare_commit().unwrap();
    let fresh = || {
        let mut disk = store(2048);
        disk.io.file.write_all(&old_bytes).unwrap();
        disk.complete = old_bytes.len() as u64;
        disk.cursor = disk.complete;
        attempt(&prepared, &baseline, disk)
    };
    let mut pilot = fresh();
    pilot.prepare(&prepared).unwrap();
    let reads = pilot.store.io.reads;
    assert!(reads > 0);
    for cut in 1..=reads {
        let mut owned = fresh();
        owned.store.io.fail_read = Some(cut);
        assert!(owned.prepare(&prepared).is_err(), "read cut {cut}");
        assert!(owned.root.is_none());
        owned.store.io.fail_read = None;
        owned.prepare(&prepared).unwrap();
        assert_eq!(&owned.store.io.bytes()[..old_bytes.len()], old_bytes);
        assert_eq!(
            owned
                .root
                .as_ref()
                .unwrap()
                .after
                .read(&key(3), &mut owned.store)
                .unwrap(),
            Some(height(2))
        );
    }
}

#[test]
fn exact_preparation_survives_detach_and_abort_but_recreated_owner_cannot_take_attempt() {
    let storage = TransactionsStorage::new();
    let mut disk = store(2048);
    let baseline = cold(&storage, &mut disk);
    let mut block = storage.block();
    block.insert_block([key(1)].into_iter().collect(), height(1));
    let prepared = block.prepare_commit().unwrap();
    let mut owned = attempt(&prepared, &baseline, disk);
    owned.store.io.cut = Some(17);
    assert!(owned.prepare(&prepared).is_err());
    let detached = prepared.detach();
    let mut block = storage.block();
    block.insert_block([key(1)].into_iter().collect(), height(1));
    let wrong = block.prepare_commit().unwrap();
    let writes = owned.store.io.writes;
    assert!(matches!(
        owned.prepare(&wrong),
        Err(MembershipAppendError::PreparationChanged)
    ));
    assert_eq!(owned.store.io.writes, writes);
    drop(wrong);
    let reacquired = detached
        .try_prepare_publication(&storage, |_, _| Ok::<_, ()>(()))
        .unwrap_or_else(|_| panic!("same original predecessor"));
    let (detached, cleanup) = reacquired.abort();
    drop(cleanup);
    let reacquired = detached
        .try_prepare_publication(&storage, |_, _| Ok::<_, ()>(()))
        .unwrap_or_else(|_| panic!("same original predecessor"));
    owned.store.io.cut = None;
    owned.prepare(&reacquired.prepared).unwrap();
    assert_eq!(
        owned
            .root
            .as_ref()
            .unwrap()
            .after
            .read(&key(1), &mut owned.store)
            .unwrap(),
        Some(height(1))
    );
    let (detached, cleanup) = reacquired.abort();
    drop(cleanup);
    drop(detached);
}

#[test]
#[cfg(all(unix, not(target_os = "espidf")))]
fn real_kura_range_and_charged_append_remain_original_through_capacity_and_sync() {
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        task::{Context, Poll, Wake, Waker},
    };
    struct Probe {
        storage: Arc<TransactionsStorage>,
        calls: AtomicUsize,
        busy: AtomicUsize,
    }
    impl Wake for Probe {
        fn wake(self: Arc<Self>) {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.storage.write_lock.try_lock().is_none() {
                self.busy.fetch_add(1, Ordering::SeqCst);
            }
        }
    }
    for unwind in [false, true] {
        let kura = crate::kura::Kura::blank_kura_for_testing();
        let mut registrations: [_; 2] = std::array::from_fn(|_| {
            crate::unit_test_support::release_registration(&kura.membership_memory_budget())
        });
        let storage = Arc::new(TransactionsStorage::new());
        let probe = Arc::new(Probe {
            storage: Arc::clone(&storage),
            calls: AtomicUsize::new(0),
            busy: AtomicUsize::new(0),
        });
        let waker = Waker::from(Arc::clone(&probe));
        let (waits, probe_cleanup) = kura.membership_fence_waits_for_tests();
        for (wait, registration) in waits.iter().zip(&mut registrations) {
            assert_eq!(
                registration.poll_wait(wait, &mut Context::from_waker(&waker)),
                Poll::Pending
            );
        }
        let range = kura.reserve_membership_range(516).unwrap();
        assert_eq!(
            probe.calls.load(Ordering::SeqCst),
            0,
            "reserve retains its original fence releases"
        );
        let budget = range.memory_budget();
        let before = budget.reserved_bytes();
        budget.with_deferred_refund_notifications(|_| {
            let mut empty_store = store(0);
            let baseline = cold(&storage, &mut empty_store);
            let mut block = storage.block();
            block.insert_block([key(1), key(2)].into_iter().collect(), height(1));
            let prepared = block.prepare_commit().unwrap();
            assert_eq!(
                PreparedMembershipAppend::record_demand(&prepared, &baseline).unwrap(),
                516
            );
            let foreign = TransactionsStorage::new();
            let mut wrong = foreign.block();
            wrong.insert_block([key(1), key(2)].into_iter().collect(), height(1));
            let wrong = wrong.prepare_commit().unwrap();
            let (range, error) = PreparedMembershipAppend::new(&wrong, &baseline, range)
                .err()
                .unwrap();
            assert!(matches!(error, MembershipAppendError::PreparationChanged));
            assert_eq!(budget.reserved_bytes(), before);
            drop(wrong);
            let held = budget
                .try_reserve_bytes(budget.limit_bytes() - budget.reserved_bytes())
                .unwrap();
            let (range, error) = PreparedMembershipAppend::new(&prepared, &baseline, range)
                .err()
                .unwrap();
            assert!(matches!(error, MembershipAppendError::Admission(_)));
            drop(held);
            let mut append = PreparedMembershipAppend::new(&prepared, &baseline, range)
                .unwrap_or_else(|(_, e)| panic!("{e}"));
            assert!(budget.reserved_bytes() > before);
            assert!(matches!(
                append.sync(),
                Err(MembershipAppendError::Unprepared)
            ));
            append.prepare(&prepared).unwrap();
            assert!(!append.is_durable());
            assert_eq!(append.read_after(&key(2)).unwrap(), Some(height(1)));
            append.sync().unwrap();
            append.sync().unwrap();
            assert!(append.is_durable());
            let end = append.inner.store.complete;
            let later = kura.reserve_membership_range(1).unwrap();
            assert_eq!(later.start_offset(), end);
            assert_eq!(append.read_after(&key(1)).unwrap(), Some(height(1)));
            // Drop all writers before returning memory credits; closed old range
            // remains a real read lease while its successor interval exists.
            let release = append
                .take_cleanup()
                .expect("original complete Kura/range cleanup");
            assert!(append.take_cleanup().is_none());
            assert_eq!(
                probe.calls.load(Ordering::SeqCst),
                0,
                "no operation return notifies under the actual membership writer"
            );
            let ended = catch_unwind(AssertUnwindSafe(|| {
                let _release = release;
                let _prepared = prepared;
                assert!(
                    !unwind,
                    "outer completion unwinds after retaining original cleanup"
                )
            }));
            assert_eq!(ended.is_err(), unwind);
            assert_eq!(probe.calls.load(Ordering::SeqCst), 2);
            assert_eq!(probe.busy.load(Ordering::SeqCst), 0);
            for (wait, registration) in waits.iter().zip(&mut registrations) {
                assert_eq!(
                    registration.poll_wait(wait, &mut Context::from_waker(&waker)),
                    Poll::Ready(())
                );
            }
            drop(append);
            assert_eq!(budget.reserved_bytes(), before);
            drop(later);
        });
        drop(probe_cleanup);
        for registration in &mut registrations {
            registration.cancel();
        }
    }
}

#[test]
fn record_codec_constructor_scratch_is_one_declared_identity_and_golden_is_unchanged() {
    let expected = "iroha_core::state::membership::RecordV1";
    assert_eq!(
        MembershipRecordCodec::construction_scratch_layout(),
        Layout::array::<u8>(expected.len()).unwrap()
    );
    let codec = MembershipRecordCodec::new().unwrap();
    let mut bytes = [0; FRAME_BYTES];
    codec
        .write(
            &mut bytes.as_mut_slice(),
            MembershipRecord::Height(NonZeroU64::new(17).unwrap()),
        )
        .unwrap();
    assert_eq!(
        hex::encode(bytes),
        include_str!("membership_record_height.hex").trim()
    );
}

#[test]
fn repeated_commit_needs_no_new_records_and_restored_identity_is_refused() {
    let storage = TransactionsStorage::new();
    let mut block = storage.block();
    block.insert_block([key(1)].into_iter().collect(), height(1));
    block.commit().unwrap();
    let mut disk = store(516);
    let baseline = cold(&storage, &mut disk);
    let original = disk.io.bytes();
    let encoded = norito::json::to_json(&storage).unwrap();
    let restored: TransactionsStorage = norito::json::from_str(&encoded).unwrap();
    let mut block = storage.block();
    block.insert_block([key(1)].into_iter().collect(), height(1));
    let prepared = block.prepare_commit().unwrap();
    assert_eq!(
        PreparedMembershipAppend::record_demand(&prepared, &baseline).unwrap(),
        0
    );
    let mut owned = attempt(&prepared, &baseline, disk);
    let writes = owned.store.io.writes;
    owned.prepare(&prepared).unwrap();
    owned.store.sync().unwrap();
    assert_eq!(owned.store.io.writes, writes);
    assert_eq!(owned.store.io.bytes(), original);
    let mut foreign = restored.block();
    foreign.insert_block([key(1)].into_iter().collect(), height(1));
    let foreign = foreign.prepare_commit().unwrap();
    assert!(matches!(
        PreparedMembershipAppend::record_demand(&foreign, &baseline),
        Err(MembershipAppendError::PreparationChanged)
    ));
    assert!(matches!(
        owned.prepare(&foreign),
        Err(MembershipAppendError::PreparationChanged)
    ));
    assert_eq!(owned.store.io.writes, writes);
}
