//! Ordered persistence (`specs/sumeragi.md` §12.3 O2, §7.4): safety records and block bodies
//! are written one at a time in the order the core emitted them, a failed write is retried with
//! backoff and never skipped (the instance is silent meanwhile), and the durable watermark
//! releases the O2 barrier. Records replace each other atomically, so a record still queued is
//! superseded by a newer one of the same key (the queue holds at most one per key, whatever a
//! failing disk does); a body still queued at an applied height is dropped with the pruning
//! that would delete it. Also the §7.4 record-provenance steps at start: the store-id check and
//! the installation event of every `(instance, key)`.

use std::{
    collections::{BTreeMap, VecDeque},
    panic::{AssertUnwindSafe, catch_unwind},
};

use iroha_sumeragi::{
    availability::AvailableBody,
    crypto::Crypto,
    safety::{RecordState, SafetyRecord},
    types::{Hash32, Millis, PublicKey},
};

use super::traits::{BodyStore, LogEntry, RecordStore};

/// One durable write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Write {
    /// A safety record (`PersistSafety`).
    Record(Box<SafetyRecord>),
    /// A block body (`StoreBody`).
    Body(Box<AvailableBody>),
    /// Drop the stored bodies at or below a height after its apply.
    Prune(u64),
}

/// Retry delays after consecutive failures: `initial`, doubling, at most `max`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Backoff {
    /// Delay after the first failure.
    pub initial: Millis,
    /// Largest delay.
    pub max: Millis,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            initial: 10,
            max: 1_000,
        }
    }
}

impl Backoff {
    /// The delay after `failures ≥ 1` consecutive failures.
    pub fn delay(&self, failures: u32) -> Millis {
        let shift = failures.saturating_sub(1).min(20);
        self.initial
            .max(1)
            .saturating_mul(1 << shift)
            .min(self.max.max(1))
    }
}

/// The ordered write queue of one instance: at most one write in flight, first in first out.
#[derive(Debug)]
pub struct PersistQueue {
    last_seq: u64,
    queue: VecDeque<(u64, Write)>,
    /// Sequence number of the write handed to the writer.
    in_flight: Option<u64>,
    failures: u32,
    retry_at: Option<Millis>,
    durable: u64,
    backoff: Backoff,
}

impl PersistQueue {
    /// An empty queue.
    pub fn new(backoff: Backoff) -> Self {
        Self {
            last_seq: 0,
            queue: VecDeque::new(),
            in_flight: None,
            failures: 0,
            retry_at: None,
            durable: 0,
            backoff,
        }
    }

    /// Queue a write; returns its sequence number. A `Prune(h)` first drops the queued bodies
    /// at heights `≤ h` (it would delete them).
    pub fn push(&mut self, write: Write) -> u64 {
        if let Write::Prune(height) = &write {
            self.queue
                .retain(|(_, w)| !matches!(w, Write::Body(b) if b.header().height <= *height));
        }
        self.last_seq += 1;
        self.queue.push_back((self.last_seq, write));
        self.last_seq
    }

    /// Queue a safety record; returns its sequence number and that of the queued (not yet
    /// started) record of the same `(instance, key)` it supersedes, which is removed: what
    /// waited for that one must now wait for this one ([`Barrier::superseded`]).
    ///
    /// [`Barrier::superseded`]: super::barrier::Barrier::superseded
    pub fn push_record(&mut self, record: Box<SafetyRecord>) -> (u64, Option<u64>) {
        let superseded = self.queued_record(&record);
        if let Some(old) = superseded {
            self.queue.retain(|(seq, _)| *seq != old);
        }
        (self.push(Write::Record(record)), superseded)
    }

    /// The oldest queued write, handed to the writer now: none while another is in flight or
    /// before the backoff of a failed one ended.
    pub fn next(&mut self, now: Millis) -> Option<(u64, Write)> {
        if self.in_flight.is_some() || self.retry_at.is_some_and(|at| at > now) {
            return None;
        }
        let (seq, write) = self.queue.pop_front()?;
        self.in_flight = Some(seq);
        Some((seq, write))
    }

    /// Write `seq` is durable; returns the new durable watermark.
    pub fn done(&mut self, seq: u64) -> u64 {
        if self.in_flight == Some(seq) {
            self.in_flight = None;
            self.failures = 0;
            self.retry_at = None;
            self.durable = seq;
        }
        self.durable
    }

    /// Write `seq` failed: it goes back to the head and is retried after the backoff — unless
    /// it is a record that a newer queued record of the same key supersedes, which is dropped;
    /// then `(seq, newer)` is returned ([`Barrier::superseded`]).
    ///
    /// [`Barrier::superseded`]: super::barrier::Barrier::superseded
    pub fn failed(&mut self, seq: u64, write: Write, now: Millis) -> Option<(u64, u64)> {
        if self.in_flight != Some(seq) {
            return None;
        }
        self.in_flight = None;
        self.failures = self.failures.saturating_add(1);
        self.retry_at = Some(now.saturating_add(self.backoff.delay(self.failures)));
        if let Write::Record(record) = &write
            && let Some(newer) = self.queued_record(record)
        {
            return Some((seq, newer));
        }
        self.queue.push_front((seq, write));
        None
    }

    /// The sequence number of the queued record of `record`'s `(instance, key)`, if any.
    fn queued_record(&self, record: &SafetyRecord) -> Option<u64> {
        self.queue.iter().find_map(|(seq, w)| {
            matches!(w, Write::Record(r) if r.instance == record.instance && r.key == record.key)
                .then_some(*seq)
        })
    }

    /// Everything up to this sequence number is durable.
    pub fn durable(&self) -> u64 {
        self.durable
    }

    /// When a failed write is due again (`Millis::MAX`: nothing to wait for).
    pub fn wakeup(&self) -> Millis {
        match (self.in_flight, self.retry_at) {
            (None, Some(at)) if !self.queue.is_empty() => at,
            _ => Millis::MAX,
        }
    }

    /// Writes queued or in flight.
    pub fn len(&self) -> usize {
        self.queue.len() + usize::from(self.in_flight.is_some())
    }

    /// Whether nothing is queued or in flight.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Safety records queued (not in flight).
    pub fn queued_records(&self) -> usize {
        self.queue
            .iter()
            .filter(|(_, w)| matches!(w, Write::Record(_)))
            .count()
    }

    /// Payload bytes of the queued bodies, per height.
    pub fn queued_bodies(&self) -> BTreeMap<u64, u64> {
        let mut out: BTreeMap<u64, u64> = BTreeMap::new();
        for (_, write) in &self.queue {
            if let Write::Body(block) = write {
                let bytes = u64::try_from(block.payload().as_slice().len()).unwrap_or(u64::MAX);
                let entry = out.entry(block.header().height).or_default();
                *entry = entry.saturating_add(bytes);
            }
        }
        out
    }
}

/// Perform one write on the stores (the persistence thread); the write comes back on failure.
/// A store that panics fails the write (it is retried like an I/O error, §12.5).
///
/// # Errors
/// The write, when it did not become durable.
pub fn perform<R, B>(
    records: &R,
    bodies: &B,
    crypto: &dyn Crypto,
    write: Write,
) -> Result<(), Write>
where
    R: RecordStore + ?Sized,
    B: BodyStore + ?Sized,
{
    let result = catch_unwind(AssertUnwindSafe(|| match &write {
        Write::Record(record) => record
            .encode(crypto)
            .map_err(|e| std::io::Error::other(e.to_string()))
            .and_then(|bytes| records.write(&record.instance, &record.key, &bytes)),
        Write::Body(block) => bodies.put(&block.header().hash(crypto), block),
        Write::Prune(height) => bodies.prune_through(*height),
    }))
    .unwrap_or_else(|_| Err(std::io::Error::other("store panicked")));
    match result {
        Ok(()) => {
            if let Write::Record(record) = &write {
                super::audit::record_durable(record);
            }
            Ok(())
        }
        Err(error) => {
            iroha_logger::warn!(%error, "sumeragi persistence failed; retrying");
            Err(write)
        }
    }
}

/// Append a log entry with a fresh store id: the id file first, then the entry (§7.4 rule 3).
fn append<R: RecordStore + ?Sized>(
    store: &R,
    entry: impl FnOnce(u128) -> LogEntry,
    fresh_id: &mut dyn FnMut() -> u128,
    log: &mut Vec<LogEntry>,
) -> std::io::Result<()> {
    let id = fresh_id();
    store.set_store_id(id)?;
    let entry = entry(id);
    store.append_log(&entry)?;
    log.push(entry);
    Ok(())
}

/// The store-id check of §7.4 rule 3 over the installation log `log` (read from `store`): if the
/// log has entries and the id next to the record files differs from the newest entry's (or is
/// missing), every key of the log is durably marked imported and `true` is returned.
///
/// The marks are one event: they are appended first, all carrying one fresh id, and the id file
/// is written last. A crash anywhere in between leaves the mismatch in place, so the next start
/// marks again; no key keeps a stale "generated" entry behind a matching id (spec Appendix E,
/// E53).
///
/// # Errors
/// A store failure.
pub fn reconcile_store_id<R: RecordStore + ?Sized>(
    store: &R,
    log: &mut Vec<LogEntry>,
    fresh_id: &mut dyn FnMut() -> u128,
) -> std::io::Result<bool> {
    let newest = log.last().map(LogEntry::store_id);
    if log.is_empty() || newest == store.store_id()? {
        return Ok(false);
    }
    let mut seen: Vec<PublicKey> = Vec::new();
    for entry in log.iter() {
        if !seen.contains(entry.key()) {
            seen.push(entry.key().clone());
        }
    }
    let store_id = fresh_id();
    for key in seen {
        let entry = LogEntry::Key {
            key,
            generated: false,
            store_id,
        };
        store.append_log(&entry)?;
        log.push(entry);
    }
    store.set_store_id(store_id)?;
    Ok(true)
}

/// The §7.4 record-provenance steps when instance `instance` starts with `keys` (configured and
/// retired, `(key, retired)`), then what is on disk for each key:
///
/// 1. store-id check (rule 3, [`reconcile_store_id`]): if the id next to the record files
///    differs from the newest log entry's, or one of them is missing while the log has entries,
///    every key of the log is durably marked imported;
/// 2. a key without a key entry is recorded as imported;
/// 3. installation event (rule 2) of every `(instance, key)` the log lacks: the initial record
///    `{instance, epoch: genesis_epoch, key, height: genesis_height}` is written first — only for a key generated on
///    this node or when the operator asserts it never signed for the instance
///    (`assert_fresh`), and never over an existing record file — then the entry.
///
/// # Errors
/// A store failure; the driver does not start.
#[allow(clippy::too_many_arguments)] // authenticated genesis context is an independent required input
pub fn install_records<R: RecordStore + ?Sized>(
    store: &R,
    crypto: &dyn Crypto,
    instance: &Hash32,
    genesis_epoch: iroha_sumeragi::types::EpochId,
    keys: &[(PublicKey, bool)],
    genesis_height: u64,
    assert_fresh: bool,
    fresh_id: &mut dyn FnMut() -> u128,
) -> std::io::Result<Vec<(PublicKey, RecordState, bool)>> {
    let mut log = store.log()?;
    reconcile_store_id(store, &mut log, fresh_id)?;
    let mut out = Vec::with_capacity(keys.len());
    for (key, retired) in keys {
        let known = log
            .iter()
            .any(|e| matches!(e, LogEntry::Key { key: k, .. } if k == key));
        if !known {
            let key = key.clone();
            append(
                store,
                |store_id| LogEntry::Key {
                    key,
                    generated: false,
                    store_id,
                },
                fresh_id,
                &mut log,
            )?;
        }
        let generated = log
            .iter()
            .rev()
            .find_map(|e| match e {
                LogEntry::Key {
                    key: k, generated, ..
                } if k == key => Some(*generated),
                _ => None,
            })
            .unwrap_or(false);
        let started = log.iter().any(
            |e| matches!(e, LogEntry::Instance { instance: i, key: k, .. } if i == instance && k == key),
        );
        if !started {
            let absent = store.load(instance, key)? == RecordState::Absent;
            if absent && (generated || assert_fresh) {
                let record = SafetyRecord::fresh(
                    *instance,
                    genesis_epoch,
                    key.clone(),
                    genesis_height,
                    None,
                );
                let bytes = record
                    .encode(crypto)
                    .map_err(|e| std::io::Error::other(e.to_string()))?;
                store.write(instance, key, &bytes)?;
            }
            let key = key.clone();
            append(
                store,
                |store_id| LogEntry::Instance {
                    instance: *instance,
                    key,
                    store_id,
                },
                fresh_id,
                &mut log,
            )?;
        }
        out.push((key.clone(), store.load(instance, key)?, *retired));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use iroha_sumeragi::testing::FakeCrypto;

    use super::{super::tests::fakes::FakeRecords, *};

    fn record(height: u64) -> Write {
        let key = PublicKey::new(vec![1; 32]).unwrap();
        Write::Record(Box::new(SafetyRecord::fresh(
            Hash32::ZERO,
            iroha_sumeragi::testing::TEST_EPOCH.id,
            key,
            height,
            None,
        )))
    }

    #[test]
    fn initial_record_binds_the_supplied_authenticated_genesis_epoch() {
        let crypto = FakeCrypto::new();
        let store = FakeRecords::default();
        let instance = Hash32([0x81; 32]);
        let key = PublicKey::new(vec![0x82; 32]).unwrap();
        let epoch = iroha_sumeragi::types::EpochId {
            epoch: 7,
            context: Hash32([0x83; 32]),
        };
        store.install_key(&key, true, 1);
        let mut id = 1;
        let found = install_records(
            &store,
            &crypto,
            &instance,
            epoch,
            &[(key, false)],
            20,
            false,
            &mut || {
                id += 1;
                id
            },
        )
        .unwrap();
        let RecordState::Present(bytes) = &found[0].1 else {
            panic!("generated key receives its initial record")
        };
        let record = SafetyRecord::decode(&crypto, bytes).unwrap();
        assert_eq!(record.epoch, epoch);
        assert_eq!(record.height, 20);
        assert_eq!(record.instance, instance);
    }

    #[test]
    fn backoff_doubles_to_its_cap() {
        let backoff = Backoff::default();
        let delays: Vec<Millis> = (1..=9).map(|n| backoff.delay(n)).collect();
        assert_eq!(delays, vec![10, 20, 40, 80, 160, 320, 640, 1_000, 1_000]);
        assert_eq!(backoff.delay(u32::MAX), 1_000);
    }

    /// One write in flight, first in first out; the watermark follows completions.
    #[test]
    fn queue_order_and_watermark() {
        let mut queue = PersistQueue::new(Backoff::default());
        assert!(queue.is_empty());
        let a = queue.push(Write::Prune(1));
        let b = queue.push(record(2));
        assert_eq!((a, b), (1, 2));
        let (seq, write) = queue.next(0).unwrap();
        assert_eq!((seq, write), (1, Write::Prune(1)));
        assert!(queue.next(0).is_none(), "one write in flight");
        assert_eq!(queue.done(1), 1);
        assert_eq!(queue.next(0).map(|(s, _)| s), Some(2));
        assert_eq!(queue.done(2), 2);
        assert_eq!(queue.durable(), 2);
        assert!(queue.is_empty() && queue.next(0).is_none());
        assert_eq!(queue.done(7), 2, "an unknown completion changes nothing");
    }

    /// A failed write is retried after its backoff and never skipped: nothing behind it
    /// becomes durable first.
    #[test]
    fn retry_without_skipping() {
        let mut queue = PersistQueue::new(Backoff::default());
        queue.push(record(1));
        queue.push(Write::Prune(1));
        let (seq, write) = queue.next(100).unwrap();
        queue.failed(seq, write, 100);
        assert_eq!(queue.wakeup(), 110);
        assert!(queue.next(109).is_none(), "backing off");
        let (again, write) = queue.next(110).unwrap();
        assert_eq!(again, 1, "the failed write is retried first");
        queue.failed(again, write, 110);
        assert_eq!(queue.wakeup(), 130, "the delay doubles");
        let (again, _) = queue.next(130).unwrap();
        assert_eq!(queue.done(again), 1);
        assert_eq!(queue.wakeup(), Millis::MAX);
        assert_eq!(queue.next(130).map(|(s, _)| s), Some(2));
        assert_eq!(queue.len(), 1);
    }

    /// A queued record is superseded by a newer one of the same key (not one of another key,
    /// nor the one in flight); a prune drops the queued bodies it would delete.
    #[test]
    fn records_supersede_and_prune_drops_bodies() {
        let mut queue = PersistQueue::new(Backoff::default());
        let other = Box::new(SafetyRecord::fresh(
            Hash32::ZERO,
            iroha_sumeragi::testing::TEST_EPOCH.id,
            PublicKey::new(vec![2; 32]).unwrap(),
            1,
            None,
        ));
        let Write::Record(r1) = record(1) else {
            unreachable!()
        };
        let body = |h: u64| {
            Write::Body(Box::new(super::super::tests::block(
                h,
                Hash32::ZERO,
                Hash32::ZERO,
                vec![0; 10],
            )))
        };
        assert_eq!(queue.push_record(r1.clone()), (1, None));
        assert_eq!(queue.next(0).map(|(s, _)| s), Some(1), "in flight");
        assert_eq!(
            queue.push_record(r1.clone()),
            (2, None),
            "not the one in flight"
        );
        queue.push(body(3));
        assert_eq!(queue.push_record(other), (4, None), "another key");
        queue.push(body(4));
        assert_eq!(queue.push_record(r1.clone()), (6, Some(2)));
        assert_eq!(queue.push_record(r1), (7, Some(6)));
        assert_eq!(queue.queued_records(), 2);
        assert_eq!(queue.queued_bodies(), BTreeMap::from([(3, 10), (4, 10)]));
        queue.push(Write::Prune(3));
        assert_eq!(queue.queued_bodies(), BTreeMap::from([(4, 10)]));
        assert_eq!(queue.done(1), 1);
        let order: Vec<u64> = std::iter::from_fn(|| {
            let (seq, _) = queue.next(0)?;
            queue.done(seq);
            Some(seq)
        })
        .collect();
        assert_eq!(order, vec![4, 5, 7, 8]);
    }

    /// A record that fails while a newer one of its key waits is dropped, not retried: the
    /// newer one supersedes it (the queue never holds two records of a key).
    #[test]
    fn failed_record_superseded_by_a_queued_one() {
        let mut queue = PersistQueue::new(Backoff::default());
        let Write::Record(r) = record(1) else {
            unreachable!()
        };
        queue.push_record(r.clone());
        let (seq, write) = queue.next(0).unwrap();
        assert_eq!(queue.push_record(r.clone()), (2, None));
        assert_eq!(queue.failed(seq, write, 0), Some((1, 2)));
        assert_eq!(queue.queued_records(), 1);
        assert!(
            queue.next(5).is_none(),
            "the newer record waits for the backoff"
        );
        let (seq, write) = queue.next(10).unwrap();
        assert_eq!(seq, 2);
        assert_eq!(queue.failed(seq, write, 10), None, "nothing newer: retried");
        assert_eq!(queue.queued_records(), 1);
        assert_eq!(queue.next(30).map(|(s, _)| s), Some(2));
    }

    /// A store that panics fails the write, which comes back to be retried.
    #[test]
    fn panicking_store_fails_the_write() {
        let crypto = FakeCrypto::new();
        let records = FakeRecords::default();
        let bodies = super::super::tests::fakes::FakeBodies::default();
        records.panic_next(1);
        let write = record(4);
        assert_eq!(
            perform(&records, &bodies, &crypto, write.clone()),
            Err(write.clone())
        );
        assert_eq!(perform(&records, &bodies, &crypto, write), Ok(()));
    }

    /// `perform` writes records and bodies to their stores and hands a failed write back.
    #[test]
    fn perform_writes_or_returns_the_write() {
        let crypto = FakeCrypto::new();
        let records = FakeRecords::default();
        let bodies = super::super::tests::fakes::FakeBodies::default();
        let Write::Record(r) = record(4) else {
            unreachable!()
        };
        assert!(perform(&records, &bodies, &crypto, Write::Record(r.clone())).is_ok());
        assert!(matches!(
            records.load(&r.instance, &r.key).unwrap(),
            RecordState::Present(_)
        ));
        records.fail_next(1);
        let back = perform(&records, &bodies, &crypto, Write::Record(r.clone()));
        assert_eq!(back, Err(Write::Record(r)));
    }

    /// The store-id check marks every key of a mismatched log imported as one event: the marks
    /// carry one fresh id, and the id file is written after them.
    #[test]
    fn reconcile_marks_every_key_then_writes_the_id() {
        let store = FakeRecords::default();
        let mut next = 10u128;
        let mut fresh = || {
            next += 1;
            next
        };
        let mut log = Vec::new();
        assert!(!reconcile_store_id(&store, &mut log, &mut fresh).unwrap());
        let (a, b) = (
            PublicKey::new(vec![1; 32]).unwrap(),
            PublicKey::new(vec![2; 32]).unwrap(),
        );
        store.install_key(&a, true, 1);
        store.install_key(&b, true, 2);
        let mut log = store.log().unwrap();
        assert!(
            !reconcile_store_id(&store, &mut log, &mut fresh).unwrap(),
            "ids match"
        );
        store.replace_records();
        let mut log = store.log().unwrap();
        assert!(reconcile_store_id(&store, &mut log, &mut fresh).unwrap());
        assert_eq!(log, store.log().unwrap());
        let marks: Vec<&LogEntry> = log[2..].iter().collect();
        assert_eq!(marks.len(), 2);
        assert!(marks.iter().all(|e| matches!(
            e,
            LogEntry::Key {
                generated: false,
                store_id: 11,
                ..
            }
        )));
        assert_eq!(store.store_id().unwrap(), Some(11));
        assert!(!reconcile_store_id(&store, &mut log, &mut fresh).unwrap());
    }

    /// §7.4 record provenance: the initial record only for a generated key (or with the
    /// operator assertion) and never over an existing record; a store-id mismatch makes every
    /// key imported; a started instance is never re-initialised.
    #[test]
    fn installation_events_and_store_id() {
        let crypto = FakeCrypto::new();
        let store = FakeRecords::default();
        let (i0, i1) = (Hash32([1; 32]), Hash32([2; 32]));
        let k = PublicKey::new(vec![7; 32]).unwrap();
        let mut next = 0u128;
        let mut fresh = || {
            next += 1;
            next
        };
        store.install_key(&k, true, 100);
        let got = install_records(
            &store,
            &crypto,
            &i0,
            iroha_sumeragi::testing::TEST_EPOCH.id,
            &[(k.clone(), false)],
            0,
            false,
            &mut fresh,
        )
        .unwrap();
        assert!(matches!(got[0].1, RecordState::Present(_)), "generated key");
        // A dataspace instance created later: initial record too; the log is consistent.
        let backup = store.snapshot_log();
        install_records(
            &store,
            &crypto,
            &i1,
            iroha_sumeragi::testing::TEST_EPOCH.id,
            &[(k.clone(), false)],
            0,
            false,
            &mut fresh,
        )
        .unwrap();
        // The record store is replaced by an empty one: every key imported, records Absent.
        store.replace_records();
        let got = install_records(
            &store,
            &crypto,
            &i1,
            iroha_sumeragi::testing::TEST_EPOCH.id,
            &[(k.clone(), true)],
            0,
            false,
            &mut fresh,
        )
        .unwrap();
        assert_eq!(got, vec![(k.clone(), RecordState::Absent, true)]);
        // The key store rolled back to before `i1`: the id differs → imported; no initial
        // record for `i1` without the assertion, one with it (the file being absent).
        store.restore_log(backup.clone());
        let got = install_records(
            &store,
            &crypto,
            &i1,
            iroha_sumeragi::testing::TEST_EPOCH.id,
            &[(k.clone(), false)],
            0,
            false,
            &mut fresh,
        )
        .unwrap();
        assert_eq!(got[0].1, RecordState::Absent);
        store.restore_log(backup);
        store.replace_records();
        let got = install_records(
            &store,
            &crypto,
            &i1,
            iroha_sumeragi::testing::TEST_EPOCH.id,
            &[(k.clone(), false)],
            0,
            true,
            &mut fresh,
        )
        .unwrap();
        assert!(
            matches!(got[0].1, RecordState::Present(_)),
            "operator assertion"
        );
        // Never over an existing record file.
        let bytes = SafetyRecord::fresh(
            i0,
            iroha_sumeragi::testing::TEST_EPOCH.id,
            k.clone(),
            9,
            None,
        )
        .encode(&crypto)
        .unwrap();
        store.replace_records();
        store.write(&i0, &k, &bytes).unwrap();
        store.restore_log(Vec::new());
        store.install_key(&k, true, 500);
        let got = install_records(
            &store,
            &crypto,
            &i0,
            iroha_sumeragi::testing::TEST_EPOCH.id,
            &[(k.clone(), false)],
            0,
            false,
            &mut fresh,
        )
        .unwrap();
        assert_eq!(got[0].1, RecordState::Present(bytes));
        // An unknown key is recorded as imported.
        let other = PublicKey::new(vec![8; 32]).unwrap();
        let got = install_records(
            &store,
            &crypto,
            &i0,
            iroha_sumeragi::testing::TEST_EPOCH.id,
            &[(other.clone(), false)],
            0,
            false,
            &mut fresh,
        )
        .unwrap();
        assert_eq!(got[0].1, RecordState::Absent);
        assert!(
            store
                .snapshot_log()
                .iter()
                .any(|e| matches!(e, LogEntry::Key { key, generated: false, .. } if *key == other))
        );
    }
}
