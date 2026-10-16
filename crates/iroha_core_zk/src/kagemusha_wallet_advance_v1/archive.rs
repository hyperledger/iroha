//! State-owner archive checkpoint generations under the same custody lock and iOS anchor.
//!
//! These records change no monetary head and sign no receipt. The checkpoint bytes are
//! durable before a fresh Released marker binds their digest. Original Selected/completion
//! identities survive metadata generations. Thus loss of both checkpoint copies is visible
//! from the authoritative marker, including after restart; an iOS restore is also checked
//! against its existing passcode-bound marker anchor.
//!
//! State-owner archive accesses of one coordinator phase share one archive phase
//! ([`KagemushaWalletProviderV1::with_archive_phase`]): its first access reconciles the slot and
//! checks protected storage like [`KagemushaWalletProviderV1::with_archive`]; later accesses of
//! the phase skip that reconcile, and every access that touches storage is still followed by a
//! protected-storage probe. Every custody call, poison, remembered status or reconcile ends the
//! phase. Exact archive records this process published durably are remembered, so a put of the
//! same bytes at the same key is answered without a read, write or sync.
//!
//! **Group commit.** While an embedder call is open on a slot
//! ([`KagemushaWalletProviderV1::open_archive_call`]), its archive records are staged in a
//! process-local batch ([`KagemushaWalletProviderV1::stage_archive_record`]) instead of being
//! published one by one. The call reads a staged record back with the frame and bound checks of
//! a disk read; a staged record is never evidence that a file exists and never fills the
//! phase's authenticated objects. The batch is published (drained) before every authority entry
//! of the provider (Advance, archive checkpoint publication, capsule collection, completion
//! pruning, ledger-control and setup signing), before every removal or synchronous publication
//! on the slot, early once it reaches its bounds, and when the call closes successfully. A drain
//! reads each copy once and classifies it (a conflict is the non-retryable error of a single
//! put, and nothing is written), probes protected storage once after any absent answer, then
//! stages and syncs every copy, renames every copy into place and syncs the archive directory
//! once, followed by a protected-storage probe. A checkpoint publication passes its two copies
//! to the same drain, so they share that directory sync before the marker names them. A failure
//! before any rename publishes nothing; a failure after one is uncertain for the whole batch.
//! Either way the batch is discarded and the slot poisoned, and a retry republishes the
//! identical bytes, adopting visible copies on fresh inodes. The open call is then failed: it
//! stages and publishes nothing more, every barrier inside it refuses, so no later authority
//! entry of the call can follow records it lost, and its successful close reports the failure.
//! Phase ends, poison, remembered statuses and reconciliation never touch the batch; a failed
//! or cancelled call, a terminal state of the slot and the provider's drop discard it. Without
//! an open call every record is published before its put returns.

use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, VecDeque},
};

use crate::kagemusha_wallet_archive_bytes_v1::PrivateArchiveBytes;
use zeroize::Zeroizing;

use super::{
    KagemushaWalletProviderErrorV1 as Error, KagemushaWalletUnavailableV1 as Unavailable,
    advance::KagemushaWalletAdvanceCapsuleV1,
    anchor::kagemusha_wallet_raise_anchor_v1,
    completion::KagemushaWalletCompletionFrameV1,
    kagemusha_wallet_provider_digest_v1,
    layout::{
        KagemushaWalletEntryNameV1 as Name, KagemushaWalletSlotIdV1 as Slot,
        kagemusha_wallet_archive_dir_v1, kagemusha_wallet_require_published_v1,
    },
    marker::{
        KagemushaWalletMarkerPublicationV1, KagemushaWalletMarkerRecordV1,
        kagemusha_wallet_publish_marker_v1, kagemusha_wallet_retire_markers_v1,
    },
    platform::{KagemushaWalletFsV1, KagemushaWalletPlatformV1, KagemushaWalletReadV1},
    provider::{KagemushaWalletProviderV1, KagemushaWalletSlotStatusV1},
    store::{
        KagemushaWalletBatchActionV1 as BatchAction, KagemushaWalletBatchEntryV1 as BatchEntry,
        KagemushaWalletDurableStoreV1,
    },
};

/// Bound on the local index-root manifest, not on proof/checkpoint payloads it references.
/// A manifest holds fixed incarnation/head fields and digest roots; large objects belong in
/// the archive by content digest and use the native descriptor's own size bound.
pub const KAGEMUSHA_WALLET_ARCHIVE_MANIFEST_MAX_BYTES_V1: usize = 4_096;

/// Content identity used by the source marker for its state-owner archive manifest.
#[must_use]
pub fn kagemusha_wallet_archive_checkpoint_digest_v1(bytes: &[u8]) -> [u8; 32] {
    kagemusha_wallet_provider_digest_v1("archive-checkpoint", bytes)
}

fn names(digest: &[u8; 32]) -> [Name; 2] {
    let base = format!("a-{}.chk", hex::encode(digest));
    [base.clone(), format!("{base}.r")]
        .map(|name| Name::new(&name).expect("fixed archive checkpoint name"))
}

fn read<F: KagemushaWalletFsV1>(
    store: &KagemushaWalletDurableStoreV1<F>,
    slot: &Slot,
    digest: &[u8; 32],
) -> Result<Vec<u8>, Error> {
    let directory = kagemusha_wallet_archive_dir_v1(slot);
    let mut unavailable = None;
    for name in names(digest) {
        match store.read(
            &directory,
            &name,
            KAGEMUSHA_WALLET_ARCHIVE_MANIFEST_MAX_BYTES_V1,
        ) {
            KagemushaWalletReadV1::Present(bytes)
                if kagemusha_wallet_archive_checkpoint_digest_v1(&bytes) == *digest =>
            {
                return Ok(bytes);
            }
            KagemushaWalletReadV1::Unavailable(reason) => unavailable = Some(reason),
            _ => {}
        }
    }
    Err(unavailable.map_or(
        Error::UnavailableCustodyData {
            object: "archive checkpoint",
        },
        Error::Unavailable,
    ))
}

impl<F, P, C, R> KagemushaWalletProviderV1<F, P, C, R>
where
    F: KagemushaWalletFsV1,
    P: KagemushaWalletPlatformV1,
    C: KagemushaWalletAdvanceCapsuleV1,
    R: KagemushaWalletCompletionFrameV1,
{
    /// Read the archive manifest selected by the authoritative current marker.
    ///
    /// # Errors
    /// Reconciliation/protected-storage errors and missing or corrupt checkpoint copies.
    /// `None` means the current marker has never selected an archive manifest.
    pub fn archive_checkpoint(
        &mut self,
        slot: &Slot,
    ) -> Result<Option<([u8; 32], Vec<u8>)>, Error> {
        let status = self.reconcile_slot(slot, None)?;
        let record = status.marker().ok_or(Error::Invalid {
            field: "archive.slot",
        })?;
        let digest = record.archive_checkpoint();
        let answer = if digest == [0; 32] {
            Ok(None)
        } else {
            read(&self.store, slot, &digest).map(|bytes| Some((digest, bytes)))
        };
        self.require_storage()?;
        answer
    }

    /// Compare-and-publish a durable archive manifest in a fresh metadata generation.
    ///
    /// The provider publishes the slot's pending archive batch, together with the two
    /// checkpoint copies, first: one drain makes them durable behind a single directory sync
    /// before the marker names the checkpoint. Referenced records published otherwise must be
    /// durable before this operation. This method does not select a monetary head or
    /// create/recreate any receipt. An exact retry adopts the existing checkpoint (and every
    /// pending record) on fresh inodes and preserves its original completion bytes.
    ///
    /// # Errors
    /// Stale manifest, non-Released head, invalid size, a failed open call
    /// (`Invalid("archive.call_failed")`), conflicting archive or checkpoint copies,
    /// storage/anchor errors or uncertain publication. An error never implies reversal
    /// of an already committed monetary head; reconcile the marker and compare its checkpoint
    /// digest before retrying.
    pub fn publish_archive_checkpoint(
        &mut self,
        slot: &Slot,
        expected: [u8; 32],
        bytes: &[u8],
    ) -> Result<[u8; 32], Error> {
        if bytes.is_empty() || bytes.len() > KAGEMUSHA_WALLET_ARCHIVE_MANIFEST_MAX_BYTES_V1 {
            return Err(Error::Invalid {
                field: "archive.manifest_size",
            });
        }
        let KagemushaWalletSlotStatusV1::Released(current) = self.reconcile_slot(slot, None)?
        else {
            return Err(Error::Invalid {
                field: "archive.head_not_released",
            });
        };
        let digest = kagemusha_wallet_archive_checkpoint_digest_v1(bytes);
        if current.archive_checkpoint() == digest {
            // The drain ends with the protected-storage probe of every archive access.
            self.drain_archive_with(slot, (digest, bytes))?;
            return Ok(digest);
        }
        if current.archive_checkpoint() != expected {
            return Err(Error::Invalid {
                field: "archive.stale_checkpoint",
            });
        }
        let result = (|| {
            // Durable (pending records and both copies, one directory sync) before the marker.
            self.drain_archive_with(slot, (digest, bytes))?;
            let record = current.checkpoint(digest, self.boot().unwrap_or([0; 32]))?;
            self.poison(slot);
            let durable = match kagemusha_wallet_publish_marker_v1(&self.store, record.clone())? {
                KagemushaWalletMarkerPublicationV1::Durable(durable) => durable,
                KagemushaWalletMarkerPublicationV1::GenerationTaken => {
                    return Err(Error::Unavailable(Unavailable::Busy));
                }
            };
            kagemusha_wallet_raise_anchor_v1(&self.platform, &record)?;
            kagemusha_wallet_retire_markers_v1(&self.store, &durable, &[current.generation()])?;
            self.require_storage()?;
            self.remember(slot, durable, KagemushaWalletSlotStatusV1::Released(record));
            Ok(digest)
        })();
        self.guard(slot, result)
    }

    /// Validate source-selected archive bytes during every reconcile, including cached ones.
    pub(super) fn require_archive_checkpoint(
        &self,
        record: &KagemushaWalletMarkerRecordV1,
    ) -> Result<(), Error> {
        let digest = record.archive_checkpoint();
        if digest != [0; 32] {
            read(&self.store, record.slot(), &digest)?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "archive_tests.rs"]
mod tests;

/// Content identity of one immutable state-owner archive object.
#[must_use]
pub fn kagemusha_wallet_archive_object_digest_v1(bytes: &[u8]) -> [u8; 32] {
    kagemusha_wallet_provider_digest_v1("archive-object", bytes)
}

/// A scoped archive capability: only the provider creates it, while holding the custody lock
/// and inside protected-storage availability brackets. It cannot reach markers or signers.
pub struct KagemushaWalletArchiveAccessV1<'a, F: KagemushaWalletFsV1> {
    store: &'a KagemushaWalletDurableStoreV1<F>,
    slot: &'a Slot,
    writes: &'a RefCell<ArchiveWritesV1>,
    // Records the open call of the slot staged: reads answer them before storage, and no record
    // is removed while any of them is unpublished.
    batch: Option<&'a ArchiveBatchV1>,
    // Inside an archive phase: the protected-storage probe taken before a create-new write
    // whose choice rests on an absent read. `with_archive` brackets the whole access instead.
    probe: Option<&'a dyn Fn() -> Result<(), Error>>,
    // Whether this access touched storage; an access answered from memory needs no probe.
    observed: Cell<bool>,
    // A callback cannot swallow a failed retirement then publish over its unfinished grave.
    retirement_failure: Cell<Option<Error>>,
}

/// Most records the exact-bytes archive write memo keeps; the oldest are forgotten first.
pub(super) const KAGEMUSHA_WALLET_ARCHIVE_WRITES_MAX_V1: usize = 8_192;

/// Archive records this process published durably, or adopted on a fresh inode, by slot and
/// record key, with the digest of their exact framed bytes (the record's own frame prefix).
///
/// Process-local, in memory and bounded: never persisted, serialized or used as evidence that a
/// file is present. A put of the same bytes at the same key is answered from it; other bytes
/// remain the immutable-record conflict. A record is forgotten before it is removed, and a full
/// reconcile or custody deletion forgets the whole slot.
#[derive(Debug, Default)]
pub(super) struct ArchiveWritesV1 {
    entries: BTreeMap<(Slot, [u8; 32]), [u8; 32]>,
    order: VecDeque<(Slot, [u8; 32])>,
}

impl ArchiveWritesV1 {
    fn get(&self, slot: &Slot, key: &[u8; 32]) -> Option<[u8; 32]> {
        self.entries.get(&(*slot, *key)).copied()
    }

    fn insert(&mut self, slot: &Slot, key: &[u8; 32], frame: [u8; 32]) {
        if self.entries.insert((*slot, *key), frame).is_none() {
            self.order.push_back((*slot, *key));
        }
        while self.entries.len() > KAGEMUSHA_WALLET_ARCHIVE_WRITES_MAX_V1 {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            self.entries.remove(&oldest);
        }
        if self.order.len() > 2 * KAGEMUSHA_WALLET_ARCHIVE_WRITES_MAX_V1 {
            let entries = &self.entries;
            self.order.retain(|key| entries.contains_key(key));
        }
    }

    fn forget(&mut self, slot: &Slot, key: &[u8; 32]) {
        self.entries.remove(&(*slot, *key));
    }

    /// Forget every record of `slot`.
    pub(super) fn forget_slot(&mut self, slot: &Slot) {
        self.entries.retain(|(owner, _), _| owner != slot);
        self.order.retain(|(owner, _)| owner != slot);
    }

    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }
}

/// Most records one archive batch holds; reaching it publishes the batch early.
pub(super) const KAGEMUSHA_WALLET_ARCHIVE_BATCH_RECORDS_MAX_V1: usize = 512;
/// Most bytes (framed records and kept object content) one archive batch holds in memory;
/// reaching it publishes the batch early.
pub(super) const KAGEMUSHA_WALLET_ARCHIVE_BATCH_BYTES_MAX_V1: usize = 8 * 1024 * 1024;

/// One record staged by an open call: its exact framed bytes (digest prefix and payload) and,
/// for an archive object, the authenticated content its successful drain keeps for the phase.
#[derive(Debug)]
struct StagedRecordV1 {
    frame: [u8; 32],
    framed: PrivateArchiveBytes,
    object: Option<(KagemushaWalletArchiveObjectKeyV1, PrivateArchiveBytes)>,
}

/// Records staged by the open call of one slot, by record key (see the module documentation).
///
/// Process-local and bounded ([`KAGEMUSHA_WALLET_ARCHIVE_BATCH_RECORDS_MAX_V1`],
/// [`KAGEMUSHA_WALLET_ARCHIVE_BATCH_BYTES_MAX_V1`]): never persisted, never evidence that a file
/// is present and never an authority. Every staged allocation is cleared when it is released.
#[derive(Debug, Default)]
pub(super) struct ArchiveBatchV1 {
    records: BTreeMap<[u8; 32], StagedRecordV1>,
    bytes: usize,
    // The error of a drain that lost records of this call: the call is failed until it is
    // closed, discarded or opened again.
    failed: Option<Error>,
}

impl ArchiveBatchV1 {
    fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

/// How a staging request is answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StagingV1 {
    /// The exact bytes were already published durably at the key by this process.
    Remembered,
    /// The open call already staged the exact bytes at the key.
    Coalesced,
    /// The bytes join the batch.
    New,
}

/// Authenticated object bytes one archive phase keeps in memory.
pub(super) const KAGEMUSHA_WALLET_ARCHIVE_PHASE_OBJECT_BYTES_V1: usize = 4 * 1024 * 1024;
/// Larger objects are never kept by an archive phase.
pub(super) const KAGEMUSHA_WALLET_ARCHIVE_PHASE_OBJECT_MAX_V1: usize = 64 * 1024;

/// Identity of one authenticated archive object: scheme, wallet and archive record key.
pub(crate) type KagemushaWalletArchiveObjectKeyV1 = [[u8; 32]; 3];

/// One archive phase of a slot (see the module documentation).
///
/// It is opened by the full archive entry check (reconcile, slot status gate and protected-storage
/// probes) and bound to the exact durable marker bytes and verified enrollment phase that check
/// saw; any difference ends it. It keeps, bounded, the content of archive objects authenticated
/// during the phase (read with every check, or published durably), and drops them with the
/// phase. Every kept payload has a non-cloneable clearing owner: removal, eviction,
/// invalidation and drop clear its allocation. A kept object is never evidence that
/// a file is present on disk.
#[derive(Debug)]
pub(super) struct ArchivePhaseV1 {
    slot: Slot,
    marker: Vec<u8>,
    enrollment: Option<([u8; 32], [Vec<u8>; 4])>,
    objects: BTreeMap<KagemushaWalletArchiveObjectKeyV1, PrivateArchiveBytes>,
    order: VecDeque<KagemushaWalletArchiveObjectKeyV1>,
    bytes: usize,
}

impl ArchivePhaseV1 {
    fn keep(
        &mut self,
        key: KagemushaWalletArchiveObjectKeyV1,
        content: &[u8],
    ) -> Result<(), Error> {
        if content.len() > KAGEMUSHA_WALLET_ARCHIVE_PHASE_OBJECT_MAX_V1
            || self.objects.contains_key(&key)
        {
            return Ok(());
        }
        // Each retained payload has its own clearing allocation. The owner is never cloned.
        let owned = PrivateArchiveBytes::copy_from(content).map_err(private_copy_error)?;
        self.objects.insert(key, owned);
        self.order.push_back(key);
        self.bytes = self.bytes.saturating_add(content.len());
        while self.bytes > KAGEMUSHA_WALLET_ARCHIVE_PHASE_OBJECT_BYTES_V1 {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            if let Some(evicted) = self.objects.remove(&oldest) {
                self.bytes = self.bytes.saturating_sub(evicted.len());
            }
        }
        if self.order.len() > 2 * self.objects.len() + 64 {
            let objects = &self.objects;
            self.order.retain(|key| objects.contains_key(key));
        }
        Ok(())
    }

    fn forget(&mut self, key: &KagemushaWalletArchiveObjectKeyV1) {
        if let Some(evicted) = self.objects.remove(key) {
            self.bytes = self.bytes.saturating_sub(evicted.len());
        }
    }
}

impl<F: KagemushaWalletFsV1> KagemushaWalletArchiveAccessV1<'_, F> {
    // Every storage access goes through here, so an archive phase knows to probe after it.
    fn store(&self) -> &KagemushaWalletDurableStoreV1<F> {
        self.observed.set(true);
        self.store
    }
}

impl<F, P, C, R> KagemushaWalletProviderV1<F, P, C, R>
where
    F: KagemushaWalletFsV1,
    P: KagemushaWalletPlatformV1,
    C: KagemushaWalletAdvanceCapsuleV1,
    R: KagemushaWalletCompletionFrameV1,
{
    /// Run bounded archive operations under the exclusive provider and protected-data checks.
    /// The callback cannot create a selected marker, sign a receipt or choose another root.
    /// Records staged for `slot` by an open call are published first, so every write of the
    /// callback is durable on return and follows them.
    ///
    /// # Errors
    /// The drain errors of [`Self::drain_archive`], reconciliation, callback or
    /// protected-storage errors. A failed final probe supersedes the callback answer, so
    /// eviction never masquerades as missing private data.
    pub fn with_archive<T>(
        &mut self,
        slot: &Slot,
        operation: impl FnOnce(&KagemushaWalletArchiveAccessV1<'_, F>) -> Result<T, Error>,
    ) -> Result<T, Error> {
        self.drain_archive(slot)?;
        let status = self.reconcile_slot(slot, None)?;
        require_archive_status(&status)?;
        let access = KagemushaWalletArchiveAccessV1 {
            store: &self.store,
            slot,
            writes: &self.archive_writes,
            batch: self.archive_batches.get(slot),
            probe: None,
            observed: Cell::new(false),
            retirement_failure: Cell::new(None),
        };
        let result = operation(&access);
        let result = access.retirement_failure.get().map_or(result, Err);
        let result = self.require_storage().and(result);
        self.guard_archive(slot, result)
    }

    /// Run one state-owner archive access inside the current archive phase of `slot`.
    ///
    /// Without a current phase this performs the entry check of [`Self::with_archive`]
    /// (reconcile and slot status gate) and opens a phase bound to the durable marker and
    /// verified enrollment phase it saw. Within the phase the reconcile is skipped. An access
    /// that touches storage, and every error, is followed by a protected-storage probe whose
    /// failure supersedes the answer; a create-new write additionally probes after the absent
    /// read it rests on. An access answered from memory (an exact-bytes memo hit, a staged
    /// record) touches no storage and needs no probe. Errors poison the slot, which ends the
    /// phase.
    ///
    /// # Errors
    /// As [`Self::with_archive`].
    pub(crate) fn with_archive_phase<T>(
        &mut self,
        slot: &Slot,
        operation: impl FnOnce(&KagemushaWalletArchiveAccessV1<'_, F>) -> Result<T, Error>,
    ) -> Result<T, Error> {
        if !self.archive_phase_current(slot) {
            // Reconciliation ends any earlier phase before it reads anything.
            let status = self.reconcile_slot(slot, None)?;
            require_archive_status(&status)?;
            let enrollment = self.slot_phases.borrow().get(slot).cloned();
            self.archive_phase = self
                .cache
                .get(slot)
                .filter(|cached| cached.status == status)
                .map(|cached| ArchivePhaseV1 {
                    slot: *slot,
                    marker: cached.durable.record().file_bytes().to_vec(),
                    enrollment,
                    objects: BTreeMap::new(),
                    order: VecDeque::new(),
                    bytes: 0,
                });
        }
        self.archive_access(slot, operation)
    }

    // One archive access of `slot` after its entry check (a reconcile and the slot status gate,
    // by the caller or at phase open): a protected-storage probe follows an access that touched
    // storage and every error, and its failure supersedes the answer; a create-new choice that
    // rests on an absent read probes first; errors poison the slot.
    fn archive_access<T>(
        &mut self,
        slot: &Slot,
        operation: impl FnOnce(&KagemushaWalletArchiveAccessV1<'_, F>) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let probe = || self.require_storage();
        let access = KagemushaWalletArchiveAccessV1 {
            store: &self.store,
            slot,
            writes: &self.archive_writes,
            batch: self.archive_batches.get(slot),
            probe: Some(&probe),
            observed: Cell::new(false),
            retirement_failure: Cell::new(None),
        };
        let result = operation(&access);
        let result = access.retirement_failure.get().map_or(result, Err);
        let observed = access.observed.get();
        let result = if observed || result.is_err() {
            self.require_storage().and(result)
        } else {
            result
        };
        self.guard_archive(slot, result)
    }

    // `guard` of an archive access: an error also makes the next full reconcile of `slot` sweep
    // the archive directory, where a failed write may have left staging files (`reconcile.rs`).
    fn guard_archive<T>(&mut self, slot: &Slot, result: Result<T, Error>) -> Result<T, Error> {
        if result.is_err() {
            self.archive_swept.remove(slot);
        }
        self.guard(slot, result)
    }

    /// Whether the archive phase of `slot` is open and still bound to the exact durable marker
    /// and verified enrollment phase of the slot.
    fn archive_phase_current(&self, slot: &Slot) -> bool {
        let Some(phase) = &self.archive_phase else {
            return false;
        };
        phase.slot == *slot
            && self.cache.get(slot).is_some_and(|cached| {
                cached.durable.record().file_bytes() == phase.marker.as_slice()
            })
            && self.slot_phases.borrow().get(slot) == phase.enrollment.as_ref()
    }

    /// End the current archive phase: the next archive access reconciles its slot again.
    pub(crate) fn end_archive_phase(&mut self) {
        self.archive_phase = None;
    }

    /// Authenticated content kept by the current archive phase of `slot` for `key`, when it
    /// is within `max_bytes` (any other bound is answered from disk).
    /// A checked copy failure ends the phase and returns no content.
    pub(crate) fn archive_phase_object(
        &mut self,
        slot: &Slot,
        key: &KagemushaWalletArchiveObjectKeyV1,
        max_bytes: usize,
    ) -> Result<Option<PrivateArchiveBytes>, Error> {
        if !self.archive_phase_current(slot) {
            self.archive_phase = None;
            return Ok(None);
        }
        let Some(content) = self
            .archive_phase
            .as_ref()
            .and_then(|phase| phase.objects.get(key))
            .filter(|content| content.len() <= max_bytes)
        else {
            return Ok(None);
        };
        // A hit returns a separate clearing owner; neither caller nor phase can expose
        // an owning Vec or extend the other's private allocation lifetime.
        let content = PrivateArchiveBytes::copy_from(content).map_err(private_copy_error);
        match content {
            Ok(content) => {
                super::counters::count(super::counters::EventV1::ArchiveObjectCacheHit);
                Ok(Some(content))
            }
            Err(error) => {
                self.end_archive_phase();
                Err(error)
            }
        }
    }

    /// Keep authenticated object content for the rest of the current archive phase of `slot`:
    /// content read with every archive and object check, or published durably by a put.
    /// Content of a record that is staged and not yet published is never kept (a read answered
    /// by the batch is not durable). A checked copy failure ends the phase; any already durable
    /// publication remains durable.
    pub(crate) fn keep_archive_phase_object(
        &mut self,
        slot: &Slot,
        key: KagemushaWalletArchiveObjectKeyV1,
        content: &[u8],
    ) -> Result<(), Error> {
        let [_, _, record] = key;
        let staged = self
            .archive_batches
            .get(slot)
            .is_some_and(|batch| batch.records.contains_key(&record));
        let result = if !staged
            && self.archive_phase_current(slot)
            && let Some(phase) = self.archive_phase.as_mut()
        {
            phase.keep(key, content)
        } else {
            Ok(())
        };
        if result.is_err() {
            self.end_archive_phase();
        }
        result
    }

    /// Drop `key` from the current archive phase before its object is removed.
    pub(crate) fn forget_archive_phase_object(&mut self, key: &KagemushaWalletArchiveObjectKeyV1) {
        if let Some(phase) = self.archive_phase.as_mut() {
            phase.forget(key);
        }
    }

    /// Forget every remembered archive write of `slot` (full reconcile, custody deletion).
    pub(super) fn forget_archive_writes(&self, slot: &Slot) {
        self.archive_writes.borrow_mut().forget_slot(slot);
    }
}

// Group commit (see the module documentation).
impl<F, P, C, R> KagemushaWalletProviderV1<F, P, C, R>
where
    F: KagemushaWalletFsV1,
    P: KagemushaWalletPlatformV1,
    C: KagemushaWalletAdvanceCapsuleV1,
    R: KagemushaWalletCompletionFrameV1,
{
    /// Open an embedder call on `slot`: until [`Self::close_archive_call`] its archive records
    /// are staged ([`Self::stage_archive_record`]) and published together at the next barrier.
    /// The embedder opens one call per externally visible call while it holds exclusive access
    /// to the wallet, and closes it before releasing that access. Records left staged by a call
    /// that was never closed are discarded, never published, and counted; the new call starts
    /// clean, also after a failed one.
    pub fn open_archive_call(&mut self, slot: &Slot) {
        if self
            .archive_batches
            .insert(*slot, ArchiveBatchV1::default())
            .is_some_and(|left| !left.is_empty())
        {
            super::counters::count(super::counters::EventV1::ArchiveBatchAbandoned);
        }
    }

    /// Close the open call of `slot`. A successful call publishes every record it staged
    /// ([`Self::drain_archive`]); a failed or cancelled call discards them, and the archive
    /// phase ends. Without an open call nothing is staged and nothing happens.
    ///
    /// # Errors
    /// When `succeeded`: the error of an earlier drain that failed the call, or the errors of
    /// [`Self::drain_archive`]. The call's records are then discarded, the slot is poisoned,
    /// and the error replaces the call's answer. The call is closed either way.
    pub fn close_archive_call(&mut self, slot: &Slot, succeeded: bool) -> Result<(), Error> {
        if !succeeded {
            self.discard_archive(slot);
            return Ok(());
        }
        let drained = self.drain_archive(slot);
        let failed = self
            .archive_batches
            .remove(slot)
            .and_then(|call| call.failed);
        failed.map_or(drained, Err)
    }

    /// Discard every record staged for `slot` and close its open call: nothing staged is
    /// published (a failed or cancelled call, a terminal transition of the slot). This ends the
    /// archive phase.
    pub fn discard_archive(&mut self, slot: &Slot) {
        self.archive_batches.remove(slot);
        self.end_archive_phase();
    }

    /// Put the exact `bytes` at the immutable record `key` of `slot`.
    ///
    /// Inside an open call the record is staged: bytes this process already published durably
    /// at the key, or already staged there, are answered from memory; other bytes are the
    /// immutable-record conflict of [`KagemushaWalletArchiveAccessV1::write_record`]. Staging
    /// passes the archive entry check (reconcile at phase open and the slot status gate) and
    /// touches no storage; conflicts with disk are found when the batch is published, before any
    /// rename. The record is readable by the call at once and durable no later than the next
    /// barrier; a batch that reaches its bounds is published at once. `object` is the
    /// authenticated content of an archive object (`[scheme, wallet, key]`): it is kept for the
    /// archive phase only after the record is durable. Without an open call this is
    /// [`Self::publish_archive_record`].
    ///
    /// # Errors
    /// `Invalid("archive.call_failed")` inside a call whose drain failed; the conflict, the
    /// archive entry check errors and, for an early or synchronous publication, the errors of
    /// [`Self::drain_archive`] and [`Self::publish_archive_record`].
    pub fn stage_archive_record(
        &mut self,
        slot: &Slot,
        key: &[u8; 32],
        bytes: &[u8],
        object: Option<([[u8; 32]; 3], &[u8])>,
    ) -> Result<(), Error> {
        if !self.archive_batches.contains_key(slot) {
            return self.publish_archive_record(slot, key, bytes, object);
        }
        self.require_archive_call_intact(slot)?;
        super::counters::count(super::counters::EventV1::ArchivePut);
        let frame = kagemusha_wallet_archive_object_digest_v1(bytes);
        match self.with_archive_phase(slot, |archive| archive.staging(key, &frame, bytes))? {
            StagingV1::Remembered => {
                super::counters::count(super::counters::EventV1::ArchivePutMemoHit);
                if let Some((object, content)) = object {
                    // Durable already: the exact content stays readable for the phase, as
                    // after a synchronous put.
                    self.keep_archive_phase_object(slot, object, content)?;
                }
                return Ok(());
            }
            StagingV1::Coalesced => {
                super::counters::count(super::counters::EventV1::ArchivePutBatchHit);
                return Ok(());
            }
            StagingV1::New => {}
        }
        let mut framed = Zeroizing::new(vec![0; record_limit(bytes.len())?]);
        framed[..32].copy_from_slice(&frame);
        framed[32..].copy_from_slice(bytes);
        let object = object
            .map(|(object, content)| {
                PrivateArchiveBytes::copy_from(content).map(|content| (object, content))
            })
            .transpose()
            .map_err(private_copy_error)?;
        let size = framed.len().saturating_add(
            object
                .as_ref()
                .map_or(0, |(_, content)| content.as_slice().len()),
        );
        let batch = self.archive_batches.get_mut(slot).ok_or(Error::Invalid {
            field: "archive.call",
        })?;
        batch.records.insert(
            *key,
            StagedRecordV1 {
                frame,
                framed: PrivateArchiveBytes::from_guarded(framed),
                object,
            },
        );
        batch.bytes = batch.bytes.saturating_add(size);
        if batch.records.len() >= KAGEMUSHA_WALLET_ARCHIVE_BATCH_RECORDS_MAX_V1
            || batch.bytes >= KAGEMUSHA_WALLET_ARCHIVE_BATCH_BYTES_MAX_V1
        {
            // Earlier durability is always safe.
            self.drain_archive(slot)?;
        }
        Ok(())
    }

    /// Publish the exact `bytes` at the immutable record `key` of `slot` before returning, as a
    /// put outside any call does: records staged for the slot are published first (a fixed-key
    /// record that binds another record follows its referents), then both copies of this one
    /// ([`KagemushaWalletArchiveAccessV1::write_record`] inside the archive phase). `object`,
    /// the authenticated content of an archive object, is then kept for the phase.
    ///
    /// # Errors
    /// The errors of [`Self::drain_archive`] and of the synchronous put.
    pub fn publish_archive_record(
        &mut self,
        slot: &Slot,
        key: &[u8; 32],
        bytes: &[u8],
        object: Option<([[u8; 32]; 3], &[u8])>,
    ) -> Result<(), Error> {
        self.drain_archive(slot)?;
        super::counters::count(super::counters::EventV1::ArchiveSyncPut);
        self.with_archive_phase(slot, |archive| archive.write_record(key, bytes))?;
        if let Some((object, content)) = object {
            // Both copies are durable: the exact content stays readable for the phase.
            self.keep_archive_phase_object(slot, object, content)?;
        }
        Ok(())
    }

    /// Remove both copies of the record `key` of `slot` after every record staged for the slot
    /// is published: a staged record is never published after its own removal, and a removal
    /// never precedes the publication of what was staged before it. The phase's kept `object`
    /// (`[scheme, wallet, key]`) and the exact-bytes memo forget the record before anything is
    /// unlinked.
    ///
    /// # Errors
    /// The errors of [`Self::drain_archive`] and of
    /// [`KagemushaWalletArchiveAccessV1::remove_record`].
    pub fn remove_archive_record(
        &mut self,
        slot: &Slot,
        key: &[u8; 32],
        object: &[[u8; 32]; 3],
    ) -> Result<(), Error> {
        self.drain_archive(slot)?;
        self.forget_archive_phase_object(object);
        self.with_archive_phase(slot, |archive| archive.remove_record(key))
    }

    /// Publish every record staged for `slot` (the archive barrier). An empty batch returns at
    /// once, without a storage access or probe. Otherwise, inside the archive phase (its entry
    /// check included): each copy is read once and classified, one protected-storage probe
    /// follows any absent answer, and every copy is staged and synced, renamed (create-new, or a
    /// fresh-inode adoption of identical visible bytes) and covered by one archive directory
    /// sync, followed by a probe. Only then are the records remembered as durable and their
    /// objects kept for the phase. The batch is taken first: on any error it is discarded, the
    /// slot poisoned and the open call failed (it stays open, and refuses every later barrier,
    /// put and successful close).
    ///
    /// # Errors
    /// `Invalid("archive.call_failed")` inside a call whose drain failed. A conflict with disk
    /// is the non-retryable error of a single put (`Invalid("archive.immutable_record")`,
    /// `UnavailableCustodyData`); storage outcomes are `NoSpace`, `NoReplaceUnsupported` or
    /// `Unavailable` before any rename and `Uncertain` after one; the archive entry check and
    /// probe errors.
    pub fn drain_archive(&mut self, slot: &Slot) -> Result<(), Error> {
        self.require_archive_call_intact(slot)?;
        let batch = self.take_archive_batch(slot);
        if batch.is_empty() {
            return Ok(());
        }
        let published =
            self.with_archive_phase(slot, |archive| archive.publish_records(&batch, None));
        self.finish_drain(slot, batch, published)
    }

    // The drain of a checkpoint publication, after its own reconcile found a Released head: the
    // staged records and both copies of the checkpoint behind one archive directory sync.
    fn drain_archive_with(
        &mut self,
        slot: &Slot,
        checkpoint: ([u8; 32], &[u8]),
    ) -> Result<(), Error> {
        self.require_archive_call_intact(slot)?;
        let batch = self.take_archive_batch(slot);
        let published = self.archive_access(slot, |archive| {
            archive.publish_records(&batch, Some(checkpoint))
        });
        self.finish_drain(slot, batch, published)
    }

    // The staged records of `slot`, taken out of its batch; an open call stays open.
    fn take_archive_batch(&mut self, slot: &Slot) -> ArchiveBatchV1 {
        self.archive_batches
            .get_mut(slot)
            .map(std::mem::take)
            .unwrap_or_default()
    }

    // After a publication: a failed one discards the batch (its access poisoned the slot) and
    // fails the open call, whose lost records no later barrier of the call may pass over; a
    // durable one keeps each object's content for the current phase.
    fn finish_drain(
        &mut self,
        slot: &Slot,
        batch: ArchiveBatchV1,
        published: Result<(), Error>,
    ) -> Result<(), Error> {
        if let Err(error) = published {
            self.fail_archive_call(slot, error);
            return Err(error);
        }
        for record in batch.records.values() {
            if let Some((key, content)) = &record.object {
                self.keep_archive_phase_object(slot, *key, content.as_slice())?;
            }
        }
        Ok(())
    }

    // Fail the open call of `slot` with `error`: the records it staged are discarded, never
    // published, and until it is closed, discarded or opened again it stages and publishes
    // nothing, every barrier refuses and its successful close reports `error`. Without an open
    // call nothing happens.
    pub(super) fn fail_archive_call(&mut self, slot: &Slot, error: Error) {
        if let Some(call) = self.archive_batches.get_mut(slot) {
            *call = ArchiveBatchV1 {
                failed: Some(error),
                ..ArchiveBatchV1::default()
            };
        }
    }

    // Inside an open call of `slot` whose drain failed, nothing may stage, publish or pass a
    // barrier: records the call staged before were lost with that batch.
    fn require_archive_call_intact(&self, slot: &Slot) -> Result<(), Error> {
        if self
            .archive_batches
            .get(slot)
            .is_some_and(|call| call.failed.is_some())
        {
            return Err(Error::Invalid {
                field: "archive.call_failed",
            });
        }
        Ok(())
    }

    /// Whether no record is staged for `slot`.
    pub(super) fn archive_batch_is_empty(&self, slot: &Slot) -> bool {
        self.archive_batches
            .get(slot)
            .is_none_or(ArchiveBatchV1::is_empty)
    }
}

// Archive records belong to a slot with a current enrollment, pending or released marker.
fn require_archive_status(status: &KagemushaWalletSlotStatusV1) -> Result<(), Error> {
    if matches!(
        status,
        KagemushaWalletSlotStatusV1::Enrollment(_)
            | KagemushaWalletSlotStatusV1::Pending(_)
            | KagemushaWalletSlotStatusV1::Released(_)
    ) {
        Ok(())
    } else {
        Err(Error::Invalid {
            field: "archive.slot",
        })
    }
}

fn record_names(key: &[u8; 32]) -> [Name; 2] {
    let base = format!("w-{}.rec", hex::encode(key));
    [base.clone(), format!("{base}.r")]
        .map(|name| Name::new(&name).expect("fixed archive record name"))
}
// Graves carry independent 128-bit retirement nonces. Only the permanent journal may
// authorize replay; an unreferenced grave is garbage and never restores a record name.
fn grave_names(key: &[u8; 32], nonce: &str) -> [Name; 2] {
    record_names(key).map(|name| {
        Name::new(&format!("{}.g-{nonce}", name.as_str()))
            .expect("bounded nonce-qualified archive grave")
    })
}

fn parse_grave(name: &str) -> Option<Name> {
    let (record, nonce) = name.split_once(".g-")?;
    let canonical_hex = |text: &str, len| {
        text.len() == len
            && text
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    };
    if !canonical_hex(nonce, 32) {
        return None;
    }
    let stem = record.strip_prefix("w-")?;
    let key = stem
        .strip_suffix(".rec.r")
        .or_else(|| stem.strip_suffix(".rec"))?;
    canonical_hex(key, 64).then(|| Name::new(record)).flatten()
}

const RETIREMENT_MAX_BYTES: usize = 1024;

fn retirement_name() -> Name {
    Name::new("retirement.norito").expect("fixed archive retirement journal name")
}

// This bounded cell is never deleted. Complete(N) can only be replaced by a durable
// Pending(N+1), before the next incarnation's original names are touched. It holds no
// monetary object or payload, only the exact slot, record and unique grave identities.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, norito::Encode, norito::Decode, norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_core::zk::kagemusha_wallet_advance_v1::ArchiveRetirementV1")]
struct ArchiveRetirementV1 {
    version: u16,
    slot: [u8; 32],
    key: [u8; 32],
    nonce: [u8; 16],
    complete: bool,
}

impl ArchiveRetirementV1 {
    fn encode(&self) -> Result<Vec<u8>, Error> {
        super::encode_envelope_v1(self, RETIREMENT_MAX_BYTES)
    }

    fn decode(bytes: &[u8], slot: &Slot) -> Result<Self, Error> {
        let journal: Self = super::decode_envelope_v1(bytes, RETIREMENT_MAX_BYTES)?;
        if journal.version != 1 || journal.slot != slot.0 {
            return Err(Error::UnavailableCustodyData {
                object: "archive retirement journal",
            });
        }
        Ok(journal)
    }

    fn graves(&self) -> [Name; 2] {
        grave_names(&self.key, &hex::encode(self.nonce))
    }
}

// The supplied Pending is already durable. Keep the exact original inodes until both
// their absence and the Complete cell are durable. Neither failure permits publication.
fn complete_archive_retirement<F: KagemushaWalletFsV1>(
    store: &KagemushaWalletDurableStoreV1<F>,
    directory: &super::KagemushaWalletCustodyDirV1,
    journal: &ArchiveRetirementV1,
    encoded: &[u8],
) -> Result<Vec<u8>, Error> {
    if journal.complete {
        return Ok(encoded.to_vec());
    }
    let records = record_names(&journal.key);
    let graves = journal.graves();
    super::layout::kagemusha_wallet_require_removed_v1(store.retain_retired_files(
        directory,
        &[(&records[0], &graves[0]), (&records[1], &graves[1])],
    ))?;
    let complete = ArchiveRetirementV1 {
        complete: true,
        ..*journal
    }
    .encode()?;
    kagemusha_wallet_require_published_v1(store.replace_exact(
        directory,
        &retirement_name(),
        encoded,
        &complete,
    ))?;
    Ok(complete)
}

/// Adopt the visible journal on a fresh inode before it authorizes any recovery action.
/// Pending retains and commits deletion; Complete and unreferenced graves are reap-only.
/// The returned Complete bytes are the exact predecessor of a subsequent Pending cell.
pub(super) fn settle_archive_graves<F: KagemushaWalletFsV1>(
    store: &KagemushaWalletDurableStoreV1<F>,
    slot: &Slot,
    directory: &super::KagemushaWalletCustodyDirV1,
    entries: &[super::KagemushaWalletListedEntryV1],
) -> Result<Option<Vec<u8>>, Error> {
    let mut garbage = Vec::new();
    for entry in entries {
        if parse_grave(&entry.name).is_none() {
            if entry.name.contains(".g-") {
                return Err(Error::UnavailableCustodyData {
                    object: "archive grave name",
                });
            }
            continue;
        }
        if entry.kind != super::KagemushaWalletEntryKindV1::File {
            return Err(Error::UnavailableCustodyData {
                object: "archive grave identity",
            });
        }
        garbage.push(Name::new(&entry.name).ok_or(Error::Invalid {
            field: "archive.grave",
        })?);
    }
    let name = retirement_name();
    let journal_entry = entries.iter().find(|entry| entry.name == name.as_str());
    let mut completed_graves = None;
    let completed = if let Some(entry) = journal_entry {
        if entry.kind != super::KagemushaWalletEntryKindV1::File {
            return Err(Error::UnavailableCustodyData {
                object: "archive retirement journal",
            });
        }
        let bytes = match store.read(directory, &name, RETIREMENT_MAX_BYTES) {
            KagemushaWalletReadV1::Present(bytes) => bytes,
            KagemushaWalletReadV1::Unavailable(reason) => return Err(Error::Unavailable(reason)),
            _ => {
                return Err(Error::UnavailableCustodyData {
                    object: "archive retirement journal",
                });
            }
        };
        let journal = ArchiveRetirementV1::decode(&bytes, slot)?;
        // The visible phase may itself be an uncommitted rename after lost writeback.
        // Reissuing it on a new inode makes the phase durable before any original moves.
        kagemusha_wallet_require_published_v1(store.rewrite_same(directory, &name, &bytes))?;
        let complete = complete_archive_retirement(store, directory, &journal, &bytes)?;
        let graves = journal.graves();
        super::layout::kagemusha_wallet_require_removed_v1(
            store.reap_retired_files(directory, &[&graves[0], &graves[1]]),
        )?;
        completed_graves = Some(graves);
        Some(complete)
    } else {
        None
    };
    // The Complete cell above, or absence of any journal for these unique names, proves
    // these graves cannot authorize replay. Never move their bytes to a live record name.
    for grave in &garbage {
        if completed_graves
            .as_ref()
            .is_some_and(|names| names.contains(grave))
        {
            continue;
        }
        super::layout::kagemusha_wallet_require_removed_v1(
            store.reap_retired_files(directory, &[grave]),
        )?;
    }
    Ok(completed)
}

fn retire_archive_record<F: KagemushaWalletFsV1>(
    store: &KagemushaWalletDurableStoreV1<F>,
    slot: &Slot,
    key: &[u8; 32],
) -> Result<(), Error> {
    let directory = kagemusha_wallet_archive_dir_v1(slot);
    let entries = store
        .list(&directory)
        .into_result()?
        .ok_or(Error::UnavailableCustodyData {
            object: "archive directory",
        })?;
    let previous = settle_archive_graves(store, slot, &directory, &entries)?;
    let nonce = store.retirement_nonce().map_err(Error::Unavailable)?;
    // retirement_nonce already requires exactly 32 lowercase hex digits. Keep this
    // conversion fallible so an invalid backend cannot panic while preparing deletion.
    let nonce: [u8; 16] = hex::decode(nonce)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(Error::Unavailable(Unavailable::Io(0)))?;
    let pending = ArchiveRetirementV1 {
        version: 1,
        slot: slot.0,
        key: *key,
        nonce,
        complete: false,
    };
    let encoded = pending.encode()?;
    let outcome = match previous {
        Some(previous) => store.replace_exact(&directory, &retirement_name(), &previous, &encoded),
        None => store.write_new(&directory, &retirement_name(), &encoded),
    };
    kagemusha_wallet_require_published_v1(outcome)?;
    complete_archive_retirement(store, &directory, &pending, &encoded)?;
    let graves = pending.graves();
    super::layout::kagemusha_wallet_require_removed_v1(
        store.reap_retired_files(&directory, &[&graves[0], &graves[1]]),
    )
}

impl<F: KagemushaWalletFsV1> KagemushaWalletArchiveAccessV1<'_, F> {
    /// Read one immutable state-owner record. A digest prefix authenticates each redundant
    /// copy; the caller additionally checks its canonical incarnation/key envelope. A record
    /// staged by the slot's open call is answered from memory, with the frame and bound checks
    /// (and errors) of a disk read, before any storage access.
    ///
    /// # Errors
    /// Unavailable or corrupt copies, conflicting valid copies, or a violated payload bound.
    pub fn read_record(
        &self,
        key: &[u8; 32],
        max_bytes: usize,
    ) -> Result<Option<PrivateArchiveBytes>, Error> {
        super::counters::count(super::counters::EventV1::ArchiveGet);
        if let Some(staged) = self.staged(key) {
            return staged_payload(staged, max_bytes).map(Some);
        }
        self.read_record_copies(key, max_bytes)
    }

    /// Read one immutable record of a content-addressed key from the first copy whose digest
    /// prefix verifies. The redundant copy is read only when the first is absent, unreadable,
    /// oversized or fails its prefix. The caller authenticates the returned payload completely
    /// (envelope binding and content digests) and fails closed, never consulting the other
    /// copy, when it does not authenticate. Other keys use [`Self::read_record`]. A staged
    /// record is answered from memory as by [`Self::read_record`].
    ///
    /// # Errors
    /// As [`Self::read_record`], except that two differing valid copies cannot be detected:
    /// for a content-addressed key they would need a digest collision.
    pub(crate) fn read_record_first(
        &self,
        key: &[u8; 32],
        max_bytes: usize,
    ) -> Result<Option<PrivateArchiveBytes>, Error> {
        super::counters::count(super::counters::EventV1::ArchiveGet);
        if let Some(staged) = self.staged(key) {
            return staged_payload(staged, max_bytes).map(Some);
        }
        let limit = record_limit(max_bytes)?;
        let directory = kagemusha_wallet_archive_dir_v1(self.slot);
        let mut unavailable = None;
        let mut corrupt = false;
        for name in record_names(key) {
            match self.store().read(&directory, &name, limit) {
                KagemushaWalletReadV1::Absent => {}
                KagemushaWalletReadV1::Oversized => corrupt = true,
                KagemushaWalletReadV1::Unavailable(reason) => unavailable = Some(reason),
                KagemushaWalletReadV1::Present(bytes) => {
                    let bytes = Zeroizing::new(bytes);
                    match framed_payload(&bytes) {
                        Some(payload) => {
                            return PrivateArchiveBytes::copy_from(payload)
                                .map(Some)
                                .map_err(private_copy_error);
                        }
                        None => corrupt = true,
                    }
                }
            }
        }
        no_valid_copy(unavailable, corrupt)
    }

    fn read_record_copies(
        &self,
        key: &[u8; 32],
        max_bytes: usize,
    ) -> Result<Option<PrivateArchiveBytes>, Error> {
        let limit = record_limit(max_bytes)?;
        let directory = kagemusha_wallet_archive_dir_v1(self.slot);
        let mut valid: Option<PrivateArchiveBytes> = None;
        let mut unavailable = None;
        let mut corrupt = false;
        for name in record_names(key) {
            match self.store().read(&directory, &name, limit) {
                KagemushaWalletReadV1::Absent => {}
                KagemushaWalletReadV1::Oversized => corrupt = true,
                KagemushaWalletReadV1::Unavailable(reason) => unavailable = Some(reason),
                KagemushaWalletReadV1::Present(bytes) => {
                    let bytes = Zeroizing::new(bytes);
                    let Some(payload) = framed_payload(&bytes) else {
                        corrupt = true;
                        continue;
                    };
                    let bytes =
                        PrivateArchiveBytes::copy_from(payload).map_err(private_copy_error)?;
                    if valid
                        .as_ref()
                        .is_some_and(|old| old.as_slice() != bytes.as_slice())
                    {
                        return Err(Error::UnavailableCustodyData {
                            object: "conflicting archive records",
                        });
                    }
                    valid = Some(bytes);
                }
            }
        }
        if let Some(bytes) = valid {
            return Ok(Some(bytes));
        }
        no_valid_copy(unavailable, corrupt)
    }
    /// Remove both copies of a state-owner record after its selected archive manifest records
    /// the collection decision. This capability remains inside the protected-data bracket.
    /// The record is forgotten by the exact-bytes write memo before anything is unlinked.
    /// Nothing is removed while the slot's open call has unpublished records
    /// ([`KagemushaWalletProviderV1::remove_archive_record`] publishes them first).
    ///
    /// # Errors
    /// `Invalid("archive.pending_records")` while records are staged; an unavailable or
    /// uncertain deletion is returned unchanged; absence is idempotent.
    pub fn remove_record(&self, key: &[u8; 32]) -> Result<(), Error> {
        super::counters::count(super::counters::EventV1::ArchiveRemove);
        if self.batch.is_some_and(|batch| !batch.is_empty()) {
            return Err(Error::Invalid {
                field: "archive.pending_records",
            });
        }
        let result = (|| {
            self.settle_failed_retirement()?;
            self.writes.borrow_mut().forget(self.slot, key);
            retire_archive_record(self.store(), self.slot, key)
        })();
        self.retirement_failure.set(result.as_ref().err().copied());
        result
    }

    // A failed removal can be caught inside a callback. Finish its visible graves before a
    // subsequent publication, and retain the failure if it cannot be reconciled.
    fn settle_failed_retirement(&self) -> Result<(), Error> {
        if self.retirement_failure.get().is_none() {
            return Ok(());
        }
        let directory = kagemusha_wallet_archive_dir_v1(self.slot);
        let entries =
            self.store()
                .list(&directory)
                .into_result()?
                .ok_or(Error::UnavailableCustodyData {
                    object: "archive directory",
                })?;
        settle_archive_graves(self.store(), self.slot, &directory, &entries)?;
        self.retirement_failure.set(None);
        Ok(())
    }

    /// Publish the exact bytes at an immutable key under the provider's custody capability.
    ///
    /// Bytes this process already published durably at the key (or adopted on a fresh inode)
    /// are answered from the exact-bytes write memo without a read, write or sync; other bytes
    /// are the same immutable-record conflict as on disk. Otherwise both copies are published:
    /// create-new for an absent copy (inside an archive phase only after a protected-storage
    /// probe that follows the absent read) and a fresh-inode rewrite for an identical one.
    /// Only a durable publication of both copies is remembered.
    ///
    /// # Errors
    /// Conflicting existing bytes, unavailable storage or uncertain durable publication.
    pub fn write_record(&self, key: &[u8; 32], bytes: &[u8]) -> Result<(), Error> {
        self.settle_failed_retirement()?;
        super::counters::count(super::counters::EventV1::ArchivePut);
        let frame = kagemusha_wallet_archive_object_digest_v1(bytes);
        let written = self.writes.borrow().get(self.slot, key);
        if let Some(written) = written {
            if written != frame {
                return Err(Error::Invalid {
                    field: "archive.immutable_record",
                });
            }
            super::counters::count(super::counters::EventV1::ArchivePutMemoHit);
            return Ok(());
        }
        if self
            .read_record_copies(key, bytes.len())?
            .as_ref()
            .is_some_and(|old| old.as_slice() != bytes)
        {
            return Err(Error::Invalid {
                field: "archive.immutable_record",
            });
        }
        let mut framed = Zeroizing::new(vec![0; record_limit(bytes.len())?]);
        framed[..32].copy_from_slice(&frame);
        framed[32..].copy_from_slice(bytes);
        let directory = kagemusha_wallet_archive_dir_v1(self.slot);
        let mut probed = false;
        for name in record_names(key) {
            let outcome = match self.store().read(&directory, &name, framed.len()) {
                KagemushaWalletReadV1::Absent => {
                    self.probe_before_create(&mut probed)?;
                    self.store().write_new(&directory, &name, &framed)
                }
                KagemushaWalletReadV1::Present(old) => {
                    let old = Zeroizing::new(old);
                    if old.as_slice() != framed.as_slice() {
                        return Err(Error::UnavailableCustodyData {
                            object: "archive immutable record",
                        });
                    }
                    self.store().rewrite_same(&directory, &name, &framed)
                }
                KagemushaWalletReadV1::Unavailable(reason) => {
                    return Err(Error::Unavailable(reason));
                }
                _ => {
                    return Err(Error::UnavailableCustodyData {
                        object: "archive immutable record",
                    });
                }
            };
            kagemusha_wallet_require_published_v1(outcome)?;
        }
        self.writes.borrow_mut().insert(self.slot, key, frame);
        Ok(())
    }

    // Inside an archive phase, a create-new choice rests on an absent read only while protected
    // storage is available after it; one probe covers both copies of a put.
    fn probe_before_create(&self, probed: &mut bool) -> Result<(), Error> {
        if let Some(probe) = self.probe
            && !*probed
        {
            probe()?;
            *probed = true;
        }
        Ok(())
    }

    // The record the slot's open call staged at `key`, if any.
    fn staged(&self, key: &[u8; 32]) -> Option<&StagedRecordV1> {
        self.batch.and_then(|batch| batch.records.get(key))
    }

    // How a put of `bytes` (frame digest `frame`) at `key` is staged; touches no storage.
    fn staging(&self, key: &[u8; 32], frame: &[u8; 32], bytes: &[u8]) -> Result<StagingV1, Error> {
        let conflict = Error::Invalid {
            field: "archive.immutable_record",
        };
        let written = self.writes.borrow().get(self.slot, key);
        if let Some(written) = written {
            return if written == *frame {
                Ok(StagingV1::Remembered)
            } else {
                Err(conflict)
            };
        }
        match self.staged(key) {
            Some(staged) if staged.frame == *frame && staged.framed.get(32..) == Some(bytes) => {
                Ok(StagingV1::Coalesced)
            }
            Some(_) => Err(conflict),
            None => Ok(StagingV1::New),
        }
    }

    // Publish `batch`, and with it both copies of `checkpoint` (its digest and exact bytes),
    // behind one archive directory sync.
    //
    // P0: every copy is read once and classified before anything is written, with the errors
    // and precedence of a single put (`write_record`) or of a checkpoint copy; a conflict
    // returns before any staging file exists. One protected-storage probe follows the last read
    // when any copy is absent, so every create-new rests on an available store. P1/P2: the batch
    // primitive syncs every staged copy before any rename and syncs the directory once after
    // the last; `NotPublished` leaves every name unchanged and any failure after a rename is
    // `Uncertain`. Only a durable publication is remembered by the exact-bytes memo.
    fn publish_records(
        &self,
        batch: &ArchiveBatchV1,
        checkpoint: Option<([u8; 32], &[u8])>,
    ) -> Result<(), Error> {
        self.settle_failed_retirement()?;
        let directory = kagemusha_wallet_archive_dir_v1(self.slot);
        let mut planned: Vec<(Name, &[u8], BatchAction)> =
            Vec::with_capacity(2 * batch.records.len() + 2);
        for (key, record) in &batch.records {
            let framed = record.framed.as_slice();
            let copies_named = record_names(key);
            let copies: [DrainCopyV1; 2] = std::array::from_fn(|copy| {
                self.store()
                    .read(&directory, &copies_named[copy], framed.len())
                    .into()
            });
            let actions = classify_record(&copies, framed)?;
            drop(copies);
            for (name, action) in copies_named.into_iter().zip(actions) {
                planned.push((name, framed, action));
            }
        }
        if let Some((digest, bytes)) = checkpoint {
            for name in names(&digest) {
                let copy: DrainCopyV1 = self
                    .store()
                    .read(
                        &directory,
                        &name,
                        KAGEMUSHA_WALLET_ARCHIVE_MANIFEST_MAX_BYTES_V1,
                    )
                    .into();
                let action = classify_checkpoint(&copy, bytes)?;
                planned.push((name, bytes, action));
            }
        }
        if planned
            .iter()
            .any(|(_, _, action)| *action == BatchAction::New)
        {
            self.probe_before_create(&mut false)?;
        }
        let entries: Vec<BatchEntry<'_>> = planned
            .iter()
            .map(|(name, bytes, action)| BatchEntry {
                name,
                bytes: *bytes,
                action: *action,
            })
            .collect();
        kagemusha_wallet_require_published_v1(self.store().publish_batch(&directory, &entries))?;
        let mut writes = self.writes.borrow_mut();
        for (key, record) in &batch.records {
            writes.insert(self.slot, key, record.frame);
        }
        Ok(())
    }
}

// One copy read by a drain; present bytes are cleared when released.
enum DrainCopyV1 {
    Absent,
    Oversized,
    Unavailable(Unavailable),
    Present(Zeroizing<Vec<u8>>),
}

impl From<KagemushaWalletReadV1> for DrainCopyV1 {
    fn from(read: KagemushaWalletReadV1) -> Self {
        match read {
            KagemushaWalletReadV1::Absent => Self::Absent,
            KagemushaWalletReadV1::Oversized => Self::Oversized,
            KagemushaWalletReadV1::Unavailable(reason) => Self::Unavailable(reason),
            KagemushaWalletReadV1::Present(bytes) => Self::Present(Zeroizing::new(bytes)),
        }
    }
}

// P0 of one staged record from one read of each copy (bound: its framed length), with the
// errors and precedence of `write_record`, which first compares both copies and then classifies
// each name: two valid differing copies, then a valid copy of other bytes, then (without a
// valid copy) unreadable storage before corrupt copies; then, per name in order, an absent
// copy is created new, an exact copy is adopted on a fresh inode and any other content is a
// conflict.
fn classify_record(copies: &[DrainCopyV1; 2], framed: &[u8]) -> Result<[BatchAction; 2], Error> {
    let payload = &framed[32..];
    let mut valid: Option<&[u8]> = None;
    let mut unavailable = None;
    let mut corrupt = false;
    for copy in copies {
        match copy {
            DrainCopyV1::Absent => {}
            DrainCopyV1::Oversized => corrupt = true,
            DrainCopyV1::Unavailable(reason) => unavailable = Some(*reason),
            DrainCopyV1::Present(bytes) => match framed_payload(bytes) {
                Some(found) => {
                    if valid.is_some_and(|old| old != found) {
                        return Err(Error::UnavailableCustodyData {
                            object: "conflicting archive records",
                        });
                    }
                    valid = Some(found);
                }
                None => corrupt = true,
            },
        }
    }
    match valid {
        Some(found) if found != payload => {
            return Err(Error::Invalid {
                field: "archive.immutable_record",
            });
        }
        Some(_) => {}
        None => {
            if let Some(reason) = unavailable {
                return Err(Error::Unavailable(reason));
            }
            if corrupt {
                return Err(Error::UnavailableCustodyData {
                    object: "archive record",
                });
            }
        }
    }
    let mut actions = [BatchAction::New; 2];
    for (action, copy) in actions.iter_mut().zip(copies) {
        *action = match copy {
            DrainCopyV1::Absent => BatchAction::New,
            DrainCopyV1::Present(bytes) if bytes.as_slice() == framed => BatchAction::Replace,
            DrainCopyV1::Unavailable(reason) => return Err(Error::Unavailable(*reason)),
            DrainCopyV1::Present(_) | DrainCopyV1::Oversized => {
                return Err(Error::UnavailableCustodyData {
                    object: "archive immutable record",
                });
            }
        };
    }
    Ok(actions)
}

// P0 of one archive-checkpoint copy, as its single publication classified it.
fn classify_checkpoint(copy: &DrainCopyV1, bytes: &[u8]) -> Result<BatchAction, Error> {
    match copy {
        DrainCopyV1::Present(old) if old.as_slice() == bytes => Ok(BatchAction::Replace),
        DrainCopyV1::Absent => Ok(BatchAction::New),
        DrainCopyV1::Unavailable(reason) => Err(Error::Unavailable(*reason)),
        DrainCopyV1::Present(_) | DrainCopyV1::Oversized => Err(Error::UnavailableCustodyData {
            object: "archive checkpoint",
        }),
    }
}

// A staged record answered as a disk read of its copies would be: the payload within the bound
// and behind its verified digest prefix; nothing touches storage.
fn staged_payload(record: &StagedRecordV1, max_bytes: usize) -> Result<PrivateArchiveBytes, Error> {
    super::counters::count(super::counters::EventV1::ArchiveOverlayHit);
    let payload = if record.framed.len() <= record_limit(max_bytes)? {
        framed_payload(record.framed.as_slice())
    } else {
        None
    };
    let payload = payload.ok_or(Error::UnavailableCustodyData {
        object: "archive record",
    })?;
    PrivateArchiveBytes::copy_from(payload).map_err(private_copy_error)
}

fn private_copy_error(error: std::io::Error) -> Error {
    Error::Unavailable(Unavailable::from_io(&error))
}

fn record_limit(max_bytes: usize) -> Result<usize, Error> {
    max_bytes.checked_add(32).ok_or(Error::Invalid {
        field: "archive.record_size",
    })
}

// The payload of one record copy whose digest prefix verifies.
fn framed_payload(bytes: &[u8]) -> Option<&[u8]> {
    (bytes.len() >= 32 && kagemusha_wallet_archive_object_digest_v1(&bytes[32..]) == bytes[..32])
        .then(|| &bytes[32..])
}

// Outcome of a record read without a valid copy: unreadable storage is never absence.
fn no_valid_copy(
    unavailable: Option<Unavailable>,
    corrupt: bool,
) -> Result<Option<PrivateArchiveBytes>, Error> {
    if let Some(reason) = unavailable {
        return Err(Error::Unavailable(reason));
    }
    if corrupt {
        return Err(Error::UnavailableCustodyData {
            object: "archive record",
        });
    }
    Ok(None)
}

#[cfg(test)]
#[path = "archive_phase_tests.rs"]
mod phase_tests;

#[cfg(test)]
#[path = "archive_batch_tests.rs"]
mod batch_tests;

#[cfg(test)]
#[path = "archive_batch_crash_tests.rs"]
mod batch_crash_tests;
