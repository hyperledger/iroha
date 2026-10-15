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

use std::{
    cell::{Cell, RefCell},
    collections::{BTreeMap, VecDeque},
};

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
    store::KagemushaWalletDurableStoreV1,
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

fn persist<F: KagemushaWalletFsV1>(
    store: &KagemushaWalletDurableStoreV1<F>,
    slot: &Slot,
    digest: &[u8; 32],
    bytes: &[u8],
) -> Result<(), Error> {
    let directory = kagemusha_wallet_archive_dir_v1(slot);
    for name in names(digest) {
        let outcome = match store.read(
            &directory,
            &name,
            KAGEMUSHA_WALLET_ARCHIVE_MANIFEST_MAX_BYTES_V1,
        ) {
            KagemushaWalletReadV1::Present(old) if old == bytes => {
                store.rewrite_same(&directory, &name, bytes)
            }
            KagemushaWalletReadV1::Absent => store.write_new(&directory, &name, bytes),
            KagemushaWalletReadV1::Unavailable(reason) => return Err(Error::Unavailable(reason)),
            _ => {
                return Err(Error::UnavailableCustodyData {
                    object: "archive checkpoint",
                });
            }
        };
        kagemusha_wallet_require_published_v1(outcome)?;
    }
    Ok(())
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
    /// The caller must durably write all referenced immutable data before this operation.
    /// This method does not select a monetary head or create/recreate any receipt. An exact
    /// retry adopts the existing checkpoint and preserves its original completion bytes.
    ///
    /// # Errors
    /// Stale manifest, non-Released head, invalid size, storage/anchor errors or uncertain
    /// publication. An error never implies reversal of an already committed monetary head;
    /// reconcile the marker and compare its checkpoint digest before retrying.
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
            persist(&self.store, slot, &digest, bytes)?;
            self.require_storage()?;
            return Ok(digest);
        }
        if current.archive_checkpoint() != expected {
            return Err(Error::Invalid {
                field: "archive.stale_checkpoint",
            });
        }
        let result = (|| {
            persist(&self.store, slot, &digest, bytes)?;
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
    // Inside an archive phase: the protected-storage probe taken before a create-new write
    // whose choice rests on an absent read. `with_archive` brackets the whole access instead.
    probe: Option<&'a dyn Fn() -> Result<(), Error>>,
    // Whether this access touched storage; an access answered from memory needs no probe.
    observed: Cell<bool>,
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
/// phase. A kept object is never evidence that a file is present on disk.
#[derive(Debug)]
pub(super) struct ArchivePhaseV1 {
    slot: Slot,
    marker: Vec<u8>,
    enrollment: Option<([u8; 32], [Vec<u8>; 4])>,
    objects: BTreeMap<KagemushaWalletArchiveObjectKeyV1, Vec<u8>>,
    order: VecDeque<KagemushaWalletArchiveObjectKeyV1>,
    bytes: usize,
}

impl ArchivePhaseV1 {
    fn keep(&mut self, key: KagemushaWalletArchiveObjectKeyV1, content: &[u8]) {
        if content.len() > KAGEMUSHA_WALLET_ARCHIVE_PHASE_OBJECT_MAX_V1
            || self.objects.contains_key(&key)
        {
            return;
        }
        self.objects.insert(key, content.to_vec());
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
    }

    fn forget(&mut self, key: &KagemushaWalletArchiveObjectKeyV1) {
        if let Some(evicted) = self.objects.remove(key) {
            self.bytes = self.bytes.saturating_sub(evicted.len());
        }
    }
}

fn object_names(digest: &[u8; 32]) -> [Name; 2] {
    let base = format!("o-{}.obj", hex::encode(digest));
    [base.clone(), format!("{base}.r")]
        .map(|name| Name::new(&name).expect("fixed archive object name"))
}

impl<F: KagemushaWalletFsV1> KagemushaWalletArchiveAccessV1<'_, F> {
    // Every storage access goes through here, so an archive phase knows to probe after it.
    fn store(&self) -> &KagemushaWalletDurableStoreV1<F> {
        self.observed.set(true);
        self.store
    }

    /// Read a content-addressed object within its authenticated descriptor's exact bound.
    ///
    /// # Errors
    /// Missing/corrupt known content, unavailable storage or an oversized object.
    pub fn read(&self, digest: &[u8; 32], max_bytes: usize) -> Result<Vec<u8>, Error> {
        let directory = kagemusha_wallet_archive_dir_v1(self.slot);
        let mut unavailable = None;
        for name in object_names(digest) {
            match self.store().read(&directory, &name, max_bytes) {
                KagemushaWalletReadV1::Present(bytes)
                    if kagemusha_wallet_archive_object_digest_v1(&bytes) == *digest =>
                {
                    return Ok(bytes);
                }
                KagemushaWalletReadV1::Unavailable(reason) => unavailable = Some(reason),
                _ => {}
            }
        }
        Err(unavailable.map_or(
            Error::UnavailableCustodyData {
                object: "archive object",
            },
            Error::Unavailable,
        ))
    }

    /// Publish redundant immutable bytes within their descriptor's bound, using a fresh inode
    /// when adopting an exact retry. All referenced objects must precede manifest publication.
    ///
    /// # Errors
    /// Oversized input, unavailable storage, conflicting content or uncertain publication.
    pub fn write(&self, bytes: &[u8], max_bytes: usize) -> Result<[u8; 32], Error> {
        if bytes.is_empty() || bytes.len() > max_bytes {
            return Err(Error::Invalid {
                field: "archive.object_size",
            });
        }
        let digest = kagemusha_wallet_archive_object_digest_v1(bytes);
        let directory = kagemusha_wallet_archive_dir_v1(self.slot);
        let mut probed = false;
        for name in object_names(&digest) {
            let outcome = match self.store().read(&directory, &name, max_bytes) {
                KagemushaWalletReadV1::Present(old) if old == bytes => {
                    self.store().rewrite_same(&directory, &name, bytes)
                }
                KagemushaWalletReadV1::Absent => {
                    self.probe_before_create(&mut probed)?;
                    self.store().write_new(&directory, &name, bytes)
                }
                KagemushaWalletReadV1::Unavailable(reason) => {
                    return Err(Error::Unavailable(reason));
                }
                _ => {
                    return Err(Error::UnavailableCustodyData {
                        object: "archive object",
                    });
                }
            };
            kagemusha_wallet_require_published_v1(outcome)?;
        }
        Ok(digest)
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
    ///
    /// # Errors
    /// Reconciliation, callback or protected-storage errors. A failed final probe supersedes
    /// the callback answer, so eviction never masquerades as missing private data.
    pub fn with_archive<T>(
        &mut self,
        slot: &Slot,
        operation: impl FnOnce(&KagemushaWalletArchiveAccessV1<'_, F>) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let status = self.reconcile_slot(slot, None)?;
        require_archive_status(&status)?;
        let result = operation(&KagemushaWalletArchiveAccessV1 {
            store: &self.store,
            slot,
            writes: &self.archive_writes,
            probe: None,
            observed: Cell::new(false),
        });
        let result = self.require_storage().and(result);
        self.guard(slot, result)
    }

    /// Run one state-owner archive access inside the current archive phase of `slot`.
    ///
    /// Without a current phase this performs the entry check of [`Self::with_archive`]
    /// (reconcile and slot status gate) and opens a phase bound to the durable marker and
    /// verified enrollment phase it saw. Within the phase the reconcile is skipped. An access
    /// that touches storage, and every error, is followed by a protected-storage probe whose
    /// failure supersedes the answer; a create-new write additionally probes after the absent
    /// read it rests on. An access answered from memory (an exact-bytes memo hit) touches no
    /// storage and needs no probe. Errors poison the slot, which ends the phase.
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
        let probe = || self.require_storage();
        let access = KagemushaWalletArchiveAccessV1 {
            store: &self.store,
            slot,
            writes: &self.archive_writes,
            probe: Some(&probe),
            observed: Cell::new(false),
        };
        let result = operation(&access);
        let observed = access.observed.get();
        let result = if observed || result.is_err() {
            self.require_storage().and(result)
        } else {
            result
        };
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
    pub(crate) fn archive_phase_object(
        &mut self,
        slot: &Slot,
        key: &KagemushaWalletArchiveObjectKeyV1,
        max_bytes: usize,
    ) -> Option<Vec<u8>> {
        if !self.archive_phase_current(slot) {
            self.archive_phase = None;
            return None;
        }
        let content = self
            .archive_phase
            .as_ref()?
            .objects
            .get(key)
            .filter(|content| content.len() <= max_bytes)
            .cloned()?;
        super::counters::count(super::counters::EventV1::ArchiveObjectCacheHit);
        Some(content)
    }

    /// Keep authenticated object content for the rest of the current archive phase of `slot`:
    /// content read with every archive and object check, or published durably by a put.
    pub(crate) fn keep_archive_phase_object(
        &mut self,
        slot: &Slot,
        key: KagemushaWalletArchiveObjectKeyV1,
        content: &[u8],
    ) {
        if self.archive_phase_current(slot)
            && let Some(phase) = self.archive_phase.as_mut()
        {
            phase.keep(key, content);
        }
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
impl<F: KagemushaWalletFsV1> KagemushaWalletArchiveAccessV1<'_, F> {
    /// Read one immutable state-owner record. A digest prefix authenticates each redundant
    /// copy; the caller additionally checks its canonical incarnation/key envelope.
    ///
    /// # Errors
    /// Unavailable or corrupt copies, conflicting valid copies, or a violated payload bound.
    pub fn read_record(&self, key: &[u8; 32], max_bytes: usize) -> Result<Option<Vec<u8>>, Error> {
        super::counters::count(super::counters::EventV1::ArchiveGet);
        self.read_record_copies(key, max_bytes)
    }

    /// Read one immutable record of a content-addressed key from the first copy whose digest
    /// prefix verifies. The redundant copy is read only when the first is absent, unreadable,
    /// oversized or fails its prefix. The caller authenticates the returned payload completely
    /// (envelope binding and content digests) and fails closed, never consulting the other
    /// copy, when it does not authenticate. Other keys use [`Self::read_record`].
    ///
    /// # Errors
    /// As [`Self::read_record`], except that two differing valid copies cannot be detected:
    /// for a content-addressed key they would need a digest collision.
    pub(crate) fn read_record_first(
        &self,
        key: &[u8; 32],
        max_bytes: usize,
    ) -> Result<Option<Vec<u8>>, Error> {
        super::counters::count(super::counters::EventV1::ArchiveGet);
        let limit = record_limit(max_bytes)?;
        let directory = kagemusha_wallet_archive_dir_v1(self.slot);
        let mut unavailable = None;
        let mut corrupt = false;
        for name in record_names(key) {
            match self.store().read(&directory, &name, limit) {
                KagemushaWalletReadV1::Absent => {}
                KagemushaWalletReadV1::Oversized => corrupt = true,
                KagemushaWalletReadV1::Unavailable(reason) => unavailable = Some(reason),
                KagemushaWalletReadV1::Present(bytes) => match framed_payload(&bytes) {
                    Some(payload) => return Ok(Some(payload.to_vec())),
                    None => corrupt = true,
                },
            }
        }
        no_valid_copy(unavailable, corrupt)
    }

    fn read_record_copies(
        &self,
        key: &[u8; 32],
        max_bytes: usize,
    ) -> Result<Option<Vec<u8>>, Error> {
        let limit = record_limit(max_bytes)?;
        let directory = kagemusha_wallet_archive_dir_v1(self.slot);
        let mut valid = None;
        let mut unavailable = None;
        let mut corrupt = false;
        for name in record_names(key) {
            match self.store().read(&directory, &name, limit) {
                KagemushaWalletReadV1::Absent => {}
                KagemushaWalletReadV1::Oversized => corrupt = true,
                KagemushaWalletReadV1::Unavailable(reason) => unavailable = Some(reason),
                KagemushaWalletReadV1::Present(bytes) => {
                    let Some(payload) = framed_payload(&bytes) else {
                        corrupt = true;
                        continue;
                    };
                    let bytes = payload.to_vec();
                    if valid.as_ref().is_some_and(|old| *old != bytes) {
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
    ///
    /// # Errors
    /// An unavailable or uncertain deletion is returned unchanged; absence is idempotent.
    pub fn remove_record(&self, key: &[u8; 32]) -> Result<(), Error> {
        super::counters::count(super::counters::EventV1::ArchiveRemove);
        self.writes.borrow_mut().forget(self.slot, key);
        let directory = kagemusha_wallet_archive_dir_v1(self.slot);
        for name in record_names(key) {
            super::layout::kagemusha_wallet_require_removed_v1(
                self.store().remove_file(&directory, &name),
            )?;
        }
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
            .is_some_and(|old| *old != bytes)
        {
            return Err(Error::Invalid {
                field: "archive.immutable_record",
            });
        }
        let mut framed = Vec::with_capacity(bytes.len() + 32);
        framed.extend_from_slice(&frame);
        framed.extend_from_slice(bytes);
        let directory = kagemusha_wallet_archive_dir_v1(self.slot);
        let mut probed = false;
        for name in record_names(key) {
            let outcome = match self.store().read(&directory, &name, framed.len()) {
                KagemushaWalletReadV1::Absent => {
                    self.probe_before_create(&mut probed)?;
                    self.store().write_new(&directory, &name, &framed)
                }
                KagemushaWalletReadV1::Present(old) if old == framed => {
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
) -> Result<Option<Vec<u8>>, Error> {
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
