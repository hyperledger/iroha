// Exact native frame admission and reads; metadata alone never authenticates execution.

/// Immutable original native frame bytes, physically prepaid from the reader's pool.
///
/// Moving or lending this owner retains the same backing and charge. There is no
/// clone, growth, mutable public slice or extraction of an uncharged vector.
pub struct NativeFrameBytes(iroha_allocation::ChargedBuffer<u8>);

impl NativeFrameBytes {
    /// Borrow the exact initialized source, without separating its physical charge.
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Verify the original operation pool without acquiring new capacity.
    pub fn belongs_to(&self, budget: &iroha_allocation::AllocationBudget) -> bool {
        self.0.belongs_to(budget)
    }
}
impl AsRef<[u8]> for NativeFrameBytes {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}
impl core::ops::Deref for NativeFrameBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}
impl core::fmt::Debug for NativeFrameBytes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NativeFrameBytes")
            .field("length", &self.as_slice().len())
            .finish_non_exhaustive()
    }
}

// Only the sole storage read can mutate this initialized fixed destination.
struct NativeFrameDestination(iroha_allocation::ChargedBuffer<u8>);
impl NativeFrameDestination {
    fn new(length: usize, budget: &iroha_allocation::AllocationBudget) -> Result<Self> {
        let mut bytes = iroha_allocation::ChargedBuffer::new(length, budget)
            .map_err(Error::NativeFrameAllocation)?;
        let zeros = [0_u8; 8192];
        while bytes.as_slice().len() < length {
            let remaining = length - bytes.as_slice().len();
            bytes
                .append(&zeros[..remaining.min(zeros.len())])
                .expect("zero fill stays within exact admitted backing");
        }
        Ok(Self(bytes))
    }
}
impl AsRef<[u8]> for NativeFrameDestination {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}
impl AsMut<[u8]> for NativeFrameDestination {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut_slice()
    }
}
/// One descriptor-owner-bound durable slot, still untrusted until native verification.
/// Capturing this receipt reads only bounded index/hash metadata, never the frame body.
pub(crate) struct NativeFrameRead<'kura> {
    kura: &'kura Kura,
    height: u64,
    hash: HashOf<BlockHeader>,
    wire_len: u64,
    start: u64,
    journals: StableCanonicalBlockStoreMetadata,
}
impl NativeFrameRead<'_> {
    /// Exact occupied slot length to admit before any body allocation or I/O.
    pub(crate) const fn wire_len(&self) -> u64 {
        self.wire_len
    }

    /// Compare the original native journal images across one complete byte scan.
    /// Metadata alone never authenticates bytes: the caller must also join full raw
    /// bytes to genuinely verified canonical receipts before any cursor reuse.
    pub(crate) fn same_journal_image(&self, other: &Self) -> bool {
        core::ptr::eq(self.kura, other.kura)
            && Kura::native_frame_journal_images_unchanged(&self.journals, &other.journals)
    }

    /// Bind the same original occupied slot while allowing later journal appends.
    /// This identifies the source owner and geometry, not continued disk-byte or QC authority.
    pub(crate) fn same_original_slot(&self, other: &Self) -> bool {
        core::ptr::eq(self.kura, other.kura)
            && self.height == other.height
            && self.hash == other.hash
            && self.wire_len == other.wire_len
            && self.start == other.start
            && Kura::native_frame_journal_objects_unchanged(&self.journals, &other.journals)
    }

    /// Load only this admitted slot, rechecking all durable metadata under storage guards.
    /// The returned bytes are untrusted and cannot authorize outputs by themselves.
    pub(crate) fn read(
        self,
        admitted_wire_len: u64,
        budget: &iroha_allocation::AllocationBudget,
    ) -> Result<Option<NativeFrameBytes>> {
        self.read_original(admitted_wire_len, budget)
    }

    // The same bounded storage scan, lending the retained original descriptor across refusal.
    pub(crate) fn read_original(
        &self,
        admitted_wire_len: u64,
        budget: &iroha_allocation::AllocationBudget,
    ) -> Result<Option<NativeFrameBytes>> {
        // Failed backing and partial reads can refund this pool. Every storage guard
        // must retire before a synchronous refund waker may reenter the same source.
        budget.with_deferred_refund_notifications(|_| {
            let Self {
                kura,
                height,
                hash,
                wire_len,
                start,
                journals,
            } = self;
            let (height, hash, wire_len, start) = (*height, *hash, *wire_len, *start);
            if admitted_wire_len != wire_len {
                return Err(Error::CanonicalBlockWireMismatch { height });
            }
            let position = height - 1;
            let _prune = kura.prune_lock.lock();
            kura.ensure_prune_recovery_not_required()?;
            let _canonical = kura.canonical_chain_lock.lock();
            kura.ensure_canonical_storage_not_poisoned()?;
            let mut store = kura.block_store.lock();
            let before = kura.native_frame_journal_binding(&mut store)?;
            if !Kura::native_frame_journal_objects_unchanged(journals, &before) {
                return Err(Error::CanonicalBlockWireMismatch { height });
            }
            let count = store.read_exact_durable_index_count()?;
            if height > count {
                return Ok(None);
            }
            if Kura::read_durable_hash_at_height(&mut store, height)? != Some(hash) {
                return Err(Error::CanonicalBlockWireMismatch { height });
            }
            let slot = store.read_block_index(position)?;
            if slot.length != wire_len
                || (!cfg!(all(test, sumeragi_core_mutation = "HC187")) && slot.start != start)
            {
                return Err(Error::CanonicalBlockWireMismatch { height });
            }
            let length = usize::try_from(wire_len)?;
            let bytes = if slot.is_evicted() {
                // The same stable sidecar walk fills the original charged backing once.
                let Some(snapshot) = Kura::read_regular_sidecar_snapshot_into(
                    &store.path_to_blockchain,
                    &store.da_block_path(height),
                    &store.da_blocks_dir,
                    length,
                    || {},
                    |length| NativeFrameDestination::new(length, budget),
                )?
                else {
                    return Ok(None);
                };
                snapshot.bytes
            } else {
                // Inline storage owns its buffer here; subsequent native decoding retains
                // this inherited cumulative scope and accounts for its separate graph.
                norito::core::reserve_decode_allocation(length).map_err(Error::NoritoFrame)?;
                let mut bytes = NativeFrameDestination::new(length, budget)?;
                store.read_block_data(slot.start, bytes.as_mut())?;
                bytes
            };
            let confirmed = store.read_block_index(position)?;
            if u64::try_from(bytes.as_ref().len())? != wire_len
                || store.read_exact_durable_index_count()? != count
                || confirmed.start != slot.start
                || confirmed.length != slot.length
                || Kura::read_durable_hash_at_height(&mut store, height)? != Some(hash)
                || !Kura::native_frame_journal_images_unchanged(
                    &before,
                    &kura.native_frame_journal_binding(&mut store)?,
                )
            {
                return Err(Error::CanonicalBlockWireMismatch { height });
            }
            Ok(Some(NativeFrameBytes(bytes.0)))
        })
    }
}
impl Kura {
    /// Bind each retained original journal descriptor to its regular direct pathname.
    /// Missing, replaced, linked or special paths refuse before frame allocation or I/O.
    fn native_frame_journal_binding(
        &self,
        store: &mut BlockStore,
    ) -> Result<StableCanonicalBlockStoreMetadata> {
        let journals = self.canonical_block_store_metadata(&store.path_to_blockchain)?;
        let bind = |expected: &StableSidecarMetadata, file: &FileWrap| -> Result<()> {
            let opened = secure_file_metadata::from_file(&file.file)
                .map_err(|error| Error::IO(error, file.path.clone()))?;
            if !opened.is_file() || !Self::sidecar_file_metadata_unchanged(&expected.file, &opened)
            {
                return Err(Error::IO(
                    std::io::Error::new(
                        ErrorKind::InvalidData,
                        "native journal pathname differs from its opened original",
                    ),
                    file.path.clone(),
                ));
            }
            Ok(())
        };
        bind(&journals.data, store.ensure_data_file()?)?;
        bind(&journals.index, store.ensure_index_file()?)?;
        bind(&journals.hashes, store.ensure_hashes_file()?)?;
        Ok(journals)
    }

    /// A later append may grow the same journals and replace the durable marker,
    /// but it cannot replace any original journal captured by this source owner.
    fn native_frame_journal_objects_unchanged(
        captured: &StableCanonicalBlockStoreMetadata,
        current: &StableCanonicalBlockStoreMetadata,
    ) -> bool {
        let same = |left: &StableSidecarMetadata, right: &StableSidecarMetadata| {
            left.canonical_path == right.canonical_path
                && Self::sidecar_metadata_same_object(&left.file, &right.file)
                && Self::sidecar_directory_binding_unchanged(&left.directory, &right.directory)
        };
        same(&captured.data, &current.data)
            && same(&captured.index, &current.index)
            && same(&captured.hashes, &current.hashes)
    }

    /// No journal bytes or path bindings may change during one fenced read.
    fn native_frame_journal_images_unchanged(
        before: &StableCanonicalBlockStoreMetadata,
        after: &StableCanonicalBlockStoreMetadata,
    ) -> bool {
        Self::stable_sidecar_file_binding_unchanged(&before.data, &after.data)
            && Self::stable_sidecar_file_binding_unchanged(&before.index, &after.index)
            && Self::stable_sidecar_file_binding_unchanged(&before.hashes, &after.hashes)
            && Self::stable_sidecar_file_binding_unchanged(
                &before.commit_marker,
                &after.commit_marker,
            )
    }

    /// Capture an exact native slot length without decoding or accepting any local certificate.
    /// No sidecar finality format, cache fallback, repair or directory creation is consulted.
    pub(crate) fn native_frame_read(
        &self,
        height: u64,
        hash: HashOf<BlockHeader>,
    ) -> Result<Option<NativeFrameRead<'_>>> {
        let position = height
            .checked_sub(1)
            .ok_or(Error::CanonicalBlockWireMismatch { height })?;
        let _prune = self.prune_lock.lock();
        self.ensure_prune_recovery_not_required()?;
        let _canonical = self.canonical_chain_lock.lock();
        self.ensure_canonical_storage_not_poisoned()?;
        let mut store = self.block_store.lock();
        if store.path_to_blockchain.as_os_str().is_empty() {
            // The explicit non-durable store has no native frame or journal pathname.
            // Its empty boundary cannot authorize any retained decoded block.
            return Ok(None);
        }
        let journals = self.native_frame_journal_binding(&mut store)?;
        if height > store.read_exact_durable_index_count()? {
            return Ok(None);
        }
        if Self::read_durable_hash_at_height(&mut store, height)? != Some(hash) {
            return Err(Error::CanonicalBlockWireMismatch { height });
        }
        let slot = store.read_block_index(position)?;
        let wire_len = slot.length;
        if wire_len == 0 || wire_len > STRICT_INIT_MAX_BLOCK_BYTES {
            return Err(Error::CorruptedBlockLength {
                length: wire_len,
                limit: STRICT_INIT_MAX_BLOCK_BYTES,
            });
        }
        Ok(Some(NativeFrameRead {
            kura: self,
            height,
            hash,
            wire_len,
            start: slot.start,
            journals,
        }))
    }

    /// Read the exact frame of an already authenticated original execution graph.
    /// The caller admits its full stored length first. No second decoded graph is constructed.
    pub(crate) fn read_authenticated_execution_wire(
        &self,
        authority: &crate::sumeragi::certified_chain::AuthenticatedExecutionBlock,
        admitted_wire_len: u64,
        budget: &iroha_allocation::AllocationBudget,
    ) -> Result<Option<(iroha_data_model::block::SharedSignedBlock, NativeFrameBytes)>> {
        let expected = authority.block();
        let height = expected.header().height().get();
        let (wire_len, wire_hash) = expected.canonical_wire_identity()?;
        if wire_len == 0 || wire_len != admitted_wire_len || wire_len > STRICT_INIT_MAX_BLOCK_BYTES
        {
            return Err(Error::CanonicalBlockWireMismatch { height });
        }
        let Some(source) = self.native_frame_read(height, expected.hash())? else {
            return Ok(None);
        };
        let Some(bytes) = source.read(admitted_wire_len, budget)? else {
            return Ok(None);
        };
        if Hash::new(&bytes) != wire_hash {
            return Err(Error::CanonicalBlockWireMismatch { height });
        }
        Ok(Some((expected.clone(), bytes)))
    }
}

#[cfg(test)]
mod native_execution_read_tests {
    use super::*;
    use crate::{
        state::World,
        sumeragi::{
            certified_chain::CertifiedChain,
            test_chain::{CertifiedTestChain, TestChainConfig},
        },
    };

    #[test]
    fn native_empty_durable_and_explicit_non_durable_stores_have_no_original_frame() {
        let chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
        let hash = chain.committed(1).block_hash();
        for non_durable in [false, true] {
            let kura = Kura::blank_kura_for_testing();
            if non_durable {
                *kura.block_store.lock() = BlockStore::new(Path::new(""));
            }
            let mut store = kura.block_store.lock();
            assert_eq!(store.read_exact_durable_index_count().unwrap(), 0);
            drop(store);
            kura.reset_canonical_query_reads_for_test();
            for height in [1, 2, u64::MAX] {
                assert!(kura.native_frame_read(height, hash).unwrap().is_none());
            }
            assert!(matches!(
                kura.native_frame_read(0, hash),
                Err(Error::CanonicalBlockWireMismatch { height: 0 })
            ));
            assert_eq!(kura.canonical_query_reads_for_test(), (0, 0));
        }
    }

    #[test]
    fn native_frame_original_start_refuses_same_inode_relocation_before_body_admission() {
        let mut chain =
            CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
        chain.commit_at(2_000, Vec::new());
        let hash = chain.committed(2).block_hash();
        let source = chain.kura().native_frame_read(2, hash).unwrap().unwrap();
        let length = source.wire_len();
        let original = {
            let mut store = chain.kura().block_store.lock();
            let slot = store.read_block_index(1).unwrap();
            assert_eq!(slot.length, length);
            assert_ne!(slot.start, EVICTED_BLOCK_START);
            store
                .write_block_index(1, slot.start.checked_add(1).unwrap(), length)
                .unwrap();
            slot
        };
        let pool = iroha_allocation::AllocationBudget::new(16 * 1024 * 1024);
        let occupied = pool.try_reserve_bytes(pool.limit_bytes()).unwrap();
        chain.kura().reset_canonical_query_reads_for_test();
        let result = source.read(length, &pool);
        // Restore the actual occupied slot before any assertion can unwind the fixture.
        chain
            .kura()
            .block_store
            .lock()
            .write_block_index(1, original.start, original.length)
            .unwrap();
        assert!(
            matches!(result, Err(Error::CanonicalBlockWireMismatch { height: 2 })),
            "captured native start must refuse relocation before original body admission: {result:?}"
        );
        assert_eq!(chain.kura().canonical_query_reads_for_test(), (0, 0));
        assert_eq!(pool.reserved_bytes(), pool.limit_bytes());
        drop(occupied);
        let bytes = chain
            .kura()
            .native_frame_read(2, hash)
            .unwrap()
            .unwrap()
            .read(length, &pool)
            .unwrap()
            .unwrap();
        assert_eq!(
            bytes.as_slice(),
            chain.committed(2).block().encode_wire().unwrap()
        );
    }

    #[test]
    fn native_original_frame_admission_preserves_cumulative_allocation_on_both_stores() {
        for evicted in [false, true] {
            let mut chain =
                CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
            chain.commit(Vec::new());
            let original = chain.committed(2);
            let wire = original.block().encode_wire().unwrap();
            let length = wire.len();
            if evicted {
                let mut store = chain.kura().block_store.lock();
                store.write_da_block_bytes(2, &wire).unwrap();
                store
                    .write_block_index(1, EVICTED_BLOCK_START, length as u64)
                    .unwrap();
                store.publish_commit_marker(2).unwrap();
            }
            let budget = chain.state().ivm_execution_budget();
            let read = |admitted| -> Result<Option<NativeFrameBytes>> {
                chain
                    .kura()
                    .native_frame_read(2, original.block_hash())?
                    .ok_or(Error::CanonicalBlockWireMismatch { height: 2 })?
                    .read(admitted, &budget)
            };
            let unspent = chain
                .kura()
                .native_frame_read(2, original.block_hash())
                .unwrap()
                .unwrap();
            let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 1, 64);
            norito::with_decode_limits_scope(limits, || {
                assert!(matches!(
                    unspent.read(length as u64 - 1, &budget),
                    Err(Error::CanonicalBlockWireMismatch { height: 2 })
                ));
                norito::core::reserve_decode_allocation(1).unwrap();
            });
            // Include the real repeated durable-marker decodes; source metadata is not free.
            // Probe cumulative consumption without guessing those current codec allocations.
            const PROBE_LIMIT: usize = 16 * 1024 * 1024;
            let limits =
                norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, PROBE_LIMIT, 64);
            let exact = norito::with_decode_limits_scope(limits, || {
                assert_eq!(read(length as u64).unwrap().unwrap().as_slice(), wire);
                let error = norito::core::reserve_decode_allocation(PROBE_LIMIT).unwrap_err();
                let norito::Error::TotalAllocationExceeded { attempted, limit } = error else {
                    panic!("original quota refusal")
                };
                usize::try_from(attempted - limit).unwrap()
            });
            assert!(
                exact >= length,
                "the original frame buffer must be charged before reading"
            );
            let limits = norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, exact, 64);
            norito::with_decode_limits_scope(limits, || {
                assert_eq!(read(length as u64).unwrap().unwrap().as_slice(), wire);
                assert!(matches!(
                    read(length as u64),
                    Err(Error::NoritoFrame(
                        norito::Error::TotalAllocationExceeded { .. }
                    ))
                ));
            });
            let limits =
                norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, exact - 1, 64);
            norito::with_decode_limits_scope(limits, || {
                assert!(matches!(
                    read(length as u64),
                    Err(Error::NoritoFrame(
                        norito::Error::TotalAllocationExceeded { .. }
                    ))
                ));
            });
            assert_eq!(read(length as u64).unwrap().unwrap().as_slice(), wire);
        }
    }

    #[test]
    fn native_frame_failed_read_refunds_after_every_original_storage_guard_retires() {
        use iroha_allocation::{AllocationRefusal, release::ReleaseRegistration};
        use std::{
            future::Future as _,
            sync::{Arc, atomic::AtomicUsize},
            task::{Context, Wake, Waker},
        };

        struct Probe {
            kura: Arc<Kura>,
            budget: iroha_allocation::AllocationBudget,
            hash: HashOf<BlockHeader>,
            expected_length: u64,
            waiter_bytes: usize,
            calls: AtomicUsize,
            blocked: AtomicUsize,
            reentered: AtomicUsize,
            premature: AtomicUsize,
        }
        impl Wake for Probe {
            fn wake(self: Arc<Self>) {
                self.wake_by_ref();
            }
            fn wake_by_ref(self: &Arc<Self>) {
                self.calls.fetch_add(1, Ordering::SeqCst);
                let prune_free = self.kura.prune_lock.try_lock().is_some();
                let canonical_free = self.kura.canonical_chain_lock.try_lock().is_some();
                let store_free = self.kura.block_store.try_lock().is_some();
                if self.budget.reserved_bytes() != self.waiter_bytes {
                    self.premature.fetch_add(1, Ordering::SeqCst);
                }
                if !(prune_free && canonical_free && store_free) {
                    self.blocked.fetch_add(1, Ordering::SeqCst);
                } else if self
                    .kura
                    .native_frame_read(2, self.hash)
                    .ok()
                    .flatten()
                    .is_some_and(|source| source.wire_len() == self.expected_length)
                {
                    self.reentered.fetch_add(1, Ordering::SeqCst);
                }
            }
        }

        for evicted in [false, true] {
            let mut chain =
                CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
            chain.commit(Vec::new());
            let original = chain.committed(2);
            let wire = original.block().encode_wire().unwrap();
            let admitted_length = if evicted { wire.len() } else { wire.len() + 1 };
            {
                let mut store = chain.kura().block_store.lock();
                let start = if evicted {
                    // A shorter stable sidecar is read, then refused against its exact slot.
                    store
                        .write_da_block_bytes(2, &wire[..wire.len() - 1])
                        .unwrap();
                    EVICTED_BLOCK_START
                } else {
                    let slot = store.read_block_index(1).unwrap();
                    assert_eq!(
                        slot.start + wire.len() as u64,
                        store.data_file_len().unwrap()
                    );
                    slot.start
                };
                store
                    .write_block_index(1, start, admitted_length as u64)
                    .unwrap();
                store.publish_commit_marker(2).unwrap();
            }
            let (body_path, original_slot) = {
                let mut store = chain.kura().block_store.lock();
                let slot = store.read_block_index(1).unwrap();
                let body_path = if evicted {
                    store.da_block_path(2)
                } else {
                    store.path_to_blockchain.join(DATA_FILE_NAME)
                };
                (body_path, (slot.start, slot.length))
            };
            let physical_source = std::fs::read(&body_path).unwrap();
            let waiter_bytes = ReleaseRegistration::allocation_layout().size();
            let budget = iroha_allocation::AllocationBudget::new(admitted_length + waiter_bytes);
            let mut registration = crate::unit_test_support::release_registration(&budget);
            let AllocationRefusal::Capacity { release, .. } =
                budget.try_reserve_bytes(admitted_length + 1).unwrap_err()
            else {
                panic!("the original pool's free frame extent must retain its release source");
            };
            let probe = Arc::new(Probe {
                kura: Arc::clone(chain.kura()),
                budget: budget.clone(),
                hash: original.block_hash(),
                expected_length: admitted_length as u64,
                waiter_bytes,
                calls: AtomicUsize::new(0),
                blocked: AtomicUsize::new(0),
                reentered: AtomicUsize::new(0),
                premature: AtomicUsize::new(0),
            });
            let waker = Waker::from(Arc::clone(&probe));
            let mut context = Context::from_waker(&waker);
            let mut wait = std::pin::pin!(release.wait_for_release(&mut registration));
            assert!(wait.as_mut().poll(&mut context).is_pending());
            let source = chain
                .kura()
                .native_frame_read(2, original.block_hash())
                .unwrap()
                .unwrap();
            assert_eq!(source.wire_len(), admitted_length as u64);
            assert!(source.read(admitted_length as u64, &budget).is_err());
            assert_eq!(budget.reserved_bytes(), waiter_bytes);
            assert!(budget.peak_reserved_bytes() > waiter_bytes);
            assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
            assert_eq!(probe.blocked.load(Ordering::SeqCst), 0);
            assert_eq!(probe.reentered.load(Ordering::SeqCst), 1);
            assert_eq!(probe.premature.load(Ordering::SeqCst), 0);
            assert!(wait.as_mut().poll(&mut context).is_ready());
            assert_eq!(std::fs::read(body_path).unwrap(), physical_source);
            let mut store = chain.kura().block_store.lock();
            let slot = store.read_block_index(1).unwrap();
            assert_eq!((slot.start, slot.length), original_slot);
        }
    }

    #[test]
    fn native_frame_backing_is_prepaid_once_and_retained_until_physical_drop() {
        for evicted in [false, true] {
            let mut chain =
                CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
            chain.commit(Vec::new());
            let original = chain.committed(2);
            let wire = original.block().encode_wire().unwrap();
            let length = wire.len();
            if evicted {
                let mut store = chain.kura().block_store.lock();
                store.write_da_block_bytes(2, &wire).unwrap();
                store
                    .write_block_index(1, EVICTED_BLOCK_START, length as u64)
                    .unwrap();
                store.publish_commit_marker(2).unwrap();
            }
            let budget = iroha_allocation::AllocationBudget::new(length);
            let occupied = iroha_allocation::ChargedBuffer::<u8>::new(1, &budget).unwrap();
            let before = chain.kura().canonical_body_bytes_read_for_test();
            let read = || {
                chain
                    .kura()
                    .native_frame_read(2, original.block_hash())
                    .unwrap()
                    .unwrap()
                    .read(length as u64, &budget)
            };
            assert!(matches!(
                read(),
                Err(Error::NativeFrameAllocation(
                    iroha_allocation::ChargedBufferError::Admission(_)
                ))
            ));
            assert_eq!(chain.kura().canonical_body_bytes_read_for_test(), before);
            assert_eq!(budget.reserved_bytes(), 1);
            drop(occupied);
            let bytes = read().unwrap().unwrap();
            assert_eq!(bytes.as_slice(), wire);
            assert!(bytes.belongs_to(&budget));
            assert!(!bytes.belongs_to(&iroha_allocation::AllocationBudget::new(length)));
            assert_eq!(budget.reserved_bytes(), length);
            let pointer = bytes.as_slice().as_ptr();
            let moved = (original.block().clone(), bytes);
            assert_eq!(moved.1.as_slice().as_ptr(), pointer);
            assert_eq!(budget.reserved_bytes(), length);
            drop(moved);
            assert_eq!(budget.reserved_bytes(), 0);
        }
    }

    #[test]
    fn native_read_requires_exact_prepaid_length_and_retains_original_graph() {
        let mut chain =
            CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
        chain.commit(Vec::new());
        let view = chain.state().view();
        let source = CertifiedChain::new(&view).unwrap();
        for height in 1..=2 {
            let receipt = source.authenticated_execution(height).unwrap();
            let (length, _) = receipt.block().canonical_wire_identity().unwrap();
            let pointer = receipt.block().clone();
            for wrong in [0, length - 1, length + 1] {
                assert!(
                    chain
                        .kura()
                        .read_authenticated_execution_wire(
                            &receipt,
                            wrong,
                            &chain.state().ivm_execution_budget()
                        )
                        .is_err()
                );
            }
            let (original, bytes) = chain
                .kura()
                .read_authenticated_execution_wire(
                    &receipt,
                    length,
                    &chain.state().ivm_execution_budget(),
                )
                .unwrap()
                .unwrap();
            assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
                &original, &pointer
            ));
            assert_eq!(bytes.as_slice(), original.encode_wire().unwrap());
            assert!(!chain.kura().store_root().join("v2_finality").exists());
        }
    }

    #[test]
    fn changed_occupied_native_frame_fails_without_repair_or_cache_substitution() {
        let mut chain =
            CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
        chain.commit(Vec::new());
        let view = chain.state().view();
        let receipt = CertifiedChain::new(&view)
            .unwrap()
            .authenticated_execution(2)
            .unwrap();
        let bytes = receipt.block().encode_wire().unwrap();
        let length = bytes.len() as u64;
        let mut changed = bytes.clone();
        *changed.last_mut().unwrap() ^= 1;
        let start = {
            let mut store = chain.kura().block_store.lock();
            let slot = store.read_block_index(1).unwrap();
            assert_eq!(slot.length, length);
            store.write_block_data(slot.start, &changed).unwrap();
            slot.start
        };
        assert!(matches!(
            chain.kura().read_authenticated_execution_wire(
                &receipt,
                length,
                &chain.state().ivm_execution_budget()
            ),
            Err(Error::CanonicalBlockWireMismatch { height: 2 })
        ));
        let mut store = chain.kura().block_store.lock();
        let mut observed = vec![0; changed.len()];
        store.read_block_data(start, &mut observed).unwrap();
        assert_eq!(
            observed, changed,
            "the reader cannot repair occupied evidence"
        );
        store.write_block_data(start, &bytes).unwrap();
        drop(store);
        let (original, _) = chain
            .kura()
            .read_authenticated_execution_wire(
                &receipt,
                length,
                &chain.state().ivm_execution_budget(),
            )
            .unwrap()
            .unwrap();
        assert!(iroha_data_model::block::SharedSignedBlock::ptr_eq(
            &original,
            receipt.block()
        ));
    }
    #[test]
    fn native_read_refuses_changed_original_journal_paths_before_body_io_and_retries_after_restore()
    {
        struct ChangedJournal {
            path: PathBuf,
            original: PathBuf,
        }
        impl Drop for ChangedJournal {
            fn drop(&mut self) {
                if std::fs::symlink_metadata(&self.path).is_ok() {
                    std::fs::remove_file(&self.path).unwrap();
                }
                std::fs::rename(&self.original, &self.path).unwrap();
            }
        }
        let mut chain =
            CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
        chain.commit(Vec::new());
        let original = chain.committed(2);
        let wire = original.block().encode_wire().unwrap();
        let budget = chain.state().ivm_execution_budget();
        let directory = Kura::canonical_storage_path(&chain.kura().store_root());
        for journal in [DATA_FILE_NAME, INDEX_FILE_NAME, HASHES_FILE_NAME] {
            for kind in ["missing", "same-bytes-replacement", "fifo", "symlink"] {
                #[cfg(not(unix))]
                if matches!(kind, "fifo" | "symlink") {
                    continue;
                }
                let source = chain
                    .kura()
                    .native_frame_read(2, original.block_hash())
                    .unwrap()
                    .unwrap();
                let path = directory.join(journal);
                let saved = path.with_extension("native-original");
                std::fs::rename(&path, &saved).unwrap();
                let changed = ChangedJournal {
                    path,
                    original: saved,
                };
                match kind {
                    "missing" => {}
                    "same-bytes-replacement" => {
                        std::fs::copy(&changed.original, &changed.path).unwrap();
                    }
                    #[cfg(unix)]
                    "fifo" => assert!(
                        std::process::Command::new("mkfifo")
                            .arg(&changed.path)
                            .status()
                            .unwrap()
                            .success()
                    ),
                    #[cfg(unix)]
                    "symlink" => {
                        std::os::unix::fs::symlink(&changed.original, &changed.path).unwrap();
                    }
                    _ => unreachable!(),
                }
                chain.kura().reset_canonical_query_reads_for_test();
                let reserved = budget.reserved_bytes();
                assert!(
                    source.read(wire.len() as u64, &budget).is_err(),
                    "{journal}: {kind}"
                );
                assert!(
                    chain
                        .kura()
                        .native_frame_read(2, original.block_hash())
                        .is_err(),
                    "a fresh owner cannot adopt {journal}: {kind}"
                );
                assert_eq!(chain.kura().canonical_query_reads_for_test(), (0, 0));
                assert_eq!(budget.reserved_bytes(), reserved);
                drop(changed);
                let retry = chain
                    .kura()
                    .native_frame_read(2, original.block_hash())
                    .unwrap()
                    .unwrap()
                    .read(wire.len() as u64, &budget)
                    .unwrap()
                    .unwrap();
                assert_eq!(retry.as_slice(), wire);
                assert_eq!(
                    chain.kura().canonical_query_reads_for_test(),
                    (1, wire.len() as u64)
                );
                drop(retry);
                assert_eq!(budget.reserved_bytes(), reserved);
            }
        }
    }

    #[test]
    fn native_original_journal_binding_allows_an_authenticated_append_before_read() {
        let mut chain =
            CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
        chain.commit(Vec::new());
        let original = chain.committed(2);
        let wire = original.block().encode_wire().unwrap();
        // The immutable source borrows Kura rather than the mutable chain handle.
        let kura = chain.kura().clone();
        let source = kura
            .native_frame_read(2, original.block_hash())
            .unwrap()
            .unwrap();
        chain.commit(Vec::new());
        let bytes = source
            .read(wire.len() as u64, &chain.state().ivm_execution_budget())
            .unwrap()
            .unwrap();
        assert_eq!(bytes.as_slice(), wire);
        assert_eq!(chain.height(), 3);
    }

    #[test]
    fn native_metadata_is_untrusted_and_cannot_expand_an_admitted_read() {
        let mut chain =
            CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
        chain.commit(Vec::new());
        let original = chain.committed(2);
        let source = chain
            .kura()
            .native_frame_read(2, original.block_hash())
            .unwrap()
            .unwrap();
        let wire_len = source.wire_len();
        assert!(
            source
                .read(wire_len - 1, &chain.state().ivm_execution_budget())
                .is_err()
        );
        let source = chain
            .kura()
            .native_frame_read(2, original.block_hash())
            .unwrap()
            .unwrap();
        let wire = source
            .read(wire_len, &chain.state().ivm_execution_budget())
            .unwrap()
            .unwrap();
        assert_eq!(wire.as_slice(), original.block().encode_wire().unwrap());
        assert!(
            chain
                .kura()
                .native_frame_read(0, original.block_hash())
                .is_err()
        );
    }
}

#[cfg(any(test, feature = "iroha-core-tests"))]
impl Kura {
    /// Corrupt the stored native frame without changing its hash/index or cached original.
    pub fn corrupt_native_frame_for_test(&self, height: NonZeroUsize) {
        let mut store = self.block_store.lock();
        let slot = store
            .read_block_index(u64::try_from(height.get() - 1).unwrap())
            .unwrap();
        assert!(!slot.is_evicted());
        let mut bytes = vec![0; usize::try_from(slot.length).unwrap()];
        store.read_block_data(slot.start, &mut bytes).unwrap();
        *bytes.last_mut().expect("native frame is nonempty") ^= 1;
        store.write_block_data(slot.start, &bytes).unwrap();
    }
}
