//! One original membership append attempt through exact replay and durable sealing.
//!
//! Acquire this owner before the enclosing Kura publication guards. Its range
//! belongs to the original Kura descriptor, while its preparation identity belongs
//! to the actual membership writer. Neither can substitute for the other.
//! TODO: install the sealed roots and their range lease inside the complete State
//! publisher, authenticate restart reconstruction, and reclaim unreachable history
//! before enabling this store in the production Validate-to-Apply path.

use std::{alloc::Layout, io, num::NonZeroU64};

use iroha_allocation::shared::Shared;
use iroha_allocation::{AllocationBudget, AllocationCharge, AllocationRefusal};
use iroha_crypto::{
    Hash, MerkleMapNode, MerkleMapNodeRef, MerkleMapNodeStore, MerkleMapUpdateWorkspace,
    MerkleMapValueRef,
};

use super::{
    CommittedMembershipRoot, Identity, Key, MembershipReadError, MembershipRootError,
    MembershipStore, PreparedMembershipRoot, PreparedTransactionsBlock, Value,
    canonical_height_digest,
    record::{
        FRAME_BYTES, MembershipLocation, MembershipRecord, MembershipRecordCodec, RecordError,
    },
};
use crate::kura::{MEMBERSHIP_RECORD_BYTES, MembershipAppendRange, MembershipStorageError};

const RECORD_BYTES: u64 = MEMBERSHIP_RECORD_BYTES;
const _: () = assert!(RECORD_BYTES == FRAME_BYTES as u64);
type Workspace = MerkleMapUpdateWorkspace<MembershipLocation, MembershipLocation>;

/// Local storage failures preserve absence as an exclusively authenticated answer.
#[derive(Debug, thiserror::Error)]
pub(in crate::state) enum MembershipAppendStoreError {
    /// The original Kura range, namespace, quota or filesystem owner refused.
    #[error(transparent)]
    Storage(#[from] MembershipStorageError),
    /// An underlying positioned operation failed or returned no progress.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// A complete record failed the single declared physical codec.
    #[error(transparent)]
    Record(#[from] RecordError),
    /// A repeated ordinal differs from its already retained exact bytes.
    #[error("membership append replay differs from the original record")]
    ReplayMismatch,
    /// The original admitted interval cannot contain this complete record.
    #[error("membership append exceeds its original reserved interval")]
    Capacity,
    /// A replay stopped before all original complete or pending records.
    #[error("membership append replay did not consume its original prefix")]
    IncompleteReplay,
    /// A closed append cannot accept more records.
    #[error("membership append is already sealed")]
    Sealed,
    /// Node and height records cannot be used interchangeably.
    #[error("membership record has the wrong content kind")]
    WrongKind,
    /// The caller's height digest does not identify its supplied canonical value.
    #[error("membership height write has the wrong content hash")]
    HeightHashMismatch,
}

/// Preparation failures do not establish a deterministic transaction rejection.
#[derive(Debug, thiserror::Error)]
pub(in crate::state) enum MembershipAppendError {
    /// The original prepared transaction owner or baseline changed.
    #[error("membership append belongs to a different preparation")]
    PreparationChanged,
    /// Complete changed-key demand cannot be represented.
    #[error("membership append demand overflows")]
    DemandOverflow,
    /// The actual membership transition refused its original preimages.
    #[error(transparent)]
    Root(#[from] MembershipRootError<MembershipAppendStoreError>),
    /// Preserve the original finite memory pool and release observation.
    #[error(transparent)]
    Admission(#[from] AllocationRefusal),
    /// Physical append, exact replay or sync failed without releasing its owner.
    #[error(transparent)]
    Store(#[from] MembershipAppendStoreError),
    /// No complete authenticated candidate exists yet.
    #[error("membership append is not prepared")]
    Unprepared,
}

// Only the concrete Kura range implements this outside tests. Keeping fault
// injection here lets controls use the same replay kernel around real files.
trait AppendIo {
    fn generation(&self) -> NonZeroU64;
    fn start_offset(&self) -> u64;
    fn reserved_end(&self) -> u64;
    fn read_exact(
        &mut self,
        offset: u64,
        bytes: &mut [u8],
    ) -> Result<(), MembershipAppendStoreError>;
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> Result<usize, MembershipAppendStoreError>;
    fn sync_data(&mut self) -> Result<(), MembershipAppendStoreError>;
    fn complete(&mut self, end: u64) -> Result<(), MembershipAppendStoreError>;
}

impl AppendIo for MembershipAppendRange<'_> {
    fn generation(&self) -> NonZeroU64 {
        self.generation()
    }
    fn start_offset(&self) -> u64 {
        self.start_offset()
    }
    fn reserved_end(&self) -> u64 {
        self.reserved_end()
    }
    fn read_exact(
        &mut self,
        offset: u64,
        bytes: &mut [u8],
    ) -> Result<(), MembershipAppendStoreError> {
        MembershipAppendRange::read_exact(self, offset, bytes).map_err(Into::into)
    }
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> Result<usize, MembershipAppendStoreError> {
        MembershipAppendRange::write_at(self, offset, bytes).map_err(Into::into)
    }
    fn sync_data(&mut self) -> Result<(), MembershipAppendStoreError> {
        MembershipAppendRange::sync_data(self).map_err(Into::into)
    }
    fn complete(&mut self, end: u64) -> Result<(), MembershipAppendStoreError> {
        MembershipAppendRange::complete(self, end).map_err(Into::into)
    }
}

struct ReplayStore<I> {
    io: I,
    codec: MembershipRecordCodec,
    cursor: u64,
    complete: u64,
    pending: Option<[u8; FRAME_BYTES]>,
    sealed: bool,
    durable: bool,
}

impl<I: AppendIo> ReplayStore<I> {
    fn new(io: I, codec: MembershipRecordCodec) -> Result<Self, MembershipAppendStoreError> {
        let start = io.start_offset();
        let end = io.reserved_end();
        if start > end || !start.is_multiple_of(RECORD_BYTES) || !end.is_multiple_of(RECORD_BYTES) {
            return Err(MembershipAppendStoreError::Capacity);
        }
        Ok(Self {
            io,
            codec,
            cursor: start,
            complete: start,
            pending: None,
            sealed: false,
            durable: false,
        })
    }

    fn restart(&mut self) -> Result<(), MembershipAppendStoreError> {
        if self.sealed {
            return Err(MembershipAppendStoreError::Sealed);
        }
        self.cursor = self.io.start_offset();
        Ok(())
    }

    fn read_record(
        &mut self,
        location: MembershipLocation,
    ) -> Result<MembershipRecord, MembershipAppendStoreError> {
        let range = location.checked_range(self.io.generation(), self.complete)?;
        let mut frame = [0; FRAME_BYTES];
        self.io.read_exact(range.start, &mut frame)?;
        Ok(self.codec.read(&frame)?)
    }

    fn append(
        &mut self,
        record: MembershipRecord,
    ) -> Result<MembershipLocation, MembershipAppendStoreError> {
        if self.sealed {
            return Err(MembershipAppendStoreError::Sealed);
        }
        let end = self
            .cursor
            .checked_add(RECORD_BYTES)
            .filter(|end| *end <= self.io.reserved_end())
            .ok_or(MembershipAppendStoreError::Capacity)?;
        // Child-before-parent is also a physical dependency: never emit a
        // reference outside the exact locally complete prefix of this generation.
        match record {
            MembershipRecord::Node(MerkleMapNode::Leaf { value, .. }) => {
                value
                    .location
                    .checked_range(self.io.generation(), self.complete)?;
            }
            MembershipRecord::Node(MerkleMapNode::Branch { left, right, .. }) => {
                left.location
                    .checked_range(self.io.generation(), self.complete)?;
                right
                    .location
                    .checked_range(self.io.generation(), self.complete)?;
            }
            MembershipRecord::Height(_) => {}
        }
        let mut expected = [0; FRAME_BYTES];
        self.codec.write(&mut expected.as_mut_slice(), record)?;
        let location = MembershipLocation::new(self.io.generation(), self.cursor)?;
        if self.cursor < self.complete {
            let mut actual = [0; FRAME_BYTES];
            self.io.read_exact(self.cursor, &mut actual)?;
            if actual != expected {
                return Err(MembershipAppendStoreError::ReplayMismatch);
            }
        } else {
            if self.cursor != self.complete {
                return Err(MembershipAppendStoreError::IncompleteReplay);
            }
            match &self.pending {
                Some(pending) if pending != &expected => {
                    return Err(MembershipAppendStoreError::ReplayMismatch);
                }
                Some(_) => {}
                None => self.pending = Some(expected),
            }
            // Install the complete original frame before any external call.
            // Error and unwind retain this same slot, even when a write reached
            // disk before its failure was reported. A retry rewrites only it.
            let mut written = 0;
            while written < FRAME_BYTES {
                match self
                    .io
                    .write_at(self.cursor + written as u64, &expected[written..])
                {
                    Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero).into()),
                    Ok(count) if count <= FRAME_BYTES - written => written += count,
                    Ok(_) => return Err(io::Error::from(io::ErrorKind::InvalidData).into()),
                    Err(MembershipAppendStoreError::Io(error))
                        if error.kind() == io::ErrorKind::Interrupted =>
                    {
                        continue;
                    }
                    Err(error) => return Err(error),
                }
            }
            self.complete = end;
            self.pending = None;
        }
        self.cursor = end;
        Ok(location)
    }

    fn seal(&mut self) -> Result<(), MembershipAppendStoreError> {
        if self.cursor != self.complete || self.pending.is_some() {
            return Err(MembershipAppendStoreError::IncompleteReplay);
        }
        self.sealed = true;
        Ok(())
    }

    fn sync(&mut self) -> Result<(), MembershipAppendStoreError> {
        if !self.sealed {
            return Err(MembershipAppendStoreError::IncompleteReplay);
        }
        if !self.durable {
            self.io.sync_data()?;
            self.io.complete(self.complete)?;
            self.durable = true;
        }
        Ok(())
    }
}

impl<I: AppendIo> MerkleMapNodeStore for ReplayStore<I> {
    type NodeLocation = MembershipLocation;
    type ValueLocation = MembershipLocation;
    type Error = MembershipAppendStoreError;
    fn read(
        &mut self,
        reference: &MerkleMapNodeRef<MembershipLocation>,
    ) -> Result<Option<MerkleMapNode<MembershipLocation, MembershipLocation>>, Self::Error> {
        match self.read_record(reference.location)? {
            MembershipRecord::Node(node) => Ok(Some(node)),
            MembershipRecord::Height(_) => Err(MembershipAppendStoreError::WrongKind),
        }
    }
    fn write(
        &mut self,
        node: MerkleMapNode<MembershipLocation, MembershipLocation>,
    ) -> Result<MembershipLocation, Self::Error> {
        self.append(MembershipRecord::Node(node))
    }
}
impl<I: AppendIo> MembershipStore for ReplayStore<I> {
    fn read_height(
        &mut self,
        reference: &MerkleMapValueRef<MembershipLocation>,
    ) -> Result<Option<u64>, Self::Error> {
        match self.read_record(reference.location)? {
            MembershipRecord::Height(height) => Ok(Some(height.get())),
            MembershipRecord::Node(_) => Err(MembershipAppendStoreError::WrongKind),
        }
    }
    fn write_height(
        &mut self,
        reference: Hash,
        height: u64,
    ) -> Result<MembershipLocation, Self::Error> {
        let height = NonZeroU64::new(height).ok_or(RecordError::InvalidHeight)?;
        if canonical_height_digest(height.get()) != reference {
            return Err(MembershipAppendStoreError::HeightHashMismatch);
        }
        self.append(MembershipRecord::Height(height))
    }
}

struct AppendInner<I> {
    preparation: Identity,
    baseline: CommittedMembershipRoot<MembershipLocation>,
    workspace: Workspace,
    store: ReplayStore<I>,
    root: Option<PreparedMembershipRoot<MembershipLocation>>,
}

impl<I: AppendIo> AppendInner<I> {
    fn prepare(
        &mut self,
        prepared: &PreparedTransactionsBlock<'_>,
    ) -> Result<(), MembershipAppendError> {
        prepared.assert_unpublished();
        if !Shared::ptr_eq(&self.preparation, &prepared.next_identity)
            || !Shared::ptr_eq(&self.baseline.identity, prepared.block._guard.identity())
        {
            return Err(MembershipAppendError::PreparationChanged);
        }
        if self.root.is_some() {
            return Ok(());
        }
        self.store.restart()?;
        let root = prepared.prepare_membership_root(
            &self.baseline,
            &mut self.store,
            &mut self.workspace,
        )?;
        self.store.seal()?;
        self.root = Some(root);
        Ok(())
    }
}

/// The same charged allocation, physical interval and preparation survive retry.
/// Field drop order deallocates the exact Box before refunding its layout charge.
/// Dropping an incomplete range cannot refund or reassign its uncertain disk bytes.
/// This owner deliberately exposes no root-publication shortcut.
pub(in crate::state) struct PreparedMembershipAppend<'kura> {
    inner: Box<AppendInner<MembershipAppendRange<'kura>>>,
    _charge: AllocationCharge,
}

impl<'kura> PreparedMembershipAppend<'kura> {
    /// Checked conservative physical demand of the actual bounded net changes.
    /// Repeated commits need zero records; no historical map scan is performed.
    pub(in crate::state) fn record_demand(
        prepared: &PreparedTransactionsBlock<'_>,
        baseline: &CommittedMembershipRoot<MembershipLocation>,
    ) -> Result<u64, MembershipAppendError> {
        prepared.assert_unpublished();
        if !Shared::ptr_eq(&baseline.identity, prepared.block._guard.identity()) {
            return Err(MembershipAppendError::PreparationChanged);
        }
        let transition = prepared
            .block
            .membership_transition()
            .map_err(MembershipRootError::Membership)?;
        let mut count = 0_u64;
        transition.visit_committed_changes(|_, _, _| {
            count = count
                .checked_add(1)
                .ok_or(MembershipAppendError::DemandOverflow)?;
            Ok::<_, MembershipAppendError>(())
        })?;
        count
            .checked_mul(Workspace::NODE_CAPACITY as u64 + 1)
            .ok_or(MembershipAppendError::DemandOverflow)
    }

    /// Attach the original Kura range and prepay the complete concrete owner.
    /// Refusal returns the unchanged range, including its original disk credits.
    /// The caller must enclose State writer acquisition, this construction and
    /// physical release in the original memory budget's refund-notification
    /// scope; retire the owner only after sibling writers have been released.
    pub(in crate::state) fn new(
        prepared: &PreparedTransactionsBlock<'_>,
        baseline: &CommittedMembershipRoot<MembershipLocation>,
        range: MembershipAppendRange<'kura>,
    ) -> Result<Self, (MembershipAppendRange<'kura>, MembershipAppendError)> {
        let demand = match Self::record_demand(prepared, baseline) {
            Ok(count) => count,
            Err(error) => return Err((range, error)),
        };
        let required = match demand.checked_mul(RECORD_BYTES) {
            Some(bytes) => bytes,
            None => return Err((range, MembershipAppendError::DemandOverflow)),
        };
        if range
            .reserved_end()
            .checked_sub(range.start_offset())
            .is_none_or(|bytes| bytes < required)
        {
            return Err((range, MembershipAppendStoreError::Capacity.into()));
        }
        let budget: AllocationBudget = range.memory_budget();
        let layout = Layout::new::<AppendInner<MembershipAppendRange<'kura>>>();
        let scratch = MembershipRecordCodec::construction_scratch_layout();
        let mut prepaid = match budget.try_reserve_layouts([layout, scratch]) {
            Ok(prepaid) => prepaid,
            Err(error) => return Err((range, error.into())),
        };
        // These exact layouts were reserved atomically above; each split is
        // checked without a second pool acquisition or growing buffer.
        let scratch_charge = match prepaid.try_split(scratch) {
            Ok(charge) => charge,
            Err(_) => return Err((range, MembershipAppendError::DemandOverflow)),
        };
        let codec = match MembershipRecordCodec::new() {
            Ok(codec) => codec,
            Err(error) => return Err((range, MembershipAppendStoreError::Record(error).into())),
        };
        drop(scratch_charge);
        let charge = match prepaid.try_split(layout) {
            Ok(charge) => charge,
            Err(_) => return Err((range, MembershipAppendError::DemandOverflow)),
        };
        // Validate immutable scalar geometry before taking ownership of the range.
        if !range.start_offset().is_multiple_of(RECORD_BYTES)
            || !range.reserved_end().is_multiple_of(RECORD_BYTES)
        {
            return Err((range, MembershipAppendStoreError::Capacity.into()));
        }
        let start = range.start_offset();
        let inner = AppendInner {
            preparation: prepared.next_identity.clone(),
            baseline: baseline.clone(),
            workspace: Workspace::new(),
            store: ReplayStore {
                io: range,
                codec,
                cursor: start,
                complete: start,
                pending: None,
                sealed: false,
                durable: false,
            },
            root: None,
        };
        // The complete requested Box layout was admitted before construction.
        // As with Kura's original control Box, allocator OOM follows Rust's
        // process policy; finite-pool refusal above retains the original range.
        let inner = Box::new(inner);
        Ok(Self {
            inner,
            _charge: charge,
        })
    }

    /// Retry the same original preparation; sealed candidates do no extra I/O.
    pub(in crate::state) fn prepare(
        &mut self,
        prepared: &PreparedTransactionsBlock<'_>,
    ) -> Result<(), MembershipAppendError> {
        self.inner.prepare(prepared)
    }

    /// Sync the retained sealed bytes without re-executing logical changes.
    /// Failure retains the complete candidate and the same original disk range.
    pub(in crate::state) fn sync(&mut self) -> Result<(), MembershipAppendError> {
        if self.inner.root.is_none() {
            return Err(MembershipAppendError::Unprepared);
        }
        self.inner.store.sync()?;
        Ok(())
    }

    /// Diagnostic state only; durable bytes do not grant State publication.
    pub(in crate::state) fn is_durable(&self) -> bool {
        self.inner.store.durable
    }

    /// Transfer the original range and Kura fence notifications to the enclosing
    /// cleanup owner. Drop it only after all State and Kura physical writers
    /// release; the completed range keeps its original readable bytes.
    pub(in crate::state) fn take_cleanup(
        &mut self,
    ) -> Option<crate::kura::MembershipAppendCleanup<'kura>> {
        self.inner.store.io.take_cleanup()
    }

    /// Authenticate a prepared cut for local verification without publishing it.
    pub(in crate::state) fn read_after(
        &mut self,
        key: &Key,
    ) -> Result<Option<Value>, MembershipReadError<MembershipAppendStoreError>> {
        let Some(root) = self.inner.root.as_ref() else {
            return Err(MembershipReadError::ValueSource(
                MembershipAppendStoreError::IncompleteReplay,
            ));
        };
        root.after.read(key, &mut self.inner.store)
    }
}

#[cfg(test)]
#[path = "membership_append_tests.rs"]
mod tests;
