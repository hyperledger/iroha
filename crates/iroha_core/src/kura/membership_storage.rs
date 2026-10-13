//! Original-descriptor custody for one finite membership segment.
//!
//! A range is physical preparation authority, not a membership root or a State
//! publication capability. Completed ranges keep their original read extent;
//! pending or abandoned ranges retain all reserved/possibly written bytes.
//! TODO: authenticate restart roots and incomplete ranges before adding reopen,
//! reclamation, rollover, or production membership publication. Existing segment
//! files deliberately require recovery instead of being adopted from their length.

use iroha_allocation::release::{DeferredRelease, ReleaseGuard, ReleaseNotification, ReleaseWait};
use std::{alloc::Layout, cell::RefCell, fs::File, io, num::NonZeroU64};

use iroha_allocation::{AllocationBudget, AllocationCharge, AllocationRefusal};
use iroha_config::parameters::actual::KuraMembershipStoragePolicy;
use parking_lot::Mutex;

use super::Kura;

pub(super) const SEGMENT_NAME: &str = "membership-0000000000000001.norito";
/// Exact frame size of the first-release membership record schema.
pub const MEMBERSHIP_RECORD_BYTES: u64 = MEMBERSHIP_RECORD_SIZE as u64;
const MEMBERSHIP_RECORD_SIZE: usize = 184;

/// A physical refusal never represents authenticated membership absence.
#[derive(Debug, thiserror::Error)]
pub enum MembershipStorageError {
    /// Original finite memory-pool refusal.
    #[error(transparent)]
    Allocation(#[from] AllocationRefusal),
    /// An original prepaid control reservation could not supply its exact layout.
    #[error(transparent)]
    Reservation(#[from] iroha_allocation::InsufficientReservation),
    /// Native positioned I/O or durability failure; the range remains owned.
    #[error(transparent)]
    Io(#[from] io::Error),
    /// Original Kura admission or durable-mutation authority refusal.
    #[error(transparent)]
    Kura(#[from] super::Error),
    /// The range or offset arithmetic is invalid.
    #[error("membership range is out of bounds")]
    Bounds,
    /// The immutable configured finite segment cannot hold this reservation.
    #[error("membership segment capacity exhausted: limit {limit}, reserved end {required}")]
    Capacity {
        /// Original configured byte limit.
        limit: u64,
        /// Required end, including the retained original prefix.
        required: u64,
    },
    /// Another original append still owns the only writable range.
    #[error("membership append range is already owned")]
    Busy {
        /// Original exclusive-range release observation; retry must recheck ownership.
        release: ReleaseWait,
    },
    /// Dropping an unfinished original range does not make its bytes reusable.
    #[error("membership append was abandoned; authenticated recovery is required")]
    Abandoned,
    /// An existing generation must not be adopted without authenticated roots.
    #[error("existing membership segment requires authenticated recovery")]
    RecoveryRequired,
    /// The original descriptor, directory entry, or physical length changed externally.
    #[error("membership segment namespace or descriptor changed")]
    NamespaceChanged,
    /// Successful completion permanently closes this range to writes.
    #[error("membership append range is closed")]
    Closed,
    /// Completion requires a successful sync of the current exact physical prefix.
    #[error("membership append has not synchronized its current complete prefix")]
    NotSynced,
    /// This platform lacks the descriptor-relative namespace authority used here.
    #[error("descriptor-bound membership storage is unsupported on this platform")]
    Unsupported,
}

struct ActiveRange {
    id: u64,
    end: u64,
    /// Installed before I/O, including an uncertain short/error write's entire request.
    touched_end: u64,
    synced: bool,
    abandoned: bool,
    uncertain: Option<UncertainWrite>,
}

struct UncertainWrite {
    offset: u64,
    len: usize,
    bytes: [u8; MEMBERSHIP_RECORD_SIZE],
}

#[derive(Default)]
struct SegmentControl {
    file: Option<File>,
    physical_len: u64,
    readable_end: u64,
    next_id: u64,
    active: Option<ActiveRange>,
}

/// Concrete backing is freed before returning its exact requested-layout charge.
pub(super) struct MembershipStorage {
    control: Box<Mutex<SegmentControl>>,
    _charge: AllocationCharge,
    budget: AllocationBudget,
    policy: KuraMembershipStoragePolicy,
    pending: std::sync::atomic::AtomicU64,
    releases: ReleaseNotification,
}

impl std::fmt::Debug for MembershipStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MembershipStorage")
            .field("policy", &self.policy)
            .field("pending", &self.pending_bytes())
            .finish_non_exhaustive()
    }
}

impl MembershipStorage {
    pub(super) fn new(policy: KuraMembershipStoragePolicy) -> Result<Self, MembershipStorageError> {
        let budget = AllocationBudget::new(policy.memory_bytes.get());
        let layout = Layout::new::<Mutex<SegmentControl>>();
        let mut admission = budget.try_reserve(layout)?;
        let charge = admission.try_split(layout)?;
        // The original charge exists before Box requests exactly this layout.
        // The outer Kura allocation and AllocationBudget's own fixed control are
        // constructor obligations, not falsely counted as workspace backing.
        let control = Box::new(Mutex::new(SegmentControl::default()));
        Ok(Self {
            control,
            _charge: charge,
            budget,
            policy,
            pending: std::sync::atomic::AtomicU64::new(0),
            releases: ReleaseNotification::default(),
        })
    }

    pub(super) fn pending_bytes(&self) -> u64 {
        self.pending.load(std::sync::atomic::Ordering::Acquire)
    }
}

/// One allocation-free range holder borrowing its original Kura and descriptor.
///
/// A completed holder remains a read lease. An unfinished holder's Drop marks
/// its original range abandoned; it does not unlink, truncate, refund, or permit
/// a new retry owner. Memory refunds must be deferred by the enclosing State
/// owner until all of its physical guards have been released.
#[must_use]
pub struct MembershipAppendRange<'kura> {
    kura: &'kura Kura,
    id: u64,
    start: u64,
    reserved_end: u64,
    base_readable_end: u64,
    completed_end: Option<u64>,
    permit: Option<ReleaseGuard<'kura, RangePermit<'kura>>>,
    pending_disk: RefCell<Option<super::PhysicalResourceMutation<'kura>>>,
    cleanup: RefCell<Option<MembershipAppendCleanup<'kura>>>,
}

/// Original range and Kura-fence notifications retained beyond all physical writers.
///
/// This fixed bundle borrows the original Kura sources and allocates no replacement
/// notification state. Drop it only after the complete enclosing State owner has
/// physically released its writers. It conveys neither roots nor write authority.
#[must_use = "retain original notifications until all enclosing physical writers release"]
pub struct MembershipAppendCleanup<'kura> {
    prune: crate::publication_lock::DeferredPublicationFence<'kura, ()>,
    canonical: crate::publication_lock::DeferredPublicationFence<'kura, ()>,
    range_release: Option<DeferredRelease>,
}

impl std::fmt::Debug for MembershipAppendRange<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MembershipAppendRange")
            .field("start", &self.start)
            .field("reserved_end", &self.reserved_end)
            .field("completed_end", &self.completed_end)
            .finish_non_exhaustive()
    }
}

struct RangePermit<'kura> {
    kura: &'kura Kura,
    id: u64,
}
impl Drop for RangePermit<'_> {
    fn drop(&mut self) {
        let mut control = self.kura.membership_storage.control.lock();
        if let Some(active) = &mut control.active {
            if active.id == self.id {
                active.abandoned = true;
            }
        }
    }
}

impl Kura {
    /// Obtain genuine contended fence observations while retaining the probe's
    /// own physical releases; the test retires this bundle after its assertions.
    #[cfg(test)]
    pub(crate) fn membership_fence_waits_for_tests(
        &self,
    ) -> ([ReleaseWait; 2], MembershipAppendCleanup<'_>) {
        let mut cleanup = MembershipAppendCleanup {
            prune: self.prune_lock.defer_notifications(),
            canonical: self.canonical_chain_lock.defer_notifications(),
            range_release: None,
        };
        let prune = cleanup.prune.lock();
        let canonical = cleanup.canonical.lock();
        let waits = [
            self.prune_lock
                .try_lock_or_wait()
                .err()
                .expect("actual held prune fence"),
            self.canonical_chain_lock
                .try_lock_or_wait()
                .err()
                .expect("actual held canonical fence"),
        ];
        drop(canonical);
        drop(prune);
        (waits, cleanup)
    }

    /// Join the separate physical publication owners without borrowing their locks together.
    pub(super) fn all_publication_budget_reserved_bytes(&self) -> super::Result<u64> {
        Ok(self.membership_storage.pending_bytes())
    }

    /// Borrow the original finite membership allocation pool before constructing
    /// an append workspace. This does not reserve bytes by itself.
    pub fn membership_memory_budget(&self) -> AllocationBudget {
        self.membership_storage.budget.clone()
    }

    /// Reserve a checked fixed-record interval before any append I/O.
    ///
    /// Invoke before acquiring outer Kura publication guards: this operation
    /// takes the original prune and canonical guards in their established order.
    /// No physical space or unknown existing bytes are treated as reclaimable.
    /// Reserve before acquiring State writers: a refused reservation has no range
    /// into which it can transfer its own Kura-fence cleanup.
    ///
    /// # Errors
    /// Returns original memory/storage/namespace failures, finite exhaustion,
    /// active ownership, or explicit abandoned/restart-recovery requirements.
    pub fn reserve_membership_range(
        &self,
        record_count: u64,
    ) -> Result<MembershipAppendRange<'_>, MembershipStorageError> {
        let release = self.membership_storage.releases.observe();
        let bytes = record_count
            .checked_mul(MEMBERSHIP_RECORD_BYTES)
            .ok_or(MembershipStorageError::Bounds)?;
        let mut cleanup = MembershipAppendCleanup {
            prune: self.prune_lock.defer_notifications(),
            canonical: self.canonical_chain_lock.defer_notifications(),
            range_release: None,
        };
        let prune_guard = cleanup.prune.lock();
        self.ensure_prune_recovery_not_required()?;
        let canonical_guard = cleanup.canonical.lock();
        self.durable_mutation_authorized()?;
        let (id, start, end) = {
            let control = self.membership_storage.control.lock();
            if let Some(active) = &control.active {
                return Err(if active.abandoned {
                    MembershipStorageError::Abandoned
                } else {
                    MembershipStorageError::Busy { release }
                });
            }
            let start = control.readable_end;
            let end = start
                .checked_add(bytes)
                .ok_or(MembershipStorageError::Bounds)?;
            if end > self.membership_storage.policy.max_bytes.get() || end > i64::MAX as u64 {
                return Err(MembershipStorageError::Capacity {
                    limit: self.membership_storage.policy.max_bytes.get(),
                    required: end,
                });
            }
            let id = control
                .next_id
                .checked_add(1)
                .ok_or(MembershipStorageError::Bounds)?;
            // This transient reservation is still pre-I/O and may be returned
            // if global admission refuses. Other admissions share canonical ownership.
            self.membership_storage
                .pending
                .store(bytes, std::sync::atomic::Ordering::Release);
            (id, start, end)
        };
        if let Err(error) = self.check_publication_capacity_under_prune_and_canonical_guards() {
            self.membership_storage
                .pending
                .store(0, std::sync::atomic::Ordering::Release);
            return Err(error.into());
        }
        let mut control = self.membership_storage.control.lock();
        control.next_id = id;
        control.active = Some(ActiveRange {
            id,
            end,
            touched_end: start,
            synced: false,
            abandoned: false,
            uncertain: None,
        });
        // From this point even creation/directory-sync ambiguity stays with this owner.
        if let Err(error) = self.open_membership_segment(&mut control) {
            if let Some(active) = &mut control.active {
                active.abandoned = true;
            }
            return Err(error);
        }
        drop(control);
        drop(canonical_guard);
        drop(prune_guard);
        Ok(MembershipAppendRange {
            kura: self,
            id,
            start,
            reserved_end: end,
            base_readable_end: start,
            completed_end: None,
            permit: Some(
                self.membership_storage
                    .releases
                    .guard(RangePermit { kura: self, id }),
            ),
            pending_disk: RefCell::new(None),
            cleanup: RefCell::new(Some(cleanup)),
        })
    }

    #[cfg(all(unix, not(target_os = "espidf")))]
    fn open_membership_segment(
        &self,
        control: &mut SegmentControl,
    ) -> Result<(), MembershipStorageError> {
        if control.file.is_none() {
            if !self.bound_storage_directory_unchanged(&self.store_root_directory) {
                return Err(MembershipStorageError::NamespaceChanged);
            }
            let mutation = self.begin_total_disk_usage_mutation();
            let opened = rustix::fs::openat(
                &self.store_root_directory.file,
                SEGMENT_NAME,
                rustix::fs::OFlags::RDWR
                    | rustix::fs::OFlags::CREATE
                    | rustix::fs::OFlags::EXCL
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
            )
            .map_err(|error| {
                if error == rustix::io::Errno::EXIST {
                    MembershipStorageError::RecoveryRequired
                } else {
                    MembershipStorageError::Io(error.into())
                }
            })?;
            // Install before the first fallible metadata/durability operation.
            control.file = Some(File::from(opened));
            self.validate_membership_segment(control)?;
            self.store_root_directory.file.sync_all()?;
            self.finish_membership_disk_mutation(mutation, 0, 0);
        }
        self.validate_membership_segment(control)
    }

    #[cfg(not(all(unix, not(target_os = "espidf"))))]
    fn open_membership_segment(
        &self,
        _: &mut SegmentControl,
    ) -> Result<(), MembershipStorageError> {
        Err(MembershipStorageError::Unsupported)
    }

    #[cfg(all(unix, not(target_os = "espidf")))]
    fn validate_membership_segment_identity(
        &self,
        control: &SegmentControl,
    ) -> Result<(), MembershipStorageError> {
        use std::os::unix::fs::MetadataExt as _;
        if !self.bound_storage_directory_unchanged(&self.store_root_directory) {
            return Err(MembershipStorageError::NamespaceChanged);
        }
        let file = control
            .file
            .as_ref()
            .ok_or(MembershipStorageError::RecoveryRequired)?;
        let metadata = file.metadata()?;
        let entry = rustix::fs::statat(
            &self.store_root_directory.file,
            SEGMENT_NAME,
            rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|_| MembershipStorageError::NamespaceChanged)?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || rustix::fs::FileType::from_raw_mode(entry.st_mode)
                != rustix::fs::FileType::RegularFile
            || entry.st_nlink as u64 != 1
            || entry.st_dev as u64 != metadata.dev()
            || entry.st_ino as u64 != metadata.ino()
        {
            return Err(MembershipStorageError::NamespaceChanged);
        }
        Ok(())
    }

    #[cfg(not(all(unix, not(target_os = "espidf"))))]
    fn validate_membership_segment_identity(
        &self,
        _: &SegmentControl,
    ) -> Result<(), MembershipStorageError> {
        Err(MembershipStorageError::Unsupported)
    }

    fn validate_membership_segment(
        &self,
        control: &SegmentControl,
    ) -> Result<(), MembershipStorageError> {
        self.validate_membership_segment_identity(control)?;
        if control
            .file
            .as_ref()
            .ok_or(MembershipStorageError::RecoveryRequired)?
            .metadata()?
            .len()
            != control.physical_len
        {
            return Err(MembershipStorageError::NamespaceChanged);
        }
        Ok(())
    }

    /// The caller holds the original descriptor lock and validates its namespace
    /// before/after I/O. Publish its exact length delta using the existing fixed
    /// physical inventory, without building a new path vector on each record.
    fn finish_membership_disk_mutation(
        &self,
        mut mutation: super::TotalDiskUsageMutation<'_>,
        before: u64,
        after: u64,
    ) {
        self.update_disk_usage_delta(before, after);
        self.finish_membership_resource_mutation(mutation.physical_resources.take(), before, after);
        mutation.published = true;
    }

    fn finish_membership_resource_mutation(
        &self,
        resources: Option<super::PhysicalResourceMutation<'_>>,
        before: u64,
        after: u64,
    ) {
        if let Some(resources) = resources {
            let values =
                std::array::from_fn::<_, { super::PHYSICAL_RESOURCE_FAMILIES.len() }, _>(|i| {
                    let family = super::PHYSICAL_RESOURCE_FAMILIES[i];
                    let usage = |storage_bytes| super::ResourceUsage {
                        storage_bytes: if family == super::ResourceFamily::StorageBytes {
                            storage_bytes
                        } else {
                            0
                        },
                        ..super::ResourceUsage::default()
                    };
                    (family, usage(before), usage(after))
                });
            if let Err(reason) = resources.mutation.publish(&values) {
                self.resource_inventory
                    .invalidate(super::physical_resource_mask(), reason);
            }
        }
    }
}

impl<'kura> MembershipAppendRange<'kura> {
    /// Single retained generation; no rollover or reopened authority is inferred.
    pub const fn generation(&self) -> NonZeroU64 {
        NonZeroU64::MIN
    }
    /// Original reserved interval start, relative to this segment descriptor.
    pub const fn start_offset(&self) -> u64 {
        self.start
    }
    /// Original maximum end; completion can release only its unwritten suffix.
    pub const fn reserved_end(&self) -> u64 {
        self.reserved_end
    }
    /// Complete prefix belonging to earlier successful ranges at reservation time.
    pub const fn base_readable_end(&self) -> u64 {
        self.base_readable_end
    }
    /// Original pool for the concrete codec/control/workspace allocations.
    pub fn memory_budget(&self) -> AllocationBudget {
        self.kura.membership_memory_budget()
    }

    /// Transfer the original range and Kura-fence notifications outside enclosing writers.
    /// An unfinished range retains its complete cleanup and cannot transfer it.
    pub fn take_cleanup(&mut self) -> Option<MembershipAppendCleanup<'kura>> {
        if self.completed_end.is_some() {
            self.cleanup.get_mut().take()
        } else {
            None
        }
    }

    fn recover_uncertain(
        &self,
        control: &mut SegmentControl,
    ) -> Result<(), MembershipStorageError> {
        let Some(request) = control
            .active
            .as_ref()
            .and_then(|active| active.uncertain.as_ref())
        else {
            return Ok(());
        };
        if control
            .active
            .as_ref()
            .is_none_or(|active| active.id != self.id)
        {
            return Err(MembershipStorageError::Closed);
        }
        self.kura.validate_membership_segment_identity(control)?;
        let file = control
            .file
            .as_ref()
            .ok_or(MembershipStorageError::RecoveryRequired)?;
        let after = file.metadata()?.len();
        let request_end = request
            .offset
            .checked_add(request.len as u64)
            .ok_or(MembershipStorageError::Bounds)?;
        if after < control.physical_len || after > control.physical_len.max(request_end) {
            return Err(MembershipStorageError::NamespaceChanged);
        }
        let present = usize::try_from(after.min(request_end).saturating_sub(request.offset))
            .map_err(|_| MembershipStorageError::Bounds)?;
        let mut actual = [0; MEMBERSHIP_RECORD_SIZE];
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileExt as _;
            file.read_exact_at(&mut actual[..present], request.offset)?;
        }
        #[cfg(not(unix))]
        {
            return Err(MembershipStorageError::Unsupported);
        }
        if actual[..present] != request.bytes[..present] {
            return Err(MembershipStorageError::NamespaceChanged);
        }
        self.kura.validate_membership_segment_identity(control)?;
        if file.metadata()?.len() != after {
            return Err(MembershipStorageError::NamespaceChanged);
        }
        let resources = self.pending_disk.borrow_mut().take();
        self.kura
            .finish_membership_resource_mutation(resources, control.physical_len, after);
        // The failed short total-usage operation already allowed rescans. A scan
        // may include these bytes, so do not add their delta to that newer cache.
        self.kura
            .disk_usage_initialized
            .store(false, std::sync::atomic::Ordering::Relaxed);
        self.kura
            .disk_usage_total_initialized
            .store(false, std::sync::atomic::Ordering::Relaxed);
        self.kura.invalidate_durable_budget_snapshot();
        control.physical_len = after;
        control
            .active
            .as_mut()
            .ok_or(MembershipStorageError::Closed)?
            .uncertain = None;
        self.kura.membership_storage.pending.store(
            self.reserved_end - after,
            std::sync::atomic::Ordering::Release,
        );
        Ok(())
    }

    fn check_active<'a>(
        &self,
        control: &'a mut SegmentControl,
    ) -> Result<&'a mut ActiveRange, MembershipStorageError> {
        if self.completed_end.is_some() {
            return Err(MembershipStorageError::Closed);
        }
        let active = control
            .active
            .as_mut()
            .ok_or(MembershipStorageError::Closed)?;
        let reserved_range_end = self.reserved_end;
        if active.id != self.id || active.end != reserved_range_end {
            return Err(MembershipStorageError::Closed);
        }
        if active.abandoned {
            return Err(MembershipStorageError::Abandoned);
        }
        Ok(active)
    }

    /// Read exact bytes from this original range or its complete original base.
    ///
    /// This supplies no hash/record authentication. Short physical files fail;
    /// reserved but unwritten bytes are never synthesized as membership absence.
    /// # Errors
    /// Rejects overflow, unreadable extents, substituted namespaces and native I/O.
    pub fn read_exact(&self, offset: u64, frame: &mut [u8]) -> Result<(), MembershipStorageError> {
        let uncertain = self.completed_end.is_none()
            && self
                .kura
                .membership_storage
                .control
                .lock()
                .active
                .as_ref()
                .is_some_and(|active| active.id == self.id && active.uncertain.is_some());
        let mut retained = self.cleanup.borrow_mut();
        let (_prune, _canonical) = if uncertain {
            let cleanup = retained.as_mut().ok_or(MembershipStorageError::Closed)?;
            (Some(cleanup.prune.lock()), Some(cleanup.canonical.lock()))
        } else {
            (None, None)
        };

        let end = offset
            .checked_add(u64::try_from(frame.len()).map_err(|_| MembershipStorageError::Bounds)?)
            .ok_or(MembershipStorageError::Bounds)?;
        let mut control = self.kura.membership_storage.control.lock();
        if self.completed_end.is_none() {
            self.recover_uncertain(&mut control)?;
        }
        let readable = self
            .completed_end
            .unwrap_or_else(|| control.physical_len.min(self.reserved_end));
        if end > readable {
            return Err(MembershipStorageError::Bounds);
        }
        if self.completed_end.is_none() {
            self.kura.validate_membership_segment(&control)?;
        } else {
            self.kura.validate_membership_segment_identity(&control)?;
        }
        let file = control
            .file
            .as_ref()
            .ok_or(MembershipStorageError::RecoveryRequired)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileExt as _;
            file.read_exact_at(frame, offset)?;
        }
        #[cfg(not(unix))]
        {
            let _ = (file, frame, offset);
            return Err(MembershipStorageError::Unsupported);
        }
        if self.completed_end.is_none() {
            self.kura.validate_membership_segment(&control)
        } else {
            self.kura.validate_membership_segment_identity(&control)
        }
    }

    /// Make one native positioned write in the original reserved interval.
    ///
    /// May return a short write or error. The enclosing replay owner must retain
    /// the exact pending frame before calling; this method never retries it or
    /// releases uncertain reservation bytes. Call before outer Kura fences.
    /// # Errors
    /// Rejects closed/abandoned ranges, offset escape, namespace changes and I/O.
    pub fn write_at(&self, offset: u64, bytes: &[u8]) -> Result<usize, MembershipStorageError> {
        let end = offset
            .checked_add(u64::try_from(bytes.len()).map_err(|_| MembershipStorageError::Bounds)?)
            .ok_or(MembershipStorageError::Bounds)?;
        if offset < self.start
            || end > self.reserved_end
            || bytes.len() > MEMBERSHIP_RECORD_SIZE
            || (!bytes.is_empty()
                && offset / MEMBERSHIP_RECORD_BYTES != (end - 1) / MEMBERSHIP_RECORD_BYTES)
        {
            return Err(MembershipStorageError::Bounds);
        }
        let mut retained = self.cleanup.borrow_mut();
        let MembershipAppendCleanup {
            prune,
            canonical,
            range_release: _,
        } = retained.as_mut().ok_or(MembershipStorageError::Closed)?;
        let _prune = prune.lock();
        self.kura.ensure_prune_recovery_not_required()?;
        let _canonical = canonical.lock();
        self.kura.durable_mutation_authorized()?;
        let mut control = self.kura.membership_storage.control.lock();
        self.recover_uncertain(&mut control)?;
        self.kura.validate_membership_segment(&control)?;
        if offset > control.physical_len {
            return Err(MembershipStorageError::Bounds);
        }
        let active = self.check_active(&mut control)?;
        active.touched_end = active.touched_end.max(end);
        active.synced = false;
        let mut request = UncertainWrite {
            offset,
            len: bytes.len(),
            bytes: [0; MEMBERSHIP_RECORD_SIZE],
        };
        request.bytes[..bytes.len()].copy_from_slice(bytes);
        active.uncertain = Some(request);
        let mut mutation = self.kura.begin_total_disk_usage_mutation();
        *self.pending_disk.borrow_mut() = mutation.physical_resources.take();
        let before = control.physical_len;
        let file = control
            .file
            .as_ref()
            .ok_or(MembershipStorageError::RecoveryRequired)?;
        #[cfg(unix)]
        let result = {
            use std::os::unix::fs::FileExt as _;
            file.write_at(bytes, offset)
        };
        #[cfg(not(unix))]
        let result: io::Result<usize> = Err(io::ErrorKind::Unsupported.into());
        #[cfg(test)]
        if let Some(length) = EXTEND_MEMBERSHIP_POST_WRITE.with(|fault| fault.take()) {
            // A foreign writer can mutate the same inode without replacing its
            // namespace entry. The original request must not adopt that growth.
            file.set_len(length)?;
        }
        #[cfg(test)]
        if FAIL_MEMBERSHIP_POST_WRITE_METADATA.with(|fault| fault.replace(false)) {
            return Err(MembershipStorageError::Io(io::ErrorKind::Other.into()));
        }
        // Even an error may have materialized bytes: retain/read the same FD.
        let after = file.metadata()?.len();
        if after < before || after > before.max(end) {
            return Err(MembershipStorageError::NamespaceChanged);
        }
        self.kura.validate_membership_segment_identity(&control)?;
        if control
            .file
            .as_ref()
            .ok_or(MembershipStorageError::RecoveryRequired)?
            .metadata()?
            .len()
            != after
        {
            return Err(MembershipStorageError::NamespaceChanged);
        }
        mutation.physical_resources = self.pending_disk.borrow_mut().take();
        self.kura
            .finish_membership_disk_mutation(mutation, before, after);
        control.physical_len = after;
        control
            .active
            .as_mut()
            .ok_or(MembershipStorageError::Closed)?
            .uncertain = None;
        self.kura.membership_storage.pending.store(
            self.reserved_end - after,
            std::sync::atomic::Ordering::Release,
        );
        result.map_err(Into::into)
    }

    /// Synchronize this descriptor's current bytes without publishing any root.
    /// # Errors
    /// Preserves native sync errors and refuses substituted or abandoned owners.
    pub fn sync_data(&self) -> Result<(), MembershipStorageError> {
        let uncertain = self.completed_end.is_none()
            && self
                .kura
                .membership_storage
                .control
                .lock()
                .active
                .as_ref()
                .is_some_and(|active| active.id == self.id && active.uncertain.is_some());
        let mut retained = self.cleanup.borrow_mut();
        let (_prune, _canonical) = if uncertain {
            let cleanup = retained.as_mut().ok_or(MembershipStorageError::Closed)?;
            (Some(cleanup.prune.lock()), Some(cleanup.canonical.lock()))
        } else {
            (None, None)
        };

        let mut control = self.kura.membership_storage.control.lock();
        if self.completed_end.is_none() {
            self.recover_uncertain(&mut control)?;
        }
        if self.completed_end.is_none() {
            self.kura.validate_membership_segment(&control)?;
        } else {
            self.kura.validate_membership_segment_identity(&control)?;
        }
        if self.completed_end.is_none() {
            self.check_active(&mut control)?;
        }
        control
            .file
            .as_ref()
            .ok_or(MembershipStorageError::RecoveryRequired)?
            .sync_data()?;
        if self.completed_end.is_none() {
            self.kura.validate_membership_segment(&control)?;
        } else {
            self.kura.validate_membership_segment_identity(&control)?;
        }
        if self.completed_end.is_none() {
            self.check_active(&mut control)?.synced = true;
        }
        Ok(())
    }

    /// Close the original synchronized range and release only its never-written tail.
    ///
    /// The caller must first authenticate every complete record and seal its roots.
    /// This is local physical completion, not State publication. Repeating the same
    /// successful completion is idempotent and never allocates another range.
    /// # Errors
    /// Rejects a different repeated end, incomplete/unsynced bytes or owner changes.
    pub fn complete(&mut self, end: u64) -> Result<(), MembershipStorageError> {
        if let Some(original) = self.completed_end {
            return if end == original {
                Ok(())
            } else {
                Err(MembershipStorageError::Closed)
            };
        }
        if end < self.start
            || end > self.reserved_end
            || !end.is_multiple_of(MEMBERSHIP_RECORD_BYTES)
        {
            return Err(MembershipStorageError::Bounds);
        }
        let mut retained = self.cleanup.borrow_mut();
        let MembershipAppendCleanup {
            prune,
            canonical,
            range_release,
        } = retained.as_mut().ok_or(MembershipStorageError::Closed)?;
        let _prune = prune.lock();
        let _canonical = canonical.lock();
        let mut control = self.kura.membership_storage.control.lock();
        self.recover_uncertain(&mut control)?;
        self.kura.validate_membership_segment(&control)?;
        if control.physical_len != end {
            return Err(MembershipStorageError::Bounds);
        }
        let active = self.check_active(&mut control)?;
        if end < active.touched_end {
            return Err(MembershipStorageError::Bounds);
        }
        if !active.synced {
            return Err(MembershipStorageError::NotSynced);
        }
        control.readable_end = end;
        control.active = None;
        self.kura
            .membership_storage
            .pending
            .store(0, std::sync::atomic::Ordering::Release);
        self.completed_end = Some(end);
        drop(control);
        if let Some(permit) = self.permit.take() {
            *range_release = Some(permit.release_deferred(drop).1);
        }
        Ok(())
    }
}

impl Drop for MembershipAppendRange<'_> {
    fn drop(&mut self) {
        // The caller owns this range through all enclosing physical release.
        // ReleasePermit first revokes write authority; accounting ambiguity and
        // the actual notification remain retained until this owner is retired.
        if let Some(permit) = self.permit.take() {
            let release = permit.release_deferred(drop).1;
            if let Some(cleanup) = self.cleanup.get_mut() {
                cleanup.range_release = Some(release);
            }
        }
    }
}

#[cfg(test)]
thread_local! {
    static FAIL_MEMBERSHIP_POST_WRITE_METADATA: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static EXTEND_MEMBERSHIP_POST_WRITE: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
#[path = "membership_storage_tests.rs"]
mod tests;
