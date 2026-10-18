//! Original-funded durable lane frames with retained startup, read and publication owners.
//!
//! One exclusive instance owner validates its entire recovered prefix before exposing a tip.
//! Complete signed availability and the original CommitQC share one canonical atomic frame.

use super::{
    AdmissionAttemptError, LaneBatch,
    merge::CommittedLaneBlock,
    proposal_reads::{ProposalReadScope, ReadInterest},
};
use crate::execution_attempt::ExecutionAttemptError as Attempt;
use crate::sumeragi::{
    availability_schedule::{AvailabilitySchedule, resolve_source},
    body_read::{BodyReadError, BodyReadJob, BodyReader},
    driver::{SharedCrypto, traits::BlockStore},
    durable_artifact,
    lanes::record::PreparedLaneWrite,
    records::{Faults, NoFaults},
};
use iroha_allocation::AllocationBudget;
use iroha_fs::OwnerDirectory;
use iroha_sumeragi::{
    availability::{AvailabilitySource, AvailableBody},
    message::{PayloadManifest, Qc, SyncEntry},
    types::Hash32,
};
use parking_lot::{Condvar, Mutex};
#[cfg(test)]
use std::fs;
use std::{
    fs::File,
    io,
    path::{Path, PathBuf},
    sync::{Arc, OnceLock, Weak},
    time::{Duration, Instant},
};

#[path = "store/read.rs"]
pub(in crate::sumeragi) mod read;
#[path = "store/recovery.rs"]
mod recovery;
use read::{LaneBodyRead, RestoreFrame, certified_source, record_error};
pub use recovery::LaneStoreOpen;

const FRAME_SUFFIX: &str = "frame";
const LOCK_NAME: &str = ".custody.lock";
// Disk-corruption/allocation bound, not a consensus parameter.
const MAX_FRAME_FILE_BYTES: usize = 80 * 1024 * 1024;

/// Read-only inspection of one original committed lane frame under independent authority.
/// Uses the same canonical decoder, certificate verification and signed RS16 restoration as
/// store recovery, without acquiring a writer lock, creating files or changing a store tip.
/// Keep this job across local resource refusals to retain its original allocation custody.
pub struct LaneFrameRead {
    budget: AllocationBudget,
    job: RestoreFrame,
}

impl LaneFrameRead {
    /// Select the canonical immutable frame in an independently pinned lane instance.
    pub(super) fn path(root: &Path, instance: Hash32, height: u64) -> PathBuf {
        root.join(hex::encode(instance.0)).join(frame_name(height))
    }

    /// Begin inspecting an independently selected path and native height. The historical
    /// schedule and BLS keys must come from authenticated authority, never the inspected frame.
    ///
    /// # Errors
    /// Initial absence returns `NotFound`; other I/O, a non-regular artifact or an oversized frame.
    pub fn open(
        path: &Path,
        height: u64,
        crypto: SharedCrypto,
        budget: AllocationBudget,
        schedule: Arc<dyn AvailabilitySchedule>,
    ) -> io::Result<Self> {
        let job = RestoreFrame::open(path, height, budget.clone(), schedule, crypto)?;
        Ok(Self { budget, job })
    }

    /// Authenticate the original certificate and restore complete available payload custody.
    /// Moves the exact restored body and certificate owners without a metadata or bulk clone.
    /// A successful job is consumed and cannot be polled again.
    ///
    /// # Errors
    /// Invalid bytes, wrong historical authority, missing artifacts, I/O or original-pool
    /// refusal. `WouldBlock` retains the exact pending read and may be retried.
    pub fn poll(&mut self) -> Result<(AvailableBody, Qc), Attempt<io::Error>> {
        let prepared = self.job.poll(&self.budget)?;
        Ok(prepared.into_parts())
    }
}

struct PendingRead {
    interest: ReadInterest,
    height: u64,
    job: RestoreFrame,
    ready: Option<PreparedLaneWrite>,
}
pub(super) struct PendingBatch {
    interest: ReadInterest,
    pub(super) read: BatchRead,
}

// Each native caller inherits cancellation cleanup if a concurrent lifecycle probe finds its
// mutex busy. This guard is declared before native guards and never performs I/O or waits.
struct CancelledReadCleanup<'a>(&'a FileLaneBlockStore);
impl Drop for CancelledReadCleanup<'_> {
    fn drop(&mut self) {
        if !cfg!(all(test, sumeragi_core_mutation = "HC434")) {
            self.0.release_cancelled_reads();
        }
    }
}

struct StoreState {
    write: Option<PreparedLaneWrite>,
    read: Option<PendingRead>,
}

// Inline custody belongs to this exact incarnation; no map allocation or shared cross-lane
// retry slot is needed. The body header identifies the retained height independently.
pub(super) struct BatchRead {
    pub(super) body: AvailableBody,
    pub(super) qc: Qc,
}

impl BatchRead {
    // Both the exclusive store and read-only replay retain this exact authenticated
    // body/QC while the one canonical payload decoder refuses its original pool.
    pub(super) fn decode_batch(&self) -> Result<Option<LaneBatch>, Attempt<io::Error>> {
        match LaneBatch::from_payload(self.body.payload().as_slice()) {
            Ok(batch) => Ok(Some(batch)),
            // A certified malformed lane payload has no effects; it is not capacity.
            Err(AdmissionAttemptError::Rejected(_)) => Ok(None),
            Err(AdmissionAttemptError::ResourceDeferred(reason)) => Err(Attempt::Deferred(reason)),
            Err(AdmissionAttemptError::Deferred(reason)) => Err(Attempt::Deferred(reason.into())),
        }
    }
}

/// One fully recovered lane incarnation. Share this owner through Arc; second opens fail.
pub struct FileLaneBlockStore {
    // Preserve the configured spelling for diagnostics and fault injection only.
    // Every native operation uses `directory` and the original acquired lock below.
    dir: PathBuf,
    instance: Hash32,
    ownership: File,
    directory: OwnerDirectory,
    crypto: SharedCrypto,
    faults: Arc<dyn Faults>,
    budget: AllocationBudget,
    schedule: Arc<dyn AvailabilitySchedule>,

    state: Mutex<StoreState>,
    // The sole validated durable tip has a short notification lock. Waiting never
    // acquires the read/publication I/O mutex; operations order state before tip.
    tip: Mutex<u64>,
    pub(super) batch_read: Mutex<Option<PendingBatch>>,
    grown: Condvar,
    // The same runtime store serves member and observer publication. Only a weak original
    // Queue is retained; no Store -> State/runner/Queue ownership cycle is introduced.
    global_queue: OnceLock<Weak<crate::queue::Queue>>,
    // Notification-only custody cannot retain this store or form an ownership cycle.
    publication_owner: OnceLock<crate::sumeragi::driver::OriginalPublicationOwner>,
}
impl core::fmt::Debug for FileLaneBlockStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let height = *self.tip.lock();
        f.debug_struct("FileLaneBlockStore")
            .field("dir", &self.dir)
            .field("height", &height)
            .finish_non_exhaustive()
    }
}
fn frame_name(height: u64) -> String {
    format!("{height:020}.{FRAME_SUFFIX}")
}
fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}
fn lock_instance(dir: &OwnerDirectory) -> io::Result<File> {
    let file = dir.open_lock(LOCK_NAME)?;
    file.try_lock().map_err(io::Error::from)?;
    dir.require_same_lock(LOCK_NAME, &file)?;
    Ok(file)
}

// A read job may outlive its store borrow. Retain the same ancestor descriptors and a
// duplicate of the actual acquired lock, never a new writable open or replacement lock.
struct LaneReadCustody {
    directory: OwnerDirectory,
    ownership: File,
}
impl LaneReadCustody {
    fn revalidate(&self) -> io::Result<()> {
        self.directory.require_same_lock(LOCK_NAME, &self.ownership)
    }
}

impl FileLaneBlockStore {
    // Every nested operation retains the same original pool. Its outermost scope
    // outlives both state and batch guards before invoking arbitrary release callbacks.
    fn with_original_refunds<R>(budget: &AllocationBudget, operation: impl FnOnce() -> R) -> R {
        if cfg!(all(test, sumeragi_core_mutation = "HC350")) {
            operation()
        } else {
            budget.with_deferred_refund_notifications(|_| operation())
        }
    }

    /// Bind this store to the actual original node Queue before its lane driver launches.
    /// Recovery/reconciliation may repeat this same-owner binding; neither a foreign pool
    /// nor another Queue can replace it. Historical read-only stores need no notification.
    ///
    /// # Errors
    /// A foreign/unbound/retired original pool or a different original Queue.
    pub(super) fn bind_global_queue(&self, queue: &Arc<crate::queue::Queue>) -> io::Result<()> {
        if !queue.belongs_to_sumeragi_pool(&self.budget)
            && !cfg!(all(test, sumeragi_core_mutation = "HC196"))
        {
            return Err(invalid(
                "lane merge notification belongs to another original State pool",
            ));
        }
        let requested = Arc::downgrade(queue);
        match self.global_queue.set(requested) {
            Ok(()) => Ok(()),
            Err(requested)
                if cfg!(all(test, sumeragi_core_mutation = "HC197"))
                    || self
                        .global_queue
                        .get()
                        .is_some_and(|original| Weak::ptr_eq(original, &requested)) =>
            {
                Ok(())
            }
            Err(_) => Err(invalid(
                "lane merge notification belongs to another original Queue",
            )),
        }
    }

    fn revalidate_custody(&self) -> io::Result<()> {
        self.directory.require_same_lock(LOCK_NAME, &self.ownership)
    }

    fn retain_read_custody(&self) -> io::Result<LaneReadCustody> {
        self.revalidate_custody()?;
        let custody = LaneReadCustody {
            directory: self.directory.retain()?,
            ownership: self.ownership.try_clone()?,
        };
        custody.revalidate()?;
        Ok(custody)
    }

    fn publish_frame(&self, height: u64, bytes: &[u8]) -> io::Result<()> {
        durable_artifact::publish_in(
            &*self.faults,
            &self.directory,
            &self.dir,
            &frame_name(height),
            bytes,
            || self.revalidate_custody(),
        )
    }

    // Called only after the complete durable append path returns and its state lock retires.
    // A final temporary Queue owner may release original residents, so defer its original
    // pool notifications through the upgrade/notify/drop, outside both store and Queue locks.
    fn notify_global_queue(&self) {
        #[cfg(not(all(test, sumeragi_core_mutation = "HC195")))]
        self.budget.with_deferred_refund_notifications(|_| {
            if let Some(queue) = self.global_queue.get().and_then(Weak::upgrade) {
                queue.wake_sumeragi_root(&self.budget);
                drop(queue);
            }
        });
    }

    /// Acquire exclusive ownership and enumerate a canonical contiguous prefix, without reading
    /// or allocating body bytes. Keep the returned owner until recovery completes or is abandoned.
    ///
    /// # Errors
    /// Filesystem, existing owner, foreign schedule, or malformed directory population.
    pub fn begin_open(
        root: &Path,
        instance: &Hash32,
        crypto: SharedCrypto,
        budget: AllocationBudget,
        schedule: Arc<dyn AvailabilitySchedule>,
    ) -> io::Result<LaneStoreOpen> {
        Self::begin_open_with_faults(root, instance, crypto, budget, schedule, Arc::new(NoFaults))
    }
    /// Begin exclusive recovery with deterministic filesystem fault injection.
    ///
    /// # Errors
    /// See `begin_open`.
    pub fn begin_open_with_faults(
        root: &Path,
        instance: &Hash32,
        crypto: SharedCrypto,
        budget: AllocationBudget,
        schedule: Arc<dyn AvailabilitySchedule>,

        faults: Arc<dyn Faults>,
    ) -> io::Result<LaneStoreOpen> {
        if schedule.instance() != *instance {
            return Err(invalid("lane schedule belongs to another instance").into());
        }
        let dir = root.join(hex::encode(instance.0));
        durable_artifact::establish_dir(&*faults, &dir)?;
        let directory = OwnerDirectory::open(&dir)?;
        let ownership = lock_instance(&directory)?;
        let mut heights = Vec::new();
        directory.visit_entries(|name| {
            directory.require_same_lock(LOCK_NAME, &ownership)?;
            let name = name
                .to_str()
                .ok_or_else(|| invalid("non-UTF-8 lane artifact name"))?;
            if name == LOCK_NAME {
                return Ok(());
            }
            // Open each exact original leaf, rejecting links, special files and shared custody.
            let original = directory
                .open_regular_optional(name)?
                .ok_or_else(|| invalid("lane artifact disappeared during enumeration"))?;
            directory.require_same_regular_file(name, &original)?;
            drop(original);
            #[expect(
                clippy::case_sensitive_file_extension_comparisons,
                reason = "lane artifacts have canonical lowercase names; uppercase lookalikes must be rejected"
            )]
            match name.strip_suffix(&format!(".{FRAME_SUFFIX}")) {
                Some(number) => {
                    let height = number
                        .parse::<u64>()
                        .map_err(|_| invalid(format!("unexpected lane frame {name}")))?;
                    if name != frame_name(height) {
                        return Err(invalid(format!("non-canonical lane frame name {name}")).into());
                    }
                    heights.push(height);
                }
                None if name.ends_with(".tmp") => {
                    directory.remove_private(name)?;
                }
                None => return Err(invalid(format!("unexpected lane file {name}")).into()),
            }
            Ok(())
        })?;
        heights.sort_unstable();
        for (i, height) in heights.iter().enumerate() {
            if *height != i as u64 + 1 {
                return Err(invalid("lane heights are not contiguous from one").into());
            }
        }
        directory.require_same_lock(LOCK_NAME, &ownership)?;
        let tip = heights.last().copied().unwrap_or(0);
        let store = Self {
            dir,
            instance: *instance,
            ownership,
            directory,
            crypto,
            faults,
            budget,
            schedule,
            state: Mutex::new(StoreState {
                write: None,
                read: None,
            }),
            tip: Mutex::new(0),
            batch_read: Mutex::new(None),
            grown: Condvar::new(),
            global_queue: OnceLock::new(),
            publication_owner: OnceLock::new(),
        };
        Ok(LaneStoreOpen::new(store, tip))
    }
    /// Take a fully authenticated committed body and its original certificate for lane merge.
    /// The store retains every read/restoration allocation across errors and resource refusals.
    ///
    /// # Errors
    /// Invalid stored artifacts, unavailable historical authority, I/O or original-pool refusal.
    pub(super) fn committed_body(
        &self,
        height: u64,
    ) -> Result<Option<(AvailableBody, Qc)>, Attempt<io::Error>> {
        let _cancelled_reads = CancelledReadCleanup(self);
        Self::with_original_refunds(&self.budget, || {
            self.take_prepared(height, &ReadInterest::Historical)
                .map(|prepared| prepared.map(|(prepared, _)| prepared.into_parts()))
        })
    }

    fn take_prepared(
        &self,
        height: u64,
        requested: &ReadInterest,
    ) -> Result<Option<(PreparedLaneWrite, ReadInterest)>, Attempt<io::Error>> {
        self.revalidate_custody()?;
        let mut state = self.state.lock();
        if height == 0 || height > *self.tip.lock() {
            return Ok(None);
        }
        self.read_prepared(&mut state, height, requested)?;
        let read = state.read.take().expect("completed original lane read");
        Ok(Some((
            read.ready.expect("restored body and QC"),
            read.interest,
        )))
    }

    /// Decode an actual historical merge without withdrawing its retained source on refusal.
    pub(super) fn committed_batch(
        &self,
        height: u64,
    ) -> Result<Option<CommittedLaneBlock>, Attempt<io::Error>> {
        self.batch_with_interest(height, ReadInterest::Historical)
    }

    /// Select local proposal work under its original request and exact operation pool.
    pub(super) fn proposal_batch(
        &self,
        height: u64,
        request: &ProposalReadScope,
    ) -> Result<Option<CommittedLaneBlock>, Attempt<io::Error>> {
        let requested = ReadInterest::proposal(request, &self.budget)?;
        self.batch_with_interest(height, requested)
    }

    fn batch_with_interest(
        &self,
        height: u64,
        requested: ReadInterest,
    ) -> Result<Option<CommittedLaneBlock>, Attempt<io::Error>> {
        let _cancelled_reads = CancelledReadCleanup(self);
        Self::with_original_refunds(&self.budget, || {
            self.revalidate_custody()?;
            let mut slot = self.batch_read.lock();
            loop {
                if slot.is_none() {
                    let Some((prepared, interest)) = self.take_prepared(height, &requested)? else {
                        return Ok(None);
                    };
                    let (body, qc) = prepared.into_parts();
                    *slot = Some(PendingBatch {
                        interest,
                        read: BatchRead { body, qc },
                    });
                }
                let pending = slot.as_mut().expect("retained authenticated batch read");
                pending
                    .interest
                    .join(&requested, pending.read.body.header().height == height)?;
                let batch = pending.read.decode_batch()?;
                self.revalidate_custody()?;
                let pending = slot.take().expect("completed original batch decode");
                if pending.read.body.header().height == height {
                    return Ok(Some(CommittedLaneBlock {
                        block_hash: pending.read.qc.block_hash,
                        result: pending.read.qc.result,
                        batch,
                    }));
                }
            }
        })
    }

    /// Release only explicitly cancelled proposal reads. Select under separate nonblocking
    /// guards, then destroy original jobs, authority and paid bodies after every guard is gone.
    pub(super) fn release_cancelled_reads(&self) {
        Self::with_original_refunds(&self.budget, || {
            let read = {
                let Some(mut state) = self.state.try_lock() else {
                    return;
                };
                if state
                    .read
                    .as_ref()
                    .is_some_and(|read| read.interest.cancelled())
                {
                    state.read.take()
                } else {
                    None
                }
            };
            let batch = {
                self.batch_read.try_lock().and_then(|mut slot| {
                    if slot
                        .as_ref()
                        .is_some_and(|pending| pending.interest.cancelled())
                    {
                        slot.take()
                    } else {
                        None
                    }
                })
            };
            drop(read);
            drop(batch);
        });
    }

    /// Observe the durable tip only after the original retained read authenticates.
    /// The completed artifact stays in the same pending slot for its normal consumer;
    /// runtime BlockStore::height remains the infallible already-committed height.
    ///
    /// # Errors
    /// Propagates the original incomplete attempt or authentication/storage rejection
    /// without taking, replacing or abandoning its retained restoration owner.
    pub(super) fn authenticated_height(&self) -> Result<u64, Attempt<io::Error>> {
        let _cancelled_reads = CancelledReadCleanup(self);
        Self::with_original_refunds(&self.budget, || {
            self.revalidate_custody()?;
            let mut state = self.state.lock();
            if let Some(read) = state.read.as_mut()
                && read.ready.is_none()
            {
                read.ready = Some(read.job.poll(&self.budget)?);
            }
            self.revalidate_custody()?;
            Ok(*self.tip.lock())
        })
    }

    // Only append installs state.write, after independent certified_source verification
    // and exact body.source equality. Recovery never installs it. This private helper
    // completes that immutable admitted owner; it cannot accept fresh or disk-supplied input.
    fn publish_pending_write(&self, state: &mut StoreState) -> Result<(), Attempt<io::Error>> {
        let pending = state.write.as_mut().expect("original publication retained");
        let height = pending.body().header().height;
        pending
            .check_context(pending.body().source(), &*self.crypto)
            .map_err(record_error)?;
        let bytes = pending.prepare(&self.budget).map_err(record_error)?;
        if bytes.len() > MAX_FRAME_FILE_BYTES {
            return Err(invalid("lane frame exceeds disk custody bound").into());
        }
        self.publish_frame(height, bytes)?;
        state.write = None;
        {
            let mut tip = self.tip.lock();
            *tip = height;
            self.grown.notify_all();
        }
        Ok(())
    }

    /// Notify the original admitted joining owner after its driver retires.
    /// The registry never takes the I/O mutex or invokes a native operation.
    pub(super) fn notify_retired_publication(&self) {
        #[cfg(all(test, sumeragi_core_mutation = "HC423"))]
        Self::with_original_refunds(&self.budget, || {
            let mut state = self.state.lock();
            let _ = self.publish_pending_write(&mut state);
        });
        if let Some(owner) = self.publication_owner.get() {
            owner.retire();
        }
    }

    // Called only by the exact bound original job after its physical worker joins
    // and every admitted append permit. A refusal retains the exact prepared write.
    fn resume_retired_publication(
        &self,
        owner: &crate::sumeragi::driver::OriginalPublicationOwner,
    ) -> Result<(), Attempt<io::Error>> {
        if !self
            .publication_owner
            .get()
            .is_some_and(|original| original.same_owner(owner))
        {
            return Err(invalid("retired publication requires its exact original owner").into());
        }
        owner.require_resume()?;
        let _cancelled_reads = CancelledReadCleanup(self);
        Self::with_original_refunds(&self.budget, || {
            let Some(mut state) = self.state.try_lock() else {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "original retired lane publication is busy",
                )
                .into());
            };
            if state.write.is_none() {
                return Ok(());
            }
            self.revalidate_custody()?;
            self.publish_pending_write(&mut state)?;
            drop(state);
            self.notify_global_queue();
            Ok(())
        })
    }

    /// Retirement preserves the original unfinished read, publication and batch owners.
    /// Each mutex is probed separately without waiting or reversing the batch-to-state lock
    /// order. A busy owner conservatively remains retained for later reconciliation.
    pub(super) fn retains_pending_work(&self) -> bool {
        if cfg!(all(test, sumeragi_core_mutation = "HC123")) {
            return self.batch_read.try_lock().is_none_or(|slot| slot.is_some());
        }
        let Some(state) = self.state.try_lock() else {
            return true;
        };
        let pending_state = state.read.is_some() || state.write.is_some();
        drop(state);
        pending_state || self.batch_read.try_lock().is_none_or(|slot| slot.is_some())
    }
    #[cfg(test)]
    pub(in crate::sumeragi) fn has_pending_work_for_test(&self) -> bool {
        self.retains_pending_work()
    }

    /// Wait until the durable validated tip reaches `height`, bounded by `timeout`.
    #[must_use]
    pub fn wait_for(&self, height: u64, timeout: Duration) -> bool {
        #[cfg(all(test, sumeragi_core_mutation = "HC389"))]
        let _original_io_state = self.state.lock();
        let deadline = Instant::now() + timeout;
        let mut tip = self.tip.lock();
        while *tip < height {
            if self.grown.wait_until(&mut tip, deadline).timed_out() {
                return *tip >= height;
            }
        }
        true
    }
    fn restore(&self, height: u64) -> io::Result<RestoreFrame> {
        RestoreFrame::open_in(
            self.retain_read_custody()?,
            &frame_name(height),
            height,
            self.budget.clone(),
            Arc::clone(&self.schedule),
            Arc::clone(&self.crypto),
        )
    }
    fn read_prepared<'a>(
        &self,
        state: &'a mut StoreState,
        height: u64,
        requested: &ReadInterest,
    ) -> Result<&'a mut PreparedLaneWrite, Attempt<io::Error>> {
        self.revalidate_custody()?;
        if let Some(read) = &mut state.read {
            read.interest.join(requested, read.height == height)?;
        }
        if state
            .read
            .as_ref()
            .is_some_and(|read| read.height != height)
        {
            // A worker may cancel its request while this store still owns a refused read.
            // Finish that exact source before switching heights; neither its partial backing
            // nor an authentication failure may be discarded by a new request.
            let original = state.read.as_mut().expect("retained original lane read");
            if original.ready.is_none() {
                original.ready = Some(original.job.poll(&self.budget)?);
            }
            self.revalidate_custody()?;
            state.read = None;
        }
        if state.read.is_none() {
            state.read = Some(PendingRead {
                interest: requested.clone(),
                height,
                job: self.restore(height)?,
                ready: None,
            });
        }
        let read = state.read.as_mut().expect("retained original read");
        if read.ready.is_none() {
            read.ready = Some(read.job.poll(&self.budget)?);
        }
        self.revalidate_custody()?;
        Ok(read.ready.as_mut().expect("restored original body and QC"))
    }
}

impl crate::sumeragi::driver::traits::RetiredPublication for FileLaneBlockStore {
    fn instance(&self) -> Hash32 {
        self.instance
    }
    fn belongs_to(&self, budget: &AllocationBudget) -> bool {
        self.budget.same_pool(budget)
    }
    fn bind_owner(
        &self,
        owner: crate::sumeragi::driver::OriginalPublicationOwner,
    ) -> io::Result<()> {
        owner.require_binding_thread()?;
        if !owner.belongs_to(self.instance, &self.budget) {
            return Err(invalid(
                "publication owner belongs to another original instance or pool",
            ));
        }
        match self.publication_owner.set(owner) {
            Ok(()) => Ok(()),
            Err(_) if cfg!(all(test, sumeragi_core_mutation = "HC424")) => Ok(()),
            Err(_) => Err(invalid("original publication owner is already bound")),
        }
    }
    fn resume(
        &self,
        owner: &crate::sumeragi::driver::OriginalPublicationOwner,
    ) -> Result<(), Attempt<io::Error>> {
        self.resume_retired_publication(owner)
    }
}

impl BlockStore for FileLaneBlockStore {
    fn retired_publication(
        self: std::sync::Arc<Self>,
    ) -> Option<std::sync::Arc<dyn crate::sumeragi::driver::traits::RetiredPublication>> {
        #[cfg(all(test, sumeragi_core_mutation = "HC414"))]
        {
            None
        }
        #[cfg(not(all(test, sumeragi_core_mutation = "HC414")))]
        {
            Some(self)
        }
    }
    fn committed_body(
        &self,
        height: u64,
    ) -> Result<Option<(AvailableBody, Qc)>, Attempt<io::Error>> {
        Self::committed_body(self, height)
    }
    fn height(&self) -> u64 {
        *self.tip.lock()
    }
    fn entry(&self, height: u64) -> Result<Option<SyncEntry>, Attempt<io::Error>> {
        let _cancelled_reads = CancelledReadCleanup(self);
        Self::with_original_refunds(&self.budget, || {
            self.revalidate_custody()?;
            let mut state = self.state.lock();
            if height == 0 || height > *self.tip.lock() {
                return Ok(None);
            }
            let prepared = self.read_prepared(&mut state, height, &ReadInterest::Historical)?;
            let entry = SyncEntry {
                manifest: PayloadManifest {
                    header: prepared.body().header().clone(),
                    availability: prepared.body().availability().clone(),
                },
                commit_qc: prepared.commit_qc().clone(),
            };
            state.read = None;
            Ok(Some(entry))
        })
    }
    fn availability_source(
        &self,
        height: u64,
        block_hash: Hash32,
    ) -> Result<Option<AvailabilitySource>, Attempt<io::Error>> {
        resolve_source(&*self.schedule, self.instance, height, block_hash)
    }
    fn append(&self, body: &AvailableBody, qc: &Qc) -> Result<(), Attempt<io::Error>> {
        let _cancelled_reads = CancelledReadCleanup(self);
        // Declare before the refund scope and every native/store guard. A refused
        // admission cannot resolve authority, mutate State or install a write.
        let _original_append = if cfg!(all(test, sumeragi_core_mutation = "HC422")) {
            None
        } else {
            Some(
                self.publication_owner
                    .get()
                    .ok_or_else(|| invalid("lane append has no original publication owner"))?
                    .admit_append()?,
            )
        };
        Self::with_original_refunds(&self.budget, || {
            if !body.admitted_to(&self.budget) {
                return Err(invalid("lane append original pool mismatch").into());
            }
            let height = body.header().height;
            let source =
                certified_source(&*self.schedule, &*self.crypto, height, body.header(), qc)?;
            if body.source() != &source {
                return Err(
                    invalid("lane body was authenticated under another historical source").into(),
                );
            }
            self.revalidate_custody()?;
            let mut state = self.state.lock();
            let tip = *self.tip.lock();
            if height <= tip {
                let stored = self.read_prepared(&mut state, height, &ReadInterest::Historical)?;
                if stored.body() != body || stored.commit_qc().result != qc.result {
                    // This healthy stored read is complete; reject the incoming decision without
                    // pinning unrelated future reads behind it. Pending publication is untouched.
                    state.read = None;
                    return Err(invalid("another lane decision is already durable").into());
                }
                let bytes = stored.prepare(&self.budget).map_err(record_error)?;
                self.publish_frame(height, bytes)?;
                state.read = None;
                drop(state);
                self.notify_global_queue();
                return Ok(());
            }
            if height != tip.saturating_add(1) {
                return Err(invalid("lane append is not the next durable height").into());
            }
            if let Some(original) = &state.write {
                if original.body() != body || original.commit_qc() != qc {
                    return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "different prepared artifact cannot replace original pending lane publication",
                )
                .into());
                }
            } else {
                state.write = Some(PreparedLaneWrite::new(body.clone(), qc.clone()));
            }
            self.publish_pending_write(&mut state)?;
            drop(state);
            self.notify_global_queue();
            Ok(())
        })
    }
}
impl BodyReader for FileLaneBlockStore {
    fn begin_read(
        &self,
        source: AvailabilitySource,
    ) -> Result<Box<dyn BodyReadJob>, BodyReadError> {
        if source.instance() != self.instance {
            return Err(BodyReadError::Io(invalid(
                "lane read source belongs to another instance",
            )));
        }
        Ok(Box::new(
            LaneBodyRead::open_in(
                source.clone(),
                self.retain_read_custody().map_err(BodyReadError::Io)?,
                &frame_name(source.height()),
                self.budget.clone(),
                Arc::clone(&self.crypto),
            )
            .map_err(BodyReadError::Io)?,
        ))
    }
}

#[cfg(test)]
#[path = "store/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "store/publication_tests.rs"]
mod publication_tests;

#[cfg(test)]
#[path = "store/retirement_probe_tests.rs"]
mod retirement_probe_tests;

#[cfg(test)]
#[path = "store/refund_tests.rs"]
mod refund_tests;

#[cfg(test)]
#[path = "store/owner_tests.rs"]
mod owner_tests;
