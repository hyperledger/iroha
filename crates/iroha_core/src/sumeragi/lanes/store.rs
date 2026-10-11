//! Original-funded durable lane frames with retained startup, read and publication owners.
//!
//! One exclusive instance owner validates its entire recovered prefix before exposing a tip.
//! Complete signed availability and the original CommitQC share one canonical atomic frame.

use super::{AdmissionAttemptError, LaneBatch, merge::CommittedLaneBlock};
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
use iroha_sumeragi::{
    availability::{AvailabilitySource, AvailableBody},
    message::{PayloadManifest, Qc, SyncEntry},
    types::Hash32,
};
use parking_lot::{Condvar, Mutex};
use std::{
    fs::{self, File, OpenOptions},
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
    /// Begin inspecting an independently selected path and native height. The historical
    /// schedule and BLS keys must come from authenticated authority, never the inspected frame.
    ///
    /// # Errors
    /// I/O, a non-regular artifact or an oversized frame.
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
    height: u64,
    job: RestoreFrame,
    ready: Option<PreparedLaneWrite>,
}
struct StoreState {
    tip: u64,
    write: Option<PreparedLaneWrite>,
    read: Option<PendingRead>,
}

// Inline custody belongs to this exact incarnation; no map allocation or shared cross-lane
// retry slot is needed. The body header identifies the retained height independently.
pub(super) struct BatchRead {
    pub(super) body: AvailableBody,
    pub(super) qc: Qc,
}

/// One fully recovered lane incarnation. Share this owner through Arc; second opens fail.
pub struct FileLaneBlockStore {
    dir: PathBuf,
    instance: Hash32,
    _ownership: File,
    crypto: SharedCrypto,
    faults: Arc<dyn Faults>,
    budget: AllocationBudget,
    schedule: Arc<dyn AvailabilitySchedule>,

    state: Mutex<StoreState>,
    pub(super) batch_read: Mutex<Option<BatchRead>>,
    grown: Condvar,
    // The same runtime store serves member and observer publication. Only a weak original
    // Queue is retained; no Store -> State/runner/Queue ownership cycle is introduced.
    global_queue: OnceLock<Weak<crate::queue::Queue>>,
}
impl core::fmt::Debug for FileLaneBlockStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FileLaneBlockStore")
            .field("dir", &self.dir)
            .field("height", &self.state.lock().tip)
            .finish_non_exhaustive()
    }
}
fn frame_name(height: u64) -> String {
    format!("{height:020}.{FRAME_SUFFIX}")
}
fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}
fn lock_instance(dir: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        let flags = rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK;
        options
            .mode(0o600)
            .custom_flags(i32::from_ne_bytes(flags.bits().to_ne_bytes()));
    }
    let file = options.open(dir.join(LOCK_NAME))?;
    if !file.metadata()?.is_file() {
        return Err(invalid("lane ownership lock is not a regular file").into());
    }
    file.try_lock().map_err(io::Error::from)?;
    Ok(file)
}

impl FileLaneBlockStore {
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
        let ownership = lock_instance(&dir)?;
        let mut heights = Vec::new();
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name == LOCK_NAME {
                continue;
            }
            if !entry.file_type()?.is_file() {
                return Err(invalid(format!("non-regular lane artifact {name}")).into());
            }
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
                None if name.ends_with(".tmp") => fs::remove_file(entry.path())?,
                None => return Err(invalid(format!("unexpected lane file {name}")).into()),
            }
        }
        heights.sort_unstable();
        for (i, height) in heights.iter().enumerate() {
            if *height != i as u64 + 1 {
                return Err(invalid("lane heights are not contiguous from one").into());
            }
        }
        let tip = heights.last().copied().unwrap_or(0);
        let store = Self {
            dir,
            instance: *instance,
            _ownership: ownership,
            crypto,
            faults,
            budget,
            schedule,
            state: Mutex::new(StoreState {
                tip: 0,
                write: None,
                read: None,
            }),
            batch_read: Mutex::new(None),
            grown: Condvar::new(),
            global_queue: OnceLock::new(),
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
        let mut state = self.state.lock();
        if height == 0 || height > state.tip {
            return Ok(None);
        }
        self.read_prepared(&mut state, height)?;
        let prepared = state
            .read
            .take()
            .and_then(|read| read.ready)
            .expect("completed original lane read");
        Ok(Some(prepared.into_parts()))
    }

    /// Decode a merge batch while retaining the exact authenticated source on local refusal.
    /// Only this incarnation's earlier read must finish before switching requested heights.
    /// Other native readers cannot consume this separate retained batch owner.
    ///
    /// # Errors
    /// Invalid stored artifacts, unavailable historical authority, I/O or original-pool refusal.
    pub(super) fn committed_batch(
        &self,
        height: u64,
    ) -> Result<Option<CommittedLaneBlock>, Attempt<io::Error>> {
        let mut slot = self.batch_read.lock();
        loop {
            if slot.is_none() {
                let Some((body, qc)) = self.committed_body(height)? else {
                    return Ok(None);
                };
                *slot = Some(BatchRead { body, qc });
            }
            let read = slot.as_ref().expect("retained authenticated batch read");
            let batch = match LaneBatch::from_payload(read.body.payload().as_slice()) {
                Ok(batch) => Some(batch),
                // An authenticated malformed payload is distinct from local resource pressure.
                Err(AdmissionAttemptError::Rejected(_)) => None,
                Err(AdmissionAttemptError::AnchorDeferred(reason)) => {
                    return Err(Attempt::Deferred(reason));
                }
                Err(AdmissionAttemptError::Deferred(reason)) => {
                    return Err(crate::execution_attempt::norito_decode_attempt_error(
                        reason.into(),
                        |error| io::Error::new(io::ErrorKind::InvalidData, error),
                    ));
                }
            };
            let read = slot.take().expect("completed original batch decode");
            if read.body.header().height == height {
                return Ok(Some(CommittedLaneBlock {
                    block_hash: read.qc.block_hash,
                    result: read.qc.result,
                    batch,
                }));
            }
        }
    }

    /// Observe the durable tip only after the original retained read authenticates.
    /// The completed artifact stays in the same pending slot for its normal consumer;
    /// runtime BlockStore::height remains the infallible already-committed height.
    ///
    /// # Errors
    /// Propagates the original incomplete attempt or authentication/storage rejection
    /// without taking, replacing or abandoning its retained restoration owner.
    pub(super) fn authenticated_height(&self) -> Result<u64, Attempt<io::Error>> {
        let mut state = self.state.lock();
        if let Some(read) = state.read.as_mut()
            && read.ready.is_none()
        {
            read.ready = Some(read.job.poll(&self.budget)?);
        }
        Ok(state.tip)
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
    /// Wait until the durable validated tip reaches `height`, bounded by `timeout`.
    #[must_use]
    pub fn wait_for(&self, height: u64, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let mut state = self.state.lock();
        while state.tip < height {
            if self.grown.wait_until(&mut state, deadline).timed_out() {
                return state.tip >= height;
            }
        }
        true
    }
    fn restore(&self, height: u64) -> io::Result<RestoreFrame> {
        RestoreFrame::open(
            &self.dir.join(frame_name(height)),
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
    ) -> Result<&'a mut PreparedLaneWrite, Attempt<io::Error>> {
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
            state.read = None;
        }
        if state.read.is_none() {
            state.read = Some(PendingRead {
                height,
                job: self.restore(height)?,
                ready: None,
            });
        }
        let read = state.read.as_mut().expect("retained original read");
        if read.ready.is_none() {
            read.ready = Some(read.job.poll(&self.budget)?);
        }
        Ok(read.ready.as_mut().expect("restored original body and QC"))
    }
}

impl BlockStore for FileLaneBlockStore {
    fn committed_body(
        &self,
        height: u64,
    ) -> Result<Option<(AvailableBody, Qc)>, Attempt<io::Error>> {
        Self::committed_body(self, height)
    }
    fn height(&self) -> u64 {
        self.state.lock().tip
    }
    fn entry(&self, height: u64) -> Result<Option<SyncEntry>, Attempt<io::Error>> {
        let mut state = self.state.lock();
        if height == 0 || height > state.tip {
            return Ok(None);
        }
        let prepared = self.read_prepared(&mut state, height)?;
        let entry = SyncEntry {
            manifest: PayloadManifest {
                header: prepared.body().header().clone(),
                availability: prepared.body().availability().clone(),
            },
            commit_qc: prepared.commit_qc().clone(),
        };
        state.read = None;
        Ok(Some(entry))
    }
    fn availability_source(
        &self,
        height: u64,
        block_hash: Hash32,
    ) -> Result<Option<AvailabilitySource>, Attempt<io::Error>> {
        resolve_source(&*self.schedule, self.instance, height, block_hash)
    }
    fn append(&self, body: &AvailableBody, qc: &Qc) -> Result<(), Attempt<io::Error>> {
        if !body.admitted_to(&self.budget) {
            return Err(invalid("lane append original pool mismatch").into());
        }
        let height = body.header().height;
        let source = certified_source(&*self.schedule, &*self.crypto, height, body.header(), qc)?;
        if body.source() != &source {
            return Err(
                invalid("lane body was authenticated under another historical source").into(),
            );
        }
        let mut state = self.state.lock();
        if height <= state.tip {
            let stored = self.read_prepared(&mut state, height)?;
            if stored.body() != body || stored.commit_qc().result != qc.result {
                // This healthy stored read is complete; reject the incoming decision without
                // pinning unrelated future reads behind it. Pending publication is untouched.
                state.read = None;
                return Err(invalid("another lane decision is already durable").into());
            }
            let bytes = stored.prepare(&self.budget).map_err(record_error)?;
            durable_artifact::publish(&*self.faults, &self.dir, &frame_name(height), bytes)?;
            state.read = None;
            drop(state);
            self.notify_global_queue();
            return Ok(());
        }
        if height != state.tip.saturating_add(1) {
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
        let pending = state.write.as_mut().expect("original publication retained");
        pending
            .check_context(&source, &*self.crypto)
            .map_err(record_error)?;
        let bytes = pending.prepare(&self.budget).map_err(record_error)?;
        if bytes.len() > MAX_FRAME_FILE_BYTES {
            return Err(invalid("lane frame exceeds disk custody bound").into());
        }
        durable_artifact::publish(&*self.faults, &self.dir, &frame_name(height), bytes)?;
        state.write = None;
        state.tip = height;
        self.grown.notify_all();
        drop(state);
        self.notify_global_queue();
        Ok(())
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
            LaneBodyRead::open(
                source.clone(),
                &self.dir.join(frame_name(source.height())),
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
