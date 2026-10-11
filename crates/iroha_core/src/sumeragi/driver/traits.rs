//! Backend traits of the Sumeragi driver (`specs/sumeragi.md` §12.2, §13.5): the transport,
//! the safety-record store with its store id and installation log, the body store, the block
//! store, the clock, the application's executor and an observer of reports.
//!
//! The node implements them over P2P, files, Kura and State; the tests and the §13.5
//! conformance runs use in-memory fakes. Every method either returns at once or blocks only the
//! driver thread that owns the call (persistence, execution, serving), never the event loop.

use crate::execution_attempt::ExecutionAttemptError as Attempt;
use std::{io, sync::Arc, time::Instant};

use iroha_sumeragi::{
    api::{ExecOutcome, HaltReason, LocalFault},
    availability::{AvailabilitySource, AvailableBody, PayloadBytes},
    message::{Evidence, Qc, SyncEntry, TrafficClass},
    safety::RecordState,
    types::{AppliedConfig, Hash32, Millis, PublicKey},
};

use super::{FrameLimitExceeded, Worker};
use crate::sumeragi::durable_artifact::BodyReader;

/// An encoded wire message for the transport: the exact `WireMessage::encode()` bytes (encoded
/// once and shared by every recipient), the instance they belong to and their O8 class.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    /// Instance id of the message (routing).
    pub instance: Hash32,
    /// Traffic class (§12.3 O8).
    pub class: TrafficClass,
    /// The canonical frame.
    pub bytes: Arc<[u8]>,
}

/// Admission of one exact frame occurrence to its recipient's transport queue.
#[must_use = "retain backpressured delivery or explicitly cancel a protocol-retried message"]
pub enum SendOutcome {
    /// The transport owns the frame; this is not a remote-delivery acknowledgement.
    Admitted,
    /// The exact frame and its queue position remain owned by this retry handle.
    Backpressured(Box<dyn PendingSend>),
    /// The transport has closed; retrying cannot succeed.
    Closed,
    /// The transport permanently rejected this frame or recipient.
    Rejected,
}

/// An original transport occurrence retained through temporary admission pressure.
pub trait PendingSend: Send {
    /// Retry without blocking or replacing the original message or admission ticket.
    fn retry(self: Box<Self>) -> SendOutcome;
}

/// The authenticated transport (§12.2): posts a frame to one peer in its traffic class.
pub trait Net: Send + Sync {
    /// Attempt admission without blocking. Streaming callers retain a backpressured
    /// occurrence until admission succeeds; cancelling its owner releases its queue position.
    fn send(&self, to: &PublicKey, frame: &Frame) -> SendOutcome;
}

/// One entry of the installation log (§7.4 record provenance), written with a fresh store id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LogEntry {
    /// A key installed on the node: generated here and never exported, or imported.
    Key {
        /// The key.
        key: PublicKey,
        /// Generated on this node.
        generated: bool,
        /// Store id drawn for this entry.
        store_id: u128,
    },
    /// Instance `instance` was started with `key` on this node.
    Instance {
        /// Instance id.
        instance: Hash32,
        /// The key.
        key: PublicKey,
        /// Store id drawn for this entry.
        store_id: u128,
    },
}

impl LogEntry {
    /// The store id this entry was written with.
    pub fn store_id(&self) -> u128 {
        match self {
            Self::Key { store_id, .. } | Self::Instance { store_id, .. } => *store_id,
        }
    }

    /// The key of this entry.
    pub fn key(&self) -> &PublicKey {
        match self {
            Self::Key { key, .. } | Self::Instance { key, .. } => key,
        }
    }
}

/// Durable safety records, one per `(instance, key)`, the store-id file next to them, and the
/// installation log kept elsewhere (§7.4). Record files are never backed up or restored.
pub trait RecordStore: Send + Sync {
    /// What is on disk for `(instance, key)`.
    ///
    /// # Errors
    /// A read failure (the driver does not start).
    fn load(&self, instance: &Hash32, key: &PublicKey) -> io::Result<RecordState>;
    /// Atomically and durably replace the record of `(instance, key)` (temp file, fsync,
    /// rename, directory fsync).
    ///
    /// # Errors
    /// A write failure; nothing was replaced (the driver retries, never skips).
    fn write(&self, instance: &Hash32, key: &PublicKey, bytes: &[u8]) -> io::Result<()>;
    /// The store id next to the record files (`None`: no id file).
    ///
    /// # Errors
    /// A read failure.
    fn store_id(&self) -> io::Result<Option<u128>>;
    /// Durably replace the store-id file.
    ///
    /// # Errors
    /// A write failure.
    fn set_store_id(&self, id: u128) -> io::Result<()>;
    /// The installation log, oldest entry first.
    ///
    /// # Errors
    /// A read failure.
    fn log(&self) -> io::Result<Vec<LogEntry>>;
    /// Durably append an entry to the installation log.
    ///
    /// # Errors
    /// A write failure.
    fn append_log(&self, entry: &LogEntry) -> io::Result<()>;
}

/// Durable store of block bodies the core accepted and that are not applied yet (§7.4 body
/// durability), keyed by `(height, block_hash)`.
pub trait BodyStore: BodyReader {
    /// Durably store `block` (hash `block_hash`).
    ///
    /// # Errors
    /// A write failure (the driver retries, never skips).
    fn put(&self, block_hash: &Hash32, block: &AvailableBody) -> io::Result<()>;
    /// Drop every body at or below `height` (applied heights live in the block store).
    ///
    /// # Errors
    /// A write failure (retried like a store).
    fn prune_through(&self, height: u64) -> io::Result<()>;
    /// Whether this store has received local authority to retire this applied height.
    /// An in-flight read that loses its path may then retry its exact source in the
    /// committed store. This is not proof that any replacement body is available.
    fn retirement_authorized(&self, _height: u64) -> bool {
        false
    }
}

/// The committed chain (Kura in the node): one block and its `CommitQC` per height above
/// genesis, written durably and in height order.
pub trait BlockStore: BodyReader {
    /// Highest stored height (the genesis height when nothing is stored above it).
    fn height(&self) -> u64;
    /// Take the fully authenticated body and certificate at this committed height.
    /// The implementation retains the original read/restoration owners on refusal.
    /// The returned body's independent source identifies the canonical block; callers
    /// must distinguish an obsolete requested hash from corrupt stored bytes.
    ///
    /// # Errors
    /// I/O, corruption, missing authority and resource refusal are never absence.
    fn committed_body(
        &self,
        height: u64,
    ) -> Result<Option<(AvailableBody, Qc)>, Attempt<io::Error>>;
    /// The committed block and `CommitQC` of `height`, if stored.
    ///
    /// # Errors
    /// I/O, corruption and resource refusal remain errors, never missing entries.
    fn entry(&self, height: u64) -> Result<Option<SyncEntry>, Attempt<io::Error>>;
    /// Resolve the exact authenticated historical schedule independently of stored bytes.
    ///
    /// # Errors
    /// A corrupt or unavailable authority owner cannot authorize serving.
    fn availability_source(
        &self,
        height: u64,
        block_hash: Hash32,
    ) -> Result<Option<AvailabilitySource>, Attempt<io::Error>>;
    /// Durably append the next height.
    ///
    /// # Errors
    /// A write failure; nothing was appended (the driver retries, never skips).
    fn append(&self, block: &AvailableBody, commit_qc: &Qc) -> Result<(), Attempt<io::Error>>;
}

/// A monotonic local clock in milliseconds (§1.5: no synchronised time is assumed).
pub trait Clock: Send + Sync {
    /// Local time now.
    fn now(&self) -> Millis;
}

/// The process clock: milliseconds since construction.
#[derive(Clone, Copy, Debug)]
pub struct SystemClock {
    origin: Instant,
}

impl SystemClock {
    /// A clock that reads 0 now.
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn now(&self) -> Millis {
        Millis::try_from(self.origin.elapsed().as_millis()).unwrap_or(Millis::MAX)
    }
}

/// Original local resource owner retained with an unfinished publication.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PublicationDeferral {
    /// The exact prepaid shared-control construction failed without a release-bearing owner.
    #[error(transparent)]
    SharedControl(iroha_allocation::PrepaidSharedError),
    /// Exact original State reader or its enclosing publishing writer must release.
    #[error("original State view reader is busy")]
    StateViewBusy(iroha_allocation::release::ReleaseWait),
    /// Exact allocation or decoder refusal from the original execution pool.
    #[error(transparent)]
    Execution(#[from] crate::execution_attempt::ExecutionDeferred),
    /// Exact World storage or execution-root decoder refusal before validation effects.
    #[error(transparent)]
    StateStorage(crate::state::StateStorageAdmissionError),
    /// Exact original evidence preparation demand or decoder scope.
    #[error(transparent)]
    EvidencePreparation(crate::state::EvidencePreparationError),
    /// Exact original hash-history acquisition or changed-predecessor observation.
    #[error(transparent)]
    BlockHashAdmission(crate::state::BlockHashAdmissionError),
    /// Exact original membership acquisition, capacity or changed-predecessor observation.
    #[error(transparent)]
    MembershipAdmission(crate::state::MembershipAdmissionError),
    /// Original block hash publication writer must release.
    #[error("original block hash publication is busy")]
    BlockHashesBusy(iroha_allocation::release::ReleaseWait),
    /// Original World, runtime or history publication participant must release.
    #[error("original State publication participant is busy")]
    PublicationBusy(iroha_allocation::release::ReleaseWait),
    /// Original membership attachment writer must release.
    #[error("original membership publication is busy")]
    MembershipBusy(iroha_allocation::release::ReleaseWait),
    /// Original provider archive index reader or writer must release.
    #[error("original provider archive index is busy")]
    ProviderArchiveBusy(iroha_allocation::release::ReleaseWait),
    /// Original reputation archive index reader or writer must release.
    #[error("original reputation archive index is busy")]
    ReputationArchiveBusy(iroha_allocation::release::ReleaseWait),
}
impl PublicationDeferral {
    /// Borrow the original execution refusal; lock contention has no VM allocation category.
    pub fn execution(&self) -> Option<&crate::execution_attempt::ExecutionDeferred> {
        match self {
            Self::Execution(original) => Some(original),
            _ => None,
        }
    }
    /// Borrow actual original allocation demand, never invented for a busy physical owner.
    pub fn allocation_refusal(&self) -> Option<&iroha_allocation::AllocationRefusal> {
        match self {
            Self::Execution(original) => original.allocation_refusal(),
            Self::StateStorage(crate::state::StateStorageAdmissionError::World(
                mv::storage::AdmittedStorageError::Allocation(original),
            ))
            | Self::StateStorage(crate::state::StateStorageAdmissionError::NativeAmx(
                crate::sumeragi::amx::NativeAmxAdmissionError::Admission(original),
            ))
            | Self::EvidencePreparation(crate::state::EvidencePreparationError::Admission(
                original,
            ))
            | Self::BlockHashAdmission(crate::state::BlockHashAdmissionError::Capacity(original))
            | Self::MembershipAdmission(crate::state::MembershipAdmissionError::Capacity(
                original,
            )) => Some(original),
            _ => None,
        }
    }
    /// Original pre-probe release observation which can permit this exact attempt to retry.
    pub fn release_wait(&self) -> Option<&iroha_allocation::release::ReleaseWait> {
        match self {
            Self::SharedControl(_) => None,
            Self::Execution(original) => match original.allocation_refusal() {
                Some(iroha_allocation::AllocationRefusal::Capacity { release, .. }) => {
                    Some(release)
                }
                _ => None,
            },
            Self::StateStorage(original) => original.release_wait(),
            Self::EvidencePreparation(original) => original.release_wait(),
            Self::BlockHashAdmission(original) => original.release_wait(),
            Self::MembershipAdmission(original) => original.release_wait(),
            Self::StateViewBusy(wait)
            | Self::BlockHashesBusy(wait)
            | Self::PublicationBusy(wait)
            | Self::MembershipBusy(wait)
            | Self::ProviderArchiveBusy(wait)
            | Self::ReputationArchiveBusy(wait) => Some(wait),
        }
    }
}

/// A local publication failure, distinguished by whether the original owner may retry.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PublicationError {
    /// No consuming publication began; the same original owner remains available.
    #[error("retryable publication refusal: {0}")]
    Retryable(String),
    /// Retain the original local resource refusal with the unchanged queued execution.
    #[error("deferred original publication: {0}")]
    Deferred(PublicationDeferral),
    /// Publication consumed its owner, may be visible, or lost its worker; recovery is required.
    #[error("publication recovery required: {0}")]
    RecoveryRequired(String),
}

impl From<crate::state::StateViewError> for PublicationError {
    fn from(error: crate::state::StateViewError) -> Self {
        match error {
            crate::state::StateViewError::Busy(wait) => {
                Self::Deferred(PublicationDeferral::StateViewBusy(wait))
            }
            crate::state::StateViewError::Runtime(
                crate::state::LaneLifecycleError::NposPolicy(
                    crate::execution_attempt::ExecutionAttemptError::Deferred(reason),
                ),
            ) => Self::Deferred(reason.into()),
            error => Self::RecoveryRequired(error.to_string()),
        }
    }
}

impl From<String> for PublicationError {
    fn from(reason: String) -> Self {
        Self::Retryable(reason)
    }
}
impl From<&str> for PublicationError {
    fn from(reason: &str) -> Self {
        Self::Retryable(reason.to_owned())
    }
}
impl From<crate::execution_attempt::ExecutionAttemptError<String>> for PublicationError {
    fn from(error: crate::execution_attempt::ExecutionAttemptError<String>) -> Self {
        match error {
            crate::execution_attempt::ExecutionAttemptError::Rejected(reason) => {
                Self::Retryable(reason)
            }
            crate::execution_attempt::ExecutionAttemptError::Deferred(original) => {
                Self::Deferred(original.into())
            }
        }
    }
}

/// The application: speculative execution with a post-state cache keyed by block hash, apply,
/// the payload builder and its quarantine (§12.2, O3, O4). The driver calls it from one thread,
/// one call at a time, and schedules the calls (parking, most recent first, apply in order).
///
/// Apply sequencing: after a successful [`prepare`](Self::prepare) of a block, the driver's next
/// executor call is [`commit`](Self::commit) of the same block (only the block-store append
/// happens in between, retried as long as it fails), so the prepared post-state may be a single
/// live overlay. A retryable refusal preserves that owner and retries after `prepare`; the
/// durable append is retained. Recovery-required errors stop the instance without reexecution.
pub trait Executor: Send {
    /// Execute `block` (hash `block_hash`) on its parent's post-state: the applied state or a
    /// cached post-state. `None` if that post-state is not held (not an error: the driver parks
    /// the request until the parent is applied or executed, O4). A `Valid` post-state is kept
    /// until the block is applied or discarded.
    fn execute(&mut self, block: &AvailableBody, block_hash: &Hash32) -> Option<ExecOutcome>;
    /// Drop the post-states of the blocks at `height` other than `keep`.
    fn discard(&mut self, height: u64, keep: &[Hash32]);
    /// The post-state of the next committed block (its parent is the applied state): the
    /// original execution of that exact block, or a new execution only if no original is held
    /// and publication has not begun (a missing cache entry is never a divergence, O3).
    /// Returns the original local commitment, even on mismatch, or `None` for `Invalid`.
    ///
    /// # Errors
    /// A retryable refusal retains the original owner. A consuming failure or unwind requires
    /// recovery; the driver halts instead of preparing or executing again.
    fn prepare(
        &mut self,
        block: &AvailableBody,
        commit_qc: &Qc,
    ) -> Result<Option<Hash32>, PublicationError>;
    /// Make the prepared post-state of `block` the applied state (after the block store holds
    /// it) and return its exact atomic epoch/configuration output. An ordinary block supplies
    /// lag-2 parameters or a pending boundary; the applied boundary supplies both its immediate
    /// successor and the following height. The driver transports this output unchanged.
    /// Called only right after
    /// a successful `prepare` of `block` (see the trait documentation).
    ///
    /// # Errors
    /// A retryable refusal retains the original owner. A consuming failure requires recovery;
    /// the driver halts and never reports a successful apply for it.
    fn commit(
        &mut self,
        block: &AvailableBody,
        commit_qc: &Qc,
    ) -> Result<AppliedConfig, PublicationError>;
    /// Build exact canonical application control independently of transactions, including EMPTY.
    /// A retryable refusal keeps the producer/source; it never substitutes an empty witness.
    ///
    /// # Errors
    /// Local refusal/awaiting shares is retryable; a lost owner requires recovery.
    fn build_control_witness(
        &mut self,
        context: &iroha_sumeragi::api::ControlWitnessContext,
    ) -> Result<iroha_sumeragi::types::ControlWitness, PublicationError>;
    /// Drive the single process-lived partial producer from this exact applied parent. Called
    /// on every current member and bounded periodic retry, regardless of proposal leadership.
    ///
    /// # Errors
    /// Revalidate the complete source against State; never trust caller-supplied parent result.
    fn drive_control(
        &mut self,
        context: &iroha_sumeragi::api::ApplicationControlContext,
    ) -> Result<Option<iroha_sumeragi::message::ApplicationControl>, PublicationError>;
    /// Verify and reduce one bounded authenticated peer partial against the same applied State.
    ///
    /// # Errors
    /// The application verifies sender/index, exact source/session and the partial signature.
    fn receive_application_control(
        &mut self,
        from: &PublicKey,
        message: &iroha_sumeragi::message::ApplicationControl,
    ) -> Result<(), PublicationError>;
    /// Build a payload of at most `max_bytes` for `(height, view)` by peeking at the queue
    /// (never removing transactions), admitted to the original instance pool.
    /// `None` means genuinely absent work.
    ///
    /// # Errors
    /// A local refusal retains the exact source and completed encoding for retry.
    fn build(
        &mut self,
        height: u64,
        view: u64,
        max_bytes: u32,
        exec_budget_ms: u32,
    ) -> Result<Option<PayloadBytes>, PublicationError>;
    /// The payload of `block_hash` executed `Invalid`: quarantine the transactions that make a
    /// block invalid on their own.
    fn reject(&mut self, height: u64, view: u64, block_hash: &Hash32);
}

/// Receives the core's reports — evidence of signed misbehaviour, local faults and a halt —
/// and the driver's own (telemetry and the evidence log in the node).
pub trait Observer: Send + Sync {
    /// Evidence the core reports (after its O2 barrier).
    fn evidence(&self, _evidence: &Evidence) {}
    /// A local fault.
    fn fault(&self, _fault: &LocalFault) {}
    /// The instance halted.
    fn halt(&self, _reason: &HaltReason) {}
    /// A thread of the instance stopped, or a worker could not be reached: the instance
    /// stopped with it (a restart recovers).
    fn stopped(&self, _worker: Worker) {}
    /// The event loop completed an explicit orderly shutdown without worker failure.
    fn finished(&self) {}
    /// A committed configuration outgrows the transport's frame limit (O10).
    fn frame_limit(&self, _exceeded: &FrameLimitExceeded) {}
}

/// An observer that ignores every report.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoObserver;

impl Observer for NoObserver {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_entry_accessors() {
        let key = PublicKey::new(vec![1; 32]).unwrap();
        let a = LogEntry::Key {
            key: key.clone(),
            generated: true,
            store_id: 7,
        };
        let b = LogEntry::Instance {
            instance: Hash32([2; 32]),
            key: key.clone(),
            store_id: 9,
        };
        assert_eq!((a.store_id(), b.store_id()), (7, 9));
        assert_eq!((a.key(), b.key()), (&key, &key));
    }

    #[test]
    fn system_clock_is_monotonic() {
        let clock = SystemClock::default();
        let a = clock.now();
        std::thread::sleep(std::time::Duration::from_millis(2));
        assert!(clock.now() >= a + 1);
    }

    #[test]
    fn no_observer_ignores_reports() {
        let observer = NoObserver;
        observer.fault(&LocalFault::RecordMissing);
        observer.halt(&HaltReason::DriverAnomaly);
        observer.stopped(Worker::Exec);
        observer.frame_limit(&FrameLimitExceeded {
            height: 1,
            needed: 2,
            limit: 1,
        });
    }
}
