//! A CowCell with linear drop behaviour
//!
//! YOU SHOULD NOT USE THIS TYPE! Normally concurrent cells do NOT require the linear dropping
//! behaviour that this implements, and it will only make your application
//! worse for it. Consider `CowCell` and `EbrCell` instead.

/*
 * The reason this exists is for protecting the major concurrently readable structures
 * that can corrupt if intermediate transactions are removed early. Effectively what we
 * need to create is:
 *
 * [ A ] -> [ B ] -> [ C ] -> [ Write Head ]
 *   ^        ^        ^
 *   read     read     read
 *
 * This way if we drop the reader on B:
 *
 * [ A ] -> [ B ] -> [ C ] -> [ Write Head ]
 *   ^                 ^
 *   read              read
 *
 * Notice that A is not dropped. It's only when A is dropped:
 *
 * [ A ] -> [ B ] -> [ C ] -> [ Write Head ]
 *                     ^
 *                     read
 *
 * [ X ] -> [ B ] -> [ C ] -> [ Write Head ]
 *                     ^
 *                     read
 * [ X ] -> [ X ] -> [ C ] -> [ Write Head ]
 *                     ^
 *                     read
 *
 *                   [ C ] -> [ Write Head ]
 *                     ^
 *                     read
 *
 * At this point we drop A and B. To achieve this we need to consider that:
 * - If WriteHead is dropped, C continues to live.
 * - If A/B are dropped, we don't affect C.
 * - Everything is dropped in order until a read txn exists.
 * - When we drop the main structure, no readers can exist.
 * - A writer must be able to commit to a stable location.
 *
 *
 *   T        T        T
 * [ A ] -> [ B ] -> [ C ] -> [ Write Head ]
 *   ^        ^        ^
 *   RRR      RR       R
 *
 *
 * As the write head proceeds, it must be able to interact with past versions to commit
 * garbage that is "last seen" in the formers generation.
 *
 */

mod results;
use results::{OwnedAcquireResult, OwnedWriteResult, WriterAdmissionResult};

use std::alloc::Layout;
use std::marker::PhantomData;
use std::ops::Deref;
use std::ops::DerefMut;
use std::sync::{OnceLock, TryLockError};

mod retained_mutex;
use retained_mutex::{Mutex, MutexGuard};

use iroha_allocation::shared::{Reserved, Shared};

/// Explicitly unaccounted shell ownership; this provides no admission policy.
#[derive(Debug)]
pub struct Untracked;

/// Exact allocation control blocks owned by a newly constructed cell.
///
/// Native mutex internals, the supplied data and its nested storage are separate.
#[derive(Clone, Copy, Debug)]
pub struct InitialLayouts {
    /// Original reader-release notification and its strong reference counter.
    pub notification: Layout,
    /// Original permanent writer root, including its mutex and reference counter.
    pub root: Layout,
    /// Original first-reader shell, including its reference counter.
    pub reader: Layout,
}

/// Move-only prepaid custody for the original root and first-reader allocations.
#[derive(Debug)]
pub struct InitialCharges<Charge> {
    /// Original notification control owner, funded before cell construction.
    pub notification: iroha_allocation::release::ReleaseNotification,
    /// Custody held until the last cell or detached writer destroys the root.
    pub root: Charge,
    /// Custody retained by the original first-reader generation.
    pub reader: Charge,
}

/// Actual control-block layouts allocated before constructing a writer.
#[derive(Clone, Copy, Debug)]
pub struct WriterLayouts {
    /// Original mutable cursor and its allocation control block.
    pub cursor: Layout,
    /// Original next-reader shell and its allocation control block.
    pub reader: Layout,
}

/// Move-only prepaid custody for the original cursor and next-reader shell.
///
/// These charges do not fund the cursor's nested buffers, nodes or payloads.
/// A complete caller must reserve those before their construction as well.
#[derive(Debug)]
pub struct WriterCharges<Charge> {
    /// Custody held until the original cursor allocation is reclaimed.
    pub cursor: Charge,
    /// Custody retained by the original published or abandoned reader shell.
    pub reader: Charge,
}

/// Original shell charges and the move-only input admitted for one writer.
///
/// The input is consumed by the original writer constructor after both shells
/// have been allocated. Reattaching a detached writer does not admit or construct
/// another input. Neither this type nor the cell supplies a default input.
#[derive(Debug)]
pub struct WriterAdmission<Charge, Input> {
    /// Prepaid custody for the original cursor and next-reader shells.
    pub charges: WriterCharges<Charge>,
    /// The original constructor input admitted while the writer was locked.
    pub input: Input,
}

/// Do not implement this. You don't need this negativity in your life.
pub trait LinCowCellCapable<R, U> {
    /// Move-only input explicitly supplied by original writer admission.
    type WriterInput;

    /// Create the first reader snapshot for a new instance.
    fn create_reader(&self) -> R;

    /// Create a writer that may be rolled back.
    fn create_writer(&self, input: Self::WriterInput) -> U;

    /// Given the current active reader, and the writer to commit, update our
    /// main structure as mut self, and our previously linear generations based on
    /// what was updated.
    fn pre_commit(&mut self, new: U, prev: &R) -> R;
}

pub(crate) mod retained_commit {
    pub trait Sealed {}
}

/// Audited ownership transfer which retains all user cleanup after publication.
/// Only the original B+tree engine implements this sealed capability.
pub trait LinCowCellRetainedCommit<R, U>:
    LinCowCellCapable<R, U> + retained_commit::Sealed
{
    /// Original bookkeeping whose destruction must follow physical unlock.
    type Retirement;
    /// Check all engine conditions before any participating cell is published.
    fn validate_commit(&self, new: &U, prev: &R);
    /// Transfer original node ownership without allocation or user destruction.
    fn pre_commit_retaining(&mut self, new: U, prev: &R) -> (R, Self::Retirement);
}

#[derive(Debug)]
/// A concurrently readable cell with linearised drop behaviour.
pub struct LinCowCell<T, R, U, Charge = Untracked> {
    updater: PhantomData<U>,
    write: Shared<Mutex<WriteState<T, R, Charge>>, Charge>,
    active: Mutex<Shared<LinCowCellInner<R, Charge>, Charge>>,
    active_released: iroha_allocation::release::ReleaseNotification,
}

type ActiveGuard<'a, R, Charge> = iroha_allocation::release::ReleaseGuard<
    'a,
    MutexGuard<'a, Shared<LinCowCellInner<R, Charge>, Charge>>,
>;

/// Opaque custody of one original charged physical root allocation.
/// Cloning this handle retains that allocation without allocating a new identity.
pub struct LinCowCellFamily<T, R, Charge = Untracked> {
    root: Shared<Mutex<WriteState<T, R, Charge>>, Charge>,
}

impl<T, R, Charge> Clone for LinCowCellFamily<T, R, Charge> {
    fn clone(&self) -> Self {
        Self {
            root: self.root.clone(),
        }
    }
}

impl<T, R, Charge> LinCowCellFamily<T, R, Charge> {
    /// Compare the actual original root, independently of its advancing reader.
    pub fn matches<U>(&self, target: &LinCowCell<T, R, U, Charge>) -> bool {
        Shared::ptr_eq(&self.root, &target.write)
    }

    /// Compare two retained original roots without locking or allocating.
    pub fn same_family(&self, other: &Self) -> bool {
        Shared::ptr_eq(&self.root, &other.root)
    }
}

/// Borrowed original root and reader generation, granting no publication authority.
pub struct LinCowCellPredecessor<'a, T, R, Charge = Untracked> {
    root: &'a Shared<Mutex<WriteState<T, R, Charge>>, Charge>,
    base: &'a Shared<LinCowCellInner<R, Charge>, Charge>,
}

impl<T, R, Charge> LinCowCellPredecessor<'_, T, R, Charge> {
    /// Retain these same original allocations without a new identity allocation.
    pub fn retain(&self) -> LinCowCellRetainedPredecessor<T, R, Charge> {
        LinCowCellRetainedPredecessor {
            base: self.base.clone(),
            root: self.root.clone(),
        }
    }

    /// Compare exact original roots and reader allocations, never their values.
    pub fn same_predecessor(&self, other: &LinCowCellPredecessor<'_, T, R, Charge>) -> bool {
        Shared::ptr_eq(self.root, other.root) && Shared::ptr_eq(self.base, other.base)
    }
}

/// Retained original reader and physical root, without cursor or edit authority.
/// The base drops before the root that keeps its final shared nodes alive.
pub struct LinCowCellRetainedPredecessor<T, R, Charge = Untracked> {
    base: Shared<LinCowCellInner<R, Charge>, Charge>,
    root: Shared<Mutex<WriteState<T, R, Charge>>, Charge>,
}
impl<T, R, Charge> Clone for LinCowCellRetainedPredecessor<T, R, Charge> {
    fn clone(&self) -> Self {
        Self {
            base: self.base.clone(),
            root: self.root.clone(),
        }
    }
}
impl<T, R, Charge> std::fmt::Debug for LinCowCellRetainedPredecessor<T, R, Charge> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinCowCellRetainedPredecessor")
            .finish_non_exhaustive()
    }
}
impl<T, R, Charge> PartialEq for LinCowCellRetainedPredecessor<T, R, Charge> {
    fn eq(&self, other: &Self) -> bool {
        Shared::ptr_eq(&self.root, &other.root) && Shared::ptr_eq(&self.base, &other.base)
    }
}
impl<T, R, Charge> Eq for LinCowCellRetainedPredecessor<T, R, Charge> {}
impl<T, R, Charge> LinCowCellRetainedPredecessor<T, R, Charge> {
    /// Compare original root/base custody with another live owner's borrowed cut.
    pub fn matches(&self, other: &LinCowCellPredecessor<'_, T, R, Charge>) -> bool {
        Shared::ptr_eq(&self.root, other.root) && Shared::ptr_eq(&self.base, other.base)
    }
}

#[derive(Debug)]
struct WriteState<T, R, Charge> {
    data: T,
    // The exact active generation is also available under the writer lock.
    // Adopting an owned writer never contends with the short-lived reader lock.
    current: Shared<LinCowCellInner<R, Charge>, Charge>,
    // The same notification control survives with original detached/root owners.
    // This is a reference to the original allocation, not a replacement source.
    _release_control: iroha_allocation::release::ReleaseNotification,
}

#[derive(Debug)]
/// A write txn over a linear cell.
pub struct LinCowCellWriteTxn<'a, T, R, U, Charge = Untracked> {
    caller: &'a LinCowCell<T, R, U, Charge>,
    // Unlock before abort destroys a charge: refunds can synchronously wake a
    // retry that reenters the cell. The retained base protects the private work
    // just as it does after detachment, until that work has been destroyed.
    guard: MutexGuard<'a, WriteState<T, R, Charge>>,
    // Allocate the cursor only during original acquisition. Every handoff moves
    // this same allocation; abort destroys it before releasing its base.
    work: Shared<U, Charge>,
    next: Reserved<LinCowCellInner<R, Charge>, Charge>,
    base: Shared<LinCowCellInner<R, Charge>, Charge>,
}

/// Original writer and reader locks checked before a retained publication.
/// Dropping this owner aborts the still-private writer after releasing both locks.
pub struct LinCowCellPreparedCommit<'a, T, R, U, Charge = Untracked> {
    caller: &'a LinCowCell<T, R, U, Charge>,
    guard: MutexGuard<'a, WriteState<T, R, Charge>>,
    active: ActiveGuard<'a, R, Charge>,
    work: Shared<U, Charge>,
    next: Reserved<LinCowCellInner<R, Charge>, Charge>,
    base: Shared<LinCowCellInner<R, Charge>, Charge>,
}

/// Caller-owned original writer throughout physical preparation and validation.
///
/// Creation only moves existing ownership. Preparation borrows this slot, so a
/// validation panic leaves both physical guards and private work with the caller.
/// The caller must release every sibling before destroying this slot's payloads
/// or original release notifications. No generation can publish before validation.
#[must_use = "retain original preparation custody through aggregate cleanup"]
pub struct LinCowCellCommitSlot<'a, T, R, U, Charge = Untracked> {
    phase: Option<LinCowCellCommitPhase<'a, T, R, U, Charge>>,
    ready: bool,
}

enum LinCowCellCommitPhase<'a, T, R, U, Charge> {
    Writer(LinCowCellWriteTxn<'a, T, R, U, Charge>),
    Prepared(LinCowCellPreparedCommit<'a, T, R, U, Charge>),
}

impl<'a, T, R, U, Charge> LinCowCellCommitSlot<'a, T, R, U, Charge>
where
    T: LinCowCellRetainedCommit<R, U>,
{
    /// Prepare while keeping the original owner in the caller on poison or panic.
    pub fn prepare(&mut self) {
        let Some(LinCowCellCommitPhase::Writer(writer)) = self.phase.as_ref() else {
            panic!("original writer prepares once");
        };
        let active = if writer.guard.is_retained() {
            writer.caller.lock_active_retained()
        } else {
            writer.caller.lock_active()
        };
        self.install_active(active);
        self.validate();
    }

    /// Try the original active-reader lock without releasing this writer on error.
    pub fn try_prepare(&mut self) -> Result<(), OwnedWriteError> {
        let Some(LinCowCellCommitPhase::Writer(writer)) = self.phase.as_ref() else {
            panic!("original writer prepares once");
        };
        let active = if writer.guard.is_retained() {
            writer.caller.try_lock_active_retained()?
        } else {
            writer.caller.try_lock_active()?
        };
        self.install_active(active);
        self.validate();
        Ok(())
    }

    fn install_active(&mut self, active: ActiveGuard<'a, R, Charge>) {
        let Some(LinCowCellCommitPhase::Writer(LinCowCellWriteTxn {
            caller,
            guard,
            work,
            next,
            base,
        })) = self.phase.take()
        else {
            unreachable!("borrowed original writer checked before acquisition");
        };
        // Only inert moves occur between taking the writer and installing it.
        // All assertions and cursor validation happen after caller custody resumes.
        self.phase = Some(LinCowCellCommitPhase::Prepared(LinCowCellPreparedCommit {
            caller,
            guard,
            active,
            work,
            next,
            base,
        }));
    }

    fn validate(&mut self) {
        let Some(LinCowCellCommitPhase::Prepared(prepared)) = self.phase.as_mut() else {
            unreachable!("original reader and writer installed before validation");
        };
        assert!(Shared::ptr_eq(&prepared.base, &prepared.guard.current));
        assert!(Shared::ptr_eq(&prepared.base, &prepared.active));
        assert!(prepared.base.pin.get().is_none());
        let original = Shared::get_mut(&mut prepared.work).expect("original cursor must be unique");
        prepared
            .guard
            .data
            .validate_commit(original, &prepared.base.data);
        self.ready = true;
    }

    /// Whether this original pair completed validation without an intervening edit.
    pub fn is_prepared(&self) -> bool {
        self.ready
    }

    /// Transfer the checked original without additional locking or callbacks.
    pub fn into_prepared(mut self) -> LinCowCellPreparedCommit<'a, T, R, U, Charge> {
        assert!(self.ready, "original preparation must complete");
        let Some(LinCowCellCommitPhase::Prepared(prepared)) = self.phase.take() else {
            unreachable!("ready preparation retains original physical guards");
        };
        prepared
    }

    /// Return the original unpublished writer and retain any actual reader release.
    /// This is also valid after failed validation; callers must use cleanup-only
    /// retirement for a failed cursor, never promote it to journal authority.
    pub fn abort_retaining(
        mut self,
    ) -> (
        LinCowCellWriteTxn<'a, T, R, U, Charge>,
        Option<iroha_allocation::release::DeferredRelease>,
    ) {
        match self.phase.take().expect("original commit slot") {
            LinCowCellCommitPhase::Writer(writer) => (writer, None),
            LinCowCellCommitPhase::Prepared(prepared) => {
                let (writer, release) = prepared.abort_retaining();
                (writer, Some(release))
            }
        }
    }
}

impl<T, R, U, Charge> AsRef<U> for LinCowCellCommitSlot<'_, T, R, U, Charge> {
    fn as_ref(&self) -> &U {
        match self.phase.as_ref().expect("original commit slot") {
            LinCowCellCommitPhase::Writer(writer) => writer.as_ref(),
            LinCowCellCommitPhase::Prepared(prepared) => &prepared.work,
        }
    }
}

/// Cleanup custody after original node ownership has been published.
/// It carries no publication authority; free it after every physical unlock.
pub struct LinCowCellCommitRetirement<R, Retirement, Charge = Untracked> {
    _engine: Retirement,
    _base: Shared<LinCowCellInner<R, Charge>, Charge>,
    _cursor_charge: Charge,
    // LAST: native wake callbacks follow real cursor/reader cleanup and remain
    // with the aggregate owner after both physical locks have been released.
    active_release: Option<iroha_allocation::release::DeferredRelease>,
}

/// Published cell retaining both physical locks and all original cleanup custody.
/// An aggregate owner must release every participating cell before cleanup.
pub struct LinCowCellPublished<'a, T, R, U, Charge = Untracked>
where
    T: LinCowCellRetainedCommit<R, U>,
{
    guard: MutexGuard<'a, WriteState<T, R, Charge>>,
    active: ActiveGuard<'a, R, Charge>,
    retirement: LinCowCellCommitRetirement<R, T::Retirement, Charge>,
}

#[derive(Debug)]
/// An unpublished writer retaining its original root and base generation.
///
/// The original cursor allocation moves intact through handoff and retry.
/// Field order keeps shared nodes alive until that cursor and its allocation
/// are destroyed, including when the original cell has already been dropped.
pub struct LinCowCellOwned<T, R, U, Charge = Untracked> {
    work: Shared<U, Charge>,
    next: Reserved<LinCowCellInner<R, Charge>, Charge>,
    base: Shared<LinCowCellInner<R, Charge>, Charge>,
    root: Shared<Mutex<WriteState<T, R, Charge>>, Charge>,
}

/// Immutable custody of the exact original private cursor allocation.
///
/// Only the frozen map facade creates this handle. It retains the original
/// working cursor, base and root in value-before-node-owner destruction order.
/// Cloning adds references to existing charged allocations and allocates nothing.
pub(crate) struct LinCowCellRetainedWork<T, R, U, Charge = Untracked> {
    work: Shared<U, Charge>,
    base: Shared<LinCowCellInner<R, Charge>, Charge>,
    root: Shared<Mutex<WriteState<T, R, Charge>>, Charge>,
}

impl<T, R, U, Charge> Clone for LinCowCellRetainedWork<T, R, U, Charge> {
    fn clone(&self) -> Self {
        Self {
            work: self.work.clone(),
            base: self.base.clone(),
            root: self.root.clone(),
        }
    }
}

impl<T, R, U, Charge> LinCowCellRetainedWork<T, R, U, Charge> {
    pub(crate) fn same_work(&self, other: &Self) -> bool {
        Shared::ptr_eq(&self.work, &other.work)
            && Shared::ptr_eq(&self.base, &other.base)
            && Shared::ptr_eq(&self.root, &other.root)
    }
}

impl<T, R, U, Charge> AsRef<U> for LinCowCellRetainedWork<T, R, U, Charge> {
    fn as_ref(&self) -> &U {
        &self.work
    }
}

/// Original physical writer before admission or successor construction.
/// No cursor allocation or caller callback runs while acquiring this owner.
#[must_use = "admit a successor or release the original acquired writer"]
pub struct LinCowCellWriterAcquisition<'a, T, R, U, Charge = Untracked> {
    guard: MutexGuard<'a, WriteState<T, R, Charge>>,
    caller: &'a LinCowCell<T, R, U, Charge>,
    poisoned: bool,
}

/// Refusal while retaining the actual writer acquired before admission.
#[derive(Debug)]
pub enum WriterAdmissionError<E> {
    /// An earlier unwind poisoned the acquired writer; admission was not called.
    Poisoned,
    /// Planning or admission refused before successor construction.
    Refused(E),
}

impl<'a, T, R, U, Charge> LinCowCellWriterAcquisition<'a, T, R, U, Charge>
where
    T: LinCowCellCapable<R, U>,
{
    /// Whether the acquired original writer was already poisoned.
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Admit the original shells and construct one successor under this guard.
    /// Refusal returns this exact guard; unwind unlocks before caller notification.
    /// Caller-owned refund deferral must surround construction and writer cleanup.
    pub fn try_write_charged<E>(
        self,
        admit: impl FnOnce(&T, WriterLayouts) -> Result<WriterAdmission<Charge, T::WriterInput>, E>,
    ) -> WriterAdmissionResult<'a, T, R, U, Charge, E> {
        if self.poisoned {
            return Err((self, WriterAdmissionError::Poisoned));
        }
        let admission = match admit(
            &self.guard.data,
            LinCowCell::<T, R, U, Charge>::writer_allocation_layouts(),
        ) {
            Ok(admission) => admission,
            Err(error) => return Err((self, WriterAdmissionError::Refused(error))),
        };
        let Self { guard, caller, .. } = self;
        Ok(caller.create_writer(guard, admission))
    }
}

/// Actual writer-lock custody before validating a retained predecessor.
///
/// A successful acquisition always owns the physical mutex, including a
/// previously poisoned mutex. Validation cannot discard that ownership on
/// refusal. Field order unlocks before private work or its charges are dropped.
#[must_use = "validate or abort the original acquired writer"]
pub struct LinCowCellOwnedAcquisition<'a, T, R, U, Charge = Untracked> {
    guard: MutexGuard<'a, WriteState<T, R, Charge>>,
    owned: LinCowCellOwned<T, R, U, Charge>,
    caller: &'a LinCowCell<T, R, U, Charge>,
    poisoned: bool,
}

impl<T, R, U, Charge> std::fmt::Debug for LinCowCellOwnedAcquisition<'_, T, R, U, Charge> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinCowCellOwnedAcquisition")
            .finish_non_exhaustive()
    }
}

impl<'a, T, R, U, Charge> LinCowCellOwnedAcquisition<'a, T, R, U, Charge> {
    /// Validate the same physical root and reader while retaining its lock.
    /// A stale or poisoned refusal returns this exact acquired owner.
    pub fn validate(
        self,
    ) -> Result<LinCowCellWriteTxn<'a, T, R, U, Charge>, (Self, OwnedWriteError)> {
        if self.poisoned {
            return Err((self, OwnedWriteError::Poisoned));
        }
        if !Shared::ptr_eq(&self.guard.current, &self.owned.base) {
            return Err((self, OwnedWriteError::Changed));
        }
        let Self {
            guard,
            owned,
            caller,
            ..
        } = self;
        let LinCowCellOwned {
            work,
            next,
            base,
            root,
        } = owned;
        // The same root remains borrowed through caller throughout this handoff.
        drop(root);
        Ok(LinCowCellWriteTxn {
            caller,
            guard,
            work,
            next,
            base,
        })
    }

    /// Unlock and return the unchanged private generation, without publishing it.
    pub fn abort(self) -> LinCowCellOwned<T, R, U, Charge> {
        let Self { guard, owned, .. } = self;
        drop(guard);
        owned
    }
}

/// Why an original unpublished writer could not be reacquired.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnedWriteError {
    /// The original writer lock is currently held.
    Busy,
    /// The original writer lock was poisoned by an unwind.
    Poisoned,
    /// The target is foreign or its original reader generation has changed.
    Changed,
}

#[derive(Debug)]
struct LinCowCellInner<R, Charge> {
    // The original writer installs exactly one successor. A once-set link
    // avoids a lazily allocated OS mutex at publication on pthread platforms.
    pin: OnceLock<Shared<LinCowCellInner<R, Charge>, Charge>>,
    data: R,
}

#[derive(Debug)]
/// A read txn over a linear cell.
pub struct LinCowCellReadTxn<'a, T, R, U, Charge = Untracked> {
    // We must outlive the root
    _caller: &'a LinCowCell<T, R, U, Charge>,
    // We pin the current version.
    work: Shared<LinCowCellInner<R, Charge>, Charge>,
}

impl<T, R, U, Charge> Clone for LinCowCellReadTxn<'_, T, R, U, Charge> {
    fn clone(&self) -> Self {
        Self {
            _caller: self._caller,
            work: self.work.clone(),
        }
    }
}

impl<R, Charge> LinCowCellInner<R, Charge> {
    pub fn new(data: R) -> Self {
        LinCowCellInner {
            pin: OnceLock::new(),
            data,
        }
    }
}

impl<R, Charge> Drop for LinCowCellInner<R, Charge> {
    fn drop(&mut self) {
        // Ensure the default drop won't recursively drop the chain
        // Consuming the last strong reference also reclaims its exact allocation.
        let mut current = self.pin.take();

        // Drop the chain iteratively to avoid stack overflow
        while let Some(arc) = current {
            // Try to get exclusive ownership of the next link
            match arc.into_inner() {
                Some(mut inner) => {
                    // Continue with the next link.
                    current = inner.pin.take();
                }
                None => {
                    // Another strong reference exists; stop without breaking its chain
                    break;
                }
            }
        }
    }
}

impl<T, R, U, Charge> LinCowCell<T, R, U, Charge> {
    /// Observe the actual active-reader mutex before a nonblocking probe.
    /// Releasing a writer or a pinned reader does not complete this wait. Every
    /// successful active-reader acquisition notifies after its mutex unlocks.
    pub fn observe_reader_release(&self) -> iroha_allocation::release::ReleaseWait {
        self.active_released.observe()
    }

    /// Retain actual releases from this original active-reader mutex in constant
    /// space. The caller keeps the batch beyond every enclosing physical fence.
    pub fn reader_release_batch(&self) -> iroha_allocation::release::DeferredReleaseBatch {
        self.active_released.deferred_batch()
    }

    fn lock_active(&self) -> ActiveGuard<'_, R, Charge> {
        self.active_released.poisoning_guard(
            self.active_released
                .with_acquisition_unwind_notification(|| {
                    self.active.lock().expect("original reader lock poisoned")
                }),
        )
    }

    // Only sealed retained preparation uses this read-only physical owner.
    // Mutable access arms the original primitive before any root transfer.
    fn lock_active_retained(&self) -> ActiveGuard<'_, R, Charge> {
        self.active_released.observed_guard(
            self.active
                .lock_retained()
                .expect("original reader lock poisoned"),
            self.active.poison_flag(),
        )
    }

    fn try_lock_active_retained(&self) -> Result<ActiveGuard<'_, R, Charge>, OwnedWriteError> {
        match self.active.try_lock_retained() {
            Ok(active) => Ok(self
                .active_released
                .observed_guard(active, self.active.poison_flag())),
            Err(TryLockError::WouldBlock) => Err(OwnedWriteError::Busy),
            Err(TryLockError::Poisoned(_)) => Err(OwnedWriteError::Poisoned),
        }
    }

    fn try_lock_active(&self) -> Result<ActiveGuard<'_, R, Charge>, OwnedWriteError> {
        match self.active.try_lock() {
            Ok(active) => Ok(self.active_released.poisoning_guard(active)),
            Err(TryLockError::WouldBlock) => Err(OwnedWriteError::Busy),
            Err(TryLockError::Poisoned(_)) => Err(OwnedWriteError::Poisoned),
        }
    }
}

impl<T, R, U, Charge> LinCowCell<T, R, U, Charge>
where
    T: LinCowCellCapable<R, U>,
{
    /// Exact original root and first-reader layouts; native mutex internals and
    /// nested storage are separate allocations, not part of this layout pair.
    pub fn initial_allocation_layouts() -> InitialLayouts {
        InitialLayouts {
            notification: iroha_allocation::release::ReleaseNotification::allocation_layout::<Charge>(
            ),
            root: Reserved::<Mutex<WriteState<T, R, Charge>>, Charge>::layout(),
            reader: Self::reader_allocation_layout(),
        }
    }

    /// Exact layout of each reader generation, including its reference counter.
    pub fn reader_allocation_layout() -> Layout {
        Reserved::<LinCowCellInner<R, Charge>, Charge>::layout()
    }

    /// Exact original cursor and next-reader layouts; nested storage is separate.
    pub fn writer_allocation_layouts() -> WriterLayouts {
        WriterLayouts {
            cursor: Reserved::<U, Charge>::layout(),
            reader: Self::reader_allocation_layout(),
        }
    }

    /// Construct the original root and reader under their prepaid charges.
    ///
    /// Both shells are allocated before `create_reader`. Input T and all nested
    /// storage require separate admission. Native mutex internals are initialized
    /// here, but their opaque platform allocations are not funded by these charges.
    /// TODO: provision native mutex and runtime control storage before claiming
    /// complete construction admission.
    pub fn new_charged(data: T, charges: InitialCharges<Charge>) -> Self {
        // A reader constructor may unwind. Tuple field order destroys the
        // original data before either prepaid shell refunds and wakes a retry.
        let root = Reserved::new(charges.root);
        let reader = Reserved::new(charges.reader);
        let construction = (data, reader, root);
        let reader = construction.0.create_reader();
        let (data, shell, root) = construction;
        let current = shell.initialize(LinCowCellInner::new(reader));
        let active = Mutex::new(current.clone());
        // Initialize both permanent native mutexes during construction. A first
        // refused writer must not allocate a lazy platform mutex at admission.
        drop(active.lock().unwrap());
        let write = root.initialize(Mutex::new(WriteState {
            data,
            current,
            _release_control: charges.notification.clone(),
        }));
        drop(write.lock().unwrap());
        LinCowCell {
            updater: PhantomData,
            write,
            active,
            active_released: charges.notification,
        }
    }

    /// Retain the original physical root without allocating an identity token.
    pub fn family(&self) -> LinCowCellFamily<T, R, Charge> {
        LinCowCellFamily {
            root: self.write.clone(),
        }
    }

    /// Begin a read transaction retaining the original generation and its charge.
    pub fn read(&self) -> LinCowCellReadTxn<'_, T, R, U, Charge> {
        let rwguard = self.lock_active();
        LinCowCellReadTxn {
            _caller: self,
            work: rwguard.clone(),
        }
    }

    /// Retain the current original generation without waiting or allocating.
    /// `Busy` and `Poisoned` refer to the active-reader lock, not a writer lease.
    pub fn try_read(&self) -> Result<LinCowCellReadTxn<'_, T, R, U, Charge>, OwnedWriteError> {
        let active = self.try_lock_active()?;
        Ok(LinCowCellReadTxn {
            _caller: self,
            work: active.clone(),
        })
    }

    /// Pin the current original reader, deferring its actual acquisition release
    /// into the caller's original batch. Foreign batches refuse before acquiring
    /// anything. Poisoned acquisitions are also unlocked and recorded in the batch.
    pub fn read_retaining(
        &self,
        releases: &mut iroha_allocation::release::DeferredReleaseBatch,
    ) -> Result<LinCowCellReadTxn<'_, T, R, U, Charge>, OwnedWriteError> {
        self.read_retaining_impl(releases, false)
    }

    /// Nonblocking original reader acquisition with the same deferred custody.
    /// Busy records no release. A foreign batch returns Changed before probing.
    pub fn try_read_retaining(
        &self,
        releases: &mut iroha_allocation::release::DeferredReleaseBatch,
    ) -> Result<LinCowCellReadTxn<'_, T, R, U, Charge>, OwnedWriteError> {
        self.read_retaining_impl(releases, true)
    }

    fn read_retaining_impl(
        &self,
        releases: &mut iroha_allocation::release::DeferredReleaseBatch,
        nonblocking: bool,
    ) -> Result<LinCowCellReadTxn<'_, T, R, U, Charge>, OwnedWriteError> {
        if !self.active_released.owns_batch(releases) {
            return Err(OwnedWriteError::Changed);
        }
        // Retain even an acquired poisoned guard. Erasing that guard into an
        // error would lose its actual release or notify inside the caller's fence.
        let (active, poisoned) = if nonblocking {
            match self.active.try_lock() {
                Ok(active) => (active, false),
                Err(TryLockError::WouldBlock) => return Err(OwnedWriteError::Busy),
                Err(TryLockError::Poisoned(error)) => (error.into_inner(), true),
            }
        } else {
            match self.active.lock() {
                Ok(active) => (active, false),
                Err(error) => (error.into_inner(), true),
            }
        };
        let active = self
            .active_released
            .observed_guard(active, self.active.poison_flag());
        // The existing transfer engine owns unwind: it releases this exact guard
        // before recording its permanent poison in the caller's same-source batch.
        // Cloning the shared reader invokes no payload code or allocation.
        match active.try_release_into(releases, |active| {
            if poisoned {
                Err(OwnedWriteError::Poisoned)
            } else {
                Ok(LinCowCellReadTxn {
                    _caller: self,
                    work: active.clone(),
                })
            }
        }) {
            Ok(result) => result,
            Err(_) => unreachable!("original reader batch checked before acquisition"),
        }
    }

    /// Borrow the exact retained reader in this same original family. No lock,
    /// allocation, current-generation sampling or notification occurs.
    pub fn read_predecessor(
        &self,
        predecessor: &LinCowCellRetainedPredecessor<T, R, Charge>,
    ) -> Option<LinCowCellReadTxn<'_, T, R, U, Charge>> {
        Shared::ptr_eq(&self.write, &predecessor.root).then(|| LinCowCellReadTxn {
            _caller: self,
            work: predecessor.base.clone(),
        })
    }

    /// Admit both original shells before allocating either or creating a cursor.
    ///
    /// This callback must draw from one complete prepaid operation. It does not
    /// retroactively fund input T, nested cursor buffers, nodes or payloads.
    /// The input constructor can destroy nested ownership before this call
    /// unwinds. Callback-bearing refunds in that input must use the caller's
    /// original notification-deferral scope around acquisition and construction,
    /// so callbacks run only after its physical guards have been released.
    pub fn write_charged<E>(
        &self,
        admit: impl FnOnce(&T, WriterLayouts) -> Result<WriterAdmission<Charge, T::WriterInput>, E>,
    ) -> Result<LinCowCellWriteTxn<'_, T, R, U, Charge>, E> {
        let guard = self.write.lock().unwrap();
        let admission = admit(&guard.data, Self::writer_allocation_layouts())?;
        Ok(self.create_writer(guard, admission))
    }

    /// Admit original shells only after acquiring the writer without waiting.
    ///
    /// Contention or poison returns None without invoking admission or allocating.
    /// Use `is_poisoned` to distinguish poison from physical contention.
    pub fn try_write_charged<E>(
        &self,
        admit: impl FnOnce(&T, WriterLayouts) -> Result<WriterAdmission<Charge, T::WriterInput>, E>,
    ) -> Result<Option<LinCowCellWriteTxn<'_, T, R, U, Charge>>, E> {
        let Some(acquired) = self.try_acquire_writer() else {
            return Ok(None);
        };
        match acquired.try_write_charged(admit) {
            Ok(writer) => Ok(Some(writer)),
            Err((acquired, error)) => {
                drop(acquired);
                match error {
                    WriterAdmissionError::Poisoned => Ok(None),
                    WriterAdmissionError::Refused(error) => Err(error),
                }
            }
        }
    }

    /// Wait for the original mutex without constructing a cursor or invoking a callback.
    /// Poison remains in the actual acquired owner until construction rejects it.
    pub fn acquire_writer(&self) -> LinCowCellWriterAcquisition<'_, T, R, U, Charge> {
        let (guard, poisoned) = match self.write.lock() {
            Ok(guard) => (guard, false),
            Err(error) => (error.into_inner(), true),
        };
        LinCowCellWriterAcquisition {
            guard,
            caller: self,
            poisoned,
        }
    }

    /// Acquire the original mutex before planning, admission or construction.
    /// Only contention returns `None`. Poison remains in the acquired owner and
    /// is rejected before admission; callers can bind its real release first.
    pub fn try_acquire_writer(&self) -> Option<LinCowCellWriterAcquisition<'_, T, R, U, Charge>> {
        let (guard, poisoned) = match self.write.try_lock() {
            Ok(guard) => (guard, false),
            Err(TryLockError::WouldBlock) => return None,
            Err(TryLockError::Poisoned(error)) => (error.into_inner(), true),
        };
        Some(LinCowCellWriterAcquisition {
            guard,
            caller: self,
            poisoned,
        })
    }

    fn create_writer<'a>(
        &'a self,
        guard: MutexGuard<'a, WriteState<T, R, Charge>>,
        admission: WriterAdmission<Charge, T::WriterInput>,
    ) -> LinCowCellWriteTxn<'a, T, R, U, Charge> {
        // Field order also releases the writer lock before shell refunds when
        // create_writer unwinds. A refund may invoke arbitrary Waker::wake code.
        let construction = (
            guard,
            Reserved::new(admission.charges.cursor),
            Reserved::new(admission.charges.reader),
        );
        let value = construction.0.data.create_writer(admission.input);
        let (guard, work, next) = construction;
        let work = work.initialize(value);
        LinCowCellWriteTxn {
            caller: self,
            work,
            next,
            base: guard.current.clone(),
            guard,
        }
    }

    /// Acquire the exact original writer without validating or releasing it.
    ///
    /// Foreign roots and contention return without acquiring a mutex. Stale
    /// generations and poison are checked by the returned original acquisition.
    /// Aggregate callers can bind that actual guard to their release source
    /// before validation, then retain refusal cleanup through enclosing fences.
    pub fn try_acquire_owned(
        &self,
        owned: LinCowCellOwned<T, R, U, Charge>,
    ) -> OwnedAcquireResult<'_, T, R, U, Charge> {
        self.acquire_owned(owned, false)
    }

    /// Reacquire unchanged original roots for a retained publication owner.
    /// An unrelated outer unwind may abandon this private cursor without
    /// poisoning untouched roots. Mutable access and joint publication arm
    /// permanent mutation poison before exposing or modifying original data.
    /// Every refusal retains the same original cursor and physical ownership.
    pub fn try_acquire_owned_retained(
        &self,
        owned: LinCowCellOwned<T, R, U, Charge>,
    ) -> OwnedAcquireResult<'_, T, R, U, Charge> {
        self.acquire_owned(owned, true)
    }

    fn acquire_owned(
        &self,
        owned: LinCowCellOwned<T, R, U, Charge>,
        retained: bool,
    ) -> OwnedAcquireResult<'_, T, R, U, Charge> {
        if !Shared::ptr_eq(&self.write, &owned.root) {
            return Err((owned, OwnedWriteError::Changed));
        }
        let acquired = if retained {
            self.write.try_lock_retained()
        } else {
            self.write.try_lock()
        };
        let (guard, poisoned) = match acquired {
            Ok(guard) => (guard, false),
            Err(TryLockError::WouldBlock) => return Err((owned, OwnedWriteError::Busy)),
            Err(TryLockError::Poisoned(error)) => (error.into_inner(), true),
        };
        Ok(LinCowCellOwnedAcquisition {
            guard,
            owned,
            caller: self,
            poisoned,
        })
    }

    /// Adopt an original writer for a single-owner operation.
    ///
    /// This composes acquisition and validation, unlocking on refusal. Aggregate
    /// publishers use `try_acquire_owned` to retain actual refusal custody.
    pub fn try_write_owned(
        &self,
        owned: LinCowCellOwned<T, R, U, Charge>,
    ) -> OwnedWriteResult<'_, T, R, U, Charge> {
        self.try_acquire_owned(owned)?
            .validate()
            .map_err(|(acquired, error)| (acquired.abort(), error))
    }

    /// Whether the original writer mutex is poisoned.
    pub fn is_poisoned(&self) -> bool {
        self.write.is_poisoned()
    }

    fn commit(&self, write: LinCowCellWriteTxn<T, R, U, Charge>) {
        let LinCowCellWriteTxn {
            caller: _caller,
            work,
            next,
            base,
            mut guard,
        } = write;

        // Perform every lock and ownership check before pre_commit transfers
        // node ownership. The shell stays private until it is initialized.
        let mut rwguard = self.lock_active();
        assert!(Shared::ptr_eq(&base, &guard.current));
        assert!(Shared::ptr_eq(&base, &rwguard));
        assert!(base.pin.get().is_none());

        // Reclaim the original cursor block, retain its charge through the
        // consuming callback, then initialize the already allocated reader shell.
        let (newdata, cursor_charge) = work
            .into_inner()
            .expect("original cursor must be uniquely owned")
            .consume(|work| guard.data.pre_commit(work, &base.data));
        let new_inner = next.initialize(LinCowCellInner::new(newdata));
        // Only the original writer can reach this link, and the retained base
        // owner prevents destruction while it is set. No reader sets the link.
        base.pin
            .set(new_inner.clone())
            .unwrap_or_else(|_| unreachable!("original generation already has a successor"));
        guard.current = new_inner.clone();
        **rwguard = new_inner;
        // No user charge destructor runs between ownership transfer and reader
        // publication, or under either physical lock. Its shell was already
        // freed before pre_commit.
        drop(guard);
        drop(rwguard);
        drop(base);
        drop(cursor_charge);
    }
}

impl<T, R, U, Charge> LinCowCellReadTxn<'_, T, R, U, Charge> {
    /// Borrow this pinned reader's original family and exact generation.
    /// Retaining the projection needs no new identity allocation or lock.
    pub fn predecessor(&self) -> LinCowCellPredecessor<'_, T, R, Charge> {
        LinCowCellPredecessor {
            root: &self._caller.write,
            base: &self.work,
        }
    }
}

impl<T, R, U, Charge> Deref for LinCowCellReadTxn<'_, T, R, U, Charge> {
    type Target = R;

    #[inline]
    fn deref(&self) -> &R {
        &self.work.data
    }
}

impl<'a, T, R, U, Charge> LinCowCellWriteTxn<'a, T, R, U, Charge>
where
    T: LinCowCellRetainedCommit<R, U>,
{
    /// Move this original writer into caller-owned preparation without callbacks.
    pub fn commit_slot(self) -> LinCowCellCommitSlot<'a, T, R, U, Charge> {
        LinCowCellCommitSlot {
            phase: Some(LinCowCellCommitPhase::Writer(self)),
            ready: false,
        }
    }

    /// Acquire and validate all physical owners before the first transfer.
    /// Aggregate callers retain `commit_slot()` before preparing it in place.
    pub fn prepare_commit(self) -> LinCowCellPreparedCommit<'a, T, R, U, Charge> {
        let mut slot = self.commit_slot();
        slot.prepare();
        slot.into_prepared()
    }

    /// Prepare without waiting for the short active-reader lock.
    /// Contention or poison returns the exact original writer, still held.
    pub fn try_prepare_commit(
        self,
    ) -> Result<LinCowCellPreparedCommit<'a, T, R, U, Charge>, (Self, OwnedWriteError)> {
        let mut slot = self.commit_slot();
        if let Err(error) = slot.try_prepare() {
            let (writer, release) = slot.abort_retaining();
            debug_assert!(release.is_none(), "failed acquisition owned no reader");
            return Err((writer, error));
        }
        Ok(slot.into_prepared())
    }
}

impl<'a, T, R, U, Charge> LinCowCellPreparedCommit<'a, T, R, U, Charge>
where
    T: LinCowCellRetainedCommit<R, U>,
{
    /// Undo preparation without abandoning or reconstructing the original writer.
    /// Only the active-reader guard is released; the original writer stays held.
    pub fn abort(self) -> LinCowCellWriteTxn<'a, T, R, U, Charge> {
        let (writer, release) = self.abort_retaining();
        drop(release);
        writer
    }

    /// Release the reader lock while retaining its notification for aggregate abort.
    /// The returned writer owns the exact unpublished cursor and remains locked.
    pub fn abort_retaining(
        self,
    ) -> (
        LinCowCellWriteTxn<'a, T, R, U, Charge>,
        iroha_allocation::release::DeferredRelease,
    ) {
        let Self {
            caller,
            guard,
            active,
            work,
            next,
            base,
        } = self;
        let ((), release) = active.release_deferred(drop);
        (
            LinCowCellWriteTxn {
                caller,
                guard,
                work,
                next,
                base,
            },
            release,
        )
    }

    /// Install the prepared successor without running any user destructor.
    /// Both physical guards remain owned by the returned published stage.
    pub fn publish(self) -> LinCowCellPublished<'a, T, R, U, Charge> {
        let Self {
            caller: _,
            mut guard,
            mut active,
            work,
            next,
            base,
        } = self;
        // The sealed transfer may touch both original roots. From here until
        // complete publication, an unwind poisons both physical owners.
        guard.begin_retained_mutation();
        active.begin_retained_mutation();
        let ((newdata, engine), cursor_charge) = work
            .into_inner()
            .expect("prepared unique cursor")
            .consume(|work| guard.data.pre_commit_retaining(work, &base.data));
        let new_inner = next.initialize(LinCowCellInner::new(newdata));
        base.pin
            .set(new_inner.clone())
            .unwrap_or_else(|_| unreachable!("prepared original generation"));
        // Each displaced Shared still has the original base owner, so these
        // assignments cannot reclaim a payload or invoke a charge destructor.
        guard.current = new_inner.clone();
        **active = new_inner;
        // Both original roots now name the completed generation. Only retained
        // custody may disarm after this point; ordinary guards remain conservative.
        // Earlier unwind keeps mutation poison armed on the actual primitives.
        guard.complete_retained_mutation();
        active.complete_retained_mutation();
        LinCowCellPublished {
            guard,
            active,
            retirement: LinCowCellCommitRetirement {
                _engine: engine,
                _base: base,
                _cursor_charge: cursor_charge,
                active_release: None,
            },
        }
    }
}

impl<T, R, U, Charge> LinCowCellPublished<'_, T, R, U, Charge>
where
    T: LinCowCellRetainedCommit<R, U>,
{
    /// Release both physical locks, retaining all user cleanup separately.
    /// This does not allocate or destroy any user payload or charge.
    pub fn release(self) -> LinCowCellCommitRetirement<R, T::Retirement, Charge> {
        let Self {
            guard,
            active,
            mut retirement,
        } = self;
        drop(guard);
        retirement.active_release = Some(active.release_deferred(drop).1);
        retirement
    }
}

impl<T, R, U, Charge> AsRef<R> for LinCowCellReadTxn<'_, T, R, U, Charge> {
    #[inline]
    fn as_ref(&self) -> &R {
        &self.work.data
    }
}

impl<T, R, U, Charge> LinCowCellWriteTxn<'_, T, R, U, Charge>
where
    T: LinCowCellCapable<R, U>,
{
    #[inline]
    /// Get the mutable inner of this type
    pub fn get_mut(&mut self) -> &mut U {
        Shared::get_mut(&mut self.work).expect("original cursor must be uniquely owned")
    }

    /// Commit the active changes.
    pub fn commit(self) {
        /* Write our data back to the LinCowCell */
        self.caller.commit(self);
    }

    /// Retain the original unpublished work and release its writer lock.
    /// No publication or reconstruction takes place.
    pub fn detach(self) -> LinCowCellOwned<T, R, U, Charge> {
        let Self {
            caller,
            work,
            next,
            base,
            guard,
        } = self;
        let root = caller.write.clone();
        drop(guard);
        LinCowCellOwned {
            work,
            next,
            base,
            root,
        }
    }
}

impl<T, R, U, Charge> LinCowCellOwned<T, R, U, Charge> {
    /// Freeze-only handle retaining the actual original cursor, not a copy.
    pub(crate) fn retain_work(&self) -> LinCowCellRetainedWork<T, R, U, Charge> {
        LinCowCellRetainedWork {
            work: self.work.clone(),
            base: self.base.clone(),
            root: self.root.clone(),
        }
    }

    /// Admit mutable handoff only after every original frozen reader retires.
    pub(crate) fn work_is_unique(&mut self) -> bool {
        Shared::get_mut(&mut self.work).is_some()
    }

    /// Exclusively borrow the original private cursor; no map lock or copy is needed.
    pub(crate) fn get_mut(&mut self) -> &mut U {
        Shared::get_mut(&mut self.work).expect("original cursor must be uniquely owned")
    }

    /// Borrow the retained original family and predecessor without new custody.
    pub fn predecessor(&self) -> LinCowCellPredecessor<'_, T, R, Charge> {
        LinCowCellPredecessor {
            root: &self.root,
            base: &self.base,
        }
    }

    /// Nonblocking advisory comparison to the target's current reader.
    /// A true observation grants no lease: reacquisition must authenticate again.
    /// Foreign or advanced targets return false, including equal-value ABA.
    pub fn try_matches_current(
        &self,
        target: &LinCowCell<T, R, U, Charge>,
    ) -> Result<bool, OwnedWriteError> {
        let (matches, release) = self.try_matches_current_retaining(target)?;
        drop(release);
        Ok(matches)
    }

    /// Compare the original predecessor and physically release the reader lock,
    /// retaining only that actual acquisition's notification for an outer owner.
    /// Foreign families and unsuccessful probes return no fabricated release.
    /// The observation is advisory and never grants publication authority.
    pub fn try_matches_current_retaining(
        &self,
        target: &LinCowCell<T, R, U, Charge>,
    ) -> Result<(bool, Option<iroha_allocation::release::DeferredRelease>), OwnedWriteError> {
        if !Shared::ptr_eq(&self.root, &target.write) {
            return Ok((false, None));
        }
        let active = target.try_lock_active()?;
        let matches = Shared::ptr_eq(&self.base, &active);
        let ((), release) = active.release_deferred(drop);
        Ok((matches, Some(release)))
    }
}

impl<T, R, U, Charge> LinCowCellWriteTxn<'_, T, R, U, Charge> {
    /// Borrow the original family and predecessor, unaffected by private edits.
    pub fn predecessor(&self) -> LinCowCellPredecessor<'_, T, R, Charge> {
        LinCowCellPredecessor {
            root: &self.caller.write,
            base: &self.base,
        }
    }
}

impl<T, R, U, Charge> AsRef<U> for LinCowCellOwned<T, R, U, Charge> {
    fn as_ref(&self) -> &U {
        &self.work
    }
}

impl<T, R, U, Charge> Deref for LinCowCellWriteTxn<'_, T, R, U, Charge> {
    type Target = U;

    #[inline]
    fn deref(&self) -> &U {
        &self.work
    }
}

impl<T, R, U, Charge> DerefMut for LinCowCellWriteTxn<'_, T, R, U, Charge> {
    #[inline]
    fn deref_mut(&mut self) -> &mut U {
        Shared::get_mut(&mut self.work).expect("original cursor must be uniquely owned")
    }
}

impl<T, R, U, Charge> AsRef<U> for LinCowCellWriteTxn<'_, T, R, U, Charge> {
    #[inline]
    fn as_ref(&self) -> &U {
        &self.work
    }
}

impl<T, R, U, Charge> AsMut<U> for LinCowCellWriteTxn<'_, T, R, U, Charge> {
    #[inline]
    fn as_mut(&mut self) -> &mut U {
        Shared::get_mut(&mut self.work).expect("original cursor must be uniquely owned")
    }
}

impl<'a, T, R, U> LinCowCellWriterAcquisition<'a, T, R, U, Untracked>
where
    T: LinCowCellCapable<R, U>,
{
    /// Construct an untracked successor while retaining this exact acquired lock.
    /// Poison panics before invoking the input constructor.
    pub fn write_with(
        self,
        input: impl FnOnce(&T) -> T::WriterInput,
    ) -> LinCowCellWriteTxn<'a, T, R, U> {
        match self.try_write_charged(|data, _| {
            Ok::<_, std::convert::Infallible>(WriterAdmission {
                charges: WriterCharges {
                    cursor: Untracked,
                    reader: Untracked,
                },
                input: input(data),
            })
        }) {
            Ok(writer) => writer,
            Err((_acquired, WriterAdmissionError::Poisoned)) => {
                panic!("original writer is poisoned")
            }
            Err((_, WriterAdmissionError::Refused(never))) => match never {},
        }
    }
}

impl<T, R, U> LinCowCell<T, R, U, Untracked>
where
    T: LinCowCellCapable<R, U>,
{
    /// Construct an explicitly unaccounted root and generation shell.
    pub fn new(data: T) -> Self {
        Self::new_charged(
            data,
            InitialCharges {
                notification: iroha_allocation::release::ReleaseNotification::default(),
                root: Untracked,
                reader: Untracked,
            },
        )
    }

    /// Construct an explicitly unaccounted input under the original writer lock.
    pub fn write_with(
        &self,
        input: impl FnOnce(&T) -> T::WriterInput,
    ) -> LinCowCellWriteTxn<'_, T, R, U> {
        self.acquire_writer().write_with(input)
    }

    /// Try an unaccounted writer, constructing its input only after locking.
    pub fn try_write_with(
        &self,
        input: impl FnOnce(&T) -> T::WriterInput,
    ) -> Option<LinCowCellWriteTxn<'_, T, R, U>> {
        self.try_write_charged(|data, _| {
            Ok::<_, std::convert::Infallible>(WriterAdmission {
                charges: WriterCharges {
                    cursor: Untracked,
                    reader: Untracked,
                },
                input: input(data),
            })
        })
        .unwrap_or_else(|never| match never {})
    }
}

impl<T, R, U> LinCowCell<T, R, U, Untracked>
where
    T: LinCowCellCapable<R, U, WriterInput = ()>,
{
    /// Begin an explicitly unaccounted writer with unit constructor input.
    pub fn write(&self) -> LinCowCellWriteTxn<'_, T, R, U> {
        self.write_with(|_| ())
    }

    /// Try an unaccounted unit-input writer without waiting.
    pub fn try_write(&self) -> Option<LinCowCellWriteTxn<'_, T, R, U>> {
        self.try_write_with(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::LinCowCell;
    use super::LinCowCellCapable;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread::scope;
    use std::time::Instant;

    #[derive(Debug)]
    struct TestData {
        x: i64,
    }

    #[derive(Debug)]
    struct TestDataReadTxn {
        x: i64,
    }

    #[derive(Debug)]
    struct TestDataWriteTxn {
        x: i64,
    }

    impl LinCowCellCapable<TestDataReadTxn, TestDataWriteTxn> for TestData {
        type WriterInput = ();

        fn create_reader(&self) -> TestDataReadTxn {
            TestDataReadTxn { x: self.x }
        }

        fn create_writer(&self, (): Self::WriterInput) -> TestDataWriteTxn {
            TestDataWriteTxn { x: self.x }
        }

        fn pre_commit(
            &mut self,
            new: TestDataWriteTxn,
            _prev: &TestDataReadTxn,
        ) -> TestDataReadTxn {
            // Update self if needed.
            self.x = new.x;
            // return a new reader.
            TestDataReadTxn { x: new.x }
        }
    }

    #[test]
    fn test_simple_create() {
        let data = TestData { x: 0 };
        let cc = LinCowCell::new(data);

        let cc_rotxn_a = cc.read();
        println!("cc_rotxn_a -> {:?}", cc_rotxn_a);
        assert_eq!(cc_rotxn_a.work.data.x, 0);

        {
            /* Take a write txn */
            let mut cc_wrtxn = cc.write();
            println!("cc_wrtxn -> {:?}", cc_wrtxn);
            assert_eq!(cc_wrtxn.work.x, 0);
            assert_eq!(cc_wrtxn.as_ref().x, 0);
            {
                let mut_ptr = cc_wrtxn.get_mut();
                /* Assert it's 0 */
                assert_eq!(mut_ptr.x, 0);
                mut_ptr.x = 1;
                assert_eq!(mut_ptr.x, 1);
            }
            // Check we haven't mutated the old data.
            assert_eq!(cc_rotxn_a.work.data.x, 0);
        }
        // The writer is dropped here. Assert no changes.
        assert_eq!(cc_rotxn_a.work.data.x, 0);
        {
            /* Take a new write txn */
            let mut cc_wrtxn = cc.write();
            println!("cc_wrtxn -> {:?}", cc_wrtxn);
            assert_eq!(cc_wrtxn.work.x, 0);
            assert_eq!(cc_wrtxn.as_ref().x, 0);
            {
                let mut_ptr = cc_wrtxn.get_mut();
                /* Assert it's 0 */
                assert_eq!(mut_ptr.x, 0);
                mut_ptr.x = 2;
                assert_eq!(mut_ptr.x, 2);
            }
            // Check we haven't mutated the old data.
            assert_eq!(cc_rotxn_a.work.data.x, 0);
            // Now commit
            cc_wrtxn.commit();
        }
        // Should not be perceived by the old txn.
        assert_eq!(cc_rotxn_a.work.data.x, 0);
        let cc_rotxn_c = cc.read();
        // Is visible to the new one though.
        assert_eq!(cc_rotxn_c.work.data.x, 2);
    }

    // == mt tests ==

    fn mt_writer(cc: &LinCowCell<TestData, TestDataReadTxn, TestDataWriteTxn>) {
        let mut last_value: i64 = 0;
        while last_value < 500 {
            let mut cc_wrtxn = cc.write();
            {
                let mut_ptr = cc_wrtxn.get_mut();
                assert!(mut_ptr.x >= last_value);
                last_value = mut_ptr.x;
                mut_ptr.x += 1;
            }
            cc_wrtxn.commit();
        }
    }

    fn rt_writer(cc: &LinCowCell<TestData, TestDataReadTxn, TestDataWriteTxn>) {
        let mut last_value: i64 = 0;
        while last_value < 500 {
            let cc_rotxn = cc.read();
            {
                assert!(cc_rotxn.work.data.x >= last_value);
                last_value = cc_rotxn.work.data.x;
            }
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_multithread_create() {
        let start = Instant::now();
        // Create the new cowcell.
        let data = TestData { x: 0 };
        let cc = LinCowCell::new(data);

        assert!(scope(|scope| {
            let cc_ref = &cc;

            let readers: Vec<_> = (0..7)
                .map(|_| {
                    scope.spawn(move || {
                        rt_writer(cc_ref);
                    })
                })
                .collect();

            let writers: Vec<_> = (0..3)
                .map(|_| {
                    scope.spawn(move || {
                        mt_writer(cc_ref);
                    })
                })
                .collect();

            for h in readers.into_iter() {
                h.join().unwrap();
            }
            for h in writers.into_iter() {
                h.join().unwrap();
            }

            true
        }));

        let end = Instant::now();
        print!("Arc MT create :{:?} ", end - start);
    }

    static GC_COUNT: AtomicUsize = AtomicUsize::new(0);

    #[derive(Debug, Clone)]
    struct TestGcWrapper<T> {
        data: T,
    }

    #[derive(Debug)]
    struct TestGcWrapperReadTxn<T> {
        _data: T,
    }

    #[derive(Debug)]
    struct TestGcWrapperWriteTxn<T> {
        data: T,
    }

    impl<T: Clone> LinCowCellCapable<TestGcWrapperReadTxn<T>, TestGcWrapperWriteTxn<T>>
        for TestGcWrapper<T>
    {
        type WriterInput = ();

        fn create_reader(&self) -> TestGcWrapperReadTxn<T> {
            TestGcWrapperReadTxn {
                _data: self.data.clone(),
            }
        }

        fn create_writer(&self, (): Self::WriterInput) -> TestGcWrapperWriteTxn<T> {
            TestGcWrapperWriteTxn {
                data: self.data.clone(),
            }
        }

        fn pre_commit(
            &mut self,
            new: TestGcWrapperWriteTxn<T>,
            _prev: &TestGcWrapperReadTxn<T>,
        ) -> TestGcWrapperReadTxn<T> {
            // Update self if needed.
            self.data = new.data.clone();
            // return a new reader.
            TestGcWrapperReadTxn {
                _data: self.data.clone(),
            }
        }
    }

    impl<T> Drop for TestGcWrapperReadTxn<T> {
        fn drop(&mut self) {
            // Add to the atomic counter ...
            GC_COUNT.fetch_add(1, Ordering::Release);
        }
    }

    fn test_gc_operation_thread(
        cc: &LinCowCell<TestGcWrapper<i64>, TestGcWrapperReadTxn<i64>, TestGcWrapperWriteTxn<i64>>,
    ) {
        while GC_COUNT.load(Ordering::Acquire) < 50 {
            // thread::sleep(std::time::Duration::from_millis(200));
            {
                let mut cc_wrtxn = cc.write();
                {
                    let mut_ptr = cc_wrtxn.get_mut();
                    mut_ptr.data += 1;
                }
                cc_wrtxn.commit();
            }
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_gc_operation() {
        GC_COUNT.store(0, Ordering::Release);
        let data = TestGcWrapper { data: 0 };
        let cc = LinCowCell::new(data);

        assert!(scope(|scope| {
            let cc_ref = &cc;
            let writers: Vec<_> = (0..3)
                .map(|_| {
                    scope.spawn(move || {
                        test_gc_operation_thread(cc_ref);
                    })
                })
                .collect();

            for h in writers.into_iter() {
                h.join().unwrap();
            }
            true
        }));

        assert!(GC_COUNT.load(Ordering::Acquire) >= 50);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_long_chain_drop_no_stack_overflow() {
        let data = TestData { x: 0 };
        let cc = LinCowCell::new(data);

        // Simulate a read txn that is not dropped.
        let initial_read = cc.read();

        // Create a long chain of versions by committing many writes.
        for i in 0..10000 {
            let mut write_txn = cc.write();
            write_txn.get_mut().x = i;
            write_txn.commit();
        }

        drop(initial_read);

        // Verify the final state is correct.
        let final_read = cc.read();
        assert_eq!(final_read.work.data.x, 9999);
    }
}

#[cfg(test)]
mod tests_linear {
    use super::LinCowCell;
    use super::LinCowCellCapable;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static GC_COUNT: AtomicUsize = AtomicUsize::new(0);

    #[derive(Debug, Clone)]
    struct TestGcWrapper<T> {
        data: T,
    }

    #[derive(Debug)]
    struct TestGcWrapperReadTxn<T> {
        _data: T,
    }

    #[derive(Debug)]
    struct TestGcWrapperWriteTxn<T> {
        data: T,
    }

    impl<T: Clone> LinCowCellCapable<TestGcWrapperReadTxn<T>, TestGcWrapperWriteTxn<T>>
        for TestGcWrapper<T>
    {
        type WriterInput = ();

        fn create_reader(&self) -> TestGcWrapperReadTxn<T> {
            TestGcWrapperReadTxn {
                _data: self.data.clone(),
            }
        }

        fn create_writer(&self, (): Self::WriterInput) -> TestGcWrapperWriteTxn<T> {
            TestGcWrapperWriteTxn {
                data: self.data.clone(),
            }
        }

        fn pre_commit(
            &mut self,
            new: TestGcWrapperWriteTxn<T>,
            _prev: &TestGcWrapperReadTxn<T>,
        ) -> TestGcWrapperReadTxn<T> {
            // Update self if needed.
            self.data = new.data.clone();
            // return a new reader.
            TestGcWrapperReadTxn {
                _data: self.data.clone(),
            }
        }
    }

    impl<T> Drop for TestGcWrapperReadTxn<T> {
        fn drop(&mut self) {
            // Add to the atomic counter ...
            GC_COUNT.fetch_add(1, Ordering::Release);
        }
    }

    /*
     * This tests an important property of the lincowcell over the cow cell
     * that read txns are dropped *in order*.
     */
    #[test]
    fn test_gc_operation_linear() {
        GC_COUNT.store(0, Ordering::Release);
        assert!(GC_COUNT.load(Ordering::Acquire) == 0);
        let data = TestGcWrapper { data: 0 };
        let cc = LinCowCell::new(data);

        // Open a read A.
        let cc_rotxn_a = cc.read();
        let cc_rotxn_a_2 = cc.read();
        // open a write, change and commit
        {
            let mut cc_wrtxn = cc.write();
            {
                let mut_ptr = cc_wrtxn.get_mut();
                mut_ptr.data += 1;
            }
            cc_wrtxn.commit();
        }
        // open a read B.
        let cc_rotxn_b = cc.read();
        // open a write, change and commit
        {
            let mut cc_wrtxn = cc.write();
            {
                let mut_ptr = cc_wrtxn.get_mut();
                mut_ptr.data += 1;
            }
            cc_wrtxn.commit();
        }
        // open a read C
        let cc_rotxn_c = cc.read();

        assert!(GC_COUNT.load(Ordering::Acquire) == 0);

        // drop B
        drop(cc_rotxn_b);

        // gc count should be 0.
        assert!(GC_COUNT.load(Ordering::Acquire) == 0);

        // drop C
        drop(cc_rotxn_c);

        // gc count should be 0
        assert!(GC_COUNT.load(Ordering::Acquire) == 0);

        // Drop the second A, should not trigger yet.
        drop(cc_rotxn_a_2);
        assert!(GC_COUNT.load(Ordering::Acquire) == 0);

        // drop A
        drop(cc_rotxn_a);

        // gc count should be 2 (A + B, C is still live)
        assert!(GC_COUNT.load(Ordering::Acquire) == 2);
    }
}

#[cfg(test)]
mod writer_input_tests {
    use super::{LinCowCell, LinCowCellCapable};

    struct Data(usize);

    impl LinCowCellCapable<usize, Box<usize>> for Data {
        type WriterInput = Box<usize>;

        fn create_reader(&self) -> usize {
            self.0
        }

        fn create_writer(&self, mut input: Self::WriterInput) -> Box<usize> {
            *input += self.0;
            input
        }

        fn pre_commit(&mut self, new: Box<usize>, _previous: &usize) -> usize {
            self.0 = *new;
            self.0
        }
    }

    #[test]
    fn untracked_entry_points_consume_explicit_input_only_under_original_lock() {
        let cell = LinCowCell::new(Data(10));
        let input = Box::new(7);
        let original = input.as_ref() as *const usize;
        let writer = cell.write_with(|data| {
            assert_eq!(data.0, 10);
            assert!(cell
                .try_write_with(|_| panic!("busy constructor input was evaluated"))
                .is_none());
            input
        });
        assert_eq!(writer.as_ref().as_ref() as *const usize, original);
        assert_eq!(**writer, 17);
        writer.commit();
        assert_eq!(*cell.read(), 17);
        let writer = cell
            .try_write_with(|data| {
                assert_eq!(data.0, 17);
                Box::new(3)
            })
            .unwrap();
        assert_eq!(**writer, 20);
        drop(writer);
        assert_eq!(*cell.read(), 17);
    }

    #[test]
    fn original_charged_root_survives_owned_retry_and_cell_destruction() {
        use super::{InitialCharges, OwnedWriteError, Shared, WriterAdmission, WriterCharges};
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        #[derive(Debug)]
        struct Data {
            dropped: Arc<AtomicUsize>,
        }
        impl Drop for Data {
            fn drop(&mut self) {
                self.dropped.fetch_add(1, Ordering::SeqCst);
            }
        }
        impl LinCowCellCapable<u64, u64> for Data {
            type WriterInput = ();
            fn create_reader(&self) -> u64 {
                17
            }
            fn create_writer(&self, (): ()) -> u64 {
                17
            }
            fn pre_commit(&mut self, value: u64, _previous: &u64) -> u64 {
                value
            }
        }
        #[derive(Debug)]
        struct Charge {
            root: bool,
            refunded: Arc<AtomicUsize>,
            payload: Arc<AtomicUsize>,
        }
        impl Drop for Charge {
            fn drop(&mut self) {
                if self.root {
                    assert_eq!(self.payload.load(Ordering::SeqCst), 1);
                    assert_eq!(self.refunded.fetch_add(1, Ordering::SeqCst), 0);
                }
            }
        }
        let dropped = Arc::new(AtomicUsize::new(0));
        let refunded = Arc::new(AtomicUsize::new(0));
        let charge = |root| Charge {
            root,
            refunded: refunded.clone(),
            payload: dropped.clone(),
        };
        let owner = LinCowCell::new_charged(
            Data {
                dropped: dropped.clone(),
            },
            InitialCharges {
                notification: iroha_allocation::release::ReleaseNotification::default(),
                root: charge(true),
                reader: charge(false),
            },
        );
        let admission = |_: &Data, _| {
            Ok::<_, ()>(WriterAdmission {
                charges: WriterCharges {
                    cursor: charge(false),
                    reader: charge(false),
                },
                input: (),
            })
        };
        let writer = owner.write_charged(admission).unwrap();
        let original = &*owner.write as *const _;
        let owned = writer.detach();
        assert!(Shared::ptr_eq(&owner.write, &owned.root));
        let held = owner.write_charged(admission).unwrap();
        let (owned, reason) = owner.try_write_owned(owned).unwrap_err();
        assert_eq!(reason, OwnedWriteError::Busy);
        assert_eq!(&*owned.root as *const _, original);
        drop(held);
        let owned = owner.try_write_owned(owned).unwrap().detach();
        assert_eq!(&*owned.root as *const _, original);
        drop(owner);
        assert_eq!(dropped.load(Ordering::SeqCst), 0);
        assert_eq!(refunded.load(Ordering::SeqCst), 0);
        assert_eq!(*owned.as_ref(), 17);
        drop(owned);
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        assert_eq!(refunded.load(Ordering::SeqCst), 1);
    }
}

#[cfg(test)]
mod identity_preparation_tests {
    use super::*;
    use crate::internals::bptree::cursor::{CursorRead, CursorReadOps, CursorWrite, SuperBlock};
    use crate::internals::bptree::node::allocation_tests::{
        all_refunded, prepaid, record, without_allocations, Charge,
    };
    use crate::internals::bptree::node::assert_released;
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    type TreeCell =
        LinCowCell<SuperBlock<usize, usize>, CursorRead<usize, usize>, CursorWrite<usize, usize>>;

    fn tree() -> TreeCell {
        // The unique original tree is immediately installed in its linear owner.
        LinCowCell::new(unsafe { SuperBlock::new() })
    }

    #[test]
    fn retained_predecessor_observation_defers_only_the_original_acquired_reader() {
        let release_budget = iroha_allocation::AllocationBudget::new(
            iroha_allocation::release::ReleaseRegistration::allocation_layout().size(),
        );
        let mut release_registration_1 = crate::release_test_support::registration(&release_budget);

        use std::{
            future::Future,
            pin::Pin,
            task::{Context, Waker},
        };
        let cell = tree();
        let foreign = tree();
        let owned = cell.write().detach();
        let mut wait = cell
            .observe_reader_release()
            .wait_for_release(&mut release_registration_1);
        assert!(Pin::new(&mut wait)
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        let (matches, release) =
            without_allocations(|| owned.try_matches_current_retaining(&cell).unwrap());
        assert!(matches);
        assert!(release.is_some());
        assert!(
            cell.active.try_lock().is_ok(),
            "actual reader already unlocked"
        );
        assert!(Pin::new(&mut wait)
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        let (matches, foreign_release) =
            without_allocations(|| owned.try_matches_current_retaining(&foreign).unwrap());
        assert!(!matches && foreign_release.is_none());
        {
            let _active = cell.active.lock().unwrap();
            assert!(matches!(
                without_allocations(|| owned.try_matches_current_retaining(&cell)),
                Err(OwnedWriteError::Busy)
            ));
        }
        assert!(Pin::new(&mut wait)
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        without_allocations(|| drop(release));
        assert!(Pin::new(&mut wait)
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready());
        cell.write().commit();
        let (matches, stale_release) =
            without_allocations(|| owned.try_matches_current_retaining(&cell).unwrap());
        assert!(
            !matches && stale_release.is_some(),
            "stale base still acquired the original reader"
        );
        drop(stale_release);
        assert!(catch_unwind(AssertUnwindSafe(|| {
            let _active = cell.active.lock().unwrap();
            panic!("actual reader poison");
        }))
        .is_err());
        assert!(matches!(
            owned.try_matches_current_retaining(&cell),
            Err(OwnedWriteError::Poisoned)
        ));
        drop((owned, cell, foreign));
        assert_released();
    }

    #[test]
    fn reader_wait_survives_refused_writer_release_and_registration_races() {
        let release_budget = iroha_allocation::AllocationBudget::new(
            2 * iroha_allocation::release::ReleaseRegistration::allocation_layout().size(),
        );
        let mut release_registration_1 = crate::release_test_support::registration(&release_budget);
        let mut release_registration_2 = crate::release_test_support::registration(&release_budget);

        use std::{
            future::Future,
            pin::Pin,
            task::{Context, Waker},
        };
        let cell = tree();
        let foreign = tree();
        let pinned = cell.read();
        let active = cell.lock_active();
        let observation = without_allocations(|| cell.observe_reader_release());
        let mut wait = observation
            .clone()
            .wait_for_release(&mut release_registration_1);
        assert!(Pin::new(&mut wait)
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        let mut writer = cell.write();
        writer.insert(1, 7);
        let cursor = &*writer.work as *const _;
        let (writer, error) = without_allocations(|| writer.try_prepare_commit())
            .err()
            .expect("actual reader mutex held");
        assert_eq!(error, OwnedWriteError::Busy);
        let owned = without_allocations(|| writer.detach());
        assert_eq!(owned.as_ref() as *const _, cursor);
        drop(pinned);
        drop(foreign.read());
        assert!(
            Pin::new(&mut wait)
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending(),
            "neither writer release, snapshot retirement nor another map releases this mutex"
        );
        let mut late = observation.wait_for_release(&mut release_registration_2);
        drop(active);
        assert!(Pin::new(&mut wait)
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready());
        assert!(Pin::new(&mut late)
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready());
        let writer = cell
            .try_write_owned(owned)
            .unwrap_or_else(|_| panic!("same original owner"));
        assert_eq!(&*writer.work as *const _, cursor);
        drop(
            writer
                .try_prepare_commit()
                .unwrap_or_else(|_| panic!("reader released"))
                .publish()
                .release(),
        );
        assert_eq!(cell.read().search(&1), Some(&7));
        drop((cell, foreign));
        assert_released();
    }

    #[test]
    fn reader_release_covers_reads_advice_abort_and_both_commit_paths() {
        let release_budget = iroha_allocation::AllocationBudget::new(
            2 * iroha_allocation::release::ReleaseRegistration::allocation_layout().size(),
        );
        let mut release_registration_1 = crate::release_test_support::registration(&release_budget);
        let mut release_registration_2 = crate::release_test_support::registration(&release_budget);

        use std::{
            future::Future,
            pin::Pin,
            task::{Context, Waker},
        };
        let cell = tree();
        let owned = cell.write().detach();
        for mode in 0..6 {
            let prepared = (mode >= 3).then(|| cell.write().prepare_commit());
            let mut wait = cell
                .observe_reader_release()
                .wait_for_release(&mut release_registration_1);
            assert!(Pin::new(&mut wait)
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
            match mode {
                0 => drop(cell.read()),
                1 => drop(cell.try_read().expect("native try read")),
                2 => assert_eq!(owned.try_matches_current(&cell), Ok(true)),
                3 => drop(prepared.unwrap().abort()),
                4 => drop(prepared.unwrap()),
                _ => {
                    let retirement = without_allocations(|| prepared.unwrap().publish().release());
                    assert!(cell.active.try_lock().is_ok());
                    assert!(cell.write.try_lock().is_ok());
                    assert!(
                        Pin::new(&mut wait)
                            .poll(&mut Context::from_waker(Waker::noop()))
                            .is_pending(),
                        "release retains notification with aggregate retirement"
                    );
                    drop(retirement);
                }
            }
            assert!(Pin::new(&mut wait)
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_ready());
        }
        let mut wait = cell
            .observe_reader_release()
            .wait_for_release(&mut release_registration_2);
        cell.write().commit();
        assert!(Pin::new(&mut wait)
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready());
        drop((owned, cell));
        assert_released();
    }

    #[test]
    fn reader_abort_retains_notification_until_the_original_writer_releases() {
        let release_budget = iroha_allocation::AllocationBudget::new(
            iroha_allocation::release::ReleaseRegistration::allocation_layout().size(),
        );
        let mut release_registration_1 = crate::release_test_support::registration(&release_budget);

        use std::{
            future::Future,
            pin::Pin,
            task::{Context, Waker},
        };
        let cell = tree();
        let mut writer = cell.write();
        writer.insert(1, 17);
        let cursor = &*writer.work as *const _;
        let prepared = writer.prepare_commit();
        let mut wait = cell
            .observe_reader_release()
            .wait_for_release(&mut release_registration_1);
        assert!(Pin::new(&mut wait)
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        let (writer, release) = without_allocations(|| prepared.abort_retaining());
        assert_eq!(&*writer.work as *const _, cursor);
        assert!(cell.active.try_lock().is_ok());
        assert!(cell.write.try_lock().is_err());
        assert!(Pin::new(&mut wait)
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        let owned = without_allocations(|| writer.detach());
        assert!(cell.write.try_lock().is_ok());
        assert!(Pin::new(&mut wait)
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending());
        drop(release);
        assert!(Pin::new(&mut wait)
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready());
        let writer = cell
            .try_write_owned(owned)
            .unwrap_or_else(|_| panic!("original retry"));
        assert_eq!(&*writer.work as *const _, cursor);
        drop(writer.prepare_commit().publish().release());
        assert_eq!(cell.read().search(&1), Some(&17));
        drop(cell);
        assert_released();
    }

    #[test]
    fn reader_wake_unwind_preserves_physical_poison_and_original_commit() {
        let release_budget = iroha_allocation::AllocationBudget::new(
            iroha_allocation::release::ReleaseRegistration::allocation_layout().size(),
        );
        let mut release_registration_1 = crate::release_test_support::registration(&release_budget);

        use std::{
            future::Future,
            pin::Pin,
            task::{Context, Wake, Waker},
        };
        struct Probe {
            cell: Arc<TreeCell>,
            calls: AtomicUsize,
        }
        impl Wake for Probe {
            fn wake(self: Arc<Self>) {
                assert!(self.cell.active.try_lock().is_ok());
                assert!(self.cell.write.try_lock().is_ok());
                self.calls.fetch_add(1, Ordering::SeqCst);
                panic!("native reader wake interruption");
            }
        }
        for retained in [false, true] {
            let cell = Arc::new(tree());
            let mut writer = cell.write();
            writer.insert(1, 7);
            let observation = cell.observe_reader_release();
            let mut wait = observation
                .clone()
                .wait_for_release(&mut release_registration_1);
            let probe = Arc::new(Probe {
                cell: Arc::clone(&cell),
                calls: AtomicUsize::new(0),
            });
            let waker = Waker::from(Arc::clone(&probe));
            assert!(Pin::new(&mut wait)
                .poll(&mut Context::from_waker(&waker))
                .is_pending());
            assert!(catch_unwind(AssertUnwindSafe(|| {
                if retained {
                    drop(writer.prepare_commit().publish().release());
                } else {
                    writer.commit();
                }
            }))
            .is_err());
            assert_eq!(probe.calls.load(Ordering::SeqCst), 1);
            assert!(!cell.active.is_poisoned());
            assert!(!cell.is_poisoned());
            assert!(!observation.is_poisoned());
            assert!(Pin::new(&mut wait)
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_ready());
            assert_eq!(cell.read().search(&1), Some(&7));
            drop((waker, probe, cell));
            assert_released();
        }
    }

    #[test]
    fn original_family_clones_allocate_nothing_and_retain_charged_root_until_actual_free() {
        struct Data(Arc<AtomicUsize>);
        impl Drop for Data {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        impl LinCowCellCapable<usize, usize> for Data {
            type WriterInput = ();
            fn create_reader(&self) -> usize {
                7
            }
            fn create_writer(&self, (): ()) -> usize {
                7
            }
            fn pre_commit(&mut self, value: usize, _: &usize) -> usize {
                value
            }
        }
        // Only the original root is observed here. Its layout includes this
        // original non-Clone charge, and the System observer proves actual free.
        struct RootCharge {
            _original: Option<Charge>,
        }
        type Cell = LinCowCell<Data, usize, usize, RootCharge>;
        let drops = Arc::new(AtomicUsize::new(0));
        let mut funding = prepaid();
        let root = funding.take_allocation_charge(Cell::initial_allocation_layouts().root);
        let cell = Cell::new_charged(
            Data(drops.clone()),
            InitialCharges {
                notification: iroha_allocation::release::ReleaseNotification::default(),
                root: RootCharge {
                    _original: Some(root),
                },
                reader: RootCharge { _original: None },
            },
        );
        let (family, clone) = without_allocations(|| {
            let family = cell.family();
            let clone = family.clone();
            assert!(family.matches(&cell));
            assert!(family.same_family(&clone));
            (family, clone)
        });
        let owned = cell
            .write_charged(|_, _| {
                Ok::<_, ()>(WriterAdmission {
                    charges: WriterCharges {
                        cursor: RootCharge { _original: None },
                        reader: RootCharge { _original: None },
                    },
                    input: (),
                })
            })
            .unwrap()
            .detach();
        let (predecessor, predecessor_clone) = without_allocations(|| {
            let predecessor = owned.predecessor().retain();
            let clone = predecessor.clone();
            assert_eq!(predecessor, clone);
            assert!(predecessor.matches(&owned.predecessor()));
            (predecessor, clone)
        });
        drop(owned);
        without_allocations(|| drop(cell));
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        assert!(!record(0).freed && !record(0).refunded);
        without_allocations(|| drop(family));
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        assert!(!record(0).freed && !record(0).refunded);
        without_allocations(|| drop(clone));
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        assert!(!record(0).freed && !record(0).refunded);
        without_allocations(|| drop(predecessor));
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        without_allocations(|| drop(predecessor_clone));
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert!(record(0).freed && record(0).refunded);
        all_refunded(&funding);
    }

    #[test]
    fn original_nonblocking_read_retains_generation_and_distinguishes_busy_from_poison() {
        let cell = tree();
        let mut writer = cell.write();
        writer.insert(1, 7);
        writer.commit();
        let read = without_allocations(|| cell.try_read().expect("available reader"));
        {
            let active = cell.active.lock().unwrap();
            assert!(Shared::ptr_eq(&read.work, &active));
            without_allocations(|| {
                assert!(matches!(cell.try_read(), Err(OwnedWriteError::Busy)));
            });
        }
        let mut writer = cell.write();
        writer.insert(1, 8);
        // An unpublished writer does not prevent observing the original reader.
        let same = without_allocations(|| cell.try_read().expect("independent reader lock"));
        assert!(Shared::ptr_eq(&read.work, &same.work));
        writer.commit();
        let current = without_allocations(|| cell.try_read().expect("published reader"));
        assert!(!Shared::ptr_eq(&read.work, &current.work));
        assert_eq!(read.as_ref().search(&1), Some(&7));
        assert_eq!(current.as_ref().search(&1), Some(&8));
        assert!(catch_unwind(AssertUnwindSafe(|| {
            let _active = cell.active.lock().unwrap();
            panic!("injected active reader poison");
        }))
        .is_err());
        without_allocations(|| {
            assert!(matches!(cell.try_read(), Err(OwnedWriteError::Poisoned)));
        });
        assert!(!cell.is_poisoned(), "reader refusal does not poison writer");
        drop(current);
        drop(same);
        drop(read);
        drop(cell);
        assert_released();
    }

    #[test]
    fn original_preparation_busy_and_abort_preserve_writer_cursor_base_and_next_shell() {
        let cell = tree();
        let foreign = tree();
        let original_read = cell.read();
        let mut writer = cell.write();
        writer.insert(1, 7);
        let work = &*writer.work as *const _;
        let base = &*writer.base as *const _;
        let active = cell.active.lock().unwrap();
        let writer = without_allocations(|| {
            let (writer, reason) = match writer.try_prepare_commit() {
                Err(refusal) => refusal,
                Ok(_) => panic!("held active lock must refuse without waiting"),
            };
            assert_eq!(reason, OwnedWriteError::Busy);
            assert_eq!(&*writer.work as *const _, work);
            assert_eq!(&*writer.base as *const _, base);
            assert!(cell.write.try_lock().is_err(), "same writer remains held");
            writer
        });
        let owned = without_allocations(|| writer.detach());
        without_allocations(|| {
            assert_eq!(owned.try_matches_current(&cell), Err(OwnedWriteError::Busy));
            assert_eq!(owned.try_matches_current(&foreign), Ok(false));
        });
        drop(active);
        let writer = without_allocations(|| {
            cell.try_write_owned(owned)
                .unwrap_or_else(|_| panic!("original reacquisition"))
        });
        let prepared = without_allocations(|| {
            writer
                .try_prepare_commit()
                .unwrap_or_else(|_| panic!("prepare after release"))
        });
        assert!(cell.active.try_lock().is_err());
        let writer = without_allocations(|| prepared.abort());
        assert!(cell.active.try_lock().is_ok());
        assert!(cell.write.try_lock().is_err());
        assert_eq!(&*writer.work as *const _, work);
        assert_eq!(&*writer.base as *const _, base);
        assert_eq!(writer.search(&1), Some(&7));
        assert_eq!(original_read.as_ref().search(&1), None);
        // Blocking preparation uses the same reversible validation/transfer path.
        let writer = without_allocations(|| writer.prepare_commit().abort());
        assert_eq!(&*writer.work as *const _, work);
        let retirement = without_allocations(|| {
            writer
                .try_prepare_commit()
                .unwrap_or_else(|_| panic!("same original next shell"))
                .publish()
                .release()
        });
        assert_eq!(cell.read().as_ref().search(&1), Some(&7));
        assert_eq!(original_read.as_ref().search(&1), None);
        drop(retirement);
        drop(original_read);
        drop(cell);
        drop(foreign);
        assert_released();
    }

    #[test]
    fn original_preparation_poison_returns_held_writer_without_refunding_or_poisoning_it() {
        let cell = tree();
        let mut writer = cell.write();
        writer.insert(1, 7);
        let work = &*writer.work as *const _;
        assert!(catch_unwind(AssertUnwindSafe(|| {
            let _active = cell.active.lock().unwrap();
            panic!("injected active-lock poison");
        }))
        .is_err());
        let writer = without_allocations(|| {
            let (writer, reason) = match writer.try_prepare_commit() {
                Err(refusal) => refusal,
                Ok(_) => panic!("poisoned active lock must refuse"),
            };
            assert_eq!(reason, OwnedWriteError::Poisoned);
            assert_eq!(&*writer.work as *const _, work);
            assert!(cell.write.try_lock().is_err());
            assert!(
                !cell.is_poisoned(),
                "caller still owns healthy physical writer"
            );
            writer
        });
        let owned = without_allocations(|| writer.detach());
        without_allocations(|| {
            assert_eq!(
                owned.try_matches_current(&cell),
                Err(OwnedWriteError::Poisoned)
            );
            assert_eq!(owned.as_ref() as *const _, work);
        });
        drop(owned);
        assert!(!cell.is_poisoned());
        drop(cell);
        assert_released();
    }
}

#[cfg(test)]
mod commit_slot_tests;

#[cfg(all(test, not(feature = "dhat-heap"), not(miri)))]
mod retained_mutex_tests;

#[cfg(all(test, not(feature = "dhat-heap"), not(miri)))]
#[path = "reader_release_tests.rs"]
mod reader_release_tests;
