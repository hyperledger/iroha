//! Opaque local identity for one storage owner's published current/undo pair.

use crate::{BlockMode, ReleaseGuard, ReleaseNotification, ReleaseWait};
use concread::bptree::{AllocationDemand, PlanningError};
use iroha_allocation::shared::Shared;
use iroha_allocation::{AllocationCharge, AllocationReservation};
use std::sync::{Mutex, TryLockError};

type Identity<T> = Shared<T, Option<AllocationCharge>>;

struct Owner;
struct Version;

/// Why a detached journal could not prepare its exact original publication.
/// These are local installation conditions, not consensus validity verdicts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicationPreparationError<E> {
    /// An original writer or the joint publication identity is already held.
    Busy(ReleaseWait),
    /// An original writer or joint publication panicked; reconstruct this local owner.
    Poisoned,
    /// The target owner or its jointly published current/undo pair changed.
    Changed,
    /// The caller refused the complete installation allocation/retention budget.
    Admission(E),
}

impl<E: std::fmt::Display> std::fmt::Display for PublicationPreparationError<E> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Busy(_) => formatter.write_str("publication writer is busy"),
            Self::Poisoned => formatter.write_str("publication owner is poisoned"),
            Self::Changed => formatter.write_str("publication owner changed"),
            Self::Admission(original) => {
                write!(formatter, "publication admission refused: {original}")
            }
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for PublicationPreparationError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Admission(original) => Some(original),
            Self::Busy(_) | Self::Poisoned | Self::Changed => None,
        }
    }
}

/// Successful preparation or the exact original journal and its local refusal.
/// The error retains custody so a caller can defer without rebuilding execution.
pub type PublicationPreparationResult<Prepared, Journal, E, Installation> = Result<
    Prepared,
    (
        Journal,
        PublicationPreparationError<E>,
        PublicationCleanup<Installation>,
    ),
>;

/// Original notifications and admission retained after a refused or aborted pair.
/// This owns no physical lock. The aggregate must keep it until all enclosing
/// participants have released, including on an error return. No source is
/// fabricated for an acquisition that did not happen.
#[must_use = "retain original cleanup through the enclosing publication fences"]
pub struct PublicationCleanup<Installation> {
    pub(crate) _readers: [Option<iroha_allocation::release::DeferredRelease>; 2],
    pub(crate) _writers: [Option<iroha_allocation::release::DeferredRelease>; 2],
    pub(crate) writer_batches: [Option<iroha_allocation::release::DeferredReleaseBatch>; 2],
    pub(crate) identities: [Option<IdentityRetirement>; 2],
    pub(crate) installation: Option<Installation>,
}

impl<I> PublicationCleanup<I> {
    pub(crate) fn empty() -> Self {
        Self {
            _readers: [None, None],
            _writers: [None, None],
            writer_batches: [None, None],
            identities: [None, None],
            installation: None,
        }
    }
}

impl<E> PublicationPreparationError<E> {
    /// Classify failed physical acquisition using its pre-probe observation.
    ///
    /// A writer that unwound may have poisoned an underlying lock whose try API
    /// reports only absence. Such an owner needs reconstruction, not another
    /// wait for a release that already happened and can never happen again.
    pub fn after_failed_acquisition(wait: ReleaseWait) -> Self {
        if wait.is_poisoned() {
            Self::Poisoned
        } else {
            Self::Busy(wait)
        }
    }
}

pub(crate) struct NextPublication(Identity<Version>);

impl NextPublication {
    /// Allocate the next identity before the first visible component is changed.
    pub(crate) fn new() -> Self {
        Self(Shared::new(Version, None))
    }

    pub(crate) fn allocation_layout() -> std::alloc::Layout {
        Identity::<Version>::layout()
    }

    pub(crate) fn try_from_charge(
        charge: AllocationCharge,
    ) -> Result<Self, (AllocationCharge, iroha_allocation::shared::ReservationError)> {
        match Shared::try_new(Version, Some(charge)) {
            Ok(original) => Ok(Self(original)),
            Err((_, Some(charge), error)) => Err((charge, error)),
            Err((_, None, _)) => unreachable!("original exact successor charge"),
        }
    }

    pub(crate) fn allocation_demand() -> Result<AllocationDemand, PlanningError> {
        let mut demand = AllocationDemand::new();
        demand.add_layout(Identity::<Version>::layout())?;
        Ok(demand)
    }
}

pub(crate) struct Publication {
    owner: Identity<Owner>,
    version: Mutex<Identity<Version>>,
    released: ReleaseNotification,
}

pub(crate) struct CapturedPublication {
    owner: Identity<Owner>,
    version: Identity<Version>,
}

/// Exact identity mutex retained before any participant transfers ownership.
pub(crate) struct PreparedIdentity<'a> {
    version: ReleaseGuard<'a, std::sync::MutexGuard<'a, Identity<Version>>>,
}

/// Released identity and original predecessor storage, retained through cleanup.
pub(crate) struct IdentityRetirement {
    _version: Option<Identity<Version>>,
    _release: iroha_allocation::release::DeferredRelease,
}

impl PreparedIdentity<'_> {
    pub(crate) fn abort(self) -> IdentityRetirement {
        let ((), release) = self.version.release_deferred(drop);
        IdentityRetirement {
            _version: None,
            _release: release,
        }
    }

    /// Transfer all participants under the already acquired identity mutex.
    /// Callbacks must only move ownership and release physical locks; arbitrary
    /// retirement stays with the returned owner after the enclosing fences.
    pub(crate) fn publish_retaining<Published, Retirement>(
        mut self,
        next: NextPublication,
        publish: impl FnOnce() -> Published,
        release: impl FnOnce(Published) -> Retirement,
    ) -> (Retirement, IdentityRetirement) {
        let published = publish();
        let version = std::mem::replace(&mut **self.version, next.0);
        let retirement = release(published);
        let ((), released) = self.version.release_deferred(drop);
        (
            retirement,
            IdentityRetirement {
                _version: Some(version),
                _release: released,
            },
        )
    }
}

/// Opaque local equality of a block's original owner, predecessor and mode.
///
/// Capturing this identity borrows no values and acquires no locks. Equality
/// remains stable while a block stages changes; publication rotates the captured
/// current/undo predecessor even if values remain equal. This observation grants
/// no mutation or publication authority and is not a portable state commitment.
pub struct BlockPublicationIdentity {
    predecessor: CapturedPublication,
    mode: BlockMode,
}

impl BlockPublicationIdentity {
    pub(crate) fn capture(predecessor: &CapturedPublication, mode: BlockMode) -> Self {
        Self {
            predecessor: CapturedPublication {
                owner: predecessor.owner.clone(),
                version: predecessor.version.clone(),
            },
            mode,
        }
    }
}

impl std::fmt::Debug for BlockPublicationIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BlockPublicationIdentity")
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

impl PartialEq for BlockPublicationIdentity {
    fn eq(&self, other: &Self) -> bool {
        self.mode == other.mode && self.predecessor.same_as(&other.predecessor)
    }
}

impl Eq for BlockPublicationIdentity {}

impl Publication {
    pub(crate) fn new() -> Self {
        Self::with_initial_controls(
            Shared::new(Owner, None),
            Shared::new(Version, None),
            ReleaseNotification::default(),
        )
    }

    fn with_initial_controls(
        owner: Identity<Owner>,
        version: Identity<Version>,
        released: ReleaseNotification,
    ) -> Self {
        let version = Mutex::new(version);
        // Some platforms allocate mutex internals on first acquisition. Perform
        // that construction here so a cold nonblocking observation or refusal
        // cannot allocate. This is initialization, not a publication release.
        // TODO: fund native mutex internals along with the remaining lock owners;
        // the three explicit initial layouts do not include platform internals.
        drop(
            version
                .lock()
                .expect("new publication mutex cannot be poisoned"),
        );
        Self {
            owner,
            version,
            released,
        }
    }

    pub(crate) fn allocation_demand() -> Result<AllocationDemand, PlanningError> {
        let mut demand = NextPublication::allocation_demand()?;
        demand.add_layout(Identity::<Owner>::layout())?;
        demand.add_layout(ReleaseNotification::allocation_layout::<AllocationCharge>())?;
        Ok(demand)
    }

    pub(crate) fn initial_layouts() -> [std::alloc::Layout; 3] {
        [
            Identity::<Owner>::layout(),
            Identity::<Version>::layout(),
            ReleaseNotification::allocation_layout::<AllocationCharge>(),
        ]
    }

    /// Build initial controls from the enclosing exact reservation. Partial
    /// physical failure retires every constructed control before refunding it.
    pub(crate) fn try_from_original(
        reservation: &mut AllocationReservation,
    ) -> Result<Self, iroha_allocation::shared::ReservationError> {
        let [owner_layout, version_layout, release_layout] = Self::initial_layouts();
        let owner_charge = reservation
            .try_split(owner_layout)
            .expect("original owner demand");
        let owner = Shared::try_new(Owner, Some(owner_charge)).map_err(|(_, charge, error)| {
            drop(charge);
            error
        })?;
        let version_charge = reservation
            .try_split(version_layout)
            .expect("original version demand");
        let version =
            Shared::try_new(Version, Some(version_charge)).map_err(|(_, charge, error)| {
                drop(charge);
                error
            })?;
        let release_charge = reservation
            .try_split(release_layout)
            .expect("original release demand");
        let released =
            ReleaseNotification::try_new_charged(release_charge).map_err(|(charge, error)| {
                drop(charge);
                error
            })?;
        Ok(Self::with_initial_controls(owner, version, released))
    }

    fn lock_version(&self) -> ReleaseGuard<'_, std::sync::MutexGuard<'_, Identity<Version>>> {
        self.released
            .poisoning_guard(self.version.lock().expect("MV publication lock poisoned"))
    }

    /// Observe the original identity with an optional protected-pointer check.
    /// The private callback may only compare already retained pointers or return
    /// true for a pure identity observation. Reader creation, collector pinning,
    /// reclamation and payload code must remain outside this short lock. A map
    /// reader brackets both physical reads with equal opaque observations.
    pub(crate) fn try_capture_reads(
        &self,
        still_current: impl FnOnce() -> bool,
    ) -> Result<CapturedPublication, PublicationPreparationError<std::convert::Infallible>> {
        let wait = self.released.observe();
        let version = match self.version.try_lock() {
            Ok(guard) => self.released.poisoning_guard(guard),
            Err(TryLockError::WouldBlock) => return Err(PublicationPreparationError::Busy(wait)),
            Err(TryLockError::Poisoned(_)) => return Err(PublicationPreparationError::Poisoned),
        };
        if !still_current() {
            return Err(PublicationPreparationError::Changed);
        }
        Ok(CapturedPublication {
            owner: self.owner.clone(),
            version: (*version).clone(),
        })
    }

    // Call only after acquiring the original current and undo writers. The
    // published pair cannot change while those writers remain owned.
    pub(crate) fn capture(&self) -> CapturedPublication {
        CapturedPublication {
            owner: self.owner.clone(),
            version: (*self.lock_version()).clone(),
        }
    }

    // Lock order is original data writers, then this identity lock. Observation
    // takes only this lock and must never acquire a data writer while holding it.
    // All mutation paths use this short lock across their actual publication.
    // A successor may acquire the data writers as commit releases them, but its
    // identity capture waits until BOTH publications and this rotation finish.
    /// Install an aggregate while every physical writer remains retained, then
    /// rotate identity before unlocking any participant. Retirement and its
    /// arbitrary destruction remain with the caller after all locks release.
    pub(crate) fn publish_retaining<Published, Retirement>(
        &self,
        next: NextPublication,
        publish: impl FnOnce() -> Published,
        release: impl FnOnce(Published) -> Retirement,
    ) -> Retirement {
        // Declare retirement first so unwind also releases the visibility lock
        // before the old identity can refund its original allocation credits.
        let retired_version;
        let mut version = self.lock_version();
        let published = publish();
        retired_version = std::mem::replace(&mut **version, next.0);
        let retirement = release(published);
        drop(version);
        drop(retired_version);
        retirement
    }
}

impl CapturedPublication {
    /// Compare only the original owner without acquiring its publication lock.
    pub(crate) fn belongs_to(&self, publication: &Publication) -> bool {
        Shared::ptr_eq(&self.owner, &publication.owner)
    }

    /// Check the original owner and version without waiting on a publication cut.
    pub(crate) fn try_check_current<E>(
        &self,
        publication: &Publication,
    ) -> (
        Result<(), PublicationPreparationError<E>>,
        Option<IdentityRetirement>,
    ) {
        match self.try_prepare_current(publication) {
            Ok(identity) => (Ok(()), Some(identity.abort())),
            Err((error, retirement)) => (Err(error), retirement),
        }
    }

    /// Acquire the original identity with ordinary blocking behavior, then check
    /// it only after the aggregate's slot retains the actual physical guard.
    pub(crate) fn prepare_current_in<'a>(
        &self,
        publication: &'a Publication,
        slot: &mut Option<PreparedIdentity<'a>>,
    ) {
        assert!(slot.is_none(), "original identity prepares once");
        *slot = Some(PreparedIdentity {
            version: publication.lock_version(),
        });
        let held = slot.as_ref().expect("original identity retained by caller");
        assert!(
            Shared::ptr_eq(&self.owner, &publication.owner),
            "original publication owner"
        );
        assert!(
            Shared::ptr_eq(&self.version, &held.version),
            "original publication predecessor"
        );
    }

    /// Retain the exact identity after a nonblocking predecessor authentication.
    pub(crate) fn try_prepare_current<'a, E>(
        &self,
        publication: &'a Publication,
    ) -> Result<PreparedIdentity<'a>, (PublicationPreparationError<E>, Option<IdentityRetirement>)>
    {
        if !Shared::ptr_eq(&self.owner, &publication.owner) {
            return Err((PublicationPreparationError::Changed, None));
        }
        let wait = publication.released.observe();
        match publication
            .version
            .try_lock()
            .map(|guard| publication.released.poisoning_guard(guard))
        {
            Ok(version) if Shared::ptr_eq(&self.version, &version) => {
                Ok(PreparedIdentity { version })
            }
            Ok(version) => Err((
                PublicationPreparationError::Changed,
                Some(PreparedIdentity { version }.abort()),
            )),
            Err(TryLockError::WouldBlock) => Err((PublicationPreparationError::Busy(wait), None)),
            Err(TryLockError::Poisoned(_)) => Err((PublicationPreparationError::Poisoned, None)),
        }
    }

    pub(crate) fn matches(&self, publication: &Publication) -> bool {
        Shared::ptr_eq(&self.owner, &publication.owner)
            && Shared::ptr_eq(&self.version, &publication.lock_version())
    }

    pub(crate) fn same_as(&self, other: &Self) -> bool {
        Shared::ptr_eq(&self.owner, &other.owner) && Shared::ptr_eq(&self.version, &other.version)
    }
}

#[cfg(test)]
#[path = "publication_nonblocking_tests.rs"]
mod nonblocking_tests;

#[cfg(test)]
mod tests {
    use std::sync::mpsc;

    #[test]
    fn identity_observation_is_excluded_until_both_actual_cell_writes_finish() {
        let cell = crate::cell::Cell::new(10_u64);
        let original = cell.publication.capture();
        let (first_written, first_read) = mpsc::channel();
        let (finish, finish_read) = mpsc::channel();
        std::thread::scope(|scope| {
            let owner = &cell;
            let publication = scope.spawn(move || {
                let mut undo = owner.revert.write();
                let mut current = owner.blocks.write();
                *undo.get_mut() = Some(10);
                *current.get_mut() = 20;
                owner.publication.publish_retaining(
                    super::NextPublication::new(),
                    || {
                        current.commit();
                        first_written.send(()).unwrap();
                        finish_read.recv().unwrap();
                        undo.commit();
                    },
                    |()| (),
                );
            });
            first_read.recv().unwrap();
            // Deliberately pause the same two-write owner between its writes.
            // Raw independent views may see that cut; an identity observer must
            // not receive the old token or the new token in that interval.
            let token_is_locked = cell.publication.version.try_lock().is_err();
            let visible_current = *cell.view();
            let visible_undo = *cell.predecessor_view();
            let observer = scope.spawn(|| original.matches(&cell.publication));
            finish.send(()).unwrap();
            publication.join().unwrap();
            assert!(!observer.join().unwrap());
            assert!(token_is_locked);
            assert_eq!(visible_current, 20);
            assert_eq!(visible_undo, None);
        });
        assert_eq!(*cell.view(), 20);
        assert_eq!(*cell.predecessor_view(), Some(10));
        assert!(!original.matches(&cell.publication));
    }
}

#[cfg(test)]
#[path = "detached_publication_tests.rs"]
mod detached_publication_tests;

#[cfg(test)]
#[path = "publication_admission_tests.rs"]
mod admission_tests;

#[cfg(test)]
#[path = "publication_original_read_tests.rs"]
mod original_read_tests;

#[cfg(test)]
mod error_tests {
    use std::{convert::Infallible, error::Error, fmt};

    use super::*;

    #[derive(Debug)]
    struct OriginalAdmission;

    impl fmt::Display for OriginalAdmission {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("original admission")
        }
    }

    impl Error for OriginalAdmission {}

    #[test]
    fn publication_display_preserves_every_existing_local_refusal() {
        let released = ReleaseNotification::default();
        let original_wait = released.observe();
        for (error, expected) in [
            (
                PublicationPreparationError::Busy(original_wait.clone()),
                "publication writer is busy",
            ),
            (
                PublicationPreparationError::Poisoned,
                "publication owner is poisoned",
            ),
            (
                PublicationPreparationError::Changed,
                "publication owner changed",
            ),
            (
                PublicationPreparationError::Admission(OriginalAdmission),
                "publication admission refused: original admission",
            ),
        ] {
            assert_eq!(error.to_string(), expected);
            if let PublicationPreparationError::Busy(wait) = error {
                assert_eq!(wait, original_wait);
            }
        }
    }

    #[test]
    fn publication_error_source_is_the_original_admission_and_infallible_local_errors_are_typed() {
        let error = PublicationPreparationError::Admission(OriginalAdmission);
        let PublicationPreparationError::Admission(original) = &error else {
            unreachable!();
        };
        let source = Error::source(&error)
            .unwrap()
            .downcast_ref::<OriginalAdmission>()
            .unwrap();
        assert!(std::ptr::eq(source, original));
        assert_eq!(source.to_string(), "original admission");
        let released = ReleaseNotification::default();
        for error in [
            PublicationPreparationError::<Infallible>::Busy(released.observe()),
            PublicationPreparationError::Poisoned,
            PublicationPreparationError::Changed,
        ] {
            let typed: &(dyn Error + 'static) = &error;
            assert!(typed.source().is_none());
            assert!(!typed.to_string().is_empty());
        }
    }
}
