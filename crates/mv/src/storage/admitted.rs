//! Finite insertion and removal in the original MV current/undo pair.
//!
//! This admits original node, cursor, reader, tracking, publication identity and
//! copied payload owners.
//! Borrowed iteration retains its traversal state inline without allocating.
//! Native mutex internals and pending notification waiters remain separate.
//! Transactions additionally admit their ordered local touch owners.
//! Replacement and snapshot restoration admit each edit and its incoming copies.
//! Detached owners retain original funding; joint preparation borrows its pool scope.
//! Mutable payload access still requires a closed admission policy.

use super::*;
use crate::ReleaseWait;
use concread::bptree::{
    AllocationDemand, ClonePlanning, MapAdmissionError, NodeFunding, PairInsertError,
    PairRemoveError, PlanningError, Prepaid,
};
use iroha_allocation::{
    AllocationBudget, AllocationCharge, AllocationRefusal, AllocationReservation, AllocationScope,
};

#[path = "restore_admitted.rs"]
mod restoration;

/// Constructs a payload policy from the original finite MV reservation.
///
/// Implementations must retain that same reservation, return its reference from
/// `admission`, and fund every planned node and payload copy from it. The adapter
/// verifies actual pool identity and the complete remaining demand before the
/// policy may mutate either map. Node charges are the real move-only allocation
/// credits, never synthetic witnesses. Payload cloning additionally implements
/// Concread's exact `ClonePlanning` contract for current and undo values.
pub trait AdmittedStoragePolicy: NodeFunding<Charge = AllocationCharge> {
    /// Retain the original reservation without spending or replacing it.
    fn from_admission(reservation: AllocationReservation) -> Self;
    /// Borrow the original remaining prepaid owner.
    fn admission(&self) -> &AllocationReservation;
}

/// Which original physical writer prevented admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageRole {
    /// Current values.
    Current,
    /// First block preimages.
    Undo,
}

/// A local refusal before publishing an admitted block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdmittedStorageError {
    /// The original writer is held. The observation grants no future authority.
    Busy {
        /// Original writer role.
        role: StorageRole,
        /// Release observation captured before the failed acquisition.
        release: ReleaseWait,
    },
    /// An earlier unwind made the original writer unavailable for reuse.
    Poisoned {
        /// Original writer role.
        role: StorageRole,
    },
    /// Exact layout or generation planning refused before allocation.
    Planning(PlanningError),
    /// Replanning after an incoming payload copy changed the admitted demand.
    Changed,
    /// The original finite pool cannot admit the complete demand.
    Allocation(AllocationRefusal),
    /// The physical allocator refused an exact already admitted layout.
    /// No backing allocation exists and no new release observation is fabricated.
    Allocator {
        /// Original requested backing layout, including its alignment.
        layout: std::alloc::Layout,
    },
    /// Publication was attempted outside the original pool's active scope.
    ScopeIdentity,
    /// A policy returned a reservation from another pool.
    PolicyIdentity,
    /// A policy did not retain the full original requested demand.
    PolicyDemand {
        /// Bytes passed to the policy constructor.
        expected_bytes: usize,
        /// Bytes retained by the returned policy.
        remaining_bytes: usize,
    },
}

impl AdmittedStorageError {
    /// Original observation that may become actionable after another owner releases.
    /// Permanent planning and authority refusals never manufacture a retry signal.
    pub fn release_wait(&self) -> Option<&ReleaseWait> {
        match self {
            Self::Busy { release, .. }
            | Self::Allocation(AllocationRefusal::Capacity { release, .. }) => Some(release),
            _ => None,
        }
    }
}

impl std::fmt::Display for AdmittedStorageError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "original storage admission refused: {self:?}")
    }
}

impl std::error::Error for AdmittedStorageError {}

/// Either opening or edit admission failed or the caller aborted its block.
#[derive(Debug)]
pub enum AdmittedBlockError<E> {
    /// Original writer or allocation admission refused.
    Admission(AdmittedStorageError),
    /// The callback abandoned its private block without publication.
    Callback(E),
}

pub(super) fn policy<P: AdmittedStoragePolicy>(
    budget: &AllocationBudget,
    reservation: AllocationReservation,
    demand: AllocationDemand,
) -> Result<P, AdmittedStorageError> {
    let expected_bytes = demand.bytes();
    if reservation.remaining_bytes() != expected_bytes {
        return Err(AdmittedStorageError::PolicyDemand {
            expected_bytes,
            remaining_bytes: reservation.remaining_bytes(),
        });
    }
    let provider = P::from_admission(reservation);
    if !provider.admission().belongs_to(budget) {
        return Err(AdmittedStorageError::PolicyIdentity);
    }
    if provider.admission().remaining_bytes() != expected_bytes {
        return Err(AdmittedStorageError::PolicyDemand {
            expected_bytes,
            remaining_bytes: provider.admission().remaining_bytes(),
        });
    }
    Ok(provider)
}

pub(super) fn admit<P: AdmittedStoragePolicy>(
    budget: &AllocationBudget,
    demand: AllocationDemand,
) -> Result<P, AdmittedStorageError> {
    let reservation = budget
        .try_reserve_bytes(demand.bytes())
        .map_err(AdmittedStorageError::Allocation)?;
    policy(budget, reservation, demand)
}

// Canonical Concread layout plans are summed once. Both move-only parts retain
// the original pool; partitioning does not acquire or refund any pool credits.
fn reserve_pair(
    budget: &AllocationBudget,
    current: AllocationDemand,
    undo: AllocationDemand,
) -> Result<(AllocationReservation, AllocationReservation), AdmittedStorageError> {
    let total =
        current
            .bytes()
            .checked_add(undo.bytes())
            .ok_or(AdmittedStorageError::Allocation(
                AllocationRefusal::DemandOverflow,
            ))?;
    let mut original = budget
        .try_reserve_bytes(total)
        .map_err(AdmittedStorageError::Allocation)?;
    let current = original
        .try_partition_bytes(current.bytes())
        .expect("part of the same checked complete demand");
    Ok((current, original))
}

// Identity storage belongs to the same admission as both map owners. A failed
// complete reservation allocates nothing and invokes no policy or user callback.
pub(super) fn reserve_owners(
    budget: &AllocationBudget,
    current: AllocationDemand,
    undo: AllocationDemand,
    identity: AllocationDemand,
) -> Result<
    (
        AllocationReservation,
        AllocationReservation,
        AllocationReservation,
    ),
    AdmittedStorageError,
> {
    let mut total = current;
    total
        .add_demand(undo)
        .map_err(AdmittedStorageError::Planning)?;
    total
        .add_demand(identity)
        .map_err(AdmittedStorageError::Planning)?;
    let mut original = budget
        .try_reserve_bytes(total.bytes())
        .map_err(AdmittedStorageError::Allocation)?;
    let current = original
        .try_partition_bytes(current.bytes())
        .expect("part of the same checked complete demand");
    let undo = original
        .try_partition_bytes(undo.bytes())
        .expect("part of the same checked complete demand");
    Ok((current, undo, original))
}

pub(super) fn writer_error(
    error: MapAdmissionError<AdmittedStorageError>,
    role: StorageRole,
    release: ReleaseWait,
) -> AdmittedStorageError {
    match error {
        MapAdmissionError::Busy if release.is_poisoned() => AdmittedStorageError::Poisoned { role },
        MapAdmissionError::Busy => AdmittedStorageError::Busy { role, release },
        MapAdmissionError::Poisoned => AdmittedStorageError::Poisoned { role },
        MapAdmissionError::Planning(error) => AdmittedStorageError::Planning(error),
        MapAdmissionError::Refused(error) => error,
        MapAdmissionError::Changed => unreachable!("new original writer has no detached input"),
    }
}

struct AdmittedWriters<'a, K: Key, V: Value, P>
where
    P: ClonePlanning<K, V> + ClonePlanning<K, Option<V>>,
{
    writers: StorageWriters<'a, K, V, Prepaid<P>>,
    next: NextPublication,
}

fn edit_error(error: MapAdmissionError<AdmittedStorageError>) -> AdmittedStorageError {
    match error {
        MapAdmissionError::Planning(error) => AdmittedStorageError::Planning(error),
        MapAdmissionError::Refused(error) => error,
        MapAdmissionError::Changed => AdmittedStorageError::Changed,
        MapAdmissionError::Busy | MapAdmissionError::Poisoned => {
            unreachable!("an acquired writer never reacquires its physical lock")
        }
    }
}

// Retained source entries are borrowed, so their copies and the destination edit
// share one admission. Both physical writers outlive all temporary payloads.
fn insert_copy<K: Key, V: Value, P: AdmittedStoragePolicy + ClonePlanning<K, V>>(
    writer: &mut BptreeMapWriteTxn<'_, K, V, Prepaid<P>>,
    key: &K,
    value: &V,
    budget: &AllocationBudget,
) -> Result<(), AdmittedStorageError> {
    let current = writer
        .insertion_demand(key)
        .map_err(AdmittedStorageError::Planning)?;
    let mut copies = AllocationDemand::new();
    P::plan_key(key, &mut copies).map_err(AdmittedStorageError::Planning)?;
    P::plan_value(value, &mut copies).map_err(AdmittedStorageError::Planning)?;
    let (current_reservation, copy_reservation) = reserve_pair(budget, current, copies)?;
    let mut copier = policy::<P>(budget, copy_reservation, copies)?;
    let key = copier.clone_key(key);
    let value = copier.clone_value(value);
    let previous = writer
        .try_insert_admitted(key, value, |actual| {
            if actual != current {
                return Err(AdmittedStorageError::Changed);
            }
            policy::<P>(budget, current_reservation, actual)
        })
        .map_err(|((key, value), error)| {
            drop((key, value));
            edit_error(error)
        })?;
    drop(previous);
    drop(copier);
    Ok(())
}

impl<K, V, P> Storage<K, V, Prepaid<P>>
where
    K: Key,
    V: Value,
    P: AdmittedStoragePolicy + ClonePlanning<K, V> + ClonePlanning<K, Option<V>>,
{
    /// The original finite pool shared by this storage's current and undo owners.
    /// Cloning this handle retains that exact pool; it grants no additional limit.
    pub fn allocation_budget(&self) -> &AllocationBudget {
        self.allocation
            .as_ref()
            .expect("admitted Storage original pool")
    }

    /// Initial current/undo map allocations and their shared publication identities.
    /// Native mutex internals and pending waiters require separate funding.
    pub fn initial_allocation_demand() -> Result<AllocationDemand, PlanningError> {
        let mut demand = BptreeMap::<K, V, Prepaid<P>>::node_custody_allocation_demand()?;
        demand
            .add_demand(BptreeMap::<K, Option<V>, Prepaid<P>>::node_custody_allocation_demand()?)?;
        demand.add_demand(Publication::allocation_demand()?)?;
        for _ in 0..2 {
            demand.add_layout(ReleaseNotification::allocation_layout::<AllocationCharge>())?;
        }
        Ok(demand)
    }

    /// Both original writer shells and the next shared publication identity.
    /// Undo reset, replacement copies and subsequent edits require additional admission.
    pub fn writer_start_allocation_demand() -> Result<AllocationDemand, PlanningError> {
        let mut demand = BptreeMap::<K, V, Prepaid<P>>::writer_start_allocation_demand()?;
        demand
            .add_demand(BptreeMap::<K, Option<V>, Prepaid<P>>::writer_start_allocation_demand()?)?;
        demand.add_demand(NextPublication::allocation_demand()?)?;
        Ok(demand)
    }

    /// Construct the same MV storage with one original finite allocation pool.
    ///
    /// A single checked admission covers both maps' real initial node/root/reader
    /// layouts and original publication identities. No empty-map substitute or
    /// untracked node path is used. Original notification control blocks share
    /// this admission. Native mutex internals and pending waiters remain open.
    pub fn try_new_admitted(budget: AllocationBudget) -> Result<Self, AdmittedStorageError> {
        budget.with_deferred_refund_notifications(|_| {
            let current = BptreeMap::<K, V, Prepaid<P>>::node_custody_allocation_demand()
                .map_err(AdmittedStorageError::Planning)?;
            let undo = BptreeMap::<K, Option<V>, Prepaid<P>>::node_custody_allocation_demand()
                .map_err(AdmittedStorageError::Planning)?;
            let mut identity =
                Publication::allocation_demand().map_err(AdmittedStorageError::Planning)?;
            let notification_layout = ReleaseNotification::allocation_layout::<AllocationCharge>();
            for _ in 0..2 {
                identity
                    .add_layout(notification_layout)
                    .map_err(AdmittedStorageError::Planning)?;
            }
            let (current, undo, mut identity) = reserve_owners(&budget, current, undo, identity)?;
            let revert_released = ReleaseNotification::try_new_charged(
                identity
                    .try_split(notification_layout)
                    .expect("original undo notification capacity"),
            )
            .map_err(|(charge, error)| {
                drop(charge);
                AdmittedStorageError::Allocator {
                    layout: error.layout(),
                }
            })?;
            let blocks_released = ReleaseNotification::try_new_charged(
                identity
                    .try_split(notification_layout)
                    .expect("original current notification capacity"),
            )
            .map_err(|(charge, error)| {
                drop(charge);
                AdmittedStorageError::Allocator {
                    layout: error.layout(),
                }
            })?;
            let revert =
                BptreeMap::try_new_with_node_custody(|demand| policy::<P>(&budget, undo, demand))?;
            let blocks = BptreeMap::try_new_with_node_custody(|demand| {
                policy::<P>(&budget, current, demand)
            })?;
            let publication = Publication::try_from_original(&mut identity).map_err(|error| {
                AdmittedStorageError::Allocator {
                    layout: error.layout(),
                }
            })?;
            debug_assert_eq!(identity.remaining_bytes(), 0);
            Ok(Self {
                publication,
                revert_released,
                blocks_released,
                revert,
                blocks,
                allocation: Some(budget.clone()),
            })
        })
    }

    /// Execute once and retain the actual current/undo successors without publishing.
    ///
    /// Opening, reset/replacement, edits and detachment use the original pool's
    /// synchronous refund scope. Both physical writers release before the journal
    /// leaves. The callback's result remains attached as separate caller admission;
    /// it must not be used to fund earlier execution retroactively. A callback
    /// error abandons both private trees. Capture itself allocates and copies nothing.
    pub fn try_capture_admitted_block<Admission, E>(
        &self,
        mode: BlockMode,
        operation: impl for<'s> FnOnce(&mut Block<'s, K, V, Prepaid<P>>) -> Result<Admission, E>,
    ) -> Result<Detached<K, V, Admission, Prepaid<P>>, AdmittedBlockError<E>> {
        let budget = self
            .allocation
            .as_ref()
            .expect("admitted Storage original pool");
        budget.with_deferred_refund_notifications(|scope| {
            let mut block = self
                .open_admitted_block(scope, mode)
                .map_err(AdmittedBlockError::Admission)?;
            let admission = operation(&mut block).map_err(AdmittedBlockError::Callback)?;
            Ok(block.detach_owned(admission))
        })
    }

    /// Run one ordinary block under the original two writers and finite pool.
    ///
    /// Both writer shells and the next identity are admitted together, then the retained undo map is
    /// cleared through genuine admitted reset. Any opening refusal abandons the
    /// private cursors without changing either published map. `Ok` publishes the
    /// actual current/undo pair; `Err` abandons it. The higher-ranked callback
    /// cannot return physical writer guards or references into its private block.
    ///
    /// The original pool defers refund wakes across acquisition, callback and
    /// final writer destruction. Do not catch an edit panic and keep using the
    /// block: both original cursors and this aggregate remain unusable. This admits
    /// insertion and removal; complete World execution and aggregate State
    /// publication still require their own admission policies.
    pub fn try_with_admitted_block<R, E>(
        &self,
        operation: impl for<'s> FnOnce(&mut Block<'s, K, V, Prepaid<P>>) -> Result<R, E>,
    ) -> Result<R, AdmittedBlockError<E>> {
        self.with_admitted_block(BlockMode::Ordinary, operation)
    }

    /// Restore the latest block's preimages, then run a replacement under the
    /// original pool and both physical writers.
    ///
    /// Each restoration admits its map edit and incoming copies before allocation.
    /// Undo is cleared only after all preimages are restored. Any opening refusal
    /// or callback error abandons both private trees, including a restored prefix.
    /// Successful edits record preimages from the restored state. Even an empty
    /// replacement advances publication identity with replacement mode.
    ///
    /// The callback cannot return writer guards. Refund notifications remain
    /// deferred until both writers unlock. This is per-edit admission; aggregate
    /// replacement work and State resource policy still require their own bounds.
    pub fn try_with_admitted_replacement<R, E>(
        &self,
        operation: impl for<'s> FnOnce(&mut Block<'s, K, V, Prepaid<P>>) -> Result<R, E>,
    ) -> Result<R, AdmittedBlockError<E>> {
        self.with_admitted_block(BlockMode::Replace, operation)
    }

    /// Restore exact current entries and undo tombstones from a borrowed snapshot.
    ///
    /// The caller authenticates the source schema and fences its acquisition with
    /// the source publication generation. Both destination trees remain private
    /// until all copies succeed. Refusal preserves the original snapshot for retry.
    /// Initial trees, writer shells and each edit's incoming copies use the one
    /// supplied pool; native control storage, decoding and aggregate restore work
    /// require separate admission.
    pub fn try_from_snapshot_admitted<M: StorageMode<K, V>>(
        snapshot: &super::snapshot::Snapshot<'_, K, V, M>,
        budget: AllocationBudget,
    ) -> Result<Self, AdmittedStorageError> {
        budget.with_deferred_refund_notifications(|_| {
            let restored = Self::try_new_admitted(budget.clone())?;
            let AdmittedWriters { mut writers, next } = restored.open_admitted_writers()?;
            let OriginalWriters { revert, blocks } = writers.as_mut();
            for (key, value) in snapshot.current().iter() {
                insert_copy(blocks, key, value, &budget)?;
            }
            for (key, value) in snapshot.revert_map().iter() {
                insert_copy(revert, key, value, &budget)?;
            }
            let predecessor = restored.publication.capture();
            writers.prepare_publication(&predecessor, true);
            let mut next = Some(next);
            writers.publish_prepared(&mut next);
            drop(writers);
            Ok(restored)
        })
    }

    fn with_admitted_block<R, E>(
        &self,
        mode: BlockMode,
        operation: impl for<'s> FnOnce(&mut Block<'s, K, V, Prepaid<P>>) -> Result<R, E>,
    ) -> Result<R, AdmittedBlockError<E>> {
        let budget = self
            .allocation
            .as_ref()
            .expect("admitted Storage original pool");
        budget.with_deferred_refund_notifications(|scope| {
            let mut block = self
                .open_admitted_block(scope, mode)
                .map_err(AdmittedBlockError::Admission)?;
            let output = operation(&mut block).map_err(AdmittedBlockError::Callback)?;
            block.assert_admitted_operable();
            block.publish();
            Ok(output)
        })
    }

    // Private: every caller retains both physical writers inside the original
    // pool's synchronous refund scope. No public open/detach escape is exposed.
    fn open_admitted_writers(&self) -> Result<AdmittedWriters<'_, K, V, P>, AdmittedStorageError> {
        let budget = self
            .allocation
            .as_ref()
            .expect("admitted Storage original pool");
        let current = BptreeMap::<K, V, Prepaid<P>>::writer_start_allocation_demand()
            .map_err(AdmittedStorageError::Planning)?;
        let undo = BptreeMap::<K, Option<V>, Prepaid<P>>::writer_start_allocation_demand()
            .map_err(AdmittedStorageError::Planning)?;
        let identity =
            NextPublication::allocation_demand().map_err(AdmittedStorageError::Planning)?;
        let (current, undo, mut identity) = reserve_owners(budget, current, undo, identity)?;
        let undo_wait = self.revert_released.observe();
        let revert = self.revert.try_acquire_writer().ok_or_else(|| {
            writer_error(
                MapAdmissionError::Busy,
                StorageRole::Undo,
                undo_wait.clone(),
            )
        })?;
        let revert = self.revert_released.poisoning_guard(revert);
        if revert.is_poisoned() {
            revert.release_with_observed_poison(drop, || self.revert.is_poisoned());
            return Err(AdmittedStorageError::Poisoned {
                role: StorageRole::Undo,
            });
        }
        let current_wait = self.blocks_released.observe();
        let blocks = self.blocks.try_acquire_writer().ok_or_else(|| {
            writer_error(
                MapAdmissionError::Busy,
                StorageRole::Current,
                current_wait.clone(),
            )
        })?;
        let blocks = self.blocks_released.poisoning_guard(blocks);
        let (revert, blocks) = revert.try_map_pair_preserving_release(
            blocks,
            |revert, blocks| {
                // Both actual poison checks precede either cursor allocation.
                if blocks.is_poisoned() {
                    return Err(AdmittedStorageError::Poisoned {
                        role: StorageRole::Current,
                    });
                }
                let revert = revert
                    .try_write_admitted(|demand| policy::<P>(budget, undo, demand))
                    .map_err(|(acquired, error)| {
                        drop(acquired);
                        writer_error(error, StorageRole::Undo, undo_wait)
                    })?;
                let blocks = blocks
                    .try_write_admitted(|demand| policy::<P>(budget, current, demand))
                    .map_err(|(acquired, error)| {
                        drop(acquired);
                        writer_error(error, StorageRole::Current, current_wait)
                    })?;
                Ok((revert, blocks))
            },
            || (self.revert.is_poisoned(), self.blocks.is_poisoned()),
        )?;
        // Refused/poisoned acquisition must not allocate an unused identity.
        // Its original reservation already exists; both writers now belong to
        // this opening, before reset, replacement copying or user execution.
        let writers = StorageWriters::new(self, revert, blocks);
        let next = NextPublication::try_from_charge(
            identity
                .try_split(NextPublication::allocation_layout())
                .expect("original successor identity admission"),
        )
        .map_err(|(charge, error)| {
            drop(charge);
            AdmittedStorageError::Allocator {
                layout: error.layout(),
            }
        })?;
        debug_assert_eq!(identity.remaining_bytes(), 0);
        Ok(AdmittedWriters { writers, next })
    }

    fn open_admitted_block<'a>(
        &'a self,
        scope: &'a AllocationScope<'a>,
        mode: BlockMode,
    ) -> Result<Block<'a, K, V, Prepaid<P>>, AdmittedStorageError> {
        let mut slot = self.try_block_acquisition_admitted(scope)?;
        slot.try_initialize(mode)?;
        Ok(slot.into_block())
    }
}

impl<K, V, P> Block<'_, K, V, Prepaid<P>>
where
    K: Key,
    V: Value,
    P: AdmittedStoragePolicy + ClonePlanning<K, V> + ClonePlanning<K, Option<V>>,
{
    // The caller-owned acquisition slot already owns both writers and their
    // identity. A refusal or unwind keeps the original partial restoration in
    // that slot; no payload retirement runs under a sibling aggregate writer.
    pub(super) fn initialize_admitted_contents(&mut self) -> Result<(), AdmittedStorageError> {
        let budget = self
            .writers
            .target
            .allocation
            .as_ref()
            .expect("admitted Storage original pool");
        let OriginalWriters { revert, blocks } = self.writers.as_mut();
        if self.mode == BlockMode::Replace {
            for (key, previous) in revert.iter() {
                if let Some(value) = previous {
                    insert_copy(blocks, key, value, budget)?;
                } else {
                    let removed = blocks
                        .try_remove_admitted(key, |demand| admit::<P>(budget, demand))
                        .map_err(edit_error)?;
                    drop(removed);
                }
            }
        }
        revert
            .try_clear_admitted(|demand| admit::<P>(budget, demand))
            .map_err(edit_error)?;
        self.failed = false;
        Ok(())
    }

    pub(super) fn assert_admitted_operable(&self) {
        assert!(
            !self.failed,
            "admitted block edit unwound; abandon both writers"
        );
        self.writers.as_ref().blocks.len();
        self.writers.as_ref().revert.len();
    }

    /// Insert current plus its missing first preimage under one checked demand.
    /// Ordinary refusal returns the exact inputs and keeps both private maps
    /// reusable. Existing first None/Some preimages are never rewritten.
    pub fn try_insert_admitted(
        &mut self,
        key: K,
        value: V,
    ) -> Result<Option<V>, ((K, V), AdmittedStorageError)> {
        self.assert_admitted_operable();
        let budget = self
            .writers
            .target
            .allocation
            .as_ref()
            .expect("admitted block original pool");
        self.failed = true;
        let OriginalWriters { revert, blocks } = self.writers.as_mut();
        let result = blocks
            .try_insert_with_undo_admitted(revert, key, value, |demand, _key| {
                admit::<P>(budget, demand)
            })
            .map_err(|(input, error)| {
                let error = match error {
                    PairInsertError::Planning(error) => AdmittedStorageError::Planning(error),
                    PairInsertError::Refused(error) => error,
                    PairInsertError::Current(_) | PairInsertError::Undo(_) => {
                        unreachable!("borrowed joined edit never reacquires either writer")
                    }
                };
                (input, error)
            });
        if result.is_ok() {
            self.dirty = true;
        }
        self.failed = false;
        result
    }

    /// Remove through the original current/undo pair under one checked demand.
    ///
    /// An absent query still retains its explicit first None preimage, while only
    /// a present removal marks the block dirty. Refusal returns the exact owned
    /// query without changing either private map. The canonical pair consumes a
    /// successful query before releasing its failure guard; a caught key-drop or
    /// copy panic therefore forbids publication of this original block.
    pub fn try_remove_admitted(&mut self, key: K) -> Result<Option<V>, (K, AdmittedStorageError)> {
        self.assert_admitted_operable();
        let budget = self
            .writers
            .target
            .allocation
            .as_ref()
            .expect("admitted block original pool");
        self.failed = true;
        let OriginalWriters { revert, blocks } = self.writers.as_mut();
        let result = blocks
            .try_remove_with_undo_admitted(revert, key, |demand, _key| admit::<P>(budget, demand))
            .map_err(|(key, error)| {
                let error = match error {
                    PairRemoveError::Planning(error) => AdmittedStorageError::Planning(error),
                    PairRemoveError::Refused(error) => error,
                };
                (key, error)
            });
        if let Ok(previous) = &result {
            self.dirty |= previous.is_some();
        }
        self.failed = false;
        result
    }

    /// Borrow a private current value without iteration allocation.
    pub fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.assert_admitted_operable();
        self.writers.as_ref().blocks.get(key)
    }

    /// Number of private current entries.
    pub fn len(&self) -> usize {
        self.assert_admitted_operable();
        self.writers.as_ref().blocks.len()
    }
    /// Whether the private current map has no entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

enum PublicationScope<'scope> {
    Borrowed {
        _scope: &'scope AllocationScope<'scope>,
    },
    Owned {
        _scope: iroha_allocation::OwnedAllocationScope,
    },
}

/// Original prepaid successors held only within their pool's synchronous scope.
///
/// Multiple owners from the same pool can be prepared together. The scope outlives
/// every physical writer, including abort and unwind. It supplies local refund
/// ordering; a complete State owner still supplies joint visibility and finality.
///
/// Detached custody can leave the scope after abort:
/// ```
/// use concread::bptree::{ClonePlanning, Prepaid};
/// use iroha_allocation::{AllocationBudget};
/// use mv::{storage::{AdmittedStoragePolicy, Detached, Storage}};
/// fn release<P>(budget: &AllocationBudget, target: &Storage<u64, u64, Prepaid<P>>,
///     journal: Detached<u64, u64, (), Prepaid<P>>) -> Detached<u64, u64, (), Prepaid<P>>
/// where P: AdmittedStoragePolicy + ClonePlanning<u64, u64> + ClonePlanning<u64, Option<u64>> {
///     budget.with_deferred_refund_notifications(|scope| {
///         match journal.try_prepare_admitted(scope, target) {
///             Ok(prepared) => prepared.abort().0,
///             Err((journal, _, cleanup)) => { drop(cleanup); journal },
///         }
///     })
/// }
/// ```
/// A physical preparation cannot leave that same scope:
/// ```compile_fail
/// use concread::bptree::{ClonePlanning, Prepaid};
/// use iroha_allocation::{AllocationBudget};
/// use mv::{storage::{AdmittedStoragePolicy,
///     AdmittedPreparedPublication, Detached, Storage}};
/// fn escape<'a, P>(budget: &'a AllocationBudget, target: &'a Storage<u64, u64, Prepaid<P>>,
///     journal: Detached<u64, u64, (), Prepaid<P>>) -> AdmittedPreparedPublication<'a, 'a, u64, u64, (), P>
/// where P: AdmittedStoragePolicy + ClonePlanning<u64, u64> + ClonePlanning<u64, Option<u64>> {
///     budget.with_deferred_refund_notifications(|scope| {
///         match journal.try_prepare_admitted(scope, target) {
///             Ok(prepared) => prepared,
///             Err(_) => panic!("local refusal"),
///         }
///     })
/// }
/// ```
#[must_use = "publish or abort the original prepared pair inside its allocation scope"]
pub struct AdmittedPreparedPublication<'scope, 'target, K: Key, V: Value, Admission, P>
where
    P: AdmittedStoragePolicy + ClonePlanning<K, V> + ClonePlanning<K, Option<V>>,
{
    inner: PreparedPublication<'target, K, V, Admission, (), Prepaid<P>>,
    _scope: PublicationScope<'scope>,
}

/// Published cleanup confined to its original admitted notification scope.
/// Keep this owner until every aggregate participant has released its locks.
/// The notification owner cannot escape the pool scope after publication:
/// ```compile_fail
/// use concread::bptree::{ClonePlanning, Prepaid};
/// use iroha_allocation::{AllocationBudget};
/// use mv::{storage::{AdmittedStoragePolicy,
///     AdmittedPublishedPublication, Detached, Storage}};
/// fn escape<'a, P>(budget: &'a AllocationBudget, target: &'a Storage<u64, u64, Prepaid<P>>,
///     journal: Detached<u64, u64, (), Prepaid<P>>) -> AdmittedPublishedPublication<'a, u64, u64, (), P>
/// where P: AdmittedStoragePolicy + ClonePlanning<u64, u64> + ClonePlanning<u64, Option<u64>> {
///     budget.with_deferred_refund_notifications(|scope| {
///         match journal.try_prepare_admitted(scope, target) {
///             Ok(prepared) => prepared.publish(),
///             Err(_) => panic!("local refusal"),
///         }
///     })
/// }
/// ```
pub struct AdmittedPublishedPublication<'scope, K: Key, V: Value, Admission, P>
where
    P: AdmittedStoragePolicy + ClonePlanning<K, V> + ClonePlanning<K, Option<V>>,
{
    inner: PublishedPublication<K, V, Admission, (), Prepaid<P>>,
    _scope: PublicationScope<'scope>,
}

impl<K: Key, V: Value, Admission, P> AdmittedPublishedPublication<'_, K, V, Admission, P>
where
    P: AdmittedStoragePolicy + ClonePlanning<K, V> + ClonePlanning<K, Option<V>>,
{
    /// Retire released physical owners before returning the caller's admission.
    pub fn into_admission(self) -> Admission {
        self.inner.into_reservations().0
    }
}

/// Aborted physical notifications confined to the original allocation scope.
/// The detached journal can leave the scope; this cleanup cannot.
/// ```compile_fail
/// use concread::bptree::{ClonePlanning, Prepaid};
/// use iroha_allocation::{AllocationBudget};
/// use mv::{storage::{AdmittedStoragePolicy,
///     AdmittedAbortedPublication, Detached, Storage}};
/// fn escape<'a, P>(budget: &'a AllocationBudget, target: &'a Storage<u64, u64, Prepaid<P>>,
///     journal: Detached<u64, u64, (), Prepaid<P>>) -> AdmittedAbortedPublication<'a>
/// where P: AdmittedStoragePolicy + ClonePlanning<u64, u64> + ClonePlanning<u64, Option<u64>> {
///     budget.with_deferred_refund_notifications(|scope| {
///         match journal.try_prepare_admitted(scope, target) {
///             Ok(prepared) => prepared.abort().1,
///             Err(_) => panic!("local refusal"),
///         }
///     })
/// }
/// ```
/// Refusal cleanup has the same scope constraint as explicit abort:
/// ```compile_fail
/// use concread::bptree::{ClonePlanning, Prepaid};
/// use iroha_allocation::{AllocationBudget};
/// use mv::{storage::{AdmittedStoragePolicy,
///     AdmittedAbortedPublication, Detached, Storage}};
/// fn escape<'a, P>(budget: &'a AllocationBudget, target: &'a Storage<u64, u64, Prepaid<P>>,
///     journal: Detached<u64, u64, (), Prepaid<P>>) -> AdmittedAbortedPublication<'a>
/// where P: AdmittedStoragePolicy + ClonePlanning<u64, u64> + ClonePlanning<u64, Option<u64>> {
///     budget.with_deferred_refund_notifications(|scope| {
///         match journal.try_prepare_admitted(scope, target) {
///             Err((_, _, cleanup)) => cleanup,
///             Ok(_) => panic!("expected local refusal"),
///         }
///     })
/// }
/// ```
pub struct AdmittedAbortedPublication<'scope> {
    _inner: PublicationCleanup<()>,
    _scope: PublicationScope<'scope>,
}

impl<'scope, K: Key, V: Value, Admission, P>
    AdmittedPreparedPublication<'scope, '_, K, V, Admission, P>
where
    P: AdmittedStoragePolicy + ClonePlanning<K, V> + ClonePlanning<K, Option<V>>,
{
    /// Release both writers and return the original journal for a later retry.
    pub fn abort(
        self,
    ) -> (
        Detached<K, V, Admission, Prepaid<P>>,
        AdmittedAbortedPublication<'scope>,
    ) {
        let (journal, retirement) = self.inner.abort();
        (
            journal,
            AdmittedAbortedPublication {
                _inner: retirement,
                _scope: self._scope,
            },
        )
    }

    /// Publish the original pair and retain cleanup with its caller admission.
    /// Every aggregate participant must already be prepared and authorized.
    pub fn publish(self) -> AdmittedPublishedPublication<'scope, K, V, Admission, P> {
        AdmittedPublishedPublication {
            inner: self.inner.publish(),
            _scope: self._scope,
        }
    }
}

/// Caller-owned retained preparation confined to the original refund scope.
///
/// Construction consumes a detached journal, never an executing mutable borrow.
/// All callbacks and cleanup remain in the slot until its aggregate has released
/// every writer. Terminal release or a caught preparation panic forbids recovery.
/// The slot cannot escape its original allocation scope:
/// ```compile_fail
/// use concread::bptree::{ClonePlanning, Prepaid};
/// use iroha_allocation::{AllocationBudget};
/// use mv::{storage::{AdmittedStoragePolicy,
///     AdmittedDetachedPublicationSlot, Detached, Storage}};
/// fn escape<'a, P>(budget: &'a AllocationBudget, target: &'a Storage<u64,u64,Prepaid<P>>,
///     original: Detached<u64,u64,(),Prepaid<P>>) -> AdmittedDetachedPublicationSlot<'a,'a,u64,u64,(),P>
/// where P: AdmittedStoragePolicy + ClonePlanning<u64,u64> + ClonePlanning<u64,Option<u64>> {
///     budget.with_deferred_refund_notifications(|scope| {
///         original.try_publication_slot(scope, target).ok().expect("original pool")
///     })
/// }
/// ```
#[must_use = "retain the original slot and scope through all aggregate writers"]
pub struct AdmittedDetachedPublicationSlot<'scope, 'target, K: Key, V: Value, Admission, P>
where
    P: AdmittedStoragePolicy + ClonePlanning<K, V> + ClonePlanning<K, Option<V>>,
{
    inner: DetachedPublicationSlotInner<'target, K, V, Admission, (), Prepaid<P>>,
    scope: PublicationScope<'scope>,
}
impl<'scope, 'target, K: Key, V: Value, Admission, P>
    AdmittedDetachedPublicationSlot<'scope, 'target, K, V, Admission, P>
where
    P: AdmittedStoragePolicy + ClonePlanning<K, V> + ClonePlanning<K, Option<V>>,
{
    /// Prepare the original prepaid pair by borrowing caller-owned custody.
    /// No successor allocation, payload copy or replacement reservation occurs.
    pub fn try_prepare(&mut self) -> Result<(), PublicationPreparationError<AdmittedStorageError>> {
        self.inner.try_prepare(|_, _| Ok(()))
    }
    /// Release physical writers without reclaiming payloads or invoking callbacks.
    /// This terminal transition cannot create a reusable journal.
    pub fn release_writers(&mut self) {
        self.inner.release_writers();
    }
    /// Return exact original journals after a normal refusal or complete abort.
    /// The actual release cleanup stays in this scoped caller-owned slot.
    pub fn recover_original(&mut self) -> Detached<K, V, Admission, Prepaid<P>> {
        self.inner.recover_original()
    }
    /// Transfer the exact completed physical owner within the same pool scope.
    pub fn into_prepared(self) -> AdmittedPreparedPublication<'scope, 'target, K, V, Admission, P> {
        AdmittedPreparedPublication {
            inner: self.inner.into_prepared(),
            _scope: self.scope,
        }
    }
    fn into_cleanup(self) -> AdmittedAbortedPublication<'scope> {
        AdmittedAbortedPublication {
            _inner: self.inner.into_cleanup(),
            _scope: self.scope,
        }
    }
}

/// A foreign-scope refusal returning the original journal unchanged.
type ScopeRefusal<Journal> = (Journal, PublicationPreparationError<AdmittedStorageError>);

/// A refused admitted preparation: the original journal, its refusal and the
/// scoped cleanup that must outlive every enclosing participant.
type AdmittedPreparationRefusal<'scope, Journal> = (
    Journal,
    PublicationPreparationError<AdmittedStorageError>,
    AdmittedAbortedPublication<'scope>,
);

impl<K: Key, V: Value, Admission, P> Detached<K, V, Admission, Prepaid<P>>
where
    P: AdmittedStoragePolicy + ClonePlanning<K, V> + ClonePlanning<K, Option<V>>,
{
    /// Install original retained custody within its authentic allocation scope.
    /// A foreign scope refuses before any physical acquisition or callback.
    #[expect(
        clippy::result_large_err,
        reason = "refusal returns original custody by value; boxing would allocate on the allocation-free path"
    )]
    pub fn try_publication_slot<'scope, 'target>(
        self,
        scope: &'scope AllocationScope<'scope>,
        target: &'target Storage<K, V, Prepaid<P>>,
    ) -> Result<
        AdmittedDetachedPublicationSlot<'scope, 'target, K, V, Admission, P>,
        ScopeRefusal<Self>,
    > {
        if !scope.belongs_to(
            target
                .allocation
                .as_ref()
                .expect("admitted Storage original pool"),
        ) {
            return Err((
                self,
                PublicationPreparationError::Admission(AdmittedStorageError::ScopeIdentity),
            ));
        }
        Ok(AdmittedDetachedPublicationSlot {
            inner: DetachedPublicationSlotInner::new(self, target),
            scope: PublicationScope::Borrowed { _scope: scope },
        })
    }

    /// Retain the original owned refund scope through physical preparation and cleanup.
    ///
    /// This returns the same admitted slot as borrowed preparation, with an
    /// original scope custodian instead of a borrowed stack boundary. It stays
    /// on the original thread. A foreign pool refuses before touching a writer;
    /// a clone neither allocates a new control nor grants more pool capacity.
    #[expect(
        clippy::result_large_err,
        reason = "refusal returns original custody by value; boxing would allocate on the allocation-free path"
    )]
    pub fn try_publication_slot_owned<'target>(
        self,
        scope: &iroha_allocation::OwnedAllocationScope,
        target: &'target Storage<K, V, Prepaid<P>>,
    ) -> Result<
        AdmittedDetachedPublicationSlot<'target, 'target, K, V, Admission, P>,
        ScopeRefusal<Self>,
    > {
        if !scope.belongs_to(target.allocation_budget()) {
            return Err((
                self,
                PublicationPreparationError::Admission(AdmittedStorageError::ScopeIdentity),
            ));
        }
        Ok(AdmittedDetachedPublicationSlot {
            inner: DetachedPublicationSlotInner::new(self, target),
            scope: PublicationScope::Owned {
                _scope: scope.clone(),
            },
        })
    }

    /// Prepare the exact retained pair without allocation or payload copying.
    ///
    /// The original pool scope must enclose every participating writer. Foreign,
    /// busy, poisoned and changed targets return this same journal. Only detached
    /// owners can leave the scope; a prepared physical owner cannot escape it.
    #[expect(
        clippy::result_large_err,
        reason = "refusal returns original custody by value; boxing would allocate on the allocation-free path"
    )]
    pub fn try_prepare_admitted<'scope, 'target>(
        self,
        scope: &'scope AllocationScope<'scope>,
        target: &'target Storage<K, V, Prepaid<P>>,
    ) -> Result<
        AdmittedPreparedPublication<'scope, 'target, K, V, Admission, P>,
        AdmittedPreparationRefusal<'scope, Self>,
    > {
        let mut slot = self
            .try_publication_slot(scope, target)
            .map_err(|(original, error)| {
                (
                    original,
                    error,
                    AdmittedAbortedPublication {
                        _inner: PublicationCleanup::empty(),
                        _scope: PublicationScope::Borrowed { _scope: scope },
                    },
                )
            })?;
        match slot.try_prepare() {
            Ok(()) => Ok(slot.into_prepared()),
            Err(error) => {
                let original = slot.recover_original();
                Err((original, error, slot.into_cleanup()))
            }
        }
    }
}
