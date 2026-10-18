//! Retained lane store ownership shared by execution, global merge and historical replay.
//!
//! An opening owns its exclusive disk lock and original funded recovery work until it becomes
//! a ready store. Storage and authority errors remain errors; only an absent committed height
//! is absent. Runtime supplies independently authenticated historical authority.

use crate::execution_attempt::ExecutionAttemptError as Attempt;

use std::{
    collections::BTreeMap,
    io,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use iroha_allocation::AllocationBudget;
use iroha_data_model::{NetworkId, sumeragi_lanes::SumeragiLaneState};
use iroha_model_base::topology::LaneId;
use iroha_sumeragi::types::Hash32;
use parking_lot::Mutex;

mod read_only;
pub(in crate::sumeragi) use read_only::LaneFrameSource;

use super::{
    incarnation_instance,
    merge::{CommittedLaneBlock, LaneBlockSource},
    store::{FileLaneBlockStore, LaneStoreOpen},
};
use crate::sumeragi::{
    availability_schedule::AvailabilitySchedule,
    driver::{SharedCrypto, traits::BlockStore as _},
};

/// Independently pinned authority owners for one native lane incarnation.
/// Returned by the node's authenticated State/archive provider, never derived from the artifact
/// being read. The schedule is pinned to the signed-genesis network and exact lane instance.
pub struct LaneStoreAuthority {
    /// Immutable historical schedule for this exact instance.
    pub schedule: Arc<dyn AvailabilitySchedule>,
}

/// Resolve original authenticated schedule and BLS committee authority for a lane incarnation.
/// Production implementations use signed genesis and certified activation/archive state. They
/// must check the independent requested instance against that authority before returning it.
pub trait LaneStoreAuthorities: Send + Sync {
    /// Return authority pinned to `lane`, `incarnation` and the independently computed `instance`.
    /// `None` means that authority is unresolved; the registry reports `WouldBlock` for it.
    ///
    /// # Errors
    /// Authentication failure, corrupt historical state or I/O.
    fn authority(
        &self,
        lane: LaneId,
        incarnation: &[u8; 32],
        instance: Hash32,
    ) -> Result<Option<LaneStoreAuthority>, Attempt<io::Error>>;
}

// Runtime cancellation and a historical joining reader are independent interests. A refused
// historical recovery keeps its original prefix even when its runtime incarnation retires.
// An unfinished historical recovery has no returned Arc yet; this inline bit records
// its joining reader. Ready readers retain actual Arcs and original pending work instead.
enum StoreSlot {
    Opening(Arc<StoreOpening>, bool),
    Ready(Arc<FileLaneBlockStore>),
}

// A caller clones this original owner while holding the map, then uses only a
// nonblocking per-key guard. The completed owner also stays here until pre-publication
// joiners finish, so an old Opening Arc can never interpret completion as a fresh open.
enum OpeningProgress {
    Pending(Option<LaneStoreOpen>),
    Ready(Arc<FileLaneBlockStore>),
}
struct StoreOpening {
    instance: Hash32,
    schedule: Arc<dyn AvailabilitySchedule>,
    progress: Mutex<OpeningProgress>,
}
impl StoreOpening {
    // Keep the large empty recovery representation out of map/authority caller frames.
    #[inline(never)]
    fn new(instance: Hash32, schedule: Arc<dyn AvailabilitySchedule>) -> Arc<Self> {
        Arc::new(Self {
            instance,
            schedule,
            progress: Mutex::new(OpeningProgress::Pending(None)),
        })
    }
}

/// The exclusive lane block store owners of one node.
pub struct LaneStores {
    root: PathBuf,
    network: NetworkId,
    chain_id: String,
    crypto: SharedCrypto,
    budget: AllocationBudget,
    authorities: Arc<dyn LaneStoreAuthorities>,
    stores: Mutex<BTreeMap<(LaneId, [u8; 32]), StoreSlot>>,
    // Native I/O observation only; genuine authority and recovery validation remain unchanged.
    #[cfg(test)]
    opening_faults: Option<(Hash32, Arc<dyn crate::sumeragi::records::Faults>)>,
}

impl core::fmt::Debug for LaneStores {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let owned = self.stores.lock().len();
        #[cfg(all(test, sumeragi_core_mutation = "HC391"))]
        let _original_map = self.stores.lock();
        formatter
            .debug_struct("LaneStores")
            .field("root", &self.root)
            .field("owned", &owned)
            .finish_non_exhaustive()
    }
}

impl LaneStores {
    /// Bind the node's lane storage root, network, original State pool and authority owners.
    #[must_use]
    pub fn new(
        root: PathBuf,
        network: NetworkId,
        chain_id: String,
        crypto: SharedCrypto,
        budget: AllocationBudget,
        authorities: Arc<dyn LaneStoreAuthorities>,
    ) -> Self {
        Self {
            root,
            network,
            chain_id,
            crypto,
            budget,
            authorities,
            stores: Mutex::new(BTreeMap::new()),
            #[cfg(test)]
            opening_faults: None,
        }
    }

    /// The root directory.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The independently computed instance id of this exact lane incarnation.
    #[must_use]
    pub fn instance(&self, lane: LaneId, incarnation: &[u8; 32]) -> Hash32 {
        incarnation_instance(
            &*self.crypto,
            &self.network,
            &self.chain_id,
            lane,
            incarnation,
        )
    }

    /// Recover one incarnation or return its already recovered shared owner.
    /// Every failed recovery is retained in `Opening`, including its original exclusive lock,
    /// validated prefix and funded read/decode/restoration owners. The caller schedules retries;
    /// this method does not spin, replace a pending owner or expose an unvalidated tip.
    ///
    /// # Errors
    /// Authentication, corruption, I/O or original-resource refusal. `WouldBlock` is retryable;
    /// callers must not reinterpret any other error as a missing or empty store.
    pub fn store(
        &self,
        lane: LaneId,
        incarnation: &[u8; 32],
    ) -> Result<Arc<FileLaneBlockStore>, Attempt<io::Error>> {
        self.store_with_runtime_owner(lane, incarnation, false)
    }

    /// Recover a store for an applied runtime incarnation. Unfinished runtime-only recovery
    /// may cancel after that incarnation retires; a joining historical `store` call retains
    /// the original opening independently. Ready readers retain actual Arcs and pending work.
    pub(super) fn runtime_store(
        &self,
        lane: LaneId,
        incarnation: &[u8; 32],
    ) -> Result<Arc<FileLaneBlockStore>, Attempt<io::Error>> {
        self.store_with_runtime_owner(lane, incarnation, true)
    }

    // All registry-owned buffers use this original pool. Keep every physical map/store
    // guard inside the scope so retirement and recovery callbacks may safely reenter.
    fn with_original_refunds<R>(&self, operation: impl FnOnce() -> R) -> R {
        if cfg!(all(test, sumeragi_core_mutation = "HC348")) {
            operation()
        } else {
            self.budget
                .with_deferred_refund_notifications(|_| operation())
        }
    }

    fn store_with_runtime_owner(
        &self,
        lane: LaneId,
        incarnation: &[u8; 32],
        runtime_owner: bool,
    ) -> Result<Arc<FileLaneBlockStore>, Attempt<io::Error>> {
        self.with_original_refunds(|| {
            let key = (lane, *incarnation);
            let mut stores = self.stores.lock();
            if let Some(StoreSlot::Ready(store)) = stores.get(&key) {
                return Ok(Arc::clone(store));
            }
            if stores.contains_key(&key) {
                let opening = Self::resume_store_opening(&mut stores, key, runtime_owner);
                drop(stores);
                return self.complete_store_opening(key, opening);
            }
            // Native authority acquisition may synchronously notify original State readers.
            // Release the registry before entering that owner, including on partial refusal.
            #[cfg(not(all(test, sumeragi_core_mutation = "HC353")))]
            drop(stores);
            let instance = self.instance(lane, incarnation);
            let authority = self
                .authorities
                .authority(lane, incarnation, instance)?
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "historical lane authority is unresolved",
                    )
                })?;
            if authority.schedule.instance() != instance {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "historical lane schedule belongs to another incarnation",
                )
                .into());
            }
            #[cfg(not(all(test, sumeragi_core_mutation = "HC353")))]
            let mut stores = self.stores.lock();
            // A concurrent caller or synchronous reader callback may have acquired this key.
            // Join its exact Ready/Opening owner before constructing any new opening. A
            // historical join still records its independent interest in unfinished recovery.
            if let Some(StoreSlot::Ready(store)) = stores.get(&key) {
                return Ok(Arc::clone(store));
            }
            if stores.contains_key(&key) {
                let opening = Self::resume_store_opening(&mut stores, key, runtime_owner);
                drop(stores);
                return self.complete_store_opening(key, opening);
            }
            let opening = Self::open_store_with_authority(
                &mut stores,
                key,
                instance,
                authority,
                runtime_owner,
            );
            drop(stores);
            self.complete_store_opening(key, opening)
        })
    }

    // Publish one retained authority owner under the short map guard. Native directory
    // creation/enumeration and complete recovery happen only after that guard is dropped.
    fn open_store_with_authority(
        stores: &mut BTreeMap<(LaneId, [u8; 32]), StoreSlot>,
        key: (LaneId, [u8; 32]),
        instance: Hash32,
        authority: LaneStoreAuthority,
        runtime_owner: bool,
    ) -> Arc<StoreOpening> {
        let opening = StoreOpening::new(instance, authority.schedule);
        stores.insert(
            key,
            StoreSlot::Opening(Arc::clone(&opening), !runtime_owner),
        );
        opening
    }

    // The map serializes historical interest; no busy per-key owner can prevent a
    // joining historical reader from retaining the same original opening.
    fn resume_store_opening(
        stores: &mut BTreeMap<(LaneId, [u8; 32]), StoreSlot>,
        key: (LaneId, [u8; 32]),
        runtime_owner: bool,
    ) -> Arc<StoreOpening> {
        let Some(StoreSlot::Opening(opening, historical)) = stores.get_mut(&key) else {
            unreachable!("ready owner returned while the same map lock is held")
        };
        *historical |= !runtime_owner && !cfg!(all(test, sumeragi_core_mutation = "HC124"));
        Arc::clone(opening)
    }

    fn complete_store_opening(
        &self,
        key: (LaneId, [u8; 32]),
        opening: Arc<StoreOpening>,
    ) -> Result<Arc<FileLaneBlockStore>, Attempt<io::Error>> {
        let mut progress = opening.progress.try_lock().ok_or_else(|| {
            io::Error::new(io::ErrorKind::WouldBlock, "original lane recovery is busy")
        })?;
        // A caller may have cloned Opening just before another caller published Ready.
        // Its exact completed Arc remains in this owner until that joining call retires.
        if let OpeningProgress::Ready(store) = &*progress {
            return Ok(Arc::clone(store));
        }
        let OpeningProgress::Pending(original) = &mut *progress else {
            unreachable!("completed original returned above")
        };
        let store = {
            #[cfg(all(test, sumeragi_core_mutation = "HC364"))]
            let _registry = self.stores.lock();
            self.progress_store_opening(&opening, original)?
        };
        *progress = OpeningProgress::Ready(Arc::clone(&store));
        let mut stores = self.stores.lock();
        // An active Opening Arc prevents retirement; only this per-key guard can finish it.
        if !matches!(stores.get(&key), Some(StoreSlot::Opening(retained, _))
            if Arc::ptr_eq(retained, &opening))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "original lane recovery owner is no longer registered",
            )
            .into());
        }
        stores.insert(key, StoreSlot::Ready(Arc::clone(&store)));
        Ok(store)
    }

    // Keep all large LaneStoreOpen values in one separate recovery frame. The map and
    // joining callers carry only Arcs; original errors return the same owner to this slot.
    #[inline(never)]
    fn progress_store_opening(
        &self,
        opening: &StoreOpening,
        original: &mut Option<LaneStoreOpen>,
    ) -> Result<Arc<FileLaneBlockStore>, Attempt<io::Error>> {
        #[cfg(test)]
        if original.is_none()
            && let Some((instance, faults)) = &self.opening_faults
            && *instance == opening.instance
        {
            *original = Some(FileLaneBlockStore::begin_open_with_faults(
                &self.root,
                &opening.instance,
                Arc::clone(&self.crypto),
                self.budget.clone(),
                Arc::clone(&opening.schedule),
                Arc::clone(faults),
            )?);
        }
        if original.is_none() {
            *original = Some(FileLaneBlockStore::begin_open(
                &self.root,
                &opening.instance,
                Arc::clone(&self.crypto),
                self.budget.clone(),
                Arc::clone(&opening.schedule),
            )?);
        }
        match original
            .take()
            .expect("original opening retained above")
            .complete()
        {
            Ok(store) => Ok(Arc::new(store)),
            Err((opening, error)) => {
                *original = Some(opening);
                Err(error)
            }
        }
    }

    /// Release a cancelled runtime-only opening, or an idle Ready owner with no reader Arcs
    /// or original pending work. A historical join independently retains unfinished recovery;
    /// ready read, publication and batch owners retain their exact allocations and native lock.
    /// An in-flight opening Arc also pins its exact exclusive owner until the call returns;
    /// a later reconciliation can cancel an idle runtime-only refusal.
    /// Certified frames remain on disk for independently authenticated replay.
    pub fn release(&self, lane: LaneId, incarnation: &[u8; 32]) {
        self.with_original_refunds(|| {
            let retired = {
                let mut stores = self.stores.lock();
                if let Some(StoreSlot::Ready(store)) = stores.get(&(lane, *incarnation)) {
                    // Reader Arcs and original pending work retain this exact owner.
                    if Arc::strong_count(store) > 1 || store.retains_pending_work() {
                        return;
                    }
                }
                if matches!(
                    stores.get(&(lane, *incarnation)),
                    Some(StoreSlot::Opening(opening, historical))
                        if *historical || Arc::strong_count(opening) > 1
                ) {
                    return;
                }
                stores.remove(&(lane, *incarnation))
            };
            // Refund deferral cannot postpone arbitrary final authority/backend
            // destructors. Drop the original owner only after releasing the map.
            #[cfg(all(
                test,
                any(sumeragi_core_mutation = "HC348", sumeragi_core_mutation = "HC415")
            ))]
            let _original_map = self.stores.lock();
            drop(retired);
        })
    }

    /// Resume each retired Ready owner's exact admitted publication outside the maps.
    /// A refusal retains the same Arc and prepared work for the next lifecycle check;
    /// no caller-supplied body, authority replacement, or history deletion is involved.
    pub(super) fn resume_retired_publications(
        &self,
        lanes: &SumeragiLaneState,
        physically_retired: impl Fn(&(LaneId, [u8; 32])) -> bool,
    ) {
        // A callback may register another historical owner while maps are unlocked.
        // Bound this pass by its initial owner count; additions can wait for the next tick.
        let owner_count = self.stores.lock().len();
        let mut after = None;
        for _ in 0..owner_count {
            let next = {
                let stores = self.stores.lock();
                let lower = after.map_or(std::ops::Bound::Unbounded, std::ops::Bound::Excluded);
                stores
                    .range((lower, std::ops::Bound::Unbounded))
                    .find_map(|(key, slot)| {
                        if lanes
                            .lane(key.0)
                            .is_some_and(|record| record.incarnation == key.1)
                        {
                            return None;
                        }
                        match slot {
                            StoreSlot::Ready(store) => Some((*key, Arc::clone(store))),
                            StoreSlot::Opening(_, _) => None,
                        }
                    })
            };
            let Some((key, store)) = next else {
                break;
            };
            after = Some(key);
            self.with_original_refunds(|| {
                // The exact driver may still be finishing an admitted backend call.
                // Check only after dropping the registry map, before touching its store.
                if (physically_retired(&key)
                    || cfg!(all(test, sumeragi_core_mutation = "HC395")))
                    && let Err(error) = store.resume_retired_publication()
                {
                    iroha_logger::warn!(lane = %key.0, %error, "sumeragi: original retired lane publication remains pending");
                }
                // Complete this store's original notifications before another store's I/O.
                // Its final temporary Arc and every refund leave both maps free.
                drop(store);
            });
        }
    }

    /// Release every runtime owner absent from the applied lane set, including openings
    /// that never reached a running driver. Call after stopping retired drivers and recovery
    /// jobs. Historical frames remain available to authenticated global replay; outstanding
    /// readers retain their exclusive ready-store owner until their final Arc is dropped.
    /// A historical reader joining unfinished runtime recovery independently retains that
    /// same opening. Completed ready owners release their lock once readers and original
    /// read, batch or publication work are gone; certified disk frames remain available.
    pub(super) fn release_retired(&self, lanes: &SumeragiLaneState) {
        self.with_original_refunds(|| {
            // A destructor can register another original owner. Bound this pass
            // by its starting size and move one removed owner at a time, without
            // a separately allocated retirement list or callbacks under the map.
            let owner_count = self.stores.lock().len();
            let mut after = None;
            for _ in 0..owner_count {
                let next = {
                    let mut stores = self.stores.lock();
                    let lower = after.map_or(std::ops::Bound::Unbounded, std::ops::Bound::Excluded);
                    let key = stores
                        .range((lower, std::ops::Bound::Unbounded))
                        .next()
                        .map(|(key, _)| *key);
                    key.map(|key| {
                        let keep = lanes
                            .lane(key.0)
                            .is_some_and(|record| record.incarnation == key.1)
                            || match stores
                                .get(&key)
                                .expect("original entry under the same map guard")
                            {
                                StoreSlot::Opening(opening, historical) => {
                                    *historical || Arc::strong_count(opening) > 1
                                }
                                StoreSlot::Ready(store) => {
                                    Arc::strong_count(store) > 1
                                        || store.retains_pending_work()
                                        || cfg!(all(test, sumeragi_core_mutation = "HC122"))
                                }
                            };
                        let retired = if keep { None } else { stores.remove(&key) };
                        (key, retired)
                    })
                };
                let Some((key, retired)) = next else { break };
                after = Some(key);
                #[cfg(all(
                    test,
                    any(sumeragi_core_mutation = "HC348", sumeragi_core_mutation = "HC415")
                ))]
                let _original_map = self.stores.lock();
                drop(retired);
            }
        })
    }
}

impl LaneBlockSource for LaneStores {
    fn tip(&self, lane: LaneId, incarnation: &[u8; 32]) -> Result<Option<u64>, Attempt<io::Error>> {
        self.store(lane, incarnation).and_then(|store| {
            if cfg!(all(test, sumeragi_core_mutation = "HC125")) {
                // Mutation: report a cached durable tip despite an unfinished original read.
                return Ok(Some(store.height()));
            }
            store.authenticated_height().map(Some)
        })
    }

    fn block(
        &self,
        lane: LaneId,
        incarnation: &[u8; 32],
        height: u64,
    ) -> Result<Option<CommittedLaneBlock>, Attempt<io::Error>> {
        self.store(lane, incarnation)?.committed_batch(height)
    }

    fn wait_for(
        &self,
        lane: LaneId,
        incarnation: &[u8; 32],
        height: u64,
        timeout: Duration,
    ) -> Result<bool, Attempt<io::Error>> {
        Ok(self.store(lane, incarnation)?.wait_for(height, timeout))
    }
}

#[cfg(test)]
#[path = "registry/tests.rs"]
mod tests;

#[cfg(test)]
pub(in crate::sumeragi) use tests::observe_pending_lane_retirement_for_test;

#[cfg(test)]
pub(in crate::sumeragi) use tests::{RetiredSyncGate, observe_retired_sync_for_test};

#[cfg(test)]
#[path = "registry/startup_isolation_tests.rs"]
mod startup_isolation_tests;

#[cfg(test)]
pub(in crate::sumeragi) use startup_isolation_tests::{
    StartupSyncGate, observe_startup_sync_for_test,
};
