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
    Opening(LaneStoreOpen, bool),
    Ready(Arc<FileLaneBlockStore>),
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
}

impl core::fmt::Debug for LaneStores {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("LaneStores")
            .field("root", &self.root)
            .field("owned", &self.stores.lock().len())
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

    fn store_with_runtime_owner(
        &self,
        lane: LaneId,
        incarnation: &[u8; 32],
        runtime_owner: bool,
    ) -> Result<Arc<FileLaneBlockStore>, Attempt<io::Error>> {
        let key = (lane, *incarnation);
        let mut stores = self.stores.lock();
        if let Some(StoreSlot::Ready(store)) = stores.get(&key) {
            return Ok(Arc::clone(store));
        }
        if stores.contains_key(&key) {
            return Self::resume_store_opening(&mut stores, key, runtime_owner);
        }
        // The absent-key removal originally had no owner to move. Keep the map locked
        // while acquiring the same authority, before entering either large opening stage.
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
        self.open_store_with_authority(&mut stores, key, instance, authority, runtime_owner)
    }

    // Only this post-authority stage constructs the large opening owner. The original
    // registry lock and finite pool remain the same through acquisition and completion.
    fn open_store_with_authority(
        &self,
        stores: &mut BTreeMap<(LaneId, [u8; 32]), StoreSlot>,
        key: (LaneId, [u8; 32]),
        instance: Hash32,
        authority: LaneStoreAuthority,
        runtime_owner: bool,
    ) -> Result<Arc<FileLaneBlockStore>, Attempt<io::Error>> {
        let opening = FileLaneBlockStore::begin_open(
            &self.root,
            &instance,
            Arc::clone(&self.crypto),
            self.budget.clone(),
            authority.schedule,
        )?;
        Self::complete_store_opening(stores, key, opening, !runtime_owner)
    }

    // The caller observed this key under the same exclusive map guard and returned any
    // Ready owner already. Removal therefore transfers this exact retained Opening once.
    fn resume_store_opening(
        stores: &mut BTreeMap<(LaneId, [u8; 32]), StoreSlot>,
        key: (LaneId, [u8; 32]),
        runtime_owner: bool,
    ) -> Result<Arc<FileLaneBlockStore>, Attempt<io::Error>> {
        let (opening, historical) = match stores.remove(&key) {
            Some(StoreSlot::Opening(opening, historical)) => (opening, historical),
            Some(StoreSlot::Ready(..)) => unreachable!("ready owner returned while lock held"),
            None => unreachable!("opening observed while the same map lock is held"),
        };
        let historical =
            historical || (!runtime_owner && !cfg!(all(test, sumeragi_core_mutation = "HC124")));
        Self::complete_store_opening(stores, key, opening, historical)
    }

    // A refused completion returns its unchanged original owner to the same key. Only
    // a fully recovered store publishes Ready; unfinished historical interest is preserved.
    fn complete_store_opening(
        stores: &mut BTreeMap<(LaneId, [u8; 32]), StoreSlot>,
        key: (LaneId, [u8; 32]),
        opening: LaneStoreOpen,
        historical: bool,
    ) -> Result<Arc<FileLaneBlockStore>, Attempt<io::Error>> {
        match opening.complete() {
            Ok(store) => {
                let store = Arc::new(store);
                stores.insert(key, StoreSlot::Ready(Arc::clone(&store)));
                Ok(store)
            }
            Err((opening, error)) => {
                stores.insert(key, StoreSlot::Opening(opening, historical));
                Err(error)
            }
        }
    }

    /// Release a cancelled runtime-only opening, or an idle Ready owner with no reader Arcs
    /// or original pending work. A historical join independently retains unfinished recovery;
    /// ready read, publication and batch owners retain their exact allocations and native lock.
    /// Certified frames remain on disk for independently authenticated replay.
    pub fn release(&self, lane: LaneId, incarnation: &[u8; 32]) {
        let mut stores = self.stores.lock();
        if let Some(StoreSlot::Ready(store)) = stores.get(&(lane, *incarnation)) {
            // The registry lock excludes another registry acquisition. Returned reader Arcs
            // pin the owner before either store mutex is acquired; pending work also pins it.
            if Arc::strong_count(store) > 1 || store.retains_pending_work() {
                return;
            }
        }
        if matches!(
            stores.get(&(lane, *incarnation)),
            Some(StoreSlot::Opening(_, true))
        ) {
            return;
        }
        stores.remove(&(lane, *incarnation));
    }

    /// Release every runtime owner absent from the applied lane set, including openings
    /// that never reached a running driver. Call after stopping retired drivers and recovery
    /// jobs. Historical frames remain available to authenticated global replay; outstanding
    /// readers retain their exclusive ready-store owner until their final Arc is dropped.
    /// A historical reader joining unfinished runtime recovery independently retains that
    /// same opening. Completed ready owners release their lock once readers and original
    /// read, batch or publication work are gone; certified disk frames remain available.
    pub(super) fn release_retired(&self, lanes: &SumeragiLaneState) {
        self.stores.lock().retain(|(lane, incarnation), slot| {
            if lanes
                .lane(*lane)
                .is_some_and(|record| record.incarnation == *incarnation)
            {
                return true;
            }
            match slot {
                StoreSlot::Opening(_, historical) => *historical,
                StoreSlot::Ready(store) => {
                    Arc::strong_count(store) > 1
                        || store.retains_pending_work()
                        || cfg!(all(test, sumeragi_core_mutation = "HC122"))
                }
            }
        });
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
