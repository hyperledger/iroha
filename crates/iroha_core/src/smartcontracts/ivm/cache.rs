#[path = "cache/runtime_slot.rs"]
mod runtime_slot;
use runtime_slot::{IdleRuntimeBacking, IdleRuntimeSlot};

use iroha_crypto::Hash;
use ivm::ProgramMetadata;
use ivm::analysis::{ProgramAnalysis, ProgramAnalysisError};
use ivm::runtime::IvmConfig;
use parking_lot::{Condvar, Mutex};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    ops::{Deref, DerefMut},
    sync::Arc,
};
/// Counters for the bounded prepared-contract artifact store.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PreparedContractCacheStats {
    /// Content-addressed cache hits.
    pub hits: u64,
    /// Content-addressed cache misses.
    pub misses: u64,
    /// Full parse, hash, validation, and predecode operations.
    pub preparations: u64,
    /// Entries removed to enforce the configured capacity.
    pub evictions: u64,
    /// Nested-call VM checkouts served by a warmed runtime.
    pub runtime_hits: u64,
    /// Nested-call VM checkouts that required a new runtime.
    pub runtime_misses: u64,
    /// Prepared programs loaded into newly allocated nested runtimes.
    pub runtime_prepared_loads: u64,
    /// Pristine nested runtime baselines built for dirty-page reset.
    pub runtime_template_builds: u64,
    /// Nested runtimes restored and returned to the shared pool.
    pub runtime_dirty_resets: u64,
}
// Field order makes the last weak reference release its Arc allocation before
// refunding the accompanying control-memory charge.
struct CacheControl<T> {
    weak: std::sync::Weak<Mutex<T>>,
    _memory: Arc<ivm::cache_memory::MemoryReservation>,
}
impl<T> CacheControl<T> {
    fn upgrade(&self) -> Option<Arc<Mutex<T>>> {
        self.weak.upgrade()
    }
}

/// Defer original-pool wakes until the cache-store guard has been destroyed.
///
/// Credits return immediately; only notification waits. The stack scope
/// allocates nothing, including on unwind, and coalesces into an enclosing
/// State refund batch for this same pool. No guard may escape the callback.
fn with_cache_store<T, R>(
    inner: &Mutex<T>,
    budget: &iroha_allocation::AllocationBudget,
    operation: impl FnOnce(&mut parking_lot::MutexGuard<'_, T>) -> R,
) -> R {
    budget.with_deferred_refund_notifications(|_| {
        let mut store = inner.lock();
        operation(&mut store)
    })
}

#[derive(Debug)]
struct PreparedContractStore {
    entries: BTreeMap<Hash, ivm::PreparedContract>,
    preparing: BTreeSet<Hash>,
    order: VecDeque<Hash>,
    nested_runtimes: BTreeMap<RuntimeKey, SharedRuntimePool>,
    nested_runtime_order: VecDeque<RuntimeKey>,
    capacity: usize,
    stats: PreparedContractCacheStats,
    #[cfg(test)]
    checkout_refusal: Option<ivm::error::ExecutionDeferral>,
    // Release aggregate charges after every owned allocation above is destroyed.
    index_memory: ivm::cache_memory::MemoryReservation,
    preparing_memory: ivm::cache_memory::MemoryReservation,
}
/// Cloneable bounded store of immutable prepared contract artifacts.
///
/// The handle is independent from runtime-pool borrowing, so an executing VM
/// can resolve nested contracts without re-entering [`IvmCache`].
#[derive(Clone, Debug)]
pub struct PreparedContractCache {
    _control_memory: Arc<ivm::cache_memory::MemoryReservation>,
    inner: Arc<Mutex<PreparedContractStore>>,
    ready: Arc<Condvar>,
    _eviction: ivm::cache_memory::CacheEvictionRegistration,
    execution_budget: iroha_allocation::AllocationBudget,
}
// The claim outlives preparation, including unwinding before publication. A
// failed worker must never strand every later borrower behind its sentinel.
struct PreparationClaim<'a> {
    cache: &'a PreparedContractCache,
    code_hash: Hash,
    active: bool,
}
impl PreparationClaim<'_> {
    fn finish(&mut self, store: &mut PreparedContractStore) {
        store.preparing.remove(&self.code_hash);
        store.refresh_preparing_memory();
        self.active = false;
    }
}
impl Drop for PreparationClaim<'_> {
    fn drop(&mut self) {
        if self.active {
            self.cache.with_store(|store| {
                store.preparing.remove(&self.code_hash);
                store.refresh_preparing_memory();
                self.cache.ready.notify_all();
            });
        }
    }
}
impl PreparedContractCache {
    fn with_store<R>(
        &self,
        operation: impl FnOnce(&mut parking_lot::MutexGuard<'_, PreparedContractStore>) -> R,
    ) -> R {
        with_cache_store(&self.inner, &self.execution_budget, operation)
    }

    /// Inject a local checkout refusal into this cache owner for attempt-boundary controls.
    #[cfg(test)]
    pub(crate) fn set_checkout_refusal_for_test(
        &self,
        reason: Option<ivm::error::ExecutionDeferral>,
    ) {
        self.with_store(|store| store.checkout_refusal = reason);
    }
    #[cfg(test)]
    fn check_checkout_for_test(&self) -> Result<(), ivm::VMError> {
        match self.with_store(|store| store.checkout_refusal) {
            Some(reason) => Err(ivm::VMError::ExecutionDeferred(reason)),
            None => Ok(()),
        }
    }
    /// Construct a store with the same entry bound used by the runtime cache.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self::with_execution_budget(
            capacity,
            iroha_allocation::AllocationBudget::new(
                iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
            ),
        )
    }

    /// Construct a cache using the State-owned active allocation pool.
    /// Retention remains governed by the independent aggregate cache limit.
    #[must_use]
    pub fn with_execution_budget(
        capacity: usize,
        execution_budget: iroha_allocation::AllocationBudget,
    ) -> Self {
        let inner = Arc::new(Mutex::new(PreparedContractStore {
            index_memory: ivm::cache_memory::MemoryReservation::active(0),
            preparing_memory: ivm::cache_memory::MemoryReservation::active(0),
            entries: BTreeMap::new(),
            preparing: BTreeSet::new(),
            order: VecDeque::new(),
            nested_runtimes: BTreeMap::new(),
            nested_runtime_order: VecDeque::new(),
            capacity,
            stats: PreparedContractCacheStats::default(),
            #[cfg(test)]
            checkout_refusal: None,
        }));
        let control_memory = Arc::new(ivm::cache_memory::MemoryReservation::active(
            norito::core::owned_arc_allocation_bytes::<Mutex<PreparedContractStore>>()
                .expect("cache owner fits")
                + norito::core::owned_arc_allocation_bytes::<Condvar>()
                    .expect("cache notifier fits")
                + norito::core::owned_arc_allocation_bytes::<ivm::cache_memory::MemoryReservation>(
                )
                .expect("accounting owner fits"),
        ));
        let control = CacheControl {
            weak: Arc::downgrade(&inner),
            _memory: Arc::clone(&control_memory),
        };
        let eviction_budget = execution_budget.clone();
        let eviction = ivm::cache_memory::register_cache_evictor(move || {
            if let Some(inner) = control.upgrade() {
                with_cache_store(&inner, &eviction_budget, |store| store.clear_storage());
            }
        });
        Self {
            _control_memory: control_memory,
            inner,
            ready: Arc::new(Condvar::new()),
            _eviction: eviction,
            execution_budget,
        }
    }

    /// Original State-owned pool shared by roots and nested runtime preparation.
    ///
    /// TODO: Enforce admission only after all construction, cloning, nested
    /// invocation and host scratch allocations consume the prepaid owner.
    pub fn execution_budget(&self) -> &iroha_allocation::AllocationBudget {
        &self.execution_budget
    }
    /// Resolve or prepare the artifact identified by `code_hash`.
    ///
    /// Hits do not inspect `bytecode`. Misses validate the complete artifact
    /// hash before publishing the prepared value.
    ///
    /// # Errors
    /// Returns [`ivm::VMError::InvalidMetadata`] for malformed artifacts,
    /// [`ivm::VMError::ArtifactAbiHashMismatch`] for stale ABI bindings, or an
    /// invalid-metadata error for an expected artifact-hash mismatch.
    pub fn get_or_prepare(
        &self,
        code_hash: Hash,
        bytecode: &[u8],
    ) -> Result<ivm::PreparedContract, ivm::VMError> {
        self.get_or_prepare_with_status(code_hash, bytecode)
            .map(|(contract, _)| contract)
    }
    /// Resolve an already prepared artifact by its trusted content address.
    ///
    /// This lookup deliberately takes no byte slice. Nested-call dispatch uses
    /// it before loading contract bytes from world state, so a warm invocation
    /// performs neither a bytecode clone nor another parse/hash/predecode pass.
    #[must_use]
    pub fn get(&self, code_hash: Hash) -> Option<ivm::PreparedContract> {
        self.with_store(|store| {
            let contract = store.entries.get(&code_hash).cloned()?;
            store.stats.hits = store.stats.hits.saturating_add(1);
            store.touch(code_hash);
            Some(contract)
        })
    }
    fn get_or_prepare_with_status(
        &self,
        code_hash: Hash,
        bytecode: &[u8],
    ) -> Result<(ivm::PreparedContract, bool), ivm::VMError> {
        self.execution_budget
            .with_deferred_refund_notifications(|_| self.prepare_with_claim(code_hash, bytecode))
    }

    // The caller's original-pool notification scope encloses this entire
    // attempt. A partial preparation refund must never reenter an active claim.
    fn prepare_with_claim(
        &self,
        code_hash: Hash,
        bytecode: &[u8],
    ) -> Result<(ivm::PreparedContract, bool), ivm::VMError> {
        let cached = self.with_store(|store| {
            loop {
                if let Some(contract) = store.entries.get(&code_hash).cloned() {
                    store.stats.hits = store.stats.hits.saturating_add(1);
                    store.touch(code_hash);
                    return Some(contract);
                }
                if store.preparing.insert(code_hash) {
                    store.refresh_preparing_memory();
                    store.stats.misses = store.stats.misses.saturating_add(1);
                    break None;
                }
                self.ready.wait(store);
            }
        });
        if let Some(contract) = cached {
            return Ok((contract, false));
        }
        let mut claim = PreparationClaim {
            cache: self,
            code_hash,
            active: true,
        };
        let prepared = ivm::prepare_contract_with_memory_budget(bytecode, &self.execution_budget)
            .map_err(ivm::ContractArtifactError::into_vm_error);
        #[cfg(test)]
        preparation_refund_tests::panic_after_preparation_if_requested();
        self.with_store(|store| {
            claim.finish(store);
            let prepared = match prepared {
                Ok(prepared) => prepared,
                Err(error) => {
                    self.ready.notify_all();
                    return Err(error);
                }
            };
            store.stats.preparations = store.stats.preparations.saturating_add(1);
            if prepared.code_hash() != code_hash {
                self.ready.notify_all();
                return Err(ivm::VMError::InvalidMetadata);
            }
            if let Some(existing) = store.entries.get(&code_hash).cloned() {
                if existing.artifact() != prepared.artifact() {
                    self.ready.notify_all();
                    return Err(ivm::VMError::InvalidMetadata);
                }
                store.touch(code_hash);
                self.ready.notify_all();
                return Ok((existing, false));
            }
            store.insert(code_hash, prepared.clone());
            self.ready.notify_all();
            Ok((prepared, true))
        })
    }
    fn publish(&self, contract: ivm::PreparedContract) -> Result<(), ivm::VMError> {
        let code_hash = contract.code_hash();
        self.with_store(|store| {
            if let Some(existing) = store.entries.get(&code_hash).cloned() {
                if existing.artifact() != contract.artifact() {
                    return Err(ivm::VMError::InvalidMetadata);
                }
                store.touch(code_hash);
                return Ok(());
            }
            store.insert(code_hash, contract);
            Ok(())
        })
    }
    /// Check out a VM for a nested contract invocation.
    ///
    /// The pool is shared by every host carrying this prepared-cache handle. Cache hits reuse the
    /// loaded program and restore only memory chunks dirtied by the previous invocation. Re-entrant
    /// calls allocate another runtime when the matching pool is temporarily empty rather than
    /// aliasing mutable VM state. `heap_limit` is part of the runtime identity, so governance
    /// changes cannot reuse a VM carrying stale heap authority.
    pub fn checkout_runtime(
        &self,
        contract: &ivm::PreparedContract,
        gas_limit: u64,
        heap_limit: u64,
    ) -> Result<PreparedRuntimeLease, ivm::VMError> {
        #[cfg(test)]
        self.check_checkout_for_test()?;
        let key = RuntimeKey::new(
            contract.code_hash(),
            stack_limit_for_gas(gas_limit),
            heap_limit,
        );
        let cached = self.with_store(|store| {
            let cached = store.nested_runtimes.get_mut(&key).and_then(|pool| {
                pool.available
                    .take()
                    .map(|(runtime, backing)| (runtime.baseline, runtime.vm, backing))
            });
            if cached.is_some() {
                store.stats.runtime_hits = store.stats.runtime_hits.saturating_add(1);
                store.touch_nested_runtime(key);
            } else {
                store.stats.runtime_misses = store.stats.runtime_misses.saturating_add(1);
            }
            cached
        });
        if let Some((baseline, mut vm, backing)) = cached {
            vm.activate_cached_runtime();
            vm.set_gas_limit(gas_limit);
            return Ok(PreparedRuntimeLease {
                cache: self.clone(),
                key,
                baseline,
                vm: Some(vm),
                backing: Some(backing),
            });
        }
        let mut vm = ivm::IVM::try_new_with_memory_budget(gas_limit, &self.execution_budget)?;
        vm.set_zk_trace_enabled(false);
        vm.memory.set_heap_max_limit(heap_limit)?;
        vm.load_prepared(contract)?;
        vm.set_gas_limit(gas_limit);
        self.with_store(|store| {
            store.stats.runtime_prepared_loads =
                store.stats.runtime_prepared_loads.saturating_add(1);
            store.stats.runtime_template_builds =
                store.stats.runtime_template_builds.saturating_add(1);
        });
        // A cold template prepays its image, tree, register and tracking copies
        // from this VM's original State pool. Keep that fallible allocation
        // outside the shared store mutex so another borrower can
        // resolve or return a prepared artifact while it is being built.
        let baseline = vm.try_runtime_template()?;
        let cacheable = self.with_store(|store| {
            // The artifact may have been evicted while the template was built.
            // Cache admission uses the current store, never the earlier lookup.
            let cacheable = store.capacity != 0 && store.entries.contains_key(&key.code_hash);
            if cacheable && !store.nested_runtimes.contains_key(&key) {
                store.insert_nested_runtime(
                    key,
                    SharedRuntimePool {
                        available: IdleRuntimeSlot::empty(),
                    },
                );
            }
            store.can_return_runtime(key)
        });
        // Optional retention never changes the completed cold VM/template admission.
        // The fixed row is allocated before the lease and outside the store guard.
        let backing = if cacheable && ivm::cache_memory::memory_stats().limit_bytes != 0 {
            IdleRuntimeBacking::try_new(&self.execution_budget).ok()
        } else {
            None
        };
        Ok(PreparedRuntimeLease {
            cache: self.clone(),
            key,
            baseline,
            vm: Some(vm),
            backing,
        })
    }
    fn return_runtime(
        &self,
        key: RuntimeKey,
        baseline: ivm::RuntimeTemplate,
        mut vm: ivm::IVM,
        backing: Option<IdleRuntimeBacking>,
    ) {
        let Some(backing) = backing.filter(|backing| backing.belongs_to(&self.execution_budget))
        else {
            return;
        };
        // A cache entry can disappear while its VM is borrowed. Do not reset
        // or admit that VM's allocations to retention if it no longer has a
        // prepared artifact or another borrower already filled the idle slot.
        if !self.with_store(|store| store.can_return_runtime(key)) {
            return;
        }
        if vm.reset_from_runtime_template(&baseline).is_err() {
            return;
        }
        self.with_store(move |store| {
            // Keep eligibility stable until admission and publication complete.
            // The global retention lock never calls an evictor while held.
            if !store.can_return_runtime(key)
                || !baseline.try_retain_cache_allocations()
                || !vm.try_retain_cache_allocations()
                || !backing.try_retain()
            {
                return;
            }
            store.stats.runtime_dirty_resets = store.stats.runtime_dirty_resets.saturating_add(1);
            let pool = store
                .nested_runtimes
                .entry(key)
                .or_insert_with(|| SharedRuntimePool {
                    available: IdleRuntimeSlot::empty(),
                });
            // One idle runtime per key is sufficient. Concurrent/re-entrant calls
            // may create extra workers, which are discarded as they return.
            if pool.available.is_empty() {
                pool.available
                    .place(backing, PooledRuntime { baseline, vm });
            }
            store.touch_nested_runtime(key);
            store.evict_nested_runtimes();
        });
    }
    /// Return current prepared-artifact cache counters.
    #[must_use]
    pub fn stats(&self) -> PreparedContractCacheStats {
        self.with_store(|store| store.stats)
    }
}
impl Default for PreparedContractCache {
    fn default() -> Self {
        Self::with_capacity(iroha_config::parameters::defaults::pipeline::CACHE_SIZE)
    }
}
impl PreparedContractStore {
    fn can_return_runtime(&self, key: RuntimeKey) -> bool {
        self.capacity != 0
            && self.entries.contains_key(&key.code_hash)
            && self
                .nested_runtimes
                .get(&key)
                .is_none_or(|pool| pool.available.is_empty())
    }

    fn clear_storage(&mut self) {
        self.stats.evictions = self
            .stats
            .evictions
            .saturating_add(self.entries.len() as u64);
        self.entries = BTreeMap::new();
        self.order = VecDeque::new();
        self.nested_runtimes = BTreeMap::new();
        self.nested_runtime_order = VecDeque::new();
        self.index_memory.set_known_bytes(0);
    }
    fn refresh_preparing_memory(&mut self) {
        if self.preparing.is_empty() {
            self.preparing = BTreeSet::new();
            self.preparing_memory.set_known_bytes(0);
        } else {
            match norito::core::owned_btree_allocation_bytes::<Hash, ()>(self.preparing.len()) {
                Ok(bytes) => self
                    .preparing_memory
                    .set_known_bytes(bytes.max(self.preparing_memory.bytes())),
                Err(_) => self.preparing_memory.mark_unmeasured(),
            }
        }
    }
    fn index_bytes(&self) -> Option<usize> {
        let values = [
            norito::core::owned_btree_allocation_bytes::<Hash, ivm::PreparedContract>(
                self.entries.len(),
            )
            .ok()?,
            norito::core::owned_btree_allocation_bytes::<RuntimeKey, SharedRuntimePool>(
                self.nested_runtimes.len(),
            )
            .ok()?,
            self.order
                .capacity()
                .checked_mul(std::mem::size_of::<Hash>())?,
            self.nested_runtime_order
                .capacity()
                .checked_mul(std::mem::size_of::<RuntimeKey>())?,
        ];
        values.into_iter().try_fold(0_usize, usize::checked_add)
    }
    fn retain_index_or_clear(&mut self) {
        if self.entries.is_empty() && self.nested_runtimes.is_empty() {
            self.clear_storage();
            return;
        }
        let Some(bytes) = self.index_bytes() else {
            self.clear_storage();
            return;
        };
        self.index_memory
            .set_known_bytes(bytes.max(self.index_memory.bytes()));
        if !self.index_memory.try_retain() {
            self.clear_storage();
        }
    }

    fn touch(&mut self, code_hash: Hash) {
        if let Some(position) = self
            .order
            .iter()
            .position(|candidate| *candidate == code_hash)
        {
            self.order.remove(position);
        }
        self.order.push_back(code_hash);
        self.retain_index_or_clear();
    }
    fn insert(&mut self, code_hash: Hash, contract: ivm::PreparedContract) {
        if self.capacity == 0 {
            return;
        }
        while !contract.try_retain_allocations() {
            let Some(evicted) = self.order.pop_front() else {
                self.clear_storage();
                return;
            };
            if self.entries.remove(&evicted).is_some() {
                self.stats.evictions = self.stats.evictions.saturating_add(1);
                self.remove_nested_runtimes_for(evicted);
            }
        }
        self.entries.insert(code_hash, contract);
        self.touch(code_hash);
        while self.entries.len() > self.capacity {
            let Some(evicted) = self.order.pop_front() else {
                break;
            };
            if self.entries.remove(&evicted).is_some() {
                self.stats.evictions = self.stats.evictions.saturating_add(1);
                self.remove_nested_runtimes_for(evicted);
            }
        }
    }
    fn touch_nested_runtime(&mut self, key: RuntimeKey) {
        if let Some(position) = self
            .nested_runtime_order
            .iter()
            .position(|candidate| *candidate == key)
        {
            self.nested_runtime_order.remove(position);
        }
        self.nested_runtime_order.push_back(key);
        self.retain_index_or_clear();
    }
    fn insert_nested_runtime(&mut self, key: RuntimeKey, pool: SharedRuntimePool) {
        if self.capacity == 0 {
            return;
        }
        self.nested_runtimes.insert(key, pool);
        self.touch_nested_runtime(key);
        self.evict_nested_runtimes();
    }
    fn evict_nested_runtimes(&mut self) {
        while self.nested_runtimes.len() > self.capacity {
            let Some(evicted) = self.nested_runtime_order.pop_front() else {
                break;
            };
            if self.nested_runtimes.remove(&evicted).is_some() {
                self.stats.evictions = self.stats.evictions.saturating_add(1);
            }
        }
    }
    fn remove_nested_runtimes_for(&mut self, code_hash: Hash) {
        self.nested_runtimes
            .retain(|key, _| key.code_hash != code_hash);
        self.nested_runtime_order
            .retain(|key| key.code_hash != code_hash);
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct SummaryKey {
    code_hash: Hash,
}
impl SummaryKey {
    fn new(code_hash: Hash) -> Self {
        Self { code_hash }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct RuntimeKey {
    code_hash: Hash,
    stack_limit: u64,
    heap_limit: u64,
}
impl RuntimeKey {
    fn new(code_hash: Hash, stack_limit: u64, heap_limit: u64) -> Self {
        Self {
            code_hash,
            stack_limit,
            heap_limit,
        }
    }
    fn summary_key(&self) -> SummaryKey {
        SummaryKey::new(self.code_hash)
    }
}
fn stack_limit_for_gas(gas_limit: u64) -> u64 {
    IvmConfig::new(gas_limit).stack_limit_for_gas()
}
/// Return whether a syscall is available to a contract-less IVM program.
///
/// The canonical policy lives in `ivm_abi` and is hashed into ABI V1. Core delegates to it at both
/// admission and host dispatch so the two enforcement points cannot drift.
#[must_use]
pub(crate) fn is_generic_syscall_allowed(number: u32) -> bool {
    ivm::syscalls::is_generic_program_syscall_allowed(ivm::SyscallPolicy::AbiV1, number)
}
/// Summary of a compiled IVM program derived during admission.
#[derive(Clone, Debug)]
pub struct ProgramSummary {
    prepared: ivm::PreparedContract,
    prepared_cache: PreparedContractCache,
    /// Parsed program metadata.
    pub metadata: ProgramMetadata,
    /// Offset to the start of the decoded instructions (after header + literal prefix).
    pub code_offset: usize,
    /// Length of the program header.
    pub header_len: usize,
    /// Domain-separated hash of the complete deployable artifact.
    pub code_hash: Hash,
    /// ABI hash derived from the declared ABI version.
    pub abi_hash: Hash,
    /// Hash of the encoded metadata header.
    pub meta_hash: Hash,
}
/// Fully validated ABI-bound generic IVM program.
///
/// Generic programs deliberately have no `CNTR` interface, contract identity,
/// entrypoints, or durable-state schema. They are used for low-level IVM
/// executables such as system triggers and state-free low-level programs. The
/// authenticated fixed header still binds them to the exact local ABI.
#[derive(Clone, Debug)]
pub struct GenericProgramSummary {
    program: ivm::cache_memory::SharedAllocation<u8>,
    /// Parsed program metadata.
    pub metadata: ProgramMetadata,
    /// Offset to the first decoded instruction.
    pub code_offset: usize,
    /// Length of the authenticated fixed header.
    pub header_len: usize,
    /// Domain-separated hash of the complete program image.
    pub code_hash: Hash,
    /// ABI hash authenticated by the fixed header.
    pub abi_hash: Hash,
    /// Hash of the canonical encoded metadata header.
    pub meta_hash: Hash,
}
impl GenericProgramSummary {
    /// Return the complete validated program image.
    #[must_use]
    pub fn program(&self) -> &[u8] {
        &self.program
    }
    /// Clone the shared immutable program image without copying its bytes.
    #[must_use]
    pub fn shared_program(&self) -> ivm::cache_memory::SharedAllocation<u8> {
        self.program.clone()
    }
}
/// Admission result for either a self-describing contract or a generic IVM program.
#[derive(Clone, Debug)]
pub enum ExecutableProgramSummary {
    /// A deployable, self-describing `CNTR` contract.
    Contract(ProgramSummary),
    /// An ABI-authenticated generic program without contract identity.
    Generic(GenericProgramSummary),
}
impl ExecutableProgramSummary {
    /// Return the parsed metadata shared by both program kinds.
    #[must_use]
    pub fn metadata(&self) -> &ProgramMetadata {
        match self {
            Self::Contract(summary) => &summary.metadata,
            Self::Generic(summary) => &summary.metadata,
        }
    }
    /// Return the instruction offset shared by both program kinds.
    #[must_use]
    pub fn code_offset(&self) -> usize {
        match self {
            Self::Contract(summary) => summary.code_offset,
            Self::Generic(summary) => summary.code_offset,
        }
    }
    /// Return the complete program hash shared by both program kinds.
    #[must_use]
    pub fn code_hash(&self) -> Hash {
        match self {
            Self::Contract(summary) => summary.code_hash,
            Self::Generic(summary) => summary.code_hash,
        }
    }
    /// Return the authenticated ABI hash shared by both program kinds.
    #[must_use]
    pub fn abi_hash(&self) -> Hash {
        match self {
            Self::Contract(summary) => summary.abi_hash,
            Self::Generic(summary) => summary.abi_hash,
        }
    }
}
impl ProgramSummary {
    /// Prepare and summarize one complete deployable contract artifact.
    ///
    /// This is the public construction boundary for callers that need a self-contained summary
    /// without managing an [`IvmCache`]. It validates and predecodes the artifact and initializes
    /// the private prepared-runtime cache carried by the returned summary.
    ///
    /// # Errors
    /// Returns [`ivm::VMError`] when the bytes are not a valid deployable IVM contract artifact.
    pub fn from_artifact(bytecode: &[u8]) -> Result<Self, ivm::VMError> {
        IvmCache::new().summarize_program(bytecode)
    }
    /// Return the immutable validated contract shared by analysis and runtimes.
    #[must_use]
    pub fn prepared_contract(&self) -> &ivm::PreparedContract {
        &self.prepared
    }
    /// Return the shared bounded cache used for nested contract preparation.
    #[must_use]
    pub fn prepared_contract_cache(&self) -> PreparedContractCache {
        self.prepared_cache.clone()
    }
    /// Check out a warmed runtime backed by the shared prepared-artifact pool.
    ///
    /// The owned lease does not hold the cache mutex while guest code runs. Dropping it on any
    /// success, error, or unwind path restores dirty memory chunks and returns the VM to the pool.
    ///
    /// # Errors
    /// Returns [`ivm::VMError`] if a cold runtime cannot load the validated
    /// prepared contract or `heap_limit` lies outside the ABI heap window.
    pub fn checkout_runtime(
        &self,
        gas_limit: u64,
        heap_limit: u64,
    ) -> Result<PreparedRuntimeLease, ivm::VMError> {
        self.prepared_cache
            .checkout_runtime(self.prepared_contract(), gas_limit, heap_limit)
    }
}
struct RuntimePool {
    available: IdleRuntimeSlot,
}
struct SharedRuntimePool {
    available: IdleRuntimeSlot,
}
struct PooledRuntime {
    baseline: ivm::RuntimeTemplate,
    vm: ivm::IVM,
}
impl std::fmt::Debug for SharedRuntimePool {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SharedRuntimePool")
            .field("baseline_policy", &"<paired-per-runtime>")
            .field("available_runtimes", &self.available.len())
            .finish()
    }
}
/// Checked-out nested-call runtime returned to the shared prepared cache on
/// every success, error, and unwind path.
pub struct PreparedRuntimeLease {
    cache: PreparedContractCache,
    key: RuntimeKey,
    baseline: ivm::RuntimeTemplate,
    vm: Option<ivm::IVM>,
    backing: Option<IdleRuntimeBacking>,
}
impl Deref for PreparedRuntimeLease {
    type Target = ivm::IVM;
    fn deref(&self) -> &Self::Target {
        self.vm
            .as_ref()
            .expect("prepared runtime lease always owns a VM")
    }
}
impl DerefMut for PreparedRuntimeLease {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.vm
            .as_mut()
            .expect("prepared runtime lease always owns a VM")
    }
}
impl Drop for PreparedRuntimeLease {
    fn drop(&mut self) {
        if let Some(vm) = self.vm.take() {
            self.cache
                .return_runtime(self.key, self.baseline.clone(), vm, self.backing.take());
        }
    }
}
/// Checked-out warmed runtime that automatically returns to its cache.
///
/// Dropping the lease restores only dirty memory chunks and makes the same VM
/// available to the next invocation. This avoids cloning the VM's complete
/// stack, heap, code image, and Merkle tree on cache hits.
pub struct RuntimeLease<'a> {
    cache: &'a mut IvmCache,
    key: RuntimeKey,
    baseline: ivm::RuntimeTemplate,
    vm: Option<ivm::IVM>,
    backing: Option<IdleRuntimeBacking>,
}
impl Deref for RuntimeLease<'_> {
    type Target = ivm::IVM;
    fn deref(&self) -> &Self::Target {
        self.vm.as_ref().expect("runtime lease always owns a VM")
    }
}
impl DerefMut for RuntimeLease<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.vm.as_mut().expect("runtime lease always owns a VM")
    }
}
impl Drop for RuntimeLease<'_> {
    fn drop(&mut self) {
        if let Some(vm) = self.vm.take() {
            self.cache
                .return_runtime(self.key, self.baseline.clone(), vm, self.backing.take());
        }
    }
}
/// Lightweight cache counters for diagnostics and tests.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CacheStats {
    /// Metadata cache hits.
    pub metadata_hits: u64,
    /// Metadata cache misses.
    pub metadata_misses: u64,
    /// Runtime template hits.
    pub runtime_hits: u64,
    /// Runtime template misses.
    pub runtime_misses: u64,
    /// Static analysis cache hits.
    pub analysis_hits: u64,
    /// Static analysis cache misses.
    pub analysis_misses: u64,
    /// Full-artifact hashes computed by the byte-slice convenience path.
    pub artifact_hashes: u64,
    /// Complete preparations performed, each including parse, hash, and predecode.
    pub preparations: u64,
    /// Cold VMs populated from a cached prepared contract.
    pub prepared_loads: u64,
    /// Pristine runtime baselines built for a program/stack configuration.
    pub template_builds: u64,
    /// Warm runtimes restored through dirty-page reset before pooling.
    pub dirty_resets: u64,
    /// Evictions triggered by capacity limits.
    pub evictions: u64,
}
/// Admission-time cache for IVM program summaries and warmed runtimes.
pub struct IvmCache {
    _control_memory: Arc<ivm::cache_memory::MemoryReservation>,
    prepared_contracts: PreparedContractCache,
    local: Arc<Mutex<LocalCacheStore>>,
    _eviction: ivm::cache_memory::CacheEvictionRegistration,
    capacity: usize,
    stats: CacheStats,
}
struct LocalCacheStore {
    summaries: BTreeMap<SummaryKey, ProgramSummary>,
    generic_summaries: BTreeMap<SummaryKey, GenericProgramSummary>,
    runtime_templates: BTreeMap<RuntimeKey, RuntimePool>,
    analyses: BTreeMap<SummaryKey, ProgramAnalysis>,
    summary_order: VecDeque<SummaryKey>,
    runtime_order: VecDeque<RuntimeKey>,
    index_memory: ivm::cache_memory::MemoryReservation,
    capacity: usize,
    evictions: u64,
}
impl Default for IvmCache {
    fn default() -> Self {
        Self::new()
    }
}
impl IvmCache {
    /// Run synchronous cache work with refund custody through its enclosing mutex.
    ///
    /// Capture the actual locked cache's original pool, then move that guard
    /// into the refund scope before running any operation that can free backing.
    /// The guard retires before notifications on both success and unwind. A
    /// caller holding additional physical writers must supply an outer refund
    /// owner for those writers; no borrowed cache guard or runtime can escape.
    pub(crate) fn with_locked<R>(cache: &Mutex<Self>, operation: impl FnOnce(&mut Self) -> R) -> R {
        let mut guard = cache.lock();
        let budget = guard.prepared_contracts.execution_budget().clone();
        budget.with_deferred_refund_notifications(move |_| {
            let result = operation(&mut guard);
            drop(guard);
            result
        })
    }

    fn with_local<R>(&self, operation: impl FnOnce(&mut LocalCacheStore) -> R) -> R {
        with_cache_store(
            &self.local,
            self.prepared_contracts.execution_budget(),
            |store| operation(store),
        )
    }

    /// Constructor with a default capacity of 64 entries.
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(iroha_config::parameters::defaults::pipeline::CACHE_SIZE)
    }
    /// Construct a cache with a specific maximum number of entries.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self::with_prepared_contract_cache(capacity, PreparedContractCache::with_capacity(capacity))
    }
    /// Construct a worker-local summary/analysis cache backed by a shared
    /// immutable prepared-contract and owned-runtime pool.
    ///
    /// This keeps cheap LRU bookkeeping local while ensuring parallel workers
    /// prepare each content-addressed artifact only once.
    #[must_use]
    pub fn with_prepared_contract_cache(
        capacity: usize,
        prepared_contracts: PreparedContractCache,
    ) -> Self {
        let local = Arc::new(Mutex::new(LocalCacheStore {
            summaries: BTreeMap::new(),
            generic_summaries: BTreeMap::new(),
            runtime_templates: BTreeMap::new(),
            analyses: BTreeMap::new(),
            summary_order: VecDeque::new(),
            runtime_order: VecDeque::new(),
            index_memory: ivm::cache_memory::MemoryReservation::active(0),
            capacity,
            evictions: 0,
        }));
        let control_memory = Arc::new(ivm::cache_memory::MemoryReservation::active(
            norito::core::owned_arc_allocation_bytes::<Mutex<LocalCacheStore>>()
                .expect("cache owner fits")
                + norito::core::owned_arc_allocation_bytes::<ivm::cache_memory::MemoryReservation>(
                )
                .expect("accounting owner fits"),
        ));
        let control = CacheControl {
            weak: Arc::downgrade(&local),
            _memory: Arc::clone(&control_memory),
        };
        let eviction_budget = prepared_contracts.execution_budget().clone();
        let eviction = ivm::cache_memory::register_cache_evictor(move || {
            if let Some(local) = control.upgrade() {
                with_cache_store(&local, &eviction_budget, |store| store.clear_storage());
            }
        });
        Self {
            _control_memory: control_memory,
            prepared_contracts,
            local,
            _eviction: eviction,
            capacity,
            stats: CacheStats::default(),
        }
    }

    /// Prepare a contract and cache its summary by the complete artifact hash.
    ///
    /// # Errors
    /// Returns [`ivm::VMError`] if the bytecode is not a valid deployable contract.
    pub fn summarize_program(&mut self, bytecode: &[u8]) -> Result<ProgramSummary, ivm::VMError> {
        let code_hash = ivm::contract_code_hash(bytecode);
        self.stats.artifact_hashes = self.stats.artifact_hashes.saturating_add(1);
        self.summarize_program_with_hash(code_hash, bytecode)
    }
    /// Validate and summarize either a self-describing contract or a generic ABI-bound IVM program.
    ///
    /// The presence of a canonical `CNTR` section is the only discriminator. Contract artifacts
    /// retain the stronger full artifact verifier and prepared-contract cache; generic programs are
    /// fully loaded once to validate literals, instructions, control flow, and syscall policy.
    ///
    /// # Errors
    /// Returns [`ivm::VMError`] when the header, ABI binding, contract section,
    /// literal table, or instruction stream is invalid.
    pub fn summarize_executable(
        &mut self,
        bytecode: &[u8],
    ) -> Result<ExecutableProgramSummary, ivm::VMError> {
        let header = ProgramMetadata::parse_header(bytecode)?;
        if header.declares_contract_interface() {
            self.summarize_program(bytecode)
                .map(ExecutableProgramSummary::Contract)
        } else {
            self.summarize_generic_program(bytecode)
                .map(ExecutableProgramSummary::Generic)
        }
    }
    /// Validate and summarize an ABI-bound program that has no `CNTR` section.
    ///
    /// # Errors
    /// Returns [`ivm::VMError::InvalidMetadata`] if a contract interface is
    /// present or any generic-program validation fails.
    pub fn summarize_generic_program(
        &mut self,
        bytecode: &[u8],
    ) -> Result<GenericProgramSummary, ivm::VMError> {
        let code_hash = ivm::contract_code_hash(bytecode);
        self.stats.artifact_hashes = self.stats.artifact_hashes.saturating_add(1);
        let key = SummaryKey::new(code_hash);
        let cached = self.with_local(|local| local.generic_summaries.get(&key).cloned());
        if let Some(hit) = cached {
            if hit.program() != bytecode {
                return Err(ivm::VMError::InvalidMetadata);
            }
            self.stats.metadata_hits = self.stats.metadata_hits.saturating_add(1);
            self.touch_summary(key);
            return Ok(hit);
        }
        let parsed = ProgramMetadata::parse(bytecode)?;
        if parsed.contract_interface.is_some() {
            return Err(ivm::VMError::InvalidMetadata);
        }
        self.finish_generic_program_summary(
            bytecode,
            code_hash,
            parsed.metadata,
            parsed.code_offset,
            parsed.header_len,
        )
    }
    /// Validate and summarize a generic program whose metadata was already parsed by the caller.
    ///
    /// `code_hash` must be the authenticated complete-program hash retained by world state. The
    /// verifier recomputes and compares that hash while loading the program, so callers cannot
    /// substitute parsed fields from another image. This entry point avoids repeating the
    /// metadata parse needed to distinguish a contract artifact from a generic program.
    ///
    /// # Errors
    /// Returns [`ivm::VMError`] if full loading, control-flow analysis, syscall policy, or the
    /// authenticated hash check fails.
    pub(crate) fn summarize_generic_program_with_parsed_metadata(
        &mut self,
        bytecode: &[u8],
        code_hash: Hash,
        metadata: ProgramMetadata,
        code_offset: usize,
        header_len: usize,
    ) -> Result<GenericProgramSummary, ivm::VMError> {
        let key = SummaryKey::new(code_hash);
        let cached = self.with_local(|local| local.generic_summaries.get(&key).cloned());
        if let Some(hit) = cached {
            if hit.program() != bytecode {
                return Err(ivm::VMError::InvalidMetadata);
            }
            self.stats.metadata_hits = self.stats.metadata_hits.saturating_add(1);
            self.touch_summary(key);
            return Ok(hit);
        }
        self.finish_generic_program_summary(bytecode, code_hash, metadata, code_offset, header_len)
    }
    fn finish_generic_program_summary(
        &mut self,
        bytecode: &[u8],
        code_hash: Hash,
        metadata: ProgramMetadata,
        code_offset: usize,
        header_len: usize,
    ) -> Result<GenericProgramSummary, ivm::VMError> {
        let key = SummaryKey::new(code_hash);
        // Loading performs the same literal, instruction, control-flow, and
        // syscall validation used at execution. Both immutable instruction
        // arrays consume this State's original pool, outside global caches;
        // warmed runtimes retain those owners for subsequent invocations.
        let mut verifier =
            ivm::IVM::try_new_with_memory_budget(0, self.prepared_contracts.execution_budget())?;
        verifier.set_zk_trace_enabled(false);
        verifier.load_program(bytecode)?;
        if Hash::prehashed(verifier.code_hash()) != code_hash {
            return Err(ivm::VMError::InvalidMetadata);
        }
        let syscalls = ivm::analysis::program_syscall_numbers(bytecode)
            .map_err(ProgramAnalysisError::into_vm_error)?;
        if let Some(forbidden) = syscalls
            .filter(|number| !is_generic_syscall_allowed(*number))
            .min()
        {
            return Err(ivm::VMError::GenericSyscallNotAllowed { syscall: forbidden });
        }
        let summary = GenericProgramSummary {
            program: ivm::cache_memory::SharedAllocation::try_copy_from_slice_with_memory_budget(
                bytecode,
                self.prepared_contracts.execution_budget(),
            )?,
            code_offset,
            header_len,
            abi_hash: Hash::prehashed(ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1)),
            meta_hash: Hash::new(metadata.encode()),
            metadata,
            code_hash,
        };
        self.insert_generic_summary(key, summary.clone());
        self.stats.metadata_misses = self.stats.metadata_misses.saturating_add(1);
        self.stats.preparations = self.stats.preparations.saturating_add(1);
        Ok(summary)
    }
    /// Return the prepared summary for a trusted content-addressed artifact.
    ///
    /// Cache hits use only `code_hash` and do not inspect, parse, hash, or
    /// predecode `bytecode`. On a miss, preparation recomputes and verifies the
    /// complete artifact hash before publishing the entry.
    ///
    /// # Errors
    /// Returns [`ivm::VMError`] if preparation fails or `bytecode` does not match `code_hash`.
    pub fn summarize_program_with_hash(
        &mut self,
        code_hash: Hash,
        bytecode: &[u8],
    ) -> Result<ProgramSummary, ivm::VMError> {
        if let Some(hit) = self.cached_program_summary(code_hash)? {
            return Ok(hit);
        }
        let key = SummaryKey::new(code_hash);
        let (prepared, prepared_now) = self
            .prepared_contracts
            .get_or_prepare_with_status(code_hash, bytecode)?;
        if prepared_now {
            self.stats.preparations = self.stats.preparations.saturating_add(1);
        }
        let metadata = prepared.metadata().clone();
        let code_offset = prepared.code_offset();
        let header_len = prepared.header_len();
        let meta_hash = Hash::new(metadata.encode());
        // Contract preparation has already compared the authenticated CNTR
        // binding with the local descriptor. Preserve the artifact-carried
        // value here so manifest checks never substitute node-local metadata.
        let abi_hash = Hash::prehashed(prepared.contract_interface().abi_hash);
        let summary = ProgramSummary {
            prepared,
            prepared_cache: self.prepared_contracts.clone(),
            metadata,
            code_offset,
            header_len,
            code_hash,
            abi_hash,
            meta_hash,
        };
        self.insert_summary(key, summary.clone());
        self.stats.metadata_misses = self.stats.metadata_misses.saturating_add(1);
        Ok(summary)
    }
    /// Resolve a locally cached summary by a trusted admitted content address.
    ///
    /// This path takes no byte slice, so callers can check a world-state binding before copying or
    /// borrowing the stored artifact. `Ok(None)` means the exact bytes must be supplied to
    /// [`Self::summarize_program_with_hash`].
    ///
    /// # Errors
    /// Returns [`ivm::VMError`] if the local summary conflicts with the shared
    /// immutable prepared-artifact store.
    pub fn cached_program_summary(
        &mut self,
        code_hash: Hash,
    ) -> Result<Option<ProgramSummary>, ivm::VMError> {
        let key = SummaryKey::new(code_hash);
        let Some(hit) = self.with_local(|local| local.summaries.get(&key).cloned()) else {
            return Ok(None);
        };
        self.prepared_contracts.publish(hit.prepared.clone())?;
        self.stats.metadata_hits = self.stats.metadata_hits.saturating_add(1);
        self.touch_summary(key);
        Ok(Some(hit))
    }
    /// Resolve a locally cached generic-program summary by its authenticated content address.
    ///
    /// The caller remains responsible for comparing the retained shared image with its
    /// authoritative storage binding. This lookup itself performs no hashing, metadata parsing,
    /// program loading, or byte copying.
    #[must_use]
    pub(crate) fn cached_generic_program_summary(
        &mut self,
        code_hash: Hash,
    ) -> Option<GenericProgramSummary> {
        let key = SummaryKey::new(code_hash);
        let hit = self.with_local(|local| local.generic_summaries.get(&key).cloned())?;
        self.stats.metadata_hits = self.stats.metadata_hits.saturating_add(1);
        self.touch_summary(key);
        Some(hit)
    }
    /// Analyze a program once per cached summary and return a reusable static AMX summary.
    ///
    /// # Errors
    /// Returns [`ProgramAnalysisError`] when metadata parsing or instruction decoding fails.
    pub fn analyze_program(
        &mut self,
        summary: &ProgramSummary,
        _bytecode: &[u8],
    ) -> Result<ProgramAnalysis, ProgramAnalysisError> {
        let key = SummaryKey::new(summary.code_hash);
        let cached = self.with_local(|local| local.analyses.get(&key).cloned());
        if let Some(hit) = cached {
            self.stats.analysis_hits = self.stats.analysis_hits.saturating_add(1);
            self.touch_summary(key);
            return Ok(hit);
        }
        self.stats.analysis_misses = self.stats.analysis_misses.saturating_add(1);
        let analysis = ivm::analysis::analyze_prepared_with_memory_budget(
            summary.prepared_contract(),
            self.prepared_contracts.execution_budget(),
        )?;
        self.insert_analysis(key, &analysis);
        Ok(analysis)
    }
    /// Analyze a validated generic program once per content-addressed summary.
    ///
    /// # Errors
    /// Returns [`ProgramAnalysisError`] if the stored validated image cannot be
    /// decoded consistently.
    pub fn analyze_generic_program(
        &mut self,
        summary: &GenericProgramSummary,
    ) -> Result<ProgramAnalysis, ProgramAnalysisError> {
        let key = SummaryKey::new(summary.code_hash);
        let cached = self.with_local(|local| local.analyses.get(&key).cloned());
        if let Some(hit) = cached {
            self.stats.analysis_hits = self.stats.analysis_hits.saturating_add(1);
            self.touch_summary(key);
            return Ok(hit);
        }
        self.stats.analysis_misses = self.stats.analysis_misses.saturating_add(1);
        let analysis = ivm::analysis::analyze_program_with_memory_budget(
            summary.program(),
            self.prepared_contracts.execution_budget(),
        )?;
        self.insert_analysis(key, &analysis);
        Ok(analysis)
    }
    /// Check out a warmed runtime for `summary.code_hash`, loading it if needed.
    ///
    /// The returned lease restores and returns the VM automatically on every
    /// exit path. Callers should attach a fresh host before execution.
    ///
    /// # Errors
    /// Propagates [`ivm::VMError`] when loading the runtime or applying the
    /// governed heap ceiling fails.
    pub fn checkout_runtime<'a>(
        &'a mut self,
        summary: &ProgramSummary,
        _bytecode: &[u8],
        gas_limit: u64,
        heap_limit: u64,
    ) -> Result<RuntimeLease<'a>, ivm::VMError> {
        let (key, baseline, vm, backing) = self.take_runtime(summary, gas_limit, heap_limit)?;
        Ok(RuntimeLease {
            cache: self,
            key,
            baseline,
            vm: Some(vm),
            backing,
        })
    }
    /// Check out a warmed runtime for a validated generic IVM program.
    ///
    /// The returned lease restores all mutated runtime state before returning
    /// the VM to the bounded pool. Generic programs remain contract-less: no
    /// interface, identity, or entrypoint metadata is synthesized.
    ///
    /// # Errors
    /// Propagates [`ivm::VMError`] if the validated program cannot be loaded
    /// or its governed heap ceiling is outside the ABI address window.
    pub fn checkout_generic_runtime<'a>(
        &'a mut self,
        summary: &GenericProgramSummary,
        gas_limit: u64,
        heap_limit: u64,
    ) -> Result<RuntimeLease<'a>, ivm::VMError> {
        #[cfg(test)]
        self.prepared_contracts.check_checkout_for_test()?;
        let stack_limit = stack_limit_for_gas(gas_limit);
        let key = RuntimeKey::new(summary.code_hash, stack_limit, heap_limit);
        let cached = self.with_local(|local| {
            local.runtime_templates.get_mut(&key).and_then(|pool| {
                pool.available
                    .take()
                    .map(|(runtime, backing)| (runtime.baseline, runtime.vm, backing))
            })
        });
        let (baseline, vm, backing) = if let Some((baseline, mut vm, backing)) = cached {
            self.stats.runtime_hits = self.stats.runtime_hits.saturating_add(1);
            self.touch_runtime(key);
            vm.activate_cached_runtime();
            vm.set_gas_limit(gas_limit);
            (baseline, vm, Some(backing))
        } else {
            self.stats.runtime_misses = self.stats.runtime_misses.saturating_add(1);
            let mut vm = ivm::IVM::try_new_with_memory_budget(
                gas_limit,
                self.prepared_contracts.execution_budget(),
            )?;
            vm.set_zk_trace_enabled(false);
            vm.memory.set_heap_max_limit(heap_limit)?;
            vm.load_program(summary.program())?;
            self.stats.prepared_loads = self.stats.prepared_loads.saturating_add(1);
            vm.set_gas_limit(gas_limit);
            self.stats.template_builds = self.stats.template_builds.saturating_add(1);
            let baseline = vm.try_runtime_template()?;
            let pool_missing = self.with_local(|local| !local.runtime_templates.contains_key(&key));
            if pool_missing {
                self.insert_runtime_pool(
                    key,
                    RuntimePool {
                        available: IdleRuntimeSlot::empty(),
                    },
                );
            }
            let backing = self.prepare_runtime_backing(key);
            (baseline, vm, backing)
        };
        Ok(RuntimeLease {
            cache: self,
            key,
            baseline,
            vm: Some(vm),
            backing,
        })
    }
    fn take_runtime(
        &mut self,
        summary: &ProgramSummary,
        gas_limit: u64,
        heap_limit: u64,
    ) -> Result<
        (
            RuntimeKey,
            ivm::RuntimeTemplate,
            ivm::IVM,
            Option<IdleRuntimeBacking>,
        ),
        ivm::VMError,
    > {
        #[cfg(test)]
        self.prepared_contracts.check_checkout_for_test()?;
        let stack_limit = stack_limit_for_gas(gas_limit);
        let key = RuntimeKey::new(summary.code_hash, stack_limit, heap_limit);
        let cached = self.with_local(|local| {
            local.runtime_templates.get_mut(&key).and_then(|pool| {
                pool.available
                    .take()
                    .map(|(runtime, backing)| (runtime.baseline, runtime.vm, backing))
            })
        });
        if let Some((baseline, mut vm, backing)) = cached {
            self.stats.runtime_hits = self.stats.runtime_hits.saturating_add(1);
            self.touch_runtime(key);
            vm.activate_cached_runtime();
            vm.set_gas_limit(gas_limit);
            return Ok((key, baseline, vm, Some(backing)));
        }
        self.stats.runtime_misses = self.stats.runtime_misses.saturating_add(1);
        let mut vm = ivm::IVM::try_new_with_memory_budget(
            gas_limit,
            self.prepared_contracts.execution_budget(),
        )?;
        vm.set_zk_trace_enabled(false);
        vm.memory.set_heap_max_limit(heap_limit)?;
        vm.load_prepared(summary.prepared_contract())?;
        self.stats.prepared_loads = self.stats.prepared_loads.saturating_add(1);
        if gas_limit > 0 {
            vm.set_gas_limit(gas_limit);
        }
        self.stats.template_builds = self.stats.template_builds.saturating_add(1);
        let baseline = vm.try_runtime_template()?;
        let pool_missing = self.with_local(|local| !local.runtime_templates.contains_key(&key));
        if pool_missing {
            self.insert_runtime_pool(
                key,
                RuntimePool {
                    available: IdleRuntimeSlot::empty(),
                },
            );
        }
        let backing = self.prepare_runtime_backing(key);
        Ok((key, baseline, vm, backing))
    }
    fn prepare_runtime_backing(&self, key: RuntimeKey) -> Option<IdleRuntimeBacking> {
        if self.capacity == 0
            || ivm::cache_memory::memory_stats().limit_bytes == 0
            || !self.with_local(|local| local.can_return_runtime(key))
        {
            return None;
        }
        // No internal store guard is held while the exact original-pool row is allocated.
        IdleRuntimeBacking::try_new(self.prepared_contracts.execution_budget()).ok()
    }
    /// Return a snapshot of cache counters.
    #[must_use]
    pub fn stats(&self) -> CacheStats {
        let mut stats = self.stats;
        stats.evictions = stats
            .evictions
            .saturating_add(self.with_local(|local| local.evictions));
        stats
    }
    /// Return the prepared-artifact store shared with contract hosts.
    #[must_use]
    pub fn prepared_contract_cache(&self) -> PreparedContractCache {
        self.prepared_contracts.clone()
    }
    fn return_runtime(
        &mut self,
        key: RuntimeKey,
        baseline: ivm::RuntimeTemplate,
        mut vm: ivm::IVM,
        backing: Option<IdleRuntimeBacking>,
    ) {
        let Some(backing) = backing
            .filter(|backing| backing.belongs_to(self.prepared_contracts.execution_budget()))
        else {
            return;
        };
        if self.capacity == 0 || !self.with_local(|local| local.can_return_runtime(key)) {
            return;
        }
        if vm.reset_from_runtime_template(&baseline).is_err() {
            return;
        }
        let returned = self.with_local(|local| {
            if !local.can_return_runtime(key)
                || !baseline.try_retain_cache_allocations()
                || !vm.try_retain_cache_allocations()
                || !backing.try_retain()
            {
                return false;
            }
            local.return_runtime(key, baseline, vm, backing);
            true
        });
        if returned {
            self.stats.dirty_resets = self.stats.dirty_resets.saturating_add(1);
        }
    }
    fn insert_summary(&mut self, key: SummaryKey, summary: ProgramSummary) {
        self.with_local(|local| local.insert_summary(key, summary));
    }
    fn insert_generic_summary(&mut self, key: SummaryKey, summary: GenericProgramSummary) {
        self.with_local(|local| local.insert_generic_summary(key, summary));
    }
    fn insert_analysis(&mut self, key: SummaryKey, analysis: &ProgramAnalysis) {
        self.with_local(|local| local.insert_analysis(key, analysis));
    }
    fn insert_runtime_pool(&mut self, key: RuntimeKey, pool: RuntimePool) {
        self.with_local(|local| local.insert_runtime_pool(key, pool));
    }
    fn touch_summary(&mut self, key: SummaryKey) {
        self.with_local(|local| {
            local.touch_summary(key);
            local.retain_index_or_clear();
        });
    }
    fn touch_runtime(&mut self, key: RuntimeKey) {
        self.with_local(|local| {
            local.touch_runtime(key);
            local.retain_index_or_clear();
        });
    }
}
impl LocalCacheStore {
    fn can_return_runtime(&self, key: RuntimeKey) -> bool {
        let summary_key = key.summary_key();
        self.capacity != 0
            && (self.summaries.contains_key(&summary_key)
                || self.generic_summaries.contains_key(&summary_key))
            && self
                .runtime_templates
                .get(&key)
                .is_none_or(|pool| pool.available.is_empty())
    }

    fn clear_storage(&mut self) {
        self.evictions = self
            .evictions
            .saturating_add(self.summary_order.len() as u64);
        self.summaries = BTreeMap::new();
        self.generic_summaries = BTreeMap::new();
        self.runtime_templates = BTreeMap::new();
        self.analyses = BTreeMap::new();
        self.summary_order = VecDeque::new();
        self.runtime_order = VecDeque::new();
        self.index_memory.set_known_bytes(0);
    }
    fn index_bytes(&self) -> Option<usize> {
        let values = [
            norito::core::owned_btree_allocation_bytes::<SummaryKey, ProgramSummary>(
                self.summaries.len(),
            )
            .ok()?,
            norito::core::owned_btree_allocation_bytes::<SummaryKey, GenericProgramSummary>(
                self.generic_summaries.len(),
            )
            .ok()?,
            norito::core::owned_btree_allocation_bytes::<RuntimeKey, RuntimePool>(
                self.runtime_templates.len(),
            )
            .ok()?,
            norito::core::owned_btree_allocation_bytes::<SummaryKey, ProgramAnalysis>(
                self.analyses.len(),
            )
            .ok()?,
            self.summary_order
                .capacity()
                .checked_mul(std::mem::size_of::<SummaryKey>())?,
            self.runtime_order
                .capacity()
                .checked_mul(std::mem::size_of::<RuntimeKey>())?,
        ];
        values.into_iter().try_fold(0_usize, usize::checked_add)
    }
    fn retain_index_or_clear(&mut self) {
        if self.summary_order.is_empty() && self.runtime_order.is_empty() {
            self.clear_storage();
            return;
        }
        let Some(bytes) = self.index_bytes() else {
            self.clear_storage();
            return;
        };
        // Conservatively keep the allocation high-water mark until the whole
        // index is released, including empty B-tree roots. Runtime row backing
        // is measured separately by its sole fixed ExecutionBuffer owner.
        self.index_memory
            .set_known_bytes(bytes.max(self.index_memory.bytes()));
        if !self.index_memory.try_retain() {
            self.clear_storage();
        }
    }
    fn insert_summary(&mut self, key: SummaryKey, summary: ProgramSummary) {
        if self.capacity == 0 || !summary.prepared.try_retain_allocations() {
            return;
        }
        self.summaries.insert(key, summary);
        self.touch_summary(key);
        self.evict_summaries_if_needed();
        self.retain_index_or_clear();
    }
    fn insert_analysis(&mut self, key: SummaryKey, analysis: &ProgramAnalysis) {
        if self.capacity == 0 {
            return;
        }
        if analysis.syscalls.try_retain() {
            let mut owned = analysis.clone();
            owned.syscalls = owned.syscalls.into_cache_owner();
            self.analyses.insert(key, owned);
            self.touch_summary(key);
            self.evict_summaries_if_needed();
            self.retain_index_or_clear();
        }
    }
    fn insert_generic_summary(&mut self, key: SummaryKey, mut summary: GenericProgramSummary) {
        if self.capacity == 0 || !summary.program.try_retain() {
            return;
        }
        summary.program = summary.program.into_cache_owner();
        self.generic_summaries.insert(key, summary);
        self.touch_summary(key);
        self.evict_summaries_if_needed();
        self.retain_index_or_clear();
    }
    fn insert_runtime_pool(&mut self, key: RuntimeKey, pool: RuntimePool) {
        if self.capacity == 0 {
            return;
        }
        self.runtime_templates.insert(key, pool);
        self.touch_runtime(key);
        self.evict_runtimes_if_needed();
        self.retain_index_or_clear();
    }
    fn return_runtime(
        &mut self,
        key: RuntimeKey,
        baseline: ivm::RuntimeTemplate,
        vm: ivm::IVM,
        backing: IdleRuntimeBacking,
    ) {
        let pool = self
            .runtime_templates
            .entry(key)
            .or_insert_with(|| RuntimePool {
                available: IdleRuntimeSlot::empty(),
            });
        if pool.available.is_empty() {
            pool.available
                .place(backing, PooledRuntime { baseline, vm });
        }
        self.touch_runtime(key);
        self.evict_runtimes_if_needed();
        self.retain_index_or_clear();
    }
    fn touch_summary(&mut self, key: SummaryKey) {
        if self.capacity == 0 {
            return;
        }
        if let Some(pos) = self.summary_order.iter().position(|k| *k == key) {
            self.summary_order.remove(pos);
        }
        self.summary_order.push_back(key);
    }
    fn touch_runtime(&mut self, key: RuntimeKey) {
        if self.capacity == 0 {
            return;
        }
        if let Some(pos) = self.runtime_order.iter().position(|k| *k == key) {
            self.runtime_order.remove(pos);
        }
        self.runtime_order.push_back(key);
        self.touch_summary(key.summary_key());
    }
    fn evict_summaries_if_needed(&mut self) {
        while self.capacity != 0 && self.summary_order.len() > self.capacity {
            if let Some(old) = self.summary_order.pop_front() {
                self.summaries.remove(&old);
                self.generic_summaries.remove(&old);
                self.analyses.remove(&old);
                self.prune_runtime_for_summary(old);
                self.evictions = self.evictions.saturating_add(1);
            }
        }
    }
    fn evict_runtimes_if_needed(&mut self) {
        while self.capacity != 0 && self.runtime_order.len() > self.capacity {
            if let Some(old) = self.runtime_order.pop_front() {
                self.runtime_templates.remove(&old);
                self.evictions = self.evictions.saturating_add(1);
            }
        }
    }
    fn prune_runtime_for_summary(&mut self, key: SummaryKey) {
        self.runtime_templates
            .retain(|runtime_key, _| runtime_key.summary_key() != key);
        self.runtime_order
            .retain(|runtime_key| runtime_key.summary_key() != key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_data_model::smart_contract::manifest::EntryPointKind;
    use ivm::runtime::IvmConfig;
    const HEAP_LIMIT: u64 = ivm::Memory::HEAP_MAX_SIZE;

    // Strict reuse positives own the canonical configuration writer for their
    // complete cache lifetime. Parallel zero-retention tests may otherwise
    // legitimately evict every registered cache between two assertions.
    fn default_retention() -> ivm::ivm_cache::CacheLimitsGuard {
        ivm::ivm_cache::CacheLimitsGuard::new(ivm::ivm_cache::CacheLimits {
            capacity: iroha_config::parameters::defaults::pipeline::CACHE_SIZE,
            max_bytes: iroha_config::parameters::defaults::pipeline::IVM_CACHE_MAX_BYTES,
            max_decoded_ops:
                iroha_config::parameters::defaults::pipeline::IVM_CACHE_MAX_DECODED_OPS,
        })
    }

    #[test]
    fn clearing_local_indexes_releases_capacity_but_keeps_borrowed_program_usable() {
        let _retention = default_retention();
        let mut cache = IvmCache::with_capacity(4);
        let program = minimal_generic_program();
        let summary = cache
            .summarize_generic_program(&program)
            .expect("valid generic program");
        let image = summary.shared_program();
        let mut local = cache.local.lock();
        assert!(!local.generic_summaries.is_empty());
        assert!(local.index_memory.bytes() > 0);
        local.clear_storage();
        assert!(local.generic_summaries.is_empty());
        assert_eq!(local.summary_order.capacity(), 0);
        assert_eq!(local.runtime_order.capacity(), 0);
        assert_eq!(local.index_memory.bytes(), 0);
        assert_eq!(image.as_ref(), program.as_slice());
    }

    #[test]
    fn runtime_lease_unwind_returns_reset_memory() {
        let mut cache = IvmCache::with_capacity(2);
        let summary = cache
            .summarize_generic_program(&minimal_generic_program())
            .expect("generic summary");
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut vm = cache
                .checkout_generic_runtime(&summary, 10_000, HEAP_LIMIT)
                .expect("runtime");
            vm.memory
                .store_u64(ivm::Memory::HEAP_START, 99)
                .expect("write heap");
            panic!("caller unwinds with a runtime lease");
        }));
        assert!(result.is_err());
        let vm = cache
            .checkout_generic_runtime(&summary, 10_000, HEAP_LIMIT)
            .expect("next runtime");
        assert_eq!(vm.memory.load_u64(ivm::Memory::HEAP_START), Ok(0));
    }

    #[test]
    fn preparation_claim_releases_waiters_on_unwind() {
        let cache = PreparedContractCache::with_capacity(1);
        let code_hash = Hash::new(b"unwind preparation");
        cache.inner.lock().preparing.insert(code_hash);
        let waiter_cache = cache.clone();
        let (waiting_tx, waiting_rx) = std::sync::mpsc::channel();
        let waiter = std::thread::spawn(move || {
            let mut store = waiter_cache.inner.lock();
            waiting_tx.send(()).expect("report waiting");
            while store.preparing.contains(&code_hash) {
                waiter_cache.ready.wait(&mut store);
            }
        });
        waiting_rx.recv().expect("waiter acquired lock");
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _claim = PreparationClaim {
                cache: &cache,
                code_hash,
                active: true,
            };
            panic!("preparation failed before publication");
        }));
        assert!(result.is_err());
        waiter.join().expect("waiter released");
        assert!(!cache.inner.lock().preparing.contains(&code_hash));
    }

    #[test]
    fn preparation_error_releases_claim_for_retry() {
        let cache = PreparedContractCache::with_capacity(1);
        let code_hash = Hash::new(b"malformed");
        assert!(cache.get_or_prepare(code_hash, b"malformed").is_err());
        assert!(!cache.inner.lock().preparing.contains(&code_hash));
        assert!(cache.get_or_prepare(code_hash, b"malformed").is_err());
        assert_eq!(cache.stats().misses, 2);
    }
    /// Assemble a minimal contract with a complete typed Unit return.
    pub(super) fn minimal_program() -> Vec<u8> {
        let mut program = ivm::ProgramMetadata::default().encode();
        let interface = ivm::EmbeddedContractInterfaceV1 {
            events: Vec::new(),
            enum_types: Vec::new(),
            permissions: Vec::new(),
            callables: vec![ivm::call::EmbeddedCallableV1 {
                entry_pc: 0,
                frame_bytes: 0,
                arguments: ivm::call::CallSchemaV1::empty(),
                results: ivm::call::CallSchemaV1::unit(),
            }],
            seiyaku_name: "CacheFixture".to_owned(),
            compiler_fingerprint: "iroha-core-cache-tests".to_owned(),
            abi_hash: ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1),
            features_bitmap: 0,
            access_set_hints: None,
            kotoba: Vec::new(),
            entrypoints: vec![ivm::EmbeddedEntrypointDescriptor {
                name: "inspect".to_owned(),
                kind: EntryPointKind::View,
                params: Vec::new(),
                argument_schema: None,
                return_type: Some("()".to_owned()),
                return_schema: Some(iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeV1 {
                    nodes: vec![iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeNodeV1::Unit],
                }),
                authorization: iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::Anyone,
                read_keys: Vec::new(),
                write_keys: Vec::new(),
                access_hints_complete: Some(true),
                access_hints_skipped: Vec::new(),
                triggers: Vec::new(),
                entry_pc: 0,
            }],
            error_messages: Vec::new(),
            error_types: Vec::new(),
            states: Vec::new(),
        };
        program.extend_from_slice(&interface.encode_section());
        for word in [
            ivm::encoding::wide::encode_store(ivm::instruction::wide::memory::STORE64, 12, 0, 0),
            ivm::encoding::wide::encode_ri(ivm::instruction::wide::arithmetic::ADDI, 10, 12, 0),
            ivm::encoding::wide::encode_ri(ivm::instruction::wide::arithmetic::ADDI, 11, 0, 1),
            ivm::encoding::wide::encode_rr(ivm::instruction::wide::control::JALR, 0, 1, 0),
        ] {
            program.extend_from_slice(&word.to_le_bytes());
        }
        program
    }
    pub(super) fn minimal_generic_program() -> Vec<u8> {
        let mut program = ivm::ProgramMetadata {
            max_cycles: 10_000,
            ..ivm::ProgramMetadata::default()
        }
        .encode();
        program.extend_from_slice(&ivm::encoding::wide::encode_halt().to_le_bytes());
        program
    }
    #[test]
    fn executable_summary_distinguishes_contracts_from_generic_programs() {
        let mut cache = IvmCache::with_capacity(4);
        assert!(matches!(
            cache
                .summarize_executable(&minimal_program())
                .expect("contract summary"),
            ExecutableProgramSummary::Contract(_)
        ));
        assert!(matches!(
            cache
                .summarize_executable(&minimal_generic_program())
                .expect("generic summary"),
            ExecutableProgramSummary::Generic(_)
        ));
        assert!(
            cache.summarize_generic_program(&minimal_program()).is_err(),
            "CNTR artifacts must never be downgraded to generic programs"
        );
    }
    #[test]
    fn generic_runtime_is_validated_and_reset_or_reloaded_after_cache_pressure() {
        const GAS_LIMIT: u64 = 10_000;
        const GOVERNED_HEAP_LIMIT: u64 = 64;
        let program = minimal_generic_program();
        let mut cache = IvmCache::with_capacity(2);
        let summary = cache
            .summarize_generic_program(&program)
            .expect("generic summary");
        let first_allocation = {
            let mut runtime = cache
                .checkout_generic_runtime(&summary, GAS_LIMIT, GOVERNED_HEAP_LIMIT)
                .expect("generic runtime");
            assert_eq!(runtime.memory.heap_limit(), GOVERNED_HEAP_LIMIT);
            assert_eq!(runtime.memory.heap_max_limit(), GOVERNED_HEAP_LIMIT);
            let allocation = runtime
                .memory
                .load_region(0, 1)
                .expect("generic code memory")
                .as_ptr();
            runtime.set_register(3, 77);
            runtime.run().expect("generic HALT program");
            allocation
        };
        let runtime = cache
            .checkout_generic_runtime(&summary, GAS_LIMIT, GOVERNED_HEAP_LIMIT)
            .expect("reused or reloaded generic runtime");
        assert_eq!(runtime.register(3), 0);
        assert_eq!(runtime.remaining_gas(), GAS_LIMIT);
        assert_eq!(runtime.memory.heap_max_limit(), GOVERNED_HEAP_LIMIT);
        let second_allocation = runtime
            .memory
            .load_region(0, 1)
            .expect("generic code memory")
            .as_ptr();
        drop(runtime);
        let stats = cache.stats();
        assert_eq!(stats.runtime_hits + stats.runtime_misses, 2);
        assert_eq!(stats.prepared_loads, stats.runtime_misses);
        assert_eq!(stats.template_builds, stats.runtime_misses);
        if stats.runtime_hits == 1 {
            assert_eq!(second_allocation, first_allocation);
        } else {
            assert_eq!(stats.runtime_misses, 2);
        }
    }
    #[test]
    fn generic_runtime_replacement_keeps_its_own_reset_baseline() {
        let _retention = default_retention();
        const GAS_LIMIT: u64 = 10_000;
        const GOVERNED_HEAP_LIMIT: u64 = 64;
        let program = minimal_generic_program();
        let mut cache = IvmCache::with_capacity(2);
        let summary = cache
            .summarize_generic_program(&program)
            .expect("generic summary");
        {
            let mut poisoned = cache
                .checkout_generic_runtime(&summary, GAS_LIMIT, GOVERNED_HEAP_LIMIT)
                .expect("initial generic runtime");
            poisoned.memory = ivm::Memory::new_with_stack_limit(
                ivm::Memory::MIN_STACK_SIZE + ivm::Memory::STACK_ALIGNMENT,
            )
            .expect("distinct ABI V1 stack geometry is valid");
        }
        let replacement_allocation = {
            let mut replacement = cache
                .checkout_generic_runtime(&summary, GAS_LIMIT, GOVERNED_HEAP_LIMIT)
                .expect("replacement generic runtime");
            let allocation = replacement
                .memory
                .load_region(0, 1)
                .expect("replacement code memory")
                .as_ptr();
            replacement
                .memory
                .preload_input(0, &[0xA5])
                .expect("dirty replacement input");
            allocation
        };
        let reused = cache
            .checkout_generic_runtime(&summary, GAS_LIMIT, GOVERNED_HEAP_LIMIT)
            .expect("replacement must return to the pool");
        assert_eq!(
            reused
                .memory
                .load_region(0, 1)
                .expect("reused code memory")
                .as_ptr(),
            replacement_allocation
        );
        assert_eq!(
            reused
                .memory
                .load_region(ivm::Memory::INPUT_START, 1)
                .expect("reset replacement input"),
            [0]
        );
    }
    #[test]
    fn generic_summary_rejects_disallowed_syscalls_during_preparation() {
        let mut program = ivm::ProgramMetadata {
            max_cycles: 10_000,
            ..ivm::ProgramMetadata::default()
        }
        .encode();
        program.extend_from_slice(&ivm::encoding::wide::encode_syscallx(0x00ff_ffff).to_le_bytes());
        program.extend_from_slice(&ivm::encoding::wide::encode_halt().to_le_bytes());
        assert!(
            IvmCache::new().summarize_generic_program(&program).is_err(),
            "unknown generic-program syscalls must fail before execution"
        );
    }
    #[test]
    fn generic_summary_rejects_contract_only_syscalls_with_stable_reason() {
        for syscall in [
            ivm::syscalls::SYSCALL_GRANT_CONTRACT_PERMISSION,
            ivm::syscalls::SYSCALL_REVOKE_CONTRACT_PERMISSION,
            ivm::syscalls::SYSCALL_DEACTIVATE_CONTRACT_INSTANCE,
            ivm::syscalls::SYSCALL_REMOVE_SMART_CONTRACT_BYTES,
            ivm::syscalls::SYSCALL_REGISTER_SMART_CONTRACT_CODE,
            ivm::syscalls::SYSCALL_REGISTER_SMART_CONTRACT_BYTES,
            ivm::syscalls::SYSCALL_ACTIVATE_CONTRACT_INSTANCE,
            ivm::syscalls::SYSCALL_STATE_GET,
            ivm::syscalls::SYSCALL_STATE_SET,
            ivm::syscalls::SYSCALL_STATE_DEL,
            ivm::syscalls::SYSCALL_STATE_HAS,
            ivm::syscalls::SYSCALL_STATE_LEN,
            ivm::syscalls::SYSCALL_STATE_COUNT,
            ivm::syscalls::SYSCALL_STATE_SCAN,
            ivm::syscalls::SYSCALL_CALL_CONTRACT,
            ivm::syscalls::SYSCALL_SMARTCONTRACT_EXECUTE_INSTRUCTION,
            ivm::syscalls::SYSCALL_SYSVAR_CONTRACT_ADDRESS,
            ivm::syscalls::SYSCALL_SYSVAR_CONTRACT_SUBJECT,
            ivm::syscalls::SYSCALL_SYSVAR_ENTRYPOINT,
        ] {
            let mut program = ivm::ProgramMetadata {
                max_cycles: 10_000,
                ..ivm::ProgramMetadata::default()
            }
            .encode();
            program.extend_from_slice(&ivm::encoding::wide::encode_syscallx(syscall).to_le_bytes());
            program.extend_from_slice(&ivm::encoding::wide::encode_halt().to_le_bytes());
            let error = IvmCache::new()
                .summarize_generic_program(&program)
                .expect_err("generic syscall profile must reject contract-only calls");
            assert_eq!(
                error,
                ivm::VMError::GenericSyscallNotAllowed { syscall },
                "generic syscall profile must reject 0x{syscall:02x}"
            );
        }
    }
    #[test]
    fn generic_summary_accepts_unconditional_and_context_gated_syscalls() {
        for syscall in [
            ivm::syscalls::SYSCALL_REGISTER_DOMAIN,
            ivm::syscalls::SYSCALL_INT_ADD,
            ivm::syscalls::SYSCALL_SUBSCRIPTION_BILL,
            ivm::syscalls::SYSCALL_SUBSCRIPTION_RECORD_USAGE,
        ] {
            let mut program = ivm::ProgramMetadata {
                max_cycles: 10_000,
                ..ivm::ProgramMetadata::default()
            }
            .encode();
            program.extend_from_slice(&ivm::encoding::wide::encode_syscallx(syscall).to_le_bytes());
            program.extend_from_slice(&ivm::encoding::wide::encode_halt().to_le_bytes());
            IvmCache::new()
                .summarize_generic_program(&program)
                .expect("system trigger syscall belongs to the generic V1 profile");
        }
    }
    #[test]
    fn runtime_is_reused_across_transactions() {
        let _retention = default_retention();
        const TEST_REGISTER: usize = 1;
        const GAS_LIMIT: u64 = 10_000;
        let program = minimal_program();
        let mut cache = IvmCache::with_capacity(2);
        // First transaction warms both summary and runtime template.
        let summary = cache.summarize_program(&program).expect("summary");
        let memory_allocation = {
            let mut runtime = cache
                .checkout_runtime(&summary, &program, GAS_LIMIT, HEAP_LIMIT)
                .expect("VM should be created");
            let allocation = runtime
                .memory
                .load_region(0, 1)
                .expect("code memory")
                .as_ptr();
            runtime.set_register(TEST_REGISTER, 42);
            runtime.gas_remaining = 1;
            runtime
                .memory
                .preload_input(0, &[0xA5])
                .expect("mutate input memory");
            allocation
        };
        // Cache stats should reflect misses.
        let stats = cache.stats();
        assert_eq!(stats.metadata_misses, 1);
        assert_eq!(stats.runtime_misses, 1);
        assert_eq!(stats.runtime_hits, 0);
        // Second transaction should reuse the cached template and preserve code load.
        let summary = cache.summarize_program(&program).expect("cached summary");
        let runtime2 = cache
            .checkout_runtime(&summary, &program, GAS_LIMIT, HEAP_LIMIT)
            .expect("VM should be reused");
        assert_eq!(runtime2.register(TEST_REGISTER), 0);
        assert_eq!(
            runtime2.remaining_gas(),
            GAS_LIMIT,
            "warm checkout must replenish the invocation gas budget"
        );
        assert_eq!(
            runtime2
                .memory
                .load_region(0, 1)
                .expect("code memory")
                .as_ptr(),
            memory_allocation,
            "warm checkout must reuse the same memory allocation"
        );
        assert_eq!(
            runtime2
                .memory
                .load_region(0x0020_0000, 1)
                .expect("input memory"),
            &[0],
            "dirty input chunk must be restored from the baseline"
        );
        drop(runtime2);
        let stats = cache.stats();
        assert_eq!(stats.metadata_hits, 1);
        assert_eq!(stats.runtime_hits, 1);
        assert_eq!(stats.runtime_misses, 1);
    }
    #[test]
    fn runtime_pool_discards_a_vm_with_mismatched_template_geometry() {
        let _retention = default_retention();
        const GAS_LIMIT: u64 = 10_000;
        let program = minimal_program();
        let mut cache = IvmCache::with_capacity(2);
        let summary = cache.summarize_program(&program).expect("summary");
        {
            let mut runtime = cache
                .checkout_runtime(&summary, &program, GAS_LIMIT, HEAP_LIMIT)
                .expect("cold runtime");
            runtime.memory = ivm::Memory::new_with_stack_limit(
                ivm::Memory::MIN_STACK_SIZE + ivm::Memory::STACK_ALIGNMENT,
            )
            .expect("distinct ABI V1 stack geometry is valid");
        }
        let after_mismatch = cache.stats();
        assert_eq!(after_mismatch.runtime_misses, 1);
        assert_eq!(after_mismatch.runtime_hits, 0);
        assert_eq!(
            after_mismatch.dirty_resets, 0,
            "a rejected reset must not count or pool the mismatched VM"
        );
        let replacement_allocation = {
            let mut runtime = cache
                .checkout_runtime(&summary, &program, GAS_LIMIT, HEAP_LIMIT)
                .expect("replacement runtime");
            assert_eq!(runtime.memory.stack_limit(), stack_limit_for_gas(GAS_LIMIT));
            let allocation = runtime
                .memory
                .load_region(0, 1)
                .expect("replacement code memory")
                .as_ptr();
            runtime
                .memory
                .preload_input(0, &[0xA5])
                .expect("dirty replacement input");
            allocation
        };
        let after_replacement = cache.stats();
        assert_eq!(after_replacement.runtime_misses, 2);
        assert_eq!(after_replacement.runtime_hits, 0);
        assert_eq!(after_replacement.dirty_resets, 1);
        let reused = cache
            .checkout_runtime(&summary, &program, GAS_LIMIT, HEAP_LIMIT)
            .expect("replacement must return to the pool");
        assert_eq!(
            reused
                .memory
                .load_region(0, 1)
                .expect("reused code memory")
                .as_ptr(),
            replacement_allocation
        );
        assert_eq!(
            reused
                .memory
                .load_region(ivm::Memory::INPUT_START, 1)
                .expect("reset replacement input"),
            [0]
        );
    }
    #[test]
    fn runtime_pool_never_reuses_stale_heap_authority() {
        let _retention = default_retention();
        const GAS_LIMIT: u64 = 10_000;
        const SMALL_HEAP_LIMIT: u64 = 64;
        const LARGE_HEAP_LIMIT: u64 = 128;
        let program = minimal_program();
        let mut cache = IvmCache::with_capacity(2);
        let summary = cache.summarize_program(&program).expect("summary");
        {
            let runtime = cache
                .checkout_runtime(&summary, &program, GAS_LIMIT, SMALL_HEAP_LIMIT)
                .expect("small governed runtime");
            assert_eq!(runtime.memory.heap_max_limit(), SMALL_HEAP_LIMIT);
        }
        {
            let runtime = cache
                .checkout_runtime(&summary, &program, GAS_LIMIT, LARGE_HEAP_LIMIT)
                .expect("large governed runtime");
            assert_eq!(runtime.memory.heap_max_limit(), LARGE_HEAP_LIMIT);
        }
        let after_distinct_limits = cache.stats();
        assert_eq!(after_distinct_limits.runtime_misses, 2);
        assert_eq!(after_distinct_limits.runtime_hits, 0);
        let runtime = cache
            .checkout_runtime(&summary, &program, GAS_LIMIT, SMALL_HEAP_LIMIT)
            .expect("warm small governed runtime");
        assert_eq!(runtime.memory.heap_max_limit(), SMALL_HEAP_LIMIT);
        drop(runtime);
        assert_eq!(cache.stats().runtime_hits, 1);
    }
    #[test]
    fn public_program_summary_constructor_initializes_prepared_runtime_state() {
        const GAS_LIMIT: u64 = 10_000;
        let program = minimal_program();
        let summary = ProgramSummary::from_artifact(&program).expect("public summary constructor");
        assert_eq!(summary.code_hash, ivm::contract_code_hash(&program));
        assert_eq!(summary.prepared_contract().code_hash(), summary.code_hash);
        assert_eq!(summary.prepared_contract().artifact(), program.as_slice());
        let runtime = summary
            .checkout_runtime(GAS_LIMIT, HEAP_LIMIT)
            .expect("summary owns initialized prepared runtime state");
        assert_eq!(runtime.remaining_gas(), GAS_LIMIT);
    }
    #[test]
    fn content_addressed_hit_skips_repreparation_and_reuses_dirty_reset_runtime() {
        let _retention = default_retention();
        const GAS_LIMIT: u64 = 10_000;
        let program = minimal_program();
        let code_hash = ivm::contract_code_hash(&program);
        let mut cache = IvmCache::with_capacity(2);
        let summary = cache
            .summarize_program_with_hash(code_hash, &program)
            .expect("first preparation");
        let memory_allocation = {
            let mut runtime = cache
                .checkout_runtime(&summary, &program, GAS_LIMIT, HEAP_LIMIT)
                .expect("first runtime");
            let allocation = runtime
                .memory
                .load_region(0, 1)
                .expect("code memory")
                .as_ptr();
            runtime.set_register(7, 99);
            runtime
                .memory
                .preload_input(0, &[0xA5])
                .expect("dirty input page");
            allocation
        };
        let after_first = cache.stats();
        assert_eq!(after_first.artifact_hashes, 0);
        assert_eq!(after_first.preparations, 1);
        assert_eq!(after_first.prepared_loads, 1);
        assert_eq!(after_first.template_builds, 1);
        assert_eq!(after_first.dirty_resets, 1);
        // A content-addressed hit does not even inspect the byte slice. The
        // canonical bytes and all decoded state come from ProgramSummary.
        let summary = cache
            .summarize_program_with_hash(code_hash, &[])
            .expect("summary cache hit");
        {
            let runtime = cache
                .checkout_runtime(&summary, &[], GAS_LIMIT, HEAP_LIMIT)
                .expect("warm runtime");
            assert_eq!(runtime.register(7), 0);
            assert_eq!(
                runtime
                    .memory
                    .load_region(0, 1)
                    .expect("code memory")
                    .as_ptr(),
                memory_allocation
            );
            assert_eq!(
                runtime
                    .memory
                    .load_region(0x0020_0000, 1)
                    .expect("input memory"),
                &[0]
            );
        }
        let after_second = cache.stats();
        assert_eq!(after_second.metadata_hits, after_first.metadata_hits + 1);
        assert_eq!(after_second.runtime_hits, after_first.runtime_hits + 1);
        assert_eq!(after_second.artifact_hashes, after_first.artifact_hashes);
        assert_eq!(after_second.preparations, after_first.preparations);
        assert_eq!(after_second.prepared_loads, after_first.prepared_loads);
        assert_eq!(after_second.template_builds, after_first.template_builds);
        assert_eq!(after_second.dirty_resets, after_first.dirty_resets + 1);
    }
    #[test]
    fn second_nested_resolution_reuses_shared_prepared_artifact() {
        let _retention = default_retention();
        let outer_program = minimal_program();
        let mut outer_cache = IvmCache::with_capacity(2);
        let outer_summary = outer_cache
            .summarize_program(&outer_program)
            .expect("outer contract summary");
        let nested_cache = outer_summary.prepared_contract_cache();
        let before_nested = nested_cache.stats();
        let mut nested_program = minimal_program();
        nested_program[8..16].copy_from_slice(&17u64.to_le_bytes());
        let nested_hash = ivm::contract_code_hash(&nested_program);
        let first = nested_cache
            .get_or_prepare(nested_hash, &nested_program)
            .expect("first nested resolution");
        let after_first = nested_cache.stats();
        assert_eq!(after_first.misses, before_nested.misses + 1);
        assert_eq!(after_first.preparations, before_nested.preparations + 1);
        // A second nested call resolves solely by the trusted content address:
        // no byte inspection, artifact hash, parse, validation, or predecode.
        let second = nested_cache
            .get(nested_hash)
            .expect("second nested resolution");
        assert!(ivm::PreparedContract::ptr_eq(&first, &second));
        let after_second = nested_cache.stats();
        assert_eq!(after_second.hits, after_first.hits + 1);
        assert_eq!(after_second.misses, after_first.misses);
        assert_eq!(after_second.preparations, after_first.preparations);
    }
    #[test]
    fn worker_caches_reuse_retained_owners_or_rebuild_after_cache_pressure() {
        const GAS_LIMIT: u64 = 10_000;
        let program = minimal_program();
        let code_hash = ivm::contract_code_hash(&program);
        let shared = PreparedContractCache::with_capacity(4);
        let mut first_worker = IvmCache::with_prepared_contract_cache(4, shared.clone());
        let mut second_worker = IvmCache::with_prepared_contract_cache(4, shared.clone());
        let first = first_worker
            .summarize_program_with_hash(code_hash, &program)
            .expect("first worker preparation");
        let (allocation, loaded_code_hash) = {
            let runtime = first
                .checkout_runtime(GAS_LIMIT, HEAP_LIMIT)
                .expect("first runtime");
            (
                runtime
                    .memory
                    .load_region(0, 1)
                    .expect("code memory")
                    .as_ptr(),
                runtime.code_hash(),
            )
        };
        // The second worker has no local summary. It can reuse the shared owner
        // or reprepare from the same bytes if aggregate cache pressure evicted it.
        let second = second_worker
            .summarize_program_with_hash(code_hash, &program)
            .expect("shared prepared hit or exact-byte reprepare");
        let runtime = second
            .checkout_runtime(GAS_LIMIT, HEAP_LIMIT)
            .expect("warm or cold runtime");
        let second_allocation = runtime
            .memory
            .load_region(0, 1)
            .expect("code memory")
            .as_ptr();
        assert_eq!(runtime.code_hash(), loaded_code_hash);
        let stats = shared.stats();
        assert_eq!(stats.runtime_hits + stats.runtime_misses, 2);
        assert_eq!(stats.runtime_prepared_loads, stats.runtime_misses);
        assert_eq!(stats.runtime_template_builds, stats.runtime_misses);
        if stats.runtime_hits == 1 {
            assert_eq!(second_allocation, allocation);
        } else {
            assert_eq!(stats.runtime_misses, 2);
        }
        assert_eq!(first_worker.stats().preparations, 1);
        let second_preparations = second_worker.stats().preparations;
        assert!(second_preparations <= 1);
        assert_eq!(stats.preparations, 1 + second_preparations);
    }
    #[test]
    fn concurrent_workers_singleflight_contract_preparation() {
        let _retention = default_retention();
        const WORKERS: usize = 8;
        let program = Arc::new(minimal_program());
        let code_hash = ivm::contract_code_hash(program.as_slice());
        let cache = PreparedContractCache::with_capacity(4);
        let barrier = Arc::new(std::sync::Barrier::new(WORKERS));
        let handles = (0..WORKERS)
            .map(|_| {
                let program = Arc::clone(&program);
                let cache = cache.clone();
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    cache
                        .get_or_prepare(code_hash, program.as_slice())
                        .expect("singleflight preparation")
                })
            })
            .collect::<Vec<_>>();
        let prepared = handles
            .into_iter()
            .map(|handle| handle.join().expect("worker must not panic"))
            .collect::<Vec<_>>();
        let artifact = prepared[0].artifact().as_ptr();
        assert!(
            prepared
                .iter()
                .all(|contract| contract.artifact().as_ptr() == artifact)
        );
        let stats = cache.stats();
        assert_eq!(stats.preparations, 1);
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.hits, (WORKERS - 1) as u64);
    }
    #[test]
    fn nested_runtime_pool_reuses_allocation_and_dirty_resets_memory() {
        let _retention = default_retention();
        const GAS_LIMIT: u64 = 10_000;
        const GOVERNED_HEAP_LIMIT: u64 = 96;
        let program = minimal_program();
        let code_hash = ivm::contract_code_hash(&program);
        let cache = PreparedContractCache::with_capacity(2);
        let prepared = cache
            .get_or_prepare(code_hash, &program)
            .expect("prepare nested contract");
        let memory_allocation = {
            let mut runtime = cache
                .checkout_runtime(prepared.as_ref(), GAS_LIMIT, GOVERNED_HEAP_LIMIT)
                .expect("cold nested runtime");
            assert_eq!(runtime.memory.heap_max_limit(), GOVERNED_HEAP_LIMIT);
            let allocation = runtime
                .memory
                .load_region(0, 1)
                .expect("code memory")
                .as_ptr();
            runtime.set_register(7, 99);
            runtime
                .memory
                .preload_input(0, &[0xA5])
                .expect("dirty nested input page");
            allocation
        };
        let after_first = cache.stats();
        assert_eq!(after_first.runtime_misses, 1);
        assert_eq!(after_first.runtime_prepared_loads, 1);
        assert_eq!(after_first.runtime_template_builds, 1);
        assert_eq!(after_first.runtime_dirty_resets, 1);
        {
            let runtime = cache
                .checkout_runtime(prepared.as_ref(), GAS_LIMIT, GOVERNED_HEAP_LIMIT)
                .expect("warm nested runtime");
            assert_eq!(runtime.register(7), 0);
            assert_eq!(runtime.remaining_gas(), GAS_LIMIT);
            assert_eq!(runtime.memory.heap_max_limit(), GOVERNED_HEAP_LIMIT);
            assert_eq!(
                runtime
                    .memory
                    .load_region(0, 1)
                    .expect("code memory")
                    .as_ptr(),
                memory_allocation,
                "warm nested invocation must reuse the VM allocation"
            );
            assert_eq!(
                runtime
                    .memory
                    .load_region(0x0020_0000, 1)
                    .expect("input memory"),
                &[0],
                "dirty nested input must be restored from the baseline"
            );
        }
        let after_second = cache.stats();
        assert_eq!(after_second.runtime_hits, after_first.runtime_hits + 1);
        assert_eq!(
            after_second.runtime_prepared_loads,
            after_first.runtime_prepared_loads
        );
        assert_eq!(
            after_second.runtime_template_builds,
            after_first.runtime_template_builds
        );
        assert_eq!(
            after_second.runtime_dirty_resets,
            after_first.runtime_dirty_resets + 1
        );
    }

    #[test]
    fn nested_runtime_and_template_charges_survive_final_baseline_owner() {
        // This positive requires enabled retention for its whole owner lifetime.
        // Serialize the canonical configuration writers that may evict every pool.
        let _cache_limits = ivm::ivm_cache::CacheLimitsGuard::new(ivm::ivm_cache::CacheLimits {
            capacity: iroha_config::parameters::defaults::pipeline::CACHE_SIZE,
            max_bytes: iroha_config::parameters::defaults::pipeline::IVM_CACHE_MAX_BYTES,
            max_decoded_ops:
                iroha_config::parameters::defaults::pipeline::IVM_CACHE_MAX_DECODED_OPS,
        });
        const GAS_LIMIT: u64 = 10_000;
        let program = minimal_program();
        let code_hash = ivm::contract_code_hash(&program);
        let budget = iroha_allocation::AllocationBudget::new(64 * 1024 * 1024);
        let cache = PreparedContractCache::with_execution_budget(2, budget.clone());
        let prepared = cache
            .get_or_prepare(code_hash, &program)
            .expect("prepare nested contract");
        let prepared_bytes = budget.reserved_bytes();

        let funded_bytes = {
            let runtime = cache
                .checkout_runtime(&prepared, GAS_LIMIT, HEAP_LIMIT)
                .expect("cold funded runtime");
            let image_bytes = usize::try_from(runtime.memory.stack_top()).unwrap();
            let leaf_bytes = image_bytes.div_ceil(32) * 32;
            let funded_bytes = budget.reserved_bytes();
            assert!(
                funded_bytes > 2 * (image_bytes + leaf_bytes),
                "both VM and baseline image, leaves, nodes, and tracking are prepaid"
            );
            funded_bytes
        };
        assert_eq!(
            budget.reserved_bytes(),
            funded_bytes,
            "idle VM and immutable baseline retain their original execution charges"
        );

        let runtime = cache
            .checkout_runtime(&prepared, GAS_LIMIT, HEAP_LIMIT)
            .expect("borrow idle runtime");
        // Core baseline ownership is strong-only. An independent final baseline
        // borrower must keep its full immutable snapshot funded after VM eviction.
        let baseline = runtime.baseline.clone();
        cache.inner.lock().clear_storage();
        assert_eq!(
            budget.reserved_bytes(),
            funded_bytes,
            "borrow outlives eviction"
        );
        drop(runtime);
        assert!(
            budget.reserved_bytes() > 0,
            "baseline still owns its snapshot"
        );
        assert!(
            budget.reserved_bytes() < funded_bytes,
            "VM backing was reclaimed"
        );
        budget.set_limit_bytes(0);
        drop(baseline);
        assert_eq!(
            budget.reserved_bytes(),
            prepared_bytes,
            "final baseline owner refunds its snapshot while the artifact remains borrowed"
        );
        drop(prepared);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn cold_nested_template_refuses_when_only_vm_backing_fits() {
        const GAS_LIMIT: u64 = 10_000;
        let budget = iroha_allocation::AllocationBudget::new(64 * 1024 * 1024);
        let cache = PreparedContractCache::with_execution_budget(1, budget.clone());
        let program = minimal_program();
        let prepared = cache
            .get_or_prepare(ivm::contract_code_hash(&program), &program)
            .unwrap();
        let prepared_bytes = budget.reserved_bytes();
        let mut vm = ivm::IVM::try_new_with_memory_budget(GAS_LIMIT, &budget).unwrap();
        vm.set_zk_trace_enabled(false);
        vm.memory.set_heap_max_limit(HEAP_LIMIT).unwrap();
        vm.load_prepared(&prepared).unwrap();
        let vm_bytes = budget.reserved_bytes() - prepared_bytes;
        drop(vm);
        budget.set_limit_bytes(prepared_bytes + vm_bytes);
        assert!(matches!(
            cache.checkout_runtime(&prepared, GAS_LIMIT, HEAP_LIMIT),
            Err(ivm::VMError::AllocationDeferred(_))
        ));
        assert_eq!(
            budget.reserved_bytes(),
            prepared_bytes,
            "failed template destroys its unpublished VM; the artifact stays borrowed"
        );
        budget.set_limit_bytes(64 * 1024 * 1024);
        let runtime = cache
            .checkout_runtime(&prepared, GAS_LIMIT, HEAP_LIMIT)
            .unwrap();
        assert!(budget.reserved_bytes() > prepared_bytes + vm_bytes);
        drop(runtime);
        cache.with_store(|store| store.clear_storage());
        assert_eq!(budget.reserved_bytes(), prepared_bytes);
        drop(prepared);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn nested_runtime_image_capacity_refusal_is_local_and_retryable() {
        let program = minimal_program();
        let code_hash = ivm::contract_code_hash(&program);
        let budget = iroha_allocation::AllocationBudget::new(64 * 1024 * 1024);
        let cache = PreparedContractCache::with_execution_budget(1, budget.clone());
        let prepared = cache
            .get_or_prepare(code_hash, &program)
            .expect("prepare contract while its original pool has capacity");
        let prepared_bytes = budget.reserved_bytes();
        budget.set_limit_bytes(0);
        assert!(matches!(
            cache.checkout_runtime(&prepared, 10_000, HEAP_LIMIT),
            Err(ivm::VMError::AllocationDeferred(
                iroha_allocation::AllocationRefusal::ExceedsLimit { .. }
            ))
        ));
        assert_eq!(budget.reserved_bytes(), prepared_bytes);
        budget.set_limit_bytes(64 * 1024 * 1024);
        let runtime = cache
            .checkout_runtime(&prepared, 10_000, HEAP_LIMIT)
            .expect("same contract retries after local capacity returns");
        assert!(budget.reserved_bytes() > 0);
        drop(runtime);
        cache.with_store(|store| store.clear_storage());
        assert_eq!(budget.reserved_bytes(), prepared_bytes);
        drop(prepared);
        assert_eq!(budget.reserved_bytes(), 0);
    }
    #[test]
    fn evicted_prepared_artifact_does_not_retain_an_active_nested_runtime() {
        const GAS_LIMIT: u64 = 10_000;
        const HEAP_LIMIT: u64 = 96;
        let mut first_program = minimal_program();
        first_program[8..16].copy_from_slice(&23u64.to_le_bytes());
        let first_hash = ivm::contract_code_hash(&first_program);
        let mut second_program = minimal_program();
        second_program[8..16].copy_from_slice(&29u64.to_le_bytes());
        let second_hash = ivm::contract_code_hash(&second_program);
        let cache = PreparedContractCache::with_capacity(1);
        let first = cache
            .get_or_prepare(first_hash, &first_program)
            .expect("first prepared contract");
        let runtime = cache
            .checkout_runtime(first.as_ref(), GAS_LIMIT, HEAP_LIMIT)
            .expect("first nested runtime");
        cache
            .get_or_prepare(second_hash, &second_program)
            .expect("replacement prepared contract");
        assert!(cache.get(first_hash).is_none());
        drop(runtime);
        assert_eq!(
            cache.stats().runtime_dirty_resets,
            0,
            "an evicted runtime must not be reset or admitted to retention"
        );
        let key = RuntimeKey::new(first_hash, stack_limit_for_gas(GAS_LIMIT), HEAP_LIMIT);
        assert!(
            !cache.inner.lock().nested_runtimes.contains_key(&key),
            "an evicted artifact must not regain an idle nested runtime"
        );
        let first = cache
            .get_or_prepare(first_hash, &first_program)
            .expect("reprepare evicted contract");
        let _runtime = cache
            .checkout_runtime(first.as_ref(), GAS_LIMIT, HEAP_LIMIT)
            .expect("fresh nested runtime");
        assert_eq!(cache.stats().runtime_misses, 2);
    }
    #[test]
    fn overlapping_nested_runtimes_return_with_their_own_baselines() {
        const GAS_LIMIT: u64 = 10_000;
        const GOVERNED_HEAP_LIMIT: u64 = 96;
        let program = minimal_program();
        let code_hash = ivm::contract_code_hash(&program);
        let cache = PreparedContractCache::with_capacity(2);
        let prepared = cache
            .get_or_prepare(code_hash, &program)
            .expect("prepare nested contract");
        let first = cache
            .checkout_runtime(prepared.as_ref(), GAS_LIMIT, GOVERNED_HEAP_LIMIT)
            .expect("first cold nested runtime");
        let (second_allocation, loaded_code_hash, code_byte) = {
            let mut second = cache
                .checkout_runtime(prepared.as_ref(), GAS_LIMIT, GOVERNED_HEAP_LIMIT)
                .expect("overlapping cold nested runtime");
            let code = second.memory.load_region(0, 1).expect("second code memory");
            let allocation = code.as_ptr();
            let code_byte = code[0];
            second
                .memory
                .preload_input(0, &[0xA5])
                .expect("dirty second input");
            (allocation, second.code_hash(), code_byte)
        };
        let third = cache
            .checkout_runtime(prepared.as_ref(), GAS_LIMIT, GOVERNED_HEAP_LIMIT)
            .expect("second runtime is reused or reloaded while first remains leased");
        let third_code = third.memory.load_region(0, 1).expect("third code memory");
        let third_allocation = third_code.as_ptr();
        assert_eq!(third_code[0], code_byte);
        assert_eq!(third.code_hash(), loaded_code_hash);
        assert_eq!(
            third
                .memory
                .load_region(ivm::Memory::INPUT_START, 1)
                .expect("third input memory"),
            [0]
        );
        let stats = cache.stats();
        assert_eq!(stats.runtime_hits + stats.runtime_misses, 3);
        assert_eq!(stats.runtime_prepared_loads, stats.runtime_misses);
        assert_eq!(stats.runtime_template_builds, stats.runtime_misses);
        assert!(stats.runtime_dirty_resets <= 1);
        if stats.runtime_hits == 1 {
            assert_eq!(third_allocation, second_allocation);
            assert_eq!(stats.runtime_dirty_resets, 1);
        } else {
            assert_eq!(stats.runtime_misses, 3);
        }
        drop((third, first));
        let after_return = cache.stats();
        assert!(after_return.runtime_dirty_resets >= stats.runtime_dirty_resets);
        assert!(after_return.runtime_dirty_resets <= stats.runtime_dirty_resets + 1);
        let key = RuntimeKey::new(
            code_hash,
            stack_limit_for_gas(GAS_LIMIT),
            GOVERNED_HEAP_LIMIT,
        );
        let idle = cache
            .inner
            .lock()
            .nested_runtimes
            .get(&key)
            .map_or(0, |pool| pool.available.len());
        assert!(
            idle <= 1,
            "overlapping returns must keep at most one idle VM"
        );
    }

    #[test]
    fn evicted_local_summary_cannot_admit_its_borrowed_runtime() {
        const GAS_LIMIT: u64 = 10_000;
        let program = minimal_program();
        let mut cache = IvmCache::with_capacity(1);
        let summary = cache.summarize_program(&program).expect("summary");
        let local = Arc::clone(&cache.local);
        let runtime = cache
            .checkout_runtime(&summary, &program, GAS_LIMIT, HEAP_LIMIT)
            .expect("runtime");
        local.lock().clear_storage();
        drop(runtime);
        assert_eq!(cache.stats().dirty_resets, 0);
        assert!(local.lock().runtime_templates.is_empty());
    }
    #[test]
    fn program_summary_owned_lease_reuses_runtime_on_early_return() {
        // This positive requires enabled retention for its whole owner lifetime.
        // Serialize the canonical configuration writers that may evict every pool.
        let _cache_limits = ivm::ivm_cache::CacheLimitsGuard::new(ivm::ivm_cache::CacheLimits {
            capacity: iroha_config::parameters::defaults::pipeline::CACHE_SIZE,
            max_bytes: iroha_config::parameters::defaults::pipeline::IVM_CACHE_MAX_BYTES,
            max_decoded_ops:
                iroha_config::parameters::defaults::pipeline::IVM_CACHE_MAX_DECODED_OPS,
        });
        const GAS_LIMIT: u64 = 10_000;
        let program = minimal_program();
        let mut cache = IvmCache::with_capacity(2);
        let summary = cache.summarize_program(&program).expect("summary");
        assert_eq!(
            summary.prepared_contract().manifest().code_hash,
            Some(summary.code_hash)
        );
        let prepared_cache = summary.prepared_contract_cache();
        fn dirty_then_return(summary: &ProgramSummary) -> Result<(), *const u8> {
            let mut runtime = summary
                .checkout_runtime(GAS_LIMIT, HEAP_LIMIT)
                .expect("prepared runtime");
            let allocation = runtime
                .memory
                .load_region(0, 1)
                .expect("code memory")
                .as_ptr();
            runtime.set_register(7, 99);
            runtime
                .memory
                .preload_input(0, &[0xA5])
                .expect("dirty input page");
            Err(allocation)
        }
        let allocation = dirty_then_return(&summary).expect_err("early return");
        let after_error = prepared_cache.stats();
        assert_eq!(after_error.runtime_dirty_resets, 1);
        let runtime = summary
            .checkout_runtime(GAS_LIMIT, HEAP_LIMIT)
            .expect("warm runtime");
        assert_eq!(runtime.register(7), 0);
        assert_eq!(runtime.remaining_gas(), GAS_LIMIT);
        assert_eq!(
            runtime
                .memory
                .load_region(0, 1)
                .expect("code memory")
                .as_ptr(),
            allocation
        );
        assert_eq!(prepared_cache.stats().runtime_hits, 1);
    }
    #[test]
    fn prepared_store_evicts_lru_and_rejects_hash_mismatches() {
        let _retention = default_retention();
        let mut first_program = minimal_program();
        first_program[8..16].copy_from_slice(&23u64.to_le_bytes());
        let first_hash = ivm::contract_code_hash(&first_program);
        let mut second_program = minimal_program();
        second_program[8..16].copy_from_slice(&29u64.to_le_bytes());
        let second_hash = ivm::contract_code_hash(&second_program);
        let cache = PreparedContractCache::with_capacity(1);
        assert!(matches!(
            cache.get_or_prepare(first_hash, &second_program),
            Err(ivm::VMError::InvalidMetadata)
        ));
        cache
            .get_or_prepare(first_hash, &first_program)
            .expect("first valid artifact");
        cache
            .get_or_prepare(second_hash, &second_program)
            .expect("second valid artifact");
        let after_eviction = cache.stats();
        assert_eq!(after_eviction.evictions, 1);
        // Once evicted, a hash-only lookup cannot silently reuse a stale or
        // different artifact. The caller must supply the exact bytes again.
        assert!(matches!(
            cache.get_or_prepare(first_hash, &[]),
            Err(ivm::VMError::InvalidMetadata)
        ));
        let final_stats = cache.stats();
        assert_eq!(final_stats.misses, after_eviction.misses + 1);
        assert_eq!(final_stats.preparations, after_eviction.preparations);
    }
    #[test]
    fn analysis_is_reused_across_transactions() {
        let _retention = default_retention();
        let program = minimal_program();
        let mut cache = IvmCache::with_capacity(2);
        let summary = cache.summarize_program(&program).expect("summary");
        let first = cache
            .analyze_program(&summary, &program)
            .expect("first analysis");
        let second = cache
            .analyze_program(&summary, &program)
            .expect("second analysis");
        assert_eq!(first.instruction_count, second.instruction_count);
        assert_eq!(first.metadata.max_cycles, second.metadata.max_cycles);
        let stats = cache.stats();
        assert_eq!(stats.analysis_misses, 1);
        assert_eq!(stats.analysis_hits, 1);
    }
    #[test]
    fn metadata_cache_distinguishes_header_changes() {
        let mut cache = IvmCache::with_capacity(4);
        // Same body but different metadata (max_cycles) must not share cache entries.
        let mut program = minimal_program();
        program[8..16].copy_from_slice(&1u64.to_le_bytes());
        let summary1 = cache.summarize_program(&program).expect("first summary");
        let mut program2 = program.clone();
        program2[8..16].copy_from_slice(&2u64.to_le_bytes());
        let summary2 = cache.summarize_program(&program2).expect("second summary");
        assert_ne!(summary1.meta_hash, summary2.meta_hash);
        let stats = cache.stats();
        assert_eq!(stats.metadata_hits, 0);
        assert_eq!(stats.metadata_misses, 2);
        {
            let vm1 = cache
                .checkout_runtime(&summary1, &program, 1_000, HEAP_LIMIT)
                .expect("runtime for first variant");
            assert_eq!(vm1.metadata().max_cycles, 1);
        }
        let vm2 = cache
            .checkout_runtime(&summary2, &program2, 1_000, HEAP_LIMIT)
            .expect("runtime for second variant");
        assert_eq!(vm2.metadata().max_cycles, 2);
    }
    #[test]
    fn runtime_stack_limit_tracks_gas_limit() {
        let mut cache = IvmCache::with_capacity(1);
        let mut program = minimal_program();
        program[8..16].copy_from_slice(&14u64.to_le_bytes());
        program[16] = 1; // abi_version
        let summary = cache.summarize_program(&program).expect("summary");
        let gas_limit = 100_000;
        let vm = cache
            .checkout_runtime(&summary, &program, gas_limit, HEAP_LIMIT)
            .expect("runtime");
        let expected = IvmConfig::new(gas_limit).stack_limit_for_gas();
        assert!(
            expected > 64 * 1024,
            "expected stack limit to exceed 64KiB; got {expected}"
        );
        assert_eq!(vm.memory.stack_limit(), expected);
    }
    #[test]
    fn eviction_prunes_runtimes_for_evicted_summary() {
        let _retention = default_retention();
        let mut cache = IvmCache::with_capacity(1);
        let gas_limit = 50_000;
        let mut program1 = minimal_program();
        program1[8..16].copy_from_slice(&1u64.to_le_bytes());
        let summary1 = cache.summarize_program(&program1).expect("summary1");
        {
            let _runtime = cache
                .checkout_runtime(&summary1, &program1, gas_limit, HEAP_LIMIT)
                .expect("runtime1");
        }
        let mut program2 = minimal_program();
        program2[8..16].copy_from_slice(&2u64.to_le_bytes());
        let summary2 = cache.summarize_program(&program2).expect("summary2");
        let summary1_key = SummaryKey::new(summary1.code_hash);
        let summary2_key = SummaryKey::new(summary2.code_hash);
        assert!(!cache.local.lock().summaries.contains_key(&summary1_key));
        assert!(cache.local.lock().summaries.contains_key(&summary2_key));
        let runtime1_key = RuntimeKey::new(
            summary1.code_hash,
            stack_limit_for_gas(gas_limit),
            HEAP_LIMIT,
        );
        assert!(
            !cache
                .local
                .lock()
                .runtime_templates
                .contains_key(&runtime1_key)
        );
        {
            let _runtime = cache
                .checkout_runtime(&summary2, &program2, gas_limit, HEAP_LIMIT)
                .expect("runtime2");
        }
        let runtime2_key = RuntimeKey::new(
            summary2.code_hash,
            stack_limit_for_gas(gas_limit),
            HEAP_LIMIT,
        );
        assert!(
            cache
                .local
                .lock()
                .runtime_templates
                .contains_key(&runtime2_key)
        );
    }
}

#[cfg(test)]
#[path = "cache/refund_tests.rs"]
mod refund_tests;

#[cfg(test)]
#[path = "cache/generic_memory_tests.rs"]
mod generic_memory_tests;

#[cfg(test)]
#[path = "cache/analysis_memory_tests.rs"]
mod analysis_memory_tests;

#[cfg(test)]
mod preparation_refund_tests;

#[cfg(test)]
#[path = "cache/range_tests.rs"]
mod range_tests;
