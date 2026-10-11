//! Bounded immutable imports and lexical pure epoch work; no current-state evidence.

use super::{AuthorityProfile, ServiceAuthority};
#[cfg(test)]
use crate::managed::native_operation::decode_checkpoint;
use crate::{
    managed::{
        Result,
        native_operation::{MAX_CHECKPOINT_BYTES, decode_checkpoint_with_validation},
    },
    verify::finality::FinalityVerifier,
};
use iroha_data_model::{
    NetworkId,
    block::execution_output::ExecutionOutputV1,
    sumeragi_finality::{EpochValidationScope, SumeragiFinalityCheckpoint, VerifiedSumeragiBlock},
};
use std::{
    mem::size_of,
    sync::{Arc, Mutex, OnceLock, TryLockError},
};

const SLOTS: usize = 3;
const MAX_CHAIN_CAPACITY: usize = 1024;

struct Entry {
    bytes: Vec<u8>,
    network: NetworkId,
    chain: String,
    verifier: FinalityVerifier,
    retained_import_envelope: usize,
}

/// Cache-owned requested retention, not producer scratch, allocator overhead or caller aliases.
/// Four independently bounded decoded graphs coexist: checkpoint, signed tip, result commitment
/// and core header. Availability has an uncharged raw copy and Arc; the signed tip's sole retained
/// Merkle array requests at most four nodes per canonically encoded 32-byte leaf. The two outer
/// Arcs are constructed after decoding. Pending observations are absent from imported originals.
fn retained_import_envelope(encoded_len: usize) -> Option<usize> {
    if encoded_len > MAX_CHECKPOINT_BYTES {
        return None;
    }
    let merkle_nodes = (encoded_len / iroha_crypto::Hash::LENGTH)
        .checked_mul(4)?
        .checked_mul(size_of::<Option<iroha_crypto::HashOf<ExecutionOutputV1>>>())?;
    norito::canonical_decode_limits(encoded_len)
        .max_total_allocated_bytes()
        .checked_mul(4)?
        .checked_add(encoded_len)?
        .checked_add(merkle_nodes)?
        .checked_add(
            norito::core::owned_arc_allocation_bytes::<SumeragiFinalityCheckpoint>().ok()?,
        )?
        .checked_add(
            norito::core::owned_arc_allocation_bytes::<OnceLock<VerifiedSumeragiBlock>>().ok()?,
        )?
        .checked_add(norito::core::owned_arc_allocation_bytes::<Vec<u8>>().ok()?)?
        .checked_add(size_of::<Entry>())?
        .checked_add(MAX_CHAIN_CAPACITY)
}

#[derive(Default)]
struct Entries {
    slots: [Option<Entry>; SLOTS],
    first: usize,
    len: usize,
}

impl Entries {
    fn clear(&mut self) {
        for slot in &mut self.slots {
            drop(slot.take());
        }
        self.first = 0;
        self.len = 0;
    }

    fn oldest(&mut self) {
        if self.len != 0 {
            drop(self.slots[self.first].take());
            self.first = (self.first + 1) % SLOTS;
            self.len -= 1;
        }
    }

    fn has_room(&self, key_capacity: usize, weight: usize) -> bool {
        let key_total = self
            .slots
            .iter()
            .flatten()
            .try_fold(key_capacity, |total, entry| {
                total.checked_add(entry.bytes.capacity())
            });
        let weight_total = self
            .slots
            .iter()
            .flatten()
            .try_fold(weight, |total, entry| {
                total.checked_add(entry.retained_import_envelope)
            });
        self.len < SLOTS
            && key_total.is_some_and(|total| total <= MAX_CHECKPOINT_BYTES)
            && weight_total
                .zip(retained_import_envelope(MAX_CHECKPOINT_BYTES))
                .is_some_and(|(total, ceiling)| total <= ceiling)
    }

    fn make_room(&mut self, key_capacity: usize, weight: usize) -> bool {
        while self.len != 0 && !self.has_room(key_capacity, weight) {
            self.oldest();
        }
        self.has_room(key_capacity, weight)
    }

    fn insert(&mut self, entry: Entry) {
        self.slots[(self.first + self.len) % SLOTS] = Some(entry);
        self.len += 1;
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Fixed FIFO slots retain only exact successful imports. Aggregate encoded key capacities stay
/// within the original one-frame bound, and final memo-owned slots fit one maximum-frame envelope.
/// An incoming candidate is checked under the gate before decoding; this is not a reservation
/// across concurrent misses. Concurrent producer work, scratch and caller-owned results are separate.
/// No entry is retained per body, purpose, height or peer, and no failure is remembered.
#[derive(Default)]
pub(super) struct CheckpointCache {
    entry: Mutex<Entries>,
    // Only a lexical graph/census owns this boxed two-context workspace. Standalone authorities
    // retain only this optional pointer, keeping the existing large orchestration frames small.
    epoch_validation: Option<Box<Mutex<EpochValidationScope>>>,
    #[cfg(test)]
    decode_attempts: std::sync::atomic::AtomicUsize,
}

/// One explicit lexical graph/census owner of the existing immutable import memo and at most
/// two complete validated epoch contexts. The epoch workspace is separate from the unchanged
/// checkpoint-entry retention envelope; it is not another checkpoint cache or authority verdict.
/// Fresh source, purpose, transaction and current-state checks remain with each caller.
#[derive(Clone)]
pub(in crate::managed) struct CheckpointImportScope {
    cache: Arc<CheckpointCache>,
}

impl CheckpointImportScope {
    #[cfg(test)]
    /// Observe lexical ownership without retaining the memo or its validated contexts.
    pub(in crate::managed) fn test_alive(&self) -> impl Fn() -> bool + 'static {
        let cache = Arc::downgrade(&self.cache);
        move || cache.strong_count() != 0
    }

    #[cfg(test)]
    /// Probe the actual workspace after its producer; a cold probe intentionally warms it.
    pub(in crate::managed) fn test_epoch_charge(
        &self,
        context: &iroha_data_model::sumeragi::epoch::ValidatorEpochContextV1,
    ) -> u64 {
        let mut selected = self
            .cache
            .epoch_validation
            .as_ref()
            .expect("lexical import scope owns its pure epoch workspace")
            .try_lock()
            .expect("read-only probe runs after the completed child import");
        let finite = norito::core::DecodeBudgetContext::new(norito::DecodeLimits::new(
            1024 * 1024,
            MAX_CHECKPOINT_BYTES,
            8 * 1024 * 1024,
            64 * 1024 * 1024,
            64,
        ));
        finite.with(|| selected.core_epoch(context)).unwrap();
        finite.consumed_allocated_bytes()
    }

    /// Begin cold pure-import work only for an inactive shared original graph.
    /// Owned profiles and active caller admission keep their original independent recipes.
    pub(in crate::managed) fn for_original(parent: &ServiceAuthority) -> Option<Self> {
        if norito::core::decode_limits_active()
            || !matches!(&parent.profile, AuthorityProfile::Shared(_))
        {
            return None;
        }
        Some(Self {
            cache: Arc::new(CheckpointCache {
                epoch_validation: Some(Box::new(Mutex::new(EpochValidationScope::new()))),
                ..CheckpointCache::default()
            }),
        })
    }
}

impl ServiceAuthority {
    // Always select the actual memo, including inside an active decode scope. Its original
    // active branch clears warmed slots and performs the physical producer without reuse.
    fn effective_checkpoint_cache(&self) -> &CheckpointCache {
        self.checkpoint_import_scope
            .as_ref()
            .map_or(&self.checkpoint_cache, |scope| scope.cache.as_ref())
    }

    /// Borrow only this transient graph's explicitly installed import owner for nested children.
    pub(in crate::managed) fn checkpoint_import_scope(&self) -> Option<&CheckpointImportScope> {
        self.checkpoint_import_scope.as_ref()
    }

    #[cfg(test)]
    /// Observe cold imports across temporary child owners without retaining any cache or result.
    pub(in crate::managed) fn test_begin_graph_import_counts() -> impl Drop {
        graph_import_counts::Counter::begin()
    }

    #[cfg(test)]
    /// Read the explicitly installed scalar observer; cache hits do not increment it.
    pub(in crate::managed) fn test_graph_import_snapshot() -> Option<usize> {
        graph_import_counts::snapshot()
    }

    #[cfg(test)]
    /// Count attempted canonical imports without changing the optional cache.
    pub(in crate::managed) fn test_checkpoint_import_attempts(&self) -> usize {
        self.effective_checkpoint_cache()
            .decode_attempts
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Import an exact independently selected checkpoint, retaining only successful immutable work.
    /// Callers still read and authenticate their original custody before supplying these bytes.
    pub(in crate::managed) fn decode_checkpoint(&self, bytes: &[u8]) -> Result<FinalityVerifier> {
        self.effective_checkpoint_cache().decode(
            bytes,
            self.config.network_id,
            self.config.chain.as_str(),
        )
    }
}

/// A borrowed pure workspace for one retained prerequisite; never stored in History.
/// A lexical graph/census workspace takes precedence, leaving freshly created local scopes empty.
/// Each decode still selects its current original bytes, source and enclosing admission owner.
pub(in crate::managed) struct CheckpointImports<'a, 'v> {
    authority: &'a ServiceAuthority,
    validation: Option<&'v mut EpochValidationScope>,
}

impl<'a, 'v> CheckpointImports<'a, 'v> {
    pub(in crate::managed) fn new(
        authority: &'a ServiceAuthority,
        validation: Option<&'v mut EpochValidationScope>,
    ) -> Self {
        Self {
            authority,
            validation,
        }
    }

    pub(in crate::managed) fn decode(&mut self, bytes: &[u8]) -> Result<FinalityVerifier> {
        self.authority
            .effective_checkpoint_cache()
            .decode_for_scope(
                bytes,
                self.authority.config.network_id,
                self.authority.config.chain.as_str(),
                self.validation.as_deref_mut(),
            )
    }

    pub(in crate::managed) fn retained_finality(
        &mut self,
        directory: &iroha_fs::PrivateDirectory,
        transaction: &iroha_data_model::transaction::SignedTransaction,
    ) -> Result<Option<crate::managed::native_operation::ManagedTransactionFinality>> {
        crate::managed::native_operation::retained_carrier_using(directory, transaction, |bytes| {
            self.decode(bytes)
        })
    }
}

impl CheckpointCache {
    fn decode(&self, bytes: &[u8], network: NetworkId, chain: &str) -> Result<FinalityVerifier> {
        self.decode_for_scope(bytes, network, chain, None)
    }

    // Select only the existing canonical producer's borrowed pure workspace. Scoped contention
    // and poison never wait or populate a second caller-local pair. A prewarmed external caller
    // workspace remains separately caller-owned; ordinary graph/prerequisite locals start empty.
    // An active owner clears the accessible selected epoch workspace and keeps its physical
    // producer and cumulative charges, even when the lexical scope was warmed before entry.
    fn decode_for_scope(
        &self,
        bytes: &[u8],
        network: NetworkId,
        chain: &str,
        validation: Option<&mut EpochValidationScope>,
    ) -> Result<FinalityVerifier> {
        let Some(shared) = &self.epoch_validation else {
            return self.decode_with_validation(bytes, network, chain, validation);
        };
        match shared.try_lock() {
            Ok(mut selected) => {
                if norito::core::decode_limits_active() {
                    *selected = EpochValidationScope::new();
                    self.decode_with_validation(bytes, network, chain, None)
                } else {
                    self.decode_with_validation(bytes, network, chain, Some(&mut selected))
                }
            }
            Err(TryLockError::Poisoned(mut poisoned)) => {
                **poisoned.get_mut() = EpochValidationScope::new();
                self.decode_with_validation(bytes, network, chain, None)
            }
            Err(TryLockError::WouldBlock) => {
                self.decode_with_validation(bytes, network, chain, None)
            }
        }
    }

    fn decode_with_validation(
        &self,
        bytes: &[u8],
        network: NetworkId,
        chain: &str,
        mut validation: Option<&mut EpochValidationScope>,
    ) -> Result<FinalityVerifier> {
        // A scope entered after warming still receives its original physical admission.
        let active_owner = norito::core::decode_limits_active();
        let weight = retained_import_envelope(bytes.len());
        let (may_store, retained_before_import) = match self.entry.try_lock() {
            Ok(mut selected) => {
                if active_owner {
                    selected.clear();
                    (false, false)
                } else {
                    if let Some(entry) = selected.slots.iter().flatten().find(|entry| {
                        entry.network == network && entry.chain == chain && entry.bytes == bytes
                    }) {
                        // Returning an Arc clone cannot advance this immutable original.
                        return Ok(entry.verifier.clone());
                    }
                    // Account the incoming decoded envelope before its canonical producer runs.
                    let eligible =
                        weight.is_some_and(|weight| selected.make_room(bytes.len(), weight));
                    if !eligible {
                        selected.clear();
                    }
                    (eligible, !selected.is_empty())
                }
            }
            Err(TryLockError::WouldBlock) => (false, false),
            Err(TryLockError::Poisoned(mut poisoned)) => {
                poisoned.get_mut().clear();
                (false, false)
            }
        };
        let offered = self.import(
            bytes,
            network,
            chain,
            if active_owner {
                None
            } else {
                validation.as_deref_mut()
            },
        );
        let verifier = match offered {
            Ok(verifier) => verifier,
            Err(error) => {
                // Mapped errors cannot identify allocator failure. Outside an enclosing owner,
                // release every accessible optional graph and retry the same canonical producer
                // once; the two pure epoch contexts may remain, never an authority verdict.
                let retry = if may_store {
                    match self.entry.try_lock() {
                        Ok(mut selected) => {
                            let retained = retained_before_import || !selected.is_empty();
                            selected.clear();
                            retained
                        }
                        Err(TryLockError::Poisoned(mut poisoned)) => {
                            poisoned.get_mut().clear();
                            false
                        }
                        Err(TryLockError::WouldBlock) => false,
                    }
                } else {
                    false
                };
                if !retry {
                    self.clear_after_refusal();
                    return Err(error);
                }
                drop(error);
                match self.import(bytes, network, chain, validation.as_deref_mut()) {
                    Ok(verifier) => verifier,
                    Err(error) => {
                        // Another caller may have filled the memo during the cold retry. Refusal
                        // clears all reachable slots without waiting for a concurrent holder.
                        self.clear_after_refusal();
                        return Err(error);
                    }
                }
            }
        };
        if may_store {
            // Optional allocation/capacity refusal never replaces a successful producer result.
            let mut image = Vec::new();
            let mut selected_chain = String::new();
            if chain.len() <= MAX_CHAIN_CAPACITY
                && image.try_reserve_exact(bytes.len()).is_ok()
                && selected_chain.try_reserve_exact(chain.len()).is_ok()
                && selected_chain.capacity() <= MAX_CHAIN_CAPACITY
                && image.capacity() <= MAX_CHECKPOINT_BYTES
            {
                image.extend_from_slice(bytes);
                selected_chain.push_str(chain);
                if let Some(weight) = weight
                    && let Ok(mut selected) = self.entry.try_lock()
                {
                    // Recheck capacities and FIFO admission after concurrent cold work. Avoid
                    // duplicate entries when another importer selected the same original.
                    let duplicate = selected.slots.iter().flatten().any(|entry| {
                        entry.network == network && entry.chain == chain && entry.bytes == bytes
                    });
                    if !duplicate && selected.make_room(image.capacity(), weight) {
                        selected.insert(Entry {
                            bytes: image,
                            network,
                            chain: selected_chain,
                            verifier: verifier.clone(),
                            retained_import_envelope: weight,
                        });
                    }
                }
            }
        }
        Ok(verifier)
    }

    fn clear_after_refusal(&self) {
        match self.entry.try_lock() {
            Ok(mut selected) => selected.clear(),
            Err(TryLockError::Poisoned(mut poisoned)) => poisoned.get_mut().clear(),
            Err(TryLockError::WouldBlock) => {}
        }
    }

    // One canonical producer for cold, nonwaiting fallback and optional-memory relief retry.
    // Each actual invocation owns its original admission and is counted independently.
    fn import(
        &self,
        bytes: &[u8],
        network: NetworkId,
        chain: &str,
        validation: Option<&mut EpochValidationScope>,
    ) -> Result<FinalityVerifier> {
        #[cfg(test)]
        graph_import_counts::record();
        #[cfg(test)]
        self.decode_attempts
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        #[cfg(test)]
        if crate::managed::native_operation::deadline_diagnostics::active() {
            crate::managed::native_operation::deadline_diagnostics::import_attempt(
                bytes,
                network,
                chain,
                self.decode_attempts
                    .load(std::sync::atomic::Ordering::Relaxed),
            );
        }
        decode_checkpoint_with_validation(bytes, network, chain, validation)
    }
}

#[cfg(test)]
mod graph_import_counts {
    //! Scalar counts at the actual cold producer; no bytes, owners or verdicts are retained.

    use std::cell::Cell;

    std::thread_local! {
        static IMPORTS: Cell<Option<usize>> = const { Cell::new(None) };
    }

    pub(super) fn record() {
        IMPORTS.with(|value| {
            if let Some(count) = value.get() {
                value.set(count.checked_add(1));
            }
        });
    }

    pub(super) fn snapshot() -> Option<usize> {
        IMPORTS.with(Cell::get)
    }

    pub(super) struct Counter(Option<usize>);

    impl Counter {
        pub(super) fn begin() -> Self {
            Self(IMPORTS.with(|value| value.replace(Some(0))))
        }
    }

    impl Drop for Counter {
        fn drop(&mut self) {
            IMPORTS.with(|value| value.set(self.0));
        }
    }

    #[test]
    fn graph_import_counts_are_explicit_scalar_observations_and_restore_the_prior_scope() {
        assert_eq!(snapshot(), None);
        record();
        assert_eq!(snapshot(), None);
        {
            let _counter = Counter::begin();
            record();
            assert_eq!(snapshot(), Some(1));
            {
                let _nested = Counter::begin();
                record();
                record();
                assert_eq!(snapshot(), Some(2));
            }
            assert_eq!(snapshot(), Some(1));
            IMPORTS.with(|value| value.set(Some(usize::MAX)));
            record();
            assert_eq!(snapshot(), None, "overflow declines observation only");
        }
        assert_eq!(snapshot(), None);
    }
}

#[cfg(test)]
#[path = "checkpoint_cache/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "checkpoint_cache/bounded_tests.rs"]
mod bounded_tests;

#[cfg(test)]
#[path = "checkpoint_cache/graph_scope_tests.rs"]
mod graph_scope_tests;
