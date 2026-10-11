//! Private native journal ownership of the certified pre-tail World cut.
//!
//! A result capture retains only touched element hashes (including absent/no-op
//! touches). Publication compares the same complete frozen journal and retains
//! only tail differences. This is neither a decoded snapshot nor caller-selected
//! root authority; restoration must replay the original execution to obtain it.

use super::*;
use crate::execution_attempt::ExecutionDeferred;
use crate::state::{NativeExecutionTip, StateBlock};
use iroha_allocation::{
    AllocationBudget, AllocationRefusal, ChargedBuffer, ChargedBufferError, ChargedShared,
};
use std::alloc::Layout;

#[derive(Debug)]
/// Native cut refusal preserves semantic failure or the original finite pool.
pub(crate) enum CutError {
    /// The original native journal no longer proves its exact root/count.
    Invalid(String),
    /// Local resource refusal; the same original owner may retry.
    Deferred(ExecutionDeferred),
}
impl From<String> for CutError {
    fn from(value: String) -> Self {
        Self::Invalid(value)
    }
}
impl From<AllocationRefusal> for CutError {
    fn from(value: AllocationRefusal) -> Self {
        Self::Deferred(value.into())
    }
}
impl From<ChargedBufferError> for CutError {
    fn from(value: ChargedBufferError) -> Self {
        match value {
            ChargedBufferError::Admission(refusal) => refusal.into(),
            ChargedBufferError::Allocator { .. } => {
                Self::Deferred(ivm::error::ExecutionDeferral::ActiveMemoryCapacity.into())
            }
        }
    }
}
impl std::fmt::Display for CutError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(reason) => reason.fmt(out),
            Self::Deferred(reason) => reason.fmt(out),
        }
    }
}

#[derive(Clone, Copy)]
struct JournalRow {
    slot: usize,
    id: &'static str,
    kind: u8,
    key: Option<Hash>,
    before: Option<Hash>,
    after: Option<Hash>,
}
impl JournalRow {
    fn identity(&self) -> (usize, u8, Option<Hash>) {
        (self.slot, self.kind, self.key)
    }
}

/// No public constructor or serialization. Rows belong to one original overlay.
pub(in crate::state) struct JournalCapture {
    rows: ChargedBuffer<JournalRow>,
    root: Hash,
    entries: u64,
}

/// Completed canonical tail whose final control shell has not been allocated.
/// Only the same immutable State publisher retains this move-only local owner.
/// Its rows retire before the original budget control; no source can be rebound.
pub(in crate::state) struct PendingCutCapsule {
    capsule: CutCapsule,
    budget: AllocationBudget,
}

impl PendingCutCapsule {
    /// Admit and allocate only the final shell using this same original pool.
    pub(in crate::state) fn try_share(self) -> Result<ChargedShared<CutCapsule>, (Self, CutError)> {
        let mut reservation = match self
            .budget
            .try_reserve(ChargedShared::<CutCapsule>::allocation_layout())
        {
            Ok(reservation) => reservation,
            Err(error) => return Err((self, error.into())),
        };
        let Self { capsule, budget } = self;
        ChargedShared::from_reservation(capsule, &mut reservation).map_err(|(capsule, error)| {
            let error = match error {
                iroha_allocation::PrepaidSharedError::Allocator { .. } => {
                    CutError::Deferred(ivm::error::ExecutionDeferral::ActiveMemoryCapacity.into())
                }
                iroha_allocation::PrepaidSharedError::Reservation(error) => CutError::Invalid(
                    format!("World cut original control layout differs: {error}"),
                ),
            };
            (Self { capsule, budget }, error)
        })
    }

    #[cfg(test)]
    pub(in crate::state) fn identity_for_test(&self) -> CutIdentityForTest {
        self.capsule.identity_for_test()
    }
}

/// Exact native preimages of only post-result changes, bound to original publication.
pub(in crate::state) struct CutCapsule {
    pub(in crate::state) tip: NativeExecutionTip,
    pub(in crate::state) generation: u64,
    pub(in crate::state) root: Hash,
    pub(in crate::state) entries: u64,
    pub(in crate::state) applied_root: Hash,
    pub(in crate::state) applied_entries: u64,
    rows: ChargedBuffer<JournalRow>,
}

impl CutCapsule {
    pub(in crate::state) fn change_for(
        &self,
        id: &str,
        kind: WorldStateElementKindV1,
        key: Option<Hash>,
    ) -> Option<(usize, Option<Hash>, Option<Hash>)> {
        let kind = if kind == WorldStateElementKindV1::Table {
            TABLE
        } else {
            CELL
        };
        self.rows
            .as_slice()
            .binary_search_by(|row| (row.id, row.kind, row.key).cmp(&(id, kind, key)))
            .ok()
            .map(|index| {
                (
                    index,
                    self.rows.as_slice()[index].before,
                    self.rows.as_slice()[index].after,
                )
            })
    }
    pub(in crate::state) fn changes(
        &self,
    ) -> impl ExactSizeIterator<
        Item = (
            &'static str,
            WorldStateElementKindV1,
            Option<Hash>,
            Option<Hash>,
            Option<Hash>,
        ),
    > + '_ {
        self.rows.as_slice().iter().map(move |row| {
            (
                row.id,
                if row.kind == TABLE {
                    WorldStateElementKindV1::Table
                } else {
                    WorldStateElementKindV1::Cell
                },
                row.key,
                row.before,
                row.after,
            )
        })
    }
}

struct JournalVisitor<'a> {
    index: &'a FieldIndex,
    visited: ChargedBuffer<bool>,
    count: usize,
    include_before: bool,
    rows: Option<ChargedBuffer<JournalRow>>,
}
impl<'a> JournalVisitor<'a> {
    fn new(
        index: &'a FieldIndex,
        budget: &AllocationBudget,
        rows: Option<ChargedBuffer<JournalRow>>,
        include_before: bool,
    ) -> Result<Self, CutError> {
        let mut visited = ChargedBuffer::new(index.canonical, budget)?;
        for _ in 0..index.canonical {
            visited.push_reserved(false);
        }
        Ok(Self {
            index,
            visited,
            count: 0,
            include_before,
            rows,
        })
    }
    fn field(&mut self, name: &str, kind: u8) -> Result<Option<usize>, CutError> {
        match self.index.by_name.get(name) {
            Some(Classified::Excluded) => Ok(None),
            Some(Classified::Canonical {
                kind: declared,
                slot,
                ..
            }) if *declared == kind => {
                if self.visited.as_slice()[*slot] {
                    return Err(format!("World cut repeats field {name}").into());
                }
                self.visited.as_mut_slice()[*slot] = true;
                Ok(Some(*slot))
            }
            _ => Err(format!("World cut has unclassified or mistyped field {name}").into()),
        }
    }
    fn record(&mut self, row: JournalRow) -> Result<(), CutError> {
        self.count = self
            .count
            .checked_add(1)
            .ok_or_else(|| CutError::from(AllocationRefusal::DemandOverflow))?;
        if let Some(rows) = self.rows.as_mut() {
            if rows.as_slice().len() == rows.capacity() {
                return Err("World cut journal count changed between borrowed passes"
                    .to_owned()
                    .into());
            }
            rows.push_reserved(row);
        }
        Ok(())
    }
    fn finish(self) -> Result<(usize, Option<ChargedBuffer<JournalRow>>), CutError> {
        if self.visited.as_slice().iter().any(|value| !value) {
            return Err("World cut omits a canonical registry field"
                .to_owned()
                .into());
        }
        Ok((self.count, self.rows))
    }
}
impl WorldProjection for JournalVisitor<'_> {
    type Error = CutError;
    // The exact original execution seal / frozen publication validation performs
    // the full trigger contract-row check. These passes must be changes-proportional.
    fn validates_trigger_contract_rows(&self) -> bool {
        false
    }
    fn append_musubi_archive_availability(
        &mut self,
        storage: &StorageField<'_, ArchiveId, MusubiArchiveAvailabilityV1>,
    ) -> Result<(), Self::Error> {
        self.append_storage_with("musubi_archive_availability", storage, |row| {
            hash_value(&crate::state::authority_registry::world::musubi_availability_policy::MusubiAvailabilityAuthorityV1::from_record(row))
        })
    }
    fn append_musubi_resolver_index(
        &mut self,
        storage: &StorageField<'_, MusubiReleaseIdV1, MusubiResolverReleaseRowV1>,
    ) -> Result<(), Self::Error> {
        self.append_storage_with("musubi_resolver_index", storage, |row| {
            hash_value(&crate::state::authority_registry::world::musubi_universal_policy::MusubiResolverAuthorityV1::from_record(row))
        })
    }
    fn append_musubi_public_directory(
        &mut self,
        storage: &StorageField<'_, MusubiPackageSelectorV1, MusubiOrderedPackageEntryV1>,
    ) -> Result<(), Self::Error> {
        self.append_storage_with("musubi_public_directory", storage, |row| {
            hash_value(&crate::state::authority_registry::world::musubi_universal_policy::MusubiDirectoryAuthorityV1::from_record(row))
        })
    }
    fn append_storage_with<K: Key + Encode, V: Value, M: mv::storage::StorageMode<K, V>>(
        &mut self,
        name: &'static str,
        storage: &StorageField<'_, K, V, M>,
        encode: impl Fn(&V) -> Result<Hash, String>,
    ) -> Result<(), Self::Error> {
        let Some(slot) = self.field(name, TABLE)? else {
            return Ok(());
        };
        for entry in storage.touched_entries() {
            let hashing = self.rows.is_some();
            self.record(JournalRow {
                slot,
                id: self.index.ids[slot],
                kind: TABLE,
                key: if hashing {
                    Some(hash_value(entry.key)?)
                } else {
                    None
                },
                before: if hashing && self.include_before {
                    entry.before.map(&encode).transpose()?
                } else {
                    None
                },
                after: if hashing {
                    entry.after.map(&encode).transpose()?
                } else {
                    None
                },
            })?;
        }
        Ok(())
    }
    fn append_cell_with<V: Value, C: Send + Sync + 'static>(
        &mut self,
        name: &'static str,
        cell: &CellField<'_, V, C>,
        encode: impl Fn(&V) -> Result<Hash, String>,
    ) -> Result<(), Self::Error> {
        let Some(slot) = self.field(name, CELL)? else {
            return Ok(());
        };
        if let Some(value) = cell.touched_value() {
            let hashing = self.rows.is_some();
            self.record(JournalRow {
                slot,
                id: self.index.ids[slot],
                kind: CELL,
                key: None,
                before: if hashing && self.include_before {
                    Some(encode(value.before)?)
                } else {
                    None
                },
                after: if hashing {
                    Some(encode(value.after)?)
                } else {
                    None
                },
            })?;
        }
        Ok(())
    }
}
fn journal(
    world: &WorldBlock<'_>,
    budget: &AllocationBudget,
    include_before: bool,
) -> Result<ChargedBuffer<JournalRow>, CutError> {
    let index = field_index().as_ref().map_err(Clone::clone)?;
    let count = {
        let mut visitor = JournalVisitor::new(index, budget, None, include_before)?;
        world.project_world(&mut visitor)?;
        visitor.finish()?.0
    };
    let rows = ChargedBuffer::new(count, budget)?;
    let mut visitor = JournalVisitor::new(index, budget, Some(rows), include_before)?;
    world.project_world(&mut visitor)?;
    let (actual, rows) = visitor.finish()?;
    if actual != count {
        return Err("World cut original journal count changed".to_owned().into());
    }
    let mut rows = rows.ok_or_else(|| CutError::Invalid("World cut journal absent".into()))?;
    rows.as_mut_slice()
        .sort_unstable_by_key(JournalRow::identity);
    if rows
        .as_slice()
        .windows(2)
        .any(|pair| pair[0].identity() == pair[1].identity())
    {
        return Err("World cut repeats a canonical touched identity"
            .to_owned()
            .into());
    }
    Ok(rows)
}

impl JournalCapture {
    pub(in crate::state) fn capture(
        world: &WorldBlock<'_>,
        genesis: bool,
        budget: &AllocationBudget,
    ) -> Result<Self, CutError> {
        // Only normal genesis initialization cold-captures the complete World;
        // every later block derives R from its original complete predecessor.
        let index = field_index().as_ref().map_err(Clone::clone)?;
        let scratch = budget.try_reserve_layouts([
            Layout::new::<[u16; LANES]>(),
            Layout::new::<[u16; LANES]>(),
            Layout::array::<bool>(index.canonical)
                .map_err(|_| AllocationRefusal::DemandOverflow)?,
        ])?;
        // Credits precede the existing accumulator pass's fixed heap lanes and
        // exhaustive visited-field scratch; none of those buffers escapes here.
        let (_, post) = world.state_transition(genesis)?;
        let root = post.root()?;
        let entries = post.entries();
        drop(post);
        drop(scratch);
        Ok(Self {
            rows: journal(world, budget, false)?,
            root,
            entries,
        })
    }
    /// Standalone component convenience retains the original one-attempt contract.
    #[cfg(test)]
    pub(in crate::state) fn prepare(
        &self,
        world: &WorldBlock<'_>,
        tip: NativeExecutionTip,
        generation: u64,
        budget: &AllocationBudget,
    ) -> Result<ChargedShared<CutCapsule>, CutError> {
        self.prepare_retained(world, tip, generation, budget)
            .map_err(|(_pending, error)| error)
    }

    /// Return a completed original capsule only when its final shell locally refuses.
    /// Earlier journal/verification errors retain their original order and no success.
    pub(in crate::state) fn prepare_retained(
        &self,
        world: &WorldBlock<'_>,
        tip: NativeExecutionTip,
        generation: u64,
        budget: &AllocationBudget,
    ) -> Result<ChargedShared<CutCapsule>, (Option<PendingCutCapsule>, CutError)> {
        let mut completed = None;
        let result = (|| -> Result<ChargedShared<CutCapsule>, CutError> {
            let mut final_rows = journal(world, budget, true)?;
            let mut old = 0;
            let mut changed = 0;
            for row in final_rows.as_mut_slice() {
                if let Some(original) = self.rows.as_slice().get(old) {
                    if original.identity() < row.identity() {
                        return Err("World cut lost an original touched identity"
                            .to_owned()
                            .into());
                    }
                    if original.identity() == row.identity() {
                        row.before = original.after;
                        old += 1;
                    }
                    // Otherwise this identity was first touched after R, so native
                    // journal.before is exactly its at-R preimage (including absence).
                }
                if row.before != row.after {
                    changed += 1;
                }
            }
            if old != self.rows.as_slice().len() {
                return Err("World cut omits original execution touches"
                    .to_owned()
                    .into());
            }
            let mut rows = ChargedBuffer::new(changed, budget)?;
            for row in final_rows.as_slice() {
                if row.before != row.after {
                    rows.push_reserved(*row);
                }
            }
            drop(final_rows);
            // Admit the accumulator's sole heap allocation before cloning its lanes.
            let layout = Layout::new::<[u16; LANES]>();
            let _scratch = budget
                .try_reserve(layout)?
                .try_split(layout)
                .map_err(|e| CutError::Invalid(e.to_string()))?;
            let applied = world.state_accumulator.get();
            let mut reconstructed = applied.clone();
            let index = field_index().as_ref().map_err(Clone::clone)?;
            for row in rows.as_slice() {
                let path = match index.by_name.get(
                    index.ids[row.slot]
                        .strip_prefix("world.")
                        .unwrap_or(index.ids[row.slot]),
                ) {
                    Some(Classified::Canonical { path, .. }) => path,
                    _ => return Err("World cut canonical path missing".to_owned().into()),
                };
                if let Some(after) = row.after {
                    reconstructed.remove(&element(path, row.key.as_ref(), &after));
                }
                if let Some(before) = row.before {
                    reconstructed.add(&element(path, row.key.as_ref(), &before));
                }
            }
            if reconstructed.entries() != self.entries || reconstructed.root()? != self.root {
                return Err(
                    "World cut exact frozen tail does not reconstruct original R/count"
                        .to_owned()
                        .into(),
                );
            }
            let capsule = CutCapsule {
                tip,
                generation,
                root: self.root,
                entries: self.entries,
                applied_root: applied.root()?,
                applied_entries: applied.entries(),
                rows,
            };
            #[cfg(test)]
            completion_observer::completed(&capsule);
            // Keep the original reconstruction and scratch alive through this first
            // shell attempt, preserving its exact earlier resource/error priority.
            let pending = PendingCutCapsule {
                capsule,
                budget: budget.clone(),
            };
            match pending.try_share() {
                Ok(shared) => Ok(shared),
                Err((pending, error)) => {
                    if matches!(&error, CutError::Deferred(_)) {
                        completed = Some(pending);
                    }
                    Err(error)
                }
            }
        })();
        result.map_err(|error| (completed, error))
    }
}

impl StateBlock<'_> {
    /// Only the original completed executor calls this before constructing R.
    pub(crate) fn capture_original_world_cut(&mut self, expected: Hash) -> Result<(), CutError> {
        if let Some(capture) = &self.world_cut_capture {
            if capture.root != expected {
                return Err("World cut original result changed during retry"
                    .to_owned()
                    .into());
            }
            return Ok(());
        }
        let capture = JournalCapture::capture(
            &self.world,
            self._curr_block.is_genesis(),
            &self.state_ref.ivm_execution_budget(),
        )?;
        if capture.root != expected {
            return Err("World cut original execution differs from R"
                .to_owned()
                .into());
        }
        self.world_cut_capture = Some(capture);
        Ok(())
    }
}

#[cfg(test)]
#[path = "world_state_cut_tests.rs"]
mod tests;

/// Observe actual completed tail backing without giving it publication authority.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CutIdentityForTest {
    rows: usize,
    count: usize,
    tip: NativeExecutionTip,
    generation: u64,
    root: Hash,
    entries: u64,
    applied_root: Hash,
    applied_entries: u64,
}

#[cfg(test)]
impl CutCapsule {
    pub(crate) fn identity_for_test(&self) -> CutIdentityForTest {
        CutIdentityForTest {
            rows: self.rows.as_slice().as_ptr() as usize,
            count: self.rows.as_slice().len(),
            tip: self.tip,
            generation: self.generation,
            root: self.root,
            entries: self.entries,
            applied_root: self.applied_root,
            applied_entries: self.applied_entries,
        }
    }
}

/// Thread-local real-pool refusal only after actual tail reconstruction succeeds.
#[cfg(test)]
pub(crate) mod completion_observer {
    use super::*;
    use std::cell::RefCell;

    struct Original {
        budget: AllocationBudget,
        held: Option<iroha_allocation::AllocationReservation>,
        completed: usize,
        first: Option<CutIdentityForTest>,
    }
    thread_local! {
        static ORIGINAL: RefCell<Option<Original>> = const { RefCell::new(None) };
    }

    /// Exact native shell size without exposing the private capsule type.
    pub(crate) fn control_bytes() -> usize {
        ChargedShared::<CutCapsule>::allocation_layout().size()
    }

    /// Borrow the observation on the actual synchronous Worker fixture thread.
    pub(crate) struct Observation;
    impl Observation {
        pub(crate) fn snapshot(&self) -> (usize, Option<CutIdentityForTest>) {
            ORIGINAL.with(|slot| {
                let slot = slot.borrow();
                let original = slot.as_ref().expect("original cut observation");
                (original.completed, original.first)
            })
        }
        pub(crate) fn release_original_blocker(&self) {
            let held = ORIGINAL.with(|slot| {
                slot.borrow_mut()
                    .as_mut()
                    .expect("original cut observation")
                    .held
                    .take()
            });
            // Physical publication guards have returned before this actual release.
            drop(held);
        }
    }

    pub(crate) fn observe<R>(
        budget: &AllocationBudget,
        action: impl FnOnce(&Observation) -> R,
    ) -> R {
        struct Restore(Option<Original>);
        impl Drop for Restore {
            fn drop(&mut self) {
                let original = ORIGINAL.with(|slot| slot.replace(self.0.take()));
                drop(original);
            }
        }
        let previous = ORIGINAL.with(|slot| {
            slot.replace(Some(Original {
                budget: budget.clone(),
                held: None,
                completed: 0,
                first: None,
            }))
        });
        let restore = Restore(previous);
        let result = action(&Observation);
        drop(restore);
        result
    }

    pub(super) fn completed(capsule: &CutCapsule) {
        ORIGINAL.with(|slot| {
            let mut slot = slot.borrow_mut();
            let Some(original) = slot.as_mut() else {
                return;
            };
            original.completed += 1;
            if original.first.is_none() {
                original.first = Some(capsule.identity_for_test());
                let remaining = original.budget.limit_bytes() - original.budget.reserved_bytes();
                let leave = ChargedShared::<CutCapsule>::allocation_layout().size() - 1;
                assert!(remaining > leave);
                original.held =
                    Some(original.budget.try_reserve_bytes(remaining - leave).expect(
                        "occupy the actual original pool only at completed tail admission",
                    ));
            }
        });
    }
}
