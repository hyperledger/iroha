//! Immutable dispatch to original executing or frozen private generations.

use super::*;
use mv::storage::StorageReadOnly;
use std::{borrow::Borrow, ops::RangeBounds};

enum ReadPhase<E, F> {
    Executing(E),
    Frozen(F),
}

impl<B: OriginalPublicationBlock> BlockField<B> {
    fn read_phase(&self) -> ReadPhase<&B, &B::Frozen> {
        assert!(!self.released, "field was terminally released");
        match self.phase.as_ref() {
            Some(Phase::Executing(block)) => ReadPhase::Executing(block),
            Some(Phase::Frozen(original)) => ReadPhase::Frozen(original),
            _ => panic!("field is not in a complete readable phase"),
        }
    }
}

// Cell reads borrow the exact same pair in either immutable phase. Storage's
// retained structural positions keep their separate fallible read boundary.
enum CellReadPhase<'read, 'block, V: Value, C: Send + Sync + 'static> {
    Executing(&'read mv::cell::Block<'block, V, C>),
    Frozen(&'read mv::cell::Detached<V, (), C>),
    Reading(&'read mv::cell::FrozenDetached<V, (), C>),
}

impl<'block, V: Value, C: Send + Sync + 'static> CellField<'block, V, C> {
    fn cell_read_phase(&self) -> CellReadPhase<'_, 'block, V, C> {
        assert!(!self.released, "field was terminally released");
        match self.phase.as_ref() {
            Some(Phase::Executing(block)) => CellReadPhase::Executing(block),
            Some(Phase::Frozen(original)) => CellReadPhase::Frozen(original),
            Some(Phase::Reading(original)) => CellReadPhase::Reading(original),
            _ => panic!("field is not in a complete readable phase"),
        }
    }

    /// Borrow exact undo without dereferencing a frozen field as an executing block.
    #[cfg(test)]
    pub(crate) fn original_undo(&self) -> &Option<V> {
        match self.cell_read_phase() {
            CellReadPhase::Executing(block) => block.original_undo(),
            CellReadPhase::Frozen(original) => original.original_undo(),
            CellReadPhase::Reading(original) => original.original_undo(),
        }
    }

    /// Borrow the exact original successor without acquiring a current view.
    pub fn get(&self) -> &V {
        match self.cell_read_phase() {
            CellReadPhase::Executing(block) => block.get(),
            CellReadPhase::Frozen(original) => original.get(),
            CellReadPhase::Reading(original) => original.get(),
        }
    }

    /// Borrow the exact original preimage, including replacement semantics.
    pub fn get_before_block(&self) -> &V {
        match self.cell_read_phase() {
            CellReadPhase::Executing(block) => block.get_before_block(),
            CellReadPhase::Frozen(original) => original.get_before_block(),
            CellReadPhase::Reading(original) => original.get_before_block(),
        }
    }

    /// Whether the original execution touched this value, including equal writes.
    pub fn is_dirty(&self) -> bool {
        match self.cell_read_phase() {
            CellReadPhase::Executing(block) => block.is_dirty(),
            CellReadPhase::Frozen(original) => original.is_dirty(),
            CellReadPhase::Reading(original) => original.is_dirty(),
        }
    }

    /// Borrow the original touched preimage and successor without copying either.
    pub fn touched_value(&self) -> Option<mv::cell::TouchedValue<'_, V>> {
        match self.cell_read_phase() {
            CellReadPhase::Executing(block) => block.touched_value(),
            CellReadPhase::Frozen(original) => original.touched_value(),
            CellReadPhase::Reading(original) => original.touched_value(),
        }
    }

    /// Compare the exact executing or frozen original owner without reacquiring it.
    pub fn belongs_to(&self, target: &mv::cell::Cell<V, C>) -> bool {
        match self.cell_read_phase() {
            CellReadPhase::Executing(block) => block.belongs_to(target),
            CellReadPhase::Frozen(original) => original.belongs_to(target),
            CellReadPhase::Reading(original) => original.belongs_to(target),
        }
    }

    /// Actual original acquisition mode; no new source can replace that cut.
    pub fn mode(&self) -> mv::BlockMode {
        match self.cell_read_phase() {
            CellReadPhase::Executing(block) => block.mode(),
            CellReadPhase::Frozen(original) => original.mode(),
            CellReadPhase::Reading(original) => original.mode(),
        }
    }

    /// Retain the same opaque source/predecessor identity without new allocation.
    pub fn publication_identity(&self) -> mv::BlockPublicationIdentity {
        match self.cell_read_phase() {
            CellReadPhase::Executing(block) => block.publication_identity(),
            CellReadPhase::Frozen(original) => original.publication_identity(),
            CellReadPhase::Reading(original) => original.publication_identity(),
        }
    }
}

/// Inline traversal of either original phase, never an allocated iterator wrapper.
pub enum OriginalReadIter<E, F> {
    /// Traversal borrowing the original executing generation.
    Executing(E),
    /// Traversal borrowing the same generation after its writer is released.
    Frozen(F),
}
impl<E: Iterator, F: Iterator<Item = E::Item>> Iterator for OriginalReadIter<E, F> {
    type Item = E::Item;
    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Executing(iter) => iter.next(),
            Self::Frozen(iter) => iter.next(),
        }
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        match self {
            Self::Executing(iter) => iter.size_hint(),
            Self::Frozen(iter) => iter.size_hint(),
        }
    }
}
impl<E: DoubleEndedIterator, F: DoubleEndedIterator<Item = E::Item>> DoubleEndedIterator
    for OriginalReadIter<E, F>
{
    fn next_back(&mut self) -> Option<Self::Item> {
        match self {
            Self::Executing(iter) => iter.next_back(),
            Self::Frozen(iter) => iter.next_back(),
        }
    }
}
impl<E: ExactSizeIterator, F: ExactSizeIterator<Item = E::Item>> ExactSizeIterator
    for OriginalReadIter<E, F>
{
}

impl<K: Key, V: Value, B> StorageReadOnly<K, V> for BlockField<B>
where
    B: OriginalPublicationBlock + StorageReadOnly<K, V>,
    B::Frozen: StorageReadOnly<K, V>,
{
    type Iter<'a>
        = OriginalReadIter<B::Iter<'a>, <B::Frozen as StorageReadOnly<K, V>>::Iter<'a>>
    where
        Self: 'a;
    type RangeIter<'a>
        = OriginalReadIter<B::RangeIter<'a>, <B::Frozen as StorageReadOnly<K, V>>::RangeIter<'a>>
    where
        Self: 'a;
    fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        match self.read_phase() {
            ReadPhase::Executing(block) => block.get(key),
            ReadPhase::Frozen(original) => original.get(key),
        }
    }
    fn get_key_value(&self, key: &K) -> Option<(&K, &V)> {
        match self.read_phase() {
            ReadPhase::Executing(block) => block.get_key_value(key),
            ReadPhase::Frozen(original) => original.get_key_value(key),
        }
    }
    fn iter(&self) -> Self::Iter<'_> {
        match self.read_phase() {
            ReadPhase::Executing(block) => OriginalReadIter::Executing(block.iter()),
            ReadPhase::Frozen(original) => OriginalReadIter::Frozen(original.iter()),
        }
    }
    fn range<Q>(&self, bounds: impl RangeBounds<Q>) -> Self::RangeIter<'_>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        match self.read_phase() {
            ReadPhase::Executing(block) => OriginalReadIter::Executing(block.range(bounds)),
            ReadPhase::Frozen(original) => OriginalReadIter::Frozen(original.range(bounds)),
        }
    }
    fn first_key_value(&self) -> Option<(&K, &V)> {
        match self.read_phase() {
            ReadPhase::Executing(block) => block.first_key_value(),
            ReadPhase::Frozen(original) => original.first_key_value(),
        }
    }
    fn last_key_value(&self) -> Option<(&K, &V)> {
        match self.read_phase() {
            ReadPhase::Executing(block) => block.last_key_value(),
            ReadPhase::Frozen(original) => original.last_key_value(),
        }
    }
    fn len(&self) -> usize {
        match self.read_phase() {
            ReadPhase::Executing(block) => block.len(),
            ReadPhase::Frozen(original) => original.len(),
        }
    }
}

impl<K: Key, V: Value, M: mv::storage::StorageMode<K, V>> StorageField<'_, K, V, M> {
    /// Borrow original undo rows without acquiring a view or reopening execution.
    #[cfg(test)]
    pub(crate) fn original_undo_entries(&self) -> impl Iterator<Item = (&K, &Option<V>)> {
        match self.read_phase() {
            ReadPhase::Executing(block) => OriginalReadIter::Executing(block.revert_map().iter()),
            ReadPhase::Frozen(original) => {
                OriginalReadIter::Frozen(original.original_undo_entries())
            }
        }
    }

    /// Borrow the original preimage; absent original entries stay absent.
    pub fn get_before_block(&self, key: &K) -> Option<&V> {
        match self.read_phase() {
            ReadPhase::Executing(block) => block.get_before_block(key),
            ReadPhase::Frozen(original) => original.get_before_block(key),
        }
    }

    /// Original touched entries, retaining no-op writes and deletions in order.
    pub fn touched_entries(
        &self,
    ) -> impl DoubleEndedIterator<Item = mv::storage::TouchedEntry<'_, K, V>> + ExactSizeIterator
    {
        match self.read_phase() {
            ReadPhase::Executing(block) => OriginalReadIter::Executing(block.touched_entries()),
            ReadPhase::Frozen(original) => OriginalReadIter::Frozen(original.touched_entries()),
        }
    }

    /// Whether this original execution requires current-map publication.
    pub fn is_dirty(&self) -> bool {
        match self.read_phase() {
            ReadPhase::Executing(block) => block.is_dirty(),
            ReadPhase::Frozen(original) => original.is_dirty(),
        }
    }

    /// Actual original acquisition mode, including a replacement's original cut.
    pub fn mode(&self) -> mv::BlockMode {
        match self.read_phase() {
            ReadPhase::Executing(block) => block.mode(),
            ReadPhase::Frozen(original) => original.mode(),
        }
    }

    /// Retain exact original owner/predecessor identity, not refreshed State.
    pub fn publication_identity(&self) -> mv::BlockPublicationIdentity {
        match self.read_phase() {
            ReadPhase::Executing(block) => block.publication_identity(),
            ReadPhase::Frozen(original) => original.publication_identity(),
        }
    }
}

impl<B> json::JsonSerialize for BlockField<B>
where
    B: OriginalPublicationBlock + json::JsonSerialize,
    B::Frozen: json::JsonSerialize,
{
    fn json_serialize(&self, out: &mut String) {
        match self.read_phase() {
            ReadPhase::Executing(block) => block.json_serialize(out),
            ReadPhase::Frozen(original) => original.json_serialize(out),
        }
    }

    fn json_serialize_to(
        &self,
        out: &mut dyn json::JsonWriteSink,
    ) -> Result<(), json::BoundedJsonError> {
        match self.read_phase() {
            ReadPhase::Executing(block) => block.json_serialize_to(out),
            ReadPhase::Frozen(original) => original.json_serialize_to(out),
        }
    }
}
