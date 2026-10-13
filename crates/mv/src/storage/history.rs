//! Borrowed committed and prior images for validation and derived storage.

use super::{Iter, Storage, StorageMode, StorageReadOnly, View};
use crate::{Key, Value};
use concread::bptree::{BptreeMapReadTxn, Untracked};
use std::{borrow::Borrow, cmp::Ordering, iter::Peekable, marker::PhantomData};

/// Read-only guard over a storage's current state and retained undo history.
///
/// The exclusive source borrow prevents writes while both images are acquired
/// and inspected. Reading history does not begin a block or consume the undo log.
pub struct History<'storage, K: Key, V: Value, M: StorageMode<K, V> = Untracked> {
    current: View<'storage, K, V, M>,
    revert: BptreeMapReadTxn<'storage, K, Option<V>, M>,
    _exclusive: PhantomData<&'storage mut Storage<K, V, M>>,
}

impl<K: Key, V: Value, M: StorageMode<K, V>> Storage<K, V, M> {
    /// Borrow the current image and the state before the latest committed block.
    ///
    /// This operation does not mutate storage. Exclusive access keeps acquisition
    /// of the two read guards coherent and excludes writes for their lifetime.
    pub fn history(&mut self) -> History<'_, K, V, M> {
        let revert = self.revert.read();
        let current = self.view();
        History {
            current,
            revert,
            _exclusive: PhantomData,
        }
    }
}

impl<'storage, K: Key, V: Value, M: StorageMode<K, V>> History<'storage, K, V, M> {
    /// Borrow the committed storage image.
    pub fn current(&self) -> &View<'storage, K, V, M> {
        &self.current
    }

    /// Read a value in the image before the latest committed block.
    pub fn get_before_block<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        match self.revert.get(key) {
            Some(previous) => previous.as_ref(),
            None => self.current.get(key),
        }
    }

    /// Borrow touched keys and their values before the last committed block.
    ///
    /// `None` records prior absence; it is not a missing undo entry. Untouched
    /// keys inherit their current values in the prior image.
    pub fn revert_map(&self) -> &BptreeMapReadTxn<'storage, K, Option<V>, M> {
        &self.revert
    }

    /// Iterate over the prior image in canonical key order without cloning values.
    ///
    /// The iterator merges unchanged current entries with retained prior values;
    /// prior-absence tombstones suppress keys inserted by the latest block.
    pub fn iter_before_block(&self) -> impl Iterator<Item = (&K, &V)> {
        before_block_iter(self.current.iter(), self.revert.iter())
    }
}

impl<K: Key, V: Value> History<'_, K, V> {
    /// Derive another storage while preserving both images and touched-key history.
    ///
    /// Apply the same pure projection to current and retained prior values. `None`
    /// excludes a value from the derived image. Source values remain borrowed;
    /// only destination keys are cloned. The original undo map is never consumed.
    /// Redundant tombstones are retained so no source touch is erased.
    pub fn project<U: Value>(&self, project: impl Fn(&V) -> Option<U>) -> Storage<K, U> {
        let blocks = self
            .current
            .iter()
            .filter_map(|(key, value)| project(value).map(|value| (key.clone(), value)))
            .collect();
        let revert = self
            .revert
            .iter()
            .map(|(key, previous)| (key.clone(), previous.as_ref().and_then(&project)))
            .collect::<concread::bptree::BptreeMap<_, _>>();
        Storage {
            allocation: None,
            publication: crate::publication::Publication::new(),
            revert_released: crate::ReleaseNotification::default(),
            blocks_released: crate::ReleaseNotification::default(),
            revert,
            blocks,
        }
    }
}

/// Merge exact current and undo roots without allocating or cloning retained values.
pub(super) fn before_block_iter<'a, K: Key, V: Value, C>(
    current: Iter<'a, K, V, C>,
    revert: Iter<'a, K, Option<V>, C>,
) -> impl Iterator<Item = (&'a K, &'a V)> {
    BeforeBlockIter {
        current: current.peekable(),
        revert: revert.peekable(),
    }
}

struct BeforeBlockIter<'a, K: Key, V: Value, C> {
    current: Peekable<Iter<'a, K, V, C>>,
    revert: Peekable<Iter<'a, K, Option<V>, C>>,
}

impl<'a, K: Key, V: Value, C> Iterator for BeforeBlockIter<'a, K, V, C> {
    type Item = (&'a K, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match (self.current.peek(), self.revert.peek()) {
                (None, None) => return None,
                (Some(_), None) => return self.current.next(),
                (None, Some(_)) => {}
                (Some((current_key, _)), Some((previous_key, _))) => {
                    match current_key.cmp(previous_key) {
                        Ordering::Less => return self.current.next(),
                        Ordering::Equal => {
                            self.current.next();
                        }
                        Ordering::Greater => {}
                    }
                }
            }
            if let Some((key, Some(value))) = self.revert.next() {
                return Some((key, value));
            }
        }
    }
}

#[cfg(test)]
#[path = "history_tests.rs"]
mod tests;
