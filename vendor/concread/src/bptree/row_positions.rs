//! Immutable original cursor custody and charged finite structural row access.
//!
//! This prerequisite carries no State/MV publication authority. Callers admit
//! exact storage for any retained position index separately. They must keep the
//! original work counter across refusal, then retire index/read handles before
//! thawing the same map owner. No writer or tree clone can escape this gate.
//! MV and Core retain paired current/undo custody and funded position indexes.
//! TODO: complete retained predecessor and semantic stages in StatePublication;
//! this primitive does not complete State capture.

use super::*;
use crate::internals::bptree::positions::{RowPath, NEXT_WORK_BOUND};

/// A local source, structural-geometry or caller-work refusal.
#[derive(Debug, PartialEq, Eq)]
pub enum RowPositionError<E> {
    /// Equal bytes cannot substitute another original cursor allocation.
    ForeignOwner,
    /// A private path is not a finite initialized row in the retained tree.
    InvalidPosition,
    /// Preserve the exact typed caller admission cause without allocating.
    Work(E),
}

/// The original unpublished map, temporarily admitting immutable access only.
///
/// All original next-shell/node/cursor/base/root owners remain in their existing
/// fields and drop order. Thaw requires unique original cursor custody and never
/// copies a cursor or gives another tree publication authority.
pub struct BptreeMapFrozenOwned<K, V, M = Untracked>
where
    K: Ord + Clone + Debug + Sync + Send + 'static,
    V: Clone + Sync + Send + 'static,
    M: MapMode + NodeCloning<K, V>,
{
    owner: BptreeMapOwned<K, V, M>,
}

/// Read-only strong custody of the exact original working cursor and its nodes.
///
/// Handle cloning retains existing charged allocations and allocates nothing.
/// The work drops before its base/root; the original payload always dies before
/// the original charges and shared-node owners that fund/retain it.
pub struct BptreeMapFrozenReader<K, V, M = Untracked>
where
    K: Ord + Clone + Debug + Sync + Send + 'static,
    V: Clone + Sync + Send + 'static,
    M: MapMode + NodeCloning<K, V>,
{
    original: MapRetainedWork<K, V, M>,
}

/// Reference-free row position retaining the original source, not a fingerprint.
/// No key/value clone, fresh identity allocation or raw node pointer is stored.
pub struct BptreeMapRowPosition<K, V, M = Untracked>
where
    K: Ord + Clone + Debug + Sync + Send + 'static,
    V: Clone + Sync + Send + 'static,
    M: MapMode + NodeCloning<K, V>,
{
    original: BptreeMapFrozenReader<K, V, M>,
    path: RowPath,
}

/// Finite ordered structural traversal, retaining completed positions on refusal.
/// The exact caller work admission precedes all node/slot examinations.
pub struct BptreeMapRowPositions<K, V, M = Untracked>
where
    K: Ord + Clone + Debug + Sync + Send + 'static,
    V: Clone + Sync + Send + 'static,
    M: MapMode + NodeCloning<K, V>,
{
    original: BptreeMapFrozenReader<K, V, M>,
    previous: Option<RowPath>,
    remaining: usize,
}

impl<K, V, M> BptreeMapOwned<K, V, M>
where
    K: Ord + Clone + Debug + Sync + Send + 'static,
    V: Clone + Sync + Send + 'static,
    M: MapMode + NodeCloning<K, V>,
{
    /// Move this exact completed original cursor into immutable custody.
    pub fn freeze(self) -> BptreeMapFrozenOwned<K, V, M> {
        BptreeMapFrozenOwned { owner: self }
    }
}

impl<K, V, M> BptreeMapFrozenOwned<K, V, M>
where
    K: Ord + Clone + Debug + Sync + Send + 'static,
    V: Clone + Sync + Send + 'static,
    M: MapMode + NodeCloning<K, V>,
{
    /// Retain actual original work/base/root allocations without new storage.
    pub fn reader(&self) -> BptreeMapFrozenReader<K, V, M> {
        BptreeMapFrozenReader {
            original: self.owner.inner.retain_work(),
        }
    }

    /// Return the same move-only owner only after every frozen reader retires.
    ///
    /// Refusal returns this intact facade. This is caller-owned reader custody,
    /// not a physical mutex wait; the caller must retire its handles before
    /// retrying. Exact target/predecessor checks still apply to reattachment.
    pub fn try_into_owned(mut self) -> Result<BptreeMapOwned<K, V, M>, Self> {
        if self.owner.inner.work_is_unique() {
            Ok(self.owner)
        } else {
            Err(self)
        }
    }
}

impl<K, V, M> Clone for BptreeMapFrozenReader<K, V, M>
where
    K: Ord + Clone + Debug + Sync + Send + 'static,
    V: Clone + Sync + Send + 'static,
    M: MapMode + NodeCloning<K, V>,
{
    fn clone(&self) -> Self {
        Self {
            original: self.original.clone(),
        }
    }
}

impl<K, V, M> Clone for BptreeMapRowPosition<K, V, M>
where
    K: Ord + Clone + Debug + Sync + Send + 'static,
    V: Clone + Sync + Send + 'static,
    M: MapMode + NodeCloning<K, V>,
{
    fn clone(&self) -> Self {
        Self {
            original: self.original.clone(),
            path: self.path,
        }
    }
}

impl<K, V, M> BptreeMapFrozenReader<K, V, M>
where
    K: Ord + Clone + Debug + Sync + Send + 'static,
    V: Clone + Sync + Send + 'static,
    M: MapMode + NodeCloning<K, V>,
{
    /// Compare exact original work/base/root allocations, never their contents.
    pub fn same_original(&self, other: &Self) -> bool {
        self.original.same_work(&other.original)
    }

    /// Create finite traversal state without an identity/storage allocation.
    pub fn positions(&self) -> BptreeMapRowPositions<K, V, M> {
        BptreeMapRowPositions {
            original: self.clone(),
            previous: None,
            remaining: self.original.as_ref().len(),
        }
    }

    /// Resolve an exact-source position with references scoped to this reader.
    ///
    /// Identity and inline depth gates precede work admission. The bound covers
    /// one checked node/slot step for every original branch and the final leaf.
    /// No key comparison, nth rescan, diagnostic allocation or row clone occurs.
    pub fn resolve<E>(
        &self,
        position: &BptreeMapRowPosition<K, V, M>,
        admit: impl FnOnce(usize) -> Result<(), E>,
    ) -> Result<(&K, &V), RowPositionError<E>> {
        if !self.same_original(&position.original) {
            return Err(RowPositionError::ForeignOwner);
        }
        let bound = position
            .path
            .work_bound()
            .ok_or(RowPositionError::InvalidPosition)?;
        admit(bound).map_err(RowPositionError::Work)?;
        self.original
            .as_ref()
            .resolve_row_path(&position.path)
            .ok_or(RowPositionError::InvalidPosition)
    }
}

impl<K, V, M> BptreeMapRowPositions<K, V, M>
where
    K: Ord + Clone + Debug + Sync + Send + 'static,
    V: Clone + Sync + Send + 'static,
    M: MapMode + NodeCloning<K, V>,
{
    /// Admit the finite next-position kernel, preserving progress on refusal.
    ///
    /// The worst case is three original paths of at most usize::BITS + 1 nodes:
    /// follow the prior path, climb its ancestors, descend the next subtree.
    /// This explicit bound covers the real kernel, not an arbitrary row-count
    /// quadratic allowance. Successful caller work is never reset/refunded here.
    pub fn try_next<E>(
        &mut self,
        admit: impl FnOnce(usize) -> Result<(), E>,
    ) -> Result<Option<BptreeMapRowPosition<K, V, M>>, RowPositionError<E>> {
        if self.remaining == 0 {
            return Ok(None);
        }
        admit(NEXT_WORK_BOUND).map_err(RowPositionError::Work)?;
        let path = self
            .original
            .original
            .as_ref()
            .next_row_path(self.previous.as_ref())
            .map_err(|()| RowPositionError::InvalidPosition)?
            .ok_or(RowPositionError::InvalidPosition)?;
        self.previous = Some(path);
        self.remaining -= 1;
        Ok(Some(BptreeMapRowPosition {
            original: self.original.clone(),
            path,
        }))
    }
}

#[cfg(test)]
#[path = "row_position_tests.rs"]
mod tests;
