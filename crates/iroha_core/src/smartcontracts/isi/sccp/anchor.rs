//! A1 records the exact original parent core hash and certified result after execution.
//!
//! Captured native tip custody is independent of G4 and never comes from a decoded claim,
//! Kura lookup or SCCP generation. Every local refusal leaves the enclosing State unapplied.

use super::anchor_owner::{AnchorOwnerError, RetainedSccpAnchorOpen};
use crate::state::{
    NativeExecutionTip, StateReadOnly, StateStorageAdmissionError, StateTransaction, WorldReadOnly,
};
use iroha_allocation::AllocationBudget;
use iroha_data_model::{block::BlockHeader, sccp::committee::SccpAnchorV1};
use iroha_sccp::v1::evidence::{
    ANCHOR_PATH_LEN, SCCP_ANCHOR_CHUNK, anchor_chunk_first_height, anchor_chunk_position,
    anchor_leaf, anchor_node,
};
use mv::storage::StorageReadOnly;

/// Exact local anchor refusal; never a deterministic invalid-block verdict.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SccpAnchorLocalError {
    /// Original finite-pool capacity and its retained release observation.
    #[error(transparent)]
    Admission(iroha_allocation::AllocationRefusal),
    /// Exact prepaid count refused by the allocator.
    #[error("SCCP anchor allocator refused {requested_bytes} prepaid bytes")]
    Allocator {
        /// Original requested byte count.
        requested_bytes: usize,
    },
    /// Captured original source or stored coordinates require local repair/replay.
    #[error("SCCP anchor ownership invariant: {0}")]
    Invariant(&'static str),
}
impl SccpAnchorLocalError {
    /// Preserve a structural owner error as a local source invariant, never peer invalidity.
    pub fn from_owner(error: AnchorOwnerError) -> Self {
        match error {
            AnchorOwnerError::Admission(original) => Self::Admission(original),
            AnchorOwnerError::Allocator { requested_bytes } => Self::Allocator { requested_bytes },
            AnchorOwnerError::Invalid(reason) | AnchorOwnerError::Invariant(reason) => {
                Self::Invariant(reason)
            }
        }
    }
    /// Only genuine releasable capacity exposes an original release wait.
    pub fn release_wait(&self) -> Option<&iroha_allocation::release::ReleaseWait> {
        match self {
            Self::Admission(iroha_allocation::AllocationRefusal::Capacity { release, .. }) => {
                Some(release)
            }
            _ => None,
        }
    }
}

/// A funded append captured before any post-execution mutation.
pub(crate) struct PreparedAnchorStep {
    header: BlockHeader,
    parent: Option<NativeExecutionTip>,
    original: RetainedSccpAnchorOpen,
    next: RetainedSccpAnchorOpen,
    complete: Option<(u64, [u8; 32])>,
}

/// Prepare A1 from the exact original parent tip. Genesis appends nothing.
pub(crate) fn prepare(
    world: &(impl WorldReadOnly + ?Sized),
    header: &BlockHeader,
    parent: Option<NativeExecutionTip>,
    budget: &AllocationBudget,
) -> Result<PreparedAnchorStep, SccpAnchorLocalError> {
    let height = header.height().get();
    let original = world.sccp_anchor_open();
    if !original.belongs_to(budget) {
        return Err(SccpAnchorLocalError::Invariant("foreign open-chunk pool"));
    }
    let (next, complete) = if height == 1 {
        if parent.is_some()
            || header.prev_block_hash().is_some()
            || !original.anchors().is_empty()
            || world.sccp_anchor_chunks().iter().next().is_some()
        {
            return Err(SccpAnchorLocalError::Invariant(
                "nonempty genesis anchor source",
            ));
        }
        (original.clone(), None)
    } else {
        let parent = parent
            .filter(|tip| {
                tip.height().checked_add(1) == Some(height)
                    && header.prev_block_hash() == Some(tip.iroha_hash())
            })
            .ok_or(SccpAnchorLocalError::Invariant(
                "missing original parent native tip",
            ))?;
        let (chunk, position) = anchor_chunk_position(parent.height()).ok_or(
            SccpAnchorLocalError::Invariant("invalid parent anchor height"),
        )?;
        if original.anchors().len() != position || world.sccp_anchor_chunks().get(&chunk).is_some()
        {
            return Err(SccpAnchorLocalError::Invariant(
                "anchor source cut differs from parent position",
            ));
        }
        let appended = original
            .appended(
                SccpAnchorV1 {
                    core_hash: parent.core_hash().0,
                    result: parent.result().0,
                },
                budget,
            )
            .map_err(SccpAnchorLocalError::from_owner)?;
        if position + 1 == SCCP_ANCHOR_CHUNK as usize {
            let root = completed_root(chunk, appended.anchors()).ok_or(
                SccpAnchorLocalError::Invariant("completed anchor chunk shape"),
            )?;
            (RetainedSccpAnchorOpen::empty(budget), Some((chunk, root)))
        } else {
            (appended, None)
        }
    };
    Ok(PreparedAnchorStep {
        header: *header,
        parent,
        original: original.clone(),
        next,
        complete,
    })
}

impl PreparedAnchorStep {
    /// Apply to that same source; caught errors remain sticky on the outer attempt.
    pub(crate) fn apply(
        self,
        state: &mut StateTransaction<'_, '_>,
        budget: &AllocationBudget,
    ) -> Result<(), StateStorageAdmissionError> {
        let source_error = state._curr_block != self.header
            || state.native_execution_tip() != self.parent
            || !state.world.sccp_anchor_open.get().ptr_eq(&self.original)
            || !self.next.belongs_to(budget)
            || self
                .complete
                .is_some_and(|(chunk, _)| state.world.sccp_anchor_chunks.get(&chunk).is_some());
        if source_error {
            let original = StateStorageAdmissionError::SccpAnchor(SccpAnchorLocalError::Invariant(
                "anchor preparation source cut changed",
            ));
            state.arm_local_storage_refusal(original.clone());
            return Err(original);
        }
        if let Some((chunk, root)) = self.complete {
            if let Err((_, original)) = state
                .world
                .sccp_anchor_chunks
                .try_insert_admitted(chunk, root)
            {
                let original = StateStorageAdmissionError::World(original);
                state.arm_local_storage_refusal(original.clone());
                return Err(original);
            }
        }
        *state.world.sccp_anchor_open.get_mut() = self.next;
        Ok(())
    }
}

/// Fixed thirteen-node frontier: no uncharged leaf/level allocation enters A1.
fn completed_root(chunk: u64, anchors: &[SccpAnchorV1]) -> Option<[u8; 32]> {
    if anchors.len() != SCCP_ANCHOR_CHUNK as usize {
        return None;
    }
    let first = anchor_chunk_first_height(chunk)?;
    let mut frontier = [None; ANCHOR_PATH_LEN + 1];
    for (position, anchor) in anchors.iter().enumerate() {
        let mut hash = anchor_leaf(
            first.checked_add(position as u64)?,
            &anchor.core_hash,
            &anchor.result,
        );
        let mut count = position;
        let mut level = 0;
        while count & 1 != 0 {
            hash = anchor_node(&frontier[level].take()?, &hash);
            count >>= 1;
            level += 1;
        }
        frontier[level] = Some(hash);
    }
    frontier[ANCHOR_PATH_LEN]
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_frontier_matches_canonical_complete_tree_and_boundaries() {
        let anchors = (0..SCCP_ANCHOR_CHUNK)
            .map(|i| SccpAnchorV1 {
                core_hash: iroha_crypto::Hash::new(i.to_be_bytes()).into(),
                result: iroha_crypto::sha256(i.to_le_bytes()),
            })
            .collect::<Vec<_>>();
        for chunk in [0, 1, (u64::MAX - SCCP_ANCHOR_CHUNK) / SCCP_ANCHOR_CHUNK] {
            let first = anchor_chunk_first_height(chunk).unwrap();
            let leaves = anchors
                .iter()
                .enumerate()
                .map(|(i, anchor)| anchor_leaf(first + i as u64, &anchor.core_hash, &anchor.result))
                .collect::<Vec<_>>();
            assert_eq!(
                completed_root(chunk, &anchors),
                iroha_sccp::v1::evidence::anchor_chunk_root(&leaves)
            );
        }
        assert!(completed_root(0, &anchors[..4095]).is_none());
        assert!(completed_root(u64::MAX, &anchors).is_none());
        let mut overflow = anchors;
        overflow.push(overflow[0]);
        assert!(completed_root(0, &overflow).is_none());
    }
}
