//! Original native consensus anchors and bounded chunk lookup (`specs/sccp.md` §4.2.1).
//!
//! An anchor retains the Sumeragi core hash and certified result. An Iroha header hash is
//! never substituted for either field. Appending the parent happens after transactions,
//! so admission and execution see the same parent-state chunk boundary.

use iroha_sccp::v1::evidence::{
    ANCHOR_PATH_LEN, SCCP_ANCHOR_CHUNK, anchor_chunk_position, anchor_leaf, verify_anchor_path,
};
use iroha_schema::IntoSchema;
use norito::{
    codec::{Decode, Encode},
    json::{JsonDeserialize, JsonSerialize},
};

/// The original consensus block identity and result at one committed height.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    Decode,
    Encode,
    IntoSchema,
    JsonSerialize,
    JsonDeserialize,
)]
#[norito(deny_unknown_fields)]
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::smartcontracts::isi::sccp::anchors::SccpAnchorV1")]
pub struct SccpAnchorV1 {
    /// Exact Sumeragi core block hash signed by the CommitQC.
    pub core_hash: [u8; 32],
    /// Exact certified execution result signed by the same CommitQC.
    pub result: [u8; 32],
}

/// Why an anchor cannot be recovered from the exact parent state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SccpAnchorLookupError {
    /// The height is zero, after the parent, or inconsistent with the parent-state layout.
    InvalidHeight,
    /// A completed chunk needs the caller's original anchor and 12 sibling hashes.
    WitnessRequired,
    /// The witness does not reach the retained chunk root.
    BadWitness,
    /// The completed chunk root has been pruned.
    EvidenceExpired,
}

/// Recover an anchor from the parent tip, the open chunk, or a retained completed root.
///
/// `parent_height` and `parent_anchor` come from the authenticated native execution tip.
/// `completed_root` is the stored root for the queried height's chunk, if retained; it is
/// consulted only for completed chunks. Supplying a witness never overrides a tip or open
/// anchor. There is no fallback from an unavailable root to unauthenticated witness bytes.
///
/// # Errors
///
/// Returns the precise height, retention or witness refusal above.
pub fn lookup_anchor(
    parent_height: u64,
    parent_anchor: SccpAnchorV1,
    open: &[SccpAnchorV1],
    height: u64,
    completed_root: Option<&[u8; 32]>,
    witness: Option<(&SccpAnchorV1, &[[u8; 32]; ANCHOR_PATH_LEN])>,
) -> Result<SccpAnchorV1, SccpAnchorLookupError> {
    let (chunk, position) = anchor_chunk_position(height)
        .filter(|_| height <= parent_height)
        .ok_or(SccpAnchorLookupError::InvalidHeight)?;
    // At the parent tip, A1 has appended only heights through parent_height - 1.
    let (open_chunk, expected_open_len) =
        anchor_chunk_position(parent_height).ok_or(SccpAnchorLookupError::InvalidHeight)?;
    if open.len() != expected_open_len || open.len() >= SCCP_ANCHOR_CHUNK as usize {
        return Err(SccpAnchorLookupError::InvalidHeight);
    }
    if height == parent_height {
        return Ok(parent_anchor);
    }
    if chunk == open_chunk {
        return open
            .get(position)
            .copied()
            .ok_or(SccpAnchorLookupError::InvalidHeight);
    }
    let root = completed_root.ok_or(SccpAnchorLookupError::EvidenceExpired)?;
    let (anchor, path) = witness.ok_or(SccpAnchorLookupError::WitnessRequired)?;
    let leaf = anchor_leaf(height, &anchor.core_hash, &anchor.result);
    if !verify_anchor_path(&leaf, position, path, root) {
        return Err(SccpAnchorLookupError::BadWitness);
    }
    Ok(*anchor)
}

/// Append only the authenticated parent's original anchor after this block's transactions.
///
/// Returns `false` for inconsistent SCCP bookkeeping, without inventing an anchor or
/// changing an existing completed root. Resource refusal remains a local execution
/// deferral. The newly completed chunk and cleared open chunk publish in one transaction.
///
/// # Errors
///
/// Fails when the local allocator or storage cannot retain the append.
pub fn append_parent(
    stx: &mut crate::state::StateTransaction<'_, '_>,
    height: u64,
    parent: Option<crate::state::NativeExecutionTip>,
) -> Result<bool, crate::block::BlockValidationError> {
    if height == 1 {
        return Ok(true);
    }
    let Some(parent) = parent.filter(|parent| parent.height().checked_add(1) == Some(height))
    else {
        return Ok(false);
    };
    append_original_anchor(
        stx,
        parent.height(),
        SccpAnchorV1 {
            core_hash: parent.core_hash().0,
            result: parent.result().0,
        },
    )
}

// Only append_parent may project an authenticated tip into this private operation. Keeping
// the append separate permits boundary DATA tests without fabricating a NativeExecutionTip.
fn append_original_anchor(
    stx: &mut crate::state::StateTransaction<'_, '_>,
    parent_height: u64,
    original: SccpAnchorV1,
) -> Result<bool, crate::block::BlockValidationError> {
    use super::store;
    use crate::block::BlockValidationError;
    use iroha_sccp::v1::evidence::anchor_node;
    let Some((chunk, position)) = anchor_chunk_position(parent_height) else {
        return Ok(false);
    };
    let old = store::anchor_open::get(&*stx.world);
    if old.len() != position || store::anchor_chunks::contains(&*stx.world, &chunk) {
        return Ok(false);
    }
    let mut open = Vec::new();
    reserve_append_buffer(&mut open, old.len() + 1)?;
    open.extend_from_slice(old);
    open.push(original);
    let completed = if open.len() == SCCP_ANCHOR_CHUNK as usize {
        let mut level = Vec::new();
        reserve_append_buffer(&mut level, open.len())?;
        let first = parent_height - (SCCP_ANCHOR_CHUNK - 1);
        for (offset, anchor) in open.iter().enumerate() {
            level.push(anchor_leaf(
                first + offset as u64,
                &anchor.core_hash,
                &anchor.result,
            ));
        }
        while level.len() > 1 {
            for index in 0..level.len() / 2 {
                level[index] = anchor_node(&level[2 * index], &level[2 * index + 1]);
            }
            level.truncate(level.len() / 2);
        }
        open.clear();
        level.first().copied()
    } else {
        None
    };
    // These are the same validated bounds as store::anchor_open::set. Retain the local
    // invariant error as a deferral rather than a verdict on the signed block.
    store::anchor_open::set(stx, open).map_err(|_| {
        BlockValidationError::ExecutionDeferred(
            ivm::error::ExecutionDeferral::LocalInvariantViolation.into(),
        )
    })?;
    if let Some(root) = completed {
        store::anchor_chunks::insert(stx, chunk, root).map_err(|_| {
            BlockValidationError::ExecutionDeferred(
                ivm::error::ExecutionDeferral::LocalInvariantViolation.into(),
            )
        })?;
    }
    Ok(true)
}

// Both bounded append allocations complete before any child-World write.
fn reserve_append_buffer<T>(
    buffer: &mut Vec<T>,
    additional: usize,
) -> Result<(), crate::block::BlockValidationError> {
    let refused = || {
        crate::block::BlockValidationError::ExecutionDeferred(
            ivm::error::ExecutionDeferral::AllocationUnavailable.into(),
        )
    };
    #[cfg(test)]
    if append_allocation_refusal::refuse_next() {
        return Err(refused());
    }
    buffer.try_reserve_exact(additional).map_err(|_| refused())
}

#[cfg(test)]
mod append_allocation_refusal {
    std::thread_local! {
        static REMAINING: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
    }

    pub(super) fn refuse_next() -> bool {
        REMAINING.with(|remaining| match remaining.get() {
            Some(0) => true,
            Some(count) => {
                remaining.set(Some(count - 1));
                false
            }
            None => false,
        })
    }

    pub(super) fn after<T>(successful_reservations: usize, f: impl FnOnce() -> T) -> T {
        struct Restore(Option<usize>);
        impl Drop for Restore {
            fn drop(&mut self) {
                REMAINING.with(|remaining| remaining.set(self.0));
            }
        }
        let _restore =
            Restore(REMAINING.with(|remaining| remaining.replace(Some(successful_reservations))));
        f()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_sccp::v1::evidence::{anchor_chunk_path, anchor_chunk_root};

    fn anchor(seed: u8) -> SccpAnchorV1 {
        SccpAnchorV1 {
            core_hash: [seed; 32],
            result: [seed.wrapping_add(1); 32],
        }
    }

    #[test]
    fn anchor_roundtrip_preserves_both_original_native_identities() {
        let original = anchor(7);
        let frame = norito::to_bytes(&original).unwrap();
        let decoded = norito::decode_from_bytes::<SccpAnchorV1>(&frame).unwrap();
        assert_eq!(decoded.core_hash, [7; 32]);
        assert_eq!(decoded.result, [8; 32]);
        let json = norito::json::to_json(&original).unwrap();
        assert_eq!(
            norito::json::from_json::<SccpAnchorV1>(&json).unwrap(),
            original
        );
    }

    #[test]
    fn tip_and_open_chunk_use_only_the_original_parent_state() {
        let open = [anchor(1), anchor(2)];
        let fake = anchor(9);
        let witness = Some((&fake, &[[0; 32]; ANCHOR_PATH_LEN]));
        assert_eq!(
            lookup_anchor(3, anchor(3), &open, 3, None, witness),
            Ok(anchor(3))
        );
        assert_eq!(
            lookup_anchor(3, anchor(3), &open, 1, None, witness),
            Ok(anchor(1))
        );
        assert_eq!(
            lookup_anchor(3, anchor(3), &open, 0, None, None),
            Err(SccpAnchorLookupError::InvalidHeight)
        );
        assert_eq!(
            lookup_anchor(3, anchor(3), &open, 4, None, None),
            Err(SccpAnchorLookupError::InvalidHeight)
        );
    }

    #[test]
    fn incomplete_open_state_never_relabels_missing_anchors_as_absent() {
        assert_eq!(
            lookup_anchor(3, anchor(3), &[anchor(1)], 1, None, None),
            Err(SccpAnchorLookupError::InvalidHeight)
        );
    }

    #[test]
    fn completed_chunk_requires_a_retained_root_and_exact_path() {
        let original = anchor(7);
        let leaves = (1..=SCCP_ANCHOR_CHUNK)
            .map(|height| anchor_leaf(height, &original.core_hash, &original.result))
            .collect::<Vec<_>>();
        let root = anchor_chunk_root(&leaves).unwrap();
        let path = anchor_chunk_path(&leaves, 0).unwrap();
        let parent_height = SCCP_ANCHOR_CHUNK + 1;
        assert_eq!(
            lookup_anchor(
                parent_height,
                anchor(8),
                &[],
                1,
                Some(&root),
                Some((&original, &path))
            ),
            Ok(original)
        );
        assert_eq!(
            lookup_anchor(
                parent_height,
                anchor(8),
                &[],
                1,
                None,
                Some((&original, &path))
            ),
            Err(SccpAnchorLookupError::EvidenceExpired)
        );
        assert_eq!(
            lookup_anchor(parent_height, anchor(8), &[], 1, Some(&root), None),
            Err(SccpAnchorLookupError::WitnessRequired)
        );
        let mut changed = original;
        changed.result[0] ^= 1;
        assert_eq!(
            lookup_anchor(
                parent_height,
                anchor(8),
                &[],
                1,
                Some(&root),
                Some((&changed, &path))
            ),
            Err(SccpAnchorLookupError::BadWitness)
        );
        assert_eq!(
            lookup_anchor(
                parent_height,
                anchor(8),
                &[],
                2,
                Some(&root),
                Some((&original, &path))
            ),
            Err(SccpAnchorLookupError::BadWitness)
        );
        let mut changed_path = path;
        changed_path[11][0] ^= 1;
        assert_eq!(
            lookup_anchor(
                parent_height,
                anchor(8),
                &[],
                1,
                Some(&root),
                Some((&original, &changed_path))
            ),
            Err(SccpAnchorLookupError::BadWitness)
        );
    }

    #[test]
    fn last_height_of_open_chunk_stays_the_tip_until_the_next_append() {
        let open = vec![anchor(1); SCCP_ANCHOR_CHUNK as usize - 1];
        assert_eq!(
            lookup_anchor(
                SCCP_ANCHOR_CHUNK,
                anchor(2),
                &open,
                SCCP_ANCHOR_CHUNK,
                None,
                None
            ),
            Ok(anchor(2))
        );
        assert_eq!(
            lookup_anchor(
                SCCP_ANCHOR_CHUNK,
                anchor(2),
                &open,
                SCCP_ANCHOR_CHUNK - 1,
                None,
                None
            ),
            Ok(anchor(1))
        );
    }

    fn snapshot(
        stx: &crate::state::StateTransaction<'_, '_>,
    ) -> (Vec<SccpAnchorV1>, Vec<(u64, [u8; 32])>) {
        use crate::smartcontracts::isi::sccp::store;
        (
            store::anchor_open::get(&*stx.world).clone(),
            store::anchor_chunks::iter(&*stx.world)
                .map(|(key, value)| (*key, *value))
                .collect(),
        )
    }

    #[test]
    fn append_uses_the_exact_original_certified_tip_and_refuses_wrong_height() {
        use crate::{
            smartcontracts::isi::sccp::{
                store,
                test_support::{blank_state, header},
            },
            state::{StateReadOnly, World},
            sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
        };
        // The tip comes from the original signed/executed genesis, never a DATA constructor.
        let chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000)).unwrap();
        let tip = chain.state().view().native_execution_tip().unwrap();
        assert_eq!(tip.height(), 1);
        let state = blank_state();
        let mut block = state.block(header(2));
        let mut stx = block.transaction();
        let before = snapshot(&stx);
        assert!(!append_parent(&mut stx, 3, Some(tip)).unwrap());
        assert!(!append_parent(&mut stx, 2, None).unwrap());
        assert_eq!(snapshot(&stx), before);
        assert!(append_parent(&mut stx, 2, Some(tip)).unwrap());
        assert_eq!(
            store::anchor_open::get(&*stx.world),
            &vec![SccpAnchorV1 {
                core_hash: tip.core_hash().0,
                result: tip.result().0,
            }]
        );
        let appended = snapshot(&stx);
        assert!(
            !append_parent(&mut stx, 2, Some(tip)).unwrap(),
            "the same parent cannot append twice"
        );
        assert_eq!(snapshot(&stx), appended);
        drop(stx);
        assert!(
            store::anchor_open::get(&block.world).is_empty(),
            "unapplied child leaves its parent unchanged"
        );
    }

    #[test]
    fn append_completes_the_exact_chunk_and_starts_the_next_atomically() {
        use crate::smartcontracts::isi::sccp::{
            store,
            test_support::{blank_state, header},
        };
        let state = blank_state();
        let mut block = state.block(header(SCCP_ANCHOR_CHUNK + 1));
        let mut stx = block.transaction();
        // Boundary DATA exercises the actual append routine; it grants no tip authority.
        let original = anchor(7);
        let open = vec![original; SCCP_ANCHOR_CHUNK as usize - 1];
        store::anchor_open::set(&mut stx, open).unwrap();
        let leaves = (1..=SCCP_ANCHOR_CHUNK)
            .map(|height| anchor_leaf(height, &original.core_hash, &original.result))
            .collect::<Vec<_>>();
        let expected = anchor_chunk_root(&leaves).unwrap();
        assert!(append_original_anchor(&mut stx, SCCP_ANCHOR_CHUNK, original).unwrap());
        assert!(store::anchor_open::get(&*stx.world).is_empty());
        assert_eq!(store::anchor_chunks::get(&*stx.world, &0), Some(&expected));
        assert_eq!(store::anchor_chunks::len(&*stx.world), 1);
        assert!(append_original_anchor(&mut stx, SCCP_ANCHOR_CHUNK + 1, anchor(8)).unwrap());
        assert_eq!(store::anchor_open::get(&*stx.world), &vec![anchor(8)]);
        assert_eq!(store::anchor_chunks::get(&*stx.world, &0), Some(&expected));
        stx.apply();
        assert_eq!(store::anchor_open::get(&block.world), &vec![anchor(8)]);
        assert_eq!(store::anchor_chunks::get(&block.world, &0), Some(&expected));
    }

    #[test]
    fn append_refusals_and_each_allocation_refusal_leave_the_child_unchanged() {
        use crate::{
            block::BlockValidationError,
            smartcontracts::isi::sccp::{
                store,
                test_support::{blank_state, header},
            },
        };
        let state = blank_state();
        let mut block = state.block(header(SCCP_ANCHOR_CHUNK + 1));
        let mut stx = block.transaction();
        let original = anchor(7);
        store::anchor_open::set(&mut stx, vec![original; SCCP_ANCHOR_CHUNK as usize - 1]).unwrap();
        let before = snapshot(&stx);
        for completed_reservations in [0, 1] {
            let error = append_allocation_refusal::after(completed_reservations, || {
                append_original_anchor(&mut stx, SCCP_ANCHOR_CHUNK, original)
            })
            .expect_err("append allocation refused locally");
            assert!(matches!(error, BlockValidationError::ExecutionDeferred(_)));
            assert_eq!(snapshot(&stx), before);
        }
        assert!(!append_original_anchor(&mut stx, SCCP_ANCHOR_CHUNK - 1, original).unwrap());
        assert_eq!(
            snapshot(&stx),
            before,
            "wrong open position leaves both stores intact"
        );
        store::anchor_chunks::insert(&mut stx, 0, [0xAA; 32]).unwrap();
        let occupied = snapshot(&stx);
        assert!(!append_original_anchor(&mut stx, SCCP_ANCHOR_CHUNK, original).unwrap());
        assert_eq!(
            snapshot(&stx),
            occupied,
            "a present root must never be overwritten"
        );
        drop(stx);
        assert!(store::anchor_open::get(&block.world).is_empty());
        assert!(store::anchor_chunks::is_empty(&block.world));
    }
}
