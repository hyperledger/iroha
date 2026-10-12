//! Block commitment and history accumulator (`specs/sccp.md` §3.4, §3.5, §4.5 step 1).
//! Owner: ws30.
//!
//! After all transactions of block `h`, the applied leaf outbox `sccp_block_leaves[(h, ·)]`
//! must hold exactly the indices `0..m`. When `m > 0`, the block root is computed over the
//! stored leaves, `history_leaf(h, root, m)` is appended to the accumulator and
//! `sccp_block_commitments[h]` is written.

use super::{leaves, store};
use crate::{block::BlockValidationError, state::StateTransaction};
use iroha_data_model::sccp::{
    commitment::{SccpBlockCommitmentV1, SccpHistoryStateV1},
    control::SccpLeafRefV1,
    events::{SccpBlockCommittedV1, SccpEvent},
};
use iroha_sccp::v1::{history::HistoryAccumulatorV1, merkle::block_root};

/// Build the execution-invariant error of a malformed block outbox.
fn invariant(message: String) -> BlockValidationError {
    BlockValidationError::ExecutionContextInvalid(format!("SCCP: {message}"))
}

/// Resolve the §3.4 leaf hash that a leaf reference of block `height` names.
fn leaf_hash(
    state_transaction: &StateTransaction<'_, '_>,
    height: u64,
    leaf: &SccpLeafRefV1,
) -> Result<[u8; 32], BlockValidationError> {
    match leaf {
        SccpLeafRefV1::Transfer(transfer) => {
            store::outbound_messages::get(&*state_transaction.world, &transfer.message_id)
                .map(|record| record.leaf)
                .ok_or_else(|| {
                    invariant(format!(
                        "block {height} references an unknown outbound message"
                    ))
                })
        }
        SccpLeafRefV1::Control(control) => store::control_messages::get(
            &*state_transaction.world,
            &(control.network, control.revision, control.control_nonce),
        )
        .map(|record| record.leaf)
        .ok_or_else(|| {
            invariant(format!(
                "block {height} references an unknown control record"
            ))
        }),
    }
}

/// Commit the leaves of block `height`, returning its commitment when it holds any leaf.
///
/// The stored indices must be exactly `0..m`; the §3.4 promote-odd root is taken over the leaf
/// hashes in index order, and `history_leaf(height, root, m)` is appended to the §3.5
/// accumulator. Emits `SccpBlockCommitted`.
///
/// # Errors
///
/// Fails the block on an execution invariant violation: a gap in the leaf indices, a leaf
/// reference without its record, an accumulator that cannot grow, or a malformed stored
/// accumulator.
pub fn commit_block(
    state_transaction: &mut StateTransaction<'_, '_>,
    height: u64,
) -> Result<Option<SccpBlockCommitmentV1>, BlockValidationError> {
    let refs: Vec<(u32, SccpLeafRefV1)> =
        store::block_leaves::range(&*state_transaction.world, (height, 0)..=(height, u32::MAX))
            .map(|((_, index), leaf)| (*index, *leaf))
            .collect();
    if refs.is_empty() {
        return Ok(None);
    }
    for (expected, (index, _)) in refs.iter().enumerate() {
        if usize::try_from(*index).ok() != Some(expected) {
            return Err(invariant(format!(
                "leaf indices of block {height} are not exactly 0..{}",
                refs.len()
            )));
        }
    }
    if refs.len() > usize::try_from(leaves::MAX_LEAVES_PER_BLOCK).unwrap_or(usize::MAX) {
        return Err(invariant(format!("block {height} exceeds the leaf limit")));
    }
    let hashes = refs
        .iter()
        .map(|(_, leaf)| leaf_hash(state_transaction, height, leaf))
        .collect::<Result<Vec<_>, _>>()?;
    let root = block_root(&hashes)
        .map_err(|error| invariant(format!("block root of {height}: {error}")))?;
    let count = u32::try_from(hashes.len())
        .map_err(|_| invariant(format!("block {height} leaf count overflows")))?;

    let stored = store::history::get(&*state_transaction.world).clone();
    let mut accumulator = HistoryAccumulatorV1::from_parts(stored.size, stored.peaks)
        .map_err(|error| invariant(format!("stored history accumulator is malformed: {error}")))?;
    let history_index = accumulator.size();
    let history_leaf = iroha_sccp::v1::hashes::history_leaf(height, &root, count);
    accumulator
        .append(&history_leaf)
        .map_err(|error| invariant(format!("history accumulator cannot grow: {error}")))?;
    let history = SccpHistoryStateV1 {
        size: accumulator.size(),
        peaks: accumulator.peaks().to_vec(),
    };
    let history_size = history.size;
    store::history::set(state_transaction, history);
    store::history_leaves::insert(state_transaction, history_index, (height, history_leaf))
        .map_err(|error| invariant(format!("history leaf of {height}: {error}")))?;
    let commitment = SccpBlockCommitmentV1 {
        root,
        message_count: count,
        history_index,
    };
    store::block_commitments::insert(state_transaction, height, commitment)
        .map_err(|error| invariant(format!("commitment of {height}: {error}")))?;
    state_transaction
        .world
        .emit_events(Some(SccpEvent::BlockCommitted(SccpBlockCommittedV1 {
            height,
            root,
            count,
            history_size,
        })));
    Ok(Some(commitment))
}

/// Return the current history root and size (§3.5); `history_root(0)` is zero.
#[must_use]
pub fn history_root_and_size(
    world: &(impl crate::state::WorldReadOnly + ?Sized),
) -> ([u8; 32], u64) {
    let stored = store::history::get(world);
    if stored.size == 0 {
        return ([0; 32], 0);
    }
    HistoryAccumulatorV1::from_parts(stored.size, stored.peaks.clone())
        .map_or(([0; 32], stored.size), |accumulator| {
            (accumulator.root(), stored.size)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smartcontracts::isi::sccp::test_support::{blank_state, header};
    use iroha_data_model::{bridge::SccpNetworkV1, sccp::control::SccpControlRecordV1};
    use iroha_sccp::v1::{
        hashes::history_leaf, history::history_root, merkle::block_root as reference_root,
    };

    fn control_record(leaf: [u8; 32], index: u32) -> SccpControlRecordV1 {
        SccpControlRecordV1 {
            track: 1,
            parliament_paused: true,
            fast_pause_until_ms: 0,
            height: 5,
            commitment_index: index,
            leaf,
            certificate_id: [9; 32],
            effect_hash: [0x45; 32],
        }
    }

    #[test]
    fn an_empty_block_commits_nothing() {
        let state = blank_state();
        let mut block = state.block(header(5));
        let mut stx = block.transaction();
        assert_eq!(commit_block(&mut stx, 5).unwrap(), None);
        assert!(store::block_commitments::is_empty(&*stx.world));
        assert_eq!(history_root_and_size(&*stx.world), ([0; 32], 0));
    }

    #[test]
    fn control_leaves_commit_root_and_history() {
        let state = blank_state();
        let mut block = state.block(header(5));
        let mut stx = block.transaction();
        let leaves = [[1_u8; 32], [2; 32], [3; 32]];
        for (nonce, leaf) in leaves.iter().enumerate() {
            let nonce = u64::try_from(nonce).expect("small") + 1;
            let index = u32::try_from(nonce - 1).expect("small");
            store::control_messages::insert(
                &mut stx,
                (SccpNetworkV1::EthereumMainnet, 1, nonce),
                control_record(*leaf, index),
            )
            .expect("record");
            store::block_leaves::insert(
                &mut stx,
                (5, index),
                SccpLeafRefV1::control(SccpNetworkV1::EthereumMainnet, 1, nonce),
            )
            .expect("leaf ref");
        }
        let commitment = commit_block(&mut stx, 5)
            .expect("dense leaves commit")
            .expect("three leaves");
        let root = reference_root(&leaves).expect("reference root");
        assert_eq!(commitment.root, root);
        assert_eq!(commitment.message_count, 3);
        assert_eq!(commitment.history_index, 0);
        assert_eq!(
            store::block_commitments::get(&*stx.world, &5),
            Some(&commitment)
        );
        let expected_history = history_root(&[history_leaf(5, &root, 3)]).expect("one leaf");
        assert_eq!(history_root_and_size(&*stx.world), (expected_history, 1));
        assert_eq!(
            store::history_leaves::get(&*stx.world, &0),
            Some(&(5, history_leaf(5, &root, 3)))
        );
    }

    #[test]
    fn a_gap_in_leaf_indices_fails_the_block() {
        let state = blank_state();
        let mut block = state.block(header(5));
        let mut stx = block.transaction();
        store::control_messages::insert(
            &mut stx,
            (SccpNetworkV1::EthereumMainnet, 1, 1),
            control_record([1; 32], 1),
        )
        .expect("record");
        store::block_leaves::insert(
            &mut stx,
            (5, 1),
            SccpLeafRefV1::control(SccpNetworkV1::EthereumMainnet, 1, 1),
        )
        .expect("leaf ref");
        let error = commit_block(&mut stx, 5).expect_err("index 0 is missing");
        assert!(error.to_string().contains("not exactly 0..1"), "{error}");
    }

    #[test]
    fn a_leaf_without_its_record_fails_the_block() {
        let state = blank_state();
        let mut block = state.block(header(5));
        let mut stx = block.transaction();
        store::block_leaves::insert(&mut stx, (5, 0), SccpLeafRefV1::transfer([4; 32]))
            .expect("leaf ref");
        let error = commit_block(&mut stx, 5).expect_err("no outbound record");
        assert!(
            error.to_string().contains("unknown outbound message"),
            "{error}"
        );
    }

    #[test]
    fn history_accumulates_across_blocks() {
        let state = blank_state();
        let mut block = state.block(header(5));
        let mut stx = block.transaction();
        let mut history_leaves = Vec::new();
        for (nonce, height) in [(1_u64, 5_u64), (2, 8), (3, 9)] {
            store::control_messages::insert(
                &mut stx,
                (SccpNetworkV1::BscMainnet, 1, nonce),
                control_record([u8::try_from(nonce).expect("small"); 32], 0),
            )
            .expect("record");
            store::block_leaves::insert(
                &mut stx,
                (height, 0),
                SccpLeafRefV1::control(SccpNetworkV1::BscMainnet, 1, nonce),
            )
            .expect("leaf ref");
            let commitment = commit_block(&mut stx, height)
                .expect("commit")
                .expect("one leaf");
            history_leaves.push(history_leaf(height, &commitment.root, 1));
        }
        let expected = history_root(&history_leaves).expect("root");
        assert_eq!(history_root_and_size(&*stx.world), (expected, 3));
    }
}
