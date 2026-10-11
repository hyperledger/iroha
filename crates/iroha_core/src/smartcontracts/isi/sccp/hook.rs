//! SCCP block hook (`specs/sccp.md` §4.5). Owner: ws30.
//!
//! [`finalize_block`] runs in `ValidBlock::finalize_owned_execution_metadata` after every
//! transaction of block `h` and before the output seal, with the consensus inputs of `h`
//! ([`SccpHeightInputsV1`]): it commits the block's leaves, appends the history leaf and
//! prunes expired light-client records.
//!
//! Block start has no SCCP work: a block exists only for a transaction, never for SCCP.
//!
//! With SCCP absent the hook is a no-op.

use super::{commitment, height::SccpHeightInputsV1, light_clients, params};
use crate::{block::BlockValidationError, state::StateBlock};
use iroha_data_model::block::BlockHeader;

/// Per-block work bound of the pruning step: the most light-client sets and checkpoints one
/// block deletes (§4.11, §4.13.1).
pub const MAX_PRUNE_DELETIONS_PER_BLOCK: usize = 1_024;

/// Run the SCCP post-execution step of block `header` (§4.5).
///
/// `height_inputs` are the authenticated consensus inputs of the block's height: from the
/// Sumeragi core's authenticated schedule on the production and signed-genesis paths. They
/// are `None` only for component fixtures that execute without consensus and for a height
/// whose inputs could not be derived.
///
/// The hook runs in one transaction: it commits the block's leaves and appends the history
/// leaf (§4.5 step 1), then prunes expired light-client sets and checkpoints within the
/// per-block budget (§4.11, §4.13.1).
///
/// TODO: WP-S2: run the rest of §4.5 here, in order: the generation step (G4, G7, G2), the
/// anchor append (A1), the pruning of generation records and anchor chunk roots (§4.11) and
/// the finality header `X_h` (§4.6). They read `height_inputs` and replace the roster rule and
/// the attestation subject of the retired attestation transport; without inputs the header is
/// inactive (fail closed).
///
/// # Errors
///
/// Fails the block on an execution invariant violation (for example non-dense leaf indices)
/// or when local storage refuses the hook's transaction.
pub fn finalize_block(
    state_block: &mut StateBlock<'_>,
    header: &BlockHeader,
    height_inputs: Option<&SccpHeightInputsV1>,
) -> Result<(), BlockValidationError> {
    if !params::exists(&state_block.world) {
        return Ok(());
    }
    #[cfg(test)]
    observed::record(header, height_inputs);
    // TODO: WP-S2: the generation step and the finality header consume the inputs.
    let _ = height_inputs;
    let height = header.height().get();
    let mut stx = state_block
        .try_transaction()
        .map_err(BlockValidationError::StateStorageAdmission)?;
    commitment::commit_block(&mut stx, height)?;
    light_clients::prune(&mut stx, MAX_PRUNE_DELETIONS_PER_BLOCK);
    stx.apply();
    Ok(())
}

/// Test observation of the inputs [`finalize_block`] received on this thread or for one
/// exact proposal executed by a native worker.
#[cfg(test)]
pub(crate) mod observed {
    use super::{BlockHeader, SccpHeightInputsV1};
    use iroha_crypto::HashOf;
    use parking_lot::Mutex;
    use std::{cell::RefCell, collections::BTreeMap, sync::LazyLock};

    type Calls = Vec<(u64, Option<SccpHeightInputsV1>)>;

    static HEADERS: LazyLock<Mutex<BTreeMap<HashOf<BlockHeader>, Calls>>> =
        LazyLock::new(|| Mutex::new(BTreeMap::new()));

    std::thread_local! {
        static CALLS: RefCell<Vec<(u64, Option<SccpHeightInputsV1>)>> =
            const { RefCell::new(Vec::new()) };
    }

    pub(super) fn record(header: &BlockHeader, inputs: Option<&SccpHeightInputsV1>) {
        CALLS.with(|calls| {
            calls
                .borrow_mut()
                .push((header.height().get(), inputs.cloned()));
        });
        if let Some(calls) = HEADERS.lock().get_mut(&header.hash()) {
            calls.push((header.height().get(), inputs.cloned()));
        }
    }

    /// Retain observations for one exact original proposal across execution threads.
    pub(crate) struct HeaderCalls {
        header: HashOf<BlockHeader>,
    }

    impl HeaderCalls {
        /// Take only calls matching the proposal selected when this observer was created.
        pub(crate) fn take(&self) -> Calls {
            core::mem::take(
                HEADERS
                    .lock()
                    .get_mut(&self.header)
                    .expect("original observer"),
            )
        }
    }

    impl Drop for HeaderCalls {
        fn drop(&mut self) {
            HEADERS.lock().remove(&self.header);
        }
    }

    /// Observe a proposal until the returned guard is dropped, including on unwind.
    pub(crate) fn for_header(header: &BlockHeader) -> HeaderCalls {
        let header = header.hash();
        let mut headers = HEADERS.lock();
        let std::collections::btree_map::Entry::Vacant(entry) = headers.entry(header) else {
            panic!("proposal already has an SCCP observer");
        };
        entry.insert(Vec::new());
        HeaderCalls { header }
    }

    /// Take the `(height, inputs)` of every SCCP finalizer call on this thread so far.
    pub(crate) fn take() -> Vec<(u64, Option<SccpHeightInputsV1>)> {
        CALLS.with(|calls| core::mem::take(&mut *calls.borrow_mut()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smartcontracts::isi::sccp::{
        leaves, store,
        test_support::{authority, blank_state, header, peer},
    };
    use iroha_data_model::{
        bridge::SccpNetworkV1,
        sccp::{
            control::{SccpLeafRefV1, SccpTransferLeafRefV1},
            light_client::{
                SccpLcCheckpointDataV1, SccpLcCheckpointOriginV1, SccpLcCheckpointV1, SccpLcHeadV1,
                SccpLcPointV1, SccpLightClientParamsV1, SccpLightClientV1,
            },
            outbound::{SccpOutboundMessageRecordV1, SccpOutboundStatusV1},
            params::SccpParametersV1,
        },
    };

    #[test]
    fn proposal_observer_is_scoped_across_threads_and_releases_on_unwind() {
        let original = header(9_031);
        let foreign = header(9_032);
        let calls = observed::for_header(&original);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                observed::record(&foreign, None);
                observed::record(&original, None);
            });
        });
        assert_eq!(calls.take(), vec![(9_031, None)]);
        assert!(calls.take().is_empty());
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                let _calls = calls;
                panic!("exercise scoped observer retirement");
            }))
            .is_err()
        );
        observed::record(&original, None);
        assert!(observed::for_header(&original).take().is_empty());
        let _ = observed::take();
    }

    #[test]
    fn the_hook_is_a_no_op_without_sccp() {
        let state = blank_state();
        let candidate = header(2);
        let mut block = state.block(candidate);
        let _ = observed::take();
        finalize_block(&mut block, &candidate, None).expect("no-op finalizer");
        assert!(
            observed::take().is_empty(),
            "the finalizer returns before reading inputs without SCCP"
        );
        assert!(store::block_commitments::is_empty(&block.world));
        assert!(block.world.sccp_execution_write_set_bytes().is_empty());
    }

    #[test]
    fn finalize_block_commits_leaves_and_history_only() {
        let state = blank_state();
        let candidate = header(2);
        let mut block = state.block(candidate);
        let message_id = [7; 32];
        {
            let mut stx = block.transaction();
            store::parameters::set(&mut stx, Some(SccpParametersV1::taira_default()));
            let commitment_index = leaves::allocate_leaf(
                &mut stx,
                SccpLeafRefV1::Transfer(SccpTransferLeafRefV1 { message_id }),
            )
            .expect("leaf");
            store::outbound_messages::insert(
                &mut stx,
                message_id,
                SccpOutboundMessageRecordV1 {
                    network: SccpNetworkV1::EthereumMainnet,
                    revision: 1,
                    nonce: 0,
                    height: 2,
                    commitment_index,
                    deadline_ms: 99,
                    sender: authority(1),
                    amount: 1,
                    payload: vec![7],
                    leaf: [8; 32],
                    status: SccpOutboundStatusV1::Recorded,
                },
            )
            .expect("record");
            stx.apply();
        }
        let _ = observed::take();
        let inputs = SccpHeightInputsV1 {
            mode: iroha_data_model::parameter::system::ConsensusMode::Npos,
            height: 2,
            epoch: 0,
            epoch_end_height: 2,
            roster: (1..=4).map(peer).collect(),
            next_roster: Some((1..=4).map(peer).collect()),
        };
        finalize_block(&mut block, &candidate, Some(&inputs)).expect("hook");
        assert_eq!(observed::take(), vec![(2, Some(inputs))]);
        let commitment = store::block_commitments::get(&block.world, &2).expect("commitment");
        assert_eq!((commitment.message_count, commitment.history_index), (1, 0));
        assert_eq!(store::history::get(&block.world).size, 1);
        assert_eq!(store::history_leaves::len(&block.world), 1);
    }

    #[test]
    fn the_hook_prunes_expired_light_client_checkpoints() {
        let state = blank_state();
        let candidate = header(2);
        let mut block = state.block(candidate);
        let network = SccpNetworkV1::EthereumMainnet;
        {
            let mut stx = block.transaction();
            store::parameters::set(&mut stx, Some(SccpParametersV1::taira_default()));
            let mut params = SccpLightClientParamsV1::defaults_for(network).expect("external");
            params.checkpoint_prune_after_ms = 1;
            let light_client = SccpLightClientV1 {
                params,
                head: SccpLcHeadV1 {
                    latest_set_id: 2,
                    latest_finalized: SccpLcPointV1 {
                        source_height: 200,
                        block_hash: [7; 32],
                        source_time_ms: 1,
                    },
                    last_progress_taira_ms: 1,
                },
                frozen: None,
                state_hash: [8; 32],
            };
            store::light_clients::insert(&mut stx, network, light_client).expect("light client");
            for source_height in [120, 150] {
                light_clients::record_checkpoint(
                    &mut stx,
                    network,
                    SccpLcCheckpointV1 {
                        data: SccpLcCheckpointDataV1 {
                            source_height,
                            block_hash: [1; 32],
                            state_root: Some([2; 32]),
                            receipts_or_tx_root: [3; 32],
                            source_time_ms: source_height,
                        },
                        recorded_at_taira_ms: 0,
                        origin: SccpLcCheckpointOriginV1::Advance,
                    },
                )
                .expect("checkpoint");
            }
            stx.apply();
        }
        // Block 2 runs at 8 000 ms, past the retention of checkpoints recorded at 0. The
        // lowest checkpoint of a stride bucket is permanent; the other one is pruned.
        finalize_block(&mut block, &candidate, None).expect("hook");
        let _ = observed::take();
        assert!(store::light_client_checkpoints::contains(
            &block.world,
            &(network, 120)
        ));
        assert!(!store::light_client_checkpoints::contains(
            &block.world,
            &(network, 150)
        ));
    }

    #[test]
    fn block_start_has_no_sccp_work() {
        let state = blank_state();
        {
            let mut parent = state.block(header(1));
            {
                let mut stx = parent.transaction();
                store::parameters::set(&mut stx, Some(SccpParametersV1::taira_default()));
                stx.apply();
            }
            parent
                .commit_world_overlay_for_testing()
                .expect("commit the parent World");
        }
        // SCCP exists in the committed parent, and the block is created long after any
        // committee heartbeat: block start still writes no SCCP state.
        let late = BlockHeader::new(
            std::num::NonZeroU64::new(2).expect("nonzero"),
            None,
            None,
            10 * SccpParametersV1::taira_default().committee_validity_ms,
            0,
        );
        let block = state.block(late);
        assert!(crate::smartcontracts::isi::sccp::params::exists(
            &block.sccp_parent_world_view()
        ));
        assert!(
            block.world.sccp_execution_write_set_bytes().is_empty(),
            "block start has no SCCP work"
        );
    }

    #[test]
    fn a_block_without_leaves_writes_nothing() {
        let state = blank_state();
        let candidate = header(3);
        let mut block = state.block(candidate);
        {
            let mut stx = block.transaction();
            store::parameters::set(&mut stx, Some(SccpParametersV1::taira_default()));
            stx.apply();
        }
        let before = block.world.sccp_execution_write_set_bytes();
        let _ = observed::take();
        finalize_block(&mut block, &candidate, None).expect("no leaves");
        assert_eq!(block.world.sccp_execution_write_set_bytes(), before);
        assert!(store::block_commitments::is_empty(&block.world));
        assert_eq!(observed::take(), vec![(3, None)]);
    }
}
