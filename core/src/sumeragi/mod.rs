//! Translates to Emperor. Consensus-related logic of Iroha.
//!
//! `Consensus` trait is now implemented only by `Sumeragi` for now.
use std::{
    fmt::{self, Debug, Formatter},
    num::NonZeroUsize,
    sync::{mpsc, Arc},
    time::{Duration, Instant},
};

use eyre::Result;
use iroha_config::parameters::actual::{Common as CommonConfig, Sumeragi as SumeragiConfig};
use iroha_crypto::{KeyPair, SignatureOf};
use iroha_data_model::{block::SignedBlock, prelude::*};
use iroha_genesis::GenesisTransaction;
use iroha_logger::prelude::*;
use network_topology::{Role, Topology};

use crate::{
    block::ValidBlock,
    handler::ThreadHandler,
    kura::BlockCount,
    state::{State, StateBlock},
};

pub mod main_loop;
pub mod message;
pub mod network_topology;
pub mod view_change;

use self::{message::*, view_change::ProofChain};
use crate::{kura::Kura, prelude::*, queue::Queue, EventsSender, IrohaNetwork, NetworkMessage};

/// Handle to `Sumeragi` actor
#[derive(Clone)]
pub struct SumeragiHandle {
    /// Counter for amount of dropped messages by sumeragi
    dropped_messages_metric: iroha_telemetry::metrics::DroppedMessagesCounter,
    _thread_handle: Arc<ThreadHandler>,
    // Should be dropped after `_thread_handle` to prevent sumeargi thread from panicking
    control_message_sender: mpsc::SyncSender<ControlFlowMessage>,
    message_sender: mpsc::SyncSender<BlockMessage>,
}

impl SumeragiHandle {
    /// Deposit a sumeragi control flow network message.
    pub fn incoming_control_flow_message(&self, msg: ControlFlowMessage) {
        if let Err(error) = self.control_message_sender.try_send(msg) {
            self.dropped_messages_metric.inc();
            error!(
                ?error,
                "This peer is faulty. \
                 Incoming control messages have to be dropped due to low processing speed."
            );
        }
    }

    /// Deposit a sumeragi network message.
    pub fn incoming_block_message(&self, msg: BlockMessage) {
        if let Err(error) = self.message_sender.try_send(msg) {
            self.dropped_messages_metric.inc();
            error!(
                ?error,
                "This peer is faulty. \
                 Incoming messages have to be dropped due to low processing speed."
            );
        }
    }

    fn replay_block(
        chain_id: &ChainId,
        genesis_public_key: &PublicKey,
        block: &SignedBlock,
        state_block: &mut StateBlock<'_>,
        events_sender: &EventsSender,
        recreate_topology: RecreateTopologyByViewChangeIndex,
    ) -> RecreateTopologyByViewChangeIndex {
        // NOTE: topology need to be updated up to block's view_change_index
        let current_topology = recreate_topology(block.header().view_change_index as usize);

        let block = ValidBlock::validate(
            block.clone(),
            &current_topology,
            chain_id,
            genesis_public_key,
            state_block,
        )
        .unpack(|e| {
            let _ = events_sender.send(e.into());
        })
        .expect("Kura: Invalid block")
        .commit(&current_topology)
        .unpack(|e| {
            let _ = events_sender.send(e.into());
        })
        .expect("Kura: Invalid block");

        if block.as_ref().header().is_genesis() {
            *state_block.world.trusted_peers_ids = block.as_ref().commit_topology().clone();
        }

        state_block
            .apply_without_execution(&block)
            .into_iter()
            .for_each(|e| {
                let _ = events_sender.send(e);
            });

        let peers = state_block.world.peers().cloned().collect();
        Box::new(move |view_change_index| {
            Topology::recreate_topology(block.as_ref(), view_change_index, peers)
        })
    }

    /// Start [`Sumeragi`] actor and return handle to it.
    ///
    /// # Panics
    /// May panic if something is of during initialization which is bug.
    #[allow(clippy::too_many_lines)]
    pub fn start(
        SumeragiStartArgs {
            sumeragi_config,
            common_config,
            events_sender,
            state,
            queue,
            kura,
            network,
            genesis_network,
            block_count: BlockCount(block_count),
            sumeragi_metrics:
                SumeragiMetrics {
                    view_changes,
                    dropped_messages,
                },
        }: SumeragiStartArgs,
    ) -> SumeragiHandle {
        let (control_message_sender, control_message_receiver) = mpsc::sync_channel(100);
        let (message_sender, message_receiver) = mpsc::sync_channel(100);

        let blocks_iter;
        let mut recreate_topology: RecreateTopologyByViewChangeIndex;

        {
            let state_view = state.view();
            let skip_block_count = state_view.block_hashes.len();
            blocks_iter = (skip_block_count + 1..=block_count).map(|block_height| {
                NonZeroUsize::new(block_height).and_then(|height| kura.get_block_by_height(height)).expect(
                    "Sumeragi should be able to load the block that was reported as presented. \
                    If not, the block storage was probably disconnected.",
                )
            });

            recreate_topology = match state_view.height() {
                // View change index of the next block doesn't affect init topology
                0 => {
                    let peers = sumeragi_config
                        .trusted_peers
                        .value()
                        .clone()
                        .into_non_empty_vec();
                    Box::new(move |_view_change_index| Topology::new(peers))
                }
                height => {
                    let block_ref = NonZeroUsize::new(height)
                        .and_then(|height| kura.get_block_by_height(height))
                        .expect(
                            "Sumeragi could not load block that was reported as present. \
                             Please check that the block storage was not disconnected.",
                        );
                    let peers = state_view.world.peers_ids().iter().cloned().collect();
                    Box::new(move |view_change_index| {
                        Topology::recreate_topology(&block_ref, view_change_index, peers)
                    })
                }
            };
        }

        for block in blocks_iter {
            let mut state_block = state.block();
            recreate_topology = Self::replay_block(
                &common_config.chain,
                &genesis_network.public_key,
                &block,
                &mut state_block,
                &events_sender,
                recreate_topology,
            );
            state_block.commit();
        }

        // There is no more blocks so we pick 0 as view change index
        let current_topology = recreate_topology(0);

        info!("Sumeragi has finished loading blocks and setting up the state");

        #[cfg(debug_assertions)]
        let debug_force_soft_fork = sumeragi_config.debug_force_soft_fork;
        #[cfg(not(debug_assertions))]
        let debug_force_soft_fork = false;

        let sumeragi = main_loop::Sumeragi {
            chain_id: common_config.chain,
            key_pair: common_config.key_pair,
            peer_id: common_config.peer,
            queue: Arc::clone(&queue),
            events_sender,
            commit_time: state.view().config.commit_time,
            block_time: state.view().config.block_time,
            max_txs_in_block: state.view().config.max_transactions_in_block.get() as usize,
            kura: Arc::clone(&kura),
            network: network.clone(),
            control_message_receiver,
            message_receiver,
            debug_force_soft_fork,
            current_topology,
            transaction_cache: Vec::new(),
            view_changes_metric: view_changes,
        };

        // Oneshot channel to allow forcefully stopping the thread.
        let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();

        let thread_handle = {
            let state = Arc::clone(&state);
            std::thread::Builder::new()
                .name("sumeragi thread".to_owned())
                .spawn(move || {
                    main_loop::run(genesis_network, sumeragi, shutdown_receiver, state);
                })
                .expect("Sumeragi thread spawn should not fail.")
        };

        let shutdown = move || {
            if let Err(error) = shutdown_sender.send(()) {
                iroha_logger::error!(?error);
            }
        };

        let thread_handle = ThreadHandler::new(Box::new(shutdown), thread_handle);
        SumeragiHandle {
            dropped_messages_metric: dropped_messages,
            control_message_sender,
            message_sender,
            _thread_handle: Arc::new(thread_handle),
        }
    }
}

/// Closure to get topology recreated at certain view change index
type RecreateTopologyByViewChangeIndex = Box<dyn FnOnce(usize) -> Topology>;

/// The interval at which sumeragi checks if there are tx in the
/// `queue`.  And will create a block if is leader and the voting is
/// not already in progress.
pub const TX_RETRIEVAL_INTERVAL: Duration = Duration::from_millis(200);
/// The interval of peers (re/dis)connection.
pub const PEERS_CONNECT_INTERVAL: Duration = Duration::from_secs(1);
/// The interval of telemetry updates.
pub const TELEMETRY_INTERVAL: Duration = Duration::from_secs(5);

/// Structure represents a block that is currently in discussion.
pub struct VotingBlock<'state> {
    /// Valid Block
    block: ValidBlock,
    /// At what time has this peer voted for this block
    pub voted_at: Instant,
    /// [`WorldState`] after applying transactions to it but before it was committed
    pub state_block: StateBlock<'state>,
}

impl AsRef<ValidBlock> for VotingBlock<'_> {
    fn as_ref(&self) -> &ValidBlock {
        &self.block
    }
}

impl VotingBlock<'_> {
    /// Construct new `VotingBlock` with current time.
    pub fn new(block: ValidBlock, state_block: StateBlock<'_>) -> VotingBlock {
        VotingBlock {
            block,
            voted_at: Instant::now(),
            state_block,
        }
    }
    /// Construct new `VotingBlock` with the given time.
    pub(crate) fn voted_at(
        block: ValidBlock,
        state_block: StateBlock<'_>,
        voted_at: Instant,
    ) -> VotingBlock {
        VotingBlock {
            block,
            voted_at,
            state_block,
        }
    }
}

/// Arguments for [`SumeragiHandle::start`] function
#[allow(missing_docs)]
pub struct SumeragiStartArgs {
    pub sumeragi_config: SumeragiConfig,
    pub common_config: CommonConfig,
    pub events_sender: EventsSender,
    pub state: Arc<State>,
    pub queue: Arc<Queue>,
    pub kura: Arc<Kura>,
    pub network: IrohaNetwork,
    pub genesis_network: GenesisWithPubKey,
    pub block_count: BlockCount,
    pub sumeragi_metrics: SumeragiMetrics,
}

/// Relevant sumeragi metrics
pub struct SumeragiMetrics {
    /// Number of view changes in current round
    pub view_changes: iroha_telemetry::metrics::ViewChangesGauge,
    /// Amount of dropped messages by sumeragi
    pub dropped_messages: iroha_telemetry::metrics::DroppedMessagesCounter,
}

/// Optional genesis paired with genesis public key for verification
#[allow(missing_docs)]
pub struct GenesisWithPubKey {
    pub genesis: Option<GenesisTransaction>,
    pub public_key: PublicKey,
}
