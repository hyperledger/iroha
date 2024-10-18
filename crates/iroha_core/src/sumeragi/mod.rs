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
use iroha_data_model::{account::AccountId, block::SignedBlock, prelude::*};
use iroha_futures::supervisor::{spawn_os_thread_as_future, Child, OnShutdown, ShutdownSignal};
use iroha_genesis::GenesisBlock;
use iroha_logger::prelude::*;
use network_topology::{Role, Topology};

use crate::{
    block::ValidBlock,
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
    peer_id: PeerId,
    /// Counter for amount of dropped messages by sumeragi
    #[cfg(feature = "telemetry")]
    dropped_messages_metric: iroha_telemetry::metrics::DroppedMessagesCounter,
    // Should be dropped after `_thread_handle` to prevent sumeargi thread from panicking
    control_message_sender: mpsc::SyncSender<ControlFlowMessage>,
    message_sender: mpsc::SyncSender<BlockMessage>,
}

impl SumeragiHandle {
    /// Deposit a sumeragi control flow network message.
    pub fn incoming_control_flow_message(&self, msg: ControlFlowMessage) {
        trace!(ty = "ViewChangeProofChain", "Incoming message");
        if let Err(error) = self.control_message_sender.try_send(msg) {
            #[cfg(feature = "telemetry")]
            self.dropped_messages_metric.inc();

            error!(
                peer_id=%self.peer_id,
                ?error,
                "This peer is faulty. \
                 Incoming control messages have to be dropped due to low processing speed."
            );
        }
    }

    /// Deposit a sumeragi network message.
    pub fn incoming_block_message(&self, msg: impl Into<BlockMessage>) {
        let msg = msg.into();
        let (ty, block) = match &msg {
            BlockMessage::BlockCommitted(BlockCommitted { hash, .. }) => ("BlockCommitted", *hash),
            BlockMessage::BlockCreated(BlockCreated { block }) => ("BlockCreated", block.hash()),
            BlockMessage::BlockSigned(BlockSigned { hash, .. }) => ("BlockSigned", *hash),
            BlockMessage::BlockSyncUpdate(BlockSyncUpdate { block }) => {
                trace!(ty="BlockSyncUpdate", block=%block.hash(), "Incoming message");
                ("BlockSyncUpdate", block.hash())
            }
        };
        trace!(ty, %block, "Incoming message");

        if let Err(error) = self.message_sender.try_send(msg) {
            #[cfg(feature = "telemetry")]
            self.dropped_messages_metric.inc();

            error!(
                peer_id=%self.peer_id,
                ?error,
                "This peer is faulty. \
                 Incoming messages have to be dropped due to low processing speed."
            );
        }
    }

    fn replay_block(
        chain_id: &ChainId,
        genesis_account: &AccountId,
        block: &SignedBlock,
        state_block: &mut StateBlock<'_>,
        events_sender: &EventsSender,
        topology: &mut Topology,
    ) {
        // NOTE: topology need to be updated up to block's view_change_index
        topology.nth_rotation(block.header().view_change_index as usize);

        if block.header().is_genesis() {
            state_block.world.genesis_creation_time_ms = Some(block.header().creation_time_ms);
        }

        let block = ValidBlock::validate(
            block.clone(),
            topology,
            chain_id,
            genesis_account,
            state_block,
        )
        .unpack(|e| {
            let _ = events_sender.send(e.into());
        })
        .expect("INTERNAL BUG: Invalid block stored in Kura")
        .commit(topology)
        .unpack(|e| {
            let _ = events_sender.send(e.into());
        })
        .expect("INTERNAL BUG: Invalid block stored in Kura");

        if block.as_ref().header().is_genesis() {
            *topology = Topology::new(state_block.world.trusted_peers_ids.clone());
        }

        topology.block_committed(state_block.world.peers().cloned());

        state_block
            .apply_without_execution(&block, topology.as_ref().to_owned())
            .into_iter()
            .for_each(|e| {
                let _ = events_sender.send(e);
            });
    }
}

impl SumeragiStartArgs {
    /// Start [`Sumeragi`] actor and return handle to it.
    ///
    /// # Panics
    /// May panic if something is of during initialization which is bug.
    #[allow(clippy::too_many_lines)]
    pub fn start(self, shutdown_signal: ShutdownSignal) -> (SumeragiHandle, Child) {
        let Self {
            sumeragi_config,
            common_config,
            events_sender,
            state,
            queue,
            kura,
            network,
            genesis_network,
            block_count: BlockCount(block_count),
            #[cfg(feature = "telemetry")]
                sumeragi_metrics:
                SumeragiMetrics {
                    view_changes,
                    dropped_messages,
                },
        } = self;

        let (control_message_sender, control_message_receiver) = mpsc::sync_channel(100);
        let (message_sender, message_receiver) = mpsc::sync_channel(100);

        let blocks_iter;
        let mut topology;

        {
            let state_view = state.view();
            let skip_block_count = state_view.height();
            blocks_iter = (skip_block_count + 1..=block_count).map(|block_height| {
                NonZeroUsize::new(block_height).and_then(|height| kura.get_block_by_height(height)).expect(
                    "Sumeragi should be able to load the block that was reported as presented. \
                    If not, the block storage was probably disconnected.",
                )
            });

            topology = match state_view.height() {
                0 => Topology::new(
                    sumeragi_config
                        .trusted_peers
                        .value()
                        .clone()
                        .into_non_empty_vec(),
                ),
                _height => Topology::new(state_view.commit_topology.clone()),
            };
        }

        let genesis_account = AccountId::new(
            iroha_genesis::GENESIS_DOMAIN_ID.clone(),
            genesis_network.public_key.clone(),
        );

        for block in blocks_iter {
            let mut state_block = state.block();
            SumeragiHandle::replay_block(
                &common_config.chain,
                &genesis_account,
                &block,
                &mut state_block,
                &events_sender,
                &mut topology,
            );

            state_block.commit();
        }

        info!("Sumeragi has finished loading blocks and setting up the state");

        #[cfg(debug_assertions)]
        let debug_force_soft_fork = sumeragi_config.debug_force_soft_fork;
        #[cfg(not(debug_assertions))]
        let debug_force_soft_fork = false;

        let peer_id = common_config.peer;
        let sumeragi = main_loop::Sumeragi {
            chain_id: common_config.chain,
            key_pair: common_config.key_pair,
            peer_id: peer_id.clone(),
            queue: Arc::clone(&queue),
            events_sender,
            kura: Arc::clone(&kura),
            network: network.clone(),
            control_message_receiver,
            message_receiver,
            debug_force_soft_fork,
            topology,
            transaction_cache: Vec::new(),
            #[cfg(feature = "telemetry")]
            view_changes_metric: view_changes,
            was_commit: false,
            round_start_time: Instant::now(),
        };

        let child = Child::new(
            tokio::task::spawn(spawn_os_thread_as_future(
                std::thread::Builder::new().name("sumeragi".to_owned()),
                move || {
                    main_loop::run(genesis_network, sumeragi, &shutdown_signal, state);
                },
            )),
            OnShutdown::Wait(Duration::from_secs(5)),
        );

        (
            SumeragiHandle {
                peer_id,
                #[cfg(feature = "telemetry")]
                dropped_messages_metric: dropped_messages,
                control_message_sender,
                message_sender,
            },
            child,
        )
    }
}

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
    fn new(block: ValidBlock, state_block: StateBlock<'_>) -> VotingBlock {
        VotingBlock {
            block,
            voted_at: Instant::now(),
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
    #[cfg(feature = "telemetry")]
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
    pub genesis: Option<GenesisBlock>,
    pub public_key: PublicKey,
}
