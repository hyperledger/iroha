//! Translates to Emperor. Consensus-related logic of Iroha.
//!
//! `Consensus` trait is now implemented only by `Sumeragi` for now.
use std::{
    fmt::{self, Debug, Formatter},
    sync::{mpsc, Arc},
    time::{Duration, Instant},
};

use eyre::{Result, WrapErr as _};
use iroha_config::parameters::actual::{Common as CommonConfig, Sumeragi as SumeragiConfig};
use iroha_crypto::{KeyPair, SignatureOf};
use iroha_data_model::{block::SignedBlock, prelude::*};
use iroha_genesis::GenesisNetwork;
use iroha_logger::prelude::*;
use iroha_telemetry::metrics::Metrics;
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

use parking_lot::Mutex;

use self::{message::*, view_change::ProofChain};
use crate::{kura::Kura, prelude::*, queue::Queue, EventsSender, IrohaNetwork, NetworkMessage};

/*
The values in the following struct are not atomics because the code that
operates on them assumes their values does not change during the course of
the function.
*/
#[derive(Debug)]
struct LastUpdateMetricsData {
    block_height: u64,
}

/// Handle to `Sumeragi` actor
#[derive(Clone)]
pub struct SumeragiHandle {
    state: Arc<State>,
    metrics: Metrics,
    last_update_metrics_mutex: Arc<Mutex<LastUpdateMetricsData>>,
    network: IrohaNetwork,
    kura: Arc<Kura>,
    queue: Arc<Queue>,
    _thread_handle: Arc<ThreadHandler>,
    // Should be dropped after `_thread_handle` to prevent sumeargi thread from panicking
    control_message_sender: mpsc::SyncSender<ControlFlowMessage>,
    message_sender: mpsc::SyncSender<BlockMessage>,
}

impl SumeragiHandle {
    /// Update the metrics on the world state view.
    ///
    /// # Errors
    /// - Domains fail to compose
    ///
    /// # Panics
    /// - If either mutex is poisoned
    #[allow(clippy::cast_precision_loss)]
    pub fn update_metrics(&self) -> Result<()> {
        let online_peers_count: u64 = self
            .network
            .online_peers(
                #[allow(clippy::disallowed_types)]
                std::collections::HashSet::len,
            )
            .try_into()
            .expect("casting usize to u64");

        let state_view = self.state.view();

        let mut last_guard = self.last_update_metrics_mutex.lock();

        let start_index = last_guard.block_height;
        {
            let mut block_index = start_index;
            while block_index < state_view.height() {
                let Some(block) = self.kura.get_block_by_height(block_index + 1) else {
                    break;
                };
                block_index += 1;
                let mut block_txs_accepted = 0;
                let mut block_txs_rejected = 0;
                for tx in block.transactions() {
                    if tx.error.is_none() {
                        block_txs_accepted += 1;
                    } else {
                        block_txs_rejected += 1;
                    }
                }

                self.metrics
                    .txs
                    .with_label_values(&["accepted"])
                    .inc_by(block_txs_accepted);
                self.metrics
                    .txs
                    .with_label_values(&["rejected"])
                    .inc_by(block_txs_rejected);
                self.metrics
                    .txs
                    .with_label_values(&["total"])
                    .inc_by(block_txs_accepted + block_txs_rejected);
                self.metrics.block_height.inc();
            }
            last_guard.block_height = block_index;
        }

        let new_tx_amounts = {
            let mut new_buf = Vec::new();
            core::mem::swap(&mut new_buf, &mut state_view.new_tx_amounts.lock());
            new_buf
        };

        for amount in &new_tx_amounts {
            self.metrics.tx_amounts.observe(*amount);
        }

        #[allow(clippy::cast_possible_truncation)]
        if let Some(timestamp) = state_view.genesis_timestamp() {
            // this will overflow in 584942417years.
            self.metrics.uptime_since_genesis_ms.set(
                (current_time() - timestamp)
                    .as_millis()
                    .try_into()
                    .expect("Timestamp should fit into u64"),
            )
        };

        self.metrics.connected_peers.set(online_peers_count);

        self.metrics
            .domains
            .set(state_view.world.domains.len() as u64);
        for domain in state_view.world.domains() {
            self.metrics
                .accounts
                .get_metric_with_label_values(&[domain.id().name.as_ref()])
                .wrap_err("Failed to compose domains")?
                .set(domain.accounts.len() as u64);
        }

        self.metrics
            .view_changes
            .set(state_view.latest_block_view_change_index());

        self.metrics.queue_size.set(self.queue.tx_len() as u64);

        Ok(())
    }

    /// Access node metrics.
    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    /// Deposit a sumeragi control flow network message.
    pub fn incoming_control_flow_message(&self, msg: ControlFlowMessage) {
        if let Err(error) = self.control_message_sender.try_send(msg) {
            self.metrics.dropped_messages.inc();
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
            self.metrics.dropped_messages.inc();
            error!(
                ?error,
                "This peer is faulty. \
                 Incoming messages have to be dropped due to low processing speed."
            );
        }
    }

    fn replay_block(
        chain_id: &ChainId,
        block: &SignedBlock,
        state_block: &mut StateBlock<'_>,
        mut current_topology: Topology,
    ) -> Topology {
        // NOTE: topology need to be updated up to block's view_change_index
        current_topology.rotate_all_n(block.header().view_change_index);

        let block = ValidBlock::validate(block.clone(), &current_topology, chain_id, state_block)
            .expect("Kura blocks should be valid")
            .commit(&current_topology)
            .expect("Kura blocks should be valid");

        if block.as_ref().header().is_genesis() {
            *state_block.world.trusted_peers_ids = block.as_ref().commit_topology().clone();
        }

        state_block.apply_without_execution(&block).expect(
            "Block application in init should not fail. \
             Blocks loaded from kura assumed to be valid",
        );

        Topology::recreate_topology(
            block.as_ref(),
            0,
            state_block.world.peers().cloned().collect(),
        )
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
        }: SumeragiStartArgs,
    ) -> SumeragiHandle {
        let (control_message_sender, control_message_receiver) = mpsc::sync_channel(100);
        let (message_sender, message_receiver) = mpsc::sync_channel(100);

        let blocks_iter;
        let mut current_topology;

        {
            let state_view = state.view();
            let skip_block_count = state_view.block_hashes.len();
            blocks_iter = (skip_block_count + 1..=block_count).map(|block_height| {
                kura.get_block_by_height(block_height as u64).expect(
                    "Sumeragi should be able to load the block that was reported as presented. \
                    If not, the block storage was probably disconnected.",
                )
            });

            current_topology = match state_view.height() {
                0 => {
                    assert!(!sumeragi_config.trusted_peers.is_empty());
                    Topology::new(sumeragi_config.trusted_peers.clone())
                }
                height => {
                    let block_ref = kura.get_block_by_height(height).expect(
                        "Sumeragi could not load block that was reported as present. \
                        Please check that the block storage was not disconnected.",
                    );
                    Topology::recreate_topology(
                        &block_ref,
                        0,
                        state_view.world.peers_ids().iter().cloned().collect(),
                    )
                }
            };
        }

        for block in blocks_iter {
            let mut state_block = state.block(false);
            current_topology = Self::replay_block(
                &common_config.chain_id,
                &block,
                &mut state_block,
                current_topology,
            );
            state_block.commit();
        }

        info!("Sumeragi has finished loading blocks and setting up the state");

        #[cfg(debug_assertions)]
        let debug_force_soft_fork = sumeragi_config.debug_force_soft_fork;
        #[cfg(not(debug_assertions))]
        let debug_force_soft_fork = false;

        let peer_id = common_config.peer_id();

        let sumeragi = main_loop::Sumeragi {
            chain_id: common_config.chain_id,
            key_pair: common_config.key_pair,
            peer_id,
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
            state,
            network,
            queue,
            kura,
            control_message_sender,
            message_sender,
            metrics: Metrics::default(),
            last_update_metrics_mutex: Arc::new(Mutex::new(LastUpdateMetricsData {
                block_height: 0,
            })),
            _thread_handle: Arc::new(thread_handle),
        }
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
#[non_exhaustive]
pub struct VotingBlock<'state> {
    /// At what time has this peer voted for this block
    pub voted_at: Instant,
    /// Valid Block
    pub block: ValidBlock,
    /// [`WorldState`] after applying transactions to it but before it was committed
    pub state_block: StateBlock<'state>,
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
            voted_at,
            block,
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
    pub genesis_network: Option<GenesisNetwork>,
    pub block_count: BlockCount,
}
