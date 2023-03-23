//! Translates to Emperor. Consensus-related logic of Iroha.
//!
//! `Consensus` trait is now implemented only by `Sumeragi` for now.
#![allow(
    clippy::arithmetic_side_effects,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc
)]
use std::{
    collections::HashSet,
    fmt::{self, Debug, Formatter},
    sync::{mpsc, Arc},
    time::{Duration, Instant},
};

use eyre::{Result, WrapErr as _};
use iroha_config::sumeragi::Configuration;
use iroha_crypto::{HashOf, KeyPair, SignatureOf};
use iroha_data_model::{block::*, prelude::*};
use iroha_genesis::GenesisNetwork;
use iroha_logger::prelude::*;
use iroha_p2p::{ConnectPeer, DisconnectPeer};
use iroha_telemetry::metrics::Metrics;
use network_topology::{Role, Topology};

use crate::handler::ThreadHandler;

pub mod main_loop;
pub mod message;
pub mod network_topology;
pub mod view_change;

use main_loop::State;
use parking_lot::{Mutex, MutexGuard};

use self::{
    message::{Message, *},
    view_change::{Proof, ProofChain},
};
use crate::{
    block::*, kura::Kura, prelude::*, queue::Queue, tx::TransactionValidator, EventsSender,
    IrohaNetwork, NetworkMessage,
};

/*
The values in the following struct are not atomics because the code that
operates on them assumes their values does not change during the course of
the function.
*/
#[derive(Debug)]
struct LastUpdateMetricsData {
    block_height: u64,
    metric_tx_amounts: f64,
    metric_tx_amounts_counter: u64,
}

/// `Sumeragi` is the implementation of the consensus.
#[derive(Debug)]
pub struct Sumeragi {
    internal: main_loop::Sumeragi,
    config: Configuration,
    metrics: Metrics,
    last_update_metrics_mutex: Mutex<LastUpdateMetricsData>,
    message_sender: mpsc::SyncSender<MessagePacket>,
}

impl Sumeragi {
    /// Construct [`Sumeragi`].
    #[allow(clippy::too_many_arguments, clippy::mutex_integer)]
    pub fn new(
        configuration: &Configuration,
        events_sender: EventsSender,
        wsv: WorldStateView,
        transaction_validator: TransactionValidator,
        queue: Arc<Queue>,
        kura: Arc<Kura>,
        network: IrohaNetwork,
    ) -> Self {
        let (message_sender, message_receiver) = mpsc::sync_channel(100);

        Self {
            internal: main_loop::Sumeragi::new(
                configuration,
                queue,
                events_sender,
                wsv,
                transaction_validator,
                kura,
                network,
                message_receiver,
            ),
            message_sender,
            config: configuration.clone(),
            metrics: Metrics::default(),
            last_update_metrics_mutex: Mutex::new(LastUpdateMetricsData {
                block_height: 0,
                metric_tx_amounts: 0.0_f64,
                metric_tx_amounts_counter: 0,
            }),
        }
    }

    /// Update the metrics on the world state view.
    ///
    /// # Errors
    /// - Domains fail to compose
    ///
    /// # Panics
    /// - If either mutex is poisoned
    #[allow(
        clippy::expect_used,
        clippy::unwrap_in_result,
        clippy::cast_precision_loss,
        clippy::float_arithmetic,
        clippy::mutex_integer
    )]
    pub fn update_metrics(&self) -> Result<()> {
        let online_peers_count: u64 = self
            .internal
            .current_online_peers
            .lock()
            .len()
            .try_into()
            .expect("casting usize to u64");

        let wsv_guard = self.internal.wsv.lock();

        let mut last_guard = self.last_update_metrics_mutex.lock();

        let start_index = last_guard.block_height;
        {
            let mut block_index = start_index;
            while block_index < wsv_guard.height() {
                let Some(block) = self.internal.kura.get_block_by_height(block_index + 1) else {
                    break;
                };
                block_index += 1;
                let block_txs_accepted = block.as_v1().transactions.len() as u64;
                let block_txs_rejected = block.as_v1().rejected_transactions.len() as u64;

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

        self.metrics.domains.set(wsv_guard.domains().len() as u64);

        let diff_count =
            wsv_guard.metric_tx_amounts_counter.get() - last_guard.metric_tx_amounts_counter;
        let diff_amount_per_count = (wsv_guard.metric_tx_amounts.get()
            - last_guard.metric_tx_amounts)
            / (diff_count as f64);
        for _ in 0..diff_count {
            last_guard.metric_tx_amounts_counter += 1;
            last_guard.metric_tx_amounts += diff_amount_per_count;

            self.metrics.tx_amounts.observe(diff_amount_per_count);
        }

        #[allow(clippy::cast_possible_truncation)]
        if let Some(timestamp) = wsv_guard.genesis_timestamp() {
            // this will overflow in 584942417years.
            self.metrics
                .uptime_since_genesis_ms
                .set((current_time().as_millis() - timestamp) as u64)
        };
        let domains = wsv_guard.domains();
        self.metrics.domains.set(domains.len() as u64);
        self.metrics.connected_peers.set(online_peers_count);
        for domain in domains {
            self.metrics
                .accounts
                .get_metric_with_label_values(&[domain.id().name.as_ref()])
                .wrap_err("Failed to compose domains")?
                .set(domain.accounts.len() as u64);
        }

        self.metrics
            .view_changes
            .set(wsv_guard.latest_block_view_change_index());

        self.metrics
            .queue_size
            .set(self.internal.queue.tx_len() as u64);

        Ok(())
    }

    /// Access node metrics.
    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    /// Get a random online peer for use in block synchronization.
    #[allow(clippy::expect_used, clippy::unwrap_in_result)]
    pub fn get_random_peer_for_block_sync(&self) -> Option<Peer> {
        use rand::{seq::IteratorRandom, SeedableRng};

        let rng = &mut rand::rngs::StdRng::from_entropy();
        let peers = self.internal.current_online_peers.lock();
        peers.iter().choose(rng).map(|id| Peer::new(id.clone()))
    }

    /// Access the world state view object in a locking fashion.
    /// If you intend to do anything substantial you should clone
    /// and release the lock. This is because no blocks can be produced
    /// while this lock is held.
    // TODO: Return result.
    #[allow(clippy::expect_used)]
    pub fn wsv_mutex_access(&self) -> MutexGuard<WorldStateView> {
        self.internal.wsv.lock()
    }

    /// Start the sumeragi thread for this sumeragi instance.
    ///
    /// # Panics
    /// - If either mutex is poisoned.
    /// - If topology was built wrong (programmer error)
    /// - Sumeragi thread failed to spawn.
    #[allow(clippy::expect_used)]
    pub fn initialize_and_start_thread(
        sumeragi: Arc<Self>,
        genesis_network: Option<GenesisNetwork>,
        block_hashes: &[HashOf<VersionedCommittedBlock>],
    ) -> ThreadHandler {
        let wsv = sumeragi.wsv_mutex_access().clone();

        for (block_hash, i) in block_hashes
            .iter()
            .take(block_hashes.len().saturating_sub(1))
            .zip(1u64..)
        {
            let block_height: u64 = i;
            let block_ref = sumeragi.internal.kura.get_block_by_height(block_height).expect("Sumeragi could not load block that was reported as present. Please check that the block storage was not disconnected.");
            assert_eq!(
                block_ref.hash(),
                *block_hash,
                "Kura init correctly reported the block hash."
            );

            wsv.apply(&block_ref)
                .expect("Failed to apply block to wsv in init.");
        }
        let finalized_wsv = wsv.clone();

        if !block_hashes.is_empty() {
            let block_ref = sumeragi.internal.kura.get_block_by_height(block_hashes.len() as u64).expect("Sumeragi could not load block that was reported as present. Please check that the block storage was not disconnected.");

            wsv.apply(&block_ref)
                .expect("Failed to apply block to wsv in init.");
        }
        *sumeragi.wsv_mutex_access() = wsv.clone();

        info!("Sumeragi has finished loading blocks and setting up the WSV");

        let latest_block_view_change_index = wsv.latest_block_view_change_index();
        let latest_block_height = wsv.height();
        let latest_block_hash = wsv.latest_block_hash();
        let previous_block_hash = wsv.previous_block_hash();

        let current_topology = if latest_block_height == 0 {
            assert!(!sumeragi.config.trusted_peers.peers.is_empty());
            Topology::new(sumeragi.config.trusted_peers.peers.clone())
        } else {
            let block_ref = sumeragi.internal.kura.get_block_by_height(latest_block_height).expect("Sumeragi could not load block that was reported as present. Please check that the block storage was not disconnected.");
            let mut topology = Topology {
                sorted_peers: block_ref.header().committed_with_topology.clone(),
            };
            topology.rotate_set_a();
            topology
        };

        let sumeragi_state_machine_data = State {
            previous_block_hash,
            latest_block_hash,
            latest_block_height,
            latest_block_view_change_index,
            current_topology,
            wsv,
            finalized_wsv,
            transaction_cache: Vec::new(),
        };

        // Oneshot channel to allow forcefully stopping the thread.
        let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();

        let thread_handle = std::thread::Builder::new()
            .name("sumeragi thread".to_owned())
            .spawn(move || {
                main_loop::run(
                    genesis_network,
                    &sumeragi.internal,
                    sumeragi_state_machine_data,
                    shutdown_receiver,
                );
            })
            .expect("Sumeragi thread spawn should not fail.");

        let shutdown = move || {
            let _result = shutdown_sender.send(());
        };

        ThreadHandler::new(Box::new(shutdown), thread_handle)
    }

    /// Update the sumeragi internal online peers list.
    #[allow(clippy::expect_used)]
    pub fn update_online_peers(&self, online_peers: HashSet<PeerId>) {
        *self.internal.current_online_peers.lock() = online_peers;
    }

    /// Deposit a sumeragi network message.
    #[allow(clippy::expect_used)]
    pub fn incoming_message(&self, msg: MessagePacket) {
        if let Err(error) = self.message_sender.try_send(msg) {
            self.metrics.dropped_messages.inc();
            error!(?error, "This peer is faulty. Incoming messages have to be dropped due to low processing speed.");
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
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct VotingBlock {
    /// At what time has this peer voted for this block
    pub voted_at: Instant,
    /// Valid Block
    pub block: PendingBlock,
}

impl VotingBlock {
    /// Construct new `VotingBlock` with current time.
    #[allow(clippy::expect_used)]
    pub fn new(block: PendingBlock) -> VotingBlock {
        VotingBlock {
            block,
            voted_at: Instant::now(),
        }
    }
    /// Construct new `VotingBlock` with the given time.
    #[allow(clippy::expect_used)]
    pub(crate) fn voted_at(block: PendingBlock, voted_at: Instant) -> VotingBlock {
        VotingBlock { block, voted_at }
    }
}
