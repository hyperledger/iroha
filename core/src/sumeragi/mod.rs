//! Translates to Emperor. Consensus-related logic of Iroha.
//!
//! `Consensus` trait is now implemented only by `Sumeragi` for now.
#![allow(
    clippy::arithmetic,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc
)]
use std::{
    collections::HashSet,
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
    sync::Arc,
    time::{Duration, Instant},
};

use eyre::{Result, WrapErr as _};
use iroha_actor::{broker::Broker, Addr};
use iroha_config::sumeragi::Configuration;
use iroha_crypto::{HashOf, KeyPair, SignatureOf};
use iroha_data_model::prelude::*;
use iroha_logger::prelude::*;
use iroha_p2p::{ConnectPeer, DisconnectPeer};
use iroha_telemetry::metrics::Metrics;
use network_topology::{Role, Topology};

use crate::{genesis::GenesisNetwork, handler::ThreadHandler};

pub mod main_loop;
pub mod message;
pub mod network_topology;
pub mod view_change;

use main_loop::State;
use parking_lot::{Mutex, MutexGuard};

use self::{
    main_loop::{NoFault, SumeragiWithFault},
    message::{Message, *},
    view_change::{Proof, ProofChain as ViewChangeProofs},
};
use crate::{
    block::VersionedPendingBlock, kura::Kura, prelude::*, queue::Queue, tx::TransactionValidator,
    EventsSender, IrohaNetwork, NetworkMessage,
};

trait Consensus {
    fn round(
        &mut self,
        transactions: Vec<VersionedAcceptedTransaction>,
    ) -> Option<VersionedPendingBlock>;
}

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
    internal: SumeragiWithFault<NoFault>,
    config: Configuration,
    metrics_mutex: Mutex<Metrics>,
    last_update_metrics_mutex: Mutex<LastUpdateMetricsData>,
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
        broker: Broker,
        kura: Arc<Kura>,
        network: Addr<IrohaNetwork>,
    ) -> Self {
        let (incoming_message_sender, incoming_message_receiver) =
            std::sync::mpsc::sync_channel(250);

        Self {
            internal: SumeragiWithFault::<NoFault> {
                key_pair: configuration.key_pair.clone(),
                peer_id: configuration.peer_id.clone(),
                events_sender,
                wsv: Mutex::new(wsv),
                commit_time: Duration::from_millis(configuration.commit_time_limit_ms),
                block_time: Duration::from_millis(configuration.block_time_ms),
                transaction_limits: configuration.transaction_limits,
                transaction_validator,
                queue,
                broker,
                kura,
                network,
                fault_injection: PhantomData,
                gossip_batch_size: configuration.gossip_batch_size,
                gossip_period: Duration::from_millis(configuration.gossip_period_ms),

                current_online_peers: Mutex::new(Vec::new()),
                message_sender: Mutex::new(incoming_message_sender),
                message_receiver: Mutex::new(incoming_message_receiver),
            },
            config: configuration.clone(),
            metrics_mutex: Mutex::new(Metrics::default()),
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

        let metrics_guard = self.metrics_mutex.lock();

        let mut last_guard = self.last_update_metrics_mutex.lock();

        let start_index = last_guard.block_height;
        {
            let mut block_index = start_index;
            while block_index < wsv_guard.height() {
                let block =
                    if let Some(block) = self.internal.kura.get_block_by_height(block_index + 1) {
                        block
                    } else {
                        break;
                    };
                block_index += 1;
                let block_txs_accepted = block.as_v1().transactions.len() as u64;
                let block_txs_rejected = block.as_v1().rejected_transactions.len() as u64;

                metrics_guard
                    .txs
                    .with_label_values(&["accepted"])
                    .inc_by(block_txs_accepted);
                metrics_guard
                    .txs
                    .with_label_values(&["rejected"])
                    .inc_by(block_txs_rejected);
                metrics_guard
                    .txs
                    .with_label_values(&["total"])
                    .inc_by(block_txs_accepted + block_txs_rejected);
                metrics_guard.block_height.inc();
            }
            last_guard.block_height = block_index;
        }

        metrics_guard.domains.set(wsv_guard.domains().len() as u64);

        let diff_count =
            wsv_guard.metric_tx_amounts_counter.get() - last_guard.metric_tx_amounts_counter;
        let diff_amount_per_count = (wsv_guard.metric_tx_amounts.get()
            - last_guard.metric_tx_amounts)
            / (diff_count as f64);
        for _ in 0..diff_count {
            last_guard.metric_tx_amounts_counter += 1;
            last_guard.metric_tx_amounts += diff_amount_per_count;

            metrics_guard.tx_amounts.observe(diff_amount_per_count);
        }

        #[allow(clippy::cast_possible_truncation)]
        if let Some(timestamp) = wsv_guard.genesis_timestamp() {
            // this will overflow in 584942417years.
            metrics_guard
                .uptime_since_genesis_ms
                .set((current_time().as_millis() - timestamp) as u64)
        };
        let domains = wsv_guard.domains();
        metrics_guard.domains.set(domains.len() as u64);
        metrics_guard.connected_peers.set(online_peers_count);
        for domain in domains {
            metrics_guard
                .accounts
                .get_metric_with_label_values(&[domain.id().name.as_ref()])
                .wrap_err("Failed to compose domains")?
                .set(domain.accounts().len() as u64);
        }
        Ok(())
    }

    /// Access node metrics.
    #[allow(clippy::expect_used)]
    pub fn metrics_mutex_access(&self) -> MutexGuard<Metrics> {
        self.metrics_mutex.lock()
    }

    /// Get a random online peer for use in block synchronization.
    #[allow(clippy::expect_used, clippy::unwrap_in_result)]
    pub fn get_random_peer_for_block_sync(&self) -> Option<Peer> {
        use rand::{seq::SliceRandom, SeedableRng};

        let rng = &mut rand::rngs::StdRng::from_entropy();
        let peers = self.internal.current_online_peers.lock();
        peers.choose(rng).map(|id| Peer::new(id.clone()))
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
    ) -> ThreadHandler {
        let wsv = sumeragi.wsv_mutex_access().clone();

        let latest_block_view_change_index = wsv.latest_block_view_change_index();
        let latest_block_height = wsv.height();
        let latest_block_hash = wsv.latest_block_hash();
        let previous_block_hash = wsv.previous_block_hash();

        let current_topology = latest_block_hash.map_or_else(
            || {
                assert!(!sumeragi.config.trusted_peers.peers.is_empty());
                Topology::builder()
                    .with_peers(sumeragi.config.trusted_peers.peers.clone())
                    .build(0)
                    .expect("This builder must have been valid. This is a programmer error.")
            },
            |block_hash| {
                Topology::builder()
                    .at_block(block_hash)
                    .with_peers(wsv.peers().iter().map(|peer| peer.id().clone()).collect())
                    .build(0)
                    .expect("Should be able to reconstruct topology from `wsv`")
            },
        );

        let sumeragi_state_machine_data = State {
            genesis_network,
            previous_block_hash,
            latest_block_hash,
            latest_block_height,
            latest_block_view_change_index,
            current_topology,
            wsv,
            transaction_cache: Vec::new(),
        };

        // Oneshot channel to allow forcefully stopping the thread.
        let (shutdown_sender, shutdown_receiver) = tokio::sync::oneshot::channel();

        let thread_handle = std::thread::Builder::new()
            .name("sumeragi thread".to_owned())
            .spawn(move || {
                main_loop::run(
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
    pub fn update_online_peers(&self, online_peers: Vec<PeerId>) {
        *self.internal.current_online_peers.lock() = online_peers;
    }

    /// Deposit a sumeragi network message.
    #[allow(clippy::expect_used)]
    pub fn incoming_message(&self, msg: MessagePacket) {
        if self.internal.message_sender.lock().try_send(msg).is_err() {
            error!("This peer is faulty. Incoming messages have to be dropped due to low processing speed.");
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
    pub voted_at: Duration,
    /// Valid Block
    pub block: SignedBlock,
}

impl VotingBlock {
    /// Constructs new `VotingBlock.`
    #[allow(clippy::expect_used)]
    pub fn new(block: SignedBlock) -> VotingBlock {
        VotingBlock {
            voted_at: current_time(),
            block,
        }
    }
}
