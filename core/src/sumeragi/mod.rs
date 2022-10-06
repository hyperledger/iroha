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

use std::sync::Mutex;

use main_loop::State;

use self::{
    main_loop::{NoFault, SumeragiWithFault},
    message::{Message, *},
    view_change::{Proof, ProofChain as ViewChangeProofs},
};
use crate::{
    block::{EmptyChainHash, VersionedPendingBlock},
    kura::Kura,
    prelude::*,
    queue::Queue,
    tx::TransactionValidator,
    EventsSender, IrohaNetwork, NetworkMessage, VersionedValidBlock,
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
                wsv: std::sync::Mutex::new(wsv),
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
                latest_block_hash: Mutex::new(Hash::zeroed().typed()),
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
            .expect("Failed to lock `current_online_peers` for `update_metrics`")
            .len()
            .try_into()
            .expect("casting usize to u64");

        let wsv_guard = self
            .internal
            .wsv
            .lock()
            .expect("Failed to lock on `wsv`. Mutex poisoned");

        let metrics_guard = self
            .metrics_mutex
            .lock()
            .expect("Failed to lock on `metrics`. Mutex poisoned");

        let mut last_guard = self
            .last_update_metrics_mutex
            .lock()
            .expect("Failed to lock on `last_update_metrics`. Mutex poisoned");

        let start_index = last_guard.block_height;
        {
            let blocks_iter = wsv_guard.blocks();
            let blocks_iter =
                blocks_iter.skip(start_index.try_into().expect("Failed to cast to u32."));
            for block in blocks_iter {
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
            last_guard.block_height = wsv_guard.height();
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
    pub fn metrics_mutex_access(&self) -> std::sync::MutexGuard<Metrics> {
        self.metrics_mutex
            .lock()
            .expect("`Mutex` in `metrics_mutex_access` poisoned. This should not happen, given that panics should stop Iroha.")
    }

    /// Get latest block hash for use by the block synchronization subsystem.
    #[allow(clippy::expect_used)]
    pub fn latest_block_hash(&self) -> HashOf<VersionedCommittedBlock> {
        *self
            .internal
            .latest_block_hash
            .lock()
            .expect("Mutex on internal WSV poisoned in `latest_block_hash`")
    }

    /// Get an array of blocks after the block identified by `block_hash`. Returns
    /// an empty array if the specified block could not be found.
    pub fn blocks_after_hash(
        &self,
        block_hash: HashOf<VersionedCommittedBlock>,
    ) -> Vec<VersionedCommittedBlock> {
        self.wsv_mutex_access().blocks_after_hash(block_hash)
    }

    /// Get an array of blocks from `block_height`. (`blocks[block_height]`, `blocks[block_height + 1]` etc.)
    pub fn blocks_from_height(&self, block_height: usize) -> Vec<VersionedCommittedBlock> {
        self.wsv_mutex_access().blocks_from_height(block_height)
    }

    /// Get a random online peer for use in block synchronization.
    #[allow(clippy::expect_used, clippy::unwrap_in_result)]
    pub fn get_random_peer_for_block_sync(&self) -> Option<Peer> {
        use rand::{seq::SliceRandom, SeedableRng};

        let rng = &mut rand::rngs::StdRng::from_entropy();
        let peers = self.internal.current_online_peers.lock().expect(
            "Mutex for `current_online_peers` poisoned in `get_random_peer_for_block_sync`",
        );
        peers.choose(rng).map(|id| Peer::new(id.clone()))
    }

    /// Access the world state view object in a locking fashion.
    /// If you intend to do anything substantial you should clone
    /// and release the lock. This is because no blocks can be produced
    /// while this lock is held.
    // TODO: Return result.
    #[allow(clippy::expect_used)]
    pub fn wsv_mutex_access(&self) -> std::sync::MutexGuard<WorldStateView> {
        self.internal
            .wsv
            .lock()
            .expect("World state view Mutex poisoned. You have had a panic somewhere else in the process, which didn't shut down the peer.")
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

        let latest_block_height = wsv.height();
        let latest_block_hash = wsv.latest_block_hash();

        let current_topology =
            if latest_block_height != 0 && latest_block_hash != Hash::zeroed().typed() {
                Topology::builder()
                    .at_block(latest_block_hash)
                    .with_peers(wsv.peers().iter().map(|peer| peer.id().clone()).collect())
                    .build(0)
                    .expect("Should be able to reconstruct topology from `wsv`")
            } else {
                assert!(!sumeragi.config.trusted_peers.peers.is_empty());
                Topology::builder()
                    .at_block(EmptyChainHash::default().into())
                    .with_peers(sumeragi.config.trusted_peers.peers.clone())
                    .build(0)
                    .expect("This builder must have been valid. This is a programmer error.")
            };

        let sumeragi_state_machine_data = State {
            genesis_network,
            latest_block_hash,
            latest_block_height,
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
        *self
            .internal
            .current_online_peers
            .lock()
            .expect("Failed to lock on update online peers.") = online_peers;
    }

    /// Deposit a sumeragi network message.
    #[allow(clippy::expect_used)]
    pub fn incoming_message(&self, msg: MessagePacket) {
        if self
            .internal
            .message_sender
            .lock()
            .expect("Lock on sender")
            .try_send(msg)
            .is_err()
        {
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
    pub block: VersionedValidBlock,
}

impl VotingBlock {
    /// Constructs new `VotingBlock.`
    #[allow(clippy::expect_used)]
    pub fn new(block: VersionedValidBlock) -> VotingBlock {
        VotingBlock {
            voted_at: current_time(),
            block,
        }
    }
}
