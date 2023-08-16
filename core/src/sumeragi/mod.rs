//! Translates to Emperor. Consensus-related logic of Iroha.
//!
//! `Consensus` trait is now implemented only by `Sumeragi` for now.
#![allow(
    clippy::arithmetic_side_effects,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc
)]
use std::{
    fmt::{self, Debug, Formatter},
    sync::{mpsc, Arc},
    time::{Duration, Instant},
};

use eyre::{Result, WrapErr as _};
use iroha_config::sumeragi::Configuration;
use iroha_crypto::{KeyPair, SignatureOf};
use iroha_data_model::prelude::*;
use iroha_genesis::GenesisNetwork;
use iroha_logger::prelude::*;
use iroha_telemetry::metrics::Metrics;
use network_topology::{Role, Topology};
use tokio::sync::watch;

use crate::{handler::ThreadHandler, kura::BlockCount};

pub mod main_loop;
pub mod message;
pub mod network_topology;
pub mod view_change;

use parking_lot::Mutex;

use self::{
    message::{Message, *},
    view_change::{Proof, ProofChain},
};
use crate::{
    block::*, kura::Kura, prelude::*, queue::Queue, EventsSender, IrohaNetwork, NetworkMessage,
};

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
    public_wsv_receiver: watch::Receiver<WorldStateView>,
    metrics: Metrics,
    last_update_metrics_mutex: Arc<Mutex<LastUpdateMetricsData>>,
    network: IrohaNetwork,
    kura: Arc<Kura>,
    queue: Arc<Queue>,
    _thread_handle: Arc<ThreadHandler>,
    // Should be dropped after `_thread_handle` to prevent sumeargi thread from panicking
    control_message_sender: mpsc::SyncSender<ControlFlowMessage>,
    message_sender: mpsc::SyncSender<MessagePacket>,
}

impl SumeragiHandle {
    /// Pass closure inside and apply fn to [`WorldStateView`].
    /// This function must be used with very cheap closures.
    /// So that it costs no more than cloning wsv.
    pub fn apply_wsv<T>(&self, f: impl FnOnce(&WorldStateView) -> T) -> T {
        f(&self.public_wsv_receiver.borrow())
    }

    /// Get public clone of [`WorldStateView`].
    pub fn wsv_clone(&self) -> WorldStateView {
        self.public_wsv_receiver.borrow().clone()
    }

    /// Notify when [`WorldStateView`] is updated.
    pub async fn wsv_updated(&mut self) {
        self.public_wsv_receiver
            .changed()
            .await
            .expect("Shouldn't return error as long as there is at least one SumeragiHandle");
    }

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
            .online_peers(std::collections::HashSet::len)
            .try_into()
            .expect("casting usize to u64");

        let wsv = self.wsv_clone();

        let mut last_guard = self.last_update_metrics_mutex.lock();

        let start_index = last_guard.block_height;
        {
            let mut block_index = start_index;
            while block_index < wsv.height() {
                let Some(block) = self.kura.get_block_by_height(block_index + 1) else {
                    break;
                };
                block_index += 1;
                let mut block_txs_accepted = 0;
                let mut block_txs_rejected = 0;
                for tx in &block.as_v1().transactions {
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
            core::mem::swap(&mut new_buf, &mut wsv.new_tx_amounts.lock());
            new_buf
        };

        for amount in &new_tx_amounts {
            self.metrics.tx_amounts.observe(*amount);
        }

        #[allow(clippy::cast_possible_truncation)]
        if let Some(timestamp) = wsv.genesis_timestamp() {
            // this will overflow in 584942417years.
            self.metrics
                .uptime_since_genesis_ms
                .set((current_time().as_millis() - timestamp) as u64)
        };

        self.metrics.connected_peers.set(online_peers_count);

        let domains = wsv.domains();
        self.metrics.domains.set(domains.len() as u64);
        for domain in domains.values() {
            self.metrics
                .accounts
                .get_metric_with_label_values(&[domain.id().name.as_ref()])
                .wrap_err("Failed to compose domains")?
                .set(domain.accounts.len() as u64);
        }

        self.metrics
            .view_changes
            .set(wsv.latest_block_view_change_index());

        self.metrics.queue_size.set(self.queue.tx_len() as u64);

        Ok(())
    }

    /// Access node metrics.
    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    /// Deposit a sumeragi network message.
    pub fn incoming_message(&self, msg: MessagePacket) {
        if msg.message.is_none() {
            if let Err(error) = self.control_message_sender.try_send(ControlFlowMessage {
                view_change_proofs: msg.view_change_proofs,
            }) {
                self.metrics.dropped_messages.inc();
                error!(?error, "This peer is faulty. Incoming control messages have to be dropped due to low processing speed.");
            }
        } else if let Err(error) = self.message_sender.try_send(msg) {
            self.metrics.dropped_messages.inc();
            error!(?error, "This peer is faulty. Incoming messages have to be dropped due to low processing speed.");
        }
    }

    /// Start [`Sumeragi`] actor and return handle to it.
    ///
    /// # Panics
    /// May panic if something is of during initialization which is bug.
    pub fn start(
        SumeragiStartArgs {
            configuration,
            events_sender,
            mut wsv,
            queue,
            kura,
            network,
            genesis_network,
            block_count:
                BlockCount {
                    total: block_count,
                    skip: skip_block_count,
                },
        }: SumeragiStartArgs,
    ) -> SumeragiHandle {
        let (control_message_sender, control_message_receiver) = mpsc::sync_channel(100);
        let (message_sender, message_receiver) = mpsc::sync_channel(100);

        let mut blocks_iter = (1..=block_count).map(|block_height| {
            kura.get_block_by_height(block_height as u64)
                .expect("Sumeragi should be able to load the block that was reported as presented. If not, the block storage was probably disconnected.")
        });

        let block_iter_except_last = (&mut blocks_iter)
            .skip(skip_block_count)
            .take(block_count.saturating_sub(1));
        for block in block_iter_except_last {
            block.revalidate(&mut wsv).expect(
                "The block should be valid in init. Blocks loaded from kura assumed to be valid",
            );
            wsv.apply_without_execution(block.as_ref())
                .expect("Block application in init should not fail. Blocks loaded from kura assumed to be valid");
        }

        // finalized_wsv is one block behind
        let finalized_wsv = wsv.clone();

        if let Some(latest_block) = blocks_iter.next() {
            latest_block.revalidate(&mut wsv).expect(
                "The block should be valid in init. Blocks loaded from kura assumed to be valid",
            );
            wsv.apply_without_execution(latest_block.as_ref())
                .expect("Block application in init should not fail. Blocks loaded from kura assumed to be valid");
        }

        info!("Sumeragi has finished loading blocks and setting up the WSV");

        let current_topology = match wsv.height() {
            0 => {
                assert!(!configuration.trusted_peers.peers.is_empty());
                Topology::new(configuration.trusted_peers.peers.clone())
            }
            height => {
                let block_ref = kura.get_block_by_height(height).expect("Sumeragi could not load block that was reported as present. Please check that the block storage was not disconnected.");
                Topology::recreate_topology(
                    &block_ref,
                    0,
                    wsv.peers_ids().iter().cloned().collect(),
                )
            }
        };

        let (public_wsv_sender, public_wsv_receiver) = watch::channel(wsv.clone());

        #[cfg(debug_assertions)]
        let debug_force_soft_fork = configuration.debug_force_soft_fork;
        #[cfg(not(debug_assertions))]
        let debug_force_soft_fork = false;

        let sumeragi = main_loop::Sumeragi {
            key_pair: configuration.key_pair.clone(),
            queue: Arc::clone(&queue),
            peer_id: configuration.peer_id.clone(),
            events_sender,
            public_wsv_sender,
            commit_time: Duration::from_millis(configuration.commit_time_limit_ms),
            block_time: Duration::from_millis(configuration.block_time_ms),
            max_txs_in_block: configuration.max_transactions_in_block as usize,
            kura: Arc::clone(&kura),
            network: network.clone(),
            control_message_receiver,
            message_receiver,
            debug_force_soft_fork,
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
                main_loop::run(genesis_network, sumeragi, shutdown_receiver);
            })
            .expect("Sumeragi thread spawn should not fail.");

        let shutdown = move || {
            if let Err(error) = shutdown_sender.send(()) {
                iroha_logger::error!(?error);
            }
        };

        let thread_handle = ThreadHandler::new(Box::new(shutdown), thread_handle);
        SumeragiHandle {
            network,
            queue,
            kura,
            control_message_sender,
            message_sender,
            public_wsv_receiver,
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
pub struct VotingBlock {
    /// At what time has this peer voted for this block
    pub voted_at: Instant,
    /// Valid Block
    pub block: PendingBlock,
    /// WSV after applying transactions to it
    pub new_wsv: WorldStateView,
}

impl VotingBlock {
    /// Construct new `VotingBlock` with current time.
    pub fn new(block: PendingBlock, new_wsv: WorldStateView) -> VotingBlock {
        VotingBlock {
            block,
            voted_at: Instant::now(),
            new_wsv,
        }
    }
    /// Construct new `VotingBlock` with the given time.
    pub(crate) fn voted_at(
        block: PendingBlock,
        new_wsv: WorldStateView,
        voted_at: Instant,
    ) -> VotingBlock {
        VotingBlock {
            block,
            voted_at,
            new_wsv,
        }
    }
}

/// Arguments for [`SumeragiHandle::start`] function
#[allow(missing_docs)]
pub struct SumeragiStartArgs<'args> {
    pub configuration: &'args Configuration,
    pub events_sender: EventsSender,
    pub wsv: WorldStateView,
    pub queue: Arc<Queue>,
    pub kura: Arc<Kura>,
    pub network: IrohaNetwork,
    pub genesis_network: Option<GenesisNetwork>,
    pub block_count: BlockCount,
}
