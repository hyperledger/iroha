//! Translates to Emperor. Consensus-related logic of Iroha.
//!
//! `Consensus` trait is now implemented only by `Sumeragi` for now.
#![allow(
    clippy::arithmetic,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc
)]
use std::{
    collections::{hash_map::Entry, BTreeMap, HashMap, HashSet},
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
    sync::Arc,
    time::{Duration, Instant},
};

use eyre::{eyre, Result};
use iroha_actor::{broker::Broker, Addr};
use iroha_config::sumeragi::Configuration;
use iroha_crypto::{HashOf, KeyPair, SignatureOf};
use iroha_data_model::prelude::*;
use iroha_logger::prelude::*;
use iroha_p2p::{ConnectPeer, DisconnectPeer};
use network_topology::{Role, Topology};
use rand::prelude::SliceRandom;

use crate::genesis::GenesisNetwork;

pub mod fault;
pub mod message;
pub mod network_topology;
pub mod view_change;

use std::sync::Mutex;

use fault::SumeragiStateMachineData;

use self::{
    fault::{NoFault, SumeragiWithFault},
    message::{Message, *},
    view_change::{Proof, ProofChain as ViewChangeProofs},
};
use crate::{
    block::{BlockHeader, ChainedBlock, EmptyChainHash, VersionedPendingBlock},
    genesis::GenesisNetworkTrait,
    kura::Kura,
    prelude::*,
    queue::Queue,
    send_event,
    tx::TransactionValidator,
    EventsSender, IrohaNetwork, NetworkMessage, VersionedValidBlock,
};

trait Consensus {
    fn round(
        &mut self,
        transactions: Vec<VersionedAcceptedTransaction>,
    ) -> Option<VersionedPendingBlock>;
}

/// `Sumeragi` is the implementation of the consensus.
#[derive(Debug)]
pub struct Sumeragi {
    internal: SumeragiWithFault<NoFault>,
}

impl Sumeragi {
    /// Construct [`Sumeragi`].
    ///
    /// # Errors
    /// Can fail during initing network topology
    #[allow(clippy::too_many_arguments)]
    pub fn from_configuration(
        configuration: &Configuration,
        events_sender: EventsSender,
        wsv: WorldStateView,
        transaction_validator: TransactionValidator,
        telemetry_started: bool,
        genesis_network: Option<GenesisNetwork>,
        queue: Arc<Queue>,
        broker: Broker,
        kura: Arc<Kura>,
        network: Addr<IrohaNetwork>,
    ) -> Result<Self> {
        let network_topology = Topology::builder()
            .at_block(EmptyChainHash::default().into())
            .with_peers(configuration.trusted_peers.peers.clone())
            .build(0)?;

        let sumeragi_state_machine_data = SumeragiStateMachineData {
            genesis_network,
            latest_block_hash: Hash::zeroed().typed(),
            latest_block_height: 0,
            current_topology: network_topology,

            sumeragi_thread_should_exit: false,
        };

        let (incoming_message_sender, incoming_message_receiver) = std::sync::mpsc::channel();

        Ok(Self {
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

                sumeragi_state_machine_data: Mutex::new(sumeragi_state_machine_data),
                current_online_peers_by_public_key: Mutex::new(Vec::new()),
                incoming_message_sender: Mutex::new(incoming_message_sender),
                incoming_message_receiver: Mutex::new(incoming_message_receiver),
            },
        })
    }

    pub fn update_metrics(&self, network: Addr<IrohaNetwork>) -> Result<()> {
        use eyre::WrapErr;
        use thiserror::Error;
        let online_peers_count: u64 = self
            .internal
            .current_online_peers_by_public_key
            .lock()
            .unwrap()
            .len()
            .try_into()
            .expect("casting usize to u64");

        let mut wsv_guard = self.internal.wsv.lock().unwrap();

        #[allow(clippy::cast_possible_truncation)]
        if let Some(timestamp) = wsv_guard.genesis_timestamp() {
            // this will overflow in 584942417years.
            wsv_guard
                .metrics
                .uptime_since_genesis_ms
                .set((current_time().as_millis() - timestamp) as u64)
        };
        let domains = wsv_guard.domains();
        wsv_guard.metrics.domains.set(domains.len() as u64);
        wsv_guard.metrics.connected_peers.set(online_peers_count);
        for domain in domains {
            wsv_guard
                .metrics
                .accounts
                .get_metric_with_label_values(&[domain.id().name.as_ref()])
                .wrap_err("Failed to compose domains")?
                .set(domain.accounts().len() as u64);
        }
        Ok(())
    }

    pub fn latest_block_hash(&self) -> HashOf<VersionedCommittedBlock> {
        self.internal.wsv.lock().unwrap().latest_block_hash()
    }

    pub fn get_network_topology(&self, header: &BlockHeader) -> Topology {
        // TODO: make use of block header
        self.internal
            .sumeragi_state_machine_data
            .lock()
            .expect("Get network topology lock.")
            .current_topology
            .clone()
    }

    pub fn blocks_after_hash(
        &self,
        block_hash: HashOf<VersionedCommittedBlock>,
    ) -> Vec<VersionedCommittedBlock> {
        self.internal
            .wsv
            .lock()
            .unwrap()
            .blocks_after_hash(block_hash)
    }

    pub fn get_random_peer_for_block_sync(&self) -> Option<Peer> {
        use rand::{prelude::SliceRandom, SeedableRng};

        let rng = &mut rand::rngs::StdRng::from_entropy();
        self.internal
            .wsv
            .lock()
            .unwrap()
            .peers()
            .choose(rng)
            .cloned()
    }

    pub fn wsv_clone(&self) -> WorldStateView {
        self.internal.wsv.lock().unwrap().clone()
    }

    pub fn initialize_and_start_thread(
        sumeragi: Arc<Self>,
        latest_block_hash: HashOf<VersionedCommittedBlock>,
        latest_block_height: u64,
    ) {
        std::thread::spawn(move || {
            fault::run_sumeragi_main_loop(
                &sumeragi.internal,
                latest_block_hash,
                latest_block_height,
            );
            info!("Sumeragi Thread has Shutdown");
        });
    }

    pub fn stop_thread(&self) {
        self.internal
            .sumeragi_state_machine_data
            .lock()
            .expect("lock to stop sumeragi thread")
            .sumeragi_thread_should_exit = true;
    }

    pub fn update_online_peers(&self, online_peers: Vec<PublicKey>) {
        *self
            .internal
            .current_online_peers_by_public_key
            .lock()
            .expect("Lock on update online peers.") = online_peers;
    }

    pub fn incoming_message(&self, msg: Message) {
        self.internal
            .incoming_message_sender
            .lock()
            .expect("Lock on sender")
            .send(msg);
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
