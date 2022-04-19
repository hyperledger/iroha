//! This module contains consensus related logic of the Iroha.
//!
//! `Consensus` trait is now implemented only by `Sumeragi` for now.

use std::{
    collections::{hash_map::Entry, BTreeMap, HashMap, HashSet},
    fmt::{self, Debug, Formatter},
    marker::PhantomData,
    sync::Arc,
    time::{Duration, Instant},
};

use eyre::{eyre, Result};
use iroha_actor::{broker::*, prelude::*, Context};
use iroha_crypto::{HashOf, KeyPair};
use iroha_data_model::prelude::*;
use iroha_logger::prelude::*;
use iroha_p2p::{ConnectPeer, DisconnectPeer};
use network_topology::{Role, Topology};
use rand::prelude::SliceRandom;

pub mod config;
pub mod fault;
pub mod message;
pub mod network_topology;
pub mod view_change;

use self::{
    fault::{NoFault, SumeragiWithFault},
    message::{Message, *},
    view_change::{Proof, ProofChain as ViewChangeProofs},
};
use crate::{
    block::{BlockHeader, ChainedBlock, EmptyChainHash, VersionedPendingBlock},
    genesis::GenesisNetworkTrait,
    kura::{GetBlockHash, KuraTrait, StoreBlock},
    prelude::*,
    queue::Queue,
    tx::TransactionValidator,
    wsv::WorldTrait,
    EventsSender, IrohaNetwork, NetworkMessage, VersionedValidBlock,
};

trait Consensus {
    fn round(
        &mut self,
        transactions: Vec<VersionedAcceptedTransaction>,
    ) -> Option<VersionedPendingBlock>;
}

/// `Sumeragi` is the implementation of the consensus.
pub type Sumeragi<G, K, W> = SumeragiWithFault<G, K, W, NoFault>;

/// Generic sumeragi trait
pub trait SumeragiTrait:
    Actor
    + ContextHandler<Message, Result = ()>
    + ContextHandler<Init, Result = ()>
    + ContextHandler<CommitBlock, Result = ()>
    + ContextHandler<GetNetworkTopology, Result = Topology>
    + ContextHandler<IsLeader, Result = bool>
    + ContextHandler<GetLeader, Result = PeerId>
    + ContextHandler<NetworkMessage, Result = ()>
    + ContextHandler<RetrieveTransactions, Result = ()>
    + Handler<Gossip, Result = ()>
    + Debug
{
    /// Genesis for sending genesis txs
    type GenesisNetwork: GenesisNetworkTrait;
    /// Data storage
    type Kura: KuraTrait<World = Self::World>;
    /// World for updating WSV after block commitment
    type World: WorldTrait;

    /// Construct [`Sumeragi`].
    ///
    /// # Errors
    /// Can fail during initing network topology
    #[allow(clippy::too_many_arguments)]
    fn from_configuration(
        configuration: &config::SumeragiConfiguration,
        events_sender: EventsSender,
        wsv: Arc<WorldStateView<Self::World>>,
        transaction_validator: TransactionValidator<Self::World>,
        telemetry_started: bool,
        genesis_network: Option<Self::GenesisNetwork>,
        queue: Arc<Queue<Self::World>>,
        broker: Broker,
        kura: AlwaysAddr<Self::Kura>,
        network: Addr<IrohaNetwork>,
    ) -> Result<Self>;
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
