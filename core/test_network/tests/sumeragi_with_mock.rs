#![allow(
    clippy::restriction,
    missing_debug_implementations,
    clippy::future_not_send,
    clippy::pedantic
)]

use std::{fmt::Debug, num::NonZeroU64, ops::Deref, path::Path, sync::Arc, time::Duration};

use async_trait::async_trait;
use eyre::Result;
use iroha_actor::{broker::*, prelude::*, Context};
use iroha_core::{
    block_sync::{BlockSynchronizer, BlockSynchronizerTrait, ContinueSync},
    event::EventsSender,
    genesis::{config::GenesisConfiguration, GenesisNetworkTrait},
    kura::{KuraTrait, StoreBlock},
    prelude::*,
    queue::Queue,
    smartcontracts::permissions::IsInstructionAllowedBoxed,
    sumeragi::{
        message::Message as SumeragiMessage,
        network_topology::{Role, Topology},
        *,
    },
    wsv::WorldTrait,
};
use iroha_data_model::prelude::*;
use iroha_p2p::network::StopSelf;
use test_network::*;
use tokio::{sync::mpsc, time};
use utils::{genesis, kura, kura::*, sumeragi, world};

pub mod utils {
    use iroha_core::genesis::RawGenesisBlock;
    use iroha_crypto::HashOf;

    use super::*;

    pub mod genesis {
        use iroha_core::IrohaNetwork;

        use super::*;

        #[derive(Debug, Clone, Copy, Default)]
        pub struct NoGenesis;

        impl Deref for NoGenesis {
            type Target = Vec<VersionedAcceptedTransaction>;
            fn deref(&self) -> &Self::Target {
                unreachable!()
            }
        }

        #[async_trait::async_trait]
        impl GenesisNetworkTrait for NoGenesis {
            fn from_configuration(
                _submit_genesis: bool,
                _block_path: RawGenesisBlock,
                _genesis_config: &GenesisConfiguration,
                _max_instructions_number: u64,
            ) -> Result<Option<Self>> {
                Ok(None)
            }

            async fn wait_for_peers(
                &self,
                _: PeerId,
                _: Topology,
                _: Addr<IrohaNetwork>,
            ) -> Result<Topology> {
                unreachable!()
            }

            fn genesis_submission_delay_ms(&self) -> u64 {
                0
            }
        }
    }

    pub mod kura {
        use iroha_core::{
            kura::{GetBlockHash, Mode},
            sumeragi,
        };

        use super::*;

        #[derive(Debug)]
        pub struct CountStored<W: WorldTrait> {
            pub broker: Broker,
            pub wsv: Arc<WorldStateView<W>>,
        }

        #[async_trait]
        impl<W: WorldTrait> KuraTrait for CountStored<W> {
            type World = W;

            async fn new(
                _: Mode,
                _: &Path,
                _: NonZeroU64,
                wsv: Arc<WorldStateView<W>>,
                broker: Broker,
                _: usize,
            ) -> Result<Self, iroha_core::kura::Error> {
                Ok(Self { broker, wsv })
            }
        }

        #[async_trait::async_trait]
        impl<W: WorldTrait> Actor for CountStored<W> {
            async fn on_start(&mut self, ctx: &mut Context<Self>) {
                self.broker.subscribe::<StoreBlock, _>(ctx);
                self.broker
                    .issue_send(sumeragi::Init {
                        last_block: HashOf::from_hash(Hash([0; 32])),
                        height: 0,
                    })
                    .await;
            }
        }

        #[async_trait::async_trait]
        impl<W: WorldTrait> Handler<StoreBlock> for CountStored<W> {
            type Result = ();

            async fn handle(&mut self, StoreBlock(block): StoreBlock) -> Self::Result {
                self.broker.issue_send(Stored(block.hash())).await;
                self.wsv.apply(block).await.unwrap();
                self.broker.issue_send(UpdateNetworkTopology).await;
                self.broker.issue_send(ContinueSync).await;
            }
        }

        #[async_trait::async_trait]
        impl<W: WorldTrait> Handler<GetBlockHash> for CountStored<W> {
            type Result = Option<HashOf<VersionedCommittedBlock>>;
            async fn handle(&mut self, _: GetBlockHash) -> Self::Result {
                panic!("Shouldn't be called here!")
            }
        }

        #[derive(Debug, iroha_actor::Message, Clone, PartialEq, Eq, Copy)]
        pub struct Stored(pub HashOf<VersionedCommittedBlock>);
    }

    pub mod sumeragi {
        use std::{fmt::Debug, marker::PhantomData, ops::DerefMut};

        use iroha_actor::Message;
        use iroha_core::{
            smartcontracts::permissions::IsQueryAllowedBoxed, IrohaNetwork, NetworkMessage,
        };

        use super::*;

        #[async_trait::async_trait]
        pub trait FaultBehaviour: Debug + Send + 'static {
            /// Does some bad stuff instead of message handling
            async fn fault<G, W, K, S>(sumeragi: &mut S, m: SumeragiMessage)
            where
                G: GenesisNetworkTrait,
                W: WorldTrait,
                K: KuraTrait<World = W>,
                S: Deref<Target = Sumeragi<G, K, W>> + DerefMut + Send;
        }

        pub trait ConstRoleTrait: Debug + Send + 'static {
            /// Returns true if we indead is that role
            fn role(role: Role) -> bool;
        }

        #[derive(Debug, Clone, Copy, Default)]
        struct Not<R>(PhantomData<R>);

        impl<R: ConstRoleTrait> ConstRoleTrait for Not<R> {
            fn role(role: Role) -> bool {
                !R::role(role)
            }
        }

        macro_rules! impl_role {
            ($($name:ident),* $(,)? ) => {$(
                #[derive(Debug, Clone, Copy, Default)]
                pub struct $name;
                impl ConstRoleTrait for $name {
                    fn role(role: Role) -> bool {
                        Role::$name == role
                    }
                }
            )*};
        }

        impl_role!(Leader, ValidatingPeer, ObservingPeer, ProxyTail);

        #[derive(Debug, Clone, Copy, Default)]
        pub struct Any;

        impl ConstRoleTrait for Any {
            fn role(_: Role) -> bool {
                true
            }
        }

        #[derive(Debug, Clone, Copy, Default)]
        pub struct Empty<A>(PhantomData<A>);

        #[async_trait::async_trait]
        impl FaultBehaviour for Empty<BlockCreated> {
            async fn fault<G, W, K, S>(sumeragi: &mut S, msg: SumeragiMessage)
            where
                G: GenesisNetworkTrait,
                W: WorldTrait,
                K: KuraTrait,
                S: Deref<Target = Sumeragi<G, K, W>> + DerefMut + Send,
            {
                let msg = if let SumeragiMessage::BlockCreated(mut block) = msg {
                    block.block.as_mut_v1().transactions = Vec::new();
                    SumeragiMessage::BlockCreated(block)
                } else {
                    msg
                };
                drop(msg.handle(sumeragi).await);
            }
        }

        #[derive(Debug, Clone, Copy, Default)]
        pub struct Skip<A>(PhantomData<A>);

        macro_rules! impl_skip {
            ( $($name:ident),* $(,)? ) => {$(
                #[derive(Debug, Clone, Copy, Default)]
                pub struct $name;
                #[async_trait::async_trait]
                impl FaultBehaviour for Skip<$name> {
                    async fn fault<G, W, K, S>(sumeragi: &mut S, m: SumeragiMessage)
                    where
                        G: GenesisNetworkTrait,
                        W: WorldTrait,
                        K: KuraTrait,
                        S: Deref<Target = Sumeragi<G, K, W>> + DerefMut + Send,
                    {
                        if let SumeragiMessage::$name(..) = m {
                            iroha_logger::error!("Fault behaviour: Skipping {}", stringify!($name));
                            return;
                        }
                        drop(m.handle(&mut *sumeragi).await);
                    }
                }
            )*};
        }

        impl_skip!(
            BlockCreated,
            BlockSigned,
            BlockCommitted,
            TransactionReceived,
            TransactionForwarded,
            ViewChangeSuggested
        );

        macro_rules! impl_handler_proxy(
            ( $name:ident : $( Handler< $msg:ty, Result = $ret:ty> $(+)? )* ) => {$(
                #[async_trait::async_trait]
                impl<R, F, G, K, W> Handler<$msg> for $name<R, F, G, K, W>
                where
                    R: ConstRoleTrait,
                    F: FaultBehaviour,
                    G: GenesisNetworkTrait,
                    K: KuraTrait<World = W>,
                    W: WorldTrait
                {
                    type Result = $ret;
                    async fn handle(&mut self, msg: $msg) -> Self::Result {
                        <Sumeragi<_, _, _> as Handler<$msg>>::handle(&mut *self, msg).await
                    }
                }
            )*}
        );

        #[derive(Debug)]
        pub struct Faulty<R, F, G, K, W>
        where
            R: ConstRoleTrait,
            F: FaultBehaviour,
            G: GenesisNetworkTrait,
            K: KuraTrait,
            W: WorldTrait,
        {
            sumeragi: Sumeragi<G, K, W>,
            _faulty: PhantomData<(R, F)>,
        }

        impl<R, F, G, K, W> Deref for Faulty<R, F, G, K, W>
        where
            R: ConstRoleTrait,
            F: FaultBehaviour,
            G: GenesisNetworkTrait,
            K: KuraTrait,
            W: WorldTrait,
        {
            type Target = Sumeragi<G, K, W>;
            fn deref(&self) -> &Self::Target {
                &self.sumeragi
            }
        }

        impl<R, F, G, K, W> DerefMut for Faulty<R, F, G, K, W>
        where
            R: ConstRoleTrait,
            F: FaultBehaviour,
            G: GenesisNetworkTrait,
            K: KuraTrait,
            W: WorldTrait,
        {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.sumeragi
            }
        }

        impl<R, F, G, K, W> Faulty<R, F, G, K, W>
        where
            R: ConstRoleTrait,
            F: FaultBehaviour,
            G: GenesisNetworkTrait,
            K: KuraTrait,
            W: WorldTrait,
        {
            pub fn new(sumeragi: Sumeragi<G, K, W>) -> Self {
                Self {
                    sumeragi,
                    _faulty: PhantomData::default(),
                }
            }
        }

        #[async_trait::async_trait]
        impl<R, F, G, K, W> Actor for Faulty<R, F, G, K, W>
        where
            R: ConstRoleTrait,
            F: FaultBehaviour,
            G: GenesisNetworkTrait,
            K: KuraTrait<World = W>,
            W: WorldTrait,
        {
            async fn on_start(&mut self, ctx: &mut Context<Self>) {
                self.broker.subscribe::<UpdateNetworkTopology, _>(ctx);
                self.broker.subscribe::<sumeragi::message::Message, _>(ctx);
                self.broker.subscribe::<Init, _>(ctx);
                self.broker.subscribe::<CommitBlock, _>(ctx);
                self.broker.subscribe::<NetworkMessage, _>(ctx);
                self.broker.subscribe::<Voting, _>(ctx);
                self.broker.subscribe::<Gossip, _>(ctx);
                ctx.notify_every::<ConnectPeers>(PEERS_CONNECT_INTERVAL);
            }
        }

        impl<R, F, G, K, W> SumeragiTrait for Faulty<R, F, G, K, W>
        where
            R: ConstRoleTrait,
            F: FaultBehaviour,
            G: GenesisNetworkTrait,
            K: KuraTrait<World = W>,
            W: WorldTrait,
        {
            type GenesisNetwork = G;
            type Kura = K;
            type World = W;

            fn from_configuration(
                configuration: &config::SumeragiConfiguration,
                events_sender: EventsSender,
                wsv: Arc<WorldStateView<W>>,
                is_instruction_allowed: IsInstructionAllowedBoxed<W>,
                is_query_allowed: Arc<IsQueryAllowedBoxed<W>>,
                telemetry_enabled: bool,
                genesis_network: Option<Self::GenesisNetwork>,
                queue: Arc<Queue>,
                broker: Broker,
                kura: AlwaysAddr<K>,
                network: Addr<IrohaNetwork>,
            ) -> Result<Self> {
                Sumeragi::from_configuration(
                    configuration,
                    events_sender,
                    wsv,
                    is_instruction_allowed,
                    is_query_allowed,
                    telemetry_enabled,
                    genesis_network,
                    queue,
                    broker,
                    kura,
                    network,
                )
                .map(Self::new)
            }
        }

        #[async_trait::async_trait]
        impl<R, F, G, K, W> Handler<Init> for Faulty<R, F, G, K, W>
        where
            R: ConstRoleTrait,
            F: FaultBehaviour,
            G: GenesisNetworkTrait,
            K: KuraTrait<World = W>,
            W: WorldTrait,
        {
            type Result = ();
            async fn handle(&mut self, Init { last_block, height }: Init) {
                self.connect_peers().await;

                if height != 0 && *last_block != Hash([0; 32]) {
                    self.init(last_block, height);
                } else if let Some(genesis_network) = self.genesis_network.take() {
                    let addr = self.network.clone();
                    if let Err(error) = genesis_network.submit_transactions(self, addr).await {
                        iroha_logger::error!(%error, "Failed to submit genesis transactions")
                    }
                }
                self.update_network_topology().await;
            }
        }

        impl_handler_proxy!(
            Faulty: Handler<UpdateNetworkTopology, Result = ()>
                     + Handler<CommitBlock, Result = ()>
                     + Handler<GetNetworkTopology, Result = Topology>
                     + Handler<IsLeader, Result = bool>
                     + Handler<GetLeader, Result = PeerId>
                     + Handler<Voting, Result = ()>
                     + Handler<ConnectPeers, Result = ()>
                     + Handler<NetworkMessage, Result = ()>
                     + Handler<Gossip, Result = ()>
        );

        #[derive(Debug, Clone, Copy, Default, Message)]
        #[message(result = "Topology")]
        pub struct NetworkTopology;

        #[async_trait::async_trait]
        impl<R, F, G, K, W> Handler<NetworkTopology> for Faulty<R, F, G, K, W>
        where
            R: ConstRoleTrait,
            F: FaultBehaviour,
            G: GenesisNetworkTrait,
            K: KuraTrait<World = W>,
            W: WorldTrait,
        {
            type Result = Topology;
            async fn handle(&mut self, _: NetworkTopology) -> Self::Result {
                self.topology.clone()
            }
        }

        #[async_trait::async_trait]
        impl<R, F, G, K, W> Handler<SumeragiMessage> for Faulty<R, F, G, K, W>
        where
            R: ConstRoleTrait,
            F: FaultBehaviour,
            G: GenesisNetworkTrait,
            K: KuraTrait<World = W>,
            W: WorldTrait,
        {
            type Result = ();
            async fn handle(&mut self, msg: SumeragiMessage) -> Self::Result {
                if R::role(self.topology.role(&self.peer_id)) {
                    F::fault(&mut *self, msg).await;
                } else {
                    drop(msg.handle(&mut *self).await);
                }
            }
        }

        #[derive(Debug, Clone, Copy, Message)]
        #[message(result = "Vec<HashOf<VersionedValidBlock>>")]
        pub struct InvalidBlocks;

        #[async_trait::async_trait]
        impl<R, F, G, K, W> Handler<InvalidBlocks> for Faulty<R, F, G, K, W>
        where
            R: ConstRoleTrait,
            F: FaultBehaviour,
            G: GenesisNetworkTrait,
            K: KuraTrait<World = W>,
            W: WorldTrait,
        {
            type Result = Vec<HashOf<VersionedValidBlock>>;
            async fn handle(&mut self, _: InvalidBlocks) -> Self::Result {
                self.invalidated_blocks_hashes.clone()
            }
        }

        #[derive(Debug, Clone, Message)]
        pub struct Round(pub Vec<VersionedAcceptedTransaction>);

        #[async_trait::async_trait]
        impl<R, F, G, K, W> Handler<Round> for Faulty<R, F, G, K, W>
        where
            R: ConstRoleTrait,
            F: FaultBehaviour,
            G: GenesisNetworkTrait,
            K: KuraTrait<World = W>,
            W: WorldTrait,
        {
            type Result = ();
            async fn handle(&mut self, Round(txs): Round) -> Self::Result {
                drop(self.round(txs).await);
            }
        }

        #[async_trait::async_trait]
        impl<G, K, W> Handler<Round> for Sumeragi<G, K, W>
        where
            G: GenesisNetworkTrait,
            K: KuraTrait,
            W: WorldTrait,
        {
            type Result = ();
            async fn handle(&mut self, Round(txs): Round) -> Self::Result {
                drop(self.round(txs).await);
            }
        }
    }

    pub mod world {
        use std::ops::{Deref, DerefMut};

        use iroha_core::{prelude::*, tx::Domain, wsv::WorldTrait};
        use iroha_data_model::prelude::*;
        use once_cell::sync::Lazy;

        #[derive(Debug, Clone, Default)]
        pub struct WithRoot(World);

        impl Deref for WithRoot {
            type Target = World;
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl DerefMut for WithRoot {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }

        pub static ROOT_KEYS: Lazy<KeyPair> = Lazy::new(|| KeyPair::generate().unwrap());
        pub static ROOT_ID: Lazy<AccountId> = Lazy::new(|| AccountId::new("root", "global"));
        pub static ROOT: Lazy<Account> = Lazy::new(|| {
            let mut account = Account::new(ROOT_ID.clone());
            account.signatories.push(ROOT_KEYS.public_key.clone());
            account
        });
        pub static GLOBAL: Lazy<Domain> = Lazy::new(|| {
            let mut domain = Domain::new("global");
            domain.accounts.insert(ROOT_ID.clone(), ROOT.clone());
            domain
        });

        impl WorldTrait for WithRoot {
            /// Creates `World` with these `domains` and `trusted_peers_ids`
            fn with(
                domains: impl IntoIterator<Item = (Name, Domain)>,
                trusted_peers_ids: impl IntoIterator<Item = PeerId>,
            ) -> Self {
                Self(World::with(
                    vec![(GLOBAL.name.clone(), GLOBAL.clone())]
                        .into_iter()
                        .chain(domains),
                    trusted_peers_ids,
                ))
            }
        }

        pub fn sign_tx(isi: impl IntoIterator<Item = Instruction>) -> VersionedAcceptedTransaction {
            let tx = Transaction::new(isi.into_iter().collect(), ROOT_ID.clone(), 100_000)
                .sign(&ROOT_KEYS)
                .unwrap();
            VersionedAcceptedTransaction::from_transaction(tx, 4096).unwrap()
        }
    }
}

/// Checks if blocks are applied on single peer
async fn blocks_applied_peer(channel: &mut mpsc::Receiver<Stored>, n: usize) -> usize {
    for i in 0..n {
        let timeout = time::timeout(Duration::from_millis(100), channel.recv())
            .await
            .map(|o| o.is_none())
            .unwrap_or(true);
        if timeout {
            return i;
        }
    }
    n
}

/// Checks if blocks applied on all peers
async fn blocks_applied(channels: &mut [mpsc::Receiver<Stored>], n: usize) {
    let mut out = Vec::new();
    for chan in channels.iter_mut() {
        // Blocks number is increased by one in order to remove false positives,
        // when peer actually accepted more blocks than needed.
        out.push(blocks_applied_peer(chan, n + 1).await);
    }
    assert_eq!(out, vec![n; channels.len()]);
}

async fn start_round_with_tx<W, G, S, K, B>(network: &Network<W, G, K, S, B>, to_leader: bool)
where
    W: WorldTrait,
    G: GenesisNetworkTrait,
    K: KuraTrait<World = W>,
    S: SumeragiTrait<GenesisNetwork = G, Kura = K, World = W> + Handler<sumeragi::Round>,
    B: BlockSynchronizerTrait<Sumeragi = S, World = W>,
{
    let tx = world::sign_tx(vec![]);
    let leader = network
        .send_to_actor_on_peers(|iroha| &iroha.sumeragi, IsLeader)
        .await;
    let (_, peer) = leader
        .into_iter()
        .find(|(leader, _)| if to_leader { *leader } else { !*leader })
        .unwrap();
    network
        .peer_by_id(&peer)
        .unwrap()
        .iroha
        .as_ref()
        .unwrap()
        .sumeragi
        .do_send(sumeragi::Round(vec![tx]))
        .await;
}

async fn put_tx_in_queue<W, G, S, K, B>(network: &Network<W, G, K, S, B>, to_leader: bool)
where
    W: WorldTrait,
    G: GenesisNetworkTrait,
    K: KuraTrait<World = W>,
    S: SumeragiTrait<GenesisNetwork = G, Kura = K, World = W> + Handler<sumeragi::Round>,
    B: BlockSynchronizerTrait<Sumeragi = S, World = W>,
{
    let tx = world::sign_tx(vec![]);
    let leader = network
        .send_to_actor_on_peers(|iroha| &iroha.sumeragi, IsLeader)
        .await;
    let (_, peer) = leader
        .into_iter()
        .find(|(leader, _)| if to_leader { *leader } else { !*leader })
        .unwrap();
    let peer = network.peer_by_id(&peer).unwrap();
    peer.iroha
        .as_ref()
        .unwrap()
        .queue
        .push(tx, &*peer.iroha.as_ref().unwrap().wsv)
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "mock"]
async fn all_peers_commit_block() {
    iroha_logger::install_panic_hook().unwrap();
    let (network, _) = <Network<
        world::WithRoot,
        genesis::NoGenesis,
        kura::CountStored<_>,
        Sumeragi<_, _, _>,
        BlockSynchronizer<_, _>,
    >>::start_test(10, 1)
    .await;

    let mut channels = network
        .peers()
        .map(|peer| peer.broker.subscribe_with_channel::<Stored>())
        .collect::<Vec<_>>();

    // Send tx to leader
    start_round_with_tx(&network, true).await;
    time::sleep(Duration::from_secs(2)).await;

    blocks_applied(&mut channels, 1).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "mock"]
async fn change_view_on_commit_timeout() {
    iroha_logger::install_panic_hook().unwrap();
    let (network, _) = <Network<
        world::WithRoot,
        genesis::NoGenesis,
        kura::CountStored<_>,
        sumeragi::Faulty<sumeragi::ProxyTail, sumeragi::Skip<sumeragi::BlockSigned>, _, _, _>,
        BlockSynchronizer<_, _>,
    >>::start_test(10, 1)
    .await;

    let mut channels = network
        .peers()
        .map(|peer| peer.broker.subscribe_with_channel::<Stored>())
        .collect::<Vec<_>>();

    // send to leader
    start_round_with_tx(&network, true).await;
    time::sleep(Duration::from_secs(2)).await;

    blocks_applied(&mut channels, 0).await;

    let topologies = network
        .send_to_actor_on_peers(|iroha| &iroha.sumeragi, sumeragi::NetworkTopology)
        .await;
    let invalid_block_hashes = network
        .send_to_actor_on_peers(|iroha| &iroha.sumeragi, sumeragi::InvalidBlocks)
        .await;

    network.send_all(StopSelf::Network).await;

    for (topology, _) in topologies {
        assert_eq!(topology.view_change_proofs().len(), 1);
    }
    for (hashes, _) in invalid_block_hashes {
        assert_eq!(hashes.len(), 1);
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "mock"]
async fn change_view_on_tx_receipt_timeout() {
    iroha_logger::install_panic_hook().unwrap();
    let (network, _) = <Network<
        world::WithRoot,
        genesis::NoGenesis,
        kura::CountStored<_>,
        sumeragi::Faulty<sumeragi::Leader, sumeragi::Skip<sumeragi::TransactionForwarded>, _, _, _>,
        BlockSynchronizer<_, _>,
    >>::start_test(10, 1)
    .await;

    let mut channels = network
        .peers()
        .map(|peer| peer.broker.subscribe_with_channel::<Stored>())
        .collect::<Vec<_>>();

    // send to not leader
    put_tx_in_queue(&network, false).await;

    // Let peers gossip tx.
    for peer in network.peers() {
        peer.iroha.as_ref().unwrap().sumeragi.do_send(Gossip).await;
    }

    // Wait while tx is gossiped
    time::sleep(Duration::from_millis(500)).await;

    // Let peers retrieve the gossiped tx and send to leader, so they can all understand the leader is unresponsive.
    for peer in network.peers() {
        peer.iroha.as_ref().unwrap().sumeragi.do_send(Voting).await;
    }

    time::sleep(Duration::from_secs(3)).await;

    blocks_applied(&mut channels, 0).await;

    let topologies = network
        .send_to_actor_on_peers(|iroha| &iroha.sumeragi, sumeragi::NetworkTopology)
        .await;
    for (topology, _) in topologies {
        assert_eq!(topology.view_change_proofs().len(), 1);
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "mock"]
async fn change_view_on_block_creation_timeout() {
    iroha_logger::install_panic_hook().unwrap();
    let (network, _) = <Network<
        world::WithRoot,
        genesis::NoGenesis,
        kura::CountStored<_>,
        sumeragi::Faulty<sumeragi::Any, sumeragi::Skip<sumeragi::BlockCreated>, _, _, _>,
        BlockSynchronizer<_, _>,
    >>::start_test(10, 1)
    .await;

    let mut channels = network
        .peers()
        .map(|peer| peer.broker.subscribe_with_channel::<Stored>())
        .collect::<Vec<_>>();

    // send to not leader
    start_round_with_tx(&network, false).await;
    time::sleep(Duration::from_secs(2)).await;

    blocks_applied(&mut channels, 0).await;

    let topologies = network
        .send_to_actor_on_peers(|iroha| &iroha.sumeragi, sumeragi::NetworkTopology)
        .await;

    for (topology, _) in topologies {
        assert_eq!(topology.view_change_proofs().len(), 1);
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "mock"]
async fn not_enough_votes() {
    iroha_logger::install_panic_hook().unwrap();
    let (network, _) = <Network<
        world::WithRoot,
        genesis::NoGenesis,
        kura::CountStored<_>,
        sumeragi::Faulty<sumeragi::Any, sumeragi::Empty<sumeragi::BlockCreated>, _, _, _>,
        BlockSynchronizer<_, _>,
    >>::start_test(10, 1)
    .await;

    let mut channels = network
        .peers()
        .map(|peer| peer.broker.subscribe_with_channel::<Stored>())
        .collect::<Vec<_>>();

    start_round_with_tx(&network, true).await;
    time::sleep(Duration::from_secs(2)).await;

    blocks_applied(&mut channels, 0).await;

    let topologies = network
        .send_to_actor_on_peers(|iroha| &iroha.sumeragi, sumeragi::NetworkTopology)
        .await;
    let invalid_block_hashes = network
        .send_to_actor_on_peers(|iroha| &iroha.sumeragi, sumeragi::InvalidBlocks)
        .await;

    for (topology, _) in topologies {
        assert_eq!(topology.view_change_proofs().len(), 1);
    }
    for (hashes, _) in invalid_block_hashes {
        assert_eq!(hashes.len(), 1);
    }
}
