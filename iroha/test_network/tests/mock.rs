#![allow(
    clippy::restriction,
    missing_debug_implementations,
    clippy::future_not_send,
    clippy::missing_panics_doc
)]

use std::ops::Deref;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use iroha::block_sync::{BlockSynchronizerTrait, ContinueSync};
use iroha::event::EventsSender;
use iroha::genesis::config::GenesisConfiguration;
use iroha::genesis::GenesisNetworkTrait;
use iroha::kura::StoreBlock;
use iroha::queue::QueueTrait;
use iroha::smartcontracts::permissions::InstructionPermissionsValidatorBox;
use iroha::sumeragi::message::Message as SumeragiMessage;
use iroha::wsv::WorldTrait;
use iroha::{block_sync::BlockSynchronizer, queue::Queue};
use iroha::{kura::KuraTrait, prelude::*, sumeragi::*};
use iroha_actor::{broker::*, prelude::*, Context};
use iroha_data_model::prelude::*;
use iroha_error::Result;
use test_network::*;
use tokio::sync::mpsc;
use tokio::time;
use utils::kura::*;
use utils::{genesis, kura, sumeragi, world};

pub mod utils {
    use super::*;

    pub mod genesis {
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
            fn from_configuration(_: &GenesisConfiguration, _: usize) -> Result<Option<Self>> {
                Ok(None)
            }

            async fn wait_for_peers(
                &self,
                _: PeerId,
                _: InitializedNetworkTopology,
            ) -> Result<InitializedNetworkTopology> {
                unreachable!()
            }
        }
    }

    pub mod kura {
        use iroha::kura::Mode;
        use iroha::sumeragi;

        use super::*;

        pub struct CountStored<W: WorldTrait> {
            pub broker: Broker,
            pub wsv: Arc<WorldStateView<W>>,
        }

        impl<W: WorldTrait> KuraTrait for CountStored<W> {
            type World = W;

            fn new(_: Mode, _: &Path, wsv: Arc<WorldStateView<W>>, broker: Broker) -> Result<Self> {
                Ok(Self { broker, wsv })
            }
        }

        #[async_trait::async_trait]
        impl<W: WorldTrait> Actor for CountStored<W> {
            async fn on_start(&mut self, ctx: &mut Context<Self>) {
                self.broker.subscribe::<StoreBlock, _>(ctx);
                self.broker
                    .issue_send(sumeragi::Init {
                        latest_block_hash: Hash([0; 32]),
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
                self.wsv.apply(block).await;
                self.broker.issue_send(UpdateNetworkTopology).await;
                self.broker.issue_send(ContinueSync).await;
            }
        }

        #[derive(Debug, iroha_actor::Message, Clone, Copy, PartialEq, Eq)]
        pub struct Stored(pub Hash);
    }

    pub mod sumeragi {
        use std::{fmt::Debug, marker::PhantomData, ops::DerefMut};

        use iroha::sumeragi;
        use iroha_actor::Message;

        use super::*;

        #[async_trait::async_trait]
        pub trait FaultBehaviour: Debug + Send + 'static {
            /// Does some bad stuff instead of message handling
            async fn fault<Q, G, W, S>(sumeragi: &mut S, m: SumeragiMessage)
            where
                Q: QueueTrait,
                G: GenesisNetworkTrait,
                W: WorldTrait,
                S: Deref<Target = Sumeragi<Q, G, W>> + DerefMut + Send;
        }

        pub trait ConstRoleTrait: Debug + Send + 'static {
            /// Returns true if we indead is that role
            fn role(role: sumeragi::Role) -> bool;
        }

        #[derive(Debug, Clone, Copy, Default)]
        struct Not<R>(PhantomData<R>);

        impl<R: ConstRoleTrait> ConstRoleTrait for Not<R> {
            fn role(role: sumeragi::Role) -> bool {
                !R::role(role)
            }
        }

        macro_rules! impl_role {
            ($($name:ident),* $(,)? ) => {$(
                #[derive(Debug, Clone, Copy, Default)]
                pub struct $name;
                impl ConstRoleTrait for $name {
                    fn role(role: sumeragi::Role) -> bool {
                        sumeragi::Role::$name == role
                    }
                }
            )*};
        }

        impl_role!(Leader, ValidatingPeer, ObservingPeer, ProxyTail);

        #[derive(Debug, Clone, Copy, Default)]
        pub struct Any;

        impl ConstRoleTrait for Any {
            fn role(_: sumeragi::Role) -> bool {
                true
            }
        }

        #[derive(Debug, Clone, Copy, Default)]
        pub struct Empty<A>(PhantomData<A>);

        #[async_trait::async_trait]
        impl FaultBehaviour for Empty<BlockCreated> {
            async fn fault<Q, G, W, S>(sumeragi: &mut S, msg: SumeragiMessage)
            where
                Q: QueueTrait,
                G: GenesisNetworkTrait,
                W: WorldTrait,
                S: Deref<Target = Sumeragi<Q, G, W>> + DerefMut + Send,
            {
                let msg = if let SumeragiMessage::BlockCreated(mut block) = msg {
                    block.block.as_mut_inner_v1().transactions = Vec::new();
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
                    async fn fault<Q, G, W, S>(sumeragi: &mut S, m: SumeragiMessage)
                    where
                        Q: QueueTrait,
                        G: GenesisNetworkTrait,
                        W: WorldTrait,
                        S: Deref<Target = Sumeragi<Q, G, W>> + DerefMut + Send,
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
            CommitTimeout,
            TransactionReceived,
            TransactionForwarded,
            NoTransactionReceiptReceived,
            BlockCreationTimeout,
        );

        macro_rules! impl_handler_proxy(
            ( $name:ident : $( Handler< $msg:ty, Result = $ret:ty> $(+)? )* ) => {$(
                #[async_trait::async_trait]
                impl<R, F, Q, G, W> Handler<$msg> for $name<R, F, Q, G, W>
                where
                    R: ConstRoleTrait,
                    F: FaultBehaviour,
                    Q: QueueTrait,
                    G: GenesisNetworkTrait,
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
        pub struct Faulty<R, F, Q, G, W>
        where
            R: ConstRoleTrait,
            F: FaultBehaviour,
            Q: QueueTrait,
            G: GenesisNetworkTrait,
            W: WorldTrait,
        {
            sumeragi: Sumeragi<Q, G, W>,
            _faulty: PhantomData<(R, F)>,
        }

        impl<R, F, Q, G, W> Deref for Faulty<R, F, Q, G, W>
        where
            R: ConstRoleTrait,
            F: FaultBehaviour,
            Q: QueueTrait,
            G: GenesisNetworkTrait,
            W: WorldTrait,
        {
            type Target = Sumeragi<Q, G, W>;
            fn deref(&self) -> &Self::Target {
                &self.sumeragi
            }
        }

        impl<R, F, Q, G, W> DerefMut for Faulty<R, F, Q, G, W>
        where
            R: ConstRoleTrait,
            F: FaultBehaviour,
            Q: QueueTrait,
            G: GenesisNetworkTrait,
            W: WorldTrait,
        {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.sumeragi
            }
        }

        impl<R, F, Q, G, W> Faulty<R, F, Q, G, W>
        where
            R: ConstRoleTrait,
            F: FaultBehaviour,
            Q: QueueTrait,
            G: GenesisNetworkTrait,
            W: WorldTrait,
        {
            pub fn new(sumeragi: Sumeragi<Q, G, W>) -> Self {
                Self {
                    sumeragi,
                    _faulty: PhantomData::default(),
                }
            }
        }

        #[async_trait::async_trait]
        impl<R, F, Q, G, W> Actor for Faulty<R, F, Q, G, W>
        where
            R: ConstRoleTrait,
            F: FaultBehaviour,
            Q: QueueTrait,
            G: GenesisNetworkTrait,
            W: WorldTrait,
        {
            async fn on_start(&mut self, ctx: &mut Context<Self>) {
                self.broker.subscribe::<UpdateNetworkTopology, _>(ctx);
                self.broker.subscribe::<SumeragiMessage, _>(ctx);
                self.broker.subscribe::<Init, _>(ctx);
                self.broker.subscribe::<CommitBlock, _>(ctx);
            }
        }

        impl<R, F, Q, G, W> SumeragiTrait for Faulty<R, F, Q, G, W>
        where
            R: ConstRoleTrait,
            F: FaultBehaviour,
            Q: QueueTrait,
            G: GenesisNetworkTrait,
            W: WorldTrait,
        {
            type Queue = Q;
            type GenesisNetwork = G;
            type World = W;

            fn from_configuration(
                configuration: &config::SumeragiConfiguration,
                events_sender: EventsSender,
                wsv: Arc<WorldStateView<W>>,
                permissions_validator: InstructionPermissionsValidatorBox<W>,
                genesis_network: Option<Self::GenesisNetwork>,
                queue: AlwaysAddr<Self::Queue>,
                broker: Broker,
            ) -> Result<Self> {
                Sumeragi::from_configuration(
                    configuration,
                    events_sender,
                    wsv,
                    permissions_validator,
                    genesis_network,
                    queue,
                    broker,
                )
                .map(Self::new)
            }
        }

        #[async_trait::async_trait]
        impl<R, F, Q, G, W> Handler<Init> for Faulty<R, F, Q, G, W>
        where
            R: ConstRoleTrait,
            F: FaultBehaviour,
            Q: QueueTrait,
            G: GenesisNetworkTrait,
            W: WorldTrait,
        {
            type Result = ();
            async fn handle(
                &mut self,
                Init {
                    latest_block_hash,
                    height,
                }: Init,
            ) {
                if height != 0 && latest_block_hash != Hash([0; 32]) {
                    self.init(latest_block_hash, height);
                } else if let Some(genesis_network) = self.genesis_network.take() {
                    if let Err(err) = genesis_network.submit_transactions(&mut self).await {
                        iroha_logger::error!("Failed to submit genesis transactions: {}", err)
                    }
                }
                self.update_network_topology().await;
            }
        }

        impl_handler_proxy!(
            Faulty: Handler<UpdateNetworkTopology, Result = ()>
                     + Handler<CommitBlock, Result = ()>
                     + Handler<GetNetworkTopology, Result = InitializedNetworkTopology>
                     + Handler<GetSortedPeers, Result = Vec<PeerId>>
                     + Handler<IsLeader, Result = bool>
                     + Handler<GetLeader, Result = PeerId>
        );

        #[derive(Debug, Clone, Copy, Default, Message)]
        #[message(result = "InitializedNetworkTopology")]
        pub struct NetworkTopology;

        #[async_trait::async_trait]
        impl<R, F, Q, G, W> Handler<NetworkTopology> for Faulty<R, F, Q, G, W>
        where
            R: ConstRoleTrait,
            F: FaultBehaviour,
            Q: QueueTrait,
            G: GenesisNetworkTrait,
            W: WorldTrait,
        {
            type Result = InitializedNetworkTopology;
            async fn handle(&mut self, _: NetworkTopology) -> Self::Result {
                self.network_topology.clone()
            }
        }

        #[async_trait::async_trait]
        impl<R, F, Q, G, W> Handler<SumeragiMessage> for Faulty<R, F, Q, G, W>
        where
            R: ConstRoleTrait,
            F: FaultBehaviour,
            Q: QueueTrait,
            G: GenesisNetworkTrait,
            W: WorldTrait,
        {
            type Result = ();
            async fn handle(&mut self, msg: SumeragiMessage) -> Self::Result {
                if R::role(self.network_topology.role(&self.peer_id)) {
                    F::fault(&mut *self, msg).await;
                } else {
                    drop(msg.handle(&mut *self).await);
                }
            }
        }

        #[derive(Debug, Clone, Copy, Message)]
        #[message(result = "Vec<Hash>")]
        pub struct InvalidBlocks;

        #[async_trait::async_trait]
        impl<R, F, Q, G, W> Handler<InvalidBlocks> for Faulty<R, F, Q, G, W>
        where
            R: ConstRoleTrait,
            F: FaultBehaviour,
            Q: QueueTrait,
            G: GenesisNetworkTrait,
            W: WorldTrait,
        {
            type Result = Vec<Hash>;
            async fn handle(&mut self, _: InvalidBlocks) -> Self::Result {
                self.invalidated_blocks_hashes.clone()
            }
        }

        #[derive(Debug, Clone, Message)]
        pub struct Round(pub Vec<VersionedAcceptedTransaction>);

        #[async_trait::async_trait]
        impl<R, F, Q, G, W> Handler<Round> for Faulty<R, F, Q, G, W>
        where
            R: ConstRoleTrait,
            F: FaultBehaviour,
            Q: QueueTrait,
            G: GenesisNetworkTrait,
            W: WorldTrait,
        {
            type Result = ();
            async fn handle(&mut self, Round(txs): Round) -> Self::Result {
                drop(self.round(txs).await);
            }
        }

        #[async_trait::async_trait]
        impl<Q, G, W> Handler<Round> for Sumeragi<Q, G, W>
        where
            Q: QueueTrait,
            G: GenesisNetworkTrait,
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

        use iroha::prelude::*;
        use iroha::{tx::Domain, wsv::WorldTrait};
        use iroha_data_model::prelude::*;
        use iroha_data_model::world::World;
        use once_cell::sync::Lazy;

        #[derive(Debug, Clone, Default)]
        pub struct WithRoot(World);

        impl Deref for WithRoot {
            type Target = World;
            fn deref(&self) -> &World {
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
            drop(domain.accounts.insert(ROOT_ID.clone(), ROOT.clone()));
            domain
        });

        impl WorldTrait for WithRoot {
            /// Creates `World` with these `domains` and `trusted_peers_ids`
            fn with(
                domains: impl IntoIterator<Item = (Name, Domain)>,
                trusted_peers_ids: impl IntoIterator<Item = PeerId>,
            ) -> Self {
                Self(iroha_data_model::world::World::with(
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
            let tx = VersionedAcceptedTransaction::from_transaction(tx, 4096).unwrap();
            dbg!(tx.hash());
            tx
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

async fn send_tx<W, G, Q, S, K, B>(network: &Network<W, G, Q, S, K, B>, to_leader: bool)
where
    W: WorldTrait,
    G: GenesisNetworkTrait,
    Q: QueueTrait<World = W>,
    S: SumeragiTrait<Queue = Q, GenesisNetwork = G, World = W> + Handler<sumeragi::Round>,
    K: KuraTrait<World = W>,
    B: BlockSynchronizerTrait<Sumeragi = S, World = W>,
{
    let tx = world::sign_tx(vec![]);
    let leader = network.send(|iroha| &iroha.sumeragi, IsLeader).await;
    let (_, peer) = leader
        .into_iter()
        .zip(network.peers())
        .find(|(leader, _)| if to_leader { *leader } else { !*leader })
        .unwrap();
    peer.iroha
        .as_ref()
        .unwrap()
        .sumeragi
        .do_send(sumeragi::Round(vec![tx]))
        .await;
}

async fn get_topology_with_shift<W, G, Q, S, K, B>(
    network: &Network<W, G, Q, S, K, B>,
    shift: u32,
) -> InitializedNetworkTopology
where
    W: WorldTrait,
    G: GenesisNetworkTrait,
    Q: QueueTrait<World = W>,
    S: SumeragiTrait<Queue = Q, GenesisNetwork = G, World = W> + Handler<sumeragi::NetworkTopology>,
    K: KuraTrait<World = W>,
    B: BlockSynchronizerTrait<Sumeragi = S, World = W>,
{
    let mut expected = network
        .genesis
        .iroha
        .as_ref()
        .unwrap()
        .sumeragi
        .send(sumeragi::NetworkTopology)
        .await;
    expected.shift_peers_by_n(shift);
    expected
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "mock"]
async fn all_peers_commit_block() {
    iroha_error::install_panic_reporter();
    let (network, _) = <Network<
        world::WithRoot,
        genesis::NoGenesis,
        Queue<_>,
        Sumeragi<_, _, _>,
        kura::CountStored<_>,
        BlockSynchronizer<_, _>,
    >>::start_test(10, 1)
    .await;

    let mut channels = network
        .peers()
        .map(|peer| peer.broker.subscribe_with_channel::<Stored>())
        .collect::<Vec<_>>();

    // Send tx to leader
    send_tx(&network, true).await;
    time::sleep(Duration::from_secs(2)).await;

    blocks_applied(&mut channels, 1).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "mock"]
async fn change_view_on_commit_timeout() {
    iroha_error::install_panic_reporter();
    let (network, _) = <Network<
        world::WithRoot,
        genesis::NoGenesis,
        Queue<_>,
        sumeragi::Faulty<sumeragi::ProxyTail, sumeragi::Skip<sumeragi::BlockSigned>, _, _, _>,
        kura::CountStored<_>,
        BlockSynchronizer<_, _>,
    >>::start_test(10, 1)
    .await;

    let mut channels = network
        .peers()
        .map(|peer| peer.broker.subscribe_with_channel::<Stored>())
        .collect::<Vec<_>>();
    let expected = get_topology_with_shift(&network, 1).await;

    // send to leader
    send_tx(&network, true).await;
    time::sleep(Duration::from_secs(2)).await;

    blocks_applied(&mut channels, 0).await;

    let got = network
        .send(|iroha| &iroha.sumeragi, sumeragi::NetworkTopology)
        .await;
    let blocks = network
        .send(|iroha| &iroha.sumeragi, sumeragi::InvalidBlocks)
        .await;

    for (got, b) in got.into_iter().zip(blocks) {
        assert_eq!(expected.sorted_peers, got.sorted_peers);
        assert_eq!(b.len(), 1);
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "mock"]
async fn change_view_on_tx_receipt_timeout() {
    iroha_error::install_panic_reporter();
    let (network, _) = <Network<
        world::WithRoot,
        genesis::NoGenesis,
        Queue<_>,
        sumeragi::Faulty<sumeragi::Leader, sumeragi::Skip<sumeragi::TransactionForwarded>, _, _, _>,
        kura::CountStored<_>,
        BlockSynchronizer<_, _>,
    >>::start_test(10, 1)
    .await;

    let mut channels = network
        .peers()
        .map(|peer| peer.broker.subscribe_with_channel::<Stored>())
        .collect::<Vec<_>>();
    let expected = get_topology_with_shift(&network, 1).await;
    //
    // send to not leader
    send_tx(&network, false).await;
    time::sleep(Duration::from_secs(2)).await;

    blocks_applied(&mut channels, 0).await;

    let got = network
        .send(|iroha| &iroha.sumeragi, sumeragi::NetworkTopology)
        .await;

    for got in got {
        assert_eq!(expected.sorted_peers, got.sorted_peers);
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "mock"]
async fn change_view_on_block_creation_timeout() {
    iroha_error::install_panic_reporter();
    let (network, _) = <Network<
        world::WithRoot,
        genesis::NoGenesis,
        Queue<_>,
        sumeragi::Faulty<sumeragi::Any, sumeragi::Skip<sumeragi::BlockCreated>, _, _, _>,
        kura::CountStored<_>,
        BlockSynchronizer<_, _>,
    >>::start_test(10, 1)
    .await;

    let mut channels = network
        .peers()
        .map(|peer| peer.broker.subscribe_with_channel::<Stored>())
        .collect::<Vec<_>>();
    let expected = get_topology_with_shift(&network, 1).await;

    // send to not leader
    send_tx(&network, false).await;
    time::sleep(Duration::from_secs(2)).await;

    blocks_applied(&mut channels, 0).await;

    let got = network
        .send(|iroha| &iroha.sumeragi, sumeragi::NetworkTopology)
        .await;

    for got in got {
        assert_eq!(expected.sorted_peers, got.sorted_peers);
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "mock"]
async fn not_enough_votes() {
    iroha_error::install_panic_reporter();
    let (network, _) = <Network<
        world::WithRoot,
        genesis::NoGenesis,
        Queue<_>,
        sumeragi::Faulty<sumeragi::Any, sumeragi::Empty<sumeragi::BlockCreated>, _, _, _>,
        kura::CountStored<_>,
        BlockSynchronizer<_, _>,
    >>::start_test(10, 1)
    .await;

    let mut channels = network
        .peers()
        .map(|peer| peer.broker.subscribe_with_channel::<Stored>())
        .collect::<Vec<_>>();
    let expected = get_topology_with_shift(&network, 1).await;

    // send to not leader
    send_tx(&network, true).await;
    time::sleep(Duration::from_secs(2)).await;

    blocks_applied(&mut channels, 0).await;

    let got = network
        .send(|iroha| &iroha.sumeragi, sumeragi::NetworkTopology)
        .await;
    let blocks = network
        .send(|iroha| &iroha.sumeragi, sumeragi::InvalidBlocks)
        .await;

    for (got, blocks) in got.into_iter().zip(blocks) {
        assert_eq!(expected.sorted_peers, got.sorted_peers);
        assert_eq!(blocks.len(), 1);
    }
}
