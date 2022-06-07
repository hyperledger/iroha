#![allow(
    clippy::restriction,
    missing_debug_implementations,
    clippy::future_not_send,
    clippy::pedantic
)]

use std::{
    collections::HashSet,
    fmt::Debug,
    ops::Deref,
    sync::{Arc, RwLock},
    time::Duration,
};

use eyre::Result;
use iroha_actor::prelude::*;
use iroha_core::{
    block_sync::{BlockSynchronizer, BlockSynchronizerTrait},
    genesis::{config::GenesisConfiguration, GenesisNetworkTrait},
    kura::KuraTrait,
    prelude::*,
    sumeragi::{
        fault::SumeragiWithFault,
        message::{Gossip, IsLeader, RetrieveTransactions},
        network_topology::Topology,
        Sumeragi, SumeragiTrait,
    },
    wsv::OriginalWorld,
};
use iroha_data_model::prelude::*;
use test_network::*;
use tokio::time;
use utils::{genesis, sumeragi, world};

pub mod utils {
    use iroha_core::genesis::RawGenesisBlock;

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
                _transaction_limits: &TransactionLimits,
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

    pub mod sumeragi {
        use std::{fmt::Debug, marker::PhantomData};

        use iroha_core::{
            genesis::GenesisNetworkTrait,
            kura::KuraTrait,
            sumeragi::{
                fault::{FaultInjection, SumeragiWithFault},
                message::Message as SumeragiMessage,
                network_topology::Role,
            },
        };

        pub trait ConstRoleTrait: Debug + Send + 'static {
            /// Returns true if this peer has this `role`
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
        pub struct EmptyBlockCreated;

        impl FaultInjection for EmptyBlockCreated {
            fn faulty_message<G, K>(
                _: &SumeragiWithFault<G, K, Self>,
                msg: SumeragiMessage,
            ) -> Option<SumeragiMessage>
            where
                G: GenesisNetworkTrait,
                K: KuraTrait,
            {
                let msg = if let SumeragiMessage::BlockCreated(mut block) = msg {
                    block.block.as_mut_v1().transactions = Vec::new();
                    SumeragiMessage::BlockCreated(block)
                } else {
                    msg
                };
                Some(msg)
            }
        }

        #[derive(Debug, Clone, Copy, Default)]
        pub struct Skip<M, R>(PhantomData<M>, PhantomData<R>);

        macro_rules! impl_skip {
            ( $($name:ident),* $(,)? ) => {$(
                #[derive(Debug, Clone, Copy, Default)]
                pub struct $name;

                impl<R: ConstRoleTrait + Send + Sync> FaultInjection for Skip<$name, R> {
                    fn faulty_message<G, K>(
                        sumeragi: &SumeragiWithFault<G, K, Self>,
                        msg: SumeragiMessage,
                    ) -> Option<SumeragiMessage>
                    where
                        G: GenesisNetworkTrait,
                        K: KuraTrait,
                    {
                        if let SumeragiMessage::$name(..) = msg {
                            if R::role(sumeragi.role()) {
                                iroha_logger::error!("Fault behaviour: Skipping {}", stringify!($name));
                                None
                            } else {
                                Some(msg)
                            }
                        } else {
                            Some(msg)
                        }
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

        #[derive(Debug, Clone, Copy, Default)]
        pub struct SkipTxForwardedAndGossipOnLeader;

        impl FaultInjection for SkipTxForwardedAndGossipOnLeader {
            fn faulty_message<G, K>(
                sumeragi: &SumeragiWithFault<G, K, Self>,
                msg: SumeragiMessage,
            ) -> Option<SumeragiMessage>
            where
                G: GenesisNetworkTrait,
                K: KuraTrait,
            {
                match (sumeragi.role(), msg) {
                    (Role::Leader, SumeragiMessage::TransactionForwarded(_))
                    | (Role::Leader, SumeragiMessage::TransactionGossip(_)) => {
                        iroha_logger::error!(
                            "Fault behaviour: Skipping TransactionForwarded and TransactionGossip"
                        );
                        None
                    }
                    (_, msg) => Some(msg),
                }
            }
        }
    }

    pub mod world {
        use std::str::FromStr as _;

        use iroha_core::{prelude::*, tx::Domain};
        use iroha_data_model::prelude::*;
        use once_cell::sync::Lazy;

        pub static ALICE_KEYS: Lazy<KeyPair> =
            Lazy::new(|| KeyPair::generate().expect("doesn't fail"));
        pub static ALICE: Lazy<Account> = Lazy::new(|| {
            let account_id = AccountId::from_str("alice@wonderland").expect("valid account name.");
            let mut account = Account::new(account_id, []).build();
            assert!(account.add_signatory(ALICE_KEYS.public_key().clone()));
            account
        });
        pub static WONDERLAND: Lazy<Domain> = Lazy::new(|| {
            let mut domain =
                Domain::new(DomainId::from_str("wonderland").expect("valid domain name")).build();
            assert!(domain.add_account(ALICE.clone()).is_none());
            domain
        });

        pub fn sign_tx(isi: impl IntoIterator<Item = Instruction>) -> VersionedAcceptedTransaction {
            let instructions: Vec<_> = isi.into_iter().collect();
            let tx = Transaction::new(ALICE.id().clone(), instructions.into(), 100_000)
                .sign(ALICE_KEYS.clone())
                .expect("Sign shall not fail");
            let tx_limits = TransactionLimits {
                max_instruction_number: 4096,
                max_wasm_size_bytes: 0,
            };
            VersionedAcceptedTransaction::from_transaction(tx, &tx_limits).expect("is valid")
        }
    }
}

/// Checks if blocks applied on all peers
async fn blocks_applied<G, S, K, B>(network: &Network<G, K, S, B>, n_blocks: usize)
where
    G: GenesisNetworkTrait,
    K: KuraTrait,
    S: SumeragiTrait<GenesisNetwork = G, Kura = K>,
    B: BlockSynchronizerTrait<Sumeragi = S>,
{
    for peer in network.peers() {
        assert_eq!(
            peer.iroha.as_ref().expect("Iroha initialised").wsv.height(),
            n_blocks as u64
        )
    }
}

async fn put_tx_in_queue_to_peer<G, S, K, B>(network: &Network<G, K, S, B>, to_leader: bool)
where
    G: GenesisNetworkTrait,
    K: KuraTrait,
    S: SumeragiTrait<GenesisNetwork = G, Kura = K>,
    B: BlockSynchronizerTrait<Sumeragi = S>,
{
    let tx = world::sign_tx(vec![]);
    let leader = network
        .send_to_actor_on_peers(|iroha| &iroha.sumeragi, IsLeader)
        .await;
    let (_, peer) = leader
        .into_iter()
        .find(|(leader, _)| if to_leader { *leader } else { !*leader })
        .expect("guaranteed one leader");
    let peer = network.peer_by_id(&peer).expect("guaranteed, leader");
    peer.iroha
        .as_ref()
        .expect("Iroha initialised")
        .queue
        .push(tx)
        .expect("queue is not full, and tx is correctly formed");
}

async fn put_tx_in_queue_to_all<G, S, K, B>(network: &Network<G, K, S, B>)
where
    G: GenesisNetworkTrait,
    K: KuraTrait,
    S: SumeragiTrait<GenesisNetwork = G, Kura = K>,
    B: BlockSynchronizerTrait<Sumeragi = S>,
{
    let tx = world::sign_tx(vec![]);
    for peer in network.peers() {
        peer.iroha
            .as_ref()
            .expect("Iroha initialised")
            .queue
            .push(tx.clone())
            .expect("queue is not full, and tx is correctly formed");
    }
}

async fn round<G, S, K, B>(network: &Network<G, K, S, B>)
where
    G: GenesisNetworkTrait,
    K: KuraTrait,
    S: SumeragiTrait<GenesisNetwork = G, Kura = K>,
    B: BlockSynchronizerTrait<Sumeragi = S>,
{
    for peer in network.peers() {
        peer.iroha
            .as_ref()
            .expect("Iroha initialised")
            .sumeragi
            .do_send(RetrieveTransactions)
            .await;
    }
}

/// Setup [`World`] Mock
///
/// Should be called from the beginning of all tests.
/// Not implemented as function because of weird return type of context
macro_rules! setup_context {
    () => {{
        let original_world: Arc<RwLock<Option<OriginalWorld>>> = Arc::new(RwLock::new(None));
        let world_clone = Arc::clone(&original_world);

        let with_context = World::with_context();
        with_context
            // Array and HashSet are used cause this generic method instantiation is used in tests
            .expect::<[Domain; 1], HashSet<PeerId>>()
            .returning(move |domains, peers| {
                {
                    let mut world_clone_write = world_clone.write().unwrap();
                    *world_clone_write = Some(OriginalWorld::with(
                        domains.into_iter().chain([world::WONDERLAND.clone()]),
                        peers,
                    ));
                }

                let world_clone_read =  world_clone.read().unwrap();
                let orig: &OriginalWorld = world_clone_read.as_ref().unwrap();

                // The next expectations are empirical
                // and can be unique for different test scenarios

                let mut mock = World::default();
                mock
                    .expect_trusted_peers_ids()
                    .return_const(
                        orig.trusted_peers_ids().clone()
                    );
                mock
                    .expect_domains()
                    .return_const(
                        orig.domains().clone()
                    );

                let mut mock2 = World::default();
                mock2
                    .expect_domains()
                    .return_const(
                        orig.domains().clone()
                    );

                mock
                    .expect_clone()
                    .return_once(move || mock2);
                mock
                    .expect_triggers()
                    .return_const(
                        orig.triggers().clone()
                    );
                mock
            });

        (with_context, original_world)
    }};
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "mock"]
async fn all_peers_commit_block() {
    let (_context, _original_world) = setup_context!();

    iroha_logger::install_panic_hook().expect("first installation");
    let (network, _) = <Network<
        genesis::NoGenesis,
        iroha_core::kura::Kura,
        Sumeragi<_, _>,
        BlockSynchronizer<_>,
    >>::start_test(10, 1)
    .await;

    // Send tx to leader
    put_tx_in_queue_to_peer(&network, true).await;
    round(&network).await;
    time::sleep(Duration::from_secs(2)).await;

    blocks_applied(&network, 1).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "mock"]
async fn change_view_on_commit_timeout() {
    let (_context, _original_world) = setup_context!();

    iroha_logger::install_panic_hook().expect("first installation");
    let (network, _) = <Network<
        genesis::NoGenesis,
        iroha_core::kura::Kura,
        SumeragiWithFault<_, _, sumeragi::Skip<sumeragi::BlockSigned, sumeragi::ProxyTail>>,
        BlockSynchronizer<_>,
    >>::start_test(10, 1)
    .await;

    // Send tx to leader
    put_tx_in_queue_to_peer(&network, true).await;
    round(&network).await;
    time::sleep(Duration::from_secs(4)).await;

    blocks_applied(&network, 0).await;

    let topologies = network
        .send_to_actor_on_peers(
            |iroha| &iroha.sumeragi,
            iroha_core::sumeragi::message::CurrentNetworkTopology,
        )
        .await;
    let invalid_block_hashes = network
        .send_to_actor_on_peers(
            |iroha| &iroha.sumeragi,
            iroha_core::sumeragi::message::InvalidatedBlockHashes,
        )
        .await;

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
    let (_context, _original_world) = setup_context!();

    iroha_logger::install_panic_hook().expect("first installation");
    let (network, _) = <Network<
        genesis::NoGenesis,
        iroha_core::kura::Kura,
        SumeragiWithFault<_, _, sumeragi::SkipTxForwardedAndGossipOnLeader>,
        BlockSynchronizer<_>,
    >>::start_test(10, 1)
    .await;

    // send to not leader
    put_tx_in_queue_to_peer(&network, false).await;

    // Let peers gossip tx.
    for peer in network.peers() {
        peer.iroha
            .as_ref()
            .expect("Iroha initialised")
            .sumeragi
            .do_send(Gossip)
            .await;
    }

    // Wait while tx is gossiped
    time::sleep(Duration::from_millis(500)).await;

    // Let peers retrieve the gossiped tx and send to leader, so they can all understand the leader is unresponsive.
    for peer in network.peers() {
        peer.iroha
            .as_ref()
            .expect("Iroha initialised")
            .sumeragi
            .do_send(RetrieveTransactions)
            .await;
    }

    time::sleep(Duration::from_secs(3)).await;

    blocks_applied(&network, 0).await;

    let topologies = network
        .send_to_actor_on_peers(
            |iroha| &iroha.sumeragi,
            iroha_core::sumeragi::message::CurrentNetworkTopology,
        )
        .await;
    for (topology, _) in topologies {
        assert_eq!(topology.view_change_proofs().len(), 1);
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "mock"]
async fn change_view_on_block_creation_timeout() {
    let (_context, _original_world) = setup_context!();

    iroha_logger::install_panic_hook().expect("first installation");
    let (network, _) = <Network<
        genesis::NoGenesis,
        iroha_core::kura::Kura,
        SumeragiWithFault<_, _, sumeragi::Skip<sumeragi::BlockCreated, sumeragi::Any>>,
        BlockSynchronizer<_>,
    >>::start_test(10, 1)
    .await;

    // send to not leader
    put_tx_in_queue_to_all(&network).await;
    round(&network).await;
    time::sleep(Duration::from_secs(3)).await;

    blocks_applied(&network, 0).await;

    let topologies = network
        .send_to_actor_on_peers(
            |iroha| &iroha.sumeragi,
            iroha_core::sumeragi::message::CurrentNetworkTopology,
        )
        .await;

    for (topology, _) in topologies {
        assert_eq!(topology.view_change_proofs().len(), 1);
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "mock"]
async fn not_enough_votes() {
    let (_context, _original_world) = setup_context!();

    iroha_logger::install_panic_hook().expect("first installation");
    let (network, _) = <Network<
        genesis::NoGenesis,
        iroha_core::kura::Kura,
        SumeragiWithFault<_, _, sumeragi::EmptyBlockCreated>,
        BlockSynchronizer<_>,
    >>::start_test(10, 1)
    .await;

    put_tx_in_queue_to_peer(&network, true).await;
    round(&network).await;
    time::sleep(Duration::from_secs(4)).await;

    blocks_applied(&network, 0).await;

    let topologies = network
        .send_to_actor_on_peers(
            |iroha| &iroha.sumeragi,
            iroha_core::sumeragi::message::CurrentNetworkTopology,
        )
        .await;
    let invalid_block_hashes = network
        .send_to_actor_on_peers(
            |iroha| &iroha.sumeragi,
            iroha_core::sumeragi::message::InvalidatedBlockHashes,
        )
        .await;

    for (topology, _) in topologies {
        assert_eq!(topology.view_change_proofs().len(), 1);
    }
    for (hashes, _) in invalid_block_hashes {
        assert_eq!(hashes.len(), 1);
    }
}
