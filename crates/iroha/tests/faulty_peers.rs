use std::time::Duration;

use eyre::Result;
use futures_util::{stream::FuturesUnordered, StreamExt};
use iroha_config_base::toml::WriteExt;
use iroha_data_model::{
    asset::AssetDefinition, isi::Register, parameter::BlockParameter, prelude::*, Level,
};
use iroha_test_network::{
    genesis_factory, once_blocks_sync, Network, NetworkBuilder, PeerLifecycleEvent,
};
use iroha_test_samples::ALICE_ID;
use nonzero_ext::nonzero;
use rand::{prelude::SliceRandom, thread_rng};
use relay::P2pRelay;
use tokio::{self, task::spawn_blocking, time::timeout};

mod relay {
    use std::{
        collections::HashMap,
        iter::once,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
    };

    use futures_util::{stream::FuturesUnordered, StreamExt};
    use iroha_data_model::peer::PeerId;
    use iroha_primitives::{
        addr::{socket_addr, SocketAddr},
        unique_vec::UniqueVec,
    };
    use iroha_test_network::fslock_ports::AllocatedPort;
    use tokio::{
        io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        select,
        sync::Notify,
        task::JoinSet,
    };

    #[derive(Debug)]
    pub struct P2pRelay {
        peers: HashMap<PeerId, RelayPeer>,
        tasks: JoinSet<()>,
    }

    #[derive(Debug)]
    struct RelayPeer {
        real_addr: SocketAddr,
        mock_outgoing: HashMap<PeerId, (SocketAddr, AllocatedPort)>,
        suspend: Suspend,
    }

    impl P2pRelay {
        pub fn new(real_topology: &UniqueVec<PeerId>) -> Self {
            let peers: HashMap<_, _> = real_topology
                .iter()
                .map(|peer_id| {
                    let real_addr = peer_id.address().clone();
                    let mock_outgoing = real_topology
                        .iter()
                        .filter(|x| *x != peer_id)
                        .map(|other_id| {
                            let mock_port = AllocatedPort::new();
                            let mock_addr = socket_addr!(127.0.0.1:*mock_port);
                            (other_id.clone(), (mock_addr, mock_port))
                        })
                        .collect();
                    let peer = RelayPeer {
                        real_addr,
                        mock_outgoing,
                        suspend: Suspend::new(),
                    };
                    (peer_id.clone(), peer)
                })
                .collect();

            let mut table = ascii_table::AsciiTable::default();
            table.set_max_width(30 * (1 + real_topology.len()));
            table.column(0).set_header("From");
            for (i, id) in real_topology.iter().enumerate() {
                table
                    .column(i + 1)
                    .set_header(format!("To {}", id.address()));
            }
            table.print(real_topology.iter().map(|id| {
                once(format!("{}", id.address()))
                    .chain(real_topology.iter().map(|peer_id| {
                        if *peer_id == *id {
                            "".to_string()
                        } else {
                            let (mock_addr, _) =
                                peers.get(id).unwrap().mock_outgoing.get(peer_id).unwrap();
                            format!("{mock_addr}")
                        }
                    }))
                    .collect::<Vec<_>>()
            }));

            Self {
                peers,
                tasks: <_>::default(),
            }
        }

        pub fn topology_for(&self, peer: &PeerId) -> UniqueVec<PeerId> {
            self.peers
                .get(peer)
                .expect("existing peer must be supplied")
                .mock_outgoing
                .iter()
                .map(|(other, (addr, _port))| PeerId::new(addr.clone(), other.public_key().clone()))
                .chain(Some(peer.clone()))
                .collect()
        }

        pub fn start(&mut self) {
            for (_peer_id, peer) in self.peers.iter() {
                for (other_id, (other_mock_addr, _)) in peer.mock_outgoing.iter() {
                    let other_peer = self.peers.get(other_id).expect("must be present");
                    let suspend =
                        SuspendIfAny(vec![peer.suspend.clone(), other_peer.suspend.clone()]);

                    P2pRelay::run_proxy(
                        &mut self.tasks,
                        other_mock_addr.clone(),
                        other_peer.real_addr.clone(),
                        suspend,
                    );
                }
            }
        }

        fn run_proxy(
            tasks: &mut JoinSet<()>,
            from: SocketAddr,
            to: SocketAddr,
            suspend: SuspendIfAny,
        ) {
            eprintln!("proxy: {from} → {to}");
            let mut proxy = Proxy::new(from, to, suspend);

            tasks.spawn(async move {
                if let Err(err) = proxy.run().await {
                    eprintln!("proxy at {} exited with an error: {err}", proxy.from);
                } else {
                    eprintln!("proxy exited normally");
                }
            });
        }

        pub fn suspend(&self, peer: &PeerId) -> Suspend {
            self.peers
                .get(peer)
                .expect("must be present")
                .suspend
                .clone()
        }
    }

    #[derive(Clone, Debug, Default)]
    pub struct Suspend {
        active: Arc<AtomicBool>,
        notify: Arc<Notify>,
    }

    impl Suspend {
        fn new() -> Self {
            Self::default()
        }

        pub fn activate(&self) {
            self.active.store(true, Ordering::Release);
        }

        pub fn deactivate(&self) {
            self.active.store(false, Ordering::Release);
            self.notify.notify_waiters();
        }
    }

    #[derive(Clone, Debug)]
    struct SuspendIfAny(Vec<Suspend>);

    impl SuspendIfAny {
        async fn is_not_active(&self) {
            loop {
                let waited_for = self
                    .0
                    .iter()
                    .filter_map(|x| {
                        x.active
                            .load(Ordering::Acquire)
                            .then_some(x.notify.notified())
                    })
                    .collect::<FuturesUnordered<_>>()
                    .collect::<Vec<_>>()
                    .await
                    .len();
                if waited_for == 0 {
                    break;
                }
            }
        }
    }

    struct Proxy {
        from: SocketAddr,
        to: SocketAddr,
        suspend: SuspendIfAny,
    }

    impl Proxy {
        fn new(from: SocketAddr, to: SocketAddr, suspend: SuspendIfAny) -> Self {
            Self { from, to, suspend }
        }

        async fn run(&mut self) -> eyre::Result<()> {
            let listener = TcpListener::bind(self.from.to_string()).await?;
            loop {
                let (client, _) = listener.accept().await?;
                let server = TcpStream::connect(self.to.to_string()).await?;

                let (mut eread, mut ewrite) = client.into_split();
                let (mut oread, mut owrite) = server.into_split();

                let suspend = self.suspend.clone();
                let e2o =
                    tokio::spawn(
                        async move { Proxy::copy(&suspend, &mut eread, &mut owrite).await },
                    );
                let suspend = self.suspend.clone();
                let o2e =
                    tokio::spawn(
                        async move { Proxy::copy(&suspend, &mut oread, &mut ewrite).await },
                    );

                select! {
                    _ = e2o => {
                        // eprintln!("{} → {}: client-to-server closed ×", self.from, self.to);
                    },
                    _ = o2e => {
                        // eprintln!("{} → {}: server-to-client closed ×", self.from, self.to);
                    },
                }
            }
        }

        async fn copy<R, W>(
            suspend: &SuspendIfAny,
            mut reader: R,
            mut writer: W,
        ) -> std::io::Result<()>
        where
            R: AsyncRead + Unpin,
            W: AsyncWrite + Unpin,
        {
            // NOTE: stack overflow happens without the box
            let mut buf = Box::new([0u8; 2usize.pow(20)]);

            loop {
                suspend.is_not_active().await;

                let n = reader.read(&mut *buf).await?;
                if n == 0 {
                    break;
                }

                writer.write_all(&buf[..n]).await?;
            }

            Ok(())
        }
    }
}

async fn start_network_with_relay(network: &Network) -> Result<P2pRelay> {
    let relay = P2pRelay::new(&network.peers().iter().map(|peer| peer.id()).collect());

    timeout(
        network.peer_startup_timeout(),
        network
            .peers()
            .iter()
            .enumerate()
            .map(|(i, peer)| {
                let topology = relay.topology_for(&peer.id());
                let config = network
                    .config()
                    .write(["sumeragi", "trusted_peers"], &topology);
                // FIXME: the topology in genesis is part of the chain.
                //        After peers used their `sumeragi.trusted_peers` to connect and to receive the genesis,
                //        they all replace their topologies with the one from genesis. This breaks our intention of having different topologies for each peer.
                //        Should be fixed by #5117
                let genesis =
                    (i == 0).then(|| genesis_factory(network.genesis_isi().clone(), topology));
                async move {
                    // FIXME: await in parallel
                    peer.start(config, genesis.as_ref()).await;
                    peer.once(|e| matches!(e, PeerLifecycleEvent::ServerStarted))
                        .await;
                }
            })
            .collect::<FuturesUnordered<_>>()
            .collect::<Vec<_>>(),
    )
    .await?;

    Ok(relay)
}

#[tokio::test]
async fn network_starts_with_relay() -> Result<()> {
    let network = NetworkBuilder::new().with_peers(4).build();
    let mut relay = start_network_with_relay(&network).await?;

    relay.start();
    network.ensure_blocks(1).await?;

    Ok(())
}

#[tokio::test]
async fn network_doesnt_start_without_relay() -> Result<()> {
    let network = NetworkBuilder::new().with_peers(4).build();
    let _relay = start_network_with_relay(&network).await?;

    if let Ok(_) = timeout(
        Duration::from_secs(3),
        once_blocks_sync(network.peers().iter(), 1),
    )
    .await
    {
        panic!("network must not start!")
    };

    Ok(())
}

#[tokio::test]
async fn suspending_works() -> Result<()> {
    const SYNC: Duration = Duration::from_secs(3);
    const N_PEERS: usize = 4;
    const { assert!(N_PEERS > 0) };

    let network = NetworkBuilder::new().with_peers(N_PEERS).build();
    let mut relay = start_network_with_relay(&network).await?;
    // we will plug/unplug the last peer who doesn't have the genesis
    let last_peer = network
        .peers()
        .last()
        .expect("there are more than 0 of them");
    let suspend = relay.suspend(&last_peer.id());

    suspend.activate();
    relay.start();

    // all peers except the last one should get the genesis
    timeout(
        SYNC,
        once_blocks_sync(network.peers().iter().take(N_PEERS - 1), 1),
    )
    .await?;
    let Err(_) = timeout(SYNC, last_peer.once_block(1)).await else {
        panic!("should not get block within timeout!")
    };

    // unsuspend, the last peer should get the block too
    suspend.deactivate();
    timeout(SYNC, last_peer.once_block(1)).await?;

    Ok(())
}

#[tokio::test]
async fn block_after_genesis_is_synced() -> Result<()> {
    let network = NetworkBuilder::new().with_peers(4).build();
    let mut relay = start_network_with_relay(&network).await?;

    relay.start();
    network.ensure_blocks(1).await?;

    for peer in network.peers() {
        relay.suspend(&peer.id()).activate();
    }
    let client = network.client();
    spawn_blocking(move || client.submit(Log::new(Level::INFO, "tick".to_owned()))).await??;
    let Err(_) = timeout(
        Duration::from_secs(3),
        once_blocks_sync(network.peers().iter(), 2),
    )
    .await
    else {
        panic!("should not sync with relay being suspended")
    };
    for peer in network.peers() {
        relay.suspend(&peer.id()).deactivate();
    }
    network.ensure_blocks(2).await?;

    Ok(())
}

// ======= ACTUAL TESTS BEGIN HERE =======

struct UnstableNetwork {
    n_peers: usize,
    n_faulty_peers: usize,
    n_transactions: usize,
    force_soft_fork: bool,
}

impl UnstableNetwork {
    async fn run(self) -> Result<()> {
        assert!(self.n_peers > self.n_faulty_peers);

        let account_id = ALICE_ID.clone();
        let asset_definition_id: AssetDefinitionId = "camomile#wonderland".parse().expect("Valid");

        let network = NetworkBuilder::new()
            .with_peers(self.n_peers)
            .with_config(|cfg| {
                if self.force_soft_fork {
                    cfg.write(["sumeragi", "debug_force_soft_fork"], true);
                }
            })
            .with_genesis_instruction(SetParameter(Parameter::Block(
                BlockParameter::MaxTransactions(nonzero!(1u64)),
            )))
            .build();
        let mut relay = start_network_with_relay(&network).await?;

        relay.start();
        {
            let client = network.client();
            let isi =
                Register::asset_definition(AssetDefinition::numeric(asset_definition_id.clone()));
            spawn_blocking(move || client.submit_blocking(isi)).await??;
        }
        let init_blocks = 2;
        network.ensure_blocks(init_blocks).await?;

        for i in 0..self.n_transactions {
            // Make random peers faulty.
            let faulty: Vec<_> = network
                .peers()
                .choose_multiple(&mut thread_rng(), self.n_faulty_peers)
                .map(|peer| peer.id())
                .collect();
            for peer in &faulty {
                relay.suspend(peer).activate();
            }

            // When minted
            let quantity = Numeric::ONE;
            let mint_asset = Mint::asset_numeric(
                quantity,
                AssetId::new(asset_definition_id.clone(), account_id.clone()),
            );
            let client = network
                .peers()
                .iter()
                .find(|x| faulty.contains(&x.id()))
                .expect("there should be some working peers")
                .client();
            spawn_blocking(move || client.submit_blocking(mint_asset)).await??;

            // Then all non-faulty peers get the new block
            timeout(
                network.sync_timeout(),
                once_blocks_sync(
                    network.peers().iter().filter(|x| !faulty.contains(&x.id())),
                    init_blocks + (i as u64),
                ),
            )
            .await?;

            // Return all peers to normal function.
            for peer in &faulty {
                relay.suspend(peer).deactivate();
            }
        }

        // When network is sync at last
        network
            .ensure_blocks(init_blocks + self.n_transactions as u64)
            .await?;

        // Then there are N assets minted
        let client = network.client();
        let asset = spawn_blocking(move || {
            client
                .query(FindAssets)
                .filter_with(|asset| asset.id.definition_id.eq(asset_definition_id))
                .execute_all()
        })
        .await??
        .into_iter()
        .next()
        .expect("there should be 1 result");
        assert_eq!(
            asset.value,
            AssetValue::Numeric(Numeric::new(self.n_transactions as u128 + 1, 0))
        );

        Ok(())
    }
}

#[tokio::test]
async fn unstable_network_5_peers_1_fault() -> Result<()> {
    UnstableNetwork {
        n_peers: 5,
        n_faulty_peers: 1,
        n_transactions: 20,
        force_soft_fork: false,
    }
    .run()
    .await
}

// #[tokio::test]
// async fn soft_fork() {
//     let n_peers = 4;
//     let n_transactions = 20;
//     unstable_network(n_peers, 0, n_transactions, true, 10_830);
// }

#[tokio::test]
async fn unstable_network_8_peers_1_fault() -> Result<()> {
    UnstableNetwork {
        n_peers: 8,
        n_faulty_peers: 1,
        n_transactions: 20,
        force_soft_fork: false,
    }
    .run()
    .await
}

#[tokio::test]
// #[ignore = "This test does not guarantee to have positive outcome given a fixed time."]
async fn unstable_network_9_peers_2_faults() -> Result<()> {
    UnstableNetwork {
        n_peers: 9,
        n_faulty_peers: 2,
        n_transactions: 5,
        force_soft_fork: false,
    }
    .run()
    .await
}
