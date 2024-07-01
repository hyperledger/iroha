//! Module for starting peers and networks. Used only for tests
use core::{fmt::Debug, time::Duration};
use std::{collections::BTreeMap, ops::Deref, path::Path, sync::Arc, thread};

use eyre::Result;
use futures::{prelude::*, stream::FuturesUnordered};
use iroha::{
    client::Client,
    config::Config as ClientConfig,
    data_model::{isi::Instruction, peer::Peer as DataModelPeer, prelude::*},
};
use iroha_config::parameters::actual::{Root as Config, Sumeragi, TrustedPeers};
pub use iroha_core::state::StateReadOnly;
use iroha_crypto::{ExposedPrivateKey, KeyPair};
use iroha_data_model::{asset::AssetDefinitionId, isi::InstructionBox, ChainId};
use iroha_executor_data_model::permission::{
    asset::{CanBurnAssetWithDefinition, CanMintAssetWithDefinition},
    domain::CanUnregisterDomain,
    executor::CanUpgradeExecutor,
    peer::CanUnregisterAnyPeer,
    role::CanUnregisterAnyRole,
};
use iroha_genesis::{GenesisBlock, RawGenesisTransaction};
use iroha_logger::{warn, InstrumentFutures};
use iroha_primitives::{
    addr::{socket_addr, SocketAddr},
    unique_vec::UniqueVec,
};
use irohad::Iroha;
use rand::{prelude::SliceRandom, seq::IteratorRandom, thread_rng};
use tempfile::TempDir;
use test_samples::{ALICE_ID, ALICE_KEYPAIR, PEER_KEYPAIR, SAMPLE_GENESIS_ACCOUNT_KEYPAIR};
use tokio::{
    runtime::{self, Runtime},
    time,
};
pub use unique_port;

/// Network of peers
pub struct Network {
    /// First peer, guaranteed to be online and submit genesis block.
    pub first_peer: Peer,
    /// Peers excluding the `first_peer`. Use [`Network::peers`] function to get all instead.
    ///
    /// [`BTreeMap`] is used in order to have deterministic order of peers.
    pub peers: BTreeMap<PeerId, Peer>,
}

/// Get a standardized blockchain id
pub fn get_chain_id() -> ChainId {
    ChainId::from("00000000-0000-0000-0000-000000000000")
}

/// Get a key pair of a common signatory in the test network
pub fn get_key_pair(signatory: Signatory) -> KeyPair {
    match signatory {
        Signatory::Peer => &PEER_KEYPAIR,
        Signatory::Genesis => &SAMPLE_GENESIS_ACCOUNT_KEYPAIR,
        Signatory::Alice => &ALICE_KEYPAIR,
    }
    .deref()
    .clone()
}

/// A common signatory in the test network
pub enum Signatory {
    Peer,
    Genesis,
    Alice,
}

/// Trait used to differentiate a test instance of `genesis`.
pub trait TestGenesis: Sized {
    /// Construct Iroha genesis
    fn test(topology: Vec<PeerId>) -> Self {
        Self::test_with_instructions::<InstructionBox>([], topology)
    }

    /// Construct genesis with additional instructions
    fn test_with_instructions<T: Instruction>(
        extra_isi: impl IntoIterator<Item = T>,
        topology: Vec<PeerId>,
    ) -> Self;
}

impl TestGenesis for GenesisBlock {
    fn test_with_instructions<T: Instruction>(
        extra_isi: impl IntoIterator<Item = T>,
        topology: Vec<PeerId>,
    ) -> Self {
        let cfg = Config::test();

        // TODO: Fix this somehow. Probably we need to make `kagami` a library (#3253).
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut genesis =
            RawGenesisTransaction::from_path(manifest_dir.join("../../defaults/genesis.json"))
                .expect("Failed to deserialize genesis block from file");

        let rose_definition_id = "rose#wonderland".parse::<AssetDefinitionId>().unwrap();

        let grant_mint_rose_permission = Grant::account_permission(
            CanMintAssetWithDefinition {
                asset_definition: rose_definition_id.clone(),
            },
            ALICE_ID.clone(),
        );
        let grant_burn_rose_permission = Grant::account_permission(
            CanBurnAssetWithDefinition {
                asset_definition: rose_definition_id,
            },
            ALICE_ID.clone(),
        );
        let grant_unregister_any_peer_permission =
            Grant::account_permission(CanUnregisterAnyPeer, ALICE_ID.clone());
        let grant_unregister_any_role_permission =
            Grant::account_permission(CanUnregisterAnyRole, ALICE_ID.clone());
        let grant_unregister_wonderland_domain = Grant::account_permission(
            CanUnregisterDomain {
                domain: "wonderland".parse().unwrap(),
            },
            ALICE_ID.clone(),
        );
        let grant_upgrade_executor_permission =
            Grant::account_permission(CanUpgradeExecutor, ALICE_ID.clone());
        for isi in [
            grant_mint_rose_permission,
            grant_burn_rose_permission,
            grant_unregister_any_peer_permission,
            grant_unregister_any_role_permission,
            grant_unregister_wonderland_domain,
            grant_upgrade_executor_permission,
        ] {
            genesis.append_instruction(isi);
        }

        for isi in extra_isi.into_iter() {
            genesis.append_instruction(isi);
        }

        let genesis_key_pair = SAMPLE_GENESIS_ACCOUNT_KEYPAIR.clone();
        if &cfg.genesis.public_key != genesis_key_pair.public_key() {
            panic!("`Config::test` expected to use SAMPLE_GENESIS_ACCOUNT_KEYPAIR");
        }
        genesis
            .with_topology(topology)
            .build_and_sign(&genesis_key_pair)
            .expect("genesis should load fine")
    }
}

pub struct NetworkBuilder {
    n_peers: u32,
    port: Option<u16>,
    config: Option<Config>,
    /// Number of offline peers.
    /// By default all peers are online.
    offline_peers: Option<u32>,
    /// Number of peers which will submit genesis.
    /// By default only first peer submits genesis.
    genesis_peers: Option<u32>,
}

impl NetworkBuilder {
    pub fn new(n_peers: u32, port: Option<u16>) -> Self {
        assert_ne!(n_peers, 0);
        Self {
            n_peers,
            port,
            config: None,
            offline_peers: None,
            genesis_peers: None,
        }
    }

    #[must_use]
    pub fn with_config(mut self, config: Config) -> Self {
        self.config = Some(config);
        self
    }

    #[must_use]
    pub fn with_offline_peers(mut self, offline_peers: u32) -> Self {
        assert!(offline_peers < self.n_peers);
        self.offline_peers = Some(offline_peers);
        self
    }

    #[must_use]
    pub fn with_genesis_peers(mut self, genesis_peers: u32) -> Self {
        assert!(0 < genesis_peers && genesis_peers <= self.n_peers);
        self.genesis_peers = Some(genesis_peers);
        self
    }

    /// Creates new network with options provided.
    pub async fn create(self) -> Network {
        let (builders, mut peers) = self.prepare_peers();

        let peer_infos = self.generate_peer_infos();
        let mut config = self.config.unwrap_or_else(Config::test);
        let topology = peers.iter().map(|peer| peer.id.clone()).collect::<Vec<_>>();
        config.sumeragi.trusted_peers.value_mut().others = UniqueVec::from_iter(topology.clone());
        let genesis_block = GenesisBlock::test(topology);

        let futures = FuturesUnordered::new();
        for ((builder, peer), peer_info) in builders
            .into_iter()
            .zip(peers.iter_mut())
            .zip(peer_infos.iter())
        {
            match peer_info {
                PeerInfo::Offline => { /* peer offline, do nothing */ }
                PeerInfo::Online { is_genesis } => {
                    let future = builder
                        .with_config(config.clone())
                        .with_into_genesis(is_genesis.then(|| genesis_block.clone()))
                        .start_with_peer(peer);
                    futures.push(future);
                }
            }
        }
        futures.collect::<()>().await;
        time::sleep(Duration::from_millis(500) * (self.n_peers + 1)).await;

        assert_eq!(peer_infos[0], PeerInfo::Online { is_genesis: true });
        let first_peer = peers.remove(0);
        let other_peers = peers
            .into_iter()
            .map(|peer| (peer.id.clone(), peer))
            .collect::<BTreeMap<_, _>>();
        Network {
            first_peer,
            peers: other_peers,
        }
    }

    fn prepare_peers(&self) -> (Vec<PeerBuilder>, Vec<Peer>) {
        let mut builders = (0..self.n_peers)
            .map(|n| {
                let mut builder = PeerBuilder::new();
                if let Some(port) = self.port {
                    let offset: u16 = (n * 5)
                        .try_into()
                        .expect("The `n_peers` is too large to fit into `u16`");
                    builder = builder.with_port(port + offset)
                }
                builder
            })
            .collect::<Vec<_>>();
        let peers = builders
            .iter_mut()
            .map(PeerBuilder::build)
            .collect::<Result<Vec<_>>>()
            .expect("Failed to init peers");
        (builders, peers)
    }

    fn generate_peer_infos(&self) -> Vec<PeerInfo> {
        let n_peers = self.n_peers as usize;
        let n_offline_peers = self.offline_peers.unwrap_or(0) as usize;
        let n_genesis_peers = self.genesis_peers.unwrap_or(1) as usize;
        assert!(n_genesis_peers + n_offline_peers <= n_peers);

        let mut peers = (0..n_peers).collect::<Vec<_>>();
        let mut result = vec![PeerInfo::Online { is_genesis: false }; n_peers];

        // First n_genesis_peers will be genesis peers.
        // Last n_offline_peers will be offline peers.
        // First peer must be online and submit genesis so don't shuffle it.
        peers[1..].shuffle(&mut thread_rng());
        for &peer in &peers[0..n_genesis_peers] {
            result[peer] = PeerInfo::Online { is_genesis: true };
        }
        for &peer in peers.iter().rev().take(n_offline_peers) {
            result[peer] = PeerInfo::Offline;
        }
        result
    }

    /// Creates new network with options provided.
    /// Returns network and client for connecting to it.
    pub async fn create_with_client(self) -> (Network, Client) {
        let network = self.create().await;
        let client = Client::test(
            &Network::peers(&network)
                .choose(&mut thread_rng())
                .unwrap()
                .api_address,
        );
        (network, client)
    }

    /// Creates new network with options provided in a new async runtime.
    pub fn create_with_runtime(self) -> (Runtime, Network, Client) {
        let rt = Runtime::test();
        let (network, client) = rt.block_on(self.create_with_client());
        (rt, network, client)
    }
}

// Auxiliary enum for `NetworkBuilder::create` implementation
#[derive(Debug, Clone, Eq, PartialEq)]
enum PeerInfo {
    Online { is_genesis: bool },
    Offline,
}

impl Network {
    /// Collect the freeze handles from all the peers in the network.
    #[cfg(debug_assertions)]
    pub fn get_freeze_status_handles(&self) -> Vec<irohad::FreezeStatus> {
        self.peers()
            .filter_map(|peer| peer.irohad.as_ref())
            .map(|iroha| iroha.freeze_status())
            .cloned()
            .collect()
    }

    /// Starts network with peers with default configuration and
    /// specified options in a new async runtime.  Returns its info
    /// and client for connecting to it.
    pub fn start_test_with_runtime(
        n_peers: u32,
        start_port: Option<u16>,
    ) -> (Runtime, Self, Client) {
        NetworkBuilder::new(n_peers, start_port).create_with_runtime()
    }

    /// Adds peer to network and waits for it to start block
    /// synchronization.
    pub async fn add_peer(&self) -> (Peer, Client) {
        let client = Client::test(
            &Network::peers(self)
                .choose(&mut thread_rng())
                .unwrap()
                .api_address,
        );

        let mut config = Config::test();
        config.sumeragi.trusted_peers.value_mut().others =
            UniqueVec::from_iter(self.peers().map(|peer| &peer.id).cloned());

        let peer = PeerBuilder::new().with_config(config).start().await;

        time::sleep(Config::pipeline_time() + Config::block_sync_gossip_time()).await;

        let add_peer = Register::peer(DataModelPeer::new(peer.id.clone()));
        client.submit(add_peer).expect("Failed to add new peer.");

        let peer_client = Client::test(&peer.api_address);
        (peer, peer_client)
    }

    /// Returns all peers.
    pub fn peers(&self) -> impl Iterator<Item = &Peer> + '_ {
        std::iter::once(&self.first_peer).chain(self.peers.values())
    }

    /// Get active clients
    pub fn clients(&self) -> Vec<Client> {
        self.peers()
            .map(|peer| Client::test(&peer.api_address))
            .collect()
    }

    /// Get peer by its Id.
    pub fn peer_by_id(&self, id: &PeerId) -> Option<&Peer> {
        self.peers.get(id).or(if self.first_peer.id == *id {
            Some(&self.first_peer)
        } else {
            None
        })
    }
}

/// Wait for peers to have committed genesis block.
///
/// # Panics
/// When unsuccessful after `MAX_RETRIES`.
pub fn wait_for_genesis_committed(clients: &[Client], offline_peers: u32) {
    const MAX_RETRIES: u32 = 40;
    wait_for_genesis_committed_with_max_retries(clients, offline_peers, MAX_RETRIES)
}

/// Wait for peers to have committed genesis block for specified amount of retries.
/// Each retry once per second.
///
/// # Panics
/// When unsuccessful after `max_retries`.
pub fn wait_for_genesis_committed_with_max_retries(
    clients: &[Client],
    offline_peers: u32,
    max_retries: u32,
) {
    const POLL_PERIOD: Duration = Duration::from_millis(1000);

    for _ in 0..max_retries {
        let ready_peers = clients
            .iter()
            .map(|client| {
                let is_ready = match client.get_status() {
                    Ok(status) => status.blocks >= 1,
                    Err(error) => {
                        warn!("Error retrieving peer status: {:?}", error);
                        false
                    }
                };
                is_ready as u32
            })
            .sum::<u32>();

        let without_genesis_peers = clients.len() as u32 - ready_peers;
        if without_genesis_peers <= offline_peers {
            return;
        }
        thread::sleep(POLL_PERIOD);
    }
    panic!(
        "Failed to wait for online peers to commit genesis block. Total wait time: {:?}",
        POLL_PERIOD * max_retries
    );
}

/// Peer structure
pub struct Peer {
    /// The id of the peer
    pub id: PeerId,
    /// API address
    pub api_address: SocketAddr,
    /// P2P address
    pub p2p_address: SocketAddr,
    /// The key-pair for the peer
    pub key_pair: KeyPair,
    /// Iroha server
    pub irohad: Option<Iroha>,
    /// Temporary directory
    // Note: last field to be dropped after Iroha (struct fields drops in FIFO RFC 1857)
    pub temp_dir: Option<Arc<TempDir>>,
}

impl From<Peer> for Box<iroha_core::tx::Peer> {
    fn from(val: Peer) -> Self {
        Box::new(iroha_data_model::peer::Peer::new(val.id.clone()))
    }
}

impl std::cmp::PartialEq for Peer {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl std::cmp::Eq for Peer {}

impl Drop for Peer {
    fn drop(&mut self) {
        self.stop();
    }
}

impl Peer {
    /// Returns per peer config with all addresses, keys, and id set up.
    fn get_config(&self, config: Config) -> Config {
        use iroha_config::{
            base::WithOrigin,
            parameters::actual::{Common, Network, Torii},
        };

        let peer_id = PeerId::new(self.p2p_address.clone(), self.key_pair.public_key().clone());
        Config {
            common: Common {
                key_pair: self.key_pair.clone(),
                peer: peer_id.clone(),
                ..config.common
            },
            network: Network {
                address: WithOrigin::inline(self.p2p_address.clone()),
                ..config.network
            },
            torii: Torii {
                address: WithOrigin::inline(self.api_address.clone()),
                ..config.torii
            },
            sumeragi: Sumeragi {
                trusted_peers: WithOrigin::inline(TrustedPeers {
                    myself: peer_id,
                    others: config.sumeragi.trusted_peers.into_value().others,
                }),
                ..config.sumeragi
            },
            ..config
        }
    }

    /// Starts a peer with arguments.
    async fn start(
        &mut self,
        config: Config,
        genesis: Option<GenesisBlock>,
        temp_dir: Arc<TempDir>,
    ) {
        let mut config = self.get_config(config);
        *config.kura.store_dir.value_mut() = temp_dir.path().to_str().unwrap().into();
        let info_span = iroha_logger::info_span!(
            "test-peer",
            p2p_addr = %self.p2p_address,
            api_addr = %self.api_address,
        );
        let logger = iroha_logger::test_logger();

        let (_, irohad) = Iroha::start_network(config, genesis, logger)
            .instrument(info_span)
            .await
            .expect("Failed to start Iroha");

        self.irohad = Some(irohad);
        time::sleep(Duration::from_millis(300)).await;
        // Prevent temporary directory deleting
        self.temp_dir = Some(temp_dir);
    }

    /// Stop the peer if it's running
    pub fn stop(&mut self) {
        iroha_logger::info!(
            p2p_addr = %self.p2p_address,
            api_addr = %self.api_address,
            "Stopping peer",
        );

        iroha_logger::info!("Shutting down peer...");
        self.irohad.take();
    }

    /// Creates peer
    ///
    /// # Errors
    /// * If can't get a unique port for
    /// - `p2p_address`
    /// - `api_address`
    /// * If keypair generation fails
    pub fn new() -> Result<Self> {
        let key_pair = KeyPair::random();
        let p2p_address = local_unique_port()?;
        let api_address = local_unique_port()?;
        let id = PeerId::new(p2p_address.clone(), key_pair.public_key().clone());
        Ok(Self {
            id,
            key_pair,
            p2p_address,
            api_address,
            irohad: None,
            temp_dir: None,
        })
    }
}

/// `WithGenesis` structure.
///
/// Options for setting up the genesis for `PeerBuilder`.
#[derive(Default)]
pub enum WithGenesis {
    /// Use the default genesis.
    #[default]
    Default,
    /// Do not use any genesis.
    None,
    /// Use the given genesis.
    Has(GenesisBlock),
}

impl From<Option<GenesisBlock>> for WithGenesis {
    fn from(genesis: Option<GenesisBlock>) -> Self {
        genesis.map_or(Self::None, Self::Has)
    }
}

/// `PeerBuilder`.
#[derive(Default)]
pub struct PeerBuilder {
    config: Option<Config>,
    genesis: WithGenesis,
    temp_dir: Option<Arc<TempDir>>,
    port: Option<u16>,
}

impl PeerBuilder {
    /// Create [`PeerBuilder`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the optional port on which to start the peer.
    /// As there are also API and telemetry ports being
    /// initialized when building a peer, subsequent peers
    /// need to be specified in at least increments of 3.
    #[must_use]
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    /// Set the optional genesis.
    #[must_use]
    pub fn with_into_genesis(mut self, genesis: impl Into<WithGenesis>) -> Self {
        self.genesis = genesis.into();
        self
    }

    /// Set the genesis.
    #[must_use]
    pub fn with_genesis(mut self, genesis: GenesisBlock) -> Self {
        self.genesis = WithGenesis::Has(genesis);
        self
    }

    /// Set Iroha configuration
    #[must_use]
    pub fn with_config(mut self, config: Config) -> Self {
        self.config = Some(config);
        self
    }

    /// Set the directory to be used as a stub.
    #[must_use]
    pub fn with_dir(mut self, temp_dir: Arc<TempDir>) -> Self {
        self.temp_dir.replace(temp_dir);
        self
    }

    /// Build the test [`Peer`] struct, currently
    /// only setting endpoint addresses if a
    /// starting port was provided. Does not
    /// consume [`Self`] as other methods could need
    /// to create a peer beforehand, but takes out
    /// the value from [`self.port`] to prevent accidental
    /// port collision.
    ///
    /// # Errors
    /// - Same as [`Peer::new()`]
    pub fn build(&mut self) -> Result<Peer> {
        let mut peer = Peer::new()?;
        if let Some(port) = self.port.take() {
            peer.p2p_address = socket_addr!(127.0.0 .1: port);
            peer.api_address = socket_addr!(127.0.0 .1: port + 1);
            // prevent field desync
            peer.id.address = peer.p2p_address.clone();
        }
        Ok(peer)
    }

    /// Accept a peer and starts it.
    pub async fn start_with_peer(self, peer: &mut Peer) {
        let config = self.config.unwrap_or_else(Config::test);
        let genesis = match self.genesis {
            WithGenesis::Default => {
                let topology = vec![peer.id.clone()];
                Some(GenesisBlock::test(topology))
            }
            WithGenesis::None => None,
            WithGenesis::Has(genesis) => Some(genesis),
        };
        let temp_dir = self
            .temp_dir
            .unwrap_or_else(|| Arc::new(TempDir::new().expect("Failed to create temp dir.")));

        peer.start(config, genesis, temp_dir).await;
    }

    /// Create and start a peer with preapplied arguments.
    pub async fn start(mut self) -> Peer {
        let mut peer = self.build().expect("Failed to build a peer.");
        self.start_with_peer(&mut peer).await;
        peer
    }

    /// Create and start a peer, create a client and connect it to the peer and return both.
    pub async fn start_with_client(self) -> (Peer, Client) {
        let peer = self.start().await;
        let client = Client::test(&peer.api_address);
        time::sleep(<Config as TestConfig>::pipeline_time()).await;

        (peer, client)
    }

    /// Create a peer with a client, create a runtime, and synchronously start the peer on the runtime.
    pub fn start_with_runtime(self) -> PeerWithRuntimeAndClient {
        let rt = Runtime::test();
        let (peer, client) = rt.block_on(self.start_with_client());
        (rt, peer, client)
    }
}

type PeerWithRuntimeAndClient = (Runtime, Peer, Client);

fn local_unique_port() -> Result<SocketAddr> {
    Ok(socket_addr!(127.0.0.1: unique_port::get_unique_free_port().map_err(eyre::Error::msg)?))
}

/// Runtime used for testing.
pub trait TestRuntime {
    /// Create test runtime
    fn test() -> Self;
}

/// Peer configuration mocking trait.
pub trait TestConfig {
    /// Creates test configuration
    fn test() -> Self;
    /// Returns default pipeline time.
    fn pipeline_time() -> Duration;
    /// Returns default time between block sync requests
    fn block_sync_gossip_time() -> Duration;
}

/// Client configuration mocking trait.
pub trait TestClientConfig {
    /// Creates test client configuration
    fn test(api_address: &SocketAddr) -> Self;
}

/// Client mocking trait
pub trait TestClient: Sized {
    /// Create test client from api url
    fn test(api_url: &SocketAddr) -> Self;

    /// Create test client from api url and keypair
    fn test_with_key(api_url: &SocketAddr, keys: KeyPair) -> Self;

    /// Create test client from api url, keypair, and account id
    fn test_with_account(api_url: &SocketAddr, keys: KeyPair, account_id: &AccountId) -> Self;

    /// Loop for events with filter and handler function
    fn for_each_event(self, event_filter: impl Into<EventFilterBox>, f: impl Fn(Result<EventBox>));

    /// Polls request till predicate `f` is satisfied, with default period and max attempts.
    ///
    /// # Errors
    /// If predicate is not satisfied after maximum retries.
    fn poll(&self, f: impl FnOnce(&Self) -> Result<bool> + Clone) -> eyre::Result<()>;

    /// Polls request till predicate `f` is satisfied with `period` and `max_attempts` supplied.
    ///
    /// # Errors
    /// If predicate is not satisfied after maximum retries.
    fn poll_with_period(
        &self,
        period: Duration,
        max_attempts: u32,
        f: impl FnOnce(&Self) -> Result<bool> + Clone,
    ) -> eyre::Result<()>;
}

impl TestRuntime for Runtime {
    fn test() -> Self {
        runtime::Builder::new_multi_thread()
            .thread_stack_size(32 * 1024 * 1024)
            .enable_all()
            .build()
            .unwrap()
    }
}

impl TestConfig for Config {
    fn test() -> Self {
        use iroha_config::base::toml::TomlSource;

        let mut raw = irohad::samples::get_config_toml(
            <_>::default(),
            get_chain_id(),
            get_key_pair(Signatory::Peer),
            get_key_pair(Signatory::Genesis).public_key(),
        );

        let (public_key, private_key) = KeyPair::random().into_parts();
        iroha_config::base::toml::Writer::new(&mut raw)
            .write("public_key", public_key)
            .write("private_key", ExposedPrivateKey(private_key));

        Config::from_toml_source(TomlSource::inline(raw))
            .expect("Test Iroha config failed to build. This is likely to be a bug.")
    }

    fn pipeline_time() -> Duration {
        let defaults = iroha_data_model::parameter::SumeragiParameters::default();
        defaults.block_time() + defaults.commit_time()
    }

    fn block_sync_gossip_time() -> Duration {
        Self::test().block_sync.gossip_period
    }
}

// Increased timeout to prevent flaky tests
const TRANSACTION_STATUS_TIMEOUT: Duration = Duration::from_secs(150);

impl TestClientConfig for ClientConfig {
    fn test(api_address: &SocketAddr) -> Self {
        let mut config = iroha::samples::get_client_config(
            get_chain_id(),
            get_key_pair(Signatory::Alice),
            format!("http://{api_address}")
                .parse()
                .expect("should be valid url"),
        );
        config.transaction_status_timeout = TRANSACTION_STATUS_TIMEOUT;
        config
    }
}

impl TestClient for Client {
    fn test(api_addr: &SocketAddr) -> Self {
        Client::new(ClientConfig::test(api_addr))
    }

    fn test_with_key(api_addr: &SocketAddr, keys: KeyPair) -> Self {
        let mut config = ClientConfig::test(api_addr);
        config.key_pair = keys;
        Client::new(config)
    }

    fn test_with_account(api_addr: &SocketAddr, keys: KeyPair, account_id: &AccountId) -> Self {
        let mut config = ClientConfig::test(api_addr);
        config.account = account_id.clone();
        config.key_pair = keys;
        Client::new(config)
    }

    fn for_each_event(self, event_filter: impl Into<EventFilterBox>, f: impl Fn(Result<EventBox>)) {
        for event_result in self
            .listen_for_events([event_filter])
            .expect("Failed to create event iterator.")
        {
            f(event_result)
        }
    }

    fn poll_with_period(
        &self,
        period: Duration,
        max_attempts: u32,
        f: impl FnOnce(&Self) -> Result<bool> + Clone,
    ) -> eyre::Result<()> {
        for _ in 0..max_attempts {
            if f.clone()(self)? {
                return Ok(());
            };
            thread::sleep(period);
        }
        Err(eyre::eyre!(
            "Failed to wait for query request completion that would satisfy specified closure"
        ))
    }

    fn poll(&self, f: impl FnOnce(&Self) -> Result<bool> + Clone) -> eyre::Result<()> {
        self.poll_with_period(Config::pipeline_time() / 2, 10, f)
    }
}

/// Construct executor from path.
///
/// `relative_path` should be relative to `CARGO_MANIFEST_DIR`.
///
/// # Errors
///
/// - Failed to create temp dir for executor output
/// - Failed to build executor
/// - Failed to optimize executor
pub fn construct_executor<P>(relative_path: &P) -> eyre::Result<Executor>
where
    P: AsRef<Path> + ?Sized,
{
    let wasm_blob = iroha_wasm_builder::Builder::new(relative_path)
        .build()?
        .optimize()?
        .into_bytes()?;

    Ok(Executor::new(WasmSmartContract::from_compiled(wasm_blob)))
}
