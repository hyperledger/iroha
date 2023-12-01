//! Module for starting peers and networks. Used only for tests
use core::{fmt::Debug, str::FromStr as _, time::Duration};
#[cfg(debug_assertions)]
use std::sync::atomic::AtomicBool;
use std::{collections::BTreeMap, path::Path, sync::Arc, thread};

use eyre::Result;
use futures::{prelude::*, stream::FuturesUnordered};
use iroha::Iroha;
use iroha_client::{
    client::{Client, QueryOutput},
    data_model::{isi::Instruction, peer::Peer as DataModelPeer, prelude::*, query::Query, Level},
};
use iroha_config::{
    base::proxy::{LoadFromEnv, Override},
    client::Configuration as ClientConfiguration,
    iroha::{Configuration, ConfigurationProxy},
    sumeragi::Configuration as SumeragiConfiguration,
    torii::Configuration as ToriiConfiguration,
};
use iroha_crypto::prelude::*;
use iroha_genesis::{GenesisNetwork, RawGenesisBlock};
use iroha_logger::{Configuration as LoggerConfiguration, InstrumentFutures};
use iroha_primitives::{
    addr::{socket_addr, SocketAddr},
    unique_vec,
    unique_vec::UniqueVec,
};
use rand::{seq::IteratorRandom, thread_rng};
use serde_json::json;
use tempfile::TempDir;
use tokio::{
    runtime::{self, Runtime},
    task::{self, JoinHandle},
    time,
};
pub use unique_port;

#[derive(Debug, Clone, Copy)]
struct ShutdownRuntime;

/// Network of peers
pub struct Network {
    /// Genesis peer which sends genesis block to everyone
    pub genesis: Peer,
    /// Peers excluding the `genesis` peer. Use [`Network::peers`] function to get all instead.
    ///
    /// [`BTreeMap`] is used in order to have deterministic order of peers.
    pub peers: BTreeMap<PeerId, Peer>,
}

/// Get a standardised key-pair from the hard-coded literals.
///
/// # Panics
/// Programmer error. Given keys must be in proper format.
pub fn get_key_pair() -> KeyPair {
    KeyPair::new(
        PublicKey::from_str(
            "ed01207233BFC89DCBD68C19FDE6CE6158225298EC1131B6A130D1AEB454C1AB5183C0",
        )
        .expect("Public key not in mulithash format"),
        PrivateKey::from_hex(
            Algorithm::Ed25519,
            "9AC47ABF59B356E0BD7DCBBBB4DEC080E302156A48CA907E47CB6AEA1D32719E7233BFC89DCBD68C19FDE6CE6158225298EC1131B6A130D1AEB454C1AB5183C0".as_ref()
        ).expect("Private key not hex encoded")
    ).expect("Key pair mismatch")
}

/// Trait used to differentiate a test instance of `genesis`.
pub trait TestGenesis: Sized {
    /// Construct Iroha genesis network and optionally submit genesis
    /// from the given peer.
    fn test(submit_genesis: bool) -> Option<Self>;
}

impl TestGenesis for GenesisNetwork {
    fn test(submit_genesis: bool) -> Option<Self> {
        let cfg = Configuration::test();

        // TODO: Fix this somehow. Probably we need to make `kagami` a library (#3253).
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut genesis =
            RawGenesisBlock::from_path(manifest_dir.join("../../configs/peer/genesis.json"))
                .expect("Failed to deserialize genesis block from file");

        let rose_definition_id =
            AssetDefinitionId::from_str("rose#wonderland").expect("valid names");
        let alice_id = AccountId::from_str("alice@wonderland").expect("valid names");

        let mint_rose_permission = PermissionToken::new(
            "CanMintAssetsWithDefinition".parse().unwrap(),
            &json!({ "asset_definition_id": rose_definition_id }),
        );
        let burn_rose_permission = PermissionToken::new(
            "CanBurnAssetsWithDefinition".parse().unwrap(),
            &json!({ "asset_definition_id": rose_definition_id }),
        );
        let unregister_any_peer_permission =
            PermissionToken::new("CanUnregisterAnyPeer".parse().unwrap(), &json!(null));
        let unregister_any_role_permission =
            PermissionToken::new("CanUnregisterAnyRole".parse().unwrap(), &json!(null));
        let unregister_wonderland_domain = PermissionToken::new(
            "CanUnregisterDomain".parse().unwrap(),
            &json!({ "domain_id": DomainId::from_str("wonderland").unwrap() } ),
        );
        let upgrade_executor_permission =
            PermissionToken::new("CanUpgradeExecutor".parse().unwrap(), &json!(null));

        let first_transaction = genesis
            .first_transaction_mut()
            .expect("At least one transaction is expected");
        for permission in [
            mint_rose_permission,
            burn_rose_permission,
            unregister_any_peer_permission,
            unregister_any_role_permission,
            unregister_wonderland_domain,
            upgrade_executor_permission,
        ] {
            first_transaction
                .append_instruction(GrantExpr::new(permission, alice_id.clone()).into());
        }

        if submit_genesis {
            return Some(
                GenesisNetwork::from_configuration(genesis, Some(&cfg.genesis))
                    .expect("Failed to init genesis"),
            );
        }

        None
    }
}

impl Network {
    /// Collect the freeze handles from all the peers in the network.
    #[cfg(debug_assertions)]
    pub fn get_freeze_status_handles(&self) -> Vec<Arc<AtomicBool>> {
        self.peers()
            .filter_map(|peer| peer.iroha.as_ref())
            .map(|iroha| iroha.freeze_status.clone())
            .collect()
    }

    /// Starts network with peers with default configuration and
    /// specified options in a new async runtime.  Returns its info
    /// and client for connecting to it.
    pub fn start_test_with_runtime(
        n_peers: u32,
        start_port: Option<u16>,
    ) -> (Runtime, Self, Client) {
        let rt = Runtime::test();
        let (network, client) = rt.block_on(Self::start_test(n_peers, start_port));
        (rt, network, client)
    }

    /// Starts network with peers with default configuration and
    /// specified options.  Returns its info and client for connecting
    /// to it.
    pub async fn start_test(n_peers: u32, start_port: Option<u16>) -> (Self, Client) {
        Self::start_test_with_offline(n_peers, 0, start_port).await
    }

    /// Starts network with peers with default configuration and
    /// specified options.  Returns its info and client for connecting
    /// to it.
    pub async fn start_test_with_offline_and_set_n_shifts(
        n_peers: u32,
        offline_peers: u32,
        start_port: Option<u16>,
    ) -> (Self, Client) {
        let mut configuration = Configuration::test();
        configuration.logger.max_log_level = Level::INFO.into();
        let network = Network::new_with_offline_peers(
            Some(configuration),
            n_peers,
            offline_peers,
            start_port,
        )
        .await
        .expect("Failed to init peers");
        let client = Client::test(
            &Network::peers(&network)
                .choose(&mut thread_rng())
                .unwrap()
                .api_address,
        );
        (network, client)
    }

    /// Starts network with peers with default configuration and
    /// specified options.  Returns its info and client for connecting
    /// to it.
    pub async fn start_test_with_offline(
        n_peers: u32,
        offline_peers: u32,
        start_port: Option<u16>,
    ) -> (Self, Client) {
        Self::start_test_with_offline_and_set_n_shifts(n_peers, offline_peers, start_port).await
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

        let mut config = Configuration::test();
        config.sumeragi.trusted_peers.peers =
            UniqueVec::from_iter(self.peers().map(|peer| &peer.id).cloned());

        let peer = PeerBuilder::new()
            .with_configuration(config)
            .with_into_genesis(GenesisNetwork::test(false))
            .start()
            .await;

        time::sleep(Configuration::pipeline_time() + Configuration::block_sync_gossip_time()).await;

        let add_peer = RegisterExpr::new(DataModelPeer::new(peer.id.clone()));
        client.submit(add_peer).expect("Failed to add new peer.");

        let peer_client = Client::test(&peer.api_address);
        (peer, peer_client)
    }

    /// Creates new network with some offline peers
    ///
    /// # Panics
    /// - If loading an environment configuration fails when
    /// no default configuration was provided.
    /// - If keypair generation fails.
    ///
    /// # Errors
    /// - (RARE) Creating new peers and collecting into a [`HashMap`] fails.
    /// - Creating new [`Peer`] instance fails.
    pub async fn new_with_offline_peers(
        default_configuration: Option<Configuration>,
        n_peers: u32,
        offline_peers: u32,
        start_port: Option<u16>,
    ) -> Result<Self> {
        let mut builders = core::iter::repeat_with(PeerBuilder::new)
            .enumerate()
            .map(|(n, builder)| {
                if let Some(port) = start_port {
                    let offset: u16 = (n * 5)
                        .try_into()
                        .expect("The `n_peers` is too large to fit into `u16`");
                    (n, builder.with_port(port + offset))
                } else {
                    (n, builder)
                }
            })
            .map(|(n, builder)| builder.with_into_genesis(GenesisNetwork::test(n == 0)))
            .take(n_peers as usize)
            .collect::<Vec<_>>();
        let mut peers = builders
            .iter_mut()
            .map(PeerBuilder::build)
            .collect::<Result<Vec<_>>>()?;

        let mut configuration = default_configuration.unwrap_or_else(Configuration::test);
        configuration.sumeragi.trusted_peers.peers =
            UniqueVec::from_iter(peers.iter().map(|peer| peer.id.clone()));

        let mut genesis_peer = peers.remove(0);
        let genesis_builder = builders.remove(0).with_configuration(configuration.clone());

        // Offset by one to account for genesis
        let online_peers = n_peers - offline_peers - 1;
        let rng = &mut rand::thread_rng();
        let futures = FuturesUnordered::new();

        futures.push(genesis_builder.start_with_peer(&mut genesis_peer));

        for (builder, peer) in builders
            .into_iter()
            .zip(peers.iter_mut())
            .choose_multiple(rng, online_peers as usize)
        {
            futures.push(
                builder
                    .with_configuration(configuration.clone())
                    .start_with_peer(peer),
            );
        }
        futures.collect::<()>().await;

        time::sleep(Duration::from_millis(500) * (n_peers + 1)).await;

        Ok(Self {
            genesis: genesis_peer,
            peers: peers
                .into_iter()
                .map(|peer| (peer.id.clone(), peer))
                .collect::<BTreeMap<_, _>>(),
        })
    }

    /// Returns all peers.
    pub fn peers(&self) -> impl Iterator<Item = &Peer> + '_ {
        std::iter::once(&self.genesis).chain(self.peers.values())
    }

    /// Get active clients
    pub fn clients(&self) -> Vec<Client> {
        self.peers()
            .map(|peer| Client::test(&peer.api_address))
            .collect()
    }

    /// Get peer by its Id.
    pub fn peer_by_id(&self, id: &PeerId) -> Option<&Peer> {
        self.peers.get(id).or(if self.genesis.id == *id {
            Some(&self.genesis)
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
    const POLL_PERIOD: Duration = Duration::from_millis(1000);
    const MAX_RETRIES: u32 = 30;

    for _ in 0..MAX_RETRIES {
        let without_genesis_peers = clients.iter().fold(0_u32, |acc, client| {
            client.get_status().map_or(
                acc + 1,
                |status| if status.blocks < 1 { acc + 1 } else { acc },
            )
        });
        if without_genesis_peers <= offline_peers {
            return;
        }
        thread::sleep(POLL_PERIOD);
    }
    panic!(
        "Failed to wait for online peers to commit genesis block. Total wait time: {:?}",
        POLL_PERIOD * MAX_RETRIES
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
    /// Shutdown handle
    shutdown: Option<JoinHandle<()>>,
    /// Iroha itself
    pub iroha: Option<Iroha>,
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
    fn get_config(&self, configuration: Configuration) -> Configuration {
        Configuration {
            sumeragi: SumeragiConfiguration {
                key_pair: self.key_pair.clone(),
                peer_id: self.id.clone(),
                ..configuration.sumeragi
            },
            torii: ToriiConfiguration {
                p2p_addr: self.p2p_address.clone(),
                api_url: self.api_address.clone(),
                ..configuration.torii
            },
            logger: LoggerConfiguration {
                ..configuration.logger
            },
            public_key: self.key_pair.public_key().clone(),
            private_key: self.key_pair.private_key().clone(),
            disable_panic_terminal_colors: true,
            ..configuration
        }
    }

    /// Starts a peer with arguments.
    async fn start(
        &mut self,
        configuration: Configuration,
        genesis: Option<GenesisNetwork>,
        temp_dir: Arc<TempDir>,
    ) {
        let mut configuration = self.get_config(configuration);
        configuration
            .kura
            .block_store_path(temp_dir.path())
            .expect("block store path not readable");
        let info_span = iroha_logger::info_span!(
            "test-peer",
            p2p_addr = %self.p2p_address,
            api_addr = %self.api_address,
        );
        let telemetry =
            iroha_logger::init(&configuration.logger).expect("Failed to initialize telemetry");
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);

        let handle = task::spawn(
            async move {
                let mut iroha = Iroha::with_genesis(genesis, configuration, telemetry)
                    .await
                    .expect("Failed to start iroha");
                let job_handle = iroha.start_as_task().unwrap();
                sender.send(iroha).unwrap();
                job_handle.await.unwrap().unwrap();
            }
            .instrument(info_span),
        );

        self.iroha = Some(receiver.recv().unwrap());
        time::sleep(Duration::from_millis(300)).await;
        self.shutdown = Some(handle);
        // Prevent temporary directory deleting
        self.temp_dir = Some(temp_dir);
    }

    /// Stop the peer if it's running
    pub fn stop(&mut self) -> Option<()> {
        iroha_logger::info!(
            p2p_addr = %self.p2p_address,
            api_addr = %self.api_address,
            "Stopping peer",
        );

        if let Some(shutdown) = self.shutdown.take() {
            shutdown.abort();
            iroha_logger::info!("Shutting down peer...");
            self.iroha.take();
            Some(())
        } else {
            None
        }
    }

    /// Creates peer
    ///
    /// # Errors
    /// * If can't get a unique port for
    /// - `p2p_address`
    /// - `api_address`
    /// * If keypair generation fails
    pub fn new() -> Result<Self> {
        let key_pair = KeyPair::generate()?;
        let p2p_address = local_unique_port()?;
        let api_address = local_unique_port()?;
        let id = PeerId {
            address: p2p_address.clone(),
            public_key: key_pair.public_key().clone(),
        };
        let shutdown = None;
        Ok(Self {
            id,
            key_pair,
            p2p_address,
            api_address,
            shutdown,
            iroha: None,
            temp_dir: None,
        })
    }
}

/// `WithGenesis` structure.
///
/// Options for setting up the genesis network for `PeerBuilder`.
#[derive(Default)]
pub enum WithGenesis {
    /// Use the default genesis network.
    #[default]
    Default,
    /// Do not use any genesis networks.
    None,
    /// Use the given genesis network.
    Has(GenesisNetwork),
}

impl<T: Into<Option<GenesisNetwork>>> From<T> for WithGenesis {
    fn from(x: T) -> Self {
        x.into().map_or(Self::None, Self::Has)
    }
}

/// `PeerBuilder`.
#[derive(Default)]
pub struct PeerBuilder {
    configuration: Option<Configuration>,
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

    /// Set the optional genesis network.
    #[must_use]
    pub fn with_into_genesis(mut self, genesis: impl Into<WithGenesis>) -> Self {
        self.genesis = genesis.into();
        self
    }

    /// Set the genesis network.
    #[must_use]
    pub fn with_genesis(mut self, genesis: GenesisNetwork) -> Self {
        self.genesis = WithGenesis::Has(genesis);
        self
    }

    /// Set the test genesis network.
    #[must_use]
    pub fn with_test_genesis(self, submit_genesis: bool) -> Self {
        self.with_into_genesis(GenesisNetwork::test(submit_genesis))
    }

    /// Set Iroha configuration
    #[must_use]
    pub fn with_configuration(mut self, configuration: Configuration) -> Self {
        self.configuration = Some(configuration);
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
        let configuration = self.configuration.unwrap_or_else(|| {
            let mut config = Configuration::test();
            config.sumeragi.trusted_peers.peers = unique_vec![peer.id.clone()];
            config
        });
        let genesis = match self.genesis {
            WithGenesis::Default => GenesisNetwork::test(true),
            WithGenesis::None => None,
            WithGenesis::Has(genesis) => Some(genesis),
        };
        let temp_dir = self
            .temp_dir
            .unwrap_or_else(|| Arc::new(TempDir::new().expect("Failed to create temp dir.")));

        peer.start(configuration, genesis, temp_dir).await;
    }

    /// Create and start a peer with preapplied arguments.
    pub async fn start(mut self) -> Peer {
        let mut peer = self.build().expect("Failed to build a peer.");
        self.start_with_peer(&mut peer).await;
        peer
    }

    /// Create and start a peer, create a client and connect it to the peer and return both.
    pub async fn start_with_client(self) -> (Peer, Client) {
        let configuration = self
            .configuration
            .clone()
            .unwrap_or_else(Configuration::test);

        let peer = self.start().await;

        let client = Client::test(&peer.api_address);

        time::sleep(Duration::from_millis(
            configuration.sumeragi.pipeline_time_ms(),
        ))
        .await;

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
pub trait TestConfiguration {
    /// Creates test configuration
    fn test() -> Self;
    /// Returns default pipeline time.
    fn pipeline_time() -> Duration;
    /// Returns default time between block sync requests
    fn block_sync_gossip_time() -> Duration;
}

/// Client configuration mocking trait.
pub trait TestClientConfiguration {
    /// Creates test client configuration
    fn test(api_url: &SocketAddr) -> Self;
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
    fn for_each_event(self, event_filter: FilterBox, f: impl Fn(Result<Event>));

    /// Submit instruction with polling
    ///
    /// # Errors
    /// If predicate is not satisfied, after maximum retries.
    fn submit_till<R: Query + Debug + Clone>(
        &self,
        instruction: impl Instruction + Debug + Clone,
        request: R,
        f: impl Fn(<R::Output as QueryOutput>::Target) -> bool,
    ) -> eyre::Result<()>
    where
        R::Output: QueryOutput,
        <R::Output as QueryOutput>::Target: core::fmt::Debug,
        <R::Output as TryFrom<Value>>::Error: Into<eyre::Error>;

    /// Submits instructions with polling
    ///
    /// # Errors
    /// If predicate is not satisfied, after maximum retries.
    fn submit_all_till<R: Query + Debug + Clone>(
        &self,
        instructions: Vec<InstructionExpr>,
        request: R,
        f: impl Fn(<R::Output as QueryOutput>::Target) -> bool,
    ) -> eyre::Result<()>
    where
        R::Output: QueryOutput,
        <R::Output as QueryOutput>::Target: core::fmt::Debug,
        <R::Output as TryFrom<Value>>::Error: Into<eyre::Error>;

    /// Polls request till predicate `f` is satisfied, with default period and max attempts.
    ///
    /// # Errors
    /// If predicate is not satisfied after maximum retries.
    fn poll_request<R: Query + Debug + Clone>(
        &self,
        request: R,
        f: impl Fn(<R::Output as QueryOutput>::Target) -> bool,
    ) -> eyre::Result<()>
    where
        R::Output: QueryOutput,
        <R::Output as QueryOutput>::Target: core::fmt::Debug,
        <R::Output as TryFrom<Value>>::Error: Into<eyre::Error>;

    /// Polls request till predicate `f` is satisfied with `period` and `max_attempts` supplied.
    ///
    /// # Errors
    /// If predicate is not satisfied after maximum retries.
    fn poll_request_with_period<R: Query + Debug + Clone + Clone>(
        &self,
        request: R,
        period: Duration,
        max_attempts: u32,
        f: impl Fn(<R::Output as QueryOutput>::Target) -> bool,
    ) -> eyre::Result<()>
    where
        R::Output: QueryOutput,
        <R::Output as QueryOutput>::Target: core::fmt::Debug,
        <R::Output as TryFrom<Value>>::Error: Into<eyre::Error>;
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

impl TestConfiguration for Configuration {
    fn test() -> Self {
        let mut sample_proxy =
            iroha::samples::get_config_proxy(UniqueVec::new(), Some(get_key_pair()));
        let env_proxy =
            ConfigurationProxy::from_std_env().expect("Test env variables should parse properly");
        let (public_key, private_key) = KeyPair::generate().unwrap().into();
        sample_proxy.public_key = Some(public_key);
        sample_proxy.private_key = Some(private_key);
        sample_proxy.override_with(env_proxy)
                    .build()
                    .expect("Test Iroha config failed to build. This is either a programmer error or a compiler bug.")
    }

    fn pipeline_time() -> Duration {
        Duration::from_millis(Self::test().sumeragi.pipeline_time_ms())
    }

    fn block_sync_gossip_time() -> Duration {
        Duration::from_millis(Self::test().block_sync.gossip_period_ms)
    }
}

impl TestClientConfiguration for ClientConfiguration {
    fn test(api_url: &SocketAddr) -> Self {
        let mut configuration = iroha_client::samples::get_client_config(&get_key_pair());
        configuration.torii_api_url = format!("http://{api_url}")
            .parse()
            .expect("Should be valid url");
        configuration
    }
}

impl TestClient for Client {
    fn test(api_url: &SocketAddr) -> Self {
        Client::new(&ClientConfiguration::test(api_url)).expect("Invalid client configuration")
    }

    fn test_with_key(api_url: &SocketAddr, keys: KeyPair) -> Self {
        let mut configuration = ClientConfiguration::test(api_url);
        let (public_key, private_key) = keys.into();
        configuration.public_key = public_key;
        configuration.private_key = private_key;
        Client::new(&configuration).expect("Invalid client configuration")
    }

    fn test_with_account(api_url: &SocketAddr, keys: KeyPair, account_id: &AccountId) -> Self {
        let mut configuration = ClientConfiguration::test(api_url);
        configuration.account_id = account_id.clone();
        let (public_key, private_key) = keys.into();
        configuration.public_key = public_key;
        configuration.private_key = private_key;
        Client::new(&configuration).expect("Invalid client configuration")
    }

    fn for_each_event(self, event_filter: FilterBox, f: impl Fn(Result<Event>)) {
        for event_result in self
            .listen_for_events(event_filter)
            .expect("Failed to create event iterator.")
        {
            f(event_result)
        }
    }

    fn submit_till<R: Query + Debug + Clone>(
        &self,
        instruction: impl Instruction + Debug + Clone,
        request: R,
        f: impl Fn(<R::Output as QueryOutput>::Target) -> bool,
    ) -> eyre::Result<()>
    where
        R::Output: QueryOutput,
        <R::Output as QueryOutput>::Target: core::fmt::Debug,
        <R::Output as TryFrom<Value>>::Error: Into<eyre::Error>,
    {
        self.submit(instruction)
            .expect("Failed to submit instruction.");
        self.poll_request(request, f)
    }

    fn submit_all_till<R: Query + Debug + Clone>(
        &self,
        instructions: Vec<InstructionExpr>,
        request: R,
        f: impl Fn(<R::Output as QueryOutput>::Target) -> bool,
    ) -> eyre::Result<()>
    where
        R::Output: QueryOutput,
        <R::Output as QueryOutput>::Target: core::fmt::Debug,
        <R::Output as TryFrom<Value>>::Error: Into<eyre::Error>,
    {
        self.submit_all(instructions)
            .expect("Failed to submit instruction.");
        self.poll_request(request, f)
    }

    fn poll_request_with_period<R: Query + Debug + Clone>(
        &self,
        request: R,
        period: Duration,
        max_attempts: u32,
        f: impl Fn(<R::Output as QueryOutput>::Target) -> bool,
    ) -> eyre::Result<()>
    where
        R::Output: QueryOutput,
        <R::Output as QueryOutput>::Target: core::fmt::Debug,
        <R::Output as TryFrom<Value>>::Error: Into<eyre::Error>,
    {
        let mut query_result = None;
        for _ in 0..max_attempts {
            query_result = match self.request(request.clone()) {
                Ok(result) if f(result.clone()) => return Ok(()),
                result => Some(result),
            };
            thread::sleep(period);
        }
        Err(eyre::eyre!("Failed to wait for query request completion that would satisfy specified closure. Got this query result instead: {:?}", &query_result))
    }

    fn poll_request<R: Query + Debug + Clone>(
        &self,
        request: R,
        f: impl Fn(<R::Output as QueryOutput>::Target) -> bool,
    ) -> eyre::Result<()>
    where
        R::Output: QueryOutput,
        <R::Output as QueryOutput>::Target: core::fmt::Debug,
        <R::Output as TryFrom<Value>>::Error: Into<eyre::Error>,
    {
        self.poll_request_with_period(request, Configuration::pipeline_time() / 2, 10, f)
    }
}
