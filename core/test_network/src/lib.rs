//! Module for starting peers and networks. Used only for tests

#![allow(clippy::restriction, clippy::future_not_send)]

use core::{fmt::Debug, str::FromStr as _, time::Duration};
use std::{collections::HashMap, sync::Arc, thread};

use eyre::{Error, Result};
use futures::{prelude::*, stream::FuturesUnordered};
use iroha::Iroha;
use iroha_actor::{broker::*, prelude::*};
use iroha_client::client::Client;
use iroha_config::{
    client::Configuration as ClientConfiguration, iroha::Configuration,
    sumeragi::Configuration as SumeragiConfiguration, torii::Configuration as ToriiConfiguration,
};
use iroha_core::{
    genesis::{GenesisNetwork, GenesisNetworkTrait, RawGenesisBlock},
    prelude::*,
    smartcontracts::permissions::judge::{InstructionJudgeBoxed, QueryJudgeBoxed},
};
use iroha_data_model::{peer::Peer as DataModelPeer, prelude::*};
use iroha_logger::{Configuration as LoggerConfiguration, InstrumentFutures};
use iroha_permissions_validators::{
    private_blockchain,
    public_blockchain::{
        self, burn::CanBurnAssetWithDefinition, mint::CanMintUserAssetDefinitions,
    },
};
use iroha_primitives::small;
use rand::seq::IteratorRandom;
use tempfile::TempDir;
use tokio::{
    runtime::{self, Runtime},
    task::{self, JoinHandle},
    time,
};
pub use unique_port;

/// Prevent port collisions in `unique_port`, when using `cargo nextest`.
#[macro_export]
macro_rules! prepare_test_for_nextest {
    () => {{
        if std::env::var("NEXTEST").is_ok() {
            use $crate::unique_port::{generate_unique_start_port, set_port_index};
            set_port_index(generate_unique_start_port!())
                .expect("Can't set port index for unique_port");
        }
    }};
}

#[derive(Debug, Clone, Copy)]
struct ShutdownRuntime;

/// Network of peers
pub struct Network {
    /// Genesis peer which sends genesis block to everyone
    pub genesis: Peer,
    /// Peers excluding the `genesis` peer. Use [`Network::peers`] function to get all instead.
    pub peers: HashMap<PeerId, Peer>,
}

/// Get a standardised key-pair from the hard-coded literals.
///
/// # Panics
/// Programmer error. Given keys must be in proper format.
pub fn get_key_pair() -> KeyPair {
    KeyPair::new(
        PublicKey::from_str(
            r#"ed01207233bfc89dcbd68c19fde6ce6158225298ec1131b6a130d1aeb454c1ab5183c0"#,
        )
        .expect("Public key not in mulithash format"),
        PrivateKey::from_hex(
            Algorithm::Ed25519,
            "9AC47ABF 59B356E0 BD7DCBBB B4DEC080 E302156A 48CA907E 47CB6AEA 1D32719E 7233BFC8 9DCBD68C 19FDE6CE 61582252 98EC1131 B6A130D1 AEB454C1 AB5183C0",
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
        let mut genesis = RawGenesisBlock::new(
            "alice".parse().expect("Valid"),
            "wonderland".parse().expect("Valid"),
            get_key_pair().public_key().clone(),
        );
        let rose_definition_id = <AssetDefinition as Identifiable>::Id::from_str("rose#wonderland")
            .expect("valid names");
        let alice_id =
            <Account as Identifiable>::Id::from_str("alice@wonderland").expect("valid names");
        let mint_rose_permission: PermissionToken =
            CanMintUserAssetDefinitions::new(rose_definition_id.clone()).into();
        let burn_rose_permission: PermissionToken =
            CanBurnAssetWithDefinition::new(rose_definition_id.clone()).into();

        genesis.transactions[0].isi.extend(
            public_blockchain::default_permission_token_definitions()
                .into_iter()
                .chain(private_blockchain::default_permission_token_definitions().into_iter())
                .map(|token_definition| RegisterBox::new(token_definition.clone()).into()),
        );
        genesis.transactions[0].isi.push(
            RegisterBox::new(AssetDefinition::quantity(
                AssetDefinitionId::from_str("rose#wonderland").expect("valid names"),
            ))
            .into(),
        );
        genesis.transactions[0]
            .isi
            .push(GrantBox::new(mint_rose_permission, alice_id.clone()).into());
        genesis.transactions[0]
            .isi
            .push(GrantBox::new(burn_rose_permission, alice_id.clone()).into());
        genesis.transactions[0].isi.push(
            RegisterBox::new(AssetDefinition::quantity(
                AssetDefinitionId::from_str("tulip#wonderland").expect("valid names"),
            ))
            .into(),
        );
        genesis.transactions[0].isi.push(
            MintBox::new(
                Value::U32(13),
                IdBox::AssetId(AssetId::new(rose_definition_id, alice_id)),
            )
            .into(),
        );

        configure_world();

        GenesisNetwork::from_configuration(
            submit_genesis,
            genesis,
            Some(&cfg.genesis),
            &cfg.sumeragi.transaction_limits,
        )
        .expect("Failed to init genesis")
    }
}

fn configure_world() {}

impl Network {
    /// Send message to an actor instance on peers.
    ///
    /// # Panics
    /// Programmer error. `self.peers()` should already have `iroha`.
    pub async fn send_to_actor_on_peers<M, A>(
        &self,
        select_actor: impl Fn(&Iroha) -> &Addr<A>,
        msg: M,
    ) -> Vec<(M::Result, PeerId)>
    where
        M: Message + Clone + Send + 'static,
        M::Result: Send,
        A: Actor + ContextHandler<M>,
    {
        let fut = self
            .peers()
            .map(|peer| {
                (
                    select_actor(peer.iroha.as_ref().expect("Already initialised")),
                    peer.id.clone(),
                )
            })
            .map(|(actor, peer_id)| async { (actor.send(msg.clone()).await, peer_id) })
            .collect::<FuturesUnordered<_>>()
            .collect::<Vec<_>>();
        time::timeout(Duration::from_secs(60), fut)
            .await
            .unwrap()
            .into_iter()
            .map(|(result, peer_id)| (result.expect("Always `Ok`"), peer_id))
            .collect()
    }

    /// Starts network with peers with default configuration and
    /// specified options in a new async runtime.  Returns its info
    /// and client for connecting to it.
    pub fn start_test_with_runtime(n_peers: u32, max_txs_in_block: u32) -> (Runtime, Self, Client) {
        let rt = Runtime::test();
        let (network, client) = rt.block_on(Self::start_test(n_peers, max_txs_in_block));
        (rt, network, client)
    }

    /// Starts network with peers with default configuration and
    /// specified options.  Returns its info and client for connecting
    /// to it.
    pub async fn start_test(n_peers: u32, max_txs_in_block: u32) -> (Self, Client) {
        Self::start_test_with_offline(n_peers, max_txs_in_block, 0).await
    }

    /// Starts network with peers with default configuration and
    /// specified options.  Returns its info and client for connecting
    /// to it.
    pub async fn start_test_with_offline_and_set_n_shifts(
        n_peers: u32,
        max_txs_in_block: u32,
        offline_peers: u32,
    ) -> (Self, Client) {
        let mut configuration = Configuration::test();
        configuration.queue.maximum_transactions_in_block = max_txs_in_block;
        configuration.logger.max_log_level = iroha_logger::Level::INFO.into();
        let network = Network::new_with_offline_peers(Some(configuration), n_peers, offline_peers)
            .await
            .expect("Failed to init peers");
        let client = Client::test(
            &network.genesis.api_address,
            &network.genesis.telemetry_address,
        );
        (network, client)
    }

    /// Starts network with peers with default configuration and
    /// specified options.  Returns its info and client for connecting
    /// to it.
    pub async fn start_test_with_offline(
        n_peers: u32,
        maximum_transactions_in_block: u32,
        offline_peers: u32,
    ) -> (Self, Client) {
        Self::start_test_with_offline_and_set_n_shifts(
            n_peers,
            maximum_transactions_in_block,
            offline_peers,
        )
        .await
    }

    /// Adds peer to network and waits for it to start block
    /// synchronization.
    pub async fn add_peer(&self) -> (Peer, Client) {
        let genesis_client =
            Client::test(&self.genesis.api_address, &self.genesis.telemetry_address);

        let mut config = Configuration::test();
        config.sumeragi.trusted_peers.peers = self.peers().map(|peer| &peer.id).cloned().collect();

        let peer = PeerBuilder::new()
            .with_configuration(config)
            .with_into_genesis(GenesisNetwork::test(false))
            .start()
            .await;

        time::sleep(Configuration::pipeline_time() + Configuration::block_sync_gossip_time()).await;

        let add_peer = RegisterBox::new(DataModelPeer::new(peer.id.clone()));
        genesis_client
            .submit(add_peer)
            .expect("Failed to add new peer.");

        let client = Client::test(&peer.api_address, &peer.telemetry_address);

        (peer, client)
    }

    /// Creates new network with some offline peers
    ///
    /// # Panics
    /// Panics if default configuration is not found.
    ///
    /// # Errors
    /// - (RARE) Creating new peers and collecting into a [`HashMap`] fails.
    /// - Creating new [`Peer`] instance fails.
    pub async fn new_with_offline_peers(
        default_configuration: Option<Configuration>,
        n_peers: u32,
        offline_peers: u32,
    ) -> Result<Self> {
        let n_peers = n_peers - 1;
        let mut genesis = Peer::new()?;
        let mut peers = (0..n_peers)
            .map(|_| Peer::new())
            .map(|result| result.map(|peer| (peer.id.clone(), peer)))
            .collect::<Result<HashMap<_, _>>>()?;

        let mut configuration = default_configuration.unwrap_or_else(Configuration::test);
        configuration.sumeragi.trusted_peers.peers = peers
            .values()
            .chain([&genesis])
            .map(|peer| peer.id.clone())
            .collect();

        let rng = &mut rand::thread_rng();
        let online_peers = n_peers - offline_peers;
        let futures = FuturesUnordered::new();

        let builder = PeerBuilder::new()
            .with_into_genesis(GenesisNetwork::test(true))
            .with_configuration(configuration.clone());

        futures.push(builder.start_with_peer(&mut genesis));
        for peer in peers
            .values_mut()
            .choose_multiple(rng, online_peers as usize)
        {
            let builder = PeerBuilder::new()
                .with_into_genesis(GenesisNetwork::test(false))
                .with_configuration(configuration.clone());

            futures.push(builder.start_with_peer(peer));
        }
        futures.collect::<()>().await;

        time::sleep(Duration::from_millis(500) * (n_peers + 1)).await;

        Ok(Self { genesis, peers })
    }

    /// Returns all peers.
    pub fn peers(&self) -> impl Iterator<Item = &Peer> + '_ {
        std::iter::once(&self.genesis).chain(self.peers.values())
    }

    /// Get active clients
    pub fn clients(&self) -> Vec<Client> {
        self.peers()
            .map(|peer| Client::test(&peer.api_address, &peer.telemetry_address))
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
    const MAX_RETRIES: u32 = 10;

    for _ in 0..MAX_RETRIES {
        let without_genesis_peers = clients.iter().fold(0_u32, |acc, client| {
            if let Ok(status) = client.get_status() {
                if status.blocks < 1 {
                    acc + 1
                } else {
                    acc
                }
            } else {
                acc + 1
            }
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
    pub api_address: String,
    /// P2P address
    pub p2p_address: String,
    /// Telemetry address
    pub telemetry_address: String,
    /// The key-pair for the peer
    pub key_pair: KeyPair,
    /// Broker
    pub broker: Broker,
    /// Shutdown handle
    shutdown: Option<JoinHandle<()>>,
    /// Iroha itself
    pub iroha: Option<Iroha>,
    /// Temporary directory
    // Note: last field to be dropped after Iroha (struct fields drops in FIFO RFC 1857)
    temp_dir: Option<Arc<TempDir>>,
}

impl From<Peer> for Box<iroha_core::tx::Peer> {
    fn from(val: Peer) -> Self {
        Box::new(iroha_core::tx::Peer { id: val.id.clone() })
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
        iroha_logger::info!(
            p2p_addr = %self.p2p_address,
            api_addr = %self.api_address,
            "Stopping peer",
        );

        if let Some(shutdown) = self.shutdown.take() {
            shutdown.abort();
            iroha_logger::info!("Shutting down peer...");
        }
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
                telemetry_url: self.telemetry_address.clone(),
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
        instruction_judge: InstructionJudgeBoxed,
        query_judge: QueryJudgeBoxed,
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
            telemetry_addr = %self.telemetry_address
        );
        let broker = self.broker.clone();
        let telemetry =
            iroha_logger::init(&configuration.logger).expect("Failed to initialize telemetry");
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);

        let handle = task::spawn(
            async move {
                let mut iroha = <Iroha>::with_genesis(
                    genesis,
                    configuration,
                    instruction_judge,
                    query_judge,
                    broker,
                    telemetry,
                )
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

    /// Creates peer
    ///
    /// # Errors
    /// If can't get a unique port for
    /// - `p2p_address`
    /// - `api_address`
    /// - `telemetry_address`
    pub fn new() -> Result<Self> {
        let key_pair = KeyPair::generate()?;
        let p2p_address = local_unique_port()?;
        let api_address = local_unique_port()?;
        let telemetry_address = local_unique_port()?;
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
            telemetry_address,
            shutdown,
            iroha: None,
            broker: Broker::new(),
            temp_dir: None,
        })
    }
}

/// `WithGenesis` structure.
///
/// Options for setting up the genesis network for `PeerBuilder`.
pub enum WithGenesis {
    /// Use the default genesis network.
    Default,
    /// Do not use any genesis networks.
    None,
    /// Use the given genesis network.
    Has(GenesisNetwork),
}

impl Default for WithGenesis {
    fn default() -> Self {
        Self::Default
    }
}

impl From<Option<GenesisNetwork>> for WithGenesis {
    fn from(x: Option<GenesisNetwork>) -> Self {
        match x {
            None => Self::None,
            Some(genesis) => Self::Has(genesis),
        }
    }
}

/// `PeerBuilder` structure that helps to create a peer.
pub struct PeerBuilder {
    configuration: Option<Configuration>,
    genesis: WithGenesis,
    instruction_judge: Option<InstructionJudgeBoxed>,
    query_judge: Option<QueryJudgeBoxed>,
    temp_dir: Option<Arc<TempDir>>,
}

impl PeerBuilder {
    /// Creates [`PeerBuilder`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the optional genesis network.
    #[must_use]
    pub fn with_into_genesis(mut self, genesis: impl Into<WithGenesis>) -> Self {
        self.genesis = genesis.into();
        self
    }

    /// Sets the genesis network.
    #[must_use]
    pub fn with_genesis(mut self, genesis: GenesisNetwork) -> Self {
        self.genesis = WithGenesis::Has(genesis);
        self
    }

    /// Sets the test genesis network.
    #[must_use]
    pub fn with_test_genesis(self, submit_genesis: bool) -> Self {
        self.with_into_genesis(GenesisNetwork::test(submit_genesis))
    }

    /// Sets Iroha configuration
    #[must_use]
    pub fn with_configuration(mut self, configuration: Configuration) -> Self {
        self.configuration.replace(configuration);
        self
    }

    /// Sets permissions for instructions.
    #[must_use]
    pub fn with_instruction_judge(mut self, instruction_judge: InstructionJudgeBoxed) -> Self {
        self.instruction_judge.replace(instruction_judge);
        self
    }

    /// Sets permissions for queries.
    #[must_use]
    pub fn with_query_judge(mut self, query_judge: QueryJudgeBoxed) -> Self {
        self.query_judge.replace(query_judge);
        self
    }

    /// Sets the directory to be used as a stub.
    #[must_use]
    pub fn with_dir(mut self, temp_dir: Arc<TempDir>) -> Self {
        self.temp_dir.replace(temp_dir);
        self
    }

    /// Accepts a peer and starts it.
    pub async fn start_with_peer(self, peer: &mut Peer) {
        let configuration = self.configuration.unwrap_or_else(|| {
            let mut config = Configuration::test();
            config.sumeragi.trusted_peers.peers = std::iter::once(peer.id.clone()).collect();
            config
        });
        let genesis = match self.genesis {
            WithGenesis::Default => GenesisNetwork::test(true),
            WithGenesis::None => None,
            WithGenesis::Has(genesis) => Some(genesis),
        };
        let instruction_validator = self.instruction_judge.unwrap_or_else(|| {
            iroha_permissions_validators::public_blockchain::default_permissions()
        });
        let query_validator = self
            .query_judge
            .unwrap_or_else(|| Box::new(AllowAll::new()));
        let temp_dir = self
            .temp_dir
            .unwrap_or_else(|| Arc::new(TempDir::new().expect("Failed to create temp dir.")));

        peer.start(
            configuration,
            genesis,
            instruction_validator,
            query_validator,
            temp_dir,
        )
        .await;
    }

    /// Creates and starts a peer with preapplied arguments.
    pub async fn start(self) -> Peer {
        let mut peer = Peer::new().expect("Failed to create a peer.");
        self.start_with_peer(&mut peer).await;
        peer
    }

    /// Creates and starts a peer, creates a client and connects it to the peer and returns both.
    pub async fn start_with_client(self) -> (Peer, Client) {
        let configuration = self
            .configuration
            .clone()
            .unwrap_or_else(Configuration::test);

        let peer = self.start().await;

        let client = Client::test(&peer.api_address, &peer.telemetry_address);

        time::sleep(Duration::from_millis(
            configuration.sumeragi.pipeline_time_ms(),
        ))
        .await;

        (peer, client)
    }

    /// Creates a peer with a client, creates a runtime, and synchronously starts the peer on the runtime.
    pub fn start_with_runtime(self) -> PeerWithRuntimeAndClient {
        let rt = Runtime::test();
        let (peer, client) = rt.block_on(self.start_with_client());
        (rt, peer, client)
    }
}

type PeerWithRuntimeAndClient = (Runtime, Peer, Client);

impl Default for PeerBuilder {
    fn default() -> Self {
        Self {
            genesis: WithGenesis::default(),
            configuration: None,
            instruction_judge: None,
            query_judge: None,
            temp_dir: None,
        }
    }
}

fn local_unique_port() -> Result<String> {
    Ok(format!(
        "127.0.0.1:{}",
        unique_port::get_unique_free_port().map_err(Error::msg)?
    ))
}

/// Runtime used for testing.
pub trait TestRuntime {
    /// Creates test runtime
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
    fn test(api_url: &str, telemetry_url: &str) -> Self;
}

/// Client mocking trait
pub trait TestClient: Sized {
    /// Creates test client from api url
    fn test(api_url: &str, telemetry_url: &str) -> Self;

    /// Creates test client from api url and keypair
    fn test_with_key(api_url: &str, telemetry_url: &str, keys: KeyPair) -> Self;

    /// Creates test client from api url, keypair, and account id
    fn test_with_account(
        api_url: &str,
        telemetry_url: &str,
        keys: KeyPair,
        account_id: &AccountId,
    ) -> Self;

    /// loops for events with filter and handler function
    fn for_each_event(self, event_filter: FilterBox, f: impl Fn(Result<Event>));

    /// Submits instruction with polling
    ///
    /// # Errors
    /// If predicate is not satisfied, after maximum retries.
    fn submit_till<R>(
        &mut self,
        instruction: impl Into<Instruction> + Debug,
        request: R,
        f: impl Fn(&R::Output) -> bool,
    ) -> eyre::Result<R::Output>
    where
        R: ValidQuery + Into<QueryBox> + Debug + Clone,
        <R::Output as TryFrom<Value>>::Error: Into<Error>,
        R::Output: Clone + Debug;

    /// Submits instructions with polling
    ///
    /// # Errors
    /// If predicate is not satisfied, after maximum retries.
    fn submit_all_till<R>(
        &mut self,
        instructions: Vec<Instruction>,
        request: R,
        f: impl Fn(&R::Output) -> bool,
    ) -> eyre::Result<R::Output>
    where
        R: ValidQuery + Into<QueryBox> + Debug + Clone,
        <R::Output as TryFrom<Value>>::Error: Into<Error>,
        R::Output: Clone + Debug;

    /// Polls request till predicate `f` is satisfied, with default period and max attempts.
    ///
    /// # Errors
    /// If predicate is not satisfied after maximum retries.
    fn poll_request<R>(
        &mut self,
        request: R,
        f: impl Fn(&R::Output) -> bool,
    ) -> eyre::Result<R::Output>
    where
        R: ValidQuery + Into<QueryBox> + Debug + Clone,
        <R::Output as TryFrom<Value>>::Error: Into<Error>,
        R::Output: Clone + Debug;

    /// Polls request till predicate `f` is satisfied with `period` and `max_attempts` supplied.
    ///
    /// # Errors
    /// If predicate is not satisfied after maximum retries.
    fn poll_request_with_period<R>(
        &mut self,
        request: R,
        period: Duration,
        max_attempts: u32,
        f: impl Fn(&R::Output) -> bool,
    ) -> eyre::Result<R::Output>
    where
        R: ValidQuery + Into<QueryBox> + Debug + Clone,
        <R::Output as TryFrom<Value>>::Error: Into<Error>,
        R::Output: Clone + Debug;
}

#[cfg(feature = "query")]
pub mod query {
    //! Query mocking module.
    use super::*;

    /// Query result mocking trait.
    pub trait TestQueryResult {
        /// Tries to find asset by id
        fn find_asset_by_id(&self, asset_id: &AssetDefinitionId) -> Option<&Asset>;
    }

    impl TestQueryResult for QueryResult {
        fn find_asset_by_id(&self, asset_id: &AssetDefinitionId) -> Option<&Asset> {
            let assets = if let QueryResult(Value::Vec(assets)) = self {
                assets
            } else {
                panic!("Wrong Query Result Type.");
            };
            assets.iter().find_map(|asset| {
                if let Value::Identifiable(IdentifiableBox::Asset(asset)) = asset {
                    if &asset.id().definition_id == asset_id {
                        return Some(asset.as_ref());
                    }
                }
                None
            })
        }
    }
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

use std::collections::HashSet;

impl TestConfiguration for Configuration {
    fn test() -> Self {
        let mut configuration = iroha::samples::get_config(HashSet::new(), Some(get_key_pair()));
        configuration
            .load_environment()
            .expect("Failed to load configuration from environment");
        let (public_key, private_key) = KeyPair::generate().unwrap().into();
        configuration.public_key = public_key;
        configuration.private_key = private_key;
        configuration
    }

    fn pipeline_time() -> Duration {
        Duration::from_millis(Self::test().sumeragi.pipeline_time_ms())
    }

    fn block_sync_gossip_time() -> Duration {
        Duration::from_millis(Self::test().block_sync.gossip_period_ms)
    }
}

impl TestClientConfiguration for ClientConfiguration {
    fn test(api_url: &str, telemetry_url: &str) -> Self {
        let mut configuration = iroha_client::samples::get_client_config(&get_key_pair());
        configuration.torii_api_url = if api_url.starts_with("http") {
            small::SmallStr::from_str(api_url)
        } else {
            small::SmallStr::from_str(&("http://".to_owned() + api_url))
        };
        configuration.torii_telemetry_url = if telemetry_url.starts_with("http") {
            small::SmallStr::from_str(telemetry_url)
        } else {
            small::SmallStr::from_str(&("http://".to_owned() + telemetry_url))
        };
        configuration
    }
}

impl TestClient for Client {
    fn test(api_url: &str, telemetry_url: &str) -> Self {
        Client::new(&ClientConfiguration::test(api_url, telemetry_url))
            .expect("Invalid client configuration")
    }

    fn test_with_key(api_url: &str, telemetry_url: &str, keys: KeyPair) -> Self {
        let mut configuration = ClientConfiguration::test(api_url, telemetry_url);
        let (public_key, private_key) = keys.into();
        configuration.public_key = public_key;
        configuration.private_key = private_key;
        Client::new(&configuration).expect("Invalid client configuration")
    }

    fn test_with_account(
        api_url: &str,
        telemetry_url: &str,
        keys: KeyPair,
        account_id: &AccountId,
    ) -> Self {
        let mut configuration = ClientConfiguration::test(api_url, telemetry_url);
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

    fn submit_till<R>(
        &mut self,
        instruction: impl Into<Instruction> + Debug,
        request: R,
        f: impl Fn(&R::Output) -> bool,
    ) -> eyre::Result<R::Output>
    where
        R: ValidQuery + Into<QueryBox> + Debug + Clone,
        <R::Output as TryFrom<Value>>::Error: Into<Error>,
        R::Output: Clone + Debug,
    {
        self.submit(instruction)
            .expect("Failed to submit instruction.");
        self.poll_request(request, f)
    }

    fn submit_all_till<R>(
        &mut self,
        instructions: Vec<Instruction>,
        request: R,
        f: impl Fn(&R::Output) -> bool,
    ) -> eyre::Result<R::Output>
    where
        R: ValidQuery + Into<QueryBox> + Debug + Clone,
        <R::Output as TryFrom<Value>>::Error: Into<Error>,
        R::Output: Clone + Debug,
    {
        self.submit_all(instructions)
            .expect("Failed to submit instruction.");
        self.poll_request(request, f)
    }

    fn poll_request_with_period<R>(
        &mut self,
        request: R,
        period: Duration,
        max_attempts: u32,
        f: impl Fn(&R::Output) -> bool,
    ) -> eyre::Result<R::Output>
    where
        R: ValidQuery + Into<QueryBox> + Debug + Clone,
        <R::Output as TryFrom<Value>>::Error: Into<Error>,
        R::Output: Clone + Debug,
    {
        let mut query_result = None;
        for _ in 0..max_attempts {
            query_result = match self.request(request.clone()) {
                Ok(result) if f(&result) => return Ok(result),
                result => Some(result),
            };
            thread::sleep(period);
        }
        Err(eyre::eyre!("Failed to wait for query request completion that would satisfy specified closure. Got this query result instead: {:?}", &query_result))
    }

    fn poll_request<R>(
        &mut self,
        request: R,
        f: impl Fn(&R::Output) -> bool,
    ) -> eyre::Result<R::Output>
    where
        R: ValidQuery + Into<QueryBox> + Debug + Clone,
        <R::Output as TryFrom<Value>>::Error: Into<Error>,
        R::Output: Clone + Debug,
    {
        self.poll_request_with_period(request, Configuration::pipeline_time() / 2, 10, f)
    }
}
