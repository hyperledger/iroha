//! Puppeteer for `irohad`, to create test networks

mod config;
mod fslock_ports;

use core::{fmt::Debug, time::Duration};
use std::{
    ops::Deref,
    path::{Path, PathBuf},
    process::{ExitStatus, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, OnceLock,
    },
};

use backoff::ExponentialBackoffBuilder;
use color_eyre::eyre::{eyre, Context, Result};
use fslock_ports::AllocatedPort;
use futures::{prelude::*, stream::FuturesUnordered};
use iroha::{client::Client, data_model::prelude::*};
use iroha_config::base::{
    read::ConfigReader,
    toml::{TomlSource, WriteExt as _, Writer as TomlWriter},
};
pub use iroha_core::state::StateReadOnly;
use iroha_crypto::{ExposedPrivateKey, KeyPair, PrivateKey};
use iroha_data_model::{
    events::pipeline::BlockEventFilter,
    isi::InstructionBox,
    parameter::{SumeragiParameter, SumeragiParameters},
    ChainId,
};
use iroha_genesis::GenesisBlock;
use iroha_primitives::{addr::socket_addr, unique_vec::UniqueVec};
use iroha_telemetry::metrics::Status;
use iroha_test_samples::{ALICE_ID, ALICE_KEYPAIR, PEER_KEYPAIR, SAMPLE_GENESIS_ACCOUNT_KEYPAIR};
use parity_scale_codec::Encode;
use rand::{prelude::IteratorRandom, thread_rng};
use tempfile::TempDir;
use tokio::{
    fs::File,
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::Child,
    runtime::{self, Runtime},
    sync::{broadcast, oneshot, watch, Mutex},
    task::{spawn_blocking, JoinSet},
    time::timeout,
};
use toml::Table;

const INSTANT_PIPELINE_TIME: Duration = Duration::from_millis(10);
const DEFAULT_BLOCK_SYNC: Duration = Duration::from_millis(150);
const PEER_START_TIMEOUT: Duration = Duration::from_secs(30);
const PEER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
const SYNC_TIMEOUT: Duration = Duration::from_secs(30);

fn iroha_bin() -> impl AsRef<Path> {
    static PATH: OnceLock<PathBuf> = OnceLock::new();

    PATH.get_or_init(|| match which::which("irohad") {
        Ok(path) => path,
        Err(_) => {
            eprintln!(
                "ERROR: could not locate `irohad` binary in $PATH\n  \
                    It is required to run `iroha_test_network`.\n  \
                    The easiest way to satisfy this is to run:\n\n    \
                    cargo install ./crates/irohad --locked"
            );
            panic!("could not proceed without `irohad`, see the message above");
        }
    })
}

const TEMPDIR_PREFIX: &str = "irohad_test_network_";
const TEMPDIR_IN_ENV: &str = "TEST_NETWORK_TMP_DIR";

fn tempdir_in() -> Option<impl AsRef<Path>> {
    static ENV: OnceLock<Option<PathBuf>> = OnceLock::new();

    ENV.get_or_init(|| std::env::var(TEMPDIR_IN_ENV).map(PathBuf::from).ok())
        .as_ref()
}

/// Network of peers
pub struct Network {
    peers: Vec<NetworkPeer>,

    genesis: GenesisBlock,
    block_time: Duration,
    commit_time: Duration,

    config: Table,
}

impl Network {
    /// Add a peer to the network.
    pub fn add_peer(&mut self, peer: &NetworkPeer) {
        self.peers.push(peer.clone());
    }

    /// Remove a peer from the network.
    pub fn remove_peer(&mut self, peer: &NetworkPeer) {
        self.peers.retain(|x| x != peer);
    }

    /// Access network peers
    pub fn peers(&self) -> &Vec<NetworkPeer> {
        &self.peers
    }

    /// Get a random peer in the network
    pub fn peer(&self) -> &NetworkPeer {
        self.peers
            .iter()
            .choose(&mut thread_rng())
            .expect("there is at least one peer")
    }

    /// Start all peers, waiting until they are up and have committed genesis (submitted by one of them).
    ///
    /// # Panics
    /// If some peer was already started
    pub async fn start_all(&self) -> &Self {
        timeout(
            PEER_START_TIMEOUT,
            self.peers
                .iter()
                .enumerate()
                .map(|(i, peer)| async move {
                    peer.start(
                        self.config(),
                        // TODO: make 0 random?
                        (i == 0).then_some(&self.genesis),
                    )
                    .await;
                    peer.once_block(1).await;
                })
                .collect::<FuturesUnordered<_>>()
                .collect::<Vec<_>>(),
        )
        .await
        .expect("expected peers to start within timeout");
        self
    }

    /// Pipeline time of the network.
    ///
    /// Is relevant only if users haven't submitted [`SumeragiParameter`] changing it.
    /// Users should do it through a network method (which hasn't been necessary yet).
    pub fn pipeline_time(&self) -> Duration {
        self.block_time + self.commit_time
    }

    pub fn consensus_estimation(&self) -> Duration {
        self.block_time + self.commit_time / 2
    }

    pub fn sync_timeout(&self) -> Duration {
        SYNC_TIMEOUT
    }

    pub fn peer_startup_timeout(&self) -> Duration {
        PEER_START_TIMEOUT
    }

    /// Get a client for a random peer in the network
    pub fn client(&self) -> Client {
        self.peer().client()
    }

    /// Chain ID of the network
    pub fn chain_id(&self) -> ChainId {
        config::chain_id()
    }

    /// Base configuration of all peers.
    ///
    /// Includes `sumeragi.trusted_peers` parameter, containing all currently present peers.
    pub fn config(&self) -> Table {
        self.config
            .clone()
            .write(["sumeragi", "trusted_peers"], self.topology())
    }

    /// Network genesis block.
    pub fn genesis(&self) -> &GenesisBlock {
        &self.genesis
    }

    /// Shutdown running peers
    pub async fn shutdown(&self) -> &Self {
        self.peers
            .iter()
            .filter(|peer| peer.is_running())
            .map(|peer| peer.shutdown())
            .collect::<FuturesUnordered<_>>()
            .collect::<Vec<_>>()
            .await;
        self
    }

    fn topology(&self) -> UniqueVec<PeerId> {
        self.peers.iter().map(|x| x.id.clone()).collect()
    }

    /// Resolves when all _running_ peers have at least N blocks
    /// # Errors
    /// If this doesn't happen within a timeout.
    pub async fn ensure_blocks(&self, height: u64) -> Result<&Self> {
        timeout(
            self.sync_timeout(),
            self.peers
                .iter()
                .filter(|x| x.is_running())
                .map(|x| x.once_block(height))
                .collect::<FuturesUnordered<_>>()
                .collect::<Vec<_>>(),
        )
        .await
        .wrap_err_with(|| {
            eyre!("Network hasn't reached the height of {height} block(s) within timeout")
        })?;

        eprintln!("network reached height={height}");

        Ok(self)
    }
}

/// Builder of [`Network`]
pub struct NetworkBuilder {
    n_peers: usize,
    config: Table,
    pipeline_time: Option<Duration>,
    extra_isi: Vec<InstructionBox>,
}

impl Default for NetworkBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Test network builder
impl NetworkBuilder {
    /// Constructor
    pub fn new() -> Self {
        Self {
            n_peers: 1,
            config: config::base_iroha_config(),
            pipeline_time: Some(INSTANT_PIPELINE_TIME),
            extra_isi: vec![],
        }
    }

    /// Set the number of peers in the network.
    ///
    /// One by default.
    pub fn with_peers(mut self, n_peers: usize) -> Self {
        assert_ne!(n_peers, 0);
        self.n_peers = n_peers;
        self
    }

    /// Set the pipeline time.
    ///
    /// Translates into setting of the [`SumeragiParameter::BlockTimeMs`] (1/3) and
    /// [`SumeragiParameter::CommitTimeMs`] (2/3) in the genesis block.
    ///
    /// Reflected in [`Network::pipeline_time`].
    pub fn with_pipeline_time(mut self, duration: Duration) -> Self {
        self.pipeline_time = Some(duration);
        self
    }

    /// Do not overwrite default pipeline time ([`SumeragiParameters::default`]) in genesis.
    pub fn with_default_pipeline_time(mut self) -> Self {
        self.pipeline_time = None;
        self
    }

    /// Add a layer of TOML configuration via [`TomlWriter`].
    ///
    /// # Example
    ///
    /// ```
    /// use iroha_test_network::NetworkBuilder;
    ///
    /// NetworkBuilder::new().with_config(|t| {
    ///     t.write(["logger", "level"], "DEBUG");
    /// });
    /// ```
    pub fn with_config<F>(mut self, f: F) -> Self
    where
        for<'a> F: FnOnce(&'a mut TomlWriter<'a>),
    {
        let mut writer = TomlWriter::new(&mut self.config);
        f(&mut writer);
        self
    }

    /// Append an instruction to genesis.
    pub fn with_genesis_instruction(mut self, isi: impl Into<InstructionBox>) -> Self {
        self.extra_isi.push(isi.into());
        self
    }

    /// Build the [`Network`]. Doesn't start it.
    pub fn build(self) -> Network {
        let peers: Vec<_> = (0..self.n_peers).map(|_| NetworkPeer::generate()).collect();

        let topology: UniqueVec<_> = peers.iter().map(|peer| peer.id.clone()).collect();

        let block_sync_gossip_period = DEFAULT_BLOCK_SYNC;

        let mut extra_isi = vec![];
        let block_time;
        let commit_time;
        if let Some(duration) = self.pipeline_time {
            block_time = duration / 3;
            commit_time = duration / 2;
            extra_isi.extend([
                InstructionBox::SetParameter(SetParameter(Parameter::Sumeragi(
                    SumeragiParameter::BlockTimeMs(block_time.as_millis() as u64),
                ))),
                InstructionBox::SetParameter(SetParameter(Parameter::Sumeragi(
                    SumeragiParameter::CommitTimeMs(commit_time.as_millis() as u64),
                ))),
            ]);
        } else {
            block_time = SumeragiParameters::default().block_time();
            commit_time = SumeragiParameters::default().commit_time();
        }

        let genesis = config::genesis(
            [
                InstructionBox::SetParameter(SetParameter(Parameter::Sumeragi(
                    SumeragiParameter::BlockTimeMs(block_time.as_millis() as u64),
                ))),
                InstructionBox::SetParameter(SetParameter(Parameter::Sumeragi(
                    SumeragiParameter::CommitTimeMs(commit_time.as_millis() as u64),
                ))),
            ]
            .into_iter()
            .chain(self.extra_isi),
            topology,
        );

        Network {
            peers,
            genesis,
            block_time,
            commit_time,
            config: self.config.write(
                ["network", "block_gossip_period_ms"],
                block_sync_gossip_period.as_millis() as u64,
            ),
        }
    }

    /// Same as [`Self::build`], but also creates a [`Runtime`].
    ///
    /// This method exists for convenience and to preserve compatibility with non-async tests.
    pub fn build_blocking(self) -> (Network, Runtime) {
        let rt = runtime::Builder::new_multi_thread()
            .thread_stack_size(32 * 1024 * 1024)
            .enable_all()
            .build()
            .unwrap();
        let network = self.build();
        (network, rt)
    }

    /// Build and start the network.
    ///
    /// Resolves when all peers are running and have committed genesis block.
    /// See [`Network::start_all`].
    pub async fn start(self) -> Result<Network> {
        let network = self.build();
        network.start_all().await;
        Ok(network)
    }

    /// Combination of [`Self::build_blocking`] and [`Self::start`].
    pub fn start_blocking(self) -> Result<(Network, Runtime)> {
        let (network, rt) = self.build_blocking();
        rt.block_on(async { network.start_all().await });
        Ok((network, rt))
    }
}

/// A common signatory in the test network.
///
/// # Example
///
/// ```
/// use iroha_test_network::Signatory;
///
/// let _alice_kp = Signatory::Alice.key_pair();
/// ```
pub enum Signatory {
    Peer,
    Genesis,
    Alice,
}

impl Signatory {
    /// Get the associated key pair
    pub fn key_pair(&self) -> &KeyPair {
        match self {
            Signatory::Peer => &PEER_KEYPAIR,
            Signatory::Genesis => &SAMPLE_GENESIS_ACCOUNT_KEYPAIR,
            Signatory::Alice => &ALICE_KEYPAIR,
        }
        .deref()
    }
}

/// Running Iroha peer.
///
/// Aborts peer forcefully when dropped
#[derive(Debug)]
struct PeerRun {
    tasks: JoinSet<()>,
    shutdown: oneshot::Sender<()>,
}

/// Lifecycle events of a peer
#[derive(Copy, Clone, Debug)]
pub enum PeerLifecycleEvent {
    /// Process spawned
    Spawned,
    /// Server started to respond
    ServerStarted,
    /// Process terminated
    Terminated { status: ExitStatus },
    /// Process was killed
    Killed,
    /// Caught a related pipeline event
    BlockApplied { height: u64 },
}

/// Controls execution of `irohad` child process.
///
/// While exists, allocates socket ports and a temporary directory (not cleared automatically).
///
/// It can be started and shut down repeatedly.
/// It stores configuration and logs for each run separately.
///
/// When dropped, aborts the child process (if it is running).
#[derive(Clone, Debug)]
pub struct NetworkPeer {
    id: PeerId,
    key_pair: KeyPair,
    dir: Arc<TempDir>,
    run: Arc<Mutex<Option<PeerRun>>>,
    runs_count: Arc<AtomicUsize>,
    is_running: Arc<AtomicBool>,
    events: broadcast::Sender<PeerLifecycleEvent>,
    block_height: watch::Sender<Option<u64>>,
    // dropping these the last
    port_p2p: Arc<AllocatedPort>,
    port_api: Arc<AllocatedPort>,
}

impl NetworkPeer {
    /// Generate a random peer
    pub fn generate() -> Self {
        let key_pair = KeyPair::random();
        let port_p2p = AllocatedPort::new();
        let port_api = AllocatedPort::new();
        let id = PeerId::new(
            socket_addr!(127.0.0.1:*port_p2p),
            key_pair.public_key().clone(),
        );
        let temp_dir = Arc::new({
            let mut builder = tempfile::Builder::new();
            builder.keep(true).prefix(TEMPDIR_PREFIX);
            match tempdir_in() {
                Some(path) => builder.tempdir_in(path),
                None => builder.tempdir(),
            }
            .expect("temp dirs must be available in the system")
        });

        let (events, _rx) = broadcast::channel(32);
        let (block_height, _rx) = watch::channel(None);

        let result = Self {
            id,
            key_pair,
            dir: temp_dir,
            run: Default::default(),
            runs_count: Default::default(),
            is_running: Default::default(),
            events,
            block_height,
            port_p2p: Arc::new(port_p2p),
            port_api: Arc::new(port_api),
        };

        eprintln!(
            "{} generated peer, dir: {}",
            result.log_prefix(),
            result.dir.path().display()
        );

        result
    }

    fn log_prefix(&self) -> String {
        format!("[PEER p2p: {}, api: {}]", self.port_p2p, self.port_api)
    }

    /// Spawn the child process.
    ///
    /// Passed configuration must contain network topology in the `sumeragi.trusted_peers` parameter.
    ///
    /// This function doesn't wait for peer server to start working, or for it to commit genesis block.
    /// Iroha could as well terminate immediately with an error, and it is not tracked by this function.
    /// Use [`Self::events`]/[`Self::once`] to monitor peer's lifecycle.
    ///
    /// # Panics
    /// If peer was not started.
    pub async fn start(&self, config: Table, genesis: Option<&GenesisBlock>) {
        let mut run_guard = self.run.lock().await;
        assert!(run_guard.is_none(), "already running");

        let run_num = self.runs_count.fetch_add(1, Ordering::Relaxed) + 1;

        let log_prefix = self.log_prefix();
        eprintln!("{log_prefix} starting (run #{run_num})");

        let mut config = config
            .clone()
            .write("public_key", self.key_pair.public_key())
            .write(
                "private_key",
                ExposedPrivateKey(self.key_pair.private_key().clone()),
            )
            .write(
                ["network", "address"],
                format!("127.0.0.1:{}", self.port_p2p),
            )
            .write(["torii", "address"], format!("127.0.0.1:{}", self.port_api))
            .write(["logger", "format"], "json");

        let config_path = self.dir.path().join(format!("run-{run_num}-config.toml"));
        let genesis_path = self.dir.path().join(format!("run-{run_num}-genesis.scale"));

        if genesis.is_some() {
            config = config.write(["genesis", "file"], &genesis_path);
        }

        tokio::fs::write(
            &config_path,
            toml::to_string(&config).expect("TOML config is valid"),
        )
        .await
        .expect("temp directory exists and there was no config file before");

        if let Some(genesis) = genesis {
            tokio::fs::write(genesis_path, genesis.0.encode())
                .await
                .expect("tmp dir is available and genesis was not written before");
        }

        let mut cmd = tokio::process::Command::new(iroha_bin().as_ref());
        cmd.stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .arg("--config")
            .arg(config_path);
        cmd.current_dir(self.dir.path());
        let mut child = cmd.spawn().expect("spawn failure is abnormal");
        self.is_running.store(true, Ordering::Relaxed);
        let _ = self.events.send(PeerLifecycleEvent::Spawned);

        let mut tasks = JoinSet::<()>::new();

        {
            // let mut events_tx = self.events.clone();
            let output = child.stdout.take().unwrap();
            let mut file = File::create(self.dir.path().join(format!("run-{run_num}-stdout.log")))
                .await
                .unwrap();
            tasks.spawn(async move {
                let mut lines = BufReader::new(output).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    // let value: serde_json::Value =
                    //     serde_json::from_str(&line).expect("each log line is a valid JSON");
                    // handle_peer_log_message(&value, &mut events_tx);

                    file.write_all(line.as_bytes())
                        .await
                        .expect("writing logs to file shouldn't fail");
                    file.flush()
                        .await
                        .expect("writing logs to file shouldn't fail");
                }
            });
        }
        {
            let output = child.stderr.take().unwrap();
            let mut file = File::create(self.dir.path().join(format!("run-{run_num}-stderr.log")))
                .await
                .unwrap();
            tasks.spawn(async move {
                // TODO: handle panic?
                tokio::io::copy(&mut BufReader::new(output), &mut file)
                    .await
                    .expect("writing logs to file shouldn't fail");
            });
        }

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let peer_exit = PeerExit {
            child,
            log_prefix: log_prefix.clone(),
            is_running: self.is_running.clone(),
            events: self.events.clone(),
            block_height: self.block_height.clone(),
        };
        tasks.spawn(async move {
            if let Err(err) = peer_exit.monitor(shutdown_rx).await {
                eprintln!("something went very bad during peer exit monitoring: {err}");
                panic!()
            }
        });

        {
            let log_prefix = log_prefix.clone();
            let client = self.client();
            let events_tx = self.events.clone();
            let block_height_tx = self.block_height.clone();
            tasks.spawn(async move {
                let status_client = client.clone();
                let status = backoff::future::retry(
                    ExponentialBackoffBuilder::new()
                        .with_initial_interval(Duration::from_millis(50))
                        .with_max_interval(Duration::from_secs(1))
                        .with_max_elapsed_time(None)
                        .build(),
                    move || {
                        let client = status_client.clone();
                        async move {
                            let status = spawn_blocking(move || client.get_status())
                                .await
                                .expect("should not panic")?;
                            Ok(status)
                        }
                    },
                )
                .await
                .expect("there is no max elapsed time");
                let _ = events_tx.send(PeerLifecycleEvent::ServerStarted);
                let _ = block_height_tx.send(Some(status.blocks));
                eprintln!("{log_prefix} server started, {status:?}");

                let mut events = client
                    .listen_for_events_async([
                        EventFilterBox::from(BlockEventFilter::default()),
                        // TransactionEventFilter::default().into(),
                    ])
                    .await
                    .unwrap_or_else(|err| {
                        eprintln!("{log_prefix} failed to subscribe on events: {err}");
                        panic!("cannot proceed")
                    });

                while let Some(Ok(event)) = events.next().await {
                    if let EventBox::Pipeline(PipelineEventBox::Block(block)) = event {
                        // FIXME: should we wait for `Applied` event instead?
                        if *block.status() == BlockStatus::Applied {
                            let height = block.header().height().get();
                            eprintln!("{log_prefix} BlockStatus::Applied height={height}",);
                            let _ = events_tx.send(PeerLifecycleEvent::BlockApplied { height });
                            block_height_tx.send_modify(|x| *x = Some(height));
                        }
                    }
                }
                eprintln!("{log_prefix} events stream is closed");
            });
        }

        *run_guard = Some(PeerRun {
            tasks,
            shutdown: shutdown_tx,
        });
    }

    /// Forcefully kills the running peer
    ///
    /// # Panics
    /// If peer was not started.
    pub async fn shutdown(&self) {
        let mut guard = self.run.lock().await;
        let Some(run) = (*guard).take() else {
            panic!("peer is not running, nothing to shut down");
        };
        if self.is_running() {
            let _ = run.shutdown.send(());
            timeout(PEER_SHUTDOWN_TIMEOUT, run.tasks.join_all())
                .await
                .expect("run-related tasks should exit within timeout");
            assert!(!self.is_running());
        }
    }

    /// Subscribe on peer lifecycle events.
    pub fn events(&self) -> broadcast::Receiver<PeerLifecycleEvent> {
        self.events.subscribe()
    }

    /// Wait _once_ an event matches a predicate.
    ///
    /// ```
    /// use iroha_test_network::{Network, NetworkBuilder, PeerLifecycleEvent};
    ///
    /// #[tokio::main]
    /// async fn mail() {
    ///     let network = NetworkBuilder::new().build();
    ///     let peer = network.peer();
    ///
    ///     tokio::join!(
    ///         peer.start(network.config(), None),
    ///         peer.once(|event| matches!(event, PeerLifecycleEvent::ServerStarted))
    ///     );
    /// }
    /// ```
    ///
    /// It is a narrowed version of [`Self::events`].
    pub async fn once<F>(&self, f: F)
    where
        F: Fn(PeerLifecycleEvent) -> bool,
    {
        let mut rx = self.events();
        loop {
            tokio::select! {
                Ok(event) = rx.recv() => {
                    if f(event) { break }
                }
            }
        }
    }

    /// Wait until peer's block height reaches N.
    ///
    /// Resolves immediately if peer is already running _and_ its current block height is greater or equal to N.
    pub async fn once_block(&self, n: u64) {
        let mut recv = self.block_height.subscribe();

        if recv.borrow().map(|x| x >= n).unwrap_or(false) {
            return;
        }

        loop {
            recv.changed()
                .await
                .expect("could fail only if the peer is dropped");

            if recv.borrow_and_update().map(|x| x >= n).unwrap_or(false) {
                break;
            }
        }
    }

    /// Generated [`PeerId`]
    pub fn id(&self) -> PeerId {
        self.id.clone()
    }

    /// Check whether the peer is running
    pub fn is_running(&self) -> bool {
        self.is_running.load(Ordering::Relaxed)
    }

    /// Create a client to interact with this peer
    pub fn client_for(&self, account_id: &AccountId, account_private_key: PrivateKey) -> Client {
        let config = ConfigReader::new()
            .with_toml_source(TomlSource::inline(
                Table::new()
                    .write("chain", config::chain_id())
                    .write(["account", "domain"], account_id.domain())
                    .write(["account", "public_key"], account_id.signatory())
                    .write(["account", "private_key"], account_private_key.expose())
                    .write("torii_url", format!("http://127.0.0.1:{}", self.port_api)),
            ))
            .read_and_complete::<iroha::config::UserConfig>()
            .expect("peer client config should be valid")
            .parse()
            .expect("peer client config should be valid");

        Client::new(config)
    }

    /// Client for Alice. ([`Self::client_for`] + [`Signatory::Alice`])
    pub fn client(&self) -> Client {
        self.client_for(&ALICE_ID, ALICE_KEYPAIR.private_key().clone())
    }

    pub async fn status(&self) -> Result<Status> {
        let client = self.client();
        spawn_blocking(move || client.get_status())
            .await
            .expect("should not panic")
    }

    pub fn blocks(&self) -> watch::Receiver<Option<u64>> {
        self.block_height.subscribe()
    }
}

/// Compare by ID
impl PartialEq for NetworkPeer {
    fn eq(&self, other: &Self) -> bool {
        self.id.eq(&other.id)
    }
}

// fn handle_peer_log_message(log: &serde_json::Value, tx: &broadcast::Sender<PeerLifecycleEvent>) {
//     let is_info = log
//         .get("level")
//         .map(|level| level.as_str().map(|value| value == "INFO"))
//         .flatten()
//         .unwrap_or(false);
//
//     let message = log
//         .get("fields")
//         .map(|fields| fields.get("message"))
//         .flatten()
//         .map(|v| v.as_str())
//         .flatten();
//
//     if is_info && message.map(|x| x == "Block committed").unwrap_or(false) {
//         let height: u64 = log
//             .get("fields")
//             .expect("exists")
//             .get("new_height")
//             .expect("should exist for this message")
//             .as_str()
//             .expect("it is a string")
//             .parse()
//             .expect("it is a valid integer");
//
//         let _ = tx.send(PeerLifecycleEvent::LogBlockCommitted { height });
//     }
// }

impl From<NetworkPeer> for Box<Peer> {
    fn from(val: NetworkPeer) -> Self {
        Box::new(Peer::new(val.id.clone()))
    }
}

struct PeerExit {
    child: Child,
    log_prefix: String,
    is_running: Arc<AtomicBool>,
    events: broadcast::Sender<PeerLifecycleEvent>,
    block_height: watch::Sender<Option<u64>>,
}

impl PeerExit {
    async fn monitor(mut self, shutdown: oneshot::Receiver<()>) -> Result<()> {
        let status = tokio::select! {
            status = self.child.wait() => status?,
            _ = shutdown => self.shutdown_or_kill().await?,
        };

        eprintln!("{} {status}", self.log_prefix);
        let _ = self.events.send(PeerLifecycleEvent::Terminated { status });
        self.is_running.store(false, Ordering::Relaxed);
        self.block_height.send_modify(|x| *x = None);

        Ok(())
    }

    async fn shutdown_or_kill(&mut self) -> Result<ExitStatus> {
        use nix::{sys::signal, unistd::Pid};
        const TIMEOUT: Duration = Duration::from_secs(5);

        eprintln!("{} sending SIGTERM", self.log_prefix);
        signal::kill(
            Pid::from_raw(self.child.id().ok_or(eyre!("race condition"))? as i32),
            signal::Signal::SIGTERM,
        )
        .wrap_err("failed to send SIGTERM")?;

        if let Ok(status) = timeout(TIMEOUT, self.child.wait()).await {
            eprintln!("{} exited gracefully", self.log_prefix);
            return status.wrap_err("wait failure");
        };
        eprintln!(
            "{} process didn't terminate after {TIMEOUT:?}, killing",
            self.log_prefix
        );
        timeout(TIMEOUT, async move {
            self.child.kill().await.expect("not a recoverable failure");
            self.child.wait().await
        })
        .await
        .wrap_err("didn't terminate after SIGKILL")?
        .wrap_err("wait failure")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn can_start_networks() {
        NetworkBuilder::new().with_peers(4).start().await.unwrap();
        NetworkBuilder::new().start().await.unwrap();
    }
}
