//! Puppeteer for `irohad`, to create test networks

mod config;
pub mod fslock_ports;

use core::{fmt::Debug, time::Duration};
use std::{
    borrow::Cow,
    iter,
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
use iroha_crypto::{Algorithm, ExposedPrivateKey, KeyPair, PrivateKey};
use iroha_data_model::{
    events::pipeline::BlockEventFilter,
    isi::InstructionBox,
    parameter::{SumeragiParameter, SumeragiParameters},
    ChainId,
};
use iroha_genesis::GenesisBlock;
use iroha_primitives::{
    addr::{socket_addr, SocketAddr},
    unique_vec::UniqueVec,
};
use iroha_telemetry::metrics::Status;
use iroha_test_samples::{ALICE_ID, ALICE_KEYPAIR, PEER_KEYPAIR, SAMPLE_GENESIS_ACCOUNT_KEYPAIR};
use parity_scale_codec::Encode;
use rand::{prelude::IteratorRandom, thread_rng};
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

pub use crate::config::genesis as genesis_factory;

const INSTANT_PIPELINE_TIME: Duration = Duration::from_millis(10);
const DEFAULT_BLOCK_SYNC: Duration = Duration::from_millis(150);
const PEER_START_TIMEOUT: Duration = Duration::from_secs(30);
const PEER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
const SYNC_TIMEOUT: Duration = Duration::from_secs(5);

fn iroha_bin() -> impl AsRef<Path> {
    static PATH: OnceLock<PathBuf> = OnceLock::new();

    PATH.get_or_init(|| {
        if let Ok(path) = which::which("irohad") {
            path
        } else {
            eprintln!(
                "ERROR: could not locate `irohad` binary in $PATH\n  \
                It is required to run `iroha_test_network`.\n  \
                The easiest way to satisfy this is to run:\n\n    \
                cargo install --path ./crates/irohad --locked"
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

fn generate_and_keep_temp_dir() -> PathBuf {
    let mut builder = tempfile::Builder::new();
    builder.keep(true).prefix(TEMPDIR_PREFIX);
    match tempdir_in() {
        Some(create_within) => builder.tempdir_in(create_within),
        None => builder.tempdir(),
    }
    .expect("tempdir creation should work")
    .path()
    .to_path_buf()
}

/// Network of peers
pub struct Network {
    peers: Vec<NetworkPeer>,

    genesis_isi: Vec<InstructionBox>,
    block_time: Duration,
    commit_time: Duration,

    config_layers: Vec<Table>,
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
    /// - If some peer was already started
    /// - If some peer exists early
    pub async fn start_all(&self) -> &Self {
        timeout(
            PEER_START_TIMEOUT,
            self.peers
                .iter()
                .enumerate()
                .map(|(i, peer)| async move {
                    peer.start_checked(
                        self.config_layers(),
                        (i == 0).then_some(Cow::Owned(self.genesis())),
                    )
                    .await
                    .expect("peer failed to start");
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
    pub fn config_layers(&self) -> impl Iterator<Item = Cow<'_, Table>> {
        self.config_layers
            .iter()
            .map(Cow::Borrowed)
            .chain(Some(Cow::Owned(
                Table::new().write(["sumeragi", "trusted_peers"], self.trusted_peers()),
            )))
    }

    /// Network genesis block.
    ///
    /// It uses the basic [`genesis_factory`] with [`Self::genesis_isi`] +
    /// topology of the network peers.
    pub fn genesis(&self) -> GenesisBlock {
        genesis_factory(
            self.genesis_isi.clone(),
            self.peers.iter().map(NetworkPeer::id).collect(),
        )
    }

    /// Base network instructions included in the genesis block.
    pub fn genesis_isi(&self) -> &Vec<InstructionBox> {
        &self.genesis_isi
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

    fn trusted_peers(&self) -> UniqueVec<Peer> {
        self.peers
            .iter()
            .map(|x| Peer::new(x.p2p_address(), x.id()))
            .collect()
    }

    /// Resolves when all _running_ peers have at least N blocks
    /// # Errors
    /// If this doesn't happen within a timeout.
    pub async fn ensure_blocks(&self, height: u64) -> Result<&Self> {
        timeout(
            self.sync_timeout(),
            once_blocks_sync(self.peers.iter().filter(|x| x.is_running()), height),
        )
        .await
        .wrap_err_with(|| {
            eyre!("Network hasn't reached the height of {height} block(s) within timeout")
        })??;

        eprintln!("network reached height={height}");

        Ok(self)
    }
}

/// Builder of [`Network`]
pub struct NetworkBuilder {
    n_peers: usize,
    config_layers: Vec<Table>,
    pipeline_time: Option<Duration>,
    genesis_isi: Vec<InstructionBox>,
    seed: Option<String>,
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
            config_layers: vec![],
            pipeline_time: Some(INSTANT_PIPELINE_TIME),
            genesis_isi: vec![],
            seed: None,
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
    /// NetworkBuilder::new().with_config_layer(|t| {
    ///     t.write(["logger", "level"], "DEBUG");
    /// });
    /// ```
    pub fn with_config_layer<F>(mut self, f: F) -> Self
    where
        for<'a> F: FnOnce(&'a mut TomlWriter<'a>),
    {
        let mut table = Table::new();
        let mut writer = TomlWriter::new(&mut table);
        f(&mut writer);
        self.config_layers.push(table);
        self
    }

    /// Append an instruction to genesis.
    pub fn with_genesis_instruction(mut self, isi: impl Into<InstructionBox>) -> Self {
        self.genesis_isi.push(isi.into());
        self
    }

    pub fn with_base_seed(mut self, seed: impl ToString) -> Self {
        self.seed = Some(seed.to_string());
        self
    }

    /// Build the [`Network`]. Doesn't start it.
    pub fn build(self) -> Network {
        let network_dir = generate_and_keep_temp_dir();
        let peers: Vec<_> = (0..self.n_peers)
            .map(|i| {
                let peer_dir = network_dir.join(format!("peer{i}"));
                std::fs::create_dir_all(&peer_dir).unwrap();
                let seed = self.seed.as_ref().map(|x| format!("{x}-peer-{i}"));
                NetworkPeerBuilder::new()
                    .with_dir(Some(peer_dir))
                    .with_seed(seed.as_ref().map(|x| x.as_bytes()))
                    .build()
            })
            .collect();

        let block_sync_gossip_period = DEFAULT_BLOCK_SYNC;

        let block_time;
        let commit_time;
        if let Some(duration) = self.pipeline_time {
            block_time = duration / 3;
            commit_time = duration / 2;
        } else {
            block_time = SumeragiParameters::default().block_time();
            commit_time = SumeragiParameters::default().commit_time();
        }

        let genesis_isi = [
            InstructionBox::SetParameter(SetParameter::new(Parameter::Sumeragi(
                SumeragiParameter::BlockTimeMs(block_time.as_millis() as u64),
            ))),
            InstructionBox::SetParameter(SetParameter::new(Parameter::Sumeragi(
                SumeragiParameter::CommitTimeMs(commit_time.as_millis() as u64),
            ))),
        ]
        .into_iter()
        .chain(self.genesis_isi)
        .collect();

        Network {
            peers,
            genesis_isi,
            block_time,
            commit_time,
            config_layers: Some(config::base_iroha_config().write(
                ["network", "block_gossip_period_ms"],
                block_sync_gossip_period.as_millis() as u64,
            ))
            .into_iter()
            .chain(self.config_layers.into_iter())
            .collect(),
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
    key_pair: KeyPair,
    dir: PathBuf,
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
    pub async fn start<T: AsRef<Table>>(
        &self,
        config_layers: impl Iterator<Item = T>,
        genesis: Option<impl AsRef<GenesisBlock>>,
    ) {
        let mut run_guard = self.run.lock().await;
        assert!(run_guard.is_none(), "already running");

        let run_num = self.runs_count.fetch_add(1, Ordering::Relaxed) + 1;
        let log_prefix = self.log_prefix();
        eprintln!("{log_prefix} starting (run #{run_num})");

        let config_path = self
            .write_config_and_genesis(config_layers, genesis, run_num)
            .await
            .expect("fatal failure");

        let mut cmd = tokio::process::Command::new(iroha_bin().as_ref());
        cmd.stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .arg("--config")
            .arg(config_path);
        cmd.current_dir(&self.dir);
        let mut child = cmd.spawn().expect("spawn failure is abnormal");
        self.is_running.store(true, Ordering::Relaxed);
        let _ = self.events.send(PeerLifecycleEvent::Spawned);

        let mut tasks = JoinSet::<()>::new();

        {
            let output = child.stdout.take().unwrap();
            let mut file = File::create(self.dir.join(format!("run-{run_num}-stdout.log")))
                .await
                .unwrap();
            tasks.spawn(async move {
                let mut lines = BufReader::new(output).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    file.write_all(line.as_bytes())
                        .await
                        .expect("writing logs to file shouldn't fail");
                    file.write_all("\n".as_bytes())
                        .await
                        .expect("shouldn't fail either");
                    file.flush()
                        .await
                        .expect("writing logs to file shouldn't fail");
                }
            });
        }
        {
            let log_prefix = log_prefix.clone();
            let output = child.stderr.take().unwrap();
            let path = self.dir.join(format!("run-{run_num}-stderr.log"));
            tasks.spawn(async move {
                let mut in_memory = PeerStderrBuffer {
                    log_prefix,
                    buffer: String::new(),
                };
                let mut lines = BufReader::new(output).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    in_memory.buffer.push_str(&line);
                    in_memory.buffer.push('\n');
                }

                let mut file = File::create(path).await.expect("should create");
                file.write_all(in_memory.buffer.as_bytes())
                    .await
                    .expect("should write");
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
                    .listen_for_events_async([EventFilterBox::from(BlockEventFilter::default())])
                    .await
                    .unwrap_or_else(|err| {
                        eprintln!("{log_prefix} failed to subscribe on events: {err}");
                        panic!("cannot proceed")
                    });

                while let Some(Ok(event)) = events.next().await {
                    if let EventBox::Pipeline(PipelineEventBox::Block(block)) = event {
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

    pub async fn start_checked<T: AsRef<Table>>(
        &self,
        config_layers: impl Iterator<Item = T>,
        genesis: Option<impl AsRef<GenesisBlock>>,
    ) -> Result<()> {
        let failure = async move {
            self.once(|e| matches!(e, PeerLifecycleEvent::Terminated { .. }))
                .await;
            panic!("a peer exited unexpectedly");
        };
        let start = async move { self.start(config_layers, genesis).await };
        let server_started = async move {
            self.once(|e| matches!(e, PeerLifecycleEvent::ServerStarted))
                .await
        };

        let success = async move {
            tokio::join!(start, server_started);
        };

        // TODO: wait for server started?

        tokio::select! {
            _ = failure => {
                Err(eyre!("Peer exited unexpectedly"))
            },
            _ = success => {
                Ok(())
            },
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
    ///         peer.start(network.config_layers(), None),
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
        PeerId::new(self.key_pair.public_key().clone())
    }

    pub fn p2p_address(&self) -> SocketAddr {
        socket_addr!(127.0.0.1:**self.port_p2p)
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
                    .write(
                        ["account", "private_key"],
                        ExposedPrivateKey(account_private_key.clone()),
                    )
                    .write(["transaction", "status_timeout_ms"], 5_000)
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

    fn base_config(&self) -> Table {
        Table::new()
            .write("public_key", self.key_pair.public_key())
            .write(
                "private_key",
                ExposedPrivateKey(self.key_pair.private_key().clone()),
            )
            .write(["network", "address"], self.p2p_address())
            .write(["network", "public_address"], self.p2p_address())
            .write(
                ["torii", "address"],
                socket_addr!(127.0.0.1:**self.port_api),
            )
    }

    async fn write_config_and_genesis<T: AsRef<Table>>(
        &self,
        extra_layers: impl Iterator<Item = T>,
        genesis: Option<impl AsRef<GenesisBlock>>,

        run: usize,
    ) -> Result<PathBuf> {
        let extra_layers: Vec<_> = extra_layers
            .enumerate()
            .map(|(i, table)| (format!("run-{run}-config.layer-{i}.toml"), table))
            .collect();

        for (path, table) in &extra_layers {
            tokio::fs::write(self.dir.join(path), toml::to_string(table.as_ref())?).await?;
        }

        let mut final_config = Table::new().write(
            "extends",
            // should be written on peers initialisation
            iter::once("config.base.toml".to_string())
                .chain(extra_layers.into_iter().map(|(path, _)| path))
                .collect::<Vec<String>>(),
        );
        if let Some(block) = genesis {
            let path = self.dir.join(format!("run-{run}-genesis.scale"));
            final_config = final_config.write(["genesis", "file"], &path);
            tokio::fs::write(path, block.as_ref().0.encode()).await?;
        }
        let path = self.dir.join(format!("run-{run}-config.toml"));
        tokio::fs::write(&path, toml::to_string(&final_config)?).await?;

        Ok(path)
    }
}

/// Compare by ID
impl PartialEq for NetworkPeer {
    fn eq(&self, other: &Self) -> bool {
        self.key_pair.eq(&other.key_pair)
    }
}

#[derive(Default)]
pub struct NetworkPeerBuilder {
    dir: Option<PathBuf>,
    seed: Option<Vec<u8>>,
}

impl NetworkPeerBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_dir(mut self, dir: Option<impl Into<PathBuf>>) -> Self {
        self.dir = dir.map(Into::into);
        self
    }

    pub fn with_seed(mut self, seed: Option<impl Into<Vec<u8>>>) -> Self {
        self.seed = seed.map(Into::into);
        self
    }

    pub fn build(self) -> NetworkPeer {
        let key_pair = self
            .seed
            .map(|seed| KeyPair::from_seed(seed, Algorithm::Ed25519))
            .unwrap_or_else(KeyPair::random);
        let port_p2p = AllocatedPort::new();
        let port_api = AllocatedPort::new();

        let dir = self.dir.unwrap_or_else(generate_and_keep_temp_dir);

        let (events, _rx) = broadcast::channel(32);
        let (block_height, _rx) = watch::channel(None);

        let peer = NetworkPeer {
            key_pair,
            dir,
            run: Default::default(),
            runs_count: Default::default(),
            is_running: Default::default(),
            events,
            block_height,
            port_p2p: Arc::new(port_p2p),
            port_api: Arc::new(port_api),
        };

        // FIXME: move code
        std::fs::write(
            peer.dir.join("config.base.toml"),
            toml::to_string(&peer.base_config()).unwrap(),
        )
        .unwrap();

        eprintln!(
            "{} generated peer\n  dir: {}\n  public key: {}",
            peer.log_prefix(),
            peer.dir.display(),
            peer.key_pair.public_key(),
        );

        peer
    }
}

/// Prints collected STDERR on drop.
///
/// Used to avoid loss of useful data in case of task abortion before it is printed directly.
struct PeerStderrBuffer {
    log_prefix: String,
    buffer: String,
}

impl Drop for PeerStderrBuffer {
    fn drop(&mut self) {
        if !self.buffer.is_empty() {
            eprintln!(
                "{} STDERR:\n=======\n{}======= END OF STDERR",
                self.log_prefix, self.buffer
            );
        }
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

/// Wait until [`NetworkPeer::once_block`] resolves for all the peers.
pub async fn once_blocks_sync(
    peers: impl Iterator<Item = &NetworkPeer>,
    height: u64,
) -> Result<()> {
    let mut futures = peers
        .map(|x| async move {
            tokio::select! {
               () = x.once_block(height) => {
                    Ok(())
                },
                () = x.once(|e| matches!(e, PeerLifecycleEvent::Terminated { .. })) => {
                    Err(eyre!("Peer terminated"))
                }
            }
        })
        .collect::<FuturesUnordered<_>>();

    loop {
        match futures.next().await {
            Some(Ok(())) => {}
            Some(Err(e)) => return Err(e),
            None => return Ok(()),
        }
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
