//! User configuration view.
//!
//! Contains structures in a format that is convenient from the user perspective. It is less strict
//! and not necessarily valid upon successful parsing of the user-provided content.
//!
//! It begins with [`Root`], containing sub-modules. Every structure has its `-Partial`
//! representation (e.g. [`RootPartial`]).

// This module's usage is documented in high detail in the Configuration Reference
// (TODO link to docs)
#![allow(missing_docs)]

use std::{
    borrow::Cow,
    convert::Infallible,
    fmt::Debug,
    num::{NonZeroU32, NonZeroUsize},
    path::PathBuf,
};

use error_stack::{Result, ResultExt};
use iroha_config_base::{
    attach::ConfigValueAndOrigin,
    env::FromEnvStr,
    util::{Bytes, DurationMs, Emitter, EmitterResultExt},
    ReadConfig, WithOrigin,
};
use iroha_crypto::{PrivateKey, PublicKey};
use iroha_data_model::{peer::Peer, ChainId};
use iroha_primitives::{addr::SocketAddr, unique_vec::UniqueVec};
use serde::Deserialize;
use url::Url;

use super::actual::{
    BlockSyncBuilder, DevTelemetryBuilder, GenesisBuilder, KuraBuilder, LiveQueryStoreBuilder,
    LoggerBuilder, NetworkBuilder, QueueBuilder, SnapshotBuilder, SumeragiBuilder,
    TelemetryBuilder, ToriiBuilder, TransactionGossiperBuilder, TrustedPeersBuilder,
};
use crate::{
    kura::InitMode as KuraInitMode,
    logger::{Directives, Format as LoggerFormat},
    parameters::{actual, defaults},
    snapshot::Mode as SnapshotMode,
};

#[derive(Deserialize, Debug)]
struct ChainIdInConfig(ChainId);

impl FromEnvStr for ChainIdInConfig {
    type Error = Infallible;

    fn from_env_str(value: Cow<'_, str>) -> std::result::Result<Self, Self::Error>
    where
        Self: Sized,
    {
        Ok(Self(ChainId::from(value)))
    }
}

#[derive(Debug, ReadConfig)]
pub struct Root {
    #[config(env = "CHAIN")]
    chain: ChainIdInConfig,
    #[config(env = "PUBLIC_KEY")]
    public_key: WithOrigin<PublicKey>,
    #[config(env = "PRIVATE_KEY")]
    private_key: WithOrigin<PrivateKey>,
    #[config(env = "TRUSTED_PEERS", default)]
    trusted_peers: WithOrigin<TrustedPeers>,
    #[config(nested)]
    genesis: Genesis,
    #[config(nested)]
    kura: Kura,
    #[config(nested)]
    sumeragi: Sumeragi,
    #[config(nested)]
    network: Network,
    #[config(nested)]
    logger: Logger,
    #[config(nested)]
    queue: Queue,
    #[config(nested)]
    snapshot: Snapshot,
    telemetry: Option<Telemetry>,
    #[config(nested)]
    dev_telemetry: DevTelemetry,
    #[config(nested)]
    torii: Torii,
}

#[derive(thiserror::Error, Debug, Copy, Clone)]
pub enum ParseError {
    #[error("Failed to construct the key pair")]
    BadKeyPair,
    #[error("Failed to build configuration")]
    BuildConfig,
}

impl Root {
    /// Parses user configuration view into the internal repr.
    ///
    /// # Errors
    /// If any invalidity found.
    pub fn parse(self) -> Result<actual::Root, ParseError> {
        self.parse_builder()
            .and_then(|builder| builder.build().change_context(ParseError::BuildConfig))
    }

    #[allow(clippy::too_many_lines)]
    pub fn parse_builder(self) -> Result<actual::RootBuilder, ParseError> {
        let mut emitter = Emitter::new();

        let (private_key, private_key_origin) = self.private_key.into_tuple();
        let (public_key, public_key_origin) = self.public_key.into_tuple();
        let key_pair = iroha_crypto::KeyPair::new(public_key, private_key)
            .attach_printable(ConfigValueAndOrigin::new("[REDACTED]", public_key_origin))
            .attach_printable(ConfigValueAndOrigin::new("[REDACTED]", private_key_origin))
            .change_context(ParseError::BadKeyPair)
            .ok_or_emit(&mut emitter);

        let (network, block_sync, transaction_gossiper) = self.network.parse()?;

        let Some(key_pair) = key_pair.as_ref() else {
            panic!("Key pair is missing");
        };
        let peer = Peer::new(
            network.address().value().clone(),
            key_pair.public_key().clone(),
        );
        let trusted_peers = self.trusted_peers.map(|x| {
            TrustedPeersBuilder::default()
                .myself(peer.clone())
                .others(x.0)
                .build()
                .change_context(ParseError::BuildConfig)
                .expect("msg")
        });
        let genesis = self.genesis.parse()?;

        let kura = self.kura.parse()?;

        let logger = self.logger;
        let queue = self.queue;
        let snapshot = self.snapshot;
        let dev_telemetry = self.dev_telemetry;
        let (torii, live_query_store) = self.torii.parse()?;
        let telemetry = self.telemetry.map(Telemetry::parse).transpose()?;

        let sumeragi = self.sumeragi.parse()?;

        emitter.into_result()?;

        let peer = actual::CommonBuilder::default()
            .chain(self.chain.0)
            .key_pair(key_pair.clone())
            .peer(peer)
            .trusted_peers(trusted_peers)
            .build()
            .change_context(ParseError::BuildConfig)?;
        let queue = queue.parse()?;
        let logger = logger.parse()?;
        let snapshot = snapshot.parse()?;
        let dev_telemetry = dev_telemetry.parse()?;

        Ok(actual::RootBuilder::default()
            .common(peer)
            .network(network)
            .genesis(genesis)
            .torii(torii)
            .kura(kura)
            .sumeragi(sumeragi)
            .block_sync(block_sync)
            .transaction_gossiper(transaction_gossiper)
            .live_query_store(live_query_store)
            .logger(logger)
            .queue(queue)
            .snapshot(snapshot)
            .telemetry(telemetry)
            .dev_telemetry(dev_telemetry))
    }
}

#[derive(Debug, ReadConfig)]
pub struct Genesis {
    #[config(env = "GENESIS_PUBLIC_KEY")]
    pub public_key: WithOrigin<PublicKey>,
    #[config(env = "GENESIS")]
    pub file: Option<WithOrigin<PathBuf>>,
}

impl Genesis {
    pub fn parse(self) -> error_stack::Result<actual::Genesis, ParseError> {
        GenesisBuilder::default()
            .public_key(self.public_key.into_value())
            .file(self.file)
            .build()
            .change_context(ParseError::BuildConfig)
    }
}

#[derive(Debug, ReadConfig)]
pub struct Kura {
    #[config(env = "KURA_INIT_MODE", default)]
    pub init_mode: KuraInitMode,
    #[config(
        env = "KURA_STORE_DIR",
        default = "PathBuf::from(defaults::kura::STORE_DIR)"
    )]
    pub store_dir: WithOrigin<PathBuf>,
    #[config(
        env = "KURA_BLOCKS_IN_MEMORY",
        default = "defaults::kura::BLOCKS_IN_MEMORY"
    )]
    pub blocks_in_memory: NonZeroUsize,
    #[config(nested)]
    pub debug: KuraDebug,
}

impl Kura {
    fn parse(self) -> error_stack::Result<actual::Kura, ParseError> {
        let Self {
            init_mode,
            store_dir,
            blocks_in_memory,
            debug:
                KuraDebug {
                    output_new_blocks: debug_output_new_blocks,
                },
        } = self;
        KuraBuilder::default()
            .init_mode(init_mode)
            .store_dir(store_dir)
            .blocks_in_memory(blocks_in_memory)
            .debug_output_new_blocks(debug_output_new_blocks)
            .build()
            .change_context(ParseError::BuildConfig)
    }
}

#[derive(Debug, Clone, Copy, ReadConfig)]
pub struct KuraDebug {
    #[config(env = "KURA_DEBUG_OUTPUT_NEW_BLOCKS", default)]
    output_new_blocks: bool,
}

#[derive(Debug, Clone, Copy, ReadConfig)]
pub struct Sumeragi {
    #[config(nested)]
    pub debug: SumeragiDebug,
}

#[derive(Debug, Deserialize)]
pub struct TrustedPeers(UniqueVec<Peer>);

impl FromEnvStr for TrustedPeers {
    type Error = json5::Error;

    fn from_env_str(value: Cow<'_, str>) -> std::result::Result<Self, Self::Error>
    where
        Self: Sized,
    {
        Ok(Self(json5::from_str(value.as_ref())?))
    }
}

impl Default for TrustedPeers {
    fn default() -> Self {
        Self(UniqueVec::new())
    }
}

impl Sumeragi {
    fn parse(self) -> error_stack::Result<actual::Sumeragi, ParseError> {
        let Self {
            debug: SumeragiDebug { force_soft_fork },
        } = self;
        SumeragiBuilder::default()
            .debug_force_soft_fork(force_soft_fork)
            .build()
            .change_context(ParseError::BuildConfig)
    }
}

#[derive(Debug, Copy, Clone, ReadConfig)]
pub struct SumeragiDebug {
    #[config(default)]
    pub force_soft_fork: bool,
}

#[derive(Debug, Clone, ReadConfig)]
pub struct Network {
    /// Peer-to-peer address (internal, will be used only to bind to it).
    #[config(env = "P2P_ADDRESS")]
    pub address: WithOrigin<SocketAddr>,
    /// Peer-to-peer address (external, as seen by other peers).
    /// Will be gossiped to connected peers so that they can gossip it to other peers.
    #[config(env = "P2P_PUBLIC_ADDRESS")]
    pub public_address: WithOrigin<SocketAddr>,
    #[config(default = "defaults::network::BLOCK_GOSSIP_SIZE")]
    pub block_gossip_size: NonZeroU32,
    #[config(default = "defaults::network::BLOCK_GOSSIP_PERIOD.into()")]
    pub block_gossip_period_ms: DurationMs,
    #[config(default = "defaults::network::TRANSACTION_GOSSIP_SIZE")]
    pub transaction_gossip_size: NonZeroU32,
    #[config(default = "defaults::network::TRANSACTION_GOSSIP_PERIOD.into()")]
    pub transaction_gossip_period_ms: DurationMs,
    /// Duration of time after which connection with peer is terminated if peer is idle
    #[config(default = "defaults::network::IDLE_TIMEOUT.into()")]
    pub idle_timeout_ms: DurationMs,
}

impl Network {
    fn parse(
        self,
    ) -> error_stack::Result<
        (
            actual::Network,
            actual::BlockSync,
            actual::TransactionGossiper,
        ),
        ParseError,
    > {
        let Self {
            address,
            public_address,
            block_gossip_size,
            block_gossip_period_ms: block_gossip_period,
            transaction_gossip_size,
            transaction_gossip_period_ms: transaction_gossip_period,
            idle_timeout_ms: idle_timeout,
        } = self;

        let network_config = NetworkBuilder::default()
            .address(address)
            .public_address(public_address)
            .idle_timeout(idle_timeout.get())
            .build()
            .change_context(ParseError::BuildConfig)?;
        let block_sync_config = BlockSyncBuilder::default()
            .gossip_period(block_gossip_period.get())
            .gossip_size(block_gossip_size)
            .build()
            .change_context(ParseError::BuildConfig)?;
        let transcation_gossiper_config = TransactionGossiperBuilder::default()
            .gossip_period(transaction_gossip_period.get())
            .gossip_size(transaction_gossip_size)
            .build()
            .change_context(ParseError::BuildConfig)?;

        Ok((
            network_config,
            block_sync_config,
            transcation_gossiper_config,
        ))
    }
}

#[derive(Debug, Clone, Copy, ReadConfig)]
pub struct Queue {
    /// The upper limit of the number of transactions waiting in the queue.
    #[config(default = "defaults::queue::CAPACITY")]
    pub capacity: NonZeroUsize,
    /// The upper limit of the number of transactions waiting in the queue for a single user.
    /// Use this option to apply throttling.
    #[config(default = "defaults::queue::CAPACITY_PER_USER")]
    pub capacity_per_user: NonZeroUsize,
    /// The transaction will be dropped after this time if it is still in the queue.
    #[config(default = "defaults::queue::TRANSACTION_TIME_TO_LIVE.into()")]
    pub transaction_time_to_live_ms: DurationMs,
}

impl Queue {
    pub fn parse(self) -> error_stack::Result<actual::Queue, ParseError> {
        let Self {
            capacity,
            capacity_per_user,
            transaction_time_to_live_ms: transaction_time_to_live,
        } = self;

        QueueBuilder::default()
            .capacity(capacity)
            .capacity_per_user(capacity_per_user)
            .transaction_time_to_live(transaction_time_to_live.0)
            .build()
            .change_context(ParseError::BuildConfig)
    }
}

#[derive(Debug, Clone, Default, ReadConfig)]
pub struct Logger {
    /// Level of logging verbosity
    // TODO: parse user provided value in a case insensitive way,
    //       because `format` is set in lowercase, and `LOG_LEVEL=INFO` + `LOG_FORMAT=pretty`
    //       looks inconsistent
    #[config(env = "LOG_LEVEL", default)]
    pub level: Directives,
    /// Output format
    #[config(env = "LOG_FORMAT", default)]
    pub format: LoggerFormat,
}

impl Logger {
    pub fn parse(self) -> error_stack::Result<actual::Logger, ParseError> {
        LoggerBuilder::default()
            .level(self.level)
            .format(self.format)
            .build()
            .change_context(ParseError::BuildConfig)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Telemetry {
    // Fields here are Options so that it is possible to warn the user if e.g. they provided `min_retry_period`, but haven't
    // provided `name` and `url`
    name: String,
    url: Url,
    #[serde(default)]
    min_retry_period_ms: TelemetryMinRetryPeriod,
    #[serde(default)]
    max_retry_delay_exponent: TelemetryMaxRetryDelayExponent,
}

#[derive(Deserialize, Debug, Copy, Clone)]
struct TelemetryMinRetryPeriod(DurationMs);

impl Default for TelemetryMinRetryPeriod {
    fn default() -> Self {
        Self(DurationMs(defaults::telemetry::MIN_RETRY_PERIOD))
    }
}

#[derive(Deserialize, Debug, Copy, Clone)]
struct TelemetryMaxRetryDelayExponent(u8);

impl Default for TelemetryMaxRetryDelayExponent {
    fn default() -> Self {
        Self(defaults::telemetry::MAX_RETRY_DELAY_EXPONENT)
    }
}

impl Telemetry {
    pub fn parse(self) -> error_stack::Result<actual::Telemetry, ParseError> {
        let TelemetryMinRetryPeriod(DurationMs(min_retry_period)) = self.min_retry_period_ms;
        let TelemetryMaxRetryDelayExponent(max_retry_delay_exponent) =
            self.max_retry_delay_exponent;
        TelemetryBuilder::default()
            .name(self.name)
            .url(self.url)
            .min_retry_period(min_retry_period)
            .max_retry_delay_exponent(max_retry_delay_exponent)
            .build()
            .change_context(ParseError::BuildConfig)
    }
}

#[derive(Debug, Clone, ReadConfig)]
pub struct DevTelemetry {
    pub out_file: Option<WithOrigin<PathBuf>>,
}

impl DevTelemetry {
    pub fn parse(self) -> error_stack::Result<actual::DevTelemetry, ParseError> {
        DevTelemetryBuilder::default()
            .out_file(self.out_file)
            .build()
            .change_context(ParseError::BuildConfig)
    }
}

#[derive(Debug, Clone, ReadConfig)]
pub struct Snapshot {
    #[config(default, env = "SNAPSHOT_MODE")]
    pub mode: SnapshotMode,
    #[config(default = "defaults::snapshot::CREATE_EVERY.into()")]
    pub create_every_ms: DurationMs,
    #[config(
        default = "PathBuf::from(defaults::snapshot::STORE_DIR)",
        env = "SNAPSHOT_STORE_DIR"
    )]
    pub store_dir: WithOrigin<PathBuf>,
}

impl Snapshot {
    pub fn parse(self) -> error_stack::Result<actual::Snapshot, ParseError> {
        SnapshotBuilder::default()
            .mode(self.mode)
            .create_every(self.create_every_ms.get())
            .store_dir(self.store_dir)
            .build()
            .change_context(ParseError::BuildConfig)
    }
}

#[derive(Debug, ReadConfig)]
pub struct Torii {
    #[config(env = "API_ADDRESS")]
    pub address: WithOrigin<SocketAddr>,
    #[config(default = "defaults::torii::MAX_CONTENT_LEN")]
    pub max_content_len: Bytes<u64>,
    #[config(default = "defaults::torii::QUERY_IDLE_TIME.into()")]
    pub query_idle_time_ms: DurationMs,
    /// The upper limit of the number of live queries.
    #[config(default = "defaults::torii::QUERY_STORE_CAPACITY")]
    pub query_store_capacity: NonZeroUsize,
    /// The upper limit of the number of live queries for a single user.
    #[config(default = "defaults::torii::QUERY_STORE_CAPACITY_PER_USER")]
    pub query_store_capacity_per_user: NonZeroUsize,
}

impl Torii {
    fn parse(self) -> error_stack::Result<(actual::Torii, actual::LiveQueryStore), ParseError> {
        let torii = ToriiBuilder::default()
            .address(self.address)
            .max_content_len(self.max_content_len)
            .build()
            .change_context(ParseError::BuildConfig)?;
        let query = LiveQueryStoreBuilder::default()
            .idle_time(self.query_idle_time_ms.get())
            .capacity(self.query_store_capacity)
            .capacity_per_user(self.query_store_capacity_per_user)
            .build()
            .change_context(ParseError::BuildConfig)?;

        Ok((torii, query))
    }
}
