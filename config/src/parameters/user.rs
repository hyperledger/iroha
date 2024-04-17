//! User configuration view. Contains structures in a format that is
//! convenient from the user perspective. It is less strict and not necessarily valid upon
//! successful parsing of the user-provided content.
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
    read::{CustomEnvFetcher, CustomEnvRead, CustomEnvReadError},
    util::{Emitter, EmitterResultExt, HumanBytes, HumanDuration},
    ReadConfig, WithOrigin,
};
use iroha_crypto::PrivateKey;
use iroha_data_model::{
    metadata::Limits as MetadataLimits, peer::PeerId, transaction::TransactionLimits, ChainId,
    LengthLimits, Level,
};
use iroha_primitives::{
    addr::SocketAddr,
    unique_vec::{PushResult, UniqueVec},
};
use serde::Deserialize;
use url::Url;

use crate::{
    kura::InitMode as KuraInitMode,
    logger::Format as LoggerFormat,
    parameters::{
        actual, defaults,
        util::{read_private_key_from_env, PrivateKeyFromEnvError},
    },
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
    #[config(env = "CHAIN_ID")]
    chain_id: ChainIdInConfig,
    #[config(env = "PUBLIC_KEY")]
    public_key: WithOrigin<iroha_crypto::PublicKey>,
    #[config(env_custom)]
    private_key: WithOrigin<RootPrivateKey>,
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
    #[config(nested)]
    chain_wide: ChainWide,
}

#[derive(Debug, Deserialize)]
struct RootPrivateKey(PrivateKey);

impl CustomEnvRead for RootPrivateKey {
    type Context = PrivateKeyFromEnvError;

    fn read<'a>(
        fetcher: &'a mut CustomEnvFetcher<'a>,
    ) -> std::result::Result<Option<Self>, CustomEnvReadError<Self::Context>> {
        read_private_key_from_env(fetcher, "PRIVATE_KEY_").map(|x| x.map(RootPrivateKey))
    }
}

#[derive(thiserror::Error, Debug)]
pub enum ParseError {
    #[error("Failed to construct the key pair")]
    BadKeyPair,
    #[error("Invalid genesis configuration")]
    BadGenesis,
    #[error("Trusted peers contains self peer id: {id}")]
    TrustedPeersWithSelf { id: PeerId },
}

impl Root {
    /// Parses user configuration view into the internal repr.
    ///
    /// # Errors
    /// If any invalidity found.
    #[allow(clippy::too_many_lines)]
    pub fn parse(self) -> Result<actual::Root, ParseError> {
        let mut emitter = Emitter::new();

        let (private_key, private_key_origin) = self.private_key.into_tuple();
        let (public_key, public_key_origin) = self.public_key.into_tuple();
        let key_pair = iroha_crypto::KeyPair::new(public_key, private_key.0)
            .attach_printable(ConfigValueAndOrigin::new("[REDACTED]", public_key_origin))
            .attach_printable(ConfigValueAndOrigin::new("[REDACTED]", private_key_origin))
            .change_context(ParseError::BadKeyPair)
            .ok_or_emit(&mut emitter);

        let genesis = self
            .genesis
            .parse()
            .change_context(ParseError::BadGenesis)
            .ok_or_emit(&mut emitter);

        let kura = self.kura.parse();

        let (network, block_sync, transaction_gossiper) = self.network.parse();
        let logger = self.logger;
        let queue = self.queue;
        let snapshot = self.snapshot;
        let dev_telemetry = self.dev_telemetry;
        let (torii, live_query_store) = self.torii.parse();
        let telemetry = self.telemetry.map(actual::Telemetry::from);
        let chain_wide = self.chain_wide.parse();

        let peer_id = key_pair.as_ref().map(|key_pair| {
            PeerId::new(
                network.address.value().clone(),
                key_pair.public_key().clone(),
            )
        });

        let sumeragi = peer_id
            .as_ref()
            .map(|id| self.sumeragi.parse_and_push_self(id.clone()))
            .transpose()
            .ok_or_emit(&mut emitter)
            .flatten();

        emitter.into_result()?;

        let key_pair = key_pair.unwrap();
        let peer = actual::Common {
            chain_id: self.chain_id.0,
            key_pair,
            peer_id: peer_id.unwrap(),
        };
        let genesis = genesis.unwrap();

        Ok(actual::Root {
            common: peer,
            network,
            genesis,
            torii,
            kura,
            sumeragi: sumeragi.unwrap(),
            block_sync,
            transaction_gossiper,
            live_query_store,
            logger,
            queue: queue.parse(),
            snapshot,
            telemetry,
            dev_telemetry,
            chain_wide,
        })
    }
}

#[derive(Debug, ReadConfig)]
pub struct Genesis {
    #[config(env = "GENESIS_PUBLIC_KEY")]
    pub public_key: WithOrigin<iroha_crypto::PublicKey>,
    #[config(env_custom)]
    pub private_key: Option<WithOrigin<GenesisPrivateKey>>,
    #[config(env = "GENESIS_FILE")]
    pub file: Option<WithOrigin<PathBuf>>,
}

#[derive(Debug, Deserialize)]
pub struct GenesisPrivateKey(PrivateKey);

impl CustomEnvRead for GenesisPrivateKey {
    type Context = PrivateKeyFromEnvError;

    fn read<'a>(
        fetcher: &'a mut CustomEnvFetcher<'a>,
    ) -> std::result::Result<Option<Self>, CustomEnvReadError<Self::Context>> {
        read_private_key_from_env(fetcher, "GENESIS_PRIVATE_KEY_").map(|x| x.map(GenesisPrivateKey))
    }
}

impl Genesis {
    fn parse(self) -> Result<actual::Genesis, GenesisConfigError> {
        match (self.private_key, self.file) {
            (None, None) => Ok(actual::Genesis::Partial {
                public_key: self.public_key.into_value(),
            }),
            (Some(private_key), Some(file)) => {
                let (private_key, priv_key_origin) = private_key.into_tuple();
                let (public_key, pub_key_origin) = self.public_key.into_tuple();
                let key_pair = iroha_crypto::KeyPair::new(public_key, private_key.0)
                    .attach_printable(ConfigValueAndOrigin::new("[REDACTED]", pub_key_origin))
                    .attach_printable(ConfigValueAndOrigin::new("[REDACTED]", priv_key_origin))
                    .change_context(GenesisConfigError::KeyPair)?;
                Ok(actual::Genesis::Full { key_pair, file })
            }
            (key, _) => {
                Err(GenesisConfigError::Inconsistent).attach_printable(if key.is_some() {
                    "`genesis.private_key` is set, but `genesis.file` is not"
                } else {
                    "`genesis.file` is set, but `genesis.private_key` is not"
                })?
            }
        }
    }
}

#[derive(Debug, displaydoc::Display, thiserror::Error, Copy, Clone)]
pub enum GenesisConfigError {
    /// Invalid combination of provided parameters
    Inconsistent,
    /// failed to construct the genesis's keypair from public and private keys
    KeyPair,
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
    #[config(nested)]
    pub debug: KuraDebug,
}

impl Kura {
    fn parse(self) -> actual::Kura {
        let Self {
            init_mode,
            store_dir,
            debug:
                KuraDebug {
                    output_new_blocks: debug_output_new_blocks,
                },
        } = self;

        actual::Kura {
            init_mode,
            store_dir,
            debug_output_new_blocks,
        }
    }
}

#[derive(Debug, Copy, Clone, ReadConfig)]
pub struct KuraDebug {
    #[config(env = "KURA_DEBUG_OUTPUT_NEW_BLOCKS", default)]
    output_new_blocks: bool,
}

#[derive(Debug, ReadConfig)]
pub struct Sumeragi {
    #[config(env = "SUMERAGI_TRUSTED_PEERS", default)]
    pub trusted_peers: WithOrigin<TrustedPeers>,
    #[config(nested)]
    pub debug: SumeragiDebug,
}

#[derive(Debug, Deserialize)]
pub struct TrustedPeers(UniqueVec<PeerId>);

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
    fn parse_and_push_self(self, self_id: PeerId) -> Result<actual::Sumeragi, ParseError> {
        let Self {
            trusted_peers,
            debug: SumeragiDebug { force_soft_fork },
        } = self;

        let mut trusted_peers = trusted_peers.map(|x| x.0);
        if let PushResult::Duplicate(duplicate) = trusted_peers.value_mut().push(self_id) {
            Err(ParseError::TrustedPeersWithSelf { id: duplicate })
                .attach_printable(trusted_peers.into_attachment().display_as_debug())?
        } else {
            Ok(actual::Sumeragi {
                trusted_peers,
                debug_force_soft_fork: force_soft_fork,
            })
        }
    }
}

#[derive(Debug, Copy, Clone, ReadConfig)]
pub struct SumeragiDebug {
    #[config(default)]
    pub force_soft_fork: bool,
}

#[derive(Debug, Clone, ReadConfig)]
pub struct Network {
    /// Peer-to-peer address
    #[config(env = "P2P_ADDRESS")]
    pub address: WithOrigin<SocketAddr>,
    #[config(default = "defaults::network::BLOCK_GOSSIP_MAX_SIZE")]
    pub block_gossip_max_size: NonZeroU32,
    #[config(default = "defaults::network::BLOCK_GOSSIP_PERIOD.into()")]
    pub block_gossip_period: HumanDuration,
    #[config(default = "defaults::network::TRANSACTION_GOSSIP_MAX_SIZE")]
    pub transaction_gossip_max_size: NonZeroU32,
    #[config(default = "defaults::network::TRANSACTION_GOSSIP_PERIOD.into()")]
    pub transaction_gossip_period: HumanDuration,
    /// Duration of time after which connection with peer is terminated if peer is idle
    #[config(default = "defaults::network::IDLE_TIMEOUT.into()")]
    pub idle_timeout: HumanDuration,
}

impl Network {
    fn parse(
        self,
    ) -> (
        actual::Network,
        actual::BlockSync,
        actual::TransactionGossiper,
    ) {
        let Self {
            address,
            block_gossip_max_size,
            block_gossip_period,
            transaction_gossip_max_size,
            transaction_gossip_period,
            idle_timeout,
        } = self;

        (
            actual::Network {
                address,
                idle_timeout: idle_timeout.get(),
            },
            actual::BlockSync {
                gossip_period: block_gossip_period.get(),
                gossip_max_size: block_gossip_max_size,
            },
            actual::TransactionGossiper {
                gossip_period: transaction_gossip_period.get(),
                gossip_max_size: transaction_gossip_max_size,
            },
        )
    }
}

#[derive(Debug, Clone, Copy, ReadConfig)]
pub struct Queue {
    /// The upper limit of the number of transactions waiting in the queue.
    #[config(default = "defaults::queue::CAPACITY")]
    pub capacity: NonZeroUsize,
    /// The upper limit of the number of transactions waiting in the queue for single user.
    /// Use this option to apply throttling.
    #[config(default = "defaults::queue::CAPACITY_PER_USER")]
    pub capacity_per_user: NonZeroUsize,
    /// The transaction will be dropped after this time if it is still in the queue.
    #[config(default = "defaults::queue::TRANSACTION_TIME_TO_LIVE.into()")]
    pub transaction_time_to_live: HumanDuration,
    /// The threshold to determine if a transaction has been tampered to have a future timestamp.
    #[config(default = "defaults::queue::FUTURE_THRESHOLD.into()")]
    pub future_threshold: HumanDuration,
}

impl Queue {
    pub fn parse(self) -> actual::Queue {
        let Self {
            capacity,
            capacity_per_user,
            transaction_time_to_live,
            future_threshold,
        } = self;
        actual::Queue {
            capacity,
            capacity_per_user,
            transaction_time_to_live: transaction_time_to_live.0,
            future_threshold: future_threshold.0,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, ReadConfig)]
pub struct Logger {
    /// Level of logging verbosity
    // TODO: parse user provided value in a case insensitive way,
    //       because `format` is set in lowercase, and `LOG_LEVEL=INFO` + `LOG_FORMAT=pretty`
    //       looks inconsistent
    #[config(env = "LOG_LEVEL", default)]
    pub level: Level,
    /// Output format
    #[config(env = "LOG_FORMAT", default)]
    pub format: LoggerFormat,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Telemetry {
    // Fields here are Options so that it is possible to warn the user if e.g. they provided `min_retry_period`, but haven't
    // provided `name` and `url`
    name: String,
    url: Url,
    #[serde(default)]
    min_retry_period: TelemetryMinRetryPeriod,
    #[serde(default)]
    max_retry_delay_exponent: TelemetryMaxRetryDelayExponent,
}

#[derive(Deserialize, Debug, Copy, Clone)]
struct TelemetryMinRetryPeriod(HumanDuration);

impl Default for TelemetryMinRetryPeriod {
    fn default() -> Self {
        Self(HumanDuration(defaults::telemetry::MIN_RETRY_PERIOD))
    }
}

#[derive(Deserialize, Debug, Copy, Clone)]
struct TelemetryMaxRetryDelayExponent(u8);

impl Default for TelemetryMaxRetryDelayExponent {
    fn default() -> Self {
        Self(defaults::telemetry::MAX_RETRY_DELAY_EXPONENT)
    }
}

impl From<Telemetry> for actual::Telemetry {
    fn from(
        Telemetry {
            name,
            url,
            min_retry_period: TelemetryMinRetryPeriod(HumanDuration(min_retry_period)),
            max_retry_delay_exponent: TelemetryMaxRetryDelayExponent(max_retry_delay_exponent),
        }: Telemetry,
    ) -> Self {
        Self {
            name,
            url,
            min_retry_period,
            max_retry_delay_exponent,
        }
    }
}

#[derive(Debug, Clone, ReadConfig)]
pub struct DevTelemetry {
    pub out_file: Option<WithOrigin<PathBuf>>,
}

#[derive(Debug, Clone, ReadConfig)]
pub struct Snapshot {
    #[config(default, env = "SNAPSHOT_MODE")]
    pub mode: SnapshotMode,
    #[config(default = "defaults::snapshot::CREATE_EVERY.into()")]
    pub create_every: HumanDuration,
    #[config(
        default = "PathBuf::from(defaults::snapshot::STORE_DIR)",
        env = "SNAPSHOT_STORE_DIR"
    )]
    pub store_dir: WithOrigin<PathBuf>,
}

// TODO: make serde
#[derive(Debug, Copy, Clone, ReadConfig)]
pub struct ChainWide {
    #[config(default = "defaults::chain_wide::MAX_TXS")]
    pub max_transactions_in_block: NonZeroU32,
    #[config(default = "defaults::chain_wide::BLOCK_TIME.into()")]
    pub block_time: HumanDuration,
    #[config(default = "defaults::chain_wide::COMMIT_TIME.into()")]
    pub commit_time: HumanDuration,
    #[config(default = "defaults::chain_wide::TRANSACTION_LIMITS")]
    pub transaction_limits: TransactionLimits,
    #[config(default = "defaults::chain_wide::METADATA_LIMITS")]
    pub domain_metadata_limits: MetadataLimits,
    #[config(default = "defaults::chain_wide::METADATA_LIMITS")]
    pub asset_definition_metadata_limits: MetadataLimits,
    #[config(default = "defaults::chain_wide::METADATA_LIMITS")]
    pub account_metadata_limits: MetadataLimits,
    #[config(default = "defaults::chain_wide::METADATA_LIMITS")]
    pub asset_metadata_limits: MetadataLimits,
    #[config(default = "defaults::chain_wide::METADATA_LIMITS")]
    pub trigger_metadata_limits: MetadataLimits,
    #[config(default = "defaults::chain_wide::IDENT_LENGTH_LIMITS")]
    pub ident_length_limits: LengthLimits,
    #[config(default = "defaults::chain_wide::WASM_FUEL_LIMIT")]
    pub executor_fuel_limit: u64,
    #[config(default = "defaults::chain_wide::WASM_MAX_MEMORY_BYTES")]
    pub executor_max_memory: u32,
    #[config(default = "defaults::chain_wide::WASM_FUEL_LIMIT")]
    pub wasm_fuel_limit: u64,
    #[config(default = "defaults::chain_wide::WASM_MAX_MEMORY_BYTES")]
    pub wasm_max_memory: u32,
}

impl ChainWide {
    fn parse(self) -> actual::ChainWide {
        let Self {
            max_transactions_in_block,
            block_time,
            commit_time,
            transaction_limits,
            asset_metadata_limits,
            trigger_metadata_limits,
            asset_definition_metadata_limits,
            account_metadata_limits,
            domain_metadata_limits,
            ident_length_limits,
            executor_fuel_limit,
            executor_max_memory,
            wasm_fuel_limit,
            wasm_max_memory,
        } = self;

        actual::ChainWide {
            max_transactions_in_block,
            block_time: block_time.get(),
            commit_time: commit_time.get(),
            transaction_limits,
            asset_metadata_limits,
            trigger_metadata_limits,
            asset_definition_metadata_limits,
            account_metadata_limits,
            domain_metadata_limits,
            ident_length_limits,
            executor_runtime: actual::WasmRuntime {
                fuel_limit: executor_fuel_limit,
                max_memory_bytes: executor_max_memory,
            },
            wasm_runtime: actual::WasmRuntime {
                fuel_limit: wasm_fuel_limit,
                max_memory_bytes: wasm_max_memory,
            },
        }
    }
}

#[derive(Debug, ReadConfig)]
pub struct Torii {
    #[config(env = "API_ADDRESS")]
    pub address: WithOrigin<SocketAddr>,
    #[config(default = "defaults::torii::MAX_CONTENT_LENGTH.into()")]
    pub max_content_length: HumanBytes<u64>,
    #[config(default = "defaults::torii::QUERY_IDLE_TIME.into()")]
    pub query_idle_time: HumanDuration,
}

impl Torii {
    fn parse(self) -> (actual::Torii, actual::LiveQueryStore) {
        let torii = actual::Torii {
            address: self.address,
            max_content_len_bytes: self.max_content_length.get(),
        };

        let query = actual::LiveQueryStore {
            idle_time: self.query_idle_time.get(),
        };

        (torii, query)
    }
}
