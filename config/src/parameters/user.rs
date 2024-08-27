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
    util::{Bytes, DurationMs, Emitter, EmitterResultExt},
    ReadConfig, WithOrigin,
};
use iroha_crypto::{PrivateKey, PublicKey};
use iroha_data_model::{peer::PeerId, ChainId};
use iroha_primitives::{addr::SocketAddr, unique_vec::UniqueVec};
use serde::Deserialize;
use url::Url;

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
        let key_pair = iroha_crypto::KeyPair::new(public_key, private_key)
            .attach_printable(ConfigValueAndOrigin::new("[REDACTED]", public_key_origin))
            .attach_printable(ConfigValueAndOrigin::new("[REDACTED]", private_key_origin))
            .change_context(ParseError::BadKeyPair)
            .ok_or_emit(&mut emitter);

        let genesis = self.genesis.into();

        let kura = self.kura.parse();

        let (network, block_sync, transaction_gossiper) = self.network.parse();
        let logger = self.logger;
        let queue = self.queue;
        let snapshot = self.snapshot;
        let dev_telemetry = self.dev_telemetry;
        let (torii, live_query_store) = self.torii.parse();
        let telemetry = self.telemetry.map(actual::Telemetry::from);

        let peer_id = key_pair.as_ref().map(|key_pair| {
            PeerId::new(
                network.address.value().clone(),
                key_pair.public_key().clone(),
            )
        });

        let sumeragi = peer_id
            .as_ref()
            .map(|id| self.sumeragi.parse_and_push_self(id.clone()));

        emitter.into_result()?;

        let key_pair = key_pair.unwrap();
        let peer = actual::Common {
            chain: self.chain.0,
            key_pair,
            peer: peer_id.unwrap(),
        };

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
        })
    }
}

#[derive(Debug, ReadConfig)]
pub struct Genesis {
    #[config(env = "GENESIS_PUBLIC_KEY")]
    pub public_key: WithOrigin<PublicKey>,
    #[config(env = "GENESIS")]
    pub file: Option<WithOrigin<PathBuf>>,
}

impl From<Genesis> for actual::Genesis {
    fn from(genesis: Genesis) -> Self {
        actual::Genesis {
            public_key: genesis.public_key.into_value(),
            file: genesis.file,
        }
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
    #[config(env = "TRUSTED_PEERS", default)]
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
    fn parse_and_push_self(self, self_id: PeerId) -> actual::Sumeragi {
        let Self {
            trusted_peers,
            debug: SumeragiDebug { force_soft_fork },
        } = self;

        actual::Sumeragi {
            trusted_peers: trusted_peers.map(|x| actual::TrustedPeers {
                myself: self_id,
                others: x.0,
            }),
            debug_force_soft_fork: force_soft_fork,
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
    ) -> (
        actual::Network,
        actual::BlockSync,
        actual::TransactionGossiper,
    ) {
        let Self {
            address,
            block_gossip_size,
            block_gossip_period_ms: block_gossip_period,
            transaction_gossip_size,
            transaction_gossip_period_ms: transaction_gossip_period,
            idle_timeout_ms: idle_timeout,
        } = self;

        (
            actual::Network {
                address,
                idle_timeout: idle_timeout.get(),
            },
            actual::BlockSync {
                gossip_period: block_gossip_period.get(),
                gossip_size: block_gossip_size,
            },
            actual::TransactionGossiper {
                gossip_period: transaction_gossip_period.get(),
                gossip_size: transaction_gossip_size,
            },
        )
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
    pub fn parse(self) -> actual::Queue {
        let Self {
            capacity,
            capacity_per_user,
            transaction_time_to_live_ms: transaction_time_to_live,
        } = self;
        actual::Queue {
            capacity,
            capacity_per_user,
            transaction_time_to_live: transaction_time_to_live.0,
        }
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

impl From<Telemetry> for actual::Telemetry {
    fn from(
        Telemetry {
            name,
            url,
            min_retry_period_ms: TelemetryMinRetryPeriod(DurationMs(min_retry_period)),
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
    pub create_every_ms: DurationMs,
    #[config(
        default = "PathBuf::from(defaults::snapshot::STORE_DIR)",
        env = "SNAPSHOT_STORE_DIR"
    )]
    pub store_dir: WithOrigin<PathBuf>,
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
    fn parse(self) -> (actual::Torii, actual::LiveQueryStore) {
        let torii = actual::Torii {
            address: self.address,
            max_content_len: self.max_content_len,
        };

        let query = actual::LiveQueryStore {
            idle_time: self.query_idle_time_ms.get(),
            capacity: self.query_store_capacity,
            capacity_per_user: self.query_store_capacity_per_user,
        };

        (torii, query)
    }
}
