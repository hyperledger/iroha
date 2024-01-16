use std::{
    fmt::Debug,
    fs::File,
    io::Read,
    num::{NonZeroU32, NonZeroU64, NonZeroUsize},
    ops::{Add, Div},
    path::{Path, PathBuf},
};

use eyre::{eyre, Report, WrapErr};
use iroha_config_base::{
    ByteSize, Complete, CompleteError, CompleteResult, Emitter, FromEnv, FromEnvDefaultFallback,
    FromEnvResult, Merge, ParseEnvResult, ReadEnv, UserDuration, UserField,
};
use iroha_crypto::{KeyPair, PrivateKey, PublicKey};
use iroha_data_model::{
    metadata::Limits as MetadataLimits, peer::PeerId, transaction::TransactionLimits, LengthLimits,
    Level,
};
use iroha_primitives::{addr::SocketAddr, unique_vec::UniqueVec};
use serde::{Deserialize, Serialize};
use url::Url;

use super::defaults::{
    chain_wide::*, kura::*, logger::*, queue::*, snapshot::*, telemetry::*, torii::*,
};
use crate::{kura::Mode, logger::Format, parameters::actual};

#[derive(Deserialize, Serialize, Debug, Default, Merge)]
#[serde(deny_unknown_fields, default)]
pub struct Root {
    iroha: Iroha,
    genesis: Genesis,
    kura: Kura,
    sumeragi: Sumeragi,
    network: Network,
    logger: Logger,
    queue: Queue,
    snapshot: Snapshot,
    telemetry: Telemetry,
    torii: Torii,
    chain_wide: ChainWide,
}

impl Root {
    pub fn from_toml(path: impl AsRef<Path>) -> eyre::Result<Self, eyre::Error> {
        let contents = {
            let mut file = File::open(path.as_ref()).wrap_err_with(|| {
                eyre!("cannot open file at location `{}`", path.as_ref().display())
            })?;
            let mut contents = String::new();
            file.read_to_string(&mut contents)?;
            contents
        };
        let mut parsed: Self = toml::from_str(&contents).wrap_err("failed to parse toml")?;
        parsed.normalise_paths(
            path.as_ref()
                .parent()
                .expect("the config file path could not be empty or root"),
        );
        Ok(parsed)
    }

    fn normalise_paths(&mut self, relative_to: impl AsRef<Path>) {
        let path = relative_to.as_ref();

        macro_rules! patch {
            ($value:expr) => {
                $value.as_mut().map(|x| {
                    *x = path.join(&x);
                })
            };
        }

        patch!(self.genesis.file);
        patch!(self.snapshot.store_path);
        patch!(self.kura.block_store_path);
        patch!(self.telemetry.dev.file);
    }

    // FIXME workaround the inconvenient way `Merge::merge` works
    pub fn merge_chain(mut self, other: Self) -> Self {
        self.merge(other);
        self
    }
}

impl Complete for Root {
    type Output = actual::Root;

    fn complete(self) -> CompleteResult<Self::Output> {
        let mut emitter = Emitter::new();

        macro_rules! complete_nested {
            ($item:expr) => {
                match iroha_config_base::Complete::complete($item) {
                    Ok(value) => Some(value),
                    Err(error) => {
                        emitter.emit_collection(error);
                        None
                    }
                }
            };
        }

        let iroha = complete_nested!(self.iroha);
        let genesis = complete_nested!(self.genesis);
        let kura = complete_nested!(self.kura);
        let sumeragi = complete_nested!(self.sumeragi);
        let network = complete_nested!(self.network);
        let logger = complete_nested!(self.logger);
        let queue = complete_nested!(self.queue);
        let snapshot = complete_nested!(self.snapshot);
        let telemetries = complete_nested!(self.telemetry);
        let torii_and_query = complete_nested!(self.torii);
        let chain_wide = complete_nested!(self.chain_wide);

        emitter.finish()?;

        let (regular_telemetry, dev_telemetry) = telemetries.unwrap();
        let (torii, live_query_store) = torii_and_query.unwrap();
        let (block_sync, transaction_gossiper) = network.unwrap();

        Ok(actual::Root {
            iroha: iroha.unwrap(),
            genesis: genesis.unwrap(),
            kura: kura.unwrap(),
            sumeragi: sumeragi.unwrap(),
            block_sync,
            transaction_gossiper,
            logger: logger.unwrap(),
            queue: queue.unwrap(),
            snapshot: snapshot.unwrap(),
            regular_telemetry,
            dev_telemetry,
            torii,
            live_query_store,
            chain_wide: chain_wide.unwrap(),
        })
    }
}

impl FromEnv for Root {
    fn from_env(env: &impl ReadEnv) -> FromEnvResult<Self> {
        fn from_env_nested<T: FromEnv>(
            env: &impl ReadEnv,
            emitter: &mut Emitter<Report>,
        ) -> Option<T> {
            match FromEnv::from_env(env) {
                Ok(parsed) => Some(parsed),
                Err(errors) => {
                    emitter.emit_collection(errors);
                    None
                }
            }
        }

        let mut emitter = Emitter::new();

        let iroha = from_env_nested(env, &mut emitter);
        let genesis = from_env_nested(env, &mut emitter);
        let kura = from_env_nested(env, &mut emitter);
        let sumeragi = from_env_nested(env, &mut emitter);
        let network = from_env_nested(env, &mut emitter);
        let logger = from_env_nested(env, &mut emitter);
        let queue = from_env_nested(env, &mut emitter);
        let snapshot = from_env_nested(env, &mut emitter);
        let telemetry = from_env_nested(env, &mut emitter);
        let torii = from_env_nested(env, &mut emitter);
        let chain_wide = from_env_nested(env, &mut emitter);

        emitter.finish()?;

        Ok(Self {
            iroha: iroha.unwrap(),
            genesis: genesis.unwrap(),
            kura: kura.unwrap(),
            sumeragi: sumeragi.unwrap(),
            network: network.unwrap(),
            logger: logger.unwrap(),
            queue: queue.unwrap(),
            snapshot: snapshot.unwrap(),
            telemetry: telemetry.unwrap(),
            torii: torii.unwrap(),
            chain_wide: chain_wide.unwrap(),
        })
    }
}

#[derive(Deserialize, Serialize, Debug, Default, Merge)]
#[serde(deny_unknown_fields, default)]
pub struct Iroha {
    pub public_key: UserField<PublicKey>,
    pub private_key: UserField<PrivateKey>,
    pub p2p_address: UserField<SocketAddr>,
}

impl Complete for Iroha {
    type Output = actual::Iroha;

    fn complete(self) -> CompleteResult<Self::Output> {
        let mut emitter = Emitter::<CompleteError>::new();

        let key_pair = match (self.public_key.get(), self.private_key.get()) {
            (Some(public_key), Some(private_key)) => {
                KeyPair::new(public_key, private_key)
                    .map(Some)
                    .wrap_err("failed to construct a key pair from `iroha.public_key` and `iroha.private_key` configuration parameters")
                    .unwrap_or_else(|report| {
                        emitter.emit(CompleteError::Custom(report));
                        None
                    })
            },
            (public_key, private_key) => {
                if public_key.is_none() {
                    emitter.emit_missing_field("iroha.public_key");
                }
                if private_key.is_none() {
                    emitter.emit_missing_field("iroha.private_key");
                }
                None
            }
        };

        if self.p2p_address.is_none() {
            emitter.emit_missing_field("iroha.p2p_address");
        }

        emitter.finish()?;

        Ok(actual::Iroha {
            key_pair: key_pair.unwrap(),
            p2p_address: self.p2p_address.get().unwrap(),
        })
    }
}

pub(crate) fn private_key_from_env(
    emitter: &mut Emitter<Report>,
    env: &impl ReadEnv,
    env_key_base: impl AsRef<str>,
    name_base: impl AsRef<str>,
) -> ParseEnvResult<PrivateKey> {
    let digest_env = format!("{}_DIGEST", env_key_base.as_ref());
    let digest_name = format!("{}.digest_function", name_base.as_ref());
    let payload_env = format!("{}_PAYLOAD", env_key_base.as_ref());
    let payload_name = format!("{}.payload", name_base.as_ref());

    let digest_function = ParseEnvResult::parse_simple(emitter, env, &digest_env, &digest_name);

    let payload = env.get(&payload_env).map(ToOwned::to_owned);

    match (digest_function, payload) {
        (ParseEnvResult::Value(digest_function), Some(payload)) => {
            PrivateKey::from_hex(digest_function, &payload)
                .wrap_err_with(|| {
                    eyre!(
                        "failed to construct `{}` from `{}` and `{}` environment variables",
                        name_base.as_ref(),
                        &digest_env,
                        &payload_env
                    )
                })
                .map_or_else(
                    |report| {
                        emitter.emit(report);
                        ParseEnvResult::ParseError
                    },
                    ParseEnvResult::Value,
                )
        }
        (ParseEnvResult::None, None) | (ParseEnvResult::ParseError, _) => ParseEnvResult::None,
        (ParseEnvResult::Value(_), None) => {
            emitter.emit(eyre!(
                "`{}` env was provided, but `{}` was not",
                &digest_env,
                &payload_env
            ));
            ParseEnvResult::ParseError
        }
        (ParseEnvResult::None, Some(_)) => {
            emitter.emit(eyre!(
                "`{}` env was provided, but `{}` was not",
                &payload_env,
                &digest_env
            ));
            ParseEnvResult::ParseError
        }
    }
}

impl FromEnv for Iroha {
    fn from_env(env: &impl ReadEnv) -> FromEnvResult<Self>
    where
        Self: Sized,
    {
        let mut emitter = Emitter::new();

        let public_key =
            ParseEnvResult::parse_simple(&mut emitter, env, "PUBLIC_KEY", "iroha.public_key")
                .into();
        let private_key =
            private_key_from_env(&mut emitter, env, "PRIVATE_KEY", "iroha.private_key").into();
        let p2p_address =
            ParseEnvResult::parse_simple(&mut emitter, env, "P2P_ADDRESS", "iroha.p2p_address")
                .into();

        emitter.finish()?;

        Ok(Self {
            public_key,
            private_key,
            p2p_address,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, Default, Merge)]
#[serde(deny_unknown_fields, default)]
pub struct Genesis {
    pub public_key: UserField<PublicKey>,
    pub private_key: UserField<PrivateKey>,
    #[serde(default)]
    pub file: UserField<PathBuf>,
}

impl Complete for Genesis {
    type Output = actual::Genesis;

    fn complete(self) -> CompleteResult<actual::Genesis> {
        let public_key = self
            .public_key
            .get()
            .ok_or_else(|| CompleteError::missing_field("genesis.public_key"))?;

        match (self.private_key.get(), self.file.get()) {
            (None, None) => Ok(actual::Genesis::Partial { public_key }),
            (Some(private_key), Some(file)) => Ok(actual::Genesis::Full {
                key_pair: KeyPair::new(public_key, private_key)
                    .map_err(GenesisConfigError::from)
                    .wrap_err("FIXME")
                    .map_err(CompleteError::Custom)?,
                file,
            }),
            _ => Err(GenesisConfigError::Inconsistent)
                .wrap_err("FIXME")
                .map_err(CompleteError::Custom)?,
        }
    }
}

impl FromEnv for Genesis {
    fn from_env(env: &impl ReadEnv) -> FromEnvResult<Self>
    where
        Self: Sized,
    {
        let mut emitter = Emitter::new();

        let public_key = ParseEnvResult::parse_simple(
            &mut emitter,
            env,
            "GENESIS_PUBLIC_KEY",
            "genesis.public_key",
        )
        .into();
        let private_key = private_key_from_env(
            &mut emitter,
            env,
            "GENESIS_PRIVATE_KEY",
            "genesis.private_key",
        )
        .into();
        let file =
            ParseEnvResult::parse_simple(&mut emitter, env, "GENESIS_FILE", "genesis.file").into();

        emitter.finish()?;

        Ok(Self {
            public_key,
            private_key,
            file,
        })
    }
}

#[derive(Debug, displaydoc::Display, thiserror::Error)]
pub enum GenesisConfigError {
    /// `genesis.file` and `genesis.private_key` should be set together
    Inconsistent,
    /// failed to construct the genesis's keypair using `genesis.public_key` and `genesis.private_key` configuration parameters
    KeyPair(#[from] iroha_crypto::error::Error),
}

/// `Kura` configuration.
#[derive(Clone, Deserialize, Serialize, Debug, Default, Merge)]
#[serde(deny_unknown_fields, default)]
pub struct Kura {
    pub init_mode: Option<Mode>,
    pub block_store_path: Option<PathBuf>,
    pub debug: KuraDebug,
}

#[derive(Clone, Deserialize, Serialize, Debug, Default, Merge)]
#[serde(deny_unknown_fields, default)]
pub struct KuraDebug {
    output_new_blocks: Option<bool>,
}

impl Complete for Kura {
    type Output = actual::Kura;

    fn complete(self) -> CompleteResult<Self::Output> {
        Ok(actual::Kura {
            init_mode: self.init_mode.unwrap_or_default(),
            block_store_path: self
                .block_store_path
                .unwrap_or_else(|| PathBuf::from(DEFAULT_BLOCK_STORE_PATH)),
            debug_output_new_blocks: self.debug.output_new_blocks.unwrap_or(false),
        })
    }
}

impl FromEnv for Kura {
    fn from_env(env: &impl ReadEnv) -> FromEnvResult<Self>
    where
        Self: Sized,
    {
        let mut emitter = Emitter::new();

        let init_mode =
            ParseEnvResult::parse_simple(&mut emitter, env, "KURA_INIT_MODE", "kura.init_mode")
                .into();
        let block_store_path = ParseEnvResult::parse_simple(
            &mut emitter,
            env,
            "KURA_BLOCK_STORE",
            "kura.block_store_path",
        )
        .into();
        let debug_output_new_blocks = ParseEnvResult::parse_simple(
            &mut emitter,
            env,
            "KURA_DEBUG_OUTPUT_NEW_BLOCKS",
            "kura.debug.output_new_blocks",
        )
        .into();

        emitter.finish()?;

        Ok(Self {
            init_mode,
            block_store_path,
            debug: KuraDebug {
                output_new_blocks: debug_output_new_blocks,
            },
        })
    }
}

#[derive(Deserialize, Serialize, Debug, Default, Merge)]
#[serde(deny_unknown_fields, default)]
pub struct Sumeragi {
    pub block_gossip_period: UserField<UserDuration>,
    pub max_blocks_per_gossip: UserField<NonZeroU32>,
    pub max_transactions_per_gossip: UserField<NonZeroU32>,
    pub transaction_gossip_period: UserField<UserDuration>,
    pub trusted_peers: UserTrustedPeers,
    pub debug: SumeragiDebug,
}

#[derive(Deserialize, Serialize, Debug, Default, Merge)]
#[serde(deny_unknown_fields, default)]
pub struct SumeragiDebug {
    pub force_soft_fork: UserField<bool>,
}

impl Complete for Sumeragi {
    type Output = actual::Sumeragi;

    fn complete(self) -> CompleteResult<Self::Output> {
        Ok(actual::Sumeragi {
            trusted_peers: construct_unique_vec(self.trusted_peers.peers)
                .map_err(CompleteError::Custom)?,
            debug_force_soft_fork: self.debug.force_soft_fork.unwrap_or(false),
        })
    }
}

impl FromEnvDefaultFallback for Sumeragi {}

#[derive(Deserialize, Serialize, Default, PartialEq, Eq, Debug, Clone)]
#[serde(transparent)]
pub struct UserTrustedPeers {
    // FIXME: doesn't raise an error on finding duplicates during deserialization
    pub peers: Vec<PeerId>,
}

impl Merge for UserTrustedPeers {
    fn merge(&mut self, mut other: Self) {
        self.peers.append(other.peers.as_mut())
    }
}

// FIXME: handle duplicates properly, not here, and with details
fn construct_unique_vec<T: Debug + PartialEq>(
    unchecked: Vec<T>,
) -> Result<UniqueVec<T>, eyre::Report> {
    let mut unique = UniqueVec::new();
    for x in unchecked.into_iter() {
        let pushed = unique.push(x);
        if !pushed {
            Err(eyre!("found duplicate"))?
        }
    }
    Ok(unique)
}

#[derive(Deserialize, Serialize, Debug, Default, Merge)]
#[serde(deny_unknown_fields, default)]
pub struct Network {
    pub block_gossip_period: UserField<UserDuration>,
    pub max_blocks_per_gossip: UserField<NonZeroU32>,
    pub max_transactions_per_gossip: UserField<NonZeroU32>,
    pub transaction_gossip_period: UserField<UserDuration>,
}

impl Complete for Network {
    type Output = (actual::BlockSync, actual::TransactionGossiper);

    fn complete(self) -> CompleteResult<Self::Output> {
        todo!()
    }
}

impl FromEnvDefaultFallback for Network {}

#[derive(Deserialize, Serialize, Debug, Default, Merge)]
#[serde(deny_unknown_fields, default)]
pub struct Queue {
    /// The upper limit of the number of transactions waiting in the queue.
    pub max_transactions_in_queue: UserField<NonZeroUsize>,
    /// The upper limit of the number of transactions waiting in the queue for single user.
    /// Use this option to apply throttling.
    pub max_transactions_in_queue_per_user: UserField<NonZeroUsize>,
    /// The transaction will be dropped after this time if it is still in the queue.
    pub transaction_time_to_live_ms: UserField<UserDuration>,
    /// The threshold to determine if a transaction has been tampered to have a future timestamp.
    pub future_threshold_ms: UserField<UserDuration>,
}

impl Complete for Queue {
    type Output = actual::Queue;

    fn complete(self) -> CompleteResult<Self::Output> {
        Ok(actual::Queue {
            max_transactions_in_queue: self
                .max_transactions_in_queue
                .unwrap_or(DEFAULT_MAX_TRANSACTIONS_IN_QUEUE),
            max_transactions_in_queue_per_user: self
                .max_transactions_in_queue_per_user
                .unwrap_or(DEFAULT_MAX_TRANSACTIONS_IN_QUEUE),
            transaction_time_to_live: self
                .transaction_time_to_live_ms
                .map_or(DEFAULT_TRANSACTION_TIME_TO_LIVE, UserDuration::get),
            future_threshold: self
                .future_threshold_ms
                .map_or(DEFAULT_FUTURE_THRESHOLD, UserDuration::get),
        })
    }
}

impl FromEnvDefaultFallback for Queue {}

/// 'Logger' configuration.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, Default, Merge)]
// `tokio_console_addr` is not `Copy`, but warning appears without `tokio-console` feature
#[allow(missing_copy_implementations)]
#[serde(deny_unknown_fields, default)]
pub struct Logger {
    /// Level of logging verbosity
    pub level: UserField<Level>,
    /// Output format
    pub format: UserField<Format>,
    #[cfg(feature = "tokio-console")]
    /// Address of tokio console (only available under "tokio-console" feature)
    pub tokio_console_addr: UserField<SocketAddr>,
}

impl Complete for Logger {
    type Output = actual::Logger;

    fn complete(self) -> CompleteResult<Self::Output> {
        Ok(actual::Logger {
            level: self.level.unwrap_or_default(),
            format: self.format.unwrap_or_default(),
            #[cfg(feature = "tokio-console")]
            tokio_console_addr: self
                .tokio_console_addr
                .get()
                .unwrap_or_else(|| DEFAULT_TOKIO_CONSOLE_ADDR.clone()),
        })
    }
}

impl FromEnv for Logger {
    fn from_env(env: &impl ReadEnv) -> FromEnvResult<Self>
    where
        Self: Sized,
    {
        let mut emitter = Emitter::new();

        let level =
            ParseEnvResult::parse_simple(&mut emitter, env, "LOG_LEVEL", "logger.level").into();
        let format =
            ParseEnvResult::parse_simple(&mut emitter, env, "LOG_FORMAT", "logger.format").into();

        emitter.finish()?;

        Ok(Self {
            level,
            format,
            ..Self::default()
        })
    }
}

#[derive(Clone, Deserialize, Serialize, Debug, Default, Merge)]
#[serde(deny_unknown_fields, default)]
pub struct Telemetry {
    /// The node's name to be seen on the telemetry
    pub name: UserField<String>,
    /// The url of the telemetry, e.g., ws://127.0.0.1:8001/submit
    pub url: UserField<Url>,
    /// The minimum period of time in seconds to wait before reconnecting
    pub min_retry_period: UserField<UserDuration>,
    /// The maximum exponent of 2 that is used for increasing delay between reconnections
    pub max_retry_delay_exponent: UserField<u8>,
    /// Dev telemetry configuration
    #[serde(default)]
    pub dev: DevUserLayer,
}

#[derive(Clone, Deserialize, Serialize, Debug, Default, Merge)]
pub struct DevUserLayer {
    /// The filepath that to write dev-telemetry to
    pub file: UserField<PathBuf>,
}

impl Complete for Telemetry {
    type Output = (
        Option<actual::RegularTelemetry>,
        Option<actual::DevTelemetry>,
    );

    fn complete(self) -> CompleteResult<Self::Output> {
        let Self {
            name,
            url,
            max_retry_delay_exponent,
            min_retry_period,
            dev: DevUserLayer { file },
        } = self;

        let regular = match (name.get(), url.get()) {
            (Some(name), Some(url)) => Some(actual::RegularTelemetry {
                name,
                url,
                max_retry_delay_exponent: max_retry_delay_exponent
                    .get()
                    .unwrap_or(DEFAULT_MAX_RETRY_DELAY_EXPONENT),
                min_retry_period: min_retry_period
                    .get()
                    .map_or(DEFAULT_MIN_RETRY_PERIOD, UserDuration::get),
            }),
            (None, None) => None,
            // TODO improve error detail
            _ => Err(eyre!(
                "telemetry.name and telemetry.file should be set together"
            ))
            .map_err(CompleteError::Custom)?,
        };

        let dev = file
            .as_ref()
            .map(|file| actual::DevTelemetry { file: file.clone() });

        Ok((regular, dev))
    }
}

impl FromEnvDefaultFallback for Telemetry {}

#[derive(Debug, Clone, Deserialize, Serialize, Default, Merge)]
#[serde(deny_unknown_fields, default)]
pub struct Snapshot {
    /// The period of time to wait between attempts to create new snapshot.
    pub create_every_ms: UserField<UserDuration>,
    /// Path to the directory where snapshots should be stored
    pub store_path: UserField<PathBuf>,
    /// Flag to enable or disable snapshot creation
    pub creation_enabled: UserField<bool>,
}

impl Complete for Snapshot {
    type Output = actual::Snapshot;

    fn complete(self) -> CompleteResult<Self::Output> {
        Ok(actual::Snapshot {
            creation_enabled: self.creation_enabled.unwrap_or(DEFAULT_ENABLED),
            create_every: self
                .create_every_ms
                .get()
                .map_or(DEFAULT_SNAPSHOT_CREATE_EVERY_MS, UserDuration::get),
            store_path: self
                .store_path
                .get()
                .unwrap_or_else(|| PathBuf::from(DEFAULT_SNAPSHOT_PATH)),
        })
    }
}

impl FromEnv for Snapshot {
    fn from_env(env: &impl ReadEnv) -> FromEnvResult<Self>
    where
        Self: Sized,
    {
        let mut emitter = Emitter::new();

        let store_path = ParseEnvResult::parse_simple(
            &mut emitter,
            env,
            "SNAPSHOT_STORE",
            "snapshot.store_path",
        )
        .into();
        let creation_enabled = ParseEnvResult::parse_simple(
            &mut emitter,
            env,
            "SNAPSHOT_CREATION_ENABLED",
            "snapshot.creation_enabled",
        )
        .into();

        emitter.finish()?;

        Ok(Self {
            store_path,
            creation_enabled,
            ..Self::default()
        })
    }
}

#[derive(Deserialize, Serialize, Debug, Default, Merge)]
#[serde(deny_unknown_fields, default)]
pub struct ChainWide {
    pub max_transactions_in_block: UserField<NonZeroU32>,
    pub block_time: UserField<UserDuration>,
    pub commit_time: UserField<UserDuration>,
    pub transaction_limits: UserField<TransactionLimits>,
    pub asset_metadata_limits: UserField<MetadataLimits>,
    pub asset_definition_metadata_limits: UserField<MetadataLimits>,
    pub account_metadata_limits: UserField<MetadataLimits>,
    pub domain_metadata_limits: UserField<MetadataLimits>,
    pub identifier_length_limits: UserField<LengthLimits>,
    pub wasm_fuel_limit: UserField<u64>,
    pub wasm_max_memory: UserField<ByteSize<u32>>,
}

impl Complete for ChainWide {
    type Output = actual::ChainWide;

    fn complete(self) -> CompleteResult<Self::Output> {
        Ok(actual::ChainWide {
            max_transactions_in_block: self.max_transactions_in_block.unwrap_or(DEFAULT_MAX_TXS),
            block_time: self
                .block_time
                .map_or(DEFAULT_BLOCK_TIME, UserDuration::get),
            commit_time: self
                .commit_time
                .map_or(DEFAULT_COMMIT_TIME_LIMIT, UserDuration::get),
            transaction_limits: self
                .transaction_limits
                .unwrap_or(DEFAULT_TRANSACTION_LIMITS),
            asset_metadata_limits: self
                .asset_metadata_limits
                .unwrap_or(DEFAULT_METADATA_LIMITS),
            asset_definition_metadata_limits: self
                .asset_definition_metadata_limits
                .unwrap_or(DEFAULT_METADATA_LIMITS),
            account_metadata_limits: self
                .account_metadata_limits
                .unwrap_or(DEFAULT_METADATA_LIMITS),
            domain_metadata_limits: self
                .domain_metadata_limits
                .unwrap_or(DEFAULT_METADATA_LIMITS),
            identifier_length_limits: self
                .identifier_length_limits
                .unwrap_or(DEFAULT_IDENT_LENGTH_LIMITS),
            wasm_runtime: actual::WasmRuntime {
                fuel_limit: self.wasm_fuel_limit.unwrap_or(DEFAULT_WASM_FUEL_LIMIT),
                max_memory: self
                    .wasm_max_memory
                    .unwrap_or(ByteSize(DEFAULT_WASM_MAX_MEMORY)),
            },
        })
    }
}

impl FromEnvDefaultFallback for ChainWide {}

#[derive(Debug, Clone, Deserialize, Serialize, Default, Merge)]
#[serde(deny_unknown_fields, default)]
pub struct Torii {
    pub address: UserField<SocketAddr>,
    pub max_content_len: UserField<ByteSize<u32>>,
    pub query_idle_time: UserField<UserDuration>,
}

impl Complete for Torii {
    type Output = (actual::Torii, actual::LiveQueryStore);

    fn complete(self) -> CompleteResult<Self::Output> {
        let torii = actual::Torii {
            address: self
                .address
                .get()
                .ok_or_else(|| CompleteError::missing_field("torii.address"))?,
            max_content_len: self
                .max_content_len
                .get()
                .unwrap_or(ByteSize(DEFAULT_MAX_CONTENT_LENGTH)),
        };

        let query = actual::LiveQueryStore {
            query_idle_time: self
                .query_idle_time
                .map_or(DEFAULT_QUERY_IDLE_TIME, UserDuration::get),
        };

        Ok((torii, query))
    }
}

impl FromEnv for Torii {
    fn from_env(env: &impl ReadEnv) -> FromEnvResult<Self>
    where
        Self: Sized,
    {
        let mut emitter = Emitter::new();

        let address =
            ParseEnvResult::parse_simple(&mut emitter, env, "API_ADDRESS", "torii.address").into();

        emitter.finish()?;

        Ok(Self {
            address,
            ..Self::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use iroha_config_base::{FromEnv, TestEnv};

    use crate::parameters::user_layer::{Iroha, Root};

    #[test]
    fn parses_private_key_from_env() {
        let env = TestEnv::new()
            .set("PRIVATE_KEY_DIGEST", "ed25519")
            .set("PRIVATE_KEY_PAYLOAD", "8f4c15e5d664da3f13778801d23d4e89b76e94c1b94b389544168b6cb894f84f8ba62848cf767d72e7f7f4b9d2d7ba07fee33760f79abe5597a51520e292a0cb");

        let private_key = Iroha::from_env(&env)
            .expect("input is valid, should not fail")
            .private_key
            .get()
            .expect("private key is provided, should not fail");

        assert_eq!(private_key.digest_function(), "ed25519".parse().unwrap());
        assert_eq!(hex::encode( private_key.payload()), "8f4c15e5d664da3f13778801d23d4e89b76e94c1b94b389544168b6cb894f84f8ba62848cf767d72e7f7f4b9d2d7ba07fee33760f79abe5597a51520e292a0cb");
    }

    #[test]
    fn fails_to_parse_private_key_in_env_without_digest() {
        let env = TestEnv::new().set("PRIVATE_KEY_DIGEST", "ed25519");
        let error = Iroha::from_env(&env).expect_err("private key is incomplete, should fail");
        let expected = expect_test::expect![[r#"
            `PRIVATE_KEY_DIGEST` env was provided, but `PRIVATE_KEY_PAYLOAD` was not

            Location:
                config/src/parameters/iroha.rs:100:26"#]];
        expected.assert_eq(&format!("{error:?}"));
    }

    #[test]
    fn fails_to_parse_private_key_in_env_without_payload() {
        let env = TestEnv::new().set("PRIVATE_KEY_PAYLOAD", "8f4c15e5d664da3f13778801d23d4e89b76e94c1b94b389544168b6cb894f84f8ba62848cf767d72e7f7f4b9d2d7ba07fee33760f79abe5597a51520e292a0cb");
        let error = Iroha::from_env(&env).expect_err("private key is incomplete, should fail");
        let expected = expect_test::expect![[r#"
            `PRIVATE_KEY_PAYLOAD` env was provided, but `PRIVATE_KEY_DIGEST` was not

            Location:
                config/src/parameters/iroha.rs:108:26"#]];
        expected.assert_eq(&format!("{error:?}"));
    }

    #[test]
    fn fails_to_parse_private_key_from_env_with_invalid_payload() {
        let env = TestEnv::new()
            .set("PRIVATE_KEY_DIGEST", "ed25519")
            .set("PRIVATE_KEY_PAYLOAD", "foo");

        let error = Iroha::from_env(&env).expect_err("input is invalid, should fail");

        let expected = expect_test::expect![[r#"
            failed to construct `iroha.private_key` from `PRIVATE_KEY_DIGEST` and `PRIVATE_KEY_PAYLOAD` environment variables

            Caused by:
                Key could not be parsed. Odd number of digits

            Location:
                config/src/parameters/iroha.rs:82:18"#]];
        expected.assert_eq(&format!("{error:?}"));
    }

    #[test]
    fn when_payload_provided_but_digest_is_invalid() {
        let env = TestEnv::new()
            .set("PRIVATE_KEY_DIGEST", "foo")
            .set("PRIVATE_KEY_PAYLOAD", "8f4c15e5d664da3f13778801d23d4e89b76e94c1b94b389544168b6cb894f84f8ba62848cf767d72e7f7f4b9d2d7ba07fee33760f79abe5597a51520e292a0cb");

        let error = Iroha::from_env(&env).expect_err("input is invalid, should fail");

        // TODO: print the bad value and supported ones
        let expected = expect_test::expect![[r#"
            failed to parse `iroha.private_key.digest_function` field from `PRIVATE_KEY_DIGEST` env variable

            Caused by:
                Algorithm not supported

            Location:
                config/src/lib.rs:237:14"#]];
        expected.assert_eq(&format!("{error:?}"));
    }

    #[test]
    fn deserialize_empty_input_works() {
        let _layer: Root = toml::from_str("").unwrap();
    }

    #[test]
    fn deserialize_iroha_namespace_with_not_all_fields_works() {
        let _layer: Root = toml::from_str(
            r#"
            [iroha]
            p2p_address = "127.0.0.1:8080"
        "#,
        )
        .unwrap();
    }
}
