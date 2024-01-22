use std::{
    error::Error,
    fmt::Debug,
    fs::File,
    io::Read,
    num::{NonZeroU32, NonZeroU64, NonZeroUsize},
    ops::{Add, Div},
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

use eyre::{eyre, Report, WrapErr};
use iroha_config_base::{
    ByteSize, Emitter, ErrorsCollection, FromEnv, FromEnvDefaultFallback, FromEnvResult, Merge,
    MissingFieldError, ParseEnvResult, ReadEnv, UnwrapPartial, UnwrapPartialResult, UserDuration,
    UserField,
};
use iroha_crypto::{KeyPair, PrivateKey, PublicKey};
use iroha_data_model::{
    metadata::Limits as MetadataLimits, peer::PeerId, transaction::TransactionLimits, ChainId,
    LengthLimits, Level,
};
use iroha_primitives::{addr::SocketAddr, unique_vec::UniqueVec};
use serde::{Deserialize, Serialize};
use url::Url;

use super::defaults::{
    chain_wide::*, kura::*, logger::*, queue::*, snapshot::*, telemetry::*, torii::*,
};
use crate::{
    kura::Mode,
    logger::Format,
    parameters::{
        actual,
        defaults::network::{
            DEFAULT_BLOCK_GOSSIP_PERIOD, DEFAULT_MAX_BLOCKS_PER_GOSSIP,
            DEFAULT_MAX_TRANSACTIONS_PER_GOSSIP, DEFAULT_TRANSACTION_GOSSIP_PERIOD,
        },
    },
};

#[derive(Deserialize, Serialize, Debug, Default, Merge)]
#[serde(deny_unknown_fields, default)]
pub struct RootPartial {
    pub iroha: IrohaPartial,
    pub genesis: GenesisPartial,
    pub kura: KuraPartial,
    pub sumeragi: SumeragiPartial,
    pub network: NetworkPartial,
    pub logger: LoggerPartial,
    pub queue: QueuePartial,
    pub snapshot: SnapshotPartial,
    pub telemetry: TelemetryPartial,
    pub torii: ToriiPartial,
    pub chain_wide: ChainWidePartial,
}

impl RootPartial {
    /// Creates new empty user configuration
    pub fn new() -> Self {
        // TODO: generate this function with macro. For now, use default
        Default::default()
    }

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
    pub fn merge(mut self, other: Self) -> Self {
        Merge::merge(&mut self, other);
        self
    }
}

#[derive(Debug)]
pub struct RootFull {
    iroha: IrohaFull,
    genesis: GenesisFull,
    kura: KuraFull,
    sumeragi: SumeragiFull,
    network: NetworkFull,
    logger: LoggerFull,
    queue: QueueFull,
    snapshot: SnapshotFull,
    telemetry: TelemetryFull,
    torii: ToriiFull,
    chain_wide: ChainWideFull,
}

impl RootFull {
    pub fn parse(self, cli: CliContext) -> Result<actual::Root, ErrorsCollection<Report>> {
        let mut emitter = Emitter::new();

        let iroha = self.iroha.parse().map_or_else(
            |err| {
                emitter.emit(err);
                None
            },
            Some,
        );

        let genesis = self.genesis.parse(&cli).map_or_else(
            |err| {
                // FIXME
                emitter.emit(eyre!("{err}"));
                None
            },
            Some,
        );

        let kura = self.kura.parse();

        let sumeragi = self.sumeragi.parse().map_or_else(
            |err| {
                emitter.emit(err);
                None
            },
            Some,
        );

        let (block_sync, transaction_gossiper) = self.network.parse();

        let logger = self.logger;
        let queue = self.queue;
        let snapshot = self.snapshot;

        let (torii, live_query_store) = self.torii.parse();

        let telemetries = self.telemetry.parse().map_or_else(
            |err| {
                emitter.emit(err);
                None
            },
            Some,
        );

        let chain_wide = self.chain_wide.parse();

        emitter.finish()?;

        let (regular_telemetry, dev_telemetry) = telemetries.unwrap();
        let iroha = iroha.unwrap();
        let genesis = genesis.unwrap();
        let sumeragi = sumeragi.unwrap();

        if !cli.submit_genesis && sumeragi.trusted_peers.len() < 2 {
            Err(eyre!("\
                The network consists from this one peer only (`sumeragi.trusted_peers` is less than 2). \
                Since `--submit-genesis` is not set, there is no way to receive the genesis block. \
                Either provide the genesis by setting `--submit-genesis` argument, `genesis.private_key`, \
                and `genesis.file` configuration parameters, or increase the number of trusted peers in \
                the network using `sumeragi.trusted_peers` configuration parameter.
            "))?;
        }

        // TODO: validate that p2p_address and torii.address are not the same

        Ok(actual::Root {
            iroha,
            genesis,
            sumeragi,
            kura,
            block_sync,
            transaction_gossiper,
            logger,
            torii,
            live_query_store,
            queue,
            regular_telemetry,
            dev_telemetry,
            chain_wide,
            snapshot,
        })
    }
}

pub struct CliContext {
    pub submit_genesis: bool,
}

impl UnwrapPartial for RootPartial {
    type Output = RootFull;

    fn unwrap_partial(self) -> UnwrapPartialResult<Self::Output> {
        let mut emitter = Emitter::new();

        macro_rules! nested {
            ($item:expr) => {
                match UnwrapPartial::unwrap_partial($item) {
                    Ok(value) => Some(value),
                    Err(error) => {
                        emitter.emit_collection(error);
                        None
                    }
                }
            };
        }

        let iroha = nested!(self.iroha);
        let genesis = nested!(self.genesis);
        let kura = nested!(self.kura);
        let sumeragi = nested!(self.sumeragi);
        let network = nested!(self.network);
        let logger = nested!(self.logger);
        let queue = nested!(self.queue);
        let snapshot = nested!(self.snapshot);
        let telemetry = nested!(self.telemetry);
        let torii = nested!(self.torii);
        let chain_wide = nested!(self.chain_wide);

        emitter.finish()?;

        Ok(RootFull {
            iroha: iroha.unwrap(),
            genesis: genesis.unwrap(),
            kura: kura.unwrap(),
            sumeragi: sumeragi.unwrap(),
            telemetry: telemetry.unwrap(),
            logger: logger.unwrap(),
            queue: queue.unwrap(),
            snapshot: snapshot.unwrap(),
            torii: torii.unwrap(),
            network: network.unwrap(),
            chain_wide: chain_wide.unwrap(),
        })
    }
}

impl FromEnv for RootPartial {
    fn from_env<E: Error, R: ReadEnv<E>>(env: &R) -> FromEnvResult<Self> {
        fn from_env_nested<T, R, RE>(env: &R, emitter: &mut Emitter<Report>) -> Option<T>
        where
            T: FromEnv,
            R: ReadEnv<RE>,
            RE: Error,
        {
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
pub struct IrohaPartial {
    pub chain_id: UserField<ChainId>,
    pub public_key: UserField<PublicKey>,
    pub private_key: UserField<PrivateKey>,
    pub p2p_address: UserField<SocketAddr>,
}

#[derive(Debug)]
pub struct IrohaFull {
    pub chain_id: ChainId,
    pub public_key: PublicKey,
    pub private_key: PrivateKey,
    pub p2p_address: SocketAddr,
}

impl UnwrapPartial for IrohaPartial {
    type Output = IrohaFull;

    fn unwrap_partial(self) -> UnwrapPartialResult<Self::Output> {
        let mut emitter = Emitter::new();

        if self.chain_id.is_none() {
            emitter.emit_missing_field("iroha.chain_id");
        }
        if self.public_key.is_none() {
            emitter.emit_missing_field("iroha.public_key");
        }
        if self.private_key.is_none() {
            emitter.emit_missing_field("iroha.private_key");
        }
        if self.p2p_address.is_none() {
            emitter.emit_missing_field("iroha.p2p_address");
        }

        emitter.finish()?;

        Ok(IrohaFull {
            chain_id: self.chain_id.get().unwrap(),
            public_key: self.public_key.get().unwrap(),
            private_key: self.private_key.get().unwrap(),
            p2p_address: self.p2p_address.get().unwrap(),
        })
    }
}

impl IrohaFull {
    fn parse(self) -> Result<actual::Iroha, Report> {
        let key_pair = KeyPair::new(self.public_key, self.private_key).wrap_err("failed to construct a key pair from `iroha.public_key` and `iroha.private_key` configuration parameters")?;

        Ok(actual::Iroha {
            chain_id: self.chain_id,
            key_pair,
            p2p_address: self.p2p_address,
        })
    }
}

pub(crate) fn private_key_from_env<E: Error>(
    emitter: &mut Emitter<Report>,
    env: &impl ReadEnv<E>,
    env_key_base: impl AsRef<str>,
    name_base: impl AsRef<str>,
) -> ParseEnvResult<PrivateKey> {
    let digest_env = format!("{}_DIGEST", env_key_base.as_ref());
    let digest_name = format!("{}.digest_function", name_base.as_ref());
    let payload_env = format!("{}_PAYLOAD", env_key_base.as_ref());
    let payload_name = format!("{}.payload", name_base.as_ref());

    let digest_function = ParseEnvResult::parse_simple(emitter, env, &digest_env, &digest_name);

    let payload = match env
        .get(&payload_env)
        .map_err(|err| eyre!("{err}"))
        .wrap_err("oops")
    {
        Ok(Some(value)) => ParseEnvResult::Value(value),
        Ok(None) => ParseEnvResult::None,
        Err(err) => {
            emitter.emit(err);
            ParseEnvResult::ParseError
        }
    };

    match (digest_function, payload) {
        (ParseEnvResult::Value(digest_function), ParseEnvResult::Value(payload)) => {
            match PrivateKey::from_hex(digest_function, &payload).wrap_err_with(|| {
                eyre!(
                    "failed to construct `{}` from `{}` and `{}` environment variables",
                    name_base.as_ref(),
                    &digest_env,
                    &payload_env
                )
            }) {
                Ok(value) => return ParseEnvResult::Value(value),
                Err(report) => {
                    emitter.emit(report);
                }
            }
        }
        (ParseEnvResult::None, ParseEnvResult::None) => return ParseEnvResult::None,
        (ParseEnvResult::Value(_), ParseEnvResult::None) => emitter.emit(eyre!(
            "`{}` env was provided, but `{}` was not",
            &digest_env,
            &payload_env
        )),
        (ParseEnvResult::None, ParseEnvResult::Value(_)) => {
            emitter.emit(eyre!(
                "`{}` env was provided, but `{}` was not",
                &payload_env,
                &digest_env
            ));
        }
        (ParseEnvResult::ParseError, _) | (_, ParseEnvResult::ParseError) => {
            // emitter already has these errors
            // adding this branch for exhaustiveness
        }
    }

    ParseEnvResult::ParseError
}

impl FromEnv for IrohaPartial {
    fn from_env<E: Error, R: ReadEnv<E>>(env: &R) -> FromEnvResult<Self>
    where
        Self: Sized,
    {
        let mut emitter = Emitter::new();

        let chain_id = env
            .get("CHAIN_ID")
            .map_err(|e| eyre!("{e}"))
            .wrap_err("failed to read CHAIN_ID field (iroha.chain_id param)")
            .map_or_else(
                |err| {
                    emitter.emit(err);
                    None
                },
                |maybe_value| maybe_value.map(ChainId::from),
            )
            .into();
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
            chain_id,
            public_key,
            private_key,
            p2p_address,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, Default, Merge)]
#[serde(deny_unknown_fields, default)]
pub struct GenesisPartial {
    pub public_key: UserField<PublicKey>,
    pub private_key: UserField<PrivateKey>,
    pub file: UserField<PathBuf>,
}

#[derive(Debug)]
pub struct GenesisFull {
    pub public_key: PublicKey,
    pub private_key: Option<PrivateKey>,
    pub file: Option<PathBuf>,
}

impl UnwrapPartial for GenesisPartial {
    type Output = GenesisFull;

    fn unwrap_partial(self) -> UnwrapPartialResult<Self::Output> {
        let public_key = self
            .public_key
            .get()
            .ok_or_else(|| MissingFieldError::new("genesis.public_key"))?;

        let private_key = self.private_key.get();
        let file = self.file.get();

        Ok(GenesisFull {
            public_key,
            private_key,
            file,
        })
    }
}

impl FromEnv for GenesisPartial {
    fn from_env<E: Error, R: ReadEnv<E>>(env: &R) -> FromEnvResult<Self>
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

impl GenesisFull {
    fn parse(self, cli: &CliContext) -> Result<actual::Genesis, GenesisConfigError> {
        match (self.private_key, self.file) {
            (None, None) => Ok(actual::Genesis::Partial {
                public_key: self.public_key,
            }),
            (Some(private_key), Some(file)) => Ok(actual::Genesis::Full {
                key_pair: KeyPair::new(self.public_key, private_key)
                    .map_err(GenesisConfigError::from)?,
                file,
            }),
            _ => Err(GenesisConfigError::Inconsistent),
        }
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
pub struct KuraPartial {
    pub init_mode: UserField<Mode>,
    pub block_store_path: UserField<PathBuf>,
    pub debug: KuraDebugPartial,
}

#[derive(Debug)]
pub struct KuraFull {
    pub init_mode: Mode,
    pub block_store_path: PathBuf,
    pub debug: KuraDebugFull,
}

impl UnwrapPartial for KuraPartial {
    type Output = KuraFull;

    fn unwrap_partial(self) -> Result<Self::Output, ErrorsCollection<MissingFieldError>> {
        let mut emitter = Emitter::new();

        let init_mode = self.init_mode.unwrap_or_default();

        let block_store_path = self
            .block_store_path
            .get()
            .unwrap_or_else(|| PathBuf::from(DEFAULT_BLOCK_STORE_PATH));

        let debug = UnwrapPartial::unwrap_partial(self.debug)
            .map(Some)
            .unwrap_or_else(|err| {
                emitter.emit_collection(err);
                None
            });

        emitter.finish()?;

        Ok(KuraFull {
            init_mode,
            block_store_path,
            debug: debug.unwrap(),
        })
    }
}

impl KuraFull {
    fn parse(self) -> actual::Kura {
        let Self {
            init_mode,
            block_store_path,
            debug:
                KuraDebugFull {
                    output_new_blocks: debug_output_new_blocks,
                },
        } = self;

        actual::Kura {
            init_mode,
            block_store_path,
            debug_output_new_blocks,
        }
    }
}

#[derive(Clone, Deserialize, Serialize, Debug, Default, Merge)]
#[serde(deny_unknown_fields, default)]
pub struct KuraDebugPartial {
    output_new_blocks: UserField<bool>,
}

#[derive(Debug)]
pub struct KuraDebugFull {
    output_new_blocks: bool,
}

impl UnwrapPartial for KuraDebugPartial {
    type Output = KuraDebugFull;

    fn unwrap_partial(self) -> Result<Self::Output, ErrorsCollection<MissingFieldError>> {
        Ok(KuraDebugFull {
            output_new_blocks: self.output_new_blocks.unwrap_or(false),
        })
    }
}

impl FromEnv for KuraPartial {
    fn from_env<E: Error, R: ReadEnv<E>>(env: &R) -> FromEnvResult<Self>
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
            debug: KuraDebugPartial {
                output_new_blocks: debug_output_new_blocks,
            },
        })
    }
}

#[derive(Deserialize, Serialize, Debug, Default, Merge)]
#[serde(deny_unknown_fields, default)]
pub struct SumeragiPartial {
    pub trusted_peers: UserTrustedPeers,
    pub debug: SumeragiDebugPartial,
}

#[derive(Debug)]
pub struct SumeragiFull {
    pub trusted_peers: Vec<PeerId>,
    pub debug: SumeragiDebugFull,
}

impl SumeragiFull {
    fn parse(self) -> Result<actual::Sumeragi, Report> {
        let Self {
            trusted_peers,
            debug: SumeragiDebugFull { force_soft_fork },
        } = self;

        let trusted_peers = construct_unique_vec(trusted_peers)?;

        Ok(actual::Sumeragi {
            trusted_peers,
            debug_force_soft_fork: force_soft_fork,
        })
    }
}

impl UnwrapPartial for SumeragiPartial {
    type Output = SumeragiFull;

    fn unwrap_partial(self) -> UnwrapPartialResult<Self::Output> {
        let mut emitter = Emitter::new();

        let trusted_peers = self.trusted_peers.unwrap_partial().map_or_else(
            |err| {
                emitter.emit_collection(err);
                None
            },
            Some,
        );

        let debug = self.debug.unwrap_partial().map_or_else(
            |err| {
                emitter.emit_collection(err);
                None
            },
            Some,
        );

        emitter.finish()?;

        Ok(SumeragiFull {
            trusted_peers: trusted_peers.unwrap(),
            debug: debug.unwrap(),
        })
    }
}

#[derive(Deserialize, Serialize, Debug, Default, Merge)]
#[serde(deny_unknown_fields, default)]
pub struct SumeragiDebugPartial {
    pub force_soft_fork: UserField<bool>,
}

impl UnwrapPartial for SumeragiDebugPartial {
    type Output = SumeragiDebugFull;

    fn unwrap_partial(self) -> UnwrapPartialResult<Self::Output> {
        Ok(SumeragiDebugFull {
            force_soft_fork: self.force_soft_fork.unwrap_or(false),
        })
    }
}

#[derive(Debug)]
pub struct SumeragiDebugFull {
    pub force_soft_fork: bool,
}

impl FromEnvDefaultFallback for SumeragiPartial {}

#[derive(Deserialize, Serialize, Default, PartialEq, Eq, Debug, Clone)]
#[serde(transparent)]
pub struct UserTrustedPeers {
    // FIXME: doesn't raise an error on finding duplicates during deserialization
    pub peers: Vec<PeerId>,
}

impl UnwrapPartial for UserTrustedPeers {
    type Output = Vec<PeerId>;
    fn unwrap_partial(self) -> UnwrapPartialResult<Self::Output> {
        Ok(self.peers)
    }
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
pub struct NetworkPartial {
    pub block_gossip_period: UserField<UserDuration>,
    pub max_blocks_per_gossip: UserField<NonZeroU32>,
    pub max_transactions_per_gossip: UserField<NonZeroU32>,
    pub transaction_gossip_period: UserField<UserDuration>,
}

#[derive(Debug)]
pub struct NetworkFull {
    pub block_gossip_period: Duration,
    pub max_blocks_per_gossip: NonZeroU32,
    pub max_transactions_per_gossip: NonZeroU32,
    pub transaction_gossip_period: Duration,
}

impl UnwrapPartial for NetworkPartial {
    type Output = NetworkFull;

    fn unwrap_partial(self) -> UnwrapPartialResult<Self::Output> {
        Ok(NetworkFull {
            block_gossip_period: self
                .block_gossip_period
                .map(UserDuration::get)
                .unwrap_or(DEFAULT_BLOCK_GOSSIP_PERIOD),
            transaction_gossip_period: self
                .transaction_gossip_period
                .map(UserDuration::get)
                .unwrap_or(DEFAULT_TRANSACTION_GOSSIP_PERIOD),
            max_transactions_per_gossip: self
                .max_transactions_per_gossip
                .get()
                .unwrap_or(DEFAULT_MAX_TRANSACTIONS_PER_GOSSIP),
            max_blocks_per_gossip: self
                .max_blocks_per_gossip
                .get()
                .unwrap_or(DEFAULT_MAX_BLOCKS_PER_GOSSIP),
        })
    }
}

impl NetworkFull {
    fn parse(self) -> (actual::BlockSync, actual::TransactionGossiper) {
        let Self {
            max_blocks_per_gossip,
            max_transactions_per_gossip,
            block_gossip_period,
            transaction_gossip_period,
        } = self;

        (
            actual::BlockSync {
                gossip_period: block_gossip_period,
                batch_size: max_blocks_per_gossip,
            },
            actual::TransactionGossiper {
                gossip_period: transaction_gossip_period,
                batch_size: max_transactions_per_gossip,
            },
        )
    }
}

impl FromEnvDefaultFallback for NetworkPartial {}

#[derive(Deserialize, Serialize, Debug, Default, Merge)]
#[serde(deny_unknown_fields, default)]
pub struct QueuePartial {
    /// The upper limit of the number of transactions waiting in the queue.
    pub max_transactions_in_queue: UserField<NonZeroUsize>,
    /// The upper limit of the number of transactions waiting in the queue for single user.
    /// Use this option to apply throttling.
    pub max_transactions_in_queue_per_user: UserField<NonZeroUsize>,
    /// The transaction will be dropped after this time if it is still in the queue.
    pub transaction_time_to_live: UserField<UserDuration>,
    /// The threshold to determine if a transaction has been tampered to have a future timestamp.
    pub future_threshold: UserField<UserDuration>,
}

#[derive(Debug, Clone, Copy)]
pub struct QueueFull {
    /// The upper limit of the number of transactions waiting in the queue.
    pub max_transactions_in_queue: NonZeroUsize,
    /// The upper limit of the number of transactions waiting in the queue for single user.
    /// Use this option to apply throttling.
    pub max_transactions_in_queue_per_user: NonZeroUsize,
    /// The transaction will be dropped after this time if it is still in the queue.
    pub transaction_time_to_live: Duration,
    /// The threshold to determine if a transaction has been tampered to have a future timestamp.
    pub future_threshold: Duration,
}

impl UnwrapPartial for QueuePartial {
    type Output = QueueFull;

    fn unwrap_partial(self) -> UnwrapPartialResult<Self::Output> {
        Ok(QueueFull {
            max_transactions_in_queue: self
                .max_transactions_in_queue
                .unwrap_or(DEFAULT_MAX_TRANSACTIONS_IN_QUEUE),
            max_transactions_in_queue_per_user: self
                .max_transactions_in_queue_per_user
                .unwrap_or(DEFAULT_MAX_TRANSACTIONS_IN_QUEUE),
            transaction_time_to_live: self
                .transaction_time_to_live
                .map_or(DEFAULT_TRANSACTION_TIME_TO_LIVE, UserDuration::get),
            future_threshold: self
                .future_threshold
                .map_or(DEFAULT_FUTURE_THRESHOLD, UserDuration::get),
        })
    }
}

impl FromEnvDefaultFallback for QueuePartial {}

/// 'Logger' configuration.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, Default, Merge)]
// `tokio_console_addr` is not `Copy`, but warning appears without `tokio-console` feature
#[allow(missing_copy_implementations)]
#[serde(deny_unknown_fields, default)]
pub struct LoggerPartial {
    /// Level of logging verbosity
    pub level: UserField<Level>,
    /// Output format
    pub format: UserField<Format>,
    #[cfg(feature = "tokio-console")]
    /// Address of tokio console (only available under "tokio-console" feature)
    pub tokio_console_addr: UserField<SocketAddr>,
}

#[derive(Debug, Clone)]
pub struct LoggerFull {
    /// Level of logging verbosity
    pub level: Level,
    /// Output format
    pub format: Format,
    #[cfg(feature = "tokio-console")]
    /// Address of tokio console (only available under "tokio-console" feature)
    pub tokio_console_addr: SocketAddr,
}

impl UnwrapPartial for LoggerPartial {
    type Output = LoggerFull;

    fn unwrap_partial(self) -> UnwrapPartialResult<Self::Output> {
        Ok(LoggerFull {
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

impl FromEnv for LoggerPartial {
    fn from_env<E: Error, R: ReadEnv<E>>(env: &R) -> FromEnvResult<Self>
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
pub struct TelemetryPartial {
    pub name: UserField<String>,
    pub url: UserField<Url>,
    pub min_retry_period: UserField<UserDuration>,
    pub max_retry_delay_exponent: UserField<u8>,
    pub dev: TelemetryDevPartial,
}

#[derive(Debug)]
pub struct TelemetryFull {
    // Fields here are Options so that it is possible to warn the user if e.g. they provided `min_retry_period`, but haven't
    // provided `name` and `url`
    pub name: Option<String>,
    pub url: Option<Url>,
    pub min_retry_period: Option<Duration>,
    pub max_retry_delay_exponent: Option<u8>,
    pub dev: TelemetryDevFull,
}

#[derive(Clone, Deserialize, Serialize, Debug, Default, Merge)]
pub struct TelemetryDevPartial {
    pub file: UserField<PathBuf>,
}

#[derive(Debug)]
pub struct TelemetryDevFull {
    pub file: Option<PathBuf>,
}

impl UnwrapPartial for TelemetryDevPartial {
    type Output = TelemetryDevFull;

    fn unwrap_partial(self) -> UnwrapPartialResult<Self::Output> {
        Ok(TelemetryDevFull {
            file: self.file.get(),
        })
    }
}

impl UnwrapPartial for TelemetryPartial {
    type Output = TelemetryFull;

    fn unwrap_partial(self) -> UnwrapPartialResult<Self::Output> {
        let Self {
            name,
            url,
            max_retry_delay_exponent,
            min_retry_period,
            dev,
        } = self;

        Ok(TelemetryFull {
            name: name.get(),
            url: url.get(),
            max_retry_delay_exponent: max_retry_delay_exponent.get(),
            min_retry_period: min_retry_period.get().map(UserDuration::get),
            dev: dev.unwrap_partial()?,
        })
    }
}

impl TelemetryFull {
    fn parse(
        self,
    ) -> Result<
        (
            Option<actual::RegularTelemetry>,
            Option<actual::DevTelemetry>,
        ),
        Report,
    > {
        let Self {
            name,
            url,
            max_retry_delay_exponent,
            min_retry_period,
            dev: TelemetryDevFull { file },
        } = self;

        let regular = match (name, url) {
            (Some(name), Some(url)) => Some(actual::RegularTelemetry {
                name,
                url,
                max_retry_delay_exponent: max_retry_delay_exponent
                    .unwrap_or(DEFAULT_MAX_RETRY_DELAY_EXPONENT),
                min_retry_period: min_retry_period.unwrap_or(DEFAULT_MIN_RETRY_PERIOD),
            }),
            // TODO warn user if they provided retry parameters while not providing essential ones
            (None, None) => None,
            _ => {
                // TODO improve error detail
                return Err(eyre!(
                    "telemetry.name and telemetry.file should be set together"
                ))?;
            }
        };

        let dev = file.map(|file| actual::DevTelemetry { file: file.clone() });

        Ok((regular, dev))
    }
}

impl FromEnvDefaultFallback for TelemetryPartial {}

#[derive(Debug, Clone, Deserialize, Serialize, Default, Merge)]
#[serde(deny_unknown_fields, default)]
pub struct SnapshotPartial {
    pub create_every: UserField<UserDuration>,
    pub store_path: UserField<PathBuf>,
    pub creation_enabled: UserField<bool>,
}

#[derive(Debug, Clone)]
pub struct SnapshotFull {
    pub create_every: Duration,
    pub store_path: PathBuf,
    pub creation_enabled: bool,
}

impl UnwrapPartial for SnapshotPartial {
    type Output = SnapshotFull;

    fn unwrap_partial(self) -> UnwrapPartialResult<Self::Output> {
        Ok(SnapshotFull {
            creation_enabled: self.creation_enabled.unwrap_or(DEFAULT_ENABLED),
            create_every: self
                .create_every
                .get()
                .map_or(DEFAULT_SNAPSHOT_CREATE_EVERY_MS, UserDuration::get),
            store_path: self
                .store_path
                .get()
                .unwrap_or_else(|| PathBuf::from(DEFAULT_SNAPSHOT_PATH)),
        })
    }
}

impl FromEnv for SnapshotPartial {
    fn from_env<E: Error, R: ReadEnv<E>>(env: &R) -> FromEnvResult<Self>
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
pub struct ChainWidePartial {
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

#[derive(Debug)]
pub struct ChainWideFull {
    pub max_transactions_in_block: NonZeroU32,
    pub block_time: Duration,
    pub commit_time: Duration,
    pub transaction_limits: TransactionLimits,
    pub asset_metadata_limits: MetadataLimits,
    pub asset_definition_metadata_limits: MetadataLimits,
    pub account_metadata_limits: MetadataLimits,
    pub domain_metadata_limits: MetadataLimits,
    pub identifier_length_limits: LengthLimits,
    pub wasm_fuel_limit: u64,
    pub wasm_max_memory: ByteSize<u32>,
}

impl UnwrapPartial for ChainWidePartial {
    type Output = ChainWideFull;

    fn unwrap_partial(self) -> UnwrapPartialResult<Self::Output> {
        Ok(ChainWideFull {
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
            wasm_fuel_limit: self.wasm_fuel_limit.unwrap_or(DEFAULT_WASM_FUEL_LIMIT),
            wasm_max_memory: self
                .wasm_max_memory
                .unwrap_or(ByteSize(DEFAULT_WASM_MAX_MEMORY)),
        })
    }
}

impl FromEnvDefaultFallback for ChainWidePartial {}

impl ChainWideFull {
    fn parse(self) -> actual::ChainWide {
        let Self {
            max_transactions_in_block,
            block_time,
            commit_time,
            transaction_limits,
            asset_metadata_limits,
            asset_definition_metadata_limits,
            account_metadata_limits,
            domain_metadata_limits,
            identifier_length_limits,
            wasm_fuel_limit,
            wasm_max_memory,
        } = self;

        actual::ChainWide {
            max_transactions_in_block,
            block_time,
            commit_time,
            transaction_limits,
            asset_metadata_limits,
            asset_definition_metadata_limits,
            account_metadata_limits,
            domain_metadata_limits,
            identifier_length_limits,
            wasm_runtime: actual::WasmRuntime {
                fuel_limit: wasm_fuel_limit,
                max_memory: wasm_max_memory,
            },
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default, Merge)]
#[serde(deny_unknown_fields, default)]
pub struct ToriiPartial {
    pub address: UserField<SocketAddr>,
    pub max_content_len: UserField<ByteSize<u64>>,
    pub query_idle_time: UserField<UserDuration>,
}

#[derive(Debug)]
pub struct ToriiFull {
    pub address: SocketAddr,
    pub max_content_len: ByteSize<u64>,
    pub query_idle_time: Duration,
}

impl UnwrapPartial for ToriiPartial {
    type Output = ToriiFull;

    fn unwrap_partial(self) -> UnwrapPartialResult<Self::Output> {
        let mut emitter = Emitter::new();

        if self.address.is_none() {
            emitter.emit_missing_field("torii.address");
        }

        let max_content_len = self
            .max_content_len
            .get()
            .unwrap_or(ByteSize(DEFAULT_MAX_CONTENT_LENGTH));

        let query_idle_time = self
            .query_idle_time
            .map(UserDuration::get)
            .unwrap_or(DEFAULT_QUERY_IDLE_TIME);

        emitter.finish()?;

        Ok(ToriiFull {
            address: self.address.get().unwrap(),
            max_content_len,
            query_idle_time,
        })
    }
}

impl ToriiFull {
    fn parse(self) -> (actual::Torii, actual::LiveQueryStore) {
        let torii = actual::Torii {
            address: self.address,
            max_content_len: self.max_content_len,
        };

        let query = actual::LiveQueryStore {
            query_idle_time: self.query_idle_time,
        };

        (torii, query)
    }
}

impl FromEnv for ToriiPartial {
    fn from_env<E: Error, R: ReadEnv<E>>(env: &R) -> FromEnvResult<Self>
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

    use crate::parameters::user_layer::{IrohaPartial, RootPartial};

    #[test]
    fn parses_private_key_from_env() {
        let env = TestEnv::new()
            .set("PRIVATE_KEY_DIGEST", "ed25519")
            .set("PRIVATE_KEY_PAYLOAD", "8f4c15e5d664da3f13778801d23d4e89b76e94c1b94b389544168b6cb894f84f8ba62848cf767d72e7f7f4b9d2d7ba07fee33760f79abe5597a51520e292a0cb");

        let private_key = IrohaPartial::from_env(&env)
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
        let error =
            IrohaPartial::from_env(&env).expect_err("private key is incomplete, should fail");
        let expected = expect_test::expect![
            "`PRIVATE_KEY_DIGEST` env was provided, but `PRIVATE_KEY_PAYLOAD` was not"
        ];
        expected.assert_eq(&format!("{error:#}"));
    }

    #[test]
    fn fails_to_parse_private_key_in_env_without_payload() {
        let env = TestEnv::new().set("PRIVATE_KEY_PAYLOAD", "8f4c15e5d664da3f13778801d23d4e89b76e94c1b94b389544168b6cb894f84f8ba62848cf767d72e7f7f4b9d2d7ba07fee33760f79abe5597a51520e292a0cb");
        let error =
            IrohaPartial::from_env(&env).expect_err("private key is incomplete, should fail");
        let expected = expect_test::expect![
            "`PRIVATE_KEY_PAYLOAD` env was provided, but `PRIVATE_KEY_DIGEST` was not"
        ];
        expected.assert_eq(&format!("{error:#}"));
    }

    #[test]
    fn fails_to_parse_private_key_from_env_with_invalid_payload() {
        let env = TestEnv::new()
            .set("PRIVATE_KEY_DIGEST", "ed25519")
            .set("PRIVATE_KEY_PAYLOAD", "foo");

        let error = IrohaPartial::from_env(&env).expect_err("input is invalid, should fail");

        let expected = expect_test::expect!["failed to construct `iroha.private_key` from `PRIVATE_KEY_DIGEST` and `PRIVATE_KEY_PAYLOAD` environment variables"];
        expected.assert_eq(&format!("{error:#}"));
    }

    #[test]
    fn when_payload_provided_but_digest_is_invalid() {
        let env = TestEnv::new()
            .set("PRIVATE_KEY_DIGEST", "foo")
            .set("PRIVATE_KEY_PAYLOAD", "8f4c15e5d664da3f13778801d23d4e89b76e94c1b94b389544168b6cb894f84f8ba62848cf767d72e7f7f4b9d2d7ba07fee33760f79abe5597a51520e292a0cb");

        let error = IrohaPartial::from_env(&env).expect_err("input is invalid, should fail");

        // TODO: print the bad value and supported ones
        let expected = expect_test::expect!["failed to parse `iroha.private_key.digest_function` field from `PRIVATE_KEY_DIGEST` env variable"];
        expected.assert_eq(&format!("{error:#}"));
    }

    #[test]
    fn deserialize_empty_input_works() {
        let _layer: RootPartial = toml::from_str("").unwrap();
    }

    #[test]
    fn deserialize_iroha_namespace_with_not_all_fields_works() {
        let _layer: RootPartial = toml::from_str(
            r#"
            [iroha]
            p2p_address = "127.0.0.1:8080"
        "#,
        )
        .unwrap();
    }
}
