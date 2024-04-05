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
    ops::Deref,
    path::PathBuf,
    time::Duration,
};

use error_stack::{Report, Result, ResultExt};
use iroha_config_base::{
    env::FromEnvStr,
    util::{Emitter, EmitterResultExt, HumanBytes, HumanDuration},
    ReadConfig, WithOrigin,
};
use iroha_data_model::{
    metadata::Limits as MetadataLimits, peer::PeerId, transaction::TransactionLimits, ChainId,
    LengthLimits, Level,
};
use iroha_primitives::{addr::SocketAddr, unique_vec::UniqueVec};
use serde::Deserialize;
use url::Url;

use crate::{
    kura::InitMode as KuraInitMode,
    logger::Format as LoggerFormat,
    parameters::{actual, defaults, util::PrivateKeyInConfig},
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
    #[config(env = "PRIVATE_KEY")]
    private_key: WithOrigin<PrivateKeyInConfig>,
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

#[derive(thiserror::Error, Debug)]
enum ParseError {
    #[error("wtf")]
    BadPrivateKey,
    #[error("failed to construct the key pair")]
    BadKeyPair,
    #[error("wtf")]
    BadGenesis,
    #[error("wait")]
    BadSumeragi,
    #[error("wtf")]
    InvalidDirPath,
    #[error("dev telemetry output file should be a file path")]
    BadTelemetryOutFile,
    #[error("the peer is alone")]
    LonePeer,
    #[error("same address specified for peer-to-peer network and Torii")]
    SameNetworkAndToriiAddrs,
}

impl Root {
    /// Parses user configuration view into the internal repr.
    ///
    /// # Errors
    /// If any invalidity found.
    pub fn parse(self, cli: CliContext) -> Result<actual::Root, ParseError> {
        let mut emitter = Emitter::new();

        let (private_key, private_key_origin) = self.private_key.into_tuple();
        let (public_key, public_key_origin) = self.public_key.into_tuple();
        let key_pair = iroha_crypto::KeyPair::new(public_key, private_key.0)
            .change_context(ParseError::BadKeyPair)
            .attach_printable_lazy(|| format!("got public key from: {}", public_key_origin))
            .attach_printable_lazy(|| format!("got private key from: {}", private_key_origin))
            .ok_or_emit(&mut emitter);

        let genesis = self
            .genesis
            .parse(cli)
            .change_context(ParseError::BadGenesis)
            .ok_or_emit(&mut emitter);

        // TODO: enable this check after fix of https://github.com/hyperledger/iroha/issues/4383
        // if let Some(actual::Genesis::Full { file, .. }) = &genesis {
        //     if !file.is_file() {
        //         emitter.emit(eyre!("unable to access `genesis.file`: {}", file.display()))
        //     }
        // }

        let kura = self.kura.parse();
        validate_directory_path(&mut emitter, &kura.store_dir);

        let mut sumeragi = self.sumeragi.parse();

        if !cli.submit_genesis && sumeragi.trusted_peers.len() == 0 {
            emitter.emit(Report::new(ParseError::LonePeer).attach_printable("\
                The network consists from this one peer only (no `sumeragi.trusted_peers` provided). \
                Since `--submit-genesis` is not set, there is no way to receive the genesis block. \
                Either provide the genesis by setting `--submit-genesis` argument, `genesis.private_key`, \
                and `genesis.file` configuration parameters, or increase the number of trusted peers in \
                the network using `sumeragi.trusted_peers` configuration parameter.\
            "));
        }

        let (network, block_sync, transaction_gossiper) = self.network.parse();

        let logger = self.logger;
        let queue = self.queue;

        let snapshot = self.snapshot;
        validate_directory_path(&mut emitter, &snapshot.store_dir);

        let dev_telemetry = self.dev_telemetry;
        if let Some(path) = &dev_telemetry.out_file {
            if path.parent().is_none() {
                emitter.emit(
                    Report::new(ParseError::BadTelemetryOutFile)
                        .attach_printable(format!("actual path: \"{}\"", path.display()))
                        .attach_printable(format!("comes from: {}", path.origin())),
                );
            }
            if path.is_dir() {
                emitter.emit(
                    Report::new(ParseError::BadTelemetryOutFile)
                        .attach_printable(format!("the path is a directory: {}", path.display()))
                        .attach_printable(format!("comes from: {}", path.origin())),
                );
            }
        }

        let (torii, live_query_store) = self.torii.parse();

        let telemetry = self.telemetry.map(actual::Telemetry::from);

        let chain_wide = self.chain_wide.parse();

        if network.address.value() == torii.address.value() {
            emitter.emit(
                Report::new(ParseError::SameNetworkAndToriiAddrs)
                    .attach_printable(format!(
                        "network address comes from: {}",
                        network.address.origin()
                    ))
                    .attach_printable(format!(
                        "Torii address comes from: {}",
                        torii.address.origin()
                    ))
                    .attach_printable(format!("they both have value: {}", network.address.deref())),
            );
        }

        emitter.into_result()?;

        let key_pair = key_pair.unwrap();
        let peer_id = PeerId::new(network.address.clone(), key_pair.public_key().clone());

        let peer = actual::Common {
            chain_id: self.chain_id.0,
            key_pair,
            peer_id,
        };
        let genesis = genesis.unwrap();

        sumeragi.trusted_peers.push(peer.peer_id());

        Ok(actual::Root {
            common: peer,
            network,
            genesis,
            torii,
            kura,
            sumeragi,
            block_sync,
            transaction_gossiper,
            live_query_store,
            logger,
            queue,
            snapshot,
            telemetry,
            dev_telemetry,
            chain_wide,
        })
    }
}

fn validate_directory_path(emitter: &mut Emitter<ParseError>, path: &WithOrigin<PathBuf>) {
    #[derive(Debug, thiserror::Error)]
    #[error(
        "expected path to be either non-existing or a directory, it points to an existing file: {path}"
    )]
    struct InvalidDirPathError {
        path: PathBuf,
    }

    if path.is_file() {
        emitter.emit(
            Report::new(InvalidDirPathError {
                path: path.value().to_path_buf(),
            })
            .change_context(ParseError::InvalidDirPath)
            .attach_printable(format!("comes from: {}", path.origin())),
        );
    }
}

#[derive(Copy, Clone)]
pub struct CliContext {
    pub submit_genesis: bool,
}

#[derive(Debug, ReadConfig)]
pub struct Genesis {
    #[config(env = "GENESIS_PUBLIC_KEY")]
    pub public_key: WithOrigin<iroha_crypto::PublicKey>,
    #[config(env = "GENESIS_PRIVATE_KEY")]
    pub private_key: Option<WithOrigin<PrivateKeyInConfig>>,
    #[config(env = "GENESIS_FILE")]
    pub file: Option<WithOrigin<PathBuf>>,
}

impl Genesis {
    fn parse(self, cli: CliContext) -> Result<actual::Genesis, GenesisConfigError> {
        match (self.private_key, self.file, cli.submit_genesis) {
            (None, None, false) => Ok(actual::Genesis::Partial {
                public_key: self.public_key.into_value(),
            }),
            (Some(private_key), Some(file), true) => {
                let (PrivateKeyInConfig(private_key), priv_key_origin) = private_key.into_tuple();
                let (public_key, pub_key_origin) = self.public_key.into_tuple();
                let key_pair = iroha_crypto::KeyPair::new(public_key, private_key)
                    .change_context(GenesisConfigError::KeyPair)
                    .attach_printable_lazy(|| format!("got public key from: {}", pub_key_origin))
                    .attach_printable_lazy(|| {
                        format!("got private key from: {}", priv_key_origin)
                    })?;
                Ok(actual::Genesis::Full { key_pair, file })
            }
            (Some(_), Some(_), false) => Err(GenesisConfigError::GenesisWithoutSubmit)?,
            (None, None, true) => Err(GenesisConfigError::SubmitWithoutGenesis)?,
            _ => Err(GenesisConfigError::Inconsistent)?,
        }
    }
}

#[derive(Debug, displaydoc::Display, thiserror::Error)]
pub enum GenesisConfigError {
    ///  `genesis.file` and `genesis.private_key` are presented, but `--submit-genesis` was not set
    GenesisWithoutSubmit,
    ///  `--submit-genesis` was set, but `genesis.file` and `genesis.private_key` are not presented
    SubmitWithoutGenesis,
    /// `genesis.file` and `genesis.private_key` should be set together
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
    pub trusted_peers: TrustedPeers,
    #[config(nested)]
    pub debug: SumeragiDebug,
}

#[derive(Debug, Deserialize)]
struct TrustedPeers(UniqueVec<PeerId>);

impl FromEnvStr for TrustedPeers {
    type Error = serde_json::Error;

    fn from_env_str(value: Cow<'_, str>) -> std::result::Result<Self, Self::Error>
    where
        Self: Sized,
    {
        Ok(Self(serde_json::from_str(value.as_ref())?))
    }
}

impl Default for TrustedPeers {
    fn default() -> Self {
        Self(UniqueVec::new())
    }
}

impl Sumeragi {
    fn parse(self) -> actual::Sumeragi {
        let Self {
            trusted_peers,
            debug: SumeragiDebug { force_soft_fork },
        } = self;

        actual::Sumeragi {
            trusted_peers: trusted_peers.0,
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
    #[config(default = "defaults::network::BLOCK_GOSSIP_MAX_SIZE")]
    pub block_gossip_max_size: NonZeroU32,
    #[config(default = "defaults::network::BLOCK_GOSSIP_PERIOD.into()")]
    pub block_gossip_period: HumanDuration,
    #[config(default = "defaults::network::TRANSACTION_GOSSIP_MAX_SIZE")]
    pub transaction_gossip_max_size: NonZeroU32,
    #[config(default = "defaults::network::TRANSACTION_GOSSIP_PERIOD.into()")]
    pub transaction_gossip_period: HumanDuration,
    /// Duration of time after which connection with peer is terminated if peer is idle
    pub idle_timeout: Duration,
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
                idle_timeout,
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
    pub name: String,
    pub url: Url,
    #[serde(default)]
    pub min_retry_period: TelemetryMinRetryPeriod,
    #[serde(default)]
    pub max_retry_delay_exponent: TelemetryMaxRetryDelayExponent,
}

#[derive(Deserialize, Debug)]
struct TelemetryMinRetryPeriod(HumanDuration);

impl Default for TelemetryMinRetryPeriod {
    fn default() -> Self {
        Self(HumanDuration(defaults::telemetry::MIN_RETRY_PERIOD))
    }
}

#[derive(Deserialize, Debug)]
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
    #[config(default = "defaults::chain_wide::BLOCK_TIME")]
    pub block_time: Duration,
    #[config(default = "defaults::chain_wide::COMMIT_TIME")]
    pub commit_time: Duration,
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

#[cfg(test)]
mod tests {
    use iroha_config_base::{FromEnv, TestEnv};

    use super::super::user::boilerplate::RootPartial;

    #[test]
    fn parses_private_key_from_env() {
        let env = TestEnv::new()
            .set("PRIVATE_KEY", "8026408F4C15E5D664DA3F13778801D23D4E89B76E94C1B94B389544168B6CB894F84F8BA62848CF767D72E7F7F4B9D2D7BA07FEE33760F79ABE5597A51520E292A0CB");

        let private_key = RootPartial::from_env(&env)
            .expect("input is valid, should not fail")
            .private_key
            .get()
            .expect("private key is provided, should not fail");

        let (algorithm, payload) = private_key.to_bytes();
        assert_eq!(algorithm, "ed25519".parse().unwrap());
        assert_eq!(hex::encode(payload), "8f4c15e5d664da3f13778801d23d4e89b76e94c1b94b389544168b6cb894f84f8ba62848cf767d72e7f7f4b9d2d7ba07fee33760f79abe5597a51520e292a0cb");
    }

    #[test]
    fn fails_to_parse_private_key_from_env_with_invalid_value() {
        let env = TestEnv::new().set("PRIVATE_KEY", "foo");
        let error = RootPartial::from_env(&env).expect_err("input is invalid, should fail");
        let expected = expect_test::expect![
            "failed to parse `iroha.private_key` field from `PRIVATE_KEY` env variable"
        ];
        expected.assert_eq(&format!("{error:#}"));
    }

    #[test]
    fn deserialize_empty_input_works() {
        let _layer: RootPartial = toml::from_str("").unwrap();
    }

    #[test]
    fn deserialize_network_namespace_with_not_all_fields_works() {
        let _layer: RootPartial = toml::toml! {
            [network]
            address = "127.0.0.1:8080"
        }
        .try_into()
        .expect("should not fail when not all fields in `network` are presented at a time");
    }
}
