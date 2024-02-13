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
    error::Error,
    fmt::Debug,
    fs::File,
    io::Read,
    num::{NonZeroU32, NonZeroUsize},
    path::{Path, PathBuf},
    time::Duration,
};

pub use boilerplate::*;
use eyre::{eyre, Report, WrapErr};
use iroha_config_base::{
    Emitter, ErrorsCollection, HumanBytes, Merge, ParseEnvResult, ReadEnv, UnwrapPartial,
    UnwrapPartialResult,
};
use iroha_crypto::{KeyPair, PrivateKey, PublicKey};
use iroha_data_model::{
    metadata::Limits as MetadataLimits, peer::PeerId, transaction::TransactionLimits, ChainId,
    LengthLimits, Level,
};
use iroha_primitives::{addr::SocketAddr, unique_vec::UniqueVec};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    kura::Mode,
    logger::Format,
    parameters::{actual, defaults::telemetry::*},
};

mod boilerplate;

#[derive(Debug)]
pub struct Root {
    chain_id: ChainId,
    public_key: PublicKey,
    private_key: PrivateKey,
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

impl RootPartial {
    /// Read the partial from TOML file
    ///
    /// # Errors
    /// - If file is not found, or not a valid TOML
    /// - If failed to parse data into a layer
    /// - If failed to read other configurations specified in `extends`
    pub fn from_toml(path: impl AsRef<Path>) -> eyre::Result<Self, eyre::Error> {
        let contents = {
            let mut file = File::open(path.as_ref()).wrap_err_with(|| {
                eyre!("cannot open file at location `{}`", path.as_ref().display())
            })?;
            let mut contents = String::new();
            file.read_to_string(&mut contents)?;
            contents
        };
        let mut layer: Self = toml::from_str(&contents).wrap_err("failed to parse toml")?;

        let base_path = path
            .as_ref()
            .parent()
            .expect("the config file path could not be empty or root");

        layer.normalise_paths(base_path);

        if let Some(paths) = layer.extends.take() {
            let base = paths
                .iter()
                .try_fold(None, |acc: Option<RootPartial>, extends_path| {
                    // extends path is not normalised relative to the config file yet
                    let full_path = base_path.join(extends_path);

                    let base = Self::from_toml(&full_path)
                        .wrap_err_with(|| eyre!("cannot extend from `{}`", full_path.display()))?;

                    match acc {
                        None => Ok::<Option<RootPartial>, Report>(Some(base)),
                        Some(other_base) => Ok(Some(other_base.merge(base))),
                    }
                })?;
            if let Some(base) = base {
                layer = base.merge(layer)
            };
        }

        Ok(layer)
    }

    /// **Note:** this function doesn't affect `extends`
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
    #[must_use]
    pub fn merge(mut self, other: Self) -> Self {
        Merge::merge(&mut self, other);
        self
    }
}

impl Root {
    /// Parses user configuration view into the internal repr.
    ///
    /// # Errors
    /// If any invalidity found.
    pub fn parse(self, cli: CliContext) -> Result<actual::Root, ErrorsCollection<Report>> {
        let mut emitter = Emitter::new();

        let key_pair =
            KeyPair::new(self.public_key, self.private_key)
                .wrap_err("failed to construct a key pair from `iroha.public_key` and `iroha.private_key` configuration parameters")
            .map_or_else(|err| {
            emitter.emit(err);
            None
        }, Some);

        let genesis = self.genesis.parse(cli).map_or_else(
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

        if let Some(ref config) = sumeragi {
            if !cli.submit_genesis && config.trusted_peers.len() == 0 {
                emitter.emit(eyre!("\
                    The network consists from this one peer only (no `sumeragi.trusted_peers` provided). \
                    Since `--submit-genesis` is not set, there is no way to receive the genesis block. \
                    Either provide the genesis by setting `--submit-genesis` argument, `genesis.private_key`, \
                    and `genesis.file` configuration parameters, or increase the number of trusted peers in \
                    the network using `sumeragi.trusted_peers` configuration parameter.\
                "));
            }
        }

        let (p2p_address, block_sync, transaction_gossiper) = self.network.parse();

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

        if p2p_address == torii.address {
            emitter.emit(eyre!(
                "`iroha.p2p_address` and `torii.address` should not be the same"
            ))
        }

        emitter.finish()?;

        let peer = actual::Common {
            chain_id: self.chain_id,
            key_pair: key_pair.unwrap(),
            p2p_address,
        };
        let (telemetry, dev_telemetry) = telemetries.unwrap();
        let genesis = genesis.unwrap();
        let sumeragi = {
            let mut x = sumeragi.unwrap();
            x.trusted_peers.push(peer.peer_id());
            x
        };

        Ok(actual::Root {
            common: peer,
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

#[derive(Copy, Clone)]
pub struct CliContext {
    pub submit_genesis: bool,
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

    // FIXME: errors handling is a mess
    let payload = match env
        .read_env(&payload_env)
        .map_err(|err| eyre!("failed to read {payload_name}: {err}"))
        .wrap_err("oops")
    {
        Ok(Some(value)) => ParseEnvResult::Value(value),
        Ok(None) => ParseEnvResult::None,
        Err(err) => {
            emitter.emit(err);
            ParseEnvResult::Error
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
        (ParseEnvResult::Error, _) | (_, ParseEnvResult::Error) => {
            // emitter already has these errors
            // adding this branch for exhaustiveness
        }
    }

    ParseEnvResult::Error
}

#[derive(Debug)]
pub struct Genesis {
    pub public_key: PublicKey,
    pub private_key: Option<PrivateKey>,
    pub file: Option<PathBuf>,
}

impl Genesis {
    fn parse(self, cli: CliContext) -> Result<actual::Genesis, GenesisConfigError> {
        match (self.private_key, self.file, cli.submit_genesis) {
            (None, None, false) => Ok(actual::Genesis::Partial {
                public_key: self.public_key,
            }),
            (Some(private_key), Some(file), true) => Ok(actual::Genesis::Full {
                key_pair: KeyPair::new(self.public_key, private_key)
                    .map_err(GenesisConfigError::from)?,
                file,
            }),
            (Some(_), Some(_), false) => Err(GenesisConfigError::GenesisWithoutSubmit),
            (None, None, true) => Err(GenesisConfigError::SubmitWithoutGenesis),
            _ => Err(GenesisConfigError::Inconsistent),
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
    /// failed to construct the genesis's keypair using `genesis.public_key` and `genesis.private_key` configuration parameters
    KeyPair(#[from] iroha_crypto::error::Error),
}

#[derive(Debug)]
pub struct Kura {
    pub init_mode: Mode,
    pub block_store_path: PathBuf,
    pub debug: KuraDebug,
}

impl Kura {
    fn parse(self) -> actual::Kura {
        let Self {
            init_mode,
            block_store_path,
            debug:
                KuraDebug {
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

#[derive(Debug, Copy, Clone)]
pub struct KuraDebug {
    output_new_blocks: bool,
}

#[derive(Debug)]
pub struct Sumeragi {
    pub trusted_peers: Vec<PeerId>,
    pub debug: SumeragiDebug,
}

impl Sumeragi {
    fn parse(self) -> Result<actual::Sumeragi, Report> {
        let Self {
            trusted_peers,
            debug: SumeragiDebug { force_soft_fork },
        } = self;

        let trusted_peers = construct_unique_vec(trusted_peers)?;

        Ok(actual::Sumeragi {
            trusted_peers,
            debug_force_soft_fork: force_soft_fork,
        })
    }
}

#[derive(Debug, Copy, Clone)]
pub struct SumeragiDebug {
    pub force_soft_fork: bool,
}

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
    for x in unchecked {
        let pushed = unique.push(x);
        if !pushed {
            Err(eyre!("found duplicate"))?
        }
    }
    Ok(unique)
}

#[derive(Debug, Clone)]
pub struct Network {
    /// Peer-to-peer address
    pub address: SocketAddr,
    pub block_gossip_period: Duration,
    pub max_blocks_per_gossip: NonZeroU32,
    pub max_transactions_per_gossip: NonZeroU32,
    pub transaction_gossip_period: Duration,
}

impl Network {
    fn parse(self) -> (SocketAddr, actual::BlockSync, actual::TransactionGossiper) {
        let Self {
            address,
            max_blocks_per_gossip,
            max_transactions_per_gossip,
            block_gossip_period,
            transaction_gossip_period,
        } = self;

        (
            address,
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

#[derive(Debug, Clone, Copy)]
pub struct Queue {
    /// The upper limit of the number of transactions waiting in the queue.
    pub capacity: NonZeroUsize,
    /// The upper limit of the number of transactions waiting in the queue for single user.
    /// Use this option to apply throttling.
    pub capacity_per_user: NonZeroUsize,
    /// The transaction will be dropped after this time if it is still in the queue.
    pub transaction_time_to_live: Duration,
    /// The threshold to determine if a transaction has been tampered to have a future timestamp.
    pub future_threshold: Duration,
}

#[allow(missing_copy_implementations)] // triggered without tokio-console
#[derive(Debug, Clone)]
pub struct Logger {
    /// Level of logging verbosity
    // TODO: parse user provided value in a case insensitive way,
    //       because `format` is set in lowercase, and `LOG_LEVEL=INFO` + `LOG_FORMAT=pretty`
    //       looks inconsistent
    pub level: Level,
    /// Output format
    pub format: Format,
    #[cfg(feature = "tokio-console")]
    /// Address of tokio console (only available under "tokio-console" feature)
    pub tokio_console_addr: SocketAddr,
}

#[allow(clippy::derivable_impls)] // triggers in absence of `tokio-console` feature
impl Default for Logger {
    fn default() -> Self {
        Self {
            level: Level::default(),
            format: Format::default(),
            #[cfg(feature = "tokio-console")]
            tokio_console_addr: super::defaults::logger::DEFAULT_TOKIO_CONSOLE_ADDR,
        }
    }
}

#[derive(Debug)]
pub struct Telemetry {
    // Fields here are Options so that it is possible to warn the user if e.g. they provided `min_retry_period`, but haven't
    // provided `name` and `url`
    pub name: Option<String>,
    pub url: Option<Url>,
    pub min_retry_period: Option<Duration>,
    pub max_retry_delay_exponent: Option<u8>,
    pub dev: TelemetryDev,
}

#[derive(Debug)]
pub struct TelemetryDev {
    pub file: Option<PathBuf>,
}

impl Telemetry {
    fn parse(self) -> Result<(Option<actual::Telemetry>, Option<actual::DevTelemetry>), Report> {
        let Self {
            name,
            url,
            max_retry_delay_exponent,
            min_retry_period,
            dev: TelemetryDev { file },
        } = self;

        let regular = match (name, url) {
            (Some(name), Some(url)) => Some(actual::Telemetry {
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

#[derive(Debug, Clone)]
pub struct Snapshot {
    pub create_every: Duration,
    pub store_path: PathBuf,
    pub creation_enabled: bool,
}

#[derive(Debug, Copy, Clone)]
pub struct ChainWide {
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
    pub wasm_max_memory: HumanBytes<u32>,
}

impl ChainWide {
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
            ident_length_limits: identifier_length_limits,
            wasm_runtime: actual::WasmRuntime {
                fuel_limit: wasm_fuel_limit,
                max_memory_bytes: wasm_max_memory.get(),
            },
        }
    }
}

#[derive(Debug)]
pub struct Torii {
    pub address: SocketAddr,
    pub max_content_len: HumanBytes<u64>,
    pub query_idle_time: Duration,
}

impl Torii {
    fn parse(self) -> (actual::Torii, actual::LiveQueryStore) {
        let torii = actual::Torii {
            address: self.address,
            max_content_len_bytes: self.max_content_len.get(),
        };

        let query = actual::LiveQueryStore {
            idle_time: self.query_idle_time,
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
            .set("PRIVATE_KEY_DIGEST", "ed25519")
            .set("PRIVATE_KEY_PAYLOAD", "8f4c15e5d664da3f13778801d23d4e89b76e94c1b94b389544168b6cb894f84f8ba62848cf767d72e7f7f4b9d2d7ba07fee33760f79abe5597a51520e292a0cb");

        let private_key = RootPartial::from_env(&env)
            .expect("input is valid, should not fail")
            .private_key
            .get()
            .expect("private key is provided, should not fail");

        let (algorithm, payload) = private_key.to_raw();
        assert_eq!(algorithm, "ed25519".parse().unwrap());
        assert_eq!(hex::encode(payload), "8f4c15e5d664da3f13778801d23d4e89b76e94c1b94b389544168b6cb894f84f8ba62848cf767d72e7f7f4b9d2d7ba07fee33760f79abe5597a51520e292a0cb");
    }

    #[test]
    fn fails_to_parse_private_key_in_env_without_digest() {
        let env = TestEnv::new().set("PRIVATE_KEY_DIGEST", "ed25519");
        let error =
            RootPartial::from_env(&env).expect_err("private key is incomplete, should fail");
        let expected = expect_test::expect![
            "`PRIVATE_KEY_DIGEST` env was provided, but `PRIVATE_KEY_PAYLOAD` was not"
        ];
        expected.assert_eq(&format!("{error:#}"));
    }

    #[test]
    fn fails_to_parse_private_key_in_env_without_payload() {
        let env = TestEnv::new().set("PRIVATE_KEY_PAYLOAD", "8f4c15e5d664da3f13778801d23d4e89b76e94c1b94b389544168b6cb894f84f8ba62848cf767d72e7f7f4b9d2d7ba07fee33760f79abe5597a51520e292a0cb");
        let error =
            RootPartial::from_env(&env).expect_err("private key is incomplete, should fail");
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

        let error = RootPartial::from_env(&env).expect_err("input is invalid, should fail");

        let expected = expect_test::expect!["failed to construct `iroha.private_key` from `PRIVATE_KEY_DIGEST` and `PRIVATE_KEY_PAYLOAD` environment variables"];
        expected.assert_eq(&format!("{error:#}"));
    }

    #[test]
    fn when_payload_provided_but_digest_is_invalid() {
        let env = TestEnv::new()
            .set("PRIVATE_KEY_DIGEST", "foo")
            .set("PRIVATE_KEY_PAYLOAD", "8f4c15e5d664da3f13778801d23d4e89b76e94c1b94b389544168b6cb894f84f8ba62848cf767d72e7f7f4b9d2d7ba07fee33760f79abe5597a51520e292a0cb");

        let error = RootPartial::from_env(&env).expect_err("input is invalid, should fail");

        // TODO: print the bad value and supported ones
        let expected = expect_test::expect!["failed to parse `iroha.private_key.digest_function` field from `PRIVATE_KEY_DIGEST` env variable"];
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
