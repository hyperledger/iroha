use std::{
    error::Error,
    fmt::Debug,
    io::Read,
    num::{NonZeroU32, NonZeroUsize},
    ops::{Add, Div},
    path::PathBuf,
    str::FromStr,
    time::Duration,
};

use eyre::{eyre, Report, WrapErr};
use iroha_config_base::{
    ByteSize, Emitter, ErrorsCollection, FromEnv, FromEnvDefaultFallback, Merge, ParseEnvResult,
    ReadEnv, UnwrapPartial, UnwrapPartialResult,
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
    parameters::{
        actual,
        defaults::{logger::*, telemetry::*},
    },
};

mod boilerplate;
pub use boilerplate::*;

#[derive(Debug, Default, Serialize, Deserialize, Eq, PartialEq)]
#[serde(untagged)]
pub enum ExtendsPaths {
    #[default]
    None,
    Single(PathBuf),
    Multiple(Vec<PathBuf>),
}

impl Merge for ExtendsPaths {
    fn merge(&mut self, other: Self) {
        match (self, other) {
            (Self::None, Self::None) => {}
            _ => unreachable!(
                "It is a bug. `ExtendsPaths` should be resolved to `None` before merging."
            ),
        }
    }
}

pub enum ExtendsPathsIter<'a> {
    None,
    Single(Option<&'a PathBuf>),
    Multiple(std::slice::Iter<'a, PathBuf>),
}

impl ExtendsPaths {
    pub fn iter(&self) -> ExtendsPathsIter<'_> {
        match &self {
            Self::None => ExtendsPathsIter::None,
            Self::Single(x) => ExtendsPathsIter::Single(Some(x)),
            Self::Multiple(vec) => ExtendsPathsIter::Multiple(vec.iter()),
        }
    }

    /// Marks this instance as used, so that subsequent [`Merge`] doesn't fail
    pub fn used(&mut self) {
        *self = Self::None
    }
}

impl<'a> Iterator for ExtendsPathsIter<'a> {
    type Item = &'a PathBuf;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::None => None,
            Self::Single(x) => x.take(),
            Self::Multiple(iter) => iter.next(),
        }
    }
}

#[derive(Debug)]
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

        let sumeragi = match self.sumeragi.parse() {
            Ok(mut sumeragi) => {
                if !cli.submit_genesis && sumeragi.trusted_peers.len() == 0 {
                    emitter.emit(eyre!("\
                        The network consists from this one peer only (no `sumeragi.trusted_peers` provided). \
                        Since `--submit-genesis` is not set, there is no way to receive the genesis block. \
                        Either provide the genesis by setting `--submit-genesis` argument, `genesis.private_key`, \
                        and `genesis.file` configuration parameters, or increase the number of trusted peers in \
                        the network using `sumeragi.trusted_peers` configuration parameter.\
                    "));
                    None
                } else {
                    Some(sumeragi)
                }
            }
            Err(err) => {
                emitter.emit(err);
                None
            }
        };

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

        if let Some(iroha) = &iroha {
            if iroha.p2p_address == torii.address {
                emitter.emit(eyre!(
                    "`iroha.p2p_address` and `torii.address` should not be the same"
                ))
            }
        }

        emitter.finish()?;

        let (regular_telemetry, dev_telemetry) = telemetries.unwrap();
        let iroha = iroha.unwrap();
        let genesis = genesis.unwrap();
        let sumeragi = {
            let mut cfg = sumeragi.unwrap();
            cfg.trusted_peers.push(iroha.peer_id());
            cfg
        };

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

#[derive(Debug)]
pub struct Iroha {
    pub chain_id: ChainId,
    pub public_key: PublicKey,
    pub private_key: PrivateKey,
    pub p2p_address: SocketAddr,
}

impl Iroha {
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

#[derive(Debug)]
pub struct Genesis {
    pub public_key: PublicKey,
    pub private_key: Option<PrivateKey>,
    pub file: Option<PathBuf>,
}

impl Genesis {
    fn parse(self, cli: &CliContext) -> Result<actual::Genesis, GenesisConfigError> {
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

#[derive(Debug)]
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

#[derive(Debug)]
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
    for x in unchecked.into_iter() {
        let pushed = unique.push(x);
        if !pushed {
            Err(eyre!("found duplicate"))?
        }
    }
    Ok(unique)
}

#[derive(Debug)]
pub struct Network {
    pub block_gossip_period: Duration,
    pub max_blocks_per_gossip: NonZeroU32,
    pub max_transactions_per_gossip: NonZeroU32,
    pub transaction_gossip_period: Duration,
}

impl Network {
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

#[derive(Debug, Clone, Copy)]
pub struct Queue {
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

#[derive(Debug, Clone)]
pub struct Logger {
    /// Level of logging verbosity
    pub level: Level,
    /// Output format
    pub format: Format,
    #[cfg(feature = "tokio-console")]
    /// Address of tokio console (only available under "tokio-console" feature)
    pub tokio_console_addr: SocketAddr,
}

impl Default for Logger {
    fn default() -> Self {
        Self {
            level: Level::default(),
            format: Format::default(),
            #[cfg(feature = "tokio-console")]
            tokio_console_addr: DEFAULT_TOKIO_CONSOLE_ADDR,
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
            dev: TelemetryDev { file },
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

#[derive(Debug, Clone)]
pub struct Snapshot {
    pub create_every: Duration,
    pub store_path: PathBuf,
    pub creation_enabled: bool,
}

#[derive(Debug)]
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
    pub wasm_max_memory: ByteSize<u32>,
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
            identifier_length_limits,
            wasm_runtime: actual::WasmRuntime {
                fuel_limit: wasm_fuel_limit,
                max_memory: wasm_max_memory,
            },
        }
    }
}

#[derive(Debug)]
pub struct Torii {
    pub address: SocketAddr,
    pub max_content_len: ByteSize<u64>,
    pub query_idle_time: Duration,
}

impl Torii {
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

#[cfg(test)]
mod tests {
    use iroha_config_base::{FromEnv, TestEnv};

    use super::*;
    use crate::parameters::user_layer::boilerplate::{IrohaPartial, RootPartial};

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
        let _layer: RootPartial = toml::toml! {
            [iroha]
            p2p_address = "127.0.0.1:8080"
        }
        .try_into()
        .expect("should not fail when not all fields in `iroha` are presented at a time");
    }

    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct TestExtends {
        extends: ExtendsPaths,
    }

    #[test]
    fn parse_empty_extends() {
        let value: TestExtends = toml::from_str("").expect("should be fine with empty input");

        assert_eq!(value.extends, ExtendsPaths::None);
    }

    #[test]
    fn parse_single_extends_path() {
        let value: TestExtends = toml::toml! {
            extends = "./path"
        }
        .try_into()
        .unwrap();

        assert_eq!(value.extends, ExtendsPaths::Single("./path".into()));
    }

    #[test]
    fn parse_multiple_extends_paths() {
        let value: TestExtends = toml::toml! {
            extends = ["foo", "bar", "baz"]
        }
        .try_into()
        .unwrap();

        assert_eq!(
            value.extends,
            ExtendsPaths::Multiple(vec!["foo".into(), "bar".into(), "baz".into()])
        );
    }

    #[test]
    fn iterating_over_extends() {
        impl ExtendsPaths {
            fn into_str_vec(&self) -> Vec<&str> {
                self.iter().map(|p| p.to_str().unwrap()).collect()
            }
        }

        let empty = ExtendsPaths::None;
        assert_eq!(empty.into_str_vec(), Vec::<&str>::new());

        let single = ExtendsPaths::Single("single".into());
        assert_eq!(single.into_str_vec(), vec!["single"]);

        let multi = ExtendsPaths::Multiple(vec!["foo".into(), "bar".into(), "baz".into()]);
        assert_eq!(multi.into_str_vec(), vec!["foo", "bar", "baz"]);
    }
}
