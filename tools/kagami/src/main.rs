//! CLI for generating iroha sample configuration, genesis and
//! cryptographic key pairs. To be used with all compliant Iroha
//! installations.
#![allow(
    clippy::arithmetic_side_effects,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc
)]
use std::{
    io::{stdout, BufWriter, Write},
    str::FromStr as _,
};

use clap::{Args as ClapArgs, Parser};
use color_eyre::eyre::WrapErr as _;
use iroha_data_model::prelude::*;

/// Outcome shorthand used throughout this crate
pub(crate) type Outcome = color_eyre::Result<()>;

// The reason for hard-coding this default is to ensure that the
// algorithm is matched to the public key. If you need to change
// either, you should definitely change both.
static DEFAULT_PUBLIC_KEY: &str =
    "ed01207233bfc89dcbd68c19fde6ce6158225298ec1131b6a130d1aeb454c1ab5183c0";
// static DEFAULT_ALGORITHM: &str = iroha_crypto::ED_25519;

fn main() -> Outcome {
    color_eyre::install()?;
    let args = Args::parse();
    let mut writer = BufWriter::new(stdout());
    args.run(&mut writer)
}

/// Trait to encapsulate common attributes of the commands and sub-commands.
pub trait RunArgs<T: Write> {
    /// Run the given command.
    ///
    /// # Errors
    /// if inner command fails.
    fn run(self, writer: &mut BufWriter<T>) -> Outcome;
}

/// Kagami is a tool used to generate and validate automatically generated data files that are
/// shipped with Iroha.
#[derive(Parser, Debug)]
#[command(name = "kagami", version, author)]
pub enum Args {
    /// Generate cryptographic key pairs using the given algorithm and either private key or seed
    Crypto(Box<crypto::Args>),
    /// Generate the schema used for code generation in Iroha SDKs
    Schema(schema::Args),
    /// Generate the genesis block that is used in tests
    Genesis(genesis::Args),
    /// Generate the default client/peer configuration
    Config(config::Args),
    /// Generate a Markdown reference of configuration parameters
    Docs(Box<docs::Args>),
    /// Generate the default validator
    Validator(validator::Args),
    /// Generate a docker-compose configuration for a variable number of peers
    /// using a Dockerhub image, GitHub repo, or a local Iroha repo.
    ///
    /// This command builds the docker-compose configuration in a specified directory. If the source
    /// is a GitHub repo, it will be cloned into the directory. Also, the default configuration is
    /// built and put into `<target>/config` directory, unless `--no-default-configuration` flag is
    /// provided. The default configuration is equivalent to running `kagami config peer`,
    /// `kagami validator`, and `kagami genesis default --compiled-validator-path ./validator.wasm` consecutively.
    ///
    /// Default configuration building will fail if Kagami is run outside of Iroha repo (tracking
    /// issue: https://github.com/hyperledger/iroha/issues/3473). If you are going to run it outside
    /// of the repo, make sure to pass `--no-default-configuration` flag.
    ///
    /// Be careful with specifying a Dockerhub image as a source: Kagami Swarm only guarantees that
    /// the docker-compose configuration it generates is compatible with the same Git revision it
    /// is built from itself. Therefore, if specified image is not compatible with the version of Swarm
    /// you are running, the generated configuration might not work.
    Swarm(swarm::Args),
}

impl<T: Write> RunArgs<T> for Args {
    fn run(self, writer: &mut BufWriter<T>) -> Outcome {
        use Args::*;

        match self {
            Crypto(args) => args.run(writer),
            Schema(args) => args.run(writer),
            Genesis(args) => args.run(writer),
            Config(args) => args.run(writer),
            Docs(args) => args.run(writer),
            Validator(args) => args.run(writer),
            Swarm(args) => args.run(),
        }
    }
}

mod crypto {
    use clap::{builder::PossibleValue, ArgGroup, ValueEnum};
    use color_eyre::eyre::WrapErr as _;
    use iroha_crypto::{Algorithm, KeyGenConfiguration, KeyPair, PrivateKey};

    use super::*;

    /// Use `Kagami` to generate cryptographic key-pairs.
    #[derive(ClapArgs, Debug, Clone)]
    #[command(group = ArgGroup::new("generate_from").required(false))]
    #[command(group = ArgGroup::new("format").required(false))]
    pub struct Args {
        /// The algorithm to use for the key-pair generation
        #[clap(default_value_t, long, short)]
        algorithm: AlgorithmArg,
        /// The `private_key` to generate the key-pair from
        #[clap(long, short, group = "generate_from")]
        private_key: Option<String>,
        /// The `seed` to generate the key-pair from
        #[clap(long, short, group = "generate_from")]
        seed: Option<String>,
        /// Output the key-pair in JSON format
        #[clap(long, short, group = "format")]
        json: bool,
        /// Output the key-pair without additional text
        #[clap(long, short, group = "format")]
        compact: bool,
    }

    #[derive(Clone, Debug, Default, derive_more::Display)]
    struct AlgorithmArg(Algorithm);

    impl ValueEnum for AlgorithmArg {
        fn value_variants<'a>() -> &'a [Self] {
            // TODO: add compile-time check to ensure all variants are enumerated
            &[
                Self(Algorithm::Ed25519),
                Self(Algorithm::Secp256k1),
                Self(Algorithm::BlsNormal),
                Self(Algorithm::BlsSmall),
            ]
        }

        fn to_possible_value(&self) -> Option<PossibleValue> {
            Some(self.0.as_static_str().into())
        }
    }

    impl<T: Write> RunArgs<T> for Args {
        fn run(self, writer: &mut BufWriter<T>) -> Outcome {
            if self.json {
                let key_pair = self.key_pair()?;
                let output = serde_json::to_string_pretty(&key_pair)
                    .wrap_err("Failed to serialise to JSON.")?;
                writeln!(writer, "{output}")?;
            } else if self.compact {
                let key_pair = self.key_pair()?;
                writeln!(writer, "{}", &key_pair.public_key())?;
                writeln!(writer, "{}", &key_pair.private_key())?;
                writeln!(writer, "{}", &key_pair.public_key().digest_function())?;
            } else {
                let key_pair = self.key_pair()?;
                writeln!(
                    writer,
                    "Public key (multihash): \"{}\"",
                    &key_pair.public_key()
                )?;
                writeln!(
                    writer,
                    "Private key ({}): \"{}\"",
                    &key_pair.public_key().digest_function(),
                    &key_pair.private_key()
                )?;
            }
            Ok(())
        }
    }

    impl Args {
        fn key_pair(self) -> color_eyre::Result<KeyPair> {
            let algorithm = self.algorithm.0;
            let config = KeyGenConfiguration::default().with_algorithm(algorithm);

            let key_pair = match (self.seed, self.private_key) {
                (None, None) => KeyPair::generate_with_configuration(config),
                (None, Some(private_key_hex)) => {
                    let private_key = PrivateKey::from_hex(algorithm, private_key_hex.as_ref())
                        .wrap_err("Failed to decode private key")?;
                    KeyPair::generate_with_configuration(config.use_private_key(private_key))
                }
                (Some(seed), None) => {
                    let seed: Vec<u8> = seed.as_bytes().into();
                    KeyPair::generate_with_configuration(config.use_seed(seed))
                }
                _ => unreachable!("Clap group invariant"),
            }
            .wrap_err("Failed to generate key pair")?;

            Ok(key_pair)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::{Algorithm, AlgorithmArg};

        #[test]
        fn algorithm_arg_displays_as_algorithm() {
            assert_eq!(
                format!("{}", AlgorithmArg(Algorithm::Ed25519)),
                format!("{}", Algorithm::Ed25519)
            )
        }
    }
}

mod schema {
    use super::*;

    #[derive(ClapArgs, Debug, Clone, Copy)]
    pub struct Args;

    impl<T: Write> RunArgs<T> for Args {
        fn run(self, writer: &mut BufWriter<T>) -> Outcome {
            let schemas = iroha_schema_gen::build_schemas();
            writeln!(writer, "{}", serde_json::to_string_pretty(&schemas)?)
                .wrap_err("Failed to write schema.")
        }
    }
}

mod genesis {
    use std::path::PathBuf;

    use clap::{ArgGroup, Parser, Subcommand};
    use iroha_config::{sumeragi::default::*, wasm::default::*, wsv::default::*};
    use iroha_data_model::{
        asset::AssetValueType,
        isi::{MintBox, RegisterBox},
        metadata::Limits,
        parameter::{default::*, ParametersBuilder},
        prelude::AssetId,
        validator::Validator,
        IdBox,
    };
    use iroha_genesis::{RawGenesisBlock, RawGenesisBlockBuilder, ValidatorMode, ValidatorPath};

    use super::*;

    #[derive(Parser, Debug, Clone)]
    #[clap(group = ArgGroup::new("validator").required(true))]
    pub struct Args {
        /// If this option provided validator will be inlined in the genesis.
        #[clap(long, group = "validator")]
        inlined_validator: bool,
        /// If this option provided validator won't be included in the genesis and only path to the validator will be included.
        /// Path is either absolute path to validator or relative to genesis location.
        /// Validator can be generated using `kagami validator` command.
        #[clap(long, group = "validator")]
        compiled_validator_path: Option<PathBuf>,
        #[clap(subcommand)]
        mode: Option<Mode>,
    }

    #[derive(Subcommand, Debug, Clone, Default)]
    pub enum Mode {
        /// Generate default genesis
        #[default]
        Default,
        /// Generate synthetic genesis with specified number of domains, accounts and assets.
        ///
        /// Synthetic mode is useful when we need a semi-realistic genesis for stress-testing
        /// Iroha's startup times as well as being able to just start an Iroha network and have
        /// instructions that represent a typical blockchain after migration.
        Synthetic {
            /// Number of domains in synthetic genesis.
            #[clap(long, default_value_t)]
            domains: u64,
            /// Number of accounts per domains in synthetic genesis.
            /// Total number of  accounts would be `domains * assets_per_domain`.
            #[clap(long, default_value_t)]
            accounts_per_domain: u64,
            /// Number of assets per domains in synthetic genesis.
            /// Total number of assets would be `domains * assets_per_domain`.
            #[clap(long, default_value_t)]
            assets_per_domain: u64,
        },
    }

    impl<T: Write> RunArgs<T> for Args {
        fn run(self, writer: &mut BufWriter<T>) -> Outcome {
            if self.inlined_validator {
                eprintln!("WARN: You're using genesis with inlined validator.");
                eprintln!("Consider providing validator in separate file `--compiled-validator-path PATH`.");
                eprintln!("Use `--help` to get more information.");
            }
            let validator_path = self.compiled_validator_path;
            let genesis = match self.mode.unwrap_or_default() {
                Mode::Default => generate_default(validator_path),
                Mode::Synthetic {
                    domains,
                    accounts_per_domain,
                    assets_per_domain,
                } => generate_synthetic(
                    validator_path,
                    domains,
                    accounts_per_domain,
                    assets_per_domain,
                ),
            }?;
            writeln!(writer, "{}", serde_json::to_string_pretty(&genesis)?)
                .wrap_err("Failed to write serialized genesis to the buffer.")
        }
    }

    #[allow(clippy::too_many_lines)]
    pub fn generate_default(
        validator_path: Option<PathBuf>,
    ) -> color_eyre::Result<RawGenesisBlock> {
        let mut meta = Metadata::new();
        meta.insert_with_limits(
            "key".parse()?,
            "value".to_owned().into(),
            Limits::new(1024, 1024),
        )?;

        let validator = match validator_path {
            Some(validator_path) => ValidatorMode::Path(ValidatorPath(validator_path)),
            None => ValidatorMode::Inline(construct_validator()?),
        };

        let mut genesis = RawGenesisBlockBuilder::new()
            .domain_with_metadata("wonderland".parse()?, meta.clone())
            .account_with_metadata(
                "alice".parse()?,
                crate::DEFAULT_PUBLIC_KEY.parse()?,
                meta.clone(),
            )
            .account_with_metadata("bob".parse()?, crate::DEFAULT_PUBLIC_KEY.parse()?, meta) // TODO: This should fail under SS58
            .asset("rose".parse()?, AssetValueType::Quantity)
            .finish_domain()
            .domain("garden_of_live_flowers".parse()?)
            .account("carpenter".parse()?, crate::DEFAULT_PUBLIC_KEY.parse()?)
            .asset("cabbage".parse()?, AssetValueType::Quantity)
            .finish_domain()
            .validator(validator)
            .build();

        let mint = MintBox::new(
            13_u32.to_value(),
            IdBox::AssetId(AssetId::new(
                "rose#wonderland".parse()?,
                "alice@wonderland".parse()?,
            )),
        );
        let mint_cabbage = MintBox::new(
            44_u32.to_value(),
            IdBox::AssetId(AssetId::new(
                "cabbage#garden_of_live_flowers".parse()?,
                "alice@wonderland".parse()?,
            )),
        );
        let alice_id = <Account as Identifiable>::Id::from_str("alice@wonderland")?;
        let grant_permission_to_set_parameters = GrantBox::new(
            PermissionToken::new("can_set_parameters".parse()?),
            alice_id,
        );
        let register_user_metadata_access = RegisterBox::new(
            Role::new("ALICE_METADATA_ACCESS".parse()?)
                .add_permission(
                    PermissionToken::new("can_set_key_value_in_user_account".parse()?).with_params(
                        [(
                            "account_id".parse()?,
                            IdBox::AccountId("alice@wonderland".parse()?).into(),
                        )],
                    ),
                )
                .add_permission(
                    PermissionToken::new("can_remove_key_value_in_user_account".parse()?)
                        .with_params([(
                            "account_id".parse()?,
                            IdBox::AccountId("alice@wonderland".parse()?).into(),
                        )]),
                ),
        )
        .into();

        let parameter_defaults = ParametersBuilder::new()
            .add_parameter(MAX_TRANSACTIONS_IN_BLOCK, DEFAULT_MAX_TRANSACTIONS_IN_BLOCK)?
            .add_parameter(BLOCK_TIME, DEFAULT_BLOCK_TIME_MS)?
            .add_parameter(COMMIT_TIME_LIMIT, DEFAULT_COMMIT_TIME_LIMIT_MS)?
            .add_parameter(TRANSACTION_LIMITS, DEFAULT_TRANSACTION_LIMITS)?
            .add_parameter(WSV_ASSET_METADATA_LIMITS, DEFAULT_METADATA_LIMITS)?
            .add_parameter(
                WSV_ASSET_DEFINITION_METADATA_LIMITS,
                DEFAULT_METADATA_LIMITS.to_value(),
            )?
            .add_parameter(WSV_ACCOUNT_METADATA_LIMITS, DEFAULT_METADATA_LIMITS)?
            .add_parameter(WSV_DOMAIN_METADATA_LIMITS, DEFAULT_METADATA_LIMITS)?
            .add_parameter(WSV_IDENT_LENGTH_LIMITS, DEFAULT_IDENT_LENGTH_LIMITS)?
            .add_parameter(WASM_FUEL_LIMIT, DEFAULT_FUEL_LIMIT)?
            .add_parameter(WASM_MAX_MEMORY, DEFAULT_MAX_MEMORY)?
            .into_create_parameters();

        genesis.transactions[0].isi.push(mint.into());
        genesis.transactions[0].isi.push(mint_cabbage.into());
        genesis.transactions[0]
            .isi
            .push(grant_permission_to_set_parameters.into());
        genesis.transactions[0].isi.push(parameter_defaults.into());
        genesis.transactions[0]
            .isi
            .push(register_user_metadata_access);

        Ok(genesis)
    }

    fn construct_validator() -> color_eyre::Result<Validator> {
        let wasm_blob = crate::validator::construct_validator()?;
        Ok(Validator::new(WasmSmartContract::from_compiled(wasm_blob)))
    }

    fn generate_synthetic(
        validator_path: Option<PathBuf>,
        domains: u64,
        accounts_per_domain: u64,
        assets_per_domain: u64,
    ) -> color_eyre::Result<RawGenesisBlock> {
        let validator = match validator_path {
            Some(validator_path) => ValidatorMode::Path(ValidatorPath(validator_path)),
            None => ValidatorMode::Inline(construct_validator()?),
        };

        // Add default `Domain` and `Account` to still be able to query
        let mut builder = RawGenesisBlockBuilder::new()
            .domain("wonderland".parse()?)
            .account("alice".parse()?, crate::DEFAULT_PUBLIC_KEY.parse()?)
            .finish_domain();

        for domain in 0..domains {
            let mut domain_builder = builder.domain(format!("domain_{domain}").parse()?);

            for account in 0..accounts_per_domain {
                let (public_key, _) = iroha_crypto::KeyPair::generate()?.into();
                domain_builder =
                    domain_builder.account(format!("account_{account}").parse()?, public_key);
            }

            for asset in 0..assets_per_domain {
                domain_builder = domain_builder
                    .asset(format!("asset_{asset}").parse()?, AssetValueType::Quantity);
            }

            builder = domain_builder.finish_domain();
        }
        let mut genesis = builder.validator(validator).build();

        let mints = {
            let mut acc = Vec::new();
            for domain in 0..domains {
                for account in 0..accounts_per_domain {
                    // FIXME: it actually generates (assets_per_domain * accounts_per_domain) assets per domain
                    //        https://github.com/hyperledger/iroha/issues/3508
                    for asset in 0..assets_per_domain {
                        let mint = MintBox::new(
                            13_u32.to_value(),
                            IdBox::AssetId(AssetId::new(
                                format!("asset_{asset}#domain_{domain}").parse()?,
                                format!("account_{account}@domain_{domain}").parse()?,
                            )),
                        );
                        acc.push(mint);
                    }
                }
            }
            acc
        }
        .into_iter()
        .map(Into::into);

        genesis.transactions[0].isi.extend(mints);

        Ok(genesis)
    }
}

mod config {
    use std::str::FromStr as _;

    use clap::{Parser, Subcommand};
    use iroha_crypto::{Algorithm, PrivateKey, PublicKey};
    use iroha_primitives::small::SmallStr;

    use super::*;

    #[derive(Parser, Debug, Clone, Copy)]
    pub struct Args {
        #[clap(subcommand)]
        mode: Mode,
    }

    #[derive(Subcommand, Debug, Clone, Copy)]
    pub enum Mode {
        Client(client::Args),
        Peer(peer::Args),
    }

    impl<T: Write> RunArgs<T> for Args {
        fn run(self, writer: &mut BufWriter<T>) -> Outcome {
            match self.mode {
                Mode::Client(args) => args.run(writer),
                Mode::Peer(args) => args.run(writer),
            }
        }
    }

    mod client {
        use iroha_config::{
            client::{BasicAuth, ConfigurationProxy, WebLogin},
            torii::{uri::DEFAULT_API_ADDR, DEFAULT_TORII_TELEMETRY_ADDR},
        };

        use super::*;

        #[derive(ClapArgs, Debug, Clone, Copy)]
        pub struct Args;

        impl<T: Write> RunArgs<T> for Args {
            fn run(self, writer: &mut BufWriter<T>) -> Outcome {
                let config = ConfigurationProxy {
                    torii_api_url: Some(format!("http://{DEFAULT_API_ADDR}").parse()?),
                    torii_telemetry_url: Some(format!("http://{DEFAULT_TORII_TELEMETRY_ADDR}").parse()?),
                    account_id: Some("alice@wonderland".parse()?),
                    basic_auth: Some(Some(BasicAuth {
                        web_login: WebLogin::new("mad_hatter")?,
                        password: SmallStr::from_str("ilovetea"),
                    })),
                    public_key: Some(PublicKey::from_str(
                        "ed01207233BFC89DCBD68C19FDE6CE6158225298EC1131B6A130D1AEB454C1AB5183C0",
                    )?),
                    private_key: Some(PrivateKey::from_hex(
                        Algorithm::Ed25519,
                        "9AC47ABF59B356E0BD7DCBBBB4DEC080E302156A48CA907E47CB6AEA1D32719E7233BFC89DCBD68C19FDE6CE6158225298EC1131B6A130D1AEB454C1AB5183C0".as_ref()
                    )?),
                    ..ConfigurationProxy::default()
                }
                .build()?;
                writeln!(writer, "{}", serde_json::to_string_pretty(&config)?)
                    .wrap_err("Failed to write serialized client configuration to the buffer.")
            }
        }
    }

    mod peer {
        use iroha_config::iroha::ConfigurationProxy as IrohaConfigurationProxy;

        use super::*;

        #[derive(ClapArgs, Debug, Clone, Copy)]
        pub struct Args;

        impl<T: Write> RunArgs<T> for Args {
            fn run(self, writer: &mut BufWriter<T>) -> Outcome {
                let config = IrohaConfigurationProxy::default();
                writeln!(writer, "{}", serde_json::to_string_pretty(&config)?)
                    .wrap_err("Failed to write serialized peer configuration to the buffer.")
            }
        }
    }
}

mod docs {
    #![allow(clippy::panic_in_result_fn, clippy::expect_used)]
    #![allow(
        clippy::arithmetic_side_effects,
        clippy::std_instead_of_core,
        clippy::std_instead_of_alloc
    )]
    use std::{fmt::Debug, io::Write};

    use color_eyre::eyre::WrapErr as _;
    use iroha_config::{base::proxy::Documented, iroha::ConfigurationProxy};
    use serde_json::Value;

    use super::*;

    impl<E: Debug, C: Documented<Error = E> + Send + Sync + Default> PrintDocs for C {}

    #[derive(ClapArgs, Debug, Clone, Copy)]
    pub struct Args;

    impl<T: Write> RunArgs<T> for Args {
        fn run(self, writer: &mut BufWriter<T>) -> crate::Outcome {
            ConfigurationProxy::get_markdown(writer).wrap_err("Failed to generate documentation")
        }
    }

    pub trait PrintDocs: Documented + Send + Sync + Default
    where
        Self::Error: Debug,
    {
        fn get_markdown<W: Write>(writer: &mut W) -> color_eyre::Result<()> {
            let Value::Object(docs) = Self::get_docs() else {
                unreachable!("As top level structure is always object")
            };
            let mut vec = Vec::new();
            let defaults = serde_json::to_string_pretty(&Self::default())?;

            writeln!(writer, "# Iroha Configuration reference\n")?;
            writeln!(writer, "In this document we provide a reference and detailed descriptions of Iroha's configuration options. \
                              The options have different underlying types and default values, which are denoted in code as types wrapped in a single \
                              `Option<..>` or in a double `Option<Option<..>>`. For the detailed explanation, please refer to \
                              this [section](#configuration-types).\n")?;
            writeln!(
                writer,
                "## Configuration types\n\n\
                 ### `Option<..>`\n\n\
                 A type wrapped in a single `Option<..>` signifies that in the corresponding `json` block there is a fallback value for this type, \
                 and that it only serves as a reference. If a default for such a type has a `null` value, it means that there is no meaningful fallback \
                 available for this particular value.\n\nAll the default values can be freely obtained from a provided [sample configuration file](../../../configs/peer/config.json), \
                 but it should only serve as a starting point. If left unchanged, the sample configuration file would still fail to build due to it having `null` in place of \
                 [public](#public_key) and [private](#private_key) keys as well as [endpoint](#torii.api_url) [URLs](#torii.telemetry_url). \
                 These should be provided either by modifying the sample config file or as environment variables. \
                 No other overloading of configuration values happens besides reading them from a file and capturing the environment variables.\n\n\
                 For both types of configuration options wrapped in a single `Option<..>` (i.e. both those that have meaningful defaults and those that have `null`), \
                 failure to provide them in any of the above two ways results in an error.\n\n\
                 ### `Option<Option<..>>`\n\n\
                 `Option<Option<..>>` types should be distinguished from types wrapped in a single `Option<..>`. Only the double option ones are allowed to stay `null`, \
                 meaning that **not** providing them in an environment variable or a file will **not** result in an error.\n\n\
                 Thus, only these types are truly optional in the mundane sense of the word. \
                 An example of this distinction is genesis [public](#genesis.account_public_key) and [private](#genesis.account_private_key) key. \
                 While the first one is a single `Option<..>` wrapped type, the latter is wrapped in `Option<Option<..>>`. This means that the genesis *public* key should always be \
                 provided by the user, be it via a file config or an environment variable, whereas the *private* key is only needed for the peer that submits the genesis block, \
                 and can be omitted for all others. The same logic goes for other double option fields such as logger file path.\n\n\
                 ### Sumeragi: default `null` values\n\n\
                 A special note about sumeragi fields with `null` as default: only the [`trusted_peers`](#sumeragi.trusted_peers) field out of the three can be initialized via a \
                 provided file or an environment variable.\n\n\
                 The other two fields, namely [`key_pair`](#sumeragi.key_pair) and [`peer_id`](#sumeragi.peer_id), go through a process of finalization where their values \
                 are derived from the corresponding ones in the uppermost Iroha config (using its [`public_key`](#public_key) and [`private_key`](#private_key) fields) \
                 or the Torii config (via its [`p2p_addr`](#torii.p2p_addr)). \
                 This ensures that these linked fields stay in sync, and prevents the programmer error when different values are provided to these field pairs. \
                 Providing either `sumeragi.key_pair` or `sumeragi.peer_id` by hand will result in an error, as it should never be done directly.\n"
            )?;
            writeln!(writer, "## Default configuration\n")?;
            writeln!(
                writer,
                "The following is the default configuration used by Iroha.\n"
            )?;
            writeln!(writer, "```json\n{defaults}\n```\n")?;
            Self::get_markdown_with_depth(writer, &docs, &mut vec, 2)?;
            Ok(())
        }

        fn get_markdown_with_depth<W: Write>(
            writer: &mut W,
            docs: &serde_json::Map<String, Value>,
            field: &mut Vec<String>,
            depth: usize,
        ) -> color_eyre::Result<()> {
            let current_field = {
                let mut docs = docs;
                for f in &*field {
                    docs = match &docs[f] {
                        Value::Object(obj) => obj,
                        _ => unreachable!(),
                    };
                }
                docs
            };

            for (f, value) in current_field {
                field.push(f.clone());
                let get_field = field.iter().map(AsRef::as_ref).collect::<Vec<&str>>();
                let (doc, inner) = match value {
                    Value::Object(_) => {
                        let doc = Self::get_doc_recursive(&get_field)
                            .expect("Should be there, as already in docs");
                        (doc.unwrap_or_default(), true)
                    }
                    Value::String(s) => (s.clone(), false),
                    _ => unreachable!("Only strings and objects in docs"),
                };
                // Hacky workaround to avoid duplicating inner fields docs in the reference
                let doc = doc.lines().take(3).collect::<Vec<&str>>().join("\n");
                let doc = doc.strip_prefix(' ').unwrap_or(&doc);
                let defaults = Self::default()
                    .get_recursive(get_field)
                    .expect("Failed to get defaults.");
                let defaults = serde_json::to_string_pretty(&defaults)?;
                let field_str = field
                    .join(".")
                    .chars()
                    .filter(|&chr| chr != ' ')
                    .collect::<String>();

                write!(writer, "{} `{}`\n\n", "#".repeat(depth), field_str)?;
                write!(writer, "{doc}\n\n")?;
                write!(writer, "```json\n{defaults}\n```\n\n")?;

                if inner {
                    Self::get_markdown_with_depth(writer, docs, field, depth + 1)?;
                }

                field.pop();
            }
            Ok(())
        }
    }
}

mod validator {
    use super::*;

    #[derive(ClapArgs, Debug, Clone, Copy)]
    pub struct Args;

    impl<T: Write> RunArgs<T> for Args {
        fn run(self, writer: &mut BufWriter<T>) -> Outcome {
            writer
                .write_all(&construct_validator()?)
                .wrap_err("Failed to write wasm validator into the buffer.")
        }
    }

    pub fn construct_validator() -> color_eyre::Result<Vec<u8>> {
        let build_dir = tempfile::tempdir()
            .wrap_err("Failed to create temp dir for runtime validator output")?;

        // FIXME: will it work when Kagami is run outside of the iroha dir?
        //        https://github.com/hyperledger/iroha/issues/3473
        let wasm_blob = iroha_wasm_builder::Builder::new("../../default_validator")
            .out_dir(build_dir.path())
            .build()?
            .optimize()?
            .into_bytes();

        Ok(wasm_blob)
    }
}

mod swarm;
