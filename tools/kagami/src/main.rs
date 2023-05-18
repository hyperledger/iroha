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

// use clap::ArgGroup;
use clap::{Args as ClapArgs, Parser};
use color_eyre::eyre::WrapErr as _;
use iroha_data_model::{prelude::*, ValueKind};

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

/// Tool generating the cryptographic key pairs, schema, genesis block and configuration reference.
#[derive(Parser, Debug)]
#[command(name = "kagami", version, author)]
pub enum Args {
    /// Generate cryptographic key pairs
    Crypto(Box<crypto::Args>),
    /// Generate the schema used for code generation in Iroha SDKs
    Schema(schema::Args),
    /// Generate the genesis block that is used in tests
    Genesis(genesis::Args),
    /// Generate the default client configuration
    Config(config::Args),
    /// Generate a Markdown reference of configuration parameters
    Docs(Box<docs::Args>),
    /// Generate a list of predefined permission tokens and their parameters
    Tokens(tokens::Args),
    /// Generate validator
    Validator(validator::Args),
    /// Generate docker-compose configuration for a variable number of peers
    /// using Dockerhub images, Git repo or a local path.
    ///
    /// In opposite to other commands, this command is channel-agnostic, i.e.
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
            Tokens(args) => args.run(writer),
            Validator(args) => args.run(writer),
            Swarm(args) => args.run(writer),
        }
    }
}

mod crypto {
    use std::fmt::{Display, Formatter};

    use clap::{builder::PossibleValue, ArgGroup, ValueEnum};
    use color_eyre::eyre::{eyre, WrapErr as _};
    use iroha_crypto::{Algorithm, KeyGenConfiguration, KeyPair, PrivateKey};

    use super::*;

    /// Use `Kagami` to generate cryptographic key-pairs.
    #[derive(ClapArgs, Debug, Clone)]
    #[command(group = ArgGroup::new("generate_from").required(false))]
    #[command(group = ArgGroup::new("format").required(false))]
    pub struct Args {
        /// Algorithm used to generate the key-pair.
        #[clap(default_value_t, long, short)]
        algorithm: AlgorithmArg,
        /// The `private_key` used to generate the key-pair
        #[clap(long, short, group = "generate_from")]
        private_key: Option<String>,
        /// The `seed` used to generate the key-pair
        #[clap(long, short, group = "generate_from")]
        seed: Option<String>,
        /// Output the key-pair in JSON format
        #[clap(long, short, group = "format")]
        json: bool,
        /// Output the key-pair without additional text
        #[clap(long, short, group = "format")]
        compact: bool,
    }

    #[derive(Clone, Debug, Default)]
    struct AlgorithmArg(Algorithm);

    impl Display for AlgorithmArg {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            self.0.fmt(f)
        }
    }

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
            let key_gen_configuration = KeyGenConfiguration::default().with_algorithm(algorithm);
            let keypair: KeyPair = self.seed.map_or_else(
                || -> color_eyre::Result<_> {
                    self.private_key.map_or_else(
                        || {
                            KeyPair::generate_with_configuration(key_gen_configuration.clone())
                                .wrap_err("failed to generate key pair")
                        },
                        |private_key| {
                            let private_key = PrivateKey::from_hex(algorithm, private_key.as_ref())
                                .wrap_err("Failed to decode private key")?;
                            KeyPair::generate_with_configuration(
                                key_gen_configuration.clone().use_private_key(private_key),
                            )
                            .wrap_err("Failed to generate key pair")
                        },
                    )
                },
                |seed| -> color_eyre::Result<_> {
                    let seed: Vec<u8> = seed.as_bytes().into();
                    // `ursa` crashes if provided seed for `secp256k1` shorter than 32 bytes
                    if seed.len() < 32 && algorithm == Algorithm::Secp256k1 {
                        return Err(eyre!("secp256k1 seed for must be at least 32 bytes long"));
                    }
                    KeyPair::generate_with_configuration(
                        key_gen_configuration.clone().use_seed(seed),
                    )
                    .wrap_err("Failed to generate key pair")
                },
            )?;
            Ok(keypair)
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
        transaction::DEFAULT_TRANSACTION_LIMITS,
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
        let token = PermissionToken::new("allowed_to_do_stuff".parse()?);

        let register_permission =
            RegisterBox::new(PermissionTokenDefinition::new(token.definition_id.clone()));
        let role_id: RoleId = "staff_that_does_stuff_in_genesis".parse()?;
        let register_role =
            RegisterBox::new(Role::new(role_id.clone()).add_permission(token.clone()));

        let alice_id = <Account as Identifiable>::Id::from_str("alice@wonderland")?;
        let grant_permission = GrantBox::new(token, alice_id.clone());
        let grant_permission_to_set_parameters = GrantBox::new(
            PermissionToken::new("can_set_parameters".parse()?),
            alice_id.clone(),
        );
        let register_user_metadata_access = RegisterBox::new(
            Role::new("USER_METADATA_ACCESS".parse()?)
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

        let grant_role = GrantBox::new(role_id, alice_id);

        genesis.transactions[0].isi.push(mint.into());
        genesis.transactions[0].isi.push(mint_cabbage.into());
        genesis.transactions[0]
            .isi
            .extend(register_permission_token_definitions()?);
        genesis.transactions[0].isi.push(register_permission.into());
        genesis.transactions[0].isi.push(grant_permission.into());
        genesis.transactions[0]
            .isi
            .push(grant_permission_to_set_parameters.into());
        genesis.transactions[0].isi.push(register_role.into());
        genesis.transactions[0].isi.push(grant_role.into());
        genesis.transactions[0].isi.push(parameter_defaults.into());
        genesis.transactions[0]
            .isi
            .push(register_user_metadata_access);

        Ok(genesis)
    }

    fn register_permission_token_definitions() -> color_eyre::Result<Vec<InstructionBox>> {
        Ok(super::tokens::permission_token_definitions()?
            .into_iter()
            .map(RegisterBox::new)
            .map(Into::into)
            .collect())
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
                    // FIXME it actually generates (assets_per_domain * accounts_per_domain) assets per domain
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
        genesis.transactions[0]
            .isi
            .extend(register_permission_token_definitions()?);

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

mod tokens {
    use color_eyre::{eyre::WrapErr, Result};

    use super::*;

    #[derive(ClapArgs, Debug, Clone, Copy)]
    pub struct Args;

    pub fn permission_token_definitions() -> Result<Vec<PermissionTokenDefinition>> {
        // TODO: Not hardcode this. Instead get this info from validator itself
        Ok(vec![
            // Account
            token_with_account_id("can_unregister_account")?,
            token_with_account_id("can_mint_user_public_keys")?,
            token_with_account_id("can_burn_user_public_keys")?,
            token_with_account_id("can_mint_user_signature_check_conditions")?,
            token_with_account_id("can_set_key_value_in_user_account")?,
            token_with_account_id("can_remove_key_value_in_user_account")?,
            // Asset
            token_with_asset_definition_id("can_register_assets_with_definition")?,
            token_with_asset_definition_id("can_unregister_assets_with_definition")?,
            token_with_asset_definition_id("can_unregister_user_assets")?,
            token_with_asset_definition_id("can_burn_assets_with_definition")?,
            token_with_asset_id("can_burn_user_asset")?,
            token_with_asset_definition_id("can_mint_assets_with_definition")?,
            token_with_asset_definition_id("can_transfer_assets_with_definition")?,
            token_with_asset_id("can_transfer_user_asset")?,
            token_with_asset_id("can_set_key_value_in_user_asset")?,
            token_with_asset_id("can_remove_key_value_in_user_asset")?,
            // Asset definition
            token_with_asset_definition_id("can_unregister_asset_definition")?,
            token_with_asset_definition_id("can_set_key_value_in_asset_definition")?,
            token_with_asset_definition_id("can_remove_key_value_in_asset_definition")?,
            // Domain
            token_with_domain_id("can_unregister_domain")?,
            token_with_domain_id("can_set_key_value_in_domain")?,
            token_with_domain_id("can_remove_key_value_in_domain")?,
            // Parameter
            bare_token("can_grant_permission_to_create_parameters")?,
            bare_token("can_revoke_permission_to_create_parameters")?,
            bare_token("can_create_parameters")?,
            bare_token("can_grant_permission_to_set_parameters")?,
            bare_token("can_revoke_permission_to_set_parameters")?,
            bare_token("can_set_parameters")?,
            // Peer
            bare_token("can_unregister_any_peer")?,
            // Role
            bare_token("can_unregister_any_role")?,
            // Trigger
            token_with_trigger_id("can_execute_user_trigger")?,
            token_with_trigger_id("can_unregister_user_trigger")?,
            token_with_trigger_id("can_mint_user_trigger")?,
            // Validator
            bare_token("can_upgrade_validator")?,
        ])
    }

    fn bare_token(token_id: &str) -> Result<PermissionTokenDefinition> {
        Ok(PermissionTokenDefinition::new(token_id.parse()?))
    }

    fn token_with_asset_definition_id(token_id: &str) -> Result<PermissionTokenDefinition> {
        token_with_id_param(token_id, "asset_definition_id")
    }

    fn token_with_asset_id(token_id: &str) -> Result<PermissionTokenDefinition> {
        token_with_id_param(token_id, "asset_id")
    }

    fn token_with_account_id(token_id: &str) -> Result<PermissionTokenDefinition> {
        token_with_id_param(token_id, "account_id")
    }

    fn token_with_domain_id(token_id: &str) -> Result<PermissionTokenDefinition> {
        token_with_id_param(token_id, "domain_id")
    }

    fn token_with_trigger_id(token_id: &str) -> Result<PermissionTokenDefinition> {
        token_with_id_param(token_id, "trigger_id")
    }

    fn token_with_id_param(token_id: &str, param_name: &str) -> Result<PermissionTokenDefinition> {
        Ok(PermissionTokenDefinition::new(token_id.parse()?)
            .with_params([(param_name.parse()?, ValueKind::Id)]))
    }

    impl<T: Write> RunArgs<T> for Args {
        fn run(self, writer: &mut BufWriter<T>) -> Outcome {
            write!(
                writer,
                "{}",
                serde_json::to_string_pretty(&permission_token_definitions()?)
                    .wrap_err("Serialization error")?
            )
            .wrap_err("Failed to write serialized token map into the buffer.")
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
        let wasm_blob = iroha_wasm_builder::Builder::new("../../default_validator")
            .out_dir(build_dir.path())
            .build()?
            .optimize()?
            .into_bytes();

        Ok(wasm_blob)
    }
}

mod swarm {
    use std::{
        fs::File,
        io::{BufWriter, Write},
        num::NonZeroUsize,
        ops::Deref,
        path::{Path, PathBuf},
        str::FromStr,
    };

    use clap::ValueEnum;
    use color_eyre::{
        eyre::{eyre, Context, ContextCompat},
        Result,
    };
    use path_absolutize::Absolutize;

    use super::ClapArgs;
    use crate::{
        swarm::{
            serialize_docker_compose::{
                DockerCompose, DockerComposeService, ServiceCommand, ServiceSource,
            },
            ui::Reporter,
        },
        Outcome, RunArgs,
    };

    const GIT_REVISION: &str = env!("VERGEN_GIT_SHA");
    const GIT_ORIGIN: &str = "https://github.com/hyperledger/iroha.git";
    const DIR_CONFIG: &str = "config";
    const DIR_CLONE: &str = "iroha-cloned";
    const FILE_VALIDATOR: &str = "validator.wasm";
    const FILE_CONFIG: &str = "config.json";
    const FILE_GENESIS: &str = "genesis.json";
    const FILE_COMPOSE: &str = "docker-compose.yml";
    const DIR_FORCE_SUGGESTION: &str =
        "You can pass `--dir-force` flag to remove the directory without prompting";

    #[derive(ClapArgs, Debug)]
    pub struct Args {
        #[command(flatten)]
        source: ImageSourceArgs,
        /// How many peers to generate within the docker-compose.
        #[arg(long, short)]
        peers: NonZeroUsize,
        /// Target directory where to place generated files.
        ///
        /// If the directory is not empty, Kagami will prompt it's re-creation. If the TTY is not
        /// interactive, Kagami will stop execution with non-zero exit code. In order to re-create
        /// the directory anyway, pass `--dir-force` flag.
        #[arg(long, short)]
        dir: PathBuf,
        /// Re-create the target directory if it already exists.
        #[arg(long)]
        dir_force: bool,
        /// Do not create default configuration in the `<dir>/config` directory.
        ///
        /// Default `config.json`, `genesis.json` and `validator.wasm` are generated and put into
        /// the `<dir>/config` directory. That directory is specified in the Docker Compose
        /// `volumes` field.
        ///
        /// If you don't need the defaults, you could set this flag. The `config` directory will be
        /// created anyway, but you should put the necessary configuration there by yourself.
        #[arg(long)]
        no_default_configuration: bool,
        /// Might be useful for deterministic key generation.
        ///
        /// It could be any string. Its UTF-8 bytes will be used as a seed.
        #[arg(long)]
        seed: Option<String>,
    }

    impl<T: Write> RunArgs<T> for Args {
        fn run(self, _writer: &mut BufWriter<T>) -> Outcome {
            let reporter = ui::Reporter::new();

            let prepare_dir_strategy = if self.dir_force {
                PrepareDirectoryStrategy::ForceRecreate
            } else {
                PrepareDirectoryStrategy::Prompt
            };
            let source = ImageSource::from(self.source);
            let target_dir = TargetDirectory::new(AbsolutePath::absolutize(self.dir)?);

            if let EarlyEnding::Halt = target_dir
                .prepare(&prepare_dir_strategy, &reporter)
                .wrap_err("failed to prepare directory")?
            {
                return Ok(());
            }

            let config_dir = AbsolutePath::absolutize(target_dir.path.join(DIR_CONFIG))?;

            let (source, reporter) = source
                .resolve(&target_dir, reporter)
                .wrap_err("failed to resolve the source of image")?;

            let reporter = if self.no_default_configuration {
                PrepareConfigurationStrategy::GenerateOnlyDirectory
            } else {
                PrepareConfigurationStrategy::GenerateDefault
            }
            .run(&config_dir, reporter)
            .wrap_err("failed to prepare configuration")?;

            DockerComposeBuilder {
                target_dir: target_dir.path.clone(),
                config_dir,
                source,
                peers: self.peers,
                seed: self.seed.map(String::into_bytes),
            }
            .build()
            .wrap_err("failed to build docker compose")?
            .write_file(&target_dir.path.join(FILE_COMPOSE))
            .wrap_err("failed to write compose file")?;

            reporter.log_complete(&target_dir.path);

            Ok(())
        }
    }

    #[derive(Clone, ValueEnum, Debug)]
    enum Channel {
        Dev,
        Stable,
        Lts,
    }

    impl Channel {
        const fn as_dockerhub_image(&self) -> &'static str {
            match self {
                Self::Dev => "hyperledger/iroha2:dev",
                Self::Stable => "hyperledger/iroha2:stable",
                Self::Lts => "hyperledger/iroha2:lts",
            }
        }
    }

    #[derive(ClapArgs, Clone, Debug)]
    #[group(required = true, multiple = false)]
    struct ImageSourceArgs {
        /// Use images published on Dockerhub.
        #[arg(long, value_name = "CHANNEL")]
        dockerhub: Option<Channel>,
        /// Clone `hyperledger/iroha` repo from the revision Kagami is built itself,
        /// and use the cloned source code to build images from.
        #[arg(long)]
        github: bool,
        /// Use local path location of the Iroha source code to build images from.
        ///
        /// If the path is relative, it will be resolved relative to the CWD.
        #[arg(long, value_name = "PATH")]
        path: Option<PathBuf>,
    }

    /// Parsed version of [`ImageSourceArgs`]
    #[derive(Clone, Debug)]
    enum ImageSource {
        Dockerhub(Channel),
        Github {
            revision: String,
        },
        /// Raw path passed from user
        Path(PathBuf),
    }

    impl From<ImageSourceArgs> for ImageSource {
        fn from(args: ImageSourceArgs) -> Self {
            match args {
                ImageSourceArgs {
                    dockerhub: Some(channel),
                    ..
                } => Self::Dockerhub(channel),
                ImageSourceArgs { github: true, .. } => Self::Github {
                    revision: GIT_REVISION.to_owned(),
                },
                ImageSourceArgs {
                    path: Some(path), ..
                } => Self::Path(path),
                _ => unreachable!("Clap must ensure the invariant"),
            }
        }
    }

    impl ImageSource {
        /// Has a side effect: if self is [`Self::Github`], it clones the repo into
        /// the target directory.
        fn resolve(
            self,
            target: &TargetDirectory,
            reporter: Reporter,
        ) -> Result<(ResolvedImageSource, Reporter)> {
            let (source, reporter) = match self {
                Self::Path(path) => (
                    ResolvedImageSource::Build {
                        path: AbsolutePath::absolutize(path)
                            .wrap_err("failed to resolve build path")?,
                    },
                    reporter,
                ),
                Self::Github { revision } => {
                    let clone_dir = target.path.join(DIR_CLONE);
                    let clone_dir = AbsolutePath::absolutize(clone_dir)?;

                    reporter.log_cloning_repo();

                    shallow_git_clone(GIT_ORIGIN, revision, &clone_dir)
                        .wrap_err("failed to clone the repo")?;

                    (ResolvedImageSource::Build { path: clone_dir }, reporter)
                }
                Self::Dockerhub(channel) => (
                    ResolvedImageSource::Image {
                        name: channel.as_dockerhub_image().to_owned(),
                    },
                    reporter,
                ),
            };

            Ok((source, reporter))
        }
    }

    fn shallow_git_clone(
        remote: impl AsRef<str>,
        revision: impl AsRef<str>,
        dir: &AbsolutePath,
    ) -> Result<()> {
        use duct::{cmd, Expression};

        trait CurrentDirExt {
            fn current_dir(&mut self, dir: PathBuf) -> Self;
        }

        impl CurrentDirExt for Expression {
            fn current_dir(&mut self, dir: PathBuf) -> Self {
                self.before_spawn(move |cmd| {
                    // idk how to avoid cloning here, cuz the closure is `Fn`, not `FnOnce`
                    cmd.current_dir(dir.clone());
                    Ok(())
                })
            }
        }

        std::fs::create_dir(dir)?;

        let dir = dir.to_path_buf();

        cmd!("git", "init").current_dir(dir.clone()).run()?;
        cmd!("git", "remote", "add", "origin", remote.as_ref())
            .current_dir(dir.clone())
            .run()?;
        cmd!("git", "fetch", "--depth=1", "origin", revision.as_ref())
            .current_dir(dir.clone())
            .run()?;
        cmd!(
            "git",
            "-c",
            "advice.detachedHead=false",
            "checkout",
            "FETCH_HEAD"
        )
        .current_dir(dir.clone())
        .run()?;

        Ok(())
    }

    #[derive(Debug)]
    enum ResolvedImageSource {
        Image { name: String },
        Build { path: AbsolutePath },
    }

    enum PrepareConfigurationStrategy {
        GenerateDefault,
        GenerateOnlyDirectory,
    }

    impl PrepareConfigurationStrategy {
        fn run(&self, config_dir: &AbsolutePath, reporter: Reporter) -> Result<Reporter> {
            std::fs::create_dir(config_dir).wrap_err("failed to create the config directory")?;

            let reporter = match self {
                Self::GenerateOnlyDirectory => {
                    reporter.warn_no_default_config(&config_dir);
                    reporter
                }
                Self::GenerateDefault => {
                    let path_validator = PathBuf::from_str(FILE_VALIDATOR).unwrap();

                    let raw_genesis_block = {
                        let block = super::genesis::generate_default(Some(path_validator.clone()))
                            .wrap_err("failed to generate genesis")?;
                        serde_json::to_string_pretty(&block)?
                    };

                    let default_config = {
                        let proxy = iroha_config::iroha::ConfigurationProxy::default();
                        serde_json::to_string_pretty(&proxy)?
                    };

                    let spinner = reporter.spinner_validator();

                    let validator = super::validator::construct_validator()
                        .wrap_err("failed to construct the validator")?;

                    let reporter = spinner.done()?;

                    File::create(config_dir.join(FILE_GENESIS))?
                        .write_all(raw_genesis_block.as_bytes())?;
                    File::create(config_dir.join(FILE_CONFIG))?
                        .write_all(default_config.as_bytes())?;
                    File::create(config_dir.join(path_validator))?
                        .write_all(validator.as_slice())?;

                    reporter.log_default_configuration_is_written(&config_dir);
                    reporter
                }
            };

            Ok(reporter)
        }
    }

    enum PrepareDirectoryStrategy {
        ForceRecreate,
        Prompt,
    }

    enum EarlyEnding {
        Halt,
        Continue,
    }

    #[derive(Clone, Debug)]
    struct TargetDirectory {
        path: AbsolutePath,
    }

    impl TargetDirectory {
        fn new(path: AbsolutePath) -> Self {
            Self { path }
        }

        fn prepare(
            &self,
            strategy: &PrepareDirectoryStrategy,
            reporter: &Reporter,
        ) -> Result<EarlyEnding> {
            // FIXME: use [`std::fs::try_exists`] when it is stable
            if self.path.exists() {
                match strategy {
                    PrepareDirectoryStrategy::ForceRecreate => {
                        self.remove_dir()?;
                        reporter.log_removed_directory(&self.path);
                    }
                    PrepareDirectoryStrategy::Prompt => {
                        if let EarlyEnding::Halt = self.remove_directory_with_prompt(&reporter)? {
                            return Ok(EarlyEnding::Halt);
                        }
                    }
                }
            }

            self.make_dir_recursive()
                .wrap_err("failed to create the directory")?;

            reporter.log_directory_created(&self.path);

            Ok(EarlyEnding::Continue)
        }

        /// `rm -r <dir>`
        fn remove_dir(&self) -> Result<()> {
            std::fs::remove_dir_all(&self.path)
                .wrap_err_with(|| eyre!("failed to remove the directory: {}", self.path.display()))
        }

        /// If user says "no", program should just exit, so it returns [`EarlyEnding::Halt`].
        ///
        /// # Errors
        ///
        /// - If TTY is not interactive
        fn remove_directory_with_prompt(&self, reporter: &Reporter) -> Result<EarlyEnding> {
            if let ui::PromptAnswer::Yes = reporter
                .prompt_remove_target_dir(&self.path)
                .wrap_err_with(|| {
                    eyre!(
                        "Failed to prompt removal for the directory: {}",
                        self.path.display()
                    )
                })?
            {
                self.remove_dir()?;
                reporter.log_removed_directory(&self.path);
                Ok(EarlyEnding::Continue)
            } else {
                Ok(EarlyEnding::Halt)
            }
        }

        /// `mkdir -r <dir>`
        fn make_dir_recursive(&self) -> Result<()> {
            std::fs::create_dir_all(&self.path).wrap_err_with(|| {
                eyre!(
                    "failed to recursively create the directory: {}",
                    self.path.display()
                )
            })
        }
    }

    #[derive(Debug)]
    struct DockerComposeBuilder {
        target_dir: AbsolutePath,
        config_dir: AbsolutePath,
        source: ResolvedImageSource,
        peers: NonZeroUsize,
        seed: Option<Vec<u8>>,
    }

    impl DockerComposeBuilder {
        fn build(&self) -> Result<DockerCompose> {
            let base_seed = self.seed.as_deref();

            let peers = peer_generator::generate_peers(self.peers, base_seed)
                .wrap_err("failed to generate peers")?;
            let genesis_key_pair = key_gen::generate(base_seed, b"genesis")
                .wrap_err("failed to generate genesis key pair")?;
            let service_source = match &self.source {
                ResolvedImageSource::Build { path } => {
                    ServiceSource::Build(path.relative_to(&self.target_dir)?)
                }
                ResolvedImageSource::Image { name } => ServiceSource::Image(name.clone()),
            };
            let volumes = vec![(
                self.config_dir
                    .relative_to(&self.target_dir)?
                    .to_str()
                    .wrap_err("config directory path is not a valid string")?
                    .to_owned(),
                DIR_CONFIG.to_owned(),
            )];

            let services = peers
                .iter()
                .enumerate()
                .map(|(i, (name, peer))| {
                    let trusted_peers = peers
                        .iter()
                        .filter(|(other_name, _)| *other_name != name)
                        .map(|(_, peer)| peer.id())
                        .collect();

                    let command = if i == 0 {
                        ServiceCommand::SubmitGenesis
                    } else {
                        ServiceCommand::None
                    };

                    let service = DockerComposeService::new(
                        peer,
                        service_source.clone(),
                        volumes.clone(),
                        command,
                        trusted_peers,
                        &genesis_key_pair,
                    );

                    (name.clone(), service)
                })
                .collect();

            let compose = DockerCompose::new(services);
            Ok(compose)
        }
    }

    #[derive(Clone, Debug)]
    struct AbsolutePath {
        path: PathBuf,
    }

    impl Deref for AbsolutePath {
        type Target = PathBuf;

        fn deref(&self) -> &Self::Target {
            &self.path
        }
    }

    impl AsRef<Path> for AbsolutePath {
        fn as_ref(&self) -> &Path {
            self.path.as_path()
        }
    }

    impl AbsolutePath {
        fn absolutize(path: PathBuf) -> Result<Self> {
            Ok(Self {
                path: if path.is_absolute() {
                    path
                } else {
                    path.absolutize()?.to_path_buf()
                },
            })
        }

        /// Relative path from self to other.
        fn relative_to(&self, other: &AbsolutePath) -> Result<PathBuf> {
            pathdiff::diff_paths(self, other)
                .ok_or_else(|| {
                    eyre!(
                        "failed to build relative path from {} to {}",
                        other.display(),
                        self.display(),
                    )
                })
                // docker-compose might not like "test" path, but "./test" instead 
                .map(|rel| {
                    if rel.starts_with("..") {
                        rel
                    } else {
                        Path::new("./").join(rel)

                    }
                })
        }
    }

    mod key_gen {
        use iroha_crypto::{error::Error, KeyGenConfiguration, KeyPair};

        /// If there is no base seed, the additional one will be ignored
        pub fn generate(
            base_seed: Option<&[u8]>,
            additional_seed: &[u8],
        ) -> Result<KeyPair, Error> {
            let cfg = base_seed
                .map(|base| {
                    let seed: Vec<_> = base.iter().chain(additional_seed).copied().collect();
                    KeyGenConfiguration::default().use_seed(seed)
                })
                .unwrap_or_default();

            KeyPair::generate_with_configuration(cfg)
        }
    }

    mod peer_generator {
        use std::{collections::HashMap, num::NonZeroUsize};

        use color_eyre::{eyre::Context, Report};
        use iroha_crypto::KeyPair;
        use iroha_data_model::prelude::PeerId;

        const BASE_PORT_P2P: u16 = 1337;
        const BASE_PORT_API: u16 = 8080;
        const BASE_PORT_TELEMETRY: u16 = 8180;
        const BASE_SERVICE_NAME: &'_ str = "iroha";

        pub struct Peer {
            pub name: String,
            pub port_p2p: u16,
            pub port_api: u16,
            pub port_telemetry: u16,
            pub key_pair: KeyPair,
        }

        impl Peer {
            pub fn id(&self) -> PeerId {
                PeerId::new(&self.url(self.port_p2p), self.key_pair.public_key())
            }

            pub fn url(&self, port: u16) -> String {
                format!("{}:{}", self.name, port)
            }
        }

        pub fn generate_peers(
            peers: NonZeroUsize,
            base_seed: Option<&[u8]>,
        ) -> Result<HashMap<String, Peer>, Report> {
            (0u16..u16::try_from(peers.get())
                .expect("Peers count is likely to be in bounds of u16"))
                .map(|i| {
                    let service_name = format!("{BASE_SERVICE_NAME}{i}");

                    let key_pair = super::key_gen::generate(base_seed, service_name.as_bytes())
                        .wrap_err("failed to generate key pair")?;

                    let peer = Peer {
                        name: service_name.clone(),
                        port_p2p: BASE_PORT_P2P + i,
                        port_api: BASE_PORT_API + i,
                        port_telemetry: BASE_PORT_TELEMETRY + i,
                        key_pair,
                    };

                    Ok((service_name, peer))
                })
                .collect()
        }
    }

    mod serialize_docker_compose {
        use std::{
            collections::{BTreeMap, BTreeSet},
            fmt::Display,
            fs::File,
            io::Write,
            path::PathBuf,
        };

        use color_eyre::eyre::{eyre, Context};
        use iroha_crypto::{KeyPair, PrivateKey, PublicKey};
        use iroha_data_model::prelude::PeerId;
        use serde::{ser::Error as _, Serialize, Serializer};

        use crate::swarm::peer_generator::Peer;

        const COMMAND_SUBMIT_GENESIS: &str = "iroha --submit-genesis";

        #[derive(Serialize, Debug)]
        pub struct DockerCompose {
            version: DockerComposeVersion,
            services: BTreeMap<String, DockerComposeService>,
        }

        impl DockerCompose {
            pub fn new(services: BTreeMap<String, DockerComposeService>) -> Self {
                Self {
                    version: DockerComposeVersion,
                    services,
                }
            }

            pub fn write_file(&self, path: &PathBuf) -> Result<(), color_eyre::Report> {
                let yaml = serde_yaml::to_string(self).wrap_err("failed to serialise YAML")?;
                File::create(path)
                    .wrap_err(eyre!("failed to create file: {:?}", path))?
                    .write_all(yaml.as_bytes())
                    .wrap_err("failed to write YAML content")?;
                Ok(())
            }
        }

        #[derive(Debug)]
        struct DockerComposeVersion;

        impl Serialize for DockerComposeVersion {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str("3.8")
            }
        }

        #[derive(Serialize, Debug)]
        pub struct DockerComposeService {
            #[serde(flatten)]
            source: ServiceSource,
            environment: FullPeerEnv,
            ports: Vec<PairColon<u16, u16>>,
            volumes: Vec<PairColon<String, String>>,
            init: AlwaysTrue,
            #[serde(skip_serializing_if = "ServiceCommand::is_none")]
            command: ServiceCommand,
        }

        impl DockerComposeService {
            pub fn new(
                peer: &Peer,
                source: ServiceSource,
                volumes: Vec<(String, String)>,
                command: ServiceCommand,
                trusted_peers: BTreeSet<PeerId>,
                genesis_key_pair: &KeyPair,
            ) -> Self {
                let ports = vec![
                    PairColon(peer.port_p2p, peer.port_p2p),
                    PairColon(peer.port_api, peer.port_api),
                    PairColon(peer.port_telemetry, peer.port_telemetry),
                ];

                let compact_env = CompactPeerEnv {
                    trusted_peers,
                    key_pair: peer.key_pair.clone(),
                    genesis_key_pair: genesis_key_pair.clone(),
                    p2p_addr: peer.url(peer.port_p2p),
                    api_url: peer.url(peer.port_api),
                    telemetry_url: peer.url(peer.port_telemetry),
                };

                Self {
                    source,
                    command,
                    init: AlwaysTrue,
                    volumes: volumes.into_iter().map(|(a, b)| PairColon(a, b)).collect(),
                    ports,
                    environment: compact_env.into(),
                }
            }
        }

        #[derive(Debug)]
        struct AlwaysTrue;

        impl Serialize for AlwaysTrue {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_bool(true)
            }
        }

        #[derive(Debug)]
        pub enum ServiceCommand {
            SubmitGenesis,
            None,
        }

        impl ServiceCommand {
            fn is_none(&self) -> bool {
                matches!(self, Self::None)
            }
        }

        impl Serialize for ServiceCommand {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                match self {
                    Self::None => serializer.serialize_none(),
                    Self::SubmitGenesis => serializer.serialize_str(COMMAND_SUBMIT_GENESIS),
                }
            }
        }

        /// Serializes as `"{0}:{1}"`
        #[derive(derive_more::Display, Debug)]
        #[display(fmt = "{_0}:{_1}")]
        struct PairColon<T, U>(T, U)
        where
            T: Display,
            U: Display;

        impl<T, U> Serialize for PairColon<T, U>
        where
            T: Display,
            U: Display,
        {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.collect_str(self)
            }
        }

        #[derive(Serialize, Clone, Debug)]
        #[serde(rename_all = "lowercase")]
        pub enum ServiceSource {
            Image(String),
            Build(PathBuf),
        }

        #[derive(Serialize, Debug)]
        #[serde(rename_all = "UPPERCASE")]
        struct FullPeerEnv {
            iroha_public_key: PublicKey,
            iroha_private_key: SerializeAsJsonStr<PrivateKey>,
            torii_p2p_addr: String,
            torii_api_url: String,
            torii_telemetry_url: String,
            iroha_genesis_account_public_key: PublicKey,
            iroha_genesis_account_private_key: SerializeAsJsonStr<PrivateKey>,
            sumeragi_trusted_peers: SerializeAsJsonStr<BTreeSet<PeerId>>,
        }

        struct CompactPeerEnv {
            key_pair: KeyPair,
            genesis_key_pair: KeyPair,
            p2p_addr: String,
            api_url: String,
            telemetry_url: String,
            trusted_peers: BTreeSet<PeerId>,
        }

        impl From<CompactPeerEnv> for FullPeerEnv {
            fn from(value: CompactPeerEnv) -> Self {
                Self {
                    iroha_public_key: value.key_pair.public_key().clone(),
                    iroha_private_key: SerializeAsJsonStr(value.key_pair.private_key().clone()),
                    iroha_genesis_account_public_key: value.genesis_key_pair.public_key().clone(),
                    iroha_genesis_account_private_key: SerializeAsJsonStr(
                        value.genesis_key_pair.private_key().clone(),
                    ),
                    torii_p2p_addr: value.p2p_addr,
                    torii_api_url: value.api_url,
                    torii_telemetry_url: value.telemetry_url,
                    sumeragi_trusted_peers: SerializeAsJsonStr(value.trusted_peers),
                }
            }
        }

        #[derive(Debug)]
        struct SerializeAsJsonStr<T>(T);

        impl<T> serde::Serialize for SerializeAsJsonStr<T>
        where
            T: serde::Serialize,
        {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                let json = serde_json::to_string(&self.0).map_err(|json_err| {
                    S::Error::custom(format!("failed to serialize as JSON: {json_err}"))
                })?;
                serializer.serialize_str(&json)
            }
        }

        #[cfg(test)]
        mod test {
            use std::{
                collections::{BTreeMap, BTreeSet, HashMap},
                env::VarError,
                ffi::OsStr,
                path::PathBuf,
                str::FromStr,
            };

            use color_eyre::eyre::Context;
            use iroha_config::{
                base::proxy::{FetchEnv, LoadFromEnv, Override},
                iroha::ConfigurationProxy,
            };
            use iroha_crypto::{KeyGenConfiguration, KeyPair};

            use super::{
                CompactPeerEnv, DockerCompose, DockerComposeService, DockerComposeVersion,
                FullPeerEnv, PairColon, SerializeAsJsonStr, ServiceSource,
            };
            use crate::swarm::serialize_docker_compose::{AlwaysTrue, ServiceCommand};

            struct TestEnv {
                env: HashMap<String, String>,
            }

            impl From<FullPeerEnv> for TestEnv {
                fn from(peer_env: FullPeerEnv) -> Self {
                    let json = serde_json::to_string(&peer_env).expect("Must be serializable");
                    let env = serde_json::from_str(&json)
                        .expect("Must be deserializable into a hash map");
                    Self { env }
                }
            }

            impl FetchEnv for TestEnv {
                fn fetch<K: AsRef<OsStr>>(&self, key: K) -> Result<String, VarError> {
                    let res = self
                        .env
                        .get(
                            key.as_ref()
                                .to_str()
                                .ok_or_else(|| VarError::NotUnicode(key.as_ref().into()))?,
                        )
                        .ok_or(VarError::NotPresent)
                        .map(std::clone::Clone::clone);

                    res
                }
            }

            // TODO: while this test ensures that the necessary fields are procided in ENV,
            //       it doesn't check if other fields are provided correctly. E.g. if there is a
            //       var that has a wrong name, it might be ignored at all
            //       because ConfigurationProxy doesn't touch it
            #[test]
            fn default_config_with_swarm_env_are_exhaustive() {
                let keypair = KeyPair::generate().unwrap();
                // TODO use compact
                let env: TestEnv = FullPeerEnv {
                    iroha_public_key: keypair.public_key().clone(),
                    iroha_private_key: SerializeAsJsonStr(keypair.private_key().clone()),
                    iroha_genesis_account_public_key: keypair.public_key().clone(),
                    iroha_genesis_account_private_key: SerializeAsJsonStr(
                        keypair.private_key().clone(),
                    ),
                    torii_p2p_addr: "127.0.0.1:1337".to_owned(),
                    torii_api_url: "127.0.0.1:1337".to_owned(),
                    torii_telemetry_url: "127.0.0.1:1337".to_owned(),
                    sumeragi_trusted_peers: SerializeAsJsonStr(BTreeSet::new()),
                }
                .into();

                let proxy = ConfigurationProxy::default()
                    .override_with(ConfigurationProxy::from_env(&env).expect("valid env"));

                let _cfg = proxy
                    .build()
                    .wrap_err("failed to build configuration")
                    .expect("default configuration with swarm's env should be exhaustive");
            }

            #[test]
            fn serialize_image_source() {
                let source = ServiceSource::Image("hyperledger/iroha2:stable".to_owned());
                let serialised = serde_json::to_string(&source).unwrap();
                assert_eq!(serialised, r#"{"image":"hyperledger/iroha2:stable"}"#);
            }

            #[test]
            fn serialize_docker_compose() {
                let compose = DockerCompose {
                    version: DockerComposeVersion,
                    services: {
                        let mut map = BTreeMap::new();

                        let key_pair = KeyPair::generate_with_configuration(
                            KeyGenConfiguration::default()
                                .use_seed(vec![1, 5, 1, 2, 2, 3, 4, 1, 2, 3]),
                        )
                        .unwrap();

                        map.insert(
                            "iroha0".to_owned(),
                            DockerComposeService {
                                source: ServiceSource::Build(PathBuf::from_str(".").unwrap()),
                                environment: CompactPeerEnv {
                                    key_pair: key_pair.clone(),
                                    genesis_key_pair: key_pair,
                                    p2p_addr: "iroha0:1337".to_owned(),
                                    api_url: "iroha0:1337".to_owned(),
                                    telemetry_url: "iroha0:1337".to_owned(),
                                    trusted_peers: BTreeSet::new(),
                                }
                                .into(),
                                ports: vec![
                                    PairColon(1337, 1337),
                                    PairColon(8080, 8080),
                                    PairColon(8081, 8081),
                                ],
                                volumes: vec![PairColon(
                                    "./configs/peer/legacy_stable".to_owned(),
                                    "/config".to_owned(),
                                )],
                                init: AlwaysTrue,
                                command: ServiceCommand::SubmitGenesis,
                            },
                        );

                        map
                    },
                };

                let actual = serde_yaml::to_string(&compose).expect("Should be serialisable");
                let expected = expect_test::expect![[r#"
                    version: '3.8'
                    services:
                      iroha0:
                        build: .
                        environment:
                          IROHA_PUBLIC_KEY: ed012039E5BF092186FACC358770792A493CA98A83740643A3D41389483CF334F748C8
                          IROHA_PRIVATE_KEY: '{"digest_function":"ed25519","payload":"db9d90d20f969177bd5882f9fe211d14d1399d5440d04e3468783d169bbc4a8e39e5bf092186facc358770792a493ca98a83740643a3d41389483cf334f748c8"}'
                          TORII_P2P_ADDR: iroha0:1337
                          TORII_API_URL: iroha0:1337
                          TORII_TELEMETRY_URL: iroha0:1337
                          IROHA_GENESIS_ACCOUNT_PUBLIC_KEY: ed012039E5BF092186FACC358770792A493CA98A83740643A3D41389483CF334F748C8
                          IROHA_GENESIS_ACCOUNT_PRIVATE_KEY: '{"digest_function":"ed25519","payload":"db9d90d20f969177bd5882f9fe211d14d1399d5440d04e3468783d169bbc4a8e39e5bf092186facc358770792a493ca98a83740643a3d41389483cf334f748c8"}'
                          SUMERAGI_TRUSTED_PEERS: '[]'
                        ports:
                        - 1337:1337
                        - 8080:8080
                        - 8081:8081
                        volumes:
                        - ./configs/peer/legacy_stable:/config
                        init: true
                        command: iroha --submit-genesis
                "#]];
                expected.assert_eq(&actual);
            }
        }
    }

    mod ui {
        use color_eyre::{eyre::WrapErr, Help};
        use iroha_crypto::ursa::sha2::digest::generic_array::typenum::Abs;
        use owo_colors::OwoColorize;

        use super::{AbsolutePath, ResolvedImageSource, Result};
        use crate::swarm::{DIR_FORCE_SUGGESTION, FILE_COMPOSE};

        const INFO: &str = "ℹ";
        const SUCCESS: &str = "✓";
        const WARNING: &str = "‼";

        pub struct Reporter;

        pub(super) enum PromptAnswer {
            Yes,
            No,
        }

        impl Reporter {
            pub(super) fn new() -> Self {
                Self
            }

            pub(super) fn log_removed_directory(&self, dir: &AbsolutePath) {
                println!("{INFO} Removed directory: {}", dir.display().dimmed());
            }

            pub(super) fn log_directory_created(&self, dir: &AbsolutePath) {
                println!("{INFO} Created directory: {}", dir.display().green().bold());
            }

            pub(super) fn log_default_configuration_is_written(&self, dir: &AbsolutePath) {
                println!(
                    "{INFO} Generated default configuration in {}",
                    dir.display().green().bold()
                );
            }

            pub(super) fn warn_no_default_config(&self, dir: &AbsolutePath) {
                println!(
                    "{}",
                    format!(
                    "{WARNING} Config directory is created, but the configuration itself is not.\
                        \n  Without any configuration, generated peers will be unable to start.\
                        \n  Don't forget to put the configuration into:\n\n    {}\n",
                    dir.display().bold()
                )
                    .yellow()
                );
            }

            pub(super) fn prompt_remove_target_dir(
                &self,
                dir: &AbsolutePath,
            ) -> Result<PromptAnswer> {
                inquire::Confirm::new(&format!(
                    "Directory {} already exists. Remove it?",
                    dir.display().blue().bold()
                ))
                .with_default(false)
                .prompt()
                .suggestion(DIR_FORCE_SUGGESTION)
                .map(|flag| {
                    if flag {
                        PromptAnswer::Yes
                    } else {
                        PromptAnswer::No
                    }
                })
            }

            pub(super) fn log_cloning_repo(&self) {
                println!("{INFO} Cloning git repo...");
            }

            pub(super) fn spinner_validator(self) -> SpinnerValidator {
                SpinnerValidator::new(self)
            }

            pub(super) fn log_complete(&self, dir: &AbsolutePath) {
                println!(
                    "{SUCCESS} Docker compose configuration is ready at:\n\n    {}\
                        \n\n  You could `{}` in it.",
                    dir.display().green().bold(),
                    "docker compose up".blue()
                );
            }
        }

        struct Spinner {
            inner: spinoff::Spinner,
            reporter: Reporter,
        }

        impl Spinner {
            fn new(message: impl AsRef<str>, reporter: Reporter) -> Self {
                let inner = spinoff::Spinner::new(
                    spinoff::spinners::Dots,
                    message.as_ref().to_owned(),
                    spinoff::Color::White,
                );

                Self { inner, reporter }
            }

            fn done(self, message: impl AsRef<str>) -> Result<Reporter> {
                self.inner.stop_and_persist(SUCCESS, message.as_ref());
                Ok(self.reporter)
            }
        }

        pub(super) struct SpinnerValidator(Spinner);

        impl SpinnerValidator {
            fn new(reporter: Reporter) -> Self {
                Self(Spinner::new(
                    "Constructing the default validator...",
                    reporter,
                ))
            }

            pub(super) fn done(self) -> Result<Reporter> {
                self.0.done("Constructed the validator")
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use std::{
            num::NonZeroUsize,
            path::{Path, PathBuf},
            str::FromStr,
        };

        use super::{AbsolutePath, Absolutize, DockerComposeBuilder, ResolvedImageSource};

        impl AbsolutePath {
            fn from_virtual(path: &PathBuf, virtual_root: impl AsRef<Path> + Sized) -> Self {
                let path = path
                    .absolutize_virtually(virtual_root)
                    .unwrap()
                    .to_path_buf();
                Self { path }
            }
        }

        #[test]
        fn relative_inner_path_starts_with_dot() {
            let root = PathBuf::from_str("/").unwrap();
            let a = AbsolutePath::from_virtual(&PathBuf::from("./a/b/c"), &root);
            let b = AbsolutePath::from_virtual(&PathBuf::from("./"), &root);

            assert_eq!(
                a.relative_to(&b).unwrap(),
                PathBuf::from_str("./a/b/c").unwrap()
            );
        }

        #[test]
        fn relative_outer_path_starts_with_dots() {
            let root = Path::new("/");
            let a = AbsolutePath::from_virtual(&PathBuf::from("./a/b/c"), root);
            let b = AbsolutePath::from_virtual(&PathBuf::from("./cde"), root);

            assert_eq!(
                b.relative_to(&a).unwrap(),
                PathBuf::from_str("../../../cde").unwrap()
            );
        }

        #[test]
        fn generate_peers_deterministically() {
            let root = Path::new("/");
            let seed: Vec<_> = b"iroha".to_vec();

            let composed = DockerComposeBuilder {
                target_dir: AbsolutePath::from_virtual(&PathBuf::from("/test"), root),
                config_dir: AbsolutePath::from_virtual(&PathBuf::from("/test/config"), root),
                peers: NonZeroUsize::new(4).unwrap(),
                source: ResolvedImageSource::Build {
                    path: AbsolutePath::from_virtual(&PathBuf::from("/test/iroha-cloned"), root),
                },
                seed: Some(seed),
            }
            .build()
            .expect("should build with no errors");

            let yaml = serde_yaml::to_string(&composed).unwrap();
            let expected = expect_test::expect![[r#"
                version: '3.8'
                services:
                  iroha0:
                    build: ./iroha-cloned
                    environment:
                      IROHA_PUBLIC_KEY: ed0120F0321EB4139163C35F88BF78520FF7071499D7F4E79854550028A196C7B49E13
                      IROHA_PRIVATE_KEY: '{"digest_function":"ed25519","payload":"5f8d1291bf6b762ee748a87182345d135fd167062857aa4f20ba39f25e74c4b0f0321eb4139163c35f88bf78520ff7071499d7f4e79854550028a196c7b49e13"}'
                      TORII_P2P_ADDR: iroha0:1337
                      TORII_API_URL: iroha0:8080
                      TORII_TELEMETRY_URL: iroha0:8180
                      IROHA_GENESIS_ACCOUNT_PUBLIC_KEY: ed01203420F48A9EEB12513B8EB7DAF71979CE80A1013F5F341C10DCDA4F6AA19F97A9
                      IROHA_GENESIS_ACCOUNT_PRIVATE_KEY: '{"digest_function":"ed25519","payload":"5a6d5f06a90d29ad906e2f6ea8b41b4ef187849d0d397081a4a15ffcbe71e7c73420f48a9eeb12513b8eb7daf71979ce80a1013f5f341c10dcda4f6aa19f97a9"}'
                      SUMERAGI_TRUSTED_PEERS: '[{"address":"iroha2:1339","public_key":"ed0120312C1B7B5DE23D366ADCF23CD6DB92CE18B2AA283C7D9F5033B969C2DC2B92F4"},{"address":"iroha3:1340","public_key":"ed0120854457B2E3D6082181DA73DC01C1E6F93A72D0C45268DC8845755287E98A5DEE"},{"address":"iroha1:1338","public_key":"ed0120A88554AA5C86D28D0EEBEC497235664433E807881CD31E12A1AF6C4D8B0F026C"}]'
                    ports:
                    - 1337:1337
                    - 8080:8080
                    - 8180:8180
                    volumes:
                    - ./config:/config
                    init: true
                    command: iroha --submit-genesis
                  iroha1:
                    build: ./iroha-cloned
                    environment:
                      IROHA_PUBLIC_KEY: ed0120A88554AA5C86D28D0EEBEC497235664433E807881CD31E12A1AF6C4D8B0F026C
                      IROHA_PRIVATE_KEY: '{"digest_function":"ed25519","payload":"8d34d2c6a699c61e7a9d5aabbbd07629029dfb4f9a0800d65aa6570113edb465a88554aa5c86d28d0eebec497235664433e807881cd31e12a1af6c4d8b0f026c"}'
                      TORII_P2P_ADDR: iroha1:1338
                      TORII_API_URL: iroha1:8081
                      TORII_TELEMETRY_URL: iroha1:8181
                      IROHA_GENESIS_ACCOUNT_PUBLIC_KEY: ed01203420F48A9EEB12513B8EB7DAF71979CE80A1013F5F341C10DCDA4F6AA19F97A9
                      IROHA_GENESIS_ACCOUNT_PRIVATE_KEY: '{"digest_function":"ed25519","payload":"5a6d5f06a90d29ad906e2f6ea8b41b4ef187849d0d397081a4a15ffcbe71e7c73420f48a9eeb12513b8eb7daf71979ce80a1013f5f341c10dcda4f6aa19f97a9"}'
                      SUMERAGI_TRUSTED_PEERS: '[{"address":"iroha2:1339","public_key":"ed0120312C1B7B5DE23D366ADCF23CD6DB92CE18B2AA283C7D9F5033B969C2DC2B92F4"},{"address":"iroha3:1340","public_key":"ed0120854457B2E3D6082181DA73DC01C1E6F93A72D0C45268DC8845755287E98A5DEE"},{"address":"iroha0:1337","public_key":"ed0120F0321EB4139163C35F88BF78520FF7071499D7F4E79854550028A196C7B49E13"}]'
                    ports:
                    - 1338:1338
                    - 8081:8081
                    - 8181:8181
                    volumes:
                    - ./config:/config
                    init: true
                  iroha2:
                    build: ./iroha-cloned
                    environment:
                      IROHA_PUBLIC_KEY: ed0120312C1B7B5DE23D366ADCF23CD6DB92CE18B2AA283C7D9F5033B969C2DC2B92F4
                      IROHA_PRIVATE_KEY: '{"digest_function":"ed25519","payload":"cf4515a82289f312868027568c0da0ee3f0fde7fef1b69deb47b19fde7cbc169312c1b7b5de23d366adcf23cd6db92ce18b2aa283c7d9f5033b969c2dc2b92f4"}'
                      TORII_P2P_ADDR: iroha2:1339
                      TORII_API_URL: iroha2:8082
                      TORII_TELEMETRY_URL: iroha2:8182
                      IROHA_GENESIS_ACCOUNT_PUBLIC_KEY: ed01203420F48A9EEB12513B8EB7DAF71979CE80A1013F5F341C10DCDA4F6AA19F97A9
                      IROHA_GENESIS_ACCOUNT_PRIVATE_KEY: '{"digest_function":"ed25519","payload":"5a6d5f06a90d29ad906e2f6ea8b41b4ef187849d0d397081a4a15ffcbe71e7c73420f48a9eeb12513b8eb7daf71979ce80a1013f5f341c10dcda4f6aa19f97a9"}'
                      SUMERAGI_TRUSTED_PEERS: '[{"address":"iroha3:1340","public_key":"ed0120854457B2E3D6082181DA73DC01C1E6F93A72D0C45268DC8845755287E98A5DEE"},{"address":"iroha1:1338","public_key":"ed0120A88554AA5C86D28D0EEBEC497235664433E807881CD31E12A1AF6C4D8B0F026C"},{"address":"iroha0:1337","public_key":"ed0120F0321EB4139163C35F88BF78520FF7071499D7F4E79854550028A196C7B49E13"}]'
                    ports:
                    - 1339:1339
                    - 8082:8082
                    - 8182:8182
                    volumes:
                    - ./config:/config
                    init: true
                  iroha3:
                    build: ./iroha-cloned
                    environment:
                      IROHA_PUBLIC_KEY: ed0120854457B2E3D6082181DA73DC01C1E6F93A72D0C45268DC8845755287E98A5DEE
                      IROHA_PRIVATE_KEY: '{"digest_function":"ed25519","payload":"ab0e99c2b845b4ac7b3e88d25a860793c7eb600a25c66c75cba0bae91e955aa6854457b2e3d6082181da73dc01c1e6f93a72d0c45268dc8845755287e98a5dee"}'
                      TORII_P2P_ADDR: iroha3:1340
                      TORII_API_URL: iroha3:8083
                      TORII_TELEMETRY_URL: iroha3:8183
                      IROHA_GENESIS_ACCOUNT_PUBLIC_KEY: ed01203420F48A9EEB12513B8EB7DAF71979CE80A1013F5F341C10DCDA4F6AA19F97A9
                      IROHA_GENESIS_ACCOUNT_PRIVATE_KEY: '{"digest_function":"ed25519","payload":"5a6d5f06a90d29ad906e2f6ea8b41b4ef187849d0d397081a4a15ffcbe71e7c73420f48a9eeb12513b8eb7daf71979ce80a1013f5f341c10dcda4f6aa19f97a9"}'
                      SUMERAGI_TRUSTED_PEERS: '[{"address":"iroha2:1339","public_key":"ed0120312C1B7B5DE23D366ADCF23CD6DB92CE18B2AA283C7D9F5033B969C2DC2B92F4"},{"address":"iroha1:1338","public_key":"ed0120A88554AA5C86D28D0EEBEC497235664433E807881CD31E12A1AF6C4D8B0F026C"},{"address":"iroha0:1337","public_key":"ed0120F0321EB4139163C35F88BF78520FF7071499D7F4E79854550028A196C7B49E13"}]'
                    ports:
                    - 1340:1340
                    - 8083:8083
                    - 8183:8183
                    volumes:
                    - ./config:/config
                    init: true
            "#]];
            expected.assert_eq(&yaml);
        }
    }
}
