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

use clap::{ArgGroup, StructOpt};
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
    let args: Args = clap::Parser::parse();
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
#[derive(StructOpt, Debug)]
#[structopt(name = "kagami", version, author)]
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
        }
    }
}

mod crypto {
    use color_eyre::eyre::{eyre, WrapErr as _};
    use iroha_crypto::{Algorithm, KeyGenConfiguration, KeyPair, PrivateKey};

    use super::*;

    /// Use `Kagami` to generate cryptographic key-pairs.
    #[derive(StructOpt, Debug, Clone)]
    #[structopt(group = ArgGroup::new("generate_from").required(false))]
    #[structopt(group = ArgGroup::new("format").required(false))]
    pub struct Args {
        /// Algorithm used to generate the key-pair.
        /// Options: `ed25519`, `secp256k1`, `bls_normal`, `bls_small`.
        #[clap(default_value_t, long, short)]
        algorithm: Algorithm,
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
                writeln!(writer, "Public key (multihash): {}", &key_pair.public_key())?;
                writeln!(writer, "Private key: {}", &key_pair.private_key())?;
                writeln!(
                    writer,
                    "Digest function: {}",
                    &key_pair.public_key().digest_function()
                )?;
            }
            Ok(())
        }
    }

    impl Args {
        fn key_pair(self) -> color_eyre::Result<KeyPair> {
            let key_gen_configuration =
                KeyGenConfiguration::default().with_algorithm(self.algorithm);
            let keypair: KeyPair = self.seed.map_or_else(
                || -> color_eyre::Result<_> {
                    self.private_key.map_or_else(
                        || {
                            KeyPair::generate_with_configuration(key_gen_configuration.clone())
                                .wrap_err("failed to generate key pair")
                        },
                        |private_key| {
                            let private_key = PrivateKey::from_hex(self.algorithm, &private_key)
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
                    if seed.len() < 32 && self.algorithm == Algorithm::Secp256k1 {
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

    #[derive(StructOpt, Debug, Clone, Copy)]
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
    use clap::{Parser, Subcommand};
    use iroha_data_model::{
        asset::AssetValueType,
        isi::{MintBox, RegisterBox},
        metadata::Limits,
        permission::{validator, Validator},
        prelude::AssetId,
        IdBox,
    };
    use iroha_genesis::{RawGenesisBlock, RawGenesisBlockBuilder};

    use super::*;

    #[derive(Parser, Debug, Clone, Copy)]
    pub struct Args {
        #[clap(subcommand)]
        mode: Option<Mode>,
    }

    #[derive(Subcommand, Debug, Clone, Copy, Default)]
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
            let genesis = match self.mode.unwrap_or_default() {
                Mode::Default => generate_default(),
                Mode::Synthetic {
                    domains,
                    accounts_per_domain,
                    assets_per_domain,
                } => generate_synthetic(domains, accounts_per_domain, assets_per_domain),
            }?;
            writeln!(writer, "{}", serde_json::to_string_pretty(&genesis)?)
                .wrap_err("Failed to write serialized genesis to the buffer.")
        }
    }

    #[allow(clippy::too_many_lines)]
    pub fn generate_default() -> color_eyre::Result<RawGenesisBlock> {
        let mut meta = Metadata::new();
        meta.insert_with_limits(
            "key".parse()?,
            "value".to_owned().into(),
            Limits::new(1024, 1024),
        )?;

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

        let parameter_defaults: Vec<_> = [
            Parameter::from_str("?BlockSyncGossipPeriod=10000")?,
            Parameter::from_str("?NetworkActorChannelCapacity=100")?,
            Parameter::from_str("?MaxTransactionsInBlock=512")?,
            Parameter::from_str("?MaxTransactionsInQueue=65536")?,
            Parameter::from_str("?TransactionTimeToLive=86400000")?,
            Parameter::from_str("?FutureThreshold=1000")?,
            Parameter::from_str("?BlockTime=1000")?,
            Parameter::from_str("?BlockSyncActorChannelCapacity=100")?,
            Parameter::from_str("?CommitTimeLimit=2000")?,
            Parameter::from_str("?TransactionLimits=4096,4194304_TL")?,
            Parameter::from_str("?GossipBatchSize=500")?,
            Parameter::from_str("?SumeragiGossipPeriod=1000")?,
            Parameter::from_str("?SumeragiActorChannelCapacity=100")?,
            Parameter::from_str("?MaxTransactionSize=32768")?,
            Parameter::from_str("?MaxContentLen=16384000")?,
            Parameter::from_str("?WSVAssetMetadataLimits=1048576,4096_ML")?,
            Parameter::from_str("?WSVAssetDefinitionMetadataLimits=1048576,4096_ML")?,
            Parameter::from_str("?WSVAccountMetadataLimits=1048576,4096_ML")?,
            Parameter::from_str("?WSVDomainMetadataLimits=1048576,4096_ML")?,
            Parameter::from_str("?WSVIdentLengthLimits=1,128_LL")?,
            Parameter::from_str("?WASMFuelLimit=1000000")?,
            Parameter::from_str("?WASMMaxMemory=524288000")?,
        ]
        .into_iter()
        .map(NewParameterBox::new)
        .map(Into::into)
        .collect();

        let param_seq = SequenceBox::new(parameter_defaults);
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
        genesis.transactions[0].isi.push(param_seq.into());
        genesis.transactions[0]
            .isi
            .push(register_user_metadata_access);

        genesis.transactions[0].isi.push(register_validator()?);

        Ok(genesis)
    }

    fn register_permission_token_definitions() -> color_eyre::Result<Vec<InstructionBox>> {
        Ok(super::tokens::permission_token_definitions()?
            .into_iter()
            .map(RegisterBox::new)
            .map(Into::into)
            .collect())
    }

    fn generate_synthetic(
        domains: u64,
        accounts_per_domain: u64,
        assets_per_domain: u64,
    ) -> color_eyre::Result<RawGenesisBlock> {
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
        let mut genesis = builder.build();

        let mints = {
            let mut acc = Vec::new();
            for domain in 0..domains {
                for account in 0..accounts_per_domain {
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

    fn register_validator() -> color_eyre::Result<InstructionBox> {
        const PERMISSION_VALIDATOR_PATH: &str = "../../permission_validators";

        let build_dir = tempfile::tempdir()
            .wrap_err("Failed to create temp dir for runtime validator output")?;

        let wasm_blob = iroha_wasm_builder::Builder::new(PERMISSION_VALIDATOR_PATH)
            .out_dir(build_dir.path())
            .build()?
            .optimize()?
            .into_bytes();

        Ok(RegisterBox::new(Validator::new(
            "permission_validator%genesis@genesis".parse()?,
            validator::ValidatorType::Instruction,
            WasmSmartContract::new(wasm_blob),
        ))
        .into())
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
            torii::{uri::DEFAULT_API_URL, DEFAULT_TORII_TELEMETRY_URL},
        };

        use super::*;

        #[derive(StructOpt, Debug, Clone, Copy)]
        pub struct Args;

        impl<T: Write> RunArgs<T> for Args {
            fn run(self, writer: &mut BufWriter<T>) -> Outcome {
                let config = ConfigurationProxy {
                    torii_api_url: Some(SmallStr::from_str(DEFAULT_API_URL)),
                    torii_telemetry_url: Some(SmallStr::from_str(DEFAULT_TORII_TELEMETRY_URL)),
                    account_id: Some("alice@wonderland".parse()?),
                    basic_auth: Some(Some(BasicAuth {
                        web_login: WebLogin::new("mad_hatter")?,
                        password: SmallStr::from_str("ilovetea"),
                    })),
                    public_key: Some(PublicKey::from_str(
                        "ed01207233bfc89dcbd68c19fde6ce6158225298ec1131b6a130d1aeb454c1ab5183c0",
                    )?),
                    private_key: Some(PrivateKey::from_hex(
                        Algorithm::Ed25519,
                        "9ac47abf59b356e0bd7dcbbbb4dec080e302156a48ca907e47cb6aea1d32719e7233bfc89dcbd68c19fde6ce6158225298ec1131b6a130d1aeb454c1ab5183c0"
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

        #[derive(StructOpt, Debug, Clone, Copy)]
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

    #[derive(StructOpt, Debug, Clone, Copy)]
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

    #[derive(StructOpt, Debug, Clone, Copy)]
    pub struct Args;

    pub fn permission_token_definitions() -> Result<Vec<PermissionTokenDefinition>> {
        // TODO: Not hardcode this. Instead get this info from validator it-self
        Ok(vec![
            // Account
            token_with_account_id("can_remove_key_value_in_user_account")?,
            token_with_account_id("can_set_key_value_in_user_account")?,
            // Asset
            token_with_asset_definition_id("can_burn_assets_with_definition")?,
            token_with_asset_id("can_burn_user_asset")?,
            token_with_asset_definition_id("can_mint_assets_with_definition")?,
            token_with_asset_id("can_remove_key_value_in_user_asset")?,
            token_with_asset_id("can_set_key_value_in_user_asset")?,
            token_with_asset_definition_id("can_transfer_assets_with_definition")?,
            token_with_asset_id("can_transfer_user_asset")?,
            token_with_asset_definition_id("can_unregister_assets_with_definition")?,
            token_with_asset_id("can_unregister_user_assets")?,
            // Asset definition
            token_with_asset_definition_id("can_remove_key_value_in_asset_definition")?,
            token_with_asset_definition_id("can_set_key_value_in_asset_definition")?,
            token_with_asset_definition_id("can_unregister_asset_definition")?,
            // Parameter
            bare_token("can_grant_permission_to_create_parameters")?,
            bare_token("can_revoke_permission_to_create_parameters")?,
            bare_token("can_create_parameters")?,
            bare_token("can_grant_permission_to_set_parameters")?,
            bare_token("can_revoke_permission_to_set_parameters")?,
            bare_token("can_set_parameters")?,
        ])
    }

    fn bare_token(token_id: &str) -> Result<PermissionTokenDefinition> {
        Ok(PermissionTokenDefinition::new(token_id.parse()?))
    }

    fn token_with_asset_definition_id(token_id: &str) -> Result<PermissionTokenDefinition> {
        Ok(PermissionTokenDefinition::new(token_id.parse()?)
            .with_params([("asset_definition_id".parse()?, ValueKind::Id)]))
    }

    fn token_with_asset_id(token_id: &str) -> Result<PermissionTokenDefinition> {
        Ok(PermissionTokenDefinition::new(token_id.parse()?)
            .with_params([("asset_id".parse()?, ValueKind::Id)]))
    }

    fn token_with_account_id(token_id: &str) -> Result<PermissionTokenDefinition> {
        Ok(PermissionTokenDefinition::new(token_id.parse()?)
            .with_params([("account_id".parse()?, ValueKind::Id)]))
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
