//! CLI for generating iroha sample configuration, genesis and
//! cryptographic key pairs. To be used with all compliant Iroha
//! installations.
#![allow(
    clippy::arithmetic,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc
)]
use std::io::{stdout, BufWriter, Write};

use clap::{ArgGroup, StructOpt};
use color_eyre::eyre::WrapErr as _;

pub type Outcome = color_eyre::Result<()>;

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
    /// Generate the default genesis block that is used in tests
    Genesis(genesis::Args),
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
        #[clap(long, short)]
        json: bool,
    }

    impl<T: Write> RunArgs<T> for Args {
        fn run(self, writer: &mut BufWriter<T>) -> Outcome {
            if self.json {
                let output = serde_json::to_string_pretty(&self.key_pair()?)
                    .wrap_err("Failed to serialise to JSON.")?;
                writeln!(writer, "{}", output)?;
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
    use iroha_core::{
        genesis::{RawGenesisBlock, RawGenesisBlockBuilder},
        tx::{AssetValueType, MintBox, RegisterBox},
    };
    use iroha_permissions_validators::public_blockchain;

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
                .wrap_err("Failed to write.")
        }
    }

    pub fn generate_default() -> color_eyre::Result<RawGenesisBlock> {
        let mut result = RawGenesisBlockBuilder::new()
            .domain("wonderland".parse()?)
            .with_account("alice".parse()?, crate::DEFAULT_PUBLIC_KEY.parse()?)
            .with_asset("rose".parse()?, AssetValueType::Quantity)
            .finish_domain()
            .build();
        let mint = MintBox::new(
            iroha_data_model::prelude::Value::U32(13_u32),
            iroha_data_model::IdBox::AssetId(iroha_data_model::prelude::AssetId::new(
                "rose#wonderland".parse()?,
                "alice@wonderland".parse()?,
            )),
        );

        result.transactions[0].isi.extend(
            public_blockchain::default_permission_token_definitions()
                .into_iter()
                .map(|token_definition| RegisterBox::new(token_definition.clone()).into()),
        );
        result.transactions[0].isi.push(mint.into());
        Ok(result)
    }

    fn generate_synthetic(
        domains: u64,
        accounts_per_domain: u64,
        assets_per_domain: u64,
    ) -> color_eyre::Result<RawGenesisBlock> {
        // Add default `Domain` and `Account` to still be able to query
        let mut builder = RawGenesisBlockBuilder::new()
            .domain("wonderland".parse()?)
            .with_account("alice".parse()?, crate::DEFAULT_PUBLIC_KEY.parse()?)
            .finish_domain();

        for domain in 0..domains {
            let mut domain_builder = builder.domain(format!("domain_{domain}").parse()?);

            for account in 0..accounts_per_domain {
                let (public_key, _) = iroha_crypto::KeyPair::generate()?.into();
                domain_builder =
                    domain_builder.with_account(format!("account_{account}").parse()?, public_key);
            }

            for asset in 0..assets_per_domain {
                domain_builder = domain_builder
                    .with_asset(format!("asset_{asset}").parse()?, AssetValueType::Quantity);
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
                            iroha_data_model::prelude::Value::U32(13_u32),
                            iroha_data_model::IdBox::AssetId(
                                iroha_data_model::prelude::AssetId::new(
                                    format!("asset_{asset}#domain_{domain}").parse()?,
                                    format!("account_{account}@domain_{domain}").parse()?,
                                ),
                            ),
                        );
                        acc.push(mint);
                    }
                }
            }
            acc
        }
        .into_iter()
        .map(Into::into);

        genesis.transactions[0].isi.extend(
            public_blockchain::default_permission_token_definitions()
                .into_iter()
                .map(|token_definition| RegisterBox::new(token_definition.clone()).into()),
        );
        genesis.transactions[0].isi.extend(mints);
        Ok(genesis)
    }
}

mod docs {
    #![allow(clippy::panic_in_result_fn, clippy::expect_used)]
    #![allow(
        clippy::arithmetic,
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
            let docs = match Self::get_docs() {
                Value::Object(obj) => obj,
                _ => unreachable!("As top level structure is always object"),
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
            writeln!(writer, "```json\n{}\n```\n", defaults)?;
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
                write!(writer, "{}\n\n", doc)?;
                write!(writer, "```json\n{}\n```\n\n", defaults)?;

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
    use std::collections::HashMap;

    use clap::ArgEnum;
    use color_eyre::{
        eyre::{bail, eyre, WrapErr},
        Result,
    };
    use iroha_permissions_validators::{
        private_blockchain::register::CanRegisterDomains,
        public_blockchain::PredefinedPermissionToken,
    };
    use iroha_schema::{IntoSchema, Metadata};

    use super::*;

    #[derive(StructOpt, Debug, Clone, Copy)]
    pub struct Args {
        #[structopt(arg_enum, default_value = "public")]
        /// Whether to list private or public blockchain tokens
        blockchain: Blockchain,
    }

    #[derive(ArgEnum, Debug, Clone, Copy)]
    pub enum Blockchain {
        Private,
        Public,
    }

    fn public_blockchain_tokens() -> Result<HashMap<String, HashMap<String, String>>> {
        let mut schema = PredefinedPermissionToken::get_schema();

        let enum_variants = match schema
            .remove("iroha_permissions_validators::public_blockchain::PredefinedPermissionToken")
            .ok_or_else(|| eyre!("Token enum is not in schema"))?
        {
            Metadata::Enum(meta) => meta.variants,
            _ => bail!("Expected enum"),
        };

        enum_variants
            .into_iter()
            .map(|variant| {
                let ty = variant.ty.ok_or_else(|| eyre!("Empty enum variant"))?;
                let fields = match schema
                    .remove(&ty)
                    .ok_or_else(|| eyre!("Token is not in schema"))?
                {
                    Metadata::Struct(meta) => meta
                        .declarations
                        .into_iter()
                        .map(|decl| (decl.name, decl.ty))
                        .collect::<HashMap<_, _>>(),
                    _ => bail!("Token is not a struct"),
                };
                Ok((ty, fields))
            })
            .collect::<Result<HashMap<_, _>, _>>()
    }

    fn private_blockchain_tokens() -> Result<HashMap<String, HashMap<String, String>>> {
        let schema = CanRegisterDomains::get_schema();

        schema
            .into_iter()
            .map(|(ty, meta)| {
                let fields = match meta {
                    Metadata::Struct(meta) => meta
                        .declarations
                        .into_iter()
                        .map(|decl| (decl.name, decl.ty))
                        .collect::<HashMap<_, _>>(),
                    _ => bail!("Token is not a struct"),
                };
                Ok((ty, fields))
            })
            .collect::<Result<HashMap<_, _>, _>>()
    }

    impl<T: Write> RunArgs<T> for Args {
        fn run(self, writer: &mut BufWriter<T>) -> Outcome {
            let token_map = match self.blockchain {
                Blockchain::Private => private_blockchain_tokens()?,
                Blockchain::Public => public_blockchain_tokens()?,
            };

            write!(
                writer,
                "{}",
                serde_json::to_string_pretty(&token_map).wrap_err("Serialization error")?
            )
            .wrap_err("Failed to write.")
        }
    }
}
