//! CLI for generating iroha sample configuration, genesis and
//! cryptographic key pairs. To be used with all compliant Iroha
//! installations.

use std::io::{stdout, BufWriter, Write};

use clap::{ArgGroup, StructOpt};
use color_eyre::eyre::WrapErr as _;
use iroha::config::Configuration;

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

/// Tool generating the cryptorgraphic key pairs, schema, genesis block and configuration reference.
#[derive(StructOpt, Debug)]
#[structopt(name = "kagami", version, author)]
pub enum Args {
    /// Generate cryptorgraphic key pairs
    Crypto(crypto::Args),
    /// Generate schema used for code generation in Iroha SDKs
    Schema(schema::Args),
    /// Generate a default genesis block that is used in tests
    Genesis(genesis::Args),
    /// Generate a Markdown reference of configuration parameters
    Docs(docs::Args),
}

impl<T: Write> RunArgs<T> for Args {
    fn run(self, writer: &mut BufWriter<T>) -> Outcome {
        use Args::*;

        match self {
            Crypto(args) => args.run(writer),
            Schema(args) => args.run(writer),
            Genesis(args) => args.run(writer),
            Docs(args) => args.run(writer),
        }
    }
}

mod crypto {
    use color_eyre::eyre::WrapErr as _;
    use iroha_crypto::{Algorithm, KeyGenConfiguration, KeyPair, PrivateKey};

    use super::*;

    /// Use `Kagami` to generate cryptographic key-pairs.
    #[derive(StructOpt, Debug, Clone)]
    #[structopt(group = ArgGroup::new("generate_from").required(false))]
    pub struct Args {
        /// Algorithm used for generating the key-pair
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
                    KeyPair::generate_with_configuration(
                        key_gen_configuration
                            .clone()
                            .use_seed(seed.as_bytes().into()),
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
    use iroha_core::{
        genesis::{RawGenesisBlock, RawGenesisBlockBuilder},
        tx::{AssetDefinition, MintBox},
    };

    use super::*;

    #[derive(StructOpt, Debug, Clone, Copy)]
    pub struct Args;

    impl<T: Write> RunArgs<T> for Args {
        fn run(self, writer: &mut BufWriter<T>) -> Outcome {
            writeln!(
                writer,
                "{}",
                serde_json::to_string_pretty(&generate_default()?)?
            )
            .wrap_err("Failed to write.")
        }
    }

    pub fn generate_default() -> color_eyre::Result<RawGenesisBlock> {
        let asset_definition = AssetDefinition::quantity("rose#wonderland".parse()?).build();
        let mut result = RawGenesisBlockBuilder::new()
            .domain("wonderland".parse()?)
            .with_account("alice".parse()?, crate::DEFAULT_PUBLIC_KEY.parse()?)
            .with_asset(asset_definition.clone())
            .finish_domain()
            .build();
        let mint = MintBox::new(
            iroha_data_model::prelude::Value::U32(13_u32),
            iroha_data_model::IdBox::AssetId(iroha_data_model::prelude::AssetId::new(
                asset_definition.id().clone(), // Probably redundant clone
                "alice@wonderland".parse()?,
            )),
        );
        result.transactions[0].isi.push(mint.into());
        Ok(result)
    }
}

mod docs {
    #![allow(clippy::panic_in_result_fn, clippy::expect_used)]
    use std::{fmt::Debug, io::Write};

    use color_eyre::eyre::WrapErr as _;
    use iroha_config::Configurable;
    use serde_json::Value;

    use super::*;

    impl<E: Debug, C: Configurable<Error = E> + Send + Sync + Default> PrintDocs for C {}

    #[derive(StructOpt, Debug, Clone, Copy)]
    pub struct Args;

    impl<T: Write> RunArgs<T> for Args {
        fn run(self, writer: &mut BufWriter<T>) -> crate::Outcome {
            Configuration::get_markdown(writer).wrap_err("Failed to generate documentation")
        }
    }

    pub trait PrintDocs: Configurable + Send + Sync + Default
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
            writeln!(writer, "In this document we provide a reference and detailed descriptions of Iroha's configuration options.\n")?;
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
                        (doc.unwrap_or_default().to_owned(), true)
                    }
                    Value::String(s) => (s.clone(), false),
                    _ => unreachable!("Only strings and objects in docs"),
                };
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
