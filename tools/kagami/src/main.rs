//! CLI for generating iroha sample configuration, genesis and
//! cryptographic key pairs. To be used with all compliant Iroha
//! installations.

use std::io::{stdout, BufWriter, Write};

use clap::{App, Arg, ArgGroup};
use color_eyre::eyre::WrapErr as _;
use docs::PrintDocs as _;
use iroha::config::Configuration;

// The reason for hard-coding this default is to ensure that the
// algorithm is matched to the public key. If you need to change
// either, you should definitely change both.
static DEFAULT_PUBLIC_KEY: &str =
    "ed01207233bfc89dcbd68c19fde6ce6158225298ec1131b6a130d1aeb454c1ab5183c0";
static DEFAULT_ALGORITHM: &str = iroha_crypto::ED_25519;

fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;
    let matches = arg_parse();
    let keypair = crypto::key_pair(&matches)?;
    let mut output = BufWriter::new(stdout());

    if matches.is_present("genesis") {
        writeln!(
            output,
            "{}",
            serde_json::to_string_pretty(&genesis::generate_default()?)?
        )?;
    } else if matches.is_present("docs") {
        Configuration::get_markdown(&mut BufWriter::new(stdout()))
            .wrap_err("Failed to generate documentation")?;
    } else if matches.is_present("schema") {
        let schemas = iroha_schema_bin::build_schemas();
        writeln!(output, "{}", serde_json::to_string_pretty(&schemas)?)?;
    } else if matches.is_present("key") {
        #[allow(clippy::print_stdout)]
        if matches.is_present("json") {
            let json =
                serde_json::to_string_pretty(&keypair).wrap_err("Failed to serialize to json.")?;
            writeln!(output, "{}", json)?;
        } else {
            writeln!(output, "Public key (multihash): {}", &keypair.public_key())?;
            writeln!(output, "Private key: {}", &keypair.private_key())?;
            writeln!(
                output,
                "Digest function: {}",
                &keypair.public_key().digest_function()
            )?;
        }
    } else {
        writeln!(output, "No arguments specified, run with `--help`")?;
    }
    Ok(())
}

// TODO: Refactor to use the `StructOpt` syntax just like all other tools.
fn arg_parse() -> clap::ArgMatches<'static> {
    let app = App::new("Kagami")
        .version("0.1")
        .author("Iroha development team.")
        .about("Generator for data used in Iroha.")
        .arg(
            Arg::with_name("seed")
                .long("seed")
                .value_name("seed")
                .help("Sets a seed for random number generator. Should be used separately from `private_key`.")
                .required(false)
                .takes_value(true)
        )
        .arg(
            Arg::with_name("private-key")
                .long("private-key")
                .value_name("private_key")
                .help("Sets a private key. Should be used separately from `seed`.")
                .required(false)
                .takes_value(true)
        )
        .arg(
            Arg::with_name("algorithm")
                .long("algorithm")
                .value_name("algorithm")
                .help("Function used to generate the key pair.")
                .takes_value(true)
                .possible_value(iroha_crypto::ED_25519)
                .possible_value(iroha_crypto::SECP_256_K1)
                .possible_value(iroha_crypto::BLS_NORMAL)
                .possible_value(iroha_crypto::BLS_SMALL)
                .default_value(DEFAULT_ALGORITHM)
        )
        .arg(
            Arg::with_name("json")
            .long("json")
            .help("If specified the output will be formatted as json.")
            .takes_value(false)
            .multiple(false)
        )
        .arg(
            Arg::with_name("genesis")
                .long("genesis")
                .short("g")
                .help("If specified, print the Genesis")
                .takes_value(false)
                .multiple(false)
        )
        .arg(
            Arg::with_name("schema")
                .long("schema")
                .short("s")
                .help("If specified, print Schema")
                .takes_value(false)
                .multiple(false)
        )
        .arg(
            Arg::with_name("docs")
                .long("docs")
                .short("d")
                .help("If specified, print configuration docs")
                .takes_value(false)
                .multiple(false)
        )
        .group(
            ArgGroup::with_name("other_gen_options")
                .args(&["docs", "schema", "genesis"])
                .required(false)
                .multiple(false)
        )
        .group(
            ArgGroup::with_name("key_gen_options")
                .args(&["seed", "private-key"])
                .required(false)
                .multiple(false)
        ).get_matches();
    app
}

mod crypto {

    use color_eyre::eyre::{eyre, WrapErr as _};
    use iroha_crypto::{Algorithm, KeyGenConfiguration, KeyPair, PrivateKey};

    pub fn key_pair(matches: &clap::ArgMatches) -> color_eyre::Result<KeyPair> {
        let seed_option = matches.value_of("seed");
        let private_key_option = matches.value_of("private-key");
        let algorithm = matches
            .value_of("algorithm")
            .ok_or_else(|| eyre!("Failed to get algorithm name."))?
            .parse::<Algorithm>()
            .wrap_err("Failed to parse algorithm.")?;
        let key_gen_configuration = KeyGenConfiguration::default().with_algorithm(algorithm);
        let keypair: KeyPair = seed_option.map_or_else(
            || -> color_eyre::Result<_> {
                private_key_option.map_or_else(
                    || {
                        KeyPair::generate_with_configuration(key_gen_configuration.clone())
                            .wrap_err("failed to generate key pair")
                    },
                    |private_key| {
                        KeyPair::generate_with_configuration(
                            key_gen_configuration
                                .clone()
                                .use_private_key(PrivateKey::from_hex(
                                    algorithm,
                                    &hex::decode(private_key)
                                        .wrap_err("Failed to decode private key")?,
                                )?),
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

mod genesis {
    use iroha_core::{
        genesis::{RawGenesisBlock, RawGenesisBlockBuilder},
        tx::{AssetDefinition, MintBox},
    };

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

    use iroha_config::Configurable;
    use serde_json::Value;

    impl<E: Debug, C: Configurable<Error = E> + Send + Sync + Default> PrintDocs for C {}

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
