//! CLI for generating iroha sample configuration and genesis, as well
//! as their documentation.

#![allow(clippy::restriction)]

use std::{
    fmt::Debug,
    io::{stdout, BufWriter, Result, Write},
};

use color_eyre::eyre::WrapErr;
use iroha::config::Configuration;
use iroha_config::Configurable;
use iroha_core::{
    genesis::{RawGenesisBlock, RawGenesisBlockBuilder},
    tx::{AssetDefinition, MintBox},
};
use serde_json::{Map, Value};

// TODO: if we merge #2077 first, we should change this to sync up with the default in docs.
static DEFAULT_PUBLIC_KEY: &str =
    "ed01207233bfc89dcbd68c19fde6ce6158225298ec1131b6a130d1aeb454c1ab5183c0";

fn main() -> color_eyre::Result<()> {
    color_eyre::install().unwrap();
    let mut output = BufWriter::new(stdout());
    if std::env::args().any(|a| is_genesis(&a)) {
        writeln!(
            output,
            "{}",
            serde_json::to_string_pretty(&generate_default_genesis()?)?
        )?;
        Ok(())
    } else if std::env::args().any(|a| is_schema(&a)) {
        let schemas = iroha_schema_bin::build_schemas();
        writeln!(output, "{}", serde_json::to_string_pretty(&schemas)?)?;
        Ok(())
    } else if std::env::args().any(|a| is_docs(&a)) {
        Configuration::get_markdown(&mut BufWriter::new(stdout()))
            .wrap_err("Failed to generate documentation")
    } else {
        print_help();
        Ok(())
    }
}

fn print_help() {
    println!("Tool for generating iroha-related data.");
    println!();
    println!("pass `--docs` or `-d` to generate sample config and its documentation.");
    println!("pass `--schema` or `-s` to generate the schema.");
    println!("pass `--genesis` or `-g` to generate the genesis block.");
}

fn is_docs(arg: &str) -> bool {
    ["--docs", "-d"].contains(&arg)
}

fn is_schema(arg: &str) -> bool {
    ["--schema", "-s"].contains(&arg)
}

fn is_genesis(arg: &str) -> bool {
    ["--genesis", "-g"].contains(&arg)
}

fn generate_default_genesis() -> color_eyre::Result<RawGenesisBlock> {
    let asset_definition = AssetDefinition::quantity("rose#wonderland".parse()?).build();
    let mut result = RawGenesisBlockBuilder::new()
        .domain("wonderland".parse()?)
        .with_account("alice".parse()?, DEFAULT_PUBLIC_KEY.parse()?)
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

impl<E: Debug, C: Configurable<Error = E> + Send + Sync + Default> PrintDocs for C {}

trait PrintDocs: Configurable + Send + Sync + Default
where
    Self::Error: Debug,
{
    fn get_markdown<W: Write>(writer: &mut W) -> Result<()> {
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
        docs: &Map<String, Value>,
        field: &mut Vec<String>,
        depth: usize,
    ) -> Result<()> {
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
