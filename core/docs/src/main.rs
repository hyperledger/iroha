//! Cli for generating documentation for iroha configuraion

#![allow(clippy::restriction)]

use std::{
    fmt::Debug,
    io::{stdout, BufWriter, Result, Write},
};

use color_eyre::eyre::WrapErr;
use iroha_config::Configurable;
use iroha_core::config::Configuration;
use serde_json::{Map, Value};

fn main() -> color_eyre::Result<()> {
    color_eyre::install().unwrap();
    Configuration::get_markdown(&mut BufWriter::new(stdout()))
        .wrap_err("Failed to generate documentation")
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
