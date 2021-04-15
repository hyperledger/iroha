//! Cli for generating documentation for iroha configuraion

#![allow(clippy::restriction)]

use std::fmt::Debug;
use std::io::Result;
use std::io::{stdout, BufWriter, Write};

use async_std::task;
use iroha::config::Configuration;
use iroha_config::Configurable;
use iroha_error::WrapErr;
use serde_json::{Map, Value};

fn main() -> iroha_error::Result<()> {
    Configuration::get_md(&mut BufWriter::new(stdout()))
        .wrap_err("Failed to generate documentation")
}

impl<E: Debug, C: Configurable<Error = E> + Send + Sync + Default> PrintDocs for C {}

trait PrintDocs: Configurable + Send + Sync + Default
where
    Self::Error: Debug,
{
    fn get_md<W: Write>(writer: &mut W) -> Result<()> {
        let docs = match Self::get_docs() {
            Value::Object(obj) => obj,
            _ => unreachable!("As top level structure is always object"),
        };
        let mut vec = Vec::new();
        let defaults = serde_json::to_string_pretty(&Self::default())?;

        write!(writer, "# Iroha config description\n\n")?;
        writeln!(writer, "Configuration of iroha is done via options in the following document. Here is defaults for whole config:\n")?;
        write!(writer, "```json\n{}\n```\n\n", defaults)?;
        Self::get_md_with_depth(writer, &docs, &mut vec, 2)?;
        Ok(())
    }

    fn get_md_with_depth<W: Write>(
        writer: &mut W,
        docs: &Map<String, Value>,
        field: &mut Vec<String>,
        depth: usize,
    ) -> Result<()> {
        let cur_field = {
            let mut docs = docs;
            for f in &*field {
                docs = match &docs[f] {
                    Value::Object(obj) => obj,
                    _ => unreachable!(),
                };
            }
            docs
        };

        for (f, value) in cur_field {
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
            let doc = doc.strip_prefix(" ").unwrap_or(&doc);
            let defaults = task::block_on(Self::default().get_recursive(get_field)).unwrap();
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
                Self::get_md_with_depth(writer, docs, field, depth + 1)?;
            }

            let _ = field.pop();
        }
        Ok(())
    }
}
