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
