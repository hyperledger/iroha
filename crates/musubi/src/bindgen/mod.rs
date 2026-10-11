//! Deterministic SDK request models derived exclusively from admitted contract artifacts.
//!
//! These bindings describe the signed entrypoint kind and exact JSON boundary. They deliberately
//! leave signing, fee policy, deployment and view transport to the SDK/application boundary.
use iroha_data_model::smart_contract::{
    entrypoint::{EntrypointValueKindV1, EntrypointValueTypeNodeV1, EntrypointValueTypeV1},
    manifest::EntryPointKind,
};
use ivm::contract_artifact::verify_contract_artifact;
use std::{collections::BTreeMap, fmt::Write as _};

mod kotlin;
mod swift;
mod typescript;

/// SDK language used for generated request models and checked result decoders.
#[derive(Clone, Copy, Debug, clap::ValueEnum)]
pub enum Language {
    /// TypeScript models for the JavaScript SDK.
    Typescript,
    /// Swift models for the Swift SDK.
    Swift,
    /// Kotlin models for the JVM SDK.
    Kotlin,
}

#[derive(Debug)]
struct Type {
    name: String,
    identity: Option<String>,
    kind: Kind,
}

#[derive(Debug)]
enum Kind {
    Struct(Vec<(String, usize)>),
    Tuple(Vec<usize>),
    Option(usize),
    Result(usize, usize),
    List(usize, u32),
    Leaf(EntrypointValueKindV1),
    Unit,
    Enum(Vec<String>),
    Cursor,
}

struct Entry {
    name: String,
    symbol: String,
    kind: &'static str,
    args: Vec<(String, usize)>,
    result: usize,
    schema_json: String,
    result_schema_json: String,
}

struct Model {
    namespace: String,
    code_hash: String,
    types: Vec<Type>,
    entries: Vec<Entry>,
}

/// Admit the complete image before reading its schemas or generating any output.
///
/// # Errors
/// Returns the artifact admission error for an invalid image, or a missing required
/// schema error. No bindings are returned unless the entire artifact is valid.
pub fn generate(bytes: &[u8], language: Language, name: &str) -> Result<String, String> {
    let verified = verify_contract_artifact(bytes).map_err(|error| error.to_string())?;
    let mut model = Model {
        namespace: format!("{}Bindings", identifier(name)),
        code_hash: verified.code_hash.to_string(),
        types: Vec::new(),
        entries: Vec::new(),
    };
    let mut interned = BTreeMap::new();
    for (ordinal, entry) in verified.contract_interface.entrypoints.iter().enumerate() {
        let mut args = Vec::new();
        if let Some(schema) = &entry.argument_schema {
            for field in &schema.fields {
                args.push((field.name.clone(), model.intern(&field.ty, &mut interned)));
            }
        }
        let result = model.intern(
            entry
                .return_schema
                .as_ref()
                .ok_or("missing return schema")?,
            &mut interned,
        );
        model.entries.push(Entry {
            name: entry.name.clone(),
            // The signed ordinal prevents all Unicode, keyword and sanitization collisions.
            symbol: format!("entry{ordinal}_{}", identifier(&entry.name)),
            kind: match entry.kind {
                EntryPointKind::Kotoage => "Kotoage",
                EntryPointKind::View => "View",
                EntryPointKind::Hajimari => "Hajimari",
                EntryPointKind::Kaizen => "Kaizen",
            },
            args,
            result,
            schema_json: norito::json::to_json(&entry.argument_schema)
                .map_err(|error| error.to_string())?,
            result_schema_json: norito::json::to_json(&entry.return_schema)
                .map_err(|error| error.to_string())?,
        });
    }
    Ok(match language {
        Language::Typescript => typescript::render(&model),
        Language::Swift => swift::render(&model),
        Language::Kotlin => kotlin::render(&model),
    })
}

impl Model {
    fn intern(
        &mut self,
        schema: &EntrypointValueTypeV1,
        interned: &mut BTreeMap<EntrypointValueTypeV1, usize>,
    ) -> usize {
        if let Some(index) = interned.get(schema) {
            return *index;
        }
        let index = self.types.len();
        self.types.push(Type {
            name: String::new(),
            identity: None,
            kind: Kind::Unit,
        });
        interned.insert(schema.clone(), index);
        let root = &schema.nodes[0];
        let mut next = 1;
        let children = match root {
            EntrypointValueTypeNodeV1::Struct(node) => node.fields.len(),
            EntrypointValueTypeNodeV1::Tuple(arity) => usize::from(*arity),
            EntrypointValueTypeNodeV1::Option | EntrypointValueTypeNodeV1::List(_) => 1,
            EntrypointValueTypeNodeV1::Result => 2,
            _ => 0,
        };
        let mut child_ids = Vec::new();
        for _ in 0..children {
            let start = next;
            skip(&schema.nodes, &mut next);
            child_ids.push(self.intern(
                &EntrypointValueTypeV1 {
                    nodes: schema.nodes[start..next].to_vec(),
                },
                interned,
            ));
        }
        let (identity, kind) = match root {
            EntrypointValueTypeNodeV1::Struct(node) => (
                Some(node.name.clone()),
                Kind::Struct(node.fields.iter().cloned().zip(child_ids).collect()),
            ),
            EntrypointValueTypeNodeV1::Tuple(_) => (None, Kind::Tuple(child_ids)),
            EntrypointValueTypeNodeV1::Option => (None, Kind::Option(child_ids[0])),
            EntrypointValueTypeNodeV1::Result => (None, Kind::Result(child_ids[0], child_ids[1])),
            EntrypointValueTypeNodeV1::List(node) => {
                (None, Kind::List(child_ids[0], u32::from(node.capacity)))
            }
            EntrypointValueTypeNodeV1::Leaf(kind) => (None, Kind::Leaf(*kind)),
            EntrypointValueTypeNodeV1::Unit => (None, Kind::Unit),
            EntrypointValueTypeNodeV1::Error(node) => (
                Some(node.identity.clone()),
                Kind::Enum(
                    node.variants
                        .iter()
                        .map(|variant| variant.name.clone())
                        .collect(),
                ),
            ),
            EntrypointValueTypeNodeV1::Enum(node) => (
                Some(node.identity.clone()),
                Kind::Enum(
                    node.variants
                        .iter()
                        .map(|variant| variant.name.clone())
                        .collect(),
                ),
            ),
            EntrypointValueTypeNodeV1::StateCursor(_) => (None, Kind::Cursor),
        };
        let suffix = identity
            .as_deref()
            .and_then(|name| name.rsplit("::").next())
            .unwrap_or("Value");
        self.types[index] = Type {
            name: format!("T{index}_{}", identifier(suffix)),
            identity,
            kind,
        };
        index
    }
    fn ty(&self, index: usize) -> &str {
        &self.types[index].name
    }
}

fn skip(nodes: &[EntrypointValueTypeNodeV1], index: &mut usize) {
    let children = match &nodes[*index] {
        EntrypointValueTypeNodeV1::Struct(node) => node.fields.len(),
        EntrypointValueTypeNodeV1::Tuple(arity) => usize::from(*arity),
        EntrypointValueTypeNodeV1::Option | EntrypointValueTypeNodeV1::List(_) => 1,
        EntrypointValueTypeNodeV1::Result => 2,
        _ => 0,
    };
    *index += 1;
    for _ in 0..children {
        skip(nodes, index);
    }
}

// Encoding underscores as well as non-ASCII scalar values makes this transformation injective.
// Prefixes on every declaration keep host-language keywords and numeric starts harmless.
fn identifier(source: &str) -> String {
    let mut output = String::from("k");
    for character in source.chars() {
        if character.is_ascii_alphanumeric() {
            output.push(character);
        } else {
            write!(output, "_u{:x}_", u32::from(character)).unwrap();
        }
    }
    output
}

fn quoted(source: &str) -> String {
    norito::json::to_json(source).expect("strings are JSON serializable")
}

fn field(index: usize, source: &str) -> String {
    format!("f{index}_{}", identifier(source))
}

#[cfg(test)]
mod tests;
