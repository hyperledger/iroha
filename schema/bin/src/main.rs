//! Binary to print all types to json string

#![allow(clippy::print_stdout)]

use iroha_schema::prelude::*;

fn build_schemas() -> MetaMap {
    use iroha_core::{
        block::{stream::prelude::*, VersionedValidBlock},
        genesis::RawGenesisBlock,
        smartcontracts::isi::query::Error as QueryError,
    };
    use iroha_data_model::{merkle::MerkleTree, prelude::*};

    macro_rules! schemas {
        ($($t:ty),* $(,)?) => {{
            let mut out = MetaMap::new();
            $(<$t as IntoSchema>::schema(&mut out);)*
            out
        }};
    }

    // It is sufficient to list top level types only
    schemas! {
        RawGenesisBlock,

        VersionedBlockPublisherMessage,
        VersionedBlockSubscriberMessage,
        VersionedEventPublisherMessage,
        VersionedEventSubscriberMessage,
        VersionedQueryResult,
        VersionedSignedQueryRequest,
        VersionedTransaction,
        QueryError,

        // Even though these schemas are not exchanged between server and client,
        // they can be useful to the client to generate and validate their hashes
        MerkleTree<VersionedTransaction>,
        VersionedValidBlock,
    }
}

// Schemas should always be serializable to JSON
#[allow(clippy::expect_used)]
fn main() {
    let schemas = build_schemas();

    println!(
        "{}",
        serde_json::to_string_pretty(&schemas).expect("Unable to serialize schemas")
    );
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    // NOTE: These type parameters should not be have their schema exposed
    // By default `PhantomData` wrapped types schema will not be included
    const SCHEMALESS_TYPES: Vec<&str> = vec![];

    // For `PhantomData` wrapped types schemas aren't expanded recursively.
    // This test ensures that schemas for those types are present as well.
    fn find_missing_type_params(schemas: &MetaMap) -> HashMap<&str, Vec<&str>> {
        let mut missing_schemas = HashMap::new();

        for type_name in schemas.keys() {
            // Missing `PhantomData` schemas
            let params_list_start = type_name.find('<');
            let params_list_end = type_name.rfind('>');

            if let (Some(start), Some(end)) = (params_list_start, params_list_end) {
                for generic in type_name[1 + start..end].split(',') {
                    let gen = generic.trim();

                    // This is const generic
                    if gen.parse::<usize>().is_ok() {
                        continue;
                    }

                    if !SCHEMALESS_TYPES.contains(&gen) && !schemas.contains_key(gen) {
                        missing_schemas
                            .entry(type_name.as_str())
                            .or_insert_with(Vec::new)
                            .push(gen);
                    }
                }
            }
        }

        missing_schemas
    }

    fn find_missing_schemas(schemas: &MetaMap) -> HashMap<&str, Vec<&str>> {
        let mut missing_schemas = HashMap::new();

        for (type_name, schema) in schemas {
            let types: Vec<&str> = match schema {
                Metadata::Enum(EnumMeta { variants }) => variants
                    .iter()
                    .map(|v| &v.ty)
                    .filter_map(Option::as_ref)
                    .map(String::as_str)
                    .collect(),
                Metadata::Struct(NamedFieldsMeta { declarations }) => {
                    declarations.iter().map(|d| d.ty.as_str()).collect()
                }
                Metadata::TupleStruct(UnnamedFieldsMeta { types }) => {
                    types.iter().map(String::as_str).collect()
                }
                Metadata::Result(ResultMeta { ok, err }) => vec![ok, err],
                Metadata::Map(MapMeta { key, value }) => vec![key, value],
                Metadata::Option(ty)
                | Metadata::Array(ArrayMeta { ty, .. })
                | Metadata::Vec(ty) => {
                    vec![ty]
                }
                Metadata::String | Metadata::Bool | Metadata::FixedPoint(_) | Metadata::Int(_) => {
                    vec![]
                }
            };

            for ty in types {
                if !schemas.contains_key(ty) {
                    missing_schemas
                        .entry(type_name.as_str())
                        .or_insert_with(Vec::new)
                        .push(ty);
                }
            }
        }

        missing_schemas.extend(find_missing_type_params(schemas));

        missing_schemas
    }

    #[test]
    fn no_missing_schemas() {
        assert!(find_missing_schemas(&build_schemas()).is_empty());
    }

    #[test]
    fn no_alloc_prefix() {
        assert!(build_schemas()
            .keys()
            .all(|type_name| !type_name.starts_with("alloc")));
    }
}
