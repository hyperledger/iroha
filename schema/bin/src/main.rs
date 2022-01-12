//! Binary to print all types to json string

#![allow(clippy::print_stdout)]

use iroha_core::block::stream::prelude::*;
use iroha_schema::prelude::*;

fn build_schemas() -> MetaMap {
    use iroha_core::genesis::RawGenesisBlock;
    use iroha_data_model::prelude::*;

    macro_rules! schemas {
        ($($t:ty),* $(,)?) => {{
            let mut out = MetaMap::new();
            $(<$t as IntoSchema>::schema(&mut out);)*
            out
        }};
    }

    schemas! {
        // It is sufficient to list top level types only
        VersionedBlockPublisherMessage,
        VersionedBlockSubscriberMessage,
        VersionedEventPublisherMessage,
        VersionedEventSubscriberMessage,
        VersionedQueryResult,
        VersionedSignedQueryRequest,
        VersionedTransaction,

        RawGenesisBlock
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

        missing_schemas
    }

    #[test]
    fn no_missing_schemas() {
        assert!(find_missing_schemas(&build_schemas()).is_empty());
    }
}
