//! Iroha schema generation support library. Contains the
//! `build_schemas` `fn`, which is the function which decides which
//! types are included in the schema.

use iroha_core::{
    block::{stream::prelude::*, VersionedValidBlock},
    genesis::RawGenesisBlock,
    smartcontracts::isi::query::Error as QueryError,
};
use iroha_schema::prelude::*;

macro_rules! schemas {
    ($($t:ty),* $(,)?) => {{
        let mut out = MetaMap::new();
        $(<$t as IntoSchema>::schema(&mut out);)*
            out
    }};
}

/// Builds the schema for the current state of Iroha.
///
/// You should only include the top-level types, because other types
/// shall be included automatically.
pub fn build_schemas() -> MetaMap {
    use iroha_crypto::MerkleTree;
    use iroha_data_model::prelude::*;

    schemas! {
        RawGenesisBlock,

        VersionedBlockPublisherMessage,
        VersionedBlockSubscriberMessage,
        VersionedEventPublisherMessage,
        VersionedEventSubscriberMessage,
        VersionedPaginatedQueryResult,
        VersionedSignedQueryRequest,
        VersionedTransaction,
        QueryError,

        RegistrableBox,

        // Even though these schemas are not exchanged between server and client,
        // they can be useful to the client to generate and validate their hashes
        MerkleTree<VersionedTransaction>,
        VersionedValidBlock,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    // NOTE: These type parameters should not be have their schema exposed
    // By default `PhantomData` wrapped types schema will not be included
    const SCHEMALESS_TYPES: Vec<&str> = vec![];

    fn is_const_generic(generic: &str) -> bool {
        generic.parse::<usize>().is_ok()
    }

    fn get_subtypes(schema: &Metadata) -> Vec<&str> {
        match schema {
            Metadata::Enum(EnumMeta { variants }) => variants
                .iter()
                .map(|v| &v.ty)
                .filter_map(Option::as_ref)
                .map(String::as_str)
                .collect(),
            Metadata::Struct(NamedFieldsMeta { declarations }) => {
                declarations.iter().map(|d| d.ty.as_str()).collect()
            }
            Metadata::Tuple(UnnamedFieldsMeta { types }) => {
                types.iter().map(String::as_str).collect()
            }
            Metadata::Result(ResultMeta { ok, err }) => vec![ok, err],
            Metadata::Map(MapMeta { key, value, .. }) => vec![key, value],
            Metadata::Option(ty)
            | Metadata::Array(ArrayMeta { ty, .. })
            | Metadata::Vec(VecMeta { ty, .. }) => {
                vec![ty]
            }
            Metadata::String | Metadata::Bool | Metadata::FixedPoint(_) | Metadata::Int(_) => {
                vec![]
            }
        }
    }

    // For `PhantomData` wrapped types schemas aren't expanded recursively.
    // This test ensures that schemas for those types are present as well.
    #[allow(clippy::string_slice)] // NOTE: There are no non-ascii characters in source code.
    fn find_missing_type_params(schemas: &MetaMap) -> HashMap<&str, Vec<&str>> {
        let mut missing_schemas = HashMap::new();

        for type_name in schemas.keys() {
            if let (Some(mut start), Some(end)) = (type_name.find('<'), type_name.rfind('>')) {
                start += 1;

                let mut angle_bracket_diff = 0_u8;
                for (i, c) in type_name[start..end].chars().enumerate() {
                    if c == '<' {
                        angle_bracket_diff += 1_u8;
                    }
                    if c == '>' {
                        angle_bracket_diff -= 1_u8;
                    }

                    if c == ',' && angle_bracket_diff == 0_u8 {
                        let generic = type_name[start..(start + i)].trim();

                        start += i + 1;
                        if !is_const_generic(generic) {
                            continue;
                        }

                        if !SCHEMALESS_TYPES.contains(&generic) && !schemas.contains_key(generic) {
                            missing_schemas
                                .entry(type_name.as_str())
                                .or_insert_with(Vec::new)
                                .push(generic);
                        }
                    }
                }

                let generic = type_name[start..end].trim();
                if !generic.is_empty()
                    && !is_const_generic(generic)
                    && !SCHEMALESS_TYPES.contains(&generic)
                    && !schemas.contains_key(generic)
                {
                    missing_schemas
                        .entry(type_name.as_str())
                        .or_insert_with(Vec::new)
                        .push(generic);
                }
            }
        }

        missing_schemas
    }

    fn find_missing_schemas(schemas: &MetaMap) -> HashMap<&str, Vec<&str>> {
        let mut missing_schemas = HashMap::new();

        for (type_name, schema) in schemas {
            let subtypes = get_subtypes(schema);

            for ty in subtypes {
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
    #[allow(clippy::use_debug)]
    #[allow(clippy::print_stdout)]
    fn no_missing_schemas() {
        let schemas = build_schemas();

        let missing_schemas = find_missing_schemas(&schemas);
        println!("Missing schemas: \n{:#?}", missing_schemas);

        assert!(missing_schemas.is_empty());
    }
}
