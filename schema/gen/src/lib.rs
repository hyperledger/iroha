//! Iroha schema generation support library. Contains the
//! `build_schemas` `fn`, which is the function which decides which
//! types are included in the schema.
#![allow(clippy::arithmetic_side_effects)]

use iroha_data_model::{block::stream::prelude::*, query::error::QueryExecutionFailure};
use iroha_genesis::RawGenesisBlock;
use iroha_schema::prelude::*;

/// Builds the schema for the current state of Iroha.
///
/// You should only include the top-level types, because other types
/// shall be included recursively.
pub fn build_schemas() -> MetaMap {
    use iroha_data_model::prelude::*;

    macro_rules! schemas {
        ($($t:ty),* $(,)?) => {{
            let mut out = MetaMap::new(); $(
            <$t as IntoSchema>::update_schema_map(&mut out); )*
            out
        }};
    }

    schemas! {
        // TODO: Should genesis belong to schema? #3284
        RawGenesisBlock,

        QueryExecutionFailure,
        VersionedBlockMessage,
        VersionedBlockSubscriptionRequest,
        VersionedEventMessage,
        VersionedEventSubscriptionRequest,
        VersionedPaginatedQueryResult,
        VersionedSignedQueryRequest,
        VersionedPendingTransactions,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use super::*;

    // NOTE: These type parameters should not be have their schema exposed
    // By default `PhantomData` wrapped types schema will not be included
    const SCHEMALESS_TYPES: [&str; 2] =
        ["MerkleTree<VersionedSignedTransaction>", "RegistrableBox"];

    fn is_const_generic(generic: &str) -> bool {
        generic.parse::<usize>().is_ok()
    }

    // For `PhantomData` wrapped types schemas aren't expanded recursively.
    // This test ensures that schemas for those types are present as well.
    fn find_missing_type_params(type_names: &HashSet<String>) -> HashMap<&str, Vec<&str>> {
        let mut missing_schemas = HashMap::<&str, _>::new();

        for type_name in type_names {
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

                        if !SCHEMALESS_TYPES.contains(&generic) && !type_names.contains(generic) {
                            missing_schemas
                                .entry(type_name)
                                .or_insert_with(Vec::new)
                                .push(generic);
                        }
                    }
                }

                let generic = type_name[start..end].trim();
                if !generic.is_empty()
                    && !is_const_generic(generic)
                    && !SCHEMALESS_TYPES.contains(&generic)
                    && !type_names.contains(generic)
                {
                    missing_schemas
                        .entry(type_name)
                        .or_insert_with(Vec::new)
                        .push(generic);
                }
            }
        }

        missing_schemas
    }

    #[test]
    fn no_missing_schemas() {
        let type_names = build_schemas()
            .into_iter()
            .map(|(_, (name, _))| name)
            .collect();
        let missing_schemas = find_missing_type_params(&type_names);

        assert!(
            missing_schemas.is_empty(),
            "Missing schemas: \n{missing_schemas:#?}"
        );
    }
}
