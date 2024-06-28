//! Smart contract which executes [`FindAllAssets`] and saves cursor to the owner's metadata.

#![no_std]

#[cfg(not(test))]
extern crate panic_halt;

extern crate alloc;

use alloc::{collections::BTreeSet, string::ToString, vec::Vec};

use iroha_smart_contract::{
    data_model::query::predicate::{string::StringPredicate, value::QueryOutputPredicate},
    prelude::*,
    QueryOutputCursor,
};
use lol_alloc::{FreeListAllocator, LockedAllocator};

#[global_allocator]
static ALLOC: LockedAllocator<FreeListAllocator> = LockedAllocator::new(FreeListAllocator::new());

getrandom::register_custom_getrandom!(iroha_smart_contract::stub_getrandom);

/// Create two asset definitions in the looking_glass domain, query all asset definitions, filter them to only be in the looking_glass domain, check that the results are consistent
#[iroha_smart_contract::main]
fn main(_owner: AccountId) {
    // create the "looking_glass" domain
    Register::domain(Domain::new("looking_glass".parse().unwrap()))
        .execute()
        .dbg_unwrap();

    // create two asset definitions inside the `looking_glass` domain
    let time_id: AssetDefinitionId = "time#looking_glass".parse().dbg_unwrap();
    let space_id: AssetDefinitionId = "space#looking_glass".parse().dbg_unwrap();

    Register::asset_definition(AssetDefinition::new(
        time_id.clone(),
        AssetType::Numeric(NumericSpec::default()),
    ))
    .execute()
    .dbg_unwrap();

    Register::asset_definition(AssetDefinition::new(
        space_id.clone(),
        AssetType::Numeric(NumericSpec::default()),
    ))
    .execute()
    .dbg_unwrap();

    // genesis registers some more asset definitions, but we apply a filter to find only the ones from the `looking_glass` domain
    let cursor: QueryOutputCursor<Vec<AssetDefinition>> = FindAllAssetsDefinitions
        .filter(QueryOutputPredicate::Identifiable(
            StringPredicate::EndsWith("#looking_glass".to_string()),
        ))
        .execute()
        .dbg_unwrap();

    let mut asset_definition_ids = BTreeSet::new();

    for asset_definition in cursor {
        let asset_definition = asset_definition.dbg_unwrap();
        asset_definition_ids.insert(asset_definition.id().clone());
    }

    assert_eq!(
        asset_definition_ids,
        [time_id, space_id].into_iter().collect()
    );
}
