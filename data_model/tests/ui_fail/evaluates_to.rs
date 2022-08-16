//! This test ensures that [`EvaluatesTo`] provides compile-time strong typing

use iroha_data_model::prelude::*;

fn get_assets_by_account_id(_account_id: impl Into<EvaluatesTo<AccountId>>) -> Vec<Asset> {
    Vec::new()
}

fn main() {
    let asset_definition_id: <AssetDefinition as Identifiable>::Id = "rose#wonderland".parse().unwrap();
    get_assets_by_account_id(asset_definition_id);
}
