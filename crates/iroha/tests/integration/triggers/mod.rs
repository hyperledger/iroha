use assert_matches::assert_matches;
use iroha::{client, client::Client};
use iroha_data_model::{
    asset::{AssetId, AssetValue},
    prelude::{Numeric, QueryBuilderExt},
};

mod by_call_trigger;
mod data_trigger;
mod event_trigger;
mod orphans;
// FIXME: rewrite all in async and with shorter timings
mod time_trigger;
mod trigger_rollback;

fn get_asset_value(client: &Client, asset_id: AssetId) -> Numeric {
    let asset = client
        .query(client::asset::all())
        .filter_with(|asset| asset.id.eq(asset_id))
        .execute_single()
        .unwrap();

    assert_matches!(*asset.value(), AssetValue::Numeric(val) => val)
}
