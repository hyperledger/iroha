//! Tests for `FindAbiVersion` singular query.

use iroha_core::state::State;
#[test]
fn find_abi_version_default_is_v1() {
    use iroha_core::{
        kura::Kura, query::store::LiveQueryStore, smartcontracts::ValidSingularQuery,
    };
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    let world = iroha_core::state::World::default();
    let state = State::new_for_testing(world, kura, query_handle);
    let q = iroha_data_model::query::runtime::prelude::FindAbiVersion;
    let resp = q.execute(&state.view()).expect("execute query");
    assert_eq!(resp.abi_version, 1, "v1 must be active by default");
}
