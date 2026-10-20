//! Real encoding errors retain every native reader and the original State fence.
use super::*;
use crate::{
    kura::Kura, query::store::LiveQueryStore,
    state::authority_registry::grouped_ownership::asset_balance_test_support as fixture,
};
fn state() -> State {
    State::new_for_testing(
        fixture::fixture(true),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    )
}
fn limits() -> LeafLimits {
    LeafLimits {
        max_tables: 1,
        max_rows: 2,
        max_payload_bytes: 16384,
        max_ordered_table_bytes: 32768,
        max_streamed_value_bytes: 65536,
    }
}
#[test]
fn asset_encoding_refusal_keeps_all_native_and_state_fences() {
    for changed in 0..11 {
        let state = state();
        let generation = state.state_view_generation();
        let checked = CheckedAssets::capture(&state.world, 16_777_216).unwrap();
        let snapshot = CanonicalTableLeafSet::paired_table_from_rows(
            "world.assets",
            LeafLimits {
                max_rows: 0,
                ..limits()
            },
            &state.ivm_execution_budget(),
            checked.rows().iter(),
        );
        assert!(matches!(&snapshot, Err(LeafError::RowLimit)));
        match changed {
            0 => {}
            1 => {
                state.world.assets.block().commit();
            }
            2 => {
                state.world.asset_definitions.block().commit();
            }
            3 => {
                state.world.domains.block().commit();
            }
            4 => {
                state.world.asset_definition_assets.block().commit();
            }
            5 => {
                state.world.asset_definition_asset_counts.block().commit();
            }
            6 => {
                state.world.assets_by_domain.block().commit();
            }
            7 => {
                state.world.asset_definition_holders.block().commit();
            }
            8 => {
                state
                    .world
                    .asset_definition_nonzero_holders
                    .block()
                    .commit();
            }
            9 => {
                let mut publication = state.state_view_publication();
                let guard = publication.begin();
                assert!(
                    finish_assets_encoding(&state, generation, checked, snapshot)
                        .unwrap()
                        .is_none()
                );
                drop(guard);
                continue;
            }
            10 => {
                let mut publication = state.state_view_publication();
                drop(publication.begin());
            }
            _ => unreachable!(),
        }
        let result = finish_assets_encoding(&state, generation, checked, snapshot);
        if changed == 0 {
            assert_eq!(result.err(), Some(LeafError::RowLimit));
        } else {
            assert!(result.unwrap().is_none());
        }
    }
}
#[test]
fn asset_capture_uses_original_pool_and_retries_without_partial_snapshot() {
    let _pin = crossbeam_epoch::pin();
    let state = state();
    let pool = state.ivm_execution_budget();
    let baseline = pool.reserved_bytes();
    let limit = pool.limit_bytes();
    pool.set_limit_bytes(0);
    assert!(matches!(
        capture_assets_once(&state, limits()),
        Err(LeafError::Admission(_) | LeafError::OrderedRange(_))
    ));
    assert_eq!(pool.reserved_bytes(), baseline);
    pool.set_limit_bytes(limit);
    let snapshot = capture_assets_once(&state, limits()).unwrap().unwrap();
    assert_eq!(snapshot.table_id(), "world.assets");
    assert_eq!(snapshot.row_count(), 1);
    assert!(pool.reserved_bytes() > baseline);
    drop(snapshot);
    assert_eq!(pool.reserved_bytes(), baseline);
}
