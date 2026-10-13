//! Telemetry test construction retains the World admission owner and custom registry.

use super::*;

#[test]
fn telemetry_constructor_keeps_original_world_pool_and_accepts_block_admission() {
    let world = World::default();
    let original = world.sccp_committee_generations.allocation_budget().clone();
    #[cfg(feature = "telemetry")]
    let metrics = std::sync::Arc::new(crate::telemetry::Metrics::default());
    #[cfg(feature = "telemetry")]
    let telemetry = StateTelemetry::new(std::sync::Arc::clone(&metrics), true);
    #[cfg(not(feature = "telemetry"))]
    let telemetry = StateTelemetry::default();
    let state = State::with_telemetry(
        world,
        crate::kura::Kura::blank_kura_for_testing(),
        crate::query::store::LiveQueryStore::start_test(),
        telemetry,
    );
    assert!(original.same_pool(&state.ivm_execution_budget()));
    assert!(original.same_pool(state.world.sccp_committee_generations.allocation_budget()));
    #[cfg(feature = "telemetry")]
    assert!(std::ptr::eq(
        state.telemetry.metrics_ref(),
        metrics.as_ref()
    ));
    let header =
        iroha_data_model::block::BlockHeader::new(core::num::NonZeroU64::MIN, None, None, 0, 0);
    let block = state
        .try_block(header.clone())
        .expect("original World admission scope");
    drop(block);
    assert!(
        state.try_block(header).is_ok(),
        "same-pool retry must remain admitted"
    );
}
