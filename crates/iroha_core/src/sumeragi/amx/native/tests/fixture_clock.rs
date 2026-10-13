//! Synthetic fixture clocks follow original work; explicitly injected clocks retain CT5 authority.

use super::*;
use iroha_primitives::time::TimeSource;
use std::time::Duration;

#[test]
fn default_synthetic_clock_executes_original_amx_due_work_at_its_signed_time() {
    let mut roots = Roots::new();
    let transaction = roots.transaction(100, 0xC8);
    let tx = transaction.id().unwrap();
    let signed = roots.global.sign(
        &global_config().genesis_key,
        [BeginAmxV1 { transaction }.into()],
        2_999,
    );
    assert_eq!(roots.global.commit_at(3_000, vec![signed]), [true]);
    assert_eq!(roots.global.committed(4).block_time_ms(), 3_000);
    assert!(
        roots
            .global
            .state()
            .view()
            .world()
            .sumeragi_amx()
            .transaction(&tx)
            .is_some(),
        "the actual historical Begin must execute through the normal due-work guard"
    );
}

#[test]
fn explicit_fixture_clock_cannot_be_rewritten_to_authorize_stale_amx_due_work() {
    let (clock, source) = TimeSource::new_mock(Duration::from_millis(2_000));
    let mut roots = Roots::new_with_time_source(source.clone());
    let transaction = roots.transaction(100, 0xC9);
    let tx = transaction.id().unwrap();
    let lag = roots
        .global
        .state()
        .view()
        .world()
        .parameters()
        .sumeragi()
        .due_work_max_lag_ms();
    let wall = Duration::from_millis(3_000 + lag + 1);
    clock.set(wall);
    let signed = roots.global.sign(
        &global_config().genesis_key,
        [BeginAmxV1 { transaction }.into()],
        2_999,
    );
    let proposal = roots.global.proposal(Some(3_000), vec![signed]);
    let refusal = roots
        .global
        .begin_proposal(proposal, iroha_sumeragi::types::ControlWitness::default())
        .err()
        .expect("an explicit stale clock must keep the original due-work refusal");
    assert!(refusal.contains("stale due work"), "{refusal}");
    assert_eq!(
        source.now(),
        wall,
        "the caller retains exclusive clock control"
    );
    assert_eq!(roots.global.height(), 3);
    assert!(
        roots
            .global
            .state()
            .view()
            .world()
            .sumeragi_amx()
            .transaction(&tx)
            .is_none(),
        "local freshness refusal cannot publish the provisional Begin"
    );
}
