//! Restore-cut checks using the real public DKG and exact BLS generation fixture.

use super::*;

#[test]
fn committee_restore_beacon_matches_both_sides_of_activation_cut() {
    let mut fixture = fixture(7);
    validate_current_beacon(
        &fixture.world.view(),
        &fixture.incumbent,
        &fixture.authorization,
        19,
    )
    .unwrap();
    let authorization = outcome(&fixture, true);
    let credentials = *fixture.transition.credentials.as_ref().unwrap();
    let generation = fixture.transition.preparation.generation();
    assert!(
        validate_current_beacon(&fixture.world.view(), &generation, &authorization, 20,).is_err(),
        "an old active pointer cannot restore an activated authority"
    );
    let BeaconEpochBindingV1::Installed(previous) = fixture.authorization.beacon else {
        panic!("fixture has an installed incumbent");
    };
    let mut old = fixture
        .world
        .global_beacon_key_sessions
        .view()
        .get(&previous.session_id)
        .unwrap()
        .clone();
    let mut next = fixture
        .world
        .global_beacon_key_sessions
        .view()
        .get(&credentials.beacon.session_id)
        .unwrap()
        .clone();
    old.retire(21).unwrap();
    next.activate(21).unwrap();
    fixture
        .world
        .global_beacon_key_sessions
        .insert(previous.session_id, old);
    fixture
        .world
        .global_beacon_key_sessions
        .insert(credentials.beacon.session_id, next.clone());
    fixture.world.global_beacon_active_session.insert(
        GLOBAL_THRESHOLD_BEACON_SINGLETON_KEY,
        credentials.beacon.session_id,
    );
    for cut in [20, 21, 29] {
        validate_current_beacon(&fixture.world.view(), &generation, &authorization, cut)
            .expect("boundary post-state already names the next-height signer");
    }
    next.activated_at_height = Some(20);
    fixture
        .world
        .global_beacon_key_sessions
        .insert(credentials.beacon.session_id, next.clone());
    assert!(
        validate_current_beacon(&fixture.world.view(), &generation, &authorization, 20).is_err(),
        "even a well-formed lifecycle cannot change the certified activation height"
    );
    next.activated_at_height = Some(21);
    fixture
        .world
        .global_beacon_key_sessions
        .insert(credentials.beacon.session_id, next);
    let mut changed = authorization;
    let BeaconEpochBindingV1::Installed(ref mut binding) = changed.beacon else {
        unreachable!()
    };
    binding.transcript_hash[0] ^= 1;
    assert!(validate_current_beacon(&fixture.world.view(), &generation, &changed, 20).is_err());
}

#[test]
fn committee_restore_bootstrap_permits_only_finalized_next_height_custody() {
    let fixture = fixture(4);
    let authorization = ValidatorEpochAuthorizationV1::genesis(&fixture.incumbent, 10).unwrap();
    validate_current_beacon(&fixture.world.view(), &fixture.incumbent, &authorization, 4)
        .expect("the bootstrap ceremony finalized at four and activates at five");
    assert!(
        validate_current_beacon(&fixture.world.view(), &fixture.incumbent, &authorization, 3)
            .is_err(),
        "a snapshot cannot contain a future finalized/active ceremony"
    );
    let world = World::new();
    validate_current_beacon(&world.view(), &fixture.incumbent, &authorization, 1)
        .expect("genesis has no finalized beacon ceremony yet");
}

#[test]
fn committee_restore_requires_retained_finality_even_when_all_progress_is_omitted() {
    let fixture = fixture(4);
    let kura = crate::kura::Kura::blank_kura_for_testing();
    let world = World::new();
    let chain_id = iroha_model_base::chain::ChainId::from("committee-restore-cut");
    validate_committed_progress(
        &world.view(),
        &chain_id,
        fixture.incumbent.network_id,
        &[],
        &kura,
        &iroha_allocation::AllocationBudget::new(64 * 1024 * 1024),
    )
    .expect("empty uncommitted State needs no finality");
    let hash = HashOf::from_untyped_unchecked(Hash::new(b"missing-certified-cut"));
    let error = validate_committed_progress(
        &world.view(),
        &chain_id,
        fixture.incumbent.network_id,
        &[hash],
        &kura,
        &iroha_allocation::AllocationBudget::new(64 * 1024 * 1024),
    )
    .expect_err("absence of progress does not permit absence of its authentication");
    assert_eq!(
        error,
        crate::execution_attempt::ExecutionAttemptError::Rejected(
            crate::sumeragi::certified_chain::ChainReadError::NotInView { height: 1 }.to_string()
        )
    );
    assert!(
        validate_committed_progress(
            &fixture.world.view(),
            &chain_id,
            fixture.incumbent.network_id,
            &[],
            &kura,
            &iroha_allocation::AllocationBudget::new(64 * 1024 * 1024),
        )
        .is_err(),
        "a pre-genesis snapshot cannot invent preparation progress"
    );
}

#[test]
fn committee_restore_authenticates_actual_native_prefix_and_rejects_schedule_omission() {
    crate::sumeragi::threads::sumeragi_thread_builder("committee-restore-native")
        .spawn(|| {
            use crate::state::StateReadOnly as _;
            use crate::sumeragi::test_chain::{CertifiedTestChain, TestChainConfig};
            let mut chain = CertifiedTestChain::start(TestChainConfig::new(World::new(), 1_000))
                .expect("actual signed genesis and original execution");
            for height in [1, 2, 3] {
                if height > 1 {
                    chain.commit(Vec::new());
                }
                let view = chain.state().view();
                let hashes = view.block_hashes().iter().copied().collect::<Vec<_>>();
                assert_eq!(hashes.len() as u64, height);
                validate_committed_progress(
                    view.world(),
                    view.chain_id(),
                    *view.network_id(),
                    &hashes,
                    chain.kura(),
                    &chain.state().ivm_execution_budget(),
                )
                .expect("same verified native cut and complete schedule");
                assert!(
                    validate_committed_progress(
                        &World::new().view(),
                        view.chain_id(),
                        *view.network_id(),
                        &hashes,
                        chain.kura(),
                        &chain.state().ivm_execution_budget(),
                    )
                    .is_err(),
                    "a retained certified prefix cannot excuse omission of its schedule"
                );
                let mut changed = hashes.clone();
                changed[0] = HashOf::from_untyped_unchecked(Hash::new(b"different-pinned-genesis"));
                assert!(
                    validate_committed_progress(
                        view.world(),
                        view.chain_id(),
                        *view.network_id(),
                        &changed,
                        chain.kura(),
                        &chain.state().ivm_execution_budget(),
                    )
                    .is_err()
                );
            }
        })
        .unwrap()
        .join()
        .unwrap();
}
