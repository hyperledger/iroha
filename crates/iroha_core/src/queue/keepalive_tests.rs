// Shared carriers retain original queue ownership until replaced through the removal owner.
#[test]
fn sccp_keepalive_queue_refresh_releases_only_stale_own_custody() {
    use crate::smartcontracts::isi::sccp::{
        committee_storage::CommitteeFixtureStorage as _, test_support::sample_generation,
    };
    use iroha_data_model::{isi::chain::Keepalive, sccp::params::SccpParametersV1};
    let parameters = SccpParametersV1::taira_default();
    let generation = sample_generation(1);
    let deadline = generation.start_timestamp_ms + parameters.committee_heartbeat_ms;
    let world = world_with_test_domains();
    {
        let mut block = world.block();
        *block.sccp_parameters.get_mut() = Some(parameters);
        *block.sccp_committee_current.get_mut() = 1;
        block.sccp_committee_generations.insert(1, generation);
        block.commit();
    }
    let mut state = State::new(
        world,
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    install_single_validator_topology_for_queue_test(&mut state, 0xB7);
    let (clock, time) = TimeSource::new_mock(Duration::from_millis(deadline));
    let queue = Queue::test(config_factory(), &time);
    let key = checked_random_queue_keypair();
    let authority = AccountId::new(key.public_key().clone());
    let carrier = || {
        accepted_tx_with(
            authority.clone(),
            &key,
            &time,
            vec![Keepalive {}.into()],
            Metadata::default(),
        )
    };
    let original = carrier();
    let old_hash = original.hash_as_entrypoint();
    assert!(state.view().world().accounts().get(&authority).is_none());
    queue
        .push(original, state.view())
        .expect("standalone unregistered Ed25519 carrier is fee-free");
    assert!(queue.has_any_fresh_pending_keepalive(&state.view(), deadline));
    assert_eq!(
        queue.has_fresh_pending_keepalive(&state.view(), &authority, deadline),
        Ok(true)
    );
    clock.advance(Duration::from_millis(30_002));
    let now = deadline + 30_002;
    assert!(!queue.has_any_fresh_pending_keepalive(&state.view(), now));
    assert_eq!(
        queue.has_fresh_pending_keepalive(&state.view(), &authority, now),
        Ok(false)
    );
    assert!(!queue.txs.contains_key(&old_hash));
    assert!(!queue.routing_plans.contains_key(&old_hash));
    assert_eq!(
        queue
            .pending_sccp_exempt
            .lock()
            .keepalive_holder(&authority),
        None
    );
    let replacement = carrier();
    let new_hash = replacement.hash_as_entrypoint();
    assert_ne!(
        old_hash, new_hash,
        "freshness requires a new original signature"
    );
    queue
        .push(replacement, state.view())
        .expect("stale holder's index and reservations were released");
    assert!(queue.has_any_fresh_pending_keepalive(&state.view(), now));
    let other_key = checked_random_queue_keypair();
    let other = AccountId::new(other_key.public_key().clone());
    assert_eq!(
        queue.has_fresh_pending_keepalive(&state.view(), &other, now),
        Ok(false)
    );
    assert_eq!(
        queue
            .pending_sccp_exempt
            .lock()
            .keepalive_holder(&authority),
        Some(new_hash)
    );
    assert_eq!(queue.active_len(), 1);
}
