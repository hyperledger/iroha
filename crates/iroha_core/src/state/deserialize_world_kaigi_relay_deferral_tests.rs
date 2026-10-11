//! Actual World relay-registry restore boundaries and original snapshot retry.

use super::*;
use crate::execution_attempt::ExecutionDeferred;
use iroha_data_model::{
    kaigi::{KaigiRelayAllowlist, KaigiRelayRegistration, kaigi_relay_metadata_key},
    prelude::{Account, AssetDefinition, Domain, Json},
};
use iroha_model_base::{domain::DomainId, name::Name};
use iroha_test_samples::ALICE_ID;
use ivm::ExecutionDeferral;

fn limits(maximum: usize) -> norito::DecodeLimits {
    norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, maximum, usize::MAX)
}

fn reclaim(pool: &iroha_allocation::AllocationBudget, retained: usize) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while pool.reserved_bytes() != retained {
        assert!(
            std::time::Instant::now() < deadline,
            "original World owners did not retire: {} != {retained}",
            pool.reserved_bytes()
        );
        crossbeam_epoch::pin().flush();
        std::thread::yield_now();
    }
}

fn restore_refusal(with_allowlist: bool) {
    let domain = DomainId::try_new("kaigi-relay-typed-restore", "universal").unwrap();
    let relay = ALICE_ID.clone();
    let registration_key = kaigi_relay_metadata_key(&relay).unwrap();
    let registration = Json::try_new(KaigiRelayRegistration {
        relay_id: relay.clone(),
        hpke_public_key: vec![1, 2, 3],
        bandwidth_class: 1,
    })
    .unwrap();
    let mut stored_domain = Domain::new(domain.clone()).build(&relay);
    stored_domain
        .metadata_mut()
        .insert(registration_key.clone(), registration.clone());
    let allowlist_key: Name = "kaigi_relay_allowlist".parse().unwrap();
    if with_allowlist {
        stored_domain.metadata_mut().insert(
            allowlist_key.clone(),
            Json::try_new(KaigiRelayAllowlist {
                allowed_relays: std::collections::BTreeSet::from([relay.clone()]),
            })
            .unwrap(),
        );
    }
    let world = World::with(
        [stored_domain],
        [Account::new(relay.clone()).build(&relay)],
        std::iter::empty::<AssetDefinition>(),
    );
    let encoded = json::to_json(&world).unwrap();
    let pointer = encoded.as_ptr();
    let pool = iroha_allocation::AllocationBudget::new(
        iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
    );
    let ivm = IVM::new(0);
    let seed = IvmSeed {
        ivm: &ivm,
        _marker: PhantomData,
    };
    let measurement = norito::core::DecodeBudgetContext::new(limits(usize::MAX));
    let fields = measurement
        .with(|| {
            decode_world_fields(
                &pool,
                SnapshotJsonMap::parse(&encoded, "world").unwrap(),
                &seed,
            )
        })
        .unwrap();
    let prefix = usize::try_from(measurement.consumed_allocated_bytes()).unwrap();
    drop(fields);
    reclaim(&pool, 0);
    let measurement = norito::core::DecodeBudgetContext::new(limits(usize::MAX));
    let decoded = measurement
        .with(|| {
            parse_world(
                &pool,
                SnapshotJsonMap::parse(&encoded, "world").unwrap(),
                &seed,
            )
        })
        .unwrap();
    let demand = usize::try_from(measurement.consumed_allocated_bytes()).unwrap();
    assert!(demand > prefix);
    drop(decoded);
    reclaim(&pool, 0);
    let context = norito::core::DecodeBudgetContext::try_new_owned(
        limits(demand.checked_mul(2).unwrap()),
        &pool,
    )
    .unwrap();
    let counter_bytes = norito::core::DecodeBudgetContext::allocation_layout().size();
    assert_eq!(pool.reserved_bytes(), counter_bytes);
    let error = context
        .with(|| {
            norito::with_decode_limits_scope(limits(prefix), || {
                parse_world(
                    &pool,
                    SnapshotJsonMap::parse(&encoded, "world").unwrap(),
                    &seed,
                )
            })
        })
        .err()
        .expect("refused registry read cannot publish a restored World");
    reclaim(&pool, counter_bytes);
    let StateRestoreError::ExecutionDeferred(reason) = error else {
        panic!(
            "Kaigi relay registry snapshot refusal must preserve ExecutionDeferred before World publication: {error:?}"
        );
    };
    assert_eq!(
        reason,
        ExecutionDeferred::from(ExecutionDeferral::ActiveMemoryCapacity)
    );
    assert!(
        reason.allocation_refusal().is_none(),
        "codec quota cannot invent a pool release owner"
    );
    let crate::snapshot::TryReadError::StateExecutionDeferred(exported) =
        crate::snapshot::TryReadError::from(StateRestoreError::ExecutionDeferred(reason.clone()))
    else {
        panic!("snapshot export must retain the exact original registry deferral")
    };
    assert_eq!(reason, exported);
    assert_eq!(encoded.as_ptr(), pointer);
    assert_eq!(json::to_json(&world).unwrap(), encoded);
    let before_retry = context.consumed_allocated_bytes();
    assert!(before_retry > u64::try_from(prefix).unwrap());
    let restored = context
        .with(|| {
            parse_world(
                &pool,
                SnapshotJsonMap::parse(&encoded, "world").unwrap(),
                &seed,
            )
        })
        .unwrap();
    assert_eq!(
        context.consumed_allocated_bytes() - before_retry,
        u64::try_from(demand).unwrap()
    );
    assert_eq!(
        restored.kaigi_relay_registry.view().get(&relay),
        Some(&domain)
    );
    assert_eq!(
        restored
            .domains
            .view()
            .get(&domain)
            .unwrap()
            .metadata()
            .get(&registration_key),
        Some(&registration)
    );
    drop(restored);
    reclaim(&pool, counter_bytes);
    drop(context);
    reclaim(&pool, 0);
    // The same real restore kernel still rejects malformed authoritative relay metadata.
    let corrupt_key = if with_allowlist {
        allowlist_key
    } else {
        registration_key
    };
    {
        let mut domains = world.domains.block();
        domains.get_mut(&domain).unwrap().metadata_mut().insert(
            corrupt_key,
            Json::new("genuine malformed retained relay source"),
        );
        domains.commit();
    }
    let corrupt = json::to_json(&world).unwrap();
    let error = parse_world(
        &pool,
        SnapshotJsonMap::parse(&corrupt, "world").unwrap(),
        &seed,
    )
    .err()
    .expect("corrupt relay source must remain completed rejection");
    assert!(
        matches!(&error, StateRestoreError::Serialization(json::Error::InvalidField { field, .. })
        if field == "kaigi_relay_registry"),
        "corrupt source remains terminal: {error:?}"
    );
    reclaim(&pool, 0);
}

#[test]
fn restored_registration_refusal_retains_original_snapshot_and_retry() {
    if crate::unit_test_support::run_in_isolated_harness(
        "state::deserialize::kaigi_relay_typed_deferral_tests::restored_registration_refusal_retains_original_snapshot_and_retry",
    ) {
        return;
    }
    restore_refusal(false);
}

#[test]
fn restored_allowlist_refusal_retains_original_snapshot_and_retry() {
    if crate::unit_test_support::run_in_isolated_harness(
        "state::deserialize::kaigi_relay_typed_deferral_tests::restored_allowlist_refusal_retains_original_snapshot_and_retry",
    ) {
        return;
    }
    restore_refusal(true);
}
