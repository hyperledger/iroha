//! Actual fallible World construction, original refusal owners and same-source retry.

use super::*;
use crate::execution_attempt::{ExecutionAttemptError, ExecutionDeferred};
use iroha_allocation::{AllocationBudget, AllocationRefusal};
use iroha_data_model::{
    asset::AssetBalancePolicy,
    kaigi::{
        KaigiId, KaigiRecord, KaigiRelayRegistration, NewKaigi, kaigi_metadata_key,
        kaigi_relay_metadata_key,
    },
    prelude::{Account, AssetDefinition, AssetDefinitionId, Domain, Json},
};
use iroha_model_base::{domain::DomainId, name::Name};
use iroha_primitives::numeric::NumericSpec;
use iroha_test_samples::ALICE_ID;
use ivm::ExecutionDeferral;
use std::error::Error;

fn limits(maximum: usize) -> norito::DecodeLimits {
    norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, maximum, usize::MAX)
}

fn reclaim(pool: &AllocationBudget, retained: usize) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while pool.reserved_bytes() != retained {
        assert!(
            std::time::Instant::now() < deadline,
            "original constructor owners did not retire: {} != {retained}",
            pool.reserved_bytes()
        );
        crossbeam_epoch::pin().flush();
        std::thread::yield_now();
    }
}

fn typed_source<'a, T: Error + 'static>(error: &'a (dyn Error + 'static)) -> Option<&'a T> {
    let mut current = Some(error);
    while let Some(error) = current {
        if let Some(source) = error.downcast_ref::<T>() {
            return Some(source);
        }
        current = error.source();
    }
    None
}

fn source(record: bool) -> (Domain, Name, Json) {
    let domain_id = DomainId::try_new("fallible-kaigi-world", "universal").unwrap();
    let (key, json) = if record {
        let call = KaigiId::new(domain_id.clone(), "retained-call".parse().unwrap());
        (
            kaigi_metadata_key(&call.call_name).unwrap(),
            Json::try_new(KaigiRecord::from_new(
                &NewKaigi::with_defaults(call, ALICE_ID.clone()),
                0,
            ))
            .unwrap(),
        )
    } else {
        (
            kaigi_relay_metadata_key(&ALICE_ID).unwrap(),
            Json::try_new(KaigiRelayRegistration {
                relay_id: ALICE_ID.clone(),
                hpke_public_key: vec![1, 2, 3],
                bandwidth_class: 1,
            })
            .unwrap(),
        )
    };
    let mut domain = Domain::new(domain_id).build(&ALICE_ID);
    domain.metadata_mut().insert(key.clone(), json.clone());
    (domain, key, json)
}

fn decoder_refusal(record: bool) {
    let (domain, key, json) = source(record);
    let domain_id = domain.id().clone();
    let account = Account::new(ALICE_ID.clone()).build(&ALICE_ID);
    let pointer = json.get().as_ptr();
    // Json clones share the same immutable backing; ordinary Domain/map/key graph
    // clones below are fixture input reconstruction, not admitted graph custody.
    assert_eq!(domain.metadata().get(&key).unwrap().get().as_ptr(), pointer);
    let pool = AllocationBudget::new(
        iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
    );
    let measurement = norito::core::DecodeBudgetContext::new(limits(usize::MAX));
    let measured = measurement
        .with(|| {
            World::try_with_execution_budget(
                [domain.clone()],
                [account.clone()],
                std::iter::empty::<AssetDefinition>(),
                &pool,
            )
        })
        .expect("genuine original constructor source is valid before refusal");
    let demand = usize::try_from(measurement.consumed_allocated_bytes()).unwrap();
    assert!(demand > 0);
    drop(measured);
    reclaim(&pool, 0);
    let original = norito::core::DecodeBudgetContext::try_new_owned(
        limits(demand.checked_mul(2).unwrap()),
        &pool,
    )
    .unwrap();
    let counter_bytes = norito::core::DecodeBudgetContext::allocation_layout().size();
    assert_eq!(pool.reserved_bytes(), counter_bytes);
    // Only this regression catches unwind: the real production constructor must
    // return a typed error, and no partially rebuilt World may escape.
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        original.with(|| {
            norito::with_decode_limits_scope(limits(0), || {
                World::try_with_execution_budget(
                    [domain.clone()],
                    [account.clone()],
                    std::iter::empty::<AssetDefinition>(),
                    &pool,
                )
            })
        })
    }));
    assert!(
        outcome.is_ok(),
        "fallible World constructor must return original Kaigi deferral instead of panicking"
    );
    let error = outcome.unwrap().err().expect("refusal cannot return World");
    reclaim(&pool, counter_bytes);
    let Some(ExecutionAttemptError::Deferred(reason)) =
        typed_source::<ExecutionAttemptError<String>>(&error)
    else {
        panic!("fallible World constructor must preserve original typed Kaigi deferral: {error:?}");
    };
    assert_eq!(
        reason,
        &ExecutionDeferred::from(ExecutionDeferral::ActiveMemoryCapacity)
    );
    assert!(reason.allocation_refusal().is_none());
    let consumed_before_retry = original.consumed_allocated_bytes();
    assert!(consumed_before_retry > 0);
    assert_eq!(json.get().as_ptr(), pointer);
    assert_eq!(domain.metadata().get(&key), Some(&json));
    assert_eq!(domain.metadata().get(&key).unwrap().get().as_ptr(), pointer);
    let retried = original
        .with(|| {
            World::try_with_execution_budget(
                [domain.clone()],
                [account],
                std::iter::empty::<AssetDefinition>(),
                &pool,
            )
        })
        .expect("same original pool/context and Json backing complete after refusal");
    assert_eq!(
        original.consumed_allocated_bytes() - consumed_before_retry,
        u64::try_from(demand).unwrap()
    );
    let domains = retried.domains.view();
    assert_eq!(
        domains.get(&domain_id).unwrap().metadata().get(&key),
        Some(&json)
    );
    assert_eq!(
        domains
            .get(&domain_id)
            .unwrap()
            .metadata()
            .get(&key)
            .unwrap()
            .get()
            .as_ptr(),
        pointer
    );
    drop(domains);
    if record {
        assert!(
            retried
                .kaigi_account_dependencies
                .view()
                .get(&ALICE_ID)
                .is_some()
        );
    } else {
        assert_eq!(
            retried.kaigi_relay_registry.view().get(&ALICE_ID),
            Some(&domain_id)
        );
    }
    let retained_world = pool.reserved_bytes() - counter_bytes;
    assert!(
        retained_world > 0,
        "original cells remain charged with returned World"
    );
    drop(error);
    drop(retried);
    reclaim(&pool, counter_bytes);
    drop(original);
    reclaim(&pool, 0);
}

#[test]
fn world_constructor_registration_refusal_is_fallible_and_retries_original_source() {
    if crate::unit_test_support::run_in_isolated_harness(
        "state::world_construction_tests::world_constructor_registration_refusal_is_fallible_and_retries_original_source",
    ) {
        return;
    }
    decoder_refusal(false);
}

#[test]
fn world_constructor_record_refusal_is_fallible_and_retries_original_source() {
    if crate::unit_test_support::run_in_isolated_harness(
        "state::world_construction_tests::world_constructor_record_refusal_is_fallible_and_retries_original_source",
    ) {
        return;
    }
    decoder_refusal(true);
}

#[test]
fn world_constructor_storage_refusal_preserves_release_before_entity_consumption_and_retries() {
    if crate::unit_test_support::run_in_isolated_harness(
        "state::world_construction_tests::world_constructor_storage_refusal_preserves_release_before_entity_consumption_and_retries",
    ) {
        return;
    }
    let pool = AllocationBudget::new(
        iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
    );
    let blocker = pool.try_reserve_bytes(pool.limit_bytes()).unwrap();
    let expected = WorldData::try_new_with_execution_budget(&pool)
        .err()
        .unwrap();
    assert!(matches!(
        &expected,
        mv::storage::AdmittedStorageError::Allocation(AllocationRefusal::Capacity { .. })
    ));
    let (domain, _, json) = source(false);
    let domain_id = domain.id().clone();
    let pointer = json.get().as_ptr();
    let consumed = std::cell::Cell::new(0);
    let domains = [domain.clone()]
        .into_iter()
        .inspect(|_| consumed.set(consumed.get() + 1));
    let accounts = [Account::new(ALICE_ID.clone()).build(&ALICE_ID)]
        .into_iter()
        .inspect(|_| consumed.set(consumed.get() + 1));
    let error = World::try_with_execution_budget(
        domains,
        accounts,
        std::iter::empty::<AssetDefinition>(),
        &pool,
    )
    .err()
    .unwrap();
    assert_eq!(
        consumed.get(),
        0,
        "original cell refusal precedes all entity consumption"
    );
    let original = typed_source::<mv::storage::AdmittedStorageError>(&error)
        .expect("actual original storage refusal must stay in the error source chain");
    assert_eq!(original, &expected);
    assert_eq!(original.release_wait(), expected.release_wait());
    assert_eq!(pool.reserved_bytes(), pool.limit_bytes());
    drop(blocker);
    let retried = World::try_with_execution_budget(
        [domain],
        [Account::new(ALICE_ID.clone()).build(&ALICE_ID)],
        std::iter::empty::<AssetDefinition>(),
        &pool,
    )
    .unwrap();
    let domains = retried.domains.view();
    let key = kaigi_relay_metadata_key(&ALICE_ID).unwrap();
    assert_eq!(
        domains
            .get(&domain_id)
            .unwrap()
            .metadata()
            .get(&key)
            .unwrap()
            .get()
            .as_ptr(),
        pointer
    );
    drop(domains);
    assert_eq!(
        retried.kaigi_relay_registry.view().get(&ALICE_ID),
        Some(&domain_id)
    );
    assert!(pool.reserved_bytes() > 0);
    drop(retried);
    drop(error);
    drop(expected);
    reclaim(&pool, 0);
}

#[test]
fn world_constructor_rejects_malformed_kaigi_without_panicking() {
    if crate::unit_test_support::run_in_isolated_harness(
        "state::world_construction_tests::world_constructor_rejects_malformed_kaigi_without_panicking",
    ) {
        return;
    }
    let pool = AllocationBudget::new(
        iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
    );
    for record in [false, true] {
        let (mut domain, key, _) = source(record);
        domain
            .metadata_mut()
            .insert(key, Json::new("malformed authoritative Kaigi source"));
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            World::try_with_execution_budget(
                [domain],
                [Account::new(ALICE_ID.clone()).build(&ALICE_ID)],
                std::iter::empty::<AssetDefinition>(),
                &pool,
            )
        }));
        assert!(
            outcome.is_ok(),
            "fallible World constructor must return malformed Kaigi rejection instead of panicking"
        );
        let error = outcome
            .unwrap()
            .err()
            .expect("malformed source cannot construct World");
        assert!(
            matches!(typed_source::<ExecutionAttemptError<String>>(&error), Some(ExecutionAttemptError::Rejected(message)) if message.contains("malformed")),
            "invalid source remains completed rejection: {error:?}"
        );
        drop(error);
        reclaim(&pool, 0);
    }
    // Shared initialization rejects invalid definitions before decoding the
    // accompanying malformed Kaigi source, exactly as the original constructor.
    let missing = DomainId::try_new("missing-definition-home", "universal").unwrap();
    for (policy, owner, expected) in [
        (
            AssetBalancePolicy::DataspaceRestricted,
            None,
            "requires an explicit owning domain",
        ),
        (
            AssetBalancePolicy::Global,
            Some(missing.clone()),
            "references missing owning domain",
        ),
    ] {
        let (mut domain, key, _) = source(false);
        domain
            .metadata_mut()
            .insert(key, Json::new("malformed later Kaigi source"));
        let definition = AssetDefinition::new(
            AssetDefinitionId::derive_from_components(
                missing.clone(),
                "original-input".parse().unwrap(),
            ),
            "Original invalid definition",
            NumericSpec::integer(),
            policy,
            owner,
        )
        .build(&ALICE_ID);
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            World::try_with_execution_budget(
                [domain],
                [Account::new(ALICE_ID.clone()).build(&ALICE_ID)],
                [definition],
                &pool,
            )
        }));
        assert!(
            outcome.is_ok(),
            "fallible World constructor must return invalid entity state instead of panicking"
        );
        let error = outcome
            .unwrap()
            .err()
            .expect("invalid entity cannot construct World");
        assert!(
            matches!(typed_source::<ExecutionAttemptError<String>>(&error), Some(ExecutionAttemptError::Rejected(message)) if message.contains(expected) && !message.contains("malformed")),
            "original entity validation precedence must remain: {error:?}"
        );
        drop(error);
        reclaim(&pool, 0);
    }
}
