//! Actual borrowed World projection restore/refusal and unchanged-source retry.

use super::*;
use iroha_data_model::{
    kaigi::{KaigiId, KaigiRecord, NewKaigi, kaigi_metadata_key},
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

#[test]
fn restored_kaigi_record_refusal_is_deferred_and_retries_original_snapshot() {
    if crate::unit_test_support::run_in_isolated_harness(
        "state::deserialize::kaigi_typed_deferral_tests::restored_kaigi_record_refusal_is_deferred_and_retries_original_snapshot",
    ) {
        return;
    }
    let domain = DomainId::try_new("kaigi-typed-restore", "universal").unwrap();
    let host = ALICE_ID.clone();
    let call = KaigiId::new(domain.clone(), "retained-record".parse::<Name>().unwrap());
    let record = KaigiRecord::from_new(&NewKaigi::with_defaults(call.clone(), host.clone()), 0);
    let key = kaigi_metadata_key(&call.call_name).unwrap();
    let original = Json::try_new(record.clone()).unwrap();
    let mut stored_domain = Domain::new(domain.clone()).build(&host);
    stored_domain
        .metadata_mut()
        .insert(key.clone(), original.clone());
    let world = World::with(
        [stored_domain],
        [Account::new(host.clone()).build(&host)],
        std::iter::empty::<AssetDefinition>(),
    );
    let encoded = json::to_json(&world).unwrap();
    let encoded_pointer = encoded.as_ptr();
    let pool = iroha_allocation::AllocationBudget::new(
        iroha_config::parameters::defaults::pipeline::IVM_EXECUTION_MAX_BYTES,
    );
    let ivm = IVM::new(0);
    let seed = IvmSeed {
        ivm: &ivm,
        _marker: PhantomData,
    };
    // Calibrate only the actual World field owner, not a replacement parser or cache.
    let fields = SnapshotJsonMap::parse(&encoded, "world").unwrap();
    let field_measurement = norito::core::DecodeBudgetContext::new(limits(usize::MAX));
    let decoded = field_measurement
        .with(|| decode_world_fields(&pool, fields, &seed))
        .unwrap();
    let prefix = usize::try_from(field_measurement.consumed_allocated_bytes()).unwrap();
    drop(decoded);
    reclaim(&pool, 0);
    let fields = SnapshotJsonMap::parse(&encoded, "world").unwrap();
    let total_measurement = norito::core::DecodeBudgetContext::new(limits(usize::MAX));
    let decoded = total_measurement
        .with(|| parse_world(&pool, fields, &seed))
        .expect("the genuine unchanged snapshot completes before testing local refusal");
    let demand = usize::try_from(total_measurement.consumed_allocated_bytes()).unwrap();
    assert!(
        demand > prefix,
        "the actual derived Kaigi read follows World field decoding"
    );
    drop(decoded);
    reclaim(&pool, 0);
    let original_context = norito::core::DecodeBudgetContext::try_new_owned(
        limits(demand.checked_mul(2).unwrap()),
        &pool,
    )
    .unwrap();
    let counter_bytes = norito::core::DecodeBudgetContext::allocation_layout().size();
    assert_eq!(pool.reserved_bytes(), counter_bytes);
    let fields = SnapshotJsonMap::parse(&encoded, "world").unwrap();
    let error = original_context
        .with(|| {
            norito::with_decode_limits_scope(limits(prefix), || parse_world(&pool, fields, &seed))
        })
        .err()
        .expect("a refused derived read cannot return a restored World");
    reclaim(&pool, counter_bytes);
    let StateRestoreError::ExecutionDeferred(actual) = error else {
        panic!(
            "Kaigi snapshot record refusal must preserve ExecutionDeferred before World publication: {error:?}"
        );
    };
    assert_eq!(actual.reason(), ExecutionDeferral::ActiveMemoryCapacity);
    assert!(
        actual.allocation_refusal().is_none(),
        "codec quota must not invent a pool release owner"
    );
    let original_reason = actual.reason();
    let original_decode = actual.decode_refusal().cloned();
    let original_phase = actual.phase();
    let crate::snapshot::TryReadError::StateExecutionDeferred(exported) =
        crate::snapshot::TryReadError::from(StateRestoreError::ExecutionDeferred(actual))
    else {
        panic!("the existing snapshot boundary must retain the exact Kaigi deferral");
    };
    assert_eq!(exported.reason(), original_reason);
    assert_eq!(exported.decode_refusal(), original_decode.as_ref());
    assert_eq!(exported.phase(), original_phase);
    assert!(exported.allocation_refusal().is_none());
    assert_eq!(encoded.as_ptr(), encoded_pointer);
    assert_eq!(json::to_json(&world).unwrap(), encoded);
    let consumed_before_retry = original_context.consumed_allocated_bytes();
    assert!(consumed_before_retry > u64::try_from(prefix).unwrap());
    let fields = SnapshotJsonMap::parse(&encoded, "world").unwrap();
    let restored = original_context
        .with(|| parse_world(&pool, fields, &seed))
        .expect("same original snapshot retries under its retained finite codec context");
    assert_eq!(
        original_context.consumed_allocated_bytes() - consumed_before_retry,
        u64::try_from(demand).unwrap()
    );
    assert_eq!(
        restored
            .domains
            .view()
            .get(&domain)
            .unwrap()
            .metadata()
            .get(&key),
        Some(&original)
    );
    assert!(
        restored
            .kaigi_account_dependencies
            .view()
            .get(&host)
            .is_some_and(|rows| rows.contains(&(2, domain.clone(), key.clone())))
    );
    drop(restored);
    reclaim(&pool, counter_bytes);
    drop(original_context);
    reclaim(&pool, 0);
    // Genuine metadata/key and lifecycle corruption remains completed rejection.
    for wrong_identity in [false, true] {
        let mut invalid = record.clone();
        if wrong_identity {
            invalid.id.call_name = "different-record".parse().unwrap();
        } else {
            invalid.ended_at_ms = Some(0);
        }
        {
            let mut domains = world.domains.block();
            domains
                .get_mut(&domain)
                .unwrap()
                .metadata_mut()
                .insert(key.clone(), Json::try_new(invalid).unwrap());
            domains.commit();
        }
        let altered = json::to_json(&world).unwrap();
        let error = parse_world(
            &pool,
            SnapshotJsonMap::parse(&altered, "world").unwrap(),
            &seed,
        )
        .err()
        .expect("invalid retained record must fail completed restoration");
        assert!(
            matches!(&error, StateRestoreError::Serialization(json::Error::InvalidField { field, .. }) if field == "kaigi_account_dependencies"),
            "genuine corrupt record remains terminal: {error:?}"
        );
        reclaim(&pool, 0);
    }
}
