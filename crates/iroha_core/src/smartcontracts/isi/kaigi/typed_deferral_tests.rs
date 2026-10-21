//! Actual Kaigi instruction refusal, sticky publication and original-source retry controls.

use super::*;
use crate::{kura::Kura, query::store::LiveQueryStore, state::State};
use core::num::NonZeroU64;
use iroha_data_model::{Registrable, asset::AssetDefinition, prelude::Account};
use iroha_test_samples::ALICE_ID;
use ivm::ExecutionDeferral;

/// The real retired JSON scope must retain its opaque cause, not only its reason.
/// Exact same-attempt/pool comparisons live in the dedicated custody regressions.
fn assert_captured_scope(owner: &crate::execution_attempt::ExecutionDeferred) {
    assert_eq!(owner.reason(), ExecutionDeferral::ActiveMemoryCapacity);
    assert!(
        owner.allocation_refusal().is_none(),
        "decoder custody must not invent a pool release observation"
    );
    let original = owner
        .decode_refusal()
        .expect("actual JSON scope refusal must retain its captured cause");
    assert_eq!(
        original.kind(),
        norito::core::DecodeLocalRefusalKind::EnclosingLimit
    );
    assert!(matches!(
        original.clone().into_error(),
        norito::Error::ScopedDecodeResource(_)
    ));
}

fn create_instruction(record: &KaigiRecord, host: &AccountId) -> CreateKaigi {
    CreateKaigi {
        call: iroha_data_model::kaigi::NewKaigi::with_defaults(record.id.clone(), host.clone()),
        commitment: None,
        nullifier: None,
        roster_root: None,
        proof: None,
    }
}

fn join_instruction(record: &KaigiRecord, participant: &AccountId) -> JoinKaigi {
    JoinKaigi {
        call_id: record.id.clone(),
        participant: participant.clone(),
        commitment: None,
        nullifier: None,
        roster_root: None,
        proof: None,
    }
}

fn seeded_state(record: &KaigiRecord, host: &AccountId, participant: &AccountId) -> State {
    State::new(
        World::with(
            [Domain::new(record.id.domain_id.clone()).build(&ALICE_ID)],
            [host.clone(), participant.clone()].map(|id| Account::new(id).build(&ALICE_ID)),
            std::iter::empty::<AssetDefinition>(),
        ),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    )
}

fn unlimited_decode_limits() -> norito::DecodeLimits {
    norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, usize::MAX)
}

#[test]
fn stored_record_refusal_is_sticky_and_retries_original_json_without_publication() {
    // Keep committed fixture generations in the exact pool baseline; unrelated
    // epoch reclamation must not look like a refund of the decoder's own backing.
    let _retirement_pin = crossbeam_epoch::pin();
    let (record, host, participant) = super::tests::new_record(KaigiPrivacyMode::Transparent);
    let state = seeded_state(&record, &host, &participant);
    let pool = state.ivm_execution_budget();
    let mut block = state.block(iroha_data_model::block::BlockHeader::new(
        NonZeroU64::MIN,
        None,
        None,
        0,
        0,
    ));
    {
        let mut transaction = block.transaction();
        create_instruction(&record, &host)
            .execute(&host, &mut transaction)
            .expect("genuine Kaigi create instruction");
        transaction.apply();
    }
    // Publish only the successful fixture setup; no refused carrier is committed.
    block.commit_world_overlay_for_testing().unwrap();
    let mut block = state.block(iroha_data_model::block::BlockHeader::new(
        NonZeroU64::MIN,
        None,
        None,
        0,
        0,
    ));
    let key = metadata_key(&record.id).unwrap();
    let original = block
        .world
        .domain(&record.id.domain_id)
        .unwrap()
        .metadata()
        .get(&key)
        .unwrap()
        .clone();
    let original_pointer = original.get().as_ptr();
    let dependencies = block
        .world
        .kaigi_account_dependencies
        .iter()
        .map(|(id, dependencies)| (id.clone(), dependencies.clone()))
        .collect::<BTreeMap<_, _>>();
    let measurement = norito::core::DecodeBudgetContext::new(unlimited_decode_limits());
    {
        let mut transaction = block.transaction();
        let instruction = join_instruction(&record, &participant);
        measurement
            .with(|| instruction.execute(&participant, &mut transaction))
            .expect("measure the unchanged real JoinKaigi call before testing its refusal");
    }
    let demand = usize::try_from(measurement.consumed_allocated_bytes()).unwrap();
    assert!(demand > 0);
    let reserved = pool.reserved_bytes();
    let original_context = norito::core::DecodeBudgetContext::try_new_owned(
        norito::DecodeLimits::new(
            usize::MAX,
            usize::MAX,
            usize::MAX,
            demand.checked_mul(2).unwrap(),
            usize::MAX,
        ),
        &pool,
    )
    .unwrap();
    assert_eq!(
        pool.reserved_bytes(),
        reserved + norito::core::DecodeBudgetContext::allocation_layout().size()
    );
    let probe: Name = "kaigi-refused-journal".parse().unwrap();
    {
        let mut transaction = block.transaction();
        // A genuine earlier overlay write must also remain unpublished after refusal.
        transaction
            .world
            .domain_mut(&record.id.domain_id)
            .unwrap()
            .metadata_mut()
            .insert(probe.clone(), Json::new("unpublished original journal"));
        let instruction = join_instruction(&record, &participant);
        let error = original_context
            .with(|| {
                norito::with_decode_limits_scope(
                    norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
                    || instruction.execute(&participant, &mut transaction),
                )
            })
            .expect_err("the original stored record must refuse a zero inner quota");
        assert_eq!(
            transaction
                .borrow_execution_deferral()
                .map(|owner| owner.reason()),
            Some(ExecutionDeferral::ActiveMemoryCapacity),
            "Kaigi record refusal must retain its original sticky execution deferral: {error:?}"
        );
        assert_captured_scope(&transaction.borrow_execution_deferral().unwrap());
        assert_eq!(transaction.last_tx_gas_used, 0);
        assert!(transaction.world.take_external_events().is_empty());
        transaction.apply();
    }
    assert!(
        block
            .world
            .domain(&record.id.domain_id)
            .unwrap()
            .metadata()
            .get(&probe)
            .is_none()
    );
    let stored = block
        .world
        .domain(&record.id.domain_id)
        .unwrap()
        .metadata()
        .get(&key)
        .unwrap();
    assert_eq!(
        stored.get().as_ptr(),
        original_pointer,
        "refusal retains the original borrowed Json backing"
    );
    assert_eq!(stored, &original);
    assert!(
        block
            .world
            .kaigi_account_dependencies
            .iter()
            .map(|(id, dependencies)| (id.clone(), dependencies.clone()))
            .eq(dependencies
                .iter()
                .map(|(id, dependencies)| (id.clone(), dependencies.clone())))
    );
    // A refused apply poisons its carrier. Retire that carrier, then retry over
    // the same committed source, pool and finite decode owner in a fresh block.
    drop(block);
    let mut block = state.block(iroha_data_model::block::BlockHeader::new(
        NonZeroU64::MIN,
        None,
        None,
        0,
        0,
    ));
    let stored = block
        .world
        .domain(&record.id.domain_id)
        .unwrap()
        .metadata()
        .get(&key)
        .unwrap();
    assert_eq!(stored, &original);
    assert_eq!(stored.get().as_ptr(), original_pointer);
    assert!(
        block
            .world
            .kaigi_account_dependencies
            .iter()
            .map(|(id, dependencies)| (id.clone(), dependencies.clone()))
            .eq(dependencies
                .iter()
                .map(|(id, dependencies)| (id.clone(), dependencies.clone())))
    );
    let before_retry = original_context.consumed_allocated_bytes();
    assert!(before_retry > 0 && before_retry <= u64::try_from(demand).unwrap());
    {
        let mut transaction = block.transaction();
        let instruction = join_instruction(&record, &participant);
        original_context
            .with(|| instruction.execute(&participant, &mut transaction))
            .expect("same original stored Json retries in the original finite context");
        assert!(!transaction.is_execution_deferred());
        transaction.apply();
    }
    assert_eq!(
        original_context.consumed_allocated_bytes() - before_retry,
        u64::try_from(demand).unwrap()
    );
    let retried: KaigiRecord = block
        .world
        .domain(&record.id.domain_id)
        .unwrap()
        .metadata()
        .get(&key)
        .unwrap()
        .try_into_any_norito()
        .unwrap();
    assert!(retried.participants.contains(&participant));
    assert!(
        block
            .world
            .kaigi_account_dependencies
            .get(&participant)
            .is_some_and(|rows| rows.contains(&(
                KAIGI_DEPENDENCY_ACTIVE_CALL,
                record.id.domain_id.clone(),
                key
            )))
    );
    // The original counter backing is charged until its owner retires. No graph funding is inferred.
    let with_counter = pool.reserved_bytes();
    drop(original_context);
    assert_eq!(
        pool.reserved_bytes() + norito::core::DecodeBudgetContext::allocation_layout().size(),
        with_counter
    );
}

#[test]
fn indexed_record_refusal_preserves_unregister_guard_and_original_retry() {
    let (record, host, participant) = super::tests::new_record(KaigiPrivacyMode::Transparent);
    let state = seeded_state(&record, &host, &participant);
    let pool = state.ivm_execution_budget();
    let mut block = state.block(iroha_data_model::block::BlockHeader::new(
        NonZeroU64::MIN,
        None,
        None,
        0,
        0,
    ));
    {
        let mut transaction = block.transaction();
        create_instruction(&record, &host)
            .execute(&host, &mut transaction)
            .unwrap();
        transaction.apply();
    }
    let key = metadata_key(&record.id).unwrap();
    let original = block
        .world
        .domain(&record.id.domain_id)
        .unwrap()
        .metadata()
        .get(&key)
        .unwrap()
        .clone();
    let original_pointer = original.get().as_ptr();
    let measurement = norito::core::DecodeBudgetContext::new(unlimited_decode_limits());
    {
        let transaction = block.transaction();
        let completed = measurement
            .with(|| ensure_kaigi_account_can_unregister(&transaction, &host))
            .expect_err("an active call genuinely prevents unregistering its original host");
        assert!(completed.to_string().contains("referenced by active Kaigi"));
        assert!(!transaction.is_execution_deferred());
    }
    let demand = usize::try_from(measurement.consumed_allocated_bytes()).unwrap();
    assert!(demand > 0);
    let original_context = norito::core::DecodeBudgetContext::try_new_owned(
        norito::DecodeLimits::new(
            usize::MAX,
            usize::MAX,
            usize::MAX,
            demand.checked_mul(2).unwrap(),
            usize::MAX,
        ),
        &pool,
    )
    .unwrap();
    {
        let transaction = block.transaction();
        let error = original_context
            .with(|| {
                norito::with_decode_limits_scope(
                    norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
                    || ensure_kaigi_account_can_unregister(&transaction, &host),
                )
            })
            .expect_err("indexed original call read must refuse its inner quota");
        assert_eq!(
            transaction
                .borrow_execution_deferral()
                .map(|owner| owner.reason()),
            Some(ExecutionDeferral::ActiveMemoryCapacity),
            "Kaigi indexed record refusal must retain the original sticky execution deferral: {error:?}"
        );
        assert_captured_scope(&transaction.borrow_execution_deferral().unwrap());
    }
    let before_retry = original_context.consumed_allocated_bytes();
    {
        let transaction = block.transaction();
        let error = original_context
            .with(|| ensure_kaigi_account_can_unregister(&transaction, &host))
            .expect_err("same original source completes with its genuine active-call rejection");
        assert!(error.to_string().contains("referenced by active Kaigi"));
        assert!(!transaction.is_execution_deferred());
    }
    assert_eq!(
        original_context.consumed_allocated_bytes() - before_retry,
        u64::try_from(demand).unwrap()
    );
    let stored = block
        .world
        .domain(&record.id.domain_id)
        .unwrap()
        .metadata()
        .get(&key)
        .unwrap();
    assert_eq!(stored, &original);
    assert_eq!(stored.get().as_ptr(), original_pointer);
    assert!(block.world.kaigi_account_dependencies.get(&host).is_some());
}
