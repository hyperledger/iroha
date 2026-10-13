//! Real relay instruction and governance refusal boundaries with unchanged-source retry.

use super::*;
use crate::{kura::Kura, query::store::LiveQueryStore, state::State};
use core::num::NonZeroU64;
use iroha_data_model::Registrable;
use iroha_data_model::prelude::{
    Account, AssetDefinition, KaigiRelayHealthStatus, NewKaigi, SetKeyValue,
};
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

fn limits(maximum: usize) -> norito::DecodeLimits {
    norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, maximum, usize::MAX)
}

fn header() -> iroha_data_model::block::BlockHeader {
    iroha_data_model::block::BlockHeader::new(NonZeroU64::MIN, None, None, 0, 0)
}

fn state(domain: &DomainId, host: &AccountId) -> State {
    State::new(
        World::with(
            [Domain::new(domain.clone()).build(&ALICE_ID)],
            [Account::new(host.clone()).build(&ALICE_ID)],
            std::iter::empty::<AssetDefinition>(),
        ),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RelayCheckpoint {
    Lineage,
    Registration,
    Feedback,
    PrimaryAlias,
}

fn relay_attempt(
    checkpoint: RelayCheckpoint,
    relay: &AccountId,
    registration: &KaigiRelayRegistration,
    transaction: &mut StateTransaction<'_, '_>,
) -> Result<(), Error> {
    if checkpoint == RelayCheckpoint::PrimaryAlias {
        RegisterKaigiRelay {
            relay: registration.clone(),
        }
        .execute(relay, transaction)
    } else {
        UnregisterKaigiRelay {
            relay_id: relay.clone(),
        }
        .execute(relay, transaction)
    }
}

// Admit the exact production caller prefix. The real attempt below still invokes
// its public instruction; no test branch replaces its decoder or authority check.
fn relay_prefix(
    transaction: &StateTransaction<'_, '_>,
    relay: &AccountId,
    domain: &DomainId,
    primary_alias: bool,
) {
    transaction.world.account(relay).unwrap();
    let graph = persisted_kaigi_rekey_graph(
        &transaction.world,
        if primary_alias {
            vec![relay.clone()]
        } else {
            vec![relay.clone(), relay.clone()]
        },
    )
    .unwrap();
    if primary_alias {
        assert_eq!(
            resolve_active_kaigi_account_with_graph(transaction, relay, &graph).unwrap(),
            Some(relay.clone())
        );
    } else {
        assert!(
            accounts_share_active_lineage_with_graph(transaction, relay, relay, &graph).unwrap()
        );
        assert_eq!(
            relay_domain_from_persisted_graph(transaction, relay, &graph).unwrap(),
            *domain
        );
    }
}

fn retirement_refusal(checkpoint: RelayCheckpoint) {
    let (record, host, _) = super::tests::new_record(KaigiPrivacyMode::Transparent);
    let domain = record.id.domain_id.clone();
    let state = state(&domain, &host);
    let pool = state.ivm_execution_budget();
    let mut block = state.block(header());
    let manifest = super::tests::sample_manifest();
    let relay = manifest.hops[0].relay_id.clone();
    {
        let mut transaction = block.transaction();
        super::tests::register_manifest_relays(&mut transaction, &domain, &manifest);
        let mut template = NewKaigi::with_defaults(record.id.clone(), host.clone());
        template.relay_manifest = Some(manifest.clone());
        CreateKaigi {
            call: template,
            commitment: None,
            nullifier: None,
            roster_root: None,
            proof: None,
        }
        .execute(&host, &mut transaction)
        .unwrap();
        ReportKaigiRelayHealth {
            call_id: record.id.clone(),
            relay_id: relay.clone(),
            status: KaigiRelayHealthStatus::Healthy,
            reported_at_ms: 0,
            notes: Some("original report".to_owned()),
        }
        .execute(&host, &mut transaction)
        .expect("real host health instruction retains the feedback source");
        EndKaigi {
            call_id: record.id.clone(),
            ended_at_ms: None,
            commitment: None,
            nullifier: None,
            roster_root: None,
            proof: None,
        }
        .execute(&host, &mut transaction)
        .unwrap();
        transaction.apply();
    }
    // Publish only successful setup before observing a refused carrier.
    block.commit_world_overlay_for_testing().unwrap();
    let mut block = state.block(header());
    let registration_key = kaigi_relay_metadata_key(&relay).unwrap();
    let feedback_key = kaigi_relay_feedback_key(&relay).unwrap();
    let original = [registration_key.clone(), feedback_key.clone()].map(|key| {
        block
            .world
            .domain(&domain)
            .unwrap()
            .metadata()
            .get(&key)
            .unwrap()
            .clone()
    });
    let pointers = original.each_ref().map(|value| value.get().as_ptr());
    let registration: KaigiRelayRegistration = original[0].try_into_any_norito().unwrap();
    let alias = block
        .world
        .account(&relay)
        .unwrap()
        .label()
        .unwrap()
        .clone();
    let selector =
        crate::sns::selector_for_account_alias(&alias, block.world.dataspace_catalog()).unwrap();
    let lease_key = crate::sns::record_storage_key(&selector);
    let original_lease = block
        .world
        .smart_contract_state
        .get(&lease_key)
        .unwrap()
        .clone();
    let lease_pointer = block
        .world
        .smart_contract_state
        .get(&lease_key)
        .unwrap()
        .as_ptr();
    // Unregister checks the two live lineages before any retained relay JSON row.
    // Register checks one live lineage before resolving its primary alias again.
    let prefix_measurement = norito::core::DecodeBudgetContext::new(limits(usize::MAX));
    {
        let transaction = block.transaction();
        prefix_measurement.with(|| {
            relay_prefix(
                &transaction,
                &relay,
                &domain,
                checkpoint == RelayCheckpoint::PrimaryAlias,
            )
        });
    }
    let lineage_prefix = usize::try_from(prefix_measurement.consumed_allocated_bytes()).unwrap();
    assert!(lineage_prefix > 0);
    let row_measurement = norito::core::DecodeBudgetContext::new(limits(usize::MAX));
    let first: KaigiRelayRegistration = row_measurement
        .with(|| original[0].try_into_any_norito())
        .unwrap();
    assert_eq!(first, registration);
    let row_prefix = usize::try_from(row_measurement.consumed_allocated_bytes()).unwrap();
    assert!(row_prefix > 0);
    let prefix = match checkpoint {
        RelayCheckpoint::Lineage => 0,
        RelayCheckpoint::Registration | RelayCheckpoint::PrimaryAlias => lineage_prefix,
        RelayCheckpoint::Feedback => lineage_prefix.checked_add(row_prefix).unwrap(),
    };
    if checkpoint == RelayCheckpoint::Lineage {
        let mut corrupt = block.transaction();
        corrupt
            .world
            .smart_contract_state
            .insert(lease_key.clone(), vec![0xff]);
        let error = relay_attempt(checkpoint, &relay, &registration, &mut corrupt).unwrap_err();
        assert!(matches!(error, Error::InvariantViolation(_)));
        assert!(
            error
                .to_string()
                .contains("failed to resolve Kaigi account-id rekey lineage")
        );
        assert!(!corrupt.is_execution_deferred());
        assert!(corrupt.world.take_external_events().is_empty());
        // Completed corrupt-source rejection never publishes this fixture edit.
        drop(corrupt);
        assert_eq!(
            block.world.smart_contract_state.get(&lease_key),
            Some(&original_lease)
        );
        assert_eq!(
            block
                .world
                .smart_contract_state
                .get(&lease_key)
                .unwrap()
                .as_ptr(),
            lease_pointer
        );
    }
    let measurement = norito::core::DecodeBudgetContext::new(limits(usize::MAX));
    {
        let mut transaction = block.transaction();
        measurement
            .with(|| relay_attempt(checkpoint, &relay, &registration, &mut transaction))
            .unwrap();
        // This calibration transaction retires without publishing its row removals.
    }
    let demand = usize::try_from(measurement.consumed_allocated_bytes()).unwrap();
    assert!(demand > prefix);
    let context = norito::core::DecodeBudgetContext::try_new_owned(
        limits(demand.checked_mul(2).unwrap()),
        &pool,
    )
    .unwrap();
    let registry = block.world.kaigi_relay_registry.get(&relay).cloned();
    let dependencies = block.world.kaigi_account_dependencies.get(&relay).cloned();
    let probe: Name = "relay-unpublished-journal".parse().unwrap();
    {
        let mut transaction = block.transaction();
        let internal_len = transaction.world.internal_event_buf.len();
        transaction
            .world
            .domain_mut(&domain)
            .unwrap()
            .metadata_mut()
            .insert(probe.clone(), Json::new("unpublished journal"));
        let error = context
            .with(|| {
                norito::with_decode_limits_scope(limits(prefix), || {
                    relay_attempt(checkpoint, &relay, &registration, &mut transaction)
                })
            })
            .expect_err("the actual retained relay row must refuse the original inner quota");
        let cause = match checkpoint {
            RelayCheckpoint::Lineage => {
                "Kaigi lineage refusal must retain its original sticky execution deferral"
            }
            RelayCheckpoint::Registration => {
                "Kaigi registration refusal must retain its original sticky execution deferral"
            }
            RelayCheckpoint::Feedback => {
                "Kaigi feedback refusal must retain its original sticky execution deferral"
            }
            RelayCheckpoint::PrimaryAlias => {
                "Kaigi primary alias refusal must retain its original sticky execution deferral"
            }
        };
        assert_eq!(
            transaction
                .borrow_execution_deferral()
                .map(|owner| owner.reason()),
            Some(ExecutionDeferral::ActiveMemoryCapacity),
            "{cause}: {error:?}"
        );
        assert_captured_scope(&transaction.borrow_execution_deferral().unwrap());
        assert_eq!(transaction.last_tx_gas_used, 0);
        assert!(transaction.world.take_external_events().is_empty());
        assert_eq!(transaction.world.internal_event_buf.len(), internal_len);
        transaction.apply();
    }
    let stored = block.world.domain(&domain).unwrap();
    assert!(stored.metadata().get(&probe).is_none());
    for (index, key) in [registration_key.clone(), feedback_key.clone()]
        .iter()
        .enumerate()
    {
        let value = stored.metadata().get(key).unwrap();
        assert_eq!(value, &original[index]);
        assert_eq!(value.get().as_ptr(), pointers[index]);
    }
    assert_eq!(
        block.world.kaigi_relay_registry.get(&relay),
        registry.as_ref()
    );
    assert_eq!(
        block.world.kaigi_account_dependencies.get(&relay),
        dependencies.as_ref()
    );
    assert_eq!(
        block.world.smart_contract_state.get(&lease_key),
        Some(&original_lease)
    );
    assert_eq!(
        block
            .world
            .smart_contract_state
            .get(&lease_key)
            .unwrap()
            .as_ptr(),
        lease_pointer
    );
    // Refused apply keeps rollback intact and poisons this carrier. A fresh
    // carrier borrows the same committed Json/lease owners and original budget.
    drop(block);
    let mut block = state.block(header());
    let stored = block.world.domain(&domain).unwrap();
    for (index, key) in [registration_key.clone(), feedback_key.clone()]
        .iter()
        .enumerate()
    {
        let value = stored.metadata().get(key).unwrap();
        assert_eq!(value, &original[index]);
        assert_eq!(value.get().as_ptr(), pointers[index]);
    }
    assert_eq!(
        block.world.kaigi_relay_registry.get(&relay),
        registry.as_ref()
    );
    assert_eq!(
        block.world.kaigi_account_dependencies.get(&relay),
        dependencies.as_ref()
    );
    assert_eq!(
        block.world.smart_contract_state.get(&lease_key),
        Some(&original_lease)
    );
    assert_eq!(
        block
            .world
            .smart_contract_state
            .get(&lease_key)
            .unwrap()
            .as_ptr(),
        lease_pointer
    );
    let before_retry = context.consumed_allocated_bytes();
    assert!(before_retry > u64::try_from(prefix).unwrap());
    assert!(before_retry <= u64::try_from(demand).unwrap());
    {
        let mut transaction = block.transaction();
        context
            .with(|| relay_attempt(checkpoint, &relay, &registration, &mut transaction))
            .expect("same original relay rows retry successfully");
        assert!(!transaction.is_execution_deferred());
        transaction.apply();
    }
    assert_eq!(
        context.consumed_allocated_bytes() - before_retry,
        u64::try_from(demand).unwrap()
    );
    let stored = block.world.domain(&domain).unwrap();
    if checkpoint == RelayCheckpoint::PrimaryAlias {
        assert_eq!(
            block.world.kaigi_relay_registry.get(&relay),
            registry.as_ref()
        );
        assert_eq!(
            block.world.kaigi_account_dependencies.get(&relay),
            dependencies.as_ref()
        );
        for (index, key) in [registration_key, feedback_key].iter().enumerate() {
            let value = stored.metadata().get(key).unwrap();
            assert_eq!(value, &original[index]);
            assert_eq!(value.get().as_ptr(), pointers[index]);
        }
    } else {
        assert!(block.world.kaigi_relay_registry.get(&relay).is_none());
        assert!(stored.metadata().get(&registration_key).is_none());
        assert!(stored.metadata().get(&feedback_key).is_none());
    }
    assert_eq!(
        block.world.smart_contract_state.get(&lease_key),
        Some(&original_lease)
    );
    assert_eq!(
        block
            .world
            .smart_contract_state
            .get(&lease_key)
            .unwrap()
            .as_ptr(),
        lease_pointer
    );
    let retained = pool.reserved_bytes();
    drop(context);
    assert_eq!(
        pool.reserved_bytes() + norito::core::DecodeBudgetContext::allocation_layout().size(),
        retained
    );
}

#[test]
fn lineage_refusal_preserves_original_relay_retirement_and_retry() {
    retirement_refusal(RelayCheckpoint::Lineage);
}

#[test]
fn primary_alias_refusal_preserves_original_registration_and_retry() {
    retirement_refusal(RelayCheckpoint::PrimaryAlias);
}

#[test]
fn registration_refusal_preserves_original_relay_retirement_and_retry() {
    retirement_refusal(RelayCheckpoint::Registration);
}

#[test]
fn feedback_refusal_preserves_both_original_relay_rows_and_retry() {
    retirement_refusal(RelayCheckpoint::Feedback);
}

#[test]
fn allowlist_refusal_prevents_domain_metadata_publication_and_retries_original_json() {
    let (record, host, _) = super::tests::new_record(KaigiPrivacyMode::Transparent);
    let domain = record.id.domain_id;
    let state = state(&domain, &host);
    let pool = state.ivm_execution_budget();
    let mut block = state.block(header());
    let key = kaigi_relay_allowlist_key().unwrap();
    let allowlist = KaigiRelayAllowlist {
        allowed_relays: BTreeSet::from([host.clone()]),
    };
    let original = Json::try_new(allowlist.clone()).unwrap();
    let pointer = original.get().as_ptr();
    let measurement = norito::core::DecodeBudgetContext::new(limits(usize::MAX));
    {
        let mut transaction = block.transaction();
        measurement
            .with(|| {
                SetKeyValue::domain(domain.clone(), key.clone(), original.clone())
                    .execute(&host, &mut transaction)
            })
            .unwrap();
    }
    let demand = usize::try_from(measurement.consumed_allocated_bytes()).unwrap();
    assert!(demand > 0);
    let context = norito::core::DecodeBudgetContext::try_new_owned(
        limits(demand.checked_mul(2).unwrap()),
        &pool,
    )
    .unwrap();
    {
        let mut transaction = block.transaction();
        let error = context
            .with(|| {
                norito::with_decode_limits_scope(limits(0), || {
                    SetKeyValue::domain(domain.clone(), key.clone(), original.clone())
                        .execute(&host, &mut transaction)
                })
            })
            .expect_err("original governance allowlist must refuse zero inner quota");
        assert_eq!(
            transaction
                .borrow_execution_deferral()
                .map(|owner| owner.reason()),
            Some(ExecutionDeferral::ActiveMemoryCapacity),
            "Kaigi allowlist refusal must retain its original sticky execution deferral: {error:?}"
        );
        assert_captured_scope(&transaction.borrow_execution_deferral().unwrap());
        assert!(transaction.world.take_external_events().is_empty());
        transaction.apply();
    }
    assert!(
        block
            .world
            .domain(&domain)
            .unwrap()
            .metadata()
            .get(&key)
            .is_none()
    );
    assert_eq!(original.get().as_ptr(), pointer);
    // Retire the refused carrier without publication. Retry the same original
    // instruction in a fresh carrier over the unchanged State and decode owner.
    drop(block);
    let mut block = state.block(header());
    assert!(
        block
            .world
            .domain(&domain)
            .unwrap()
            .metadata()
            .get(&key)
            .is_none()
    );
    assert_eq!(original.get().as_ptr(), pointer);
    let before_retry = context.consumed_allocated_bytes();
    assert!(before_retry > 0 && before_retry <= u64::try_from(demand).unwrap());
    {
        let mut transaction = block.transaction();
        context
            .with(|| {
                SetKeyValue::domain(domain.clone(), key.clone(), original.clone())
                    .execute(&host, &mut transaction)
            })
            .unwrap();
        assert!(!transaction.is_execution_deferred());
        transaction.apply();
    }
    assert_eq!(
        context.consumed_allocated_bytes() - before_retry,
        u64::try_from(demand).unwrap()
    );
    let stored = block
        .world
        .domain(&domain)
        .unwrap()
        .metadata()
        .get(&key)
        .unwrap();
    assert_eq!(stored, &original);
    assert_eq!(stored.get().as_ptr(), pointer);
    {
        let mut transaction = block.transaction();
        let invalid = Json::new("genuinely malformed allowlist");
        let error = SetKeyValue::domain(domain.clone(), key.clone(), invalid)
            .execute(&host, &mut transaction)
            .unwrap_err();
        assert!(matches!(error, Error::InvalidParameter(_)));
        assert!(!transaction.is_execution_deferred());
        transaction.apply();
    }
    assert_eq!(
        block.world.domain(&domain).unwrap().metadata().get(&key),
        Some(&original)
    );
    let retained = pool.reserved_bytes();
    drop(context);
    assert_eq!(
        pool.reserved_bytes() + norito::core::DecodeBudgetContext::allocation_layout().size(),
        retained
    );
}

#[test]
fn checked_record_writer_refusal_keeps_original_create_unpublished_and_retries() {
    let (record, host, _) = super::tests::new_record(KaigiPrivacyMode::Transparent);
    let domain = record.id.domain_id.clone();
    let state = state(&domain, &host);
    let pool = state.ivm_execution_budget();
    let mut block = state.block(header());
    let template = NewKaigi::with_defaults(record.id.clone(), host.clone());
    let create = || CreateKaigi {
        call: template.clone(),
        commitment: None,
        nullifier: None,
        roster_root: None,
        proof: None,
    };
    let measurement = norito::core::DecodeBudgetContext::new(limits(usize::MAX));
    {
        let mut transaction = block.transaction();
        measurement
            .with(|| create().execute(&host, &mut transaction))
            .unwrap();
    }
    let demand = usize::try_from(measurement.consumed_allocated_bytes()).unwrap();
    assert!(demand > 0);
    let context = norito::core::DecodeBudgetContext::try_new_owned(
        limits(demand.checked_mul(2).unwrap()),
        &pool,
    )
    .unwrap();
    let key = metadata_key(&record.id).unwrap();
    {
        let mut transaction = block.transaction();
        let error = context
            .with(|| {
                norito::with_decode_limits_scope(limits(0), || {
                    create().execute(&host, &mut transaction)
                })
            })
            .unwrap_err();
        assert_eq!(
            transaction
                .borrow_execution_deferral()
                .map(|owner| owner.reason()),
            Some(ExecutionDeferral::ActiveMemoryCapacity),
            "Kaigi checked JSON writer refusal must retain its original sticky execution deferral: {error:?}"
        );
        assert_captured_scope(&transaction.borrow_execution_deferral().unwrap());
        assert!(transaction.world.take_external_events().is_empty());
        transaction.apply();
    }
    assert!(
        block
            .world
            .domain(&domain)
            .unwrap()
            .metadata()
            .get(&key)
            .is_none()
    );
    assert!(block.world.kaigi_account_dependencies.get(&host).is_none());
    // Retire the refused carrier without publication. Retry the same original
    // instruction in a fresh carrier over the unchanged State and decode owner.
    drop(block);
    let mut block = state.block(header());
    assert!(
        block
            .world
            .domain(&domain)
            .unwrap()
            .metadata()
            .get(&key)
            .is_none()
    );
    assert!(block.world.kaigi_account_dependencies.get(&host).is_none());
    let before_retry = context.consumed_allocated_bytes();
    assert!(before_retry > 0 && before_retry <= u64::try_from(demand).unwrap());
    {
        let mut transaction = block.transaction();
        context
            .with(|| create().execute(&host, &mut transaction))
            .unwrap();
        assert!(!transaction.is_execution_deferred());
        transaction.apply();
    }
    assert_eq!(
        context.consumed_allocated_bytes() - before_retry,
        u64::try_from(demand).unwrap()
    );
    let decoded: KaigiRecord = block
        .world
        .domain(&domain)
        .unwrap()
        .metadata()
        .get(&key)
        .unwrap()
        .try_into_any_norito()
        .unwrap();
    assert_eq!(decoded.id, record.id);
    assert_eq!(decoded.host, host);
    assert_eq!(decoded.status, KaigiStatus::Active);
    let retained = pool.reserved_bytes();
    drop(context);
    assert_eq!(
        pool.reserved_bytes() + norito::core::DecodeBudgetContext::allocation_layout().size(),
        retained
    );
}

#[test]
fn live_manifest_dependency_refusal_preserves_original_route_and_retry() {
    let (record, host, _) = super::tests::new_record(KaigiPrivacyMode::Transparent);
    let domain = record.id.domain_id.clone();
    let state = state(&domain, &host);
    let pool = state.ivm_execution_budget();
    let mut block = state.block(header());
    let manifest = super::tests::sample_manifest();
    let relay = manifest.hops[0].relay_id.clone();
    {
        let mut transaction = block.transaction();
        super::tests::register_manifest_relays(&mut transaction, &domain, &manifest);
        let mut template = NewKaigi::with_defaults(record.id.clone(), host.clone());
        template.relay_manifest = Some(manifest.clone());
        CreateKaigi {
            call: template,
            commitment: None,
            nullifier: None,
            roster_root: None,
            proof: None,
        }
        .execute(&host, &mut transaction)
        .unwrap();
        transaction.apply();
    }
    // Publish only successful setup before observing a refused carrier.
    block.commit_world_overlay_for_testing().unwrap();
    let mut block = state.block(header());
    let record_key = metadata_key(&record.id).unwrap();
    let registration_key = kaigi_relay_metadata_key(&relay).unwrap();
    let original = [record_key.clone(), registration_key.clone()].map(|key| {
        block
            .world
            .domain(&domain)
            .unwrap()
            .metadata()
            .get(&key)
            .unwrap()
            .clone()
    });
    let pointers = original.each_ref().map(|value| value.get().as_ptr());
    let registration: KaigiRelayRegistration = original[1].try_into_any_norito().unwrap();
    let mut rotated = registration.clone();
    rotated.hpke_public_key = vec![0xAA, 0xBB];
    let registry = block.world.kaigi_relay_registry.get(&relay).cloned();
    let dependencies = block.world.kaigi_account_dependencies.get(&relay).cloned();
    assert!(dependencies.as_ref().unwrap().iter().any(|dependency| {
        dependency.0 == KAIGI_DEPENDENCY_ACTIVE_CALL && dependency.2 == record_key
    }));

    // Calibrate only the real caller prefix before its active-call dependency read.
    // The observed attempt below still executes the public key-rotation instruction.
    let prefix_context = norito::core::DecodeBudgetContext::new(limits(usize::MAX));
    {
        let transaction = block.transaction();
        prefix_context.with(|| {
            transaction.world.account(&relay).unwrap();
            let graph = persisted_kaigi_rekey_graph(&transaction.world, [relay.clone()]).unwrap();
            assert_eq!(
                relay_domain_with_graph(&transaction, &relay, &graph).unwrap(),
                domain
            );
            let parsed =
                decode_stored_relay_registration(&domain, &registration_key, &original[1]).unwrap();
            assert_eq!(parsed, registration);
        });
    }
    let prefix = usize::try_from(prefix_context.consumed_allocated_bytes()).unwrap();
    assert!(prefix > 0);
    let measurement = norito::core::DecodeBudgetContext::new(limits(usize::MAX));
    {
        let mut transaction = block.transaction();
        let error = measurement
            .with(|| {
                RegisterKaigiRelay {
                    relay: rotated.clone(),
                }
                .execute(&relay, &mut transaction)
            })
            .unwrap_err();
        super::tests::assert_smart_contract_error(error, "active Kaigi");
        assert!(!transaction.is_execution_deferred());
    }
    let demand = usize::try_from(measurement.consumed_allocated_bytes()).unwrap();
    assert!(demand > prefix);
    let context = norito::core::DecodeBudgetContext::try_new_owned(
        limits(demand.checked_mul(2).unwrap()),
        &pool,
    )
    .unwrap();
    let reserved = pool.reserved_bytes();
    let probe: Name = "unpublished-live-route-refusal".parse().unwrap();
    {
        let mut transaction = block.transaction();
        let internal_len = transaction.world.internal_event_buf.len();
        transaction
            .world
            .domain_mut(&domain)
            .unwrap()
            .metadata_mut()
            .insert(probe.clone(), Json::new("unpublished lifecycle journal"));
        let error = context
            .with(|| {
                norito::with_decode_limits_scope(limits(prefix), || {
                    RegisterKaigiRelay {
                        relay: rotated.clone(),
                    }
                    .execute(&relay, &mut transaction)
                })
            })
            .expect_err("the original active-call dependency must refuse its inner decode quota");
        assert_eq!(
            transaction
                .borrow_execution_deferral()
                .map(|owner| owner.reason()),
            Some(ExecutionDeferral::ActiveMemoryCapacity),
            "Kaigi live manifest dependency refusal must retain its original sticky execution deferral: {error:?}"
        );
        assert_captured_scope(&transaction.borrow_execution_deferral().unwrap());
        assert_eq!(transaction.last_tx_gas_used, 0);
        assert!(transaction.world.take_external_events().is_empty());
        assert_eq!(transaction.world.internal_event_buf.len(), internal_len);
        transaction.apply();
    }
    assert_eq!(pool.reserved_bytes(), reserved);
    let stored = block.world.domain(&domain).unwrap();
    assert!(stored.metadata().get(&probe).is_none());
    for (index, key) in [record_key.clone(), registration_key.clone()]
        .iter()
        .enumerate()
    {
        let value = stored.metadata().get(key).unwrap();
        assert_eq!(value, &original[index]);
        assert_eq!(value.get().as_ptr(), pointers[index]);
    }
    assert_eq!(
        block.world.kaigi_relay_registry.get(&relay),
        registry.as_ref()
    );
    assert_eq!(
        block.world.kaigi_account_dependencies.get(&relay),
        dependencies.as_ref()
    );
    // Refused apply keeps rollback intact and poisons this carrier. A fresh
    // carrier borrows the same committed Json/lease owners and original budget.
    drop(block);
    let mut block = state.block(header());
    for (index, key) in [record_key.clone(), registration_key.clone()]
        .iter()
        .enumerate()
    {
        let value = block
            .world
            .domain(&domain)
            .unwrap()
            .metadata()
            .get(key)
            .unwrap();
        assert_eq!(value, &original[index]);
        assert_eq!(value.get().as_ptr(), pointers[index]);
    }
    assert_eq!(
        block.world.kaigi_relay_registry.get(&relay),
        registry.as_ref()
    );
    assert_eq!(
        block.world.kaigi_account_dependencies.get(&relay),
        dependencies.as_ref()
    );
    let before_retry = context.consumed_allocated_bytes();
    assert!(
        before_retry > u64::try_from(prefix).unwrap()
            && before_retry <= u64::try_from(demand).unwrap()
    );
    {
        let mut transaction = block.transaction();
        let error = context
            .with(|| RegisterKaigiRelay { relay: rotated }.execute(&relay, &mut transaction))
            .unwrap_err();
        super::tests::assert_smart_contract_error(error, "active Kaigi");
        assert_eq!(
            transaction
                .borrow_execution_deferral()
                .map(|owner| owner.reason()),
            None,
            "same original source retry reaches the completed live-route guard"
        );
        assert!(transaction.world.take_external_events().is_empty());
        transaction.apply();
    }
    assert_eq!(
        context.consumed_allocated_bytes() - before_retry,
        u64::try_from(demand).unwrap()
    );
    for (index, key) in [record_key, registration_key].iter().enumerate() {
        let value = block
            .world
            .domain(&domain)
            .unwrap()
            .metadata()
            .get(key)
            .unwrap();
        assert_eq!(value, &original[index]);
        assert_eq!(value.get().as_ptr(), pointers[index]);
    }
    assert_eq!(
        block.world.kaigi_relay_registry.get(&relay),
        registry.as_ref()
    );
    assert_eq!(
        block.world.kaigi_account_dependencies.get(&relay),
        dependencies.as_ref()
    );
    drop(context);
    assert_eq!(
        pool.reserved_bytes() + norito::core::DecodeBudgetContext::allocation_layout().size(),
        reserved
    );
}
