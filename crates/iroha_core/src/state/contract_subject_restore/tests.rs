//! Actual lifecycle writes and restored logical inverse images preserve original sources.
use super::*;
use crate::{
    smartcontracts::Execute,
    state::{contract_subject_validation::test_support::*, snapshot_storage},
};
use iroha_data_model::{
    account::{AccountDetails, AccountValue},
    block::BlockHeader,
    isi::smart_contract_code::OfferContractOwnership,
    smart_contract::ContractLifecycleOwnerV1,
};
use iroha_test_samples::{ALICE_ID, BOB_ID};
use norito::{codec::Encode, json};

fn encoded<K: mv::Key + Encode, V: mv::Value + Encode>(store: &Storage<K, V>) -> String {
    let mut text = String::new();
    snapshot_storage::serialize(store, &mut text);
    text
}
fn sources(world: &World) -> [String; 3] {
    [
        encoded(&world.contract_subject_bindings),
        encoded(&world.accounts),
        encoded(&world.contract_instances),
    ]
}
fn reverse_images(
    world: &mut World,
) -> [BTreeMap<
    iroha_data_model::account::AccountId,
    iroha_data_model::smart_contract::ContractAddress,
>; 2] {
    let history = world.contract_subject_addresses.history();
    [
        history
            .current()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        history
            .iter_before_block()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
    ]
}

#[test]
fn actual_ownership_offer_changes_binding_history_without_fabricating_reverse_undo() {
    let mut state = state();
    {
        let mut block = state.block(BlockHeader::new(
            core::num::NonZeroU64::new(1).unwrap(),
            None,
            None,
            0,
            0,
        ));
        let mut tx = block.transaction();
        OfferContractOwnership {
            contract_address: address(),
            expected_revision: 1,
            new_owner: ContractLifecycleOwnerV1::Account(BOB_ID.clone()),
        }
        .execute(&ALICE_ID, &mut tx)
        .expect("actual authorized lifecycle offer");
        tx.apply();
        block.commit_world_overlay_for_testing().unwrap();
    }
    assert!(
        !state
            .world
            .contract_subject_bindings
            .snapshot()
            .revert_map()
            .is_empty()
    );
    assert!(
        state
            .world
            .contract_subject_addresses
            .snapshot()
            .revert_map()
            .is_empty()
    );
    let original = sources(&state.world);
    let expected = reverse_images(&mut state.world);
    rebuild(&mut state.world).unwrap();
    assert_eq!(sources(&state.world), original);
    assert_eq!(reverse_images(&mut state.world), expected);
    assert!(
        state
            .world
            .contract_subject_addresses
            .snapshot()
            .revert_map()
            .is_empty()
    );
    assert_eq!(
        state
            .world
            .contract_subject_bindings
            .view()
            .get(&address())
            .unwrap()
            .lifecycle
            .pending_owner,
        Some(ContractLifecycleOwnerV1::Account(BOB_ID.clone()))
    );
}

#[test]
fn new_binding_prior_absence_inactive_retention_and_replacement_are_exact() {
    let mut world = world();
    let new_address = other_address();
    let new_binding = crate::smartcontracts::code::ContractSubjectBinding::new_direct(
        &new_address,
        ALICE_ID.clone(),
    );
    let new_subject = new_binding.subject.clone();
    {
        let mut block = world.block();
        block.accounts.insert(
            new_subject.clone(),
            AccountValue::new(AccountDetails::default()),
        );
        block
            .contract_subject_bindings
            .insert(new_address.clone(), new_binding);
        block
            .contract_subject_addresses
            .insert(new_subject.clone(), new_address.clone());
        block.commit();
    }
    let original = sources(&world);
    let expected = reverse_images(&mut world);
    world.contract_subject_addresses = Storage::new();
    rebuild(&mut world).unwrap();
    assert_eq!(sources(&world), original);
    assert_eq!(reverse_images(&mut world), expected);
    assert_eq!(
        world
            .contract_subject_addresses
            .snapshot()
            .revert_map()
            .get(&new_subject),
        Some(&None)
    );
    assert_eq!(
        world
            .contract_subject_addresses
            .view()
            .get(&binding().subject),
        Some(&address()),
        "an inactive retained contract stays non-signing"
    );
    {
        let replacement = world.block_and_revert();
        assert!(
            replacement
                .contract_subject_addresses
                .get(&new_subject)
                .is_none()
        );
        assert!(
            replacement
                .contract_subject_bindings
                .get(&new_address)
                .is_none()
        );
    }
    assert_eq!(sources(&world), original);
    rebuild(&mut world).unwrap();
    assert_eq!(reverse_images(&mut world), expected);
    world.block_and_revert().commit();
    rebuild(&mut world).unwrap();
    assert_eq!(
        world
            .contract_subject_addresses
            .view()
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect::<BTreeMap<_, _>>(),
        expected[1]
    );
}

#[test]
fn prior_only_source_failure_does_not_replace_index_or_consume_any_source_undo() {
    for field in 0..3 {
        let mut world = world();
        match field {
            0 => {
                let mut bad = binding();
                bad.lifecycle.revision = 0;
                world.contract_subject_bindings.insert(address(), bad);
                let mut block = world.contract_subject_bindings.block();
                block.insert(address(), binding());
                block.commit();
            }
            1 => {
                let subject = binding().subject;
                let filtered = world
                    .accounts
                    .view()
                    .iter()
                    .filter(|(key, _)| *key != &subject)
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect();
                world.accounts = filtered;
                let mut block = world.accounts.block();
                block.insert(subject, AccountValue::new(AccountDetails::default()));
                block.commit();
            }
            2 => {
                world
                    .contract_instances
                    .insert(address(), iroha_crypto::Hash::new(b"bad predecessor"));
                let mut block = world.contract_instances.block();
                block.remove(address());
                block.commit();
            }
            _ => unreachable!(),
        }
        let original = sources(&world);
        let original_index = encoded(&world.contract_subject_addresses);
        let error = rebuild(&mut world).unwrap_err();
        assert!(error.contains("Predecessor"), "{error}");
        assert_eq!(sources(&world), original);
        assert_eq!(encoded(&world.contract_subject_addresses), original_index);
    }
}

#[test]
fn actual_kura_seed_roundtrip_preserves_both_images_and_rejects_prior_only_corruption() {
    use crate::{kura::Kura, query::store::LiveQueryStore, state::deserialize};
    let mut state = state();
    {
        let mut block = state.world.contract_subject_bindings.block();
        let mut changed = binding();
        changed.lifecycle.revision = 2;
        block.insert(address(), changed);
        block.commit();
    }
    let expected = reverse_images(&mut state.world);
    let execution_budget = state.ivm_execution_budget();
    let lane_manifests = state.lane_manifests.read().clone();
    let restore = |value| {
        deserialize::KuraSeed {
            execution_budget: execution_budget.clone(),
            lane_manifests: lane_manifests.clone(),
            kura: Kura::blank_kura_for_testing(),
            query_handle: LiveQueryStore::start_test(),
            #[cfg(feature = "telemetry")]
            telemetry: crate::telemetry::StateTelemetry::default(),
        }
        .into_state_from_json(value)
    };
    let mut recovered = restore(json::to_value(&state).unwrap()).unwrap();
    assert_eq!(reverse_images(&mut recovered.world), expected);
    assert_eq!(sources(&recovered.world), sources(&state.world));
    let mut bad = binding();
    bad.lifecycle.revision = 0;
    state.world.contract_subject_bindings = [(address(), bad)].into_iter().collect();
    {
        let mut block = state.world.contract_subject_bindings.block();
        block.insert(address(), binding());
        block.commit();
    }
    let error = restore(json::to_value(&state).unwrap())
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("Predecessor"), "{error}");
}
