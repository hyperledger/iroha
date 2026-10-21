//! Compiled fixed-argument scheduled callbacks through the real output owner.
//!
//! These are component execution and trigger-storage recovery tests. They do
//! not claim a validator process restart, certified public route or BOI release.

use super::*;
use crate::smartcontracts::isi::triggers::{
    set::{Set, SetDto},
    specialized::TimeTriggerRetryState,
};
use iroha_data_model::{
    events::time::Schedule,
    permission::Permission,
    smart_contract::{ContractAddress, ContractArtifactId},
    transaction::{
        ExecutableBatchItem,
        executable::{ContractArgumentRecord, ContractInvocation},
    },
    trigger::action::TimeTriggerRetryPolicy,
};
use iroha_model_base::{
    state_path::StatePath,
    topology::{DataSpaceId, LaneId},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

fn permission(address: &ContractAddress, name: &str) -> Permission {
    iroha_executor_data_model::permission::smart_contract::CanUseContractPermission {
        contract: address.clone(),
        permission: name.parse().unwrap(),
    }
    .into()
}

fn source_at(state: &State, time_ms: u64) -> SignedBlock {
    let parent = state.view().latest_block().unwrap().unwrap();
    let header = BlockHeader::new(
        NonZeroU64::new(parent.header().height().get() + 1).unwrap(),
        Some(parent.hash()),
        None,
        time_ms,
        0,
    );
    let mut transaction = TransactionBuilder::new(
        state.network_id,
        ALICE_ID.clone(),
        FeePaymentIntent::authority(vec![], None),
    );
    transaction.set_creation_time(Duration::from_millis(time_ms - 1));
    let signed = transaction
        .with_instructions(plain_network())
        .sign(ALICE_KEYPAIR.private_key());
    let mut builder = BlockBuilder::new(header);
    builder.set_execution_context(Some(
        iroha_data_model::block::BlockExecutionContextBundle::new(vec![
            iroha_data_model::block::ExternalExecutionContext::new(
                signed.hash_as_entrypoint(),
                LaneId::SINGLE,
                DataSpaceId::UNIVERSAL,
            ),
        ]),
    ));
    builder.push_transaction(signed);
    builder.build_with_signature(0, ALICE_KEYPAIR.private_key())
}

fn compiled_fixture() -> (State, SignedBlock, ContractAddress, Permission) {
    let signing = crate::manifest_signing_test_support::ManifestSigningFixture::new();
    let (program, manifest) = kotodama_lang::compiler::Compiler::new()
        .compile_source_with_manifest(
            r#"
seiyaku ScheduledFixture {
    permission Run;
    permission RetryRun;
    error enum JobError { Refused = 1, }
    state StateMap<int, int> Applied;
    kotoage fn run(int job) authorize(Run) {
        Applied[job] = Applied.get(job).unwrap_or(0) + 1;
    }
    kotoage fn retry_run(int job) authorize(RetryRun) {
        Applied[job] = Applied.get(job).unwrap_or(0) + 1;
    }
    kotoage fn reject(int job) authorize(Run) {
        Applied[job] = 99;
        require(false, JobError::Refused);
    }
}
"#,
        )
        .expect("compile current native callback fixture");
    let code_hash = ivm::contract_code_hash(&program);
    let (state, source) = fixture(1_048_576, 3, vec![], plain_network());
    let address = ContractAddress::derive(
        state.network_id_ref(),
        &ALICE_ID,
        97,
        DataSpaceId::UNIVERSAL,
    )
    .unwrap();
    let retry_permission = permission(&address, "RetryRun");
    let due_ms = output_fixture_parent_time(&state) + 1;
    let mut triggers = Vec::new();
    for (id, entrypoint, job) in [
        ("a_retry", "retry_run", "1"),
        ("b_refused", "reject", "2"),
        ("z_ready", "run", "3"),
    ] {
        let descriptor = manifest
            .entrypoints
            .as_ref()
            .unwrap()
            .iter()
            .find(|entry| entry.name == entrypoint)
            .unwrap();
        let encoded = ivm_abi::arguments::encode_argument_record_from_json(
            descriptor.argument_schema.as_ref().unwrap(),
            &Json::new(norito::json!({"job": job})),
        )
        .unwrap();
        let call = ContractInvocation {
            contract_address: address.clone(),
            expected_code_hash: code_hash,
            entrypoint: entrypoint.into(),
            arguments: Some(ContractArgumentRecord::try_new(encoded).unwrap()),
        };
        let action = Action::new(
            Executable::Batch(vec![ExecutableBatchItem::ContractCall(call)].into()),
            Repeats::Exactly(1),
            ALICE_ID.clone(),
            TimeEventFilter::new(ExecutionTime::Schedule(
                Schedule::starting_at(Duration::from_millis(due_ms))
                    .with_period(Duration::from_millis(5)),
            )),
        )
        .unwrap()
        .with_retry_policy(TimeTriggerRetryPolicy {
            max_retries: NonZeroU32::new(1).unwrap(),
            retry_after_ms: NonZeroU64::new(5).unwrap(),
        })
        .unwrap();
        triggers.push(Trigger::new(id.parse().unwrap(), action));
    }
    {
        let (mut setup, _recording) = output_fixture_setup(&state);
        let mut transaction = setup.transaction_for_callback_testing();
        Register::account(Account::new(address.subject_id()))
            .execute(&ALICE_ID, &mut transaction)
            .unwrap();
        let artifact = ContractArtifactId::new(DataSpaceId::UNIVERSAL, code_hash);
        transaction.world.contract_code.insert(artifact, program);
        transaction.world.contract_manifests.insert(
            artifact,
            manifest
                .try_signed(signing.context(), signing.max_frame_bytes(), &ALICE_KEYPAIR)
                .unwrap(),
        );
        transaction
            .world
            .bind_active_contract_subject_for_testing(address.clone(), code_hash);
        let mut permissions = transaction
            .world
            .account_permissions
            .get(&ALICE_ID)
            .cloned()
            .unwrap_or_default();
        permissions.insert(permission(&address, "Run"));
        permissions.insert(retry_permission.clone());
        transaction
            .world
            .account_permissions
            .insert(ALICE_ID.clone(), permissions.clone());
        for trigger in triggers {
            Register::trigger(trigger)
                .execute(&ALICE_ID, &mut transaction)
                .unwrap();
        }
        // Permissions are rechecked at firing; registration does not grant a
        // lasting exception. Only the independent retry job loses its role.
        permissions.remove(&retry_permission);
        transaction
            .world
            .account_permissions
            .insert(ALICE_ID.clone(), permissions);
        transaction.apply_callback_for_testing().unwrap();
        setup.commit_world_overlay_for_testing().unwrap();
    }
    (state, source, address, retry_permission)
}

fn run_and_capture(state: &State, source: &SignedBlock) -> Vec<(String, bool)> {
    let (mut block, recording) = recorded_component_block(state, source.header());
    block.reserve_ordinary_execution_outputs(source).unwrap();
    block
        .produce_ordinary_execution_outputs(source, |producer| {
            execute_network(producer)?;
            producer.execute_scheduled_time_outputs()
        })
        .unwrap();
    let statuses = retained(&block)
        .rows
        .iter()
        .filter_map(|row| {
            if let ExecutionOutputV1::Time(output) = row {
                Some((
                    output.invocation.trigger.trigger_id.to_string(),
                    output.result.is_ok(),
                ))
            } else {
                None
            }
        })
        .collect();
    drop(recording);
    // Explicit component overlay publication, not consensus/finality.
    block.commit_world_overlay_for_testing().unwrap();
    statuses
}

fn encoded_state_int(value: i128) -> Vec<u8> {
    use ivm_abi::state_value::{
        StateValueAtomV1, StateValueRecordV1, state_value_schema_for_embedded_type_v1,
        state_value_schema_hash_v1,
    };

    let schema = state_value_schema_for_embedded_type_v1(&ivm::EmbeddedStateType::Int)
        .expect("fixture Int state schema");
    let schema_bytes = norito::encode_canonical(&schema).unwrap();
    let envelope =
        ivm_abi::numeric_tlv::encode_int(&iroha_primitives::bigint::BigInt::from_i128(value))
            .unwrap();
    norito::encode_canonical(&StateValueRecordV1 {
        schema_hash: state_value_schema_hash_v1(&schema_bytes),
        atoms: vec![StateValueAtomV1::Pointer(envelope)],
    })
    .unwrap()
}

fn assert_applied_state(state: &State, address: &ContractAddress, expected: &[(i128, i128)]) {
    let scope = hex::encode(iroha_crypto::Hash::new(address.to_string().as_bytes()).as_ref());
    let prefix = format!("sc/{scope}/");
    let path = |job| -> StatePath {
        let logical = ivm::host::canonical_state_map_path(
            &"Applied".parse().unwrap(),
            &encoded_state_int(job),
        )
        .unwrap();
        format!("{prefix}{logical}").parse().unwrap()
    };
    let view = state.view();
    let stored = view.world.smart_contract_state();
    assert!(
        stored.get(&path(2)).is_none(),
        "the rejected callback's Applied[2] = 99 must always roll back"
    );
    let actual: BTreeMap<_, _> = stored
        .iter()
        .filter(|(key, _)| key.as_ref().starts_with(&prefix))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    let expected: BTreeMap<_, _> = expected
        .iter()
        .map(|&(job, value)| (path(job), encoded_state_int(value)))
        .collect();
    assert_eq!(
        actual, expected,
        "the exact contract namespace must contain only successful fixed-argument writes"
    );
}

#[test]
fn scheduled_batch_fixed_arguments_isolate_rejections_and_rollback_callback_state() {
    let (state, source, address, _) = compiled_fixture();
    assert_applied_state(&state, &address, &[]);
    assert_eq!(
        run_and_capture(&state, &source),
        vec![
            ("a_retry".into(), false),
            ("b_refused".into(), false),
            ("z_ready".into(), true),
        ]
    );
    assert_applied_state(&state, &address, &[(3, 1)]);
    let view = state.view();
    assert!(
        view.world
            .triggers()
            .ids()
            .get(&"z_ready".parse().unwrap())
            .is_none()
    );
    for id in ["a_retry", "b_refused"] {
        let action = view
            .world
            .triggers()
            .time_triggers()
            .get(&id.parse().unwrap())
            .unwrap();
        assert_eq!(action.repeats, Repeats::Exactly(1));
        assert_eq!(
            action.retry_state,
            Some(TimeTriggerRetryState {
                retries_used: 1,
                next_retry_at_ms: u64::try_from(source.header().creation_time().as_millis())
                    .unwrap()
                    + 5,
            })
        );
    }
}

#[test]
fn scheduled_callback_retry_survives_trigger_snapshot_and_executes_once_after_role_restore() {
    let (mut state, source, address, retry_permission) = compiled_fixture();
    assert_applied_state(&state, &address, &[]);
    run_and_capture(&state, &source);
    assert_applied_state(&state, &address, &[(3, 1)]);
    let saved = SetDto::from(&state.world.triggers).encode().unwrap();
    state.world.triggers = Set::try_from(SetDto::decode(&saved).unwrap()).unwrap();
    assert_applied_state(&state, &address, &[(3, 1)]);
    {
        let (mut setup, _recording) = output_fixture_setup(&state);
        let mut transaction = setup.transaction_for_callback_testing();
        let mut permissions = transaction
            .world
            .account_permissions
            .get(&ALICE_ID)
            .cloned()
            .unwrap_or_else(BTreeSet::new);
        permissions.insert(retry_permission);
        transaction
            .world
            .account_permissions
            .insert(ALICE_ID.clone(), permissions);
        transaction.apply_callback_for_testing().unwrap();
        setup.commit_world_overlay_for_testing().unwrap();
    }
    let first_ms = u64::try_from(source.header().creation_time().as_millis()).unwrap();
    let before_retry = source_at(&state, first_ms + 4);
    assert!(
        run_and_capture(&state, &before_retry).is_empty(),
        "no early retry after rehydration"
    );
    assert_applied_state(&state, &address, &[(3, 1)]);
    let due_retry = source_at(&state, first_ms + 6);
    assert_eq!(
        run_and_capture(&state, &due_retry),
        vec![("a_retry".into(), true), ("b_refused".into(), false),]
    );
    assert_applied_state(&state, &address, &[(1, 1), (3, 1)]);
    {
        let view = state.view();
        assert!(
            view.world
                .triggers()
                .ids()
                .get(&"a_retry".parse().unwrap())
                .is_none()
        );
        assert!(
            view.world
                .triggers()
                .ids()
                .get(&"b_refused".parse().unwrap())
                .is_none(),
            "the permanently rejected job exhausts its own bounded retry budget"
        );
    }
    let later = source_at(&state, first_ms + 20);
    assert!(run_and_capture(&state, &later).is_empty());
    assert_applied_state(&state, &address, &[(1, 1), (3, 1)]);
}
