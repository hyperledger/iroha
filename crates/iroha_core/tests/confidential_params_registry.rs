#![doc = "Confidential parameter registry flow tests covering publish and lifecycle operations."]
#![cfg(feature = "zk-tests")]
use iroha_core::{
    kura::Kura,
    query::store::LiveQueryStore,
    smartcontracts::Execute,
    state::{State, World, WorldReadOnly},
};
use iroha_data_model::{
    Registrable, ValidationFail,
    block::BlockHeader,
    confidential::{ConfidentialParamsId, ConfidentialStatus, PedersenParams, PoseidonParams},
    isi::{
        confidential,
        error::{InstructionExecutionError, InvalidParameterError},
    },
    permission::Permission,
    prelude::{Account, Domain, Grant, InstructionBox},
};
use iroha_executor_data_model::permission::governance::CanManageConfidentialParams;
use iroha_test_samples::ALICE_ID;
use mv::storage::StorageReadOnly;
use nonzero_ext::nonzero;
fn fresh_state() -> State {
    let domain_id: iroha_model_base::domain::DomainId =
        iroha_model_base::domain::DomainId::try_new("wonderland", "universal").expect("domain");
    let domain: Domain = Domain::new(domain_id).build(&ALICE_ID);
    let account: Account = Account::new(ALICE_ID.clone()).build(&ALICE_ID);
    let world = World::with([domain], [account], []);
    let kura = Kura::blank_kura_for_testing();
    let query_handle = LiveQueryStore::start_test();
    State::new_for_testing(world, kura, query_handle)
}
fn grant_manage_confidential_params(state: &mut State) {
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let perm = Permission::from(CanManageConfidentialParams);
    Grant::account_permission(perm, ALICE_ID.clone())
        .execute(&ALICE_ID, &mut stx)
        .expect("grant confidential permission");
    stx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit grant block");
}
fn sample_pedersen_params(id: u32) -> PedersenParams {
    PedersenParams {
        params_id: ConfidentialParamsId::new(id),
        generators_hash: [0x11; 32],
        constants_hash: [0x22; 32],
        metadata_uri_cid: Some(format!("ipfs://pedersen-{id}-meta")),
        params_cid: Some(format!("ipfs://pedersen-{id}-params")),
        activation_height: Some(10),
        withdraw_height: Some(30),
        status: ConfidentialStatus::Active,
    }
}
fn sample_poseidon_params(id: u32) -> PoseidonParams {
    PoseidonParams {
        params_id: ConfidentialParamsId::new(id),
        round_constants_hash: [0x33; 32],
        mds_matrix_hash: [0x44; 32],
        metadata_uri_cid: Some(format!("ipfs://poseidon-{id}-meta")),
        params_cid: Some(format!("ipfs://poseidon-{id}-params")),
        activation_height: Some(15),
        withdraw_height: Some(55),
        status: ConfidentialStatus::Active,
    }
}
#[test]
fn publish_pedersen_params_inserts_record() {
    let mut state = fresh_state();
    grant_manage_confidential_params(&mut state);
    let header = BlockHeader::new(nonzero!(2_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let executor = stx.world.executor().clone();
    let params = sample_pedersen_params(7);
    let id = params.params_id;
    let publish: InstructionBox = confidential::PublishPedersenParams {
        params: params.clone(),
    }
    .into();
    executor
        .execute_instruction(&mut stx, &ALICE_ID.clone(), publish)
        .expect("publish pedersen params");
    stx.apply();
    block
        .commit_world_overlay_for_testing()
        .expect("commit publish block");
    let view = state.view();
    let stored = view
        .world()
        .pedersen_params()
        .get(&id)
        .expect("pedersen params stored");
    assert_eq!(stored, &params);
}
#[test]
fn publish_pedersen_params_requires_permission() {
    let state = fresh_state();
    let header = BlockHeader::new(nonzero!(2_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let executor = stx.world.executor().clone();
    let params = sample_pedersen_params(3);
    let publish: InstructionBox = confidential::PublishPedersenParams { params }.into();
    let err = executor
        .execute_instruction(&mut stx, &ALICE_ID.clone(), publish)
        .expect_err("missing permission must fail");
    match err {
        ValidationFail::InstructionFailed(InstructionExecutionError::InvariantViolation(msg)) => {
            assert!(
                msg.contains("CanManageConfidentialParams"),
                "unexpected message: {msg}"
            );
        }
        other => panic!("unexpected error: {other:?}"),
    }
    drop(stx);
    block
        .commit_world_overlay_for_testing()
        .expect("commit missing permission block");
}
#[test]
fn publish_pedersen_params_rejects_duplicate_or_withdrawn() {
    let mut state = fresh_state();
    grant_manage_confidential_params(&mut state);
    let header = BlockHeader::new(nonzero!(3_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let executor = {
        let mut stx = block.transaction();
        let executor = stx.world.executor().clone();
        let params = sample_pedersen_params(11);
        let publish: InstructionBox = confidential::PublishPedersenParams {
            params: params.clone(),
        }
        .into();
        executor
            .execute_instruction(&mut stx, &ALICE_ID.clone(), publish)
            .expect("initial publish");
        stx.apply();
        executor
    };
    {
        let mut stx_dup = block.transaction();
        let params = sample_pedersen_params(11);
        let duplicate: InstructionBox = confidential::PublishPedersenParams {
            params: params.clone(),
        }
        .into();
        let dup_err = executor
            .execute_instruction(&mut stx_dup, &ALICE_ID.clone(), duplicate)
            .expect_err("duplicate publish must fail");
        match dup_err {
            ValidationFail::InstructionFailed(InstructionExecutionError::InvariantViolation(
                msg,
            )) => {
                assert!(
                    msg.contains("parameter set already exists"),
                    "unexpected message: {msg}"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
    {
        let withdrawn = confidential::PublishPedersenParams {
            params: PedersenParams {
                status: ConfidentialStatus::Withdrawn,
                ..sample_pedersen_params(12)
            },
        };
        let mut stx_withdrawn = block.transaction();
        let err = executor
            .execute_instruction(&mut stx_withdrawn, &ALICE_ID.clone(), withdrawn.into())
            .expect_err("withdrawn publish must fail");
        match err {
            ValidationFail::InstructionFailed(InstructionExecutionError::InvalidParameter(
                InvalidParameterError::SmartContract(msg),
            )) => {
                assert!(
                    msg.contains("cannot publish pedersen params with Withdrawn status"),
                    "unexpected message: {msg}"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
    block
        .commit_world_overlay_for_testing()
        .expect("commit pedersen duplicate block");
}
#[test]
fn set_pedersen_params_lifecycle_updates_entry() {
    let mut state = fresh_state();
    grant_manage_confidential_params(&mut state);
    let header = BlockHeader::new(nonzero!(4_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let params = sample_pedersen_params(5);
    let id = params.params_id;
    let executor = {
        let mut stx = block.transaction();
        let executor = stx.world.executor().clone();
        executor
            .execute_instruction(
                &mut stx,
                &ALICE_ID.clone(),
                confidential::PublishPedersenParams {
                    params: params.clone(),
                }
                .into(),
            )
            .expect("publish pedersen params");
        stx.apply();
        executor
    };
    {
        let mut stx_update = block.transaction();
        let update = confidential::SetPedersenParamsLifecycle {
            params_id: id,
            status: ConfidentialStatus::Proposed,
            activation_height: Some(42),
            withdraw_height: Some(80),
        };
        executor
            .execute_instruction(&mut stx_update, &ALICE_ID.clone(), update.into())
            .expect("update lifecycle");
        stx_update.apply();
    }
    block
        .commit_world_overlay_for_testing()
        .expect("commit pedersen lifecycle block");
    let view = state.view();
    let stored = view
        .world()
        .pedersen_params()
        .get(&id)
        .expect("pedersen params present");
    assert_eq!(stored.status, ConfidentialStatus::Proposed);
    assert_eq!(stored.activation_height, Some(42));
    assert_eq!(stored.withdraw_height, Some(80));
}
#[test]
fn set_pedersen_params_lifecycle_missing_or_withdrawn() {
    let mut state = fresh_state();
    grant_manage_confidential_params(&mut state);
    let header = BlockHeader::new(nonzero!(5_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let executor = stx.world.executor().clone();
    // Missing entry
    let missing = confidential::SetPedersenParamsLifecycle {
        params_id: ConfidentialParamsId::new(99),
        status: ConfidentialStatus::Active,
        activation_height: None,
        withdraw_height: None,
    };
    let err = executor
        .execute_instruction(&mut stx, &ALICE_ID.clone(), missing.into())
        .expect_err("missing params should fail");
    match err {
        ValidationFail::InstructionFailed(InstructionExecutionError::Find(find_err)) => {
            assert!(
                format!("{find_err:?}").contains("PedersenParamsMissing"),
                "unexpected find error: {find_err:?}"
            );
        }
        other => panic!("unexpected error: {other:?}"),
    }
    drop(stx);
    // Insert params and withdraw them.
    let params = sample_pedersen_params(13);
    let id = params.params_id;
    {
        let mut stx_publish = block.transaction();
        executor
            .execute_instruction(
                &mut stx_publish,
                &ALICE_ID.clone(),
                confidential::PublishPedersenParams {
                    params: params.clone(),
                }
                .into(),
            )
            .expect("publish pedersen params");
        stx_publish.apply();
    }
    {
        let mut stx_withdraw = block.transaction();
        let withdraw = confidential::SetPedersenParamsLifecycle {
            params_id: id,
            status: ConfidentialStatus::Withdrawn,
            activation_height: None,
            withdraw_height: Some(120),
        };
        executor
            .execute_instruction(&mut stx_withdraw, &ALICE_ID.clone(), withdraw.into())
            .expect("withdraw params");
        stx_withdraw.apply();
    }
    // Attempt to update withdrawn entry again.
    {
        let mut stx_again = block.transaction();
        let update_again = confidential::SetPedersenParamsLifecycle {
            params_id: id,
            status: ConfidentialStatus::Active,
            activation_height: None,
            withdraw_height: None,
        };
        let err = executor
            .execute_instruction(&mut stx_again, &ALICE_ID.clone(), update_again.into())
            .expect_err("updating withdrawn params must fail");
        match err {
            ValidationFail::InstructionFailed(InstructionExecutionError::InvariantViolation(
                msg,
            )) => {
                assert!(
                    msg.contains("cannot update withdrawn pedersen params"),
                    "unexpected message: {msg}"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
    block
        .commit_world_overlay_for_testing()
        .expect("commit pedersen lifecycle missing block");
}
#[test]
fn publish_poseidon_params_and_update_lifecycle() {
    let mut state = fresh_state();
    grant_manage_confidential_params(&mut state);
    let header = BlockHeader::new(nonzero!(6_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let params = sample_poseidon_params(2);
    let id = params.params_id;
    let executor = {
        let mut stx = block.transaction();
        let executor = stx.world.executor().clone();
        executor
            .execute_instruction(
                &mut stx,
                &ALICE_ID.clone(),
                confidential::PublishPoseidonParams {
                    params: params.clone(),
                }
                .into(),
            )
            .expect("publish poseidon params");
        stx.apply();
        executor
    };
    {
        // Update lifecycle metadata.
        let mut stx_update = block.transaction();
        let update = confidential::SetPoseidonParamsLifecycle {
            params_id: id,
            status: ConfidentialStatus::Proposed,
            activation_height: Some(30),
            withdraw_height: Some(120),
        };
        executor
            .execute_instruction(&mut stx_update, &ALICE_ID.clone(), update.into())
            .expect("update poseidon lifecycle");
        stx_update.apply();
    }
    block
        .commit_world_overlay_for_testing()
        .expect("commit poseidon lifecycle block");
    let view = state.view();
    let stored = view
        .world()
        .poseidon_params()
        .get(&id)
        .expect("poseidon params available");
    assert_eq!(stored.status, ConfidentialStatus::Proposed);
    assert_eq!(stored.activation_height, Some(30));
    assert_eq!(stored.withdraw_height, Some(120));
}
#[test]
fn poseidon_lifecycle_missing_and_withdrawn_behaviour() {
    let mut state = fresh_state();
    grant_manage_confidential_params(&mut state);
    let header = BlockHeader::new(nonzero!(7_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut stx = block.transaction();
    let executor = stx.world.executor().clone();
    // Missing entry
    let missing = confidential::SetPoseidonParamsLifecycle {
        params_id: ConfidentialParamsId::new(200),
        status: ConfidentialStatus::Active,
        activation_height: None,
        withdraw_height: None,
    };
    let err = executor
        .execute_instruction(&mut stx, &ALICE_ID.clone(), missing.into())
        .expect_err("missing poseidon params should fail");
    match err {
        ValidationFail::InstructionFailed(InstructionExecutionError::Find(find_err)) => {
            assert!(
                format!("{find_err:?}").contains("PoseidonParamsMissing"),
                "unexpected error: {find_err:?}"
            );
        }
        other => panic!("unexpected error: {other:?}"),
    }
    drop(stx);
    // Publish + withdraw poseidon params.
    let params = sample_poseidon_params(3);
    let id = params.params_id;
    {
        let mut stx_publish = block.transaction();
        executor
            .execute_instruction(
                &mut stx_publish,
                &ALICE_ID.clone(),
                confidential::PublishPoseidonParams {
                    params: params.clone(),
                }
                .into(),
            )
            .expect("publish poseidon params");
        stx_publish.apply();
    }
    {
        let mut stx_withdraw = block.transaction();
        let withdraw = confidential::SetPoseidonParamsLifecycle {
            params_id: id,
            status: ConfidentialStatus::Withdrawn,
            activation_height: None,
            withdraw_height: Some(250),
        };
        executor
            .execute_instruction(&mut stx_withdraw, &ALICE_ID.clone(), withdraw.into())
            .expect("withdraw poseidon params");
        stx_withdraw.apply();
    }
    let err = {
        let mut stx_again = block.transaction();
        executor
            .execute_instruction(
                &mut stx_again,
                &ALICE_ID.clone(),
                confidential::SetPoseidonParamsLifecycle {
                    params_id: id,
                    status: ConfidentialStatus::Active,
                    activation_height: None,
                    withdraw_height: None,
                }
                .into(),
            )
            .expect_err("updating withdrawn poseidon params must fail")
    };
    match err {
        ValidationFail::InstructionFailed(InstructionExecutionError::InvariantViolation(msg)) => {
            assert!(
                msg.contains("cannot update withdrawn poseidon params"),
                "unexpected message: {msg}"
            );
        }
        other => panic!("unexpected error: {other:?}"),
    }
    block
        .commit_world_overlay_for_testing()
        .expect("commit poseidon lifecycle missing block");
}
