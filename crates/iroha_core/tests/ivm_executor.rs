//! Unit tests for executing single instructions via the IVM executor.

use iroha_core::{
    executor::Executor,
    kura::Kura,
    query,
    state::{State, World, WorldReadOnly},
};
use iroha_data_model::prelude::*;
use iroha_model_base::domain::DomainId;
use iroha_test_samples::ALICE_ID;
use nonzero_ext::nonzero;
use std::sync::Arc;
#[test]
fn ivm_instruction_executes() {
    let executor = Executor::default();
    let world = World::new();
    let kura = Kura::blank_kura_for_testing();
    let query_handle = query::store::LiveQueryStore::start_test();
    let state = new_state(world, kura, query_handle);
    let block_header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(block_header);
    let mut state_tx = block.transaction();
    let domain_id: DomainId = DomainId::try_new("test", "universal").expect("domain id");
    let instruction: InstructionBox = Register::domain(Domain::new(domain_id.clone())).into();
    executor
        .execute_instruction(&mut state_tx, &ALICE_ID.clone(), instruction)
        .expect("execution");
    assert!(state_tx.world.domain(&domain_id).is_ok());
}
#[test]
fn ivm_instruction_reports_error() {
    let executor = Executor::default();
    let world = World::new();
    let kura = Kura::blank_kura_for_testing();
    let query_handle = query::store::LiveQueryStore::start_test();
    let state = new_state(world, kura, query_handle);
    let block_header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(block_header);
    let mut state_tx = block.transaction();
    let domain_id: DomainId = DomainId::try_new("fail", "universal").expect("domain id");
    let instruction: InstructionBox = Register::domain(Domain::new(domain_id.clone())).into();
    executor
        .execute_instruction(&mut state_tx, &ALICE_ID.clone(), instruction.clone())
        .expect("first execution");
    let result = executor.execute_instruction(&mut state_tx, &ALICE_ID.clone(), instruction);
    assert!(result.is_err());
}
#[test]
fn register_genesis_domain_rejected() {
    let executor = Executor::default();
    let world = World::new();
    let kura = Kura::blank_kura_for_testing();
    let query_handle = query::store::LiveQueryStore::start_test();
    let state = new_state(world, kura, query_handle);
    let block_header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(block_header);
    let mut state_tx = block.transaction();
    let domain_id = (*iroha_genesis::GENESIS_DOMAIN_ID).clone();
    let instruction: InstructionBox = Register::domain(Domain::new(domain_id.clone())).into();
    let result = executor.execute_instruction(&mut state_tx, &ALICE_ID.clone(), instruction);
    let err = result.expect_err("genesis domain must be rejected");
    assert!(format!("{err:?}").contains("genesis domain"));
}
fn new_state(
    world: World,
    kura: Arc<Kura>,
    query_handle: query::store::LiveQueryStoreHandle,
) -> State {
    State::new_for_testing(world, kura, query_handle)
}
