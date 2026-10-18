//! Executor fixture admission and migration-boundary tests.

use core::num::NonZeroU64;
use iroha_core::{
    executor::Executor as RuntimeExecutor,
    kura::Kura,
    query::store::LiveQueryStore,
    state::{State, World, WorldReadOnly},
};
use iroha_data_model::{block::BlockHeader, smart_contract::payloads::ExecutorContext};
use iroha_data_model::{
    executor::Executor as DataModelExecutor, transaction::executable::IvmBytecode,
};
use iroha_model_base::chain::ChainId;
use iroha_test_samples::ALICE_ID;
use ivm::{IVM, Memory, VMError, host::IVMHost};
struct LoggingHost;
impl IVMHost for LoggingHost {
    fn prepare_syscall(&self, _number: u32, _vm: &IVM) -> Result<u64, VMError> {
        Ok(0)
    }
    fn syscall(&mut self, number: u32, _vm: &mut IVM) -> Result<u64, VMError> {
        println!("syscall {number:#x}");
        Err(VMError::UnknownSyscall(number))
    }
    fn as_any(&mut self) -> &mut dyn core::any::Any {
        self
    }
}
#[test]
fn canonical_executor_runs_without_hidden_host_semantics() {
    const LENGTH_PREFIX_BYTES: usize = 8;
    let bytes = include_bytes!("../../../defaults/executor.to");
    let mut vm = IVM::new(0);
    vm.load_program(bytes).unwrap();
    vm.set_host(LoggingHost);
    let context = ExecutorContext {
        authority: ALICE_ID.clone(),
        curr_block: BlockHeader::new(NonZeroU64::new(1).unwrap(), None, None, 0, 0),
    };
    let payload = norito::to_bytes(&context).unwrap();
    let mut bytes_with_len = Vec::with_capacity(LENGTH_PREFIX_BYTES + payload.len());
    let framed_len = u64::try_from(LENGTH_PREFIX_BYTES + payload.len()).unwrap();
    bytes_with_len.extend_from_slice(&framed_len.to_le_bytes());
    bytes_with_len.extend_from_slice(&payload);
    vm.store_bytes(Memory::HEAP_START, &bytes_with_len).unwrap();
    vm.set_register(10, Memory::HEAP_START);
    vm.set_gas_limit(50_000_000);
    vm.run()
        .expect("canonical executor must run through ordinary guest semantics");
}
#[test]
fn tiny_halt_bytecode_cannot_select_fixture_migration_behavior() {
    let state = State::new_with_chain_for_testing(
        World::new(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
        ChainId::from("executor-fixture-migration-regression"),
    );
    let block_header = BlockHeader::new(
        NonZeroU64::new(1).expect("nonzero block height"),
        None,
        None,
        0,
        0,
    );
    let mut block = state.block(block_header);
    let mut state_transaction = block.transaction();
    let original_data_model = state_transaction.world.executor_data_model().clone();
    let mut executor = RuntimeExecutor::Initial;
    for vector_length in 1..=8 {
        let mut bytecode = ivm::ProgramMetadata {
            version_major: 1,
            version_minor: 1,
            mode: 0,
            vector_length,
            max_cycles: 1_000_000,
            abi_version: 1,
        }
        .encode();
        bytecode.extend_from_slice(&ivm::encoding::wide::encode_halt().to_le_bytes());
        let raw = DataModelExecutor::new(IvmBytecode::from_compiled(bytecode));
        let error = executor
            .migrate(raw, &mut state_transaction, &ALICE_ID)
            .expect_err("a HALT-only program does not return a canonical migration result");
        assert!(
            matches!(
                error,
                iroha_core::executor::ExecutorMigrationError::Rejected(VMError::DecodeError)
            ),
            "vector-length metadata must not select host fixture behavior"
        );
        assert!(
            matches!(executor, RuntimeExecutor::Initial),
            "failed guest migration must not install its executor"
        );
        assert_eq!(
            state_transaction.world.executor_data_model(),
            &original_data_model,
            "failed guest migration must not apply a host-side fixture model"
        );
    }
}
