//! Shared nested-return capture keeps the original resource owner for rollback and retry.

use super::CoreHost;
use crate::{
    execution_attempt::{ExecutionAttemptError, vm_attempt_error},
    smartcontracts::ivm::return_value::resource_tests::{funded_return_vm, leave_read_slots},
};
use iroha_data_model::smart_contract::entrypoint::{
    EntrypointValueTypeNodeV1, EntrypointValueTypeV1,
};
use ivm::VMError;

#[test]
fn nested_return_capture_preserves_read_refusal_and_original_pool_retry() {
    let (vm, budget) = funded_return_vm();
    let schema = EntrypointValueTypeV1 {
        nodes: vec![EntrypointValueTypeNodeV1::Unit],
    };
    let baseline = ivm::value_record::capture_completed_return_funded(&vm, &schema, &budget)
        .unwrap()
        .get()
        .clone();
    let gas = vm.remaining_gas();
    let expected = leave_read_slots(&vm, &budget, 0);
    let error = ivm::value_record::capture_completed_return_funded(&vm, &schema, &budget)
        .err()
        .expect("the original VM read capacity refuses capture");
    assert_eq!(error, expected);
    assert_eq!(vm.remaining_gas(), gas);
    let attempt = vm_attempt_error(VMError::metered(99, error), |_| {
        panic!("local refusal became rejection")
    });
    let ExecutionAttemptError::Deferred(owner) = attempt else {
        panic!("nested return capacity must preserve an unfinished attempt");
    };
    assert_eq!(owner.clone().into_vm_error(), expected);
    budget.set_limit_bytes(128 * 1024 * 1024);
    assert_eq!(
        ivm::value_record::capture_completed_return_funded(&vm, &schema, &budget)
            .unwrap()
            .get(),
        &baseline
    );
    assert_eq!(vm.remaining_gas(), gas);
    drop(vm);
    assert_eq!(budget.reserved_bytes(), 0);
    // The retry receipt may outlive every physical allocation and the original
    // budget handle without replacing its release-observation owner.
    drop(budget);
    assert_eq!(owner.into_vm_error(), expected);
}

fn assert_sticky_deferral(error: VMError) {
    use crate::{
        kura::Kura,
        query::store::LiveQueryStore,
        state::{State, World},
    };
    let expected = crate::execution_attempt::ExecutionDeferred::from_vm_error(&error).unwrap();
    let state = State::new_for_testing(
        World::default(),
        Kura::blank_kura_for_testing(),
        LiveQueryStore::start_test(),
    );
    let mut block = state.block(iroha_data_model::block::BlockHeader::new(
        std::num::NonZeroU64::MIN,
        None,
        None,
        0,
        0,
    ));
    let mut transaction = block.transaction();
    transaction.vm_error_to_validation_fail(VMError::metered(99, error), |_| {
        panic!("local syscall refusal became deterministic rejection")
    });
    assert_eq!(transaction.execution_deferral(), Some(expected));
    assert_eq!(transaction.last_tx_gas_used, 0);
}

#[test]
fn contract_lookup_syscall_preserves_both_actual_tlv_read_refusals() {
    use ivm::{IVMHost, PointerType, codec::encode_canonical_norito, syscalls};
    let (mut vm, budget) = funded_return_vm();
    let alias_name: super::Name = "fixture::resource".parse().unwrap();
    let alias: super::ContractAlias = alias_name.as_ref().parse().unwrap();
    let payload = encode_canonical_norito(&alias_name).unwrap();
    let envelope = CoreHost::encode_tlv_payload(PointerType::Name, &payload).unwrap();
    let pointer = vm.alloc_host_tlv(&envelope).unwrap();
    let table = vm.register(10);
    let mut host = CoreHost::new(iroha_test_samples::ALICE_ID.clone());
    assert!(
        matches!(CoreHost::decode_contract_instance_lookup(&vm, pointer), Ok(super::ContractInstanceLookup::Alias(actual)) if actual == alias)
    );
    let gas = vm.remaining_gas();
    for spare_reads in 0..2 {
        vm.set_register(10, table);
        let expected = leave_read_slots(&vm, &budget, spare_reads);
        vm.set_register(10, pointer);
        let error = host
            .syscall(syscalls::SYSCALL_QUERY_GET_CONTRACT_INSTANCE, &mut vm)
            .unwrap_err();
        assert_eq!(error, expected);
        assert_eq!(vm.register(10), pointer);
        assert_eq!(vm.remaining_gas(), gas);
        assert_sticky_deferral(error);
        budget.set_limit_bytes(128 * 1024 * 1024);
        assert!(
            matches!(CoreHost::decode_contract_instance_lookup(&vm, pointer), Ok(super::ContractInstanceLookup::Alias(actual)) if actual == alias)
        );
    }
}

#[test]
fn contract_lookup_dispatch_preserves_current_shapes_and_semantic_errors() {
    use ivm::{PointerType, codec::encode_canonical_norito};
    let (mut vm, _budget) = funded_return_vm();
    let address = super::ContractAddress::derive(
        &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
            .parse()
            .unwrap(),
        &iroha_test_samples::ALICE_ID,
        43,
        iroha_model_base::topology::DataSpaceId::UNIVERSAL,
    )
    .unwrap();
    let encoded = encode_canonical_norito(&address).unwrap();
    let envelope = CoreHost::encode_tlv_payload(PointerType::NoritoBytes, &encoded).unwrap();
    let pointer = vm.alloc_host_tlv(&envelope).unwrap();
    assert!(
        matches!(CoreHost::decode_contract_instance_lookup(&vm, pointer), Ok(super::ContractInstanceLookup::Address(actual)) if actual == address)
    );
    for (pointer_type, payload, expected) in [
        (PointerType::NoritoBytes, vec![0xFF], VMError::NoritoInvalid),
        (PointerType::Name, vec![0xFF], VMError::DecodeError),
        (PointerType::Blob, vec![0xFF], VMError::NoritoInvalid),
    ] {
        let envelope = CoreHost::encode_tlv_payload(pointer_type, &payload).unwrap();
        let pointer = vm.alloc_host_tlv(&envelope).unwrap();
        assert_eq!(
            CoreHost::decode_contract_instance_lookup(&vm, pointer).err(),
            Some(expected)
        );
    }
}

fn fill_input(vm: &mut ivm::IVM) {
    for bytes in [&[0_u8; 1024][..], &[0_u8; 1][..]] {
        loop {
            match vm.alloc_input_tlv(bytes) {
                Ok(_) => {}
                Err(VMError::MemoryOutOfBounds) => break,
                Err(error) => panic!("unexpected local input allocation failure: {error}"),
            }
        }
    }
}

#[test]
fn vrf_seed_syscall_defers_funded_output_without_guest_status_or_gas() {
    use ivm::{IVMHost, PointerType, syscalls};
    let (mut vm, budget) = funded_return_vm();
    // Exhaust INPUT so the seed must use the actual funded HEAP write owner.
    fill_input(&mut vm);
    let _read_refusal = leave_read_slots(&vm, &budget, 2);
    let reserved = budget.reserved_bytes();
    let gas = vm.remaining_gas();
    let mut host = CoreHost::new(iroha_test_samples::ALICE_ID.clone());
    host.vrf_epoch_seeds.insert(7, [0x42; 32]);
    vm.set_register(10, 7);
    vm.set_register(11, 0xA5);
    let error = host
        .syscall(syscalls::SYSCALL_VRF_EPOCH_SEED, &mut vm)
        .unwrap_err();
    assert!(matches!(
        &error,
        VMError::AllocationDeferred(iroha_allocation::AllocationRefusal::Capacity { .. })
    ));
    assert_eq!(vm.register(10), 7);
    assert_eq!(
        vm.register(11),
        0xA5,
        "local refusal must not publish a guest status"
    );
    assert_eq!(vm.remaining_gas(), gas);
    assert_eq!(
        budget.reserved_bytes(),
        reserved,
        "refused output retains no partial payload"
    );
    assert_sticky_deferral(error);
    budget.set_limit_bytes(128 * 1024 * 1024);
    host.syscall(syscalls::SYSCALL_VRF_EPOCH_SEED, &mut vm)
        .unwrap();
    assert_eq!(vm.register(11), 0xA5);
    let response = vm.validate_tlv(vm.register(10)).unwrap();
    assert_eq!(response.type_id, PointerType::Blob);
    assert_eq!(response.payload, [0x42; 32]);
}

#[test]
fn vrf_seed_syscall_preserves_deterministic_guest_oom_fault() {
    use ivm::{IVMHost, syscalls};
    let (mut vm, _budget) = funded_return_vm();
    fill_input(&mut vm);
    let heap_end = vm.alloc_heap(0).unwrap();
    vm.memory
        .set_heap_max_limit(heap_end - ivm::Memory::HEAP_START)
        .unwrap();
    vm.set_register(10, 7);
    vm.set_register(11, 0xA5);
    let mut host = CoreHost::new(iroha_test_samples::ALICE_ID.clone());
    host.vrf_epoch_seeds.insert(7, [0x42; 32]);
    assert!(matches!(
        host.syscall(syscalls::SYSCALL_VRF_EPOCH_SEED, &mut vm),
        Err(VMError::OutOfMemory)
    ));
    assert_eq!(vm.register(10), 7);
    assert_eq!(vm.register(11), 0xA5);
}

#[test]
fn original_npos_policy_refusal_preserves_host_seed_projection_and_retries() {
    use crate::{
        state::{World, WorldReadOnly},
        sumeragi::test_chain::{CertifiedTestChain, TestChainConfig},
    };
    use iroha_data_model::parameter::{
        Parameter,
        system::{SumeragiConsensusMode, SumeragiNposParameters},
    };
    let mut config = TestChainConfig::new(World::new(), 1_000);
    config.consensus_mode = SumeragiConsensusMode::Npos;
    config.genesis_parameters.push(Parameter::Custom(
        SumeragiNposParameters::default().into_custom_parameter(),
    ));
    let chain = CertifiedTestChain::start(config).unwrap();
    let view = chain.state().view();
    let original = view
        .world()
        .parameters()
        .custom()
        .get(&SumeragiNposParameters::parameter_id())
        .unwrap();
    let bytes = original.payload().get().to_owned();
    let mut host = CoreHost::new(iroha_test_samples::ALICE_ID.clone());
    host.vrf_epoch_seeds.insert(7, [0x42; 32]);
    let before = host.vrf_epoch_seeds.clone();
    let error = norito::with_decode_limits_scope(
        norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, 64),
        || host.set_vrf_epoch_seeds_from_state(&view),
    )
    .unwrap_err();
    let ExecutionAttemptError::Deferred(refusal) = error else {
        panic!("original policy refusal cleared completed seeds: {error:?}");
    };
    assert_eq!(
        refusal.reason(),
        ivm::error::ExecutionDeferral::ActiveMemoryCapacity
    );
    assert!(refusal.allocation_refusal().is_none());
    assert_eq!(host.vrf_epoch_seeds, before);
    assert_eq!(original.payload().get(), &bytes);
    host.set_vrf_epoch_seeds_from_state(&view).unwrap();
    assert!(
        host.vrf_epoch_seeds.is_empty(),
        "the authenticated source has no finalized pulses"
    );
    assert_eq!(original.payload().get(), &bytes);
}
