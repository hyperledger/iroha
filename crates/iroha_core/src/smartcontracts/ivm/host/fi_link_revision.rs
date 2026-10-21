//! Metered exact scalar projection of the current owner-approved FI-link revision.

use super::*;
use crate::state::asset_fi::AssetFiLinkRevisionError;

fn map_revision_error(error: AssetFiLinkRevisionError) -> ivm::VMError {
    match error {
        AssetFiLinkRevisionError::Local(original) => original.into_vm_error(),
        AssetFiLinkRevisionError::Query(error)
        | AssetFiLinkRevisionError::Execution(
            iroha_data_model::isi::error::InstructionExecutionError::Query(error),
        ) => map_query_execution_error(crate::execution_attempt::ExecutionAttemptError::Rejected(
            error,
        )),
        AssetFiLinkRevisionError::Execution(_) => ivm::VMError::DecodeError,
    }
}

impl QueryStateRef<'_, '_, '_> {
    pub(super) fn read_fi_link_revision(
        &self,
        authority: &AccountId,
        context: &ContractRuntimeExecutionContext,
        definition: &AssetDefinitionId,
        account: &AccountId,
        expected_fi: &AccountId,
        budget: QueryExecutionBudget,
    ) -> Result<(u64, QueryExecutionStats), ivm::VMError> {
        macro_rules! read {
            ($state:expr) => {
                crate::state::asset_fi::link_revision_for_contract(
                    $state.world(),
                    authority,
                    context,
                    definition,
                    account,
                    expected_fi,
                    budget,
                )
                .map_err(map_revision_error)
            };
        }
        match *self {
            Self::View(value) => read!(value),
            Self::QueryView(value) => read!(value),
            Self::Block(value) => read!(value),
            Self::Transaction(value) => read!(value),
        }
    }
}

impl<QS: Default + QueryStateAccess> CoreHostImpl<QS> {
    pub(super) fn execute_fi_link_revision(
        &mut self,
        vm: &mut IVM,
        syscall: u32,
    ) -> Result<u64, ivm::VMError> {
        let context = self
            .current_contract_runtime_context
            .as_ref()
            .ok_or(ivm::VMError::PermissionDenied)?;
        vm.ensure_public_register(10)?;
        vm.ensure_public_register(11)?;
        vm.ensure_public_register(12)?;
        let definition: AssetDefinitionId =
            Self::decode_tlv_typed(vm, vm.register(10), PointerType::AssetDefinitionId)?;
        let account: AccountId =
            Self::decode_tlv_typed(vm, vm.register(11), PointerType::AccountId)?;
        let expected_fi: AccountId =
            Self::decode_tlv_typed(vm, vm.register(12), PointerType::AccountId)?;
        let remaining = vm.remaining_gas();
        let gas_context = QueryGasContext::singular();
        let budget = Self::query_execution_budget(&gas_context, remaining)?;
        let state = self
            .query_state
            .get()
            .ok_or(ivm::VMError::NotImplemented { syscall })?;
        let (revision, stats) = state.fi_link_revision(
            &self.effect_authority(),
            context,
            &definition,
            &account,
            &expected_fi,
            budget,
        )?;
        let encoded = ivm_abi::numeric_tlv::encode_int(&BigInt::from(revision))?;
        let length = u64::try_from(encoded.len()).map_err(|_| ivm::VMError::GasCostOverflow)?;
        let gas = Self::finish_core_query_encoded_bytes_gas(
            vm,
            remaining,
            &gas_context,
            stats.processed_items(),
            stats.processed_bytes(),
            length,
        )?;
        vm.preflight_host_tlv_allocations_with_reserved_heap(&[encoded.len()], 0)?;
        let pointer = vm.alloc_host_tlv(&encoded)?;
        vm.set_register(10, pointer);
        Ok(gas)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{norito_blob, store_tlv};
    use super::*;
    use crate::state::asset_fi::FiLinkReaderFixture as Fixture;
    use iroha_data_model::prelude::BlockHeader;
    use ivm::host::IVMHost;
    use std::num::NonZeroU64;

    fn header() -> BlockHeader {
        BlockHeader::new(NonZeroU64::new(1).unwrap(), None, None, 1_000, 0)
    }
    fn arguments(f: &Fixture, gas: u64) -> IVM {
        let mut vm = IVM::new(gas);
        for (register, kind, payload) in [
            (
                10,
                PointerType::AssetDefinitionId,
                norito_blob(&f.definition),
            ),
            (11, PointerType::AccountId, norito_blob(&f.wallet)),
            (12, PointerType::AccountId, norito_blob(&f.bank)),
        ] {
            let pointer = store_tlv(&mut vm, kind, &payload);
            vm.set_register(register, pointer);
        }
        vm
    }
    fn assert_revision(vm: &IVM, pointer: u64, expected: u64) {
        let actual = CoreHost::decode_pointer_tlv(vm, pointer, PointerType::Int).unwrap();
        assert_eq!(
            actual.payload,
            IntValueV1::try_new(BigInt::from(expected))
                .unwrap()
                .encode_frame()
                .unwrap()
        );
    }

    #[test]
    fn fi_revision_host_returns_exact_full_u64_tlv_and_shared_source_output_gas() {
        let (f, state) = Fixture::new();
        let mut block = state.block(header());
        let mut tx = block.transaction();
        f.install(&mut tx);
        let mut host: CoreHostImpl<QueryStateSlot<_>> = CoreHostImpl::new(f.owner.clone());
        host.set_query_state(&tx);
        host.set_contract_runtime_context(Some(f.context.clone()));
        let mut vm = arguments(&f, 50_000_000);
        let gas = host
            .syscall(ivm::syscalls::SYSCALL_ASSET_FI_LINK_REVISION, &mut vm)
            .unwrap();
        assert_revision(&vm, vm.register(10), u64::MAX);
        let (_, stats) = f.read(tx.world()).unwrap();
        let encoded = ivm_abi::numeric_tlv::encode_int(&BigInt::from(u64::MAX)).unwrap();
        assert_eq!(
            gas,
            CoreHost::query_gas_cost(
                &QueryGasContext::singular(),
                stats.processed_items(),
                stats.processed_bytes() + encoded.len() as u64
            )
        );
        assert!(host.queued.is_empty());
        assert_eq!(host.instruction_queue_count, 0);
    }

    fn read_revision(f: &Fixture, state: QueryStateRef<'_, '_, '_>) -> u64 {
        state
            .read_fi_link_revision(
                &f.context.contract_subject,
                &f.context,
                &f.definition,
                &f.wallet,
                &f.bank,
                QueryExecutionBudget::from_weighted_limit(10_000_000, 7, 3),
            )
            .unwrap()
            .0
    }

    #[test]
    fn fi_revision_all_four_query_state_views_read_same_retained_grant() {
        let (f, state) = Fixture::new();
        let mut block = state.block(header());
        let mut tx = block.transaction();
        f.install(&mut tx);
        assert_eq!(read_revision(&f, QueryStateRef::Transaction(&tx)), u64::MAX);
        tx.apply();
        assert_eq!(read_revision(&f, QueryStateRef::Block(&block)), u64::MAX);
        block.commit_world_overlay_for_testing().unwrap();
        assert_eq!(
            read_revision(&f, QueryStateRef::View(&state.view())),
            u64::MAX
        );
        assert_eq!(
            read_revision(&f, QueryStateRef::QueryView(&state.query_view())),
            u64::MAX
        );
    }

    #[test]
    fn fi_revision_host_refuses_missing_or_forged_frame_expected_fi_and_wrong_pointer() {
        let (f, state) = Fixture::new();
        let mut block = state.block(header());
        let mut tx = block.transaction();
        f.install(&mut tx);
        for defect in 0..5 {
            let mut host: CoreHostImpl<QueryStateSlot<_>> = CoreHostImpl::new(f.owner.clone());
            host.set_query_state(&tx);
            let mut context = f.context.clone();
            if defect == 1 {
                context.contract_subject = f.owner.clone();
            }
            if defect != 0 {
                host.set_contract_runtime_context(Some(context));
            }
            let mut vm = arguments(&f, 50_000_000);
            if defect == 2 {
                let pointer = store_tlv(&mut vm, PointerType::AccountId, &norito_blob(&f.other));
                vm.set_register(12, pointer);
            }
            if defect == 3 {
                vm.set_register(12, vm.register(10));
            }
            if defect == 4 {
                vm.set_register(11, vm.register(10));
            }
            let before = vm.register(10);
            let input_before = vm.alloc_input_tlv(&[]).unwrap();
            assert!(
                host.syscall(ivm::syscalls::SYSCALL_ASSET_FI_LINK_REVISION, &mut vm)
                    .is_err(),
                "defect {defect}"
            );
            assert_eq!(vm.register(10), before);
            assert_eq!(vm.alloc_input_tlv(&[]).unwrap(), input_before);
            assert!(host.queued.is_empty());
            assert_eq!(host.instruction_queue_count, 0);
        }
        // A frame does not permit fallback to an authority-only host without native state.
        let mut host = CoreHost::new(f.owner.clone());
        host.set_contract_runtime_context(Some(f.context.clone()));
        let mut vm = arguments(&f, 50_000_000);
        assert!(matches!(
            host.syscall(ivm::syscalls::SYSCALL_ASSET_FI_LINK_REVISION, &mut vm),
            Err(ivm::VMError::NotImplemented { .. })
        ));
    }

    #[test]
    fn fi_revision_whole_allocation_refusal_preserves_arenas_registers_and_queue() {
        let (f, state) = Fixture::new();
        let mut block = state.block(header());
        let mut tx = block.transaction();
        f.install(&mut tx);
        let mut host: CoreHostImpl<QueryStateSlot<_>> = CoreHostImpl::new(f.owner.clone());
        host.set_query_state(&tx);
        host.set_contract_runtime_context(Some(f.context.clone()));
        let mut vm = arguments(&f, 50_000_000);
        let next = vm.alloc_input_tlv(&[]).unwrap() - ivm::Memory::INPUT_START;
        vm.alloc_input_tlv(&vec![0; (ivm::Memory::INPUT_SIZE - next) as usize])
            .unwrap();
        let heap_before = (vm.alloc_heap(0).unwrap() - ivm::Memory::HEAP_START);
        vm.memory.set_heap_limit(heap_before).unwrap();
        let before = vm.register(10);
        assert!(matches!(
            host.syscall(ivm::syscalls::SYSCALL_ASSET_FI_LINK_REVISION, &mut vm),
            Err(ivm::VMError::OutOfMemory)
        ));
        assert_eq!(vm.register(10), before);
        assert_eq!(
            (vm.alloc_heap(0).unwrap() - ivm::Memory::HEAP_START),
            heap_before
        );
        assert_eq!(
            vm.alloc_input_tlv(&[]).unwrap(),
            ivm::Memory::INPUT_START + ivm::Memory::INPUT_SIZE
        );
        assert!(host.queued.is_empty());
        assert_eq!(host.instruction_queue_count, 0);
    }

    #[test]
    fn fi_revision_mapping_preserves_original_local_owner_and_deterministic_gas() {
        let budget = iroha_allocation::AllocationBudget::new(2);
        let retained = budget.try_reserve_bytes(2).unwrap();
        let refusal = budget.try_reserve_bytes(1).unwrap_err();
        let expected = refusal.clone();
        let mapped = map_revision_error(AssetFiLinkRevisionError::Local(refusal.into()));
        assert!(matches!(mapped,ivm::VMError::AllocationDeferred(actual) if actual == expected));
        drop(retained);
        assert!(budget.try_reserve_bytes(1).is_ok());
        assert!(matches!(
            map_revision_error(AssetFiLinkRevisionError::Query(
                QueryExecutionFail::GasBudgetExceeded
            )),
            ivm::VMError::OutOfGas
        ));
    }

    const SOURCE: &str = r#"seiyaku FiRevision {
        view fn revision(AssetDefinitionId asset, AccountId wallet, AccountId fi) authorize(anyone) -> int {
            ledger::fi::link_revision(asset_definition: asset, account: wallet, expected_fi: fi)
        }
    }"#;
    // Observation only: real compiled bytecode and CoreHost perform every read/check.
    struct GasProbe<QS: Default + QueryStateAccess> {
        inner: CoreHostImpl<QS>,
        before: std::cell::Cell<Option<u64>>,
        reserve: Option<u64>,
        actual: Option<u64>,
        input_before: Option<u64>,
        heap_before: Option<u64>,
        register_before: Option<u64>,
    }
    impl<QS: Default + QueryStateAccess> IVMHost for GasProbe<QS> {
        fn prepared_entrypoint_arguments(&self) -> Option<ivm::PreparedArgumentRecord> {
            self.inner.prepared_entrypoint_arguments()
        }
        fn allows_syscall(&self, policy: ivm::SyscallPolicy, number: u32) -> bool {
            self.inner.allows_syscall(policy, number)
        }
        fn prepare_syscall(&self, number: u32, vm: &IVM) -> Result<u64, ivm::VMError> {
            if number == ivm::syscalls::SYSCALL_ASSET_FI_LINK_REVISION {
                assert!(self.before.replace(Some(vm.remaining_gas())).is_none());
            }
            self.inner.prepare_syscall(number, vm)
        }
        fn syscall(&mut self, number: u32, vm: &mut IVM) -> Result<u64, ivm::VMError> {
            if number == ivm::syscalls::SYSCALL_ASSET_FI_LINK_REVISION {
                assert!(self.reserve.replace(vm.syscall_reserved_gas()).is_none());
                assert!(vm.syscall_reserved_gas() > 0);
                self.input_before = Some(vm.alloc_input_tlv(&[]).unwrap());
                self.heap_before = Some((vm.alloc_heap(0).unwrap() - ivm::Memory::HEAP_START));
                self.register_before = Some(vm.register(10));
            }
            let result = self.inner.syscall(number, vm);
            if number == ivm::syscalls::SYSCALL_ASSET_FI_LINK_REVISION {
                self.actual = result.as_ref().ok().copied();
            }
            result
        }
        fn as_any(&mut self) -> &mut dyn std::any::Any
        where
            Self: 'static,
        {
            self
        }
    }
    fn run_probe(program: &[u8], gas_limit: u64, expect_success: bool) -> (u64, Option<u64>) {
        let (f, state) = Fixture::new();
        let mut block = state.block(header());
        let mut tx = block.transaction();
        f.install(&mut tx);
        let metadata = ivm::ProgramMetadata::parse(program).unwrap();
        let entry = metadata
            .contract_interface
            .as_ref()
            .unwrap()
            .entrypoints
            .iter()
            .find(|e| e.name == "revision")
            .unwrap();
        let schema = entry.argument_schema.as_ref().unwrap();
        let arguments = Json::new(std::collections::BTreeMap::from([
            ("asset", f.definition.canonical_address()),
            ("wallet", f.wallet.canonical_i105().unwrap()),
            ("fi", f.bank.canonical_i105().unwrap()),
        ]));
        let canonical =
            ivm_abi::arguments::encode_argument_record_from_json(schema, &arguments).unwrap();
        let prepared =
            ivm::prepare_argument_record_with_gas_limit(schema, Arc::from(canonical), gas_limit)
                .unwrap();
        let mut inner: CoreHostImpl<QueryStateSlot<_>> = CoreHostImpl::new(f.owner.clone());
        inner.set_query_state(&tx);
        inner.set_contract_runtime_context(Some(f.context.clone()));
        inner.set_entrypoint_argument_record(Some(prepared.clone()));
        let mut host = GasProbe {
            inner,
            before: std::cell::Cell::new(None),
            reserve: None,
            actual: None,
            input_before: None,
            heap_before: None,
            register_before: None,
        };
        let mut vm = IVM::new(gas_limit);
        vm.load_program(program).unwrap();
        vm.set_register(1, vm.memory.code_len());
        vm.set_program_counter(metadata.prefix_len() as u64 + entry.entry_pc)
            .unwrap();
        prepared.precharge_vm(&mut vm).unwrap();
        let result = vm.run_with_host(&mut host);
        if expect_success {
            result.expect("real compiled read succeeds");
            assert_eq!(vm.call_result_word_count().unwrap(), 1);
            assert_revision(&vm, vm.public_call_result_word(0).unwrap(), u64::MAX);
            assert!(host.reserve.unwrap() >= host.actual.unwrap());
        } else {
            assert!(matches!(
                result.unwrap_err().as_unmetered(),
                ivm::VMError::OutOfGas
            ));
            assert!(host.actual.is_none());
            assert!(vm.call_result_word_count().is_err());
            if let Some(before) = host.input_before {
                assert_eq!(vm.alloc_input_tlv(&[]).unwrap(), before);
                assert_eq!(
                    (vm.alloc_heap(0).unwrap() - ivm::Memory::HEAP_START),
                    host.heap_before.unwrap()
                );
                assert_eq!(vm.register(10), host.register_before.unwrap());
            }
        }
        assert!(host.inner.queued.is_empty());
        assert_eq!(host.inner.instruction_queue_count, 0);
        (
            host.before.get().expect("target syscall reached"),
            host.actual,
        )
    }
    #[test]
    fn compiled_fi_revision_preserves_u64_and_real_vm_refuses_one_unit_short() {
        const CONTROL: u64 = 50_000_000;
        let program = kotodama_lang::compiler::Compiler::new()
            .compile_source(SOURCE)
            .unwrap();
        let (before, actual) = run_probe(&program, CONTROL, true);
        let actual = actual.unwrap();
        assert!(actual > 0);
        let (remaining, _) = run_probe(&program, CONTROL - before + actual - 1, false);
        assert_eq!(remaining, actual - 1);
    }
}
