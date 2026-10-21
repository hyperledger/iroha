//! Reader-granted scalar equality of exact native retail memberships.
use super::*;
use crate::state::asset_uid_reader::AssetUidHoldingQuoteError;
fn map_same_uid_error(error: AssetUidHoldingQuoteError) -> ivm::VMError {
    match error {
        AssetUidHoldingQuoteError::Local(owner) => owner.into_vm_error(),
        AssetUidHoldingQuoteError::Query(error)
        | AssetUidHoldingQuoteError::Execution(
            iroha_data_model::isi::error::InstructionExecutionError::Query(error),
        ) => map_query_execution_error(crate::execution_attempt::ExecutionAttemptError::Rejected(
            error,
        )),
        AssetUidHoldingQuoteError::Execution(_) => ivm::VMError::DecodeError,
    }
}
impl QueryStateRef<'_, '_, '_> {
    pub(super) fn read_same_uid(
        &self,
        authority: &AccountId,
        context: &ContractRuntimeExecutionContext,
        definition: &AssetDefinitionId,
        source: &AccountId,
        destination: &AccountId,
        budget: QueryExecutionBudget,
    ) -> Result<(bool, QueryExecutionStats), ivm::VMError> {
        macro_rules! read {
            ($state:expr) => {
                crate::state::asset_uid_reader::same_uid_for_contract(
                    $state.world(),
                    authority,
                    context,
                    definition,
                    source,
                    destination,
                    budget,
                )
                .map_err(map_same_uid_error)
            };
        }
        match *self {
            Self::View(v) => read!(v),
            Self::QueryView(v) => read!(v),
            Self::Block(v) => read!(v),
            Self::Transaction(v) => read!(v),
        }
    }
}
impl<QS: Default + QueryStateAccess> CoreHostImpl<QS> {
    pub(super) fn execute_same_uid(
        &mut self,
        vm: &mut IVM,
        syscall: u32,
    ) -> Result<u64, ivm::VMError> {
        let context = self
            .current_contract_runtime_context
            .as_ref()
            .ok_or(ivm::VMError::PermissionDenied)?;
        for register in 10..=12 {
            vm.ensure_public_register(register)?;
        }
        let definition: AssetDefinitionId =
            Self::decode_tlv_typed(vm, vm.register(10), PointerType::AssetDefinitionId)?;
        let source: AccountId =
            Self::decode_tlv_typed(vm, vm.register(11), PointerType::AccountId)?;
        let destination: AccountId =
            Self::decode_tlv_typed(vm, vm.register(12), PointerType::AccountId)?;
        let remaining = vm.remaining_gas();
        let context_gas = QueryGasContext::singular();
        let budget = Self::query_execution_budget(&context_gas, remaining)?;
        let state = self
            .query_state
            .get()
            .ok_or(ivm::VMError::NotImplemented { syscall })?;
        let (equal, stats) = state.same_uid(
            &self.effect_authority(),
            context,
            &definition,
            &source,
            &destination,
            budget,
        )?;
        let gas = Self::finish_core_query_encoded_bytes_gas(
            vm,
            remaining,
            &context_gas,
            stats.processed_items(),
            stats.processed_bytes(),
            0,
        )?;
        // Bool is one canonical public word. No heap/TLV allocation and no queued effect.
        // All source/response gas is preflighted before publishing that word.
        vm.set_register(10, u64::from(equal));
        Ok(gas)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{norito_blob, store_tlv};
    use super::*;
    use crate::state::asset_uid_reader::SameUidReaderFixture as Fixture;
    use iroha_data_model::prelude::BlockHeader;
    use ivm::host::IVMHost;
    use std::num::NonZeroU64;
    fn header() -> BlockHeader {
        BlockHeader::new(NonZeroU64::new(1).unwrap(), None, None, 1_000, 0)
    }
    fn arguments(f: &Fixture, destination: &AccountId, gas: u64) -> IVM {
        let mut vm = IVM::new(gas);
        for (r, k, p) in [
            (
                10,
                PointerType::AssetDefinitionId,
                norito_blob(&f.definition),
            ),
            (11, PointerType::AccountId, norito_blob(&f.source)),
            (12, PointerType::AccountId, norito_blob(destination)),
        ] {
            let ptr = store_tlv(&mut vm, k, &p);
            vm.set_register(r, ptr);
        }
        vm
    }
    fn read(f: &Fixture, state: QueryStateRef<'_, '_, '_>) -> bool {
        state
            .read_same_uid(
                &f.context.contract_subject,
                &f.context,
                &f.definition,
                &f.source,
                &f.destination,
                QueryExecutionBudget::from_weighted_limit(10_000_000, 7, 3),
            )
            .unwrap()
            .0
    }
    #[test]
    fn same_uid_host_returns_only_canonical_boolean_with_source_gas_and_no_allocations() {
        let (f, state) = Fixture::new();
        let mut block = state.block(header());
        let mut tx = block.transaction();
        f.install(&mut tx);
        for (destination, expected) in [(&f.destination, true), (&f.foreign, false)] {
            let mut host: CoreHostImpl<QueryStateSlot<_>> = CoreHostImpl::new(f.owner.clone());
            host.set_query_state(&tx);
            host.set_contract_runtime_context(Some(f.context.clone()));
            let mut vm = arguments(&f, destination, 50_000_000);
            let input = vm.alloc_input_tlv(&[]).unwrap();
            let heap = vm.alloc_heap(0).unwrap();
            let gas = host
                .syscall(ivm::syscalls::SYSCALL_ASSET_SAME_UID, &mut vm)
                .unwrap();
            assert_eq!(vm.register(10), u64::from(expected));
            assert_eq!(vm.alloc_input_tlv(&[]).unwrap(), input);
            assert_eq!(vm.alloc_heap(0).unwrap(), heap);
            let (_, stats) = f.read(tx.world(), &f.source, destination).unwrap();
            assert_eq!(
                gas,
                CoreHost::query_gas_cost(
                    &QueryGasContext::singular(),
                    stats.processed_items(),
                    stats.processed_bytes()
                )
            );
            assert!(host.queued.is_empty());
            assert_eq!(host.instruction_queue_count, 0);
        }
    }
    #[test]
    fn same_uid_all_four_native_query_views_share_exact_retained_policy() {
        let (f, state) = Fixture::new();
        let mut block = state.block(header());
        let mut tx = block.transaction();
        f.install(&mut tx);
        assert!(read(&f, QueryStateRef::Transaction(&tx)));
        tx.apply();
        assert!(read(&f, QueryStateRef::Block(&block)));
        block.commit_world_overlay_for_testing().unwrap();
        assert!(read(&f, QueryStateRef::View(&state.view())));
        assert!(read(&f, QueryStateRef::QueryView(&state.query_view())));
    }
    #[test]
    fn same_uid_host_refuses_frame_or_typed_operand_substitution_without_result() {
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
            let mut vm = arguments(
                &f,
                if defect == 2 {
                    &f.owner
                } else {
                    &f.destination
                },
                50_000_000,
            );
            if defect == 3 {
                vm.set_register(11, vm.register(10));
            }
            if defect == 4 {
                vm.set_register(12, vm.register(10));
            }
            let before = vm.register(10);
            let input = vm.alloc_input_tlv(&[]).unwrap();
            let heap = vm.alloc_heap(0).unwrap();
            assert!(
                host.syscall(ivm::syscalls::SYSCALL_ASSET_SAME_UID, &mut vm)
                    .is_err()
            );
            assert_eq!(vm.register(10), before);
            assert_eq!(vm.alloc_input_tlv(&[]).unwrap(), input);
            assert_eq!(vm.alloc_heap(0).unwrap(), heap);
            assert!(host.queued.is_empty());
        }
        let mut host = CoreHost::new(f.owner.clone());
        host.set_contract_runtime_context(Some(f.context.clone()));
        let mut vm = arguments(&f, &f.destination, 50_000_000);
        assert!(matches!(
            host.syscall(ivm::syscalls::SYSCALL_ASSET_SAME_UID, &mut vm),
            Err(ivm::VMError::NotImplemented { .. })
        ));
    }
    #[test]
    fn same_uid_error_mapping_preserves_original_local_owner() {
        let budget = iroha_allocation::AllocationBudget::new(2);
        let retained = budget.try_reserve_bytes(2).unwrap();
        let refusal = budget.try_reserve_bytes(1).unwrap_err();
        let expected = refusal.clone();
        assert!(
            matches!(map_same_uid_error(AssetUidHoldingQuoteError::Local(refusal.into())),ivm::VMError::AllocationDeferred(actual) if actual==expected)
        );
        drop(retained);
        assert!(budget.try_reserve_bytes(1).is_ok());
        assert!(matches!(
            map_same_uid_error(AssetUidHoldingQuoteError::Query(
                QueryExecutionFail::GasBudgetExceeded
            )),
            ivm::VMError::OutOfGas
        ));
    }
    const SOURCE: &str = r#"seiyaku SameUid {
        view fn same(AssetDefinitionId asset, AccountId source, AccountId destination) authorize(anyone) -> bool {
            ledger::asset::same_uid(asset_definition: asset, source: source, destination: destination)
        }
    }"#;
    struct Probe<QS: Default + QueryStateAccess> {
        inner: CoreHostImpl<QS>,
        before: std::cell::Cell<Option<u64>>,
        reserve: Option<u64>,
        actual: Option<u64>,
        input: Option<u64>,
        heap: Option<u64>,
        argument: Option<u64>,
    }
    impl<QS: Default + QueryStateAccess> IVMHost for Probe<QS> {
        fn prepared_entrypoint_arguments(&self) -> Option<ivm::PreparedArgumentRecord> {
            self.inner.prepared_entrypoint_arguments()
        }
        fn allows_syscall(&self, policy: ivm::SyscallPolicy, number: u32) -> bool {
            self.inner.allows_syscall(policy, number)
        }
        fn prepare_syscall(&self, number: u32, vm: &IVM) -> Result<u64, ivm::VMError> {
            if number == ivm::syscalls::SYSCALL_ASSET_SAME_UID {
                assert!(self.before.replace(Some(vm.remaining_gas())).is_none());
            }
            self.inner.prepare_syscall(number, vm)
        }
        fn syscall(&mut self, number: u32, vm: &mut IVM) -> Result<u64, ivm::VMError> {
            if number == ivm::syscalls::SYSCALL_ASSET_SAME_UID {
                assert!(self.reserve.replace(vm.syscall_reserved_gas()).is_none());
                assert!(vm.syscall_reserved_gas() > 0);
                self.input = Some(vm.alloc_input_tlv(&[]).unwrap());
                self.heap = Some(vm.alloc_heap(0).unwrap());
                self.argument = Some(vm.register(10));
            }
            let result = self.inner.syscall(number, vm);
            if number == ivm::syscalls::SYSCALL_ASSET_SAME_UID {
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
    fn run_probe(
        program: &[u8],
        gas_limit: u64,
        expected: Option<bool>,
        foreign: bool,
    ) -> (u64, Option<u64>) {
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
            .find(|e| e.name == "same")
            .unwrap();
        let schema = entry.argument_schema.as_ref().unwrap();
        let arguments = Json::new(std::collections::BTreeMap::from([
            ("asset", f.definition.canonical_address()),
            ("source", f.source.canonical_i105().unwrap()),
            (
                "destination",
                if foreign { &f.foreign } else { &f.destination }
                    .canonical_i105()
                    .unwrap(),
            ),
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
        let mut host = Probe {
            inner,
            before: std::cell::Cell::new(None),
            reserve: None,
            actual: None,
            input: None,
            heap: None,
            argument: None,
        };
        let mut vm = IVM::new(gas_limit);
        vm.load_program(program).unwrap();
        vm.set_register(1, vm.memory.code_len());
        vm.set_program_counter(metadata.prefix_len() as u64 + entry.entry_pc)
            .unwrap();
        prepared.precharge_vm(&mut vm).unwrap();
        let result = vm.run_with_host(&mut host);
        if let Some(expected) = expected {
            result.unwrap();
            assert_eq!(vm.call_result_word_count().unwrap(), 1);
            assert_eq!(vm.public_call_result_word(0).unwrap(), u64::from(expected));
            assert!(host.reserve.unwrap() >= host.actual.unwrap());
        } else {
            assert!(matches!(
                result.unwrap_err().as_unmetered(),
                ivm::VMError::OutOfGas
            ));
            assert!(host.actual.is_none());
            assert!(vm.call_result_word_count().is_err());
            if let Some(input) = host.input {
                assert_eq!(vm.alloc_input_tlv(&[]).unwrap(), input);
                assert_eq!(vm.alloc_heap(0).unwrap(), host.heap.unwrap());
                assert_eq!(vm.register(10), host.argument.unwrap());
            }
        }
        assert!(host.inner.queued.is_empty());
        assert_eq!(host.inner.instruction_queue_count, 0);
        (host.before.get().unwrap(), host.actual)
    }
    #[test]
    fn compiled_same_uid_returns_true_false_and_refuses_one_unit_short_without_publication() {
        const CONTROL: u64 = 50_000_000;
        let program = kotodama_lang::compiler::Compiler::new()
            .compile_source(SOURCE)
            .unwrap();
        let (before, actual) = run_probe(&program, CONTROL, Some(true), false);
        let actual = actual.unwrap();
        assert!(actual > 0);
        run_probe(&program, CONTROL, Some(false), true);
        let (remaining, _) = run_probe(&program, CONTROL - before + actual - 1, None, false);
        assert_eq!(remaining, actual - 1);
    }
}
