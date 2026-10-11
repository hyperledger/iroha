//! Authenticated typed cross-contract calls with atomic effects and funded value transfer.

use super::*;
use iroha_data_model::smart_contract::manifest::EntryPointKind;
use ivm::value_record;
use ivm_abi::contract_call::{ContractCallBindingV1, MAX_CONTRACT_CALL_BINDING_BYTES_V1};

impl<QS: Default + QueryStateAccess> CoreHostImpl<QS> {
    /// Check the fixed public descriptors before reserving the caller's gas escrow.
    pub(super) fn quote_contract_call_descriptors(vm: &IVM) -> Result<usize, ivm::VMError> {
        for register in 10..=15 {
            vm.ensure_public_register(register)?;
        }
        let address_bytes = quote_tlv_payload_len_at(vm, vm.register(10), PointerType::Blob)?;
        let binding_bytes =
            quote_tlv_payload_len_at(vm, vm.register(11), PointerType::NoritoBytes)?;
        if address_bytes != iroha_data_model::smart_contract::CONTRACT_ADDRESS_LITERAL_LEN_V1
            || binding_bytes > MAX_CONTRACT_CALL_BINDING_BYTES_V1
            || vm.register(13) > ivm_abi::call::MAX_CALL_WORDS_V1 as u64
            || vm.register(15) > ivm_abi::call::MAX_CALL_WORDS_V1 as u64
            || vm.register(15) == 0
            || (vm.register(12) == 0) != (vm.register(13) == 0)
        {
            return Err(ivm::VMError::DecodeError);
        }
        value_record::validate_return_destination(vm, vm.register(14), vm.register(15) as usize)?;
        address_bytes
            .checked_add(binding_bytes)
            .ok_or(ivm::VMError::OutOfGas)
    }

    /// Dispatch the exact admitted artifact and ordinal named by the compiler's binding.
    pub(super) fn handle_call_contract(&mut self, vm: &mut IVM) -> Result<u64, ivm::VMError> {
        let mut boundary_gas = ivm::gas::G_CALL_CONTRACT;
        let meter = |gas, error| ivm::VMError::metered(gas, error);
        if self.nested_contract_call_depth >= MAX_NESTED_CONTRACT_CALL_DEPTH {
            return Err(meter(boundary_gas, ivm::VMError::CallDepthExceeded));
        }
        let caller = self
            .current_contract_runtime_context
            .clone()
            .ok_or_else(|| meter(boundary_gas, ivm::VMError::PermissionDenied))?;
        let authorization = self
            .current_entrypoint_authorization
            .as_ref()
            .ok_or_else(|| meter(boundary_gas, ivm::VMError::PermissionDenied))?;
        if caller.contract_subject != caller.contract_address.subject_id()
            || caller.contract_address != authorization.contract_address
            || caller.entrypoint != authorization.entrypoint
            || self.authority != authorization.authority
            || Hash::prehashed(vm.code_hash()) != authorization.code_hash
            || !vm.contract_interface().is_some_and(|interface| {
                interface
                    .entrypoints
                    .iter()
                    .any(|entrypoint| entrypoint.name == caller.entrypoint)
            })
        {
            return Err(meter(boundary_gas, ivm::VMError::PermissionDenied));
        }
        let request_bytes = Self::quote_contract_call_descriptors(vm)
            .map_err(|error| meter(boundary_gas, error))?;
        boundary_gas = ivm::gas::syscall_byte_gas(boundary_gas, request_bytes, 0);
        ivm::host::preflight_reserved_syscall_gas(vm, boundary_gas)?;
        if vm.remaining_gas() < boundary_gas {
            return Err(ivm::VMError::OutOfGas);
        }
        let address_bytes = Self::decode_pointer_tlv(vm, vm.register(10), PointerType::Blob)
            .map_err(|error| meter(boundary_gas, error))?
            .payload;
        let literal = std::str::from_utf8(address_bytes)
            .map_err(|_| meter(boundary_gas, ivm::VMError::DecodeError))?;
        let address: ContractAddress = literal
            .parse()
            .map_err(|_| meter(boundary_gas, ivm::VMError::PermissionDenied))?;
        if address.as_ref() != literal {
            return Err(meter(boundary_gas, ivm::VMError::DecodeError));
        }
        if self.contract_address_is_active(&address) {
            return Err(meter(boundary_gas, ivm::VMError::ReentrantCall));
        }
        let binding = ContractCallBindingV1::from_bytes(
            Self::decode_pointer_tlv(vm, vm.register(11), PointerType::NoritoBytes)
                .map_err(|error| meter(boundary_gas, error))?
                .payload,
        )
        .map_err(|_| meter(boundary_gas, ivm::VMError::DecodeError))?;
        let (identity, subject, artifact_bytes) = self
            .resolve_bound_contract_dispatch_identity_by_address(&address)
            .map_err(|error| meter(boundary_gas, error))?
            .ok_or_else(|| meter(boundary_gas, ivm::VMError::PermissionDenied))?;
        if identity.code_hash != binding.code_hash {
            return Err(meter(boundary_gas, ivm::VMError::PermissionDenied));
        }
        // Cache warmth cannot change consensus gas. Charge artifact preparation on every call.
        boundary_gas = Self::nested_contract_host_gas(request_bytes, artifact_bytes, 0);
        ivm::host::preflight_reserved_syscall_gas(vm, boundary_gas)?;
        if vm.remaining_gas() < boundary_gas {
            return Err(ivm::VMError::OutOfGas);
        }
        let prepared = self
            .prepare_nested_contract(&identity)
            .map_err(|error| meter(boundary_gas, error))?;
        if prepared.artifact().len() != artifact_bytes {
            return Err(meter(boundary_gas, ivm::VMError::InvalidMetadata));
        }
        let descriptor = prepared
            .contract_interface()
            .entrypoints
            .get(binding.entrypoint as usize)
            .ok_or_else(|| meter(boundary_gas, ivm::VMError::PermissionDenied))?;
        let entrypoint = descriptor.name.clone();
        let is_view = descriptor.kind == EntryPointKind::View;
        if (matches!(
            self.execution_class,
            HostExecutionClass::View | HostExecutionClass::LocalViewDebug
        ) && !is_view)
            || prepared.entrypoint_requires_private_inputs(&entrypoint) != Some(false)
        {
            return Err(meter(boundary_gas, ivm::VMError::PermissionDenied));
        }
        let permission =
            crate::executor::nested_contract_entrypoint_authorization(descriptor, &entrypoint)
                .map_err(|error| meter(boundary_gas, map_validation_fail(&error)))?;
        let heap_limit = {
            let state = self
                .query_state
                .get()
                .ok_or_else(|| meter(boundary_gas, ivm::VMError::PermissionDenied))?;
            state
                .ensure_contract_entrypoint_lifecycle(&address, identity.code_hash, descriptor.kind)
                .map_err(|error| meter(boundary_gas, map_validation_fail(&error)))?;
            state
                .enforce_named_contract_entrypoint_authorization(
                    &caller.contract_subject,
                    &address,
                    &entrypoint,
                    &permission,
                )
                .map_err(|error| {
                    meter(
                        boundary_gas,
                        error.into_vm_error(|error| map_validation_fail(&error)),
                    )
                })?;
            state.smart_contract_heap_limit()
        };
        let return_schema = descriptor
            .return_schema
            .as_ref()
            .ok_or_else(|| meter(boundary_gas, ivm::VMError::InvalidMetadata))?;
        let result_words = return_schema
            .word_count()
            .ok_or_else(|| meter(boundary_gas, ivm::VMError::InvalidMetadata))?;
        if vm.register(15) != result_words as u64 {
            return Err(meter(boundary_gas, ivm::VMError::DecodeError));
        }
        let result_base = vm.register(14);
        let budget = self.prepared_contract_cache.execution_budget().clone();
        // Authenticate identity, lifecycle, permissions and exact schemas before copying input.
        let arguments = if let Some(schema) = descriptor.argument_schema.as_ref() {
            let quote = value_record::quote_argument_record(
                vm,
                schema,
                vm.register(12),
                vm.register(13) as usize,
                vm.remaining_gas().saturating_sub(boundary_gas),
            )
            .map_err(|error| meter(boundary_gas, error))?;
            boundary_gas = boundary_gas
                .checked_add(quote.gas)
                .ok_or(ivm::VMError::OutOfGas)?;
            ivm::host::preflight_reserved_syscall_gas(vm, boundary_gas)?;
            Some(
                value_record::capture_argument_record_funded(
                    vm,
                    schema,
                    vm.register(12),
                    vm.register(13) as usize,
                    &budget,
                )
                .map_err(|error| meter(boundary_gas, error))?,
            )
        } else {
            if vm.register(12) != 0 || vm.register(13) != 0 {
                return Err(meter(boundary_gas, ivm::VMError::DecodeError));
            }
            None
        };
        let reserved_gas = vm.syscall_reserved_gas();
        let call_budget = if reserved_gas == 0 {
            vm.remaining_gas()
        } else {
            reserved_gas
        };
        let child_limit = call_budget.saturating_sub(boundary_gas);
        let mut child = self
            .prepared_contract_cache
            .checkout_runtime(prepared.as_ref(), child_limit, heap_limit)
            .map_err(|error| meter(boundary_gas, error))?;
        let entrypoint_pc = prepared
            .entrypoint_pc(&entrypoint)
            .ok_or_else(|| meter(boundary_gas, ivm::VMError::InvalidMetadata))?;
        let code_len = child.memory.code_len();
        child.set_register(1, code_len);
        child
            .set_program_counter(entrypoint_pc)
            .map_err(|error| meter(boundary_gas, error))?;
        child.set_gas_limit(child_limit);
        let installation = match (arguments.as_ref(), descriptor.argument_schema.as_ref()) {
            (Some(arguments), Some(schema)) => value_record::install_captured_arguments(
                arguments,
                schema,
                &mut child,
                result_words,
                &budget,
            ),
            (None, None) => {
                value_record::install_empty_captured_arguments(&mut child, result_words)
            }
            _ => unreachable!("the argument record and schema were matched above"),
        };
        drop(arguments);
        if let Err(error) = installation {
            vm.inherit_execution_fault(
                &child,
                &error,
                iroha_data_model::executor::fault::IvmFaultPositionV1::Initialization,
            );
            let spent = child_limit.saturating_sub(child.remaining_gas());
            if reserved_gas == 0 {
                vm.set_syscall_spendable_gas(child.remaining_gas().saturating_add(boundary_gas));
            }
            return Err(meter(
                boundary_gas.saturating_add(if reserved_gas == 0 { 0 } else { spent }),
                error,
            ));
        }
        let snapshot = self.snapshot_nested_contract_call();
        self.authority = caller.contract_subject.clone();
        self.execution_class = if is_view {
            HostExecutionClass::View
        } else {
            HostExecutionClass::Contract
        };
        self.current_contract_runtime_context = Some(ContractRuntimeExecutionContext {
            contract_address: address,
            contract_subject: subject,
            contract_alias: identity.contract_alias.clone(),
            entrypoint: entrypoint.clone(),
        });
        self.current_entrypoint_authorization = Some(
            ContractEntrypointAuthorizationSnapshot::new(
                caller.contract_subject,
                entrypoint,
                permission,
                &identity,
            )
            .with_parent(self.current_entrypoint_authorization.clone()),
        );
        self.args = None;
        self.entrypoint_argument_record = None;
        self.fastpq_batch_entries = None;
        self.nested_contract_ancestors[self.nested_contract_call_depth] =
            Some(caller.contract_address);
        self.nested_contract_call_depth += 1;
        let run_result = child.run_with_host_and_parent_cycle_budget(self, vm);
        self.nested_contract_call_depth -= 1;
        self.nested_contract_ancestors[self.nested_contract_call_depth] = None;
        let child_spent = child_limit.saturating_sub(child.remaining_gas());
        if reserved_gas == 0 {
            vm.set_syscall_spendable_gas(child.remaining_gas().saturating_add(boundary_gas));
        }
        let child_bill = if reserved_gas == 0 { 0 } else { child_spent };
        let mut fault_position =
            iroha_data_model::executor::fault::IvmFaultPositionV1::Initialization;
        let result: Result<NestedContractCallOutcome, ivm::VMError> = (|| {
            run_result?;
            fault_position =
                iroha_data_model::executor::fault::IvmFaultPositionV1::ReturnValidation;
            let quote = value_record::quote_completed_return_record(
                &child,
                return_schema,
                child.remaining_gas(),
            )?;
            boundary_gas = boundary_gas
                .checked_add(quote.gas)
                .ok_or(ivm::VMError::OutOfGas)?;
            let returned_error = ivm::sum::entrypoint_return_is_error(&child, return_schema)?;
            let captured =
                value_record::capture_completed_return_funded(&child, return_schema, &budget)?;
            let transfer_gas = value_record::transfer_return_record_funded(
                &captured,
                return_schema,
                vm,
                result_base,
                result_words,
                child.remaining_gas().saturating_sub(quote.gas),
                &budget,
            )?;
            boundary_gas = boundary_gas
                .checked_add(transfer_gas)
                .ok_or(ivm::VMError::OutOfGas)?;
            Ok(if is_view || returned_error {
                NestedContractCallOutcome::RollbackPreservingReads
            } else {
                NestedContractCallOutcome::Commit
            })
        })();
        let total_gas = boundary_gas.saturating_add(child_bill);
        match result {
            Ok(outcome) => {
                self.finish_nested_contract_call(snapshot, outcome)
                    .map_err(|error| meter(total_gas, error))?;
                // r10..r15 remain the immutable caller descriptors. Only the reserved
                // result table and its newly materialized values become visible.
                Ok(total_gas)
            }
            Err(error) => {
                let rollback =
                    self.finish_nested_contract_call(snapshot, NestedContractCallOutcome::Rollback);
                if error.execution_deferral().is_some() {
                    return Err(error.into_unmetered());
                }
                rollback.map_err(|error| meter(total_gas, error))?;
                vm.inherit_execution_fault(&child, &error, fault_position);
                Err(meter(total_gas, error))
            }
        }
    }
}
