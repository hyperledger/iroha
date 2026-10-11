//! Admitted contract fixtures and typed calls for the local diagnostic WSV.

use super::*;
use crate::{PreparedContract, value_record};
use iroha_data_model::smart_contract::{
    ContractArtifactId, ContractLifecycleControlV1,
    manifest::{ContractPermissionScopeV1, EntryPointKind, EntrypointAuthorizationV1},
};
use ivm_abi::contract_call::{ContractCallBindingV1, MAX_CONTRACT_CALL_BINDING_BYTES_V1};

const MAX_NESTED_CALLS: usize = 32;

#[derive(Clone)]
pub(super) struct MockContractInstance {
    pub(super) lifecycle: ContractLifecycleControlV1,
    pub(super) pending: Option<EntryPointKind>,
}

/// One local diagnostic emission retaining its original captured value owner.
/// This is not a committed transaction output or a claim of consensus custody.
#[derive(Clone)]
pub struct MockContractEvent {
    contract: ContractAddress,
    artifact: PreparedContract,
    ordinal: usize,
    payload: Arc<value_record::CapturedValueRecord>,
}
impl MockContractEvent {
    /// Exact emitting instance.
    pub fn contract(&self) -> &ContractAddress {
        &self.contract
    }
    /// Authenticated source declaration name.
    pub fn name(&self) -> &Name {
        &self.artifact.contract_interface().events[self.ordinal].name
    }
    /// Immutable canonical event value, with its original allocation credit retained.
    pub fn payload(
        &self,
    ) -> &iroha_data_model::smart_contract::entrypoint::EntrypointReturnRecordV1 {
        self.payload.get()
    }
}

/// Canonical durable namespace for one deployed instance in the diagnostic WSV.
///
/// # Errors
/// Rejects an invalid logical state path or a scoped path above protocol bounds.
pub fn contract_state_path(
    address: &ContractAddress,
    logical: &StatePath,
) -> Result<StatePath, VMError> {
    format!("{}{logical}", contract_state_namespace(address))
        .parse()
        .map_err(|_| VMError::NoritoInvalid)
}
fn contract_state_namespace(address: &ContractAddress) -> String {
    format!(
        "sc/{}/",
        hex::encode(CryptoHash::new(address.as_ref().as_bytes()).as_ref())
    )
}

impl WsvHost {
    /// Install an exact artifact and explicit lifecycle fixture, without simulating deployment.
    /// Both active and suspended fixtures retain the same complete admitted artifact.
    ///
    /// # Errors
    /// Rejects invalid artifacts, inconsistent lifecycle hashes and undeclared pending hooks.
    pub fn install_contract_fixture(
        &mut self,
        address: ContractAddress,
        artifact: Vec<u8>,
        lifecycle: ContractLifecycleControlV1,
        pending: Option<EntryPointKind>,
    ) -> Result<(), VMError> {
        lifecycle.validate().map_err(|_| VMError::InvalidMetadata)?;
        let prepared =
            crate::prepare_contract_with_memory_budget(&artifact, &self.contract_execution_budget)
                .map_err(|error| error.into_vm_error())?;
        if lifecycle.retained_code_hash != Some(prepared.code_hash())
            || lifecycle
                .active_code_hash
                .is_some_and(|hash| hash != prepared.code_hash())
            || pending.is_some_and(|kind| {
                !matches!(kind, EntryPointKind::Hajimari | EntryPointKind::Kaizen)
                    || !prepared
                        .contract_interface()
                        .entrypoints
                        .iter()
                        .any(|entry| entry.kind == kind)
            })
        {
            return Err(VMError::InvalidMetadata);
        }
        let artifact_id = ContractArtifactId::for_address(&address, prepared.code_hash())
            .map_err(|_| VMError::InvalidMetadata)?;
        Self::materialize_subject_account(&mut self.wsv, &address.subject_id());
        self.wsv.contract_artifacts.insert(artifact_id, prepared);
        self.wsv
            .contract_instances
            .insert(address, MockContractInstance { lifecycle, pending });
        Ok(())
    }
    /// Read the immutable admitted artifact retained by a fixture, including suspended fixtures.
    pub fn contract_fixture(&self, address: &ContractAddress) -> Option<&PreparedContract> {
        let hash = self
            .wsv
            .contract_instances
            .get(address)?
            .lifecycle
            .retained_code_hash?;
        self.wsv
            .contract_artifacts
            .get(&ContractArtifactId::for_address(address, hash).ok()?)
    }
    /// Replace an active admitted fixture at its existing address using the same exact storage
    /// compatibility rules as production activation. The caller must be its current owner and
    /// consume its current lifecycle revision; an unfinished hook cannot be overwritten.
    ///
    /// This diagnostic control stages the replacement's real `kaizen` hook. It does not execute
    /// the hook or infer successful migration from declared metadata.
    ///
    /// # Errors
    /// Rejects stale revisions, unauthorized owners, suspended or pending fixtures, identical
    /// artifacts, incompatible storage, and malformed or absent prior scalar state.
    pub fn replace_contract_fixture(
        &mut self,
        address: &ContractAddress,
        artifact: Vec<u8>,
        authority: &AccountId,
        expected_revision: u64,
    ) -> Result<Option<EntryPointKind>, VMError> {
        let instance = self
            .wsv
            .contract_instances
            .get(address)
            .ok_or(VMError::PermissionDenied)?;
        if instance.lifecycle.owner
            != iroha_data_model::smart_contract::ContractLifecycleOwnerV1::Account(
                authority.clone(),
            )
            || instance.lifecycle.revision != expected_revision
            || instance.lifecycle.active_code_hash.is_none()
            || instance.pending.is_some()
        {
            return Err(VMError::PermissionDenied);
        }
        let mut lifecycle = instance.lifecycle.clone();
        lifecycle.revision = lifecycle
            .revision
            .checked_add(1)
            .ok_or(VMError::PermissionDenied)?;
        let previous = self
            .contract_fixture(address)
            .ok_or(VMError::InvalidMetadata)?;
        let replacement =
            crate::prepare_contract_with_memory_budget(&artifact, &self.contract_execution_budget)
                .map_err(|error| error.into_vm_error())?;
        if previous.code_hash() == replacement.code_hash() {
            return Err(VMError::PermissionDenied);
        }
        ivm_abi::upgrade::validate_contract_upgrade(
            previous.contract_interface(),
            replacement.contract_interface(),
        )
        .map_err(|_| VMError::InvalidMetadata)?;
        self.validate_contract_fixture_state(address)?;
        let pending = replacement
            .contract_interface()
            .entrypoints
            .iter()
            .any(|entry| entry.kind == EntryPointKind::Kaizen)
            .then_some(EntryPointKind::Kaizen);
        lifecycle.active_code_hash = Some(replacement.code_hash());
        lifecycle.retained_code_hash = Some(replacement.code_hash());
        let artifact_id = ContractArtifactId::for_address(address, replacement.code_hash())
            .map_err(|_| VMError::InvalidMetadata)?;
        self.wsv.contract_artifacts.insert(artifact_id, replacement);
        self.wsv
            .contract_instances
            .insert(address.clone(), MockContractInstance { lifecycle, pending });
        Ok(pending)
    }
    /// Move the ordered local emissions out of the host without copying their value graphs.
    pub fn drain_contract_events(&mut self) -> Vec<MockContractEvent> {
        std::mem::take(&mut self.contract_events)
    }
    /// Select the local allocation owner used by admitted fixtures and nested value transfers.
    /// This is a diagnostic fixture control; it does not alter protocol gas or authorization.
    pub fn with_contract_execution_budget(
        mut self,
        budget: iroha_allocation::AllocationBudget,
    ) -> Self {
        self.contract_execution_budget = budget;
        self
    }
    /// Choose the installed fixture whose state unbound diagnostic test helpers inspect.
    /// This grants no invocation identity, entrypoint authority, or runtime address.
    ///
    /// # Errors
    /// Rejects a scope without an admitted retained artifact.
    pub fn set_contract_fixture_state_scope(
        &mut self,
        address: Option<ContractAddress>,
    ) -> Result<(), VMError> {
        if address
            .as_ref()
            .is_some_and(|address| self.contract_fixture(address).is_none())
        {
            return Err(VMError::PermissionDenied);
        }
        self.contract_fixture_state_scope = address;
        Ok(())
    }
    /// Complete a harness-managed lifecycle fixture after its hook returned successfully.
    /// The harness owns invocation and canonical Result validation; this method checks the
    /// exact pending hook and real initialized scalar state before changing fixture status.
    ///
    /// # Errors
    /// Rejects a stale hook, suspended fixture, missing scalar, or invalid stored value.
    pub fn finish_contract_fixture_hook(
        &mut self,
        address: &ContractAddress,
        expected_kind: EntryPointKind,
    ) -> Result<(), VMError> {
        let instance = self
            .wsv
            .contract_instances
            .get(address)
            .ok_or(VMError::PermissionDenied)?;
        if instance.pending != Some(expected_kind) || instance.lifecycle.active_code_hash.is_none()
        {
            return Err(VMError::PermissionDenied);
        }
        self.validate_contract_fixture_state(address)?;
        self.wsv
            .contract_instances
            .get_mut(address)
            .unwrap()
            .pending = None;
        Ok(())
    }
    /// Validate the completed scalar storage of an admitted diagnostic fixture.
    ///
    /// # Errors
    /// Rejects missing or malformed scalar values; maps may be empty.
    pub fn validate_contract_fixture_state(
        &self,
        address: &ContractAddress,
    ) -> Result<(), VMError> {
        let artifact = self
            .contract_fixture(address)
            .ok_or(VMError::PermissionDenied)?;
        for state in &artifact.contract_interface().states {
            if matches!(state.ty, crate::EmbeddedStateType::StateMap { .. }) {
                continue;
            }
            let logical: StatePath = state.name.parse().map_err(|_| VMError::InvalidMetadata)?;
            let path = contract_state_path(address, &logical)?;
            let value = match self.state_overlay.get(&path) {
                Some(Some(value)) => value.as_slice(),
                Some(None) => return Err(VMError::PermissionDenied),
                None => self
                    .wsv
                    .state_overlay
                    .value_payload_ref(&path)?
                    .ok_or(VMError::PermissionDenied)?,
            };
            crate::host::validate_persisted_state_value_payload(&state.ty, value)?;
        }
        Ok(())
    }
    pub(super) fn scoped_state_path(&self, path: &StatePath) -> Result<StatePath, VMError> {
        self.contract_runtime_address
            .as_ref()
            .or(self.contract_fixture_state_scope.as_ref())
            .map_or_else(
                || Ok(path.clone()),
                |address| contract_state_path(address, path),
            )
    }
    pub(super) fn state_namespace(&self) -> String {
        self.contract_runtime_address
            .as_ref()
            .or(self.contract_fixture_state_scope.as_ref())
            .map(contract_state_namespace)
            .unwrap_or_default()
    }

    fn authenticated_caller(&self, vm: &IVM) -> Result<(ContractAddress, EntryPointKind), VMError> {
        let address = self
            .contract_runtime_address
            .as_ref()
            .ok_or(VMError::PermissionDenied)?;
        let entrypoint = self
            .contract_runtime_entrypoint
            .as_ref()
            .ok_or(VMError::PermissionDenied)?;
        let instance = self
            .wsv
            .contract_instances
            .get(address)
            .ok_or(VMError::PermissionDenied)?;
        if instance.lifecycle.active_code_hash != Some(CryptoHash::prehashed(vm.code_hash()))
            || self.caller != address.subject_id()
        {
            return Err(VMError::PermissionDenied);
        }
        let entry = vm
            .contract_interface()
            .and_then(|interface| {
                interface
                    .entrypoints
                    .iter()
                    .find(|entry| &entry.name == entrypoint)
            })
            .ok_or(VMError::PermissionDenied)?;
        Ok((address.clone(), entry.kind))
    }
    pub(super) fn quote_contract_call(vm: &IVM) -> Result<usize, VMError> {
        for register in 10..=15 {
            vm.ensure_public_register(register)?;
        }
        let address = quote_tlv_payload_len_at(vm, vm.register(10), PointerType::Blob)?;
        let binding = quote_tlv_payload_len_at(vm, vm.register(11), PointerType::NoritoBytes)?;
        if address != iroha_data_model::smart_contract::CONTRACT_ADDRESS_LITERAL_LEN_V1
            || binding > MAX_CONTRACT_CALL_BINDING_BYTES_V1
            || vm.register(13) > ivm_abi::call::MAX_CALL_WORDS_V1 as u64
            || (vm.register(12) == 0) != (vm.register(13) == 0)
        {
            return Err(VMError::DecodeError);
        }
        value_record::validate_return_destination(
            vm,
            vm.register(14),
            usize::try_from(vm.register(15)).map_err(|_| VMError::DecodeError)?,
        )?;
        address.checked_add(binding).ok_or(VMError::OutOfGas)
    }
    fn authorize_fixture(
        &self,
        address: &ContractAddress,
        entry: &crate::EmbeddedEntrypointDescriptor,
        artifact: &PreparedContract,
    ) -> Result<(), VMError> {
        let instance = self
            .wsv
            .contract_instances
            .get(address)
            .ok_or(VMError::PermissionDenied)?;
        if instance.lifecycle.active_code_hash != Some(artifact.code_hash())
            || instance
                .lifecycle
                .emergency_hold
                .as_ref()
                .is_some_and(|hold| self.wsv.current_block_height < hold.expires_at_height)
            || instance.pending.is_some()
            || matches!(
                entry.kind,
                EntryPointKind::Hajimari | EntryPointKind::Kaizen
            )
        {
            return Err(VMError::PermissionDenied);
        }
        let token = match &entry.authorization {
            EntrypointAuthorizationV1::Anyone => return Ok(()),
            EntrypointAuthorizationV1::RuntimeLifecycle => return Err(VMError::PermissionDenied),
            EntrypointAuthorizationV1::Permission(name) => {
                let declaration = artifact
                    .contract_interface()
                    .permissions
                    .iter()
                    .find(|permission| &permission.name == name)
                    .ok_or(VMError::InvalidMetadata)?;
                match &declaration.scope {
                    ContractPermissionScopeV1::Instance => PermissionToken::ContractPermission {
                        contract: address.clone(),
                        permission: name.clone(),
                    },
                    ContractPermissionScopeV1::Chain { permission_name } => {
                        PermissionToken::Custom(permission_name.to_string())
                    }
                }
            }
        };
        if self.wsv.has_permission(&self.caller, &token) {
            Ok(())
        } else {
            Err(VMError::PermissionDenied)
        }
    }
    pub(super) fn call_contract(&mut self, vm: &mut IVM) -> Result<u64, VMError> {
        let mut boundary_gas = gas::G_CALL_CONTRACT;
        let result = self.call_contract_inner(vm, &mut boundary_gas);
        result.map_err(|error| VMError::metered(boundary_gas, error))
    }
    fn call_contract_inner(
        &mut self,
        vm: &mut IVM,
        boundary_gas: &mut u64,
    ) -> Result<u64, VMError> {
        if self.contract_ancestors.len() >= MAX_NESTED_CALLS {
            return Err(VMError::CallDepthExceeded);
        }
        let (caller, caller_kind) = self.authenticated_caller(vm)?;
        let request_bytes = Self::quote_contract_call(vm)?;
        *boundary_gas = gas::syscall_byte_gas(gas::G_CALL_CONTRACT, request_bytes, 0);
        preflight_reserved_syscall_gas(vm, *boundary_gas)?;
        if vm.remaining_gas() < *boundary_gas {
            return Err(VMError::OutOfGas);
        }
        let literal = std::str::from_utf8(vm.validate_tlv(vm.register(10))?.payload)
            .map_err(|_| VMError::DecodeError)?;
        let address: ContractAddress = literal.parse().map_err(|_| VMError::PermissionDenied)?;
        if address.as_ref() != literal {
            return Err(VMError::DecodeError);
        }
        if caller == address || self.contract_ancestors.contains(&address) {
            return Err(VMError::ReentrantCall);
        }
        let binding = ContractCallBindingV1::from_bytes(vm.validate_tlv(vm.register(11))?.payload)
            .map_err(|_| VMError::DecodeError)?;
        let artifact = self
            .contract_fixture(&address)
            .ok_or(VMError::PermissionDenied)?
            .clone();
        if artifact.code_hash() != binding.code_hash {
            return Err(VMError::PermissionDenied);
        }
        *boundary_gas = boundary_gas.saturating_add(
            gas::CONSERVATIVE_SYSCALL_INPUT_MULTIPLIER
                .saturating_mul(artifact.artifact().len() as u64),
        );
        preflight_reserved_syscall_gas(vm, *boundary_gas)?;
        if vm.remaining_gas() < *boundary_gas {
            return Err(VMError::OutOfGas);
        }
        let entry = artifact
            .contract_interface()
            .entrypoints
            .get(binding.entrypoint as usize)
            .ok_or(VMError::PermissionDenied)?;
        let is_view = entry.kind == EntryPointKind::View;
        if (caller_kind == EntryPointKind::View && !is_view)
            || artifact.entrypoint_requires_private_inputs(&entry.name) != Some(false)
        {
            return Err(VMError::PermissionDenied);
        }
        self.authorize_fixture(&address, entry, &artifact)?;
        let schema = entry
            .return_schema
            .as_ref()
            .ok_or(VMError::InvalidMetadata)?;
        let result_words = schema.word_count().ok_or(VMError::InvalidMetadata)?;
        if vm.register(15) != result_words as u64 {
            return Err(VMError::DecodeError);
        }
        let destination = vm.register(14);
        let budget = self.contract_execution_budget.clone();
        let arguments = if let Some(schema) = &entry.argument_schema {
            let quote = value_record::quote_argument_record(
                vm,
                schema,
                vm.register(12),
                vm.register(13) as usize,
                vm.remaining_gas().saturating_sub(*boundary_gas),
            )?;
            *boundary_gas = boundary_gas
                .checked_add(quote.gas)
                .ok_or(VMError::OutOfGas)?;
            Some(value_record::capture_argument_record_funded(
                vm,
                schema,
                vm.register(12),
                vm.register(13) as usize,
                &budget,
            )?)
        } else {
            if vm.register(13) != 0 {
                return Err(VMError::DecodeError);
            }
            None
        };
        let reserve = vm.syscall_reserved_gas();
        let child_limit = vm.remaining_gas().saturating_sub(*boundary_gas);
        let mut child = IVM::try_new_with_memory_budget(child_limit, &budget)?;
        child.load_prepared(&artifact)?;
        child.select_entrypoint(&entry.name)?;
        child.set_gas_limit(child_limit);
        let installation = match arguments.as_ref() {
            Some(arguments) => value_record::install_captured_arguments(
                arguments,
                entry.argument_schema.as_ref().unwrap(),
                &mut child,
                result_words,
                &budget,
            ),
            None => value_record::install_empty_captured_arguments(&mut child, result_words),
        };
        if let Err(error) = installation {
            vm.inherit_execution_fault(
                &child,
                &error,
                iroha_data_model::executor::fault::IvmFaultPositionV1::Initialization,
            );
            let spent = child_limit.saturating_sub(child.remaining_gas());
            if reserve == 0 {
                vm.set_syscall_spendable_gas(child.remaining_gas().saturating_add(*boundary_gas));
            } else {
                *boundary_gas = boundary_gas.saturating_add(spent);
            }
            return Err(error);
        }
        drop(arguments);
        let snapshot = self.checkpoint_state();
        self.bind_contract_runtime_context(
            caller.subject_id(),
            address.clone(),
            entry.name.clone(),
        )
        .map_err(|_| VMError::InvalidMetadata)?;
        self.public_inputs.clear();
        self.fastpq_batch_entries = None;
        self.contract_ancestors.push(caller);
        // Nested execution always stages durable state so no failed child flushes a file.
        self.tx_active = true;
        let run = child.run_with_host_and_parent_cycle_budget(self, vm);
        let spent = child_limit.saturating_sub(child.remaining_gas());
        if reserve == 0 {
            vm.set_syscall_spendable_gas(child.remaining_gas().saturating_add(*boundary_gas));
        }
        let mut fault_position =
            iroha_data_model::executor::fault::IvmFaultPositionV1::Initialization;
        let outcome = (|| {
            run?;
            fault_position =
                iroha_data_model::executor::fault::IvmFaultPositionV1::ReturnValidation;
            let quote =
                value_record::quote_completed_return_record(&child, schema, child.remaining_gas())?;
            *boundary_gas = boundary_gas
                .checked_add(quote.gas)
                .ok_or(VMError::OutOfGas)?;
            let returned_error = crate::sum::entrypoint_return_is_error(&child, schema)?;
            let captured = value_record::capture_completed_return_funded(&child, schema, &budget)?;
            let transfer = value_record::transfer_return_record_funded(
                &captured,
                schema,
                vm,
                destination,
                result_words,
                child.remaining_gas().saturating_sub(quote.gas),
                &budget,
            )?;
            *boundary_gas = boundary_gas
                .checked_add(transfer)
                .ok_or(VMError::OutOfGas)?;
            Ok(returned_error)
        })();
        *boundary_gas = boundary_gas.saturating_add(if reserve == 0 { 0 } else { spent });
        match outcome {
            Ok(rollback) => {
                if rollback || is_view {
                    let reads = self.actual_access.read_keys.clone();
                    let durable_reads = self.actual_access.durable_read_paths.clone();
                    self.restore_state(&snapshot)?;
                    self.actual_access.read_keys.extend(reads);
                    self.actual_access.durable_read_paths.extend(durable_reads);
                } else {
                    self.caller = snapshot.caller;
                    self.contract_runtime_invoker = snapshot.contract_runtime_invoker;
                    self.contract_runtime_address = snapshot.contract_runtime_address;
                    self.contract_runtime_entrypoint = snapshot.contract_runtime_entrypoint;
                    self.public_inputs = snapshot.public_inputs;
                    self.fastpq_batch_entries = snapshot.fastpq_batch_entries;
                    self.contract_ancestors = snapshot.contract_ancestors;
                    if !snapshot.tx_active {
                        self.finish_tx()?;
                    }
                }
                Ok(*boundary_gas)
            }
            Err(error) => {
                self.restore_state(&snapshot)?;
                vm.inherit_execution_fault(&child, &error, fault_position);
                Err(error)
            }
        }
    }
    pub(super) fn emit_contract_event(&mut self, vm: &IVM) -> Result<u64, VMError> {
        let (contract, kind) = self.authenticated_caller(vm)?;
        if kind == EntryPointKind::View {
            return Err(VMError::PermissionDenied);
        }
        for register in 10..=12 {
            vm.ensure_public_register(register)?;
        }
        let ordinal = usize::try_from(vm.register(10)).map_err(|_| VMError::DecodeError)?;
        let artifact = self
            .contract_fixture(&contract)
            .ok_or(VMError::PermissionDenied)?
            .clone();
        let definition = artifact
            .contract_interface()
            .events
            .get(ordinal)
            .ok_or(VMError::DecodeError)?;
        let words = usize::try_from(vm.register(12)).map_err(|_| VMError::DecodeError)?;
        let quote = value_record::quote_value_record(
            vm,
            &definition.payload_type,
            vm.register(11),
            words,
            vm.remaining_gas(),
        )?;
        preflight_reserved_syscall_gas(vm, quote.gas)?;
        let result = (|| {
            let payload = value_record::capture_value_record_funded(
                vm,
                &definition.payload_type,
                vm.register(11),
                words,
                &self.contract_execution_budget,
            )?;
            self.contract_events.try_reserve(1).map_err(|_| {
                VMError::ExecutionDeferred(crate::ExecutionDeferral::AllocationUnavailable)
            })?;
            Ok(payload)
        })();
        let payload = result.map_err(|error| VMError::metered(quote.gas, error))?;
        self.contract_events.push(MockContractEvent {
            contract,
            artifact,
            ordinal,
            payload: Arc::new(payload),
        });
        Ok(quote.gas)
    }
}
