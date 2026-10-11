//! Native event capture and immutable invocation provenance.

use super::*;
use iroha_data_model::smart_contract::event::{ContractEmissionV1, ContractEventDescriptorV1};

impl<QS: Default + QueryStateAccess> CoreHostImpl<QS> {
    fn event_context<'a>(
        &'a self,
        vm: &'a IVM,
    ) -> Result<
        (
            &'a ContractRuntimeExecutionContext,
            &'a ContractEntrypointAuthorizationSnapshot,
            u32,
            u32,
            &'a ContractEventDescriptorV1,
        ),
        ivm::VMError,
    > {
        if !matches!(
            self.execution_class,
            HostExecutionClass::Contract | HostExecutionClass::LocalContractDebug
        ) {
            return Err(ivm::VMError::PermissionDenied);
        }
        for register in [10, 11, 12] {
            vm.ensure_public_register(register)?;
        }
        let context = self
            .current_contract_runtime_context
            .as_ref()
            .ok_or(ivm::VMError::PermissionDenied)?;
        let authorization = self
            .current_entrypoint_authorization
            .as_ref()
            .ok_or(ivm::VMError::PermissionDenied)?;
        if context.contract_address != authorization.contract_address
            || context.entrypoint != authorization.entrypoint
            || self.authority != authorization.authority
            || Hash::prehashed(vm.code_hash()) != authorization.code_hash
        {
            return Err(ivm::VMError::PermissionDenied);
        }
        let interface = vm
            .contract_interface()
            .ok_or(ivm::VMError::InvalidMetadata)?;
        let (entrypoint, descriptor) = interface
            .entrypoints
            .iter()
            .enumerate()
            .find(|(_, entrypoint)| entrypoint.name == authorization.entrypoint)
            .ok_or(ivm::VMError::InvalidMetadata)?;
        if matches!(
            descriptor.kind,
            iroha_data_model::smart_contract::manifest::EntryPointKind::View
        ) {
            return Err(ivm::VMError::PermissionDenied);
        }
        let event = u32::try_from(vm.register(10)).map_err(|_| ivm::VMError::DecodeError)?;
        let definition = interface
            .events
            .get(event as usize)
            .ok_or(ivm::VMError::DecodeError)?;
        if !definition.validate() {
            return Err(ivm::VMError::InvalidMetadata);
        }
        Ok((
            context,
            authorization,
            u32::try_from(entrypoint).map_err(|_| ivm::VMError::InvalidMetadata)?,
            event,
            definition,
        ))
    }

    /// Preparation authenticates only signed descriptors; recursive guest data
    /// traversal runs after the interpreter reserves the available syscall gas.
    pub(super) fn quote_contract_event(&self, vm: &IVM) -> Result<u64, ivm::VMError> {
        let _ = self.event_context(vm)?;
        ivm::host::reserve_available_syscall_gas_at_least(vm, 32)
    }

    pub(super) fn emit_contract_event(&mut self, vm: &IVM) -> Result<u64, ivm::VMError> {
        let (_, _, _, _, definition) = self.event_context(vm)?;
        let words = usize::try_from(vm.register(12)).map_err(|_| ivm::VMError::DecodeError)?;
        let gas = ivm::value_record::quote_value_record(
            vm,
            &definition.payload_type,
            vm.register(11),
            words,
            vm.remaining_gas(),
        )?
        .gas;
        ivm::host::preflight_reserved_syscall_gas(vm, gas)?;
        let result = (|| {
            // Finish any earlier instruction batch before inserting this emission.
            self.flush_pending_fastpq_batch();
            self.queued.try_reserve(1).map_err(|_| {
                ivm::VMError::ExecutionDeferred(ivm::ExecutionDeferral::AllocationUnavailable)
            })?;
            let (context, authorization, entrypoint, event, definition) = self.event_context(vm)?;
            let emission = contract_event::capture(
                vm,
                self.prepared_contract_cache.execution_budget(),
                &context.contract_address,
                authorization.code_hash,
                entrypoint,
                event,
                &authorization.authority,
                definition,
                vm.register(11),
                usize::try_from(vm.register(12)).map_err(|_| ivm::VMError::DecodeError)?,
            )?;
            if !self.try_reserve_serialized_output(&emission.value, 1) {
                self.ensure_output_budget()?;
                return Err(ivm::VMError::ExecutionDeferred(
                    ivm::ExecutionDeferral::LocalInvariantViolation,
                ));
            }
            self.queued.push(QueuedEffect {
                payload: QueuedEffectPayload::Emission(emission),
                authority: self.effect_authority(),
                contract_runtime_context: self.current_contract_runtime_context.clone(),
                entrypoint_authorization: self.current_entrypoint_authorization.clone(),
            });
            Ok(gas)
        })();
        result.map_err(|error| ivm::VMError::metered(gas, error))
    }
}

impl HostExecutionArtifacts {
    pub(crate) fn validate_emission_provenance(
        world: &impl WorldReadOnly,
        emission: &ContractEmissionV1,
        runtime_context: Option<&ContractRuntimeExecutionContext>,
        authorization: Option<&ContractEntrypointAuthorizationSnapshot>,
    ) -> Result<(), ValidationFail> {
        let (Some(context), Some(authorization)) = (runtime_context, authorization) else {
            return Err(ValidationFail::NotPermitted(
                "contract emission has no invocation authorization".into(),
            ));
        };
        if emission.contract != context.contract_address
            || emission.contract != authorization.contract_address
            || emission.code_hash != authorization.code_hash
            || emission.caller != authorization.authority
            || context.entrypoint != authorization.entrypoint
        {
            return Err(ValidationFail::NotPermitted(
                "contract emission does not retain its authenticated invocation provenance".into(),
            ));
        }
        let dataspace = emission.contract.dataspace_id().map_err(|_| {
            ValidationFail::NotPermitted("contract emission has an invalid dataspace".into())
        })?;
        let artifact = iroha_data_model::smart_contract::ContractArtifactId::new(
            dataspace,
            emission.code_hash,
        );
        let manifest = world.contract_manifests().get(&artifact).ok_or_else(|| {
            ValidationFail::NotPermitted("contract emission has no current signed manifest".into())
        })?;
        let entrypoint = manifest
            .entrypoints
            .as_deref()
            .and_then(|entries| entries.get(emission.entrypoint as usize))
            .ok_or_else(|| {
                ValidationFail::NotPermitted(
                    "contract emission has an invalid entrypoint ordinal".into(),
                )
            })?;
        if entrypoint.name.as_ref() != authorization.entrypoint
            || matches!(
                entrypoint.kind,
                iroha_data_model::smart_contract::manifest::EntryPointKind::View
            )
            || manifest.events.get(emission.event as usize) != Some(&emission.definition)
        {
            return Err(ValidationFail::NotPermitted(
                "contract emission differs from its signed declaration".into(),
            ));
        }
        Ok(())
    }
}
