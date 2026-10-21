//! Typed projection of controller-authorized beneficial holdings into Kotodama values.

use super::*;
use crate::state::asset_uid_reader::AssetUidHoldingQuoteError;
use iroha_data_model::asset::uid::AssetUidHoldingQuoteV1;

fn map_quote_error(error: AssetUidHoldingQuoteError) -> ivm::VMError {
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
    pub(super) fn read_uid_holding_quote(
        &self,
        authority: &AccountId,
        context: &ContractRuntimeExecutionContext,
        definition: &AssetDefinitionId,
        account: &AccountId,
        incoming: &Quantity,
        budget: QueryExecutionBudget,
    ) -> Result<(AssetUidHoldingQuoteV1, QueryExecutionStats), ivm::VMError> {
        macro_rules! read {
            ($state:expr) => {
                crate::state::asset_uid_reader::quote_for_contract(
                    $state.world(),
                    authority,
                    context,
                    definition,
                    account,
                    incoming,
                    budget,
                )
                .map_err(map_quote_error)
            };
        }
        match *self {
            Self::View(view) => read!(view),
            Self::QueryView(view) => read!(view),
            Self::Block(block) => read!(block),
            Self::Transaction(transaction) => read!(transaction),
        }
    }
}

impl<QS: Default + QueryStateAccess> CoreHostImpl<QS> {
    pub(super) fn execute_uid_holding_quote(
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
        let account: AccountId =
            Self::decode_tlv_typed(vm, vm.register(11), PointerType::AccountId)?;
        let incoming = Self::decode_quantity(vm, vm.register(12))?;
        let gas_remaining = vm.remaining_gas();
        let gas_context = QueryGasContext::singular();
        let budget = Self::query_execution_budget(&gas_context, gas_remaining)?;
        let state = self
            .query_state
            .get()
            .ok_or(ivm::VMError::NotImplemented { syscall })?;
        // The native helper validates the installed controller and explicit reader grant.
        // The outer transaction's human signer cannot substitute for that controller.
        let (quote, stats) = state.uid_holding_quote(
            &self.effect_authority(),
            context,
            &definition,
            &account,
            &incoming,
            budget,
        )?;
        let prepared = PreparedUidHoldingQuote::prepare(&quote)?;
        let gas = Self::finish_core_query_encoded_bytes_gas(
            vm,
            gas_remaining,
            &gas_context,
            stats.processed_items(),
            stats.processed_bytes(),
            prepared.encoded_bytes()?,
        )?;
        let table = prepared.materialize(vm)?;
        vm.set_register(10, table);
        Ok(gas)
    }
}

/// Prepared pointer leaves, before gas and allocation preflight publishes any result.
struct PreparedUidHoldingQuote {
    definition: Vec<u8>,
    account: Vec<u8>,
    revision: Vec<u8>,
    holdings: Vec<u8>,
    limit: Option<Vec<u8>>,
    overflow: Vec<u8>,
}

impl PreparedUidHoldingQuote {
    fn prepare(quote: &AssetUidHoldingQuoteV1) -> Result<Self, ivm::VMError> {
        let typed = |kind, payload: Vec<u8>| CoreHost::encode_tlv_payload(kind, &payload);
        Ok(Self {
            definition: typed(
                PointerType::AssetDefinitionId,
                CoreHost::encode_norito_payload(&quote.asset_definition_id)?,
            )?,
            account: typed(
                PointerType::AccountId,
                CoreHost::encode_norito_payload(&quote.account_id)?,
            )?,
            // Kotodama integers are exact values, so every u64 revision is retained.
            revision: ivm_abi::numeric_tlv::encode_int(&BigInt::from(quote.policy_revision))?,
            holdings: ivm_abi::numeric_tlv::encode_quantity(&quote.beneficial_holdings)?,
            limit: quote
                .holding_limit
                .as_ref()
                .map(ivm_abi::numeric_tlv::encode_quantity)
                .transpose()?,
            overflow: ivm_abi::numeric_tlv::encode_quantity(&quote.required_overflow)?,
        })
    }

    fn leaf_lengths(&self) -> Vec<usize> {
        let mut lengths = vec![
            self.definition.len(),
            self.account.len(),
            self.revision.len(),
            self.holdings.len(),
        ];
        if let Some(limit) = &self.limit {
            lengths.push(limit.len());
        }
        lengths.push(self.overflow.len());
        lengths
    }

    fn encoded_bytes(&self) -> Result<u64, ivm::VMError> {
        self.leaf_lengths()
            .into_iter()
            .try_fold(0_u64, |total, length| {
                total
                    .checked_add(u64::try_from(length).map_err(|_| ivm::VMError::GasCostOverflow)?)
                    .ok_or(ivm::VMError::GasCostOverflow)
            })
    }

    /// Materialize the six-word product only after the caller completes gas preflight.
    fn materialize(self, vm: &mut IVM) -> Result<u64, ivm::VMError> {
        let option = ivm::sum::SumLayoutV1::option(1).map_err(|_| ivm::VMError::DecodeError)?;
        let table_bytes = 6 * 8;
        let reserved_heap = table_bytes
            + option
                .allocation_bytes()
                .map_err(|_| ivm::VMError::DecodeError)?;
        // Check the whole allocation before publishing a pointer or advancing either arena.
        vm.preflight_host_tlv_allocations_with_reserved_heap(&self.leaf_lengths(), reserved_heap)?;
        let definition = vm.alloc_host_tlv(&self.definition)?;
        let account = vm.alloc_host_tlv(&self.account)?;
        let revision = vm.alloc_host_tlv(&self.revision)?;
        let holdings = vm.alloc_host_tlv(&self.holdings)?;
        let limit = match self.limit {
            Some(value) => {
                let pointer = vm.alloc_host_tlv(&value)?;
                ivm::sum::allocate_words(vm, option, 1, &[pointer])?
            }
            None => ivm::sum::allocate_words(vm, option, 0, &[])?,
        };
        let overflow = vm.alloc_host_tlv(&self.overflow)?;
        let table = vm.alloc_heap(table_bytes)?;
        for (index, value) in [definition, account, revision, holdings, limit, overflow]
            .into_iter()
            .enumerate()
        {
            vm.store_u64(table + index as u64 * 8, value)?;
        }
        Ok(table)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_model_base::domain::DomainId;
    use iroha_test_samples::ALICE_ID;

    fn quote(limit: Option<u32>) -> AssetUidHoldingQuoteV1 {
        AssetUidHoldingQuoteV1 {
            asset_definition_id: AssetDefinitionId::derive_from_components(
                DomainId::try_new("escrow", "universal").unwrap(),
                "ds".parse().unwrap(),
            ),
            account_id: ALICE_ID.clone(),
            policy_revision: u64::MAX,
            beneficial_holdings: 1_050_u32.into(),
            holding_limit: limit.map(Into::into),
            required_overflow: if limit.is_some() { 75_u32 } else { 0 }.into(),
        }
    }

    #[test]
    fn quote_projection_preserves_nominal_fields_full_revision_and_optional_limit() {
        for cap in [None, Some(1_000)] {
            let quote = quote(cap);
            let prepared = PreparedUidHoldingQuote::prepare(&quote).unwrap();
            assert!(prepared.encoded_bytes().unwrap() > 0);
            let mut vm = IVM::new(100_000);
            let table = prepared.materialize(&mut vm).unwrap();
            vm.ensure_owned_heap_range(table, 48).unwrap();
            let words = (0..6)
                .map(|index| vm.load_u64(table + index * 8).unwrap())
                .collect::<Vec<_>>();
            assert_eq!(
                CoreHost::decode_tlv_typed::<AssetDefinitionId>(
                    &vm,
                    words[0],
                    PointerType::AssetDefinitionId,
                )
                .unwrap(),
                quote.asset_definition_id,
            );
            assert_eq!(
                CoreHost::decode_tlv_typed::<AccountId>(&vm, words[1], PointerType::AccountId)
                    .unwrap(),
                quote.account_id,
            );
            let revision = CoreHost::decode_pointer_tlv(&vm, words[2], PointerType::Int).unwrap();
            assert_eq!(
                revision.payload,
                IntValueV1::try_new(BigInt::from(u64::MAX))
                    .unwrap()
                    .encode_frame()
                    .unwrap(),
            );
            assert_eq!(
                CoreHost::decode_quantity(&vm, words[3]).unwrap(),
                quote.beneficial_holdings
            );
            let (present, values) =
                ivm::sum::read_words(&vm, words[4], ivm::sum::SumLayoutV1::option(1).unwrap())
                    .unwrap();
            assert_eq!(present, cap.is_some());
            if let Some(limit) = quote.holding_limit {
                assert_eq!(CoreHost::decode_quantity(&vm, values[0]).unwrap(), limit);
            }
            assert_eq!(
                CoreHost::decode_quantity(&vm, words[5]).unwrap(),
                quote.required_overflow
            );
        }
    }

    #[test]
    fn quote_projection_memory_refusal_does_not_publish_a_partial_table() {
        let mut vm = IVM::new(100_000);
        vm.memory.set_heap_limit(0).unwrap();
        let before = vm.alloc_heap(0).unwrap();
        let prepared = PreparedUidHoldingQuote::prepare(&quote(Some(1_000))).unwrap();
        assert!(matches!(
            prepared.materialize(&mut vm),
            Err(ivm::VMError::OutOfMemory)
        ));
        assert_eq!(vm.alloc_heap(0).unwrap(), before);
        assert_eq!(vm.register(10), 0);
        let probe = ivm_abi::numeric_tlv::encode_quantity(&Quantity::zero()).unwrap();
        let expected = IVM::new(100_000).alloc_host_tlv(&probe).unwrap();
        assert_eq!(vm.alloc_host_tlv(&probe).unwrap(), expected);
    }

    #[test]
    fn quote_failures_preserve_original_local_capacity_and_deterministic_gas() {
        let budget = iroha_allocation::AllocationBudget::new(2);
        let retained = budget.try_reserve_bytes(2).unwrap();
        let refusal = budget.try_reserve_bytes(1).unwrap_err();
        let expected = refusal.clone();
        let mapped = map_quote_error(AssetUidHoldingQuoteError::Local(refusal.into()));
        assert!(matches!(mapped, ivm::VMError::AllocationDeferred(actual) if actual == expected));
        drop(retained);
        assert!(budget.try_reserve_bytes(1).is_ok());
        assert!(matches!(
            map_quote_error(AssetUidHoldingQuoteError::Query(
                QueryExecutionFail::GasBudgetExceeded,
            )),
            ivm::VMError::OutOfGas,
        ));
    }

    #[test]
    fn quote_requires_authenticated_frame_before_decoding_or_returning_values() {
        let mut host = CoreHost::new(ALICE_ID.clone());
        let mut vm = IVM::new(100_000);
        vm.set_register(10, u64::MAX);
        assert!(matches!(
            host.execute_uid_holding_quote(&mut vm, 0x01_0224),
            Err(ivm::VMError::PermissionDenied),
        ));
        assert_eq!(vm.register(10), u64::MAX);
        assert!(host.queued.is_empty());
    }
}
