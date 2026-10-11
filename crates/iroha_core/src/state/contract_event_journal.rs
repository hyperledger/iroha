//! One transaction-owned emission order and its original physical allocation custody.

use super::StateReadOnly;
use iroha_allocation::{
    AllocationBudget, ChargedBuffer, ChargedBufferError, RetainedPayload, SharedFromChargeError,
};
use iroha_crypto::Hash;
use iroha_data_model::{
    ValidationFail,
    smart_contract::event::{
        ContractEmissionAdmissionErrorV1, ContractEmissionsV1, PreparedContractEmissionsV1,
    },
};

use crate::{
    execution_attempt::ExecutionAttemptError,
    smartcontracts::ivm::host::contract_event::OwnedContractEmission,
};

/// The actual root output alone consumes the transaction's ordered emissions.
pub(super) enum DrainedContractEvents {
    Complete(ContractEmissionsV1),
    OutputLimit,
}

/// Move-only staging; callbacks append to this owner instead of their own output rows.
pub(super) struct ContractEventJournal {
    maximum_bytes: Result<u64, String>,
    call: Option<Hash>,
    entries: Option<ChargedBuffer<OwnedContractEmission>>,
    prepared: Option<PreparedContractEmissionsV1>,
    payload_bytes: u64,
    overflow: bool,
    rejected: bool,
    refused: bool,
    consumed: bool,
}

fn invariant() -> ExecutionAttemptError<String> {
    ExecutionAttemptError::Deferred(ivm::ExecutionDeferral::LocalInvariantViolation.into())
}

fn allocation(error: ChargedBufferError) -> ExecutionAttemptError<String> {
    ExecutionAttemptError::Deferred(match error {
        ChargedBufferError::Admission(reason) => reason.into(),
        ChargedBufferError::Allocator { .. } => {
            ivm::ExecutionDeferral::AllocationUnavailable.into()
        }
    })
}

impl ContractEventJournal {
    pub(super) fn new(maximum_bytes: Result<u64, String>) -> Self {
        Self {
            maximum_bytes,
            call: None,
            entries: None,
            prepared: None,
            payload_bytes: 0,
            overflow: false,
            rejected: false,
            refused: false,
            consumed: false,
        }
    }

    fn check_owner(&self, call: Option<Hash>) -> Result<Hash, ExecutionAttemptError<String>> {
        if self.consumed || self.refused || self.rejected || self.maximum_bytes.is_err() {
            return Err(invariant());
        }
        let call = call.ok_or_else(invariant)?;
        if self.call.is_some_and(|owner| owner != call) {
            return Err(invariant());
        }
        Ok(call)
    }

    pub(super) fn append(
        &mut self,
        call: Option<Hash>,
        emission: OwnedContractEmission,
        budget: &AllocationBudget,
    ) -> Result<(), ExecutionAttemptError<String>> {
        let result = (|| {
            let call = self.check_owner(call)?;
            if self.prepared.is_some()
                || !emission.metadata_charges.belongs_to(budget)
                || !emission.value_charges.belongs_to(budget)
                || emission
                    .metadata_charges
                    .as_slice()
                    .iter()
                    .chain(emission.value_charges.as_slice())
                    .any(|charge| !charge.belongs_to(budget))
                || self
                    .entries
                    .as_ref()
                    .is_some_and(|entries| !entries.belongs_to(budget))
            {
                return Err(invariant());
            }
            self.call = Some(call);
            if self.overflow {
                return Ok(());
            }
            // Nested payload length is a lower bound on the enclosing result. Do
            // not add independent frame headers and reject exact-boundary rows.
            let _flags =
                norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
            let bytes =
                norito::core::encoded_payload_len(&emission.value).map_err(|_| invariant())?;
            let total = u64::try_from(bytes)
                .ok()
                .and_then(|bytes| self.payload_bytes.checked_add(bytes));
            if total.is_none_or(|bytes| bytes > *self.maximum_bytes.as_ref().expect("checked")) {
                self.entries = None;
                self.overflow = true;
                return Ok(());
            }
            let len = self
                .entries
                .as_ref()
                .map_or(0, |entries| entries.as_slice().len());
            if self
                .entries
                .as_ref()
                .is_none_or(|entries| len == entries.capacity())
            {
                let capacity = len.checked_mul(2).unwrap_or(usize::MAX).max(1);
                let mut replacement = ChargedBuffer::new(capacity, budget).map_err(allocation)?;
                if let Some(mut original) = self.entries.take() {
                    for entry in original.drain_all() {
                        replacement.push_reserved(entry);
                    }
                    // Only the now-empty old backing is reclaimed. Each record
                    // still owns its unchanged metadata and payload allocations.
                }
                self.entries = Some(replacement);
            }
            self.entries
                .as_mut()
                .expect("reserved above")
                .push_reserved(emission);
            self.payload_bytes = total.expect("bounded above");
            Ok(())
        })();
        if result.is_err() {
            self.refused = true;
        }
        result
    }

    /// Actual rejection and a proved output overflow destroy every business emission.
    pub(super) fn discard_rejected(
        &mut self,
        call: Hash,
    ) -> Result<(), ExecutionAttemptError<String>> {
        if let Err(error) = self.check_owner(Some(call)) {
            self.refused = true;
            return Err(error);
        }
        self.entries = None;
        self.prepared = None;
        self.rejected = true;
        self.consumed = true;
        Ok(())
    }

    /// Transfer the exact original fields and allocation charges, never cloned records.
    #[allow(unsafe_code)]
    pub(super) fn take(
        &mut self,
        call: Hash,
        budget: &AllocationBudget,
    ) -> Result<DrainedContractEvents, ExecutionAttemptError<String>> {
        if let Err(error) = self.check_owner(Some(call)) {
            self.refused = true;
            return Err(error);
        }
        if self.overflow {
            self.consumed = true;
            return Ok(DrainedContractEvents::OutputLimit);
        }
        if self.entries.is_none() && self.prepared.is_none() {
            self.consumed = true;
            return Ok(DrainedContractEvents::Complete(
                ContractEmissionsV1::default(),
            ));
        }
        if self.prepared.is_none() {
            let entries = self.entries.as_ref().ok_or_else(invariant)?;
            if !entries.belongs_to(budget) {
                self.refused = true;
                return Err(invariant());
            }
            let mut charge_count = 1usize; // canonical outer Vec backing
            for entry in entries.as_slice() {
                charge_count = charge_count
                    .checked_add(entry.metadata_charges.as_slice().len())
                    .and_then(|count| count.checked_add(entry.value_charges.as_slice().len()))
                    .ok_or_else(invariant)?;
            }
            // Reserve every final container before consuming any original entry.
            let mut values =
                ChargedBuffer::new(entries.as_slice().len(), budget).map_err(allocation)?;
            let mut charges = ChargedBuffer::new(charge_count, budget).map_err(allocation)?;
            let layout = ContractEmissionsV1::allocation_layout();
            let mut control_reservation = budget
                .try_reserve(layout)
                .map_err(|reason| ExecutionAttemptError::Deferred(reason.into()))?;
            let control = control_reservation
                .try_split(layout)
                .map_err(|_| invariant())?;
            let mut entries = self.entries.take().expect("checked above");
            for OwnedContractEmission {
                value,
                mut metadata_charges,
                mut value_charges,
            } in entries.drain_all()
            {
                values.push_reserved(value);
                for charge in metadata_charges
                    .drain_all()
                    .chain(value_charges.drain_all())
                {
                    charges.push_reserved(charge);
                }
                // Empty temporary ledger backing dies here, while every charge
                // for the canonical fields has already moved into the final ledger.
            }
            // SAFETY: unchanged exact backing moves into the immutable canonical
            // Vec; its original charge joins all original nested-field charges.
            let (values, backing) = unsafe { values.into_allocation_parts() };
            charges.push_reserved(backing);
            // SAFETY: every allocation originated in the funded materializer or
            // exact outer Vec above. No field is copied, grown or exposed mutably.
            let payload = match unsafe { RetainedPayload::try_new(values, charges, budget) } {
                Ok(payload) => payload,
                Err((values, charges, _)) => {
                    drop(values);
                    drop(charges);
                    self.refused = true;
                    return Err(invariant());
                }
            };
            self.prepared = Some(PreparedContractEmissionsV1::new(payload, control));
        }
        match self
            .prepared
            .as_mut()
            .expect("prepared above")
            .try_admit(budget)
        {
            Ok(events) => {
                self.prepared = None;
                self.consumed = true;
                Ok(DrainedContractEvents::Complete(events))
            }
            Err(error) => {
                // Retain the identical graph and shell charge on local refusal;
                // retry never refunds/reacquires any payload reservation.
                Err(match error {
                    ContractEmissionAdmissionErrorV1::Shared(
                        SharedFromChargeError::Allocator { .. },
                    ) => ExecutionAttemptError::Deferred(
                        ivm::ExecutionDeferral::AllocationUnavailable.into(),
                    ),
                    _ => {
                        self.refused = true;
                        invariant()
                    }
                })
            }
        }
    }

    pub(super) fn allows_apply(&self) -> bool {
        !self.refused
            && !self.rejected
            && !self.overflow
            && self.entries.is_none()
            && self.prepared.is_none()
    }
}

impl super::StateTransaction<'_, '_> {
    /// Append one authenticated host emission to the actual root invocation owner.
    pub(crate) fn record_contract_emission(
        &mut self,
        emission: OwnedContractEmission,
    ) -> Result<(), ValidationFail> {
        let budget = self.execution_budget();
        self.contract_event_journal
            .append(self.tx_call_hash, emission, &budget)
            .map_err(|error| {
                self.attempt_error_to_validation_fail(
                    error.map_rejection(ValidationFail::InternalError),
                )
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smartcontracts::ivm::host::contract_event::capture;
    use iroha_data_model::smart_contract::{
        ContractAddress,
        entrypoint::{
            EntrypointStructTypeNodeV1, EntrypointValueTypeNodeV1, EntrypointValueTypeV1,
        },
        event::ContractEventDescriptorV1,
    };
    use iroha_model_base::topology::DataSpaceId;
    use iroha_test_samples::ALICE_ID;

    fn emission(budget: &AllocationBudget, ordinal: u32) -> OwnedContractEmission {
        let contract = ContractAddress::derive(
            &"hash:0000000000000000000000000000000000000000000000000000000000000001#C50E"
                .parse()
                .unwrap(),
            &ALICE_ID,
            42,
            DataSpaceId::UNIVERSAL,
        )
        .unwrap();
        let definition = ContractEventDescriptorV1 {
            name: "Accepted".parse().unwrap(),
            payload_type: EntrypointValueTypeV1 {
                nodes: vec![EntrypointValueTypeNodeV1::Struct(
                    EntrypointStructTypeNodeV1 {
                        name: "Fixture::Accepted".to_owned(),
                        fields: Vec::new(),
                    },
                )],
            },
        };
        let mut vm = ivm::IVM::new(100_000);
        let base = vm.alloc_heap(8).unwrap();
        vm.store_u64(base, 0).unwrap();
        capture(
            &vm,
            budget,
            &contract,
            Hash::new(b"artifact"),
            0,
            ordinal,
            &ALICE_ID,
            &definition,
            base,
            1,
        )
        .unwrap()
    }

    #[test]
    fn emission_journal_transfers_original_graph_in_execution_order_until_final_carrier_drop() {
        let budget = AllocationBudget::new(1024 * 1024);
        let call = Hash::new(b"actual root");
        let mut journal = ContractEventJournal::new(Ok(1024 * 1024));
        assert!(journal.allows_apply());
        let first = emission(&budget, 0);
        let original_nodes = first.value.definition.payload_type.nodes.as_ptr();
        journal.append(Some(call), first, &budget).unwrap();
        journal
            .append(Some(call), emission(&budget, 1), &budget)
            .unwrap();
        journal
            .append(Some(call), emission(&budget, 2), &budget)
            .unwrap();
        assert!(!journal.allows_apply());
        let DrainedContractEvents::Complete(events) = journal.take(call, &budget).unwrap() else {
            panic!("fitting emissions");
        };
        assert!(journal.allows_apply());
        assert!(events.admitted_to(&budget));
        assert_eq!(
            events.iter().map(|event| event.event).collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
        assert_eq!(
            events.as_slice()[0].definition.payload_type.nodes.as_ptr(),
            original_nodes
        );
        let retained = budget.reserved_bytes();
        let copy = events.clone();
        assert!(ContractEmissionsV1::ptr_eq(&events, &copy));
        assert_eq!(budget.reserved_bytes(), retained);
        drop(journal);
        drop(events);
        assert_eq!(budget.reserved_bytes(), retained);
        drop(copy);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn emission_journal_final_container_refusal_retains_source_for_retry() {
        let budget = AllocationBudget::new(1024 * 1024);
        let call = Hash::new(b"actual root");
        let mut journal = ContractEventJournal::new(Ok(1024 * 1024));
        let original = emission(&budget, 0);
        let original_nodes = original.value.definition.payload_type.nodes.as_ptr();
        journal.append(Some(call), original, &budget).unwrap();
        let before = budget.reserved_bytes();
        budget.set_limit_bytes(before);
        assert!(matches!(
            journal.take(call, &budget),
            Err(ExecutionAttemptError::Deferred(_))
        ));
        assert_eq!(budget.reserved_bytes(), before);
        assert!(!journal.allows_apply());
        budget.set_limit_bytes(1024 * 1024);
        let DrainedContractEvents::Complete(events) = journal.take(call, &budget).unwrap() else {
            panic!("fitting emissions");
        };
        assert_eq!(
            events.as_slice()[0].definition.payload_type.nodes.as_ptr(),
            original_nodes
        );
        assert!(journal.allows_apply());
        assert!(journal.take(call, &budget).is_err());
        assert!(
            !journal.allows_apply(),
            "a repeated drain poisons application"
        );
        drop(events);
        assert_eq!(budget.reserved_bytes(), 0);
    }

    #[test]
    fn emission_journal_rejection_and_output_overflow_publish_nothing() {
        for overflow in [false, true] {
            let budget = AllocationBudget::new(1024 * 1024);
            let call = Hash::new(b"actual root");
            let mut journal = ContractEventJournal::new(Ok(if overflow { 0 } else { 1024 * 1024 }));
            journal
                .append(Some(call), emission(&budget, 0), &budget)
                .unwrap();
            if overflow {
                assert!(matches!(
                    journal.take(call, &budget).unwrap(),
                    DrainedContractEvents::OutputLimit
                ));
            } else {
                journal.discard_rejected(call).unwrap();
            }
            assert!(!journal.allows_apply());
            assert_eq!(budget.reserved_bytes(), 0);
        }
    }

    #[test]
    fn emission_journal_rejects_foreign_call_and_foreign_allocation_pool() {
        let budget = AllocationBudget::new(1024 * 1024);
        let foreign = AllocationBudget::new(1024 * 1024);
        let call = Hash::new(b"actual root");
        let mut journal = ContractEventJournal::new(Ok(1024 * 1024));
        assert!(
            journal
                .append(Some(call), emission(&foreign, 0), &budget)
                .is_err()
        );
        assert_eq!(foreign.reserved_bytes(), 0);
        assert!(!journal.allows_apply());
        let mut journal = ContractEventJournal::new(Ok(1024 * 1024));
        journal
            .append(Some(call), emission(&budget, 0), &budget)
            .unwrap();
        assert!(journal.take(Hash::new(b"foreign root"), &budget).is_err());
        assert!(!journal.allows_apply());
        assert!(budget.reserved_bytes() > 0);
        drop(journal);
        assert_eq!(budget.reserved_bytes(), 0);
        let mut missing = ContractEventJournal::new(Ok(1024 * 1024));
        assert!(missing.append(None, emission(&budget, 0), &budget).is_err());
        assert!(!missing.allows_apply());
        assert_eq!(budget.reserved_bytes(), 0);
    }
}
