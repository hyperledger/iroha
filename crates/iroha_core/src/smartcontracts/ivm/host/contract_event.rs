//! Exact original-pool construction of immutable native emission graphs.

use std::alloc::Layout;

use iroha_allocation::{
    AllocationBudget, AllocationCharge, AllocationReservation, ChargedBuffer, PrepaidBufferError,
};
use iroha_crypto::Hash;
use iroha_data_model::{
    account::AccountId,
    smart_contract::{
        ContractAddress,
        entrypoint::{
            EntrypointStructTypeNodeV1, EntrypointValueTypeNodeV1, EntrypointValueTypeV1,
        },
        event::{ContractEmissionV1, ContractEventDescriptorV1},
        manifest::{
            ContractEnumTypeDescriptorV1, ContractEnumVariantDescriptorV1,
            ContractErrorTypeDescriptor, ContractErrorVariantDescriptor,
        },
    },
};
use ivm::{IVM, VMError, value_record::capture_value_record_funded};

/// One complete emission and its original allocation ledgers, moved together.
///
/// The field order guarantees all canonical allocations die before their credits.
pub(crate) struct OwnedContractEmission {
    pub(crate) value: ContractEmissionV1,
    pub(crate) metadata_charges: ChargedBuffer<AllocationCharge>,
    pub(crate) value_charges: ChargedBuffer<AllocationCharge>,
}

impl std::fmt::Debug for OwnedContractEmission {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OwnedContractEmission")
            .field("value", &self.value)
            .finish_non_exhaustive()
    }
}

#[derive(Default)]
struct Demand {
    bytes: usize,
    allocations: usize,
}
impl Demand {
    fn add(&mut self, layout: Layout) -> Result<(), VMError> {
        self.bytes = self.bytes.checked_add(layout.size()).ok_or_else(overflow)?;
        self.allocations = self.allocations.checked_add(1).ok_or_else(overflow)?;
        Ok(())
    }
    fn vector<T>(&mut self, count: usize) -> Result<(), VMError> {
        self.add(Layout::array::<T>(count).map_err(|_| overflow())?)
    }
    fn string(&mut self, value: &str) -> Result<(), VMError> {
        self.vector::<u8>(value.len())
    }
    fn event(&mut self, event: &ContractEventDescriptorV1) -> Result<(), VMError> {
        if let Some(layout) = event.name.admission_clone_layout() {
            self.add(layout)?;
        }
        self.vector::<EntrypointValueTypeNodeV1>(event.payload_type.nodes.len())?;
        for node in &event.payload_type.nodes {
            match node {
                EntrypointValueTypeNodeV1::Struct(node) => {
                    self.string(&node.name)?;
                    self.vector::<String>(node.fields.len())?;
                    for field in &node.fields {
                        self.string(field)?;
                    }
                }
                EntrypointValueTypeNodeV1::Error(error) => {
                    self.string(&error.identity)?;
                    self.vector::<ContractErrorVariantDescriptor>(error.variants.len())?;
                    for variant in &error.variants {
                        self.string(&variant.name)?;
                    }
                }
                EntrypointValueTypeNodeV1::Enum(descriptor) => {
                    self.string(&descriptor.identity)?;
                    self.vector::<ContractEnumVariantDescriptorV1>(descriptor.variants.len())?;
                    for variant in &descriptor.variants {
                        self.string(&variant.name)?;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }
}
fn overflow() -> VMError {
    VMError::AllocationDeferred(iroha_allocation::AllocationRefusal::DemandOverflow)
}
fn invariant() -> VMError {
    VMError::ExecutionDeferred(ivm::error::ExecutionDeferral::LocalInvariantViolation)
}
fn allocation() -> VMError {
    VMError::ExecutionDeferred(ivm::error::ExecutionDeferral::AllocationUnavailable)
}

/// Pre-copy exact metadata allocation demand used by emission gas/output preflight.
pub(crate) fn metadata_allocation_bytes(
    contract: &ContractAddress,
    caller: &AccountId,
    definition: &ContractEventDescriptorV1,
) -> Result<usize, VMError> {
    let mut demand = Demand::default();
    demand.event(definition)?;
    if let Some(layout) = contract.admission_clone_layout() {
        demand.add(layout)?;
    }
    let mut error = None;
    caller
        .for_each_admission_clone_layout(|layout| {
            if let Err(reason) = demand.add(layout) {
                error = Some(reason);
            }
        })
        .map_err(|_| invariant())?;
    if let Some(error) = error {
        return Err(error);
    }
    Ok(demand.bytes)
}
fn prepaid(error: PrepaidBufferError) -> VMError {
    match error {
        PrepaidBufferError::Allocation(iroha_allocation::ChargedBufferError::Admission(reason)) => {
            VMError::AllocationDeferred(reason)
        }
        PrepaidBufferError::Allocation(iroha_allocation::ChargedBufferError::Allocator {
            ..
        }) => allocation(),
        PrepaidBufferError::Reservation(_) => invariant(),
    }
}

struct Construction {
    reservation: AllocationReservation,
    charges: ChargedBuffer<AllocationCharge>,
}
impl Construction {
    fn retain(&mut self, charge: AllocationCharge) -> Result<(), VMError> {
        self.charges.try_push(charge).map_err(|charge| {
            // A construction defect cannot refund a charge while its original field lives.
            std::mem::forget(charge);
            invariant()
        })
    }
    fn buffer<T>(&mut self, count: usize) -> Result<ChargedBuffer<T>, VMError> {
        ChargedBuffer::from_reservation(count, &mut self.reservation).map_err(prepaid)
    }
    #[allow(unsafe_code)]
    fn vector<T>(&mut self, source: ChargedBuffer<T>) -> Result<Vec<T>, VMError> {
        // SAFETY: exact fixed backing moves unchanged into a canonical field; the
        // original charge stays in this ledger until the whole value is destroyed.
        let (value, charge) = unsafe { source.into_allocation_parts() };
        if let Err(error) = self.retain(charge) {
            drop(value);
            return Err(error);
        }
        Ok(value)
    }
    fn string(&mut self, source: &str) -> Result<String, VMError> {
        let mut bytes = self.buffer(source.len())?;
        for byte in source.as_bytes() {
            bytes.push_reserved(*byte);
        }
        Ok(String::from_utf8(self.vector(bytes)?).expect("original UTF-8 source bytes"))
    }
    fn event(
        &mut self,
        source: &ContractEventDescriptorV1,
    ) -> Result<ContractEventDescriptorV1, VMError> {
        if let Some(layout) = source.name.admission_clone_layout() {
            let charge = self
                .reservation
                .try_split(layout)
                .map_err(|_| invariant())?;
            self.retain(charge)?;
        }
        let name = source
            .name
            .try_clone_for_admission()
            .map_err(|_| allocation())?;
        let mut nodes = self.buffer(source.payload_type.nodes.len())?;
        for source in &source.payload_type.nodes {
            let node = match source {
                EntrypointValueTypeNodeV1::Struct(source) => {
                    let name = self.string(&source.name)?;
                    let mut fields = self.buffer(source.fields.len())?;
                    for field in &source.fields {
                        fields.push_reserved(self.string(field)?);
                    }
                    EntrypointValueTypeNodeV1::Struct(EntrypointStructTypeNodeV1 {
                        name,
                        fields: self.vector(fields)?,
                    })
                }
                EntrypointValueTypeNodeV1::Error(source) => {
                    let identity = self.string(&source.identity)?;
                    let mut variants = self.buffer(source.variants.len())?;
                    for variant in &source.variants {
                        variants.push_reserved(ContractErrorVariantDescriptor {
                            name: self.string(&variant.name)?,
                            code: variant.code,
                        });
                    }
                    EntrypointValueTypeNodeV1::Error(ContractErrorTypeDescriptor {
                        identity,
                        variants: self.vector(variants)?,
                    })
                }
                EntrypointValueTypeNodeV1::Enum(source) => {
                    let identity = self.string(&source.identity)?;
                    let mut variants = self.buffer(source.variants.len())?;
                    for variant in &source.variants {
                        variants.push_reserved(ContractEnumVariantDescriptorV1 {
                            name: self.string(&variant.name)?,
                            code: variant.code,
                        });
                    }
                    EntrypointValueTypeNodeV1::Enum(ContractEnumTypeDescriptorV1 {
                        identity,
                        variants: self.vector(variants)?,
                    })
                }
                EntrypointValueTypeNodeV1::Tuple(value) => EntrypointValueTypeNodeV1::Tuple(*value),
                EntrypointValueTypeNodeV1::Option => EntrypointValueTypeNodeV1::Option,
                EntrypointValueTypeNodeV1::Result => EntrypointValueTypeNodeV1::Result,
                EntrypointValueTypeNodeV1::List(value) => {
                    EntrypointValueTypeNodeV1::List(value.clone())
                }
                EntrypointValueTypeNodeV1::Leaf(value) => EntrypointValueTypeNodeV1::Leaf(*value),
                EntrypointValueTypeNodeV1::Unit => EntrypointValueTypeNodeV1::Unit,
                // Authenticated event schemas exclude cursors recursively.
                EntrypointValueTypeNodeV1::StateCursor(_) => return Err(invariant()),
            };
            nodes.push_reserved(node);
        }
        Ok(ContractEventDescriptorV1 {
            name,
            payload_type: EntrypointValueTypeV1 {
                nodes: self.vector(nodes)?,
            },
        })
    }
}

/// Capture an authenticated source declaration, immutable origin and live public payload.
/// The caller quotes/debits work and output capacity before calling this materializer.
#[allow(clippy::too_many_arguments)]
pub(crate) fn capture(
    vm: &IVM,
    budget: &AllocationBudget,
    contract: &ContractAddress,
    code_hash: Hash,
    entrypoint: u32,
    event: u32,
    caller: &AccountId,
    definition: &ContractEventDescriptorV1,
    base: u64,
    words: usize,
) -> Result<OwnedContractEmission, VMError> {
    if !definition.validate() {
        return Err(VMError::DecodeError);
    }
    let mut demand = Demand::default();
    demand.event(definition)?;
    if let Some(layout) = contract.admission_clone_layout() {
        demand.add(layout)?;
    }
    let mut plan_error = None;
    caller
        .for_each_admission_clone_layout(|layout| {
            if let Err(error) = demand.add(layout) {
                plan_error = Some(error);
            }
        })
        .map_err(|_| invariant())?;
    if let Some(error) = plan_error {
        return Err(error);
    }
    let ledger = Layout::array::<AllocationCharge>(demand.allocations).map_err(|_| overflow())?;
    let bytes = demand
        .bytes
        .checked_add(ledger.size())
        .ok_or_else(overflow)?;
    let mut reservation = budget
        .try_reserve_bytes(bytes)
        .map_err(VMError::AllocationDeferred)?;
    let charges =
        ChargedBuffer::from_reservation(demand.allocations, &mut reservation).map_err(prepaid)?;
    let mut construction = Construction {
        reservation,
        charges,
    };
    let definition = construction.event(definition)?;
    if let Some(layout) = contract.admission_clone_layout() {
        let charge = construction
            .reservation
            .try_split(layout)
            .map_err(|_| invariant())?;
        construction.retain(charge)?;
    }
    let contract = contract
        .try_clone_for_admission()
        .map_err(|_| allocation())?;
    let mut clone_error = None;
    caller
        .for_each_admission_clone_layout(|layout| {
            let result = construction
                .reservation
                .try_split(layout)
                .map_err(|_| invariant())
                .and_then(|charge| construction.retain(charge));
            if let Err(error) = result {
                clone_error = Some(error);
            }
        })
        .map_err(|_| invariant())?;
    if let Some(error) = clone_error {
        return Err(error);
    }
    let caller = caller.try_clone_for_admission().map_err(|_| allocation())?;
    let captured = capture_value_record_funded(vm, &definition.payload_type, base, words, budget)?;
    // SAFETY: the original record and ledger move together into OwnedContractEmission;
    // fields are immutable and the value is destroyed before either ledger.
    #[allow(unsafe_code)]
    let (payload, value_charges) = unsafe { captured.into_allocation_parts() };
    let value = ContractEmissionV1 {
        contract,
        code_hash,
        entrypoint,
        event,
        caller,
        definition,
        payload,
    };
    if construction.charges.as_slice().len() != demand.allocations
        || construction.reservation.remaining_bytes() != 0
    {
        drop(value);
        drop(value_charges);
        return Err(invariant());
    }
    Ok(OwnedContractEmission {
        value,
        metadata_charges: construction.charges,
        value_charges,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_data_model::smart_contract::entrypoint::EntrypointValueKindV1;
    use iroha_model_base::topology::DataSpaceId;
    use iroha_test_samples::ALICE_ID;

    #[test]
    fn emission_materializer_keeps_every_original_allocation_until_payload_drop() {
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
                nodes: vec![
                    EntrypointValueTypeNodeV1::Struct(EntrypointStructTypeNodeV1 {
                        name: "Fixture::Accepted".to_owned(),
                        fields: vec!["flag".to_owned()],
                    }),
                    EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Bool),
                ],
            },
        };
        let mut vm = IVM::new(100_000);
        let base = vm.alloc_heap(8).unwrap();
        vm.store_u64(base, 1).unwrap();
        let budget = AllocationBudget::new(1024 * 1024);
        let code_hash = Hash::new(b"authenticated test artifact");
        let owned = capture(
            &vm,
            &budget,
            &contract,
            code_hash,
            2,
            0,
            &ALICE_ID,
            &definition,
            base,
            1,
        )
        .unwrap();
        assert_eq!(owned.value.definition, definition);
        assert_eq!(owned.value.contract, contract);
        assert_eq!(owned.value.code_hash, code_hash);
        assert_eq!(owned.value.entrypoint, 2);
        assert_eq!(owned.value.caller, *ALICE_ID);
        let retained = budget.reserved_bytes();
        assert!(retained > metadata_allocation_bytes(&contract, &ALICE_ID, &definition).unwrap());
        budget.set_limit_bytes(retained);
        assert!(matches!(
            capture(
                &vm,
                &budget,
                &contract,
                code_hash,
                2,
                0,
                &ALICE_ID,
                &definition,
                base,
                1
            ),
            Err(VMError::AllocationDeferred(_))
        ));
        assert_eq!(budget.reserved_bytes(), retained);
        drop(owned);
        assert_eq!(budget.reserved_bytes(), 0);
        budget.set_limit_bytes(1024 * 1024);
        vm.store_u64(base, 7).unwrap();
        assert!(
            capture(
                &vm,
                &budget,
                &contract,
                code_hash,
                2,
                0,
                &ALICE_ID,
                &definition,
                base,
                1
            )
            .is_err()
        );
        assert_eq!(
            budget.reserved_bytes(),
            0,
            "invalid values release the entire unpublished graph"
        );
    }
}
