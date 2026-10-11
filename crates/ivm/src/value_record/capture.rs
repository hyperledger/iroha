//! Bounded mid-invocation capture using the canonical result value collector.

use super::*;
use crate::VMError;
use iroha_data_model::smart_contract::entrypoint::{
    EntrypointArgumentRecordV1, EntrypointArgumentSchemaV1, MAX_ENTRYPOINT_ARGUMENT_TYPE_NODES,
    entrypoint_argument_schema_hash_v1,
};

/// Pre-copy work and retained-allocation quote for one public value table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValueRecordCaptureQuote {
    /// Deterministic work charged before validating and copying payload bodies.
    pub gas: u64,
    /// Concrete upper bound on retained atom and pointer backing.
    pub retained_bytes: usize,
    /// Exact number of canonical atoms in this active value.
    pub atoms: usize,
    /// Number of separately retained TLV envelope allocations.
    pub pointers: usize,
    /// Sum of exact complete retained TLV envelope allocation lengths.
    pub pointer_bytes: usize,
}

/// Original canonical record graph and exact prepaid allocation ledger.
///
/// Fields remain ordered so the value graph is destroyed before its charges.
pub struct CapturedValueRecord {
    record: EntrypointReturnRecordV1,
    charges: iroha_allocation::ChargedBuffer<iroha_allocation::AllocationCharge>,
}
impl CapturedValueRecord {
    pub(super) fn belongs_to(&self, budget: &iroha_allocation::AllocationBudget) -> bool {
        self.charges.belongs_to(budget)
            && self
                .charges
                .as_slice()
                .iter()
                .all(|charge| charge.belongs_to(budget))
    }
    /// Borrow the immutable canonical graph without separating its original charges.
    pub fn get(&self) -> &EntrypointReturnRecordV1 {
        &self.record
    }
    /// Move the same graph and charge ledger into its next immutable protocol owner.
    ///
    /// # Safety
    /// The caller must move every original field without cloning, growing or exporting
    /// allocations, and preserve graph-before-ledger destruction on every exit path.
    #[allow(unsafe_code)]
    pub unsafe fn into_allocation_parts(
        self,
    ) -> (
        EntrypointReturnRecordV1,
        iroha_allocation::ChargedBuffer<iroha_allocation::AllocationCharge>,
    ) {
        (self.record, self.charges)
    }
}

pub(super) fn prepaid_error(error: iroha_allocation::PrepaidBufferError) -> VMError {
    use iroha_allocation::{ChargedBufferError, PrepaidBufferError};
    match error {
        PrepaidBufferError::Allocation(ChargedBufferError::Admission(reason)) => {
            VMError::AllocationDeferred(reason)
        }
        PrepaidBufferError::Allocation(ChargedBufferError::Allocator { .. }) => {
            VMError::ExecutionDeferred(crate::error::ExecutionDeferral::AllocationUnavailable)
        }
        PrepaidBufferError::Reservation(_) => {
            VMError::ExecutionDeferred(crate::error::ExecutionDeferral::LocalInvariantViolation)
        }
    }
}

#[derive(Clone, Copy)]
struct Visit {
    node: usize,
    base: u64,
    count: u64,
    stride: u64,
}

fn table(vm: &IVM, schema: &EntrypointValueTypeV1, base: u64, words: usize) -> Result<(), VMError> {
    if !schema.validate() || schema.word_count() != Some(words) || !base.is_multiple_of(8) {
        return Err(VMError::DecodeError);
    }
    let bytes = u64::try_from(words)
        .ok()
        .and_then(|words| words.checked_mul(8))
        .ok_or(VMError::DecodeError)?;
    vm.ensure_owned_heap_range(base, bytes)?;
    vm.ensure_public_memory(base, bytes)
}

/// Quote a live public value without cloning any guest pointer payload.
///
/// This bounded schema walk reads active tags, list lengths and TLV headers. Full
/// pointer digest and payload validation happens only after the caller has paid
/// this quote and retained the required allocation credit.
///
/// # Errors
/// Rejects malformed public tables, values above the record limit, or work that
/// cannot fit in `gas_limit`. Deterministic failures carry the quote work already
/// visited (capped at this allowance); callers add their earlier boundary work.
/// Original local memory refusals remain unmetered deferrals.
pub fn quote_value_record(
    vm: &IVM,
    schema: &EntrypointValueTypeV1,
    base: u64,
    words: usize,
    gas_limit: u64,
) -> Result<ValueRecordCaptureQuote, VMError> {
    let mut gas = 32_u64;
    if gas > gas_limit {
        return Err(VMError::metered(gas_limit, VMError::OutOfGas));
    }
    let result = (|| {
        table(vm, schema, base, words)?;
        let mut widths = [0_usize; MAX_ENTRYPOINT_ARGUMENT_TYPE_NODES];
        for index in (0..schema.nodes.len()).rev() {
            let node = &schema.nodes[index];
            widths[index] = match node {
                EntrypointValueTypeNodeV1::Struct(_) | EntrypointValueTypeNodeV1::Tuple(_) => {
                    let mut next = index + 1;
                    let mut sum = 0_usize;
                    for _ in 0..return_node_child_count(node) {
                        sum = sum.checked_add(widths[next]).ok_or(VMError::DecodeError)?;
                        next = entrypoint_value_subtree_range_v1(&schema.nodes, next)
                            .ok_or(VMError::DecodeError)?
                            .end;
                    }
                    sum.max(1)
                }
                _ => 1,
            };
        }
        let mut pending = [Visit {
            node: 0,
            base: 0,
            count: 0,
            stride: 0,
        }; MAX_ENTRYPOINT_ARGUMENT_TYPE_NODES * 2];
        pending[0] = Visit {
            node: 0,
            base,
            count: 1,
            stride: 0,
        };
        let mut pending_len = 1_usize;
        let mut atoms = 0_usize;
        let mut pointer_bytes = 0_usize;
        let mut pointers = 0_usize;
        let mut aggregate_bytes = 0_usize;
        let schema_bytes = norito::canonical_frame_len(schema).map_err(|_| VMError::DecodeError)?;
        gas = gas.saturating_add(schema_bytes as u64);
        let mut record_lower_bound = norito::core::Header::SIZE + 32;
        while pending_len != 0 {
            pending_len -= 1;
            let visit = pending[pending_len];
            gas = gas.saturating_add(32);
            if gas > gas_limit {
                return Err(VMError::OutOfGas);
            }
            let mut push = |task: Visit| -> Result<(), VMError> {
                *pending.get_mut(pending_len).ok_or(VMError::DecodeError)? = task;
                pending_len += 1;
                Ok(())
            };
            if visit.count > 1 {
                push(Visit {
                    base: visit
                        .base
                        .checked_add(visit.stride)
                        .ok_or(VMError::DecodeError)?,
                    count: visit.count - 1,
                    ..visit
                })?;
            }
            let node = schema.nodes.get(visit.node).ok_or(VMError::DecodeError)?;
            match node {
                EntrypointValueTypeNodeV1::Struct(_) | EntrypointValueTypeNodeV1::Tuple(_) => {
                    let mut next = visit.node + 1;
                    let mut address = visit.base;
                    for _ in 0..return_node_child_count(node) {
                        push(Visit {
                            node: next,
                            base: address,
                            count: 1,
                            stride: 0,
                        })?;
                        address = address
                            .checked_add(
                                (widths[next] as u64)
                                    .checked_mul(8)
                                    .ok_or(VMError::DecodeError)?,
                            )
                            .ok_or(VMError::DecodeError)?;
                        next = entrypoint_value_subtree_range_v1(&schema.nodes, next)
                            .ok_or(VMError::DecodeError)?
                            .end;
                    }
                    if return_node_child_count(node) == 0 && vm.load_u64(visit.base)? != 0 {
                        return Err(VMError::DecodeError);
                    }
                }
                EntrypointValueTypeNodeV1::Option | EntrypointValueTypeNodeV1::Result => {
                    atoms += 1;
                    let pointer = vm.load_u64(visit.base)?;
                    let first = visit.node + 1;
                    let second = entrypoint_value_subtree_range_v1(&schema.nodes, first)
                        .ok_or(VMError::DecodeError)?
                        .end;
                    let option = matches!(node, EntrypointValueTypeNodeV1::Option);
                    let layout = if option {
                        SumLayoutV1::option(widths[first] as u64)
                    } else {
                        SumLayoutV1::try_new(widths[second] as u64, widths[first] as u64)
                    }
                    .map_err(|_| VMError::DecodeError)?;
                    if !pointer.is_multiple_of(8) {
                        return Err(VMError::DecodeError);
                    }
                    vm.ensure_owned_heap_range(
                        pointer,
                        layout
                            .allocation_bytes()
                            .map_err(|_| VMError::DecodeError)?,
                    )?;
                    let tag = vm.load_u64(pointer)?;
                    let active = layout.active_words(tag).map_err(|_| VMError::DecodeError)?;
                    aggregate_bytes = aggregate_bytes
                        .checked_add(
                            usize::try_from(active)
                                .map_err(|_| VMError::DecodeError)?
                                .checked_mul(8)
                                .ok_or(VMError::DecodeError)?,
                        )
                        .ok_or(VMError::DecodeError)?;
                    if !option || tag == 1 {
                        push(Visit {
                            node: if tag == 1 { first } else { second },
                            base: pointer.checked_add(8).ok_or(VMError::DecodeError)?,
                            count: 1,
                            stride: 0,
                        })?;
                    }
                }
                EntrypointValueTypeNodeV1::List(list) => {
                    atoms += 1;
                    let pointer = vm.load_u64(visit.base)?;
                    let element = visit.node + 1;
                    let layout =
                        ListLayoutV1::try_new(u64::from(list.capacity), widths[element] as u64)
                            .map_err(|_| VMError::DecodeError)?;
                    let len = crate::list::len(vm, pointer, layout)?;
                    aggregate_bytes = aggregate_bytes
                        .checked_add(
                            usize::try_from(len)
                                .map_err(|_| VMError::DecodeError)?
                                .checked_mul(
                                    widths[element]
                                        .checked_mul(8)
                                        .and_then(|bytes| {
                                            bytes.checked_add(std::mem::size_of::<Vec<u64>>())
                                        })
                                        .ok_or(VMError::DecodeError)?,
                                )
                                .ok_or(VMError::DecodeError)?,
                        )
                        .ok_or(VMError::DecodeError)?;
                    if len != 0 {
                        push(Visit {
                            node: element,
                            base: pointer
                                .checked_add(
                                    layout.slot_offset(0).map_err(|_| VMError::DecodeError)?,
                                )
                                .ok_or(VMError::DecodeError)?,
                            count: len,
                            stride: (widths[element] as u64)
                                .checked_mul(8)
                                .ok_or(VMError::DecodeError)?,
                        })?;
                    }
                }
                EntrypointValueTypeNodeV1::Leaf(kind) if kind.is_pointer() => {
                    atoms += 1;
                    pointers += 1;
                    let pointer = vm.load_u64(visit.base)?;
                    let expected = expected_pointer_type(*kind).ok_or(VMError::DecodeError)?;
                    let payload = crate::host::quote_tlv_payload_len_at(vm, pointer, expected)?;
                    let bytes = payload
                        .checked_add(ENTRYPOINT_RETURN_TLV_ENVELOPE_BYTES_V1)
                        .ok_or(VMError::DecodeError)?;
                    pointer_bytes = pointer_bytes
                        .checked_add(bytes)
                        .ok_or(VMError::DecodeError)?;
                    gas = gas.saturating_add(bytes as u64);
                }
                EntrypointValueTypeNodeV1::StateCursor(_) => {
                    atoms += 1;
                    pointers += 1;
                    let pointer = vm.load_u64(visit.base)?;
                    let payload = crate::host::quote_tlv_payload_len_at(
                        vm,
                        pointer,
                        PointerType::NoritoBytes,
                    )?;
                    let bytes = payload
                        .checked_add(ENTRYPOINT_RETURN_TLV_ENVELOPE_BYTES_V1)
                        .ok_or(VMError::DecodeError)?;
                    pointer_bytes = pointer_bytes
                        .checked_add(bytes)
                        .ok_or(VMError::DecodeError)?;
                    gas = gas.saturating_add(bytes as u64);
                }
                _ => {
                    atoms += 1;
                    let _ = vm.load_u64(visit.base)?;
                }
            }
            record_lower_bound =
                record_lower_bound.max(norito::core::Header::SIZE + 32 + atoms + pointer_bytes);
            if record_lower_bound > MAX_ENTRYPOINT_RETURN_RECORD_BYTES {
                return Err(VMError::DecodeError);
            }
            if gas > gas_limit {
                return Err(VMError::OutOfGas);
            }
        }
        let retained_bytes = atoms
            .checked_mul(std::mem::size_of::<EntrypointValueAtomV1>())
            .and_then(|bytes| bytes.checked_add(pointer_bytes))
            .and_then(|bytes| bytes.checked_add(aggregate_bytes))
            .ok_or(VMError::DecodeError)?;
        Ok(ValueRecordCaptureQuote {
            gas,
            retained_bytes,
            atoms,
            pointers,
            pointer_bytes,
        })
    })();
    result.map_err(|error| meter_quote_error(gas, gas_limit, error))
}

/// Capture a public value into exact original-pool backing for committed effects.
///
/// All retained allocations are reserved before the first payload copy. The
/// caller keeps the returned graph and ledger together through its final owner.
///
/// # Errors
/// Preserves original allocation refusals and rejects malformed schema or guest data.
pub fn capture_value_record_funded(
    vm: &IVM,
    schema: &EntrypointValueTypeV1,
    base: u64,
    words: usize,
    budget: &iroha_allocation::AllocationBudget,
) -> Result<CapturedValueRecord, VMError> {
    use iroha_allocation::{AllocationCharge, ChargedBuffer};
    use std::alloc::Layout;
    let quote = quote_value_record(vm, schema, base, words, u64::MAX)?;
    let hash = funded_schema_hash(
        schema,
        iroha_data_model::smart_contract::entrypoint::ENTRYPOINT_RETURN_SCHEMA_HASH_DOMAIN_V1,
        budget,
    )?;
    let ledger_count = quote.pointers.checked_add(1).ok_or(VMError::DecodeError)?;
    let ledger_layout = Layout::array::<AllocationCharge>(ledger_count).map_err(|_| {
        VMError::AllocationDeferred(iroha_allocation::AllocationRefusal::DemandOverflow)
    })?;
    let atom_layout = Layout::array::<EntrypointValueAtomV1>(quote.atoms).map_err(|_| {
        VMError::AllocationDeferred(iroha_allocation::AllocationRefusal::DemandOverflow)
    })?;
    let demand = ledger_layout
        .size()
        .checked_add(atom_layout.size())
        .and_then(|bytes| bytes.checked_add(quote.pointer_bytes))
        .ok_or(VMError::AllocationDeferred(
            iroha_allocation::AllocationRefusal::DemandOverflow,
        ))?;
    let mut reservation = budget
        .try_reserve_bytes(demand)
        .map_err(VMError::AllocationDeferred)?;
    let mut charges =
        ChargedBuffer::from_reservation(ledger_count, &mut reservation).map_err(prepaid_error)?;
    let buffer =
        ChargedBuffer::<EntrypointValueAtomV1>::from_reservation(quote.atoms, &mut reservation)
            .map_err(prepaid_error)?;
    // SAFETY: the exact fixed backing never grows; the quote bounds every atom push.
    // The original charge moves into the same construction's retained ledger.
    #[allow(unsafe_code)]
    let (atoms, atom_charge) = unsafe { buffer.into_allocation_parts() };
    charges.push_reserved(atom_charge);
    struct Construction {
        atoms: Vec<EntrypointValueAtomV1>,
        budget: ReturnRecordBudget,
    }
    let mut construction = Construction {
        atoms,
        budget: ReturnRecordBudget {
            lower_bound_bytes: norito::core::Header::SIZE + 32,
            max_bytes: MAX_ENTRYPOINT_RETURN_RECORD_BYTES,
            reservation: Some(reservation),
            charges: Some(charges),
        },
    };
    let mut cursor = ResultTableCursor {
        vm,
        live_base: Some(base),
        word_index: 0,
        budget: &mut construction.budget,
    };
    let mut node = 0;
    collect_node(
        &schema.nodes,
        &mut node,
        &mut cursor,
        &mut construction.atoms,
    )
    .map_err(EntrypointReturnDecodeError::into_nested_vm_error)?;
    if node != schema.nodes.len()
        || cursor.word_index != words
        || construction.atoms.len() != quote.atoms
        || construction.atoms.capacity() != quote.atoms
    {
        return Err(VMError::ExecutionDeferred(
            crate::error::ExecutionDeferral::LocalInvariantViolation,
        ));
    }
    let record = EntrypointReturnRecordV1 {
        schema_hash: hash,
        atoms: construction.atoms,
    };
    if norito::canonical_frame_len(&record).map_err(|_| VMError::DecodeError)?
        > MAX_ENTRYPOINT_RETURN_RECORD_BYTES
    {
        drop(record);
        return Err(VMError::DecodeError);
    }
    let charges = construction
        .budget
        .charges
        .take()
        .expect("original funded capture ledger");
    if charges.as_slice().len() != ledger_count {
        drop(record);
        drop(charges);
        return Err(VMError::ExecutionDeferred(
            crate::error::ExecutionDeferral::LocalInvariantViolation,
        ));
    }
    Ok(CapturedValueRecord { record, charges })
}

/// Capture one live public value with the same collector used for completed returns.
///
/// # Errors
/// Rejects malformed/private values and oversize records. Callers must quote and
/// prepay their gas and retained backing before invoking this materialization step.
pub fn capture_value_record(
    vm: &IVM,
    schema: &EntrypointValueTypeV1,
    base: u64,
    words: usize,
) -> Result<EntrypointReturnRecordV1, VMError> {
    table(vm, schema, base, words)?;
    let quote = quote_value_record(vm, schema, base, words, u64::MAX)?;
    let mut atoms = Vec::new();
    atoms.try_reserve_exact(quote.atoms).map_err(|_| {
        VMError::ExecutionDeferred(crate::error::ExecutionDeferral::AllocationUnavailable)
    })?;
    let mut budget = ReturnRecordBudget::default();
    let mut cursor = ResultTableCursor {
        vm,
        live_base: Some(base),
        word_index: 0,
        budget: &mut budget,
    };
    let mut node = 0;
    collect_node(&schema.nodes, &mut node, &mut cursor, &mut atoms)
        .map_err(EntrypointReturnDecodeError::into_nested_vm_error)?;
    if node != schema.nodes.len() || cursor.word_index != words || atoms.len() != quote.atoms {
        return Err(VMError::DecodeError);
    }
    let record = EntrypointReturnRecordV1 {
        schema_hash: schema_hash(schema)
            .map_err(EntrypointReturnDecodeError::into_nested_vm_error)?,
        atoms,
    };
    let bytes = norito::canonical_frame_len(&record).map_err(|_| VMError::DecodeError)?;
    if bytes > MAX_ENTRYPOINT_RETURN_RECORD_BYTES {
        return Err(VMError::DecodeError);
    }
    Ok(record)
}

/// Capture a typed test or nested-call argument table using the canonical value collector.
///
/// # Errors
/// Rejects schema/table mismatches, private or malformed values, and allocation refusals.
pub fn capture_argument_record(
    vm: &IVM,
    schema: &EntrypointArgumentSchemaV1,
    base: u64,
    words: usize,
) -> Result<EntrypointArgumentRecordV1, VMError> {
    if !schema.validate() || schema.word_count() != Some(words) {
        return Err(VMError::DecodeError);
    }
    let mut atoms = Vec::new();
    let mut offset = 0_usize;
    for field in &schema.fields {
        let count = field.ty.word_count().ok_or(VMError::DecodeError)?;
        let address = base
            .checked_add((offset as u64).checked_mul(8).ok_or(VMError::DecodeError)?)
            .ok_or(VMError::DecodeError)?;
        let record = capture_value_record(vm, &field.ty, address, count)?;
        atoms.try_reserve(record.atoms.len()).map_err(|_| {
            VMError::ExecutionDeferred(crate::error::ExecutionDeferral::AllocationUnavailable)
        })?;
        atoms.extend(record.atoms);
        offset += count;
    }
    let schema_bytes = encode_canonical_norito(schema)?;
    Ok(EntrypointArgumentRecordV1 {
        schema_hash: entrypoint_argument_schema_hash_v1(&schema_bytes),
        atoms,
    })
}

/// Original captured argument atoms and their exact allocation custody.
/// The record graph is destroyed before its ledger on every exit path.
pub struct CapturedArgumentRecord {
    record: EntrypointArgumentRecordV1,
    charges: iroha_allocation::ChargedBuffer<iroha_allocation::AllocationCharge>,
}
impl CapturedArgumentRecord {
    pub(super) fn belongs_to(&self, budget: &iroha_allocation::AllocationBudget) -> bool {
        self.charges.belongs_to(budget)
            && self
                .charges
                .as_slice()
                .iter()
                .all(|charge| charge.belongs_to(budget))
    }
    /// Borrow the immutable schema-bound record while retaining its original credit.
    pub fn get(&self) -> &EntrypointArgumentRecordV1 {
        &self.record
    }
    /// Move every original allocation into another owner without copying.
    ///
    /// # Safety
    /// The recipient must keep the graph and ledger together and destroy the graph first.
    #[allow(unsafe_code)]
    pub unsafe fn into_allocation_parts(
        self,
    ) -> (
        EntrypointArgumentRecordV1,
        iroha_allocation::ChargedBuffer<iroha_allocation::AllocationCharge>,
    ) {
        (self.record, self.charges)
    }
}

pub(super) fn buffer_error(error: iroha_allocation::ChargedBufferError) -> VMError {
    match error {
        iroha_allocation::ChargedBufferError::Admission(reason) => {
            VMError::AllocationDeferred(reason)
        }
        iroha_allocation::ChargedBufferError::Allocator { .. } => {
            VMError::ExecutionDeferred(crate::ExecutionDeferral::AllocationUnavailable)
        }
    }
}

// Schema hashing owns its exact domain+frame scratch before writing any bytes.
// It shares the public hash domain and canonical serializer, without a second
// uncharged concatenation hidden inside the convenience hash helper.
pub(super) fn funded_schema_hash<T: norito::NoritoSerialize>(
    schema: &T,
    domain: &[u8],
    budget: &iroha_allocation::AllocationBudget,
) -> Result<[u8; 32], VMError> {
    let length = norito::canonical_frame_len(schema).map_err(|_| VMError::DecodeError)?;
    let total = length
        .checked_add(domain.len())
        .ok_or(VMError::DecodeError)?;
    let mut scratch =
        iroha_allocation::ChargedBuffer::<u8>::new(total, budget).map_err(buffer_error)?;
    for byte in domain {
        scratch.push_reserved(*byte);
    }
    for _ in 0..length {
        scratch.push_reserved(0);
    }
    let mut writer = std::io::Cursor::new(&mut scratch.as_mut_slice()[domain.len()..]);
    norito::core::write_canonical_to_writer(schema, &mut writer)
        .map_err(|_| VMError::DecodeError)?;
    if writer.position() != length as u64 {
        return Err(VMError::DecodeError);
    }
    Ok(iroha_crypto::Hash::new(scratch.as_slice()).into())
}

// Quoting reads bounded guest structures before capture. Every failed path
// retains the work already visited; nested argument fields add their prior work.
// Local refusal carries no gas and remains an original-owner deferral.
fn meter_quote_error(gas: u64, limit: u64, error: VMError) -> VMError {
    let (nested, error) = error.split_metered();
    VMError::metered(gas.saturating_add(nested.unwrap_or(0)).min(limit), error)
}

/// Quote every declared argument field before retaining or copying any payload.
///
/// # Errors
/// Rejects noncanonical tables, invalid schemas, excessive records or unaffordable work.
pub fn quote_argument_record(
    vm: &IVM,
    schema: &EntrypointArgumentSchemaV1,
    base: u64,
    words: usize,
    gas_limit: u64,
) -> Result<ValueRecordCaptureQuote, VMError> {
    let mut quote = ValueRecordCaptureQuote {
        gas: 32,
        retained_bytes: 0,
        atoms: 0,
        pointers: 0,
        pointer_bytes: 0,
    };
    if quote.gas > gas_limit {
        return Err(VMError::metered(gas_limit, VMError::OutOfGas));
    }
    let result = (|| {
        if !schema.validate() || schema.word_count() != Some(words) || !base.is_multiple_of(8) {
            return Err(VMError::DecodeError);
        }
        let bytes = (words as u64).checked_mul(8).ok_or(VMError::DecodeError)?;
        vm.ensure_owned_heap_range(base, bytes)?;
        vm.ensure_public_memory(base, bytes)?;
        let mut offset = 0;
        for field in &schema.fields {
            let count = field.ty.word_count().ok_or(VMError::DecodeError)?;
            let next = quote_value_record(
                vm,
                &field.ty,
                base + (offset * 8) as u64,
                count,
                gas_limit.saturating_sub(quote.gas),
            )?;
            quote.gas = quote.gas.checked_add(next.gas).ok_or(VMError::OutOfGas)?;
            quote.atoms = quote
                .atoms
                .checked_add(next.atoms)
                .ok_or(VMError::DecodeError)?;
            quote.pointers = quote
                .pointers
                .checked_add(next.pointers)
                .ok_or(VMError::DecodeError)?;
            quote.pointer_bytes = quote
                .pointer_bytes
                .checked_add(next.pointer_bytes)
                .ok_or(VMError::DecodeError)?;
            offset += count;
        }
        quote.gas = quote
            .gas
            .checked_add(
                norito::canonical_frame_len(schema).map_err(|_| VMError::DecodeError)? as u64,
            )
            .ok_or(VMError::OutOfGas)?;
        quote.retained_bytes = quote
            .atoms
            .checked_mul(std::mem::size_of::<EntrypointValueAtomV1>())
            .and_then(|size| size.checked_add(quote.pointer_bytes))
            .ok_or(VMError::DecodeError)?;
        if quote.gas > gas_limit {
            return Err(VMError::OutOfGas);
        }
        if quote.pointer_bytes.saturating_add(quote.atoms) > MAX_ENTRYPOINT_RETURN_RECORD_BYTES {
            return Err(VMError::DecodeError);
        }
        Ok(quote)
    })();
    result.map_err(|error| meter_quote_error(quote.gas, gas_limit, error))
}

/// Capture the whole argument tape into one prepaid original allocation owner.
///
/// # Errors
/// Returns canonical boundary errors or the original local allocation deferral.
pub fn capture_argument_record_funded(
    vm: &IVM,
    schema: &EntrypointArgumentSchemaV1,
    base: u64,
    words: usize,
    budget: &iroha_allocation::AllocationBudget,
) -> Result<CapturedArgumentRecord, VMError> {
    use iroha_allocation::{AllocationCharge, ChargedBuffer};
    let quote = quote_argument_record(vm, schema, base, words, u64::MAX)?;
    let schema_hash = funded_schema_hash(
        schema,
        iroha_data_model::smart_contract::entrypoint::ENTRYPOINT_ARGUMENT_SCHEMA_HASH_DOMAIN_V1,
        budget,
    )?;
    let ledger_count = quote.pointers.checked_add(1).ok_or(VMError::DecodeError)?;
    let demand = std::alloc::Layout::array::<AllocationCharge>(ledger_count)
        .map_err(|_| VMError::DecodeError)?
        .size()
        .checked_add(
            std::alloc::Layout::array::<EntrypointValueAtomV1>(quote.atoms)
                .map_err(|_| VMError::DecodeError)?
                .size(),
        )
        .and_then(|size| size.checked_add(quote.pointer_bytes))
        .ok_or(VMError::DecodeError)?;
    let mut reservation = budget
        .try_reserve_bytes(demand)
        .map_err(VMError::AllocationDeferred)?;
    let mut charges =
        ChargedBuffer::from_reservation(ledger_count, &mut reservation).map_err(prepaid_error)?;
    let buffer =
        ChargedBuffer::<EntrypointValueAtomV1>::from_reservation(quote.atoms, &mut reservation)
            .map_err(prepaid_error)?;
    // SAFETY: the exact quoted backing is never grown and its original charge
    // remains in the graph's owner until destruction or an explicit custody move.
    #[allow(unsafe_code)]
    let (atoms, charge) = unsafe { buffer.into_allocation_parts() };
    charges.push_reserved(charge);
    struct Construction {
        atoms: Vec<EntrypointValueAtomV1>,
        budget: ReturnRecordBudget,
    }
    let mut construction = Construction {
        atoms,
        budget: ReturnRecordBudget {
            lower_bound_bytes: norito::core::Header::SIZE + 32,
            max_bytes: MAX_ENTRYPOINT_RETURN_RECORD_BYTES,
            reservation: Some(reservation),
            charges: Some(charges),
        },
    };
    let mut cursor = ResultTableCursor {
        vm,
        live_base: Some(base),
        word_index: 0,
        budget: &mut construction.budget,
    };
    for field in &schema.fields {
        let mut node = 0;
        collect_node(
            &field.ty.nodes,
            &mut node,
            &mut cursor,
            &mut construction.atoms,
        )
        .map_err(EntrypointReturnDecodeError::into_nested_vm_error)?;
        if node != field.ty.nodes.len() {
            return Err(VMError::DecodeError);
        }
    }
    if cursor.word_index != words || construction.atoms.len() != quote.atoms {
        return Err(VMError::DecodeError);
    }
    let record = EntrypointArgumentRecordV1 {
        schema_hash,
        atoms: construction.atoms,
    };
    if norito::canonical_frame_len(&record).map_err(|_| VMError::DecodeError)?
        > MAX_ENTRYPOINT_RETURN_RECORD_BYTES
    {
        drop(record);
        return Err(VMError::DecodeError);
    }
    let charges = construction
        .budget
        .charges
        .take()
        .expect("original captured argument ledger");
    Ok(CapturedArgumentRecord { record, charges })
}

/// Quote an authenticated completed return before copying its atom or TLV backing.
///
/// # Errors
/// Rejects unfinished, private, malformed or unaffordable completed return tables.
pub fn quote_completed_return_record(
    vm: &IVM,
    schema: &EntrypointValueTypeV1,
    gas_limit: u64,
) -> Result<ValueRecordCaptureQuote, VMError> {
    let mut gas = 32_u64;
    if gas > gas_limit {
        return Err(VMError::metered(gas_limit, VMError::OutOfGas));
    }
    let result = (|| {
        let words = vm.call_result_word_count()?;
        if schema.word_count() != Some(words) || words == 0 {
            return Err(VMError::DecodeError);
        }
        let base = vm.memory.call_frames.completed_result_word(0)?;
        for index in 0..words {
            gas = gas.saturating_add(8);
            if gas > gas_limit {
                return Err(VMError::OutOfGas);
            }
            vm.public_call_result_word(index)?;
        }
        let mut quote = quote_value_record(vm, schema, base, words, gas_limit.saturating_sub(gas))?;
        quote.gas = quote.gas.saturating_add(gas);
        Ok(quote)
    })();
    result.map_err(|error| meter_quote_error(gas, gas_limit, error))
}

/// Capture only an interpreter-authenticated completed public return table.
///
/// # Errors
/// Rejects unfinished or wrong-width returns, malformed values and allocation refusals.
pub fn capture_completed_return_funded(
    vm: &IVM,
    schema: &EntrypointValueTypeV1,
    budget: &iroha_allocation::AllocationBudget,
) -> Result<CapturedValueRecord, VMError> {
    let words = vm.call_result_word_count()?;
    if schema.word_count() != Some(words) || words == 0 {
        return Err(VMError::DecodeError);
    }
    let base = vm.memory.call_frames.completed_result_word(0)?;
    // Every slot is checked against interpreter-owned completion and privacy,
    // rather than trusting guest x10/x11 after the root has returned.
    for index in 0..words {
        vm.public_call_result_word(index)?;
    }
    capture_value_record_funded(vm, schema, base, words, budget)
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_data_model::smart_contract::entrypoint::EntrypointStructTypeNodeV1;

    #[test]
    fn live_capture_accepts_empty_struct_and_rejects_nonzero_unit() {
        let schema = EntrypointValueTypeV1 {
            nodes: vec![EntrypointValueTypeNodeV1::Struct(
                EntrypointStructTypeNodeV1 {
                    name: "Fixture::Accepted".to_owned(),
                    fields: Vec::new(),
                },
            )],
        };
        let mut vm = IVM::new(100_000);
        let base = vm.alloc_heap(8).unwrap();
        vm.store_u64(base, 0).unwrap();
        let quote = quote_value_record(&vm, &schema, base, 1, u64::MAX).unwrap();
        assert_eq!(quote.atoms, 0);
        let record = capture_value_record(&vm, &schema, base, 1).unwrap();
        assert!(record.atoms.is_empty());
        assert_eq!(
            render_entrypoint_return_record(&schema, &record).unwrap(),
            norito::json!({})
        );
        assert!(matches!(
            quote_value_record(&vm, &schema, base, 1, quote.gas - 1),
            Err(error) if error.as_unmetered() == &VMError::OutOfGas
        ));
        vm.store_u64(base, 1).unwrap();
        assert!(capture_value_record(&vm, &schema, base, 1).is_err());
    }

    #[test]
    fn live_capture_preserves_exact_pointer_bytes_and_schema_binding() {
        let schema = EntrypointValueTypeV1 {
            nodes: vec![EntrypointValueTypeNodeV1::Leaf(
                EntrypointValueKindV1::String,
            )],
        };
        let mut vm = IVM::new(100_000);
        let envelope =
            crate::pointer_abi::encode_tlv(PointerType::Blob, "hello".as_bytes()).unwrap();
        let pointer = vm.alloc_host_tlv(&envelope).unwrap();
        let base = vm.alloc_heap(8).unwrap();
        vm.store_u64(base, pointer).unwrap();
        let quote = quote_value_record(&vm, &schema, base, 1, u64::MAX).unwrap();
        assert_eq!(quote.atoms, 1);
        assert!(quote.retained_bytes >= envelope.len());
        let record = capture_value_record(&vm, &schema, base, 1).unwrap();
        assert_eq!(record.atoms, vec![EntrypointValueAtomV1::Pointer(envelope)]);
        assert_eq!(
            render_entrypoint_return_record(&schema, &record).unwrap(),
            Value::String("hello".to_owned())
        );
        assert!(capture_value_record(&vm, &schema, base, 2).is_err());
    }

    #[test]
    fn funded_capture_retains_original_pool_until_record_destruction() {
        let schema = EntrypointValueTypeV1 {
            nodes: vec![EntrypointValueTypeNodeV1::Leaf(
                EntrypointValueKindV1::String,
            )],
        };
        let mut vm = IVM::new(100_000);
        let envelope = crate::pointer_abi::encode_tlv(PointerType::Blob, b"owned").unwrap();
        let pointer = vm.alloc_host_tlv(&envelope).unwrap();
        let base = vm.alloc_heap(8).unwrap();
        vm.store_u64(base, pointer).unwrap();
        let budget = iroha_allocation::AllocationBudget::new(1024 * 1024);
        let owned = capture_value_record_funded(&vm, &schema, base, 1, &budget).unwrap();
        assert_eq!(
            owned.get().atoms,
            vec![EntrypointValueAtomV1::Pointer(envelope)]
        );
        let retained = budget.reserved_bytes();
        assert!(retained > 0);
        budget.set_limit_bytes(retained);
        assert!(matches!(
            capture_value_record_funded(&vm, &schema, base, 1, &budget),
            Err(VMError::AllocationDeferred(_))
        ));
        assert_eq!(budget.reserved_bytes(), retained);
        drop(owned);
        assert_eq!(budget.reserved_bytes(), 0);
    }
    #[test]
    fn failed_value_and_argument_quotes_charge_the_actual_visited_work() {
        use iroha_data_model::smart_contract::entrypoint::EntrypointArgumentFieldV1;
        let schema = EntrypointValueTypeV1 {
            nodes: vec![
                EntrypointValueTypeNodeV1::Option,
                EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Bool),
            ],
        };
        let mut vm = IVM::new(100_000);
        let base = vm.alloc_heap(16).unwrap();
        // An invalid, misaligned sum pointer is discovered only after visiting
        // its public table word. The exact prefix work must survive rejection.
        vm.store_u64(base, 1).unwrap();
        vm.store_u64(base + 8, 1).unwrap();
        let schema_bytes = norito::canonical_frame_len(&schema).unwrap() as u64;
        let failure = quote_value_record(&vm, &schema, base, 1, u64::MAX).unwrap_err();
        assert_eq!(failure.as_unmetered(), &VMError::DecodeError);
        assert_eq!(failure.metered_gas(), Some(64 + schema_bytes));
        let limited = quote_value_record(&vm, &schema, base, 1, 33).unwrap_err();
        assert_eq!(limited.as_unmetered(), &VMError::OutOfGas);
        assert_eq!(limited.metered_gas(), Some(33));
        let first = EntrypointValueTypeV1 {
            nodes: vec![EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Bool)],
        };
        let first_gas = quote_value_record(&vm, &first, base, 1, u64::MAX)
            .unwrap()
            .gas;
        let arguments = EntrypointArgumentSchemaV1 {
            fields: vec![
                EntrypointArgumentFieldV1 {
                    name: "ready".into(),
                    ty: first,
                },
                EntrypointArgumentFieldV1 {
                    name: "value".into(),
                    ty: schema,
                },
            ],
        };
        let failure = quote_argument_record(&vm, &arguments, base, 2, u64::MAX).unwrap_err();
        assert_eq!(failure.as_unmetered(), &VMError::DecodeError);
        assert_eq!(
            failure.metered_gas(),
            Some(32 + first_gas + 64 + schema_bytes)
        );
    }

    #[test]
    fn quote_metering_preserves_local_refusal_without_a_gas_wrapper() {
        let error = VMError::ExecutionDeferred(crate::ExecutionDeferral::AllocationUnavailable);
        let actual = meter_quote_error(77, 100, error.clone());
        assert_eq!(actual, error);
        assert_eq!(actual.metered_gas(), None);
    }
}
