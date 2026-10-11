//! Funded, schema-bound table materialization for production nested calls.

use super::{capture::*, *};
use crate::VMError;
use iroha_allocation::{AllocationBudget, ChargedBuffer};
use iroha_data_model::smart_contract::entrypoint::{
    ENTRYPOINT_ARGUMENT_SCHEMA_HASH_DOMAIN_V1, ENTRYPOINT_RETURN_SCHEMA_HASH_DOMAIN_V1,
    EntrypointArgumentSchemaV1, MAX_ENTRYPOINT_ARGUMENT_TYPE_NODES,
};

enum Effect<'a> {
    Scalar {
        destination: u64,
        value: u64,
    },
    Pointer {
        destination: u64,
        atom: usize,
        envelope: &'a [u8],
    },
    Sum {
        destination: u64,
        layout: SumLayoutV1,
        tag: bool,
    },
    List {
        destination: u64,
        layout: ListLayoutV1,
        count: u8,
    },
}
#[derive(Clone, Copy, Default)]
struct Visit {
    node: usize,
    destination: u64,
    repeat: u16,
    stride: u64,
}

fn widths(
    schema: &EntrypointValueTypeV1,
) -> Result<[usize; MAX_ENTRYPOINT_ARGUMENT_TYPE_NODES], VMError> {
    if !schema.validate() {
        return Err(VMError::DecodeError);
    }
    let mut widths = [0usize; MAX_ENTRYPOINT_ARGUMENT_TYPE_NODES];
    for node in (0..schema.nodes.len()).rev() {
        widths[node] = match &schema.nodes[node] {
            EntrypointValueTypeNodeV1::Struct(_) | EntrypointValueTypeNodeV1::Tuple(_) => {
                let mut child = node + 1;
                let mut width = 0usize;
                for _ in 0..return_node_child_count(&schema.nodes[node]) {
                    width = width
                        .checked_add(widths[child])
                        .ok_or(VMError::DecodeError)?;
                    child = entrypoint_value_subtree_range_v1(&schema.nodes, child)
                        .ok_or(VMError::DecodeError)?
                        .end;
                }
                width.max(1)
            }
            _ => 1,
        };
    }
    Ok(widths)
}

// The one bounded traversal serves preflight and materialization. Products do
// not own scratch vectors; a list uses one continuation regardless of capacity.
fn walk<'a>(
    schema: &EntrypointValueTypeV1,
    atoms: &'a [EntrypointValueAtomV1],
    atom_index: &mut usize,
    destination: u64,
    mut effect: impl FnMut(Effect<'a>) -> Result<u64, VMError>,
) -> Result<u64, VMError> {
    use EntrypointValueAtomV1 as Atom;
    use EntrypointValueTypeNodeV1 as Node;
    let widths = widths(schema)?;
    let mut stack = [Visit::default(); MAX_ENTRYPOINT_ARGUMENT_TYPE_NODES * 2];
    stack[0] = Visit {
        node: 0,
        destination,
        repeat: 1,
        stride: 0,
    };
    let mut len = 1usize;
    let mut visited = 0u64;
    while len != 0 {
        len -= 1;
        let task = stack[len];
        visited = visited.checked_add(1).ok_or(VMError::OutOfGas)?;
        let mut push = |task: Visit| -> Result<(), VMError> {
            *stack.get_mut(len).ok_or(VMError::DecodeError)? = task;
            len += 1;
            Ok(())
        };
        if task.repeat > 1 {
            push(Visit {
                destination: task
                    .destination
                    .checked_add(task.stride)
                    .ok_or(VMError::DecodeError)?,
                repeat: task.repeat - 1,
                ..task
            })?;
        }
        let node = &schema.nodes[task.node];
        if matches!(node, Node::Struct(_) | Node::Tuple(_)) {
            let count = return_node_child_count(node);
            if count == 0 {
                effect(Effect::Scalar {
                    destination: task.destination,
                    value: 0,
                })?;
                continue;
            }
            let mut children = [Visit::default(); MAX_ENTRYPOINT_ARGUMENT_TYPE_NODES];
            let mut child = task.node + 1;
            let mut destination = task.destination;
            for slot in children.iter_mut().take(count) {
                *slot = Visit {
                    node: child,
                    destination,
                    repeat: 1,
                    stride: 0,
                };
                destination = destination
                    .checked_add(
                        (widths[child] as u64)
                            .checked_mul(8)
                            .ok_or(VMError::DecodeError)?,
                    )
                    .ok_or(VMError::DecodeError)?;
                child = entrypoint_value_subtree_range_v1(&schema.nodes, child)
                    .ok_or(VMError::DecodeError)?
                    .end;
            }
            for child in children[..count].iter().rev() {
                push(*child)?;
            }
            continue;
        }
        let atom_number = *atom_index;
        let atom = atoms.get(atom_number).ok_or(VMError::DecodeError)?;
        *atom_index += 1;
        match (node, atom) {
            (Node::Option | Node::Result, Atom::Tag(tag)) => {
                let first = task.node + 1;
                let second = entrypoint_value_subtree_range_v1(&schema.nodes, first)
                    .ok_or(VMError::DecodeError)?
                    .end;
                let option = matches!(node, Node::Option);
                let layout = if option {
                    SumLayoutV1::option(widths[first] as u64)
                } else {
                    SumLayoutV1::try_new(widths[second] as u64, widths[first] as u64)
                }
                .map_err(|_| VMError::DecodeError)?;
                let base = effect(Effect::Sum {
                    destination: task.destination,
                    layout,
                    tag: *tag,
                })?;
                if *tag || !option {
                    push(Visit {
                        node: if *tag { first } else { second },
                        destination: base.checked_add(8).ok_or(VMError::DecodeError)?,
                        repeat: 1,
                        stride: 0,
                    })?;
                }
            }
            (Node::List(node), Atom::List(count)) if *count <= node.capacity => {
                let child = task.node + 1;
                let layout = ListLayoutV1::try_new(u64::from(node.capacity), widths[child] as u64)
                    .map_err(|_| VMError::DecodeError)?;
                let base = effect(Effect::List {
                    destination: task.destination,
                    layout,
                    count: *count,
                })?;
                if *count != 0 {
                    push(Visit {
                        node: child,
                        destination: base
                            .checked_add(layout.slot_offset(0).map_err(|_| VMError::DecodeError)?)
                            .ok_or(VMError::DecodeError)?,
                        repeat: u16::from(*count),
                        stride: (widths[child] * 8) as u64,
                    })?;
                }
            }
            (Node::Leaf(EntrypointValueKindV1::Bool), Atom::Bool(value)) => {
                effect(Effect::Scalar {
                    destination: task.destination,
                    value: u64::from(*value),
                })?;
            }
            (Node::Unit, Atom::Unit) => {
                effect(Effect::Scalar {
                    destination: task.destination,
                    value: 0,
                })?;
            }
            (Node::Error(descriptor), Atom::ErrorCode(value))
                if descriptor
                    .variants
                    .iter()
                    .any(|variant| variant.code == *value) =>
            {
                effect(Effect::Scalar {
                    destination: task.destination,
                    value: u64::from(*value),
                })?;
            }
            (Node::Enum(descriptor), Atom::EnumCode(value))
                if descriptor
                    .variants
                    .iter()
                    .any(|variant| variant.code == *value) =>
            {
                effect(Effect::Scalar {
                    destination: task.destination,
                    value: u64::from(*value),
                })?;
            }
            (Node::Leaf(kind), Atom::Pointer(envelope)) => {
                let tlv = crate::pointer_abi::validate_tlv_bytes(envelope)?;
                if expected_pointer_type(*kind) != Some(tlv.type_id) {
                    return Err(VMError::DecodeError);
                }
                effect(Effect::Pointer {
                    destination: task.destination,
                    atom: atom_number,
                    envelope,
                })?;
            }
            (Node::StateCursor(kind), Atom::Pointer(envelope)) => {
                crate::state_cursor::validate_cursor_envelope(
                    iroha_data_model::smart_contract::entrypoint::state_key_schema_hash_v1(kind)
                        .ok_or(VMError::DecodeError)?,
                    envelope,
                )?;
                effect(Effect::Pointer {
                    destination: task.destination,
                    atom: atom_number,
                    envelope,
                })?;
            }
            _ => return Err(VMError::DecodeError),
        }
    }
    Ok(visited)
}

#[derive(Default)]
struct Quote {
    raw_heap: u64,
    pointer_bytes: u64,
    pointers: usize,
    nodes: u64,
}
impl Quote {
    fn effect(&mut self, effect: Effect<'_>) -> Result<u64, VMError> {
        let bytes = match effect {
            Effect::Sum { layout, .. } => layout
                .allocation_bytes()
                .map_err(|_| VMError::DecodeError)?,
            Effect::List { layout, .. } => layout
                .allocation_bytes()
                .map_err(|_| VMError::DecodeError)?,
            Effect::Pointer { envelope, .. } => {
                self.pointers += 1;
                self.pointer_bytes = self
                    .pointer_bytes
                    .checked_add(envelope.len() as u64)
                    .ok_or(VMError::OutOfGas)?;
                0
            }
            Effect::Scalar { .. } => 0,
        };
        self.raw_heap = self.raw_heap.checked_add(bytes).ok_or(VMError::OutOfGas)?;
        Ok(0)
    }
    fn gas(&self) -> Result<u64, VMError> {
        self.nodes
            .checked_mul(32)
            .and_then(|gas| gas.checked_add(32))
            .and_then(|gas| gas.checked_add(self.raw_heap))
            .and_then(|gas| gas.checked_add(self.pointer_bytes))
            .ok_or(VMError::OutOfGas)
    }
}
enum Meter {
    Debit,
    Escrow(u64),
}
struct Materializer {
    pointers: ChargedBuffer<u64>,
}
impl Materializer {
    fn prepare(
        vm: &mut IVM,
        atoms: &[EntrypointValueAtomV1],
        quote: &Quote,
        budget: &AllocationBudget,
        meter: Meter,
    ) -> Result<Self, VMError> {
        let gas = quote.gas()?;
        if gas
            > match meter {
                Meter::Debit => vm.gas_remaining,
                Meter::Escrow(available) => available,
            }
        {
            return Err(VMError::OutOfGas);
        }
        // Both scratch backings are funded before a TLV body or guest heap is copied.
        let mut lengths =
            ChargedBuffer::<usize>::new(quote.pointers, budget).map_err(buffer_error)?;
        let mut pointers = ChargedBuffer::<u64>::new(atoms.len(), budget).map_err(buffer_error)?;
        for atom in atoms {
            pointers.push_reserved(0);
            if let EntrypointValueAtomV1::Pointer(envelope) = atom {
                lengths.push_reserved(envelope.len());
            }
        }
        vm.preflight_host_tlv_allocations_with_reserved_heap(lengths.as_slice(), quote.raw_heap)?;
        if matches!(meter, Meter::Debit) {
            vm.debit_gas(gas)?;
        }
        for (index, atom) in atoms.iter().enumerate() {
            if let EntrypointValueAtomV1::Pointer(envelope) = atom {
                pointers.as_mut_slice()[index] = vm.alloc_host_tlv(envelope)?;
            }
        }
        Ok(Self { pointers })
    }
    fn effect(&self, vm: &mut IVM, effect: Effect<'_>) -> Result<u64, VMError> {
        let (destination, value) = match effect {
            Effect::Scalar { destination, value } => (destination, value),
            Effect::Pointer {
                destination, atom, ..
            } => (
                destination,
                *self
                    .pointers
                    .as_slice()
                    .get(atom)
                    .ok_or(VMError::DecodeError)?,
            ),
            Effect::Sum {
                destination,
                layout,
                tag,
            } => {
                let base = vm.alloc_heap(
                    layout
                        .allocation_bytes()
                        .map_err(|_| VMError::DecodeError)?,
                )?;
                vm.store_u64(base, u64::from(tag))?;
                (destination, base)
            }
            Effect::List {
                destination,
                layout,
                count,
            } => {
                let base = vm.alloc_heap(
                    layout
                        .allocation_bytes()
                        .map_err(|_| VMError::DecodeError)?,
                )?;
                vm.store_u64(base, u64::from(count))?;
                vm.store_u64(base + 8, u64::from(layout.capacity()))?;
                (destination, base)
            }
        };
        vm.store_u64(destination, value)?;
        Ok(value)
    }
}

/// Materialize captured input directly into an authenticated child's root tables.
///
/// The exact selected entrypoint/schema is checked before mutation. Gas is debited
/// once before payload copies; an opaque interpreter marker consumes these tables
/// once, without public-input transport, decoding, or another preparation charge.
///
/// # Errors
/// Rejects schema/entrypoint mismatches, unaffordable gas, guest capacity and local allocation refusals.
pub fn install_captured_arguments(
    record: &CapturedArgumentRecord,
    schema: &EntrypointArgumentSchemaV1,
    vm: &mut IVM,
    result_words: usize,
    budget: &AllocationBudget,
) -> Result<(), VMError> {
    vm.validate_captured_root_schema(Some(schema), result_words)?;
    if !record.belongs_to(budget) {
        return Err(VMError::ExecutionDeferred(
            crate::ExecutionDeferral::LocalInvariantViolation,
        ));
    }
    let record = record.get();
    if record.schema_hash
        != funded_schema_hash(schema, ENTRYPOINT_ARGUMENT_SCHEMA_HASH_DOMAIN_V1, budget)?
    {
        return Err(VMError::DecodeError);
    }
    let words = schema.word_count().ok_or(VMError::DecodeError)?;
    let mut quote = Quote {
        raw_heap: ((words + result_words) * 8) as u64,
        ..Quote::default()
    };
    let mut atom = 0;
    for field in &schema.fields {
        quote.nodes += walk(&field.ty, &record.atoms, &mut atom, 0, |effect| {
            quote.effect(effect)
        })?;
    }
    if atom != record.atoms.len() {
        return Err(VMError::DecodeError);
    }
    let materializer = Materializer::prepare(vm, &record.atoms, &quote, budget, Meter::Debit)?;
    let arguments = vm.alloc_heap((words * 8) as u64)?;
    let results = vm.alloc_heap((result_words * 8) as u64)?;
    let mut atom = 0;
    let mut destination = arguments;
    for field in &schema.fields {
        walk(&field.ty, &record.atoms, &mut atom, destination, |effect| {
            materializer.effect(vm, effect)
        })?;
        destination += (field.ty.word_count().ok_or(VMError::DecodeError)? * 8) as u64;
    }
    vm.retain_captured_root_tables(arguments, words, results, result_words)
}

/// Prepare the exact authenticated zero-argument child without a synthetic record.
///
/// # Errors
/// Rejects nonempty schemas, duplicate preparation, unaffordable gas and guest memory refusal.
pub fn install_empty_captured_arguments(vm: &mut IVM, result_words: usize) -> Result<(), VMError> {
    vm.validate_captured_root_schema(None, result_words)?;
    let bytes = (result_words * 8) as u64;
    vm.preflight_host_tlv_allocations_with_reserved_heap(&[], bytes)?;
    vm.debit_gas(32u64.checked_add(bytes).ok_or(VMError::OutOfGas)?)?;
    let results = vm.alloc_heap(bytes)?;
    vm.retain_captured_root_tables(0, 0, results, result_words)
}

/// Copy one immutable captured return into a caller's exact public result table.
///
/// All schema, arity, destination range and capacity checks precede the first
/// guest payload copy. The caller publishes child effects only after success.
///
/// # Errors
/// Rejects mismatched records, invalid destinations, unaffordable gas and local resource refusals.
pub fn transfer_return_record_funded(
    record: &CapturedValueRecord,
    schema: &EntrypointValueTypeV1,
    destination: &mut IVM,
    result_table: u64,
    arity: usize,
    gas_limit: u64,
    budget: &AllocationBudget,
) -> Result<u64, VMError> {
    if !record.belongs_to(budget) {
        return Err(VMError::ExecutionDeferred(
            crate::ExecutionDeferral::LocalInvariantViolation,
        ));
    }
    let record = record.get();
    if schema.word_count() != Some(arity)
        || arity == 0
        || record.schema_hash
            != funded_schema_hash(schema, ENTRYPOINT_RETURN_SCHEMA_HASH_DOMAIN_V1, budget)?
    {
        return Err(VMError::DecodeError);
    }
    validate_return_destination(destination, result_table, arity)?;
    let mut quote = Quote::default();
    let mut atom = 0;
    quote.nodes = walk(schema, &record.atoms, &mut atom, result_table, |effect| {
        quote.effect(effect)
    })?;
    if atom != record.atoms.len() {
        return Err(VMError::DecodeError);
    }
    let materializer = Materializer::prepare(
        destination,
        &record.atoms,
        &quote,
        budget,
        Meter::Escrow(gas_limit),
    )?;
    let mut atom = 0;
    walk(schema, &record.atoms, &mut atom, result_table, |effect| {
        materializer.effect(destination, effect)
    })?;
    quote.gas()
}

/// Validate the caller's complete reserved result table before running a child.
///
/// # Errors
/// Rejects wrong widths, nonowned storage, private bytes, or unwritable ranges.
pub fn validate_return_destination(
    vm: &IVM,
    result_table: u64,
    arity: usize,
) -> Result<(), VMError> {
    if arity == 0 || arity > ivm_abi::call::MAX_CALL_WORDS_V1 || !result_table.is_multiple_of(8) {
        return Err(VMError::DecodeError);
    }
    let bytes = (arity * 8) as u64;
    let end = result_table
        .checked_add(bytes)
        .ok_or(VMError::DecodeError)?;
    let heap = result_table >= crate::Memory::HEAP_START
        && end <= crate::Memory::HEAP_START + vm.memory.heap_allocated_len();
    let stack =
        result_table >= crate::Memory::STACK_START && vm.memory.call_frames.entry_pc().is_ok();
    if !heap && !stack {
        return Err(VMError::DecodeError);
    }
    vm.memory
        .checked_region_bounds_for(result_table, bytes, crate::error::Perm::WRITE)?;
    vm.ensure_public_memory(result_table, bytes)
}
