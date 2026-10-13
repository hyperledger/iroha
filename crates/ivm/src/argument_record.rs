//! One-shot preparation and table materialization for public entrypoint calls.
//!
//! Torii, CLI, and SDK boundaries may accept ergonomic JSON, but they convert it before signing
//! into one schema-hashed canonical Norito record. Execution preparation decodes and validates that
//! complete record once against the authenticated callable schema. Before guest execution the
//! host materializes aligned, owned word tables in declaration order.
use crate::{
    VMError,
    host::quote_tlv_payload_len_at,
    ivm::IVM,
    pointer_abi::{self, PointerType, Tlv},
};
use iroha_crypto::Hash;
use iroha_data_model::{
    account::AccountId,
    prelude::{AssetDefinitionId, AssetId, NftId},
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::name::Name;
use iroha_model_base::topology::DataSpaceId;
#[cfg(test)]
use iroha_primitives::{bigint::BigInt, numeric::Quantity};
use iroha_primitives::{
    json::Json,
    numeric_abi::{DecimalValueV1, IntValueV1, QuantityValueV1},
};
#[cfg(test)]
use ivm_abi::arguments::{argument_record_from_json, encode_argument_record_from_json};
use ivm_abi::codec::decode_canonical_norito as decode_abi_canonical_norito;
use ivm_abi::entrypoint::{
    EntrypointArgumentRecordV1, EntrypointArgumentSchemaV1, EntrypointValueAtomV1,
    EntrypointValueKindV1, EntrypointValueTypeNodeV1, EntrypointValueTypeV1,
    EntrypointValueWordKindV1, MAX_ENTRYPOINT_ARGUMENT_RECORD_BYTES,
    MAX_ENTRYPOINT_ARGUMENT_SCHEMA_BYTES, MAX_ENTRYPOINT_ARGUMENT_TYPE_NODES,
    MAX_ENTRYPOINT_ARGUMENT_WORDS, MAX_ENTRYPOINT_ARGUMENTS, entrypoint_argument_schema_hash_v1,
};
use ivm_abi::entrypoint::{
    value_child_starts as argument_child_starts, value_subtree_end as argument_subtree_end,
};
use ivm_abi::list::ListLayoutV1;
use ivm_abi::pointer_abi::encode_tlv;
use ivm_abi::sum::SumLayoutV1;
use norito::NoritoSerialize;
#[cfg(test)]
use norito::json as njson;
#[cfg(test)]
use norito::{decode_from_bytes, to_bytes};
use std::{mem::size_of, sync::Arc};
const ARGUMENT_DECODE_GAS_BASE: u64 = 32;
const ARGUMENT_DECODE_GAS_PER_BYTE: u64 = 1;
const TLV_ENVELOPE_BYTES: usize = 7 + Hash::LENGTH;
#[cfg(any(test, debug_assertions))]
thread_local! {
    static RECORD_DECODE_COUNT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
/// Reset the thread-local canonical-record decode counter used by debug tests.
///
/// Release builds keep no counter and this function is a no-op.
#[doc(hidden)]
pub fn reset_argument_record_decode_count() {
    #[cfg(any(test, debug_assertions))]
    RECORD_DECODE_COUNT.with(|count| count.set(0));
}
/// Return the thread-local canonical-record decode count used by debug tests.
///
/// Release builds return zero and incur no decode-path instrumentation.
#[doc(hidden)]
#[must_use]
pub fn argument_record_decode_count() -> usize {
    #[cfg(any(test, debug_assertions))]
    {
        RECORD_DECODE_COUNT.with(std::cell::Cell::get)
    }
    #[cfg(not(any(test, debug_assertions)))]
    {
        0
    }
}
#[derive(Debug)]
enum DecodedArgument {
    Scalar(u64),
    Pointer(Vec<u8>),
    Sum {
        layout: SumLayoutV1,
        tag: u64,
        active: Vec<usize>,
    },
    List {
        layout: ListLayoutV1,
        elements: Vec<Vec<usize>>,
    },
}
#[derive(Debug)]
struct ArgumentDecodePlan {
    decoded: Vec<DecodedArgument>,
    roots: Vec<usize>,
    record_bytes: usize,
    schema_bytes: usize,
    materialized_bytes: u64,
}
impl ArgumentDecodePlan {
    fn gas(&self) -> u64 {
        argument_record_gas_for_bytes(
            self.record_bytes,
            self.schema_bytes,
            self.materialized_bytes,
        )
    }
    fn allocation_lengths(&self) -> Vec<usize> {
        let mut lengths = Vec::new();
        for value in &self.decoded {
            if let DecodedArgument::Pointer(envelope) = value {
                lengths.push(envelope.len());
            }
        }
        lengths
    }
    fn raw_heap_bytes(&self) -> u64 {
        self.decoded
            .iter()
            .map(|value| match value {
                DecodedArgument::Scalar(_) | DecodedArgument::Pointer(_) => 0,
                DecodedArgument::Sum { layout, .. } => {
                    layout.allocation_bytes().unwrap_or(u64::MAX)
                }
                DecodedArgument::List { layout, .. } => {
                    layout.allocation_bytes().unwrap_or(u64::MAX)
                }
            })
            .fold(
                decoded_table_bytes(self.roots.len()) as u64,
                u64::saturating_add,
            )
    }
}
struct PreparedArgumentRecordInner {
    canonical_record: Arc<[u8]>,
    canonical_schema: Arc<[u8]>,
    decode_plan: ArgumentDecodePlan,
}
/// A schema-validated public argument record ready for one IVM invocation.
///
/// The canonical signed bytes and their decoded ABI-word plan are immutable and
/// shared across host construction, access prepasses, and execution. Runtime
/// materialization only assigns VM-local pointers; it never decodes Norito.
#[derive(Clone)]
pub struct PreparedArgumentRecord {
    inner: Arc<PreparedArgumentRecordInner>,
}
impl core::fmt::Debug for PreparedArgumentRecord {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PreparedArgumentRecord")
            .field("record_bytes", &self.inner.canonical_record.len())
            .field("schema_bytes", &self.inner.canonical_schema.len())
            .field("abi_words", &self.inner.decode_plan.roots.len())
            .finish_non_exhaustive()
    }
}
impl PreparedArgumentRecord {
    /// Exact number of flattened argument slots in the authenticated schema.
    #[must_use]
    pub fn word_count(&self) -> usize {
        self.inner.decode_plan.roots.len()
    }
    /// Install the invocation's argument and result tables after exact gas prepayment.
    ///
    /// All pointer copies, active aggregate allocations, argument slots, and result slots are
    /// preflighted together before any allocation. The result reservation does not initialize
    /// result slots: runtime write coverage starts when the root callable is entered.
    ///
    /// # Errors
    ///
    /// Rejects invalid table counts, a missing or mismatched decode-gas prepayment, insufficient
    /// remaining gas, or insufficient owned memory for the complete invocation preparation.
    pub fn install_call_arguments(&self, vm: &mut IVM, result_words: usize) -> Result<(), VMError> {
        let result_bytes = result_table_bytes(result_words)?;
        vm.consume_prepaid_argument_decode(self.inner.decode_plan.gas())?;
        vm.debit_gas(
            result_bytes
                .checked_mul(crate::call_gas::PER_BYTE)
                .ok_or(VMError::OutOfGas)?,
        )?;
        let reserved_heap = self
            .inner
            .decode_plan
            .raw_heap_bytes()
            .checked_add(result_bytes)
            .ok_or(VMError::DecodeError)?;
        vm.preflight_host_tlv_allocations_with_reserved_heap(
            &self.inner.decode_plan.allocation_lengths(),
            reserved_heap,
        )?;
        materialize_decode_plan(vm, &self.inner.decode_plan)?;
        let result_base = vm.alloc_heap(result_bytes)?;
        vm.set_register(12, result_base);
        vm.set_register(13, result_words as u64);
        Ok(())
    }
    /// Return the unchanged canonical record bytes carried by the signed call.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.inner.canonical_record
    }
    /// Return the canonical compiler-emitted schema bytes bound to this record.
    #[must_use]
    pub fn schema_bytes(&self) -> &[u8] {
        &self.inner.canonical_schema
    }
    /// Return whether this plan is bound to the exact canonical record and schema.
    ///
    /// Schema framing is pinned to the V1 default Norito layout so an ambient
    /// decoder context cannot force a valid plan to be discarded or reused
    /// under different compiler-emitted schema bytes.
    ///
    /// # Errors
    ///
    /// Returns [`VMError::DecodeError`] if the trusted schema cannot be framed.
    #[doc(hidden)]
    pub fn is_bound_to(
        &self,
        schema: &EntrypointArgumentSchemaV1,
        canonical_record: &[u8],
    ) -> Result<bool, VMError> {
        if self.canonical_bytes() != canonical_record {
            return Ok(false);
        }
        let canonical_schema = canonical_norito_frame(schema).map_err(|_| VMError::DecodeError)?;
        Ok(self.schema_bytes() == canonical_schema)
    }
    /// Debit the complete deterministic decode/materialization cost before guest execution begins.
    ///
    /// This escrow is mandatory for prepared records: it prevents a hand-built
    /// artifact from avoiding argument preparation by ignoring its arguments.
    /// The interpreter consumes this prepayment before entering the root callable.
    ///
    /// # Errors
    ///
    /// Returns [`VMError::OutOfGas`] when the invocation cannot afford the prepared record, or
    /// [`VMError::DecodeError`] if the same VM is charged more than once.
    pub fn precharge_vm(&self, vm: &mut IVM) -> Result<(), VMError> {
        vm.prepay_argument_decode(self.inner.decode_plan.gas())
    }
}
/// Prepare the canonical `entrypoint_argument_record` public input from a host.
///
/// The firing-event JSON is a separate input and cannot substitute for this record.
///
/// The same metered public-input route is used by default and custom hosts, so root preparation
/// preserves their authorization, staged gas accounting, and canonical pointer validation.
///
/// # Errors
///
/// Returns the host's input error, an unaffordable preparation charge, or a canonical-record error
/// before any guest instruction executes.
pub(crate) fn prepare_default_call_arguments(
    host: &mut dyn crate::host::IVMHost,
    vm: &mut IVM,
    schema: &EntrypointArgumentSchemaV1,
    result_words: usize,
) -> Result<(), VMError> {
    // Default-root argument effects include a host syscall. Admit its one
    // detached logger before gas, allocation or descriptor writes.
    let prepared_log = vm.prepare_host_register_log()?;
    let name: Name = ivm_abi::arguments::ENTRYPOINT_ARGUMENT_RECORD_PUBLIC_INPUT_KEY
        .parse()
        .map_err(|_| VMError::DecodeError)?;
    let name_payload = canonical_norito_frame(&name).map_err(|_| VMError::DecodeError)?;
    let syscall = crate::syscalls::SYSCALL_GET_PUBLIC_INPUT;
    let instruction = crate::encoding::wide::encode_syscallx(syscall);
    vm.debit_gas(crate::gas::cost_of(instruction).ok_or(VMError::DecodeError)?)?;
    let name_pointer = vm.alloc_host_tlv(&encode_tlv(PointerType::Name, &name_payload)?)?;
    vm.set_register(10, name_pointer);
    vm.execute_syscall_with_register_log(host, syscall, Some(&prepared_log))?;
    let canonical_record = {
        let record = validate_tlv_any_region(vm, vm.register(10), PointerType::NoritoBytes)?;
        if record.payload.len() > MAX_ENTRYPOINT_ARGUMENT_RECORD_BYTES {
            return Err(VMError::DecodeError);
        }
        let bound = schema_materialization_bound(schema)?;
        let gas_bound = argument_record_gas_for_schema_bound(
            record.payload.len(),
            canonical_norito_frame_len(schema),
            bound,
        );
        if gas_bound > vm.gas_remaining {
            return Err(VMError::OutOfGas);
        }
        Arc::<[u8]>::from(record.payload)
    };
    let prepared =
        prepare_argument_record_with_gas_limit(schema, canonical_record, vm.gas_remaining)?;
    prepared.precharge_vm(vm)?;
    prepared.install_call_arguments(vm, result_words)
}
fn result_table_bytes(result_words: usize) -> Result<u64, VMError> {
    if !(1..=ivm_abi::call::MAX_CALL_WORDS_V1).contains(&result_words) {
        return Err(VMError::DecodeError);
    }
    Ok((result_words * ivm_abi::call::CALL_WORD_BYTES_V1) as u64)
}
/// Install canonical empty arguments and a bounded host-owned result reservation.
///
/// # Errors
///
/// Rejects invalid result counts, unaffordable allocation gas, or insufficient owned HEAP.
pub fn install_empty_call_arguments(vm: &mut IVM, result_words: usize) -> Result<(), VMError> {
    let bytes = result_table_bytes(result_words)?;
    vm.debit_gas(bytes)?;
    vm.preflight_host_tlv_allocations_with_reserved_heap(&[], bytes)?;
    let result_base = vm.alloc_heap(bytes)?;
    vm.set_register(10, 0);
    vm.set_register(11, 0);
    vm.set_register(12, result_base);
    vm.set_register(13, result_words as u64);
    Ok(())
}
fn argument_record_gas_for_bytes(
    record_bytes: usize,
    schema_bytes: usize,
    materialized_bytes: u64,
) -> u64 {
    let charged_bytes = u64::try_from(record_bytes)
        .unwrap_or(u64::MAX)
        .saturating_add(u64::try_from(schema_bytes).unwrap_or(u64::MAX))
        .saturating_add(materialized_bytes);
    ARGUMENT_DECODE_GAS_BASE
        .saturating_add(ARGUMENT_DECODE_GAS_PER_BYTE.saturating_mul(charged_bytes))
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct SchemaMaterializationBound {
    words: u64,
    pointer_envelopes: u64,
    raw_heap_bytes: u64,
}
impl SchemaMaterializationBound {
    const ZERO: Self = Self {
        words: 0,
        pointer_envelopes: 0,
        raw_heap_bytes: 0,
    };
}
fn max_schema_pointer_envelopes() -> u64 {
    u64::try_from(MAX_ENTRYPOINT_ARGUMENT_RECORD_BYTES / TLV_ENVELOPE_BYTES).unwrap_or(u64::MAX)
}
fn cap_pointer_envelopes(count: u64) -> u64 {
    count.min(max_schema_pointer_envelopes())
}
fn add_pointer_envelopes(lhs: u64, rhs: u64) -> u64 {
    cap_pointer_envelopes(lhs.saturating_add(rhs))
}
fn multiply_pointer_envelopes(count: u64, multiplier: u64) -> u64 {
    cap_pointer_envelopes(count.saturating_mul(multiplier))
}
fn cap_raw_heap_bytes(bytes: u64) -> u64 {
    bytes.min(crate::memory::Memory::HEAP_SIZE)
}
fn add_raw_heap_bytes(lhs: u64, rhs: u64) -> u64 {
    cap_raw_heap_bytes(lhs.saturating_add(rhs))
}
fn multiply_raw_heap_bytes(bytes: u64, count: u64) -> u64 {
    cap_raw_heap_bytes(bytes.saturating_mul(count))
}
fn aggregate_allocation_bytes(header_words: u64, payload_words: u64) -> u64 {
    cap_raw_heap_bytes(
        header_words
            .saturating_add(payload_words)
            .saturating_mul(u64::try_from(size_of::<u64>()).unwrap_or(u64::MAX)),
    )
}
/// Derive the largest materializable aggregate layout from one validated flat
/// preorder type tape without recursion or attacker-controlled allocation.
fn value_materialization_bound(
    ty: &EntrypointValueTypeV1,
) -> Result<SchemaMaterializationBound, VMError> {
    // The public schema validator enforces this same node bound. A fixed local
    // stack keeps quote construction allocation-free after validation.
    let mut rendered = [SchemaMaterializationBound::ZERO; MAX_ENTRYPOINT_ARGUMENT_TYPE_NODES];
    let mut rendered_len = 0_usize;
    for node in ty.nodes.iter().rev() {
        let child_count = argument_node_child_count(node);
        let children_start = rendered_len
            .checked_sub(child_count)
            .ok_or(VMError::DecodeError)?;
        let children = &rendered[children_start..rendered_len];
        let bound = match node {
            EntrypointValueTypeNodeV1::Unit
            | EntrypointValueTypeNodeV1::Error(_)
            | EntrypointValueTypeNodeV1::Enum(_) => SchemaMaterializationBound {
                words: 1,
                pointer_envelopes: 0,
                raw_heap_bytes: 0,
            },
            EntrypointValueTypeNodeV1::Struct(node) if node.fields.is_empty() => {
                SchemaMaterializationBound {
                    words: 1,
                    pointer_envelopes: 0,
                    raw_heap_bytes: 0,
                }
            }
            EntrypointValueTypeNodeV1::Struct(_) | EntrypointValueTypeNodeV1::Tuple(_) => children
                .iter()
                .fold(SchemaMaterializationBound::ZERO, |total, child| {
                    SchemaMaterializationBound {
                        words: total.words.saturating_add(child.words),
                        pointer_envelopes: add_pointer_envelopes(
                            total.pointer_envelopes,
                            child.pointer_envelopes,
                        ),
                        raw_heap_bytes: add_raw_heap_bytes(
                            total.raw_heap_bytes,
                            child.raw_heap_bytes,
                        ),
                    }
                }),
            EntrypointValueTypeNodeV1::Option => {
                let child = *children.first().ok_or(VMError::DecodeError)?;
                let own_allocation = aggregate_allocation_bytes(1, child.words);
                SchemaMaterializationBound {
                    words: 1,
                    pointer_envelopes: child.pointer_envelopes,
                    raw_heap_bytes: add_raw_heap_bytes(own_allocation, child.raw_heap_bytes),
                }
            }
            EntrypointValueTypeNodeV1::Result => {
                let first = *children.first().ok_or(VMError::DecodeError)?;
                let second = *children.get(1).ok_or(VMError::DecodeError)?;
                let own_allocation = aggregate_allocation_bytes(1, first.words.max(second.words));
                SchemaMaterializationBound {
                    words: 1,
                    pointer_envelopes: first.pointer_envelopes.max(second.pointer_envelopes),
                    raw_heap_bytes: add_raw_heap_bytes(
                        own_allocation,
                        first.raw_heap_bytes.max(second.raw_heap_bytes),
                    ),
                }
            }
            EntrypointValueTypeNodeV1::List(list) => {
                let element = *children.first().ok_or(VMError::DecodeError)?;
                let capacity = u64::from(list.capacity);
                let own_allocation =
                    aggregate_allocation_bytes(2, capacity.saturating_mul(element.words));
                SchemaMaterializationBound {
                    words: 1,
                    pointer_envelopes: multiply_pointer_envelopes(
                        element.pointer_envelopes,
                        capacity,
                    ),
                    raw_heap_bytes: add_raw_heap_bytes(
                        own_allocation,
                        multiply_raw_heap_bytes(element.raw_heap_bytes, capacity),
                    ),
                }
            }
            EntrypointValueTypeNodeV1::StateCursor(_) => SchemaMaterializationBound {
                words: 1,
                pointer_envelopes: 1,
                raw_heap_bytes: 0,
            },
            EntrypointValueTypeNodeV1::Leaf(kind) => SchemaMaterializationBound {
                words: 1,
                pointer_envelopes: u64::from(kind.is_pointer()),
                raw_heap_bytes: 0,
            },
        };
        rendered_len = children_start;
        let slot = rendered.get_mut(rendered_len).ok_or(VMError::DecodeError)?;
        *slot = bound;
        rendered_len = rendered_len.checked_add(1).ok_or(VMError::DecodeError)?;
    }
    if rendered_len != 1 {
        return Err(VMError::DecodeError);
    }
    Ok(rendered[0])
}
fn schema_materialization_bound(
    schema: &EntrypointArgumentSchemaV1,
) -> Result<SchemaMaterializationBound, VMError> {
    if !schema.validate() {
        return Err(VMError::DecodeError);
    }
    let bound =
        schema
            .fields
            .iter()
            .try_fold(SchemaMaterializationBound::ZERO, |total, field| {
                let field_bound = value_materialization_bound(&field.ty)?;
                Ok::<_, VMError>(SchemaMaterializationBound {
                    words: total.words.saturating_add(field_bound.words),
                    pointer_envelopes: add_pointer_envelopes(
                        total.pointer_envelopes,
                        field_bound.pointer_envelopes,
                    ),
                    raw_heap_bytes: add_raw_heap_bytes(
                        total.raw_heap_bytes,
                        field_bound.raw_heap_bytes,
                    ),
                })
            })?;
    if usize::try_from(bound.words).ok() != schema.word_count()
        || bound.words > u64::try_from(MAX_ENTRYPOINT_ARGUMENT_WORDS).unwrap_or(u64::MAX)
    {
        return Err(VMError::DecodeError);
    }
    Ok(bound)
}
fn argument_record_gas_for_schema_bound(
    record_bytes: usize,
    schema_bytes: usize,
    bound: SchemaMaterializationBound,
) -> u64 {
    argument_record_gas_for_bytes(
        record_bytes,
        schema_bytes,
        materialized_bytes_for_schema_bound(record_bytes, bound),
    )
}
fn aligned_allocation_bytes(length: usize) -> u64 {
    u64::try_from(length)
        .ok()
        .and_then(|length| length.checked_add(7))
        .map(|length| length & !7)
        .unwrap_or(u64::MAX)
}
fn pointer_copy_allocation_upper_bound(record_bytes: usize, pointer_envelopes: u64) -> u64 {
    let record_bytes_u64 = u64::try_from(record_bytes).unwrap_or(u64::MAX);
    let envelope_bytes = u64::try_from(TLV_ENVELOPE_BYTES).unwrap_or(u64::MAX);
    let record_pointer_limit = record_bytes_u64.checked_div(envelope_bytes).unwrap_or(0);
    record_bytes_u64.saturating_add(
        pointer_envelopes
            .min(record_pointer_limit)
            .saturating_mul(7),
    )
}
fn materialized_bytes_for_schema_bound(
    record_bytes: usize,
    bound: SchemaMaterializationBound,
) -> u64 {
    let word_count = usize::try_from(bound.words).unwrap_or(usize::MAX);
    pointer_copy_allocation_upper_bound(record_bytes, bound.pointer_envelopes)
        .saturating_add(aligned_allocation_bytes(decoded_table_bytes(word_count)))
        .saturating_add(bound.raw_heap_bytes)
}
fn argument_record_runtime_gas_upper_bound(record_bytes: usize, schema_bytes: usize) -> u64 {
    // Every pointer envelope is embedded in the record, so one additional
    // record-sized allowance bounds all VM copies before their shapes are
    // decoded. The raw syscall cannot authenticate or parse its schema until
    // after gas debit, so it deliberately retains the full-HEAP reserve.
    let materialized_bytes = pointer_copy_allocation_upper_bound(record_bytes, u64::MAX)
        .saturating_add(aligned_allocation_bytes(decoded_table_bytes(
            MAX_ENTRYPOINT_ARGUMENT_WORDS,
        )))
        .saturating_add(crate::memory::Memory::HEAP_SIZE);
    argument_record_gas_for_bytes(record_bytes, schema_bytes, materialized_bytes)
}
fn canonical_norito_frame_len<T: NoritoSerialize>(value: &T) -> usize {
    let _flags = norito::core::DecodeFlagsGuard::enter(norito::core::default_encode_flags());
    norito::core::encoded_frame_len(value).expect("trusted schema serialization must be infallible")
}
fn canonical_norito_frame<T: NoritoSerialize>(value: &T) -> Result<Vec<u8>, norito::core::Error> {
    norito::encode_canonical(value)
}
fn decoded_table_bytes(word_count: usize) -> usize {
    word_count.saturating_mul(size_of::<u64>())
}
fn validate_tlv_any_region(
    vm: &IVM,
    address: u64,
    expected: PointerType,
) -> Result<Tlv<'_>, VMError> {
    let tlv = vm.validate_tlv(address)?;
    if tlv.type_id != expected {
        return Err(VMError::NoritoInvalid);
    }
    Ok(tlv)
}
fn argument_node_child_count(node: &EntrypointValueTypeNodeV1) -> usize {
    match node {
        EntrypointValueTypeNodeV1::Struct(node) => node.fields.len(),
        EntrypointValueTypeNodeV1::Tuple(arity) => usize::from(*arity),
        EntrypointValueTypeNodeV1::Option | EntrypointValueTypeNodeV1::List(_) => 1,
        EntrypointValueTypeNodeV1::Result => 2,
        EntrypointValueTypeNodeV1::Leaf(_)
        | EntrypointValueTypeNodeV1::Unit
        | EntrypointValueTypeNodeV1::StateCursor(_)
        | EntrypointValueTypeNodeV1::Error(_)
        | EntrypointValueTypeNodeV1::Enum(_) => 0,
    }
}
fn argument_node_word_count(
    nodes: &[EntrypointValueTypeNodeV1],
    node_index: &mut usize,
) -> Result<usize, VMError> {
    #[derive(Clone, Copy)]
    struct Frame {
        remaining: usize,
        suppress_words: bool,
    }
    let start = *node_index;
    let end = argument_subtree_end(nodes, start)?;
    let mut frames = Vec::<Frame>::new();
    let mut words = 0_usize;
    for (offset, node) in nodes[start..end].iter().enumerate() {
        while frames.last().is_some_and(|frame| frame.remaining == 0) {
            frames.pop();
        }
        let suppress_words = if offset == 0 {
            false
        } else {
            let parent = frames.last_mut().ok_or(VMError::DecodeError)?;
            parent.remaining = parent
                .remaining
                .checked_sub(1)
                .ok_or(VMError::DecodeError)?;
            parent.suppress_words
        };
        let is_handle = matches!(
            node,
            EntrypointValueTypeNodeV1::Option
                | EntrypointValueTypeNodeV1::Result
                | EntrypointValueTypeNodeV1::List(_)
        );
        if !suppress_words
            && (is_handle
                || matches!(node, EntrypointValueTypeNodeV1::Struct(node) if node.fields.is_empty())
                || matches!(
                    node,
                    EntrypointValueTypeNodeV1::Leaf(_)
                        | EntrypointValueTypeNodeV1::Unit
                        | EntrypointValueTypeNodeV1::StateCursor(_)
                        | EntrypointValueTypeNodeV1::Error(_)
                        | EntrypointValueTypeNodeV1::Enum(_)
                ))
        {
            words = words.checked_add(1).ok_or(VMError::DecodeError)?;
        }
        let children = argument_node_child_count(node);
        if children != 0 {
            frames.push(Frame {
                remaining: children,
                suppress_words: suppress_words || is_handle,
            });
        }
    }
    while frames.last().is_some_and(|frame| frame.remaining == 0) {
        frames.pop();
    }
    if !frames.is_empty() {
        return Err(VMError::DecodeError);
    }
    *node_index = end;
    Ok(words)
}
// The canonical owner captures enclosing resource provenance before its
// decoder scopes unwind. Protocol limits and malformed frames stay DecodeError.
fn decode_argument_frame<T>(payload: &[u8]) -> Result<T, VMError>
where
    T: norito::NoritoSerialize,
    for<'de> T: norito::NoritoDeserialize<'de>,
{
    norito::decode_canonical_for_admission(payload, norito::canonical_decode_limits(payload.len()))
        .map_err(|error| match error.into_local_refusal() {
            Ok(original) => VMError::DecodeDeferred(original),
            Err(_) => VMError::DecodeError,
        })
}
fn decode_schema(payload: &[u8]) -> Result<EntrypointArgumentSchemaV1, VMError> {
    if payload.len() > MAX_ENTRYPOINT_ARGUMENT_SCHEMA_BYTES {
        return Err(VMError::DecodeError);
    }
    let schema: EntrypointArgumentSchemaV1 = decode_argument_frame(payload)?;
    if !schema.validate() || schema.fields.len() > MAX_ENTRYPOINT_ARGUMENTS {
        return Err(VMError::DecodeError);
    }
    Ok(schema)
}
fn decode_record(payload: &[u8]) -> Result<EntrypointArgumentRecordV1, VMError> {
    if payload.len() > MAX_ENTRYPOINT_ARGUMENT_RECORD_BYTES {
        return Err(VMError::DecodeError);
    }
    #[cfg(any(test, debug_assertions))]
    RECORD_DECODE_COUNT.with(|count| count.set(count.get().saturating_add(1)));
    decode_argument_frame(payload)
}
fn validate_argument_envelope_lengths(record: &Tlv<'_>, schema: &Tlv<'_>) -> Result<(), VMError> {
    validate_argument_envelope_payload_lengths(record.payload.len(), schema.payload.len())
}
fn validate_argument_envelope_payload_lengths(
    record_bytes: usize,
    schema_bytes: usize,
) -> Result<(), VMError> {
    if record_bytes > MAX_ENTRYPOINT_ARGUMENT_RECORD_BYTES
        || schema_bytes > MAX_ENTRYPOINT_ARGUMENT_SCHEMA_BYTES
    {
        return Err(VMError::NoritoInvalid);
    }
    Ok(())
}
fn quote_argument_envelope_lengths(vm: &IVM) -> Result<(usize, usize), VMError> {
    let record_bytes = quote_tlv_payload_len_at(vm, vm.register(10), PointerType::NoritoBytes)?;
    let schema_bytes = quote_tlv_payload_len_at(vm, vm.register(11), PointerType::NoritoBytes)?;
    validate_argument_envelope_payload_lengths(record_bytes, schema_bytes)?;
    Ok((record_bytes, schema_bytes))
}
fn expected_pointer_type(kind: EntrypointValueKindV1) -> Option<PointerType> {
    Some(match kind {
        EntrypointValueKindV1::Bool => return None,
        EntrypointValueKindV1::Int => PointerType::Int,
        EntrypointValueKindV1::Decimal => PointerType::Decimal,
        EntrypointValueKindV1::Quantity => PointerType::Quantity,
        EntrypointValueKindV1::String | EntrypointValueKindV1::Blob => PointerType::Blob,
        EntrypointValueKindV1::Json => PointerType::Json,
        EntrypointValueKindV1::Name => PointerType::Name,
        EntrypointValueKindV1::AccountId => PointerType::AccountId,
        EntrypointValueKindV1::AssetDefinitionId => PointerType::AssetDefinitionId,
        EntrypointValueKindV1::AssetId => PointerType::AssetId,
        EntrypointValueKindV1::DomainId => PointerType::DomainId,
        EntrypointValueKindV1::NftId => PointerType::NftId,
        EntrypointValueKindV1::DataSpaceId => PointerType::DataSpaceId,
    })
}
fn decode_canonical_norito<T>(payload: &[u8]) -> Result<T, VMError>
where
    T: for<'__frame> norito::NoritoDeserialize<'__frame> + norito::NoritoSerialize,
{
    decode_abi_canonical_norito(payload).map_err(|_| VMError::DecodeError)
}
pub(crate) fn validate_pointer_payload(
    kind: EntrypointValueKindV1,
    payload: &[u8],
) -> Result<(), VMError> {
    match kind {
        EntrypointValueKindV1::Bool => return Err(VMError::DecodeError),
        EntrypointValueKindV1::Int => {
            IntValueV1::decode_frame(payload).map_err(|_| VMError::DecodeError)?;
        }
        EntrypointValueKindV1::Decimal => {
            DecimalValueV1::decode_frame(payload).map_err(|_| VMError::DecodeError)?;
        }
        EntrypointValueKindV1::Quantity => {
            QuantityValueV1::decode_frame(payload).map_err(|_| VMError::DecodeError)?;
        }
        EntrypointValueKindV1::String => {
            std::str::from_utf8(payload).map_err(|_| VMError::DecodeError)?;
        }
        EntrypointValueKindV1::Json => {
            let _: Json = decode_canonical_norito(payload)?;
        }
        EntrypointValueKindV1::Name => {
            let _: Name = decode_canonical_norito(payload)?;
        }
        EntrypointValueKindV1::AccountId => {
            let _: AccountId = decode_canonical_norito(payload)?;
        }
        EntrypointValueKindV1::AssetDefinitionId => {
            let _: AssetDefinitionId = decode_canonical_norito(payload)?;
        }
        EntrypointValueKindV1::AssetId => {
            let _: AssetId = decode_canonical_norito(payload)?;
        }
        EntrypointValueKindV1::DomainId => {
            let _: DomainId = decode_canonical_norito(payload)?;
        }
        EntrypointValueKindV1::NftId => {
            let _: NftId = decode_canonical_norito(payload)?;
        }
        EntrypointValueKindV1::DataSpaceId => {
            let _: DataSpaceId = decode_canonical_norito(payload)?;
        }
        EntrypointValueKindV1::Blob => {}
    }
    Ok(())
}
fn validate_pointer_atom(
    policy: ivm_abi::SyscallPolicy,
    kind: EntrypointValueKindV1,
    envelope: &[u8],
) -> Result<(), VMError> {
    let expected = expected_pointer_type(kind).ok_or(VMError::DecodeError)?;
    let tlv = pointer_abi::validate_tlv_bytes(envelope)?;
    if tlv.type_id != expected || !pointer_abi::is_type_allowed_for_policy(policy, tlv.type_id) {
        return Err(VMError::DecodeError);
    }
    // Exact TLV validation already proves the version, declared length,
    // payload hash, and absence of trailing bytes. Re-encoding would hash the
    // authenticated payload a second time without strengthening the check.
    validate_pointer_payload(kind, tlv.payload)
}
fn validate_argument_atoms(
    policy: ivm_abi::SyscallPolicy,
    nodes: &[EntrypointValueTypeNodeV1],
    atoms: &[EntrypointValueAtomV1],
    node_index: &mut usize,
    atom_index: &mut usize,
) -> Result<(), VMError> {
    let start = *node_index;
    let end = argument_subtree_end(nodes, start)?;
    let mut actions = vec![start];
    let mut cursor = *atom_index;
    while let Some(node_start) = actions.pop() {
        let node = nodes.get(node_start).ok_or(VMError::DecodeError)?;
        match node {
            EntrypointValueTypeNodeV1::StateCursor(key) => {
                let Some(EntrypointValueAtomV1::Pointer(envelope)) = atoms.get(cursor) else {
                    return Err(VMError::DecodeError);
                };
                ivm_abi::state_cursor::validate_cursor_envelope(
                    iroha_data_model::smart_contract::entrypoint::state_key_schema_hash_v1(key)
                        .ok_or(VMError::DecodeError)?,
                    envelope,
                )?;
                cursor = cursor.checked_add(1).ok_or(VMError::DecodeError)?;
            }
            EntrypointValueTypeNodeV1::Unit => {
                if !matches!(atoms.get(cursor), Some(EntrypointValueAtomV1::Unit)) {
                    return Err(VMError::DecodeError);
                }
                cursor = cursor.checked_add(1).ok_or(VMError::DecodeError)?;
            }
            EntrypointValueTypeNodeV1::Error(error) => {
                let Some(EntrypointValueAtomV1::ErrorCode(code)) = atoms.get(cursor) else {
                    return Err(VMError::DecodeError);
                };
                error.variant(*code).ok_or(VMError::DecodeError)?;
                cursor = cursor.checked_add(1).ok_or(VMError::DecodeError)?;
            }
            EntrypointValueTypeNodeV1::Enum(descriptor) => {
                let Some(EntrypointValueAtomV1::EnumCode(code)) = atoms.get(cursor) else {
                    return Err(VMError::DecodeError);
                };
                descriptor.variant(*code).ok_or(VMError::DecodeError)?;
                cursor = cursor.checked_add(1).ok_or(VMError::DecodeError)?;
            }
            EntrypointValueTypeNodeV1::Struct(node) => {
                let starts = argument_child_starts(nodes, node_start, node.fields.len())?;
                actions.extend(starts.into_iter().rev());
            }
            EntrypointValueTypeNodeV1::Tuple(arity) => {
                let starts = argument_child_starts(nodes, node_start, usize::from(*arity))?;
                actions.extend(starts.into_iter().rev());
            }
            EntrypointValueTypeNodeV1::Option => {
                let EntrypointValueAtomV1::Tag(active) =
                    atoms.get(cursor).ok_or(VMError::DecodeError)?
                else {
                    return Err(VMError::DecodeError);
                };
                cursor = cursor.checked_add(1).ok_or(VMError::DecodeError)?;
                if *active {
                    actions.push(node_start.checked_add(1).ok_or(VMError::DecodeError)?);
                }
            }
            EntrypointValueTypeNodeV1::Result => {
                let EntrypointValueAtomV1::Tag(ok_active) =
                    atoms.get(cursor).ok_or(VMError::DecodeError)?
                else {
                    return Err(VMError::DecodeError);
                };
                cursor = cursor.checked_add(1).ok_or(VMError::DecodeError)?;
                let ok_start = node_start.checked_add(1).ok_or(VMError::DecodeError)?;
                let err_start = argument_subtree_end(nodes, ok_start)?;
                actions.push(if *ok_active { ok_start } else { err_start });
            }
            EntrypointValueTypeNodeV1::List(list) => {
                let EntrypointValueAtomV1::List(item_count) =
                    atoms.get(cursor).ok_or(VMError::DecodeError)?
                else {
                    return Err(VMError::DecodeError);
                };
                cursor = cursor.checked_add(1).ok_or(VMError::DecodeError)?;
                if *item_count > list.capacity {
                    return Err(VMError::DecodeError);
                }
                let element_start = node_start.checked_add(1).ok_or(VMError::DecodeError)?;
                let _ = argument_subtree_end(nodes, element_start)?;
                actions.extend(core::iter::repeat_n(
                    element_start,
                    usize::from(*item_count),
                ));
            }
            EntrypointValueTypeNodeV1::Leaf(kind) => {
                let atom = atoms.get(cursor).ok_or(VMError::DecodeError)?;
                cursor = cursor.checked_add(1).ok_or(VMError::DecodeError)?;
                match (kind, atom) {
                    (EntrypointValueKindV1::Bool, EntrypointValueAtomV1::Bool(_)) => {}
                    (kind, EntrypointValueAtomV1::Pointer(envelope)) if kind.is_pointer() => {
                        validate_pointer_atom(policy, *kind, envelope)?;
                    }
                    _ => return Err(VMError::DecodeError),
                }
            }
        }
    }
    *node_index = end;
    *atom_index = cursor;
    Ok(())
}
fn validate_record_shape(
    schema: &EntrypointArgumentSchemaV1,
    schema_bytes: &[u8],
    record: &EntrypointArgumentRecordV1,
    policy: ivm_abi::SyscallPolicy,
) -> Result<Vec<EntrypointValueWordKindV1>, VMError> {
    if record.schema_hash != entrypoint_argument_schema_hash_v1(schema_bytes)
        || !schema.validate_atoms(&record.atoms)
    {
        return Err(VMError::DecodeError);
    }
    let mut atom_index = 0;
    for field in &schema.fields {
        let mut node_index = 0;
        validate_argument_atoms(
            policy,
            &field.ty.nodes,
            &record.atoms,
            &mut node_index,
            &mut atom_index,
        )?;
        if node_index != field.ty.nodes.len() {
            return Err(VMError::DecodeError);
        }
    }
    if atom_index != record.atoms.len() {
        return Err(VMError::DecodeError);
    }
    let word_kinds = schema
        .word_kinds_for_atoms(&record.atoms)
        .ok_or(VMError::DecodeError)?;
    Ok(word_kinds)
}
/// Validate canonical record bytes against an exact compiler-emitted schema.
///
/// The byte bound is checked before Norito decoding. Canonical re-encoding, schema binding,
/// active-only atom shape, pointer envelopes, and typed pointer payloads are all fail-closed.
pub fn validate_argument_record(
    schema: &EntrypointArgumentSchemaV1,
    payload: &[u8],
) -> Result<EntrypointArgumentRecordV1, VMError> {
    if !schema.validate() || payload.len() > MAX_ENTRYPOINT_ARGUMENT_RECORD_BYTES {
        return Err(VMError::DecodeError);
    }
    let record = decode_record(payload)?;
    let schema_bytes = canonical_norito_frame(schema).map_err(|_| VMError::DecodeError)?;
    validate_record_shape(
        schema,
        &schema_bytes,
        &record,
        ivm_abi::SyscallPolicy::AbiV1,
    )?;
    Ok(record)
}
fn plan_argument_atoms(
    nodes: &[EntrypointValueTypeNodeV1],
    atoms: &[EntrypointValueAtomV1],
    node_index: &mut usize,
    atom_index: &mut usize,
    decoded: &mut Vec<DecodedArgument>,
    roots: &mut Vec<usize>,
) -> Result<(), VMError> {
    enum Completion {
        Root,
        Sum {
            layout: SumLayoutV1,
            tag: u64,
            expected_words: usize,
        },
        ListItem,
    }
    struct PlanFrame {
        actions: Vec<usize>,
        roots: Vec<usize>,
        completion: Completion,
    }
    struct ListFrame {
        layout: ListLayoutV1,
        element_start: usize,
        element_words: usize,
        remaining_items: usize,
        elements: Vec<Vec<usize>>,
    }
    enum Frame {
        Plan(PlanFrame),
        List(ListFrame),
    }
    let start = *node_index;
    let end = argument_subtree_end(nodes, start)?;
    let mut frames = vec![Frame::Plan(PlanFrame {
        actions: vec![start],
        roots: Vec::new(),
        completion: Completion::Root,
    })];
    let mut cursor = *atom_index;
    let mut final_roots = None::<Vec<usize>>;
    while !frames.is_empty() {
        let plan_complete = matches!(
            frames.last(),
            Some(Frame::Plan(frame)) if frame.actions.is_empty()
        );
        if plan_complete {
            let Frame::Plan(frame) = frames.pop().expect("frame exists") else {
                unreachable!("completion predicate checked the frame variant");
            };
            match frame.completion {
                Completion::Root => {
                    if !frames.is_empty() {
                        return Err(VMError::DecodeError);
                    }
                    final_roots = Some(frame.roots);
                }
                Completion::Sum {
                    layout,
                    tag,
                    expected_words,
                } => {
                    if frame.roots.len() != expected_words {
                        return Err(VMError::DecodeError);
                    }
                    let index = decoded.len();
                    decoded.push(DecodedArgument::Sum {
                        layout,
                        tag,
                        active: frame.roots,
                    });
                    let Some(Frame::Plan(parent)) = frames.last_mut() else {
                        return Err(VMError::DecodeError);
                    };
                    parent.roots.push(index);
                }
                Completion::ListItem => {
                    let Some(Frame::List(_)) = frames.last() else {
                        return Err(VMError::DecodeError);
                    };
                    let Frame::List(mut list) = frames.pop().expect("list frame exists") else {
                        unreachable!("variant checked");
                    };
                    if frame.roots.len() != list.element_words {
                        return Err(VMError::DecodeError);
                    }
                    list.elements.push(frame.roots);
                    if list.remaining_items != 0 {
                        list.remaining_items = list
                            .remaining_items
                            .checked_sub(1)
                            .ok_or(VMError::DecodeError)?;
                        let element_start = list.element_start;
                        frames.push(Frame::List(list));
                        frames.push(Frame::Plan(PlanFrame {
                            actions: vec![element_start],
                            roots: Vec::new(),
                            completion: Completion::ListItem,
                        }));
                    } else {
                        let index = decoded.len();
                        decoded.push(DecodedArgument::List {
                            layout: list.layout,
                            elements: list.elements,
                        });
                        let Some(Frame::Plan(parent)) = frames.last_mut() else {
                            return Err(VMError::DecodeError);
                        };
                        parent.roots.push(index);
                    }
                }
            }
            continue;
        }
        let mut spawned = Vec::<Frame>::new();
        {
            let Some(Frame::Plan(frame)) = frames.last_mut() else {
                return Err(VMError::DecodeError);
            };
            let node_start = frame.actions.pop().ok_or(VMError::DecodeError)?;
            let node = nodes.get(node_start).ok_or(VMError::DecodeError)?;
            match node {
                EntrypointValueTypeNodeV1::Struct(node) => {
                    if node.fields.is_empty() {
                        let index = decoded.len();
                        decoded.push(DecodedArgument::Scalar(0));
                        frame.roots.push(index);
                    }
                    let starts = argument_child_starts(nodes, node_start, node.fields.len())?;
                    frame.actions.extend(starts.into_iter().rev());
                }
                EntrypointValueTypeNodeV1::Tuple(arity) => {
                    let starts = argument_child_starts(nodes, node_start, usize::from(*arity))?;
                    frame.actions.extend(starts.into_iter().rev());
                }
                EntrypointValueTypeNodeV1::Option => {
                    let EntrypointValueAtomV1::Tag(tag) =
                        atoms.get(cursor).ok_or(VMError::DecodeError)?
                    else {
                        return Err(VMError::DecodeError);
                    };
                    cursor = cursor.checked_add(1).ok_or(VMError::DecodeError)?;
                    let child_start = node_start.checked_add(1).ok_or(VMError::DecodeError)?;
                    let mut child_end = child_start;
                    let child_words = argument_node_word_count(nodes, &mut child_end)?;
                    let layout = SumLayoutV1::option(
                        u64::try_from(child_words).map_err(|_| VMError::DecodeError)?,
                    )
                    .map_err(|_| VMError::DecodeError)?;
                    if *tag {
                        spawned.push(Frame::Plan(PlanFrame {
                            actions: vec![child_start],
                            roots: Vec::with_capacity(child_words),
                            completion: Completion::Sum {
                                layout,
                                tag: 1,
                                expected_words: child_words,
                            },
                        }));
                    } else {
                        let index = decoded.len();
                        decoded.push(DecodedArgument::Sum {
                            layout,
                            tag: 0,
                            active: Vec::new(),
                        });
                        frame.roots.push(index);
                    }
                }
                EntrypointValueTypeNodeV1::Result => {
                    let EntrypointValueAtomV1::Tag(tag) =
                        atoms.get(cursor).ok_or(VMError::DecodeError)?
                    else {
                        return Err(VMError::DecodeError);
                    };
                    cursor = cursor.checked_add(1).ok_or(VMError::DecodeError)?;
                    let ok_start = node_start.checked_add(1).ok_or(VMError::DecodeError)?;
                    let mut ok_end = ok_start;
                    let ok_words = argument_node_word_count(nodes, &mut ok_end)?;
                    let mut err_end = ok_end;
                    let err_words = argument_node_word_count(nodes, &mut err_end)?;
                    let (active_start, active_words) = if *tag {
                        (ok_start, ok_words)
                    } else {
                        (ok_end, err_words)
                    };
                    let layout = SumLayoutV1::try_new(
                        u64::try_from(err_words).map_err(|_| VMError::DecodeError)?,
                        u64::try_from(ok_words).map_err(|_| VMError::DecodeError)?,
                    )
                    .map_err(|_| VMError::DecodeError)?;
                    spawned.push(Frame::Plan(PlanFrame {
                        actions: vec![active_start],
                        roots: Vec::with_capacity(active_words),
                        completion: Completion::Sum {
                            layout,
                            tag: u64::from(*tag),
                            expected_words: active_words,
                        },
                    }));
                }
                EntrypointValueTypeNodeV1::List(list) => {
                    let EntrypointValueAtomV1::List(item_count) =
                        atoms.get(cursor).ok_or(VMError::DecodeError)?
                    else {
                        return Err(VMError::DecodeError);
                    };
                    cursor = cursor.checked_add(1).ok_or(VMError::DecodeError)?;
                    if *item_count > list.capacity {
                        return Err(VMError::DecodeError);
                    }
                    let element_start = node_start.checked_add(1).ok_or(VMError::DecodeError)?;
                    let mut element_end = element_start;
                    let element_words = argument_node_word_count(nodes, &mut element_end)?;
                    let layout = ListLayoutV1::try_new(
                        u64::from(list.capacity),
                        u64::try_from(element_words).map_err(|_| VMError::DecodeError)?,
                    )
                    .map_err(|_| VMError::DecodeError)?;
                    let item_count = usize::from(*item_count);
                    if item_count != 0 {
                        spawned.push(Frame::List(ListFrame {
                            layout,
                            element_start,
                            element_words,
                            remaining_items: item_count - 1,
                            elements: Vec::with_capacity(item_count),
                        }));
                        spawned.push(Frame::Plan(PlanFrame {
                            actions: vec![element_start],
                            roots: Vec::with_capacity(element_words),
                            completion: Completion::ListItem,
                        }));
                    } else {
                        let index = decoded.len();
                        decoded.push(DecodedArgument::List {
                            layout,
                            elements: Vec::new(),
                        });
                        frame.roots.push(index);
                    }
                }
                EntrypointValueTypeNodeV1::Unit
                | EntrypointValueTypeNodeV1::Error(_)
                | EntrypointValueTypeNodeV1::Enum(_) => {
                    let scalar = match (node, atoms.get(cursor)) {
                        (EntrypointValueTypeNodeV1::Unit, Some(EntrypointValueAtomV1::Unit)) => 0,
                        (
                            EntrypointValueTypeNodeV1::Error(error),
                            Some(EntrypointValueAtomV1::ErrorCode(code)),
                        ) if error.variant(*code).is_some() => u64::from(*code),
                        (
                            EntrypointValueTypeNodeV1::Enum(descriptor),
                            Some(EntrypointValueAtomV1::EnumCode(code)),
                        ) if descriptor.variant(*code).is_some() => u64::from(*code),
                        _ => return Err(VMError::DecodeError),
                    };
                    cursor = cursor.checked_add(1).ok_or(VMError::DecodeError)?;
                    let index = decoded.len();
                    decoded.push(DecodedArgument::Scalar(scalar));
                    frame.roots.push(index);
                }
                EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Bool) => {
                    let EntrypointValueAtomV1::Bool(value) =
                        atoms.get(cursor).ok_or(VMError::DecodeError)?
                    else {
                        return Err(VMError::DecodeError);
                    };
                    cursor = cursor.checked_add(1).ok_or(VMError::DecodeError)?;
                    let index = decoded.len();
                    decoded.push(DecodedArgument::Scalar(u64::from(*value)));
                    frame.roots.push(index);
                }
                EntrypointValueTypeNodeV1::Leaf(_) | EntrypointValueTypeNodeV1::StateCursor(_) => {
                    let EntrypointValueAtomV1::Pointer(envelope) =
                        atoms.get(cursor).ok_or(VMError::DecodeError)?
                    else {
                        return Err(VMError::DecodeError);
                    };
                    cursor = cursor.checked_add(1).ok_or(VMError::DecodeError)?;
                    let index = decoded.len();
                    decoded.push(DecodedArgument::Pointer(envelope.clone()));
                    frame.roots.push(index);
                }
            }
        }
        frames.extend(spawned);
    }
    let planned_roots = final_roots.ok_or(VMError::DecodeError)?;
    *node_index = end;
    *atom_index = cursor;
    roots.extend(planned_roots);
    Ok(())
}
fn build_decode_plan(
    schema: &EntrypointArgumentSchemaV1,
    schema_bytes: &[u8],
    record: EntrypointArgumentRecordV1,
    policy: ivm_abi::SyscallPolicy,
    record_bytes: usize,
) -> Result<ArgumentDecodePlan, VMError> {
    let word_kinds = validate_record_shape(schema, schema_bytes, &record, policy)?;
    let mut decoded = Vec::with_capacity(word_kinds.len());
    let mut roots = Vec::with_capacity(word_kinds.len());
    let mut atom_index = 0;
    for field in &schema.fields {
        let mut node_index = 0;
        plan_argument_atoms(
            &field.ty.nodes,
            &record.atoms,
            &mut node_index,
            &mut atom_index,
            &mut decoded,
            &mut roots,
        )?;
        if node_index != field.ty.nodes.len() {
            return Err(VMError::DecodeError);
        }
    }
    if atom_index != record.atoms.len() || roots.len() != word_kinds.len() {
        return Err(VMError::DecodeError);
    }
    let (pointer_envelope_bytes, pointer_allocation_bytes) = decoded
        .iter()
        .filter_map(|value| match value {
            DecodedArgument::Pointer(envelope) => Some((
                u64::try_from(envelope.len()).unwrap_or(u64::MAX),
                aligned_allocation_bytes(envelope.len()),
            )),
            _ => None,
        })
        .fold((0_u64, 0_u64), |totals, bytes| {
            (
                totals.0.saturating_add(bytes.0),
                totals.1.saturating_add(bytes.1),
            )
        });
    if pointer_envelope_bytes > u64::try_from(record_bytes).unwrap_or(u64::MAX) {
        return Err(VMError::DecodeError);
    }
    let raw_heap_bytes = decoded
        .iter()
        .filter_map(|value| match value {
            DecodedArgument::Sum { layout, .. } => {
                Some(layout.allocation_bytes().unwrap_or(u64::MAX))
            }
            DecodedArgument::List { layout, .. } => {
                Some(layout.allocation_bytes().unwrap_or(u64::MAX))
            }
            DecodedArgument::Scalar(_) | DecodedArgument::Pointer(_) => None,
        })
        .fold(0_u64, u64::saturating_add);
    // No successful invocation can materialize more than the VM's owned HEAP.
    // Capping the charged raw-allocation component keeps the predecode schema
    // bound valid even for a value which will later fail the allocation
    // preflight; pointer copies and the output table remain charged exactly.
    let materialized_bytes = aligned_allocation_bytes(decoded_table_bytes(roots.len()))
        .saturating_add(pointer_allocation_bytes)
        .saturating_add(cap_raw_heap_bytes(raw_heap_bytes));
    Ok(ArgumentDecodePlan {
        decoded,
        roots,
        record_bytes,
        schema_bytes: schema_bytes.len(),
        materialized_bytes,
    })
}
/// Validate and prepare a canonical record only after its deterministic work
/// fits the invocation's gas allowance.
///
/// The compiler-owned schema is validated first and its framed length is counted under the
/// canonical V1 Norito flags, independently of any prior decode context. Its flat preorder tape
/// then yields a bounded, allocation-free maximum for ABI words and aggregate HEAP storage.
/// Together with signed wire lengths and the record-bounded aligned pointer-copy allowance, that
/// quote is checked before the first untrusted record decode.
///
/// # Errors
///
/// Returns [`VMError::OutOfGas`] when the deterministic preparation bound is
/// unaffordable, or a decode/ABI/memory error when the bounded record is not a
/// canonical executable V1 argument record.
pub fn prepare_argument_record_with_gas_limit(
    schema: &EntrypointArgumentSchemaV1,
    canonical_record: Arc<[u8]>,
    gas_limit: u64,
) -> Result<PreparedArgumentRecord, VMError> {
    if canonical_record.len() > MAX_ENTRYPOINT_ARGUMENT_RECORD_BYTES {
        return Err(VMError::DecodeError);
    }
    let schema_bound = schema_materialization_bound(schema)?;
    let schema_bytes_len = canonical_norito_frame_len(schema);
    if schema_bytes_len > MAX_ENTRYPOINT_ARGUMENT_SCHEMA_BYTES {
        return Err(VMError::DecodeError);
    }
    let gas_bound = argument_record_gas_for_schema_bound(
        canonical_record.len(),
        schema_bytes_len,
        schema_bound,
    );
    if gas_bound > gas_limit {
        return Err(VMError::OutOfGas);
    }
    let schema_bytes: Arc<[u8]> =
        Arc::from(canonical_norito_frame(schema).map_err(|_| VMError::DecodeError)?);
    debug_assert_eq!(schema_bytes.len(), schema_bytes_len);
    let record = decode_record(&canonical_record)?;
    let decode_plan = build_decode_plan(
        schema,
        &schema_bytes,
        record,
        ivm_abi::SyscallPolicy::AbiV1,
        canonical_record.len(),
    )?;
    if decode_plan.gas() > gas_bound {
        return Err(VMError::DecodeError);
    }
    // The authenticated schema and signed record remain host-owned. Only decoded
    // leaf envelopes and raw argument/aggregate storage consume VM arenas.
    let fresh_allocation_lengths = decode_plan.allocation_lengths();
    let raw_heap_bytes = decode_plan.raw_heap_bytes();
    IVM::preflight_fresh_host_tlv_allocations_with_reserved_heap(
        &fresh_allocation_lengths,
        raw_heap_bytes,
    )?;
    Ok(PreparedArgumentRecord {
        inner: Arc::new(PreparedArgumentRecordInner {
            canonical_record,
            canonical_schema: schema_bytes,
            decode_plan,
        }),
    })
}
fn plan_argument_record_decode(vm: &IVM) -> Result<ArgumentDecodePlan, VMError> {
    let record_tlv = validate_tlv_any_region(vm, vm.register(10), PointerType::NoritoBytes)?;
    let schema_tlv = validate_tlv_any_region(vm, vm.register(11), PointerType::NoritoBytes)?;
    validate_argument_envelope_lengths(&record_tlv, &schema_tlv)?;
    let schema = decode_schema(schema_tlv.payload)?;
    let record_bytes = record_tlv.payload.len();
    let record = decode_record(record_tlv.payload)?;
    build_decode_plan(
        &schema,
        schema_tlv.payload,
        record,
        vm.syscall_policy(),
        record_bytes,
    )
}
/// Compute a conservative gas reserve for [`decode_argument_record`] without
/// decoding either payload, allocating, or changing VM state.
pub(crate) fn decode_argument_record_gas_quote(vm: &IVM) -> Result<u64, VMError> {
    let (record_bytes, schema_bytes) = quote_argument_envelope_lengths(vm)?;
    Ok(argument_record_runtime_gas_upper_bound(
        record_bytes,
        schema_bytes,
    ))
}
/// Decode the public argument object in `r10` using the schema in `r11`.
///
/// On success, `r10` receives an aligned owned-HEAP table address and `r11` its exact word count.
/// The operation decodes the boundary payload exactly once before allocating typed envelopes.
pub(crate) fn decode_argument_record(vm: &mut IVM) -> Result<u64, VMError> {
    let plan = plan_argument_record_decode(vm)?;
    materialize_decode_plan(vm, &plan)
}
fn materialize_decode_plan(vm: &mut IVM, plan: &ArgumentDecodePlan) -> Result<u64, VMError> {
    let gas = plan.gas();
    let raw_heap_bytes = plan.raw_heap_bytes();
    vm.preflight_host_tlv_allocations_with_reserved_heap(
        &plan.allocation_lengths(),
        raw_heap_bytes,
    )?;
    let mut materialized = Vec::<u64>::with_capacity(plan.decoded.len());
    for (index, value) in plan.decoded.iter().enumerate() {
        let word = match value {
            DecodedArgument::Scalar(value) => Ok(*value),
            DecodedArgument::Pointer(envelope) => vm.alloc_host_tlv(envelope),
            DecodedArgument::Sum {
                layout,
                tag,
                active,
            } => {
                let mut payload = Vec::with_capacity(active.len());
                for child in active {
                    if *child >= index {
                        return Err(VMError::DecodeError);
                    }
                    payload.push(*materialized.get(*child).ok_or(VMError::DecodeError)?);
                }
                crate::sum::allocate_words(vm, *layout, *tag, &payload)
            }
            DecodedArgument::List { layout, elements } => {
                let width =
                    usize::try_from(layout.element_words()).map_err(|_| VMError::DecodeError)?;
                let mut words = Vec::with_capacity(elements.len());
                for element in elements {
                    let mut item = Vec::with_capacity(width);
                    for child in element {
                        if *child >= index {
                            return Err(VMError::DecodeError);
                        }
                        item.push(*materialized.get(*child).ok_or(VMError::DecodeError)?);
                    }
                    if item.len() != width {
                        return Err(VMError::DecodeError);
                    }
                    words.push(item);
                }
                crate::list::allocate_words(vm, *layout, &words)
            }
        }?;
        materialized.push(word);
    }
    let mut words = Vec::with_capacity(plan.roots.len());
    for root in &plan.roots {
        words.push(*materialized.get(*root).ok_or(VMError::DecodeError)?);
    }
    let table_pointer = if words.is_empty() {
        0
    } else {
        let pointer = vm.alloc_heap(decoded_table_bytes(words.len()) as u64)?;
        for (index, word) in words.iter().enumerate() {
            vm.store_u64(pointer + (index * 8) as u64, *word)?;
        }
        pointer
    };
    vm.set_register(10, table_pointer);
    vm.set_register(11, words.len() as u64);
    Ok(gas)
}
#[cfg(test)]
mod tests {
    use super::*;
    use ivm_abi::entrypoint::{
        EntrypointArgumentFieldV1, EntrypointListTypeNodeV1, EntrypointStructTypeNodeV1,
        EntrypointValueKindV1, EntrypointValueTypeNodeV1, EntrypointValueTypeV1,
        MAX_ENTRYPOINT_ARGUMENT_TYPE_DEPTH,
    };
    fn argument_type(kind: EntrypointValueKindV1) -> EntrypointValueTypeV1 {
        EntrypointValueTypeV1 {
            nodes: vec![EntrypointValueTypeNodeV1::Leaf(kind)],
        }
    }
    fn list_type(capacity: u8, element: EntrypointValueTypeV1) -> EntrypointValueTypeV1 {
        let mut nodes = Vec::with_capacity(element.nodes.len().saturating_add(1));
        nodes.push(EntrypointValueTypeNodeV1::List(EntrypointListTypeNodeV1 {
            capacity,
        }));
        nodes.extend(element.nodes);
        EntrypointValueTypeV1 { nodes }
    }
    fn nested_list_type(levels: usize) -> EntrypointValueTypeV1 {
        let mut nodes = Vec::with_capacity(levels.saturating_add(1));
        for _ in 0..levels {
            nodes.push(EntrypointValueTypeNodeV1::List(EntrypointListTypeNodeV1 {
                capacity: 1,
            }));
        }
        nodes.push(EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int));
        EntrypointValueTypeV1 { nodes }
    }
    fn prepared_gas_bound(schema: &EntrypointArgumentSchemaV1, record_bytes: usize) -> u64 {
        let schema_bytes = canonical_norito_frame(schema).expect("encode schema for gas bound");
        let bound = schema_materialization_bound(schema).expect("valid schema bound");
        argument_record_gas_for_schema_bound(record_bytes, schema_bytes.len(), bound)
    }
    fn int_atom(value: i128) -> EntrypointValueAtomV1 {
        EntrypointValueAtomV1::Pointer(
            ivm_abi::numeric_tlv::encode_int(&BigInt::from_i128(value))
                .expect("encode canonical Int atom"),
        )
    }
    #[test]
    fn empty_nominal_product_arguments_materialize_unit_without_atoms() {
        let empty = EntrypointValueTypeV1 {
            nodes: vec![EntrypointValueTypeNodeV1::Struct(
                ivm_abi::entrypoint::EntrypointStructTypeNodeV1 {
                    name: "Fixture::Empty".into(),
                    fields: Vec::new(),
                },
            )],
        };
        let schema = EntrypointArgumentSchemaV1 {
            fields: vec![
                EntrypointArgumentFieldV1 {
                    name: "value".into(),
                    ty: empty.clone(),
                },
                EntrypointArgumentFieldV1 {
                    name: "values".into(),
                    ty: list_type(2, empty),
                },
            ],
        };
        let payload = Json::new(norito::json!({"value": {}, "values": [{}, {}]}));
        let record = argument_record_from_json(&schema, &payload).unwrap();
        assert_eq!(record.atoms, vec![EntrypointValueAtomV1::List(2)]);
        let prepared = prepare_argument_record_with_gas_limit(
            &schema,
            Arc::from(encode_argument_record_from_json(&schema, &payload).unwrap()),
            u64::MAX,
        )
        .unwrap();
        assert_eq!(prepared.word_count(), 2);
        let mut vm = IVM::new(u64::MAX);
        prepared.precharge_vm(&mut vm).unwrap();
        prepared.install_call_arguments(&mut vm, 1).unwrap();
        let table = vm.register(10);
        assert!(matches!(vm.load_u64(table), Ok(0)));
        let list = vm.load_u64(table + 8).unwrap();
        assert_eq!(
            crate::list::read_words(&vm, list, ListLayoutV1::try_new(2, 1).unwrap()).unwrap(),
            vec![vec![0], vec![0]]
        );
    }
    #[test]
    fn root_call_installation_consumes_prepaid_decode_once_and_reserves_disjoint_tables() {
        let schema = EntrypointArgumentSchemaV1 {
            fields: vec![EntrypointArgumentFieldV1 {
                name: "ready".into(),
                ty: argument_type(EntrypointValueKindV1::Bool),
            }],
        };
        let record =
            encode_argument_record_from_json(&schema, &Json::new(norito::json!({"ready": true})))
                .expect("canonical arguments");
        reset_argument_record_decode_count();
        let prepared = prepare_argument_record_with_gas_limit(&schema, Arc::from(record), u64::MAX)
            .expect("prepare once");
        assert_eq!(argument_record_decode_count(), 1);
        assert_eq!(prepared.word_count(), 1);
        let mut vm = IVM::new(u64::MAX);
        prepared.precharge_vm(&mut vm).expect("prepay decode");
        let gas_before = vm.gas_remaining;
        prepared
            .install_call_arguments(&mut vm, 32)
            .expect("install tables");
        assert_eq!(argument_record_decode_count(), 1);
        assert_eq!(gas_before - vm.gas_remaining, 32 * 8);
        assert_eq!(vm.register(11), 1);
        assert_eq!(vm.load_u64(vm.register(10)).unwrap(), 1);
        assert_eq!(vm.register(13), 32);
        assert!(vm.register(12) >= vm.register(10) + 8);
        assert_eq!(vm.register(10) % 8, 0);
        assert_eq!(vm.register(12) % 8, 0);
        assert!(matches!(
            prepared.install_call_arguments(&mut vm, 32),
            Err(VMError::DecodeError)
        ));
    }
    #[test]
    fn default_root_preparation_uses_the_metered_public_input_route() {
        let schema = EntrypointArgumentSchemaV1 {
            fields: vec![EntrypointArgumentFieldV1 {
                name: "ready".into(),
                ty: argument_type(EntrypointValueKindV1::Bool),
            }],
        };
        let record =
            encode_argument_record_from_json(&schema, &Json::new(norito::json!({"ready": true})))
                .unwrap();
        let input = encode_tlv(PointerType::NoritoBytes, &record).unwrap();
        let mut host = crate::host::DefaultHost::default().with_public_inputs(
            std::collections::BTreeMap::from([(
                ivm_abi::arguments::ENTRYPOINT_ARGUMENT_RECORD_PUBLIC_INPUT_KEY
                    .parse()
                    .unwrap(),
                input,
            )]),
        );
        let mut vm = IVM::new(u64::MAX);
        reset_argument_record_decode_count();
        prepare_default_call_arguments(&mut host, &mut vm, &schema, 1)
            .expect("prepare public input");
        assert_eq!(argument_record_decode_count(), 1);
        assert_eq!(vm.load_u64(vm.register(10)).unwrap(), 1);
        assert_eq!((vm.register(11), vm.register(13)), (1, 1));
        assert!(vm.gas_remaining < u64::MAX - 8);
        let mut missing_host = crate::host::DefaultHost::default();
        let mut denied_vm = IVM::new(u64::MAX);
        assert!(matches!(
            prepare_default_call_arguments(&mut missing_host, &mut denied_vm, &schema, 1),
            Err(VMError::PermissionDenied)
        ));
    }

    #[test]
    fn default_root_arguments_do_not_consume_trigger_event_json() {
        use crate::host::IVMHost;

        let schema = EntrypointArgumentSchemaV1 {
            fields: vec![EntrypointArgumentFieldV1 {
                name: "ready".into(),
                ty: argument_type(EntrypointValueKindV1::Bool),
            }],
        };
        let record =
            encode_argument_record_from_json(&schema, &Json::new(norito::json!({"ready": true})))
                .expect("encode original schema-bound arguments");
        let event = Json::new(norito::json!({"firing_event": "original-event"}));
        let event_frame = canonical_norito_frame(&event).expect("encode actual firing JSON");
        let record_tlv = encode_tlv(PointerType::NoritoBytes, &record).unwrap();
        let event_tlv = encode_tlv(PointerType::Json, &event_frame).unwrap();
        let mut host = crate::host::DefaultHost::default().with_public_inputs(
            std::collections::BTreeMap::from([
                (
                    "entrypoint_argument_record".parse().unwrap(),
                    record_tlv.clone(),
                ),
                ("trigger_event_json".parse().unwrap(), event_tlv.clone()),
            ]),
        );
        let mut vm = IVM::new(u64::MAX);
        reset_argument_record_decode_count();
        prepare_default_call_arguments(&mut host, &mut vm, &schema, 1)
            .expect("default root must acquire the canonical argument-record key");
        assert_eq!(argument_record_decode_count(), 1);
        let argument_base = vm.register(10);
        let result_base = vm.register(12);
        assert_eq!(vm.load_u64(argument_base).unwrap(), 1);
        assert_eq!((vm.register(11), vm.register(13)), (1, 1));
        assert!(vm.gas_remaining < u64::MAX - 8);
        let event_name: Name = "trigger_event_json".parse().unwrap();
        let name_frame = canonical_norito_frame(&event_name).unwrap();
        let name_pointer = vm
            .alloc_host_tlv(&encode_tlv(PointerType::Name, &name_frame).unwrap())
            .expect("allocate actual event input name");
        vm.set_register(10, name_pointer);
        let quote = host
            .prepare_syscall(crate::syscalls::SYSCALL_GET_PUBLIC_INPUT, &vm)
            .expect("quote event input independently of root preparation");
        let gas = host
            .syscall(crate::syscalls::SYSCALL_GET_PUBLIC_INPUT, &mut vm)
            .expect("read actual firing JSON");
        let returned = vm.validate_tlv(vm.register(10)).unwrap();
        assert_eq!(returned.type_id, PointerType::Json);
        assert_eq!(returned.payload, event_frame);
        assert_eq!(
            gas,
            crate::gas::HOST_BYTE_GAS_BASE
                + crate::gas::SYSCALL_GAS_PER_BYTE * u64::try_from(event_tlv.len()).unwrap()
        );
        assert!(gas <= quote);
        assert_eq!(vm.load_u64(argument_base).unwrap(), 1);
        assert_eq!(
            (vm.register(11), vm.register(12), vm.register(13)),
            (1, result_base, 1)
        );
        assert_eq!(argument_record_decode_count(), 1);

        // A record placed under the event name cannot serve as the root input.
        let mut event_only = crate::host::DefaultHost::default().with_public_inputs(
            std::collections::BTreeMap::from([("trigger_event_json".parse().unwrap(), record_tlv)]),
        );
        let mut denied = IVM::new(u64::MAX);
        assert!(
            matches!(
                prepare_default_call_arguments(&mut event_only, &mut denied, &schema, 1),
                Err(VMError::PermissionDenied)
            ),
            "default preparation must not fall back to the firing-event key"
        );
        assert_eq!(
            (
                denied.register(11),
                denied.register(12),
                denied.register(13)
            ),
            (0, 0, 0)
        );
        assert_eq!(argument_record_decode_count(), 1);
    }

    #[test]
    fn empty_root_arguments_use_zero_descriptor_and_bounded_result_reservation() {
        let mut vm = IVM::new(u64::MAX);
        assert!(matches!(
            install_empty_call_arguments(&mut vm, 0),
            Err(VMError::DecodeError)
        ));
        assert!(matches!(
            install_empty_call_arguments(&mut vm, ivm_abi::call::MAX_CALL_WORDS_V1 + 1),
            Err(VMError::DecodeError)
        ));
        assert_eq!(vm.gas_remaining, u64::MAX);
        install_empty_call_arguments(&mut vm, ivm_abi::call::MAX_CALL_WORDS_V1)
            .expect("full result table");
        assert_eq!((vm.register(10), vm.register(11)), (0, 0));
        assert_eq!(vm.register(13), 8192);
        assert_eq!(u64::MAX - vm.gas_remaining, 65536);
    }
    fn alloc(vm: &mut IVM, pointer_type: PointerType, payload: &[u8]) -> u64 {
        vm.alloc_input_tlv(&encode_tlv(pointer_type, payload).expect("encode TLV"))
            .expect("allocate TLV")
    }
    fn install_record(schema: &EntrypointArgumentSchemaV1, payload: &Json) -> IVM {
        let mut vm = IVM::new(u64::MAX);
        let record = encode_argument_record_from_json(schema, payload)
            .expect("convert boundary JSON to argument record");
        let record_ptr = alloc(&mut vm, PointerType::NoritoBytes, &record);
        let schema_ptr = alloc(
            &mut vm,
            PointerType::NoritoBytes,
            &canonical_norito_frame(schema).expect("encode schema"),
        );
        vm.set_register(10, record_ptr);
        vm.set_register(11, schema_ptr);
        vm
    }
    fn install_raw_record(
        schema: &EntrypointArgumentSchemaV1,
        record: &EntrypointArgumentRecordV1,
    ) -> IVM {
        let mut vm = IVM::new(u64::MAX);
        let record_ptr = alloc(
            &mut vm,
            PointerType::NoritoBytes,
            &to_bytes(record).expect("encode raw argument record"),
        );
        let schema_ptr = alloc(
            &mut vm,
            PointerType::NoritoBytes,
            &canonical_norito_frame(schema).expect("encode raw argument schema"),
        );
        vm.set_register(10, record_ptr);
        vm.set_register(11, schema_ptr);
        vm
    }
    fn decoded_words(vm: &IVM) -> Vec<u64> {
        let base = vm.register(10);
        let count = vm.register(11);
        assert!(count <= ivm_abi::call::MAX_CALL_WORDS_V1 as u64);
        (0..count)
            .map(|index| vm.memory.load_u64(base + index * 8).expect("argument word"))
            .collect()
    }
    fn decoded_int(vm: &IVM, pointer: u64) -> BigInt {
        let value = vm.validate_tlv(pointer).expect("materialized Int TLV");
        assert_eq!(value.type_id, PointerType::Int);
        IntValueV1::decode_frame(value.payload)
            .expect("decode canonical Int frame")
            .into_int()
    }
    #[test]
    fn cursor_argument_materializes_exact_frame_and_rejects_wrong_key_kind() {
        use iroha_data_model::smart_contract::state_cursor::StateCursorV1;
        let cursor = StateCursorV1 {
            instance: "local::金庫".into(),
            map: "balances".parse().unwrap(),
            schema_hash: [3; 32],
            key_schema_hash: iroha_data_model::smart_contract::entrypoint::state_key_schema_hash_v1(&iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeV1 { nodes: vec![iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int)] }).unwrap(),
            last_key: "balances/00".parse().unwrap(),
        };
        let frame = cursor.encode_frame().unwrap();
        let schema = EntrypointArgumentSchemaV1 {
            fields: vec![EntrypointArgumentFieldV1 {
                name: "cursor".into(),
                ty: EntrypointValueTypeV1 {
                    nodes: vec![EntrypointValueTypeNodeV1::StateCursor(iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeV1 { nodes: vec![iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int)] })],
                },
            }],
        };
        let cursor_hex = format!("0x{}", hex::encode(&frame));
        let payload = Json::new(norito::json!({"cursor": cursor_hex}));
        let mut vm = install_record(&schema, &payload);
        decode_argument_record(&mut vm).unwrap();
        let words = decoded_words(&vm);
        let materialized = vm.validate_tlv(words[0]).unwrap();
        assert_eq!(materialized.type_id, PointerType::NoritoBytes);
        assert_eq!(materialized.payload, frame);
        let mut wrong = schema;
        wrong.fields[0].ty.nodes[0] = EntrypointValueTypeNodeV1::StateCursor(
            iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeV1 {
                nodes: vec![
                    iroha_data_model::smart_contract::entrypoint::EntrypointValueTypeNodeV1::Leaf(
                        EntrypointValueKindV1::Bool,
                    ),
                ],
            },
        );
        assert!(argument_record_from_json(&wrong, &payload).is_err());
    }
    #[test]
    fn ordinary_enum_arguments_use_exact_names_and_scalar_materialization() {
        let schema = EntrypointArgumentSchemaV1 {
            fields: vec![EntrypointArgumentFieldV1 {
                name: "status".into(),
                ty: EntrypointValueTypeV1 { nodes: vec![EntrypointValueTypeNodeV1::Enum(iroha_data_model::smart_contract::manifest::ContractEnumTypeDescriptorV1 {
                identity: "local::Status".into(),
                variants: vec![
                    iroha_data_model::smart_contract::manifest::ContractEnumVariantDescriptorV1 { name: "Open".into(), code: 1 },
                    iroha_data_model::smart_contract::manifest::ContractEnumVariantDescriptorV1 { name: "Closed".into(), code: 7 },
                ],
            })] },
            }],
        };
        let payload = Json::new(norito::json!({"status":"Closed"}));
        let mut vm = install_record(&schema, &payload);
        decode_argument_record(&mut vm).unwrap();
        assert_eq!(decoded_words(&vm), vec![7]);
        let bound = value_materialization_bound(&schema.fields[0].ty).unwrap();
        assert_eq!(
            (bound.words, bound.pointer_envelopes, bound.raw_heap_bytes),
            (1, 0, 0)
        );
        for invalid in [
            norito::json!({"status":7}),
            norito::json!({"status":"closed"}),
            norito::json!({"status":"Missing"}),
        ] {
            assert!(argument_record_from_json(&schema, &Json::new(invalid)).is_err());
        }
        for atom in [
            EntrypointValueAtomV1::ErrorCode(7),
            EntrypointValueAtomV1::EnumCode(2),
        ] {
            let mut node = 0;
            let mut value = 0;
            assert!(matches!(
                validate_argument_atoms(
                    ivm_abi::SyscallPolicy::AbiV1,
                    &schema.fields[0].ty.nodes,
                    &[atom],
                    &mut node,
                    &mut value
                ),
                Err(VMError::DecodeError)
            ));
        }
    }
    #[test]
    fn unit_and_nominal_error_arguments_materialize_as_canonical_scalar_words() {
        let schema = EntrypointArgumentSchemaV1 {
            fields: vec![
                EntrypointArgumentFieldV1 {
                    name: "completed".into(),
                    ty: EntrypointValueTypeV1 {
                        nodes: vec![EntrypointValueTypeNodeV1::Unit],
                    },
                },
                EntrypointArgumentFieldV1 {
                    name: "failure".into(),
                    ty: EntrypointValueTypeV1 {
                        nodes: vec![EntrypointValueTypeNodeV1::Error(
                            ivm_abi::error_types::list_error_type(),
                        )],
                    },
                },
            ],
        };
        let payload = Json::new(norito::json!({"completed": null, "failure": "CapacityExceeded"}));
        let mut vm = install_record(&schema, &payload);
        decode_argument_record(&mut vm).expect("decode nominal scalar arguments");
        assert_eq!(decoded_words(&vm), vec![0, 2]);
        for invalid in [
            norito::json!({"completed": 0, "failure": "CapacityExceeded"}),
            norito::json!({"completed": null, "failure": 2}),
            norito::json!({"completed": null, "failure": "Unknown"}),
        ] {
            assert!(argument_record_from_json(&schema, &Json::new(invalid)).is_err());
        }
    }
    #[test]
    fn complete_record_performs_exactly_one_record_decode() {
        RECORD_DECODE_COUNT.with(|count| count.set(0));
        let schema = EntrypointArgumentSchemaV1 {
            fields: vec![
                EntrypointArgumentFieldV1 {
                    name: "count".to_owned(),
                    ty: argument_type(EntrypointValueKindV1::Int),
                },
                EntrypointArgumentFieldV1 {
                    name: "label".to_owned(),
                    ty: argument_type(EntrypointValueKindV1::Name),
                },
                EntrypointArgumentFieldV1 {
                    name: "bytes".to_owned(),
                    ty: argument_type(EntrypointValueKindV1::Blob),
                },
            ],
        };
        let payload = Json::from(norito::json!({
            "count": "7",
            "label": "ready",
            "bytes": "0x0102",
        }));
        let mut vm = install_record(&schema, &payload);
        decode_argument_record(&mut vm).expect("decode complete record");
        RECORD_DECODE_COUNT.with(|count| assert_eq!(count.get(), 1));
        let words = decoded_words(&vm);
        assert_eq!(words.len(), 3);
        assert_eq!(vm.register(10) % 8, 0);
        assert_eq!(decoded_int(&vm, words[0]), BigInt::from_i128(7));
        for pointer in &words[1..] {
            vm.validate_tlv(*pointer).expect("typed output TLV");
        }
    }
    #[test]
    fn prepared_record_materializes_without_a_second_record_decode() {
        let schema = EntrypointArgumentSchemaV1 {
            fields: vec![
                EntrypointArgumentFieldV1 {
                    name: "count".to_owned(),
                    ty: argument_type(EntrypointValueKindV1::Int),
                },
                EntrypointArgumentFieldV1 {
                    name: "label".to_owned(),
                    ty: argument_type(EntrypointValueKindV1::Name),
                },
            ],
        };
        let payload = Json::from(norito::json!({
            "count": "7",
            "label": "ready",
        }));
        let canonical: Arc<[u8]> = Arc::from(
            encode_argument_record_from_json(&schema, &payload).expect("encode argument record"),
        );
        RECORD_DECODE_COUNT.with(|count| count.set(0));
        let prepared =
            prepare_argument_record_with_gas_limit(&schema, Arc::clone(&canonical), u64::MAX)
                .expect("prepare arguments");
        let shared = prepared.clone();
        assert!(core::ptr::eq(
            prepared.canonical_bytes().as_ptr(),
            shared.canonical_bytes().as_ptr(),
        ));
        let mut vm = IVM::new(u64::MAX);
        prepared
            .precharge_vm(&mut vm)
            .expect("precharge prepared arguments");
        prepared
            .install_call_arguments(&mut vm, 1)
            .expect("materialize prepared arguments");
        RECORD_DECODE_COUNT.with(|count| assert_eq!(count.get(), 1));
        let count_pointer = decoded_words(&vm)[0];
        assert_eq!(decoded_int(&vm, count_pointer), BigInt::from_i128(7));
    }
    #[test]
    fn prepared_record_rejects_substituted_record_or_schema() {
        let schema = EntrypointArgumentSchemaV1 {
            fields: vec![EntrypointArgumentFieldV1 {
                name: "count".to_owned(),
                ty: argument_type(EntrypointValueKindV1::Int),
            }],
        };
        let canonical: Arc<[u8]> = Arc::from(
            encode_argument_record_from_json(&schema, &Json::from(norito::json!({"count": "7"})))
                .unwrap(),
        );
        let prepared =
            prepare_argument_record_with_gas_limit(&schema, Arc::clone(&canonical), u64::MAX)
                .unwrap();
        assert!(prepared.is_bound_to(&schema, &canonical).unwrap());
        let substituted_record =
            encode_argument_record_from_json(&schema, &Json::from(norito::json!({"count": "8"})))
                .unwrap();
        assert!(!prepared.is_bound_to(&schema, &substituted_record).unwrap());
        let mut substituted_schema = schema.clone();
        substituted_schema.fields[0].name = "other".to_owned();
        assert_eq!(
            canonical_norito_frame_len(&schema),
            canonical_norito_frame_len(&substituted_schema)
        );
        assert!(
            !prepared
                .is_bound_to(&substituted_schema, &canonical)
                .unwrap(),
            "same-length schema substitution must fail exact identity before root installation"
        );
    }
    #[test]
    fn unaffordable_preparation_rejects_before_canonical_record_decode() {
        let schema = EntrypointArgumentSchemaV1 {
            fields: vec![EntrypointArgumentFieldV1 {
                name: "payload".to_owned(),
                ty: argument_type(EntrypointValueKindV1::String),
            }],
        };
        let canonical: Arc<[u8]> = Arc::from(
            encode_argument_record_from_json(
                &schema,
                &Json::from(norito::json!({ "payload": "meter me first" })),
            )
            .expect("encode argument record"),
        );
        let quote = prepared_gas_bound(&schema, canonical.len());
        RECORD_DECODE_COUNT.with(|count| count.set(0));
        assert!(matches!(
            prepare_argument_record_with_gas_limit(
                &schema,
                Arc::clone(&canonical),
                quote.saturating_sub(1),
            ),
            Err(VMError::OutOfGas)
        ));
        RECORD_DECODE_COUNT.with(|count| assert_eq!(count.get(), 0));
        prepare_argument_record_with_gas_limit(&schema, canonical, quote)
            .expect("the exact conservative preparation quote is affordable");
        RECORD_DECODE_COUNT.with(|count| assert_eq!(count.get(), 1));
    }
    #[test]
    fn allocation_free_schema_length_matches_canonical_norito_frame() {
        let schema = EntrypointArgumentSchemaV1 {
            fields: vec![
                EntrypointArgumentFieldV1 {
                    name: "count".to_owned(),
                    ty: argument_type(EntrypointValueKindV1::Int),
                },
                EntrypointArgumentFieldV1 {
                    name: "payload".to_owned(),
                    ty: argument_type(EntrypointValueKindV1::Blob),
                },
            ],
        };
        let canonical = canonical_norito_frame(&schema).expect("encode canonical schema");
        assert_eq!(canonical_norito_frame_len(&schema), canonical.len());
        let alternate_flags =
            norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
        let _ambient_flags = norito::core::DecodeFlagsGuard::enter(alternate_flags);
        assert_eq!(
            canonical_norito_frame_len(&schema),
            canonical.len(),
            "compiler-owned schema admission must ignore an ambient decode layout"
        );
        assert_eq!(
            canonical_norito_frame(&schema).expect("re-encode canonical schema"),
            canonical,
            "compiler-owned schema bytes must ignore an ambient decode layout"
        );
    }
    #[test]
    fn canonical_argument_boundary_ignores_ambient_norito_layout_flags() {
        let schema = EntrypointArgumentSchemaV1 {
            fields: vec![EntrypointArgumentFieldV1 {
                name: "value".to_owned(),
                ty: EntrypointValueTypeV1 {
                    nodes: vec![
                        EntrypointValueTypeNodeV1::Result,
                        EntrypointValueTypeNodeV1::List(EntrypointListTypeNodeV1 { capacity: 2 }),
                        EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::String),
                        EntrypointValueTypeNodeV1::Tuple(2),
                        EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int),
                        EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int),
                    ],
                },
            }],
        };
        let payload = Json::from(norito::json!({
            "value": { "err": ["7", "9"] }
        }));
        let expected_schema = canonical_norito_frame(&schema).expect("canonical schema");
        let expected_record =
            encode_argument_record_from_json(&schema, &payload).expect("canonical record");
        let alternate_flags =
            norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
        let _ambient = norito::core::DecodeFlagsGuard::enter(alternate_flags);
        let ambient_schema = to_bytes(&schema).expect("ambient-layout schema");
        assert_ne!(
            ambient_schema, expected_schema,
            "the adversarial ambient layout must exercise a distinct encoding"
        );
        assert_eq!(
            canonical_norito_frame(&schema).expect("pinned canonical schema"),
            expected_schema
        );
        assert_eq!(canonical_norito_frame_len(&schema), expected_schema.len());
        assert_eq!(
            encode_argument_record_from_json(&schema, &payload).expect("pinned canonical record"),
            expected_record
        );
        let prepared = prepare_argument_record_with_gas_limit(
            &schema,
            Arc::from(expected_record.clone()),
            u64::MAX,
        )
        .expect("prepare under adversarial ambient layout");
        assert_eq!(prepared.schema_bytes(), expected_schema);
        assert!(
            prepared
                .is_bound_to(&schema, &expected_record)
                .expect("compare a canonical prepared binding"),
            "ambient Norito flags must not invalidate the canonical prepared binding"
        );
        let mut changed_record = expected_record.clone();
        changed_record.push(0);
        assert!(
            !prepared
                .is_bound_to(&schema, &changed_record)
                .expect("compare a substituted record binding"),
            "different canonical record bytes must never reuse the prepared plan"
        );
        validate_argument_record(&schema, &expected_record)
            .expect("validate under adversarial ambient layout");
        assert_eq!(
            to_bytes(&schema).expect("ambient layout after canonical operations"),
            ambient_schema,
            "nested canonical framing must restore the caller's ambient Norito layout"
        );
    }
    #[test]
    fn canonical_validator_rejects_semantically_equivalent_alternate_norito_layout() {
        let schema = EntrypointArgumentSchemaV1 {
            fields: vec![EntrypointArgumentFieldV1 {
                name: "values".to_owned(),
                ty: list_type(2, argument_type(EntrypointValueKindV1::String)),
            }],
        };
        let record = argument_record_from_json(
            &schema,
            &Json::from(norito::json!({ "values": ["first", "second"] })),
        )
        .expect("build canonical semantic record");
        let canonical = canonical_norito_frame(&record).expect("encode canonical record");
        validate_argument_record(&schema, &canonical).expect("accept canonical record");
        let alternate_flags =
            norito::core::default_encode_flags() ^ norito::core::header_flags::COMPACT_LEN;
        let alternate = {
            let _ambient = norito::core::DecodeFlagsGuard::enter(alternate_flags);
            to_bytes(&record).expect("encode alternate-layout record")
        };
        assert_ne!(
            alternate, canonical,
            "the fixture must exercise a distinct noncanonical Norito layout"
        );
        assert_eq!(
            decode_from_bytes::<EntrypointArgumentRecordV1>(&alternate)
                .expect("decode alternate-layout record by its advertised flags"),
            record,
            "the alternate bytes must represent the same semantic record"
        );
        assert!(
            matches!(
                validate_argument_record(&schema, &alternate),
                Err(VMError::DecodeError)
            ),
            "the V1 boundary must reject noncanonical bytes even when Norito can decode them"
        );
    }
    #[test]
    fn large_prepared_argument_spills_to_heap_without_input_arena_trap() {
        let schema = EntrypointArgumentSchemaV1 {
            fields: vec![EntrypointArgumentFieldV1 {
                name: "payload".to_owned(),
                ty: argument_type(EntrypointValueKindV1::String),
            }],
        };
        let large = "x".repeat((crate::memory::Memory::INPUT_SIZE as usize) * 2);
        let canonical: Arc<[u8]> = Arc::from(
            encode_argument_record_from_json(
                &schema,
                &Json::from(norito::json!({ "payload": large })),
            )
            .expect("encode large argument record"),
        );
        let prepared = prepare_argument_record_with_gas_limit(&schema, canonical, u64::MAX)
            .expect("prepare large record");
        let mut vm = IVM::new(u64::MAX);
        prepared
            .precharge_vm(&mut vm)
            .expect("precharge large prepared value");
        prepared
            .install_call_arguments(&mut vm, 1)
            .expect("large prepared value must use bounded HEAP spill");
        assert!(
            (crate::memory::Memory::HEAP_START..crate::memory::Memory::INPUT_START)
                .contains(&vm.register(10)),
            "call tables always use owned HEAP"
        );
        let words = decoded_words(&vm);
        assert_eq!(words.len(), 1);
        assert!(
            (crate::memory::Memory::HEAP_START..crate::memory::Memory::INPUT_START)
                .contains(&words[0]),
            "the typed value larger than INPUT must be materialized in owned HEAP"
        );
    }
    #[test]
    fn exact_wire_cap_record_is_admitted_and_materialized() {
        let schema = EntrypointArgumentSchemaV1 {
            fields: vec![EntrypointArgumentFieldV1 {
                name: "payload".to_owned(),
                ty: argument_type(EntrypointValueKindV1::Blob),
            }],
        };
        let schema_bytes = to_bytes(&schema).expect("encode schema");
        let mut payload_len = MAX_ENTRYPOINT_ARGUMENT_RECORD_BYTES.saturating_sub(256);
        let mut canonical = Vec::new();
        for _ in 0..8 {
            let envelope = encode_tlv(PointerType::Blob, &vec![0x5A; payload_len])
                .expect("encode exact-bound blob envelope");
            canonical = to_bytes(&EntrypointArgumentRecordV1 {
                schema_hash: entrypoint_argument_schema_hash_v1(&schema_bytes),
                atoms: vec![EntrypointValueAtomV1::Pointer(envelope)],
            })
            .expect("encode exact-bound record");
            match canonical.len().cmp(&MAX_ENTRYPOINT_ARGUMENT_RECORD_BYTES) {
                core::cmp::Ordering::Equal => break,
                core::cmp::Ordering::Less => {
                    payload_len = payload_len
                        .saturating_add(MAX_ENTRYPOINT_ARGUMENT_RECORD_BYTES - canonical.len());
                }
                core::cmp::Ordering::Greater => {
                    payload_len = payload_len
                        .saturating_sub(canonical.len() - MAX_ENTRYPOINT_ARGUMENT_RECORD_BYTES);
                }
            }
        }
        assert_eq!(
            canonical.len(),
            MAX_ENTRYPOINT_ARGUMENT_RECORD_BYTES,
            "the fixture must exercise the inclusive signed wire boundary"
        );
        let gas_bound = prepared_gas_bound(&schema, canonical.len());
        let prepared =
            prepare_argument_record_with_gas_limit(&schema, Arc::from(canonical), gas_bound)
                .expect("the exact V1 wire cap must be executable at its schema-derived gas bound");
        let mut vm = IVM::new(u64::MAX);
        prepared
            .precharge_vm(&mut vm)
            .expect("precharge exact-cap prepared value");
        prepared
            .install_call_arguments(&mut vm, 1)
            .expect("exact-cap pointer atom and word table fit the V1 VM resource envelope");
        let words = decoded_words(&vm);
        assert_eq!(words.len(), 1);
        assert!(
            (crate::memory::Memory::HEAP_START..crate::memory::Memory::INPUT_START)
                .contains(&words[0])
        );
    }
    #[test]
    fn materialization_preflight_prevents_partial_allocation_on_oom() {
        let schema = EntrypointArgumentSchemaV1 {
            fields: vec![
                EntrypointArgumentFieldV1 {
                    name: "small".to_owned(),
                    ty: argument_type(EntrypointValueKindV1::String),
                },
                EntrypointArgumentFieldV1 {
                    name: "large".to_owned(),
                    ty: argument_type(EntrypointValueKindV1::String),
                },
            ],
        };
        let large = "x".repeat((crate::memory::Memory::INPUT_SIZE as usize) * 2);
        let canonical: Arc<[u8]> = Arc::from(
            encode_argument_record_from_json(
                &schema,
                &Json::from(norito::json!({ "small": "fits-input", "large": large })),
            )
            .expect("encode large argument record"),
        );
        let prepared = prepare_argument_record_with_gas_limit(&schema, canonical, u64::MAX)
            .expect("prepare large record");
        let mut vm = IVM::new(u64::MAX);
        prepared
            .precharge_vm(&mut vm)
            .expect("precharge prepared value");
        vm.memory
            .set_heap_limit(crate::memory::Memory::INPUT_SIZE)
            .expect("constrain test heap");
        let mut allocation_control = vm.try_clone_snapshot().expect("fund VM snapshot");
        assert!(matches!(
            prepared.install_call_arguments(&mut vm, 1),
            Err(VMError::OutOfMemory)
        ));
        assert_eq!(
            vm.memory.heap_allocated_len(),
            0,
            "capacity failure must occur before the first guest-visible allocation"
        );
        assert_eq!(vm.register(10), 0);
        assert_eq!(vm.register(11), 0);
        let sentinel = encode_tlv(PointerType::Blob, b"after-preflight").expect("encode sentinel");
        assert_eq!(
            vm.alloc_input_tlv(&sentinel)
                .expect("allocate after failed preflight"),
            allocation_control
                .alloc_input_tlv(&sentinel)
                .expect("allocate in untouched control"),
            "capacity rejection must not consume INPUT for an earlier small pointer"
        );
    }
    #[test]
    fn materialization_preflight_combines_tlv_spill_and_list_heap_capacity() {
        let schema = EntrypointArgumentSchemaV1 {
            fields: vec![EntrypointArgumentFieldV1 {
                name: "values".to_owned(),
                ty: list_type(8, argument_type(EntrypointValueKindV1::String)),
            }],
        };
        let canonical: Arc<[u8]> = Arc::from(
            encode_argument_record_from_json(
                &schema,
                &Json::from(norito::json!({ "values": ["heap-spill"] })),
            )
            .expect("encode list argument record"),
        );
        let prepared = prepare_argument_record_with_gas_limit(&schema, canonical, u64::MAX)
            .expect("prepare list argument record");
        let mut vm = IVM::new(u64::MAX);
        vm.alloc_input_tlv(&vec![0_u8; crate::memory::Memory::INPUT_SIZE as usize])
            .expect("fill INPUT exactly");
        let plan = &prepared.inner.decode_plan;
        let raw_heap_bytes = plan.raw_heap_bytes() + 8; // One reserved root result word.
        let spilled_tlv_bytes = plan
            .allocation_lengths()
            .into_iter()
            .map(|length| {
                u64::try_from(length)
                    .expect("bounded TLV length")
                    .checked_add(7)
                    .expect("bounded aligned TLV length")
                    & !7
            })
            .sum::<u64>();
        assert!(raw_heap_bytes > 0 && spilled_tlv_bytes > 0);
        let baseline = vm.memory.heap_allocated_len();
        let exact_combined_limit = baseline
            .checked_add(raw_heap_bytes)
            .and_then(|limit| limit.checked_add(spilled_tlv_bytes))
            .expect("bounded combined capacity");
        let mut exact_vm = vm.try_clone_snapshot().expect("fund VM snapshot");
        exact_vm
            .memory
            .set_heap_limit(exact_combined_limit)
            .expect("set exact combined HEAP capacity");
        prepared
            .precharge_vm(&mut exact_vm)
            .expect("precharge exact-capacity VM after cloning");
        prepared
            .install_call_arguments(&mut exact_vm, 1)
            .expect("the exact combined HEAP limit must be inclusive");
        assert_eq!(exact_vm.memory.heap_allocated_len(), exact_combined_limit);
        vm.memory
            .set_heap_limit(exact_combined_limit - 1)
            .expect("constrain combined HEAP capacity by one byte");
        prepared
            .precharge_vm(&mut vm)
            .expect("precharge constrained VM");
        let mut allocation_control = vm.try_clone_snapshot().expect("fund VM snapshot");
        assert!(matches!(
            prepared.install_call_arguments(&mut vm, 1),
            Err(VMError::OutOfMemory)
        ));
        assert_eq!(vm.memory.heap_allocated_len(), baseline);
        assert_eq!((vm.register(10), vm.register(11)), (0, 0));
        let sentinel =
            encode_tlv(PointerType::Blob, b"after-combined-preflight").expect("encode sentinel");
        assert_eq!(
            vm.alloc_host_tlv(&sentinel)
                .expect("allocate after combined preflight failure"),
            allocation_control
                .alloc_host_tlv(&sentinel)
                .expect("allocate in untouched control"),
            "combined capacity rejection must precede every output allocation"
        );
    }
    #[test]
    fn prepared_outputs_spill_pointer_and_word_table_to_owned_heap() {
        let schema = EntrypointArgumentSchemaV1 {
            fields: vec![EntrypointArgumentFieldV1 {
                name: "payload".to_owned(),
                ty: argument_type(EntrypointValueKindV1::String),
            }],
        };
        let canonical: Arc<[u8]> = Arc::from(
            encode_argument_record_from_json(
                &schema,
                &Json::from(norito::json!({ "payload": "heap-owned" })),
            )
            .expect("encode argument record"),
        );
        let prepared = prepare_argument_record_with_gas_limit(&schema, canonical, u64::MAX)
            .expect("prepare arguments");
        let mut vm = IVM::new(u64::MAX);
        vm.alloc_input_tlv(&vec![0_u8; crate::memory::Memory::INPUT_SIZE as usize])
            .expect("fill INPUT exactly");
        prepared
            .precharge_vm(&mut vm)
            .expect("precharge prepared arguments");
        prepared
            .install_call_arguments(&mut vm, 1)
            .expect("spill the complete result sequence to HEAP");
        assert!(
            (crate::memory::Memory::HEAP_START..crate::memory::Memory::INPUT_START)
                .contains(&vm.register(10)),
            "the decoded word table must be in the owned HEAP prefix"
        );
        let words = decoded_words(&vm);
        assert_eq!(words.len(), 1);
        assert!(
            (crate::memory::Memory::HEAP_START..crate::memory::Memory::INPUT_START)
                .contains(&words[0]),
            "the decoded pointer TLV must be in the owned HEAP prefix"
        );
    }
    #[test]
    fn raw_argument_record_decoder_accepts_heap_backed_record_and_schema() {
        let schema = EntrypointArgumentSchemaV1 {
            fields: vec![EntrypointArgumentFieldV1 {
                name: "payload".to_owned(),
                ty: argument_type(EntrypointValueKindV1::String),
            }],
        };
        let record = encode_argument_record_from_json(
            &schema,
            &Json::from(norito::json!({ "payload": "heap-input" })),
        )
        .expect("encode argument record");
        let record_envelope =
            encode_tlv(PointerType::NoritoBytes, &record).expect("encode record TLV");
        let schema_envelope = encode_tlv(
            PointerType::NoritoBytes,
            &to_bytes(&schema).expect("encode schema"),
        )
        .expect("encode schema TLV");
        let mut vm = IVM::new(u64::MAX);
        let record_pointer = vm
            .alloc_heap(u64::try_from(record_envelope.len()).expect("record length fits u64"))
            .expect("allocate HEAP record");
        vm.store_bytes(record_pointer, &record_envelope)
            .expect("store HEAP record");
        let schema_pointer = vm
            .alloc_heap(u64::try_from(schema_envelope.len()).expect("schema length fits u64"))
            .expect("allocate HEAP schema");
        vm.store_bytes(schema_pointer, &schema_envelope)
            .expect("store HEAP schema");
        vm.set_register(10, record_pointer);
        vm.set_register(11, schema_pointer);
        let quote = decode_argument_record_gas_quote(&vm).expect("quote HEAP arguments");
        let actual = decode_argument_record(&mut vm).expect("decode HEAP arguments");
        assert!(actual <= quote);
        let words = decoded_words(&vm);
        assert_eq!(words.len(), 1);
        let value = vm.validate_tlv(words[0]).expect("materialized string TLV");
        assert_eq!(value.type_id, PointerType::Blob);
        assert_eq!(value.payload, b"heap-input");
    }
    #[test]
    fn raw_argument_record_decoder_rejects_forged_pointer_regions_before_output() {
        let schema = EntrypointArgumentSchemaV1 {
            fields: vec![EntrypointArgumentFieldV1 {
                name: "count".to_owned(),
                ty: argument_type(EntrypointValueKindV1::Int),
            }],
        };
        let record =
            encode_argument_record_from_json(&schema, &Json::from(norito::json!({ "count": "7" })))
                .expect("encode argument record");
        let record_envelope =
            encode_tlv(PointerType::NoritoBytes, &record).expect("encode record TLV");
        let schema_envelope = encode_tlv(
            PointerType::NoritoBytes,
            &to_bytes(&schema).expect("encode schema"),
        )
        .expect("encode schema TLV");
        for (label, pointer) in [
            ("unallocated HEAP", crate::memory::Memory::HEAP_START),
            ("OUTPUT", crate::memory::Memory::OUTPUT_START),
            ("stack", crate::memory::Memory::STACK_START),
        ] {
            let mut vm = IVM::new(u64::MAX);
            vm.store_bytes(pointer, &record_envelope)
                .unwrap_or_else(|error| panic!("store {label} record: {error:?}"));
            let schema_pointer = vm
                .alloc_input_tlv(&schema_envelope)
                .expect("allocate schema fixture");
            vm.set_register(10, pointer);
            vm.set_register(11, schema_pointer);
            let registers_before = [vm.register(10), vm.register(11)];
            let writes_before = vm
                .memory
                .try_write_log_snapshot()
                .expect("allocate write-log snapshot");
            assert!(
                matches!(
                    decode_argument_record_gas_quote(&vm),
                    Err(VMError::NoritoInvalid)
                ),
                "{label} must fail during header-only preparation"
            );
            assert!(matches!(
                decode_argument_record(&mut vm),
                Err(VMError::NoritoInvalid)
            ));
            assert_eq!([vm.register(10), vm.register(11)], registers_before);
            assert_eq!(
                vm.memory
                    .try_write_log_snapshot()
                    .expect("allocate write-log snapshot"),
                writes_before
            );
        }
        let mut partial_vm = IVM::new(u64::MAX);
        let owned_record_bytes = record_envelope
            .len()
            .checked_sub(8)
            .expect("record envelope exceeds one HEAP alignment unit");
        let partial_pointer = partial_vm
            .alloc_heap(u64::try_from(owned_record_bytes).expect("partial record length fits u64"))
            .expect("allocate truncated HEAP record range");
        partial_vm
            .store_bytes(partial_pointer, &record_envelope)
            .expect("store across unowned HEAP boundary");
        let schema_pointer = partial_vm
            .alloc_input_tlv(&schema_envelope)
            .expect("allocate partial-case schema");
        partial_vm.set_register(10, partial_pointer);
        partial_vm.set_register(11, schema_pointer);
        assert!(matches!(
            decode_argument_record(&mut partial_vm),
            Err(VMError::NoritoInvalid)
        ));
        let mut corrupted_vm = IVM::new(u64::MAX);
        let mut corrupted = record_envelope;
        let last = corrupted.len() - 1;
        corrupted[last] ^= 1;
        let record_pointer = corrupted_vm
            .alloc_input_tlv(&corrupted)
            .expect("allocate corrupted record");
        let schema_pointer = corrupted_vm
            .alloc_input_tlv(&schema_envelope)
            .expect("allocate corrupted-case schema");
        corrupted_vm.set_register(10, record_pointer);
        corrupted_vm.set_register(11, schema_pointer);
        decode_argument_record_gas_quote(&corrupted_vm)
            .expect("hash corruption is intentionally checked after bounded preparation");
        assert!(matches!(
            decode_argument_record(&mut corrupted_vm),
            Err(VMError::NoritoInvalid)
        ));
    }
    #[test]
    fn canonical_v1_scalars_and_typed_ids_roundtrip() {
        let account = AccountId::new(
            "ed012059C8A4DA1EBB5380F74ABA51F502714652FDCCE9611FAFB9904E4A3C4D382774"
                .parse()
                .expect("fixture public key"),
        );
        let mut definition_bytes = [0x11; 16];
        definition_bytes[6] = 0x41;
        definition_bytes[8] = 0x81;
        let definition = AssetDefinitionId::from_uuid_bytes(definition_bytes)
            .expect("fixture UUIDv4 asset definition");
        let asset = AssetId::new(definition.clone(), account.clone());
        let domain = DomainId::try_new("wonderland", "universal").expect("fixture domain");
        let nft = NftId::new(
            domain.clone(),
            "collectible".parse().expect("fixture NFT name"),
        );
        let dataspace = DataSpaceId::new(u64::MAX);
        let wide = BigInt::from(u128::MAX);
        let account_literal = account.canonical_i105().expect("canonical account literal");
        let definition_literal = definition.canonical_address();
        let asset_literal = asset.canonical_literal();
        let domain_literal = domain.to_string();
        let nft_literal = nft.to_string();
        let wide_literal = wide.to_string();
        let schema = EntrypointArgumentSchemaV1 {
            fields: vec![
                EntrypointArgumentFieldV1 {
                    name: "ready".to_owned(),
                    ty: argument_type(EntrypointValueKindV1::Bool),
                },
                EntrypointArgumentFieldV1 {
                    name: "memo".to_owned(),
                    ty: argument_type(EntrypointValueKindV1::String),
                },
                EntrypointArgumentFieldV1 {
                    name: "wide".to_owned(),
                    ty: argument_type(EntrypointValueKindV1::Int),
                },
                EntrypointArgumentFieldV1 {
                    name: "account".to_owned(),
                    ty: argument_type(EntrypointValueKindV1::AccountId),
                },
                EntrypointArgumentFieldV1 {
                    name: "definition".to_owned(),
                    ty: argument_type(EntrypointValueKindV1::AssetDefinitionId),
                },
                EntrypointArgumentFieldV1 {
                    name: "asset".to_owned(),
                    ty: argument_type(EntrypointValueKindV1::AssetId),
                },
                EntrypointArgumentFieldV1 {
                    name: "domain".to_owned(),
                    ty: argument_type(EntrypointValueKindV1::DomainId),
                },
                EntrypointArgumentFieldV1 {
                    name: "nft".to_owned(),
                    ty: argument_type(EntrypointValueKindV1::NftId),
                },
                EntrypointArgumentFieldV1 {
                    name: "dataspace".to_owned(),
                    ty: argument_type(EntrypointValueKindV1::DataSpaceId),
                },
            ],
        };
        let payload = Json::from(norito::json!({
            "ready": true,
            "memo": "言霊",
            "wide": wide_literal,
            "account": account_literal,
            "definition": definition_literal,
            "asset": asset_literal,
            "domain": domain_literal,
            "nft": nft_literal,
            "dataspace": (dataspace.as_u64()),
        }));
        let mut vm = install_record(&schema, &payload);
        decode_argument_record(&mut vm).expect("decode canonical V1 arguments");
        let words = decoded_words(&vm);
        assert_eq!(words.len(), schema.fields.len());
        assert_eq!(words[0], 1);
        let string = vm.validate_tlv(words[1]).expect("string TLV");
        assert_eq!(string.type_id, PointerType::Blob);
        assert_eq!(string.payload, "言霊".as_bytes());
        assert_eq!(decoded_int(&vm, words[2]), wide);
        let account_tlv = vm.validate_tlv(words[3]).expect("AccountId TLV");
        assert_eq!(account_tlv.type_id, PointerType::AccountId);
        assert_eq!(
            decode_from_bytes::<AccountId>(account_tlv.payload).expect("decode AccountId"),
            account
        );
        let definition_tlv = vm.validate_tlv(words[4]).expect("AssetDefinitionId TLV");
        assert_eq!(definition_tlv.type_id, PointerType::AssetDefinitionId);
        assert_eq!(
            decode_from_bytes::<AssetDefinitionId>(definition_tlv.payload)
                .expect("decode AssetDefinitionId"),
            definition
        );
        let asset_tlv = vm.validate_tlv(words[5]).expect("AssetId TLV");
        assert_eq!(asset_tlv.type_id, PointerType::AssetId);
        assert_eq!(
            decode_from_bytes::<AssetId>(asset_tlv.payload).expect("decode AssetId"),
            asset
        );
        let domain_tlv = vm.validate_tlv(words[6]).expect("DomainId TLV");
        assert_eq!(domain_tlv.type_id, PointerType::DomainId);
        assert_eq!(
            decode_from_bytes::<DomainId>(domain_tlv.payload).expect("decode DomainId"),
            domain
        );
        let nft_tlv = vm.validate_tlv(words[7]).expect("NftId TLV");
        assert_eq!(nft_tlv.type_id, PointerType::NftId);
        assert_eq!(
            decode_from_bytes::<NftId>(nft_tlv.payload).expect("decode NftId"),
            nft
        );
        let dataspace_tlv = vm.validate_tlv(words[8]).expect("DataSpaceId TLV");
        assert_eq!(dataspace_tlv.type_id, PointerType::DataSpaceId);
        assert_eq!(
            decode_from_bytes::<DataSpaceId>(dataspace_tlv.payload).expect("decode DataSpaceId"),
            dataspace
        );
    }
    #[test]
    fn recursive_struct_tuple_option_and_result_decode_in_one_pass() {
        let schema = EntrypointArgumentSchemaV1 {
            fields: vec![EntrypointArgumentFieldV1 {
                name: "request".into(),
                ty: EntrypointValueTypeV1 {
                    nodes: vec![
                        EntrypointValueTypeNodeV1::Struct(
                            ivm_abi::entrypoint::EntrypointStructTypeNodeV1 {
                                name: "Fixture::Request".into(),
                                fields: vec!["pair".into(), "memo".into(), "outcome".into()],
                            },
                        ),
                        EntrypointValueTypeNodeV1::Tuple(2),
                        EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int),
                        EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Bool),
                        EntrypointValueTypeNodeV1::Option,
                        EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::String),
                        EntrypointValueTypeNodeV1::Result,
                        EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Name),
                        EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Bool),
                    ],
                },
            }],
        };
        assert_eq!(schema.word_count(), Some(4));
        let payload = Json::from(norito::json!({
            "request": {
                "pair": ["7", true],
                "memo": { "some": "言霊" },
                "outcome": { "err": true },
            },
        }));
        RECORD_DECODE_COUNT.with(|count| count.set(0));
        let mut vm = install_record(&schema, &payload);
        decode_argument_record(&mut vm).expect("decode recursive argument");
        RECORD_DECODE_COUNT.with(|count| assert_eq!(count.get(), 1));
        let words = decoded_words(&vm);
        assert_eq!(words.len(), 4);
        assert_eq!(decoded_int(&vm, words[0]), BigInt::from_i128(7));
        assert_eq!(words[1], 1);
        let (some, memo) = crate::sum::read_words(
            &vm,
            words[2],
            SumLayoutV1::option(1).expect("Option layout"),
        )
        .expect("read Option");
        assert!(some);
        assert_eq!(memo.len(), 1);
        let memo = vm.validate_tlv(memo[0]).expect("memo string TLV");
        assert_eq!(memo.type_id, PointerType::Blob);
        assert_eq!(memo.payload, "言霊".as_bytes());
        let (ok, outcome) = crate::sum::read_words(
            &vm,
            words[3],
            SumLayoutV1::try_new(1, 1).expect("Result layout"),
        )
        .expect("read Result");
        assert!(!ok);
        assert_eq!(outcome, vec![1]);
    }
    #[test]
    fn nested_quantity_lists_materialize_as_one_schema_bound_sequence() {
        let quantity = argument_type(EntrypointValueKindV1::Quantity);
        let inner = list_type(2, quantity);
        let schema = EntrypointArgumentSchemaV1 {
            fields: vec![EntrypointArgumentFieldV1 {
                name: "amounts".to_owned(),
                ty: list_type(2, inner),
            }],
        };
        let payload = Json::from(norito::json!({
            "amounts": [["1.25"], ["2"]],
        }));
        let mut vm = install_record(&schema, &payload);
        decode_argument_record(&mut vm).expect("decode nested quantity list");
        let words = decoded_words(&vm);
        assert_eq!(words.len(), 1, "a bounded list is one VM handle");
        let outer_layout = ListLayoutV1::try_new(2, 1).expect("outer layout");
        let outer = crate::list::read_words(&vm, words[0], outer_layout).expect("read outer list");
        assert_eq!(outer.len(), 2);
        for item in outer {
            let inner_layout = ListLayoutV1::try_new(2, 1).expect("inner layout");
            let inner =
                crate::list::read_words(&vm, item[0], inner_layout).expect("read inner list");
            assert_eq!(inner.len(), 1, "inner list must contain one element");
            assert_eq!(
                inner[0].len(),
                1,
                "inner list element must contain one quantity pointer word"
            );
            let quantity = vm.validate_tlv(inner[0][0]).expect("valid quantity TLV");
            assert_eq!(quantity.type_id, PointerType::Quantity);
            QuantityValueV1::decode_frame(quantity.payload).expect("decode canonical quantity");
        }
        let overflow = Json::from(norito::json!({
            "amounts": [[], [], []],
        }));
        assert!(matches!(
            argument_record_from_json(&schema, &overflow),
            Err(VMError::DecodeError)
        ));
    }
    #[test]
    fn maximum_flat_list_depth_decodes_validates_and_materializes_on_the_test_thread() {
        let levels = MAX_ENTRYPOINT_ARGUMENT_TYPE_DEPTH - 1;
        let schema = EntrypointArgumentSchemaV1 {
            fields: vec![EntrypointArgumentFieldV1 {
                name: "value".to_owned(),
                ty: nested_list_type(levels),
            }],
        };
        assert!(schema.validate());
        // Logical type depth is represented by a flat tape, independently of
        // the JSON boundary's smaller structural nesting budget.
        let schema_bytes = canonical_norito_frame(&schema).expect("encode maximum-depth schema");
        let mut atoms = vec![EntrypointValueAtomV1::List(1); levels];
        atoms.push(int_atom(7));
        let record = EntrypointArgumentRecordV1 {
            schema_hash: entrypoint_argument_schema_hash_v1(&schema_bytes),
            atoms,
        };
        let encoded = canonical_norito_frame(&record).expect("encode maximum-depth flat tape");
        assert_eq!(
            (validate_argument_record(&schema, &encoded))
                .expect("expected successful fixture result"),
            record.clone()
        );
        let mut vm = install_raw_record(&schema, &record);
        decode_argument_record(&mut vm).expect("materialize the exact V1 nesting boundary");
        let mut word = decoded_words(&vm)[0];
        let layout = ListLayoutV1::try_new(1, 1).expect("unit-width list layout");
        for _ in 0..levels {
            let items =
                crate::list::read_words(&vm, word, layout).expect("read one nested list level");
            assert_eq!(items.len(), 1);
            assert_eq!(items[0].len(), 1);
            word = items[0][0];
        }
        assert_eq!(decoded_int(&vm, word), BigInt::from_i128(7));
        let over_limit = EntrypointArgumentSchemaV1 {
            fields: vec![EntrypointArgumentFieldV1 {
                name: "value".to_owned(),
                ty: nested_list_type(MAX_ENTRYPOINT_ARGUMENT_TYPE_DEPTH),
            }],
        };
        assert!(!over_limit.validate());
        assert!(matches!(
            validate_argument_record(&over_limit, &encoded),
            Err(VMError::DecodeError)
        ));
        assert!(matches!(
            argument_record_from_json(&over_limit, &Json::from(norito::json!({ "value": [] }))),
            Err(VMError::DecodeError)
        ));
    }
    #[test]
    fn json_list_nesting_boundary_produces_a_flat_record_and_rejects_one_more_level() {
        // An object envelope and terminal string each consume one JSON level.
        let levels = njson::MAX_JSON_VALUE_NESTING_DEPTH - 2;
        let schema = EntrypointArgumentSchemaV1 {
            fields: vec![EntrypointArgumentFieldV1 {
                name: "value".to_owned(),
                ty: nested_list_type(levels),
            }],
        };
        let input = format!(
            r#"{{"value":{}"7"{}}}"#,
            "[".repeat(levels),
            "]".repeat(levels)
        );
        let payload: Json = input.parse().expect("maximum-depth JSON argument");
        let record =
            argument_record_from_json(&schema, &payload).expect("convert JSON to flat tape");
        assert_eq!(record.atoms.len(), levels + 1);
        assert!(
            record.atoms[..levels]
                .iter()
                .all(|atom| *atom == EntrypointValueAtomV1::List(1))
        );
        assert_eq!(record.atoms.last(), Some(&int_atom(7)));
        let encoded = canonical_norito_frame(&record).expect("encode converted flat record");
        assert_eq!(
            (validate_argument_record(&schema, &encoded))
                .expect("expected successful fixture result"),
            record
        );

        let too_deep = format!(
            r#"{{"value":{}"7"{}}}"#,
            "[".repeat(levels + 1),
            "]".repeat(levels + 1),
        );
        assert!(matches!(
            njson::parse_value(&too_deep),
            Err(njson::Error::NestingDepthExceeded { depth, limit, .. })
                if depth == njson::MAX_JSON_VALUE_NESTING_DEPTH + 1
                    && limit == njson::MAX_JSON_VALUE_NESTING_DEPTH
        ));
        assert!(too_deep.parse::<Json>().is_err());
        assert!(
            argument_record_from_json(&schema, &payload).is_ok(),
            "failure restores nesting budget"
        );
    }
    #[test]
    fn flat_list_element_subtree_controls_item_width_and_rejects_trailing_atoms() {
        let tuple = EntrypointValueTypeV1 {
            nodes: vec![
                EntrypointValueTypeNodeV1::Tuple(2),
                EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int),
                EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Bool),
            ],
        };
        let schema = EntrypointArgumentSchemaV1 {
            fields: vec![EntrypointArgumentFieldV1 {
                name: "pairs".to_owned(),
                ty: list_type(2, tuple),
            }],
        };
        let payload = Json::from(norito::json!({
            "pairs": [["7", true], ["9", false]],
        }));
        let record = argument_record_from_json(&schema, &payload).expect("encode flat list tape");
        assert_eq!(
            record.atoms,
            vec![
                EntrypointValueAtomV1::List(2),
                int_atom(7),
                EntrypointValueAtomV1::Bool(true),
                int_atom(9),
                EntrypointValueAtomV1::Bool(false),
            ],
            "list items must live inline in the record's single preorder atom tape",
        );
        let mut vm = install_record(&schema, &payload);
        decode_argument_record(&mut vm).expect("decode flat list element subtree");
        let table = decoded_words(&vm);
        assert_eq!(table.len(), 1, "the list itself is one ABI word");
        let pairs = crate::list::read_words(
            &vm,
            table[0],
            ListLayoutV1::try_new(2, 2).expect("pair-list layout"),
        )
        .expect("read contiguous pair list");
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0][1], 1);
        assert_eq!(pairs[1][1], 0);
        assert_eq!(decoded_int(&vm, pairs[0][0]), BigInt::from_i128(7));
        assert_eq!(decoded_int(&vm, pairs[1][0]), BigInt::from_i128(9));
        let schema_bytes = to_bytes(&schema).expect("encode pair-list schema");
        let schema_hash = entrypoint_argument_schema_hash_v1(&schema_bytes);
        for (label, atoms) in [
            (
                "trailing atom",
                vec![
                    EntrypointValueAtomV1::List(1),
                    int_atom(7),
                    EntrypointValueAtomV1::Bool(true),
                    int_atom(99),
                ],
            ),
            (
                "missing atom",
                vec![EntrypointValueAtomV1::List(1), int_atom(7)],
            ),
            (
                "wrong atom kind",
                vec![
                    EntrypointValueAtomV1::List(1),
                    EntrypointValueAtomV1::Bool(true),
                    EntrypointValueAtomV1::Bool(false),
                ],
            ),
            (
                "capacity overflow",
                vec![
                    EntrypointValueAtomV1::List(3),
                    int_atom(1),
                    EntrypointValueAtomV1::Bool(true),
                    int_atom(2),
                    EntrypointValueAtomV1::Bool(true),
                    int_atom(3),
                    EntrypointValueAtomV1::Bool(true),
                ],
            ),
            (
                "item count exceeds available elements",
                vec![
                    EntrypointValueAtomV1::List(2),
                    int_atom(1),
                    EntrypointValueAtomV1::Bool(true),
                ],
            ),
        ] {
            let record = EntrypointArgumentRecordV1 { schema_hash, atoms };
            let encoded = to_bytes(&record).expect("encode adversarial pair-list record");
            assert!(
                matches!(
                    validate_argument_record(&schema, &encoded),
                    Err(VMError::DecodeError)
                ),
                "{label} must fail closed"
            );
        }
    }
    #[test]
    fn recursive_legacy_list_record_encoding_is_rejected() {
        #[derive(norito::Encode)]
        enum LegacyAtom {
            Tag(bool),
            Int(i64),
            Bool(bool),
            Pointer(Vec<u8>),
            List(Vec<Vec<LegacyAtom>>),
        }
        #[derive(norito::Encode)]
        struct LegacyRecord {
            schema_hash: [u8; 32],
            atoms: Vec<LegacyAtom>,
        }
        let schema = EntrypointArgumentSchemaV1 {
            fields: vec![EntrypointArgumentFieldV1 {
                name: "values".to_owned(),
                ty: list_type(1, argument_type(EntrypointValueKindV1::Int)),
            }],
        };
        let schema_bytes = to_bytes(&schema).expect("encode list schema");
        let schema_hash = entrypoint_argument_schema_hash_v1(&schema_bytes);
        let canonical_record = EntrypointArgumentRecordV1 {
            schema_hash,
            atoms: vec![EntrypointValueAtomV1::List(1), int_atom(7)],
        };
        let canonical = to_bytes(&canonical_record).expect("encode flat list record");
        assert_eq!(
            (validate_argument_record(&schema, &canonical))
                .expect("expected successful fixture result"),
            canonical_record,
            "the corresponding flat list is accepted"
        );
        let legacy = LegacyRecord {
            schema_hash,
            atoms: vec![LegacyAtom::List(vec![vec![LegacyAtom::Int(7)]])],
        };
        // Advertise the real record identity so this exercises rejection of the
        // retired payload shape after frame validation, rather than a name mismatch.
        let (payload, flags) = norito::codec::encode_with_header_flags(&legacy);
        let encoded = norito::core::frame_bare_with_header_flags::<EntrypointArgumentRecordV1>(
            &payload, flags,
        )
        .expect("frame retired recursive list shape");
        let view = norito::core::from_bytes_view(&encoded).expect("valid frame and checksum");
        assert_eq!(
            view.schema(),
            norito::schema::identity::frame_hash::<EntrypointArgumentRecordV1>(),
        );
        assert_eq!(view.as_bytes(), payload);
        assert!(
            matches!(
                validate_argument_record(&schema, &encoded),
                Err(VMError::DecodeError)
            ),
            "the first release accepts only the flat list-count tape"
        );
        // Keep every retired discriminant represented so this test continues
        // to encode the exact former enum ordering instead of a lookalike.
        drop((
            LegacyAtom::Tag(false),
            LegacyAtom::Bool(false),
            LegacyAtom::Pointer(Vec::new()),
        ));
    }
    #[test]
    fn empty_flat_list_advances_past_its_element_subtree_before_a_sibling() {
        let schema = EntrypointArgumentSchemaV1 {
            fields: vec![EntrypointArgumentFieldV1 {
                name: "request".to_owned(),
                ty: EntrypointValueTypeV1 {
                    nodes: vec![
                        EntrypointValueTypeNodeV1::Struct(
                            ivm_abi::entrypoint::EntrypointStructTypeNodeV1 {
                                name: "Fixture::Request".to_owned(),
                                fields: vec!["pairs".to_owned(), "nonce".to_owned()],
                            },
                        ),
                        EntrypointValueTypeNodeV1::List(EntrypointListTypeNodeV1 { capacity: 2 }),
                        EntrypointValueTypeNodeV1::Tuple(2),
                        EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int),
                        EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Bool),
                        EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int),
                    ],
                },
            }],
        };
        let mut vm = install_record(
            &schema,
            &Json::from(norito::json!({
                "request": { "pairs": [], "nonce": "41" },
            })),
        );
        decode_argument_record(&mut vm).expect("decode empty list before product sibling");
        let words = decoded_words(&vm);
        assert_eq!(words.len(), 2);
        assert!(
            crate::list::read_words(
                &vm,
                words[0],
                ListLayoutV1::try_new(2, 2).expect("empty pair-list layout"),
            )
            .expect("read empty list")
            .is_empty(),
        );
        assert_eq!(decoded_int(&vm, words[1]), BigInt::from_i128(41));
    }
    #[test]
    fn list_of_nested_option_results_materializes_active_only_sum_handles() {
        let element = EntrypointValueTypeV1 {
            nodes: vec![
                EntrypointValueTypeNodeV1::Option,
                EntrypointValueTypeNodeV1::Result,
                EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Quantity),
                EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Bool),
            ],
        };
        let schema = EntrypointArgumentSchemaV1 {
            fields: vec![EntrypointArgumentFieldV1 {
                name: "values".to_owned(),
                ty: list_type(3, element),
            }],
        };
        let payload = Json::from(norito::json!({
            "values": [
                { "some": { "ok": "1.25" } },
                { "some": { "err": true } },
                { "none": true },
            ],
        }));
        let mut vm = install_record(&schema, &payload);
        decode_argument_record(&mut vm).expect("decode nested sums");
        let table = decoded_words(&vm);
        assert_eq!(table.len(), 1);
        let list = crate::list::read_words(
            &vm,
            table[0],
            ListLayoutV1::try_new(3, 1).expect("list layout"),
        )
        .expect("read list");
        assert_eq!(list.len(), 3);
        let option_layout = SumLayoutV1::option(1).expect("Option layout");
        let result_layout = SumLayoutV1::try_new(1, 1).expect("Result layout");
        let (some, first) =
            crate::sum::read_words(&vm, list[0][0], option_layout).expect("read first Option");
        assert!(some);
        let (ok, amount) =
            crate::sum::read_words(&vm, first[0], result_layout).expect("read first Result");
        assert!(ok);
        let quantity = vm.validate_tlv(amount[0]).expect("quantity TLV");
        assert_eq!(quantity.type_id, PointerType::Quantity);
        let quantity = QuantityValueV1::decode_frame(quantity.payload)
            .expect("decode quantity")
            .into_quantity();
        assert_eq!(
            quantity,
            "1.25".parse::<Quantity>().expect("canonical quantity")
        );
        let (some, second) =
            crate::sum::read_words(&vm, list[1][0], option_layout).expect("read second Option");
        assert!(some);
        let (ok, error) =
            crate::sum::read_words(&vm, second[0], result_layout).expect("read second Result");
        assert!(!ok);
        assert_eq!(error, vec![1]);
        let (some, none_payload) =
            crate::sum::read_words(&vm, list[2][0], option_layout).expect("read Option::none");
        assert!(!some);
        assert!(none_payload.is_empty());
        vm.store_u64(list[2][0] + 8, 99)
            .expect("forge inactive Option payload");
        assert!(matches!(
            crate::sum::read_words(&vm, list[2][0], option_layout),
            Err(VMError::DecodeError)
        ));
    }
    #[test]
    fn runtime_rejects_schema_mismatch_hidden_payload_and_malformed_pointer() {
        let option_schema = EntrypointArgumentSchemaV1 {
            fields: vec![EntrypointArgumentFieldV1 {
                name: "value".into(),
                ty: EntrypointValueTypeV1 {
                    nodes: vec![
                        EntrypointValueTypeNodeV1::Option,
                        EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int),
                    ],
                },
            }],
        };
        let option_schema_bytes = to_bytes(&option_schema).expect("option schema bytes");
        let hidden = EntrypointArgumentRecordV1 {
            schema_hash: entrypoint_argument_schema_hash_v1(&option_schema_bytes),
            atoms: vec![EntrypointValueAtomV1::Tag(false), int_atom(99)],
        };
        let mut vm = install_raw_record(&option_schema, &hidden);
        assert!(matches!(
            decode_argument_record(&mut vm),
            Err(VMError::DecodeError)
        ));
        let wrong_hash = EntrypointArgumentRecordV1 {
            schema_hash: [7; 32],
            atoms: vec![EntrypointValueAtomV1::Tag(false)],
        };
        let mut vm = install_raw_record(&option_schema, &wrong_hash);
        assert!(matches!(
            decode_argument_record(&mut vm),
            Err(VMError::DecodeError)
        ));
        let name_schema = EntrypointArgumentSchemaV1 {
            fields: vec![EntrypointArgumentFieldV1 {
                name: "value".into(),
                ty: argument_type(EntrypointValueKindV1::Name),
            }],
        };
        let name_schema_bytes = to_bytes(&name_schema).expect("Name schema bytes");
        let malformed_name = EntrypointArgumentRecordV1 {
            schema_hash: entrypoint_argument_schema_hash_v1(&name_schema_bytes),
            atoms: vec![EntrypointValueAtomV1::Pointer(
                encode_tlv(PointerType::Name, b"hash-valid but not Norito Name")
                    .expect("malformed Name envelope"),
            )],
        };
        let mut vm = install_raw_record(&name_schema, &malformed_name);
        assert!(matches!(
            decode_argument_record(&mut vm),
            Err(VMError::DecodeError)
        ));
    }
    #[test]
    fn canonical_record_rejects_trailing_truncated_and_adversarial_counts() {
        let schema = EntrypointArgumentSchemaV1 {
            fields: vec![EntrypointArgumentFieldV1 {
                name: "value".into(),
                ty: argument_type(EntrypointValueKindV1::Int),
            }],
        };
        let canonical =
            encode_argument_record_from_json(&schema, &Json::from(norito::json!({ "value": "7" })))
                .expect("canonical record");
        validate_argument_record(&schema, &canonical).expect("valid record");
        let mut trailing = canonical.clone();
        trailing.push(0);
        assert!(matches!(
            validate_argument_record(&schema, &trailing),
            Err(VMError::DecodeError)
        ));
        for end in 0..canonical.len() {
            assert!(
                matches!(
                    validate_argument_record(&schema, &canonical[..end]),
                    Err(VMError::DecodeError)
                ),
                "truncation at byte {end} must fail closed"
            );
        }
        let empty = EntrypointArgumentRecordV1 {
            schema_hash: [0xa5; 32],
            atoms: Vec::new(),
        };
        let mut forged_count = to_bytes(&empty).expect("encode empty record");
        let count_offset = forged_count
            .windows(size_of::<u64>())
            .rposition(|window| window == [0; size_of::<u64>()])
            .expect("empty atom sequence count");
        forged_count[count_offset..count_offset + size_of::<u64>()]
            .copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(
            matches!(
                validate_argument_record(&schema, &forged_count),
                Err(VMError::DecodeError)
            ),
            "adversarial atom counts must not allocate or panic"
        );
    }
    #[test]
    fn new_v1_kinds_reject_noncanonical_boundary_values_without_record_decode() {
        let cases = [
            (
                EntrypointValueKindV1::Bool,
                njson::Value::String("true".to_owned()),
            ),
            (EntrypointValueKindV1::String, njson::Value::Bool(true)),
            (EntrypointValueKindV1::Int, njson::Value::from(7_u64)),
            (
                EntrypointValueKindV1::Int,
                njson::Value::String("01".to_owned()),
            ),
            (
                EntrypointValueKindV1::Quantity,
                njson::Value::String("-1".to_owned()),
            ),
            (
                EntrypointValueKindV1::AssetId,
                njson::Value::String("not-an-asset".to_owned()),
            ),
            (
                EntrypointValueKindV1::DomainId,
                njson::Value::String("missing_dataspace".to_owned()),
            ),
            (
                EntrypointValueKindV1::DataSpaceId,
                njson::Value::String("7".to_owned()),
            ),
            (
                EntrypointValueKindV1::Blob,
                njson::Value::String("0102".to_owned()),
            ),
            (
                EntrypointValueKindV1::Blob,
                njson::Value::String("0xAB".to_owned()),
            ),
            (
                EntrypointValueKindV1::Blob,
                njson::Value::String("hash:0102".to_owned()),
            ),
        ];
        for (kind, value) in cases {
            RECORD_DECODE_COUNT.with(|count| count.set(0));
            let schema = EntrypointArgumentSchemaV1 {
                fields: vec![EntrypointArgumentFieldV1 {
                    name: "value".into(),
                    ty: argument_type(kind),
                }],
            };
            let payload = Json::from(norito::json!({ "value": value }));
            assert!(matches!(
                argument_record_from_json(&schema, &payload),
                Err(VMError::DecodeError)
            ));
            RECORD_DECODE_COUNT.with(|count| assert_eq!(count.get(), 0));
        }
    }
    fn quote_fixture() -> IVM {
        let schema = EntrypointArgumentSchemaV1 {
            fields: vec![
                EntrypointArgumentFieldV1 {
                    name: "count".to_owned(),
                    ty: argument_type(EntrypointValueKindV1::Int),
                },
                EntrypointArgumentFieldV1 {
                    name: "bytes".to_owned(),
                    ty: argument_type(EntrypointValueKindV1::Blob),
                },
            ],
        };
        let max_count = i64::MAX.to_string();
        let payload = Json::from(norito::json!({
            "count": max_count,
            "bytes": "0x000102ff",
        }));
        install_record(&schema, &payload)
    }
    #[track_caller]
    fn assert_aggregate_schema_predecode_bound(
        label: &str,
        schema: &EntrypointArgumentSchemaV1,
        payload: &Json,
        expected_materialized_raw_heap: u64,
    ) {
        let canonical: Arc<[u8]> = Arc::from(
            encode_argument_record_from_json(schema, payload)
                .expect("encode aggregate argument record"),
        );
        let schema_bound = schema_materialization_bound(schema).expect("aggregate schema bound");
        let bound = prepared_gas_bound(schema, canonical.len());
        let schema_bytes = canonical_norito_frame(schema).expect("encode aggregate schema");
        assert_eq!(
            canonical_norito_frame_len(schema),
            schema_bytes.len(),
            "{label} counted schema frame must match canonical Norito bytes"
        );
        let record = decode_record(&canonical).expect("decode aggregate record for diagnostics");
        let diagnostic_plan = build_decode_plan(
            schema,
            &schema_bytes,
            record,
            ivm_abi::SyscallPolicy::AbiV1,
            canonical.len(),
        )
        .unwrap_or_else(|error| panic!("{label} decode plan must be canonical: {error:?}"));
        assert!(
            diagnostic_plan.gas() <= bound,
            "{label} decode plan must fit the schema-derived gas bound"
        );
        let mut allocation_lengths = Vec::with_capacity(diagnostic_plan.decoded.len() + 2);
        allocation_lengths.push(TLV_ENVELOPE_BYTES + Hash::LENGTH);
        allocation_lengths.extend(diagnostic_plan.allocation_lengths());
        IVM::preflight_fresh_host_tlv_allocations_with_reserved_heap(
            &allocation_lengths,
            diagnostic_plan.raw_heap_bytes(),
        )
        .unwrap_or_else(|error| panic!("{label} allocation plan must fit a fresh VM: {error:?}"));
        reset_argument_record_decode_count();
        assert!(matches!(
            prepare_argument_record_with_gas_limit(
                schema,
                Arc::clone(&canonical),
                bound.saturating_sub(1),
            ),
            Err(VMError::OutOfGas)
        ));
        assert_eq!(argument_record_decode_count(), 0);
        let prepared = prepare_argument_record_with_gas_limit(schema, canonical, bound)
            .unwrap_or_else(|error| {
                panic!("{label} record must fit its conservative bound: {error:?}")
            });
        assert_eq!(argument_record_decode_count(), 1);
        assert!(prepared.inner.decode_plan.gas() <= bound);
        assert!(
            prepared.inner.decode_plan.materialized_bytes
                <= materialized_bytes_for_schema_bound(
                    prepared.canonical_bytes().len(),
                    schema_bound,
                ),
            "actual materialization must stay inside the schema-derived envelope"
        );
        let materialized_raw_heap = prepared.inner.decode_plan.raw_heap_bytes();
        assert_eq!(
            materialized_raw_heap,
            expected_materialized_raw_heap + (prepared.word_count() * 8) as u64,
            "raw HEAP includes the expected active aggregate layout and naked argument slots"
        );
        assert!(materialized_raw_heap <= crate::memory::Memory::HEAP_SIZE);
    }
    #[test]
    fn prepared_gas_admission_tracks_list_capacity_and_fits_the_default() {
        let schema_with_capacity = |capacity| EntrypointArgumentSchemaV1 {
            fields: vec![EntrypointArgumentFieldV1 {
                name: "value".to_owned(),
                ty: list_type(capacity, argument_type(EntrypointValueKindV1::Int)),
            }],
        };
        let narrow = schema_with_capacity(1);
        let wide = schema_with_capacity(64);
        let payload = Json::from(norito::json!({ "value": [] }));
        let narrow_record: Arc<[u8]> = Arc::from(
            encode_argument_record_from_json(&narrow, &payload).expect("encode narrow record"),
        );
        let wide_record: Arc<[u8]> = Arc::from(
            encode_argument_record_from_json(&wide, &payload).expect("encode wide record"),
        );
        let narrow_schema = to_bytes(&narrow).expect("encode narrow schema");
        let wide_schema = to_bytes(&wide).expect("encode wide schema");
        assert_eq!(narrow_record.len(), wide_record.len());
        assert_eq!(narrow_schema.len(), wide_schema.len());
        let narrow_bound = schema_materialization_bound(&narrow).expect("narrow schema bound");
        let wide_bound = schema_materialization_bound(&wide).expect("wide schema bound");
        assert_eq!(narrow_bound.raw_heap_bytes, 24);
        assert_eq!(wide_bound.raw_heap_bytes, 528);
        assert_eq!(narrow_bound.pointer_envelopes, 1);
        assert_eq!(wide_bound.pointer_envelopes, 64);
        let narrow_quote = prepared_gas_bound(&narrow, narrow_record.len());
        let wide_quote = prepared_gas_bound(&wide, wide_record.len());
        let narrow_materialized =
            materialized_bytes_for_schema_bound(narrow_record.len(), narrow_bound);
        let wide_materialized = materialized_bytes_for_schema_bound(wide_record.len(), wide_bound);
        assert_eq!(
            wide_quote - narrow_quote,
            wide_materialized - narrow_materialized,
            "equal wire lengths must differ by the schema-derived List and pointer-copy bounds"
        );
        assert!(
            wide_materialized - narrow_materialized
                >= wide_bound.raw_heap_bytes - narrow_bound.raw_heap_bytes,
            "the conservative pointer-copy allowance must not reduce the raw List reservation"
        );
        assert!(
            wide_quote < 1_000_000,
            "a representative capacity-64 call must fit the production default"
        );
        let raw_vm = install_record(&wide, &payload);
        assert!(
            decode_argument_record_gas_quote(&raw_vm).expect("raw syscall quote") > wide_quote,
            "an unauthenticated raw syscall schema must retain its full-HEAP reserve"
        );
        reset_argument_record_decode_count();
        for (schema, record, quote) in [
            (&narrow, Arc::clone(&narrow_record), narrow_quote),
            (&wide, Arc::clone(&wide_record), wide_quote),
        ] {
            assert!(matches!(
                prepare_argument_record_with_gas_limit(schema, record, quote - 1),
                Err(VMError::OutOfGas)
            ));
        }
        assert_eq!(argument_record_decode_count(), 0);
        prepare_argument_record_with_gas_limit(&narrow, narrow_record, narrow_quote)
            .expect("the exact schema bound must cover the narrow shape");
        prepare_argument_record_with_gas_limit(&wide, wide_record, 1_000_000)
            .expect("the capacity-64 shape must fit the default cycle limit");
        assert_eq!(
            argument_record_decode_count(),
            2,
            "unaffordable rejection must precede each successful canonical record decode"
        );
    }
    #[test]
    fn aggregate_predecode_gas_bound_covers_fixed_and_nested_raw_heap_layouts() {
        let empty_string_list = EntrypointArgumentSchemaV1 {
            fields: vec![EntrypointArgumentFieldV1 {
                name: "value".to_owned(),
                ty: list_type(64, argument_type(EntrypointValueKindV1::String)),
            }],
        };
        let empty_list_payload = Json::from(norito::json!({ "value": [] }));
        let empty_string_list_bound =
            schema_materialization_bound(&empty_string_list).expect("list schema bound");
        assert_eq!(empty_string_list_bound.raw_heap_bytes, 528);
        assert_eq!(
            empty_string_list_bound.pointer_envelopes, 64,
            "pointer-copy alignment allowance must scale with bounded element capacity"
        );
        assert_aggregate_schema_predecode_bound(
            "empty string list",
            &empty_string_list,
            &empty_list_payload,
            528,
        );
        assert_aggregate_schema_predecode_bound(
            "populated string list",
            &empty_string_list,
            &Json::from(norito::json!({ "value": ["a", "bb"] })),
            528,
        );
        let option_wide_tuple = EntrypointArgumentSchemaV1 {
            fields: vec![EntrypointArgumentFieldV1 {
                name: "value".to_owned(),
                ty: EntrypointValueTypeV1 {
                    nodes: vec![
                        EntrypointValueTypeNodeV1::Option,
                        EntrypointValueTypeNodeV1::Tuple(4),
                        EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int),
                        EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int),
                        EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int),
                        EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int),
                    ],
                },
            }],
        };
        let none_payload = Json::from(norito::json!({ "value": { "none": true } }));
        assert_eq!(
            schema_materialization_bound(&option_wide_tuple)
                .expect("Option schema bound")
                .raw_heap_bytes,
            40
        );
        assert_aggregate_schema_predecode_bound(
            "inactive wide Option",
            &option_wide_tuple,
            &none_payload,
            40,
        );
        let named_product = EntrypointArgumentSchemaV1 {
            fields: vec![EntrypointArgumentFieldV1 {
                name: "value".to_owned(),
                ty: EntrypointValueTypeV1 {
                    nodes: vec![
                        EntrypointValueTypeNodeV1::Struct(EntrypointStructTypeNodeV1 {
                            name: "Fixture::Pair".to_owned(),
                            fields: vec!["items".to_owned(), "maybe".to_owned()],
                        }),
                        EntrypointValueTypeNodeV1::List(EntrypointListTypeNodeV1 { capacity: 1 }),
                        EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int),
                        EntrypointValueTypeNodeV1::Option,
                        EntrypointValueTypeNodeV1::Tuple(2),
                        EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int),
                        EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int),
                    ],
                },
            }],
        };
        let product_payload = Json::from(norito::json!({
            "value": { "items": [], "maybe": { "none": true } }
        }));
        assert_eq!(
            schema_materialization_bound(&named_product).expect("named product schema bound"),
            SchemaMaterializationBound {
                words: 2,
                pointer_envelopes: 3,
                raw_heap_bytes: 48,
            }
        );
        assert_aggregate_schema_predecode_bound(
            "named product",
            &named_product,
            &product_payload,
            48,
        );
        let result_unequal_branches = EntrypointArgumentSchemaV1 {
            fields: vec![EntrypointArgumentFieldV1 {
                name: "value".to_owned(),
                ty: EntrypointValueTypeV1 {
                    nodes: vec![
                        EntrypointValueTypeNodeV1::Result,
                        EntrypointValueTypeNodeV1::List(EntrypointListTypeNodeV1 { capacity: 64 }),
                        EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::String),
                        EntrypointValueTypeNodeV1::Tuple(4),
                        EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int),
                        EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int),
                        EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int),
                        EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int),
                    ],
                },
            }],
        };
        let err_payload = Json::from(norito::json!({ "value": { "err": ["1", "2", "3", "4"] } }));
        assert_eq!(
            schema_materialization_bound(&result_unequal_branches)
                .expect("Result schema bound")
                .raw_heap_bytes,
            568,
            "the fixed Result allocation plus the larger active branch must be reserved"
        );
        assert_aggregate_schema_predecode_bound(
            "unequal Result branch",
            &result_unequal_branches,
            &err_payload,
            40,
        );
        let nested_element = EntrypointValueTypeV1 {
            nodes: vec![
                EntrypointValueTypeNodeV1::Option,
                EntrypointValueTypeNodeV1::List(EntrypointListTypeNodeV1 { capacity: 64 }),
                EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::String),
            ],
        };
        let nested = EntrypointArgumentSchemaV1 {
            fields: vec![EntrypointArgumentFieldV1 {
                name: "value".to_owned(),
                ty: list_type(64, nested_element),
            }],
        };
        assert_eq!(
            schema_materialization_bound(&nested)
                .expect("nested schema bound")
                .raw_heap_bytes,
            35_344
        );
        assert_aggregate_schema_predecode_bound(
            "nested empty list",
            &nested,
            &empty_list_payload,
            528,
        );
        reset_argument_record_decode_count();
        let mut vm = install_record(&empty_string_list, &empty_list_payload);
        let raw_quote = decode_argument_record_gas_quote(&vm).expect("quote aggregate record");
        assert_eq!(argument_record_decode_count(), 0);
        let actual = decode_argument_record(&mut vm).expect("decode aggregate record");
        assert!(actual <= raw_quote);
    }
    #[test]
    fn deep_aggregate_schema_bound_is_iterative_and_caps_at_owned_heap() {
        let levels = MAX_ENTRYPOINT_ARGUMENT_TYPE_DEPTH - 1;
        let mut nodes = Vec::with_capacity(levels.saturating_add(1));
        for _ in 0..levels {
            nodes.push(EntrypointValueTypeNodeV1::List(EntrypointListTypeNodeV1 {
                capacity: 64,
            }));
        }
        nodes.push(EntrypointValueTypeNodeV1::Leaf(
            EntrypointValueKindV1::String,
        ));
        let schema = EntrypointArgumentSchemaV1 {
            fields: vec![EntrypointArgumentFieldV1 {
                name: "value".to_owned(),
                ty: EntrypointValueTypeV1 { nodes },
            }],
        };
        assert!(schema.validate());
        assert_eq!(
            schema_materialization_bound(&schema)
                .expect("deep schema bound")
                .raw_heap_bytes,
            crate::memory::Memory::HEAP_SIZE,
            "exponential nested capacity must saturate at the executable HEAP ceiling"
        );
        assert_aggregate_schema_predecode_bound(
            "maximum-depth empty list",
            &schema,
            &Json::from(norito::json!({ "value": [] })),
            528,
        );
    }
    #[test]
    fn malformed_schema_cannot_obtain_a_cheaper_predecode_quote() {
        let malformed = EntrypointArgumentSchemaV1 {
            fields: vec![EntrypointArgumentFieldV1 {
                name: "value".to_owned(),
                ty: EntrypointValueTypeV1 {
                    nodes: vec![
                        EntrypointValueTypeNodeV1::List(EntrypointListTypeNodeV1 { capacity: 0 }),
                        EntrypointValueTypeNodeV1::Leaf(EntrypointValueKindV1::Int),
                    ],
                },
            }],
        };
        assert!(matches!(
            schema_materialization_bound(&malformed),
            Err(VMError::DecodeError)
        ));
        reset_argument_record_decode_count();
        assert!(matches!(
            prepare_argument_record_with_gas_limit(&malformed, Arc::from([]), 0),
            Err(VMError::DecodeError)
        ));
        assert_eq!(
            argument_record_decode_count(),
            0,
            "schema rejection must precede any untrusted record decode"
        );
    }
    #[test]
    fn schema_bound_arithmetic_saturates_at_the_heap_ceiling() {
        assert_eq!(
            add_pointer_envelopes(u64::MAX, u64::MAX),
            max_schema_pointer_envelopes()
        );
        assert_eq!(
            multiply_pointer_envelopes(u64::MAX, u64::MAX),
            max_schema_pointer_envelopes()
        );
        assert_eq!(aligned_allocation_bytes(usize::MAX), u64::MAX);
        assert_eq!(
            pointer_copy_allocation_upper_bound(usize::MAX, u64::MAX),
            u64::MAX
        );
        assert_eq!(
            aggregate_allocation_bytes(u64::MAX, u64::MAX),
            crate::memory::Memory::HEAP_SIZE
        );
        assert_eq!(
            add_raw_heap_bytes(u64::MAX, u64::MAX),
            crate::memory::Memory::HEAP_SIZE
        );
        assert_eq!(
            multiply_raw_heap_bytes(u64::MAX, u64::MAX),
            crate::memory::Memory::HEAP_SIZE
        );
        assert_eq!(
            argument_record_gas_for_schema_bound(
                usize::MAX,
                usize::MAX,
                SchemaMaterializationBound {
                    words: u64::MAX,
                    pointer_envelopes: u64::MAX,
                    raw_heap_bytes: u64::MAX,
                },
            ),
            u64::MAX
        );
    }
    #[test]
    fn gas_quote_is_conservative_repeatable_and_side_effect_free() {
        RECORD_DECODE_COUNT.with(|count| count.set(0));
        let mut quoted_vm = quote_fixture();
        let mut control_vm = quote_fixture();
        let input_registers = (quoted_vm.register(10), quoted_vm.register(11));
        let quote = decode_argument_record_gas_quote(&quoted_vm).expect("quote valid record");
        assert_eq!(
            decode_argument_record_gas_quote(&quoted_vm).expect("repeat quote"),
            quote
        );
        assert_eq!(
            (quoted_vm.register(10), quoted_vm.register(11)),
            input_registers
        );
        RECORD_DECODE_COUNT.with(|count| {
            assert_eq!(
                count.get(),
                0,
                "prepare/quote must not deserialize the argument record"
            );
        });
        let sentinel = encode_tlv(PointerType::Blob, b"sentinel").expect("encode sentinel");
        let quoted_next = quoted_vm
            .alloc_input_tlv(&sentinel)
            .expect("allocate after quote");
        let control_next = control_vm
            .alloc_input_tlv(&sentinel)
            .expect("allocate without quote");
        assert_eq!(quoted_next, control_next, "quote must not advance INPUT");
        let actual = decode_argument_record(&mut quoted_vm).expect("execute valid record");
        assert!(
            actual <= quote,
            "the pre-decode reserve must bound the exact post-decode cost"
        );
        assert!(
            actual < quote,
            "this pointer-bearing fixture must exercise conservative-reserve refunding"
        );
        RECORD_DECODE_COUNT.with(|count| assert_eq!(count.get(), 1));
    }
    #[test]
    fn unaffordable_vm_dispatch_never_decodes_or_allocates_outputs() {
        RECORD_DECODE_COUNT.with(|count| count.set(0));
        let mut vm = quote_fixture();
        let quote = decode_argument_record_gas_quote(&vm).expect("quote argument record");
        let input_registers = (vm.register(10), vm.register(11));
        let sentinel = encode_tlv(PointerType::Blob, b"sentinel").expect("encode sentinel");
        let control_next = vm.alloc_input_tlv(&sentinel).expect("control allocation");
        let mut program = crate::metadata::ProgramMetadata::default().encode();
        program.extend_from_slice(
            &crate::encoding::wide::encode_syscallx(
                ivm_abi::syscalls::SYSCALL_DECODE_ARGUMENT_RECORD,
            )
            .to_le_bytes(),
        );
        program.extend_from_slice(&crate::encoding::wide::encode_halt().to_le_bytes());
        vm.load_program(&program).expect("load argument syscall");
        vm.set_register(10, input_registers.0);
        vm.set_register(11, input_registers.1);
        vm.set_host(crate::host::DefaultHost::new());
        vm.set_gas_limit(5_u64.saturating_add(quote).saturating_sub(1));
        assert!(matches!(vm.run(), Err(VMError::OutOfGas)));
        RECORD_DECODE_COUNT
            .with(|count| assert_eq!(count.get(), 0, "unaffordable calls must not deserialize"));
        assert_eq!((vm.register(10), vm.register(11)), input_registers);
        let next = vm
            .alloc_input_tlv(&sentinel)
            .expect("allocation after rejected call");
        let expected_next = crate::memory::Memory::INPUT_START
            + ((control_next - crate::memory::Memory::INPUT_START
                + u64::try_from(sentinel.len()).expect("sentinel length fits u64")
                + 7)
                & !7);
        assert_eq!(
            next, expected_next,
            "rejected dispatch must not allocate typed outputs"
        );
    }
    #[test]
    fn unaffordable_malformed_envelopes_fail_before_digest_or_canonical_decode() {
        RECORD_DECODE_COUNT.with(|count| count.set(0));
        let mut vm = IVM::new(u64::MAX);
        let mut record_envelope = encode_tlv(PointerType::NoritoBytes, b"not a record")
            .expect("encode malformed record envelope");
        *record_envelope.last_mut().expect("record has a digest") ^= 1;
        let mut schema_envelope = encode_tlv(PointerType::NoritoBytes, b"not a schema")
            .expect("encode malformed schema envelope");
        *schema_envelope.last_mut().expect("schema has a digest") ^= 1;
        let record_ptr = vm
            .alloc_input_tlv(&record_envelope)
            .expect("allocate malformed record envelope");
        let schema_ptr = vm
            .alloc_input_tlv(&schema_envelope)
            .expect("allocate malformed schema envelope");
        vm.set_register(10, record_ptr);
        vm.set_register(11, schema_ptr);
        let quote = decode_argument_record_gas_quote(&vm)
            .expect("bounded envelope shapes receive a conservative quote");
        let mut program = crate::metadata::ProgramMetadata::default().encode();
        program.extend_from_slice(
            &crate::encoding::wide::encode_syscallx(
                ivm_abi::syscalls::SYSCALL_DECODE_ARGUMENT_RECORD,
            )
            .to_le_bytes(),
        );
        program.extend_from_slice(&crate::encoding::wide::encode_halt().to_le_bytes());
        vm.load_program(&program).expect("load argument syscall");
        vm.set_register(10, record_ptr);
        vm.set_register(11, schema_ptr);
        vm.set_host(crate::host::DefaultHost::new());
        vm.set_gas_limit(5_u64.saturating_add(quote).saturating_sub(1));
        assert!(
            matches!(vm.run(), Err(VMError::OutOfGas)),
            "gas debit must reject the call before envelope authentication"
        );
        RECORD_DECODE_COUNT.with(|count| {
            assert_eq!(
                count.get(),
                0,
                "unaffordable malformed calls must not reach canonical decoding"
            );
        });
        assert_eq!(vm.register(10), record_ptr);
        assert_eq!(vm.register(11), schema_ptr);
    }
    #[test]
    fn gas_quote_does_not_decode_invalid_schema_before_debit() {
        let schema = EntrypointArgumentSchemaV1 {
            fields: vec![
                EntrypointArgumentFieldV1 {
                    name: "same".to_owned(),
                    ty: argument_type(EntrypointValueKindV1::Int),
                },
                EntrypointArgumentFieldV1 {
                    name: "same".to_owned(),
                    ty: argument_type(EntrypointValueKindV1::Blob),
                },
            ],
        };
        let record = EntrypointArgumentRecordV1 {
            schema_hash: [0; 32],
            atoms: Vec::new(),
        };
        let mut vm = IVM::new(u64::MAX);
        let record_ptr = alloc(
            &mut vm,
            PointerType::NoritoBytes,
            &to_bytes(&record).expect("encode record"),
        );
        let schema_ptr = alloc(
            &mut vm,
            PointerType::NoritoBytes,
            &to_bytes(&schema).expect("encode schema"),
        );
        vm.set_register(10, record_ptr);
        vm.set_register(11, schema_ptr);
        let before = (vm.register(10), vm.register(11));
        let quote = decode_argument_record_gas_quote(&vm)
            .expect("bounded envelope lengths are sufficient to quote");
        assert!(quote > 0);
        assert_eq!((vm.register(10), vm.register(11)), before);
        assert!(
            matches!(decode_argument_record(&mut vm), Err(VMError::DecodeError)),
            "schema validation belongs to post-debit execution"
        );
    }
    #[test]
    fn gas_quote_does_not_authenticate_envelope_digest_before_debit() {
        let schema = EntrypointArgumentSchemaV1 {
            fields: vec![EntrypointArgumentFieldV1 {
                name: "value".to_owned(),
                ty: argument_type(EntrypointValueKindV1::Int),
            }],
        };
        let record =
            encode_argument_record_from_json(&schema, &Json::from(norito::json!({"value": "1"})))
                .expect("encode record");
        let mut record_envelope =
            encode_tlv(PointerType::NoritoBytes, &record).expect("encode record envelope");
        *record_envelope.last_mut().expect("envelope has a digest") ^= 1;
        let mut vm = IVM::new(u64::MAX);
        let record_ptr = vm
            .alloc_input_tlv(&record_envelope)
            .expect("allocate corrupted record envelope");
        let schema_ptr = alloc(
            &mut vm,
            PointerType::NoritoBytes,
            &to_bytes(&schema).expect("encode schema"),
        );
        vm.set_register(10, record_ptr);
        vm.set_register(11, schema_ptr);
        assert!(
            decode_argument_record_gas_quote(&vm).is_ok(),
            "header and bounded lengths are sufficient for pre-debit quoting"
        );
        assert!(
            matches!(decode_argument_record(&mut vm), Err(VMError::NoritoInvalid)),
            "digest authentication belongs to post-debit execution"
        );
    }
    #[test]
    fn gas_quote_arithmetic_saturates_instead_of_wrapping() {
        let plan = ArgumentDecodePlan {
            decoded: Vec::new(),
            roots: Vec::new(),
            record_bytes: usize::MAX,
            schema_bytes: usize::MAX,
            materialized_bytes: u64::MAX,
        };
        assert_eq!(plan.gas(), u64::MAX);
    }
    #[test]
    fn quote_rejects_oversized_envelopes_without_decoding_them() {
        RECORD_DECODE_COUNT.with(|count| count.set(0));
        let schema = EntrypointArgumentSchemaV1 {
            fields: vec![EntrypointArgumentFieldV1 {
                name: "value".into(),
                ty: argument_type(EntrypointValueKindV1::Int),
            }],
        };
        let oversized: Arc<[u8]> = Arc::from(vec![0_u8; MAX_ENTRYPOINT_ARGUMENT_RECORD_BYTES + 1]);
        assert!(matches!(
            prepare_argument_record_with_gas_limit(&schema, oversized, u64::MAX),
            Err(VMError::DecodeError)
        ));
        RECORD_DECODE_COUNT.with(|count| assert_eq!(count.get(), 0));
    }

    #[test]
    fn prepared_argument_record_preserves_original_enclosing_decode_refusal_and_retry() {
        use crate::error::ExecutionDeferral;
        use iroha_allocation::AllocationBudget;
        use norito::core::{DecodeBudgetContext, DecodeLimits, with_decode_limits_scope};
        let schema = EntrypointArgumentSchemaV1 {
            fields: vec![EntrypointArgumentFieldV1 {
                name: "ready".into(),
                ty: argument_type(EntrypointValueKindV1::Bool),
            }],
        };
        let canonical: Arc<[u8]> = Arc::from(
            encode_argument_record_from_json(&schema, &Json::new(norito::json!({"ready": true})))
                .unwrap(),
        );
        let original_pointer = canonical.as_ptr();
        let original_bytes = canonical.to_vec();
        let pool = AllocationBudget::new(32 * 1024 * 1024);
        let context = DecodeBudgetContext::try_new_owned(
            DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, usize::MAX, usize::MAX),
            &pool,
        )
        .unwrap();
        let mut vm = IVM::try_new_with_memory_budget(u64::MAX, &pool).unwrap();
        let baseline = (
            pool.reserved_bytes(),
            vm.remaining_gas(),
            vm.register(10),
            vm.register(11),
        );
        context.with(|| {
            let error = with_decode_limits_scope(
                DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
                || prepare_argument_record_with_gas_limit(&schema, canonical.clone(), u64::MAX),
            )
            .expect_err("the actual canonical record cannot decode under zero caller allocation");
            assert_eq!(
                error.execution_deferral(),
                Some(ExecutionDeferral::ActiveMemoryCapacity),
                "canonical prepared record must retain its original enclosing decoder deferral"
            );
            let VMError::DecodeDeferred(original_refusal) = error else {
                panic!("prepared record lost its captured decoder owner");
            };
            assert_eq!(
                original_refusal.kind(),
                norito::core::DecodeLocalRefusalKind::EnclosingLimit
            );
            assert_eq!(
                (
                    pool.reserved_bytes(),
                    vm.remaining_gas(),
                    vm.register(10),
                    vm.register(11)
                ),
                baseline
            );
            let prepared =
                prepare_argument_record_with_gas_limit(&schema, canonical.clone(), u64::MAX)
                    .expect(
                        "unchanged original record retries after only the narrower scope retires",
                    );
            assert_eq!(prepared.canonical_bytes().as_ptr(), original_pointer);
            assert_eq!(prepared.canonical_bytes(), original_bytes);
            prepared.precharge_vm(&mut vm).unwrap();
            prepared.install_call_arguments(&mut vm, 1).unwrap();
            assert!(matches!(vm.load_u64(vm.register(10)), Ok(1)));
            assert!(vm.allocation_budget().unwrap().same_pool(&pool));
        });
        let mut malformed = original_bytes.clone();
        malformed[0] ^= 0xff;
        let invalid = context
            .with(|| {
                with_decode_limits_scope(
                    DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
                    || {
                        prepare_argument_record_with_gas_limit(
                            &schema,
                            Arc::from(malformed),
                            u64::MAX,
                        )
                    },
                )
            })
            .unwrap_err();
        assert!(
            matches!(invalid, VMError::DecodeError),
            "invalid framing remains a protocol rejection"
        );
        assert_eq!(canonical.as_ref(), original_bytes);
        drop(vm);
        drop(context);
        assert_eq!(pool.reserved_bytes(), 0);
    }

    #[test]
    fn schema_bound_argument_syscall_preserves_original_decode_refusal_before_table_writes() {
        use crate::error::ExecutionDeferral;
        use norito::core::{DecodeBudgetContext, DecodeLimits, with_decode_limits_scope};
        let schema = EntrypointArgumentSchemaV1 {
            fields: vec![EntrypointArgumentFieldV1 {
                name: "ready".into(),
                ty: argument_type(EntrypointValueKindV1::Bool),
            }],
        };
        let mut vm = install_record(&schema, &Json::new(norito::json!({"ready": true})));
        let original = (vm.register(10), vm.register(11), vm.remaining_gas());
        let context = DecodeBudgetContext::new(DecodeLimits::new(
            usize::MAX,
            usize::MAX,
            usize::MAX,
            usize::MAX,
            usize::MAX,
        ));
        context.with(|| {
            let error = with_decode_limits_scope(
                DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
                || decode_argument_record(&mut vm),
            )
            .unwrap_err();
            assert_eq!(
                error.execution_deferral(),
                Some(ExecutionDeferral::ActiveMemoryCapacity),
                "canonical argument schema must retain its original enclosing decoder deferral"
            );
            let VMError::DecodeDeferred(original_refusal) = error else {
                panic!("argument syscall lost its captured decoder owner");
            };
            assert_eq!(
                original_refusal.kind(),
                norito::core::DecodeLocalRefusalKind::EnclosingLimit
            );
            assert_eq!(
                (vm.register(10), vm.register(11), vm.remaining_gas()),
                original
            );
            decode_argument_record(&mut vm)
                .expect("same schema and record retry under the original context");
            assert!(matches!(vm.load_u64(vm.register(10)), Ok(1)));
            assert_eq!(vm.register(11), 1);
        });
    }
}
