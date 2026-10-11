//! Runtime support for active-only compiler-owned Kotodama sums.
use crate::{IVM, VMError};
use ivm_abi::entrypoint::{EntrypointValueTypeNodeV1, EntrypointValueTypeV1};
use ivm_abi::sum::SUM_WORD_BYTES_V1;
pub use ivm_abi::sum::SumLayoutV1;
fn layout_error() -> VMError {
    VMError::DecodeError
}
/// Classify a completed, validated public return as an outer `Result::err`.
///
/// Hosts call this after protected return and canonical boundary validation,
/// before publishing invocation effects. Only the outermost Result controls
/// rollback: an error carried inside a product, Option, or List remains data.
/// This does not replace validation of the complete signed return schema.
///
/// # Errors
/// Returns an error for an incomplete table, invalid schema or root sum tag.
pub fn entrypoint_return_is_error(
    vm: &IVM,
    schema: &EntrypointValueTypeV1,
) -> Result<bool, VMError> {
    if !schema.validate() || schema.word_count() != Some(vm.call_result_word_count()?) {
        return Err(layout_error());
    }
    if !matches!(
        schema.nodes.first(),
        Some(EntrypointValueTypeNodeV1::Result)
    ) {
        return Ok(false);
    }
    let pointer = vm.public_call_result_word(0)?;
    if !pointer.is_multiple_of(SUM_WORD_BYTES_V1) {
        return Err(layout_error());
    }
    vm.ensure_owned_heap_range(pointer, SUM_WORD_BYTES_V1)?;
    match vm.load_u64(pointer)? {
        0 => Ok(true),
        1 => Ok(false),
        _ => Err(layout_error()),
    }
}
/// Allocate one active-only `Option` or `Result` value.
///
/// The complete larger-branch capacity is reserved once, but only the selected
/// branch words are written. Validation occurs before allocation, so malformed
/// values cannot partially advance or mutate the VM heap.
pub fn allocate_words(
    vm: &mut IVM,
    layout: SumLayoutV1,
    tag: u64,
    active_payload: &[u64],
) -> Result<u64, VMError> {
    let actual = u64::try_from(active_payload.len()).map_err(|_| layout_error())?;
    layout
        .validate_active_width(tag, actual)
        .map_err(|_| layout_error())?;
    let bytes = layout.allocation_bytes().map_err(|_| layout_error())?;
    let base = vm.alloc_heap(bytes)?;
    vm.store_u64(base, tag)?;
    for (index, word) in active_payload.iter().copied().enumerate() {
        let offset = u64::try_from(index)
            .map_err(|_| layout_error())?
            .checked_add(1)
            .and_then(|word_index| word_index.checked_mul(SUM_WORD_BYTES_V1))
            .ok_or_else(layout_error)?;
        let address = base.checked_add(offset).ok_or_else(layout_error)?;
        vm.store_u64(address, word)?;
    }
    Ok(base)
}
/// Validate and read only the selected payload of one compiler-owned sum.
///
/// Reserved words beyond the active branch must remain canonical zero, so an
/// inactive branch can never smuggle a placeholder payload across a boundary.
/// Returns the tag and active word count without allocating or copying payload words.
///
/// # Errors
/// Rejects invalid tags, layouts, heap ranges, or nonzero inactive padding.
pub fn validate_active_words(
    vm: &IVM,
    base: u64,
    layout: SumLayoutV1,
) -> Result<(bool, u64), VMError> {
    if !base.is_multiple_of(SUM_WORD_BYTES_V1) {
        return Err(layout_error());
    }
    let bytes = layout.allocation_bytes().map_err(|_| layout_error())?;
    vm.ensure_owned_heap_range(base, bytes)?;
    let raw_tag = vm.load_u64(base)?;
    let active_words = layout.active_words(raw_tag).map_err(|_| layout_error())?;
    for index in active_words..layout.payload_capacity_words() {
        let offset = index
            .checked_add(1)
            .and_then(|word_index| word_index.checked_mul(SUM_WORD_BYTES_V1))
            .ok_or_else(layout_error)?;
        let address = base.checked_add(offset).ok_or_else(layout_error)?;
        if vm.load_u64(address)? != 0 {
            return Err(layout_error());
        }
    }
    Ok((raw_tag == 1, active_words))
}
/// Validate one sum and copy only its active payload into fallibly allocated scratch.
///
/// # Errors
/// Rejects malformed layout, noncanonical padding, unreadable memory, or local allocation refusal.
pub fn read_words(vm: &IVM, base: u64, layout: SumLayoutV1) -> Result<(bool, Vec<u64>), VMError> {
    let (tag, active_words) = validate_active_words(vm, base, layout)?;
    let mut payload = Vec::new();
    payload
        .try_reserve_exact(usize::try_from(active_words).map_err(|_| layout_error())?)
        .map_err(|_| VMError::ExecutionDeferred(crate::ExecutionDeferral::AllocationUnavailable))?;
    for index in 0..active_words {
        let offset = index
            .checked_add(1)
            .and_then(|index| index.checked_mul(SUM_WORD_BYTES_V1))
            .ok_or_else(layout_error)?;
        payload.push(vm.load_u64(base.checked_add(offset).ok_or_else(layout_error)?)?);
    }
    Ok((tag, payload))
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::Memory;
    #[test]
    fn entrypoint_error_disposition_requires_a_completed_outer_result() {
        use ivm_abi::entrypoint::EntrypointValueTypeNodeV1 as Node;
        let schema = EntrypointValueTypeV1 {
            nodes: vec![Node::Result, Node::Unit, Node::Unit],
        };
        assert!(entrypoint_return_is_error(&IVM::new(0), &schema).is_err());
        for (tag, expected) in [(0, true), (1, false)] {
            let mut vm = IVM::new(0);
            let handle =
                allocate_words(&mut vm, SumLayoutV1::try_new(1, 1).unwrap(), tag, &[0]).unwrap();
            crate::value_record::complete_test_result(&mut vm, &[handle]);
            assert_eq!(entrypoint_return_is_error(&vm, &schema), Ok(expected));
            let wrapped = EntrypointValueTypeV1 {
                nodes: vec![
                    Node::Tuple(2),
                    Node::Result,
                    Node::Unit,
                    Node::Unit,
                    Node::Unit,
                ],
            };
            let mut wrapped_vm = IVM::new(0);
            let wrapped_handle = allocate_words(
                &mut wrapped_vm,
                SumLayoutV1::try_new(1, 1).unwrap(),
                tag,
                &[0],
            )
            .unwrap();
            crate::value_record::complete_test_result(&mut wrapped_vm, &[wrapped_handle, 0]);
            assert_eq!(entrypoint_return_is_error(&wrapped_vm, &wrapped), Ok(false));
            vm.store_u64(handle, 2).unwrap();
            assert!(entrypoint_return_is_error(&vm, &schema).is_err());
        }
    }
    #[test]
    fn option_none_and_some_materialize_only_the_active_payload() {
        let mut vm = IVM::new(0);
        let layout = SumLayoutV1::option(2).expect("Option layout");
        let none = allocate_words(&mut vm, layout, 0, &[]).expect("none");
        assert_eq!(none, Memory::HEAP_START);
        assert_eq!(validate_active_words(&vm, none, layout), Ok((false, 0)));
        assert_eq!(read_words(&vm, none, layout), Ok((false, vec![])));
        let some = allocate_words(&mut vm, layout, 1, &[7, 9]).expect("some");
        assert_eq!(validate_active_words(&vm, some, layout), Ok((true, 2)));
        assert_eq!(read_words(&vm, some, layout), Ok((true, vec![7, 9])));
    }
    #[test]
    fn result_branches_use_their_own_exact_width() {
        let mut vm = IVM::new(0);
        let layout = SumLayoutV1::try_new(1, 3).expect("Result layout");
        let err = allocate_words(&mut vm, layout, 0, &[44]).expect("err");
        assert_eq!(read_words(&vm, err, layout), Ok((false, vec![44])));
        let ok = allocate_words(&mut vm, layout, 1, &[1, 2, 3]).expect("ok");
        assert_eq!(read_words(&vm, ok, layout), Ok((true, vec![1, 2, 3])));
    }
    #[test]
    fn malformed_values_and_forged_handles_fail_closed() {
        let mut vm = IVM::new(0);
        let layout = SumLayoutV1::try_new(1, 2).expect("layout");
        assert_eq!(
            allocate_words(&mut vm, layout, 1, &[1]),
            Err(VMError::DecodeError)
        );
        assert_eq!(
            allocate_words(&mut vm, layout, 3, &[1]),
            Err(VMError::DecodeError)
        );
        let value = allocate_words(&mut vm, layout, 0, &[8]).expect("valid sum");
        vm.store_u64(value + 16, 9)
            .expect("forge inactive reserved payload");
        assert_eq!(read_words(&vm, value, layout), Err(VMError::DecodeError));
        vm.store_u64(value + 16, 0)
            .expect("restore inactive reserved payload");
        vm.store_u64(value, 2).expect("forge tag");
        assert_eq!(read_words(&vm, value, layout), Err(VMError::DecodeError));
        assert_eq!(
            read_words(&vm, Memory::HEAP_START + 4096, layout),
            Err(VMError::DecodeError)
        );
        assert_eq!(
            read_words(&vm, value + 1, layout),
            Err(VMError::DecodeError)
        );
    }
}
