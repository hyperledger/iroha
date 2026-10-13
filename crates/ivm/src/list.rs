//! Runtime support for compiler-owned bounded Kotodama lists.
//!
//! A list is not a pointer-ABI envelope. Its handle is the base address of one owned heap
//! allocation whose exact element shape and capacity come from the compiler-emitted schema. Hosts
//! must therefore validate the complete range against that schema before reading it.
use crate::{IVM, VMError};
#[cfg(test)]
use ivm_abi::list::LIST_HEADER_WORDS_V1;
use ivm_abi::list::LIST_WORD_BYTES_V1;
pub use ivm_abi::list::ListLayoutV1;
fn layout_error() -> VMError {
    VMError::DecodeError
}
fn validate_header(vm: &IVM, base: u64, layout: ListLayoutV1) -> Result<u64, VMError> {
    if !base.is_multiple_of(LIST_WORD_BYTES_V1) {
        return Err(layout_error());
    }
    vm.ensure_owned_heap_range(base, layout.allocation_bytes().map_err(|_| layout_error())?)?;
    let len = vm.load_u64(base)?;
    let encoded_capacity = vm.load_u64(
        base.checked_add(LIST_WORD_BYTES_V1)
            .ok_or_else(layout_error)?,
    )?;
    if encoded_capacity != u64::from(layout.capacity()) || len > encoded_capacity {
        return Err(layout_error());
    }
    Ok(len)
}
fn element_slot(base: u64, layout: ListLayoutV1, index: u64) -> Result<u64, VMError> {
    base.checked_add(layout.slot_offset(index).map_err(|_| layout_error())?)
        .ok_or_else(layout_error)
}
fn read_element(vm: &IVM, slot: u64, element_words: u64) -> Result<Vec<u64>, VMError> {
    let mut element =
        Vec::with_capacity(usize::try_from(element_words).map_err(|_| layout_error())?);
    for word_index in 0..element_words {
        let address = slot
            .checked_add(
                word_index
                    .checked_mul(LIST_WORD_BYTES_V1)
                    .ok_or_else(layout_error)?,
            )
            .ok_or_else(layout_error)?;
        element.push(vm.load_u64(address)?);
    }
    Ok(element)
}
fn write_element(vm: &mut IVM, slot: u64, element: &[u64]) -> Result<(), VMError> {
    for (word_index, word) in element.iter().copied().enumerate() {
        let address = slot
            .checked_add(
                u64::try_from(word_index)
                    .map_err(|_| layout_error())?
                    .checked_mul(LIST_WORD_BYTES_V1)
                    .ok_or_else(layout_error)?,
            )
            .ok_or_else(layout_error)?;
        vm.store_u64(address, word)?;
    }
    Ok(())
}
/// Allocate and initialise one contiguous list from flattened element words.
///
/// Only active elements are written. Inactive capacity never requires a
/// placeholder value, although the whole bounded allocation is reserved up
/// front so `try_push` cannot allocate or partially mutate later.
pub fn allocate_words(
    vm: &mut IVM,
    layout: ListLayoutV1,
    elements: &[Vec<u64>],
) -> Result<u64, VMError> {
    if elements.len() > usize::from(layout.capacity())
        || elements
            .iter()
            .any(|element| element.len() as u64 != layout.element_words())
    {
        return Err(layout_error());
    }
    let bytes = layout.allocation_bytes().map_err(|_| layout_error())?;
    let base = vm.alloc_heap(bytes)?;
    vm.store_u64(
        base,
        u64::try_from(elements.len()).map_err(|_| layout_error())?,
    )?;
    vm.store_u64(
        base.checked_add(LIST_WORD_BYTES_V1)
            .ok_or_else(layout_error)?,
        u64::from(layout.capacity()),
    )?;
    for (index, element) in elements.iter().enumerate() {
        let slot = base
            .checked_add(
                layout
                    .slot_offset(u64::try_from(index).map_err(|_| layout_error())?)
                    .map_err(|_| layout_error())?,
            )
            .ok_or_else(layout_error)?;
        for (word_index, word) in element.iter().copied().enumerate() {
            let address = slot
                .checked_add(
                    u64::try_from(word_index)
                        .map_err(|_| layout_error())?
                        .checked_mul(LIST_WORD_BYTES_V1)
                        .ok_or_else(layout_error)?,
                )
                .ok_or_else(layout_error)?;
            vm.store_u64(address, word)?;
        }
    }
    Ok(base)
}
/// Validate and read the active elements of one compiler-owned list.
pub fn read_words(vm: &IVM, base: u64, layout: ListLayoutV1) -> Result<Vec<Vec<u64>>, VMError> {
    let len = validate_header(vm, base, layout)?;
    let mut elements = Vec::with_capacity(usize::try_from(len).map_err(|_| layout_error())?);
    for index in 0..len {
        let offset = layout
            .present_slot_offset(len, index)
            .map_err(|_| layout_error())?;
        let slot = base.checked_add(offset).ok_or_else(layout_error)?;
        elements.push(read_element(vm, slot, layout.element_words())?);
    }
    Ok(elements)
}
/// Return the validated active length of a compiler-owned list.
pub fn len(vm: &IVM, base: u64, layout: ListLayoutV1) -> Result<u64, VMError> {
    validate_header(vm, base, layout)
}
/// Read one present element, returning `None` for an out-of-range index.
pub fn get_words(
    vm: &IVM,
    base: u64,
    layout: ListLayoutV1,
    index: u64,
) -> Result<Option<Vec<u64>>, VMError> {
    let len = validate_header(vm, base, layout)?;
    if index >= len {
        return Ok(None);
    }
    let slot = element_slot(base, layout, index)?;
    read_element(vm, slot, layout.element_words()).map(Some)
}
/// Replace one present element without changing the list on failure.
pub fn try_set_words(
    vm: &mut IVM,
    base: u64,
    layout: ListLayoutV1,
    index: u64,
    element: &[u64],
) -> Result<bool, VMError> {
    if u64::try_from(element.len()).map_err(|_| layout_error())? != layout.element_words() {
        return Err(layout_error());
    }
    let len = validate_header(vm, base, layout)?;
    if index >= len {
        return Ok(false);
    }
    let slot = element_slot(base, layout, index)?;
    write_element(vm, slot, element)?;
    Ok(true)
}
/// Append one element when capacity remains.
///
/// The length word is committed last, so a failed precondition leaves every
/// word of the list unchanged.
pub fn try_push_words(
    vm: &mut IVM,
    base: u64,
    layout: ListLayoutV1,
    element: &[u64],
) -> Result<bool, VMError> {
    if u64::try_from(element.len()).map_err(|_| layout_error())? != layout.element_words() {
        return Err(layout_error());
    }
    let len = validate_header(vm, base, layout)?;
    if len == u64::from(layout.capacity()) {
        return Ok(false);
    }
    let slot = element_slot(base, layout, len)?;
    write_element(vm, slot, element)?;
    vm.store_u64(base, len.checked_add(1).ok_or_else(layout_error)?)?;
    Ok(true)
}
/// Remove and return the last element, or `None` when the list is empty.
pub fn pop_words(
    vm: &mut IVM,
    base: u64,
    layout: ListLayoutV1,
) -> Result<Option<Vec<u64>>, VMError> {
    let len = validate_header(vm, base, layout)?;
    let Some(index) = len.checked_sub(1) else {
        return Ok(None);
    };
    let slot = element_slot(base, layout, index)?;
    let element = read_element(vm, slot, layout.element_words())?;
    let zeros = vec![0; usize::try_from(layout.element_words()).map_err(|_| layout_error())?];
    write_element(vm, slot, &zeros)?;
    vm.store_u64(base, index)?;
    Ok(Some(element))
}
/// Test whether an active element has exactly the supplied flattened words.
pub fn contains_words(
    vm: &IVM,
    base: u64,
    layout: ListLayoutV1,
    element: &[u64],
) -> Result<bool, VMError> {
    if u64::try_from(element.len()).map_err(|_| layout_error())? != layout.element_words() {
        return Err(layout_error());
    }
    Ok(read_words(vm, base, layout)?
        .iter()
        .any(|candidate| candidate == element))
}
/// Return the fixed byte offset of the list capacity word.
#[must_use]
#[cfg(test)]
pub(crate) const fn capacity_word_offset() -> u64 {
    (LIST_HEADER_WORDS_V1 - 1) * LIST_WORD_BYTES_V1
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::Memory;
    #[test]
    fn list_roundtrip_uses_one_owned_allocation() {
        let mut vm = IVM::new(0);
        let layout = ListLayoutV1::try_new(4, 2).expect("layout");
        let base =
            allocate_words(&mut vm, layout, &[vec![1, 2], vec![3, 4]]).expect("allocate list");
        assert_eq!(base, Memory::HEAP_START);
        assert!(matches!(vm.load_u64(base), Ok(2)));
        assert_eq!(
            (vm.load_u64(base + capacity_word_offset()))
                .expect("expected successful fixture result"),
            u64::from(layout.capacity())
        );
        assert_eq!(
            (read_words(&vm, base, layout)).expect("expected successful fixture result"),
            vec![vec![1, 2], vec![3, 4]]
        );
    }
    #[test]
    fn allocation_rejects_capacity_and_element_width_before_mutating_vm() {
        let mut vm = IVM::new(0);
        let layout = ListLayoutV1::try_new(2, 2).expect("layout");
        assert!(matches!(
            allocate_words(&mut vm, layout, &[vec![1], vec![2, 3]]),
            Err(VMError::DecodeError)
        ));
        assert!(matches!(
            allocate_words(&mut vm, layout, &[vec![1, 2], vec![3, 4], vec![5, 6]]),
            Err(VMError::DecodeError)
        ));
        assert_eq!(
            (allocate_words(&mut vm, layout, &[])).expect("expected successful fixture result"),
            Memory::HEAP_START
        );
    }
    #[test]
    fn forged_headers_and_unowned_ranges_fail_closed() {
        let mut vm = IVM::new(0);
        let layout = ListLayoutV1::try_new(2, 1).expect("layout");
        let base = allocate_words(&mut vm, layout, &[vec![7]]).expect("list");
        vm.store_u64(base + capacity_word_offset(), 3)
            .expect("forge capacity");
        assert!(matches!(
            read_words(&vm, base, layout),
            Err(VMError::DecodeError)
        ));
        vm.store_u64(base + capacity_word_offset(), 2)
            .expect("restore capacity");
        vm.store_u64(base, 3).expect("forge length");
        assert!(matches!(
            read_words(&vm, base, layout),
            Err(VMError::DecodeError)
        ));
        assert!(matches!(
            read_words(&vm, Memory::HEAP_START + 4096, layout),
            Err(VMError::DecodeError)
        ));
        assert!(matches!(
            read_words(&vm, base + 1, layout),
            Err(VMError::DecodeError)
        ));
    }
    #[test]
    fn safe_list_operations_preserve_capacity_and_element_order() {
        let mut vm = IVM::new(0);
        let layout = ListLayoutV1::try_new(3, 2).expect("layout");
        let base =
            allocate_words(&mut vm, layout, &[vec![1, 2], vec![3, 4]]).expect("allocate list");
        assert!(matches!(len(&vm, base, layout), Ok(2)));
        assert_eq!(
            (get_words(&vm, base, layout, 0)).expect("expected successful fixture result"),
            Some(vec![1, 2])
        );
        assert_eq!(
            (get_words(&vm, base, layout, 2)).expect("expected successful fixture result"),
            None
        );
        assert!(matches!(
            contains_words(&vm, base, layout, &[3, 4]),
            Ok(true)
        ));
        assert!(matches!(
            contains_words(&vm, base, layout, &[4, 3]),
            Ok(false)
        ));
        assert!(matches!(
            try_set_words(&mut vm, base, layout, 1, &[5, 6]),
            Ok(true)
        ));
        assert!(matches!(
            try_push_words(&mut vm, base, layout, &[7, 8]),
            Ok(true)
        ));
        assert_eq!(
            (read_words(&vm, base, layout)).expect("expected successful fixture result"),
            vec![vec![1, 2], vec![5, 6], vec![7, 8]]
        );
        assert_eq!(
            (pop_words(&mut vm, base, layout)).expect("expected successful fixture result"),
            Some(vec![7, 8])
        );
        assert_eq!(
            (read_words(&vm, base, layout)).expect("expected successful fixture result"),
            vec![vec![1, 2], vec![5, 6]]
        );
        assert!(
            matches!(
                vm.load_u64(base + layout.slot_offset(2).expect("third slot")),
                Ok(0)
            ),
            "pop clears inactive storage"
        );
    }
    #[test]
    fn failed_mutations_leave_every_reserved_word_unchanged() {
        let mut vm = IVM::new(0);
        for capacity in 1..=64 {
            let layout = ListLayoutV1::try_new(capacity, 2).expect("layout");
            let elements = (0..capacity)
                .map(|index| vec![index, index + 100])
                .collect::<Vec<_>>();
            let base = allocate_words(&mut vm, layout, &elements).expect("allocate full list");
            let before = (0..layout.allocation_bytes().expect("allocation bytes") / 8)
                .map(|word| vm.load_u64(base + word * 8).expect("reserved word"))
                .collect::<Vec<_>>();
            assert!(matches!(
                try_set_words(&mut vm, base, layout, capacity, &[999, 1000]),
                Ok(false)
            ));
            assert!(matches!(
                try_push_words(&mut vm, base, layout, &[999, 1000]),
                Ok(false)
            ));
            let after = (0..layout.allocation_bytes().expect("allocation bytes") / 8)
                .map(|word| vm.load_u64(base + word * 8).expect("reserved word"))
                .collect::<Vec<_>>();
            assert_eq!(after, before, "capacity {capacity}");
        }
    }
    #[test]
    fn list_operations_match_a_vec_model_for_every_capacity_and_active_length() {
        fn snapshot(vm: &IVM, base: u64, layout: ListLayoutV1) -> Vec<u64> {
            (0..layout.allocation_bytes().expect("allocation bytes") / 8)
                .map(|word| vm.load_u64(base + word * 8).expect("reserved word"))
                .collect()
        }
        for element_words in [1_u64, 2, 4] {
            let mut vm = IVM::new(0);
            let template = vm
                .try_runtime_template()
                .expect("runtime template allocation fits test host");
            for capacity in 1..=64 {
                // Every capacity is an independent model-checking scenario.
                // Reusing one VM across all capacities retains every prior
                // bounded allocation and eventually tests heap exhaustion
                // instead of list semantics.
                vm.reset_from_runtime_template(&template)
                    .expect("List model VM retains its template geometry");
                let layout = ListLayoutV1::try_new(capacity, element_words).expect("layout");
                for active_len in 0..=capacity {
                    let mut model = (0..active_len)
                        .map(|index| {
                            (0..element_words)
                                .map(|word| index * 100 + word + 1)
                                .collect::<Vec<_>>()
                        })
                        .collect::<Vec<_>>();
                    let base = allocate_words(&mut vm, layout, &model).expect("allocate list");
                    assert_eq!(
                        (read_words(&vm, base, layout))
                            .expect("expected successful fixture result"),
                        model.clone()
                    );
                    assert_eq!(
                        (len(&vm, base, layout)).expect("expected successful fixture result"),
                        active_len
                    );
                    for index in 0..active_len {
                        assert_eq!(
                            (get_words(&vm, base, layout, index))
                                .expect("expected successful fixture result"),
                            Some(model[usize::try_from(index).expect("bounded index")].clone())
                        );
                    }
                    assert_eq!(
                        (get_words(&vm, base, layout, active_len))
                            .expect("expected successful fixture result"),
                        None
                    );
                    let width = usize::try_from(element_words).expect("bounded element width");
                    let replacement = vec![9_000 + active_len; width];
                    let before_failed_set = snapshot(&vm, base, layout);
                    assert!(matches!(
                        try_set_words(&mut vm, base, layout, active_len, &replacement,),
                        Ok(false)
                    ));
                    assert_eq!(
                        snapshot(&vm, base, layout),
                        before_failed_set,
                        "failed set mutated capacity {capacity}, length {active_len}, width {element_words}"
                    );
                    if active_len == 0 {
                        let before_empty_pop = snapshot(&vm, base, layout);
                        assert_eq!(
                            (pop_words(&mut vm, base, layout))
                                .expect("expected successful fixture result"),
                            None
                        );
                        assert_eq!(
                            snapshot(&vm, base, layout),
                            before_empty_pop,
                            "empty pop mutated capacity {capacity}, width {element_words}"
                        );
                    }
                    if active_len == capacity {
                        let before_failed_push = snapshot(&vm, base, layout);
                        assert!(matches!(
                            try_push_words(&mut vm, base, layout, &replacement),
                            Ok(false)
                        ));
                        assert_eq!(
                            snapshot(&vm, base, layout),
                            before_failed_push,
                            "failed push mutated capacity {capacity}, width {element_words}"
                        );
                    } else {
                        assert!(matches!(
                            try_push_words(&mut vm, base, layout, &replacement),
                            Ok(true)
                        ));
                        model.push(replacement.clone());
                        assert_eq!(
                            (read_words(&vm, base, layout))
                                .expect("expected successful fixture result"),
                            model.clone()
                        );
                    }
                    if let Some(first) = model.first() {
                        assert!(matches!(contains_words(&vm, base, layout, first), Ok(true)));
                    }
                    let absent = vec![u64::MAX; width];
                    assert!(matches!(
                        contains_words(&vm, base, layout, &absent),
                        Ok(false)
                    ));
                    let expected = model.pop();
                    assert_eq!(
                        (pop_words(&mut vm, base, layout))
                            .expect("expected successful fixture result"),
                        expected
                    );
                    assert_eq!(
                        (read_words(&vm, base, layout))
                            .expect("expected successful fixture result"),
                        model
                    );
                }
            }
        }
    }
    #[test]
    fn malformed_element_width_fails_before_mutation() {
        let mut vm = IVM::new(0);
        let layout = ListLayoutV1::try_new(2, 2).expect("layout");
        let base = allocate_words(&mut vm, layout, &[vec![1, 2]]).expect("allocate list");
        let before = read_words(&vm, base, layout).expect("read before");
        assert!(matches!(
            try_set_words(&mut vm, base, layout, 0, &[9]),
            Err(VMError::DecodeError)
        ));
        assert!(matches!(
            try_push_words(&mut vm, base, layout, &[9]),
            Err(VMError::DecodeError)
        ));
        assert_eq!(
            (read_words(&vm, base, layout)).expect("expected successful fixture result"),
            before
        );
    }
}
