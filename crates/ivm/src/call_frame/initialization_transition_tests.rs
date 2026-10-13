//! Native region-relative initialization oracles for the held typed byte-mask bank.
//!
//! These exercise the existing memory and frame owners without adding a public
//! test shim or granting proof authority to a descriptor or packet.
use super::*;

const TOP: u64 = Memory::STACK_START + 256;
const ARG: u64 = Memory::HEAP_START + 64;
const RESULT: u64 = Memory::HEAP_START + 8;

fn callable(frame_bytes: u32, results: usize) -> CallFrameShape {
    CallFrameShape {
        entry_pc: 0,
        frame_bytes,
        argument_words: 1,
        result_words: results,
    }
}
fn tables(argument: u64, result: u64, result_words: u64) -> CallTables {
    CallTables {
        argument_base: argument,
        argument_words: 1,
        result_base: result,
        result_words,
    }
}
fn mask(region: &InitializedRegion, cell: u64) -> u16 {
    (0..16).fold(0, |value, byte| {
        value | (u16::from(region.initialized(Region::new(cell + byte, 1).unwrap())) << byte)
    })
}
fn top_mask(frames: &CallFrameMemory, cell: u64) -> u16 {
    let frame = frames.frames.last().unwrap();
    mask(&frame.stack, cell) | mask(&frame.results, cell)
}

#[test]
fn absolute_cell_masks_match_native_shifted_region_bitmaps_and_partial_writes() {
    for start in [Memory::STACK_START, Memory::STACK_START + 8] {
        for length in [8, 16, 24, 32] {
            let mut region =
                InitializedRegion::new(Region::new(start, length).unwrap(), None).unwrap();
            let mut written = std::collections::BTreeSet::new();
            // Overlap, narrow writes and final-byte completion use actual native
            // record_write rather than assuming a word count initializes bytes.
            for (address, bytes) in [
                (start, 7),
                (start + 7, 1),
                (start, 8),
                (start + length - 8, 8),
            ] {
                region.record_write(Region::new(address, bytes).unwrap());
                written.extend(address..address + bytes);
                for cell in (start & !15..(start + length + 15) & !15).step_by(16) {
                    let expected = (0..16).fold(0, |bits, i| {
                        bits | (u16::from(written.contains(&(cell + i))) << i)
                    });
                    assert_eq!(mask(&region, cell), expected);
                }
                for address in start..start + length {
                    for bytes in 1..=start + length - address {
                        assert_eq!(
                            region.initialized(Region::new(address, bytes).unwrap()),
                            (address..address + bytes).all(|a| written.contains(&a))
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn successful_memory_stores_initialize_exact_bytes_and_failed_stores_leave_no_mask_or_log() {
    let mut memory = Memory::new_with_stack_limit(Memory::MIN_STACK_SIZE).unwrap();
    memory
        .call_frames
        .enter_root(TOP, &callable(128, 2), tables(ARG, RESULT, 2), TOP)
        .unwrap();
    assert_eq!(top_mask(&memory.call_frames, RESULT & !15), 0);
    assert!(match (
        &(memory.store_u128(RESULT, 1)),
        &(VMError::MisalignedAccess {
            addr: RESULT as u32
        })
    ) {
        (
            Err(VMError::MisalignedAccess {
                addr: actual_field_0,
            }),
            VMError::MisalignedAccess {
                addr: expected_field_0,
            },
        ) => actual_field_0 == expected_field_0,
        _ => false,
    });
    assert!(
        memory.store_u64(ARG, 1).is_err(),
        "argument table remains read-only"
    );
    assert!(
        memory.store_u64(TOP - 136, 1).is_err(),
        "outside-frame access is refused"
    );
    assert!(memory.try_write_log_snapshot().unwrap().is_empty());
    assert_eq!(top_mask(&memory.call_frames, RESULT & !15), 0);
    assert!(memory.call_frames.active_result_word(0).is_err());
    memory.store_u64(RESULT, 0x0123_4567_89ab_cdef).unwrap();
    assert_eq!(top_mask(&memory.call_frames, RESULT & !15), 0xff00);
    assert_eq!(top_mask(&memory.call_frames, (RESULT & !15) + 16), 0);
    assert_eq!(
        memory.active_call_result(0).unwrap(),
        (RESULT, 0x0123_4567_89ab_cdef)
    );
    assert!(memory.call_frames.active_result_word(1).is_err());
    assert!(memory.call_frames.finish(TOP, RESULT, 2).is_err());
    memory.store_u64(RESULT + 8, 0xfedc_ba98_7654_3210).unwrap();
    assert_eq!(top_mask(&memory.call_frames, (RESULT & !15) + 16), 0x00ff);
    let log = memory.try_write_log_snapshot().unwrap();
    assert_eq!(log.len(), 2);
    assert_eq!(log[0].address(), RESULT);
    assert_eq!(log[0].bytes(), &0x0123_4567_89ab_cdef_u64.to_le_bytes());
    assert_eq!(log[1].address(), RESULT + 8);
    assert_eq!(log[1].bytes(), &0xfedc_ba98_7654_3210_u64.to_le_bytes());
    memory.call_frames.finish(TOP, RESULT, 2).unwrap();
    assert_eq!(memory.call_frames.completed_word_count().unwrap(), 2);
    // Existing bytes survive, while a fresh frame cannot borrow old initialized bits.
    memory
        .call_frames
        .enter_root(TOP, &callable(128, 2), tables(ARG, RESULT, 2), TOP)
        .unwrap();
    assert_eq!(top_mask(&memory.call_frames, RESULT & !15), 0);
    assert!(memory.call_frames.active_result_word(0).is_err());
    assert!(memory.call_frames.finish(TOP, RESULT, 2).is_err());
}

#[test]
fn write_tracking_allocation_refusal_precedes_memory_and_initialization_mutation() {
    let budget = AllocationBudget::new(128 * 1024 * 1024);
    let mut memory = Memory::new_with_stack_limit_funded(Memory::MIN_STACK_SIZE, &budget).unwrap();
    memory
        .call_frames
        .enter_root(TOP, &callable(128, 1), tables(ARG, RESULT, 1), TOP)
        .unwrap();
    let reserved = budget.reserved_bytes();
    budget.set_limit_bytes(reserved);
    assert!(matches!(
        memory.store_u64(RESULT, 7),
        Err(VMError::AllocationDeferred(_))
    ));
    assert_eq!(budget.reserved_bytes(), reserved);
    assert_eq!(top_mask(&memory.call_frames, RESULT & !15), 0);
    assert!(memory.call_frames.active_result_word(0).is_err());
    budget.set_limit_bytes(128 * 1024 * 1024);
    assert!(memory.try_write_log_snapshot().unwrap().is_empty());
    memory.store_u64(RESULT, 7).unwrap();
    assert_eq!(top_mask(&memory.call_frames, RESULT & !15), 0xff00);
    assert_eq!(memory.active_call_result(0).unwrap(), (RESULT, 7));
    assert_eq!(memory.try_write_log_snapshot().unwrap().len(), 1);
}

#[test]
fn adjacent_stack_result_masks_and_child_return_preserve_separate_generation_lifetimes() {
    let mut frames = CallFrameMemory::default();
    // A legal root can put the two disjoint regions in opposite halves of one
    // physical cell. Their native bitmap indexes are both zero, not bit aliases.
    let cell = Memory::STACK_START + 128;
    frames
        .enter_root(cell + 8, &callable(16, 1), tables(ARG, cell + 8, 1), TOP)
        .unwrap();
    frames.record_write(cell, 8);
    assert_eq!(top_mask(&frames, cell), 0x00ff);
    assert!(frames.active_result_word(0).is_err());
    frames.record_write(cell + 8, 7);
    assert_eq!(top_mask(&frames, cell), 0x7fff);
    assert!(frames.finish(cell + 8, cell + 8, 1).is_err());
    frames.record_write(cell + 15, 1);
    assert_eq!(top_mask(&frames, cell), 0xffff);
    frames.finish(cell + 8, cell + 8, 1).unwrap();
    frames
        .enter_root(TOP, &callable(128, 1), tables(ARG, RESULT, 1), TOP)
        .unwrap();
    let arg = TOP - 32;
    let result = TOP - 16;
    frames.record_write(arg, 8);
    frames
        .enter_child(TOP - 128, &callable(64, 1), tables(arg, result, 1), TOP)
        .unwrap();
    assert_eq!(top_mask(&frames, result), 0);
    frames.record_write(result, 7);
    assert!(frames.finish(TOP - 128, result, 1).is_err());
    frames.record_write(result + 7, 1);
    frames.finish(TOP - 128, result, 1).unwrap();
    frames.check_access(result, 8, Perm::READ).unwrap();
    assert_eq!(top_mask(&frames, result), 0x00ff);
    frames
        .enter_child(TOP - 128, &callable(64, 1), tables(arg, result, 1), TOP)
        .unwrap();
    assert_eq!(
        top_mask(&frames, result),
        0,
        "same physical bytes have fresh child initialization"
    );
    assert!(frames.finish(TOP - 128, result, 1).is_err());
}
