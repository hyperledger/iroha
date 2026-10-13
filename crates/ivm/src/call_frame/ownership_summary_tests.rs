//! Source-coupled ancestry reduction controls for a future constrained memory owner.
//!
//! This is a test-only prototype. It cannot authorize a memory packet or replace
//! constrained frame initialization, call entry, return, permissions or privacy.

use super::*;

const TOP: u64 = Memory::STACK_START + 4096;
const ARG: u64 = Memory::HEAP_START;
const RESULT: u64 = Memory::HEAP_START + 32;

fn callable(frame_bytes: u32, words: usize) -> CallFrameShape {
    CallFrameShape {
        entry_pc: 0,
        frame_bytes,
        argument_words: words,
        result_words: words,
    }
}

fn tables(argument_base: u64, result_base: u64, words: u64) -> CallTables {
    CallTables {
        argument_base,
        argument_words: words,
        result_base,
        result_words: words,
    }
}

/// Candidate owner decision only; all regional/privacy/cursor checks remain external.
fn summarized_access(
    frames: &CallFrameMemory,
    address: u64,
    bytes: u64,
    permission: Perm,
) -> Result<(), VMError> {
    let Some(frame) = frames.frames.last() else {
        return Ok(());
    };
    let range = Region::new(address, bytes)?;
    if bytes == 0 {
        return Ok(());
    }
    let read = permission.contains(Perm::READ);
    let write = permission.contains(Perm::WRITE);
    let permitted = if frame.stack.region.contains(range) {
        !read || frame.stack.initialized(range)
    } else if frame.arguments.contains(range) {
        read && !write
    } else if frame.results.region.contains(range) {
        write && !read
    } else {
        let root = &frames.frames[0];
        address < Memory::STACK_START
            && range.end <= Memory::STACK_START
            && !root.arguments.overlaps(range)
            && !root.results.region.overlaps(range)
    };
    if permitted {
        Ok(())
    } else {
        Err(VMError::MemoryAccessViolation {
            addr: address as u32,
            perm: permission,
        })
    }
}

fn assert_lifecycle_invariant(frames: &CallFrameMemory) {
    for (index, frame) in frames.frames.iter().enumerate() {
        assert!(frame.stack.region.start >= Memory::STACK_START);
        assert!(frame.stack.region.end >= frame.stack.region.start);
        if index != 0 {
            let parent = &frames.frames[index - 1];
            for table in [frame.arguments, frame.results.region] {
                if table.empty() {
                    assert_eq!(table, Region { start: 0, end: 0 });
                } else {
                    assert!(parent.stack.region.contains(table));
                    assert!(table.start >= Memory::STACK_START);
                }
            }
        }
    }
}

fn assert_equivalent(frames: &CallFrameMemory) {
    assert_lifecycle_invariant(frames);
    let mut addresses = vec![0, 1, ARG, RESULT, Memory::STACK_START, u64::MAX];
    for frame in frames.frames.iter() {
        for region in [frame.stack.region, frame.arguments, frame.results.region] {
            for boundary in [region.start, region.end] {
                for offset in 0..=17 {
                    addresses.push(boundary.saturating_sub(offset));
                    addresses.push(boundary.saturating_add(offset));
                }
            }
        }
    }
    addresses.sort_unstable();
    addresses.dedup();
    for address in addresses {
        for bytes in [0, 1, 7, 8, 9, 16, 17, 64, u64::MAX] {
            for permission in [
                Perm::READ,
                Perm::WRITE,
                Perm::READ | Perm::WRITE,
                Perm::EXECUTE,
                Perm::NONE,
            ] {
                let actual = frames.check_access(address, bytes, permission);
                let expected = summarized_access(frames, address, bytes, permission);
                let equivalent = match (&actual, &expected) {
                    (Ok(()), Ok(()))
                    | (Err(VMError::MemoryOutOfBounds), Err(VMError::MemoryOutOfBounds)) => true,
                    (
                        Err(VMError::MemoryAccessViolation { addr: a, perm: p }),
                        Err(VMError::MemoryAccessViolation { addr: b, perm: q }),
                    ) => a == b && p == q,
                    _ => false,
                };
                assert!(
                    equivalent,
                    "depth={} address={address} bytes={bytes} permission={permission:?}: {actual:?} != {expected:?}",
                    frames.frames.len(),
                );
            }
        }
    }
}

#[test]
fn exact_owner_summary_matches_all_ancestors_across_nested_calls_and_returns() {
    let mut frames = CallFrameMemory::default();
    assert_equivalent(&frames);
    frames
        .enter_root(TOP, &callable(128, 1), tables(ARG, RESULT, 1), TOP)
        .unwrap();
    for _ in 1..32 {
        assert_equivalent(&frames);
        let stack = frames.frames.last().unwrap().stack.region;
        let argument = stack.start + 8;
        let result = stack.start + 24;
        // A partial write must not create a fully initialized argument.
        frames.record_write(argument, 7);
        assert!(matches!(
            frames.prepare_child(
                stack.start,
                &callable(128, 1),
                tables(argument, result, 1),
                TOP
            ),
            Err(VMError::AssertionFailed)
        ));
        frames.record_write(argument + 7, 1);
        frames
            .enter_child(
                stack.start,
                &callable(128, 1),
                tables(argument, result, 1),
                TOP,
            )
            .unwrap();
    }
    assert_equivalent(&frames);
    while !frames.is_empty() {
        let frame = frames.frames.last().unwrap();
        let result = frame.results.region.start;
        let entry = frame.entry_stack_pointer;
        frames.record_write(result, 7);
        assert!(frames.finish(entry, result, 1).is_err());
        frames.record_write(result + 7, 1);
        frames.finish(entry, result, 1).unwrap();
        assert_equivalent(&frames);
    }
}

#[test]
fn exact_owner_summary_preserves_zero_tables_and_zero_sized_frames_at_arbitrary_depth() {
    let mut frames = CallFrameMemory::default();
    // The v1 callable ABI requires a result slot, including for Unit. An empty
    // result table is malformed; a zero-byte frame and empty arguments are valid.
    let rejected = callable(0, 0);
    assert!(!rejected.validate());
    assert!(matches!(
        frames.enter_root(TOP, &rejected, tables(0, 0, 0), TOP),
        Err(VMError::AssertionFailed)
    ));
    assert!(frames.is_empty());
    assert_equivalent(&frames);
    let leaf = CallFrameShape {
        result_words: 1,
        ..callable(0, 0)
    };
    assert!(leaf.validate());
    let reserved = CallFrameShape {
        frame_bytes: 16,
        ..leaf.clone()
    };
    let result_table = |result_base| CallTables {
        argument_base: 0,
        argument_words: 0,
        result_base,
        result_words: 1,
    };
    // Preserve 257 live ancestor frames, with the minimum valid reservation
    // needed to own each child's mandatory result slot.
    let top = TOP + 16;
    frames
        .enter_root(top, &reserved, result_table(RESULT), top)
        .unwrap();
    for depth in 0..=256 {
        assert_equivalent(&frames);
        let stack = frames.frames.last().unwrap().stack.region;
        assert_eq!(frames.frames.len(), depth + 1);
        assert!(matches!(
            frames.prepare_child(stack.start, &rejected, tables(0, 0, 0), top),
            Err(VMError::AssertionFailed)
        ));
        assert_eq!(frames.frames.len(), depth + 1);
        frames
            .enter_child(stack.start, &leaf, result_table(stack.start), top)
            .unwrap();
        assert!(frames.frames.last().unwrap().stack.region.empty());
        assert_equivalent(&frames);
        // Empty stack ownership cannot host another callable's result slot.
        assert!(matches!(
            frames.prepare_child(stack.start, &leaf, result_table(stack.start), top),
            Err(VMError::AssertionFailed)
        ));
        assert_eq!(frames.frames.len(), depth + 2);
        assert!(frames.finish(stack.start, stack.start, 1).is_err());
        frames.record_write(stack.start, 8);
        frames.finish(stack.start, stack.start, 1).unwrap();
        assert_equivalent(&frames);
        if depth != 256 {
            frames
                .enter_child(stack.start, &reserved, result_table(stack.start), top)
                .unwrap();
        }
    }
    while !frames.is_empty() {
        let frame = frames.frames.last().unwrap();
        let entry = frame.entry_stack_pointer;
        let result = frame.results.region.start;
        frames.record_write(result, 8);
        frames.finish(entry, result, 1).unwrap();
        assert_equivalent(&frames);
    }
}

#[test]
fn exact_owner_summary_preserves_straddling_root_tables_and_range_overflow() {
    let mut frames = CallFrameMemory::default();
    let argument = Memory::STACK_START - 8;
    frames
        .enter_root(TOP, &callable(128, 2), tables(argument, RESULT, 2), TOP)
        .unwrap();
    assert_equivalent(&frames);
    let child_argument = TOP - 112;
    let child_result = TOP - 80;
    frames.record_write(child_argument, 16);
    frames
        .enter_child(
            TOP - 128,
            &callable(128, 2),
            tables(child_argument, child_result, 2),
            TOP,
        )
        .unwrap();
    assert_equivalent(&frames);
    assert!(matches!(
        frames.check_access(u64::MAX, 8, Perm::READ),
        Err(VMError::MemoryOutOfBounds)
    ));
    assert!(frames.check_access(argument - 1, 2, Perm::READ).is_err());
    assert!(
        frames
            .check_access(Memory::STACK_START - 1, 2, Perm::READ)
            .is_err()
    );
}

#[test]
fn owner_summary_requires_authenticated_child_lifecycle_not_supplied_descriptors() {
    let mut frames = CallFrameMemory::default();
    frames
        .enter_root(TOP, &callable(128, 1), tables(ARG, RESULT, 1), TOP)
        .unwrap();
    let foreign_argument = ARG + 128;
    let foreign_result = RESULT + 128;
    assert!(matches!(
        frames.prepare_child(
            TOP - 128,
            &callable(128, 1),
            tables(foreign_argument, foreign_result, 1),
            TOP
        ),
        Err(VMError::AssertionFailed)
    ));
    // Deliberately bypass the native constructor to model an unbound witness.
    // A valid root descriptor in a foreign machine is not child authority here.
    let mut foreign = CallFrameMemory::default();
    let unbound = foreign
        .prepare_root(
            TOP - 128,
            &callable(128, 1),
            tables(foreign_argument, foreign_result, 1),
            TOP,
        )
        .unwrap();
    frames.enter_prepared_child(unbound);
    let stack = frames.frames.last().unwrap().stack.region;
    frames.record_write(stack.start + 8, 8);
    frames
        .enter_child(
            stack.start,
            &callable(128, 1),
            tables(stack.start + 8, stack.start + 24, 1),
            TOP,
        )
        .unwrap();
    assert!(
        frames
            .check_access(foreign_argument, 8, Perm::READ)
            .is_err()
    );
    assert!(summarized_access(&frames, foreign_argument, 8, Perm::READ).is_ok());
}
