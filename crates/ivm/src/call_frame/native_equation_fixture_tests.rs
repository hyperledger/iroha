//! Genuine native frame-owner captures for independent private-equation testing.
//!
//! Fixed public diagnostic values only. These captures do not authorize a proof
//! and do not claim complete instruction, callable, gas or finalized-state coverage.

use super::*;
use norito::{json, json::Value};

const CELLS: usize = 4097;

fn callable(frame_bytes: u32, result_words: usize) -> CallFrameShape {
    CallFrameShape {
        entry_pc: 4,
        frame_bytes,
        argument_words: 0,
        result_words,
    }
}

fn initialized_cells(frame: &Frame, first: u64) -> Vec<u64> {
    (0..CELLS)
        .map(|offset| {
            let cell = first + offset as u64 * 16;
            (0..16).fold(0, |mask, byte| {
                let single = Region::new(cell + byte, 1).unwrap();
                mask | (u64::from(
                    frame.stack.initialized(single) || frame.results.initialized(single),
                ) << byte)
            })
        })
        .collect()
}

fn descriptor(frame: &Frame) -> [u64; 8] {
    [
        frame.stack.region.start,
        frame.stack.region.end,
        frame.arguments.start,
        frame.arguments.end,
        frame.results.region.start,
        frame.results.region.end,
        frame.entry_stack_pointer,
        frame.entry_pc,
    ]
}

/// Observe original native owner state for a test in the interpreter module.
/// There is no corresponding release-build observer or authority-bearing API.
pub(crate) fn observe(memory: &Memory, first_cell: u64) -> Value {
    let frames = &memory.call_frames;
    json!({
        "descriptors": (frames.frames.iter().map(|frame| descriptor(frame).to_vec()).collect::<Vec<_>>()),
        "initialization": (frames.frames.iter().map(|frame| initialized_cells(frame, first_cell)).collect::<Vec<_>>()),
        "first_cell": first_cell,
        "stack_top": (memory.stack_top()),
        "heap_end": (Memory::HEAP_START + memory.heap_allocated_len()),
        "completed": (frames.completed.map(|range| vec![range.start, range.end])),
    })
}

fn owner_capture(result_words: usize, shift: u64, root_return: bool) -> Value {
    let mut memory = Memory::new_with_stack_limit(Memory::STACK_SIZE).unwrap();
    let top = memory.stack_top();
    let root_callable = callable(128 * 1024 + 32, if root_return { result_words } else { 1 });
    let root_result = Memory::HEAP_START + shift;
    assert_eq!(memory.alloc(65552).unwrap(), Memory::HEAP_START);
    assert_eq!(memory.heap_allocated_len(), 65552);
    memory
        .call_frames
        .enter_root(
            top,
            &root_callable,
            CallTables {
                argument_base: 0,
                argument_words: 0,
                result_base: root_result,
                result_words: root_callable.result_words as u64,
            },
            top,
        )
        .unwrap();
    let root_descriptor = descriptor(memory.call_frames.frames.last().unwrap());
    let root_entry = json!({
        "root": true, "sp": top, "frame_bytes": (root_callable.frame_bytes as u64),
        "entry_pc": (root_callable.entry_pc), "argument": 0_u64, "argument_words": 0_u64,
        "result": root_result, "result_words": (root_callable.result_words as u64),
        "stack_top": top, "heap_end": (Memory::HEAP_START + memory.heap_allocated_len()),
        "parent_start": 0_u64, "parent_end": 0_u64, "descriptor": (root_descriptor.to_vec()),
    });
    let mut entries = vec![root_entry];
    let (result, saved_sp, before_entry, installed, parent_before) = if root_return {
        let result = root_result;
        let installed = observe(&memory, result & !15);
        (result, top, Value::Null, installed, Vec::<u64>::new())
    } else {
        let parent_start = memory.call_frames.frames.last().unwrap().stack.region.start;
        let result = parent_start + 16 + shift;
        // A native parent byte outside the child's result survives copyback.
        memory.store_u8(result - 1, 1).unwrap();
        let before = observe(&memory, result & !15);
        let parent_before =
            initialized_cells(memory.call_frames.frames.last().unwrap(), result & !15);
        let child_callable = callable(64, result_words);
        memory
            .call_frames
            .enter_child(
                parent_start,
                &child_callable,
                CallTables {
                    argument_base: 0,
                    argument_words: 0,
                    result_base: result,
                    result_words: result_words as u64,
                },
                top,
            )
            .unwrap();
        let installed = observe(&memory, result & !15);
        entries.push(json!({
            "root": false, "sp": parent_start, "frame_bytes": (child_callable.frame_bytes as u64),
            "entry_pc": (child_callable.entry_pc), "argument": 0_u64, "argument_words": 0_u64,
            "result": result, "result_words": (result_words as u64), "stack_top": top,
            "heap_end": (Memory::HEAP_START + memory.heap_allocated_len()),
            "parent_start": (root_descriptor[0]), "parent_end": (root_descriptor[1]),
            "descriptor": (descriptor(memory.call_frames.frames.last().unwrap()).to_vec()),
        }));
        (result, parent_start, before, installed, parent_before)
    };
    let original_descriptor = descriptor(memory.call_frames.frames.last().unwrap());
    let end = result + result_words as u64 * 8;
    for address in result..end - 1 {
        memory
            .store_u8(address, u8::from(address % 8 == 0))
            .unwrap();
    }
    let before_failed = observe(&memory, result & !15);
    assert!(matches!(
        memory
            .call_frames
            .finish(saved_sp, result, result_words as u64),
        Err(VMError::AssertionFailed)
    ));
    assert_eq!(observe(&memory, result & !15), before_failed);
    memory.store_u8(end - 1, 0).unwrap();
    let before_return = observe(&memory, result & !15);
    for (sp, base, count) in [
        (saved_sp + 8, result, result_words as u64),
        (saved_sp, result + 8, result_words as u64),
        (saved_sp, result, result_words as u64 - 1),
    ] {
        assert!(memory.call_frames.finish(sp, base, count).is_err());
        assert_eq!(observe(&memory, result & !15), before_return);
    }
    memory
        .call_frames
        .finish(saved_sp, result, result_words as u64)
        .unwrap();
    let after_return = observe(&memory, result & !15);
    if root_return {
        assert!(memory.call_frames.frames.is_empty());
        assert_eq!(
            memory.call_frames.completed_word_count().unwrap(),
            result_words
        );
    } else {
        memory
            .call_frames
            .check_access(result, result_words as u64 * 8, Perm::READ)
            .unwrap();
        let parent_after =
            initialized_cells(memory.call_frames.frames.last().unwrap(), result & !15);
        for (offset, (&before, &after)) in parent_before.iter().zip(&parent_after).enumerate() {
            let cell = (result & !15) + offset as u64 * 16;
            let expected = (0..16).fold(before, |bits, byte| {
                bits | (u64::from(result <= cell + byte && cell + byte < end) << byte)
            });
            assert_eq!(after, expected);
        }
    }
    json!({
        "scope": "Actual Memory stores and CallFrameMemory entry/finish; no instruction-dispatch or gas qualification",
        "entries": entries,
        "root_return": root_return,
        "result_words": (result_words as u64),
        "shift": shift,
        "stack_top": top,
        "root_descriptor": (root_descriptor.to_vec()),
        "selected_descriptor": (original_descriptor.to_vec()),
        "before_entry": before_entry,
        "installed": installed,
        "before_failed_return": before_failed,
        "before_return": before_return,
        "after_return": after_return,
    })
}

fn owner_captures() -> Value {
    let cases = [1, 2, 8192]
        .into_iter()
        .flat_map(|words| [0, 8].into_iter().map(move |shift| (words, shift)))
        .flat_map(|(words, shift)| {
            [true, false]
                .into_iter()
                .map(move |root| owner_capture(words, shift, root))
        })
        .collect::<Vec<_>>();
    json!({"schema": "ivm.native-frame-owner-equations.v1", "cells": (CELLS as u64), "cases": cases})
}

#[test]
fn actual_native_frame_owner_captures_are_complete_and_canonically_roundtrip() {
    let captures = owner_captures();
    assert_eq!(captures["cases"].as_array().unwrap().len(), 12);
    let bytes = norito::json::to_vec(&captures).unwrap();
    assert!(bytes.len() < 16 * 1024 * 1024);
    let decoded: Value = norito::json::from_slice(&bytes).unwrap();
    assert_eq!(decoded, captures);
}

#[test]
#[ignore = "explicit genuine native frame-owner capture for the private AIR consumer"]
fn capture_actual_native_frame_owner_equations() {
    println!(
        "IVM_NATIVE_FRAME_OWNER_CAPTURE={}",
        norito::json::to_json(&owner_captures()).unwrap()
    );
}
