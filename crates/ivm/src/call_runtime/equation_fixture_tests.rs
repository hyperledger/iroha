//! Native interpreter call-method observations from an authenticated compiler image.
//!
//! The explicit method sequence is a diagnostic transition fixture, not a full
//! instruction trace or proof. A separate complete native run checks the image.

use super::*;
use crate::{
    ProgramMetadata, call_frame::native_equation_fixture_tests::observe, host::DefaultHost,
};
use kotodama_lang::compiler::Compiler;
use norito::{json, json::Value};

fn operands(vm: &IVM) -> Value {
    json!({
        "values": ([10, 11, 12, 13, 31].map(|register| vm.registers.get(register)).to_vec()),
        "tags": ([10, 11, 12, 13, 31].map(|register| vm.registers.tag(register)).to_vec()),
    })
}

fn runtime_capture() -> Value {
    // Both real private calls execute in the complete native run. The repeated
    // helper retains its authenticated callable and exercises a child frame;
    // runtime view roots cannot be invoked through the private call boundary.
    let code = Compiler::new().compile_source(
        "seiyaku NativeFrameCapture { fn leaf(bool value) -> bool { value } view fn main() authorize(anyone) -> bool { leaf(value: leaf(value: true)) } }"
    ).unwrap();
    let metadata = ProgramMetadata::parse(&code).unwrap();
    let interface = metadata.contract_interface.as_ref().unwrap();
    let main_pc = interface
        .entrypoints
        .iter()
        .find(|entry| entry.name == "main")
        .unwrap()
        .entry_pc;
    let root_callable = interface
        .callables
        .iter()
        .find(|callable| callable.entry_pc == main_pc)
        .unwrap();
    let child_callable = interface
        .callables
        .iter()
        .find(|callable| {
            callable.argument_word_count().unwrap() == 1
                && callable.result_word_count().unwrap() == 1
        })
        .unwrap();
    let mut vm = IVM::new(1_000_000);
    vm.load_program(&code).unwrap();
    vm.select_entrypoint("main").unwrap();
    vm.registers.set(31, u64::MAX);
    vm.registers.set_tag(31, true);
    vm.begin_root_call(&mut DefaultHost::default()).unwrap();
    assert_eq!(vm.registers.get(31), vm.memory.stack_top());
    assert!(!vm.registers.tag(31));
    let root_result = vm.registers.get(12);
    let root_sp = vm.registers.get(31);
    let root_entry = json!({"operands": (operands(&vm)), "owner": (observe(&vm.memory, root_result & !15)),
        "frame_bytes": (root_callable.frame_bytes as u64), "entry_pc": (root_callable.entry_pc),
        "argument_words": (root_callable.argument_word_count().unwrap() as u64), "result_words": (root_callable.result_word_count().unwrap() as u64)});
    let parent_start = root_entry["owner"]["descriptors"][0][0].as_u64().unwrap();
    let parent_end = root_entry["owner"]["descriptors"][0][1].as_u64().unwrap();
    assert!(parent_end - parent_start >= 16);
    let child_argument = parent_start;
    let child_result = parent_start + 8;
    vm.store_u64(child_argument, 1).unwrap();
    for (register, value) in [
        (10, child_argument),
        (11, 1),
        (12, child_result),
        (13, 1),
        (31, parent_start),
    ] {
        vm.registers.set(register, value);
        vm.registers.set_tag(register, false);
    }
    let child_operands = operands(&vm);
    let before_child = observe(&vm.memory, child_result & !15);
    vm.begin_child_call(metadata.prefix_len() as u64 + child_callable.entry_pc)
        .unwrap();
    let child_entry = json!({"operands": child_operands, "before_owner": before_child,
        "owner": (observe(&vm.memory, child_result & !15)), "frame_bytes": (child_callable.frame_bytes as u64),
        "entry_pc": (child_callable.entry_pc), "argument_words": (child_callable.argument_word_count().unwrap() as u64),
        "result_words": (child_callable.result_word_count().unwrap() as u64)});
    vm.registers.set(10, child_result);
    vm.registers.set(11, 1);
    assert_eq!(vm.finish_call(), Err(VMError::AssertionFailed));
    vm.store_u64(child_result, 1).unwrap();
    vm.registers.set(31, parent_start + 8);
    let before_wrong_sp = observe(&vm.memory, child_result & !15);
    let gas_before_wrong_sp = vm.remaining_gas();
    assert_eq!(vm.finish_call(), Err(VMError::AssertionFailed));
    let gas_after_wrong_sp = vm.remaining_gas();
    assert!(
        gas_after_wrong_sp < gas_before_wrong_sp,
        "native typed-word gas precedes final SP refusal"
    );
    assert_eq!(observe(&vm.memory, child_result & !15), before_wrong_sp);
    vm.registers.set(31, parent_start);
    let child_before_return = observe(&vm.memory, child_result & !15);
    let child_return_operands = operands(&vm);
    vm.finish_call().unwrap();
    let child_after_return = observe(&vm.memory, child_result & !15);
    assert_eq!(vm.memory.load_u64(child_result).unwrap(), 1);
    vm.store_u64(root_result, 1).unwrap();
    vm.registers.set(10, root_result);
    vm.registers.set(11, 1);
    vm.registers.set(31, root_sp);
    let root_before_return = observe(&vm.memory, root_result & !15);
    let root_return_operands = operands(&vm);
    vm.finish_call().unwrap();
    let root_after_return = observe(&vm.memory, root_result & !15);
    assert_eq!(vm.call_result_word_count(), Ok(1));
    assert_eq!(vm.public_call_result_word(0), Ok(1));
    let mut executed = IVM::new(1_000_000);
    executed.load_program(&code).unwrap();
    executed.select_entrypoint("main").unwrap();
    executed.run().unwrap();
    assert_eq!(executed.public_call_result_word(0), Ok(1));
    json!({
        "schema": "ivm.native-call-runtime-equations.v1",
        "scope": "Native call methods on compiler-loaded image plus separate complete native run; no AIR or finalized-state qualification",
        "program_bytes": code,
        "root_entry": root_entry, "child_entry": child_entry,
        "child_return": {"operands": child_return_operands, "before_owner": child_before_return, "after_owner": child_after_return},
        "root_return": {"operands": root_return_operands, "before_owner": root_before_return, "after_owner": root_after_return},
        "failed_sp_gas_before": gas_before_wrong_sp, "failed_sp_gas_after": gas_after_wrong_sp,
        "native_program_result": 1_u64,
    })
}

#[test]
fn native_runtime_frame_capture_preserves_actual_root_sp_and_failed_return_gas_order() {
    let capture = runtime_capture();
    let bytes = norito::json::to_vec(&capture).unwrap();
    assert!(bytes.len() < 4 * 1024 * 1024);
    let decoded: Value = norito::json::from_slice(&bytes).unwrap();
    assert_eq!(decoded, capture);
}

#[test]
#[ignore = "explicit native call-runtime capture for the private AIR consumer"]
fn capture_native_runtime_frame_equations() {
    println!(
        "IVM_NATIVE_CALL_RUNTIME_CAPTURE={}",
        norito::json::to_json(&runtime_capture()).unwrap()
    );
}
