//! Actual VM controls for dead host operands, opposite-register cycles and live source custody.

use ivm::{
    CoreHost, IVM, encoding,
    host::{DefaultHost, IVMHost},
    instruction,
};
use kotodama_lang::compiler::Compiler;
mod common;

fn compile(source: &str) -> Vec<u8> {
    Compiler::new()
        .compile_source(source)
        .expect("canonical typed compiler")
}
fn run(program: &[u8], host: &mut dyn IVMHost) -> IVM {
    let mut vm = IVM::new(4_000_000);
    vm.load_program(program).unwrap();
    common::select_kotodama_entrypoint(&mut vm, program, "main");
    vm.run_with_host(host)
        .expect("unchanged typed tables, numeric and host checks");
    assert!(vm.remaining_gas() < 4_000_000);
    vm
}
fn cycle_source() -> String {
    let parameters = (0..13)
        .map(|index| format!("int a{index}"))
        .chain((0..6).map(|index| format!("bool b{index}")))
        .collect::<Vec<_>>()
        .join(", ");
    let branches = (0..6)
        .map(|index| {
            format!(
                "if b{index} {{ return a{} - a{}; }}",
                index * 2,
                index * 2 + 1
            )
        })
        .collect::<Vec<_>>()
        .join(" ");
    let calls = (0..7)
        .map(|selected| {
            let arguments = (0..13)
                .map(|index| format!("a{index}: {}", index * index + 3))
                .chain((0..6).map(|index| format!("b{index}: {}", selected == index)))
                .collect::<Vec<_>>()
                .join(", ");
            format!("choose({arguments})")
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "seiyaku Cycles {{ fn choose({parameters}) -> int {{ {branches} return a11 - a12; }} view fn main() authorize(anyone) -> (int, int, int, int, int, int, int) {{ return ({calls}); }} }}"
    )
}

#[test]
fn dead_numeric_register_cycle_executes_all_branches_on_both_hosts() {
    let program = compile(&cycle_source());
    let expected = [-1, -5, -9, -13, -17, -21, -23];
    let mut default = DefaultHost::new();
    let vm = run(&program, &mut default);
    for (index, expected) in expected.iter().enumerate() {
        assert_eq!(common::decode_i64_return_word(&vm, index), *expected);
    }
    let mut core = CoreHost::new();
    let mut vm = IVM::new(4_000_000);
    vm.load_program(&program).unwrap();
    common::select_kotodama_entrypoint(&mut vm, &program, "main");
    let budget = iroha_allocation::AllocationBudget::new(32 * 1024 * 1024);
    let mut steps =
        ivm::execution_step_recorder::DiagnosticStepRecorder::try_new(32_768, &budget).unwrap();
    vm.run_with_host_diagnostic_steps(&mut core, &mut steps)
        .unwrap();
    for (index, expected) in expected.iter().enumerate() {
        assert_eq!(common::decode_i64_return_word(&vm, index), *expected);
    }
    let addi = instruction::wide::arithmetic::ADDI;
    let cycle = [
        Some(encoding::wide::encode_ri(addi, 27, 10, 0)),
        Some(encoding::wide::encode_ri(addi, 10, 11, 0)),
        Some(encoding::wide::encode_ri(addi, 11, 27, 0)),
    ];
    assert!(
        steps
            .records()
            .windows(3)
            .any(|steps| steps.iter().map(|step| step.instruction).eq(cycle)),
        "a real r11/r10 source cycle must execute through the existing scratch move kernel"
    );
    assert!(vm.remaining_gas() < 4_000_000);
}

#[test]
fn host_operands_live_in_tuples_survive_numeric_state_and_nested_calls() {
    let program = compile(
        r#"seiyaku CarriedOperands { permission WriteState;
        state StateMap<Name, int> Values;
        fn subtract(int left, int right) -> int { return left - right; }
        fn carry(Name key, int left, int right) -> (int, int, int, int) {
            let originals = (left, right);
            let difference = left - right;
            Values[key] = difference;
            let result = subtract(left: left, right: right);
            return (originals.0, originals.1, Values.get(key).unwrap_or(0), result);
        }
        kotoage fn main() authorize(WriteState) -> (int, int, int, int) {
            return carry(key: Name::parse("retained"), left: 91, right: 37);
        }
    }"#,
    );
    let mut default = DefaultHost::new();
    let mut core = CoreHost::new();
    for host in [
        &mut default as &mut dyn IVMHost,
        &mut core as &mut dyn IVMHost,
    ] {
        let vm = run(&program, host);
        for (index, expected) in [91, 37, 54, 54].into_iter().enumerate() {
            assert_eq!(common::decode_i64_return_word(&vm, index), expected);
        }
    }
}

#[path = "kotodama_private_single_use.rs"]
mod private_single_use;

#[path = "kotodama_frame_emission.rs"]
mod frame_emission;

#[path = "kotodama_compact_emission.rs"]
mod compact_emission;

#[path = "kotodama_local_emission.rs"]
mod local_emission;

#[path = "kotodama_numeric_zero.rs"]
mod numeric_zero;
