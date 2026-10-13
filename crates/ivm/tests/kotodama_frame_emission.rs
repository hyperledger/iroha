//! Actual VM results, durable effects and checked faults for identical-source native pairs.

use super::common;
use ivm::{
    CoreHost, IVM, ProgramMetadata, VMError,
    host::{DefaultHost, IVMHost},
    numeric::NumericFaultV1,
};
#[path = "../../../fixtures/kotodama/frame_emission/cases.rs"]
mod cases;

fn artifacts(case_id: &str) -> cases::Pair {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    cases::load_pairs(&root)
        .remove(case_id)
        .expect("exact native pair")
}

fn run_entry(
    program: &[u8],
    entrypoint: &str,
    host: &mut dyn IVMHost,
) -> (IVM, Result<(), VMError>) {
    let mut vm = IVM::new(4_000_000);
    vm.load_program(program)
        .expect("current strict canonical artifact admission");
    common::select_kotodama_entrypoint(&mut vm, program, entrypoint);
    let result = vm.run_with_host(host);
    assert!(
        vm.remaining_gas() < 4_000_000,
        "actual charged VM execution"
    );
    (vm, result)
}

fn execute(
    program: &[u8],
    case: &cases::Case,
    host: &mut dyn IVMHost,
) -> (IVM, Result<(), VMError>) {
    let parsed = ProgramMetadata::parse(program).unwrap();
    let interface = parsed
        .contract_interface
        .as_ref()
        .expect("authenticated CNTR");
    assert!(
        interface
            .callables
            .iter()
            .all(|callable| callable.validate())
    );
    if interface
        .entrypoints
        .iter()
        .any(|entrypoint| entrypoint.name == "hajimari")
    {
        let (vm, result) = run_entry(program, "hajimari", host);
        assert!(
            matches!(result, Ok(())),
            "actual constructor for {}",
            case.id
        );
        assert!(
            matches!(vm.public_call_result_word(0), Ok(0)),
            "constructor Unit is canonical"
        );
    }
    run_entry(program, "main", host)
}

fn assert_outcome(case: &cases::Case, vm: &IVM, result: Result<(), VMError>) {
    match case.outcome {
        cases::Outcome::Success(words) => {
            assert!(
                matches!(result, Ok(())),
                "actual source result for {}",
                case.id
            );
            assert_eq!(
                (vm.call_result_word_count()).expect("expected successful fixture result"),
                words.len()
            );
            for (index, word) in words.iter().enumerate() {
                match word {
                    cases::Word::Int(value) => {
                        assert_eq!(common::decode_i64_return_word(vm, index), *value)
                    }
                    cases::Word::Unit => {
                        assert!(matches!(vm.public_call_result_word(index), Ok(0)))
                    }
                }
            }
        }
        cases::Outcome::Fault(fault) => {
            let expected = match fault {
                cases::Fault::DivisionByZero => NumericFaultV1::DivisionByZero,
            };
            assert!(
                matches!((&(result), &(VMError::NumericFault(expected))), (Err(VMError::NumericFault(__actual_value)), VMError::NumericFault(__expected_value)) if __actual_value == __expected_value),
                "the exact checked fault must remain observable"
            );
            assert!(
                vm.public_call_result_word(0).is_err(),
                "a trapped call has no completed public result"
            );
        }
    }
}

fn assert_pair(case_id: &str) {
    let case = cases::CASES.iter().find(|case| case.id == case_id).unwrap();
    let pair = artifacts(case_id);
    assert!(
        case.source
            .contains(&format!("fn {}(", case.retained_helper))
    );
    let public_interface = |artifact: &[u8]| {
        let parsed = ProgramMetadata::parse(artifact).unwrap();
        let mut interface = parsed.contract_interface.unwrap();
        interface.callables.clear();
        for entrypoint in &mut interface.entrypoints {
            entrypoint.entry_pc = 0;
        }
        interface
    };
    assert_eq!(
        public_interface(&pair.before),
        public_interface(&pair.after),
        "identical complete public source/ABI roots and metadata"
    );
    let mut snapshots = Vec::new();
    for program in [&pair.before, &pair.after] {
        let mut default = DefaultHost::new();
        let (vm, result) = execute(program, case, &mut default);
        assert_outcome(case, &vm, result);
        let mut core = CoreHost::new();
        let (vm, result) = execute(program, case, &mut core);
        assert_outcome(case, &vm, result);
        let state = core
            .state_paths()
            .into_iter()
            .map(|path| {
                let bytes = core
                    .state_bytes(&path)
                    .expect("published actual state value");
                (path, bytes)
            })
            .collect::<std::collections::BTreeMap<_, _>>();
        if let Some(expected) = case.trace {
            let trace = state
                .get("trace")
                .expect("actual durable trace after constructor and main");
            assert_eq!(common::decode_int_state_value(trace), expected);
        } else {
            assert!(state.is_empty());
        }
        snapshots.push(state);
    }
    assert_eq!(
        snapshots[0], snapshots[1],
        "all actual CoreHost state effects remain exact for {case_id}"
    );
}

#[test]
fn actual_frame_pairs_preserve_every_large_result_word_and_retained_calls() {
    assert_pair("large_frame");
}
#[test]
fn actual_frame_pairs_restore_exact_call_frames_on_both_conditional_returns() {
    assert_pair("both_returns");
}
#[test]
fn actual_frame_pairs_preserve_checked_fault_and_prior_complete_durable_effects() {
    assert_pair("division_trap");
}

#[test]
fn actual_frame_pairs_publish_canonical_unit_before_both_shared_return_paths() {
    assert_pair("unit_returns");
}
