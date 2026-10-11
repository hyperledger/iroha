//! Runtime coverage for canonical aggregate equality and operand evaluation.
use ivm::{CoreHost, IVM, ProgramMetadata, encoding};
use ivm_abi::{list::ListLayoutV1, sum::SumLayoutV1};
use kotodama_lang::compiler::Compiler as KotodamaCompiler;
use kotodama_lang::compiler::{CompilerMode, CompilerOptions};

fn run(source: &str, core_host: bool) -> (bool, u64) {
    let program = KotodamaCompiler::new()
        .compile_source(source)
        .expect("compile equality");
    let metadata = ProgramMetadata::parse(&program).expect("equality metadata");
    let entry = metadata
        .contract_interface
        .as_ref()
        .expect("interface")
        .entrypoints
        .iter()
        .find(|entry| entry.name == "main")
        .expect("main entrypoint");
    let mut vm = IVM::new(u64::MAX);
    if core_host {
        vm.set_host(CoreHost::new());
    }
    vm.load_program(&program).expect("load equality program");
    vm.set_program_counter(metadata.prefix_len() as u64 + entry.entry_pc)
        .expect("select main");
    vm.run().expect("run equality program");
    assert!(
        vm.public_call_result_word(0).unwrap() <= 1,
        "canonical bool result"
    );
    (
        vm.public_call_result_word(0).expect("Boolean result slot") == 1,
        u64::MAX - vm.remaining_gas(),
    )
}

#[test]
fn structural_equality_compares_recursive_values_with_nominal_errors_and_unit() {
    let source = r#"seiyaku Equality {
        error enum Failure { Missing = 1; Denied = 2 }
        struct Record { () marker; (int, bool) pair; Option<List<Result<quantity, Failure>, 2>> values; }
        fn same(Record left, Record right) -> bool { left == right }
        view fn main() authorize(anyone) -> bool {
            let Record first = Record { marker: (), pair: (3, true), values: Option::some([Result::ok(4), Result::err(Failure::Missing)]) };
            let Record second = Record { values: Option::some([Result::ok(4), Result::err(Failure::Missing)]), pair: (3, true), marker: () };
            let Record third = Record { marker: (), pair: (3, true), values: Option::some([Result::ok(4), Result::err(Failure::Denied)]) };
            let Option<(bytes, bool)> none = Option::none;
            let Option<(bytes, bool)> other_none = Option::none;
            let Option<(bytes, bool)> some = Option::some((b"active", true));
            let Result<(bytes, bool), Failure> ok = Result::ok((b"active", true));
            let Result<(bytes, bool), Failure> err = Result::err(Failure::Missing);
            let List<((), Failure), 1> markers = [((), Failure::Missing)];
            let result = same(left: first, right: second) && first != third &&
                none == other_none && none != some && ok != err &&
                ((), Failure::Missing, b"same") == ((), Failure::Missing, b"same") &&
                markers.contains(((), Failure::Missing));
            let _ = first; let _ = second; let _ = third; let _ = ok; let _ = err;
            result
        }
    }"#;
    let scalar = run(source, false);
    assert!(scalar.0);
    assert_eq!(run(source, false), scalar, "repeated result and gas");
    assert_eq!(
        run(source, true),
        scalar,
        "both hosts use the canonical comparator"
    );
}

#[test]
fn structural_equality_uses_active_list_length_after_mutation() {
    let source = r#"seiyaku Equality {
        view fn main() authorize(anyone) -> bool {
            var List<int, 4> changed = [1, 2, 999];
            let _ = changed.pop();
            let List<int, 4> original = [1, 2];
            let List<int, 4> shorter = [1];
            let List<int, 4> different = [1, 3];
            changed == original && changed != shorter && changed != different
        }
    }"#;
    assert!(run(source, false).0);
}

#[test]
fn structural_equality_evaluates_operands_once_in_source_order() {
    let source = r#"seiyaku Equality {
        fn left(List<int, 1> trace) -> (int, bool) {
            var log = trace;
            log.set(index: 0, value: log.get(0).unwrap_or(0) * 10 + 1);
            (7, true)
        }
        fn right(List<int, 1> trace) -> (int, bool) {
            var log = trace;
            log.set(index: 0, value: log.get(0).unwrap_or(0) * 10 + 2);
            (7, true)
        }
        fn replace(List<int, 1> values) -> List<int, 1> {
            var alias = values;
            alias.set(index: 0, value: 9);
            [9]
        }
        view fn main() authorize(anyone) -> bool {
            let List<int, 1> trace = [0];
            let equal = left(trace: trace) == right(trace: trace);
            let List<int, 1> aliased = [1];
            let alias_equal = aliased == replace(values: aliased);
            equal && alias_equal && trace.get(0).unwrap_or(0) == 12
        }
    }"#;
    assert!(run(source, false).0);
}

fn compare_raw_handles(ty: &str, initialize: impl FnOnce(&mut IVM) -> (u64, u64)) -> (bool, u64) {
    // Call the compiler-owned implementation directly so malformed inactive
    // storage reaches only equality, not the public argument validator.
    let source = format!(
        "seiyaku Equality {{ view fn compare({ty} left, {ty} right) -> bool {{ left == right }} }}"
    );
    let compiler = KotodamaCompiler::new_with_options(CompilerOptions {
        mode: CompilerMode::Test,
        ..CompilerOptions::default()
    });
    let (mut program, _, report) = compiler
        .compile_source_with_manifest_and_report(&source)
        .expect("compile raw comparison");
    // This raw-opcode comparator harness terminates independently of the authenticated test loader.
    program.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());
    let metadata = ProgramMetadata::parse(&program).expect("raw comparison metadata");
    let function = report
        .source_map
        .iter()
        .find(|entry| entry.function_name == "compare")
        .expect("comparison implementation");
    let mut vm = IVM::new(u64::MAX);
    vm.load_program(&program).expect("load raw comparison");
    let (left, right) = initialize(&mut vm);
    let arguments = vm.alloc_heap(16).expect("argument table");
    vm.store_u64(arguments, left).expect("left argument");
    vm.store_u64(arguments + 8, right).expect("right argument");
    let results = vm.alloc_heap(8).expect("result table");
    vm.set_register(10, arguments);
    vm.set_register(11, 2);
    vm.set_register(12, results);
    vm.set_register(13, 1);
    assert_eq!(
        &program[program.len() - 4..],
        &encoding::wide::encode_halt().to_le_bytes()
    );
    vm.set_register(1, (program.len() - metadata.header_len - 4) as u64);
    vm.set_program_counter(metadata.prefix_len() as u64 + function.pc_start)
        .expect("select comparison implementation");
    vm.run().expect("compare only active storage");
    (
        vm.load_u64(results).expect("raw Boolean result slot") == 1,
        u64::MAX - vm.remaining_gas(),
    )
}

#[test]
fn structural_equality_never_reads_inactive_sum_payloads_or_unused_list_capacity() {
    let mut control = None;
    for poison in [false, true] {
        let option = compare_raw_handles("Option<(int, int)>", |vm| {
            let layout = SumLayoutV1::option(2).expect("option layout");
            let left = ivm::sum::allocate_words(vm, layout, 0, &[]).expect("left none");
            let right = ivm::sum::allocate_words(vm, layout, 0, &[]).expect("right none");
            if poison {
                vm.store_u64(left + 8, u64::MAX)
                    .expect("poison inactive left");
                vm.store_u64(right + 16, u64::MAX - 1)
                    .expect("poison inactive right");
            }
            (left, right)
        });
        assert!(option.0);
        let result = compare_raw_handles("Result<(int, int), bool>", |vm| {
            let layout = SumLayoutV1::try_new(1, 2).expect("result layout");
            let left = ivm::sum::allocate_words(vm, layout, 0, &[1]).expect("left error");
            let right = ivm::sum::allocate_words(vm, layout, 0, &[1]).expect("right error");
            if poison {
                vm.store_u64(left + 16, u64::MAX)
                    .expect("poison inactive success");
                vm.store_u64(right + 16, u64::MAX - 1)
                    .expect("poison other inactive success");
            }
            (left, right)
        });
        assert!(result.0);
        let list = compare_raw_handles("List<int, 2>", |vm| {
            let layout = ListLayoutV1::try_new(2, 1).expect("list layout");
            let left = ivm::list::allocate_words(vm, layout, &[]).expect("left empty list");
            let right = ivm::list::allocate_words(vm, layout, &[]).expect("right empty list");
            if poison {
                vm.store_u64(left + 16, u64::MAX)
                    .expect("poison unused left");
                vm.store_u64(right + 24, u64::MAX - 1)
                    .expect("poison unused right");
            }
            (left, right)
        });
        assert!(list.0);
        let observed = (option, result, list);
        if let Some(control) = control {
            assert_eq!(
                observed, control,
                "inactive bytes affect neither result nor charged gas"
            );
        } else {
            control = Some(observed);
        }
    }
    let mismatched = compare_raw_handles("Option<(int, int)>", |vm| {
        let layout = SumLayoutV1::option(2).expect("option layout");
        let left = ivm::sum::allocate_words(vm, layout, 0, &[]).expect("none");
        let right =
            ivm::sum::allocate_words(vm, layout, 1, &[u64::MAX, u64::MAX]).expect("unread some");
        (left, right)
    });
    assert!(
        !mismatched.0,
        "different tags do not inspect either payload"
    );
}
