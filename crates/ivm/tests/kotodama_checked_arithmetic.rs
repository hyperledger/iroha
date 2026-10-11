//! Checked and explicitly wrapping Kotodama `int` arithmetic regressions.
use iroha_crypto::Hash;
use iroha_model_base::name::Name;
use iroha_primitives::{
    bigint::BigInt,
    json::Json,
    numeric::{Numeric, Quantity},
    numeric_abi::{DecimalValueV1, QuantityValueV1},
};
use ivm::{
    IVM, ProgramMetadata, VMError, encoding, host::DefaultHost, numeric::NumericFaultV1,
    pointer_abi::PointerType, syscalls,
};
use kotodama_lang::compiler::Compiler;
use std::collections::BTreeMap;
mod common;
const MAX_INT: &str = "6703903964971298549787012499102923063739682910296196688861780721860882015036773488400937149083451713845015929093243025426876941405973284973216824503042047";
const MIN_INT: &str = "-6703903964971298549787012499102923063739682910296196688861780721860882015036773488400937149083451713845015929093243025426876941405973284973216824503042048";
fn compile(source: &str) -> Vec<u8> {
    Compiler::new()
        .compile_source(source)
        .expect("compile arithmetic contract")
}
fn entrypoint_pc(program: &[u8]) -> u64 {
    let parsed = ProgramMetadata::parse(program).expect("parse checked arithmetic artifact");
    let entrypoint = parsed
        .contract_interface
        .as_ref()
        .expect("embedded contract interface")
        .entrypoints
        .iter()
        .find(|entrypoint| entrypoint.name == "run")
        .expect("run entrypoint");
    u64::try_from(parsed.prefix_len()).expect("prefix fits u64") + entrypoint.entry_pc
}
fn tlv(pointer_type: PointerType, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(7 + payload.len() + Hash::LENGTH);
    out.extend_from_slice(&(pointer_type as u16).to_be_bytes());
    out.push(1);
    out.extend_from_slice(
        &u32::try_from(payload.len())
            .expect("test payload fits u32")
            .to_be_bytes(),
    );
    out.extend_from_slice(payload);
    out.extend_from_slice(Hash::new(payload).as_ref());
    out
}
fn argument_host(program: &[u8], payload: &Json) -> Result<DefaultHost, VMError> {
    let parsed = ProgramMetadata::parse(program)?;
    let entrypoint = parsed
        .contract_interface
        .as_ref()
        .and_then(|interface| {
            interface
                .entrypoints
                .iter()
                .find(|entrypoint| entrypoint.name == "run")
        })
        .expect("run entrypoint descriptor");
    let schema = entrypoint
        .argument_schema
        .as_ref()
        .expect("parameterized run entrypoint schema");
    let record = ivm_abi::arguments::encode_argument_record_from_json(schema, payload)?;
    let key: Name = ivm_abi::arguments::ENTRYPOINT_ARGUMENT_RECORD_PUBLIC_INPUT_KEY
        .parse()
        .expect("public input key");
    Ok(DefaultHost::new().with_public_inputs(BTreeMap::from([(
        key,
        tlv(PointerType::NoritoBytes, &record),
    )])))
}
fn run_binary(program: &[u8], left: &str, right: &str) -> Result<BigInt, VMError> {
    let mut vm = IVM::new(u64::MAX);
    vm.load_program(program)?;
    vm.set_program_counter(entrypoint_pc(program))?;
    let payload = Json::from_str_norito(&format!(r#"{{"left":"{left}","right":"{right}"}}"#))
        .expect("valid binary arguments");
    vm.set_host(argument_host(program, &payload)?);
    vm.run()?;
    Ok(common::decode_int_word(
        &vm,
        vm.public_call_result_word(0).unwrap(),
    ))
}
fn run_unary(program: &[u8], value: &str) -> Result<BigInt, VMError> {
    let mut vm = IVM::new(u64::MAX);
    vm.load_program(program)?;
    vm.set_program_counter(entrypoint_pc(program))?;
    let payload =
        Json::from_str_norito(&format!(r#"{{"value":"{value}"}}"#)).expect("valid unary arguments");
    vm.set_host(argument_host(program, &payload)?);
    vm.run()?;
    Ok(common::decode_int_word(
        &vm,
        vm.public_call_result_word(0).unwrap(),
    ))
}
fn run_mixed_int_decimal(program: &[u8], left: &str, right: &str) -> Result<Numeric, VMError> {
    let mut vm = IVM::new(u64::MAX);
    vm.load_program(program)?;
    vm.set_program_counter(entrypoint_pc(program))?;
    let payload = Json::from_str_norito(&format!(r#"{{"left":"{left}","right":"{right}"}}"#))
        .expect("valid mixed numeric arguments");
    vm.set_host(argument_host(program, &payload)?);
    vm.run()?;
    let output = vm.validate_tlv(vm.public_call_result_word(0)?)?;
    assert_eq!(output.type_id, PointerType::Decimal);
    DecimalValueV1::decode_frame(output.payload)
        .map(DecimalValueV1::into_numeric)
        .map_err(|_| VMError::DecodeError)
}
fn bigint(value: &str) -> BigInt {
    value.parse().expect("parse bounded integer fixture")
}
#[derive(Clone, Copy, Debug)]
enum NumericReturnKind {
    Int,
    Decimal,
    Quantity,
}
#[derive(Debug, PartialEq, Eq)]
enum NumericValue {
    Int(BigInt),
    Decimal(Numeric),
    Quantity(Quantity),
}
#[derive(Debug, PartialEq, Eq)]
enum NumericOutcome {
    Value(NumericValue),
    Fault(NumericFaultV1),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FoldedSyscallExpectation {
    Omitted,
    Retained,
}
fn contains_extended_syscall(program: &[u8], syscall: u32) -> bool {
    let metadata = ProgramMetadata::parse(program).expect("parse numeric differential artifact");
    let expected = encoding::wide::encode_syscallx(syscall);
    program[metadata.code_offset..]
        .chunks_exact(4)
        .any(|word| u32::from_le_bytes(word.try_into().expect("four-byte instruction")) == expected)
}
fn decode_numeric_return(vm: &IVM, kind: NumericReturnKind) -> NumericValue {
    match kind {
        NumericReturnKind::Int => NumericValue::Int(common::decode_int_word(
            vm,
            vm.public_call_result_word(0).unwrap(),
        )),
        NumericReturnKind::Decimal => {
            let output = vm
                .validate_tlv(
                    vm.public_call_result_word(0)
                        .expect("completed numeric result"),
                )
                .expect("validate returned decimal pointer");
            assert_eq!(output.type_id, PointerType::Decimal);
            NumericValue::Decimal(
                DecimalValueV1::decode_frame(output.payload)
                    .expect("decode returned canonical decimal")
                    .into_numeric(),
            )
        }
        NumericReturnKind::Quantity => {
            let output = vm
                .validate_tlv(
                    vm.public_call_result_word(0)
                        .expect("completed numeric result"),
                )
                .expect("validate returned quantity pointer");
            assert_eq!(output.type_id, PointerType::Quantity);
            NumericValue::Quantity(
                QuantityValueV1::decode_frame(output.payload)
                    .expect("decode returned canonical quantity")
                    .into_quantity(),
            )
        }
    }
}
fn numeric_fault_from_vm_error(error: &VMError) -> Option<NumericFaultV1> {
    match error {
        VMError::NumericFault(fault) => Some(*fault),
        VMError::Metered { source, .. } => numeric_fault_from_vm_error(source),
        _ => None,
    }
}
fn execute_numeric_program(
    program: &[u8],
    payload: Option<&Json>,
    kind: NumericReturnKind,
) -> NumericOutcome {
    let mut vm = IVM::new(u64::MAX);
    vm.load_program(program)
        .expect("load numeric differential artifact");
    vm.set_program_counter(entrypoint_pc(program))
        .expect("select numeric differential entrypoint");
    let host = match payload {
        Some(payload) => argument_host(program, payload).expect("encode numeric arguments"),
        None => DefaultHost::new(),
    };
    vm.set_host(host);
    match vm.run() {
        Ok(()) => NumericOutcome::Value(decode_numeric_return(&vm, kind)),
        Err(error) => {
            let fault = numeric_fault_from_vm_error(&error);
            NumericOutcome::Fault(
                fault.unwrap_or_else(|| panic!("unexpected numeric runtime failure: {error:?}")),
            )
        }
    }
}
fn compiler_numeric_fault(error: &str) -> NumericFaultV1 {
    for (code, fault) in [
        (
            "E_DECIMAL_MANTISSA_OVERFLOW",
            NumericFaultV1::MantissaOverflow,
        ),
        ("E_INT_OVERFLOW", NumericFaultV1::MantissaOverflow),
        ("E_DECIMAL_SCALE_OVERFLOW", NumericFaultV1::ScaleOverflow),
        ("E_DIVISION_BY_ZERO", NumericFaultV1::DivisionByZero),
        ("E_REPEATING_DECIMAL", NumericFaultV1::RepeatingDecimal),
        (
            "E_EXACT_DIVISION_SCALE_OVERFLOW",
            NumericFaultV1::ExactDivisionScaleOverflow,
        ),
        ("E_INVALID_SCALE", NumericFaultV1::InvalidScale),
        ("E_INEXACT_CONVERSION", NumericFaultV1::InexactConversion),
        ("E_NEGATIVE_QUANTITY", NumericFaultV1::NegativeQuantity),
        ("E_QUANTITY_UNDERFLOW", NumericFaultV1::QuantityUnderflow),
    ] {
        if error.contains(code) {
            return fault;
        }
    }
    panic!("unexpected folded numeric failure: {error}");
}
fn assert_numeric_fold_runtime_parity(
    case: &str,
    folded_source: &str,
    runtime_source: &str,
    runtime_payload: &str,
    kind: NumericReturnKind,
    syscall: u32,
    folded_syscall: FoldedSyscallExpectation,
) {
    let runtime_program = compile(runtime_source);
    assert!(
        contains_extended_syscall(&runtime_program, syscall),
        "{case}: parameterized runtime program must invoke syscall 0x{syscall:06x}"
    );
    let payload = Json::from_str_norito(runtime_payload).expect("valid numeric argument JSON");
    let runtime = execute_numeric_program(&runtime_program, Some(&payload), kind);
    let folded = match Compiler::new().compile_source(folded_source) {
        Ok(program) => {
            let contains = contains_extended_syscall(&program, syscall);
            match folded_syscall {
                FoldedSyscallExpectation::Omitted => assert!(
                    !contains,
                    "{case}: constant-folded program retained syscall 0x{syscall:06x}"
                ),
                FoldedSyscallExpectation::Retained => assert!(
                    contains,
                    "{case}: recoverable conversion unexpectedly lost its runtime syscall"
                ),
            }
            execute_numeric_program(&program, None, kind)
        }
        Err(error) => NumericOutcome::Fault(compiler_numeric_fault(&error)),
    };
    assert_eq!(
        folded, runtime,
        "{case}: constant folding and parameterized VM execution diverged"
    );
}
#[derive(Debug, PartialEq, Eq)]
enum ArithmeticOutcome {
    Value(BigInt),
    MantissaOverflow,
    DivisionByZero,
}
fn classify_runtime(result: Result<BigInt, VMError>) -> ArithmeticOutcome {
    match result {
        Ok(value) => ArithmeticOutcome::Value(value),
        Err(VMError::NumericFault(NumericFaultV1::MantissaOverflow)) => {
            ArithmeticOutcome::MantissaOverflow
        }
        Err(VMError::NumericFault(NumericFaultV1::DivisionByZero)) => {
            ArithmeticOutcome::DivisionByZero
        }
        Err(error) => panic!("unexpected runtime arithmetic failure: {error:?}"),
    }
}
fn folded_outcome(expression: &str) -> ArithmeticOutcome {
    let source = format!(
        "seiyaku FoldedArithmetic {{ view fn run() authorize(anyone) -> int {{ return {expression}; }} }}"
    );
    let program = match Compiler::new().compile_source(&source) {
        Ok(program) => program,
        Err(error) if error.contains("E_INT_OVERFLOW") => {
            return ArithmeticOutcome::MantissaOverflow;
        }
        Err(error) if error.contains("E_DIVISION_BY_ZERO") => {
            return ArithmeticOutcome::DivisionByZero;
        }
        Err(error) => panic!("unexpected folded arithmetic failure: {error}"),
    };
    let mut vm = IVM::new(u64::MAX);
    vm.load_program(&program)
        .expect("load folded arithmetic program");
    vm.set_program_counter(entrypoint_pc(&program))
        .expect("select folded arithmetic entrypoint");
    vm.run().expect("execute folded arithmetic result");
    ArithmeticOutcome::Value(common::decode_int_word(
        &vm,
        vm.public_call_result_word(0).unwrap(),
    ))
}
#[test]
fn constant_folding_and_runtime_match_signed_512_bit_boundaries_and_failures() {
    for (operator, left, right) in [
        ("+", MAX_INT, "0"),
        ("+", MAX_INT, "1"),
        ("+", MIN_INT, "-1"),
        ("-", MIN_INT, "0"),
        ("-", MIN_INT, "1"),
        ("-", MAX_INT, "-1"),
        ("*", MAX_INT, "1"),
        ("*", MAX_INT, "2"),
        ("*", MIN_INT, "-1"),
        ("/", MIN_INT, "1"),
        ("/", MIN_INT, "-1"),
        ("/", "1", "0"),
        ("%", MIN_INT, "1"),
        ("%", MIN_INT, "-1"),
        ("%", "1", "0"),
    ] {
        let program = compile(&format!(
            "seiyaku RuntimeArithmetic {{ view fn run(int left, int right) authorize(anyone) -> int {{ return left {operator} right; }} }}"
        ));
        let runtime = classify_runtime(run_binary(&program, left, right));
        let folded = folded_outcome(&format!("({left}) {operator} ({right})"));
        assert_eq!(
            folded, runtime,
            "folded/runtime mismatch for ({left}) {operator} ({right})"
        );
    }
    let negation = compile(
        "seiyaku RuntimeNegation { view fn run(int value) authorize(anyone) -> int { return -value; } }",
    );
    for value in [MAX_INT, MIN_INT] {
        let runtime = classify_runtime(run_unary(&negation, value));
        let folded = folded_outcome(&format!("-({value})"));
        assert_eq!(folded, runtime, "folded/runtime mismatch for -({value})");
    }
}
#[test]
fn explicit_int_to_decimal_conversion_matches_contextual_literal_folding() {
    let runtime = compile(
        "seiyaku MixedRuntime { view fn run(int left, decimal right) authorize(anyone) -> decimal { return decimal::from_int(left) + right; } }",
    );
    let metadata = ProgramMetadata::parse(&runtime).expect("parse explicit-conversion artifact");
    let conversion =
        encoding::wide::encode_syscallx(syscalls::SYSCALL_DECIMAL_FROM_INT).to_le_bytes();
    assert!(
        runtime[metadata.code_offset..]
            .windows(conversion.len())
            .any(|window| window == conversion),
        "decimal::from_int must lower through DECIMAL_FROM_INT"
    );
    let runtime_value = run_mixed_int_decimal(&runtime, "9007199254740993", "0.125")
        .expect("execute mixed runtime arithmetic");
    let folded = compile(
        "seiyaku MixedFolded { view fn run() authorize(anyone) -> decimal { return 9007199254740993 + 0.125; } }",
    );
    let mut folded_vm = IVM::new(u64::MAX);
    folded_vm
        .load_program(&folded)
        .expect("load folded decimal");
    folded_vm
        .set_program_counter(entrypoint_pc(&folded))
        .expect("select folded decimal entrypoint");
    folded_vm.run().expect("execute folded decimal");
    let folded_output = folded_vm
        .validate_tlv(folded_vm.public_call_result_word(0).unwrap())
        .expect("validate folded decimal pointer");
    assert_eq!(folded_output.type_id, PointerType::Decimal);
    let folded_value = DecimalValueV1::decode_frame(folded_output.payload)
        .expect("decode folded decimal")
        .into_numeric();
    assert_eq!(runtime_value, folded_value);
    assert_eq!(runtime_value.to_string(), "9007199254740993.125");
}
#[test]
fn decimal_constant_folding_matches_parameterized_vm_arithmetic_and_faults() {
    for (case, operator, left, right, syscall) in [
        (
            "decimal-add",
            "+",
            "1.2",
            "2.3",
            syscalls::SYSCALL_DECIMAL_ADD,
        ),
        (
            "decimal-sub",
            "-",
            "5",
            "1.25",
            syscalls::SYSCALL_DECIMAL_SUB,
        ),
        (
            "decimal-mul",
            "*",
            "1.5",
            "2",
            syscalls::SYSCALL_DECIMAL_MUL,
        ),
        (
            "decimal-exact-div",
            "/",
            "1",
            "8",
            syscalls::SYSCALL_DECIMAL_DIV_EXACT,
        ),
        (
            "decimal-repeating-div",
            "/",
            "1",
            "3",
            syscalls::SYSCALL_DECIMAL_DIV_EXACT,
        ),
        (
            "decimal-exact-div-scale-overflow",
            "/",
            "1",
            "100000000000000000000000000000",
            syscalls::SYSCALL_DECIMAL_DIV_EXACT,
        ),
        (
            "decimal-div-zero",
            "/",
            "1",
            "0",
            syscalls::SYSCALL_DECIMAL_DIV_EXACT,
        ),
        (
            "decimal-result-scale-overflow",
            "*",
            "0.000000000000001",
            "0.000000000000001",
            syscalls::SYSCALL_DECIMAL_MUL,
        ),
        (
            "decimal-mantissa-overflow",
            "+",
            MAX_INT,
            "1",
            syscalls::SYSCALL_DECIMAL_ADD,
        ),
    ] {
        let folded_source = format!(
            "seiyaku FoldedDecimal {{\nconst decimal LEFT = {left};\nconst decimal RIGHT = {right};\nview fn run() authorize(anyone) -> decimal {{ return LEFT {operator} RIGHT; }}\n}}"
        );
        let runtime_source = format!(
            "seiyaku RuntimeDecimal {{\nview fn run(decimal left, decimal right) authorize(anyone) -> decimal {{\nreturn left {operator} right;\n}}\n}}"
        );
        let payload = format!(r#"{{"left":"{left}","right":"{right}"}}"#);
        assert_numeric_fold_runtime_parity(
            case,
            &folded_source,
            &runtime_source,
            &payload,
            NumericReturnKind::Decimal,
            syscall,
            FoldedSyscallExpectation::Omitted,
        );
    }
}
#[test]
fn every_decimal_rounding_mode_matches_between_folding_and_vm_execution() {
    for (mode, dividend) in [
        ("toward_zero", "1"),
        ("away_from_zero", "1"),
        ("floor", "-1"),
        ("ceil", "-1"),
        ("nearest_even", "1"),
        ("nearest_away", "1"),
        ("nearest_toward_zero", "1"),
    ] {
        let folded_source = format!(
            "seiyaku FoldedRoundedDecimal {{\nconst decimal VALUE = {dividend};\nconst decimal DIVISOR = 8.0;\nconst int SCALE = 2;\nview fn run() authorize(anyone) -> decimal {{\nreturn VALUE.div_round(\ndivisor: DIVISOR, scale: SCALE, mode: Rounding::{mode});\n}}\n}}"
        );
        let runtime_source = format!(
            "seiyaku RuntimeRoundedDecimal {{\nview fn run(decimal value, decimal divisor, int scale) authorize(anyone) -> decimal {{\nreturn value.div_round(\ndivisor: divisor, scale: scale, mode: Rounding::{mode});\n}}\n}}"
        );
        let payload = format!(r#"{{"divisor":"8","scale":"2","value":"{dividend}"}}"#);
        assert_numeric_fold_runtime_parity(
            mode,
            &folded_source,
            &runtime_source,
            &payload,
            NumericReturnKind::Decimal,
            syscalls::SYSCALL_DECIMAL_DIV_ROUND,
            FoldedSyscallExpectation::Omitted,
        );
    }
}
#[test]
fn every_quantity_rounding_mode_matches_between_folding_and_vm_execution() {
    for mode in [
        "toward_zero",
        "away_from_zero",
        "floor",
        "ceil",
        "nearest_even",
        "nearest_away",
        "nearest_toward_zero",
    ] {
        let folded_source = format!(
            "seiyaku FoldedRoundedQuantity {{\nconst quantity VALUE = 1;\nconst decimal DIVISOR = 8;\nconst int SCALE = 2;\nview fn run() authorize(anyone) -> quantity {{\nreturn VALUE.div_round(\ndivisor: DIVISOR, scale: SCALE, mode: Rounding::{mode});\n}}\n}}"
        );
        let runtime_source = format!(
            "seiyaku RuntimeRoundedQuantity {{\nview fn run(quantity value, decimal divisor, int scale) authorize(anyone) -> quantity {{\nreturn value.div_round(\ndivisor: divisor, scale: scale, mode: Rounding::{mode});\n}}\n}}"
        );
        assert_numeric_fold_runtime_parity(
            mode,
            &folded_source,
            &runtime_source,
            r#"{"divisor":"8","scale":"2","value":"1"}"#,
            NumericReturnKind::Quantity,
            syscalls::SYSCALL_QUANTITY_DIV_DECIMAL_ROUND,
            FoldedSyscallExpectation::Omitted,
        );
    }
}
#[test]
fn decimal_to_int_conversions_match_folding_for_success_and_failure() {
    for (case, value) in [
        ("decimal-to-int-exact", "42"),
        ("decimal-to-int-inexact", "1.25"),
    ] {
        // The outer checked addition makes the exact cast part of a foldable numeric
        // expression. It also guards against a future lowering that silently defers a
        // known-inexact constant to runtime.
        let folded_source = format!(
            "seiyaku FoldedExactConversion {{\nconst decimal VALUE = {value};\nview fn run() authorize(anyone) -> int {{\nreturn decimal::to_int_exact(VALUE) + 0;\n}}\n}}"
        );
        let runtime_source = "seiyaku RuntimeExactConversion {\nview fn run(decimal value) authorize(anyone) -> int {\nreturn decimal::to_int_exact(value) + 0;\n}\n}";
        let payload = format!(r#"{{"value":"{value}"}}"#);
        assert_numeric_fold_runtime_parity(
            case,
            &folded_source,
            runtime_source,
            &payload,
            NumericReturnKind::Int,
            syscalls::SYSCALL_DECIMAL_TO_INT_EXACT,
            FoldedSyscallExpectation::Omitted,
        );
    }
    assert_numeric_fold_runtime_parity(
        "decimal-to-int-trunc",
        "seiyaku FoldedTruncConversion {\nview fn run() authorize(anyone) -> int {\nreturn decimal::to_int_trunc(-1.9);\n}\n}",
        "seiyaku RuntimeTruncConversion {\nview fn run(decimal value) authorize(anyone) -> int {\nreturn decimal::to_int_trunc(value);\n}\n}",
        r#"{"value":"-1.9"}"#,
        NumericReturnKind::Int,
        syscalls::SYSCALL_DECIMAL_TO_INT_TRUNC,
        FoldedSyscallExpectation::Omitted,
    );
    for mode in [
        "toward_zero",
        "away_from_zero",
        "floor",
        "ceil",
        "nearest_even",
        "nearest_away",
        "nearest_toward_zero",
    ] {
        let folded_source = format!(
            "seiyaku FoldedRoundedConversion {{\nview fn run() authorize(anyone) -> int {{\nreturn decimal::to_int_round(\n2.5, mode: Rounding::{mode});\n}}\n}}"
        );
        let runtime_source = format!(
            "seiyaku RuntimeRoundedConversion {{\nview fn run(decimal value) authorize(anyone) -> int {{\nreturn decimal::to_int_round(\nvalue, mode: Rounding::{mode});\n}}\n}}"
        );
        assert_numeric_fold_runtime_parity(
            mode,
            &folded_source,
            &runtime_source,
            r#"{"value":"2.5"}"#,
            NumericReturnKind::Int,
            syscalls::SYSCALL_DECIMAL_TO_INT_ROUND,
            FoldedSyscallExpectation::Omitted,
        );
    }
}
#[test]
fn quantity_arithmetic_folding_matches_parameterized_vm_execution() {
    for (case, constants, params, expression, payload, kind, syscall) in [
        (
            "quantity-add",
            "const quantity LEFT = 1.25; const quantity RIGHT = 2.75;",
            "quantity left, quantity right",
            "left + right",
            r#"{"left":"1.25","right":"2.75"}"#,
            NumericReturnKind::Quantity,
            syscalls::SYSCALL_QUANTITY_ADD,
        ),
        (
            "quantity-sub",
            "const quantity LEFT = 5.0; const quantity RIGHT = 1.25;",
            "quantity left, quantity right",
            "left - right",
            r#"{"left":"5","right":"1.25"}"#,
            NumericReturnKind::Quantity,
            syscalls::SYSCALL_QUANTITY_SUB,
        ),
        (
            "quantity-underflow",
            "const quantity LEFT = 1.0; const quantity RIGHT = 2.0;",
            "quantity left, quantity right",
            "left - right",
            r#"{"left":"1","right":"2"}"#,
            NumericReturnKind::Quantity,
            syscalls::SYSCALL_QUANTITY_SUB,
        ),
        (
            "quantity-mul-decimal",
            "const quantity LEFT = 1.5; const decimal RIGHT = 2.0;",
            "quantity left, decimal right",
            "left * right",
            r#"{"left":"1.5","right":"2"}"#,
            NumericReturnKind::Quantity,
            syscalls::SYSCALL_QUANTITY_MUL_DECIMAL,
        ),
        (
            "quantity-negative-result",
            "const quantity LEFT = 1.0; const decimal RIGHT = -1.0;",
            "quantity left, decimal right",
            "left * right",
            r#"{"left":"1","right":"-1"}"#,
            NumericReturnKind::Quantity,
            syscalls::SYSCALL_QUANTITY_MUL_DECIMAL,
        ),
        (
            "quantity-div-decimal",
            "const quantity LEFT = 1.0; const decimal RIGHT = 8.0;",
            "quantity left, decimal right",
            "left / right",
            r#"{"left":"1","right":"8"}"#,
            NumericReturnKind::Quantity,
            syscalls::SYSCALL_QUANTITY_DIV_DECIMAL_EXACT,
        ),
        (
            "quantity-div-decimal-repeating",
            "const quantity LEFT = 1.0; const decimal RIGHT = 3.0;",
            "quantity left, decimal right",
            "left / right",
            r#"{"left":"1","right":"3"}"#,
            NumericReturnKind::Quantity,
            syscalls::SYSCALL_QUANTITY_DIV_DECIMAL_EXACT,
        ),
        (
            "quantity-div-decimal-zero",
            "const quantity LEFT = 1.0; const decimal RIGHT = 0.0;",
            "quantity left, decimal right",
            "left / right",
            r#"{"left":"1","right":"0"}"#,
            NumericReturnKind::Quantity,
            syscalls::SYSCALL_QUANTITY_DIV_DECIMAL_EXACT,
        ),
        (
            "quantity-ratio",
            "const quantity LEFT = 1.0; const quantity RIGHT = 8.0;",
            "quantity left, quantity right",
            "left / right",
            r#"{"left":"1","right":"8"}"#,
            NumericReturnKind::Decimal,
            syscalls::SYSCALL_QUANTITY_RATIO_EXACT,
        ),
        (
            "quantity-ratio-repeating",
            "const quantity LEFT = 1.0; const quantity RIGHT = 3.0;",
            "quantity left, quantity right",
            "left / right",
            r#"{"left":"1","right":"3"}"#,
            NumericReturnKind::Decimal,
            syscalls::SYSCALL_QUANTITY_RATIO_EXACT,
        ),
        (
            "quantity-ratio-zero",
            "const quantity LEFT = 1.0; const quantity RIGHT = 0.0;",
            "quantity left, quantity right",
            "left / right",
            r#"{"left":"1","right":"0"}"#,
            NumericReturnKind::Decimal,
            syscalls::SYSCALL_QUANTITY_RATIO_EXACT,
        ),
    ] {
        let return_type = match kind {
            NumericReturnKind::Int => "int",
            NumericReturnKind::Decimal => "decimal",
            NumericReturnKind::Quantity => "quantity",
        };
        let folded_expression = expression.replace("left", "LEFT").replace("right", "RIGHT");
        let folded_source = format!(
            "seiyaku FoldedQuantity {{\n{constants}\nview fn run() authorize(anyone) -> {return_type} {{ return {folded_expression}; }}\n}}"
        );
        let runtime_source = format!(
            "seiyaku RuntimeQuantity {{\n\
                 view fn run({params}) authorize(anyone) -> {return_type} {{ return {expression}; }}\n\
             }}"
        );
        assert_numeric_fold_runtime_parity(
            case,
            &folded_source,
            &runtime_source,
            payload,
            kind,
            syscall,
            FoldedSyscallExpectation::Omitted,
        );
    }
}
#[test]
fn dex_samples_floor_input_and_payout_at_each_declared_precision() {
    for (sample_name, sample) in [
        (
            "dex_simple",
            include_str!("../../kotodama_lang/src/samples/dex_simple.ko"),
        ),
        (
            "dex_contract",
            include_str!("../../kotodama_lang/src/samples/dex_contract.ko"),
        ),
    ] {
        // Add only a public test entrypoint. Execute the sample's real private
        // quote helper and its declared precision/rounding policies unchanged.
        let body = sample
            .trim_end()
            .strip_suffix('}')
            .expect("one final seiyaku brace");
        let runtime_source = format!(
            "{body}\n view fn run(quantity reserve_in, quantity reserve_out, quantity amount_in) authorize(anyone) -> quantity {{ quote_sell(reserve_in: reserve_in, reserve_out: reserve_out, amount_in: amount_in) }}\n}}"
        );
        let runtime_program = compile(&runtime_source);
        assert!(contains_extended_syscall(
            &runtime_program,
            syscalls::SYSCALL_QUANTITY_MUL_DIV_ROUND,
        ));
        for (reserve_in, reserve_out, amount_in, effective, payout) in [
            // With integer attounits x: effective=floor(x*997/1000), then
            // payout=floor(reserve_out*effective/(reserve_in+effective)).
            // Omitting input floor OR rounding payout up gives ...2024.
            (
                "2",
                "7",
                "1.000000000000000019",
                "0.997000000000000018",
                "2.328661995328662023",
            ),
            // The first floor removes the whole input. Rounding only the final
            // payout would instead produce 0.000000000996999999.
            ("1", "1000000000", "0.000000000000000001", "0", "0"),
        ] {
            let payload = Json::try_new(norito::json!({
                "reserve_in": reserve_in,
                "reserve_out": reserve_out,
                "amount_in": amount_in,
            }))
            .expect("exact decimal quantity arguments");
            let runtime = execute_numeric_program(
                &runtime_program,
                Some(&payload),
                NumericReturnKind::Quantity,
            );
            let expected = NumericOutcome::Value(NumericValue::Quantity(
                payout
                    .parse()
                    .expect("independently calculated two-floor payout"),
            ));
            assert_eq!(runtime, expected, "{sample_name}, input {amount_in}");
            let folded_effective_expression = "AMOUNT_IN.mul_div_round(multiplier: 997, divisor: 1000, scale: 18, mode: Rounding::floor)";
            let folded_payout_expression = format!(
                "RESERVE_OUT.mul_div_round(multiplier: decimal::from_quantity({folded_effective_expression}), divisor: decimal::from_quantity(RESERVE_IN + {folded_effective_expression}), scale: 18, mode: Rounding::floor)"
            );
            let folded_source = format!(
                "seiyaku FoldedDex {{\n                    const quantity RESERVE_IN = {reserve_in};\n                    const quantity RESERVE_OUT = {reserve_out};\n                    const quantity AMOUNT_IN = {amount_in};\n                    view fn run() authorize(anyone) -> quantity {{ {folded_payout_expression} }}\n                }}"
            );
            let folded_program = compile(&folded_source);
            assert!(
                !contains_extended_syscall(
                    &folded_program,
                    syscalls::SYSCALL_QUANTITY_MUL_DIV_ROUND
                ),
                "the constant reference must exercise folding rather than the same runtime primitive",
            );
            let folded =
                execute_numeric_program(&folded_program, None, NumericReturnKind::Quantity);
            assert_eq!(folded, runtime, "{sample_name}, input {amount_in}");
            // Pin the independently calculated first-stage reference too. The
            // vectors also distinguish skipping that floor from the real sample.
            let folded_effective = compile(
                &folded_source.replace(&folded_payout_expression, folded_effective_expression),
            );
            assert!(
                !contains_extended_syscall(
                    &folded_effective,
                    syscalls::SYSCALL_QUANTITY_MUL_DIV_ROUND
                ),
                "the intermediate reference must also be constant-folded",
            );
            assert_eq!(
                execute_numeric_program(&folded_effective, None, NumericReturnKind::Quantity),
                NumericOutcome::Value(NumericValue::Quantity(effective.parse().unwrap())),
            );
        }
    }
}

#[test]
fn constant_quantity_exact_division_rejects_each_failure_class_at_compile_time() {
    for (case, value, divisor, expected_code) in [
        ("zero divisor", "1", "0", "E_DIVISION_BY_ZERO"),
        ("repeating quotient", "1", "3", "E_REPEATING_DECIMAL"),
        (
            "terminating quotient beyond the exact scale limit",
            "0.0000000000000000000000000001",
            "10",
            "E_EXACT_DIVISION_SCALE_OVERFLOW",
        ),
    ] {
        let source = format!(
            "seiyaku InvalidConstantQuantityDivision {{\nconst quantity VALUE = {value};\nconst decimal DIVISOR = {divisor};\nview fn run() authorize(anyone) -> quantity {{ return VALUE / DIVISOR; }}\n}}"
        );
        let error = Compiler::new()
            .compile_source(&source)
            .expect_err("invalid constant Quantity division must be rejected before bytecode");
        assert!(
            error.contains(expected_code),
            "{case} used the wrong compile-time diagnostic: {error}"
        );
    }
}
#[test]
fn explicit_quantity_conversions_match_for_values_and_negative_failures() {
    for (case, source_type, value, syscall) in [
        (
            "quantity-from-int",
            "int",
            "7",
            syscalls::SYSCALL_QUANTITY_FROM_INT,
        ),
        (
            "quantity-from-decimal",
            "decimal",
            "7.25",
            syscalls::SYSCALL_QUANTITY_FROM_DECIMAL,
        ),
    ] {
        let conversion = if source_type == "int" {
            "quantity::try_from_int"
        } else {
            "quantity::try_from_decimal"
        };
        let folded_source = format!(
            "seiyaku FoldedQuantityConversion {{\nview fn run() authorize(anyone) -> quantity {{\nlet outcome = {conversion}({value});\nreturn match outcome {{\nResult::ok(converted) => converted,\nResult::err(_) => 0\n}};\n}}\n}}"
        );
        let runtime_source = format!(
            "seiyaku RuntimeQuantityConversion {{\n\
                 view fn run({source_type} value) authorize(anyone) -> quantity {{\n\
                     let outcome = {conversion}(value);\n\
                     return match outcome {{\n\
                         Result::ok(converted) => converted,\n\
                         Result::err(_) => 0\n\
                     }};\n\
                 }}\n\
             }}"
        );
        let payload = format!(r#"{{"value":"{value}"}}"#);
        assert_numeric_fold_runtime_parity(
            case,
            &folded_source,
            &runtime_source,
            &payload,
            NumericReturnKind::Quantity,
            syscall,
            // Recoverable conversions deliberately remain runtime operations so
            // their Result shape and stable fault payload cannot be optimized away.
            FoldedSyscallExpectation::Retained,
        );
    }
    for (case, source_type, value, syscall) in [
        (
            "negative-int-to-quantity",
            "int",
            "-1",
            syscalls::SYSCALL_QUANTITY_FROM_INT,
        ),
        (
            "negative-decimal-to-quantity",
            "decimal",
            "-1.25",
            syscalls::SYSCALL_QUANTITY_FROM_DECIMAL,
        ),
    ] {
        let conversion = if source_type == "int" {
            "quantity::try_from_int"
        } else {
            "quantity::try_from_decimal"
        };
        let folded_source = format!(
            "seiyaku FoldedNegativeQuantityConversion {{\nerror enum ConversionCheck {{ WrongError = 1 }}\nview fn run() authorize(anyone) -> int {{\nlet outcome = {conversion}({value});\nreturn match outcome {{\nResult::ok(_) => {{ require(false, ConversionCheck::WrongError); 0 }},\nResult::err(failure) => {{ require(failure == NumericError::NegativeQuantity, ConversionCheck::WrongError); 1 }}\n}};\n}}\n}}"
        );
        let runtime_source = format!(
            "seiyaku RuntimeNegativeQuantityConversion {{\n\
                 error enum ConversionCheck {{ WrongError = 1 }}\n\
                 view fn run({source_type} value) authorize(anyone) -> int {{\n\
                     let outcome = {conversion}(value);\n\
                     return match outcome {{\n\
                         Result::ok(_) => {{ require(false, ConversionCheck::WrongError); 0 }},\n\
                         Result::err(failure) => {{ require(failure == NumericError::NegativeQuantity, ConversionCheck::WrongError); 1 }}\n\
                     }};\n\
                 }}\n\
             }}"
        );
        let payload = format!(r#"{{"value":"{value}"}}"#);
        assert_numeric_fold_runtime_parity(
            case,
            &folded_source,
            &runtime_source,
            &payload,
            NumericReturnKind::Int,
            syscall,
            FoldedSyscallExpectation::Retained,
        );
    }
    assert_numeric_fold_runtime_parity(
        "quantity-to-decimal",
        "seiyaku FoldedQuantityToDecimal {\nconst quantity VALUE = 1.25;\nview fn run() authorize(anyone) -> decimal {\nreturn decimal::from_quantity(VALUE) + 0.0;\n}\n}",
        "seiyaku RuntimeQuantityToDecimal {\nview fn run(quantity value) authorize(anyone) -> decimal {\nreturn decimal::from_quantity(value) + 0.0;\n}\n}",
        r#"{"value":"1.25"}"#,
        NumericReturnKind::Decimal,
        syscalls::SYSCALL_QUANTITY_TO_DECIMAL,
        FoldedSyscallExpectation::Omitted,
    );
}
#[test]
fn ordinary_addition_and_subtraction_trap_at_signed_512_bit_boundaries() {
    let add = compile(
        "seiyaku CheckedAdd { view fn run(int left, int right) authorize(anyone) -> int { return left + right; } }",
    );
    assert_eq!(run_binary(&add, MAX_INT, "0").unwrap(), bigint(MAX_INT));
    assert_eq!(run_binary(&add, MIN_INT, "0").unwrap(), bigint(MIN_INT));
    assert!(matches!(
        run_binary(&add, MAX_INT, "1"),
        Err(VMError::NumericFault(NumericFaultV1::MantissaOverflow))
    ));
    assert!(matches!(
        run_binary(&add, MIN_INT, "-1"),
        Err(VMError::NumericFault(NumericFaultV1::MantissaOverflow))
    ));
    let sub = compile(
        "seiyaku CheckedSub { view fn run(int left, int right) authorize(anyone) -> int { return left - right; } }",
    );
    assert_eq!(run_binary(&sub, MIN_INT, "0").unwrap(), bigint(MIN_INT));
    assert_eq!(run_binary(&sub, MAX_INT, "0").unwrap(), bigint(MAX_INT));
    assert!(matches!(
        run_binary(&sub, MIN_INT, "1"),
        Err(VMError::NumericFault(NumericFaultV1::MantissaOverflow))
    ));
    assert!(matches!(
        run_binary(&sub, MAX_INT, "-1"),
        Err(VMError::NumericFault(NumericFaultV1::MantissaOverflow))
    ));
}
#[test]
fn ordinary_multiplication_and_negation_trap_at_signed_512_bit_boundaries() {
    let mul = compile(
        "seiyaku CheckedMul { view fn run(int left, int right) authorize(anyone) -> int { return left * right; } }",
    );
    assert_eq!(run_binary(&mul, MAX_INT, "1").unwrap(), bigint(MAX_INT));
    assert_eq!(run_binary(&mul, MIN_INT, "1").unwrap(), bigint(MIN_INT));
    assert!(matches!(
        run_binary(&mul, MAX_INT, "2"),
        Err(VMError::NumericFault(NumericFaultV1::MantissaOverflow))
    ));
    assert!(matches!(
        run_binary(&mul, MIN_INT, "-1"),
        Err(VMError::NumericFault(NumericFaultV1::MantissaOverflow))
    ));
    let neg = compile(
        "seiyaku CheckedNeg { view fn run(int value) authorize(anyone) -> int { return -value; } }",
    );
    assert_eq!(
        run_unary(&neg, MAX_INT).unwrap(),
        bigint(&format!("-{MAX_INT}"))
    );
    assert_eq!(run_unary(&neg, "0").unwrap(), bigint("0"));
    assert!(matches!(
        run_unary(&neg, MIN_INT),
        Err(VMError::NumericFault(NumericFaultV1::MantissaOverflow))
    ));
}
#[test]
fn constant_folding_uses_checked_signed_512_bit_rules() {
    let safe = compile(
        "seiyaku CheckedConstant { view fn run() authorize(anyone) -> int { return (6703903964971298549787012499102923063739682910296196688861780721860882015036773488400937149083451713845015929093243025426876941405973284973216824503042047 - 1) + 1; } }",
    );
    let mut vm = IVM::new(u64::MAX);
    vm.load_program(&safe).unwrap();
    vm.set_program_counter(entrypoint_pc(&safe)).unwrap();
    vm.run().unwrap();
    assert_eq!(
        common::decode_int_word(&vm, vm.public_call_result_word(0).unwrap()),
        bigint(MAX_INT)
    );
    for source in [
        "seiyaku OverflowAdd { view fn run() authorize(anyone) -> int { return 6703903964971298549787012499102923063739682910296196688861780721860882015036773488400937149083451713845015929093243025426876941405973284973216824503042047 + 1; } }",
        "seiyaku OverflowNeg { view fn run() authorize(anyone) -> int { return -(-6703903964971298549787012499102923063739682910296196688861780721860882015036773488400937149083451713845015929093243025426876941405973284973216824503042048); } }",
    ] {
        let error = Compiler::new()
            .compile_source(source)
            .expect_err("constant overflow must fail compilation");
        assert!(
            error.contains("E_INT_OVERFLOW"),
            "unexpected error: {error}"
        );
    }
}
#[test]
fn wrapping_builtins_are_the_explicit_modular_opt_in() {
    let program = compile(
        r#"
seiyaku WrappingArithmetic {
  view fn run() authorize(anyone) -> (int, int, int, int) {
    return (
        math::wrapping_add(left: 6703903964971298549787012499102923063739682910296196688861780721860882015036773488400937149083451713845015929093243025426876941405973284973216824503042047, right: 1),
        math::wrapping_sub(left: -6703903964971298549787012499102923063739682910296196688861780721860882015036773488400937149083451713845015929093243025426876941405973284973216824503042048, right: 1),
        math::wrapping_mul(left: 6703903964971298549787012499102923063739682910296196688861780721860882015036773488400937149083451713845015929093243025426876941405973284973216824503042047, right: 2),
        math::wrapping_neg(-6703903964971298549787012499102923063739682910296196688861780721860882015036773488400937149083451713845015929093243025426876941405973284973216824503042048)
    );
  }
}
"#,
    );
    let mut vm = IVM::new(u64::MAX);
    vm.load_program(&program).unwrap();
    vm.set_program_counter(entrypoint_pc(&program)).unwrap();
    vm.run().unwrap();
    assert_eq!(
        common::decode_int_word(&vm, vm.public_call_result_word(0).unwrap()),
        bigint(MIN_INT)
    );
    assert_eq!(
        common::decode_int_word(&vm, vm.public_call_result_word(1).unwrap()),
        bigint(MAX_INT)
    );
    assert_eq!(
        common::decode_int_word(&vm, vm.public_call_result_word(2).unwrap()),
        bigint("-2")
    );
    assert_eq!(
        common::decode_int_word(&vm, vm.public_call_result_word(3).unwrap()),
        bigint(MIN_INT)
    );
}

#[test]
fn full_width_math_helpers_match_constant_folding_and_runtime() {
    use iroha_primitives::numeric_int::{IntBinaryOperation, IntUnaryOperation};
    let maximum = MAX_INT.parse::<BigInt>().expect("maximum int");
    let minimum = MIN_INT.parse::<BigInt>().expect("minimum int");
    for (name, operation) in [
        ("isqrt", IntUnaryOperation::Isqrt),
        ("abs", IntUnaryOperation::Abs),
    ] {
        let source = format!(
            "seiyaku Math {{ view fn run(int value) authorize(anyone) -> int {{ return math::{name}(value); }} }}"
        );
        let runtime = compile(&source);
        let folded = compile(&format!(
            "seiyaku Math {{ view fn run(int value) authorize(anyone) -> int {{ return math::{name}({MAX_INT}); }} }}"
        ));
        let expected = operation.evaluate(&maximum).unwrap();
        assert_eq!(run_unary(&runtime, MAX_INT).unwrap(), expected);
        assert_eq!(run_unary(&folded, "0").unwrap(), expected);
    }
    for (name, operation, left, right) in [
        ("min", IntBinaryOperation::Min, &minimum, &maximum),
        ("max", IntBinaryOperation::Max, &minimum, &maximum),
        ("div_ceil", IntBinaryOperation::DivCeil, &maximum, &maximum),
        ("gcd", IntBinaryOperation::Gcd, &minimum, &maximum),
        ("mean", IntBinaryOperation::Mean, &maximum, &maximum),
    ] {
        let (first, second) = binary_math_labels(name);
        let source = format!(
            "seiyaku Math {{ view fn run(int left, int right) authorize(anyone) -> int {{ return math::{name}({first}: left, {second}: right); }} }}"
        );
        let runtime = compile(&source);
        let folded = compile(&format!(
            "seiyaku Math {{ view fn run(int left, int right) authorize(anyone) -> int {{ return math::{name}({first}: {left}, {second}: {right}); }} }}"
        ));
        let expected = operation.evaluate(left, right).unwrap();
        assert_eq!(
            run_binary(&runtime, &left.to_string(), &right.to_string()).unwrap(),
            expected
        );
        assert_eq!(run_binary(&folded, "0", "0").unwrap(), expected);
    }
    let constant = compile(
        "seiyaku Math { const int ROOT = math::isqrt(340282366920938463463374607431768211456); const int MID = math::mean(right: ROOT, left: ROOT); view fn run(int value) authorize(anyone) -> int { return MID; } }",
    );
    assert_eq!(
        run_unary(&constant, "0").unwrap(),
        "18446744073709551616".parse::<BigInt>().unwrap()
    );
    for (expression, diagnostic) in [
        ("math::isqrt(-1)".to_owned(), "E_NEGATIVE_SQUARE_ROOT"),
        (format!("math::abs({MIN_INT})"), "E_INT_OVERFLOW"),
        (
            "math::div_ceil(dividend: 1, divisor: 0)".to_owned(),
            "E_DIVISION_BY_ZERO",
        ),
        (
            format!("math::gcd(left: {MIN_INT}, right: 0)"),
            "E_INT_OVERFLOW",
        ),
    ] {
        let error = Compiler::new()
            .compile_source(&format!(
                "seiyaku Math {{ view fn run() authorize(anyone) -> int {{ return {expression}; }} }}"
            ))
            .expect_err("constant math fault");
        assert!(error.contains(diagnostic), "{expression}: {error}");
    }
}

#[test]
fn rematerialized_literal_call_pressure_keeps_runtime_values_and_overflow() {
    let source = include_str!("../../kotodama_lang/src/compiler/fixtures/v1/literal_homes.ko");
    let (program, _, report) = Compiler::new()
        .compile_source_with_manifest_and_report(source)
        .expect("compile pressure fixture");
    let frame_sum = report
        .budget_report
        .iter()
        .map(|function| u64::from(function.frame_bytes))
        .sum::<u64>();
    for (input, expected) in [("17", "317"), ("-500", "-200"), ("0", "300")] {
        let mut vm = IVM::new(1_000_000);
        vm.load_program(&program)
            .expect("load real call-table artifact");
        vm.set_program_counter(entrypoint_pc(&program)).unwrap();
        let payload = Json::from_str_norito(&format!(r#"{{"value":"{input}"}}"#)).unwrap();
        let mut host = argument_host(&program, &payload).unwrap();
        let observer_budget = iroha_allocation::AllocationBudget::new(32 * 1024 * 1024);
        let mut steps =
            ivm::execution_step_recorder::DiagnosticStepRecorder::try_new(4096, &observer_budget)
                .expect("prepay bounded local diagnostic rows");
        vm.run_with_host_diagnostic_steps(&mut host, &mut steps)
            .expect("execute full argument table and checked arithmetic");
        let initial_sp = steps
            .records()
            .first()
            .expect("actual interpreter steps")
            .before
            .registers[31];
        let minimum_sp = steps
            .records()
            .iter()
            .map(|step| step.after.registers[31])
            .min()
            .unwrap();
        let peak_stack = initial_sp
            .checked_sub(minimum_sp)
            .expect("descending call frames");
        assert!(
            peak_stack > 0 && peak_stack <= frame_sum,
            "actual stack={peak_stack}, authenticated frames={frame_sum}"
        );
        let memory_steps = steps
            .records()
            .iter()
            .filter(|step| {
                matches!(
                    step.opcode,
                    Some(
                        ivm::instruction::wide::memory::LOAD64
                            | ivm::instruction::wide::memory::STORE64
                    )
                )
            })
            .count();
        assert!(memory_steps > 0, "the real call tables must execute");
        assert_eq!(
            common::decode_int_word(&vm, vm.public_call_result_word(0).unwrap()),
            bigint(expected)
        );
        eprintln!(
            "literal-home runtime input={input} artifact_bytes={} gas_used={} memory_steps={memory_steps} peak_stack={peak_stack}",
            program.len(),
            1_000_000 - vm.remaining_gas()
        );
    }
    let error = run_unary(&program, MAX_INT).expect_err("checked overflow remains observable");
    assert_eq!(
        numeric_fault_from_vm_error(&error),
        Some(NumericFaultV1::MantissaOverflow)
    );
}

#[test]
fn rematerialized_numeric_operands_keep_rounding_branch_and_quantity_faults() {
    let decimal = compile(
        r#"seiyaku LiteralRounding {
        view fn run(decimal value) authorize(anyone) -> decimal {
            if (value < 0) { return value - 1.25; }
            return value.div_round(divisor: 3, scale: 2, mode: Rounding::floor);
        }
    }"#,
    );
    for (value, expected) in [("2", "0.66"), ("-2", "-3.25")] {
        let payload = Json::from_str_norito(&format!(r#"{{"value":"{value}"}}"#)).unwrap();
        assert_eq!(
            execute_numeric_program(&decimal, Some(&payload), NumericReturnKind::Decimal),
            NumericOutcome::Value(NumericValue::Decimal(expected.parse().unwrap()))
        );
    }
    let quantity = compile(
        r#"seiyaku LiteralQuantity {
        view fn run(quantity value) authorize(anyone) -> quantity { let quantity one = 1; return value - one; }
    }"#,
    );
    for (value, expected) in [
        (
            "3.5",
            NumericOutcome::Value(NumericValue::Quantity("2.5".parse().unwrap())),
        ),
        (
            "0",
            NumericOutcome::Fault(NumericFaultV1::QuantityUnderflow),
        ),
    ] {
        let payload = Json::from_str_norito(&format!(r#"{{"value":"{value}"}}"#)).unwrap();
        assert_eq!(
            execute_numeric_program(&quantity, Some(&payload), NumericReturnKind::Quantity),
            expected
        );
    }
}

#[test]
fn borrowed_numeric_operands_keep_values_faults_and_real_typed_call_tables() {
    let program = compile(
        r#"seiyaku BorrowedNumeric {
        fn arithmetic(int left, int right) -> int {
            if (left < right) { return (left + right) * (right - left); }
            return (left - right) + (left * right);
        }
        view fn run(int left, int right) authorize(anyone) -> int {
            // Two live calls preserve the private typed boundary under single-use inlining.
            return arithmetic(left, right) + arithmetic(0, 0);
        }
    }"#,
    );
    let parsed = ProgramMetadata::parse(&program).unwrap();
    assert_eq!(
        parsed.contract_interface.as_ref().unwrap().callables.len(),
        2,
        "both original call boundaries retain typed descriptors"
    );
    let publish = encoding::wide::encode_sys(
        ivm::instruction::wide::system::SCALL,
        syscalls::SYSCALL_INPUT_PUBLISH_TLV as u8,
    );
    assert!(
        !program[parsed.code_offset..]
            .chunks_exact(4)
            .any(|word| u32::from_le_bytes(word.try_into().unwrap()) == publish)
    );
    for (left, right, expected) in [
        ("3", "7", "40"),
        ("7", "3", "25"),
        ("5", "5", "25"),
        ("-3", "4", "7"),
    ] {
        let mut vm = IVM::new(1_000_000);
        vm.load_program(&program).unwrap();
        vm.set_program_counter(entrypoint_pc(&program)).unwrap();
        let payload =
            Json::from_str_norito(&format!(r#"{{"left":"{left}","right":"{right}"}}"#)).unwrap();
        let mut host = argument_host(&program, &payload).unwrap();
        let observer_budget = iroha_allocation::AllocationBudget::new(32 * 1024 * 1024);
        let mut steps =
            ivm::execution_step_recorder::DiagnosticStepRecorder::try_new(4096, &observer_budget)
                .unwrap();
        vm.run_with_host_diagnostic_steps(&mut host, &mut steps)
            .unwrap();
        assert_eq!(
            common::decode_int_word(&vm, vm.public_call_result_word(0).unwrap()),
            bigint(expected)
        );
        let arithmetic = steps
            .records()
            .iter()
            .filter(|step| {
                step.instruction.is_some_and(|word| {
                    ivm::instruction::wide::opcode(word) == ivm::instruction::wide::system::SYSTEM
                        && [
                            syscalls::SYSCALL_INT_ADD,
                            syscalls::SYSCALL_INT_SUB,
                            syscalls::SYSCALL_INT_MUL,
                            syscalls::SYSCALL_INT_LT,
                        ]
                        .contains(&encoding::wide::decode_syscallx(word))
                })
            })
            .collect::<Vec<_>>();
        assert!(
            arithmetic.len() >= 4,
            "actual branch and arithmetic syscalls execute"
        );
        for step in arithmetic {
            assert!(
                step.before.gas_remaining > step.after.gas_remaining,
                "the original typed numeric work remains metered"
            );
        }
        assert!(
            steps
                .records()
                .iter()
                .all(|step| step.instruction != Some(publish))
        );
        eprintln!(
            "borrowed numeric runtime left={left} right={right} artifact_bytes={} gas_used={} steps={}",
            program.len(),
            1_000_000 - vm.remaining_gas(),
            steps.records().len()
        );
    }
    let overflow = run_binary(&program, MAX_INT, "1").unwrap_err();
    assert_eq!(
        numeric_fault_from_vm_error(&overflow),
        Some(NumericFaultV1::MantissaOverflow)
    );
    let division = compile(
        "seiyaku Division { view fn run(int left, int right) authorize(anyone) -> int { return left / right; } }",
    );
    let failure = run_binary(&division, "7", "0").unwrap_err();
    assert_eq!(
        numeric_fault_from_vm_error(&failure),
        Some(NumericFaultV1::DivisionByZero)
    );
}

#[test]
fn borrowed_numeric_literal_and_host_results_keep_decimal_and_quantity_faults() {
    // Existing complete entry/call/result validation is used with literal and
    // freshly allocated numeric results, including both comparison outcomes.
    let decimal = compile(
        r#"seiyaku BorrowedDecimal {
        view fn run(decimal value) authorize(anyone) -> decimal {
            let decimal sum = value + 1.25;
            if (sum < 0) { return sum - 2.5; }
            return sum * 2;
        }
    }"#,
    );
    for (value, expected) in [("2", "6.5"), ("-2", "-3.25")] {
        let payload = Json::from_str_norito(&format!(r#"{{"value":"{value}"}}"#)).unwrap();
        assert_eq!(
            execute_numeric_program(&decimal, Some(&payload), NumericReturnKind::Decimal),
            NumericOutcome::Value(NumericValue::Decimal(expected.parse().unwrap()))
        );
    }
    let quantity = compile(
        r#"seiyaku BorrowedQuantity {
        view fn run(quantity value) authorize(anyone) -> quantity { let quantity one = 1; return value - one; }
    }"#,
    );
    for (value, expected) in [
        (
            "3.5",
            NumericOutcome::Value(NumericValue::Quantity("2.5".parse().unwrap())),
        ),
        (
            "0",
            NumericOutcome::Fault(NumericFaultV1::QuantityUnderflow),
        ),
    ] {
        let payload = Json::from_str_norito(&format!(r#"{{"value":"{value}"}}"#)).unwrap();
        assert_eq!(
            execute_numeric_program(&quantity, Some(&payload), NumericReturnKind::Quantity),
            expected
        );
    }
}

/// Parameter labels of a two-operand `math::` helper, in declaration order.
fn binary_math_labels(name: &str) -> (&'static str, &'static str) {
    if name == "div_ceil" {
        ("dividend", "divisor")
    } else {
        ("left", "right")
    }
}

#[test]
fn binary_math_labels_follow_the_builtin_signatures() {
    assert_eq!(binary_math_labels("div_ceil"), ("dividend", "divisor"));
    assert_eq!(binary_math_labels("mean"), ("left", "right"));
}

#[test]
fn reversed_named_helpers_preserve_noncommutative_results_and_odd_signed_means() {
    for (name, syscall, cases) in [
        (
            "div_ceil",
            syscalls::SYSCALL_INT_DIV_CEIL,
            &[
                ("7", "2", "4"),
                ("-7", "2", "-3"),
                ("7", "-2", "-3"),
                ("-7", "-2", "4"),
                (
                    "340282366920938463463374607431768211457",
                    "3",
                    "113427455640312821154458202477256070486",
                ),
                (
                    "-340282366920938463463374607431768211457",
                    "3",
                    "-113427455640312821154458202477256070485",
                ),
            ][..],
        ),
        (
            "mean",
            syscalls::SYSCALL_INT_MEAN,
            &[
                ("7", "2", "4"),
                ("-7", "-2", "-4"),
                ("7", "-2", "2"),
                ("-7", "2", "-2"),
                ("-1", "0", "0"),
                ("0", "-1", "0"),
            ][..],
        ),
    ] {
        let (first, second) = binary_math_labels(name);
        let runtime = compile(&format!(
            "seiyaku NamedMath {{ view fn run(int left, int right) authorize(anyone) -> int {{ return math::{name}({second}: right, {first}: left); }} }}"
        ));
        assert!(contains_extended_syscall(&runtime, syscall));
        for &(left, right, expected) in cases {
            let folded = compile(&format!(
                "seiyaku NamedMath {{ view fn run(int left, int right) authorize(anyone) -> int {{ return math::{name}({second}: {right}, {first}: {left}); }} }}"
            ));
            assert!(!contains_extended_syscall(&folded, syscall));
            let expected = bigint(expected);
            assert_eq!(run_binary(&runtime, left, right).unwrap(), expected);
            assert_eq!(run_binary(&folded, "0", "0").unwrap(), expected);
        }
    }
    let reversed_division = compile(
        "seiyaku NamedMath { view fn run(int left, int right) authorize(anyone) -> int { return math::div_ceil(divisor: right, dividend: left); } }",
    );
    assert_eq!(
        classify_runtime(run_binary(&reversed_division, MIN_INT, "-1")),
        ArithmeticOutcome::MantissaOverflow
    );
    assert_eq!(
        folded_outcome(&format!("math::div_ceil(divisor: -1, dividend: {MIN_INT})")),
        ArithmeticOutcome::MantissaOverflow
    );
}
