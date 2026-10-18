//! Exhaustive signed-boundary checks for trapping IVM arithmetic opcodes.
use crate::common;
use ivm::{IVM, VMError, encoding, instruction};
const HALT_WORD: u32 = encoding::wide::encode_halt();
const DESTINATION_SENTINEL: u64 = 0xCAFE_BABE_DEAD_BEEF;
const BOUNDARY_VALUES: [i64; 7] = [i64::MIN, i64::MIN + 1, -1, 0, 1, i64::MAX - 1, i64::MAX];
fn assemble_words(words: &[u32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(words.len() * 4);
    for word in words {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    common::assemble(&bytes)
}
fn vm_with_instruction(instruction: u32) -> IVM {
    let program = assemble_words(&[instruction, HALT_WORD]);
    let mut vm = IVM::new(u64::MAX);
    vm.load_program(&program).expect("load boundary program");
    vm
}
fn execute_binary(vm: &mut IVM, left: i64, right: i64) -> (Result<(), VMError>, u64) {
    vm.reset().expect("private lifecycle cleanup succeeds");
    vm.set_register(1, left as u64);
    vm.set_register(2, right as u64);
    vm.set_register(3, DESTINATION_SENTINEL);
    let result = vm.run();
    (result, vm.register(3))
}
fn execute_abs(vm: &mut IVM, value: i64) -> (Result<(), VMError>, u64) {
    vm.reset().expect("private lifecycle cleanup succeeds");
    vm.set_register(1, value as u64);
    vm.set_register(3, DESTINATION_SENTINEL);
    let result = vm.run();
    (result, vm.register(3))
}
fn assert_checked_result(
    operation: &str,
    operands: (i64, Option<i64>),
    actual: (Result<(), VMError>, u64),
    expected: Option<i64>,
) {
    let (left, right) = operands;
    let (result, destination) = actual;
    match expected {
        Some(value) => {
            assert!(
                matches!(result, Ok(())),
                "{operation} unexpectedly trapped for {left} and {right:?}"
            );
            assert_eq!(
                destination as i64, value,
                "{operation} returned the wrong value for {left} and {right:?}"
            );
        }
        None => {
            assert!(
                matches!(result, Err(VMError::AssertionFailed)),
                "{operation} must trap for {left} and {right:?}"
            );
            assert_eq!(
                destination, DESTINATION_SENTINEL,
                "{operation} must not write its destination before trapping"
            );
        }
    }
}
fn checked_div_oracle(left: i64, right: i64) -> Option<i64> {
    if right == 0 {
        return None;
    }
    i64::try_from(i128::from(left) / i128::from(right)).ok()
}
fn checked_rem_oracle(left: i64, right: i64) -> Option<i64> {
    if right == 0 || (left == i64::MIN && right == -1) {
        return None;
    }
    i64::try_from(i128::from(left) % i128::from(right)).ok()
}
fn checked_div_ceil_oracle(left: i64, right: i64) -> Option<i64> {
    if right == 0 {
        return None;
    }
    let left = i128::from(left);
    let right = i128::from(right);
    let quotient = left / right;
    let remainder = left % right;
    let rounded = if remainder != 0 && remainder.signum() == right.signum() {
        quotient + 1
    } else {
        quotient
    };
    i64::try_from(rounded).ok()
}
#[test]
fn signed_division_traps_on_zero_and_overflow_across_boundaries() {
    let mut vm = vm_with_instruction(encoding::wide::encode_rr(
        instruction::wide::arithmetic::DIV,
        3,
        1,
        2,
    ));
    for left in BOUNDARY_VALUES {
        for right in BOUNDARY_VALUES {
            assert_checked_result(
                "DIV",
                (left, Some(right)),
                execute_binary(&mut vm, left, right),
                checked_div_oracle(left, right),
            );
        }
    }
}
#[test]
fn signed_remainder_traps_on_zero_and_overflow_across_boundaries() {
    let mut vm = vm_with_instruction(encoding::wide::encode_rr(
        instruction::wide::arithmetic::REM,
        3,
        1,
        2,
    ));
    for left in BOUNDARY_VALUES {
        for right in BOUNDARY_VALUES {
            assert_checked_result(
                "REM",
                (left, Some(right)),
                execute_binary(&mut vm, left, right),
                checked_rem_oracle(left, right),
            );
        }
    }
}
#[test]
fn signed_div_ceil_traps_on_zero_and_overflow_across_boundaries() {
    let mut vm = vm_with_instruction(encoding::wide::encode_rr(
        instruction::wide::arithmetic::DIV_CEIL,
        3,
        1,
        2,
    ));
    for left in BOUNDARY_VALUES {
        for right in BOUNDARY_VALUES {
            assert_checked_result(
                "DIV_CEIL",
                (left, Some(right)),
                execute_binary(&mut vm, left, right),
                checked_div_ceil_oracle(left, right),
            );
        }
    }
}
#[test]
fn signed_abs_traps_only_for_min_across_boundaries() {
    let mut vm = vm_with_instruction(encoding::wide::encode_rr(
        instruction::wide::arithmetic::ABS,
        3,
        1,
        0,
    ));
    for value in BOUNDARY_VALUES {
        let expected = i64::try_from(i128::from(value).abs()).ok();
        assert_checked_result("ABS", (value, None), execute_abs(&mut vm, value), expected);
    }
}
