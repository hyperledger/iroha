//! Kotodama V1 exact numeric syscall implementation.
use crate::{
    IVM, VMError,
    numeric::{
        NUMERIC_FAILURE_MODE_REGISTER, NUMERIC_FAILURE_STATUS, NUMERIC_FAILURE_TRAP,
        NUMERIC_RESULT_REGISTER, NUMERIC_ROUNDING_REGISTER, NUMERIC_SCALE_REGISTER,
        NUMERIC_STATUS_REGISTER, NumericFaultV1, PointerAbiFaultV1, RoundingModeV1,
    },
    numeric_gas, numeric_tlv,
    syscall_metering::SyscallMeteringPhase,
    syscalls,
};
use core::cmp::Ordering;
use iroha_primitives::numeric_int::{IntBinaryOperation, IntUnaryOperation};
use iroha_primitives::{
    bigint::{BigInt, BigIntError},
    numeric::{
        MAX_MANTISSA_BYTES, Numeric, NumericOperationError, NumericWorkStep, ObservedNumericError,
        Quantity, RoundingMode,
    },
};
#[derive(Clone, Copy)]
enum FailureMode {
    Trap,
    Status,
}
fn failure_mode(vm: &IVM, reserved: &[usize]) -> Result<FailureMode, VMError> {
    if reserved.iter().any(|&register| vm.register(register) != 0) {
        return Err(VMError::NumericFault(
            NumericFaultV1::ReservedRegisterNonZero,
        ));
    }
    match vm.register(NUMERIC_FAILURE_MODE_REGISTER) {
        NUMERIC_FAILURE_TRAP => Ok(FailureMode::Trap),
        NUMERIC_FAILURE_STATUS => Ok(FailureMode::Status),
        _ => Err(VMError::NumericFault(NumericFaultV1::InvalidFailureMode)),
    }
}
fn require_zero_registers(vm: &IVM, reserved: &[usize]) -> Result<(), VMError> {
    if reserved.iter().any(|&register| vm.register(register) != 0) {
        Err(VMError::NumericFault(
            NumericFaultV1::ReservedRegisterNonZero,
        ))
    } else {
        Ok(())
    }
}
fn rounding_mode(vm: &IVM) -> Result<RoundingMode, VMError> {
    rounding_mode_at(vm, NUMERIC_ROUNDING_REGISTER)
}
fn rounding_mode_at(vm: &IVM, register: usize) -> Result<RoundingMode, VMError> {
    let mode = RoundingModeV1::from_tag(vm.register(register))
        .ok_or(VMError::NumericFault(NumericFaultV1::InvalidRoundingMode))?;
    Ok(match mode {
        RoundingModeV1::TowardZero => RoundingMode::TowardZero,
        RoundingModeV1::AwayFromZero => RoundingMode::AwayFromZero,
        RoundingModeV1::Floor => RoundingMode::Floor,
        RoundingModeV1::Ceil => RoundingMode::Ceil,
        RoundingModeV1::NearestEven => RoundingMode::NearestEven,
        RoundingModeV1::NearestAway => RoundingMode::NearestAway,
        RoundingModeV1::NearestTowardZero => RoundingMode::NearestTowardZero,
    })
}
fn numeric_fault(error: NumericOperationError) -> Result<NumericFaultV1, VMError> {
    Ok(match error {
        NumericOperationError::MantissaOverflow => NumericFaultV1::MantissaOverflow,
        NumericOperationError::ScaleOverflow => NumericFaultV1::ScaleOverflow,
        NumericOperationError::DivisionByZero => NumericFaultV1::DivisionByZero,
        NumericOperationError::RepeatingDecimal => NumericFaultV1::RepeatingDecimal,
        NumericOperationError::ExactDivisionScaleOverflow => {
            NumericFaultV1::ExactDivisionScaleOverflow
        }
        NumericOperationError::InvalidScale => NumericFaultV1::InvalidScale,
        NumericOperationError::InexactConversion => NumericFaultV1::InexactConversion,
        NumericOperationError::NegativeQuantity => NumericFaultV1::NegativeQuantity,
        NumericOperationError::QuantityUnderflow => NumericFaultV1::QuantityUnderflow,
        NumericOperationError::NegativeSquareRoot => NumericFaultV1::NegativeSquareRoot,
        NumericOperationError::NonCanonical => {
            return Err(VMError::PointerAbiFault(PointerAbiFaultV1::NonCanonical));
        }
    })
}
fn bigint_fault(error: BigIntError) -> Result<NumericFaultV1, VMError> {
    match error {
        BigIntError::Overflow => Ok(NumericFaultV1::MantissaOverflow),
        BigIntError::DivisionByZero => Ok(NumericFaultV1::DivisionByZero),
        BigIntError::NonCanonical => Err(VMError::PointerAbiFault(PointerAbiFaultV1::NonCanonical)),
    }
}
fn enforce_int_domain(value: BigInt) -> Result<BigInt, BigIntError> {
    if value.twos_byte_len() <= MAX_MANTISSA_BYTES {
        Ok(value)
    } else {
        Err(BigIntError::Overflow)
    }
}
fn checked_int_result(result: Result<BigInt, BigIntError>) -> Result<BigInt, BigIntError> {
    result.and_then(enforce_int_domain)
}
fn checked_int_div_rem(
    result: Result<(BigInt, BigInt), BigIntError>,
) -> Result<(BigInt, BigInt), BigIntError> {
    let (quotient, remainder) = result?;
    // The quotient is validated even for `%`: `MIN / -1` is one overflowing
    // signed division operation, so both paired results have the same fault.
    Ok((
        enforce_int_domain(quotient)?,
        enforce_int_domain(remainder)?,
    ))
}
fn wrap_int_result(value: BigInt) -> Result<BigInt, BigIntError> {
    let source = value.to_twos_bytes();
    let extension = if value.is_negative() { 0xff } else { 0x00 };
    let mut low = vec![extension; MAX_MANTISSA_BYTES];
    let copied = source.len().min(MAX_MANTISSA_BYTES);
    low[..copied].copy_from_slice(&source[..copied]);
    BigInt::from_twos_bytes(&low)
}
fn recover(vm: &mut IVM, fault: NumericFaultV1) -> Result<(), VMError> {
    vm.set_register(NUMERIC_RESULT_REGISTER, 0);
    vm.set_register(NUMERIC_STATUS_REGISTER, fault.tag());
    vm.mark_staged_syscall_recoverable_failure()
}
fn resolve_failure<T>(
    vm: &mut IVM,
    mode: FailureMode,
    result: Result<T, NumericOperationError>,
) -> Result<Option<T>, VMError> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(error) => {
            let fault = numeric_fault(error)?;
            match mode {
                FailureMode::Trap => Err(VMError::NumericFault(fault)),
                FailureMode::Status => {
                    recover(vm, fault)?;
                    Ok(None)
                }
            }
        }
    }
}
fn resolve_bigint_failure<T>(
    vm: &mut IVM,
    mode: FailureMode,
    result: Result<T, BigIntError>,
) -> Result<Option<T>, VMError> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(error) => {
            let fault = bigint_fault(error)?;
            match mode {
                FailureMode::Trap => Err(VMError::NumericFault(fault)),
                FailureMode::Status => {
                    recover(vm, fault)?;
                    Ok(None)
                }
            }
        }
    }
}
fn resolve_observed<T>(
    vm: &mut IVM,
    mode: FailureMode,
    result: Result<T, ObservedNumericError<VMError>>,
) -> Result<Option<T>, VMError> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(ObservedNumericError::Observer(error)) => Err(error),
        Err(ObservedNumericError::Numeric(error)) => resolve_failure(vm, mode, Err(error)),
    }
}
fn observe_work(vm: &mut IVM, step: NumericWorkStep) -> Result<(), VMError> {
    let phase = match step {
        NumericWorkStep::CanonicalityProbe { .. } => SyscallMeteringPhase::CanonicalValidation,
        NumericWorkStep::Normalize { .. } => SyscallMeteringPhase::Normalization,
        NumericWorkStep::ScaleByPowerOfTen { .. }
        | NumericWorkStep::Materialize { .. }
        | NumericWorkStep::Negate { .. }
        | NumericWorkStep::Compare { .. }
        | NumericWorkStep::Add { .. }
        | NumericWorkStep::Subtract { .. }
        | NumericWorkStep::Multiply { .. }
        | NumericWorkStep::ExactDivisionAttempt { .. }
        | NumericWorkStep::DivisionClassificationPrepare { .. }
        | NumericWorkStep::DivisionClassification { .. }
        | NumericWorkStep::RoundedDivision { .. }
        | NumericWorkStep::Finalize { .. } => SyscallMeteringPhase::Arithmetic,
    };
    vm.charge_syscall_stage(phase, numeric_gas::work_step_gas(step)?)
}
fn limb_count(value: &BigInt) -> u64 {
    numeric_gas::limbs_for_bits(u64::try_from(value.bit_len()).unwrap_or(u64::MAX))
}
fn twos_limb_count(value: &BigInt) -> Result<u64, VMError> {
    let magnitude_bits = u64::try_from(value.bit_len()).map_err(|_| VMError::GasCostOverflow)?;
    let conservative_signed_bits = magnitude_bits
        .checked_add(1)
        .ok_or(VMError::GasCostOverflow)?;
    Ok(numeric_gas::limbs_for_bits(conservative_signed_bits))
}
fn charge_limb_work(vm: &mut IVM, work: u64) -> Result<(), VMError> {
    vm.charge_syscall_stage(
        SyscallMeteringPhase::Arithmetic,
        numeric_gas::work_gas(work)?,
    )
}
fn charge_unary(vm: &mut IVM, value: &BigInt) -> Result<(), VMError> {
    charge_limb_work(vm, limb_count(value))
}
fn charge_checked_unary(vm: &mut IVM, value: &BigInt) -> Result<(), VMError> {
    charge_limb_work(vm, numeric_gas::checked_int_unary_work(limb_count(value))?)
}
fn charge_additive(vm: &mut IVM, lhs: &BigInt, rhs: &BigInt) -> Result<(), VMError> {
    charge_limb_work(vm, limb_count(lhs).max(limb_count(rhs)))
}
fn charge_checked_additive(vm: &mut IVM, lhs: &BigInt, rhs: &BigInt) -> Result<(), VMError> {
    charge_limb_work(
        vm,
        numeric_gas::checked_int_additive_work(limb_count(lhs), limb_count(rhs))?,
    )
}
fn charge_wrapping_additive(vm: &mut IVM, lhs: &BigInt, rhs: &BigInt) -> Result<(), VMError> {
    charge_limb_work(
        vm,
        numeric_gas::wrapping_additive_work(limb_count(lhs), limb_count(rhs))?,
    )
}
fn charge_checked_multiplication(vm: &mut IVM, lhs: &BigInt, rhs: &BigInt) -> Result<(), VMError> {
    charge_limb_work(
        vm,
        numeric_gas::checked_int_multiplication_work(limb_count(lhs), limb_count(rhs))?,
    )
}
fn charge_wrapping_multiplication(vm: &mut IVM, lhs: &BigInt, rhs: &BigInt) -> Result<(), VMError> {
    charge_limb_work(
        vm,
        numeric_gas::wrapping_multiplication_work(limb_count(lhs), limb_count(rhs))?,
    )
}
fn charge_checked_division(vm: &mut IVM, lhs: &BigInt, rhs: &BigInt) -> Result<(), VMError> {
    charge_limb_work(
        vm,
        numeric_gas::checked_int_division_work(limb_count(lhs), limb_count(rhs))?,
    )
}
fn charge_wrapping_unary(vm: &mut IVM, value: &BigInt) -> Result<(), VMError> {
    charge_limb_work(vm, numeric_gas::wrapping_unary_work(limb_count(value))?)
}
fn charge_wrapping_reduction(vm: &mut IVM, value: &BigInt) -> Result<(), VMError> {
    charge_limb_work(
        vm,
        numeric_gas::wrapping_reduction_work(twos_limb_count(value)?)?,
    )
}
fn charge_decimal_comparison(vm: &mut IVM, lhs: &Numeric, rhs: &Numeric) -> Result<(), VMError> {
    let target = lhs.scale().max(rhs.scale());
    let lhs_delta = u8::try_from(target - lhs.scale()).map_err(|_| VMError::GasCostOverflow)?;
    let rhs_delta = u8::try_from(target - rhs.scale()).map_err(|_| VMError::GasCostOverflow)?;
    let lhs_bits = u64::try_from(lhs.mantissa().bit_len()).map_err(|_| VMError::GasCostOverflow)?;
    let rhs_bits = u64::try_from(rhs.mantissa().bit_len()).map_err(|_| VMError::GasCostOverflow)?;
    let lhs_aligned = numeric_gas::scaled_limbs(lhs_bits, lhs_delta)?;
    let rhs_aligned = numeric_gas::scaled_limbs(rhs_bits, rhs_delta)?;
    let work = numeric_gas::aligned_work(
        lhs_bits,
        lhs_delta,
        lhs_aligned,
        rhs_bits,
        rhs_delta,
        rhs_aligned,
    )?;
    charge_limb_work(vm, work)
}
fn publish_int(vm: &mut IVM, value: &BigInt) -> Result<(), VMError> {
    let pointer = numeric_tlv::allocate_int_metered(vm, value)?;
    vm.set_register(NUMERIC_RESULT_REGISTER, pointer);
    vm.set_register(NUMERIC_STATUS_REGISTER, 0);
    Ok(())
}
fn publish_decimal(vm: &mut IVM, value: &Numeric) -> Result<(), VMError> {
    let pointer = numeric_tlv::allocate_decimal_metered(vm, value)?;
    vm.set_register(NUMERIC_RESULT_REGISTER, pointer);
    vm.set_register(NUMERIC_STATUS_REGISTER, 0);
    Ok(())
}
fn publish_quantity(vm: &mut IVM, value: &Quantity) -> Result<(), VMError> {
    let pointer = numeric_tlv::allocate_quantity_metered(vm, value)?;
    vm.set_register(NUMERIC_RESULT_REGISTER, pointer);
    vm.set_register(NUMERIC_STATUS_REGISTER, 0);
    Ok(())
}
fn publish_bool(vm: &mut IVM, value: bool) {
    vm.set_register(NUMERIC_RESULT_REGISTER, u64::from(value));
}
fn decode_int_register(vm: &mut IVM, register: usize) -> Result<BigInt, VMError> {
    let pointer = vm.register(register);
    numeric_tlv::decode_int_metered(vm, pointer)
}
fn decode_decimal_register(vm: &mut IVM, register: usize) -> Result<Numeric, VMError> {
    let pointer = vm.register(register);
    numeric_tlv::decode_decimal_metered(vm, pointer)
}
fn decode_quantity_register(vm: &mut IVM, register: usize) -> Result<Quantity, VMError> {
    let pointer = vm.register(register);
    numeric_tlv::decode_quantity_metered(vm, pointer)
}
fn decode_scale(vm: &mut IVM) -> Result<Result<u32, NumericOperationError>, VMError> {
    let scale = decode_int_register(vm, NUMERIC_SCALE_REGISTER)?;
    Ok(match scale.try_to_u64() {
        Some(scale) if scale <= u64::from(numeric_gas::MAX_DECIMAL_SCALE) => {
            Ok(u32::try_from(scale).expect("bounded scale fits u32"))
        }
        _ => Err(NumericOperationError::InvalidScale),
    })
}
fn decimal_exact_division_observed(
    vm: &mut IVM,
    lhs: &Numeric,
    rhs: &Numeric,
) -> Result<Numeric, ObservedNumericError<VMError>> {
    lhs.try_decimal_div_exact_observed(rhs, &mut |step| observe_work(vm, step))
}
/// Execute one allowed Kotodama V1 numeric syscall.
///
/// # Errors
/// Returns stable pointer, arithmetic, metering, memory, or malformed-register
/// errors. The caller must register these syscalls for staged metering.
#[allow(clippy::too_many_lines)]
pub fn execute(number: u32, vm: &mut IVM) -> Result<u64, VMError> {
    match number {
        syscalls::SYSCALL_DECIMAL_MUL_DIV_ROUND | syscalls::SYSCALL_QUANTITY_MUL_DIV_ROUND => {
            require_zero_registers(vm, &[15])?;
            let quantity = number == syscalls::SYSCALL_QUANTITY_MUL_DIV_ROUND;
            let value = if quantity {
                decode_quantity_register(vm, 10)?.into_numeric()
            } else {
                decode_decimal_register(vm, 10)?
            };
            let multiplier = decode_decimal_register(vm, 11)?;
            let divisor = decode_decimal_register(vm, 12)?;
            let scale = decode_int_register(vm, 13)?
                .try_to_u64()
                .filter(|scale| *scale <= u64::from(numeric_gas::MAX_DECIMAL_SCALE))
                .ok_or(VMError::NumericFault(NumericFaultV1::InvalidScale))?
                as u32;
            let rounding = rounding_mode_at(vm, 14)?;
            let observed = value.try_decimal_mul_div_round_observed(
                &multiplier,
                &divisor,
                scale,
                rounding,
                &mut |step| observe_work(vm, step),
            );
            if let Some(value) = resolve_observed(vm, FailureMode::Trap, observed)? {
                if quantity {
                    let value = Quantity::from_canonical_numeric(value).map_err(|error| {
                        numeric_fault(error)
                            .map(VMError::NumericFault)
                            .unwrap_or_else(|error| error)
                    })?;
                    publish_quantity(vm, &value)?;
                } else {
                    publish_decimal(vm, &value)?;
                }
            }
        }
        syscalls::SYSCALL_INT_ISQRT | syscalls::SYSCALL_INT_ABS => {
            let value = decode_int_register(vm, 10)?;
            let mode = failure_mode(vm, &[11, 12, 13])?;
            let operation = if number == syscalls::SYSCALL_INT_ISQRT {
                IntUnaryOperation::Isqrt
            } else {
                IntUnaryOperation::Abs
            };
            let result = operation.evaluate_observed(&value, &mut |step| observe_work(vm, step));
            if let Some(result) = resolve_observed(vm, mode, result)? {
                publish_int(vm, &result)?;
            }
        }
        syscalls::SYSCALL_INT_MIN
        | syscalls::SYSCALL_INT_MAX
        | syscalls::SYSCALL_INT_DIV_CEIL
        | syscalls::SYSCALL_INT_GCD
        | syscalls::SYSCALL_INT_MEAN => {
            let lhs = decode_int_register(vm, 10)?;
            let rhs = decode_int_register(vm, 11)?;
            let mode = failure_mode(vm, &[12, 13])?;
            let operation = match number {
                syscalls::SYSCALL_INT_MIN => IntBinaryOperation::Min,
                syscalls::SYSCALL_INT_MAX => IntBinaryOperation::Max,
                syscalls::SYSCALL_INT_DIV_CEIL => IntBinaryOperation::DivCeil,
                syscalls::SYSCALL_INT_GCD => IntBinaryOperation::Gcd,
                _ => IntBinaryOperation::Mean,
            };
            let result =
                operation.evaluate_observed(&lhs, &rhs, &mut |step| observe_work(vm, step));
            if let Some(result) = resolve_observed(vm, mode, result)? {
                publish_int(vm, &result)?;
            }
        }
        syscalls::SYSCALL_INT_FROM_I64 | syscalls::SYSCALL_INT_FROM_U64 => {
            let value = if number == syscalls::SYSCALL_INT_FROM_I64 {
                BigInt::from(vm.register(10) as i64)
            } else {
                BigInt::from(vm.register(10))
            };
            charge_unary(vm, &value)?;
            publish_int(vm, &value)?;
        }
        syscalls::SYSCALL_INT_TO_I64 | syscalls::SYSCALL_INT_TO_U64 => {
            let value = decode_int_register(vm, 10)?;
            let mode = failure_mode(vm, &[11, 12, 13])?;
            charge_unary(vm, &value)?;
            let result = if number == syscalls::SYSCALL_INT_TO_I64 {
                value.try_to_i64().map(|value| value as u64)
            } else {
                value.try_to_u64()
            };
            if let Some(result) = resolve_failure(
                vm,
                mode,
                result.ok_or(NumericOperationError::InexactConversion),
            )? {
                vm.set_register(NUMERIC_RESULT_REGISTER, result);
                vm.set_register(NUMERIC_STATUS_REGISTER, 0);
            }
        }
        syscalls::SYSCALL_INT_NEG => {
            let value = decode_int_register(vm, 10)?;
            let mode = failure_mode(vm, &[11, 12, 13])?;
            charge_checked_unary(vm, &value)?;
            if let Some(result) =
                resolve_bigint_failure(vm, mode, checked_int_result(value.checked_neg()))?
            {
                publish_int(vm, &result)?;
            }
        }
        syscalls::SYSCALL_INT_ADD | syscalls::SYSCALL_INT_SUB => {
            let lhs = decode_int_register(vm, 10)?;
            let rhs = decode_int_register(vm, 11)?;
            let mode = failure_mode(vm, &[12, 13])?;
            charge_checked_additive(vm, &lhs, &rhs)?;
            let result = if number == syscalls::SYSCALL_INT_ADD {
                lhs.checked_add(&rhs)
            } else {
                lhs.checked_sub(&rhs)
            };
            if let Some(result) = resolve_bigint_failure(vm, mode, checked_int_result(result))? {
                publish_int(vm, &result)?;
            }
        }
        syscalls::SYSCALL_INT_MUL => {
            let lhs = decode_int_register(vm, 10)?;
            let rhs = decode_int_register(vm, 11)?;
            let mode = failure_mode(vm, &[12, 13])?;
            charge_checked_multiplication(vm, &lhs, &rhs)?;
            if let Some(result) =
                resolve_bigint_failure(vm, mode, checked_int_result(lhs.checked_mul(&rhs)))?
            {
                publish_int(vm, &result)?;
            }
        }
        syscalls::SYSCALL_INT_DIV | syscalls::SYSCALL_INT_REM => {
            let lhs = decode_int_register(vm, 10)?;
            let rhs = decode_int_register(vm, 11)?;
            let mode = failure_mode(vm, &[12, 13])?;
            if rhs.is_zero()
                && resolve_bigint_failure::<()>(vm, mode, Err(BigIntError::DivisionByZero))?
                    .is_none()
            {
                return Ok(0);
            }
            charge_checked_division(vm, &lhs, &rhs)?;
            if let Some((quotient, remainder)) =
                resolve_bigint_failure(vm, mode, checked_int_div_rem(lhs.checked_div_rem(&rhs)))?
            {
                publish_int(
                    vm,
                    if number == syscalls::SYSCALL_INT_DIV {
                        &quotient
                    } else {
                        &remainder
                    },
                )?;
            }
        }
        syscalls::SYSCALL_INT_EQ
        | syscalls::SYSCALL_INT_NE
        | syscalls::SYSCALL_INT_LT
        | syscalls::SYSCALL_INT_LE
        | syscalls::SYSCALL_INT_GT
        | syscalls::SYSCALL_INT_GE => {
            let lhs = decode_int_register(vm, 10)?;
            let rhs = decode_int_register(vm, 11)?;
            charge_additive(vm, &lhs, &rhs)?;
            let ordering = lhs.cmp(&rhs);
            publish_bool(vm, comparison(number, ordering));
        }
        syscalls::SYSCALL_INT_WRAP_NEG => {
            let value = decode_int_register(vm, 10)?;
            charge_wrapping_unary(vm, &value)?;
            let intermediate = value
                .checked_neg()
                .expect("a 512-bit operand negation fits the generic bigint domain");
            charge_wrapping_reduction(vm, &intermediate)?;
            let result = wrap_int_result(intermediate)
                .expect("a 512-bit operand reduction fits the generic bigint domain");
            publish_int(vm, &result)?;
        }
        syscalls::SYSCALL_INT_WRAP_ADD | syscalls::SYSCALL_INT_WRAP_SUB => {
            let lhs = decode_int_register(vm, 10)?;
            let rhs = decode_int_register(vm, 11)?;
            charge_wrapping_additive(vm, &lhs, &rhs)?;
            let intermediate = if number == syscalls::SYSCALL_INT_WRAP_ADD {
                lhs.checked_add(&rhs)
            } else {
                lhs.checked_sub(&rhs)
            }
            .expect("512-bit add/sub intermediates fit the generic bigint domain");
            charge_wrapping_reduction(vm, &intermediate)?;
            let result = wrap_int_result(intermediate)
                .expect("512-bit add/sub intermediates fit the generic bigint domain");
            publish_int(vm, &result)?;
        }
        syscalls::SYSCALL_INT_WRAP_MUL => {
            let lhs = decode_int_register(vm, 10)?;
            let rhs = decode_int_register(vm, 11)?;
            charge_wrapping_multiplication(vm, &lhs, &rhs)?;
            let intermediate = lhs
                .checked_mul(&rhs)
                .expect("512-bit multiplication intermediates fit the generic bigint domain");
            charge_wrapping_reduction(vm, &intermediate)?;
            let result = wrap_int_result(intermediate)
                .expect("512-bit multiplication reduction fits the generic bigint domain");
            publish_int(vm, &result)?;
        }
        syscalls::SYSCALL_DECIMAL_FROM_INT => {
            let value = decode_int_register(vm, 10)?;
            charge_unary(vm, &value)?;
            publish_decimal(vm, &Numeric::new(value, 0))?;
        }
        syscalls::SYSCALL_DECIMAL_NEG => {
            let value = decode_decimal_register(vm, 10)?;
            let mode = failure_mode(vm, &[11, 12, 13])?;
            let result = value.try_decimal_neg_observed(&mut |step| observe_work(vm, step));
            if let Some(result) = resolve_observed(vm, mode, result)? {
                publish_decimal(vm, &result)?;
            }
        }
        syscalls::SYSCALL_DECIMAL_ADD
        | syscalls::SYSCALL_DECIMAL_SUB
        | syscalls::SYSCALL_DECIMAL_MUL => {
            let lhs = decode_decimal_register(vm, 10)?;
            let rhs = decode_decimal_register(vm, 11)?;
            let mode = failure_mode(vm, &[12, 13])?;
            let result = match number {
                syscalls::SYSCALL_DECIMAL_ADD => {
                    lhs.try_decimal_add_observed(&rhs, &mut |step| observe_work(vm, step))
                }
                syscalls::SYSCALL_DECIMAL_SUB => {
                    lhs.try_decimal_sub_observed(&rhs, &mut |step| observe_work(vm, step))
                }
                _ => lhs.try_decimal_mul_observed(&rhs, &mut |step| observe_work(vm, step)),
            };
            if let Some(result) = resolve_observed(vm, mode, result)? {
                publish_decimal(vm, &result)?;
            }
        }
        syscalls::SYSCALL_DECIMAL_DIV_EXACT => {
            let lhs = decode_decimal_register(vm, 10)?;
            let rhs = decode_decimal_register(vm, 11)?;
            let mode = failure_mode(vm, &[12, 13])?;
            let result = decimal_exact_division_observed(vm, &lhs, &rhs);
            if let Some(result) = resolve_observed(vm, mode, result)? {
                publish_decimal(vm, &result)?;
            }
        }
        syscalls::SYSCALL_DECIMAL_DIV_ROUND => {
            let lhs = decode_decimal_register(vm, 10)?;
            let rhs = decode_decimal_register(vm, 11)?;
            let decoded_scale = decode_scale(vm)?;
            let rounding = rounding_mode(vm)?;
            let mode = failure_mode(vm, &[])?;
            let scale = match resolve_failure(vm, mode, decoded_scale)? {
                Some(scale) => scale,
                None => return Ok(0),
            };
            let result = lhs.try_decimal_div_round_observed(&rhs, scale, rounding, &mut |step| {
                observe_work(vm, step)
            });
            if let Some(result) = resolve_observed(vm, mode, result)? {
                publish_decimal(vm, &result)?;
            }
        }
        syscalls::SYSCALL_DECIMAL_EQ
        | syscalls::SYSCALL_DECIMAL_NE
        | syscalls::SYSCALL_DECIMAL_LT
        | syscalls::SYSCALL_DECIMAL_LE
        | syscalls::SYSCALL_DECIMAL_GT
        | syscalls::SYSCALL_DECIMAL_GE => {
            let lhs = decode_decimal_register(vm, 10)?;
            let rhs = decode_decimal_register(vm, 11)?;
            charge_decimal_comparison(vm, &lhs, &rhs)?;
            publish_bool(vm, comparison(number, lhs.cmp(&rhs)));
        }
        syscalls::SYSCALL_DECIMAL_TO_INT_EXACT
        | syscalls::SYSCALL_DECIMAL_TO_INT_TRUNC
        | syscalls::SYSCALL_DECIMAL_TO_INT_ROUND => {
            let value = decode_decimal_register(vm, 10)?;
            let mode = if number == syscalls::SYSCALL_DECIMAL_TO_INT_EXACT {
                failure_mode(vm, &[11, 12, 13])?
            } else {
                FailureMode::Status
            };
            let rounded_mode = if number == syscalls::SYSCALL_DECIMAL_TO_INT_ROUND {
                require_zero_registers(vm, &[11, 12])?;
                Some(rounding_mode(vm)?)
            } else {
                None
            };
            let result = match number {
                syscalls::SYSCALL_DECIMAL_TO_INT_EXACT => {
                    value.try_decimal_to_int_exact_observed(&mut |step| observe_work(vm, step))
                }
                syscalls::SYSCALL_DECIMAL_TO_INT_TRUNC => {
                    value.decimal_to_int_trunc_observed(&mut |step| observe_work(vm, step))
                }
                _ => value.decimal_to_int_round_observed(
                    rounded_mode.expect("rounded conversion initialized its mode"),
                    &mut |step| observe_work(vm, step),
                ),
            };
            if let Some(result) = resolve_observed(vm, mode, result)? {
                publish_int(vm, &result)?;
            }
        }
        syscalls::SYSCALL_QUANTITY_FROM_INT => {
            let value = decode_int_register(vm, 10)?;
            let mode = failure_mode(vm, &[11, 12, 13])?;
            charge_unary(vm, &value)?;
            let decimal = Numeric::new(value, 0);
            if let Some(quantity) =
                resolve_failure(vm, mode, Quantity::from_canonical_numeric(decimal))?
            {
                publish_quantity(vm, &quantity)?;
            }
        }
        syscalls::SYSCALL_QUANTITY_FROM_DECIMAL => {
            let value = decode_decimal_register(vm, 10)?;
            let mode = failure_mode(vm, &[11, 12, 13])?;
            charge_unary(vm, value.mantissa())?;
            if let Some(quantity) =
                resolve_failure(vm, mode, Quantity::from_canonical_numeric(value))?
            {
                publish_quantity(vm, &quantity)?;
            }
        }
        syscalls::SYSCALL_QUANTITY_TO_DECIMAL => {
            let value = decode_quantity_register(vm, 10)?;
            charge_unary(vm, value.mantissa())?;
            publish_decimal(vm, value.as_numeric())?;
        }
        syscalls::SYSCALL_QUANTITY_ADD
        | syscalls::SYSCALL_QUANTITY_SUB
        | syscalls::SYSCALL_QUANTITY_MUL_DECIMAL => {
            let lhs = decode_quantity_register(vm, 10)?;
            let rhs = if number == syscalls::SYSCALL_QUANTITY_MUL_DECIMAL {
                decode_decimal_register(vm, 11)?
            } else {
                decode_quantity_register(vm, 11)?.into_numeric()
            };
            let mode = failure_mode(vm, &[12, 13])?;
            let result = match number {
                syscalls::SYSCALL_QUANTITY_ADD => lhs
                    .as_numeric()
                    .try_decimal_add_observed(&rhs, &mut |step| observe_work(vm, step)),
                syscalls::SYSCALL_QUANTITY_SUB => lhs
                    .as_numeric()
                    .try_decimal_sub_observed(&rhs, &mut |step| observe_work(vm, step)),
                _ => lhs
                    .as_numeric()
                    .try_decimal_mul_observed(&rhs, &mut |step| observe_work(vm, step)),
            };
            if let Some(result) = resolve_observed(vm, mode, result)? {
                let quantity = Quantity::from_canonical_numeric(result).map_err(|error| {
                    if number == syscalls::SYSCALL_QUANTITY_SUB
                        && error == NumericOperationError::NegativeQuantity
                    {
                        NumericOperationError::QuantityUnderflow
                    } else {
                        error
                    }
                });
                match quantity {
                    Ok(quantity) => publish_quantity(vm, &quantity)?,
                    Err(error) => {
                        if resolve_failure::<()>(vm, mode, Err(error))?.is_none() {
                            return Ok(0);
                        }
                    }
                }
            }
        }
        syscalls::SYSCALL_QUANTITY_DIV_DECIMAL_EXACT | syscalls::SYSCALL_QUANTITY_RATIO_EXACT => {
            let lhs = decode_quantity_register(vm, 10)?;
            let rhs = if number == syscalls::SYSCALL_QUANTITY_RATIO_EXACT {
                decode_quantity_register(vm, 11)?.into_numeric()
            } else {
                decode_decimal_register(vm, 11)?
            };
            let mode = failure_mode(vm, &[12, 13])?;
            let result = decimal_exact_division_observed(vm, lhs.as_numeric(), &rhs);
            if let Some(result) = resolve_observed(vm, mode, result)? {
                if number == syscalls::SYSCALL_QUANTITY_RATIO_EXACT {
                    publish_decimal(vm, &result)?;
                } else {
                    match Quantity::from_canonical_numeric(result) {
                        Ok(quantity) => publish_quantity(vm, &quantity)?,
                        Err(error) => {
                            if resolve_failure::<()>(vm, mode, Err(error))?.is_none() {
                                return Ok(0);
                            }
                        }
                    }
                }
            }
        }
        syscalls::SYSCALL_QUANTITY_DIV_DECIMAL_ROUND | syscalls::SYSCALL_QUANTITY_RATIO_ROUND => {
            let lhs = decode_quantity_register(vm, 10)?;
            let rhs = if number == syscalls::SYSCALL_QUANTITY_RATIO_ROUND {
                decode_quantity_register(vm, 11)?.into_numeric()
            } else {
                decode_decimal_register(vm, 11)?
            };
            let decoded_scale = decode_scale(vm)?;
            let rounding = rounding_mode(vm)?;
            let mode = failure_mode(vm, &[])?;
            let scale = match resolve_failure(vm, mode, decoded_scale)? {
                Some(scale) => scale,
                None => return Ok(0),
            };
            let result = lhs.as_numeric().try_decimal_div_round_observed(
                &rhs,
                scale,
                rounding,
                &mut |step| observe_work(vm, step),
            );
            if let Some(result) = resolve_observed(vm, mode, result)? {
                if number == syscalls::SYSCALL_QUANTITY_RATIO_ROUND {
                    publish_decimal(vm, &result)?;
                } else {
                    match Quantity::from_canonical_numeric(result) {
                        Ok(quantity) => publish_quantity(vm, &quantity)?,
                        Err(error) => {
                            if resolve_failure::<()>(vm, mode, Err(error))?.is_none() {
                                return Ok(0);
                            }
                        }
                    }
                }
            }
        }
        syscalls::SYSCALL_QUANTITY_EQ
        | syscalls::SYSCALL_QUANTITY_NE
        | syscalls::SYSCALL_QUANTITY_LT
        | syscalls::SYSCALL_QUANTITY_LE
        | syscalls::SYSCALL_QUANTITY_GT
        | syscalls::SYSCALL_QUANTITY_GE => {
            let lhs = decode_quantity_register(vm, 10)?;
            let rhs = decode_quantity_register(vm, 11)?;
            charge_decimal_comparison(vm, lhs.as_numeric(), rhs.as_numeric())?;
            publish_bool(vm, comparison(number, lhs.cmp(&rhs)));
        }
        _ => return Err(VMError::UnknownSyscall(number)),
    }
    Ok(0)
}
fn comparison(number: u32, ordering: Ordering) -> bool {
    match number {
        syscalls::SYSCALL_INT_EQ | syscalls::SYSCALL_DECIMAL_EQ | syscalls::SYSCALL_QUANTITY_EQ => {
            ordering == Ordering::Equal
        }
        syscalls::SYSCALL_INT_NE | syscalls::SYSCALL_DECIMAL_NE | syscalls::SYSCALL_QUANTITY_NE => {
            ordering != Ordering::Equal
        }
        syscalls::SYSCALL_INT_LT | syscalls::SYSCALL_DECIMAL_LT | syscalls::SYSCALL_QUANTITY_LT => {
            ordering == Ordering::Less
        }
        syscalls::SYSCALL_INT_LE | syscalls::SYSCALL_DECIMAL_LE | syscalls::SYSCALL_QUANTITY_LE => {
            ordering != Ordering::Greater
        }
        syscalls::SYSCALL_INT_GT | syscalls::SYSCALL_DECIMAL_GT | syscalls::SYSCALL_QUANTITY_GT => {
            ordering == Ordering::Greater
        }
        syscalls::SYSCALL_INT_GE | syscalls::SYSCALL_DECIMAL_GE | syscalls::SYSCALL_QUANTITY_GE => {
            ordering != Ordering::Less
        }
        _ => unreachable!("comparison helper called for non-comparison syscall"),
    }
}
