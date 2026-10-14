//! Fuzzing for numeric frames, arithmetic, and staged syscall gas.

#![no_main]
use iroha_primitives::{
    bigint::BigInt,
    numeric::{Numeric, NumericOperationError, Quantity, RoundingMode},
    numeric_abi::{DecimalValueV1, IntValueV1, QuantityValueV1},
};
use ivm::{
    IVM, ProgramMetadata, VMError, encoding,
    host::DefaultHost,
    numeric::NUMERIC_FAILURE_TRAP,
    numeric_tlv::{self, MAX_QUANTITY_ENVELOPE_BYTES_V1},
    syscall_metering::SyscallCompletion,
    syscalls,
};
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let Some((&mode, payload)) = data.split_first() else {
        return;
    };
    match mode {
        b'I' => fuzz_valid_int(payload),
        b'D' => fuzz_valid_decimal(payload),
        b'Q' => fuzz_valid_quantity(payload),
        b'A' => fuzz_decimal_arithmetic(payload),
        b'G' => fuzz_staged_out_of_gas(payload),
        _ => match mode % 9 {
            0 => fuzz_envelope(payload),
            1 => fuzz_int_frame(payload),
            2 => fuzz_decimal_frame(payload),
            3 => fuzz_quantity_frame(payload),
            4 => fuzz_valid_int(payload),
            5 => fuzz_valid_decimal(payload),
            6 => fuzz_valid_quantity(payload),
            7 => fuzz_decimal_arithmetic(payload),
            8 => fuzz_staged_out_of_gas(payload),
            _ => unreachable!("modulo nine is exhaustive"),
        },
    }
});
fn fuzz_envelope(envelope: &[u8]) {
    // Feed the complete attacker-controlled slice. Truncating it at the
    // largest valid envelope size would turn an oversized/trailing-data input
    // into a different potentially valid message and leave the rejection path
    // unfuzzed.
    if envelope.len() > MAX_QUANTITY_ENVELOPE_BYTES_V1 {
        assert!(numeric_tlv::decode_int_bytes(envelope).is_err());
        assert!(numeric_tlv::decode_decimal_bytes(envelope).is_err());
        assert!(numeric_tlv::decode_quantity_bytes(envelope).is_err());
        return;
    }
    if let Ok(value) = numeric_tlv::decode_int_bytes(envelope) {
        let canonical =
            ivm_abi::numeric_tlv::encode_int(&value).expect("decoded int must re-encode");
        assert_eq!(canonical, envelope);
        assert_eq!(
            (numeric_tlv::decode_int_bytes(&canonical))
                .expect("expected successful fixture result"),
            value
        );
    }
    if let Ok(value) = numeric_tlv::decode_decimal_bytes(envelope) {
        let canonical =
            ivm_abi::numeric_tlv::encode_decimal(&value).expect("decoded decimal must re-encode");
        assert_eq!(canonical, envelope);
        assert_eq!(
            (numeric_tlv::decode_decimal_bytes(&canonical))
                .expect("expected successful fixture result"),
            value
        );
    }
    if let Ok(value) = numeric_tlv::decode_quantity_bytes(envelope) {
        let canonical =
            ivm_abi::numeric_tlv::encode_quantity(&value).expect("decoded quantity must re-encode");
        assert_eq!(canonical, envelope);
        assert_eq!(
            (numeric_tlv::decode_quantity_bytes(&canonical))
                .expect("expected successful fixture result"),
            value
        );
    }
}
fn fuzz_int_frame(frame: &[u8]) {
    if let Ok(value) = IntValueV1::decode_frame(frame) {
        assert_eq!(
            value.encode_frame().expect("decoded int must re-encode"),
            frame
        );
    }
}
fn fuzz_decimal_frame(frame: &[u8]) {
    if let Ok(value) = DecimalValueV1::decode_frame(frame) {
        assert_eq!(
            value
                .encode_frame()
                .expect("decoded decimal must re-encode"),
            frame
        );
    }
}
fn fuzz_quantity_frame(frame: &[u8]) {
    if let Ok(value) = QuantityValueV1::decode_frame(frame) {
        assert_eq!(
            value
                .encode_frame()
                .expect("decoded quantity must re-encode"),
            frame
        );
    }
}
fn bounded_mantissa(payload: &[u8]) -> BigInt {
    // Every 64-byte two's-complement value is inside the signed 512-bit
    // language domain, including both endpoints and every logical limb width.
    BigInt::from_twos_bytes(&payload[..payload.len().min(64)])
        .expect("the bounded byte slice always fits the primitive bigint")
}
fn fuzz_valid_int(payload: &[u8]) {
    let value = bounded_mantissa(payload);
    let frame = IntValueV1::try_new(value.clone())
        .expect("bounded mantissa is a V1 int")
        .encode_frame()
        .expect("valid int frame encodes");
    assert_eq!(
        (IntValueV1::decode_frame(&frame).map(IntValueV1::into_int))
            .expect("expected successful fixture result"),
        value.clone()
    );
    let envelope = ivm_abi::numeric_tlv::encode_int(&value).expect("valid int envelope encodes");
    assert_eq!(
        (numeric_tlv::decode_int_bytes(&envelope)).expect("expected successful fixture result"),
        value
    );
    exercise_envelope_corruptions(&envelope);
}
fn valid_decimal(payload: &[u8]) -> Numeric {
    let scale = payload.first().map_or(0, |byte| u32::from(*byte % 29));
    Numeric::try_new(
        bounded_mantissa(payload.get(1..).unwrap_or_default()),
        scale,
    )
    .expect("bounded mantissa and scale form a decimal")
    .canonicalize_decimal()
    .expect("bounded decimal canonicalizes")
}
fn fuzz_valid_decimal(payload: &[u8]) {
    let value = valid_decimal(payload);
    let frame = DecimalValueV1::from_canonical_numeric(value.clone())
        .expect("derived decimal is canonical")
        .encode_frame()
        .expect("valid decimal frame encodes");
    assert_eq!(
        (DecimalValueV1::decode_frame(&frame).map(DecimalValueV1::into_numeric))
            .expect("expected successful fixture result"),
        value.clone()
    );
    let envelope =
        ivm_abi::numeric_tlv::encode_decimal(&value).expect("valid decimal envelope encodes");
    assert_eq!(
        (numeric_tlv::decode_decimal_bytes(&envelope)).expect("expected successful fixture result"),
        value
    );
    exercise_envelope_corruptions(&envelope);
}
fn valid_quantity(payload: &[u8]) -> Quantity {
    let decimal = valid_decimal(payload);
    let non_negative = if decimal.mantissa().is_negative() {
        // The absolute value of the signed minimum is not representable. Map
        // that single input to zero so this structured-valid branch remains
        // total; malformed/end-point rejection is exercised by the raw paths.
        Numeric::try_new(
            decimal
                .mantissa()
                .checked_abs()
                .unwrap_or_else(|_| BigInt::zero()),
            decimal.scale(),
        )
        .expect("absolute mantissa retains the valid scale")
        .canonicalize_decimal()
        .expect("absolute decimal canonicalizes")
    } else {
        decimal
    };
    Quantity::from_canonical_numeric(non_negative)
        .expect("non-negative canonical decimal is a quantity")
}
fn fuzz_valid_quantity(payload: &[u8]) {
    let value = valid_quantity(payload);
    let frame = QuantityValueV1::new(value.clone())
        .encode_frame()
        .expect("valid quantity frame encodes");
    assert_eq!(
        (QuantityValueV1::decode_frame(&frame).map(QuantityValueV1::into_quantity))
            .expect("expected successful fixture result"),
        value.clone()
    );
    let envelope =
        ivm_abi::numeric_tlv::encode_quantity(&value).expect("valid quantity envelope encodes");
    assert_eq!(
        (numeric_tlv::decode_quantity_bytes(&envelope))
            .expect("expected successful fixture result"),
        value
    );
    exercise_envelope_corruptions(&envelope);
}
fn exercise_envelope_corruptions(envelope: &[u8]) {
    let mut truncated = envelope.to_vec();
    truncated.pop();
    fuzz_envelope(&truncated);
    let mut trailing = envelope.to_vec();
    trailing.push(0xa5);
    fuzz_envelope(&trailing);
    let mut oversized = envelope.to_vec();
    oversized[3..7].copy_from_slice(&u32::MAX.to_be_bytes());
    fuzz_envelope(&oversized);
    let mut wrong_version = envelope.to_vec();
    wrong_version[2] = wrong_version[2].wrapping_add(1);
    fuzz_envelope(&wrong_version);
    let mut corrupted_payload = envelope.to_vec();
    let payload_index = 7 + (envelope.len().saturating_sub(39) / 2);
    corrupted_payload[payload_index] ^= 0x80;
    fuzz_envelope(&corrupted_payload);
}
fn split_payload(payload: &[u8]) -> (&[u8], &[u8]) {
    let Some((&selector, remaining)) = payload.split_first() else {
        return (&[], &[]);
    };
    let split = usize::from(selector) % (remaining.len() + 1);
    remaining.split_at(split)
}
fn fuzz_decimal_arithmetic(payload: &[u8]) {
    let (lhs_payload, rhs_payload) = split_payload(payload);
    let lhs = valid_decimal(lhs_payload);
    let rhs = valid_decimal(rhs_payload);
    assert_eq!(
        lhs.try_decimal_add(&rhs),
        rhs.try_decimal_add(&lhs),
        "decimal addition must be commutative, including failure classification"
    );
    assert_eq!(
        lhs.try_decimal_mul(&rhs),
        rhs.try_decimal_mul(&lhs),
        "decimal multiplication must be commutative, including failure classification"
    );
    if let Ok(sum) = lhs.try_decimal_add(&rhs) {
        assert_eq!(
            (sum.try_decimal_sub(&rhs)).expect("expected successful fixture result"),
            lhs.clone()
        );
        assert_eq!(
            (sum.try_decimal_sub(&lhs)).expect("expected successful fixture result"),
            rhs.clone()
        );
    }
    if rhs.is_zero() {
        assert_eq!(
            lhs.try_decimal_div_exact(&rhs),
            Err(NumericOperationError::DivisionByZero)
        );
    } else if let Ok(quotient) = lhs.try_decimal_div_exact(&rhs) {
        assert_eq!(
            (quotient.try_decimal_mul(&rhs)).expect("expected successful fixture result"),
            lhs.clone()
        );
    }
    let output_scale = payload.first().map_or(0, |byte| u32::from(*byte % 29));
    let rounding_modes = [
        RoundingMode::TowardZero,
        RoundingMode::AwayFromZero,
        RoundingMode::Floor,
        RoundingMode::Ceil,
        RoundingMode::NearestEven,
        RoundingMode::NearestAway,
        RoundingMode::NearestTowardZero,
    ];
    let mode = rounding_modes[payload.get(1).map_or(0, |byte| usize::from(*byte) % 7)];
    if !rhs.is_zero()
        && let Ok(rounded) = lhs.try_decimal_div_round(&rhs, output_scale, mode)
    {
        assert!(rounded.scale() <= output_scale);
        assert_eq!(
            rounded
                .clone()
                .canonicalize_decimal()
                .expect("expected successful fixture result"),
            rounded
        );
    }
    if let Ok(quantized) = lhs.try_quantize(output_scale, mode) {
        assert!(quantized.scale() <= output_scale.min(lhs.scale()));
        assert_eq!(
            quantized
                .clone()
                .canonicalize_decimal()
                .expect("expected successful fixture result"),
            quantized
        );
    }
    let lhs_quantity = valid_quantity(lhs_payload);
    let rhs_quantity = valid_quantity(rhs_payload);
    assert_eq!(
        lhs_quantity.try_add(&rhs_quantity),
        rhs_quantity.try_add(&lhs_quantity)
    );
    if let Ok(sum) = lhs_quantity.try_add(&rhs_quantity) {
        assert_eq!(
            (sum.try_sub(&rhs_quantity)).expect("expected successful fixture result"),
            lhs_quantity
        );
    }
}
fn numeric_program(syscall: u32) -> Vec<u8> {
    let mut program = ProgramMetadata::default_for(1, 1, 1).encode();
    program.extend_from_slice(&encoding::wide::encode_syscallx(syscall).to_le_bytes());
    program.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());
    program
}
fn wrapping_add_vm(lhs: &BigInt, rhs: &BigInt, gas: u64) -> (IVM, u64) {
    let syscall = syscalls::SYSCALL_INT_WRAP_ADD;
    let mut vm = IVM::new(gas);
    vm.load_program(&numeric_program(syscall))
        .expect("load numeric fuzz program");
    vm.set_host(DefaultHost::new());
    let lhs_pointer = vm
        .alloc_host_tlv(&ivm_abi::numeric_tlv::encode_int(lhs).expect("encode lhs"))
        .expect("install lhs");
    let rhs_pointer = vm
        .alloc_host_tlv(&ivm_abi::numeric_tlv::encode_int(rhs).expect("encode rhs"))
        .expect("install rhs");
    vm.set_register(10, lhs_pointer);
    vm.set_register(11, rhs_pointer);
    vm.set_register(14, NUMERIC_FAILURE_TRAP);
    (vm, lhs_pointer)
}
fn result_int(vm: &IVM) -> BigInt {
    IntValueV1::decode_frame(
        vm.validate_tlv(vm.register(10))
            .expect("successful numeric result TLV")
            .payload,
    )
    .expect("successful numeric result frame")
    .into_int()
}
fn fuzz_staged_out_of_gas(payload: &[u8]) {
    let (lhs_payload, rhs_payload) = split_payload(payload);
    let lhs = bounded_mantissa(lhs_payload);
    let rhs = bounded_mantissa(rhs_payload);
    let (mut baseline, _) = wrapping_add_vm(&lhs, &rhs, u64::MAX);
    baseline.run().expect("wrapping addition is total");
    let baseline_used = u64::MAX - baseline.remaining_gas();
    let baseline_result = result_int(&baseline);
    let mut budget_bytes = [0_u8; 8];
    let copied = payload.len().min(budget_bytes.len());
    budget_bytes[..copied].copy_from_slice(&payload[..copied]);
    let modulus = baseline_used
        .checked_add(2)
        .expect("a bounded numeric call cannot consume u64::MAX gas");
    let budget = u64::from_le_bytes(budget_bytes) % modulus;
    let (mut candidate, original_result_pointer) = wrapping_add_vm(&lhs, &rhs, budget);
    let outcome = candidate.run();
    let consumed = budget - candidate.remaining_gas();
    if budget >= baseline_used {
        assert!(matches!(outcome, Ok(())));
        assert_eq!(consumed, baseline_used);
        assert_eq!(result_int(&candidate), baseline_result);
        return;
    }
    match outcome {
        Err(VMError::SyscallOutOfGas { syscall, .. }) => {
            assert_eq!(syscall, syscalls::SYSCALL_INT_WRAP_ADD);
            assert_eq!(candidate.register(10), original_result_pointer);
            assert_eq!(
                candidate
                    .last_staged_syscall_context()
                    .expect("staged OOG records its context")
                    .completion(),
                Some(SyscallCompletion::Trap)
            );
        }
        Err(VMError::OutOfGas) => {
            // Plain instruction OOG may occur before the syscall or at HALT
            // after a completed atomic syscall. It must expose either the
            // untouched input pointer or the complete canonical result.
            if candidate.register(10) != original_result_pointer {
                assert_eq!(result_int(&candidate), baseline_result);
            }
        }
        Err(error) => panic!("insufficient gas produced a non-OOG failure: {error}"),
        Ok(()) => panic!("budget {budget} below exact cost {baseline_used} succeeded"),
    }
}
