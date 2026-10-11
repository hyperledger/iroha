//! Consensus and adversarial coverage for the Kotodama V1 numeric syscall ABI.
use iroha_primitives::{
    bigint::BigInt,
    numeric::{Numeric, Quantity},
    numeric_abi::{DecimalValueV1, IntValueV1, QuantityValueV1},
};
use ivm::{
    IVM, Memory, ProgramMetadata, VMError, encoding,
    host::{DefaultHost, IVMHost},
    ivm_mode,
    numeric::{
        NUMERIC_FAILURE_STATUS, NUMERIC_FAILURE_TRAP, NumericFaultV1, PointerAbiFaultV1,
        RoundingModeV1,
    },
    numeric_gas::SuccessfulCallGas,
    syscall_metering::{SyscallCompletion, SyscallMetering, SyscallMeteringPhase},
    syscalls,
};
use std::collections::{BTreeMap, BTreeSet};
fn program(syscall: u32) -> Vec<u8> {
    let mut program = ProgramMetadata::default_for(1, 1, 1).encode();
    program.extend_from_slice(&encoding::wide::encode_syscallx(syscall).to_le_bytes());
    program.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());
    program
}
fn vm_for(syscall: u32, gas: u64) -> IVM {
    let mut vm = IVM::new(gas);
    vm.load_program(&program(syscall))
        .expect("load numeric program");
    vm.set_host(DefaultHost::new());
    vm
}
fn zk_vm_for(syscall: u32, gas: u64) -> IVM {
    let mut metadata = ProgramMetadata::default_for(1, 1, 1);
    metadata.mode = ivm_mode::ZK;
    let mut program = metadata.encode();
    program.extend_from_slice(&encoding::wide::encode_syscallx(syscall).to_le_bytes());
    program.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());
    let mut vm = IVM::new(gas);
    vm.load_program(&program).expect("load ZK numeric program");
    vm.set_host(DefaultHost::new());
    vm
}
fn install_int(vm: &mut IVM, value: &BigInt) -> u64 {
    let envelope = ivm_abi::numeric_tlv::encode_int(value).expect("encode int envelope");
    vm.alloc_host_tlv(&envelope).expect("install int")
}
fn install_decimal(vm: &mut IVM, value: &Numeric) -> u64 {
    let envelope = ivm_abi::numeric_tlv::encode_decimal(value).expect("encode decimal envelope");
    vm.alloc_host_tlv(&envelope).expect("install decimal")
}
fn install_quantity(vm: &mut IVM, value: &Quantity) -> u64 {
    let envelope = ivm_abi::numeric_tlv::encode_quantity(value).expect("encode quantity envelope");
    vm.alloc_host_tlv(&envelope).expect("install quantity")
}
fn numeric_envelope_from_frame(pointer_type: ivm::PointerType, frame: &[u8]) -> Vec<u8> {
    let mut envelope = Vec::with_capacity(7 + frame.len() + iroha_crypto::Hash::LENGTH);
    envelope.extend_from_slice(&(pointer_type as u16).to_be_bytes());
    envelope.push(1);
    envelope.extend_from_slice(
        &u32::try_from(frame.len())
            .expect("bounded numeric frame")
            .to_be_bytes(),
    );
    envelope.extend_from_slice(frame);
    envelope.extend_from_slice(iroha_crypto::Hash::new(frame).as_ref());
    envelope
}
fn result_int(vm: &IVM) -> BigInt {
    IntValueV1::decode_frame(
        vm.validate_tlv(vm.register(10))
            .expect("result int TLV")
            .payload,
    )
    .expect("result int frame")
    .into_int()
}
fn result_decimal(vm: &IVM) -> Numeric {
    DecimalValueV1::decode_frame(
        vm.validate_tlv(vm.register(10))
            .expect("result decimal TLV")
            .payload,
    )
    .expect("result decimal frame")
    .into_numeric()
}
fn result_quantity(vm: &IVM) -> Quantity {
    QuantityValueV1::decode_frame(
        vm.validate_tlv(vm.register(10))
            .expect("result quantity TLV")
            .payload,
    )
    .expect("result quantity frame")
    .into_quantity()
}
fn run_int_binary(syscall: u32, lhs: i128, rhs: i128) -> IVM {
    let mut vm = vm_for(syscall, u64::MAX);
    let lhs = install_int(&mut vm, &BigInt::from_i128(lhs));
    let rhs = install_int(&mut vm, &BigInt::from_i128(rhs));
    vm.set_register(10, lhs);
    vm.set_register(11, rhs);
    vm.set_register(14, NUMERIC_FAILURE_TRAP);
    vm.run().expect("execute int binary syscall");
    vm
}
fn run_decimal_binary(syscall: u32, lhs: &str, rhs: &str) -> IVM {
    let mut vm = vm_for(syscall, u64::MAX);
    let lhs = install_decimal(&mut vm, &lhs.parse().expect("lhs decimal"));
    let rhs = install_decimal(&mut vm, &rhs.parse().expect("rhs decimal"));
    vm.set_register(10, lhs);
    vm.set_register(11, rhs);
    vm.set_register(14, NUMERIC_FAILURE_TRAP);
    vm.run().expect("execute decimal binary syscall");
    vm
}
fn run_quantity_binary(syscall: u32, lhs: &str, rhs: &str) -> IVM {
    let mut vm = vm_for(syscall, u64::MAX);
    let lhs = install_quantity(&mut vm, &lhs.parse().expect("lhs quantity"));
    let rhs = install_quantity(&mut vm, &rhs.parse().expect("rhs quantity"));
    vm.set_register(10, lhs);
    vm.set_register(11, rhs);
    vm.set_register(14, NUMERIC_FAILURE_TRAP);
    vm.run().expect("execute quantity binary syscall");
    vm
}
fn max_int() -> BigInt {
    let mut bytes = vec![0xff; iroha_primitives::numeric::MAX_MANTISSA_BYTES];
    bytes[iroha_primitives::numeric::MAX_MANTISSA_BYTES - 1] = 0x7f;
    BigInt::from_twos_bytes(&bytes).expect("maximum int")
}
fn min_int() -> BigInt {
    let mut bytes = vec![0; iroha_primitives::numeric::MAX_MANTISSA_BYTES];
    bytes[iroha_primitives::numeric::MAX_MANTISSA_BYTES - 1] = 0x80;
    BigInt::from_twos_bytes(&bytes).expect("minimum int")
}
fn positive_int_with_limbs(limbs: usize) -> BigInt {
    let mut bytes = vec![0_u8; limbs * 8];
    bytes[0] = 1;
    *bytes.last_mut().expect("positive limb count") = 0x3f;
    BigInt::from_twos_bytes(&bytes).expect("bounded limb fixture")
}
fn envelope_len(vm: &IVM, pointer: u64) -> u64 {
    let payload = vm.validate_tlv(pointer).expect("numeric TLV").payload.len();
    u64::try_from(payload + 39).expect("bounded envelope")
}
fn frame_len_for_envelope(envelope_bytes: u64) -> u64 {
    envelope_bytes
        .checked_sub(39)
        .expect("numeric envelope includes fixed overhead")
}
fn output_length_work(value: &BigInt) -> u64 {
    let magnitude_bits = u64::try_from(value.bit_len()).expect("bounded bit width");
    ivm::numeric_gas::limbs_for_bits(magnitude_bits + 1)
}
fn validation_work_for_envelope(bytes: u64) -> u64 {
    let frame_bytes = bytes.checked_sub(39).expect("numeric envelope overhead");
    ivm::numeric_gas::numeric_frame_validation_work(
        usize::try_from(frame_bytes).expect("bounded frame length"),
    )
    .expect("bounded validation work")
}
fn decimal_validation_work_for_envelope(bytes: u64, value: &Numeric) -> u64 {
    let mut work = validation_work_for_envelope(bytes);
    if value.scale() > 0 {
        let limbs = u64::try_from(value.mantissa().bit_len())
            .expect("bounded bit width")
            .max(1)
            .div_ceil(64);
        work +=
            ivm::numeric_gas::quotient_remainder_work(limbs, 1).expect("bounded canonicality work");
    }
    work
}
fn collect_oog_prefixes<F>(syscall: u32, setup: F) -> BTreeMap<u8, BTreeSet<u64>>
where
    F: Fn(&mut IVM),
{
    #[derive(Clone, Copy, Debug)]
    enum Probe {
        Success,
        OutOfGas { phase: u8, charged: u64 },
    }
    let mut probe_vm = vm_for(syscall, u64::MAX);
    setup(&mut probe_vm);
    // Every budget must observe the same initialized operands and pristine
    // result state. A runtime template provides that isolation while avoiding
    // a full VM construction, program decode, and operand installation for
    // every boundary probe.
    let template = probe_vm
        .try_runtime_template()
        .expect("runtime template allocation fits test host");
    probe_vm.run().expect("baseline staged operation");
    let staged = probe_vm
        .last_staged_syscall_context()
        .expect("baseline staged context")
        .charged();
    let instruction = ivm::cost_of(encoding::wide::encode_syscallx(syscall)).expect("SCALLX gas");
    let maximum_budget = instruction
        .checked_add(staged)
        .expect("bounded staged test budget");
    let mut probe = |gas: u64| {
        probe_vm
            .reset_from_runtime_template(&template)
            .expect("numeric probe template geometry must match");
        probe_vm.set_gas_limit(gas);
        let original_result_register = probe_vm.register(10);
        match probe_vm.run() {
            Ok(()) => Probe::Success,
            Err(VMError::SyscallOutOfGas {
                syscall: failed,
                phase,
            }) => {
                assert_eq!(failed, syscall);
                assert_eq!(probe_vm.register(10), original_result_register);
                let context = probe_vm
                    .last_staged_syscall_context()
                    .expect("failed staged context");
                assert_eq!(context.completion(), Some(SyscallCompletion::Trap));
                assert_eq!(
                    gas - probe_vm.remaining_gas(),
                    instruction + context.charged(),
                    "only completed phases consume gas",
                );
                Probe::OutOfGas {
                    phase,
                    charged: context.charged(),
                }
            }
            Err(error) => panic!("unexpected staged probe failure at gas {gas}: {error}"),
        }
    };
    // The completed-charge prefix is a monotonic step function of the gas
    // budget. Discover every step boundary with binary search instead of
    // executing once for every individual gas unit; each discovered OOG
    // prefix still undergoes the full atomicity and accounting assertions
    // above. This keeps the exhaustive repeated-stage contract practical in
    // the mandatory workspace suite even when an operation costs many limbs.
    let mut prefixes = BTreeMap::<u8, BTreeSet<u64>>::new();
    let mut budget = instruction;
    loop {
        let Probe::OutOfGas { phase, charged } = probe(budget) else {
            break;
        };
        prefixes.entry(phase).or_default().insert(charged);
        let mut low = budget.checked_add(1).expect("bounded staged probe budget");
        let mut high = maximum_budget;
        while low < high {
            let middle = low + (high - low) / 2;
            let progressed = match probe(middle) {
                Probe::Success => true,
                Probe::OutOfGas {
                    charged: candidate, ..
                } => {
                    assert!(
                        candidate >= charged,
                        "completed staged charge must be monotonic in available gas",
                    );
                    candidate > charged
                }
            };
            if progressed {
                high = middle;
            } else {
                low = middle + 1;
            }
        }
        assert!(low <= maximum_budget);
        budget = low;
    }
    assert!(matches!(probe(maximum_budget), Probe::Success));
    prefixes
}
#[test]
fn abi_contains_exactly_the_61_numeric_calls_and_rejects_retired_numbers() {
    let numbers = (0x01_0100..=0x01_011A)
        .chain(0x01_0120..=0x01_0130)
        .chain(0x01_0140..=0x01_0150)
        .collect::<Vec<_>>();
    assert_eq!(numbers.len(), 61);
    let vm = IVM::new(u64::MAX);
    let host = DefaultHost::new();
    for number in numbers {
        assert!(syscalls::is_numeric_v1_syscall(number));
        let metering = ivm::host::host_syscall_metering_spec(vm.syscall_policy(), number)
            .expect("numeric metering registration");
        assert_eq!(metering.metering, SyscallMetering::Staged);
        assert_eq!(host.prepare_syscall(number, &vm), Ok(0));
    }
    for retired in (0x69..=0x76)
        .chain(0xd2..=0xde)
        .chain(0x01_0040..=0x01_004d)
    {
        assert_eq!(
            host.prepare_syscall(retired, &vm),
            Err(VMError::UnknownSyscall(retired))
        );
    }
}
#[test]
fn every_shipping_numeric_syscall_executes_with_a_semantic_assertion() {
    let expected = (0x01_0100..=0x01_011A)
        .chain(0x01_0120..=0x01_0130)
        .chain(0x01_0140..=0x01_0150)
        .collect::<BTreeSet<_>>();
    let mut covered = BTreeSet::new();
    for (syscall, raw, expected) in [
        (syscalls::SYSCALL_INT_FROM_I64, (-7_i64) as u64, -7_i128),
        (syscalls::SYSCALL_INT_FROM_U64, 7_u64, 7_i128),
    ] {
        let mut vm = vm_for(syscall, u64::MAX);
        vm.set_register(10, raw);
        vm.run().expect("construct int");
        assert_eq!(result_int(&vm), BigInt::from_i128(expected));
        covered.insert(syscall);
    }
    for (syscall, input, expected) in [
        (syscalls::SYSCALL_INT_ISQRT, 17_i128, 4_i128),
        (syscalls::SYSCALL_INT_ABS, -7, 7),
    ] {
        let mut vm = vm_for(syscall, u64::MAX);
        let input = install_int(&mut vm, &BigInt::from_i128(input));
        vm.set_register(10, input);
        vm.run().expect("execute integer helper");
        assert_eq!(result_int(&vm), BigInt::from_i128(expected));
        covered.insert(syscall);
    }
    for (syscall, left, right, expected) in [
        (syscalls::SYSCALL_INT_MIN, -7, 3, -7),
        (syscalls::SYSCALL_INT_MAX, -7, 3, 3),
        (syscalls::SYSCALL_INT_DIV_CEIL, -7, 3, -2),
        (syscalls::SYSCALL_INT_GCD, -12, 8, 4),
        (syscalls::SYSCALL_INT_MEAN, -7, 2, -2),
    ] {
        let vm = run_int_binary(syscall, left, right);
        assert_eq!(result_int(&vm), BigInt::from_i128(expected));
        covered.insert(syscall);
    }
    for (syscall, input, expected) in [
        (syscalls::SYSCALL_INT_TO_I64, -7_i128, (-7_i64) as u64),
        (syscalls::SYSCALL_INT_TO_U64, 7_i128, 7_u64),
    ] {
        let mut vm = vm_for(syscall, u64::MAX);
        let input = install_int(&mut vm, &BigInt::from_i128(input));
        vm.set_register(10, input);
        vm.run().expect("convert int");
        assert_eq!(vm.register(10), expected);
        assert_eq!(vm.register(11), 0);
        covered.insert(syscall);
    }
    for (syscall, expected) in [
        (syscalls::SYSCALL_INT_NEG, -5_i128),
        (syscalls::SYSCALL_INT_WRAP_NEG, -5_i128),
    ] {
        let mut vm = vm_for(syscall, u64::MAX);
        let input = install_int(&mut vm, &BigInt::from_i128(5));
        vm.set_register(10, input);
        vm.set_register(14, NUMERIC_FAILURE_TRAP);
        vm.run().expect("negate int");
        assert_eq!(result_int(&vm), BigInt::from_i128(expected));
        covered.insert(syscall);
    }
    for (syscall, lhs, rhs, expected) in [
        (syscalls::SYSCALL_INT_ADD, 7, 3, 10),
        (syscalls::SYSCALL_INT_SUB, 7, 3, 4),
        (syscalls::SYSCALL_INT_MUL, 7, 3, 21),
        (syscalls::SYSCALL_INT_DIV, 7, 3, 2),
        (syscalls::SYSCALL_INT_REM, 7, 3, 1),
        (syscalls::SYSCALL_INT_WRAP_ADD, 7, 3, 10),
        (syscalls::SYSCALL_INT_WRAP_SUB, 7, 3, 4),
        (syscalls::SYSCALL_INT_WRAP_MUL, 7, 3, 21),
    ] {
        let vm = run_int_binary(syscall, lhs, rhs);
        assert_eq!(result_int(&vm), BigInt::from_i128(expected));
        covered.insert(syscall);
    }
    let comparison_expectations = [false, true, true, true, false, false];
    for (syscall, expected_value) in [
        syscalls::SYSCALL_INT_EQ,
        syscalls::SYSCALL_INT_NE,
        syscalls::SYSCALL_INT_LT,
        syscalls::SYSCALL_INT_LE,
        syscalls::SYSCALL_INT_GT,
        syscalls::SYSCALL_INT_GE,
    ]
    .into_iter()
    .zip(comparison_expectations)
    {
        let vm = run_int_binary(syscall, 1, 2);
        assert_eq!(vm.register(10), u64::from(expected_value));
        covered.insert(syscall);
    }
    let mut from_int = vm_for(syscalls::SYSCALL_DECIMAL_FROM_INT, u64::MAX);
    let integer = install_int(&mut from_int, &BigInt::from_i128(7));
    from_int.set_register(10, integer);
    from_int.run().expect("int to decimal");
    assert_eq!(result_decimal(&from_int).to_string(), "7");
    covered.insert(syscalls::SYSCALL_DECIMAL_FROM_INT);
    let mut decimal_neg = vm_for(syscalls::SYSCALL_DECIMAL_NEG, u64::MAX);
    let value = install_decimal(&mut decimal_neg, &"1.25".parse().expect("decimal"));
    decimal_neg.set_register(10, value);
    decimal_neg.set_register(14, NUMERIC_FAILURE_TRAP);
    decimal_neg.run().expect("decimal negation");
    assert_eq!(result_decimal(&decimal_neg).to_string(), "-1.25");
    covered.insert(syscalls::SYSCALL_DECIMAL_NEG);
    for (syscall, lhs, rhs, expected_value) in [
        (syscalls::SYSCALL_DECIMAL_ADD, "1.25", "0.5", "1.75"),
        (syscalls::SYSCALL_DECIMAL_SUB, "1.25", "0.5", "0.75"),
        (syscalls::SYSCALL_DECIMAL_MUL, "1.25", "0.4", "0.5"),
        (syscalls::SYSCALL_DECIMAL_DIV_EXACT, "6", "4", "1.5"),
    ] {
        let vm = run_decimal_binary(syscall, lhs, rhs);
        assert_eq!(result_decimal(&vm).to_string(), expected_value);
        covered.insert(syscall);
    }
    let mut decimal_round = vm_for(syscalls::SYSCALL_DECIMAL_DIV_ROUND, u64::MAX);
    let lhs = install_decimal(&mut decimal_round, &Numeric::new(1, 0));
    let rhs = install_decimal(&mut decimal_round, &Numeric::new(8, 0));
    let scale = install_int(&mut decimal_round, &BigInt::from_i128(2));
    decimal_round.set_register(10, lhs);
    decimal_round.set_register(11, rhs);
    decimal_round.set_register(12, scale);
    decimal_round.set_register(13, RoundingModeV1::NearestEven.tag());
    decimal_round.set_register(14, NUMERIC_FAILURE_TRAP);
    decimal_round.run().expect("rounded decimal division");
    assert_eq!(result_decimal(&decimal_round).to_string(), "0.12");
    covered.insert(syscalls::SYSCALL_DECIMAL_DIV_ROUND);
    for (syscall, expected_value) in [
        syscalls::SYSCALL_DECIMAL_EQ,
        syscalls::SYSCALL_DECIMAL_NE,
        syscalls::SYSCALL_DECIMAL_LT,
        syscalls::SYSCALL_DECIMAL_LE,
        syscalls::SYSCALL_DECIMAL_GT,
        syscalls::SYSCALL_DECIMAL_GE,
    ]
    .into_iter()
    .zip(comparison_expectations)
    {
        let vm = run_decimal_binary(syscall, "1", "2");
        assert_eq!(vm.register(10), u64::from(expected_value));
        covered.insert(syscall);
    }
    for (syscall, input, mode, expected_value) in [
        (syscalls::SYSCALL_DECIMAL_TO_INT_EXACT, "7", None, 7_i128),
        (syscalls::SYSCALL_DECIMAL_TO_INT_TRUNC, "7.9", None, 7_i128),
        (
            syscalls::SYSCALL_DECIMAL_TO_INT_ROUND,
            "7.5",
            Some(RoundingModeV1::NearestEven),
            8_i128,
        ),
    ] {
        let mut vm = vm_for(syscall, u64::MAX);
        let input = install_decimal(&mut vm, &input.parse().expect("conversion decimal"));
        vm.set_register(10, input);
        if let Some(mode) = mode {
            vm.set_register(13, mode.tag());
        }
        vm.run().expect("decimal to int conversion");
        assert_eq!(result_int(&vm), BigInt::from_i128(expected_value));
        covered.insert(syscall);
    }
    let mut quantity_from_int = vm_for(syscalls::SYSCALL_QUANTITY_FROM_INT, u64::MAX);
    let int = install_int(&mut quantity_from_int, &BigInt::from_i128(7));
    quantity_from_int.set_register(10, int);
    quantity_from_int.run().expect("int to quantity");
    assert_eq!(result_quantity(&quantity_from_int).to_string(), "7");
    covered.insert(syscalls::SYSCALL_QUANTITY_FROM_INT);
    let mut quantity_from_decimal = vm_for(syscalls::SYSCALL_QUANTITY_FROM_DECIMAL, u64::MAX);
    let decimal = install_decimal(
        &mut quantity_from_decimal,
        &"1.25".parse().expect("decimal"),
    );
    quantity_from_decimal.set_register(10, decimal);
    quantity_from_decimal.run().expect("decimal to quantity");
    assert_eq!(result_quantity(&quantity_from_decimal).to_string(), "1.25");
    covered.insert(syscalls::SYSCALL_QUANTITY_FROM_DECIMAL);
    let mut quantity_to_decimal = vm_for(syscalls::SYSCALL_QUANTITY_TO_DECIMAL, u64::MAX);
    let quantity = install_quantity(&mut quantity_to_decimal, &"1.25".parse().expect("quantity"));
    quantity_to_decimal.set_register(10, quantity);
    quantity_to_decimal.run().expect("quantity to decimal");
    assert_eq!(result_decimal(&quantity_to_decimal).to_string(), "1.25");
    covered.insert(syscalls::SYSCALL_QUANTITY_TO_DECIMAL);
    for (syscall, lhs, rhs, expected_value) in [
        (syscalls::SYSCALL_QUANTITY_ADD, "2", "1", "3"),
        (syscalls::SYSCALL_QUANTITY_SUB, "2", "1", "1"),
        (syscalls::SYSCALL_QUANTITY_RATIO_EXACT, "6", "4", "1.5"),
    ] {
        let vm = run_quantity_binary(syscall, lhs, rhs);
        if syscall == syscalls::SYSCALL_QUANTITY_RATIO_EXACT {
            assert_eq!(result_decimal(&vm).to_string(), expected_value);
        } else {
            assert_eq!(result_quantity(&vm).to_string(), expected_value);
        }
        covered.insert(syscall);
    }
    for (syscall, rhs, expected_value) in [
        (syscalls::SYSCALL_QUANTITY_MUL_DECIMAL, "1.5", "3"),
        (syscalls::SYSCALL_QUANTITY_DIV_DECIMAL_EXACT, "4", "0.5"),
    ] {
        let mut vm = vm_for(syscall, u64::MAX);
        let lhs = install_quantity(&mut vm, &"2".parse().expect("quantity"));
        let rhs = install_decimal(&mut vm, &rhs.parse().expect("decimal"));
        vm.set_register(10, lhs);
        vm.set_register(11, rhs);
        vm.set_register(14, NUMERIC_FAILURE_TRAP);
        vm.run().expect("quantity/decimal operation");
        assert_eq!(result_quantity(&vm).to_string(), expected_value);
        covered.insert(syscall);
    }
    for (syscall, ratio) in [
        (syscalls::SYSCALL_QUANTITY_DIV_DECIMAL_ROUND, false),
        (syscalls::SYSCALL_QUANTITY_RATIO_ROUND, true),
    ] {
        let mut vm = vm_for(syscall, u64::MAX);
        let lhs = install_quantity(&mut vm, &"1".parse().expect("quantity"));
        let rhs = if ratio {
            install_quantity(&mut vm, &"8".parse().expect("quantity"))
        } else {
            install_decimal(&mut vm, &"8".parse().expect("decimal"))
        };
        let scale = install_int(&mut vm, &BigInt::from_i128(2));
        vm.set_register(10, lhs);
        vm.set_register(11, rhs);
        vm.set_register(12, scale);
        vm.set_register(13, RoundingModeV1::NearestEven.tag());
        vm.set_register(14, NUMERIC_FAILURE_TRAP);
        vm.run().expect("rounded quantity division");
        if ratio {
            assert_eq!(result_decimal(&vm).to_string(), "0.12");
        } else {
            assert_eq!(result_quantity(&vm).to_string(), "0.12");
        }
        covered.insert(syscall);
    }
    for (syscall, expected_value) in [
        syscalls::SYSCALL_QUANTITY_EQ,
        syscalls::SYSCALL_QUANTITY_NE,
        syscalls::SYSCALL_QUANTITY_LT,
        syscalls::SYSCALL_QUANTITY_LE,
        syscalls::SYSCALL_QUANTITY_GT,
        syscalls::SYSCALL_QUANTITY_GE,
    ]
    .into_iter()
    .zip(comparison_expectations)
    {
        let vm = run_quantity_binary(syscall, "1", "2");
        assert_eq!(vm.register(10), u64::from(expected_value));
        covered.insert(syscall);
    }
    for syscall in [
        syscalls::SYSCALL_DECIMAL_MUL_DIV_ROUND,
        syscalls::SYSCALL_QUANTITY_MUL_DIV_ROUND,
    ] {
        let vm = run_fused(
            syscall,
            &"3".parse().unwrap(),
            &"2".parse().unwrap(),
            &"7".parse().unwrap(),
            2,
            RoundingModeV1::Floor,
        );
        let actual = if syscall == syscalls::SYSCALL_DECIMAL_MUL_DIV_ROUND {
            result_decimal(&vm)
        } else {
            result_quantity(&vm).into_numeric()
        };
        assert_eq!(actual.to_string(), "0.85");
        covered.insert(syscall);
    }
    assert_eq!(
        covered, expected,
        "every shipping numeric syscall must execute"
    );
}
#[test]
fn actual_staged_contexts_match_the_normative_gas_identity_and_width_boundaries() {
    let mut previous = 0;
    for limbs in 1_usize..=8 {
        let syscall = syscalls::SYSCALL_INT_ADD;
        let mut vm = vm_for(syscall, u64::MAX);
        let lhs_value = positive_int_with_limbs(limbs);
        let lhs_envelope = ivm_abi::numeric_tlv::encode_int(&lhs_value).expect("lhs envelope");
        let rhs_envelope = ivm_abi::numeric_tlv::encode_int(&BigInt::one()).expect("rhs envelope");
        let lhs = vm.alloc_host_tlv(&lhs_envelope).expect("lhs");
        let rhs = vm.alloc_host_tlv(&rhs_envelope).expect("rhs");
        vm.set_register(10, lhs);
        vm.set_register(11, rhs);
        vm.set_register(14, NUMERIC_FAILURE_TRAP);
        vm.run().expect("width-boundary addition");
        let output_value = result_int(&vm);
        let output_bytes = envelope_len(&vm, vm.register(10));
        let input_bytes = u64::try_from(lhs_envelope.len() + rhs_envelope.len()).unwrap();
        let input_hash_bytes = frame_len_for_envelope(lhs_envelope.len() as u64)
            + frame_len_for_envelope(rhs_envelope.len() as u64);
        let output_frame_bytes = frame_len_for_envelope(output_bytes);
        let validation = validation_work_for_envelope(lhs_envelope.len() as u64)
            + validation_work_for_envelope(rhs_envelope.len() as u64);
        let expected = ivm::numeric_gas::successful_call_gas(SuccessfulCallGas {
            input_envelope_bytes: input_bytes,
            input_hash_frame_bytes: input_hash_bytes,
            output_envelope_bytes: output_bytes,
            output_frame_bytes,
            output_length_limb_work: output_length_work(&output_value),
            arithmetic_limb_work: ivm::numeric_gas::checked_int_additive_work(limbs as u64, 1)
                .expect("bounded checked-add work"),
            validation_limb_work: validation,
            normalization_limb_work: 0,
        })
        .expect("bounded gas identity");
        let context = vm.last_staged_syscall_context().expect("staged context");
        assert_eq!(context.charged(), expected, "limbs={limbs}");
        assert_eq!(context.completion(), Some(SyscallCompletion::Success));
        assert!(
            context.charged() > previous,
            "each defined limb transition costs more"
        );
        previous = context.charged();
    }
    for (value, expected_output_limbs) in [
        (BigInt::from_i128(1_i128 << 63), 2_u64),
        (BigInt::from_i128(i128::from(i64::MIN)), 2_u64),
        (min_int(), 9_u64),
    ] {
        let mut vm = vm_for(syscalls::SYSCALL_INT_ADD, u64::MAX);
        let lhs = install_int(&mut vm, &value);
        let zero = install_int(&mut vm, &BigInt::zero());
        vm.set_register(10, lhs);
        vm.set_register(11, zero);
        vm.set_register(14, NUMERIC_FAILURE_TRAP);
        vm.run().expect("signed output-width addition");
        assert_eq!(result_int(&vm), value);
        assert_eq!(output_length_work(&value), expected_output_limbs);
        let output_envelope = envelope_len(&vm, vm.register(10));
        let output_frame = frame_len_for_envelope(output_envelope);
        assert_eq!(
            vm.last_staged_syscall_context()
                .expect("signed output-width context")
                .phase_charge(SyscallMeteringPhase::OutputSerialization),
            4 * expected_output_limbs + output_envelope + 2 * output_frame,
        );
    }
    let maximum = Numeric::new(max_int(), 0);
    let tiny: Numeric = "0.0000000000000000000000000001"
        .parse()
        .expect("scale-28 decimal");
    let mut compare = vm_for(syscalls::SYSCALL_DECIMAL_GT, u64::MAX);
    let lhs_envelope = ivm_abi::numeric_tlv::encode_decimal(&maximum).expect("maximum decimal");
    let rhs_envelope = ivm_abi::numeric_tlv::encode_decimal(&tiny).expect("tiny decimal");
    let lhs = compare.alloc_host_tlv(&lhs_envelope).expect("lhs");
    let rhs = compare.alloc_host_tlv(&rhs_envelope).expect("rhs");
    compare.set_register(10, lhs);
    compare.set_register(11, rhs);
    compare.run().expect("ten-limb aligned comparison");
    assert_eq!(compare.register(10), 1);
    let lhs_bits = u64::try_from(maximum.mantissa().bit_len()).unwrap();
    let rhs_bits = u64::try_from(tiny.mantissa().bit_len()).unwrap();
    let aligned_lhs = ivm::numeric_gas::scaled_limbs(lhs_bits, 28).expect("aligned lhs");
    let aligned_rhs = ivm::numeric_gas::scaled_limbs(rhs_bits, 0).expect("aligned rhs");
    assert_eq!(aligned_lhs, 10);
    let comparison_work =
        ivm::numeric_gas::aligned_work(lhs_bits, 28, aligned_lhs, rhs_bits, 0, aligned_rhs)
            .expect("comparison work");
    let validation = decimal_validation_work_for_envelope(lhs_envelope.len() as u64, &maximum)
        + decimal_validation_work_for_envelope(rhs_envelope.len() as u64, &tiny);
    let expected = ivm::numeric_gas::successful_call_gas(SuccessfulCallGas {
        input_envelope_bytes: (lhs_envelope.len() + rhs_envelope.len()) as u64,
        input_hash_frame_bytes: frame_len_for_envelope(lhs_envelope.len() as u64)
            + frame_len_for_envelope(rhs_envelope.len() as u64),
        output_envelope_bytes: 0,
        output_frame_bytes: 0,
        output_length_limb_work: 0,
        arithmetic_limb_work: comparison_work,
        validation_limb_work: validation,
        normalization_limb_work: 0,
    })
    .expect("comparison gas");
    assert_eq!(
        compare
            .last_staged_syscall_context()
            .expect("comparison context")
            .charged(),
        expected,
    );
    let zero = Numeric::zero();
    let mut zero_compare = vm_for(syscalls::SYSCALL_DECIMAL_LT, u64::MAX);
    let zero_envelope = ivm_abi::numeric_tlv::encode_decimal(&zero).expect("zero decimal");
    let tiny_envelope = ivm_abi::numeric_tlv::encode_decimal(&tiny).expect("tiny decimal");
    let zero_pointer = zero_compare
        .alloc_host_tlv(&zero_envelope)
        .expect("zero pointer");
    let tiny_pointer = zero_compare
        .alloc_host_tlv(&tiny_envelope)
        .expect("tiny pointer");
    zero_compare.set_register(10, zero_pointer);
    zero_compare.set_register(11, tiny_pointer);
    zero_compare.run().expect("zero-aligned comparison");
    assert_eq!(zero_compare.register(10), 1);
    let zero_comparison_work = ivm::numeric_gas::aligned_work(0, 28, 1, rhs_bits, 0, aligned_rhs)
        .expect("zero comparison work");
    assert_eq!(zero_comparison_work, 3);
    let zero_validation = decimal_validation_work_for_envelope(zero_envelope.len() as u64, &zero)
        + decimal_validation_work_for_envelope(tiny_envelope.len() as u64, &tiny);
    let zero_expected = ivm::numeric_gas::successful_call_gas(SuccessfulCallGas {
        input_envelope_bytes: (zero_envelope.len() + tiny_envelope.len()) as u64,
        input_hash_frame_bytes: frame_len_for_envelope(zero_envelope.len() as u64)
            + frame_len_for_envelope(tiny_envelope.len() as u64),
        output_envelope_bytes: 0,
        output_frame_bytes: 0,
        output_length_limb_work: 0,
        arithmetic_limb_work: zero_comparison_work,
        validation_limb_work: zero_validation,
        normalization_limb_work: 0,
    })
    .expect("zero comparison gas");
    assert_eq!(
        zero_compare
            .last_staged_syscall_context()
            .expect("zero comparison context")
            .charged(),
        zero_expected,
    );
    let mut product = vm_for(syscalls::SYSCALL_DECIMAL_MUL, u64::MAX);
    let lhs_envelope = ivm_abi::numeric_tlv::encode_decimal(&maximum).expect("lhs");
    let rhs_envelope = lhs_envelope.clone();
    let lhs = product.alloc_host_tlv(&lhs_envelope).expect("lhs");
    let rhs = product.alloc_host_tlv(&rhs_envelope).expect("rhs");
    product.set_register(10, lhs);
    product.set_register(11, rhs);
    product.set_register(14, NUMERIC_FAILURE_STATUS);
    product.run().expect("recoverable 16-limb product overflow");
    let product_context = product
        .last_staged_syscall_context()
        .expect("product context");
    assert_eq!(
        product_context.completion(),
        Some(SyscallCompletion::RecoverableFailure)
    );
    assert_eq!(
        product_context.phase_charge(SyscallMeteringPhase::Arithmetic),
        4 * (8 * 8 + 16),
    );
    assert_eq!(product.register(10), 0);
    for (syscall, lhs, rhs, scale) in [
        (syscalls::SYSCALL_DECIMAL_MUL, "1.25", "0.4", None),
        (syscalls::SYSCALL_DECIMAL_DIV_EXACT, "1", "40", None),
        (syscalls::SYSCALL_DECIMAL_DIV_ROUND, "1", "7", Some(28_u32)),
    ] {
        let lhs_value: Numeric = lhs.parse().expect("lhs");
        let rhs_value: Numeric = rhs.parse().expect("rhs");
        let mut observed_work = 0_u64;
        let mut observer = |step| {
            observed_work += ivm::numeric_gas::work_step_gas(step).expect("step gas") / 4;
            Ok::<_, ()>(())
        };
        match syscall {
            syscalls::SYSCALL_DECIMAL_MUL => {
                lhs_value
                    .try_decimal_mul_observed(&rhs_value, &mut observer)
                    .expect("reference multiply");
            }
            syscalls::SYSCALL_DECIMAL_DIV_EXACT => {
                lhs_value
                    .try_decimal_div_exact_observed(&rhs_value, &mut observer)
                    .expect("reference exact division");
            }
            _ => {
                lhs_value
                    .try_decimal_div_round_observed(
                        &rhs_value,
                        scale.expect("rounded scale"),
                        iroha_primitives::numeric::RoundingMode::NearestEven,
                        &mut observer,
                    )
                    .expect("reference rounded division");
            }
        }
        let mut vm = vm_for(syscall, u64::MAX);
        let lhs_envelope = ivm_abi::numeric_tlv::encode_decimal(&lhs_value).expect("lhs envelope");
        let rhs_envelope = ivm_abi::numeric_tlv::encode_decimal(&rhs_value).expect("rhs envelope");
        let lhs = vm.alloc_host_tlv(&lhs_envelope).expect("lhs");
        let rhs = vm.alloc_host_tlv(&rhs_envelope).expect("rhs");
        vm.set_register(10, lhs);
        vm.set_register(11, rhs);
        vm.set_register(14, NUMERIC_FAILURE_TRAP);
        let mut input_bytes = (lhs_envelope.len() + rhs_envelope.len()) as u64;
        let mut validation =
            decimal_validation_work_for_envelope(lhs_envelope.len() as u64, &lhs_value)
                + decimal_validation_work_for_envelope(rhs_envelope.len() as u64, &rhs_value);
        if let Some(scale) = scale {
            let scale_envelope = ivm_abi::numeric_tlv::encode_int(&BigInt::from_i128(scale.into()))
                .expect("scale envelope");
            let scale_pointer = vm.alloc_host_tlv(&scale_envelope).expect("scale");
            vm.set_register(12, scale_pointer);
            vm.set_register(13, RoundingModeV1::NearestEven.tag());
            input_bytes += scale_envelope.len() as u64;
            validation += validation_work_for_envelope(scale_envelope.len() as u64);
        }
        vm.run().expect("representative decimal operation");
        let output_value = result_decimal(&vm);
        let output_bytes = envelope_len(&vm, vm.register(10));
        let expected = ivm::numeric_gas::successful_call_gas(SuccessfulCallGas {
            input_envelope_bytes: input_bytes,
            input_hash_frame_bytes: input_bytes - 39 * if scale.is_some() { 3 } else { 2 },
            output_envelope_bytes: output_bytes,
            output_frame_bytes: frame_len_for_envelope(output_bytes),
            output_length_limb_work: output_length_work(output_value.mantissa()),
            arithmetic_limb_work: observed_work,
            validation_limb_work: validation,
            normalization_limb_work: 0,
        })
        .expect("representative gas identity");
        assert_eq!(
            vm.last_staged_syscall_context()
                .expect("representative context")
                .charged(),
            expected,
            "syscall={syscall:#x}",
        );
    }
}
#[test]
fn both_signs_have_exact_gas_at_every_logical_limb_transition() {
    fn add_zero_gas(value: &BigInt, expected_mantissa_bytes: usize) -> (u64, u64) {
        let value_envelope = ivm_abi::numeric_tlv::encode_int(value).expect("boundary envelope");
        let zero_envelope =
            ivm_abi::numeric_tlv::encode_int(&BigInt::zero()).expect("zero envelope");
        // 39 pointer-envelope bytes + 40 frame-header bytes + 4 length bytes.
        assert_eq!(value_envelope.len(), 83 + expected_mantissa_bytes);
        assert_eq!(zero_envelope.len(), 83);
        let mut vm = vm_for(syscalls::SYSCALL_INT_ADD, u64::MAX);
        let value_pointer = vm
            .alloc_host_tlv(&value_envelope)
            .expect("install boundary value");
        let zero_pointer = vm.alloc_host_tlv(&zero_envelope).expect("install zero");
        vm.set_register(10, value_pointer);
        vm.set_register(11, zero_pointer);
        vm.set_register(14, NUMERIC_FAILURE_TRAP);
        vm.run().expect("boundary add-zero operation");
        assert_eq!(result_int(&vm), *value);
        let context = vm
            .last_staged_syscall_context()
            .expect("completed boundary context");
        assert_eq!(context.completion(), Some(SyscallCompletion::Success));
        (
            context.charged(),
            context.phase_charge(SyscallMeteringPhase::Arithmetic),
        )
    }
    for lower_limbs in 1_u64..8 {
        let boundary_byte = usize::try_from(8 * lower_limbs).expect("bounded byte index");
        let mantissa_bytes = boundary_byte + 1;
        // +(2^(64L) - 1) and +2^(64L) straddle the work boundary while both
        // occupy the same minimal signed payload width.
        let mut positive_before_bytes = vec![0xff; mantissa_bytes];
        positive_before_bytes[boundary_byte] = 0;
        let mut positive_after_bytes = vec![0; mantissa_bytes];
        positive_after_bytes[boundary_byte] = 1;
        // -(2^(64L) - 1) and -2^(64L) are the matching negative fixtures.
        let mut negative_before_bytes = vec![0; mantissa_bytes];
        negative_before_bytes[0] = 1;
        negative_before_bytes[boundary_byte] = 0xff;
        let mut negative_after_bytes = vec![0; mantissa_bytes];
        negative_after_bytes[boundary_byte] = 0xff;
        let mut sign_totals = [(0_u64, 0_u64); 2];
        for (sign_index, (sign, before_bytes, after_bytes)) in [
            ("positive", positive_before_bytes, positive_after_bytes),
            ("negative", negative_before_bytes, negative_after_bytes),
        ]
        .into_iter()
        .enumerate()
        {
            let before = BigInt::from_twos_bytes(&before_bytes).expect("canonical lower fixture");
            let after = BigInt::from_twos_bytes(&after_bytes).expect("canonical upper fixture");
            assert_eq!(
                before.bit_len(),
                usize::try_from(64 * lower_limbs).unwrap(),
                "{sign} lower fixture",
            );
            assert_eq!(
                after.bit_len(),
                usize::try_from(64 * lower_limbs + 1).unwrap(),
                "{sign} upper fixture",
            );
            let (before_total, before_arithmetic) = add_zero_gas(&before, mantissa_bytes);
            let (after_total, after_arithmetic) = add_zero_gas(&after, mantissa_bytes);
            // Independently expanded checked-add work is `3L + 2`, charged
            // at four gas per limb. At this equal-byte-width transition, the
            // one extra work limb is therefore the only changing term.
            assert_eq!(before_arithmetic, 12 * lower_limbs + 8, "{sign}");
            assert_eq!(after_arithmetic, 12 * (lower_limbs + 1) + 8, "{sign}",);
            assert_eq!(after_arithmetic - before_arithmetic, 12, "{sign}");
            // For b = 8L + 1 encoded mantissa bytes, independently summing
            // entry, transport/authentication, validation, arithmetic, and
            // output serialization gives these complete staged-call totals.
            assert_eq!(before_total, 882 + 64 * lower_limbs, "{sign}");
            assert_eq!(after_total, 894 + 64 * lower_limbs, "{sign}");
            assert_eq!(after_total - before_total, 12, "{sign}");
            sign_totals[sign_index] = (before_total, after_total);
        }
        assert_eq!(
            sign_totals[0],
            sign_totals[1],
            "gas at the {lower_limbs}-to-{} limb boundary must be sign-independent",
            lower_limbs + 1,
        );
    }
}
#[test]
fn signed_division_remainder_and_wrapping_endpoints_are_pinned() {
    for (lhs, rhs, quotient, remainder) in [
        (-7, 3, -2, -1),
        (7, -3, -2, 1),
        (-7, -3, 2, -1),
        (7, 3, 2, 1),
    ] {
        for (syscall, expected) in [
            (syscalls::SYSCALL_INT_DIV, quotient),
            (syscalls::SYSCALL_INT_REM, remainder),
        ] {
            let mut vm = vm_for(syscall, u64::MAX);
            let lhs = install_int(&mut vm, &BigInt::from_i128(lhs));
            let rhs = install_int(&mut vm, &BigInt::from_i128(rhs));
            vm.set_register(10, lhs);
            vm.set_register(11, rhs);
            vm.set_register(14, NUMERIC_FAILURE_TRAP);
            vm.run().expect("signed integer operation");
            assert_eq!(result_int(&vm), BigInt::from_i128(expected));
        }
    }
    let mut add = vm_for(syscalls::SYSCALL_INT_WRAP_ADD, u64::MAX);
    let max = install_int(&mut add, &max_int());
    let one = install_int(&mut add, &BigInt::one());
    add.set_register(10, max);
    add.set_register(11, one);
    add.run().expect("wrapping add");
    assert_eq!(result_int(&add), min_int());
    let mut neg = vm_for(syscalls::SYSCALL_INT_WRAP_NEG, u64::MAX);
    let minimum = install_int(&mut neg, &min_int());
    neg.set_register(10, minimum);
    neg.run().expect("wrapping negation");
    assert_eq!(result_int(&neg), min_int());
    assert_eq!(
        neg.last_staged_syscall_context()
            .expect("minimum wrapping context")
            .phase_charge(SyscallMeteringPhase::Arithmetic),
        4 * (ivm::numeric_gas::wrapping_unary_work(8).expect("unary work")
            + ivm::numeric_gas::wrapping_reduction_work(9).expect("reduction work")),
    );
    let mut neg_i64 = vm_for(syscalls::SYSCALL_INT_WRAP_NEG, u64::MAX);
    let i64_minimum = install_int(&mut neg_i64, &BigInt::from_i128(i128::from(i64::MIN)));
    neg_i64.set_register(10, i64_minimum);
    neg_i64.run().expect("i64-boundary wrapping negation");
    assert_eq!(
        result_int(&neg_i64),
        BigInt::from_i128(-(i128::from(i64::MIN)))
    );
    assert_eq!(
        neg_i64
            .last_staged_syscall_context()
            .expect("i64-boundary wrapping context")
            .phase_charge(SyscallMeteringPhase::Arithmetic),
        4 * (ivm::numeric_gas::wrapping_unary_work(1).expect("unary work")
            + ivm::numeric_gas::wrapping_reduction_work(2).expect("reduction work")),
    );
    let mut sub = vm_for(syscalls::SYSCALL_INT_WRAP_SUB, u64::MAX);
    let minimum = install_int(&mut sub, &min_int());
    let one = install_int(&mut sub, &BigInt::one());
    sub.set_register(10, minimum);
    sub.set_register(11, one);
    sub.run().expect("wrapping subtraction");
    assert_eq!(result_int(&sub), max_int());
    let mut mul = vm_for(syscalls::SYSCALL_INT_WRAP_MUL, u64::MAX);
    let maximum = install_int(&mut mul, &max_int());
    let two = install_int(&mut mul, &BigInt::from_i128(2));
    mul.set_register(10, maximum);
    mul.set_register(11, two);
    mul.run().expect("wrapping multiplication");
    assert_eq!(result_int(&mul), BigInt::from_i128(-2));
}
#[test]
fn checked_int_endpoints_fault_before_output_in_trap_and_status_modes() {
    for syscall in [
        syscalls::SYSCALL_INT_NEG,
        syscalls::SYSCALL_INT_ADD,
        syscalls::SYSCALL_INT_MUL,
        syscalls::SYSCALL_INT_DIV,
        syscalls::SYSCALL_INT_REM,
    ] {
        for mode in [NUMERIC_FAILURE_TRAP, NUMERIC_FAILURE_STATUS] {
            let mut vm = vm_for(syscall, u64::MAX);
            let (lhs, rhs) = match syscall {
                syscalls::SYSCALL_INT_NEG => (min_int(), None),
                syscalls::SYSCALL_INT_ADD => (max_int(), Some(BigInt::one())),
                syscalls::SYSCALL_INT_MUL => (max_int(), Some(BigInt::from_i128(2))),
                syscalls::SYSCALL_INT_DIV | syscalls::SYSCALL_INT_REM => {
                    (min_int(), Some(BigInt::from_i128(-1)))
                }
                _ => unreachable!(),
            };
            let lhs = install_int(&mut vm, &lhs);
            vm.set_register(10, lhs);
            if let Some(rhs) = rhs {
                let rhs = install_int(&mut vm, &rhs);
                vm.set_register(11, rhs);
            }
            vm.set_register(14, mode);
            if mode == NUMERIC_FAILURE_TRAP {
                assert_eq!(
                    vm.run(),
                    Err(VMError::NumericFault(NumericFaultV1::MantissaOverflow)),
                    "trap syscall {syscall:#x}",
                );
            } else {
                vm.run().expect("recoverable endpoint overflow");
                assert_eq!(vm.register(10), 0, "status syscall {syscall:#x}");
                assert_eq!(
                    vm.register(11),
                    NumericFaultV1::MantissaOverflow.tag(),
                    "status syscall {syscall:#x}",
                );
            }
        }
    }
}
#[test]
fn checked_int_zero_divisors_stop_before_arithmetic_in_both_failure_modes() {
    for syscall in [syscalls::SYSCALL_INT_DIV, syscalls::SYSCALL_INT_REM] {
        for mode in [NUMERIC_FAILURE_TRAP, NUMERIC_FAILURE_STATUS] {
            let mut vm = vm_for(syscall, u64::MAX);
            let lhs = install_int(&mut vm, &BigInt::from_i128(7));
            let rhs = install_int(&mut vm, &BigInt::zero());
            vm.set_register(10, lhs);
            vm.set_register(11, rhs);
            vm.set_register(14, mode);
            if mode == NUMERIC_FAILURE_TRAP {
                assert_eq!(
                    vm.run(),
                    Err(VMError::NumericFault(NumericFaultV1::DivisionByZero)),
                    "trap syscall {syscall:#x}",
                );
            } else {
                vm.run().expect("recoverable zero divisor");
                assert_eq!(vm.register(10), 0, "status syscall {syscall:#x}");
                assert_eq!(
                    vm.register(11),
                    NumericFaultV1::DivisionByZero.tag(),
                    "status syscall {syscall:#x}",
                );
            }
            let context = vm.last_staged_syscall_context().expect("staged context");
            assert_eq!(
                context.phase_charge(SyscallMeteringPhase::Arithmetic),
                0,
                "zero-divisor syscall {syscall:#x} must not enter bigint division",
            );
            assert_eq!(
                context.phase_charge(SyscallMeteringPhase::OutputSerialization),
                0,
                "zero-divisor syscall {syscall:#x} must not publish output",
            );
        }
    }
}
#[test]
fn exact_and_rounded_decimal_division_have_distinct_faults_and_signed_public_modes() {
    let mut exact = vm_for(syscalls::SYSCALL_DECIMAL_DIV_EXACT, u64::MAX);
    let one = install_decimal(&mut exact, &Numeric::new(1, 0));
    let three = install_decimal(&mut exact, &Numeric::new(3, 0));
    exact.set_register(10, one);
    exact.set_register(11, three);
    exact.set_register(14, NUMERIC_FAILURE_STATUS);
    exact.run().expect("recoverable repeating division");
    assert_eq!(exact.register(10), 0);
    assert_eq!(exact.register(11), NumericFaultV1::RepeatingDecimal.tag());
    assert_eq!(
        exact
            .last_staged_syscall_context()
            .expect("staged context")
            .completion(),
        Some(SyscallCompletion::RecoverableFailure)
    );
    for (mode, expected_positive, expected_negative) in [
        (RoundingModeV1::TowardZero, "2", "-2"),
        (RoundingModeV1::AwayFromZero, "3", "-3"),
        (RoundingModeV1::Floor, "2", "-3"),
        (RoundingModeV1::Ceil, "3", "-2"),
        (RoundingModeV1::NearestEven, "2", "-2"),
        (RoundingModeV1::NearestAway, "3", "-3"),
        (RoundingModeV1::NearestTowardZero, "2", "-2"),
    ] {
        for (numerator, expected) in [(5, expected_positive), (-5, expected_negative)] {
            let mut vm = vm_for(syscalls::SYSCALL_DECIMAL_DIV_ROUND, u64::MAX);
            let lhs = install_decimal(&mut vm, &Numeric::new(numerator, 0));
            let rhs = install_decimal(&mut vm, &Numeric::new(2, 0));
            let scale = install_int(&mut vm, &BigInt::zero());
            vm.set_register(10, lhs);
            vm.set_register(11, rhs);
            vm.set_register(12, scale);
            vm.set_register(13, mode.tag());
            vm.set_register(14, NUMERIC_FAILURE_TRAP);
            vm.run().expect("rounded tie");
            assert_eq!(result_decimal(&vm).to_string(), expected);
        }
    }
}
#[test]
fn quantity_is_nominal_and_underflow_is_recoverable_without_output() {
    let mut convert = vm_for(syscalls::SYSCALL_QUANTITY_FROM_DECIMAL, u64::MAX);
    let negative = install_decimal(&mut convert, &Numeric::new(-1, 0));
    convert.set_register(10, negative);
    convert.set_register(14, NUMERIC_FAILURE_STATUS);
    convert.run().expect("recoverable negative quantity");
    assert_eq!(convert.register(10), 0);
    assert_eq!(convert.register(11), NumericFaultV1::NegativeQuantity.tag());
    let mut subtract = vm_for(syscalls::SYSCALL_QUANTITY_SUB, u64::MAX);
    let one: Quantity = "1".parse().expect("quantity");
    let two: Quantity = "2".parse().expect("quantity");
    let lhs = install_quantity(&mut subtract, &one);
    let rhs = install_quantity(&mut subtract, &two);
    subtract.set_register(10, lhs);
    subtract.set_register(11, rhs);
    subtract.set_register(14, NUMERIC_FAILURE_STATUS);
    subtract.run().expect("recoverable quantity underflow");
    assert_eq!(subtract.register(10), 0);
    assert_eq!(
        subtract.register(11),
        NumericFaultV1::QuantityUnderflow.tag()
    );
    let underflow_arithmetic = subtract
        .last_staged_syscall_context()
        .expect("underflow context")
        .phase_charge(SyscallMeteringPhase::Arithmetic);
    let mut add = vm_for(syscalls::SYSCALL_QUANTITY_ADD, u64::MAX);
    let lhs = install_quantity(&mut add, &one);
    let rhs = install_quantity(&mut add, &two);
    add.set_register(10, lhs);
    add.set_register(11, rhs);
    add.set_register(14, NUMERIC_FAILURE_TRAP);
    add.run().expect("quantity add");
    assert_eq!(result_quantity(&add).to_string(), "3");
    // Quantity subtraction performs one aligned subtraction and maps a
    // negative mathematical result to underflow. It must not perform and
    // charge a separate comparison pass first.
    let mut successful_subtract = vm_for(syscalls::SYSCALL_QUANTITY_SUB, u64::MAX);
    let lhs = install_quantity(&mut successful_subtract, &two);
    let rhs = install_quantity(&mut successful_subtract, &one);
    successful_subtract.set_register(10, lhs);
    successful_subtract.set_register(11, rhs);
    successful_subtract.set_register(14, NUMERIC_FAILURE_TRAP);
    successful_subtract
        .run()
        .expect("successful quantity subtraction");
    assert_eq!(result_quantity(&successful_subtract).to_string(), "1");
    let successful_arithmetic = successful_subtract
        .last_staged_syscall_context()
        .expect("successful subtraction context")
        .phase_charge(SyscallMeteringPhase::Arithmetic);
    assert_eq!(underflow_arithmetic, successful_arithmetic);
    let mut same_operands_add = vm_for(syscalls::SYSCALL_QUANTITY_ADD, u64::MAX);
    let lhs = install_quantity(&mut same_operands_add, &two);
    let rhs = install_quantity(&mut same_operands_add, &one);
    same_operands_add.set_register(10, lhs);
    same_operands_add.set_register(11, rhs);
    same_operands_add.set_register(14, NUMERIC_FAILURE_TRAP);
    same_operands_add
        .run()
        .expect("same-width quantity addition");
    assert_eq!(result_quantity(&same_operands_add).to_string(), "3");
    assert_eq!(
        same_operands_add
            .last_staged_syscall_context()
            .expect("addition context")
            .phase_charge(SyscallMeteringPhase::Arithmetic),
        successful_arithmetic,
    );
}
#[test]
fn negative_quantity_factors_report_negative_quantity_in_trap_and_status_modes() {
    for syscall in [
        syscalls::SYSCALL_QUANTITY_MUL_DECIMAL,
        syscalls::SYSCALL_QUANTITY_DIV_DECIMAL_EXACT,
        syscalls::SYSCALL_QUANTITY_DIV_DECIMAL_ROUND,
    ] {
        for failure_mode in [NUMERIC_FAILURE_STATUS, NUMERIC_FAILURE_TRAP] {
            let mut vm = vm_for(syscall, u64::MAX);
            let quantity: Quantity = "2".parse().expect("quantity");
            let lhs = install_quantity(&mut vm, &quantity);
            let negative = install_decimal(&mut vm, &Numeric::new(-1, 0));
            vm.set_register(10, lhs);
            vm.set_register(11, negative);
            if syscall == syscalls::SYSCALL_QUANTITY_DIV_DECIMAL_ROUND {
                let scale = install_int(&mut vm, &BigInt::zero());
                vm.set_register(12, scale);
                vm.set_register(13, RoundingModeV1::TowardZero.tag());
            }
            vm.set_register(14, failure_mode);
            let outcome = vm.run();
            if failure_mode == NUMERIC_FAILURE_STATUS {
                outcome.expect("negative result is a recoverable quantity fault");
                assert_eq!(vm.register(10), 0, "fault must not publish a result");
                assert_eq!(
                    vm.register(11),
                    NumericFaultV1::NegativeQuantity.tag(),
                    "{syscall:#x} must distinguish a negative factor from subtraction underflow"
                );
                assert_eq!(
                    vm.last_staged_syscall_context()
                        .expect("numeric context")
                        .phase_charge(SyscallMeteringPhase::OutputSerialization),
                    0,
                    "faulted quantity arithmetic must not charge or serialize output"
                );
            } else {
                assert!(
                    matches!(
                        outcome,
                        Err(VMError::NumericFault(NumericFaultV1::NegativeQuantity))
                    ),
                    "{syscall:#x} must trap with NegativeQuantity"
                );
            }
        }
    }
}
#[test]
fn malformed_operand_precedes_invalid_controls_and_control_faults_are_distinct() {
    let mut malformed = vm_for(syscalls::SYSCALL_INT_ADD, u64::MAX);
    let mut envelope = ivm_abi::numeric_tlv::encode_int(&BigInt::one()).expect("int envelope");
    *envelope.last_mut().expect("hash byte") ^= 1;
    let bad = malformed
        .alloc_host_tlv(&envelope)
        .expect("install malformed int");
    let rhs = install_int(&mut malformed, &BigInt::one());
    malformed.set_register(10, bad);
    malformed.set_register(11, rhs);
    malformed.set_register(12, 9);
    malformed.set_register(14, 99);
    assert_eq!(
        malformed.run(),
        Err(VMError::PointerAbiFault(
            PointerAbiFaultV1::PayloadHashMismatch
        ))
    );
    let mut reserved = vm_for(syscalls::SYSCALL_INT_ADD, u64::MAX);
    let lhs = install_int(&mut reserved, &BigInt::one());
    let rhs = install_int(&mut reserved, &BigInt::one());
    reserved.set_register(10, lhs);
    reserved.set_register(11, rhs);
    reserved.set_register(12, 1);
    reserved.set_register(14, 99);
    assert_eq!(
        reserved.run(),
        Err(VMError::NumericFault(
            NumericFaultV1::ReservedRegisterNonZero
        ))
    );
    let mut failure = vm_for(syscalls::SYSCALL_INT_ADD, u64::MAX);
    let lhs = install_int(&mut failure, &BigInt::one());
    let rhs = install_int(&mut failure, &BigInt::one());
    failure.set_register(10, lhs);
    failure.set_register(11, rhs);
    failure.set_register(14, 99);
    assert_eq!(
        failure.run(),
        Err(VMError::NumericFault(NumericFaultV1::InvalidFailureMode))
    );
    for invalid_tag in [7, u64::MAX] {
        let mut rounding = vm_for(syscalls::SYSCALL_DECIMAL_DIV_ROUND, u64::MAX);
        let lhs = install_decimal(&mut rounding, &Numeric::new(1, 0));
        let rhs = install_decimal(&mut rounding, &Numeric::new(2, 0));
        let scale = install_int(&mut rounding, &BigInt::zero());
        rounding.set_register(10, lhs);
        rounding.set_register(11, rhs);
        rounding.set_register(12, scale);
        rounding.set_register(13, invalid_tag);
        rounding.set_register(14, NUMERIC_FAILURE_TRAP);
        assert_eq!(
            rounding.run(),
            Err(VMError::NumericFault(NumericFaultV1::InvalidRoundingMode)),
            "rounding tag {invalid_tag} must be rejected"
        );
    }
    // A scale pointer is the third operand and is authenticated before either
    // scalar control tag is interpreted.
    let mut bad_scale_pointer = vm_for(syscalls::SYSCALL_DECIMAL_DIV_ROUND, u64::MAX);
    let lhs = install_decimal(&mut bad_scale_pointer, &Numeric::new(1, 0));
    let rhs = install_decimal(&mut bad_scale_pointer, &Numeric::new(2, 0));
    let mut scale_envelope =
        ivm_abi::numeric_tlv::encode_int(&BigInt::zero()).expect("scale envelope");
    *scale_envelope.last_mut().expect("scale hash") ^= 1;
    let scale = bad_scale_pointer
        .alloc_host_tlv(&scale_envelope)
        .expect("install bad scale");
    bad_scale_pointer.set_register(10, lhs);
    bad_scale_pointer.set_register(11, rhs);
    bad_scale_pointer.set_register(12, scale);
    bad_scale_pointer.set_register(13, u64::MAX);
    bad_scale_pointer.set_register(14, u64::MAX);
    assert_eq!(
        bad_scale_pointer.run(),
        Err(VMError::PointerAbiFault(
            PointerAbiFaultV1::PayloadHashMismatch
        ))
    );
    // An out-of-domain but canonical scale is a recoverable numeric failure.
    // Malformed scalar controls are traps, so rounding and then failure-mode
    // validation precede resolving that semantic scale failure.
    for (rounding_tag, failure_tag, expected) in [
        (
            u64::MAX,
            u64::MAX,
            Err(VMError::NumericFault(NumericFaultV1::InvalidRoundingMode)),
        ),
        (
            RoundingModeV1::NearestEven.tag(),
            u64::MAX,
            Err(VMError::NumericFault(NumericFaultV1::InvalidFailureMode)),
        ),
    ] {
        let mut vm = vm_for(syscalls::SYSCALL_DECIMAL_DIV_ROUND, u64::MAX);
        let lhs = install_decimal(&mut vm, &Numeric::new(1, 0));
        let rhs = install_decimal(&mut vm, &Numeric::new(2, 0));
        let scale = install_int(&mut vm, &BigInt::from_i128(29));
        vm.set_register(10, lhs);
        vm.set_register(11, rhs);
        vm.set_register(12, scale);
        vm.set_register(13, rounding_tag);
        vm.set_register(14, failure_tag);
        assert_eq!(vm.run(), expected);
    }
    let mut invalid_scale = vm_for(syscalls::SYSCALL_DECIMAL_DIV_ROUND, u64::MAX);
    let lhs = install_decimal(&mut invalid_scale, &Numeric::new(1, 0));
    let rhs = install_decimal(&mut invalid_scale, &Numeric::new(2, 0));
    let scale = install_int(&mut invalid_scale, &BigInt::from_i128(29));
    invalid_scale.set_register(10, lhs);
    invalid_scale.set_register(11, rhs);
    invalid_scale.set_register(12, scale);
    invalid_scale.set_register(13, RoundingModeV1::NearestEven.tag());
    invalid_scale.set_register(14, NUMERIC_FAILURE_STATUS);
    invalid_scale.run().expect("recoverable invalid scale");
    assert_eq!(invalid_scale.register(10), 0);
    assert_eq!(
        invalid_scale.register(11),
        NumericFaultV1::InvalidScale.tag()
    );
    // Control validity is established before the zero-divisor branch begins.
    let mut zero_with_bad_mode = vm_for(syscalls::SYSCALL_DECIMAL_DIV_EXACT, u64::MAX);
    let lhs = install_decimal(&mut zero_with_bad_mode, &Numeric::new(1, 0));
    let rhs = install_decimal(&mut zero_with_bad_mode, &Numeric::new(0, 0));
    zero_with_bad_mode.set_register(10, lhs);
    zero_with_bad_mode.set_register(11, rhs);
    zero_with_bad_mode.set_register(14, u64::MAX);
    assert_eq!(
        zero_with_bad_mode.run(),
        Err(VMError::NumericFault(NumericFaultV1::InvalidFailureMode))
    );
    // Required-zero registers have precedence over the rounded conversion's
    // rounding tag because they are earlier in the public register contract.
    let mut reserved_round = vm_for(syscalls::SYSCALL_DECIMAL_TO_INT_ROUND, u64::MAX);
    let value = install_decimal(&mut reserved_round, &Numeric::new(15, 1));
    reserved_round.set_register(10, value);
    reserved_round.set_register(11, 1);
    reserved_round.set_register(13, u64::MAX);
    assert_eq!(
        reserved_round.run(),
        Err(VMError::NumericFault(
            NumericFaultV1::ReservedRegisterNonZero
        ))
    );
}
#[test]
fn structural_failure_precedes_canonical_phase_and_body_failure_follows_it() {
    let valid_frame = IntValueV1::try_new(BigInt::one())
        .expect("bounded integer")
        .encode_frame()
        .expect("valid frame");
    let mut bad_crc_frame = valid_frame;
    *bad_crc_frame.last_mut().expect("body byte") ^= 1;
    let bad_crc_envelope = numeric_envelope_from_frame(ivm::PointerType::Int, &bad_crc_frame);
    let mut bad_crc = vm_for(syscalls::SYSCALL_INT_NEG, u64::MAX);
    let pointer = bad_crc
        .alloc_host_tlv(&bad_crc_envelope)
        .expect("install structurally invalid frame");
    bad_crc.set_register(10, pointer);
    bad_crc.set_register(14, NUMERIC_FAILURE_TRAP);
    assert!(matches!(
        bad_crc.run(),
        Err(VMError::PointerAbiFault(PointerAbiFaultV1::MalformedFrame))
    ));
    let context = bad_crc
        .last_staged_syscall_context()
        .expect("structural failure context");
    assert!(context.phase_charge(SyscallMeteringPhase::NoritoDecode) > 0);
    assert_eq!(
        context.phase_charge(SyscallMeteringPhase::CanonicalValidation),
        0,
        "body validation must not be charged or begun after structural failure"
    );
    let mut noncanonical_body = Vec::new();
    noncanonical_body.extend_from_slice(&1_u32.to_le_bytes());
    noncanonical_body.push(0);
    let noncanonical_frame =
        norito::core::frame_bare_with_header_flags::<IntValueV1>(&noncanonical_body, 0)
            .expect("structurally valid noncanonical frame");
    let noncanonical_envelope =
        numeric_envelope_from_frame(ivm::PointerType::Int, &noncanonical_frame);
    let mut noncanonical = vm_for(syscalls::SYSCALL_INT_NEG, u64::MAX);
    let pointer = noncanonical
        .alloc_host_tlv(&noncanonical_envelope)
        .expect("install noncanonical frame");
    noncanonical.set_register(10, pointer);
    noncanonical.set_register(14, NUMERIC_FAILURE_TRAP);
    assert_eq!(
        noncanonical.run(),
        Err(VMError::PointerAbiFault(PointerAbiFaultV1::NonCanonical))
    );
    let context = noncanonical
        .last_staged_syscall_context()
        .expect("canonical failure context");
    assert!(context.phase_charge(SyscallMeteringPhase::NoritoDecode) > 0);
    assert!(context.phase_charge(SyscallMeteringPhase::CanonicalValidation) > 0);
}
#[test]
fn every_decode_and_output_phase_has_a_charge_before_work() {
    let syscall = syscalls::SYSCALL_INT_NEG;
    let mut baseline = vm_for(syscall, u64::MAX);
    let operand = install_int(&mut baseline, &BigInt::one());
    baseline.set_register(10, operand);
    baseline.set_register(14, NUMERIC_FAILURE_TRAP);
    baseline.run().expect("baseline numeric call");
    let context = baseline
        .last_staged_syscall_context()
        .expect("baseline staged context")
        .clone();
    let frame_bytes = ivm_abi::numeric_tlv::encode_int(&BigInt::one())
        .expect("reference envelope")
        .len()
        - 39;
    assert_eq!(context.phase_charge(SyscallMeteringPhase::PointerHeader), 7);
    assert_eq!(
        context.phase_charge(SyscallMeteringPhase::PointerEnvelope),
        u64::try_from(frame_bytes).expect("bounded frame")
    );
    assert_eq!(
        context.phase_charge(SyscallMeteringPhase::PayloadHash),
        32 + u64::try_from(frame_bytes).expect("bounded frame")
    );
    let instruction_gas =
        ivm::cost_of(encoding::wide::encode_syscallx(syscall)).expect("SCALLX gas");
    let phases = [
        SyscallMeteringPhase::Entry,
        SyscallMeteringPhase::PointerHeader,
        SyscallMeteringPhase::PointerEnvelope,
        SyscallMeteringPhase::PayloadHash,
        SyscallMeteringPhase::NoritoDecode,
        SyscallMeteringPhase::CanonicalValidation,
        SyscallMeteringPhase::Arithmetic,
        SyscallMeteringPhase::OutputSerialization,
    ];
    let mut completed = instruction_gas;
    for phase in phases {
        let charge = context.phase_charge(phase);
        assert!(charge > 0, "phase {phase:?} must have a nonzero charge");
        let mut vm = vm_for(syscall, completed + charge - 1);
        let operand = install_int(&mut vm, &BigInt::one());
        vm.set_register(10, operand);
        vm.set_register(14, NUMERIC_FAILURE_TRAP);
        assert_eq!(
            vm.run(),
            Err(VMError::SyscallOutOfGas {
                syscall,
                phase: phase.tag(),
            }),
            "phase {phase:?}"
        );
        assert_eq!(
            vm.register(10),
            operand,
            "failed phase must not publish output"
        );
        completed += charge;
    }
}
#[test]
fn maximum_frame_hash_and_output_traversals_are_pinned_and_oog_safe() {
    let syscall = syscalls::SYSCALL_INT_NEG;
    let value = max_int();
    let envelope = ivm_abi::numeric_tlv::encode_int(&value).expect("maximum envelope");
    let frame_bytes = frame_len_for_envelope(envelope.len() as u64);
    assert_eq!(frame_bytes, 108);
    let mut baseline = vm_for(syscall, u64::MAX);
    let operand = baseline.alloc_host_tlv(&envelope).expect("maximum operand");
    baseline.set_register(10, operand);
    baseline.set_register(14, NUMERIC_FAILURE_TRAP);
    baseline.run().expect("maximum negation");
    let result = result_int(&baseline);
    let output_bytes = envelope_len(&baseline, baseline.register(10));
    let output_frame = frame_len_for_envelope(output_bytes);
    let context = baseline
        .last_staged_syscall_context()
        .expect("maximum context")
        .clone();
    assert_eq!(
        context.phase_charge(SyscallMeteringPhase::PayloadHash),
        32 + frame_bytes
    );
    assert_eq!(
        context.phase_charge(SyscallMeteringPhase::OutputSerialization),
        4 * output_length_work(&result) + output_bytes + 2 * output_frame
    );
    let instruction = ivm::cost_of(encoding::wide::encode_syscallx(syscall)).expect("SCALLX gas");
    let hash_prefix = instruction
        + context.phase_charge(SyscallMeteringPhase::Entry)
        + context.phase_charge(SyscallMeteringPhase::PointerHeader)
        + context.phase_charge(SyscallMeteringPhase::PointerEnvelope);
    let mut hash_oog = vm_for(
        syscall,
        hash_prefix + context.phase_charge(SyscallMeteringPhase::PayloadHash) - 1,
    );
    let operand = hash_oog
        .alloc_host_tlv(&envelope)
        .expect("maximum hash operand");
    hash_oog.set_register(10, operand);
    hash_oog.set_register(14, NUMERIC_FAILURE_TRAP);
    assert_eq!(
        hash_oog.run(),
        Err(VMError::SyscallOutOfGas {
            syscall,
            phase: SyscallMeteringPhase::PayloadHash.tag(),
        })
    );
    let output_charge = context.phase_charge(SyscallMeteringPhase::OutputSerialization);
    let before_output = instruction + context.charged() - output_charge;
    let mut output_oog = vm_for(syscall, before_output + output_charge - 1);
    let operand = output_oog
        .alloc_host_tlv(&envelope)
        .expect("maximum output operand");
    output_oog.set_register(10, operand);
    output_oog.set_register(14, NUMERIC_FAILURE_TRAP);
    assert_eq!(
        output_oog.run(),
        Err(VMError::SyscallOutOfGas {
            syscall,
            phase: SyscallMeteringPhase::OutputSerialization.tag(),
        })
    );
    assert_eq!(output_oog.register(10), operand);
}
#[test]
fn entry_oog_precedes_staged_numeric_privacy_validation() {
    let syscall = syscalls::SYSCALL_INT_NEG;
    let instruction_gas =
        ivm::cost_of(encoding::wide::encode_syscallx(syscall)).expect("SCALLX gas");
    let mut vm = zk_vm_for(
        syscall,
        instruction_gas + ivm::numeric_gas::NUMERIC_ENTRY_GAS - 1,
    );
    vm.set_register(10, 1);
    vm.registers.set_tag(10, true);
    assert_eq!(
        vm.run(),
        Err(VMError::SyscallOutOfGas {
            syscall,
            phase: SyscallMeteringPhase::Entry.tag(),
        })
    );
    let context = vm
        .last_staged_syscall_context()
        .expect("entry OOG staged context");
    assert_eq!(context.charged(), 0);
    assert_eq!(context.completion(), Some(SyscallCompletion::Trap));
}
#[test]
fn every_stable_staged_phase_tag_is_reachable_in_production_numeric_paths() {
    let mut unary = vm_for(syscalls::SYSCALL_INT_NEG, u64::MAX);
    let operand = install_int(&mut unary, &BigInt::one());
    unary.set_register(10, operand);
    unary.set_register(14, NUMERIC_FAILURE_TRAP);
    unary.run().expect("unary phase fixture");
    let unary = unary
        .last_staged_syscall_context()
        .expect("unary staged context")
        .clone();
    let mut normalized = vm_for(syscalls::SYSCALL_DECIMAL_MUL, u64::MAX);
    let lhs = install_decimal(&mut normalized, &"1.25".parse().expect("lhs"));
    let rhs = install_decimal(&mut normalized, &"0.4".parse().expect("rhs"));
    normalized.set_register(10, lhs);
    normalized.set_register(11, rhs);
    normalized.set_register(14, NUMERIC_FAILURE_TRAP);
    normalized.run().expect("normalization phase fixture");
    let normalized = normalized
        .last_staged_syscall_context()
        .expect("normalization staged context");
    let phases = [
        SyscallMeteringPhase::Entry,
        SyscallMeteringPhase::PointerHeader,
        SyscallMeteringPhase::PointerEnvelope,
        SyscallMeteringPhase::PayloadHash,
        SyscallMeteringPhase::NoritoDecode,
        SyscallMeteringPhase::CanonicalValidation,
        SyscallMeteringPhase::Arithmetic,
        SyscallMeteringPhase::Normalization,
        SyscallMeteringPhase::OutputSerialization,
    ];
    assert_eq!(phases.len(), SyscallMeteringPhase::COUNT);
    for phase in phases {
        assert!(
            unary.phase_charge(phase) > 0 || normalized.phase_charge(phase) > 0,
            "stable phase {phase:?} must be reachable"
        );
    }
}
#[test]
fn repeated_arithmetic_normalization_and_scale_steps_are_individually_oog_safe() {
    let wrapping = collect_oog_prefixes(syscalls::SYSCALL_INT_WRAP_MUL, |vm| {
        let maximum = max_int();
        let lhs = install_int(vm, &maximum);
        let rhs = install_int(vm, &maximum);
        vm.set_register(10, lhs);
        vm.set_register(11, rhs);
    });
    assert!(
        wrapping
            .get(&SyscallMeteringPhase::Arithmetic.tag())
            .is_some_and(|prefixes| prefixes.len() >= 2),
        "wrapping multiplication and its 512-bit reduction have separate OOG boundaries",
    );
    let scaled_decode = collect_oog_prefixes(syscalls::SYSCALL_DECIMAL_ADD, |vm| {
        let lhs = install_decimal(vm, &"0.1".parse().expect("lhs"));
        let rhs = install_decimal(vm, &"0.2".parse().expect("rhs"));
        vm.set_register(10, lhs);
        vm.set_register(11, rhs);
        vm.set_register(14, NUMERIC_FAILURE_TRAP);
    });
    assert!(
        scaled_decode
            .get(&SyscallMeteringPhase::CanonicalValidation.tag())
            .is_some_and(|prefixes| prefixes.len() >= 4),
        "each body scan and scaled-mantissa divisibility probe has its own OOG boundary",
    );
    let normalization = collect_oog_prefixes(syscalls::SYSCALL_DECIMAL_MUL, |vm| {
        let lhs = install_decimal(vm, &"1.25".parse().expect("lhs"));
        let rhs = install_decimal(vm, &"0.4".parse().expect("rhs"));
        vm.set_register(10, lhs);
        vm.set_register(11, rhs);
        vm.set_register(14, NUMERIC_FAILURE_TRAP);
    });
    assert!(
        normalization
            .get(&SyscallMeteringPhase::Normalization.tag())
            .is_some_and(|prefixes| prefixes.len() >= 3),
        "every divide-by-ten probe must have its own pre-work OOG boundary",
    );
    let exact = collect_oog_prefixes(syscalls::SYSCALL_DECIMAL_DIV_EXACT, |vm| {
        let lhs = install_decimal(vm, &Numeric::new(1, 0));
        let rhs = install_decimal(vm, &Numeric::new(40, 0));
        vm.set_register(10, lhs);
        vm.set_register(11, rhs);
        vm.set_register(14, NUMERIC_FAILURE_TRAP);
    });
    assert!(
        exact
            .get(&SyscallMeteringPhase::Arithmetic.tag())
            .is_some_and(|prefixes| prefixes.len() >= 4),
        "GCD, denominator classification, and the proven exact division are separately debited",
    );
    let rounded = collect_oog_prefixes(syscalls::SYSCALL_DECIMAL_DIV_ROUND, |vm| {
        let lhs = install_decimal(vm, &Numeric::new(1, 0));
        let rhs = install_decimal(vm, &Numeric::new(7, 0));
        let scale = install_int(vm, &BigInt::from_i128(28));
        vm.set_register(10, lhs);
        vm.set_register(11, rhs);
        vm.set_register(12, scale);
        vm.set_register(13, RoundingModeV1::NearestEven.tag());
        vm.set_register(14, NUMERIC_FAILURE_TRAP);
    });
    assert!(
        rounded
            .get(&SyscallMeteringPhase::Arithmetic.tag())
            .is_some_and(|prefixes| prefixes.len() >= 2),
        "scale multiplication and rounded division are separately debited",
    );
    let maximum = Numeric::new(max_int(), 0);
    let tiny: Numeric = "0.0000000000000000000000000001"
        .parse()
        .expect("scale-28 divisor");
    let mut maximum_rounded = vm_for(syscalls::SYSCALL_DECIMAL_DIV_ROUND, u64::MAX);
    let lhs = install_decimal(&mut maximum_rounded, &maximum);
    let rhs = install_decimal(&mut maximum_rounded, &tiny);
    let scale = install_int(&mut maximum_rounded, &BigInt::from_i128(28));
    maximum_rounded.set_register(10, lhs);
    maximum_rounded.set_register(11, rhs);
    maximum_rounded.set_register(12, scale);
    maximum_rounded.set_register(13, RoundingModeV1::NearestEven.tag());
    maximum_rounded.set_register(14, NUMERIC_FAILURE_STATUS);
    maximum_rounded
        .run()
        .expect("maximum scale-adjusted division is recoverable");
    assert_eq!(maximum_rounded.register(10), 0);
    assert_eq!(
        maximum_rounded.register(11),
        NumericFaultV1::MantissaOverflow.tag()
    );
    assert_eq!(
        ivm::numeric_gas::scaled_limbs(511, 56),
        Ok(11),
        "divisor scale plus requested scale reaches an eleven-limb dividend"
    );
    let expected_arithmetic_work = ivm::numeric_gas::scale_work(8, 56)
        .expect("bounded maximum scaling")
        + ivm::numeric_gas::materialization_work(1)
        + ivm::numeric_gas::rounded_division_work(11, 1).expect("bounded eleven-limb division")
        + ivm::numeric_gas::finalization_work(10);
    assert_eq!(
        maximum_rounded
            .last_staged_syscall_context()
            .expect("maximum rounded-division context")
            .phase_charge(SyscallMeteringPhase::Arithmetic),
        ivm::numeric_gas::work_gas(expected_arithmetic_work)
            .expect("bounded maximum arithmetic charge")
    );
    let maximum_rounded_oog = collect_oog_prefixes(syscalls::SYSCALL_DECIMAL_DIV_ROUND, |vm| {
        let lhs = install_decimal(vm, &maximum);
        let rhs = install_decimal(vm, &tiny);
        let scale = install_int(vm, &BigInt::from_i128(28));
        vm.set_register(10, lhs);
        vm.set_register(11, rhs);
        vm.set_register(12, scale);
        vm.set_register(13, RoundingModeV1::NearestEven.tag());
        vm.set_register(14, NUMERIC_FAILURE_STATUS);
    });
    assert!(
        maximum_rounded_oog
            .get(&SyscallMeteringPhase::Arithmetic.tag())
            .is_some_and(|prefixes| prefixes.len() >= 4),
        "maximum scaling, materialization, eleven-limb division, and finalization have distinct OOG boundaries",
    );
    assert!(
        maximum_rounded_oog
            .get(&SyscallMeteringPhase::Normalization.tag())
            .is_some_and(|prefixes| prefixes.len() >= 28),
        "all twenty-eight maximum-width normalization probes have distinct OOG boundaries",
    );
}
#[test]
fn zero_result_uses_the_dedicated_zero_rule_without_normalization_work() {
    let mut vm = vm_for(syscalls::SYSCALL_DECIMAL_ADD, u64::MAX);
    let lhs = install_decimal(&mut vm, &"0.1".parse().expect("lhs"));
    let rhs = install_decimal(&mut vm, &"-0.1".parse().expect("rhs"));
    vm.set_register(10, lhs);
    vm.set_register(11, rhs);
    vm.set_register(14, NUMERIC_FAILURE_TRAP);
    vm.run().expect("zero-producing decimal addition");
    assert_eq!(result_decimal(&vm), Numeric::zero());
    assert_eq!(
        vm.last_staged_syscall_context()
            .expect("zero-result context")
            .phase_charge(SyscallMeteringPhase::Normalization),
        0,
        "(0, scale) canonicalizes directly without a bigint probe"
    );
}
#[test]
fn numeric_failure_paths_charge_completed_work_without_output_and_oog_precedes_controls() {
    for (rhs, expected_fault) in [
        ("0", NumericFaultV1::DivisionByZero),
        ("3", NumericFaultV1::RepeatingDecimal),
    ] {
        let mut vm = vm_for(syscalls::SYSCALL_DECIMAL_DIV_EXACT, u64::MAX);
        let lhs = install_decimal(&mut vm, &Numeric::new(1, 0));
        let rhs = install_decimal(&mut vm, &rhs.parse().expect("rhs"));
        vm.set_register(10, lhs);
        vm.set_register(11, rhs);
        vm.set_register(14, NUMERIC_FAILURE_STATUS);
        vm.run().expect("recoverable exact-division failure");
        let context = vm.last_staged_syscall_context().expect("failure context");
        assert_eq!(
            context.completion(),
            Some(SyscallCompletion::RecoverableFailure)
        );
        assert_eq!(
            context.phase_charge(SyscallMeteringPhase::OutputSerialization),
            0
        );
        assert_eq!(vm.register(10), 0);
        assert_eq!(vm.register(11), expected_fault.tag());
    }
    let mut scale_overflow = vm_for(syscalls::SYSCALL_DECIMAL_DIV_EXACT, u64::MAX);
    let lhs: Numeric = "0.0000000000000000000000000001"
        .parse()
        .expect("scale-28 lhs");
    let lhs = install_decimal(&mut scale_overflow, &lhs);
    let ten = install_decimal(&mut scale_overflow, &Numeric::new(10, 0));
    scale_overflow.set_register(10, lhs);
    scale_overflow.set_register(11, ten);
    scale_overflow.set_register(14, NUMERIC_FAILURE_STATUS);
    scale_overflow.run().expect("recoverable scale overflow");
    let context = scale_overflow
        .last_staged_syscall_context()
        .expect("scale-overflow context");
    assert_eq!(
        context.completion(),
        Some(SyscallCompletion::RecoverableFailure)
    );
    assert_eq!(
        context.phase_charge(SyscallMeteringPhase::OutputSerialization),
        0
    );
    assert_eq!(scale_overflow.register(10), 0);
    assert_eq!(
        scale_overflow.register(11),
        NumericFaultV1::ExactDivisionScaleOverflow.tag(),
    );
    let syscall = syscalls::SYSCALL_DECIMAL_DIV_ROUND;
    let instruction = ivm::cost_of(encoding::wide::encode_syscallx(syscall)).expect("SCALLX gas");
    let mut invalid = vm_for(
        syscall,
        instruction + ivm::numeric_gas::NUMERIC_ENTRY_GAS + 6,
    );
    let lhs = install_decimal(&mut invalid, &Numeric::new(1, 0));
    let rhs = install_decimal(&mut invalid, &Numeric::new(2, 0));
    let scale = install_int(&mut invalid, &BigInt::zero());
    invalid.set_register(10, lhs);
    invalid.set_register(11, rhs);
    invalid.set_register(12, scale);
    invalid.set_register(13, u64::MAX);
    invalid.set_register(14, u64::MAX);
    assert_eq!(
        invalid.run(),
        Err(VMError::SyscallOutOfGas {
            syscall,
            phase: SyscallMeteringPhase::PointerHeader.tag(),
        }),
        "unaffordable operand validation precedes invalid rounding/failure controls",
    );
}
#[test]
fn allocation_failure_is_fully_charged_and_never_publishes_result_registers() {
    let syscall = syscalls::SYSCALL_INT_NEG;
    let mut vm = vm_for(syscall, u64::MAX);
    let operand_envelope = ivm_abi::numeric_tlv::encode_int(&BigInt::one()).expect("operand");
    let operand = vm
        .alloc_host_tlv(&operand_envelope)
        .expect("install operand before filling input");
    let aligned = operand_envelope.len().div_ceil(8) * 8;
    let remaining = usize::try_from(Memory::INPUT_SIZE).expect("input size") - aligned;
    vm.alloc_input_tlv(&vec![0; remaining])
        .expect("fill remaining input exactly");
    vm.memory.set_heap_limit(0).expect("disable heap spill");
    vm.set_register(10, operand);
    vm.set_register(14, NUMERIC_FAILURE_TRAP);
    assert_eq!(vm.run(), Err(VMError::OutOfMemory));
    assert_eq!(vm.register(10), operand);
    let context = vm
        .last_staged_syscall_context()
        .expect("failed staged context");
    assert!(context.phase_charge(SyscallMeteringPhase::OutputSerialization) > 0);
    assert_eq!(context.completion(), Some(SyscallCompletion::Trap));
}

fn run_fused(
    syscall: u32,
    value: &Numeric,
    multiplier: &Numeric,
    divisor: &Numeric,
    scale: u32,
    mode: RoundingModeV1,
) -> IVM {
    let mut vm = vm_for(syscall, u64::MAX);
    let value = if syscall == syscalls::SYSCALL_QUANTITY_MUL_DIV_ROUND {
        install_quantity(
            &mut vm,
            &Quantity::from_canonical_numeric(value.clone()).unwrap(),
        )
    } else {
        install_decimal(&mut vm, value)
    };
    let multiplier = install_decimal(&mut vm, multiplier);
    let divisor = install_decimal(&mut vm, divisor);
    let scale = install_int(&mut vm, &BigInt::from(u64::from(scale)));
    for (register, value) in [value, multiplier, divisor, scale, mode.tag(), 0]
        .into_iter()
        .enumerate()
    {
        vm.set_register(10 + register, value);
    }
    vm.run().expect("fused numeric execution");
    vm
}
#[test]
fn fused_numeric_keeps_overflowing_intermediates_and_rounds_once_in_every_mode() {
    use iroha_primitives::numeric::RoundingMode;
    let maximum = Numeric::new(max_int(), 0);
    for syscall in [
        syscalls::SYSCALL_DECIMAL_MUL_DIV_ROUND,
        syscalls::SYSCALL_QUANTITY_MUL_DIV_ROUND,
    ] {
        let vm = run_fused(
            syscall,
            &maximum,
            &maximum,
            &maximum,
            0,
            RoundingModeV1::Floor,
        );
        let actual = if syscall == syscalls::SYSCALL_DECIMAL_MUL_DIV_ROUND {
            result_decimal(&vm)
        } else {
            result_quantity(&vm).into_numeric()
        };
        assert_eq!(actual, maximum);
        for (tag, mode) in [
            (RoundingModeV1::TowardZero, RoundingMode::TowardZero),
            (RoundingModeV1::AwayFromZero, RoundingMode::AwayFromZero),
            (RoundingModeV1::Floor, RoundingMode::Floor),
            (RoundingModeV1::Ceil, RoundingMode::Ceil),
            (RoundingModeV1::NearestEven, RoundingMode::NearestEven),
            (RoundingModeV1::NearestAway, RoundingMode::NearestAway),
            (
                RoundingModeV1::NearestTowardZero,
                RoundingMode::NearestTowardZero,
            ),
        ] {
            let value: Numeric = "7.13".parse().unwrap();
            let multiplier: Numeric = "1.17".parse().unwrap();
            let divisor: Numeric = "3".parse().unwrap();
            let expected = value
                .try_decimal_mul_div_round(&multiplier, &divisor, 2, mode)
                .unwrap();
            let vm = run_fused(syscall, &value, &multiplier, &divisor, 2, tag);
            let actual = if syscall == syscalls::SYSCALL_DECIMAL_MUL_DIV_ROUND {
                result_decimal(&vm)
            } else {
                result_quantity(&vm).into_numeric()
            };
            assert_eq!(actual, expected, "{syscall:#x} {tag:?}");
            assert!(vm.last_staged_syscall_context().unwrap().charged() > 0);
        }
    }
}
#[test]
fn fused_numeric_gas_exhaustion_is_fatal_before_unfunded_work() {
    let phases = collect_oog_prefixes(syscalls::SYSCALL_DECIMAL_MUL_DIV_ROUND, |vm| {
        let value = install_decimal(vm, &"11.23".parse().unwrap());
        let multiplier = install_decimal(vm, &"17.4".parse().unwrap());
        let divisor = install_decimal(vm, &"7".parse().unwrap());
        let scale = install_int(vm, &BigInt::from(2_u64));
        for (register, value) in [
            value,
            multiplier,
            divisor,
            scale,
            RoundingModeV1::NearestEven.tag(),
            0,
        ]
        .into_iter()
        .enumerate()
        {
            vm.set_register(10 + register, value);
        }
    });
    assert!(!phases.is_empty());
}

#[test]
fn integer_helpers_cover_full_width_results_and_staged_failures() {
    use iroha_primitives::numeric_int::{IntBinaryOperation, IntUnaryOperation};
    let maximum = max_int();
    let minimum = min_int();
    for (syscall, operation) in [
        (syscalls::SYSCALL_INT_ISQRT, IntUnaryOperation::Isqrt),
        (syscalls::SYSCALL_INT_ABS, IntUnaryOperation::Abs),
    ] {
        let mut vm = vm_for(syscall, u64::MAX);
        let pointer = install_int(&mut vm, &maximum);
        vm.set_register(10, pointer);
        vm.run().expect("full-width unary helper");
        assert_eq!(result_int(&vm), operation.evaluate(&maximum).unwrap());
        let prefixes = collect_oog_prefixes(syscall, |vm| {
            let pointer = install_int(vm, &BigInt::from(17_u64));
            vm.set_register(10, pointer);
        });
        assert!(prefixes[&SyscallMeteringPhase::Arithmetic.tag()].len() >= 2);
    }
    for (syscall, operation, left, right) in [
        (
            syscalls::SYSCALL_INT_MIN,
            IntBinaryOperation::Min,
            &minimum,
            &maximum,
        ),
        (
            syscalls::SYSCALL_INT_MAX,
            IntBinaryOperation::Max,
            &minimum,
            &maximum,
        ),
        (
            syscalls::SYSCALL_INT_DIV_CEIL,
            IntBinaryOperation::DivCeil,
            &maximum,
            &maximum,
        ),
        (
            syscalls::SYSCALL_INT_GCD,
            IntBinaryOperation::Gcd,
            &minimum,
            &maximum,
        ),
        (
            syscalls::SYSCALL_INT_MEAN,
            IntBinaryOperation::Mean,
            &maximum,
            &maximum,
        ),
    ] {
        let mut vm = vm_for(syscall, u64::MAX);
        let left_pointer = install_int(&mut vm, left);
        let right_pointer = install_int(&mut vm, right);
        vm.set_register(10, left_pointer);
        vm.set_register(11, right_pointer);
        vm.run().expect("full-width binary helper");
        assert_eq!(result_int(&vm), operation.evaluate(left, right).unwrap());
        let prefixes = collect_oog_prefixes(syscall, |vm| {
            let left = install_int(vm, &BigInt::from(17_u64));
            let right = install_int(vm, &BigInt::from(6_u64));
            vm.set_register(10, left);
            vm.set_register(11, right);
        });
        assert!(prefixes[&SyscallMeteringPhase::Arithmetic.tag()].len() >= 2);
    }
    for (syscall, left, right, fault) in [
        (
            syscalls::SYSCALL_INT_ISQRT,
            BigInt::from(-1_i64),
            None,
            NumericFaultV1::NegativeSquareRoot,
        ),
        (
            syscalls::SYSCALL_INT_ABS,
            minimum.clone(),
            None,
            NumericFaultV1::MantissaOverflow,
        ),
        (
            syscalls::SYSCALL_INT_DIV_CEIL,
            maximum,
            Some(BigInt::zero()),
            NumericFaultV1::DivisionByZero,
        ),
        (
            syscalls::SYSCALL_INT_DIV_CEIL,
            minimum.clone(),
            Some(BigInt::from(-1_i64)),
            NumericFaultV1::MantissaOverflow,
        ),
        (
            syscalls::SYSCALL_INT_GCD,
            minimum,
            Some(BigInt::zero()),
            NumericFaultV1::MantissaOverflow,
        ),
    ] {
        for mode in [NUMERIC_FAILURE_TRAP, NUMERIC_FAILURE_STATUS] {
            let mut vm = vm_for(syscall, u64::MAX);
            let pointer = install_int(&mut vm, &left);
            vm.set_register(10, pointer);
            if let Some(right) = &right {
                let pointer = install_int(&mut vm, right);
                vm.set_register(11, pointer);
            }
            vm.set_register(14, mode);
            if mode == NUMERIC_FAILURE_TRAP {
                assert_eq!(vm.run(), Err(VMError::NumericFault(fault)));
                assert_eq!(vm.register(10), pointer);
            } else {
                vm.run().expect("reported numeric domain failure");
                assert_eq!(vm.register(10), 0);
                assert_eq!(vm.register(11), fault.tag());
            }
        }
    }
}

// The work vectors below are independently enumerated from the V1 event rules.
// This helper never calls numeric_int or numeric_gas to derive expected charges.
fn assert_int_helper_gas_boundaries(
    syscall: u32,
    left: &BigInt,
    right: Option<&BigInt>,
    arithmetic_steps: &[u64],
    expected: Result<(&BigInt, u64), NumericFaultV1>,
) {
    for mode in [NUMERIC_FAILURE_TRAP, NUMERIC_FAILURE_STATUS] {
        let mut vm = vm_for(syscall, u64::MAX);
        let left_pointer = install_int(&mut vm, left);
        vm.set_register(10, left_pointer);
        let mut input_frames = vec![envelope_len(&vm, left_pointer) - 39];
        if let Some(right) = right {
            let pointer = install_int(&mut vm, right);
            vm.set_register(11, pointer);
            input_frames.push(envelope_len(&vm, pointer) - 39);
        }
        vm.set_register(14, mode);
        let original = [10, 11, 12, 13, 14].map(|register| vm.register(register));
        let template = vm.try_runtime_template().expect("pristine helper template");
        let outcome = vm.run();
        let arithmetic_work = arithmetic_steps.iter().sum::<u64>();
        // Entry=384; each operand pays header=7, frame snapshot, digest=32+frame,
        // full eight-byte frame scan, then the body scan after the fixed 40-byte header.
        let decode_charge = 384
            + input_frames
                .iter()
                .map(|&frame| {
                    7 + frame
                        + 32
                        + frame
                        + 4 * frame.div_ceil(8).max(1)
                        + 4 * (frame - 40).div_ceil(8).max(1)
                })
                .sum::<u64>();
        let output_charge = match expected {
            Ok((value, output_limbs)) => {
                assert_eq!(outcome, Ok(()));
                assert_eq!(result_int(&vm), *value);
                assert_eq!(vm.register(11), 0);
                let bytes = envelope_len(&vm, vm.register(10));
                4 * output_limbs + bytes + 2 * (bytes - 39)
            }
            Err(fault) => {
                if mode == NUMERIC_FAILURE_TRAP {
                    assert_eq!(outcome, Err(VMError::NumericFault(fault)));
                    assert_eq!(vm.register(10), original[0]);
                    assert_eq!(vm.register(11), original[1]);
                } else {
                    assert_eq!(outcome, Ok(()));
                    assert_eq!(vm.register(10), 0);
                    assert_eq!(vm.register(11), fault.tag());
                }
                0
            }
        };
        let context = vm.last_staged_syscall_context().expect("helper context");
        assert_eq!(context.phase_charge(SyscallMeteringPhase::Entry), 384);
        assert_eq!(
            context.phase_charge(SyscallMeteringPhase::Arithmetic),
            4 * arithmetic_work
        );
        assert_eq!(context.phase_charge(SyscallMeteringPhase::Normalization), 0);
        assert_eq!(
            context.phase_charge(SyscallMeteringPhase::OutputSerialization),
            output_charge
        );
        assert_eq!(
            context.charged(),
            decode_charge + 4 * arithmetic_work + output_charge
        );
        assert_eq!(
            context.completion(),
            Some(match expected {
                Ok(_) => SyscallCompletion::Success,
                Err(_) if mode == NUMERIC_FAILURE_STATUS => SyscallCompletion::RecoverableFailure,
                Err(_) => SyscallCompletion::Trap,
            })
        );
        assert_eq!(
            ivm::cost_of(encoding::wide::encode_syscallx(syscall)),
            Some(5)
        );
        // One gas unit short of each independently known event must trap before
        // that event. Even Status mode cannot turn an observer refusal into a result.
        let mut completed_work = 0;
        for &next_work in arithmetic_steps {
            assert!(next_work > 0);
            let gas = 5 + decode_charge + 4 * (completed_work + next_work) - 1;
            vm.reset_from_runtime_template(&template)
                .expect("restore same initialized operands");
            vm.set_gas_limit(gas);
            assert_eq!(
                vm.run(),
                Err(VMError::SyscallOutOfGas {
                    syscall,
                    phase: SyscallMeteringPhase::Arithmetic.tag(),
                })
            );
            assert_eq!(
                [10, 11, 12, 13, 14].map(|register| vm.register(register)),
                original,
                "no result/status/control publication on observer refusal"
            );
            let stopped = vm.last_staged_syscall_context().expect("refused context");
            assert_eq!(stopped.completion(), Some(SyscallCompletion::Trap));
            assert_eq!(
                stopped.phase_charge(SyscallMeteringPhase::Arithmetic),
                4 * completed_work
            );
            assert_eq!(stopped.charged(), decode_charge + 4 * completed_work);
            assert_eq!(
                stopped.phase_charge(SyscallMeteringPhase::OutputSerialization),
                0
            );
            assert_eq!(gas - vm.remaining_gas(), 5 + stopped.charged());
            completed_work += next_work;
        }
    }
}

#[test]
fn integer_helper_gas_vectors_pin_independent_steps_and_fault_prefixes() {
    let zero = BigInt::zero();
    let two = BigInt::from(2_u64);
    let maximum = max_int();
    let minimum = min_int();
    for value in [BigInt::from(17_u64), BigInt::from(-17_i64)] {
        assert_int_helper_gas_boundaries(
            syscalls::SYSCALL_INT_ABS,
            &value,
            None,
            &[1, 1, 1], // input Finalize, Materialize/Negate, result Finalize
            Ok((&BigInt::from(17_u64), 1)),
        );
    }
    assert_int_helper_gas_boundaries(
        syscalls::SYSCALL_INT_ABS,
        &minimum,
        None,
        &[8, 8, 8],
        Err(NumericFaultV1::MantissaOverflow),
    );
    assert_int_helper_gas_boundaries(
        syscalls::SYSCALL_INT_ISQRT,
        &zero,
        None,
        &[1, 1, 1],
        Ok((&zero, 1)),
    );
    assert_int_helper_gas_boundaries(
        syscalls::SYSCALL_INT_ISQRT,
        &BigInt::from(-1_i64),
        None,
        &[1],
        Err(NumericFaultV1::NegativeSquareRoot),
    );
    assert_int_helper_gas_boundaries(
        syscalls::SYSCALL_INT_ISQRT,
        &BigInt::from(17_u64),
        None,
        // Seed 8; descending roots 5,4,4. Each iteration pays QR=5,
        // Add=1, QR(/2)=5 and Compare=1; input/seed/final each cost 1.
        &[1, 1, 5, 1, 5, 1, 5, 1, 5, 1, 5, 1, 5, 1, 1],
        Ok((&BigInt::from(4_u64), 1)),
    );
    for (syscall, result, result_limbs) in [
        (syscalls::SYSCALL_INT_MIN, &minimum, 9),
        (syscalls::SYSCALL_INT_MAX, &maximum, 8),
    ] {
        assert_int_helper_gas_boundaries(
            syscall,
            &minimum,
            Some(&maximum),
            &[8, 8, 8, 8, 8], // input scans, compare, selected copy, final scan
            Ok((result, result_limbs)),
        );
    }
    for (left, right, result, steps) in [
        (7, 2, 4, &[1, 1, 5, 1, 1][..]),
        (-7, -2, 4, &[1, 1, 5, 1, 1][..]),
        (-7, 2, -3, &[1, 1, 5, 1][..]),
        (7, -2, -3, &[1, 1, 5, 1][..]),
    ] {
        assert_int_helper_gas_boundaries(
            syscalls::SYSCALL_INT_DIV_CEIL,
            &BigInt::from(left),
            Some(&BigInt::from(right)),
            steps,
            Ok((&BigInt::from(result), 1)),
        );
    }
    assert_int_helper_gas_boundaries(
        syscalls::SYSCALL_INT_DIV_CEIL,
        &maximum,
        Some(&zero),
        &[8, 1], // zero divisor stops before any QR work
        Err(NumericFaultV1::DivisionByZero),
    );
    assert_int_helper_gas_boundaries(
        syscalls::SYSCALL_INT_DIV_CEIL,
        &minimum,
        Some(&BigInt::from(-1_i64)),
        &[8, 1, 33, 8], // QR(8,1)=17+8+8; final positive 2^511 scan refuses
        Err(NumericFaultV1::MantissaOverflow),
    );
    assert_int_helper_gas_boundaries(
        syscalls::SYSCALL_INT_GCD,
        &minimum,
        Some(&zero),
        &[8, 1, 8, 1, 8],
        Err(NumericFaultV1::MantissaOverflow),
    );
    assert_int_helper_gas_boundaries(
        syscalls::SYSCALL_INT_GCD,
        &minimum,
        Some(&minimum),
        &[8, 8, 8, 8, 40, 8], // QR(8,8)=24+8+8
        Err(NumericFaultV1::MantissaOverflow),
    );
    assert_int_helper_gas_boundaries(
        syscalls::SYSCALL_INT_GCD,
        &minimum,
        Some(&two),
        &[8, 1, 8, 1, 33, 1],
        Ok((&two, 1)),
    );
    let wide = "340282366920938463463374607431768211457"
        .parse::<BigInt>()
        .unwrap();
    let divisor = "18446744073709551616".parse::<BigInt>().unwrap();
    assert_int_helper_gas_boundaries(
        syscalls::SYSCALL_INT_GCD,
        &wide,
        Some(&divisor),
        // (2^128+1) mod 2^64 = 1, then 2^64 mod 1 = 0;
        // QR(3,2)=9+4+3=16 and QR(2,1)=5+2+2=9.
        &[3, 2, 3, 2, 16, 9, 1],
        Ok((&BigInt::one(), 1)),
    );
    for (value, steps, output_limbs) in [
        (&maximum, &[8, 8, 8, 33, 8][..], 8),
        (&minimum, &[8, 8, 8, 37, 8][..], 9),
    ] {
        assert_int_helper_gas_boundaries(
            syscalls::SYSCALL_INT_MEAN,
            value,
            Some(value),
            // MIN+MIN has a nine-limb magnitude before division; MAX+MAX has eight.
            steps,
            Ok((value, output_limbs)),
        );
    }
    assert_int_helper_gas_boundaries(
        syscalls::SYSCALL_INT_MEAN,
        &BigInt::from(-7_i64),
        Some(&two),
        &[1, 1, 1, 5, 1],
        Ok((&BigInt::from(-2_i64), 1)),
    );
}

#[test]
fn borrowed_numeric_outputs_keep_exact_frames_and_both_output_refusal_boundaries() {
    use ivm::PointerType;
    let mut maximum = vec![0xff; 64];
    maximum[63] = 0x7f;
    let mut minimum = vec![0; 64];
    minimum[63] = 0x80;
    // Literal bodies and output-debit pairs come from the V1 wire/gas equations,
    // independently of prepare_frame, numeric_gas and the candidate serializers.
    let cases = [
        (
            syscalls::SYSCALL_INT_FROM_I64,
            PointerType::Int,
            vec![],
            None,
            44,
            83,
            4,
            171,
        ),
        (
            syscalls::SYSCALL_INT_MAX,
            PointerType::Int,
            maximum.clone(),
            None,
            108,
            147,
            32,
            363,
        ),
        (
            syscalls::SYSCALL_INT_MIN,
            PointerType::Int,
            minimum.clone(),
            None,
            108,
            147,
            36,
            363,
        ),
        (
            syscalls::SYSCALL_DECIMAL_FROM_INT,
            PointerType::Decimal,
            vec![],
            Some(0),
            45,
            84,
            4,
            174,
        ),
        (
            syscalls::SYSCALL_QUANTITY_FROM_INT,
            PointerType::Quantity,
            vec![],
            Some(0),
            45,
            84,
            4,
            174,
        ),
        (
            syscalls::SYSCALL_DECIMAL_FROM_INT,
            PointerType::Decimal,
            maximum.clone(),
            Some(0),
            109,
            148,
            32,
            366,
        ),
        (
            syscalls::SYSCALL_DECIMAL_FROM_INT,
            PointerType::Decimal,
            minimum,
            Some(0),
            109,
            148,
            36,
            366,
        ),
        (
            syscalls::SYSCALL_QUANTITY_FROM_INT,
            PointerType::Quantity,
            maximum,
            Some(0),
            109,
            148,
            32,
            366,
        ),
        (
            syscalls::SYSCALL_DECIMAL_NEG,
            PointerType::Decimal,
            vec![0xff],
            Some(28),
            46,
            85,
            4,
            177,
        ),
        (
            syscalls::SYSCALL_QUANTITY_FROM_DECIMAL,
            PointerType::Quantity,
            vec![1],
            Some(28),
            46,
            85,
            4,
            177,
        ),
    ];
    for (syscall, pointer_type, bytes, scale, frame_bytes, envelope_bytes, probe, byte_debit) in
        cases
    {
        let mut body = (bytes.len() as u32).to_le_bytes().to_vec();
        body.extend_from_slice(&bytes);
        if let Some(scale) = scale {
            body.push(scale);
        }
        let frame = match pointer_type {
            PointerType::Int => norito::core::frame_bare_with_header_flags::<IntValueV1>(&body, 0),
            PointerType::Decimal => {
                norito::core::frame_bare_with_header_flags::<DecimalValueV1>(&body, 0)
            }
            PointerType::Quantity => {
                norito::core::frame_bare_with_header_flags::<QuantityValueV1>(&body, 0)
            }
            _ => unreachable!("closed nominal numeric fixtures"),
        }
        .unwrap();
        let expected_envelope = numeric_envelope_from_frame(pointer_type, &frame);
        assert_eq!(frame.len() as u64, frame_bytes);
        assert_eq!(expected_envelope.len() as u64, envelope_bytes);
        assert_eq!(byte_debit, envelope_bytes + 2 * frame_bytes);
        for mode in [NUMERIC_FAILURE_TRAP, NUMERIC_FAILURE_STATUS] {
            let mut vm = vm_for(syscall, u64::MAX);
            match syscall {
                syscalls::SYSCALL_INT_FROM_I64 => vm.set_register(10, 0),
                syscalls::SYSCALL_DECIMAL_NEG | syscalls::SYSCALL_QUANTITY_FROM_DECIMAL => {
                    let source = Numeric::try_new(1, 28).unwrap();
                    let pointer = install_decimal(&mut vm, &source);
                    vm.set_register(10, pointer);
                }
                _ => {
                    let source = BigInt::from_twos_bytes(&bytes).unwrap();
                    let pointer = install_int(&mut vm, &source);
                    vm.set_register(10, pointer);
                    if matches!(
                        syscall,
                        syscalls::SYSCALL_INT_MIN | syscalls::SYSCALL_INT_MAX
                    ) {
                        let right = install_int(&mut vm, &BigInt::zero());
                        vm.set_register(11, right);
                    }
                }
            }
            vm.set_register(14, mode);
            let original = [10, 11, 12, 13, 14].map(|register| vm.register(register));
            let template = vm
                .try_runtime_template()
                .expect("original numeric input/template owner");
            assert_eq!(vm.run(), Ok(()));
            assert_eq!(vm.register(11), 0);
            assert_eq!(vm.validate_tlv(vm.register(10)).unwrap().payload, &frame);
            assert_eq!(
                vm.memory
                    .load_region(vm.register(10), envelope_bytes)
                    .unwrap(),
                expected_envelope
            );
            let context = vm.last_staged_syscall_context().unwrap().clone();
            assert_eq!(context.completion(), Some(SyscallCompletion::Success));
            assert_eq!(
                context.phase_charge(SyscallMeteringPhase::OutputSerialization),
                probe + byte_debit
            );
            let instruction = ivm::cost_of(encoding::wide::encode_syscallx(syscall)).unwrap();
            let prior_stages = context.charged() - probe - byte_debit;
            for (completed_output, next_debit) in [(0, probe), (probe, byte_debit)] {
                let gas = instruction + prior_stages + completed_output + next_debit - 1;
                vm.reset_from_runtime_template(&template)
                    .expect("same original input custody");
                vm.set_gas_limit(gas);
                assert_eq!(
                    vm.run(),
                    Err(VMError::SyscallOutOfGas {
                        syscall,
                        phase: SyscallMeteringPhase::OutputSerialization.tag()
                    })
                );
                assert_eq!(
                    [10, 11, 12, 13, 14].map(|register| vm.register(register)),
                    original,
                    "output observer refusal preserves result/status/control registers"
                );
                let stopped = vm.last_staged_syscall_context().unwrap();
                assert_eq!(stopped.completion(), Some(SyscallCompletion::Trap));
                assert_eq!(
                    stopped.phase_charge(SyscallMeteringPhase::OutputSerialization),
                    completed_output
                );
                assert_eq!(stopped.charged(), prior_stages + completed_output);
                assert_eq!(gas - vm.remaining_gas(), instruction + stopped.charged());
            }
        }
    }
}

#[test]
fn conversions_preserve_exact_faults_and_output_in_both_failure_modes() {
    for (syscall, fault) in [
        (
            syscalls::SYSCALL_INT_TO_I64,
            NumericFaultV1::InexactConversion,
        ),
        (
            syscalls::SYSCALL_INT_TO_U64,
            NumericFaultV1::InexactConversion,
        ),
        (
            syscalls::SYSCALL_DECIMAL_TO_INT_EXACT,
            NumericFaultV1::InexactConversion,
        ),
        (
            syscalls::SYSCALL_QUANTITY_FROM_INT,
            NumericFaultV1::NegativeQuantity,
        ),
        (
            syscalls::SYSCALL_QUANTITY_FROM_DECIMAL,
            NumericFaultV1::NegativeQuantity,
        ),
    ] {
        let mut arithmetic = None;
        for mode in [NUMERIC_FAILURE_TRAP, NUMERIC_FAILURE_STATUS] {
            let mut vm = vm_for(syscall, u64::MAX);
            let input = match syscall {
                syscalls::SYSCALL_INT_TO_I64 => install_int(&mut vm, &max_int()),
                syscalls::SYSCALL_INT_TO_U64 | syscalls::SYSCALL_QUANTITY_FROM_INT => {
                    install_int(&mut vm, &BigInt::from_i128(-1))
                }
                syscalls::SYSCALL_DECIMAL_TO_INT_EXACT => {
                    install_decimal(&mut vm, &Numeric::new(15, 1))
                }
                _ => install_decimal(&mut vm, &Numeric::new(-1, 0)),
            };
            let output_before = vm.memory.output_used_len();
            vm.set_register(10, input);
            vm.set_register(14, mode);
            if mode == NUMERIC_FAILURE_TRAP {
                assert_eq!(vm.run(), Err(VMError::NumericFault(fault)), "{syscall:#x}");
                assert_eq!(vm.register(10), input);
                assert_eq!(vm.register(11), 0);
            } else {
                vm.run().expect("status conversion failure");
                assert_eq!(vm.register(10), 0);
                assert_eq!(vm.register(11), fault.tag());
                assert_eq!(
                    vm.last_staged_syscall_context().unwrap().completion(),
                    Some(SyscallCompletion::RecoverableFailure)
                );
            }
            assert_eq!(vm.memory.output_used_len(), output_before);
            let work = vm
                .last_staged_syscall_context()
                .unwrap()
                .phase_charge(SyscallMeteringPhase::Arithmetic);
            assert!(work > 0);
            if let Some(previous) = arithmetic {
                assert_eq!(work, previous);
            }
            arithmetic = Some(work);
        }
    }
}

#[test]
fn conversion_modes_and_reserved_registers_fail_after_authentication_before_arithmetic() {
    for syscall in [
        syscalls::SYSCALL_INT_TO_I64,
        syscalls::SYSCALL_INT_TO_U64,
        syscalls::SYSCALL_DECIMAL_TO_INT_EXACT,
        syscalls::SYSCALL_QUANTITY_FROM_INT,
        syscalls::SYSCALL_QUANTITY_FROM_DECIMAL,
    ] {
        let mut wrong_type = vm_for(syscall, u64::MAX);
        let wrong_input = if matches!(
            syscall,
            syscalls::SYSCALL_INT_TO_I64
                | syscalls::SYSCALL_INT_TO_U64
                | syscalls::SYSCALL_QUANTITY_FROM_INT
        ) {
            install_decimal(&mut wrong_type, &Numeric::one())
        } else {
            install_int(&mut wrong_type, &BigInt::one())
        };
        wrong_type.set_register(10, wrong_input);
        wrong_type.set_register(11, 2);
        wrong_type.set_register(14, 2);
        assert_eq!(
            wrong_type.run(),
            Err(VMError::PointerAbiFault(PointerAbiFaultV1::WrongType))
        );
        assert_eq!(wrong_type.register(10), wrong_input);
        for invalid_register in [11, 12, 13, 14] {
            let mut vm = vm_for(syscall, u64::MAX);
            let input = if matches!(
                syscall,
                syscalls::SYSCALL_INT_TO_I64
                    | syscalls::SYSCALL_INT_TO_U64
                    | syscalls::SYSCALL_QUANTITY_FROM_INT
            ) {
                install_int(&mut vm, &BigInt::one())
            } else {
                install_decimal(&mut vm, &Numeric::one())
            };
            vm.set_register(10, input);
            vm.set_register(invalid_register, 2);
            let before = vm.memory.output_used_len();
            let expected = if invalid_register == 14 {
                NumericFaultV1::InvalidFailureMode
            } else {
                NumericFaultV1::ReservedRegisterNonZero
            };
            assert_eq!(
                vm.run(),
                Err(VMError::NumericFault(expected)),
                "{syscall:#x}"
            );
            assert_eq!(vm.register(10), input);
            assert_eq!(vm.memory.output_used_len(), before);
            assert_eq!(
                vm.last_staged_syscall_context()
                    .unwrap()
                    .phase_charge(SyscallMeteringPhase::Arithmetic),
                0
            );
        }
    }
}
