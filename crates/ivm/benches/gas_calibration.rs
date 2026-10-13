//! Microbenchmarks to relate IVM runtime latency with the gas schedule.
//!
//! For each selected instruction, this bench:
//! - Builds a tiny program that repeats the instruction `N` times then HALTs.
//! - Runs the program in the VM and measures elapsed time.
//! - Reads gas consumed from the VM and prints `ns/op`, `gas/op`, and `ns/gas`.
//!
//! Use output to calibrate a target `ns_per_gas` scalar for your baseline CPU and
//! to tune `ivm_gas_limit_per_block` for a desired block time (e.g., ~200 ms).
use criterion::{BatchSize, BenchmarkId, Criterion};
use iroha_primitives::{
    bigint::BigInt,
    numeric::{
        Numeric, NumericOperationError, NumericWorkStep, ObservedNumericError, RoundingMode,
    },
};
use ivm::{
    IVM, ProgramMetadata, VMError, encoding, host::DefaultHost, instruction,
    numeric::PointerAbiFaultV1,
};
// Assemble header + code (mode=0, max_cycles=0, abi=1) — copied from tests/common.rs
fn assemble(code: &[u8]) -> Vec<u8> {
    let mut v = ProgramMetadata {
        version_major: 1,
        version_minor: 1,
        mode: 0,
        vector_length: 0,
        max_cycles: 0,
        abi_version: 1,
    }
    .encode();
    v.extend_from_slice(code);
    v
}
fn program_for_repeated(instr: u32, reps: usize) -> Vec<u8> {
    let mut code = Vec::with_capacity(4 * (reps + 1));
    for _ in 0..reps {
        code.extend_from_slice(&instr.to_le_bytes());
    }
    code.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());
    assemble(&code)
}
fn bench_instr(c: &mut Criterion, name: &str, instr: u32, reps: usize) {
    let code = program_for_repeated(instr, reps);
    let mut group = c.benchmark_group("ivm-gas-cal");
    group.bench_function(name, |b| {
        b.iter_batched(
            || {
                let mut vm = IVM::new(1_000_000_000);
                vm.load_program(&code).expect("load program");
                // Seed registers used by our wide templates (rs1=1, rs2=2) to
                // avoid traps like divide-by-zero in DIVU during warmup.
                vm.registers.set(1, 123);
                vm.registers.set(2, 7);
                vm
            },
            |mut vm| {
                let start_remaining = vm.remaining_gas();
                vm.run().expect("run");
                let used = start_remaining - vm.remaining_gas();
                let _gas_per_op = used as f64 / reps as f64;
            },
            BatchSize::SmallInput,
        )
    });
    group.finish();
}
fn bench_empty_harness(c: &mut Criterion) {
    let code = program_for_repeated(0, 0);
    let mut group = c.benchmark_group("ivm-gas-cal");
    group.bench_function("EMPTY_HARNESS", |b| {
        b.iter_batched(
            || {
                let mut vm = IVM::new(1_000_000_000);
                vm.load_program(&code)
                    .expect("load empty calibration program");
                vm
            },
            |mut vm| {
                let start_remaining = vm.remaining_gas();
                vm.run().expect("run empty calibration program");
                std::hint::black_box(start_remaining - vm.remaining_gas());
            },
            BatchSize::SmallInput,
        )
    });
    group.finish();
}
fn positive_with_limbs(limbs: usize, low: u8) -> BigInt {
    let mut bytes = vec![0_u8; limbs * 8];
    bytes[0] = low;
    *bytes.last_mut().expect("at least one limb") = 0x3f;
    BigInt::from_twos_bytes(&bytes).expect("calibration operand fits generic bigint")
}
fn wrap_v1(value: &BigInt) -> BigInt {
    let source = value.to_twos_bytes();
    let extension = if value.is_negative() { 0xff } else { 0x00 };
    let mut low = vec![extension; iroha_primitives::numeric::MAX_MANTISSA_BYTES];
    let copied = source.len().min(low.len());
    low[..copied].copy_from_slice(&source[..copied]);
    BigInt::from_twos_bytes(&low).expect("V1 reduction is representable")
}
fn bench_numeric_limb_work(c: &mut Criterion) {
    let mut group = c.benchmark_group("ivm-numeric-limb-cal");
    let entry_instruction = encoding::wide::encode_syscallx(ivm::syscalls::SYSCALL_INT_NEG);
    let mut entry_program = ProgramMetadata::default_for(1, 1, 1).encode();
    entry_program.extend_from_slice(&entry_instruction.to_le_bytes());
    entry_program.extend_from_slice(&encoding::wide::encode_halt().to_le_bytes());
    // Keep the benchmark denominator scoped to the staged numeric lifecycle.
    // The VM additionally charges the generic SCALLX opcode, which is asserted
    // below but deliberately excluded from the numeric-constant calibration.
    let staged_entry_failure_gas =
        ivm::numeric_gas::NUMERIC_ENTRY_GAS + ivm::numeric_gas::POINTER_HEADER_BYTES;
    let total_entry_failure_gas = staged_entry_failure_gas
        + ivm::gas::cost_of(entry_instruction).expect("SCALLX has a gas schedule entry");
    {
        let mut vm = IVM::new(u64::MAX);
        vm.load_program(&entry_program)
            .expect("load numeric entry calibration proof");
        vm.set_host(DefaultHost::new());
        let start_remaining = vm.remaining_gas();
        assert!(
            matches!(vm.run(), Err(VMError::PointerAbiFault(__actual_error_field)) if __actual_error_field == (PointerAbiFaultV1::InvalidAddress))
        );
        assert_eq!(
            start_remaining - vm.remaining_gas(),
            total_entry_failure_gas
        );
    }
    group.bench_with_input(
        BenchmarkId::new(
            "entry_control_pipeline",
            format!("gas={staged_entry_failure_gas}"),
        ),
        &total_entry_failure_gas,
        |b, expected_total_gas| {
            b.iter_batched(
                || {
                    let mut vm = IVM::new(u64::MAX);
                    vm.load_program(&entry_program)
                        .expect("load numeric entry calibration program");
                    vm.set_host(DefaultHost::new());
                    vm
                },
                |mut vm| {
                    let start_remaining = vm.remaining_gas();
                    let _ = std::hint::black_box(vm.run());
                    std::hint::black_box((
                        start_remaining - vm.remaining_gas(),
                        expected_total_gas,
                    ));
                },
                BatchSize::SmallInput,
            );
        },
    );
    for limbs in 1_usize..=8 {
        let lhs = positive_with_limbs(limbs, 0x5b);
        let rhs = positive_with_limbs(limbs, 0x13);
        let checked_add_work = ivm::numeric_gas::checked_int_additive_work(
            u64::try_from(limbs).expect("limb count"),
            u64::try_from(limbs).expect("limb count"),
        )
        .expect("bounded checked-add work");
        group.bench_with_input(
            BenchmarkId::new(
                "checked_add",
                format!("limbs={limbs};work={checked_add_work}"),
            ),
            &limbs,
            |b, _| {
                b.iter(|| {
                    let result = lhs.checked_add(&rhs).expect("calibration addition fits");
                    std::hint::black_box(result.twos_byte_len());
                    std::hint::black_box(result)
                });
            },
        );
        let checked_multiplication_work = ivm::numeric_gas::checked_int_multiplication_work(
            u64::try_from(limbs).expect("limb count"),
            u64::try_from(limbs).expect("limb count"),
        )
        .expect("bounded checked-multiplication work");
        group.bench_with_input(
            BenchmarkId::new(
                "checked_multiply",
                format!("limbs={limbs};work={checked_multiplication_work}"),
            ),
            &limbs,
            |b, _| {
                b.iter(|| {
                    let result = lhs
                        .checked_mul(&rhs)
                        .expect("512-bit inputs fit the generic product domain");
                    std::hint::black_box(result.twos_byte_len());
                    std::hint::black_box(result)
                });
            },
        );
        let division_work = ivm::numeric_gas::checked_int_division_work(
            u64::try_from(limbs).expect("limb count"),
            u64::try_from(limbs).expect("limb count"),
        )
        .expect("bounded division work");
        group.bench_with_input(
            BenchmarkId::new(
                "divide_remainder",
                format!("limbs={limbs};work={division_work}"),
            ),
            &limbs,
            |b, _| {
                b.iter(|| {
                    let (quotient, remainder) = lhs
                        .checked_div_rem(&rhs)
                        .expect("nonzero calibration divisor");
                    std::hint::black_box(quotient.twos_byte_len());
                    std::hint::black_box(remainder.twos_byte_len());
                    std::hint::black_box((quotient, remainder))
                });
            },
        );
    }
    let wrapping_lhs = positive_with_limbs(8, 0x5b);
    let wrapping_rhs = positive_with_limbs(8, 0x13);
    let wrapping_intermediate = wrapping_lhs
        .checked_mul(&wrapping_rhs)
        .expect("512-bit inputs fit the generic product domain");
    let source_limbs = ivm::numeric_gas::limbs_for_bits(
        u64::try_from(wrapping_intermediate.bit_len()).expect("bounded bit width") + 1,
    );
    let wrapping_work = ivm::numeric_gas::wrapping_multiplication_work(8, 8)
        .and_then(|work| {
            ivm::numeric_gas::wrapping_reduction_work(source_limbs)
                .and_then(|reduction| ivm::numeric_gas::checked_add(work, reduction))
        })
        .expect("bounded wrapping work");
    group.bench_with_input(
        BenchmarkId::new(
            "wrapping_multiply",
            format!("limbs=8;source_limbs={source_limbs};work={wrapping_work}"),
        ),
        &wrapping_work,
        |b, _| {
            b.iter(|| {
                let intermediate = wrapping_lhs
                    .checked_mul(&wrapping_rhs)
                    .expect("512-bit inputs fit the generic product domain");
                std::hint::black_box(wrap_v1(&intermediate))
            });
        },
    );
    let one: Numeric = "1".parse().expect("decimal one");
    let seven: Numeric = "7".parse().expect("decimal seven");
    let mut rounded_division_work =
        ivm::numeric_gas::scale_work(1, 28).expect("bounded scale work");
    for work in [
        ivm::numeric_gas::materialization_work(1),
        ivm::numeric_gas::rounded_division_work(2, 1).expect("bounded rounded division"),
        // The scale-28 result is noncanonical until one failed divide-by-ten
        // normalization probe confirms its last digit.
        ivm::numeric_gas::quotient_remainder_work(2, 1).expect("bounded normalization"),
        ivm::numeric_gas::finalization_work(2),
    ] {
        rounded_division_work =
            ivm::numeric_gas::checked_add(rounded_division_work, work).expect("bounded work sum");
    }
    group.bench_with_input(
        BenchmarkId::new(
            "decimal_div_round",
            format!("scale=28;work={rounded_division_work}"),
        ),
        &rounded_division_work,
        |b, _| {
            b.iter(|| {
                std::hint::black_box(
                    one.try_decimal_div_round(&seven, 28, RoundingMode::NearestEven)
                        .expect("rounded division"),
                )
            });
        },
    );
    let mut maximum_bytes = vec![0xff_u8; iroha_primitives::numeric::MAX_MANTISSA_BYTES];
    *maximum_bytes.last_mut().expect("nonempty mantissa") = 0x7f;
    let maximum_int = BigInt::from_twos_bytes(&maximum_bytes).expect("signed maximum");
    let maximum = Numeric::new(maximum_int.clone(), 0);
    let scale_28: Numeric = "0.0000000000000000000000000001"
        .parse()
        .expect("scale-28 decimal");
    let mut maximum_adjusted_limbs = 0_u16;
    let mut maximum_round_work = 0_u64;
    let maximum_round_result = maximum.try_decimal_div_round_observed(
        &scale_28,
        28,
        RoundingMode::NearestEven,
        &mut |step| {
            if let NumericWorkStep::RoundedDivision {
                numerator_limbs, ..
            } = step
            {
                maximum_adjusted_limbs = numerator_limbs;
            }
            let step_gas = ivm::numeric_gas::work_step_gas(step)
                .expect("maximum scale-adjusted work is bounded");
            maximum_round_work = ivm::numeric_gas::checked_add(
                maximum_round_work,
                step_gas / ivm::numeric_gas::NUMERIC_GAS_PER_LIMB_WORK,
            )
            .expect("maximum scale-adjusted work sum is bounded");
            Ok::<(), core::convert::Infallible>(())
        },
    );
    assert!(matches!(
        maximum_round_result,
        Err(ObservedNumericError::Numeric(
            NumericOperationError::MantissaOverflow
        ))
    ));
    assert_eq!(maximum_adjusted_limbs, 11);
    group.bench_with_input(
        BenchmarkId::new(
            "decimal_div_round_max_adjusted",
            format!("scale=28;numerator_limbs={maximum_adjusted_limbs};work={maximum_round_work}"),
        ),
        &maximum_round_work,
        |b, _| {
            b.iter(|| {
                std::hint::black_box(maximum.try_decimal_div_round(
                    &scale_28,
                    28,
                    RoundingMode::NearestEven,
                ))
            });
        },
    );
    let comparison_work =
        ivm::numeric_gas::aligned_work(511, 28, 10, 1, 0, 1).expect("bounded scale-alignment work");
    group.bench_with_input(
        BenchmarkId::new(
            "decimal_compare",
            format!("aligned_limbs=10;work={comparison_work}"),
        ),
        &comparison_work,
        |b, _| b.iter(|| std::hint::black_box(maximum.cmp(&scale_28))),
    );
    for (label, value) in [("minimum", BigInt::zero()), ("maximum", maximum_int)] {
        let envelope = ivm_abi::numeric_tlv::encode_int(&value).expect("numeric envelope");
        let frame_bytes = envelope.len() - 39;
        let validation_work =
            ivm::numeric_gas::numeric_frame_validation_work(frame_bytes).expect("validation work");
        let input_gas = u64::try_from(envelope.len())
            .expect("bounded envelope bytes")
            .checked_add(
                ivm::numeric_gas::payload_hash_gas(frame_bytes)
                    .expect("bounded payload authentication"),
            )
            .and_then(|bytes| {
                bytes.checked_add(
                    ivm::numeric_gas::work_gas(validation_work).expect("validation gas"),
                )
            })
            .expect("bounded input pipeline gas");
        group.bench_with_input(
            BenchmarkId::new(
                "input_envelope_pipeline",
                format!(
                    "{label};envelope={};frame={frame_bytes};gas={input_gas}",
                    envelope.len()
                ),
            ),
            &envelope,
            |b, envelope| {
                b.iter(|| {
                    // Production authenticates and decodes an immutable
                    // snapshot, not the guest-memory slice in place.  Include
                    // that bounded transport copy because the declared input
                    // envelope bytes are its calibration denominator.
                    let snapshot = envelope.to_vec();
                    let value = ivm::numeric_tlv::decode_int_bytes(&snapshot)
                        .expect("decode calibration envelope");
                    std::hint::black_box((snapshot, value));
                });
            },
        );
        let length_work = ivm::numeric_gas::limbs_for_bits(
            u64::try_from(value.bit_len()).expect("bounded bit width") + 1,
        );
        let output_gas = ivm::numeric_gas::output_serialization_gas(envelope.len(), frame_bytes)
            .and_then(|bytes| {
                ivm::numeric_gas::work_gas(length_work)
                    .and_then(|probe| ivm::numeric_gas::checked_add(bytes, probe))
            })
            .expect("bounded output gas");
        group.bench_with_input(
            BenchmarkId::new(
                "output_envelope_pipeline",
                format!(
                    "{label};envelope={};frame={frame_bytes};gas={output_gas}",
                    envelope.len()
                ),
            ),
            &value,
            |b, value| {
                b.iter_batched(
                    || IVM::new(u64::MAX),
                    |mut vm| {
                        std::hint::black_box(value.twos_byte_len());
                        let envelope = ivm_abi::numeric_tlv::encode_int(value)
                            .expect("encode calibration envelope");
                        // Output byte gas covers both canonical construction
                        // and publication into VM-owned memory.  Keep the
                        // publication copy in the measured routine so release
                        // calibration cannot approve a denominator using only
                        // the cheaper codec half of the production pipeline.
                        let pointer = vm
                            .alloc_host_tlv(&envelope)
                            .expect("publish calibration envelope");
                        std::hint::black_box(pointer);
                        std::hint::black_box(envelope);
                        // Return the synthetic VM so Criterion drops it after
                        // the timing window.  A production numeric syscall
                        // keeps its VM alive; timing destruction of the whole
                        // memory image would not be output-publication work.
                        vm
                    },
                    BatchSize::SmallInput,
                );
            },
        );
    }
    group.finish();
}
fn run_benchmarks(c: &mut Criterion) {
    // Wide arithmetic with small register indices (rd=3, rs1=1, rs2=2)
    let add = encoding::wide::encode_rr(instruction::wide::arithmetic::ADD, 3, 1, 2);
    let mul = encoding::wide::encode_rr(instruction::wide::arithmetic::MUL, 3, 1, 2);
    let divu = encoding::wide::encode_rr(instruction::wide::arithmetic::DIVU, 3, 1, 2);
    // Repeat count large enough to amortize overhead
    let reps = 50_000;
    bench_empty_harness(c);
    bench_instr(c, "ADD", add, reps);
    bench_instr(c, "MUL", mul, reps);
    bench_instr(c, "DIVU", divu, reps);
    // Numeric benchmark IDs pin the logical-work denominator used to compare
    // backend latency against the consensus factor of four gas per limb-work
    // unit. Run this on every release baseline; see kotodama_numeric_v1.md.
    bench_numeric_limb_work(c);
    // You can extend with more: logic ops, shifts, branches, loads/stores, vector ops, crypto ops.
}
/// Entry point for the benchmark binary.
fn main() {
    // Silence ASCII banner and feature selection in benches.
    ivm::set_banner_enabled(false);
    let mut c = Criterion::default().configure_from_args();
    run_benchmarks(&mut c);
    c.final_summary();
}
