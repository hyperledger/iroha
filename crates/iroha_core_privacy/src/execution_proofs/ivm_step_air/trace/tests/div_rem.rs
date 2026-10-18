//! Interpreter parity and adversarial attempted-step division boundaries.

mod attacks;
mod native;

use super::*;

fn unit_root_call_gas() -> u64 {
    let callable = crate::ivm_test_support::unit_callable(0);
    assert_eq!(callable.frame_bytes, 0);
    let result_words = u64::try_from(callable.result_word_count().unwrap()).unwrap();
    // V1 root setup charges one logical byte per reserved result byte and one
    // initialization bitmap byte per result word for this zero-byte frame.
    result_words * ivm_abi::call::CALL_WORD_BYTES_V1 as u64 + result_words
}

pub(super) fn attempted(
    body: &[u32],
    steps: usize,
    inputs: &[(usize, u64)],
    gas: u64,
) -> (ScalarSegment, Vec<DiagnosticStepRecord>) {
    let contract = contract(body);
    // Root invocation allocates the authenticated Unit result table and its frame bitmap
    // before diagnostic opcode recording begins. The supplied budget belongs to the
    // scalar prefix, so fund that production work separately without bypassing it.
    let root_gas = unit_root_call_gas();
    let invocation_gas = gas
        .checked_add(root_gas)
        .expect("funded root and opcode budget");
    let mut vm = IVM::new(invocation_gas);
    vm.load_prepared(&contract).unwrap();
    for (register, value) in inputs {
        vm.set_register(*register, *value);
    }
    let budget = AllocationBudget::new(128 * std::mem::size_of::<DiagnosticStepRecord>());
    let mut recorder = DiagnosticStepRecorder::try_new(128, &budget).unwrap();
    let actual = vm.run_with_host_diagnostic_steps(&mut DefaultHost::default(), &mut recorder);
    let records = recorder
        .records()
        .get(..steps)
        .unwrap_or_else(|| {
            panic!(
                "attempted scalar prefix: requested {steps}, recorded {}, invocation {actual:?}",
                recorder.records().len()
            )
        })
        .to_vec();
    assert_eq!(records[0].before.gas_remaining, gas);
    assert_eq!(invocation_gas - records[0].before.gas_remaining, root_gas);
    let outcome = match records[steps - 1].outcome {
        DiagnosticStepOutcome::Completed => SegmentOutcome::Continue,
        DiagnosticStepOutcome::Trapped(VmTrapKind::OutOfGas) => {
            assert!(matches!(actual, Err(ivm::VMError::OutOfGas)));
            SegmentOutcome::OutOfGas
        }
        DiagnosticStepOutcome::Trapped(VmTrapKind::AssertionFailed) => {
            assert!(matches!(actual, Err(ivm::VMError::AssertionFailed)));
            SegmentOutcome::AssertionFailed
        }
        other => panic!("unexpected division boundary {other:?}"),
    };
    let segment = ScalarSegment::new(
        contract,
        steps,
        records[0].before,
        records[steps - 1].after,
        outcome,
    )
    .unwrap();
    (segment, records)
}

fn expected(kind: usize, a: u64, b: u64, gas: u64) -> Result<u64, SegmentOutcome> {
    if gas < 10 {
        return Err(SegmentOutcome::OutOfGas);
    }
    if b == 0 || (division::signed_kind(kind) && a == i64::cast_unsigned(i64::MIN) && b == u64::MAX)
    {
        return Err(SegmentOutcome::AssertionFailed);
    }
    Ok(match kind {
        0 => i64::cast_unsigned(u64::cast_signed(a) / u64::cast_signed(b)),
        1 => a / b,
        2 => i64::cast_unsigned(u64::cast_signed(a) % u64::cast_signed(b)),
        3 => a % b,
        _ => unreachable!(),
    })
}

fn single(kind: usize, a: u64, b: u64, gas: u64) -> (ScalarSegment, Vec<DiagnosticStepRecord>) {
    attempted(
        &[enc::encode_rr(DIVISION_OPS[kind], 8, 6, 7)],
        1,
        &[(6, a), (7, b), (8, 91)],
        gas,
    )
}

fn from_records(
    segment: &ScalarSegment,
    records: &[DiagnosticStepRecord],
    outcome: SegmentOutcome,
) -> ScalarSegment {
    ScalarSegment::new(
        segment.contract.clone(),
        records.len(),
        records[0].before,
        records.last().unwrap().after,
        outcome,
    )
    .unwrap()
}

#[test]
fn division_variants_match_interpreter_full_width_signed_quadrants_aliases_and_r0() {
    let pairs = [
        (0, 1),
        (17, 5),
        (i64::cast_unsigned(-17_i64), 5),
        (17, i64::cast_unsigned(-5_i64)),
        (i64::cast_unsigned(-17_i64), i64::cast_unsigned(-5_i64)),
        (u64::MAX, 1),
        (1, u64::MAX),
        (i64::cast_unsigned(i64::MIN), 1),
        (i64::cast_unsigned(i64::MIN), i64::cast_unsigned(i64::MIN)),
        (i64::cast_unsigned(i64::MIN), u64::MAX),
        (i64::MAX as u64, 3),
        (0xffff_ffff_0000_0001, 7),
        (17, 0),
    ];
    for (kind, opcode) in DIVISION_OPS.into_iter().enumerate() {
        for (left, right) in pairs {
            for (rd, rs1, rs2) in [
                (8, 6, 7),
                (6, 6, 7),
                (7, 6, 7),
                (6, 6, 6),
                (0, 6, 7),
                (8, 0, 7),
                (8, 6, 0),
                (0, 0, 0),
            ] {
                let (segment, records) = attempted(
                    &[enc::encode_rr(opcode, rd, rs1, rs2)],
                    1,
                    &[(6, left), (7, right), (8, 91)],
                    1_000,
                );
                let result = expected(
                    kind,
                    segment.before.registers[usize::from(rs1)],
                    segment.before.registers[usize::from(rs2)],
                    1_000,
                );
                let mut wanted = segment.before.registers;
                match result {
                    Ok(value) => {
                        if rd != 0 {
                            wanted[usize::from(rd)] = value;
                        }
                        assert_eq!(segment.outcome, SegmentOutcome::Continue);
                    }
                    Err(outcome) => assert_eq!(segment.outcome, outcome),
                }
                assert_eq!(segment.after.registers, wanted);
                assert_eq!(segment.after.tags, segment.before.tags);
                assert_eq!(segment.after.gas_remaining, 990);
                assert_eq!(
                    segment.after.pc,
                    segment.before.pc + 4 * u64::from(result.is_ok())
                );
                assert_eq!(
                    segment.after.cycles,
                    segment.before.cycles + u64::from(result.is_ok())
                );
                assert!(!segment.after.halted && !segment.after.constraint_failed);
                assert_eq!(records[0].opcode_gas, Some(10));
                assert_rows(&segment, &segment.witness_rows(&records).unwrap());
            }
        }
    }
}

#[test]
fn division_gas_precedes_arithmetic_and_traps_have_exact_opcode_boundary_state() {
    for kind in 0..4 {
        for (a, b) in [
            (17, 5),
            (17, 0),
            (i64::cast_unsigned(i64::MIN), u64::MAX),
            (0xffff_ffff_0000_0001, 0xffff_ffff_0000_0001),
        ] {
            for gas in [0, 9, 10, 11, 1 << 32, u64::MAX - unit_root_call_gas()] {
                let (segment, records) = single(kind, a, b, gas);
                let outcome = expected(kind, a, b, gas)
                    .err()
                    .unwrap_or(SegmentOutcome::Continue);
                assert_eq!(segment.outcome, outcome);
                assert_eq!(
                    segment.after.gas_remaining,
                    if gas < 10 { gas } else { gas - 10 }
                );
                assert_eq!(records[0].opcode_gas, Some(10));
                if outcome.trapped() {
                    assert_eq!(segment.after.pc, segment.before.pc);
                    assert_eq!(segment.after.cycles, segment.before.cycles);
                    assert_eq!(segment.after.registers, segment.before.registers);
                    assert_eq!(segment.after.tags, segment.before.tags);
                }
                let rows = segment.witness_rows(&records).unwrap();
                if gas < 10 {
                    assert_eq!(rows[0][GAS_BORROW], F::ZERO);
                }
                assert_rows(&segment, &rows);
            }
        }
    }
}

#[test]
fn trapped_division_does_not_inherit_priced_gas_or_completed_cycle_carries() {
    for (kind, a, b, gas) in [
        (0, 17, 5, 9),
        (2, i64::cast_unsigned(i64::MIN), u64::MAX, 10),
        (1, 17, 0, u64::MAX - unit_root_call_gas()),
    ] {
        let (segment, mut records) = single(kind, a, b, gas);
        for cycles in [u64::from(u32::MAX), u64::MAX] {
            records[0].before.cycles = cycles;
            records[0].after.cycles = cycles;
            let changed = from_records(&segment, &records, segment.outcome);
            let rows = changed.witness_rows(&records).unwrap();
            assert_eq!(rows[0][CYCLE_CARRY], F::ZERO);
            if gas < 10 {
                assert_eq!(rows[0][GAS_BORROW], F::ZERO);
            }
            assert_rows(&changed, &rows);
            for column in [GAS_BORROW, CYCLE_CARRY] {
                let mut forged = rows.clone();
                forged[0][column] = F::ONE;
                assert!(rejects(&changed, &forged));
            }
        }
    }
}

#[test]
fn authenticated_root_gas_is_distinct_from_recorded_division_budget() {
    let root_gas = unit_root_call_gas();
    assert_eq!(root_gas, 9);
    let instruction = enc::encode_rr(DIVISION_OPS[0], 8, 6, 7);
    let prepared = contract(&[instruction]);
    for invocation_gas in [0, root_gas - 1, root_gas] {
        let mut vm = IVM::new(invocation_gas);
        vm.load_prepared(&prepared).unwrap();
        vm.set_register(6, 17);
        vm.set_register(7, 5);
        let budget = AllocationBudget::new(128 * std::mem::size_of::<DiagnosticStepRecord>());
        let mut recorder = DiagnosticStepRecorder::try_new(128, &budget).unwrap();
        assert!(matches!(
            vm.run_with_host_diagnostic_steps(&mut DefaultHost::default(), &mut recorder),
            Err(ivm::VMError::OutOfGas)
        ));
        if invocation_gas < root_gas {
            assert!(recorder.records().is_empty());
        } else {
            assert_eq!(recorder.records().len(), 1);
            assert_eq!(recorder.records()[0].before.gas_remaining, 0);
            assert_eq!(recorder.records()[0].after.gas_remaining, 0);
            assert_eq!(recorder.records()[0].opcode_gas, Some(10));
            assert_eq!(
                recorder.records()[0].outcome,
                DiagnosticStepOutcome::Trapped(VmTrapKind::OutOfGas)
            );
        }
    }
    let (segment, records) = single(0, 17, 5, u64::MAX - root_gas);
    assert_eq!(segment.before.gas_remaining, u64::MAX - root_gas);
    assert_eq!(segment.after.gas_remaining, u64::MAX - root_gas - 10);
    assert_eq!(records[0].opcode_gas, Some(10));
    assert_rows(&segment, &segment.witness_rows(&records).unwrap());
}

#[test]
fn division_attempts_enforce_strict_artifact_cycle_limit_and_public_boundaries() {
    let (segment, records) = single(0, 17, 0, 10);
    let instruction = records[0].instruction.unwrap();
    for (max, mode, limit) in [(7, 0, 7), (0, ivm::ivm_mode::ZK, ivm::zk::MAX_CYCLES)] {
        let contract = contract_with_cycle_policy(&[instruction], max, mode);
        for cycles in [limit - 1, limit] {
            let mut changed = records.clone();
            let pc = (contract.code_offset() - contract.header_len()) as u64;
            changed[0].before.pc = pc;
            changed[0].after.pc = pc;
            changed[0].before.cycles = cycles;
            changed[0].after.cycles = cycles;
            let result = ScalarSegment::new(
                contract.clone(),
                1,
                changed[0].before,
                changed[0].after,
                segment.outcome,
            );
            if cycles == limit {
                assert!(result.is_err());
            } else {
                let valid = result.unwrap();
                assert_rows(&valid, &valid.witness_rows(&changed).unwrap());
            }
        }
    }
    for register in [0, 6, 7, 8, 255] {
        let mut before = segment.before;
        before.tags[register] = true;
        assert!(
            ScalarSegment::new(
                segment.contract.clone(),
                1,
                before,
                segment.after,
                segment.outcome
            )
            .is_err()
        );
        let mut after = segment.after;
        after.tags[register] = true;
        assert!(
            ScalarSegment::new(
                segment.contract.clone(),
                1,
                segment.before,
                after,
                segment.outcome
            )
            .is_err()
        );
    }
    for steps in [0, MAX_STEPS + 1, usize::MAX] {
        assert!(
            ScalarSegment::new(
                segment.contract.clone(),
                steps,
                segment.before,
                segment.after,
                segment.outcome
            )
            .is_err()
        );
    }
    let mut before = segment.before;
    before.cycles = u64::MAX;
    let after = before;
    assert!(
        ScalarSegment::new(segment.contract.clone(), 2, before, after, segment.outcome).is_err()
    );
}
