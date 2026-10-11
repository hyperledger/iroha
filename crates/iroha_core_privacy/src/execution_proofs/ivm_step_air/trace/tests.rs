//! Mixed interpreter, algebraic forgery, layout and native proof checks.

mod absolute;
mod bit_counts;
mod conditional_move;
mod div_rem;
mod gcd;
mod mean;
mod multiplication;
mod roots_and_ceiling;
mod unary_control;

use std::sync::Arc;

use super::*;
use crate::execution_proofs::stark::{
    aggregate_stark::{
        AggregateProofLayoutV1, AggregateTraceGroupLayoutV1,
        maximum_encoded_proof_with_deep_bytes_v1,
    },
    proof_managed_note_stark::{
        degree_audit::measured_maximum_affine_degree_v1, prove_proof_managed_note_stark_v1,
        verify_proof_managed_note_stark_v1,
    },
};
use iroha_allocation::AllocationBudget;
use ivm::{
    IVM, ProgramMetadata, encoding::wide as enc, execution_step_recorder::DiagnosticStepRecorder,
    host::DefaultHost,
};

fn contract(body: &[u32]) -> PreparedContract {
    contract_with_cycle_policy(body, 0, 0)
}

fn contract_with_cycle_policy(body: &[u32], max_cycles: u64, mode: u8) -> PreparedContract {
    use iroha_data_model::smart_contract::{
        entrypoint::{EntrypointValueTypeNodeV1, EntrypointValueTypeV1},
        manifest::EntryPointKind,
    };
    let interface = ivm::EmbeddedContractInterfaceV1 {
        events: Vec::new(),
        enum_types: Vec::new(),
        permissions: Vec::new(),
        callables: vec![crate::ivm_test_support::unit_callable(0)],
        seiyaku_name: "ScalarSegmentFixture".into(),
        compiler_fingerprint: "scalar-segment-test".into(),
        abi_hash: ivm::syscalls::compute_abi_hash(ivm::SyscallPolicy::AbiV1),
        features_bitmap: if mode & ivm::ivm_mode::ZK != 0 {
            ivm::CONTRACT_FEATURE_BIT_ZK
        } else {
            0
        },
        access_set_hints: None,
        kotoba: Vec::new(),
        error_messages: Vec::new(),
        error_types: Vec::new(),
        states: Vec::new(),
        entrypoints: vec![ivm::EmbeddedEntrypointDescriptor {
            name: "main".into(),
            kind: EntryPointKind::Kotoage,
            params: Vec::new(),
            argument_schema: None,
            return_type: Some("()".into()),
            return_schema: Some(EntrypointValueTypeV1 {
                nodes: vec![EntrypointValueTypeNodeV1::Unit],
            }),
            authorization:
                iroha_data_model::smart_contract::manifest::EntrypointAuthorizationV1::Anyone,
            read_keys: Vec::new(),
            write_keys: Vec::new(),
            access_hints_complete: Some(true),
            access_hints_skipped: Vec::new(),
            triggers: Vec::new(),
            entry_pc: 0,
        }],
    };
    let mut program = ProgramMetadata {
        max_cycles,
        mode,
        ..ProgramMetadata::default()
    }
    .encode();
    program.extend_from_slice(&interface.encode_section());
    program.extend(body.iter().flat_map(|word| word.to_le_bytes()));
    program.extend_from_slice(&crate::ivm_test_support::unit_return());
    ivm::prepare_contract(Arc::from(program)).expect("admitted V1 scalar fixture")
}

fn recorded(
    body: &[u32],
    steps: usize,
    inputs: &[(usize, u64)],
    gas: u64,
) -> (ScalarSegment, Vec<DiagnosticStepRecord>) {
    let contract = contract(body);
    let mut vm = IVM::new(gas);
    vm.load_prepared(&contract).unwrap();
    for (register, value) in inputs {
        vm.set_register(*register, *value);
    }
    let budget = AllocationBudget::new(128 * std::mem::size_of::<DiagnosticStepRecord>());
    let mut recorder = DiagnosticStepRecorder::try_new(128, &budget).unwrap();
    // A scalar segment may precede a later return failure (for example an
    // alias test deliberately overwrites a return register). Only completed
    // prefix instructions enter this relation.
    let _outcome = vm.run_with_host_diagnostic_steps(&mut DefaultHost::default(), &mut recorder);
    let records = recorder
        .records()
        .get(..steps)
        .expect("completed scalar prefix")
        .to_vec();
    assert!(
        records
            .iter()
            .all(|record| record.outcome == DiagnosticStepOutcome::Completed)
    );
    let segment = ScalarSegment::new(
        contract,
        steps,
        records[0].before,
        records[steps - 1].after,
        SegmentOutcome::Continue,
    )
    .unwrap();
    (segment, records)
}

fn mixed() -> (ScalarSegment, Vec<DiagnosticStepRecord>) {
    let body = [
        enc::encode_ri(wide::arithmetic::ADDI, 2, 0, 3),
        enc::encode_rr(wide::arithmetic::ADD, 3, 3, 4),
        enc::encode_ri(wide::arithmetic::ROTL_IMM, 3, 3, -1),
        enc::encode_rr(wide::arithmetic::XOR, 3, 3, 5),
        enc::encode_ri(wide::arithmetic::ADDI, 2, 2, -1),
        enc::encode_branch(wide::control::BNE, 2, 0, -4),
        enc::encode_rr(wide::arithmetic::SRA, 6, 3, 7),
        enc::encode_ri(wide::arithmetic::ANDI, 0, 6, -1),
    ];
    recorded(
        &body,
        18,
        &[
            (3, 0x8000_0000_0000_0001),
            (4, u64::MAX),
            (5, 0xa5a5_ffff_1234_5678),
            (7, u64::MAX),
            (255, u64::MAX),
        ],
        u64::MAX,
    )
}

fn assert_rows(segment: &ScalarSegment, rows: &[Vec<F>]) {
    for index in 0..=segment.physical_steps() {
        let row = &rows[index];
        let next = &rows[(index + 1).min(segment.physical_steps())];
        let residuals = residues(segment, row, next, &segment.fixed_row(index)).unwrap();
        assert_eq!(residuals.len(), CONSTRAINT_COUNT);
        assert!(
            residuals.iter().all(|value| *value == F::ZERO),
            "failed row {index}: {:?}",
            residuals
                .iter()
                .enumerate()
                .filter(|(_, value)| **value != F::ZERO)
                .collect::<Vec<_>>()
        );
    }
    // The final polynomial-domain row does not force the final state to equal
    // the initial state; all local bank/range constraints still apply there.
    assert!(
        residues(
            segment,
            rows.last().unwrap(),
            &rows[0],
            &segment.fixed_row(TRACE_SIZE - 1)
        )
        .unwrap()
        .iter()
        .all(|value| *value == F::ZERO)
    );
}
fn rejects(segment: &ScalarSegment, rows: &[Vec<F>]) -> bool {
    (0..=segment.physical_steps()).any(|index| {
        residues(
            segment,
            &rows[index],
            &rows[(index + 1).min(segment.physical_steps())],
            &segment.fixed_row(index),
        )
        .unwrap()
        .iter()
        .any(|value| *value != F::ZERO)
    })
}

#[test]
fn scalar_segment_mixed_loop_matches_interpreter_full_registers_fetch_and_u64_gas() {
    let (segment, records) = mixed();
    assert_eq!(segment.steps, 18);
    assert!(
        segment.first_pc > 0,
        "CNTR prefix makes PC/address confusion observable"
    );
    assert_eq!(segment.before.pc, u64::from(segment.first_pc));
    assert!(segment.before.gas_remaining > u64::from(u32::MAX));
    assert_ne!(segment.before.registers, segment.after.registers);
    assert_rows(&segment, &segment.witness_rows(&records).unwrap());
    let debit: u64 = records
        .iter()
        .map(|record| record.opcode_gas.unwrap())
        .sum();
    assert_eq!(
        segment.before.gas_remaining - segment.after.gas_remaining,
        debit
    );
    for record in &records {
        let offset = segment.contract.header_len() + record.before.pc as usize;
        assert_eq!(
            segment.contract.artifact()[offset..offset + 4],
            record.instruction.unwrap().to_le_bytes()
        );
    }
}

#[test]
fn scalar_segment_all_families_immediates_aliases_zero_register_and_full_amounts() {
    let opcodes = [
        wide::arithmetic::ADD,
        wide::arithmetic::SUB,
        wide::arithmetic::AND,
        wide::arithmetic::OR,
        wide::arithmetic::XOR,
        wide::arithmetic::SLL,
        wide::arithmetic::SRL,
        wide::arithmetic::SRA,
        wide::arithmetic::ROTL,
        wide::arithmetic::ROTR,
    ];
    for opcode in opcodes {
        for (rd, left, right) in [
            (8, 6, 7),
            (6, 6, 7),
            (7, 6, 7),
            (8, 6, 6),
            (6, 6, 6),
            (0, 6, 7),
            (8, 0, 7),
            (8, 6, 0),
            (0, 0, 0),
        ] {
            let (segment, records) = recorded(
                &[enc::encode_rr(opcode, rd, left, right)],
                1,
                &[(6, 0x8000_1234_5678_9abc), (7, u64::MAX)],
                1 << 32,
            );
            assert_rows(&segment, &segment.witness_rows(&records).unwrap());
        }
    }
    for opcode in [
        wide::arithmetic::ADDI,
        wide::arithmetic::ANDI,
        wide::arithmetic::ORI,
        wide::arithmetic::XORI,
        wide::arithmetic::ROTL_IMM,
        wide::arithmetic::ROTR_IMM,
    ] {
        for value in [i8::MIN, -1, 0, 63, 64, i8::MAX] {
            let (segment, records) = recorded(
                &[enc::encode_ri(opcode, 6, 6, value)],
                1,
                &[(6, 0x8000_1234_5678_9abc)],
                1 << 32,
            );
            assert_rows(&segment, &segment.witness_rows(&records).unwrap());
        }
    }
    for opcode in BRANCH_OPS {
        for (left, right) in [
            (0, 0),
            (0, 1),
            (u64::MAX, 0),
            (i64::MIN as u64, i64::MAX as u64),
        ] {
            let (segment, records) = recorded(
                &[
                    enc::encode_branch(opcode, 6, 7, 2),
                    enc::encode_ri(wide::arithmetic::ADDI, 8, 0, 1),
                ],
                1,
                &[(6, left), (7, right)],
                1_000,
            );
            assert_rows(&segment, &segment.witness_rows(&records).unwrap());
        }
    }
}

#[test]
fn scalar_segment_rejects_forged_fetch_sources_writes_padding_and_bank_witnesses() {
    let (segment, records) = mixed();
    let base = segment.witness_rows(&records).unwrap();
    for (step, column) in [
        (0, FETCH),
        (0, FETCH + 1),
        (0, FETCH + MAX_WORDS - 1),
        (0, PC),
        (2, 2 * 255),
        (2, 2 * 255 + 1),
        (2, 0),
        (2, RESULT),
        (2, ALU),
        (2, BRANCH),
        (2, SHIFT),
        (2, SHIFT + shift::BANK_WIDTH - 1),
        (2, GAS),
        (2, GAS + 1),
        (2, GAS_DIGITS),
        (2, GAS_BORROW),
        (2, CYCLES),
        (2, CYCLE_DIGITS),
        (2, CYCLE_CARRY),
        (segment.steps, 2 * 255),
        (segment.steps, FETCH),
    ] {
        let mut forged = base.clone();
        forged[step][column] = forged[step][column].add(F::ONE);
        assert!(
            rejects(&segment, &forged),
            "accepted row {step} column {column}"
        );
    }
    let mut swapped = base.clone();
    swapped.swap(2, 3);
    assert!(rejects(&segment, &swapped));
    let mut duplicated = base.clone();
    duplicated[3] = duplicated[2].clone();
    assert!(rejects(&segment, &duplicated));
    // An extra write in padding must fail even away from the end-boundary row.
    let last = base.last().unwrap();
    let mut hidden_write = last.clone();
    hidden_write[2 * 255] = F::ZERO;
    assert!(
        residues(
            &segment,
            last,
            &hidden_write,
            &segment.fixed_row(segment.steps + 1)
        )
        .unwrap()
        .iter()
        .any(|value| *value != F::ZERO)
    );
    // A selected admitted but unsupported STORE cannot be presented as a scalar step.
    let mut unsupported = base.clone();
    unsupported[0][FETCH] = F::ZERO;
    unsupported[0][FETCH + 8] = F::ONE;
    unsupported[0][PC] = F(u64::from(segment.first_pc) + 32);
    assert!(rejects(&segment, &unsupported));
}

#[test]
fn scalar_segment_self_consistent_false_results_gas_and_branch_targets_fail() {
    let (mut segment, mut records) = recorded(
        &[enc::encode_rr(wide::arithmetic::ADD, 6, 6, 7)],
        1,
        &[(6, u64::MAX), (7, 2)],
        1 << 32,
    );
    records[0].after.registers[6] ^= 1;
    segment.after = records[0].after;
    segment.validate().unwrap();
    let rows = segment.witness_rows(&records).unwrap();
    assert!(rejects(&segment, &rows));
    let (mut segment, mut records) = recorded(
        &[enc::encode_rr(wide::arithmetic::ROTL, 6, 6, 7)],
        1,
        &[(6, 3), (7, 64)],
        1 << 32,
    );
    records[0].after.gas_remaining += 1;
    segment.after = records[0].after;
    assert!(rejects(&segment, &segment.witness_rows(&records).unwrap()));
    let (mut segment, mut records) = recorded(
        &[
            enc::encode_branch(wide::control::BLT, 6, 7, 2),
            enc::encode_ri(wide::arithmetic::ADDI, 8, 0, 1),
        ],
        1,
        &[(6, i64::MIN as u64), (7, i64::MAX as u64)],
        1_000,
    );
    records[0].after.pc -= 4;
    segment.after = records[0].after;
    segment.validate().unwrap();
    assert!(rejects(&segment, &segment.witness_rows(&records).unwrap()));
}

#[test]
fn scalar_segment_boundaries_code_table_tags_and_record_claims_are_bound() {
    let (segment, records) = mixed();
    let digest = segment.digest().unwrap();
    for register in 0..REGISTERS {
        for initial in [false, true] {
            let mut before = segment.before;
            let mut after = segment.after;
            let boundary = if initial { &mut before } else { &mut after };
            boundary.tags[register] = true;
            assert!(
                ScalarSegment::new(
                    segment.contract.clone(),
                    segment.steps,
                    before,
                    after,
                    SegmentOutcome::Continue
                )
                .is_err()
            );
        }
    }
    for pc in [segment.before.pc - 1, segment.before.pc + 2, 0, u64::MAX] {
        let mut before = segment.before;
        before.pc = pc;
        assert!(
            ScalarSegment::new(
                segment.contract.clone(),
                segment.steps,
                before,
                segment.after,
                SegmentOutcome::Continue
            )
            .is_err()
        );
    }
    for steps in [0, 65] {
        assert!(
            ScalarSegment::new(
                segment.contract.clone(),
                steps,
                segment.before,
                segment.after,
                SegmentOutcome::Continue
            )
            .is_err()
        );
    }
    let mut changed = ScalarSegment::new(
        segment.contract.clone(),
        segment.steps,
        segment.before,
        segment.after,
        SegmentOutcome::Continue,
    )
    .unwrap();
    changed.words[0] ^= 1;
    assert!(changed.validate().is_err());
    let mut bad = records.clone();
    bad[1].instruction = Some(enc::encode_rr(wide::arithmetic::SUB, 3, 3, 4));
    assert!(segment.witness_rows(&bad).is_err());
    bad = records.clone();
    bad[1].before.registers[255] ^= 1;
    assert!(segment.witness_rows(&bad).is_err());
    bad = records.clone();
    bad[1].after.tags[255] = true;
    assert!(segment.witness_rows(&bad).is_err());
    bad = records.clone();
    bad[1].before.cycles += 1;
    assert!(segment.witness_rows(&bad).is_err());
    assert!(segment.witness_rows(&records[..records.len() - 1]).is_err());
    for (before, after) in [
        (
            {
                let mut x = segment.before;
                x.registers[255] ^= 1;
                x
            },
            segment.after,
        ),
        (segment.before, {
            let mut x = segment.after;
            x.gas_remaining -= 1;
            x
        }),
        (
            {
                let mut x = segment.before;
                x.vector_length += 1;
                x
            },
            {
                let mut x = segment.after;
                x.vector_length += 1;
                x
            },
        ),
    ] {
        let changed = ScalarSegment::new(
            segment.contract.clone(),
            segment.steps,
            before,
            after,
            SegmentOutcome::Continue,
        )
        .unwrap();
        assert_ne!(changed.digest().unwrap(), digest);
        if before.vector_length == segment.before.vector_length {
            assert!(rejects(&changed, &segment.witness_rows(&records).unwrap()));
        }
    }
}

#[test]
fn scalar_segment_native_layout_fits_envelope_and_dynamic_degree_is_four() {
    let (segment, _) = mixed();
    let protocol = segment.protocol_v1();
    protocol.validate().unwrap();
    assert_eq!(segment.base_width_v1(), 1_356);
    let layout = AggregateProofLayoutV1::new(
        protocol.parameters,
        vec![AggregateTraceGroupLayoutV1 {
            native_trace_log2: TRACE_LOG2,
            segment_instances: 1,
            base_width: segment.base_width_v1(),
            aux_width: NOTE_COPY_AUX_WIDTH_V1,
        }],
    )
    .unwrap();
    let bound = maximum_encoded_proof_with_deep_bytes_v1(protocol.parameters, &layout).unwrap();
    assert_eq!(bound, 4_153_152);
    assert!(bound <= protocol.parameters.maximum_proof_bytes);
    assert_eq!(
        measured_maximum_affine_degree_v1(
            [0x63; 32],
            [ROW_WIDTH, ROW_WIDTH, 0, 0, FIXED_WIDTH],
            3,
            4,
            |row, next, _, _, fixed| residues(&segment, row, next, fixed)
        ),
        4
    );
}

#[test]
fn native_stark_proves_mixed_scalar_segment_and_rejects_changed_boundaries_and_artifact() {
    let (segment, records) = mixed();
    let proof =
        prove_proof_managed_note_stark_v1(&segment, &segment.columns(&records).unwrap()).unwrap();
    verify_proof_managed_note_stark_v1(&segment, &proof).unwrap();
    for (before, after) in [
        (
            {
                let mut x = segment.before;
                x.registers[255] ^= 1;
                x
            },
            segment.after,
        ),
        (segment.before, {
            let mut x = segment.after;
            x.registers[6] ^= 1;
            x
        }),
        (segment.before, {
            let mut x = segment.after;
            x.gas_remaining -= 1;
            x
        }),
    ] {
        let changed = ScalarSegment::new(
            segment.contract.clone(),
            segment.steps,
            before,
            after,
            SegmentOutcome::Continue,
        )
        .unwrap();
        assert!(verify_proof_managed_note_stark_v1(&changed, &proof).is_err());
    }
    let mut artifact = segment.contract.artifact().to_vec();
    let offset = segment.contract.code_offset();
    artifact[offset..offset + 4]
        .copy_from_slice(&enc::encode_ri(wide::arithmetic::ADDI, 2, 0, 2).to_le_bytes());
    let changed_contract = ivm::prepare_contract(Arc::from(artifact)).unwrap();
    let changed = ScalarSegment::new(
        changed_contract,
        segment.steps,
        segment.before,
        segment.after,
        SegmentOutcome::Continue,
    )
    .unwrap();
    assert!(verify_proof_managed_note_stark_v1(&changed, &proof).is_err());
    let mut corrupt = proof.clone();
    let midpoint = corrupt.len() / 2;
    corrupt[midpoint] ^= 1;
    assert!(verify_proof_managed_note_stark_v1(&segment, &corrupt).is_err());
}

#[test]
fn scalar_segment_caps_and_counter_carries_are_explicit() {
    // Sixty-four executed steps need not mean sixty-four distinct code words.
    let (segment, records) = recorded(
        &[enc::encode_branch(wide::control::BNE, 6, 0, 0)],
        MAX_STEPS,
        &[(6, 1)],
        1_000,
    );
    assert_rows(&segment, &segment.witness_rows(&records).unwrap());
    let too_large = contract(&vec![
        enc::encode_ri(wide::arithmetic::ADDI, 6, 6, 1);
        MAX_WORDS - 3
    ]);
    assert!(
        ScalarSegment::new(
            too_large,
            segment.steps,
            segment.before,
            segment.after,
            SegmentOutcome::Continue
        )
        .is_err()
    );
    let (mut segment, mut records) = recorded(
        &[enc::encode_ri(wide::arithmetic::ADDI, 6, 6, 1)],
        1,
        &[(6, u64::MAX)],
        1 << 32,
    );
    // Exercise a later segment's full-width counters independently of the
    // root-call setup debit preceding the recorded scalar instruction.
    records[0].before.gas_remaining = 1 << 32;
    records[0].after.gas_remaining = (1 << 32) - 1;
    records[0].before.cycles = u64::from(u32::MAX);
    records[0].after.cycles = 1 << 32;
    segment.before = records[0].before;
    segment.after = records[0].after;
    let rows = segment.witness_rows(&records).unwrap();
    assert_eq!(rows[0][GAS_BORROW], F::ONE);
    assert_eq!(rows[0][CYCLE_CARRY], F::ONE);
    assert_rows(&segment, &rows);
    records[0].before.gas_remaining = 0;
    records[0].after.gas_remaining = u64::MAX;
    segment.before = records[0].before;
    segment.after = records[0].after;
    assert!(rejects(&segment, &segment.witness_rows(&records).unwrap()));
    let mut before = segment.before;
    before.cycles = u64::MAX;
    let mut after = segment.after;
    after.cycles = 0;
    assert!(
        ScalarSegment::new(
            segment.contract.clone(),
            1,
            before,
            after,
            SegmentOutcome::Continue
        )
        .is_err()
    );
}

#[test]
fn scalar_segment_enforces_artifact_and_normalized_zk_cycle_limits() {
    let body = [enc::encode_ri(wide::arithmetic::ADDI, 6, 6, 1)];
    let (unbounded, records) = recorded(&body, 1, &[(6, 9)], 1_000);
    assert_eq!(unbounded.cycle_limit(), 0);
    for (max_cycles, mode, expected_limit) in [
        (7, 0, 7),
        (0, ivm::ivm_mode::ZK, ivm::zk::MAX_CYCLES),
        (7, ivm::ivm_mode::ZK, 7),
    ] {
        let contract = contract_with_cycle_policy(&body, max_cycles, mode);
        let first_pc = (contract.code_offset() - contract.header_len()) as u64;
        let mut bounded_records = records.clone();
        bounded_records[0].before.pc = first_pc;
        bounded_records[0].after.pc = first_pc + 4;
        bounded_records[0].before.cycles = expected_limit - 1;
        bounded_records[0].after.cycles = expected_limit;
        let segment = ScalarSegment::new(
            contract.clone(),
            1,
            bounded_records[0].before,
            bounded_records[0].after,
            SegmentOutcome::Continue,
        )
        .unwrap();
        assert_eq!(segment.cycle_limit(), expected_limit);
        assert_rows(&segment, &segment.witness_rows(&bounded_records).unwrap());
        // An interpreter would reject this next attempted step before fetch.
        bounded_records[0].before.cycles = expected_limit;
        bounded_records[0].after.cycles = expected_limit + 1;
        assert!(
            ScalarSegment::new(
                contract,
                1,
                bounded_records[0].before,
                bounded_records[0].after,
                SegmentOutcome::Continue
            )
            .is_err()
        );
    }
}

#[test]
fn scalar_segment_every_interior_column_and_outside_endpoints_reject_forgery() {
    let (segment, records) = mixed();
    let rows = segment.witness_rows(&records).unwrap();
    for column in 0..ROW_WIDTH {
        let mut forged = rows[1].clone();
        forged[column] = forged[column].add(F::ONE);
        let incoming = residues(&segment, &rows[0], &forged, &segment.fixed_row(0)).unwrap();
        let outgoing = residues(&segment, &forged, &rows[2], &segment.fixed_row(1)).unwrap();
        assert!(
            incoming
                .iter()
                .chain(&outgoing)
                .any(|value| *value != F::ZERO),
            "accepted interior column {column}"
        );
    }
    let code_end = u64::from(segment.first_pc) + 4 * segment.words.len() as u64;
    for pc in [code_end, code_end + 4, u64::MAX] {
        let mut forged = records.clone();
        forged.last_mut().unwrap().after.pc = pc;
        let after = forged.last().unwrap().after;
        assert!(
            ScalarSegment::new(
                segment.contract.clone(),
                segment.steps,
                segment.before,
                after,
                SegmentOutcome::Continue
            )
            .is_err()
        );
    }
}

fn comparison_mix() -> (ScalarSegment, Vec<DiagnosticStepRecord>) {
    let body = [
        enc::encode_rr(wide::arithmetic::SLT, 8, 6, 7),
        enc::encode_rr(wide::arithmetic::SLTU, 9, 6, 7),
        enc::encode_rr(wide::arithmetic::SEQ, 20, 8, 9),
        enc::encode_rr(wide::arithmetic::SNE, 21, 8, 9),
        enc::encode_rr(wide::arithmetic::MIN, 6, 6, 7),
        enc::encode_rr(wide::arithmetic::MAX, 7, 6, 7),
        enc::encode_rr(wide::arithmetic::XOR, 22, 6, 7),
        enc::encode_branch(wide::control::BEQ, 20, 0, 2),
        enc::encode_ri(wide::arithmetic::ADDI, 23, 0, 99),
        enc::encode_ri(wide::arithmetic::ROTR_IMM, 23, 7, -1),
    ];
    recorded(
        &body,
        9,
        &[(6, i64::MIN as u64), (7, i64::MAX as u64)],
        u64::MAX,
    )
}

#[test]
fn scalar_comparisons_match_interpreter_extrema_equalities_and_all_register_shapes() {
    let extrema = [
        (i64::MIN as u64, i64::MAX as u64),
        (i64::MAX as u64, i64::MIN as u64),
        (i64::MIN as u64, i64::MIN as u64),
        (i64::MAX as u64, i64::MAX as u64),
        (u64::MAX, 0),
        (0, u64::MAX),
        (0, 0),
        (1, 1),
        (0, 1),
        (1, 0),
        (0xffff_ffff, 0x1_0000_0000),
        (0x1_0000_0000, 0xffff_ffff),
    ];
    for opcode in COMPARE_OPS {
        for (left, right) in extrema {
            let (segment, records) = recorded(
                &[enc::encode_rr(opcode, 8, 6, 7)],
                1,
                &[(6, left), (7, right)],
                1_000,
            );
            assert_rows(&segment, &segment.witness_rows(&records).unwrap());
            assert_eq!(records[0].after.pc, records[0].before.pc + 4);
            assert_eq!(records[0].after.cycles, records[0].before.cycles + 1);
            assert_eq!(
                records[0].before.gas_remaining - records[0].after.gas_remaining,
                if matches!(opcode, wide::arithmetic::MIN | wide::arithmetic::MAX) {
                    1
                } else {
                    2
                }
            );
        }
        for (rd, left, right) in [
            (8, 6, 7),
            (6, 6, 7),
            (7, 6, 7),
            (8, 6, 6),
            (6, 6, 6),
            (0, 6, 7),
            (8, 0, 7),
            (8, 6, 0),
            (0, 0, 0),
        ] {
            let (segment, records) = recorded(
                &[enc::encode_rr(opcode, rd, left, right)],
                1,
                &[(6, i64::MIN as u64), (7, i64::MAX as u64)],
                1_000,
            );
            assert_rows(&segment, &segment.witness_rows(&records).unwrap());
            assert_eq!(records[0].after.registers[0], 0);
        }
    }
}

#[test]
fn scalar_comparison_results_control_and_high_halves_cannot_be_forged() {
    for opcode in COMPARE_OPS {
        let (segment, records) = recorded(
            &[enc::encode_rr(opcode, 6, 6, 7)],
            1,
            &[(6, i64::MIN as u64), (7, i64::MAX as u64)],
            1_000,
        );
        let actual = records[0].after.registers[6];
        let mut false_results = vec![actual ^ 1, 2, actual ^ (1_u64 << 32)];
        if opcode == wide::arithmetic::MIN {
            false_results.push(records[0].before.registers[7]);
        } else if opcode == wide::arithmetic::MAX {
            false_results.push(records[0].before.registers[6]);
        }
        for result in false_results {
            let mut forged = records.clone();
            forged[0].after.registers[6] = result;
            let changed = ScalarSegment::new(
                segment.contract.clone(),
                1,
                forged[0].before,
                forged[0].after,
                SegmentOutcome::Continue,
            )
            .unwrap();
            assert!(rejects(&changed, &changed.witness_rows(&forged).unwrap()));
        }
        let rows = segment.witness_rows(&records).unwrap();
        for column in [RESULT, RESULT + 1, BRANCH + branch::TAKEN_BANK_OFFSET] {
            let mut forged = rows.clone();
            forged[0][column] = forged[0][column].add(F::ONE);
            assert!(rejects(&segment, &forged));
        }
        let mut forged = records.clone();
        forged[0].after.pc += 4; // Still a valid instruction boundary in the return sequence.
        let changed = ScalarSegment::new(
            segment.contract.clone(),
            1,
            forged[0].before,
            forged[0].after,
            SegmentOutcome::Continue,
        )
        .unwrap();
        assert!(rejects(&changed, &changed.witness_rows(&forged).unwrap()));
    }
}

#[test]
fn scalar_comparisons_mixed_with_branches_keep_degree_four_and_the_same_native_envelope() {
    let (segment, records) = comparison_mix();
    let rows = segment.witness_rows(&records).unwrap();
    assert_rows(&segment, &rows);
    assert_eq!(segment.after.registers[8], 1);
    assert_eq!(segment.after.registers[9], 0);
    assert_eq!(segment.after.registers[20], 0);
    assert_eq!(segment.after.registers[21], 1);
    assert_eq!(segment.after.registers[6], i64::MIN as u64);
    assert_eq!(segment.after.registers[7], i64::MAX as u64);
    assert_eq!(segment.base_width_v1(), 1_356);
    assert_eq!(segment.profile_constraint_count_v1(), 3_369);
    let protocol = segment.protocol_v1();
    protocol.validate().unwrap();
    let layout = AggregateProofLayoutV1::new(
        protocol.parameters,
        vec![AggregateTraceGroupLayoutV1 {
            native_trace_log2: TRACE_LOG2,
            segment_instances: 1,
            base_width: segment.base_width_v1(),
            aux_width: NOTE_COPY_AUX_WIDTH_V1,
        }],
    )
    .unwrap();
    assert_eq!(
        maximum_encoded_proof_with_deep_bytes_v1(protocol.parameters, &layout).unwrap(),
        4_153_152
    );
    assert_eq!(
        measured_maximum_affine_degree_v1(
            [0xc6; 32],
            [ROW_WIDTH, ROW_WIDTH, 0, 0, FIXED_WIDTH],
            3,
            4,
            |row, next, _, _, fixed| residues(&segment, row, next, fixed)
        ),
        4
    );
}

#[test]
fn native_stark_proves_scalar_comparisons_and_rejects_changed_results_and_signedness() {
    let (segment, records) = comparison_mix();
    let proof =
        prove_proof_managed_note_stark_v1(&segment, &segment.columns(&records).unwrap()).unwrap();
    verify_proof_managed_note_stark_v1(&segment, &proof).unwrap();
    for register in [8, 9, 20, 21, 6, 7] {
        let mut after = segment.after;
        after.registers[register] ^= 1;
        let changed = ScalarSegment::new(
            segment.contract.clone(),
            segment.steps,
            segment.before,
            after,
            SegmentOutcome::Continue,
        )
        .unwrap();
        assert!(verify_proof_managed_note_stark_v1(&changed, &proof).is_err());
    }
    let mut artifact = segment.contract.artifact().to_vec();
    let offset = segment.contract.code_offset();
    artifact[offset..offset + 4]
        .copy_from_slice(&enc::encode_rr(wide::arithmetic::SLTU, 8, 6, 7).to_le_bytes());
    let changed_contract = ivm::prepare_contract(Arc::from(artifact)).unwrap();
    let changed = ScalarSegment::new(
        changed_contract,
        segment.steps,
        segment.before,
        segment.after,
        SegmentOutcome::Continue,
    )
    .unwrap();
    assert!(verify_proof_managed_note_stark_v1(&changed, &proof).is_err());
}

#[test]
fn scalar_comparison_modes_reject_every_interior_profile_column_mutation() {
    for opcode in [
        wide::arithmetic::SLT,
        wide::arithmetic::MIN,
        wide::arithmetic::MAX,
    ] {
        let body = [
            enc::encode_ri(wide::arithmetic::ADDI, 24, 24, 0),
            enc::encode_rr(opcode, 6, 6, 7),
            enc::encode_ri(wide::arithmetic::ADDI, 25, 25, 0),
        ];
        let (segment, records) = recorded(
            &body,
            3,
            &[(6, i64::MIN as u64), (7, i64::MAX as u64)],
            1_000,
        );
        let rows = segment.witness_rows(&records).unwrap();
        assert_rows(&segment, &rows);
        for column in 0..ROW_WIDTH {
            let mut forged = rows[1].clone();
            forged[column] = forged[column].add(F::ONE);
            let incoming = residues(&segment, &rows[0], &forged, &segment.fixed_row(0)).unwrap();
            let outgoing = residues(&segment, &forged, &rows[2], &segment.fixed_row(1)).unwrap();
            assert!(
                incoming
                    .iter()
                    .chain(&outgoing)
                    .any(|value| *value != F::ZERO),
                "accepted comparison opcode {opcode:#x} column {column}"
            );
        }
    }
}

/// Change every arithmetic witness consistently while retaining the canonical
/// register read and public result. This isolates false-source binding attacks.
fn replace_auxiliary_sources(row: &mut [F], word: u32, left: u64, right: u64) {
    let selected = family(word).unwrap();
    let alu_opcode = if let Family::Alu(opcode) = selected {
        opcode
    } else {
        wide::arithmetic::ADD
    };
    let branch_opcode = match selected {
        Family::Branch(index) => BRANCH_OPS[index],
        Family::Compare(index) => BRANCH_OPS[COMPARE_PREDICATES[index]],
        Family::Move(_) => wide::control::BNE,
        _ => wide::control::BEQ,
    };
    let shift_opcode = if let Family::Shift(index) = selected {
        SHIFT_OPS[index]
    } else {
        wide::arithmetic::SLL
    };
    row[SOURCES..ALU].copy_from_slice(&word::witness(left, right));
    row[ALU..BRANCH].copy_from_slice(&alu_bank_witness(alu_opcode, left, right));
    row[BRANCH..SHIFT].copy_from_slice(&branch::bank_witness(branch_opcode, left, right));
    row[SHIFT..RESULT].copy_from_slice(&shift::bank_witness(shift_opcode, left, right));
    let active = matches!(selected, Family::Multiply(_));
    let workspace = if active {
        multiply::product_digits(left, right)
    } else {
        bit_count::witness(
            Sources::new(&row[SOURCES..ALU]).bits(0),
            matches!(selected, Family::Count(1)),
        )
    };
    row[BIT_COUNT..MULTIPLY].copy_from_slice(&workspace);
    row[MULTIPLY..ABSOLUTE].copy_from_slice(&multiply::witness(left, right, &workspace, active));
}
