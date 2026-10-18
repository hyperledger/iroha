//! Native direct-jump diagnostics and original private control/history adversaries.

use super::tests::{Fixture, bits, bytes, carries, contract, event};
use super::*;
use iroha_allocation::AllocationBudget;
use ivm::{
    IVM,
    encoding::wide as enc,
    execution_step_recorder::{
        DiagnosticStepOutcome, DiagnosticStepRecord, DiagnosticStepRecorder,
    },
    host::DefaultHost,
};
use std::sync::Arc;

fn jump(opcode: u8, displacement: i16) -> u32 {
    match opcode {
        wide::control::JAL => enc::encode_jump(opcode, 0, displacement),
        wide::control::JMP => enc::encode_offset24(opcode, i32::from(displacement)),
        _ => unreachable!("direct jump fixture"),
    }
}

fn recorded(body: &[u32], capacity: usize, gas: u64) -> (Program, DiagnosticStepRecorder) {
    recorded_with_limit(body, capacity, gas, 1_000)
}

fn recorded_with_limit(
    body: &[u32],
    capacity: usize,
    gas: u64,
    max_cycles: u64,
) -> (Program, DiagnosticStepRecorder) {
    let artifact = contract(body, max_cycles, ivm::ivm_mode::ZK);
    let mut vm = IVM::new(gas);
    vm.load_prepared(&artifact).unwrap();
    for (index, value, tag) in [(6, 91, true), (7, u64::MAX, true), (255, 37, false)] {
        vm.set_register(index, value);
        vm.registers.set_tag(index, tag);
    }
    let budget = AllocationBudget::new(capacity * std::mem::size_of::<DiagnosticStepRecord>());
    let mut recorder = DiagnosticStepRecorder::try_new(capacity, &budget).unwrap();
    // A local capacity stop is intentional for self/backward loops. These
    // snapshots are diagnostics, never an authenticated invocation initializer.
    let _outcome = vm.run_with_host_diagnostic_steps(&mut DefaultHost::default(), &mut recorder);
    (Program::new(artifact).unwrap(), recorder)
}

fn set_depth(fixture: &mut Fixture, before: u64, after: u64) {
    for (side, value) in [before, after].into_iter().enumerate() {
        bits(
            &mut fixture.row[DEPTH_BITS + side * DEPTH_BITS_PER_VALUE
                ..DEPTH_BITS + (side + 1) * DEPTH_BITS_PER_VALUE],
            value,
        );
    }
    fixture.packets.fields[CALL_DEPTH] = event(
        Space::Owner,
        0,
        CALL_DEPTH_OWNER,
        before,
        after,
        false,
        fixture.schedule.clocks[CALL_DEPTH],
        false,
        false,
    );
}

fn from_record(program: &Program, record: &DiagnosticStepRecord) -> Fixture {
    assert_eq!(record.outcome, DiagnosticStepOutcome::Completed);
    assert!(role(record.instruction.unwrap()) == Some(Role::Jump));
    let slot = usize::try_from((record.before.pc - u64::from(program.first_pc)) / 4).unwrap();
    assert_eq!(program.words[slot], record.instruction.unwrap());
    assert_eq!(record.opcode_gas, Some(2));
    assert_eq!(record.before.gas_remaining - record.after.gas_remaining, 2);
    assert_eq!(record.after.cycles, record.before.cycles + 1);
    assert_eq!(record.before.registers, record.after.registers);
    assert_eq!(record.before.tags, record.after.tags);
    assert!(!record.before.halted && !record.after.halted);
    let mut fixture = Fixture::with_controls(
        program,
        slot,
        false,
        0,
        record.before.gas_remaining,
        record.before.cycles,
    );
    set_depth(&mut fixture, 0, 0);
    for (slot, owner, before, after, word) in [
        (
            GAS_DEBIT,
            GAS_OWNER,
            record.before.gas_remaining,
            record.after.gas_remaining,
            2,
        ),
        (
            CYCLE_WRITE,
            CYCLE_OWNER,
            record.before.cycles,
            record.after.cycles,
            4,
        ),
    ] {
        fixture.packets.fields[slot] = event(
            Space::Owner,
            0,
            owner,
            before,
            after,
            true,
            fixture.schedule.clocks[slot],
            false,
            false,
        );
        bits(
            &mut fixture.row[WORDS + word * 64..WORDS + (word + 1) * 64],
            after,
        );
    }
    fixture.packets.fields[PC_WRITE] = event(
        Space::Owner,
        0,
        PC_OWNER,
        record.before.pc,
        record.after.pc,
        true,
        fixture.schedule.clocks[PC_WRITE],
        false,
        false,
    );
    assert!(fixture.accepts(program));
    fixture
}

#[test]
fn native_direct_jumps_bind_forward_backward_and_self_targets_without_register_effects() {
    for opcode in [wide::control::JAL, wide::control::JMP] {
        for displacement in [0, 1, 2] {
            let (program, recorder) = recorded(
                &[jump(opcode, displacement), jump(opcode, 1), jump(opcode, 1)],
                4,
                100,
            );
            let first = recorder.records().first().unwrap();
            assert_eq!(first.after.pc, first.before.pc + displacement as u64 * 4);
            for record in recorder.records() {
                if record
                    .instruction
                    .is_some_and(|word| role(word) == Some(Role::Jump))
                {
                    from_record(&program, record);
                }
            }
        }
        let (program, recorder) = recorded(&[jump(opcode, 1), jump(opcode, -1)], 4, 100);
        assert_eq!(recorder.records().len(), 4);
        for (index, record) in recorder.records().iter().enumerate() {
            assert_eq!(
                record.before.pc,
                u64::from(program.first_pc) + (index as u64 % 2) * 4
            );
            from_record(&program, record);
        }
    }
}

#[test]
fn native_direct_jumps_preserve_the_outer_protected_return_and_private_tags() {
    for opcode in [wide::control::JAL, wide::control::JMP] {
        let (program, recorder) = recorded(
            &[jump(opcode, 2), jump(opcode, 0), jump(opcode, 1)],
            16,
            2_000,
        );
        let end = recorder.end().unwrap();
        assert_eq!(end.outcome, Ok(()));
        assert!(end.state.halted);
        assert_eq!(end.state.pc, program.code_end());
        assert_eq!(end.state.registers[6], 91);
        assert_eq!(end.state.registers[7], u64::MAX);
        assert!(end.state.tags[6] && end.state.tags[7]);
        assert_eq!(recorder.records().len(), 6);
        for record in &recorder.records()[..2] {
            from_record(&program, record);
        }
    }
}

#[test]
fn direct_jump_controls_reject_coherent_wrong_pc_gas_cycles_depth_and_halt() {
    for opcode in [wide::control::JAL, wide::control::JMP] {
        let (program, recorder) =
            recorded(&[jump(opcode, 2), jump(opcode, 0), jump(opcode, 1)], 1, 100);
        let record = &recorder.records()[0];
        let fixture = from_record(&program, record);
        for target in [
            record.before.pc,
            record.before.pc + 4,
            program.code_end(),
            u64::MAX,
        ] {
            let mut bad = fixture.clone();
            bad.packets.fields[PC_WRITE] = event(
                Space::Owner,
                0,
                PC_OWNER,
                record.before.pc,
                target,
                true,
                bad.schedule.clocks[PC_WRITE],
                false,
                false,
            );
            assert!(!bad.accepts(&program), "wrong target {target}");
        }
        for debit in [0, 1, 3] {
            let mut bad = fixture.clone();
            let after = record.before.gas_remaining - debit;
            bits(&mut bad.row[WORDS + 2 * 64..WORDS + 3 * 64], after);
            carries(
                &mut bad.row[CARRIES..CARRIES + 4],
                record.before.gas_remaining,
                debit,
                true,
            );
            bad.packets.fields[GAS_DEBIT] = event(
                Space::Owner,
                0,
                GAS_OWNER,
                record.before.gas_remaining,
                after,
                true,
                bad.schedule.clocks[GAS_DEBIT],
                false,
                false,
            );
            assert!(!bad.accepts(&program), "wrong debit {debit}");
        }
        for cycles in [0, 2, 12] {
            let mut bad = fixture.clone();
            let after = record.before.cycles + cycles;
            bits(&mut bad.row[WORDS + 4 * 64..WORDS + 5 * 64], after);
            carries(
                &mut bad.row[CARRIES + 4..CARRIES + 8],
                record.before.cycles,
                cycles,
                false,
            );
            bad.packets.fields[CYCLE_WRITE] = event(
                Space::Owner,
                0,
                CYCLE_OWNER,
                record.before.cycles,
                after,
                true,
                bad.schedule.clocks[CYCLE_WRITE],
                false,
                false,
            );
            assert!(!bad.accepts(&program), "wrong cycles {cycles}");
        }
        for depth in [0, 1, 1023, MAX_CONTRACT_CALL_DEPTH as u64] {
            let mut same = fixture.clone();
            set_depth(&mut same, depth, depth);
            assert!(same.accepts(&program));
            let mut changed = same.clone();
            set_depth(&mut changed, depth, depth ^ 1);
            assert!(!changed.accepts(&program));
            changed.packets.fields[CALL_DEPTH][WRITE] = F::ONE;
            assert!(!changed.accepts(&program));
        }
        let mut overflow = fixture.clone();
        set_depth(&mut overflow, 1025, 1025);
        assert!(!overflow.accepts(&program));
        let mut halted = fixture.clone();
        halted.packets.fields[RUNNING_WRITE][AFTER] = F::ZERO;
        halted.row[HALT] = F::ONE;
        assert!(!halted.accepts(&program));
    }
}

#[test]
fn direct_jumps_reject_every_extra_register_frame_and_memory_producer() {
    for opcode in [wide::control::JAL, wide::control::JMP] {
        let program = Program::new(contract(&[jump(opcode, 1)], 1_000, ivm::ivm_mode::ZK)).unwrap();
        let fixture = Fixture::new(&program, 0, false, 0);
        assert!(fixture.accepts(&program));
        for slot in 0..PORTS {
            if [
                PC_READ,
                GAS_DEBIT,
                CALL_DEPTH,
                PC_WRITE,
                CYCLE_WRITE,
                RUNNING_WRITE,
            ]
            .contains(&slot)
            {
                continue;
            }
            assert_eq!(fixture.packets.fields[slot], [F::ZERO; packet::WIDTH]);
            for field in 0..packet::WIDTH {
                let mut bad = fixture.clone();
                bad.packets.fields[slot][field] = F::ONE;
                assert!(!bad.accepts(&program), "extra slot {slot} field {field}");
            }
            let mut bad = fixture.clone();
            bad.packets.fields[slot] = event(
                Space::Register,
                0,
                1,
                0,
                7,
                true,
                bad.schedule.clocks[slot],
                false,
                false,
            );
            assert!(!bad.accepts(&program));
        }
    }
}

#[test]
fn direct_jump_encoding_scope_and_prepared_target_ownership_remain_exact() {
    for displacement in [i16::MIN, -1, 0, i16::MAX] {
        assert!(role(jump(wide::control::JAL, displacement)) == Some(Role::Jump));
    }
    for displacement in [-0x80_0000, -1, 0, 0x7f_ffff] {
        assert!(role(enc::encode_offset24(wide::control::JMP, displacement)) == Some(Role::Jump));
    }
    assert!(role(enc::encode_jump(wide::control::JAL, 1, 1)) == Some(Role::Child));
    for instruction in [
        enc::encode_jump(wide::control::JAL, 2, 1),
        enc::encode_jump(wide::control::JAL, 255, 1),
        enc::encode_ri(wide::control::JALR, 1, 1, 0),
        enc::encode_ri(wide::control::JALR, 0, 2, 0),
        enc::encode_ri(wide::control::JALR, 0, 1, 1),
        enc::encode_rr(wide::control::JR, 0, 2, 0),
    ] {
        assert!(role(instruction).is_none());
        let admitted = contract(&[jump(wide::control::JAL, 1)], 1_000, ivm::ivm_mode::ZK);
        let mut artifact = admitted.artifact().to_vec();
        let offset = admitted.code_offset();
        artifact[offset..offset + 4].copy_from_slice(&instruction.to_le_bytes());
        if let Ok(unsupported) = ivm::prepare_contract(Arc::from(artifact)) {
            let mut vm = IVM::new(100);
            vm.load_prepared(&unsupported).unwrap();
            let budget = AllocationBudget::new(4 * std::mem::size_of::<DiagnosticStepRecord>());
            let mut recorder = DiagnosticStepRecorder::try_new(4, &budget).unwrap();
            assert!(
                vm.run_with_host_diagnostic_steps(&mut DefaultHost::default(), &mut recorder)
                    .is_err()
            );
            assert!(matches!(
                recorder.records()[0].outcome,
                DiagnosticStepOutcome::Trapped(_)
            ));
            let valid = Program::new(admitted).unwrap();
            let forged = Fixture::new(&valid, 0, false, 0);
            assert!(!forged.accepts(&Program::new(unsupported).unwrap()));
        }
    }
    for opcode in [wide::control::JAL, wide::control::JMP] {
        let admitted = contract(&[jump(opcode, 1)], 1_000, ivm::ivm_mode::ZK);
        for displacement in [-1, 5, i16::MAX] {
            let mut artifact = admitted.artifact().to_vec();
            let offset = admitted.code_offset();
            artifact[offset..offset + 4].copy_from_slice(&jump(opcode, displacement).to_le_bytes());
            assert!(ivm::prepare_contract(Arc::from(artifact)).is_err());
        }
        let original_program = Program::new(admitted).unwrap();
        let original = Fixture::new(&original_program, 0, false, 0);
        let changed = Program::new(contract(&[jump(opcode, 0)], 1_000, ivm::ivm_mode::ZK)).unwrap();
        assert!(!original.accepts(&changed));
        let mut missing_fetch = original.clone();
        missing_fetch.row[FETCH] = F::ZERO;
        assert!(!missing_fetch.accepts(&original_program));
        let mut duplicate_fetch = original.clone();
        duplicate_fetch.row[FETCH + 1] = F::ONE;
        assert!(!duplicate_fetch.accepts(&original_program));
    }
}

#[test]
fn native_direct_jump_oog_and_cycle_limit_cannot_be_successful_rows() {
    let root = crate::ivm_test_support::unit_callable(0);
    let root_gas = (root.result_word_count().unwrap() * (ivm::call::CALL_WORD_BYTES_V1 + 1)) as u64;
    for opcode in [wide::control::JAL, wide::control::JMP] {
        let (program, recorder) = recorded(&[jump(opcode, 0)], 4, root_gas + 1);
        let record = &recorder.records()[0];
        assert_eq!(
            record.outcome,
            DiagnosticStepOutcome::Trapped(ivm::error::VmTrapKind::OutOfGas)
        );
        assert_eq!(record.before, record.after);
        let mut forged = Fixture::with_controls(&program, 0, false, 0, 2, 0);
        bits(&mut forged.row[WORDS + 64..WORDS + 2 * 64], 1);
        bits(&mut forged.row[WORDS + 2 * 64..WORDS + 3 * 64], u64::MAX);
        carries(&mut forged.row[CARRIES..CARRIES + 4], 1, 2, true);
        forged.packets.fields[GAS_DEBIT] = event(
            Space::Owner,
            0,
            GAS_OWNER,
            1,
            u64::MAX,
            true,
            forged.schedule.clocks[GAS_DEBIT],
            false,
            false,
        );
        assert!(!forged.accepts(&program));
        let (limited, captured) = recorded_with_limit(&[jump(opcode, 0)], 4, 100, 1);
        assert_eq!(captured.records().len(), 1);
        from_record(&limited, &captured.records()[0]);
        assert_eq!(
            captured.end().unwrap().outcome,
            Err(ivm::error::VmTrapKind::ExceededMaxCycles)
        );
        assert_eq!(captured.end().unwrap().state.cycles, 1);
        let allowed = Fixture::with_controls(&program, 0, false, 0, 2, 999);
        assert!(allowed.accepts(&program));
        let mut late = allowed.clone();
        bits(&mut late.row[WORDS + 3 * 64..WORDS + 4 * 64], 1_000);
        bits(&mut late.row[WORDS + 4 * 64..WORDS + 5 * 64], 1_001);
        bits(&mut late.row[WORDS + 9 * 64..WORDS + 10 * 64], u64::MAX);
        carries(&mut late.row[CARRIES + 4..CARRIES + 8], 1_000, 1, false);
        carries(&mut late.row[CARRIES + 16..CARRIES + 20], 999, 1_000, true);
        late.packets.fields[CYCLE_WRITE] = event(
            Space::Owner,
            0,
            CYCLE_OWNER,
            1_000,
            1_001,
            true,
            late.schedule.clocks[CYCLE_WRITE],
            false,
            false,
        );
        assert!(!late.accepts(&program));
    }
}

#[test]
fn direct_jumps_keep_the_original_twenty_one_ports_and_fixed_degree_geometry() {
    use crate::execution_proofs::stark::proof_managed_note_stark::degree_audit::measured_maximum_affine_degree_v1;
    assert_eq!(PORTS, 21);
    let program = Program::new(contract(
        &[
            jump(wide::control::JMP, 0),
            jump(wide::control::JAL, -1),
            enc::encode_branch(wide::control::BEQ, 6, 7, -1),
            enc::encode_rr(wide::arithmetic::CMOV, 4, 6, 7),
        ],
        1_000,
        ivm::ivm_mode::ZK,
    ))
    .unwrap();
    let fixtures: Vec<_> = [Some(0), Some(1), None]
        .into_iter()
        .map(|slot| {
            slot.map_or_else(Fixture::padding, |slot| {
                Fixture::new(&program, slot, false, 0)
            })
        })
        .collect();
    let mut lengths = Vec::new();
    for fixture in &fixtures {
        let mut out = Vec::new();
        append_residues(
            &mut out,
            &program,
            fixture.schedule,
            &fixture.row,
            &fixture.packets,
        );
        assert!(out.iter().all(|value| *value == F::ZERO));
        lengths.push(out.len());
        assert_eq!(fixture.packets.fields.len(), 21);
        assert_eq!(fixture.row.len(), SCALAR + scalar::WIDTH);
    }
    assert!(lengths.windows(2).all(|pair| pair[0] == pair[1]));
    let schedule = fixtures[0].schedule;
    for (composed, maximum) in [(false, 2), (true, 4)] {
        let measured = measured_maximum_affine_degree_v1(
            [0xb7; 32],
            [WIDTH + PORTS * packet::WIDTH, 0, 0, 0, 0],
            8,
            maximum,
            |row, _, _, _, _| {
                let packets = OriginalPackets::candidate(core::array::from_fn(|slot| {
                    row[WIDTH + slot * packet::WIDTH..WIDTH + (slot + 1) * packet::WIDTH]
                        .try_into()
                        .unwrap()
                }));
                let mut out = Vec::new();
                if composed {
                    append_residues(
                        &mut out,
                        &program,
                        schedule,
                        row[..WIDTH].try_into().unwrap(),
                        &packets,
                    );
                } else {
                    append_control_residues(
                        &mut out,
                        &program,
                        schedule,
                        row[..WIDTH].try_into().unwrap(),
                        &packets,
                    );
                }
                Ok::<_, core::convert::Infallible>(out)
            },
        );
        assert_eq!(measured, usize::from(maximum));
    }
}

#[test]
fn every_original_direct_jump_port_joins_all_private_history_stages() {
    use super::super::{
        E, NOTE_COPY_WIDTH_V1, ORDERED, PublicPacketBus, ROW_WIDTH, SORTED, permutation,
        private_history,
    };
    use packet::Event;
    fn history_accepts(fixture: &Fixture, substitution: Option<(usize, bool)>) -> bool {
        let mut original = fixture.packets.clone();
        let mut events = original
            .fields
            .iter()
            .map(|fields| {
                (fields[ENABLED] == F::ONE).then(|| Event {
                    space: Space::Owner,
                    vm: fields[VM].0 as u8,
                    generation: fields[GENERATION].0 as u16,
                    index: fields[INDEX].0 as u32,
                    write: fields[WRITE] == F::ONE,
                    before: bytes(packet::half(fields, BEFORE, 0)),
                    after: bytes(packet::half(fields, AFTER, 0)),
                    before_private: fields[BEFORE_TAG].0 as u16,
                    after_private: fields[AFTER_TAG].0 as u16,
                })
            })
            .collect::<Vec<_>>();
        if let Some((slot, missing)) = substitution {
            if missing {
                events[slot] = None;
            } else {
                let changed = events[slot].as_mut().unwrap();
                let replacement = u64::from_le_bytes(changed.after[..8].try_into().unwrap()) + 1;
                changed.after = bytes(replacement);
                if !changed.write {
                    changed.before = changed.after;
                    let index = changed.index;
                    let before = changed.before;
                    // Preserve the alternative sorted history's PC read/write
                    // continuity so the original-source join is the rejecting gate.
                    for alias in events
                        .iter_mut()
                        .flatten()
                        .filter(|event| event.index == index)
                    {
                        alias.before = before;
                        if !alias.write {
                            alias.after = before;
                        }
                    }
                }
            }
        }
        // Test-only initializers establish local history coherence, with no
        // assertion about invocation initialization or finalized State custody.
        let mut first = std::collections::BTreeMap::new();
        for event in events.iter().flatten() {
            first.entry(event.index).or_insert_with(|| {
                Some(Event {
                    space: Space::Owner,
                    vm: 7,
                    generation: 0,
                    index: event.index,
                    write: true,
                    before: [0; 16],
                    after: event.before,
                    before_private: 0,
                    after_private: 0,
                })
            });
        }
        let prefix = first.len();
        let mut all = first.into_values().collect::<Vec<_>>();
        all.extend(events);
        for (slot, fields) in original.fields.iter_mut().enumerate() {
            if fields[ENABLED] == F::ONE {
                fields[CLOCK] = F((prefix + slot) as u64);
            }
        }
        let bus = PublicPacketBus::new(all).unwrap();
        let columns = bus.columns();
        let challenges = permutation::Challenges::testing(
            E::canonical([2, 1, 0, 0]).unwrap(),
            E::canonical([7, 0, 1, 0]).unwrap(),
        );
        let aux = permutation::columns(
            &columns[NOTE_COPY_WIDTH_V1 + ORDERED..NOTE_COPY_WIDTH_V1 + SORTED],
            &columns[NOTE_COPY_WIDTH_V1 + SORTED..NOTE_COPY_WIDTH_V1 + super::super::PREVIOUS],
            &challenges,
            bus.size(),
        )
        .unwrap();
        let rows = (0..bus.size())
            .map(|i| {
                core::array::from_fn::<_, ROW_WIDTH, _>(|column| {
                    columns[NOTE_COPY_WIDTH_V1 + column][i]
                })
            })
            .collect::<Vec<_>>();
        let aux_rows = (0..bus.size())
            .map(|i| aux.iter().map(|column| column[i]).collect::<Vec<_>>())
            .collect::<Vec<_>>();
        let schedule = private_history::Schedule::new(bus.trace_log2, 1).unwrap();
        let fixed = (0..bus.size())
            .map(|i| schedule.fixed(i).unwrap())
            .collect::<Vec<_>>();
        let mut residues = Vec::new();
        for i in 0..bus.size() {
            let next = (i + 1) % bus.size();
            private_history::append_residues(
                &mut residues,
                &rows[i],
                &rows[next],
                &aux_rows[i],
                &aux_rows[next],
                &fixed[i],
                rows[i][ORDERED..SORTED].try_into().unwrap(),
                &challenges,
            );
            assert!(
                residues.iter().all(|value| *value == F::ZERO),
                "locally valid alternative history at row {i}, substitution {substitution:?}"
            );
            residues.clear();
        }
        let windows = core::array::from_fn(|index| {
            let i = prefix * super::super::PHASES + index;
            HistoryRow {
                current: &rows[i],
                next: &rows[i + 1],
                aux: &aux_rows[i],
                next_aux: &aux_rows[i + 1],
                fixed: &fixed[i],
            }
        });
        original.append_history_residues(&mut residues, &windows, &challenges);
        residues.iter().all(|value| *value == F::ZERO)
    }
    for opcode in [wide::control::JAL, wide::control::JMP] {
        let (program, recorder) = recorded(&[jump(opcode, 1)], 1, 100);
        let fixture = from_record(&program, &recorder.records()[0]);
        assert!(history_accepts(&fixture, None));
        for slot in [
            PC_READ,
            GAS_DEBIT,
            CALL_DEPTH,
            PC_WRITE,
            CYCLE_WRITE,
            RUNNING_WRITE,
        ] {
            for missing in [false, true] {
                assert!(
                    !history_accepts(&fixture, Some((slot, missing))),
                    "slot {slot} missing {missing}"
                );
            }
        }
    }
}
