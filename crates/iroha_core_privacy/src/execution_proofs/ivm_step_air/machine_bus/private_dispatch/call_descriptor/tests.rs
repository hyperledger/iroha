//! Original callable/descriptor joins, complete history substitutions and native CALL boundaries.

use super::super::tests as dispatch_tests;
use super::*;
use ivm::{Memory, encoding::wide as enc};
use packet::{
    AFTER, AFTER_TAG, BEFORE_TAG, CLOCK, ENABLED, Event, GENERATION, INDEX, KEY, SPACE, Space, VM,
    WRITE,
};

#[derive(Clone)]
pub(super) struct Fixture {
    pub(super) dispatch: [F; super::super::WIDTH],
    pub(super) descriptor: [F; frame_descriptor::WIDTH],
    pub(super) frame_work: [F; FRAME_WORK_WIDTH],
    pub(super) packets: [[F; packet::WIDTH]; PORTS],
    pub(super) schedule: Schedule,
}
impl Fixture {
    pub(super) fn new(program: &Program, slot: usize) -> Self {
        Self::from_dispatch(
            program,
            slot,
            dispatch_tests::Fixture::with_controls(program, slot, false, 0, 10_000_000, 100),
        )
    }
    pub(super) fn from_dispatch(
        program: &Program,
        slot: usize,
        dispatch: dispatch_tests::Fixture,
    ) -> Self {
        let shape = callable(program, slot).map(|c| {
            (
                c.entry_pc,
                u64::from(c.frame_bytes),
                c.argument_word_count().unwrap() as u64,
                c.result_word_count().unwrap() as u64,
            )
        });
        let (entry, frame, arguments, results) = shape.unwrap_or((0, 0, 0, 0));
        let (descriptor, ports) = frame_descriptor::tests::callable_lookup_witness(
            entry,
            frame,
            arguments,
            results,
            shape.is_some(),
        );
        let schedule = Schedule::new(7, 64).unwrap();
        let mut packets = [[F::ZERO; packet::WIDTH]; PORTS];
        for (slot, p) in dispatch.packets.fields.iter().enumerate() {
            packets[dispatch_slot(slot)] = *p;
        }
        for (slot, original) in ports.iter().enumerate() {
            packets[descriptor_slot(slot)] = *original;
        }
        for (slot, source) in VALIDATION_SOURCES.into_iter().enumerate() {
            packets[VALIDATION_START + slot] = ports[source];
        }
        let mut frame_work = [F::ZERO; FRAME_WORK_WIDTH];
        if let Some(callable) = callable(program, slot) {
            let cost = super::frame_work(callable);
            let before = packet::half(&dispatch.packets.fields[super::super::GAS_DEBIT], AFTER, 0);
            dispatch_tests::bits(&mut frame_work[..64], before.wrapping_sub(cost));
            dispatch_tests::carries(&mut frame_work[64..], before, cost, true);
            let mut debit = dispatch.packets.fields[super::super::GAS_DEBIT];
            for limb in 0..8 {
                debit[BEFORE + limb] =
                    dispatch.packets.fields[super::super::GAS_DEBIT][AFTER + limb];
                debit[AFTER + limb] = if limb < 4 {
                    gas_limb(&frame_work, limb)
                } else {
                    F::ZERO
                };
            }
            packets[FRAME_DEBIT] = debit;
        }
        for (slot, p) in packets.iter_mut().enumerate() {
            if p[ENABLED] == F::ONE {
                p[CLOCK] = F(u64::from(schedule.clock(slot)));
            }
        }
        Self {
            dispatch: dispatch.row,
            descriptor,
            frame_work,
            packets,
            schedule,
        }
    }
    pub(super) fn padding(program: &Program) -> Self {
        Self::from_dispatch(program, usize::MAX, dispatch_tests::Fixture::padding())
    }
    pub(super) fn borrowed(&self) -> Row<'_> {
        Row {
            dispatch: &self.dispatch,
            descriptor: &self.descriptor,
            frame_work: &self.frame_work,
            packets: core::array::from_fn(|slot| &self.packets[slot]),
        }
    }
    pub(super) fn residues(&self, program: &Program) -> Vec<F> {
        let mut out = Vec::new();
        append_semantics(&mut out, program, self.schedule, &self.borrowed());
        out
    }
    pub(super) fn accepts(&self, program: &Program) -> bool {
        self.residues(program).iter().all(|x| *x == F::ZERO)
    }
}
fn program(jals: bool, backwards: bool, frame: u32) -> (Program, usize) {
    let slot = if backwards { 1 } else { 0 };
    let offset = if backwards { -1 } else { 2 };
    let call = if jals {
        enc::encode_offset24(wide::control::JALS, offset)
    } else {
        enc::encode_jump(wide::control::JAL, 1, offset as i16)
    };
    let halt = enc::encode_halt();
    let body = if backwards {
        [halt, call, halt]
    } else {
        [call, halt, halt]
    };
    (
        Program::new(dispatch_tests::contract_with_frame_at(
            &body,
            1000,
            ivm::ivm_mode::ZK,
            frame,
            slot as u64 * 4,
        ))
        .unwrap(),
        slot,
    )
}

#[test]
fn callable_fields_come_from_the_original_artifact_for_both_call_encodings_and_coordinates() {
    for jals in [false, true] {
        for backwards in [false, true] {
            for frame in [0, 16, 128] {
                let (program, slot) = program(jals, backwards, frame);
                assert_eq!(
                    program.artifact().contract_interface().entrypoints[0].entry_pc,
                    slot as u64 * 4,
                    "the original CALL is reachable from its declared entrypoint"
                );
                let c = callable(&program, slot).unwrap();
                assert_eq!(c.entry_pc, if backwards { 0 } else { 8 });
                assert_eq!(c.frame_bytes, frame);
                assert!(program.first_pc > 0);
                let fixture = Fixture::new(&program, slot);
                assert!(fixture.accepts(&program));
                assert_eq!(
                    packet::half(&fixture.packets[descriptor_slot(16)], AFTER, 0),
                    c.entry_pc
                );
                assert_eq!(
                    packet::half(
                        &fixture.packets[dispatch_slot(super::super::PC_WRITE)],
                        AFTER,
                        0
                    ),
                    u64::from(program.first_pc) + c.entry_pc
                );
            }
        }
    }
}

#[test]
fn original_fetch_cannot_borrow_another_callable_or_accept_a_non_call_running_row() {
    let (program, slot) = program(false, false, 16);
    let fixture = Fixture::new(&program, slot);
    assert!(fixture.accepts(&program));
    let (other, _) = program_for_other_frame();
    assert!(
        !fixture.accepts(&other),
        "coherent artifact with different callable frame cannot reuse descriptor"
    );
    // Change the fetched CALL to another in-code destination with no callable.
    // This deliberately forged Program is available only to this private test;
    // production construction always owns the prepared immutable artifact.
    let mut missing = Program::new(program.artifact().clone()).unwrap();
    let mut words = missing.words.to_vec();
    words[slot] = enc::encode_jump(wide::control::JAL, 1, 1);
    let bytes = words
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect::<Vec<_>>();
    missing.words = super::super::code_words::CodeWords::new(&bytes).unwrap();
    let dispatch = dispatch_tests::Fixture::new(&missing, slot, false, 0);
    assert!(dispatch.accepts(&missing));
    let bad = Fixture::from_dispatch(&missing, slot, dispatch);
    assert!(!bad.accepts(&missing));
    for word in [
        enc::encode_jump(wide::control::JAL, 0, 1),
        enc::encode_ri(wide::control::JALR, 0, 1, 0),
        enc::encode_load(wide::memory::LOAD64, 3, 2, 0),
    ] {
        let p = Program::new(dispatch_tests::contract(
            &[word, enc::encode_halt()],
            1000,
            ivm::ivm_mode::ZK,
        ))
        .unwrap();
        let mut dispatch = dispatch_tests::Fixture::new(&p, 0, false, 0);
        if super::super::role(word) == Some(Role::Load) {
            // The canonical dispatcher consumes the LOAD's original atomic
            // destination even before the memory-success bank supplies its value.
            let slot = super::super::SCALAR_DESTINATION;
            dispatch.packets.fields[slot] = dispatch_tests::event(
                Space::Register,
                0,
                u32::try_from(wide::rd(word)).expect("bounded register index"),
                7,
                11,
                true,
                dispatch.schedule.clocks[slot],
                false,
                false,
            );
        }
        assert!(
            dispatch.accepts(&p),
            "valid non-CALL instruction {word:08x}"
        );
        assert!(!Fixture::from_dispatch(&p, 0, dispatch).accepts(&p));
    }
    fn program_for_other_frame() -> (Program, usize) {
        self::program(false, false, 128)
    }
}

#[test]
fn a_coherent_detached_descriptor_cannot_replace_any_artifact_callable_field() {
    let (program, slot) = program(false, false, 128);
    let fixture = Fixture::new(&program, slot);
    assert!(fixture.accepts(&program));
    for shape in [
        (12, 128, 0, 1),
        (8, 144, 0, 1),
        (8, 128, 1, 1),
        (8, 128, 0, 2),
    ] {
        // Verify each forged shape in the standalone descriptor bank before
        // requiring the composed relation to bind it to the original artifact.
        let (descriptor, mut packets) = frame_descriptor::tests::callable_lookup_witness(
            shape.0, shape.1, shape.2, shape.3, true,
        );
        let mut bad = fixture.clone();
        bad.descriptor = descriptor;
        for (i, p) in packets.iter_mut().enumerate() {
            if p[ENABLED] == F::ONE {
                p[CLOCK] = F(u64::from(bad.schedule.clock(descriptor_slot(i))));
            }
        }
        let mut standalone = Vec::new();
        frame_descriptor::append_residues(
            &mut standalone,
            bad.schedule.descriptor(),
            &descriptor,
            F::ONE,
            &super::super::super::callable_lookup::SelectedCallable::unbound_diagnostic(
                core::array::from_fn(|i| super::super::constant_limb(shape.0, i)),
                F(shape.1),
                F(shape.2),
                F(shape.3),
            ),
            frame_descriptor::Ports {
                active: &bad.packets[dispatch_slot(super::super::CHILD_ACTIVE)],
                packets: core::array::from_fn(|i| &packets[i]),
            },
        );
        assert!(standalone.iter().all(|residue| *residue == F::ZERO));
        for (slot, original) in packets.iter().enumerate() {
            bad.packets[descriptor_slot(slot)] = *original;
        }
        assert!(!bad.accepts(&program), "detached callable fields {shape:?}");
    }
}

#[test]
fn descriptor_and_lifecycle_original_substitutions_refuse_and_padding_is_canonical() {
    let (program, slot) = program(true, false, 128);
    let fixture = Fixture::new(&program, slot);
    assert!(fixture.accepts(&program));
    for descriptor_slot in 0..17 {
        if fixture.packets[super::descriptor_slot(descriptor_slot)][ENABLED] == F::ZERO {
            continue;
        }
        for field in [
            KEY, GENERATION, INDEX, CLOCK, ENABLED, BEFORE_TAG, AFTER_TAG,
        ] {
            let mut bad = fixture.clone();
            bad.packets[super::descriptor_slot(descriptor_slot)][field] =
                bad.packets[super::descriptor_slot(descriptor_slot)][field].add(F(7));
            assert!(
                !bad.accepts(&program),
                "descriptor {descriptor_slot}, field {field}"
            );
        }
        for limb in 0..8 {
            let mut bad = fixture.clone();
            bad.packets[super::descriptor_slot(descriptor_slot)][AFTER + limb] = bad.packets
                [super::descriptor_slot(descriptor_slot)][AFTER + limb]
                .add(F(0x0123_4567));
            assert!(!bad.accepts(&program));
        }
    }
    for slot in [
        super::super::CHILD_COUNTER,
        super::super::CHILD_ACTIVE,
        super::super::CHILD_PARENT,
    ] {
        for field in [KEY, BEFORE, AFTER, GENERATION] {
            let mut bad = fixture.clone();
            let p = &mut bad.packets[dispatch_slot(slot)];
            p[field] = p[field].add(F(0x0123_4567));
            assert!(!bad.accepts(&program));
        }
    }
    let padding = Fixture::padding(&program);
    assert!(padding.accepts(&program));
    for slot in DESCRIPTOR_START..dispatch_slot(super::super::CHILD_COUNTER) {
        for field in 0..packet::WIDTH {
            let mut bad = padding.clone();
            bad.packets[slot][field] = F::ONE;
            assert!(!bad.accepts(&program));
        }
    }
}

#[test]
fn composed_descriptor_geometry_and_degree_remain_explicit() {
    use crate::execution_proofs::stark::proof_managed_note_stark::degree_audit::measured_maximum_affine_degree_v1;
    let (program, _) = program(false, false, 128);
    let degree = measured_maximum_affine_degree_v1(
        [0xcb; 32],
        [WIDTH, 0, 0, 0, 0],
        4,
        4,
        |values, _, _, _, _| {
            let original_banks = super::super::WIDTH + frame_descriptor::WIDTH;
            let banks = original_banks + FRAME_WORK_WIDTH;
            let row = Row {
                dispatch: values[..super::super::WIDTH].try_into().unwrap(),
                descriptor: values[super::super::WIDTH..original_banks]
                    .try_into()
                    .unwrap(),
                frame_work: values[original_banks..banks].try_into().unwrap(),
                packets: core::array::from_fn(|slot| {
                    values[banks + slot * packet::WIDTH..banks + (slot + 1) * packet::WIDTH]
                        .try_into()
                        .unwrap()
                }),
            };
            let mut out = Vec::new();
            append_semantics(&mut out, &program, Schedule::new(7, 64).unwrap(), &row);
            Ok::<_, core::convert::Infallible>(out)
        },
    );
    assert_eq!(degree, 4);
    assert_eq!(
        (WIDTH, PORTS, PORTS * super::super::super::PHASES),
        (4801, 47, 376)
    );
    assert!(Schedule::new(7, u32::MAX - 46).is_some());
    assert!(Schedule::new(7, u32::MAX - 45).is_none());
}

#[test]
fn all_forty_seven_original_packets_and_all_eight_stages_share_one_private_history() {
    use super::super::super::{
        E, NOTE_COPY_WIDTH_V1, ORDERED, PREVIOUS, PublicPacketBus, ROW_WIDTH, SORTED,
    };
    let (program, slot) = program(false, false, 128);
    let fixture = Fixture::new(&program, slot);
    assert!(fixture.accepts(&program));
    let to_event = |p: &[F; packet::WIDTH]| Event {
        space: match p[SPACE].0 {
            1 => Space::Memory,
            2 => Space::Register,
            3 => Space::Initialization,
            4 => Space::Owner,
            _ => panic!("enabled typed event"),
        },
        vm: p[VM].0 as u8,
        generation: p[GENERATION].0 as u16,
        index: p[INDEX].0 as u32,
        write: p[WRITE] == F::ONE,
        before: core::array::from_fn(|i| ((p[BEFORE + i / 2].0 >> (8 * (i % 2))) & 255) as u8),
        after: core::array::from_fn(|i| ((p[AFTER + i / 2].0 >> (8 * (i % 2))) & 255) as u8),
        before_private: p[BEFORE_TAG].0 as u16,
        after_private: p[AFTER_TAG].0 as u16,
    };
    let original = fixture.borrowed();
    let mut events = vec![None; 64];
    let mut keys = std::collections::BTreeSet::new();
    let mut next = 0;
    for slot in 0..PORTS {
        let p = original.producer(slot);
        if p[ENABLED] != F::ONE {
            continue;
        }
        if keys.insert(p[KEY].0) {
            let source = to_event(p);
            events[next] = Some(Event {
                write: true,
                before: [0; 16],
                after: source.before,
                before_private: 0,
                after_private: source.before_private,
                ..source
            });
            next += 1;
        }
    }
    assert!(next < 64);
    for slot in 0..PORTS {
        let p = original.producer(slot);
        events.push((p[ENABLED] == F::ONE).then(|| to_event(p)));
    }
    let bus = PublicPacketBus::new(events).unwrap();
    let columns = bus.columns();
    let challenges = permutation::Challenges::testing(
        E::canonical([2, 1, 0, 0]).unwrap(),
        E::canonical([7, 0, 1, 0]).unwrap(),
    );
    let aux = permutation::columns(
        &columns[NOTE_COPY_WIDTH_V1 + ORDERED..NOTE_COPY_WIDTH_V1 + SORTED],
        &columns[NOTE_COPY_WIDTH_V1 + SORTED..NOTE_COPY_WIDTH_V1 + PREVIOUS],
        &challenges,
        bus.size(),
    )
    .unwrap();
    let count = PORTS * super::super::super::PHASES;
    let start = 64 * super::super::super::PHASES;
    let rows = (start..=start + count)
        .map(|i| core::array::from_fn::<_, ROW_WIDTH, _>(|c| columns[NOTE_COPY_WIDTH_V1 + c][i]))
        .collect::<Vec<_>>();
    let aux_rows = (start..=start + count)
        .map(|i| aux.iter().map(|column| column[i]).collect::<Vec<_>>())
        .collect::<Vec<_>>();
    let history_schedule = private_history::Schedule::new(bus.trace_log2, 1).unwrap();
    let fixed = (start..start + count)
        .map(|i| history_schedule.fixed(i).unwrap())
        .collect::<Vec<_>>();
    let windows = core::array::from_fn(|i| super::super::HistoryRow {
        current: &rows[i],
        next: &rows[i + 1],
        aux: &aux_rows[i],
        next_aux: &aux_rows[i + 1],
        fixed: &fixed[i],
    });
    let mut residues = Vec::new();
    append_residues(
        &mut residues,
        &program,
        fixture.schedule,
        &original,
        &windows,
        &challenges,
    );
    assert!(residues.iter().all(|r| *r == F::ZERO));
    for index in [0, 7, 8, count - 1] {
        let mut changed = fixed.clone();
        changed[index][super::super::super::SLOT] =
            changed[index][super::super::super::SLOT].add(F::ONE);
        let altered = core::array::from_fn(|i| super::super::HistoryRow {
            current: &rows[i],
            next: &rows[i + 1],
            aux: &aux_rows[i],
            next_aux: &aux_rows[i + 1],
            fixed: &changed[i],
        });
        residues.clear();
        append_residues(
            &mut residues,
            &program,
            fixture.schedule,
            &original,
            &altered,
            &challenges,
        );
        assert!(
            residues.iter().any(|r| *r != F::ZERO),
            "misplaced history stage {index}"
        );
    }
    // Every complete tuple field, including otherwise free overwritten old
    // bytes, must equal the same original source in each of its eight stages.
    for slot in 0..PORTS {
        for field in 0..packet::WIDTH {
            for stage in 0..super::super::super::PHASES {
                let i = slot * super::super::super::PHASES + stage;
                let h = &windows[i];
                let mut substituted = *original.producer(slot);
                substituted[field] = substituted[field].add(F::ONE);
                residues.clear();
                private_history::append_residues(
                    &mut residues,
                    h.current,
                    h.next,
                    h.aux,
                    h.next_aux,
                    h.fixed,
                    &substituted,
                    &challenges,
                );
                assert!(
                    residues.iter().any(|r| *r != F::ZERO),
                    "slot={slot} field={field} stage={stage}"
                );
            }
        }
    }
}

#[test]
fn actual_prepared_call_preserves_relative_descriptor_identity_and_joins_native_frame_gas() {
    for jals in [false, true] {
        let call = if jals {
            enc::encode_offset24(wide::control::JALS, 2)
        } else {
            enc::encode_jump(wide::control::JAL, 1, 2)
        };
        let body = [
            enc::encode_ri(wide::arithmetic::ADDI, 31, 31, -64),
            enc::encode_ri(wide::arithmetic::ADDI, 12, 31, 32),
            call,
            enc::encode_halt(),
        ];
        let program = Program::new(dispatch_tests::contract_with_frame(
            &body,
            1000,
            ivm::ivm_mode::ZK,
            64,
        ))
        .unwrap();
        let selected = callable(&program, 2).unwrap();
        assert_eq!(selected.entry_pc, 16);
        assert_eq!(
            (
                selected.frame_bytes,
                selected.argument_word_count().unwrap(),
                selected.result_word_count().unwrap()
            ),
            (64, 0, 1)
        );
        let mut vm = ivm::IVM::new(1000);
        vm.load_prepared(program.artifact()).unwrap();
        vm.set_zk_trace_enabled(true);
        let budget = iroha_allocation::AllocationBudget::new(64 * 1024 * 1024);
        let mut recorder =
            ivm::execution_step_recorder::DiagnosticStepRecorder::try_new(3, &budget).unwrap();
        assert!(match (
            &(vm.run_with_host_diagnostic_steps(
                &mut ivm::host::DefaultHost::default(),
                &mut recorder
            )),
            &(ivm::VMError::ExecutionDeferred(ivm::error::ExecutionDeferral::ActiveMemoryCapacity))
        ) {
            (
                Err(ivm::VMError::ExecutionDeferred(actual_field_0)),
                ivm::VMError::ExecutionDeferred(expected_field_0),
            ) => actual_field_0 == expected_field_0,
            _ => false,
        });
        assert_eq!(recorder.records().len(), 3);
        for (slot, step) in recorder.records().iter().enumerate() {
            assert_eq!(step.instruction, Some(body[slot]));
            assert_eq!(
                step.outcome,
                ivm::execution_step_recorder::DiagnosticStepOutcome::Completed
            );
            assert_eq!(
                step.before.pc,
                u64::from(program.first_pc) + slot as u64 * 4
            );
            assert_eq!(step.after.cycles, step.before.cycles + 1);
        }
        let step = &recorder.records()[2];
        let sp = Memory::STACK_START + Memory::MIN_STACK_SIZE - 64;
        assert_eq!(step.before.registers[31], sp);
        assert_eq!(
            [10, 11, 12, 13].map(|r| step.before.registers[r]),
            [0, 0, sp + 32, 1]
        );
        assert_eq!(
            step.after.pc,
            u64::from(program.first_pc) + selected.entry_pc
        );
        let mut expected_registers = step.before.registers;
        expected_registers[1] = step.before.pc + 4;
        assert_eq!(step.after.registers, expected_registers);
        let mut expected_tags = step.before.tags;
        expected_tags[1] = false;
        assert_eq!(step.after.tags, expected_tags);
        assert_eq!(step.opcode_gas, Some(2));
        let frame_work = u64::from(selected.frame_bytes).div_ceil(8)
            + selected.result_word_count().unwrap() as u64;
        assert_eq!(
            step.before.gas_remaining - step.after.gas_remaining,
            2 + frame_work
        );
        // Retain the original opcode-only bank and its refusal of a collapsed
        // full-CALL debit. The new frame packet then matches the actual native
        // remaining gas without changing the base debit or its original owner.
        let dispatch = dispatch_tests::Fixture::with_controls(
            &program,
            2,
            false,
            0,
            step.before.gas_remaining,
            step.before.cycles,
        );
        assert!(dispatch.accepts(&program));
        let mut collapsed = dispatch.clone();
        dispatch_tests::bits(
            &mut collapsed.row[super::super::WORDS + 2 * 64..super::super::WORDS + 3 * 64],
            step.after.gas_remaining,
        );
        for limb in 0..4 {
            collapsed.packets.fields[super::super::GAS_DEBIT][AFTER + limb] =
                super::super::constant_limb(step.after.gas_remaining, limb);
        }
        assert!(
            !collapsed.accepts(&program),
            "opcode debit cannot absorb dynamic work"
        );
        let joined = Fixture::from_dispatch(&program, 2, dispatch);
        assert!(joined.accepts(&program));
        assert_eq!(
            packet::half(&joined.packets[FRAME_DEBIT], BEFORE, 0),
            step.before.gas_remaining - 2
        );
        assert_eq!(
            packet::half(&joined.packets[FRAME_DEBIT], AFTER, 0),
            step.after.gas_remaining
        );
        // Only the tariff and callable fields are projected from this local
        // diagnostic; synthetic parent/generation descriptor fixtures below do
        // not establish original native frame custody or allocation success.
        // Explain all root/setup/CALL accesses, including the second table-read
        // phase that this descriptor-only semantic normalization cannot replace.
        let root_tables = [(10, 0), (11, 0), (12, Memory::HEAP_START), (13, 1)];
        let mut expected = root_tables.map(|(r, v)| (true, r, v, false)).to_vec();
        expected.extend(root_tables.map(|(r, v)| (false, r, v, false)));
        for (r, v) in [(31, sp + 64), (1, program.code_end())] {
            expected.extend([(true, r, v, false); 2]);
        }
        expected.extend([
            (false, 10, 0, false),
            (false, 12, Memory::HEAP_START, false),
            (false, 11, 0, false),
            (false, 13, 1, false),
            (false, 31, sp + 64, false),
            (true, 31, sp, false),
            (true, 31, sp, false),
            (false, 31, sp, false),
            (true, 12, sp + 32, false),
            (true, 12, sp + 32, false),
            (false, 31, sp, false),
            (false, 10, 0, false),
            (false, 11, 0, false),
            (false, 12, sp + 32, false),
            (false, 13, 1, false),
            (false, 10, 0, false),
            (false, 12, sp + 32, false),
            (false, 11, 0, false),
            (false, 13, 1, false),
            (true, 1, step.before.pc + 4, false),
            (true, 1, step.before.pc + 4, false),
        ]);
        let snapshot = vm.try_diagnostic_snapshot(&budget).unwrap();
        let actual = snapshot
            .register_events()
            .map(|e| (e.written, e.index, e.value, e.tag))
            .collect::<Vec<_>>();
        assert_eq!(
            actual, expected,
            "full unfiltered prepared root, table setup and native CALL event stream"
        );
    }
}

#[test]
fn frame_work_exact_subtraction_binds_both_gas_owners_and_rejects_underflow() {
    for jals in [false, true] {
        for frame in [0, 16, 128, 256] {
            let (program, slot) = program(jals, false, frame);
            let cost = super::frame_work(callable(&program, slot).unwrap());
            for gas in [
                2,
                cost + 1,
                cost + 2,
                cost + 3,
                65535,
                65536,
                65537,
                1_u64 << 32,
                1_u64 << 48,
                u64::MAX,
            ] {
                let dispatch =
                    dispatch_tests::Fixture::with_controls(&program, slot, false, 0, gas, 100);
                assert!(dispatch.accepts(&program));
                let fixture = Fixture::from_dispatch(&program, slot, dispatch);
                assert_eq!(
                    fixture.accepts(&program),
                    gas - 2 >= cost,
                    "frame={frame} gas={gas}"
                );
                if gas - 2 < cost {
                    continue;
                }
                assert_eq!(
                    packet::half(&fixture.packets[FRAME_DEBIT], BEFORE, 0),
                    gas - 2
                );
                assert_eq!(
                    packet::half(&fixture.packets[FRAME_DEBIT], AFTER, 0),
                    gas - 2 - cost
                );
                let mut cheaper = fixture.clone();
                let wrong_cost = cost - 1;
                let after = gas - 2 - wrong_cost;
                dispatch_tests::bits(&mut cheaper.frame_work[..64], after);
                dispatch_tests::carries(&mut cheaper.frame_work[64..], gas - 2, wrong_cost, true);
                for limb in 0..4 {
                    cheaper.packets[FRAME_DEBIT][AFTER + limb] =
                        super::super::constant_limb(after, limb);
                }
                assert!(
                    !cheaper.accepts(&program),
                    "coherent wrong tariff cannot replace artifact work"
                );
                let mut detached = fixture.clone();
                detached.packets[FRAME_DEBIT][BEFORE] =
                    detached.packets[FRAME_DEBIT][BEFORE].add(F::ONE);
                assert!(
                    !detached.accepts(&program),
                    "dynamic gas cannot use another opcode remainder"
                );
            }
        }
    }
}

#[test]
fn repeated_tables_and_frame_debit_reject_every_field_and_noncanonical_workspace() {
    let (program, slot) = program(false, false, 128);
    let fixture = Fixture::new(&program, slot);
    assert!(fixture.accepts(&program));
    for index in VALIDATION_START..=FRAME_DEBIT {
        for field in 0..packet::WIDTH {
            for delta in [F::ONE, F(1_u64 << 48)] {
                let mut bad = fixture.clone();
                bad.packets[index][field] = bad.packets[index][field].add(delta);
                assert!(
                    !bad.accepts(&program),
                    "new original {index}, field {field}"
                );
            }
        }
    }
    for index in 0..FRAME_WORK_WIDTH {
        let mut bad = fixture.clone();
        bad.frame_work[index] = bad.frame_work[index].add(F(7));
        assert!(!bad.accepts(&program), "non-Boolean gas cell {index}");
    }
    let padding = Fixture::padding(&program);
    assert!(padding.accepts(&program));
    for index in 0..FRAME_WORK_WIDTH {
        let mut bad = padding.clone();
        bad.frame_work[index] = F::ONE;
        assert!(!bad.accepts(&program), "inactive gas cell {index}");
    }
    // Each second read is at its exact native relative place, and the debit is
    // before descriptor publication, not a second post-commit gas history.
    assert_eq!(
        VALIDATION_SOURCES.map(|i| packet::half(&fixture.packets[descriptor_slot(i)], BEFORE, 0)),
        core::array::from_fn(|i| packet::half(&fixture.packets[VALIDATION_START + i], BEFORE, 0))
    );
    assert_eq!(
        VALIDATION_SOURCES.map(|i| fixture.packets[descriptor_slot(i)][INDEX].0),
        [10, 12, 11, 13]
    );
    assert!(fixture.packets[FRAME_DEBIT][CLOCK].0 < fixture.packets[descriptor_slot(9)][CLOCK].0);
    assert!(
        fixture.packets[descriptor_slot(16)][CLOCK].0
            < fixture.packets[dispatch_slot(super::super::CHILD_ACTIVE)][CLOCK].0
    );
}

#[test]
fn authenticated_v1_frame_work_limits_preserve_the_native_bitmap_formula() {
    let mut callable = crate::ivm_test_support::unit_callable(0);
    for frame in [0, 16, 128, ivm::call::MAX_CALL_FRAME_BYTES_V1] {
        for results in [1, 2, ivm::call::MAX_CALL_WORDS_V1] {
            callable.frame_bytes = frame;
            callable.results = ivm::call::CallSchemaV1 {
                nodes: if results == 1 {
                    vec![ivm::call::CallTypeNodeV1::Unit]
                } else {
                    std::iter::once(ivm::call::CallTypeNodeV1::Tuple(results as u32))
                        .chain(std::iter::repeat_n(
                            ivm::call::CallTypeNodeV1::Unit,
                            results,
                        ))
                        .collect()
                },
            };
            assert!(callable.validate());
            let cost = super::frame_work(&callable);
            assert_eq!(cost, u64::from(frame) / 8 + results as u64);
            assert!(cost <= 532_480);
        }
    }
    assert_eq!(super::frame_work(&callable), 532_480);
}

#[test]
fn actual_native_frame_work_oog_retains_opcode_debit_without_completing_or_writing_link() {
    for jals in [false, true] {
        let call = if jals {
            enc::encode_offset24(wide::control::JALS, 2)
        } else {
            enc::encode_jump(wide::control::JAL, 1, 2)
        };
        let body = [
            enc::encode_ri(wide::arithmetic::ADDI, 31, 31, -64),
            enc::encode_ri(wide::arithmetic::ADDI, 12, 31, 32),
            call,
            enc::encode_halt(),
        ];
        let program = Program::new(dispatch_tests::contract_with_frame(
            &body,
            1000,
            ivm::ivm_mode::ZK,
            64,
        ))
        .unwrap();
        // Root install8 + root frame9 + two ADDIs2 leaves10: opcode2
        // succeeds, then the exact frame9 charge refuses the remaining8.
        let mut vm = ivm::IVM::new(29);
        vm.load_prepared(program.artifact()).unwrap();
        vm.set_zk_trace_enabled(true);
        let budget = iroha_allocation::AllocationBudget::new(64 * 1024 * 1024);
        let mut recorder =
            ivm::execution_step_recorder::DiagnosticStepRecorder::try_new(3, &budget).unwrap();
        assert!(matches!(
            (
                &(vm.run_with_host_diagnostic_steps(
                    &mut ivm::host::DefaultHost::default(),
                    &mut recorder
                )),
                &(ivm::VMError::OutOfGas)
            ),
            (Err(ivm::VMError::OutOfGas), ivm::VMError::OutOfGas)
        ));
        assert_eq!(recorder.records().len(), 3);
        assert!(
            recorder.records()[..2].iter().all(
                |r| r.outcome == ivm::execution_step_recorder::DiagnosticStepOutcome::Completed
            )
        );
        let step = &recorder.records()[2];
        assert_eq!(step.instruction, Some(call));
        assert_eq!(step.opcode_gas, Some(2));
        assert_eq!(
            step.outcome,
            ivm::execution_step_recorder::DiagnosticStepOutcome::Trapped(
                ivm::error::VmTrapKind::OutOfGas
            )
        );
        assert_eq!(
            (step.before.gas_remaining, step.after.gas_remaining),
            (10, 8)
        );
        assert_eq!(step.after.pc, step.before.pc);
        assert_eq!(step.after.cycles, step.before.cycles);
        assert_eq!(step.after.registers, step.before.registers);
        assert_eq!(step.after.tags, step.before.tags);
        let dispatch = dispatch_tests::Fixture::with_controls(
            &program,
            2,
            false,
            0,
            step.before.gas_remaining,
            step.before.cycles,
        );
        assert!(dispatch.accepts(&program));
        assert!(
            !Fixture::from_dispatch(&program, 2, dispatch).accepts(&program),
            "successful descriptor/frame component cannot admit actual frame OutOfGas"
        );
    }
}
