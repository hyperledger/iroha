//! Original successful ZK LOAD packets, atomic destinations and history adversaries.

use super::super::{tests as dispatch_tests, wide};
use super::*;
use ivm::{Memory, encoding::wide as enc};
use ivm::{
    execution_diagnostics::DiagnosticExecutionRecorders,
    execution_memory_recorder::{DiagnosticMemoryAccessKind, DiagnosticMemoryPrivacyTag},
};
use packet::Event;

#[derive(Clone)]
struct Fixture {
    rows: [Box<[F; WIDTH]>; PHASES],
    schedule: Schedule,
}
fn set_port(row: &mut [F; WIDTH], slot: usize, fields: [F; packet::WIDTH]) {
    row[PACKETS + slot * packet::WIDTH..PACKETS + (slot + 1) * packet::WIDTH]
        .copy_from_slice(&fields);
}
fn event(
    space: Space,
    generation: u16,
    index: u32,
    clock: u32,
    before: [u8; 16],
    after: [u8; 16],
    tags: [u16; 2],
    write: bool,
) -> [F; packet::WIDTH] {
    Event {
        space,
        vm: 7,
        generation,
        index,
        write,
        before,
        after,
        before_private: tags[0],
        after_private: tags[1],
    }
    .fields(clock as usize)
}
fn word_event(index: u32, clock: u32, before: u64, after: u64, write: bool) -> [F; packet::WIDTH] {
    event(
        Space::Owner,
        0,
        index,
        clock,
        u128::from(before).to_le_bytes(),
        u128::from(after).to_le_bytes(),
        [0, 0],
        write,
    )
}
fn program(base: u8, destination: u8, imm: i8) -> Program {
    Program::new(dispatch_tests::contract(
        &[
            enc::encode_load(wide::memory::LOAD64, destination, base, imm),
            enc::encode_halt(),
            enc::encode_halt(),
            enc::encode_halt(),
        ],
        1_000,
        ivm::ivm_mode::ZK,
    ))
    .unwrap()
}
impl Fixture {
    fn new(program: &Program, address: u64, mask: u16, active: u16, old_tag: bool) -> Self {
        Self::at(program, 0, address, mask, active, old_tag)
    }
    fn at(
        program: &Program,
        pc_slot: usize,
        address: u64,
        mask: u16,
        active: u16,
        old_tag: bool,
    ) -> Self {
        let schedule = Schedule::new(7, 64).unwrap();
        let mut dispatch = dispatch_tests::Fixture::new(program, pc_slot, false, 0);
        dispatch.schedule = schedule.dispatch();
        let instruction = program.words[pc_slot];
        let base = address.wrapping_sub(i64::cast_unsigned(i64::from(wide::imm8(instruction))));
        let destination = wide::rd(instruction);
        let old_tag = old_tag && destination != 0 && destination != wide::rs1(instruction);
        let old_value = if destination == 0 {
            0
        } else if destination == wide::rs1(instruction) {
            base
        } else {
            0x1234_5678
        };
        for (w, value) in [(6, base), (7, address)] {
            dispatch_tests::bits(
                &mut dispatch.row[super::super::WORDS + w * 64..super::super::WORDS + (w + 1) * 64],
                value,
            );
        }
        dispatch_tests::carries(
            &mut dispatch.row[super::super::CARRIES + 8..super::super::CARRIES + 12],
            base,
            i64::cast_unsigned(i64::from(wide::imm8(instruction))),
            false,
        );
        dispatch.packets.fields[4] = dispatch_tests::event(
            Space::Register,
            0,
            wide::rs1(instruction) as u32,
            base,
            base,
            false,
            schedule.dispatch().clocks[4],
            false,
            false,
        );
        for slot in 0..super::super::PORTS {
            if dispatch.packets.fields[slot][ENABLED] == F::ONE {
                dispatch.packets.fields[slot][CLOCK] =
                    F(u64::from(schedule.dispatch().clocks[slot]));
            }
        }
        let policies = [
            Memory::STACK_START + Memory::MIN_STACK_SIZE,
            Memory::INPUT_START,
            program.code_end(),
        ];
        let descriptors = [
            Memory::STACK_START,
            policies[0],
            Memory::HEAP_START + 0x800,
            Memory::HEAP_START + 0x810,
            Memory::HEAP_START + 0x900,
            Memory::HEAP_START + 0x910,
            Memory::HEAP_START + 0x800,
            Memory::HEAP_START + 0x810,
            Memory::HEAP_START + 0x900,
            Memory::HEAP_START + 0x910,
        ];
        let mut frame = frame_access::tests::Fixture::new(
            true,
            active,
            address,
            8,
            false,
            descriptors,
            u16::MAX,
        );
        for i in 0..12 {
            if frame.ports[i][ENABLED] == F::ONE {
                frame.ports[i][CLOCK] = F(u64::from(schedule.clock(20 + i)));
            }
        }
        let frame_schedule = frame_access::Schedule::new(
            7,
            8,
            false,
            core::array::from_fn(|i| schedule.clock(20 + i)),
        )
        .unwrap();
        let addr = core::array::from_fn(|i| F((address >> (16 * i)) & 0xffff));
        let mut ignored = Vec::new();
        let decision = frame_access::append_residues(
            &mut ignored,
            frame_schedule,
            &frame.row,
            frame_access::Request {
                selected: F::ONE,
                address: &addr,
            },
            frame_access::Ports {
                active: &frame.ports[0],
                descriptors: core::array::from_fn(|i| &frame.ports[1 + i]),
                initialized: &frame.ports[11],
            },
        );
        let mut rows = dispatch_tests::zeroed_rows::<PHASES, WIDTH>();
        rows[0][..super::super::WIDTH].copy_from_slice(&dispatch.row);
        for i in 0..21 {
            set_port(&mut rows[0], i, dispatch.packets.fields[i]);
        }
        for (i, value) in policies.into_iter().enumerate() {
            set_port(
                &mut rows[1],
                i,
                word_event(
                    POLICY_INDEXES[i],
                    schedule.clock(17 + i),
                    value,
                    value,
                    false,
                ),
            );
        }
        rows[2][..frame_access::WIDTH].copy_from_slice(&frame.row);
        for i in 0..12 {
            set_port(&mut rows[2], i, frame.ports[i]);
        }
        let cell = if address < program.code_end() {
            core::array::from_fn(|i| {
                program
                    .artifact()
                    .artifact()
                    .get(program.artifact().header_len() + (address & !15) as usize + i)
                    .copied()
                    .unwrap_or(0)
            })
        } else {
            0xfedc_ba98_7654_3210_0123_4567_89ab_cdef_u128.to_le_bytes()
        };
        let half = (address & 8) as usize;
        let value = u64::from_le_bytes(cell[half..half + 8].try_into().unwrap());
        let private = ((mask >> half) & 255) == 255
            && address >= Memory::STACK_START
            && address.wrapping_add(8) <= policies[0];
        set_port(
            &mut rows[3],
            0,
            event(
                Space::Memory,
                0,
                (address >> 4) as u32,
                schedule.clock(32),
                cell,
                cell,
                [mask; 2],
                false,
            ),
        );
        if destination != 0 {
            set_port(
                &mut rows[3],
                1,
                event(
                    Space::Register,
                    0,
                    destination as u32,
                    schedule.clock(33),
                    u128::from(old_value).to_le_bytes(),
                    u128::from(value).to_le_bytes(),
                    [u16::from(old_tag), u16::from(private)],
                    true,
                ),
            );
        }
        for i in 0..3 {
            set_port(&mut rows[3], 2 + i, dispatch.packets.fields[18 + i]);
        }
        // Fetch and memory consume one original atomic destination, including
        // the old value/tag authenticated by the global history.
        let destination_packet = *port(&rows[3], 1);
        set_port(
            &mut rows[0],
            super::super::SCALAR_DESTINATION,
            destination_packet,
        );
        rows[3][..effect::WIDTH].copy_from_slice(&effect::witness(address, true, policies, mask));
        let mut carry = [F::ZERO; CARRY_WIDTH];
        carry[ADDRESS..ADDRESS + 4].copy_from_slice(&addr);
        carry[LOAD] = F::ONE;
        carry[DESTINATION] = F(destination as u64);
        carry[DESTINATION_ENABLED] = F(u64::from(destination != 0));
        for i in 0..3 {
            carry[COMPLETION + i * packet::WIDTH..COMPLETION + (i + 1) * packet::WIDTH]
                .copy_from_slice(&dispatch.packets.fields[18 + i]);
            carry[POLICY + i * packet::WIDTH..POLICY + (i + 1) * packet::WIDTH]
                .copy_from_slice(port(&rows[1], i));
        }
        carry[PERMITTED] = decision.permitted;
        carry[RANGE_ERROR] = decision.range_error;
        for row in rows.iter_mut() {
            row[CARRY..].copy_from_slice(&carry);
        }
        Self { rows, schedule }
    }
    fn padding() -> Self {
        let schedule = Schedule::new(7, 64).unwrap();
        let mut dispatch = dispatch_tests::Fixture::padding();
        for slot in 0..21 {
            if dispatch.packets.fields[slot][ENABLED] == F::ONE {
                dispatch.packets.fields[slot][CLOCK] =
                    F(u64::from(schedule.dispatch().clocks[slot]));
            }
        }
        let frame = frame_access::tests::Fixture::new(false, 0, 0, 8, false, [0; 10], 0);
        let mut rows = dispatch_tests::zeroed_rows::<PHASES, WIDTH>();
        rows[0][..super::super::WIDTH].copy_from_slice(&dispatch.row);
        for i in 0..21 {
            set_port(&mut rows[0], i, dispatch.packets.fields[i]);
        }
        rows[2][..frame_access::WIDTH].copy_from_slice(&frame.row);
        for i in 0..12 {
            set_port(&mut rows[2], i, frame.ports[i]);
        }
        rows[3][..effect::WIDTH].copy_from_slice(&effect::witness(0, false, [0; 3], 0));
        for i in 0..3 {
            set_port(&mut rows[3], 2 + i, dispatch.packets.fields[18 + i]);
        }
        for phase in 0..PHASES {
            for i in 0..3 {
                rows[phase][CARRY + COMPLETION + i * packet::WIDTH
                    ..CARRY + COMPLETION + (i + 1) * packet::WIDTH]
                    .copy_from_slice(&dispatch.packets.fields[18 + i]);
            }
        }
        Self { rows, schedule }
    }
    fn borrowed(&self) -> Rows<'_> {
        Rows {
            phases: core::array::from_fn(|i| self.rows[i].as_ref()),
        }
    }
    fn residues(&self, program: &Program) -> Vec<F> {
        let mut out = Vec::new();
        append_semantics(&mut out, program, self.schedule, &self.borrowed());
        out
    }
    fn accepts(&self, program: &Program) -> bool {
        self.residues(program).iter().all(|&r| r == F::ZERO)
    }
}

#[test]
fn successful_load_owns_all_regions_halves_tags_aliases_and_original_controls() {
    for destination in [0, 2, 3] {
        for half in [0, 8] {
            for active in [0, 3] {
                for old_tag in [false, true] {
                    let program = program(2, destination, -8);
                    for address in [
                        half,
                        Memory::HEAP_START + 0x100 + half,
                        Memory::HEAP_START + 0x800 + half,
                        Memory::INPUT_START + half,
                        Memory::OUTPUT_START + half,
                        Memory::STACK_START + 0x100 + half,
                    ] {
                        for mask in [0, 1, 0xff, 0xff00, 0xa55a, u16::MAX] {
                            let f = Fixture::new(&program, address, mask, active, old_tag);
                            let bits = (mask >> half) & 255;
                            let expected =
                                bits == 0 || (bits == 255 && address >= Memory::STACK_START);
                            assert_eq!(
                                f.accepts(&program),
                                expected,
                                "addr={address:x} rd={destination} mask={mask:x} active={active}"
                            );
                            let originals = f.borrowed();
                            assert_eq!(
                                packet::half(originals.producer(1), BEFORE, 0)
                                    - packet::half(originals.producer(1), AFTER, 0),
                                3
                            );
                            assert_eq!(
                                packet::half(originals.producer(35), AFTER, 0)
                                    - packet::half(originals.producer(35), BEFORE, 0),
                                1
                            );
                            assert_eq!(
                                packet::half(originals.producer(34), AFTER, 0)
                                    - packet::half(originals.producer(34), BEFORE, 0),
                                4
                            );
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn every_load_phase_original_tuple_and_carry_rejects_arbitrary_substitution() {
    let program = program(2, 3, -8);
    let original = Fixture::new(&program, Memory::STACK_START + 0x108, 0xff00, 3, true);
    let padding = Fixture::padding();
    assert!(original.accepts(&program));
    assert!(padding.accepts(&program));
    for phase in 0..PHASES {
        let mut mixed = original.clone();
        mixed.rows[phase].copy_from_slice(padding.rows[phase].as_ref());
        assert!(!mixed.accepts(&program));
        for field in CARRY..WIDTH {
            for delta in [F::ONE, F(0x0123_4567)] {
                let mut bad = original.clone();
                bad.rows[phase][field] = bad.rows[phase][field].add(delta);
                assert!(
                    !bad.accepts(&program),
                    "phase={phase} carry={}",
                    field - CARRY
                );
            }
        }
        let mut reordered = original.clone();
        reordered.rows.swap(phase, (phase + 1) % PHASES);
        assert!(!reordered.accepts(&program));
    }
    for (phase, used) in [21, 3, 12, 5].into_iter().enumerate() {
        for slot in 0..used {
            for field in 0..packet::WIDTH {
                let mut bad = original.clone();
                let c = PACKETS + slot * packet::WIDTH + field;
                bad.rows[phase][c] = bad.rows[phase][c].add(F(0x0123_4567));
                assert_eq!(
                    bad.accepts(&program),
                    false,
                    "phase={phase} slot={slot} field={field}"
                );
            }
        }
    }
}

#[test]
fn permission_initialization_privacy_and_memory_policy_cannot_be_chosen() {
    let program = program(2, 3, 0);
    for address in [
        program.code_end(),
        Memory::HEAP_START + 1,
        Memory::STACK_START + Memory::MIN_STACK_SIZE,
        u64::MAX - 7,
    ] {
        assert!(
            !Fixture::new(&program, address, 0, 0, false).accepts(&program),
            "addr={address:x}"
        );
    }
    let original = Fixture::new(&program, Memory::STACK_START + 0x108, 0xff00, 3, false);
    assert!(original.accepts(&program));
    for slot in [0, 1, 11] {
        let mut bad = original.clone();
        set_port(&mut bad.rows[2], slot, [F::ZERO; packet::WIDTH]);
        assert!(!bad.accepts(&program));
    }
    for offset in [
        PERMITTED,
        RANGE_ERROR,
        DESTINATION,
        DESTINATION_ENABLED,
        POLICY + BEFORE,
        ADDRESS,
    ] {
        let mut bad = original.clone();
        for row in bad.rows.iter_mut() {
            row[CARRY + offset] = row[CARRY + offset].add(F::ONE);
        }
        assert!(!bad.accepts(&program));
    }
    // A full private stack word cannot be relabeled as a public read, and a
    // foreign generation cannot supply its initialization packet.
    for field in [GENERATION, BEFORE, AFTER] {
        let mut bad = original.clone();
        let c = PACKETS + 11 * packet::WIDTH + field;
        bad.rows[2][c] = bad.rows[2][c].add(F::ONE);
        assert!(!bad.accepts(&program));
    }
    for address in [
        Memory::HEAP_START,
        Memory::INPUT_START,
        Memory::OUTPUT_START,
    ] {
        assert!(!Fixture::new(&program, address, 0xff, 0, false).accepts(&program));
    }
    assert!(!Fixture::new(&program, Memory::STACK_START, 0x7f, 0, false).accepts(&program));
    let zero_base = self::program(0, 3, 8);
    assert!(Fixture::new(&zero_base, 8, 0, 0, false).accepts(&zero_base));
    assert!(!Fixture::new(&zero_base, 16, 0, 0, false).accepts(&zero_base));
}

#[test]
fn every_load_effect_and_padding_workspace_column_has_a_canonical_owner() {
    let program = program(2, 3, 0);
    let original = Fixture::new(&program, Memory::STACK_START + 0x108, 0xff00, 3, true);
    assert!(original.accepts(&program));
    let padding = Fixture::padding();
    assert!(padding.accepts(&program));
    for field in 0..PACKETS {
        for candidate in [&original, &padding] {
            let mut bad = candidate.clone();
            bad.rows[3][field] = bad.rows[3][field].add(F::ONE);
            assert!(!bad.accepts(&program), "effect={field}");
        }
    }
    for (phase, used) in [21, 3, 12, 5].into_iter().enumerate() {
        for field in PACKETS + used * packet::WIDTH..CARRY {
            let mut bad = original.clone();
            bad.rows[phase][field] = F::ONE;
            assert!(!bad.accepts(&program));
        }
    }
}
#[test]
fn four_phases_and_all_success_joins_preserve_degree_four_and_explicit_geometry() {
    use crate::execution_proofs::stark::proof_managed_note_stark::degree_audit::measured_maximum_affine_degree_v1;
    let program = program(2, 3, 0);
    let schedule = Schedule::new(7, 0).unwrap();
    let degree = measured_maximum_affine_degree_v1(
        [0xb7; 32],
        [PHASES * WIDTH, 0, 0, 0, 0],
        4,
        4,
        |row, _, _, _, _| {
            let rows = Rows {
                phases: core::array::from_fn(|i| {
                    row[i * WIDTH..(i + 1) * WIDTH].try_into().unwrap()
                }),
            };
            let mut out = Vec::new();
            append_semantics(&mut out, &program, schedule, &rows);
            Ok::<_, core::convert::Infallible>(out)
        },
    );
    assert_eq!(degree, 4);
    assert_eq!((WIDTH, CARRY_WIDTH, PORTS, PHASES), (2411, 165, 37, 4));
    assert_eq!(PORTS * super::super::super::PHASES, 296);
    assert!(Schedule::new(7, u32::MAX - 36).is_some());
    assert!(Schedule::new(7, u32::MAX - 35).is_none());
}

#[test]
fn all_thirty_seven_original_packets_and_all_eight_stages_share_one_private_history() {
    use super::super::super::{
        E, NOTE_COPY_WIDTH_V1, ORDERED, PREVIOUS, PublicPacketBus, ROW_WIDTH, SORTED,
    };
    let program = program(2, 3, -8);
    let fixture = Fixture::new(&program, Memory::STACK_START + 0x108, 0xff00, 3, true);
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
    // This fixture owns exactly one complete PublicPacketBus segment.
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
                substituted[field] = substituted[field].add(F(0x0123_4567));
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
    assert_eq!(
        original.producer(31)[SPACE],
        F(Space::Initialization as u64)
    );
    assert_eq!(original.producer(32)[SPACE], F(Space::Memory as u64));
    assert_eq!(original.producer(33)[SPACE], F(Space::Register as u64));
    assert_eq!(original.producer(33)[INDEX], F(3));
}

// Native controls retain the exact admitted image, root frame and Unit return.
fn native_program(body: &[u32], frame_bytes: u32) -> Program {
    let original = dispatch_tests::contract(body, 128, ivm::ivm_mode::ZK);
    let mut interface = original.contract_interface().clone();
    interface.callables[0].frame_bytes = frame_bytes;
    let mut artifact = original.metadata().encode();
    artifact.extend_from_slice(&interface.encode_section());
    artifact.extend_from_slice(&original.artifact()[original.code_offset()..]);
    Program::new(ivm::prepare_contract(std::sync::Arc::<[u8]>::from(artifact)).unwrap()).unwrap()
}
fn native(program: &Program, gas: u64) -> ivm::IVM {
    let mut vm = ivm::IVM::new(gas);
    vm.load_prepared(program.artifact()).unwrap();
    vm.set_zk_trace_enabled(true);
    assert_eq!(vm.pc(), u64::from(program.first_pc));
    vm
}
fn run_native(vm: &mut ivm::IVM) -> DiagnosticExecutionRecorders {
    let plan = DiagnosticExecutionRecorders::allocation_plan(16, 256, None).unwrap();
    let budget = iroha_allocation::AllocationBudget::new(plan.requested_bytes());
    let mut recorder = DiagnosticExecutionRecorders::try_new(16, 256, None, &budget).unwrap();
    vm.run_with_host_diagnostic_steps_and_memory(
        &mut ivm::host::DefaultHost::default(),
        &mut recorder.steps,
        &recorder.memory_accesses,
    )
    .unwrap();
    assert_eq!(vm.call_result_word_count().unwrap(), 1);
    assert_eq!(vm.public_call_result_word(0).unwrap(), 0);
    recorder
}
impl Fixture {
    fn bind_native_control(
        &mut self,
        program: &Program,
        record: &ivm::execution_step_recorder::DiagnosticStepRecord,
        vm: &ivm::IVM,
        recorder: &DiagnosticExecutionRecorders,
        load_step: usize,
    ) {
        use super::super::{CARRIES, DEPTH_BITS, DEPTH_BITS_PER_VALUE, WORDS};
        let before = &record.before;
        let after = &record.after;
        for (word, value) in [
            (1, before.gas_remaining),
            (2, after.gas_remaining),
            (3, before.cycles),
            (4, after.cycles),
            (9, program.cycle_limit - 1 - before.cycles),
        ] {
            dispatch_tests::bits(
                &mut self.rows[0][WORDS + word * 64..WORDS + (word + 1) * 64],
                value,
            );
        }
        for (offset, left, right, subtract) in [
            (0, before.gas_remaining, 3, true),
            (4, before.cycles, 1, false),
            (16, program.cycle_limit - 1, before.cycles, true),
        ] {
            dispatch_tests::carries(
                &mut self.rows[0][CARRIES + offset..CARRIES + offset + 4],
                left,
                right,
                subtract,
            );
        }
        self.rows[0][DEPTH_BITS..DEPTH_BITS + 2 * DEPTH_BITS_PER_VALUE].fill(F::ZERO);
        for (slot, left, right) in [
            (0, before.pc, before.pc),
            (1, before.gas_remaining, after.gas_remaining),
            (14, 0, 0),
            (18, before.pc, after.pc),
            (19, before.cycles, after.cycles),
        ] {
            let packet = &mut self.rows[0]
                [PACKETS + slot * packet::WIDTH..PACKETS + (slot + 1) * packet::WIDTH];
            for limb in 0..4 {
                packet[BEFORE + limb] = F((left >> (16 * limb)) & 0xffff);
                packet[AFTER + limb] = F((right >> (16 * limb)) & 0xffff);
            }
        }
        for index in 0..3 {
            let original = *port(&self.rows[0], 18 + index);
            set_port(&mut self.rows[3], 2 + index, original);
            for row in self.rows.iter_mut() {
                row[CARRY + COMPLETION + index * packet::WIDTH
                    ..CARRY + COMPLETION + (index + 1) * packet::WIDTH]
                    .copy_from_slice(&original);
            }
        }
        // This fresh invocation has one authenticated root. Its table registers
        // are installed before the first diagnostic instruction; no body word
        // changes them or the entry stack pointer before this LOAD.
        let stack_top = vm.memory.stack_top();
        assert_eq!(before.registers[31], stack_top);
        assert!(!before.tags[31]);
        assert_eq!(before.registers[10], 0);
        assert_eq!(before.registers[11], 0);
        assert_eq!(before.registers[12], Memory::HEAP_START);
        assert_eq!(before.registers[13], 1);
        let stack_start =
            stack_top - u64::from(program.artifact().contract_interface().callables[0].frame_bytes);
        let arguments = before.registers[10];
        let argument_end = arguments + before.registers[11] * 8;
        let results = before.registers[12];
        let result_end = results + before.registers[13] * 8;
        let descriptors = [
            stack_start,
            stack_top,
            arguments,
            argument_end,
            results,
            result_end,
            arguments,
            argument_end,
            results,
            result_end,
        ];
        let originals = self.borrowed();
        let memory = originals.producer(32);
        let instruction = record.instruction.unwrap();
        let address = before.registers[wide::rs1(instruction)]
            .wrapping_add_signed(i64::from(wide::imm8(instruction)));
        assert_eq!(memory[INDEX], F(address >> 4));
        let cell = address & !15;
        let privacy = memory[BEFORE_TAG].0 as u16;
        // Root initialization starts empty. Only prior checked guest writes
        // establish its stack bitmap; pre-run host bytes cannot initialize it.
        let initialized = recorder.memory_accesses.with_records(|accesses| {
            let mut initialized = 0_u16;
            for access in accesses {
                if access.kind == DiagnosticMemoryAccessKind::Write
                    && access
                        .step_ordinal
                        .is_some_and(|step| step < load_step as u64)
                    && (cell..cell + 16).contains(&access.address)
                {
                    initialized |= 1 << (access.address - cell);
                }
            }
            let reads = accesses
                .iter()
                .filter(|access| {
                    access.kind == DiagnosticMemoryAccessKind::Read
                        && access.step_ordinal == Some(load_step as u64)
                })
                .collect::<Vec<_>>();
            assert_eq!(reads.len(), 8);
            for (byte, access) in reads.into_iter().enumerate() {
                let offset = ((address & 15) as usize) + byte;
                assert_eq!(access.address, address + byte as u64);
                assert_eq!(access.byte_offset, byte as u32);
                let value = ((memory[BEFORE + offset / 2].0 >> (8 * (offset % 2))) & 255) as u8;
                assert_eq!((access.before, access.after), (value, value));
                assert_eq!(
                    access.privacy_tag,
                    if privacy & (1 << offset) != 0 {
                        DiagnosticMemoryPrivacyTag::Private
                    } else {
                        DiagnosticMemoryPrivacyTag::Public
                    }
                );
            }
            initialized
        });
        let mut frame =
            frame_access::tests::Fixture::new(true, 1, address, 8, false, descriptors, initialized);
        self.rows[2][..frame_access::WIDTH].copy_from_slice(&frame.row);
        for index in 0..12 {
            if frame.ports[index][ENABLED] == F::ONE {
                frame.ports[index][CLOCK] = F(u64::from(self.schedule.clock(20 + index)));
            }
            set_port(&mut self.rows[2], index, frame.ports[index]);
        }
        assert_eq!(packet::half(self.borrowed().producer(20), BEFORE, 0), 1);
        for (index, descriptor) in descriptors.into_iter().enumerate() {
            assert_eq!(
                packet::half(self.borrowed().producer(21 + index), BEFORE, 0),
                descriptor
            );
        }
        if (stack_start..stack_top).contains(&address) {
            assert_eq!(initialized, 0xff << (address & 8));
            assert_eq!(
                packet::half(self.borrowed().producer(31), BEFORE, 0),
                u64::from(initialized)
            );
        } else {
            assert_eq!(self.borrowed().producer(31), &[F::ZERO; packet::WIDTH]);
        }
        let policies = [
            stack_top,
            Memory::HEAP_START + vm.memory.heap_limit(),
            program.code_end(),
        ];
        for (index, value) in policies.into_iter().enumerate() {
            let original = word_event(
                POLICY_INDEXES[index],
                self.schedule.clock(17 + index),
                value,
                value,
                false,
            );
            set_port(&mut self.rows[1], index, original);
            for row in self.rows.iter_mut() {
                row[CARRY + POLICY + index * packet::WIDTH
                    ..CARRY + POLICY + (index + 1) * packet::WIDTH]
                    .copy_from_slice(&original);
            }
        }
        self.rows[3][..effect::WIDTH]
            .copy_from_slice(&effect::witness(address, true, policies, privacy));
        assert!(self.accepts(program));
    }
}
fn assert_native_load_record(
    record: &ivm::execution_step_recorder::DiagnosticStepRecord,
    fixture: &Fixture,
) {
    assert_eq!(
        record.outcome,
        ivm::execution_step_recorder::DiagnosticStepOutcome::Completed
    );
    assert_eq!(record.opcode_gas, Some(3));
    let instruction = record.instruction.unwrap();
    assert_eq!(wide::opcode(instruction), wide::memory::LOAD64);
    let base = wide::rs1(instruction);
    let destination = wide::rd(instruction);
    let original = fixture.borrowed();
    assert_eq!(
        record.before.registers[base],
        packet::half(original.producer(4), BEFORE, 0)
    );
    assert!(!record.before.tags[base]);
    for register in 0..256 {
        if register == destination && register != 0 {
            let packet = original.producer(33);
            assert_eq!(
                record.before.registers[register],
                packet::half(packet, BEFORE, 0)
            );
            assert_eq!(record.before.tags[register], packet[BEFORE_TAG] == F::ONE);
            assert_eq!(
                record.after.registers[register],
                packet::half(packet, AFTER, 0)
            );
            assert_eq!(record.after.tags[register], packet[AFTER_TAG] == F::ONE);
        } else {
            assert_eq!(
                record.after.registers[register],
                record.before.registers[register]
            );
            assert_eq!(record.after.tags[register], record.before.tags[register]);
        }
    }
    for (slot, before, after) in [
        (0, record.before.pc, record.before.pc),
        (1, record.before.gas_remaining, record.after.gas_remaining),
        (34, record.before.pc, record.after.pc),
        (35, record.before.cycles, record.after.cycles),
    ] {
        assert_eq!(packet::half(original.producer(slot), BEFORE, 0), before);
        assert_eq!(packet::half(original.producer(slot), AFTER, 0), after);
    }
    assert_eq!(record.before.gas_remaining - record.after.gas_remaining, 3);
    assert_eq!(record.after.cycles - record.before.cycles, 1);
    assert_eq!(record.after.pc - record.before.pc, 4);
}

#[test]
fn actual_native_load_matches_five_regions_both_halves_aliases_zero_and_signed_immediates() {
    let stack = ivm::IVM::new(10_000).memory.stack_top() - 512;
    for region in [
        0,
        Memory::HEAP_START + 0x100,
        Memory::INPUT_START,
        Memory::OUTPUT_START,
        stack,
    ] {
        for half in [0, 8] {
            for destination in [0, 2, 3] {
                for imm in [-128, -8, 0, 127] {
                    for old_tag in [false, true] {
                        let load = enc::encode_load(wide::memory::LOAD64, destination, 2, imm);
                        let body = if region == stack {
                            vec![enc::encode_store(wide::memory::STORE64, 2, 4, imm), load]
                        } else {
                            vec![load]
                        };
                        let program = native_program(&body, 512);
                        let address = region + half;
                        let mut fixture =
                            Fixture::at(&program, body.len() - 1, address, 0, 0, old_tag);
                        assert!(fixture.accepts(&program));
                        let data = {
                            let original = fixture.borrowed();
                            let memory = original.producer(32);
                            core::array::from_fn::<_, 16, _>(|i| {
                                ((memory[BEFORE + i / 2].0 >> (8 * (i % 2))) & 255) as u8
                            })
                        };
                        let mut vm = native(&program, 10_000);
                        if region == Memory::INPUT_START {
                            vm.memory.preload_input(0, &data).unwrap();
                        } else if region != 0 {
                            vm.memory
                                .store_u128(region, u128::from_le_bytes(data))
                                .unwrap();
                        }
                        vm.set_register(
                            2,
                            address.wrapping_sub(i64::cast_unsigned(i64::from(imm))),
                        );
                        vm.set_register(
                            4,
                            u64::from_le_bytes(
                                data[half as usize..half as usize + 8].try_into().unwrap(),
                            ),
                        );
                        if destination == 3 {
                            vm.set_register(3, 0x1234_5678);
                            vm.registers.set_tag(3, old_tag);
                        }
                        vm.memory.clear_tracking();
                        let recorder = run_native(&mut vm);
                        let record = &recorder.steps.records()[body.len() - 1];
                        fixture.bind_native_control(
                            &program,
                            record,
                            &vm,
                            &recorder,
                            body.len() - 1,
                        );
                        assert_native_load_record(record, &fixture);
                        assert!(!record.after.tags[usize::from(destination)]);
                        assert!(vm.memory.try_read_log_snapshot().unwrap().iter().any(|r| (
                            r.addr, r.len
                        ) == (
                            address, 8
                        )));
                        let writes = vm.memory.try_write_log_snapshot().unwrap();
                        assert_eq!(
                            writes.iter().filter(|w| w.address() == address).count(),
                            usize::from(region == stack)
                        );
                        assert_eq!(vm.memory.load_u128(region).unwrap().to_le_bytes(), data);
                        assert_eq!(vm.pc(), program.code_end());
                        assert_eq!(vm.get_cycle_count(), program.cycle_limit);
                    }
                }
            }
        }
    }
}

#[test]
fn actual_native_private_stack_load_preserves_atomic_value_and_tag_and_rejects_failed_success_paths()
 {
    let stack = ivm::IVM::new(10_000).memory.stack_top() - 512;
    for half in [0, 8] {
        for destination in [0, 2, 3] {
            let words = [
                enc::encode_store(wide::memory::STORE64, 2, 4, 0),
                enc::encode_load(wide::memory::LOAD64, destination, 2, 0),
            ];
            let program = native_program(&words, 512);
            let address = stack + half;
            let mut fixture = Fixture::at(&program, 1, address, 0xff << half, 0, false);
            assert!(fixture.accepts(&program));
            let value = packet::half(fixture.borrowed().producer(32), BEFORE, (half / 8) as usize);
            let mut vm = native(&program, 10_000);
            vm.memory
                .store_u128(
                    address & !15,
                    0xfedc_ba98_7654_3210_0123_4567_89ab_cdef_u128,
                )
                .unwrap();
            vm.set_register(2, address);
            vm.set_register(4, value);
            vm.registers.set_tag(4, true);
            if destination == 3 {
                vm.set_register(3, 0x1234_5678);
            }
            vm.memory.clear_tracking();
            let recorder = run_native(&mut vm);
            let record = &recorder.steps.records()[1];
            fixture.bind_native_control(&program, record, &vm, &recorder, 1);
            assert_native_load_record(record, &fixture);
            assert_eq!(
                record.after.tags[usize::from(destination)],
                destination != 0
            );
            assert_eq!(
                record.after.registers[usize::from(destination)],
                if destination == 0 { 0 } else { value }
            );
            assert!(
                vm.memory
                    .try_read_log_snapshot()
                    .unwrap()
                    .iter()
                    .any(|r| (r.addr, r.len) == (address, 8))
            );
            assert_eq!(vm.pc(), program.code_end());
            assert_eq!(vm.get_cycle_count(), program.cycle_limit);
        }
    }
    for frame_bytes in [0, 512] {
        let p = native_program(
            &[enc::encode_load(wide::memory::LOAD64, 3, 2, 0)],
            frame_bytes,
        );
        let stack_top = native(&p, 1_000).memory.stack_top();
        let stack_start = stack_top - u64::from(frame_bytes);
        let setup_gas = 8 + ivm::call_gas::frame(frame_bytes, 1).unwrap();
        use ivm::error::{Perm, VMError, VmTrapKind};
        let read_fault = |address| VMError::MemoryAccessViolation {
            addr: address as u32,
            perm: Perm::READ,
        };
        // LOAD64 checks base privacy before reading; load_u64 checks alignment
        // before permissions. Base gas is charged before those checks, but an
        // instruction that cannot pay its base gas stops without a debit.
        for (address, private_base, gas, expected_error, expected_trap) in [
            (
                Memory::HEAP_START + 0x100,
                true,
                1_000,
                VMError::PrivacyViolation,
                VmTrapKind::PrivacyViolation,
            ),
            (
                Memory::HEAP_START + 0x101,
                false,
                1_000,
                VMError::MisalignedAccess {
                    addr: (Memory::HEAP_START + 0x101) as u32,
                },
                VmTrapKind::MemoryFault,
            ),
            (
                Memory::HEAP_START + 0x100,
                false,
                setup_gas + 2,
                VMError::OutOfGas,
                VmTrapKind::OutOfGas,
            ),
            (
                p.code_end().next_multiple_of(8),
                false,
                1_000,
                read_fault(p.code_end().next_multiple_of(8)),
                VmTrapKind::MemoryFault,
            ),
            // The active frame rejects reads outside its stack and reads of
            // its unwritten bytes, including all stack reads in an empty frame.
            (
                stack_start - 8,
                false,
                1_000,
                read_fault(stack_start - 8),
                VmTrapKind::MemoryFault,
            ),
            (
                stack_top,
                false,
                1_000,
                read_fault(stack_top),
                VmTrapKind::MemoryFault,
            ),
            (
                stack_start,
                false,
                1_000,
                read_fault(stack_start),
                VmTrapKind::MemoryFault,
            ),
        ] {
            let mut vm = native(&p, gas);
            vm.set_register(2, address);
            vm.registers.set_tag(2, private_base);
            vm.set_register(3, 99);
            let budget = iroha_allocation::AllocationBudget::new(
                16 * core::mem::size_of::<ivm::execution_step_recorder::DiagnosticStepRecord>(),
            );
            let mut recorder =
                ivm::execution_step_recorder::DiagnosticStepRecorder::try_new(16, &budget).unwrap();
            assert!(match (
                vm.run_with_host_diagnostic_steps(
                    &mut ivm::host::DefaultHost::default(),
                    &mut recorder
                ),
                expected_error
            ) {
                (Err(VMError::PrivacyViolation), VMError::PrivacyViolation)
                | (Err(VMError::OutOfGas), VMError::OutOfGas) => true,
                (
                    Err(VMError::MisalignedAccess { addr: actual }),
                    VMError::MisalignedAccess { addr: expected },
                ) => actual == expected,
                (
                    Err(VMError::MemoryAccessViolation {
                        addr: actual_addr,
                        perm: actual_perm,
                    }),
                    VMError::MemoryAccessViolation {
                        addr: expected_addr,
                        perm: expected_perm,
                    },
                ) => actual_addr == expected_addr && actual_perm == expected_perm,
                _ => false,
            });
            let record = &recorder.records()[0];
            assert_eq!(record.instruction, Some(p.words[0]));
            assert_eq!(
                record.outcome,
                ivm::execution_step_recorder::DiagnosticStepOutcome::Trapped(expected_trap)
            );
            assert_eq!(record.before.registers[3], 99);
            assert_eq!(record.after.registers[3], 99);
            assert_eq!(record.after.pc, record.before.pc);
            assert_eq!(record.after.cycles, record.before.cycles);
            assert_eq!(record.before.gas_remaining, gas - setup_gas);
            assert_eq!(record.before.registers[31], stack_top);
            assert_eq!(record.before.registers[12], Memory::HEAP_START);
            assert_eq!(record.before.registers[13], 1);
            assert_eq!(
                record.before.gas_remaining - record.after.gas_remaining,
                if gas - setup_gas < 3 { 0 } else { 3 }
            );
            assert_eq!(vm.pc(), u64::from(p.first_pc));
            assert_eq!(vm.get_cycle_count(), 0);
        }
    }
    let mut exhausted = program(2, 3, 0);
    let candidate = Fixture::new(&exhausted, Memory::HEAP_START, 0, 0, false);
    exhausted.cycle_limit = 100;
    assert!(!candidate.accepts(&exhausted));
    let original = program(2, 3, 0);
    let mut base_private = Fixture::new(&original, Memory::HEAP_START, 0, 0, false);
    for offset in [BEFORE_TAG, AFTER_TAG] {
        base_private.rows[0][PACKETS + 4 * packet::WIDTH + offset] = F::ONE;
    }
    assert!(!base_private.accepts(&original));
}

#[test]
fn other_running_opcodes_cannot_bypass_the_closed_load_step() {
    let program = Program::new(dispatch_tests::contract(
        &[
            enc::encode_jump(wide::control::JAL, 1, 4),
            enc::encode_offset24(wide::control::JALS, 3),
            enc::encode_store(wide::memory::STORE64, 2, 3, -8),
            enc::encode_ri(wide::control::JALR, 0, 1, 0),
        ],
        1_000,
        ivm::ivm_mode::ZK,
    ))
    .unwrap();
    assert!(Fixture::padding().accepts(&program));
    for slot in [0, 1, 2, 3] {
        let mut fixture = Fixture::padding();
        let mut dispatch = dispatch_tests::Fixture::new(&program, slot, false, 0);
        dispatch.schedule = fixture.schedule.dispatch();
        for i in 0..21 {
            if dispatch.packets.fields[i][ENABLED] == F::ONE {
                dispatch.packets.fields[i][CLOCK] = F(u64::from(dispatch.schedule.clocks[i]));
            }
        }
        assert!(
            dispatch.accepts(&program),
            "actual otherwise-valid non-LOAD dispatcher"
        );
        fixture.rows[0][..super::super::WIDTH].copy_from_slice(&dispatch.row);
        for i in 0..21 {
            set_port(&mut fixture.rows[0], i, dispatch.packets.fields[i]);
        }
        for phase in 0..PHASES {
            for i in 0..3 {
                fixture.rows[phase][CARRY + COMPLETION + i * packet::WIDTH
                    ..CARRY + COMPLETION + (i + 1) * packet::WIDTH]
                    .copy_from_slice(&dispatch.packets.fields[18 + i]);
            }
        }
        for i in 0..3 {
            set_port(&mut fixture.rows[3], 2 + i, dispatch.packets.fields[18 + i]);
        }
        let nonzero = fixture
            .residues(&program)
            .into_iter()
            .filter(|r| *r != F::ZERO)
            .collect::<Vec<_>>();
        assert_eq!(
            nonzero,
            [F::ZERO.sub(F::ONE)],
            "only the new closed-opcode guard must reject slot {slot}"
        );
    }
}
