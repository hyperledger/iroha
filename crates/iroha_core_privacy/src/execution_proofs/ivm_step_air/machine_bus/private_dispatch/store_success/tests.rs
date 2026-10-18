//! Original successful STORE packets, strict phase joins and native adversaries.

use super::super::{tests as dispatch_tests, wide};
use super::*;
use ivm::{Memory, encoding::wide as enc};
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
fn program(base: u8, source: u8, imm: i8) -> Program {
    Program::new(dispatch_tests::contract(
        &[enc::encode_store(wide::memory::STORE64, base, source, imm)],
        1_000,
        ivm::ivm_mode::ZK,
    ))
    .unwrap()
}
impl Fixture {
    fn new(program: &Program, address: u64, private: bool, active: u16, cursor: u64) -> Self {
        let schedule = Schedule::new(7, 64).unwrap();
        let mut dispatch = dispatch_tests::Fixture::new(program, 0, false, 0);
        dispatch.schedule = schedule.dispatch();
        let instruction = program.words[0];
        let base = address.wrapping_sub(i64::cast_unsigned(i64::from(wide::imm8(instruction))));
        let value = if wide::rs1(instruction) == 0 {
            0
        } else if wide::rs1(instruction) == wide::rd(instruction) {
            base
        } else {
            0x0123_4567_89ab_cdef
        };
        let private = private
            && wide::rs1(instruction) != 0
            && wide::rs1(instruction) != wide::rd(instruction);
        for (word, value) in [(6, base), (7, address)] {
            dispatch_tests::bits(
                &mut dispatch.row
                    [super::super::WORDS + word * 64..super::super::WORDS + (word + 1) * 64],
                value,
            );
        }
        dispatch_tests::carries(
            &mut dispatch.row[super::super::CARRIES + 8..super::super::CARRIES + 12],
            base,
            i64::cast_unsigned(i64::from(wide::imm8(instruction))),
            false,
        );
        for (slot, index, value, tag) in [
            (4, wide::rd(instruction), base, false),
            (5, wide::rs1(instruction), value, private),
        ] {
            dispatch.packets.fields[slot] = dispatch_tests::event(
                Space::Register,
                0,
                index as u32,
                value,
                value,
                false,
                schedule.dispatch().clocks[slot],
                tag,
                tag,
            );
        }
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
            cursor,
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
        let mut frame =
            frame_access::tests::Fixture::new(true, active, address, 8, true, descriptors, 0);
        for i in 0..12 {
            if frame.ports[i][ENABLED] == F::ONE {
                frame.ports[i][CLOCK] = F(u64::from(schedule.clock(22 + i)));
            }
        }
        let frame_schedule = frame_access::Schedule::new(
            7,
            8,
            true,
            core::array::from_fn(|i| schedule.clock(22 + i)),
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
        let tracked = decision.initialized_write == F::ONE;
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
                    schedule.clock(18 + i),
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
        let old = [0x5a_u8; 16];
        let mut after = old;
        let half = (address & 8) as usize;
        after[half..half + 8].copy_from_slice(&value.to_le_bytes());
        let prior_mask = 0xa55a;
        let selected = 0xffu16 << half;
        let after_mask = (prior_mask & !selected) | if private { selected } else { 0 };
        set_port(
            &mut rows[3],
            1,
            event(
                Space::Memory,
                0,
                (address >> 4) as u32,
                schedule.clock(35),
                old,
                after,
                [prior_mask, after_mask],
                true,
            ),
        );
        if tracked {
            set_port(
                &mut rows[3],
                2,
                event(
                    Space::Initialization,
                    active,
                    (address >> 4) as u32,
                    schedule.clock(36),
                    17_u128.to_le_bytes(),
                    u128::from(17 | selected).to_le_bytes(),
                    [0, 0],
                    true,
                ),
            );
        }
        let end = address.wrapping_add(8);
        let output =
            address >= Memory::OUTPUT_START && end <= Memory::OUTPUT_START + Memory::OUTPUT_SIZE;
        let after_cursor = if output {
            address - Memory::OUTPUT_START + 8
        } else {
            cursor
        };
        set_port(
            &mut rows[3],
            0,
            word_event(23, schedule.clock(34), cursor, after_cursor, true),
        );
        for i in 0..3 {
            set_port(&mut rows[3], 3 + i, dispatch.packets.fields[18 + i]);
        }
        rows[3][..effect::WIDTH].copy_from_slice(&effect::witness(
            address, true, policies, prior_mask, 17, tracked, value,
        ));
        let mut carry = [F::ZERO; CARRY_WIDTH];
        carry[ADDRESS..ADDRESS + 4].copy_from_slice(&addr);
        carry[STORE] = F::ONE;
        carry[SOURCE..SOURCE + packet::WIDTH].copy_from_slice(&dispatch.packets.fields[5]);
        for i in 0..3 {
            carry[COMPLETION + i * packet::WIDTH..COMPLETION + (i + 1) * packet::WIDTH]
                .copy_from_slice(&dispatch.packets.fields[18 + i]);
        }
        for i in 0..4 {
            carry[POLICY + i * packet::WIDTH..POLICY + (i + 1) * packet::WIDTH]
                .copy_from_slice(port(&rows[1], i));
        }
        for (i, v) in [
            (PERMITTED, decision.permitted),
            (ACTIVE, decision.active_generation),
            (INITIALIZE, decision.initialized_write),
            (RANGE_ERROR, decision.range_error),
        ] {
            carry[i] = v;
        }
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
        let frame = frame_access::tests::Fixture::new(false, 0, 0, 8, true, [0; 10], 0);
        let mut rows = dispatch_tests::zeroed_rows::<PHASES, WIDTH>();
        rows[0][..super::super::WIDTH].copy_from_slice(&dispatch.row);
        for i in 0..21 {
            set_port(&mut rows[0], i, dispatch.packets.fields[i]);
        }
        rows[2][..frame_access::WIDTH].copy_from_slice(&frame.row);
        for i in 0..12 {
            set_port(&mut rows[2], i, frame.ports[i]);
        }
        rows[3][..effect::WIDTH]
            .copy_from_slice(&effect::witness(0, false, [0; 4], 0, 0, false, 0));
        for i in 0..3 {
            set_port(&mut rows[3], 3 + i, dispatch.packets.fields[18 + i]);
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
fn successful_store_owns_all_regions_halves_tags_aliases_and_original_controls() {
    for source in [0, 2, 3] {
        for half in [0, 8] {
            for active in [0, 3] {
                for private in [false, true] {
                    let program = program(2, source, -8);
                    for address in [
                        Memory::HEAP_START + 0x100 + half,
                        Memory::HEAP_START + 0x900 + half,
                        Memory::OUTPUT_START + 0x100 + half,
                        Memory::STACK_START + 0x100 + half,
                    ] {
                        let fixture = Fixture::new(&program, address, private, active, 8);
                        let actual_private = private && source == 3;
                        let expected = !actual_private || address >= Memory::STACK_START;
                        assert_eq!(
                            fixture.accepts(&program),
                            expected,
                            "address={address:x} source={source} active={active} private={private}"
                        );
                        let p = fixture.borrowed();
                        assert_eq!(
                            packet::half(p.producer(1), BEFORE, 0)
                                - packet::half(p.producer(1), AFTER, 0),
                            3
                        );
                        assert_eq!(
                            packet::half(p.producer(38), AFTER, 0)
                                - packet::half(p.producer(38), BEFORE, 0),
                            1
                        );
                        assert_eq!(
                            packet::half(p.producer(37), AFTER, 0)
                                - packet::half(p.producer(37), BEFORE, 0),
                            4
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn every_original_port_and_carry_join_rejects_single_field_substitution() {
    let program = program(2, 3, -8);
    let original = Fixture::new(&program, Memory::STACK_START + 0x108, true, 3, 0);
    assert!(original.accepts(&program));
    let padding = Fixture::padding();
    assert!(padding.accepts(&program));
    for phase in 0..PHASES {
        let mut mixed = original.clone();
        mixed.rows[phase].copy_from_slice(padding.rows[phase].as_ref());
        assert!(
            !mixed.accepts(&program),
            "substituted padding phase {phase}"
        );
    }
    for phase in 0..PHASES {
        for field in CARRY..WIDTH {
            let mut bad = original.clone();
            bad.rows[phase][field] = bad.rows[phase][field].add(F::ONE);
            assert!(
                !bad.accepts(&program),
                "carry phase={phase} field={}",
                field - CARRY
            );
        }
    }
    for (phase, used) in [21, 4, 12, 6].into_iter().enumerate() {
        for slot in 0..used {
            for field in 0..packet::WIDTH {
                let mut bad = original.clone();
                let c = PACKETS + slot * packet::WIDTH + field;
                bad.rows[phase][c] = bad.rows[phase][c].add(F::ONE);
                // Overwritten old bytes are original typed-history values;
                // the full forty-port history test below owns their binding.
                let history_only =
                    phase == 3 && slot == 1 && (BEFORE + 4..BEFORE + 8).contains(&field);
                assert_eq!(
                    bad.accepts(&program),
                    history_only,
                    "tuple phase={phase} slot={slot} field={field}"
                );
            }
        }
    }
    for phase in 0..PHASES {
        let mut bad = original.clone();
        bad.rows.swap(phase, (phase + 1) % PHASES);
        assert!(!bad.accepts(&program), "reordered {phase}");
    }
}

#[test]
fn permission_policy_frame_output_and_initialization_cannot_be_selected_by_witness() {
    let program = program(2, 3, 0);
    for address in [
        0,
        8,
        Memory::INPUT_START,
        Memory::HEAP_START + 1,
        Memory::STACK_START + Memory::MIN_STACK_SIZE,
        u64::MAX - 7,
    ] {
        assert!(
            !Fixture::new(&program, address, false, 0, 0).accepts(&program),
            "forbidden {address:x}"
        );
    }
    assert!(!Fixture::new(&program, Memory::OUTPUT_START + 8, false, 0, 16).accepts(&program));
    for address in [Memory::HEAP_START + 0x800, Memory::HEAP_START + 0x808] {
        assert!(
            !Fixture::new(&program, address, false, 3, 0).accepts(&program),
            "live read-only argument {address:x}"
        );
    }
    let original = Fixture::new(&program, Memory::STACK_START + 0x100, true, 3, 0);
    assert!(original.accepts(&program));
    for (field, value) in [
        (ACTIVE, F(4)),
        (INITIALIZE, F::ZERO),
        (PERMITTED, F::ZERO),
        (RANGE_ERROR, F::ONE),
    ] {
        let mut bad = original.clone();
        for row in bad.rows.iter_mut() {
            row[CARRY + field] = value;
        }
        assert!(!bad.accepts(&program), "coherent carry replacement {field}");
    }
    let mut missing = original.clone();
    set_port(&mut missing.rows[3], 2, [F::ZERO; packet::WIDTH]);
    assert!(!missing.accepts(&program));
    for slot in [0, 1, 2] {
        for offset in [SPACE, VM, GENERATION, INDEX, CLOCK, WRITE] {
            let mut bad = original.clone();
            let field = PACKETS + slot * packet::WIDTH + offset;
            bad.rows[3][field] = bad.rows[3][field].add(F::ONE);
            assert!(!bad.accepts(&program));
        }
    }
}

#[test]
fn effect_workspace_and_padding_columns_have_closed_canonical_owners() {
    let program = program(2, 3, 0);
    let original = Fixture::new(&program, Memory::STACK_START + 0x108, true, 3, 0);
    assert!(original.accepts(&program));
    for field in 0..PACKETS {
        let mut bad = original.clone();
        bad.rows[3][field] = bad.rows[3][field].add(F::ONE);
        assert!(!bad.accepts(&program), "effect field {field}");
    }
    for (phase, used) in [21, 4, 12, 6].into_iter().enumerate() {
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
    assert_eq!((WIDTH, CARRY_WIDTH, PORTS, PHASES), (2463, 217, 40, 4));
    assert_eq!(PORTS * super::super::super::PHASES, 320);
    assert!(Schedule::new(7, u32::MAX - 39).is_some());
    assert!(Schedule::new(7, u32::MAX - 38).is_none());
}

#[test]
fn all_forty_original_packets_and_all_eight_stages_share_one_private_history() {
    use super::super::super::{
        E, NOTE_COPY_WIDTH_V1, ORDERED, PREVIOUS, PublicPacketBus, ROW_WIDTH, SORTED,
    };
    let program = program(2, 3, -8);
    let fixture = Fixture::new(&program, Memory::STACK_START + 0x108, true, 3, 0);
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
    // A descriptor result cannot independently drop the original initialized write.
    assert_eq!(
        original.producer(36)[SPACE],
        F(Space::Initialization as u64)
    );
    assert_eq!(original.producer(35)[SPACE], F(Space::Memory as u64));
    assert_eq!(original.producer(34)[INDEX], F(23));
}

#[test]
fn actual_native_store_matches_original_operand_order_bytes_and_completion_tariff() {
    // Generic native programs isolate STORE itself; this is not an invocation-
    // admission fixture. The AIR's prepared artifact and full invocation roots
    // remain separate mandatory owners documented by the enclosing module.
    for region in [
        Memory::HEAP_START,
        Memory::OUTPUT_START,
        Memory::STACK_START,
    ] {
        for half in [0, 8] {
            for source in [0, 2, 3] {
                for private in [false, true] {
                    if private && (region != Memory::STACK_START || source != 3) {
                        continue;
                    }
                    let program = program(2, source, -8);
                    let address = region + 0x100 + half;
                    let fixture = Fixture::new(&program, address, private, 0, 0);
                    assert!(fixture.accepts(&program));
                    let originals = fixture.borrowed();
                    let mut bytes = ivm::ProgramMetadata {
                        mode: ivm::ivm_mode::ZK,
                        max_cycles: 2,
                        ..Default::default()
                    }
                    .encode();
                    bytes.extend_from_slice(&program.words[0].to_le_bytes());
                    bytes.extend_from_slice(&enc::encode_halt().to_le_bytes());
                    let mut vm = ivm::IVM::new(100);
                    vm.load_program(&bytes).unwrap();
                    vm.set_zk_trace_enabled(true);
                    vm.set_register(2, packet::half(originals.producer(4), BEFORE, 0));
                    if source == 3 {
                        vm.set_register(3, packet::half(originals.producer(5), BEFORE, 0));
                        vm.registers.set_tag(3, private);
                    }
                    let before: Vec<_> = (0..256)
                        .map(|i| (vm.registers.get(i), vm.registers.tag(i)))
                        .collect();
                    vm.memory.clear_tracking();
                    vm.run().unwrap();
                    let log = vm.memory.try_write_log_snapshot().unwrap();
                    assert_eq!(log.len(), 1);
                    assert_eq!(log[0].address(), address);
                    assert_eq!(
                        log[0].bytes(),
                        packet::half(originals.producer(5), BEFORE, 0).to_le_bytes()
                    );
                    let budget = iroha_allocation::AllocationBudget::new(64 * 1024 * 1024);
                    let captured = vm.try_diagnostic_snapshot(&budget).unwrap();
                    let actual: Vec<_> = captured
                        .register_events()
                        .map(|e| (e.written, e.index, e.value, e.tag))
                        .collect();
                    let expected: Vec<_> = [4, 5]
                        .map(|slot| {
                            let p = originals.producer(slot);
                            (
                                false,
                                p[INDEX].0 as usize,
                                packet::half(p, BEFORE, 0),
                                p[BEFORE_TAG] == F::ONE,
                            )
                        })
                        .into_iter()
                        .collect();
                    assert_eq!(actual, expected);
                    for (i, (value, tag)) in before.into_iter().enumerate() {
                        assert_eq!((vm.registers.get(i), vm.registers.tag(i)), (value, tag));
                    }
                    assert_eq!(
                        (vm.gas_remaining, vm.pc(), vm.get_cycle_count()),
                        (97, 8, 2)
                    );
                    assert_eq!(
                        vm.memory.output_used_len(),
                        if region == Memory::OUTPUT_START {
                            0x100 + half + 8
                        } else {
                            0
                        }
                    );
                    assert!(
                        !vm.memory
                            .try_read_log_snapshot()
                            .unwrap()
                            .iter()
                            .any(|r| r.addr == address && r.len == 8)
                    );
                }
            }
        }
    }
}

#[test]
fn other_running_opcodes_cannot_bypass_the_closed_store_step() {
    let program = Program::new(dispatch_tests::contract(
        &[
            enc::encode_jump(wide::control::JAL, 1, 4),
            enc::encode_offset24(wide::control::JALS, 3),
            enc::encode_store(wide::memory::STORE64, 2, 3, -8),
            enc::encode_ri(wide::control::JALR, 0, 1, 0),
            enc::encode_load(wide::memory::LOAD64, 3, 2, -8),
            enc::encode_halt(),
        ],
        1_000,
        ivm::ivm_mode::ZK,
    ))
    .unwrap();
    assert!(Fixture::padding().accepts(&program));
    for slot in [0, 1, 3, 4] {
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
            "actual otherwise-valid non-STORE dispatcher"
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
            set_port(&mut fixture.rows[3], 3 + i, dispatch.packets.fields[18 + i]);
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
