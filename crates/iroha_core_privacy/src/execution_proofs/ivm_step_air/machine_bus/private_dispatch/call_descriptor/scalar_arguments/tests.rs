//! Original scalar words, all padded joins, integer gas and prepared native calls.
use super::super::super::tests as dispatch_tests;
use super::super::{frame_descriptor, tests::Fixture as Original};
use super::*;
use iroha_data_model::smart_contract::manifest::{
    ContractErrorTypeDescriptor, ContractErrorVariantDescriptor,
};
use ivm::{Memory, encoding::wide as enc, instruction::wide};
use packet::Event;
fn boolean() -> CallTypeNodeV1 {
    CallTypeNodeV1::Leaf(EntrypointValueKindV1::Bool)
}
fn error_type(identity: &str, codes: &[u32]) -> CallTypeNodeV1 {
    CallTypeNodeV1::Error(ContractErrorTypeDescriptor {
        identity: identity.into(),
        variants: codes
            .iter()
            .enumerate()
            .map(|(i, &code)| ContractErrorVariantDescriptor {
                name: format!("Variant{i}"),
                code,
            })
            .collect(),
    })
}
fn error() -> CallTypeNodeV1 {
    error_type("test/scalar/E", &[7, u32::MAX])
}

fn program(body: &[u32], call_slot: usize, roles: &[CallTypeNodeV1]) -> Program {
    let base = dispatch_tests::contract_with_frame(body, 1000, ivm::ivm_mode::ZK, 64);
    let mut interface = base.contract_interface().clone();
    let offset = if wide::opcode(body[call_slot]) == wide::control::JALS {
        i64::from(wide::imm24(body[call_slot]))
    } else {
        i64::from(wide::imm16(body[call_slot]))
    };
    let target = (call_slot as u64 * 4)
        .checked_add_signed(offset * 4)
        .unwrap();
    interface
        .callables
        .iter_mut()
        .find(|c| c.entry_pc == target)
        .unwrap()
        .arguments = ivm::call::CallSchemaV1 {
        nodes: roles.to_vec(),
    };
    for node in roles {
        if let CallTypeNodeV1::Error(error) = node {
            if let Some(original) = interface
                .error_types
                .iter()
                .find(|entry| entry.identity == error.identity)
            {
                assert_eq!(original, error, "one exact original nominal catalog");
            } else {
                interface.error_types.push(error.clone());
            }
        }
    }
    let mut bytes = base.metadata().encode();
    bytes.extend_from_slice(&interface.encode_section());
    bytes.extend_from_slice(&base.artifact()[base.code_offset()..]);
    Program::new(ivm::prepare_contract(std::sync::Arc::<[u8]>::from(bytes)).unwrap()).unwrap()
}
fn simple(roles: &[CallTypeNodeV1]) -> Program {
    program(
        &[
            enc::encode_jump(wide::control::JAL, 1, 2),
            enc::encode_halt(),
        ],
        0,
        roles,
    )
}
#[derive(Clone)]
struct Fixture<'p> {
    original: Original,
    words: Vec<[F; WORD_WIDTH]>,
    packets: Vec<[[F; packet::WIDTH]; WORD_PORTS]>,
    completion: [F; packet::WIDTH],
    schedule: Schedule<'p>,
    errors: Vec<F>,
}
impl<'p> Fixture<'p> {
    fn new(program: &'p Program, slot: usize, values: &[u64]) -> Self {
        Self::from_original(program, Original::new(program, slot), values)
    }
    fn from_original(program: &'p Program, mut original: Original, values: &[u64]) -> Self {
        let schedule = Schedule::new(program, 7, 64).unwrap();
        for (slot, packet) in original.packets.iter_mut().enumerate() {
            if packet[ENABLED] == F::ONE {
                packet[CLOCK] = F(u64::from(schedule.clock(schedule.shape.old_slot(slot))));
            }
        }
        original.schedule = schedule.original();
        let active = original.packets[super::super::FRAME_DEBIT][ENABLED] == F::ONE;
        let mut fixture = Self {
            original,
            words: vec![[F::ZERO; WORD_WIDTH]; schedule.shape.words],
            packets: vec![[[F::ZERO; packet::WIDTH]; WORD_PORTS]; schedule.shape.words],
            completion: [F::ZERO; packet::WIDTH],
            errors: vec![F::ZERO; schedule.shape.error_width()],
            schedule: schedule.clone(),
        };
        if !active {
            return fixture;
        }
        let argument = packet::half(
            &fixture.original.packets[super::super::descriptor_slot(0)],
            BEFORE,
            0,
        );
        let parent = fixture.original.packets
            [super::super::dispatch_slot(super::super::super::CHILD_ACTIVE)][BEFORE]
            .0 as u16;
        let mut gas = packet::half(
            &fixture.original.packets[super::super::FRAME_DEBIT],
            AFTER,
            0,
        );
        for (index, &value) in values.iter().enumerate() {
            let address = argument + index as u64 * 8;
            let w = &mut fixture.words[index];
            dispatch_tests::bits(&mut w[ADDRESS..ADDRESS + 64], address);
            dispatch_tests::carries(
                &mut w[ADD_CARRY..ADD_CARRY + 4],
                argument,
                index as u64 * 8,
                false,
            );
            dispatch_tests::bits(&mut w[INITIALIZED..INITIALIZED + 16], 0xffff);
            dispatch_tests::bits(&mut w[VALUE..VALUE + 64], value);
            dispatch_tests::bits(&mut w[NODE_GAS..NODE_GAS + 64], gas.wrapping_sub(1));
            dispatch_tests::carries(&mut w[NODE_BORROW..NODE_BORROW + 4], gas, 1, true);
            dispatch_tests::bits(&mut w[GAS..GAS + 64], gas.wrapping_sub(9));
            dispatch_tests::carries(&mut w[BORROW..BORROW + 4], gas.wrapping_sub(1), 8, true);
            let clock = |port| schedule.clock(schedule.shape.word_slot(index, port));
            let init = Event {
                space: Space::Initialization,
                vm: 7,
                generation: parent,
                index: (address / 16) as u32,
                write: false,
                before: dispatch_tests::bytes(0xffff),
                after: dispatch_tests::bytes(0xffff),
                before_private: 0,
                after_private: 0,
            };
            fixture.packets[index][EARLY] = init.fields(clock(EARLY) as usize);
            fixture.packets[index][LATE] = init.fields(clock(LATE) as usize);
            let mut bytes = [0; 16];
            for (j, &word) in values.iter().enumerate() {
                let a = argument + j as u64 * 8;
                if a / 16 == address / 16 {
                    let half = (a % 16) as usize;
                    bytes[half..half + 8].copy_from_slice(&word.to_le_bytes());
                }
            }
            fixture.packets[index][MEMORY] = Event {
                space: Space::Memory,
                vm: 7,
                generation: 0,
                index: (address / 16) as u32,
                write: false,
                before: bytes,
                after: bytes,
                before_private: 0,
                after_private: 0,
            }
            .fields(clock(MEMORY) as usize);
            for (port, before, after) in [(NODE, gas, NODE_GAS), (DEBIT, gas.wrapping_sub(1), GAS)]
            {
                let mut debit = fixture.original.packets[super::super::FRAME_DEBIT];
                debit[CLOCK] = F(u64::from(clock(port)));
                for i in 0..4 {
                    debit[BEFORE + i] = super::super::super::constant_limb(before, i);
                    debit[AFTER + i] = limb(w, after, i);
                }
                fixture.packets[index][port] = debit;
            }
            let selected = fixture.original.dispatch[..super::super::super::MAX_WORDS]
                .iter()
                .position(|v| *v == F::ONE)
                .unwrap();
            if let Some(CallTypeNodeV1::Error(descriptor)) = schedule.leaf(selected, index) {
                if let Ok(code) = u32::try_from(value) {
                    if let Ok(ordinal) = descriptor.variants.binary_search_by_key(&code, |v| v.code)
                    {
                        fixture.errors[schedule.shape.error_range(index).start + ordinal] = F::ONE;
                    }
                }
            }
            gas = gas.wrapping_sub(9);
        }
        fixture.completion = fixture.original.packets[super::super::FRAME_DEBIT];
        fixture.completion[CLOCK] = F(u64::from(schedule.clock(schedule.shape.completion_slot())));
        fixture.completion[WRITE] = F::ZERO;
        for i in 0..4 {
            fixture.completion[BEFORE + i] = super::super::super::constant_limb(gas, i);
            fixture.completion[AFTER + i] = fixture.completion[BEFORE + i];
        }
        fixture
    }
    fn row(&self) -> Row<'_> {
        Row {
            original: self.original.borrowed(),
            words: &self.words,
            packets: &self.packets,
            error_selectors: &self.errors,
            completion_gas: &self.completion,
        }
    }
    fn residues(&self, p: &Program) -> Vec<F> {
        let mut out = Vec::new();
        let schedule = Schedule::new(p, self.schedule.vm, self.schedule.first_clock).unwrap();
        if schedule.shape.words != self.words.len()
            || schedule.shape.error_width() != self.errors.len()
        {
            return vec![F::ONE];
        }
        append_semantics(&mut out, &schedule, &self.row());
        out
    }
    fn accepts(&self, p: &Program) -> bool {
        self.residues(p).iter().all(|r| *r == F::ZERO)
    }
}

#[test]
fn scalar_roles_and_both_original_halves_are_exact() {
    for (roles, values) in [
        (vec![], vec![]),
        (vec![CallTypeNodeV1::Unit], vec![0]),
        (vec![boolean(); 2], vec![0, 1]),
        (
            vec![CallTypeNodeV1::Unit, boolean(), error()],
            vec![0, 1, u64::from(u32::MAX)],
        ),
    ] {
        let p = simple(&roles);
        let f = Fixture::new(&p, 0, &values);
        assert!(f.accepts(&p));
        assert_eq!(
            packet::half(&f.completion, BEFORE, 0),
            packet::half(&f.original.packets[super::super::FRAME_DEBIT], AFTER, 0)
                - 9 * values.len() as u64
        );
        for i in 0..values.len() {
            assert_eq!(
                packet::half(&f.packets[i][MEMORY], BEFORE, i % 2),
                values[i]
            );
        }
    }
    for (role, value) in [
        (CallTypeNodeV1::Unit, 1),
        (boolean(), 2),
        (error(), 1 << 32),
    ] {
        let p = simple(&[role]);
        assert!(!Fixture::new(&p, 0, &[value]).accepts(&p));
    }
    for (nodes, words) in [
        (vec![CallTypeNodeV1::Option, boolean()], 1),
        (vec![CallTypeNodeV1::List { capacity: 2 }, boolean()], 1),
        (vec![CallTypeNodeV1::Leaf(EntrypointValueKindV1::Int)], 1),
        (
            vec![CallTypeNodeV1::Tuple(2), CallTypeNodeV1::Unit, boolean()],
            2,
        ),
        (
            vec![CallTypeNodeV1::Struct {
                name: "ScalarArguments::Empty".into(),
                fields: vec![],
            }],
            1,
        ),
    ] {
        assert_eq!(
            ivm::call::CallSchemaV1 {
                nodes: nodes.clone(),
            }
            .word_count(),
            Some(words),
            "each flat-bank refusal control must first pass native schema admission"
        );
        let p = simple(&nodes);
        assert!(
            !Fixture::new(&p, 0, &vec![0; words]).accepts(&p),
            "native recursive/pointer schema remains unqualified by this flat bank"
        );
    }
}

#[test]
fn unqualified_nominal_schema_is_refused_before_flat_bank_witness_construction() {
    let schema = ivm::call::CallSchemaV1 {
        nodes: vec![CallTypeNodeV1::Struct {
            name: "Empty".into(),
            fields: vec![],
        }],
    };
    assert!(schema.analyze().is_none());
    assert!(schema.word_count().is_none());
}

#[test]
fn initialization_privacy_value_and_padding_have_closed_original_owners() {
    let p = simple(&[CallTypeNodeV1::Unit, boolean(), error()]);
    let f = Fixture::new(&p, 0, &[0, 1, u64::from(u32::MAX)]);
    assert!(f.accepts(&p));
    for index in 0..3 {
        for column in 0..WORD_WIDTH {
            let mut bad = f.clone();
            bad.words[index][column] = bad.words[index][column].add(F(7));
            assert!(!bad.accepts(&p), "word{index}/cell{column}");
        }
        for port in 0..WORD_PORTS {
            for field in 0..packet::WIDTH {
                let mut bad = f.clone();
                bad.packets[index][port][field] = bad.packets[index][port][field].add(F(7));
                assert!(!bad.accepts(&p), "word{index}/port{port}/field{field}");
            }
        }
    }
    let padding = Fixture::from_original(&p, Original::padding(&p), &[]);
    assert!(padding.accepts(&p));
    for index in 0..3 {
        for column in 0..WORD_WIDTH {
            let mut bad = padding.clone();
            bad.words[index][column] = F::ONE;
            assert!(!bad.accepts(&p));
        }
    }
    for field in 0..packet::WIDTH {
        let mut bad = padding.clone();
        bad.completion[field] = F::ONE;
        assert!(!bad.accepts(&p));
    }
    // Preserve the unused half's real privacy bits, and reject every chosen bit.
    let p = simple(&[boolean()]);
    let mut f = Fixture::new(&p, 0, &[1]);
    f.packets[0][MEMORY][BEFORE_TAG] = F(0xff00);
    f.packets[0][MEMORY][AFTER_TAG] = F(0xff00);
    dispatch_tests::bits(&mut f.words[0][PRIVATE..PRIVATE + 16], 0xff00);
    assert!(f.accepts(&p));
    for byte in 0..8 {
        let mut bad = f.clone();
        let mask = 0xff00 | 1 << byte;
        bad.packets[0][MEMORY][BEFORE_TAG] = F(mask);
        bad.packets[0][MEMORY][AFTER_TAG] = F(mask);
        dispatch_tests::bits(&mut bad.words[0][PRIVATE..PRIVATE + 16], mask);
        assert!(!bad.accepts(&p));
    }
}

#[test]
fn final_gas_and_all_original_completion_joins_reject_substitution() {
    let p = simple(&vec![boolean(); 3]);
    let f = Fixture::new(&p, 0, &[1, 0, 1]);
    assert!(f.accepts(&p));
    for field in 0..packet::WIDTH {
        let mut bad = f.clone();
        bad.completion[field] = bad.completion[field].add(F(7));
        assert!(!bad.accepts(&p));
    }
    let mut old = f.clone();
    for limb in 0..8 {
        old.completion[BEFORE + limb] =
            old.original.packets[super::super::FRAME_DEBIT][AFTER + limb];
        old.completion[AFTER + limb] = old.completion[BEFORE + limb];
    }
    assert!(
        !old.accepts(&p),
        "coherent frame-only gas cannot replace true post-WORD state"
    );
    for slot in 0..super::super::PORTS {
        for field in [
            KEY, GENERATION, INDEX, CLOCK, ENABLED, BEFORE_TAG, AFTER_TAG,
        ] {
            let mut bad = f.clone();
            bad.original.packets[slot][field] = bad.original.packets[slot][field].add(F(7));
            assert!(!bad.accepts(&p), "original{slot}/field{field}");
        }
    }
    for remaining in [
        0_u64,
        7,
        8,
        15,
        23,
        24,
        25,
        65535,
        65536,
        1 << 32,
        u64::MAX - 2,
    ] {
        let cost = super::super::frame_work(super::super::callable(&p, 0).unwrap());
        let gas = remaining.checked_add(cost + 2);
        if let Some(gas) = gas {
            let d = dispatch_tests::Fixture::with_controls(&p, 0, false, 0, gas, 100);
            let f = Fixture::from_original(&p, Original::from_dispatch(&p, 0, d), &[1, 0, 1]);
            assert_eq!(f.accepts(&p), remaining >= 27);
        }
    }
}

#[test]
fn public_geometry_retains_all_callables_and_fixed_degree_four() {
    use crate::execution_proofs::stark::proof_managed_note_stark::degree_audit::measured_maximum_affine_degree_v1;
    let p = simple(&[CallTypeNodeV1::Unit, boolean(), error()]);
    let shape = Shape::new(&p).unwrap();
    assert_eq!(
        (
            shape.words,
            shape.ports(),
            shape.width(),
            shape.history_rows()
        ),
        (3, 63, 6119, 504)
    );
    let mut slots = (0..super::super::PORTS)
        .map(|i| shape.old_slot(i))
        .collect::<Vec<_>>();
    slots.push(shape.completion_slot());
    for i in 0..shape.words {
        slots.extend((0..WORD_PORTS).map(|j| shape.word_slot(i, j)));
    }
    slots.sort_unstable();
    assert_eq!(slots, (0..shape.ports()).collect::<Vec<_>>());
    let degree = measured_maximum_affine_degree_v1(
        [0x71; 32],
        [shape.width(), 0, 0, 0, 0],
        4,
        4,
        |v, _, _, _, _| {
            let base_banks = super::super::super::WIDTH
                + frame_descriptor::WIDTH
                + super::super::FRAME_WORK_WIDTH;
            let base_end = super::super::WIDTH;
            let word_end = base_end + shape.words * WORD_WIDTH;
            let packets_end = word_end + shape.words * WORD_PORTS * packet::WIDTH;
            let words = v[base_end..word_end]
                .chunks_exact(WORD_WIDTH)
                .map(|w| *<&[F; WORD_WIDTH]>::try_from(w).unwrap())
                .collect::<Vec<_>>();
            let packets = v[word_end..packets_end]
                .chunks_exact(WORD_PORTS * packet::WIDTH)
                .map(|p| {
                    core::array::from_fn(|i| {
                        p[i * packet::WIDTH..(i + 1) * packet::WIDTH]
                            .try_into()
                            .unwrap()
                    })
                })
                .collect::<Vec<_>>();
            let original = super::super::Row {
                dispatch: v[..super::super::super::WIDTH].try_into().unwrap(),
                descriptor: v
                    [super::super::super::WIDTH..base_banks - super::super::FRAME_WORK_WIDTH]
                    .try_into()
                    .unwrap(),
                frame_work: v[base_banks - super::super::FRAME_WORK_WIDTH..base_banks]
                    .try_into()
                    .unwrap(),
                packets: core::array::from_fn(|i| {
                    v[base_banks + i * packet::WIDTH..base_banks + (i + 1) * packet::WIDTH]
                        .try_into()
                        .unwrap()
                }),
            };
            let row = Row {
                original,
                words: &words,
                packets: &packets,
                error_selectors: &v[packets_end..packets_end + shape.error_width()],
                completion_gas: v[packets_end + shape.error_width()..].try_into().unwrap(),
            };
            let mut out = Vec::new();
            append_semantics(&mut out, &Schedule::new(&p, 7, 64).unwrap(), &row);
            Ok::<_, core::convert::Infallible>(out)
        },
    );
    assert_eq!(degree, 4);
    let zero = simple(&[]);
    let z = Shape::new(&zero).unwrap();
    assert_eq!((z.ports(), z.width(), z.history_rows()), (48, 4827, 384));
    assert!(Schedule::new(&p, 7, u32::MAX - shape.ports() as u32 + 1).is_some());
    assert!(Schedule::new(&p, 7, u32::MAX - shape.ports() as u32 + 2).is_none());
}

#[test]
fn all_original_and_scalar_packets_share_every_typed_history_stage() {
    use super::super::super::super::{
        E, NOTE_COPY_WIDTH_V1, ORDERED, PREVIOUS, PublicPacketBus, ROW_WIDTH, SORTED,
    };
    let program = simple(&[CallTypeNodeV1::Unit, boolean(), error()]);
    let fixture = Fixture::new(&program, 0, &[0, 1, u64::from(u32::MAX)]);
    let shape = &fixture.schedule.shape;
    let ports = shape.ports();
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
    let original = fixture.row();
    let mut events = vec![None; 64];
    let mut keys = std::collections::BTreeSet::new();
    let mut next = 0;
    for slot in 0..ports {
        let p = original.producer(shape, slot);
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
    for slot in 0..ports {
        let p = original.producer(shape, slot);
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
    let count = ports * super::super::super::super::PHASES;
    let start = 64 * super::super::super::super::PHASES;
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
    let windows = (0..count)
        .map(|i| super::super::super::HistoryRow {
            current: &rows[i],
            next: &rows[i + 1],
            aux: &aux_rows[i],
            next_aux: &aux_rows[i + 1],
            fixed: &fixed[i],
        })
        .collect::<Vec<_>>();
    let mut residues = Vec::new();
    append_residues(
        &mut residues,
        &fixture.schedule,
        &original,
        &windows,
        &challenges,
    );
    assert!(residues.iter().all(|r| *r == F::ZERO));
    for index in [0, 7, 8, count - 1] {
        let mut changed = fixed.clone();
        changed[index][super::super::super::super::SLOT] =
            changed[index][super::super::super::super::SLOT].add(F::ONE);
        let altered = (0..count)
            .map(|i| super::super::super::HistoryRow {
                current: &rows[i],
                next: &rows[i + 1],
                aux: &aux_rows[i],
                next_aux: &aux_rows[i + 1],
                fixed: &changed[i],
            })
            .collect::<Vec<_>>();
        residues.clear();
        append_residues(
            &mut residues,
            &fixture.schedule,
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
    for slot in 0..ports {
        for field in 0..packet::WIDTH {
            for stage in 0..super::super::super::super::PHASES {
                let i = slot * super::super::super::super::PHASES + stage;
                let h = &windows[i];
                let mut substituted = *original.producer(shape, slot);
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

fn native_case(jals: bool, roles: &[CallTypeNodeV1], values: &[u64], gas: u64) -> u64 {
    let mut body = vec![
        enc::encode_ri(wide::arithmetic::ADDI, 31, 31, -64),
        enc::encode_ri(
            wide::arithmetic::ADDI,
            10,
            if roles.is_empty() { 0 } else { 31 },
            0,
        ),
        enc::encode_ri(wide::arithmetic::ADDI, 11, 0, roles.len() as i8),
        enc::encode_ri(wide::arithmetic::ADDI, 12, 31, 32),
    ];
    for i in 0..values.len() {
        body.push(enc::encode_store(
            wide::memory::STORE64,
            31,
            2 + i as u8,
            (i * 8) as i8,
        ));
    }
    let call_slot = body.len();
    body.push(if jals {
        enc::encode_offset24(wide::control::JALS, 2)
    } else {
        enc::encode_jump(wide::control::JAL, 1, 2)
    });
    body.push(enc::encode_halt());
    let p = program(&body, call_slot, roles);
    let mut vm = ivm::IVM::new(gas);
    // Limb-boundary gas can exceed the minimum guest stack. Bind the original
    // VM owner to the immutable V1 policy before checking every native address.
    let top = Memory::STACK_START + ivm::IvmStackPolicy::V1.stack_limit_for_gas(gas);
    assert_eq!(vm.memory.stack_top(), top);
    vm.load_prepared(p.artifact()).unwrap();
    vm.set_zk_trace_enabled(true);
    for (i, &v) in values.iter().enumerate() {
        vm.set_register(2 + i, v);
    }
    vm.memory.clear_tracking();
    let budget = iroha_allocation::AllocationBudget::new(64 * 1024 * 1024);
    let mut recorder =
        ivm::execution_step_recorder::DiagnosticStepRecorder::try_new(call_slot + 1, &budget)
            .unwrap();
    assert!(match (
        &(vm.run_with_host_diagnostic_steps(&mut ivm::host::DefaultHost::default(), &mut recorder)),
        &(ivm::VMError::ExecutionDeferred(ivm::error::ExecutionDeferral::ActiveMemoryCapacity))
    ) {
        (
            Err(ivm::VMError::ExecutionDeferred(actual_field_0)),
            ivm::VMError::ExecutionDeferred(expected_field_0),
        ) => actual_field_0 == expected_field_0,
        _ => false,
    });
    assert_eq!(recorder.records().len(), call_slot + 1);
    for (i, step) in recorder.records().iter().enumerate() {
        assert_eq!(step.instruction, Some(body[i]));
        assert_eq!(
            step.outcome,
            ivm::execution_step_recorder::DiagnosticStepOutcome::Completed
        );
        assert_eq!(step.before.pc, u64::from(p.first_pc) + i as u64 * 4);
        assert_eq!(step.after.cycles, step.before.cycles + 1);
    }
    let step = &recorder.records()[call_slot];
    let c = super::super::callable(&p, call_slot).unwrap();
    assert_eq!(
        step.before.gas_remaining - step.after.gas_remaining,
        2 + super::super::frame_work(c) + 9 * roles.len() as u64
    );
    let sp = top - 64;
    assert_eq!(
        [10, 11, 12, 13, 31].map(|r| step.before.registers[r]),
        [
            if roles.is_empty() { 0 } else { sp },
            roles.len() as u64,
            sp + 32,
            1,
            sp
        ]
    );
    let d = dispatch_tests::Fixture::with_controls(
        &p,
        call_slot,
        false,
        0,
        step.before.gas_remaining,
        step.before.cycles,
    );
    let mut original = Original::from_dispatch(&p, call_slot, d);
    // These diagnostic descriptor coordinates come from the actual root frame
    // and before-CALL registers. Abstract lifecycle generations remain the
    // component's declared original fixture owners, not a whole-invocation claim.
    let (descriptor, ports) = frame_descriptor::tests::child_for_original_tables(
        (
            c.entry_pc,
            u64::from(c.frame_bytes),
            c.argument_word_count().unwrap() as u64,
            c.result_word_count().unwrap() as u64,
        ),
        top,
        [sp, top],
        if roles.is_empty() { 0 } else { sp },
        sp + 32,
    );
    original.descriptor = descriptor;
    for (i, port) in ports.iter().enumerate() {
        original.packets[super::super::descriptor_slot(i)] = *port;
    }
    for (i, source) in super::super::VALIDATION_SOURCES.into_iter().enumerate() {
        original.packets[super::super::VALIDATION_START + i] = ports[source];
    }
    let mut f = Fixture::from_original(&p, original, values);
    // Derive each parent initialization cell from every observed STORE byte,
    // rather than granting the unused half of a partial final cell. Root setup
    // has empty arguments and all writes below belong to the declared parent.
    let observed_writes = vm.memory.try_write_log_snapshot().unwrap();
    for index in 0..values.len() {
        let address = sp + index as u64 * 8;
        let cell = address / 16;
        let mut initialized = 0_u64;
        for write in observed_writes.iter() {
            for offset in 0..write.bytes().len() {
                let written = write.address().checked_add(offset as u64).unwrap();
                if written / 16 == cell {
                    initialized |= 1 << (written % 16);
                }
            }
        }
        dispatch_tests::bits(
            &mut f.words[index][INITIALIZED..INITIALIZED + 16],
            initialized,
        );
        for port in [EARLY, LATE] {
            f.packets[index][port][BEFORE] = F(initialized);
            f.packets[index][port][AFTER] = F(initialized);
        }
        assert_eq!((initialized >> (address % 16)) & 0xff, 0xff);
        if index + 1 == values.len() && values.len() % 2 == 1 {
            assert_eq!(
                initialized, 0xff,
                "unused trailing half remains uninitialized"
            );
        }
    }
    // Bind the explicit final original read from the actual post-CALL snapshot,
    // then require the same owner and last WORD debit in the composed equations.
    for i in 0..4 {
        f.completion[BEFORE + i] = super::super::super::constant_limb(step.after.gas_remaining, i);
        f.completion[AFTER + i] = f.completion[BEFORE + i];
    }
    assert!(f.accepts(&p));
    let mut wrong = f.clone();
    for i in 0..4 {
        wrong.completion[BEFORE + i] =
            super::super::super::constant_limb(step.after.gas_remaining + 8, i);
        wrong.completion[AFTER + i] = wrong.completion[BEFORE + i];
    }
    assert!(!wrong.accepts(&p));
    let mut registers = step.before.registers;
    registers[1] = step.before.pc + 4;
    let mut tags = step.before.tags;
    tags[1] = false;
    assert_eq!(step.after.registers, registers);
    assert_eq!(step.after.tags, tags);
    assert_eq!(step.after.pc, u64::from(p.first_pc) + c.entry_pc);
    assert_eq!(
        (vm.gas_remaining, vm.pc(), vm.get_cycle_count()),
        (step.after.gas_remaining, step.after.pc, step.after.cycles)
    );
    assert!(vm.call_result_word_count().is_err());
    let tables = [(10, 0), (11, 0), (12, Memory::HEAP_START), (13, 1)];
    let mut expected = tables.map(|(r, v)| (true, r, v, false)).to_vec();
    expected.extend(tables.map(|(r, v)| (false, r, v, false)));
    for (r, v) in [(31, top), (1, p.code_end())] {
        expected.extend([(true, r, v, false); 2]);
    }
    expected.extend([
        (false, 10, 0, false),
        (false, 12, Memory::HEAP_START, false),
        (false, 11, 0, false),
        (false, 13, 1, false),
    ]);
    for (i, step) in recorder.records()[..4].iter().enumerate() {
        let r = [31, 10, 11, 12][i];
        let source = [31, if roles.is_empty() { 0 } else { 31 }, 0, 31][i];
        expected.push((false, source, step.before.registers[source], false));
        expected.extend([(true, r, step.after.registers[r], false); 2]);
    }
    for (i, &v) in values.iter().enumerate() {
        expected.extend([(false, 31, sp, false), (false, 2 + i, v, false)]);
    }
    for r in [31, 10, 11, 12, 13, 10, 12, 11, 13] {
        expected.push((false, r, step.before.registers[r], false));
    }
    expected.extend([(true, 1, step.before.pc + 4, false); 2]);
    let snapshot = vm.try_diagnostic_snapshot(&budget).unwrap();
    let actual = snapshot
        .register_events()
        .map(|e| (e.written, e.index, e.value, e.tag))
        .collect::<Vec<_>>();
    assert_eq!(
        actual, expected,
        "all root/setup/STORE/CALL accesses, with no discarded prefix"
    );
    assert_eq!(
        vm.memory
            .try_read_log_snapshot()
            .unwrap()
            .iter()
            .map(|r| (r.addr, r.len))
            .collect::<Vec<_>>(),
        (0..values.len())
            .map(|i| (sp + i as u64 * 8, 8))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        vm.memory
            .try_write_log_snapshot()
            .unwrap()
            .iter()
            .map(|w| (w.address(), w.bytes().to_vec()))
            .collect::<Vec<_>>(),
        values
            .iter()
            .enumerate()
            .map(|(i, v)| (sp + i as u64 * 8, v.to_le_bytes().to_vec()))
            .collect::<Vec<_>>()
    );
    // Expose the actual budget at the first NODE to the boundary controls;
    // all original native, chronology, scalar-bank and final-gas assertions above remain.
    step.before.gas_remaining - 2 - super::super::frame_work(c)
}

#[test]
fn genuine_prepared_scalar_call_binds_native_final_gas_and_complete_access_order() {
    for jals in [false, true] {
        native_case(jals, &[], &[], 10000);
        native_case(jals, &[CallTypeNodeV1::Unit], &[0], 10000);
        native_case(jals, &[boolean()], &[1], 44);
        native_case(
            jals,
            &[boolean(), error()],
            &[1, u64::from(u32::MAX)],
            10000,
        );
        native_case(
            jals,
            &[CallTypeNodeV1::Unit, boolean(), error()],
            &[0, 1, u64::from(u32::MAX)],
            10000,
        );
    }
}

#[test]
fn coherent_missing_initialization_wrong_parent_and_half_substitution_refuse() {
    let p = simple(&vec![boolean(); 2]);
    let f = Fixture::new(&p, 0, &[1, 0]);
    assert!(f.accepts(&p));
    for index in 0..2 {
        for byte in 0..8 {
            let mut bad = f.clone();
            let mask = 0xffff ^ (1 << (index * 8 + byte));
            dispatch_tests::bits(&mut bad.words[index][INITIALIZED..INITIALIZED + 16], mask);
            for port in [EARLY, LATE] {
                bad.packets[index][port][BEFORE] = F(mask);
                bad.packets[index][port][AFTER] = F(mask);
            }
            assert!(
                !bad.accepts(&p),
                "original selected initialization byte{index}/{byte}"
            );
        }
    }
    for index in 0..2 {
        let mut bad = f.clone();
        for port in [EARLY, LATE] {
            bad.packets[index][port][GENERATION] = F(4);
            bad.packets[index][port][KEY] = bad.packets[index][port][KEY].add(F(1 << 32));
        }
        assert!(!bad.accepts(&p));
    }
    let mut bad = f.clone();
    bad.words.swap(0, 1);
    bad.packets.swap(0, 1);
    assert!(
        !bad.accepts(&p),
        "coherent packets cannot exchange positions/halves"
    );
    let padding = Fixture::from_original(&p, Original::padding(&p), &[]);
    for index in 0..2 {
        for port in 0..WORD_PORTS {
            for field in 0..packet::WIDTH {
                let mut bad = padding.clone();
                bad.packets[index][port][field] = F::ONE;
                assert!(!bad.accepts(&p));
            }
        }
    }
}

#[test]
fn original_public_capacity_is_complete_or_explicitly_unqualified() {
    let p = simple(&vec![CallTypeNodeV1::Unit; 3267]);
    let shape = Shape::new(&p).unwrap();
    assert_eq!(
        (shape.ports(), shape.history_rows(), shape.width()),
        (16383, 131_064, 1_409_637)
    );
    for count in [3268, 8192] {
        let p = simple(&vec![CallTypeNodeV1::Unit; count]);
        assert!(
            Shape::new(&p).is_none(),
            "unqualified shape is not silently truncated"
        );
    }
}

#[test]
fn genuine_scalar_failures_preserve_word_gas_order_and_cannot_publish_completion() {
    use ivm::error::VmTrapKind;
    for jals in [false, true] {
        for (role, value, private, initialized, gas, error, trap, spent) in [
            (
                CallTypeNodeV1::Unit,
                1,
                false,
                true,
                10000,
                ivm::VMError::DecodeError,
                VmTrapKind::DecodeError,
                20,
            ),
            (
                boolean(),
                2,
                false,
                true,
                10000,
                ivm::VMError::DecodeError,
                VmTrapKind::DecodeError,
                20,
            ),
            (
                error(),
                1 << 32,
                false,
                true,
                10000,
                ivm::VMError::DecodeError,
                VmTrapKind::DecodeError,
                20,
            ),
            (
                boolean(),
                1,
                true,
                true,
                10000,
                ivm::VMError::PrivacyViolation,
                VmTrapKind::PrivacyViolation,
                20,
            ),
            (
                boolean(),
                1,
                false,
                false,
                10000,
                ivm::VMError::AssertionFailed,
                VmTrapKind::AssertionFailed,
                2,
            ),
            (
                boolean(),
                1,
                false,
                true,
                42,
                ivm::VMError::OutOfGas,
                VmTrapKind::OutOfGas,
                12,
            ),
            (
                boolean(),
                1,
                false,
                true,
                35,
                ivm::VMError::OutOfGas,
                VmTrapKind::OutOfGas,
                11,
            ),
            (
                boolean(),
                1,
                false,
                true,
                36,
                ivm::VMError::OutOfGas,
                VmTrapKind::OutOfGas,
                12,
            ),
            (
                boolean(),
                1,
                false,
                true,
                43,
                ivm::VMError::OutOfGas,
                VmTrapKind::OutOfGas,
                12,
            ),
            (
                error(),
                8,
                false,
                true,
                10000,
                ivm::VMError::DecodeError,
                VmTrapKind::DecodeError,
                20,
            ),
            (
                error(),
                0,
                false,
                true,
                10000,
                ivm::VMError::DecodeError,
                VmTrapKind::DecodeError,
                20,
            ),
        ] {
            let call = if jals {
                enc::encode_offset24(wide::control::JALS, 2)
            } else {
                enc::encode_jump(wide::control::JAL, 1, 2)
            };
            let body = [
                enc::encode_ri(wide::arithmetic::ADDI, 31, 31, -64),
                enc::encode_ri(wide::arithmetic::ADDI, 10, 31, 0),
                enc::encode_ri(wide::arithmetic::ADDI, 11, 0, 1),
                enc::encode_ri(wide::arithmetic::ADDI, 12, 31, 32),
                if initialized {
                    enc::encode_store(wide::memory::STORE64, 31, 2, 0)
                } else {
                    enc::encode_ri(wide::arithmetic::ADDI, 0, 0, 0)
                },
                call,
                enc::encode_halt(),
            ];
            let p = program(&body, 5, &[role]);
            let mut vm = ivm::IVM::new(gas);
            vm.load_prepared(p.artifact()).unwrap();
            vm.set_zk_trace_enabled(true);
            vm.set_register(2, value);
            vm.registers.set_tag(2, private);
            vm.memory.clear_tracking();
            let budget = iroha_allocation::AllocationBudget::new(64 * 1024 * 1024);
            let mut recorder =
                ivm::execution_step_recorder::DiagnosticStepRecorder::try_new(6, &budget).unwrap();
            assert!(matches!(
                (
                    vm.run_with_host_diagnostic_steps(
                        &mut ivm::host::DefaultHost::default(),
                        &mut recorder
                    ),
                    error
                ),
                (
                    Err(ivm::VMError::PrivacyViolation),
                    ivm::VMError::PrivacyViolation
                ) | (
                    Err(ivm::VMError::AssertionFailed),
                    ivm::VMError::AssertionFailed
                ) | (Err(ivm::VMError::OutOfGas), ivm::VMError::OutOfGas)
                    | (Err(ivm::VMError::DecodeError), ivm::VMError::DecodeError)
            ));

            assert_eq!(recorder.records().len(), 6);
            for (i, step) in recorder.records()[..5].iter().enumerate() {
                assert_eq!(step.instruction, Some(body[i]));
                assert_eq!(
                    step.outcome,
                    ivm::execution_step_recorder::DiagnosticStepOutcome::Completed
                );
            }
            let step = &recorder.records()[5];
            assert_eq!(step.instruction, Some(call));
            assert_eq!(
                step.outcome,
                ivm::execution_step_recorder::DiagnosticStepOutcome::Trapped(trap)
            );
            assert_eq!(step.before.gas_remaining - step.after.gas_remaining, spent);
            assert_eq!(step.after.pc, step.before.pc);
            assert_eq!(step.after.cycles, step.before.cycles);
            assert_eq!(step.after.registers, step.before.registers);
            assert_eq!(step.after.tags, step.before.tags);
            assert!(vm.call_result_word_count().is_err());
            let reads = vm.memory.try_read_log_snapshot().unwrap();
            let expected = if spent == 20 {
                vec![(step.before.registers[10], 8)]
            } else {
                vec![]
            };
            assert_eq!(
                reads.iter().map(|r| (r.addr, r.len)).collect::<Vec<_>>(),
                expected
            );
        }
    }
}

#[test]
fn original_nominal_error_catalog_rejects_detached_codes_ordinals_and_padding() {
    let a = simple(&[error_type("test/a/E", &[7, 99])]);
    let b = simple(&[error_type("test/b/E", &[8, 99])]);
    let valid = Fixture::new(&a, 0, &[7]);
    assert!(valid.accepts(&a));
    assert!(
        !valid.accepts(&b),
        "equal-width other nominal type cannot permit A's code"
    );
    // Isolate the exact nominal membership equations too: a changed artifact's
    // public encoding length/PC cannot be the sole cause of the refusal above.
    let mut membership = Vec::new();
    append_error_membership(
        &mut membership,
        &Schedule::new(&b, 7, 64).unwrap(),
        &valid.row(),
        0,
    );
    assert!(membership.iter().any(|value| *value != F::ZERO));
    let other = Fixture::new(&b, 0, &[8]);
    assert!(!other.accepts(&a));
    // A shared code legitimately satisfies either exact selected catalog.
    assert!(Fixture::new(&a, 0, &[99]).accepts(&a));
    assert!(Fixture::new(&b, 0, &[99]).accepts(&b));
    for index in 0..valid.errors.len() {
        for value in [F::ZERO, F::ONE, F(2)] {
            if value == valid.errors[index] {
                continue;
            }
            let mut changed = valid.clone();
            changed.errors[index] = value;
            assert!(!changed.accepts(&a));
        }
    }
    let padding = Fixture::from_original(&a, Original::padding(&a), &[]);
    for i in 0..padding.errors.len() {
        let mut changed = padding.clone();
        changed.errors[i] = F::ONE;
        assert!(!changed.accepts(&a));
    }
    for value in [0, 8, u64::from(u32::MAX), 1 << 32] {
        assert!(!Fixture::new(&a, 0, &[value]).accepts(&a));
    }
}

#[test]
fn node_and_word_gas_cannot_be_omitted_combined_reordered_or_coherently_detached() {
    let p = simple(&[boolean(), boolean()]);
    let original = Fixture::new(&p, 0, &[0, 1]);
    assert!(original.accepts(&p));
    for i in 0..2 {
        let mut swapped = original.clone();
        swapped.packets[i].swap(NODE, DEBIT);
        assert!(!swapped.accepts(&p));
        let mut missing = original.clone();
        missing.packets[i][NODE] = [F::ZERO; packet::WIDTH];
        missing.words[i][NODE_GAS..NODE_BORROW + 4].fill(F::ZERO);
        assert!(!missing.accepts(&p));
        // Retain both headers and all original gas owners. Recompute both
        // debits, every later leaf and all bit/borrow witnesses coherently,
        // charging zero NODE gas at this leaf instead of the required one.
        let mut detached = original.clone();
        let mut gas = packet::half(
            &detached.original.packets[super::super::FRAME_DEBIT],
            AFTER,
            0,
        );
        for j in 0..2 {
            let node_cost = u64::from(j != i);
            for (port, offset, borrow, tariff) in [
                (NODE, NODE_GAS, NODE_BORROW, node_cost),
                (DEBIT, GAS, BORROW, 8),
            ] {
                let after = gas.checked_sub(tariff).unwrap();
                dispatch_tests::bits(&mut detached.words[j][offset..offset + 64], after);
                dispatch_tests::carries(
                    &mut detached.words[j][borrow..borrow + 4],
                    gas,
                    tariff,
                    true,
                );
                for limb in 0..4 {
                    detached.packets[j][port][BEFORE + limb] =
                        super::super::super::constant_limb(gas, limb);
                    detached.packets[j][port][AFTER + limb] =
                        super::super::super::constant_limb(after, limb);
                }
                gas = after;
            }
        }
        assert_eq!(gas, packet::half(&original.completion, BEFORE, 0) + 1);
        assert!(
            !detached.accepts(&p),
            "coherent retired tariff cannot replace the original final observation"
        );
        // Even a coherently detached completion observation cannot legalize
        // the wrong tariff: its fixed NODE subtraction still rejects.
        for limb in 0..4 {
            detached.completion[BEFORE + limb] = super::super::super::constant_limb(gas, limb);
            detached.completion[AFTER + limb] = detached.completion[BEFORE + limb];
        }
        assert!(!detached.accepts(&p));
    }
}

#[test]
fn public_shape_uses_unselected_callables_and_all_error_ordinals() {
    let codes = (1..=256).map(|i| i * 1009).collect::<Vec<_>>();
    let p = simple(&[error_type("test/max/E", &codes)]);
    let shape = Shape::new(&p).unwrap();
    assert_eq!(
        (shape.words, shape.error_width(), shape.width()),
        (1, 256, 5513)
    );
    for code in codes {
        let candidate = Fixture::new(&p, 0, &[u64::from(code)]);
        assert!(candidate.accepts(&p));
        assert_eq!(candidate.errors.iter().filter(|v| **v == F::ONE).count(), 1);
        assert!(!Fixture::new(&p, 0, &[u64::from(code) + 1]).accepts(&p));
    }
    let body = [
        enc::encode_jump(wide::control::JAL, 1, 3),
        enc::encode_jump(wide::control::JAL, 1, 3),
        enc::encode_halt(),
        enc::encode_halt(),
        enc::encode_halt(),
    ];
    // Rebuild and admit the whole image; no writable Program or CodeWords API.
    let base = dispatch_tests::contract_with_frame(&body, 1000, ivm::ivm_mode::ZK, 64);
    let mut interface = base.contract_interface().clone();
    interface
        .callables
        .iter_mut()
        .find(|c| c.entry_pc == 16)
        .unwrap()
        .arguments = ivm::call::CallSchemaV1 {
        nodes: vec![CallTypeNodeV1::Unit; 3267],
    };
    let mut bytes = base.metadata().encode();
    bytes.extend_from_slice(&interface.encode_section());
    bytes.extend_from_slice(&base.artifact()[base.code_offset()..]);
    let p =
        Program::new(ivm::prepare_contract(std::sync::Arc::<[u8]>::from(bytes)).unwrap()).unwrap();
    assert_eq!(
        p.callables()
            .argument_word_count(p.callables().child_index(0).unwrap()),
        Some(0)
    );
    assert_eq!(
        Shape::new(&p).unwrap().words,
        3267,
        "unselected longer callable sets public padding"
    );
}

#[test]
fn public_shape_storage_has_fixed_bounds_and_no_heap_owner() {
    assert_eq!(MAX_PLAN_WORDS, 3267);
    assert_eq!(ELIGIBILITY_LIMBS, 1);
    assert_eq!(core::mem::size_of::<[u32; MAX_PLAN_WORDS + 1]>(), 13_072);
    assert!(core::mem::size_of::<Shape>() <= 13_088);
    assert!(!core::mem::needs_drop::<Shape>());
    assert!(!core::mem::needs_drop::<Schedule<'_>>());
    let p = simple(&[error_type("test/fixed/E", &[7, 99]), boolean()]);
    let shape = Shape::new(&p).unwrap();
    let cloned = shape.clone();
    assert_eq!(cloned.words, 2);
    assert_eq!(cloned.error_range(0), 0..2);
    assert_eq!(cloned.error_range(1), 2..2);
    assert!(cloned.errors[cloned.words + 1..].iter().all(|v| *v == 0));
    assert!(cloned.supports(p.callables().child_index(0).unwrap()));
    for outside in [super::super::super::MAX_WORDS, usize::MAX] {
        assert!(!cloned.supports(outside));
        assert!(p.callables().child_index(outside).is_none());
        assert!(p.callables().argument_word_count(outside).is_none());
        assert!(p.callables().child_frame_work(outside).is_none());
    }
    assert_eq!(shape.width(), cloned.width());
    for slot in 0..p.words.len() {
        assert_eq!(
            p.callables().child_frame_work(slot),
            super::super::callable(&p, slot).map(super::super::frame_work)
        );
    }
}

#[test]
fn same_program_error_callables_bind_distinct_ordinals_to_original_fetch() {
    let body = [
        enc::encode_jump(wide::control::JAL, 1, 3),
        enc::encode_jump(wide::control::JAL, 1, 3),
        enc::encode_halt(),
        enc::encode_halt(),
        enc::encode_halt(),
    ];
    let a = error_type("test/two/A", &[7, 99]);
    let b = error_type("test/two/B", &[8, 70, 99]);
    let base = dispatch_tests::contract_with_frame(&body, 1000, ivm::ivm_mode::ZK, 64);
    let mut interface = base.contract_interface().clone();
    for (entry_pc, node) in [(12, a), (16, b)] {
        let CallTypeNodeV1::Error(descriptor) = &node else {
            unreachable!()
        };
        interface.error_types.push(descriptor.clone());
        interface
            .callables
            .iter_mut()
            .find(|c| c.entry_pc == entry_pc)
            .unwrap()
            .arguments = ivm::call::CallSchemaV1 { nodes: vec![node] };
    }
    let mut bytes = base.metadata().encode();
    bytes.extend_from_slice(&interface.encode_section());
    bytes.extend_from_slice(&base.artifact()[base.code_offset()..]);
    let p =
        Program::new(ivm::prepare_contract(std::sync::Arc::<[u8]>::from(bytes)).unwrap()).unwrap();
    let schedule = Schedule::new(&p, 7, 64).unwrap();
    assert_eq!((schedule.shape.words, schedule.shape.error_width()), (1, 3));
    let membership_accepts = |fixture: &Fixture<'_>| {
        let mut residues = Vec::new();
        append_error_membership(&mut residues, &schedule, &fixture.row(), 0);
        residues.iter().all(|value| *value == F::ZERO)
    };
    for (slot, accepted, refused) in [(0, vec![7, 99], vec![8, 70]), (1, vec![8, 70, 99], vec![7])]
    {
        for value in accepted {
            let fixture = Fixture::new(&p, slot, &[value]);
            assert!(fixture.accepts(&p));
            assert!(membership_accepts(&fixture));
        }
        for value in refused {
            assert!(!Fixture::new(&p, slot, &[value]).accepts(&p));
        }
    }
    // Code99 is shared, but its ordinal differs in the two original catalogs.
    let a_shared = Fixture::new(&p, 0, &[99]);
    let b_shared = Fixture::new(&p, 1, &[99]);
    assert_eq!(a_shared.errors, [F::ZERO, F::ONE, F::ZERO]);
    assert_eq!(b_shared.errors, [F::ZERO, F::ZERO, F::ONE]);
    for (original, donor) in [(&a_shared, &b_shared), (&b_shared, &a_shared)] {
        let mut wrong = original.clone();
        wrong.errors.clone_from(&donor.errors);
        assert!(!wrong.accepts(&p));
        assert!(
            !membership_accepts(&wrong),
            "refusal cannot depend on descriptor/PC differences"
        );
    }
    // Even a coherent foreign code/ordinal pair must follow the original fetch.
    let b_only = Fixture::new(&p, 1, &[8]);
    let mut foreign = Fixture::new(&p, 0, &[8]);
    foreign.errors.clone_from(&b_only.errors);
    assert!(!membership_accepts(&foreign));
    // Isolate the original fetch coefficients without changing programs, schema
    // objects, packet headers or the code/ordinal witness being checked.
    let mut fetch_only = b_shared.clone();
    fetch_only.original.dispatch[super::super::super::FETCH + 1] = F::ZERO;
    fetch_only.original.dispatch[super::super::super::FETCH] = F::ONE;
    assert!(!membership_accepts(&fetch_only));
}

// Empty root result reservation8, root frame9, four ADDI4, two STORE64 six,
// then CALL opcode2 and child frame9 precede the first argument NODE.
fn two_word_initial_gas(post_frame: u64) -> u64 {
    assert_eq!(ivm::call_gas::frame(64, 1).unwrap(), 9);
    assert_eq!((ivm::call_gas::NODE, ivm::call_gas::WORD), (1, 8));
    post_frame.checked_add(8 + 9 + 4 + 6 + 2 + 9).unwrap()
}

fn native_second_word_gas_failure(jals: bool, post_frame: u64) {
    assert!((9..18).contains(&post_frame));
    let call = if jals {
        enc::encode_offset24(wide::control::JALS, 2)
    } else {
        enc::encode_jump(wide::control::JAL, 1, 2)
    };
    let body = [
        enc::encode_ri(wide::arithmetic::ADDI, 31, 31, -64),
        enc::encode_ri(wide::arithmetic::ADDI, 10, 31, 0),
        enc::encode_ri(wide::arithmetic::ADDI, 11, 0, 2),
        enc::encode_ri(wide::arithmetic::ADDI, 12, 31, 32),
        enc::encode_store(wide::memory::STORE64, 31, 2, 0),
        enc::encode_store(wide::memory::STORE64, 31, 3, 8),
        call,
        enc::encode_halt(),
    ];
    let p = program(&body, 6, &[boolean(), boolean()]);
    let initial = two_word_initial_gas(post_frame);
    let mut vm = ivm::IVM::new(initial);
    vm.load_prepared(p.artifact()).unwrap();
    vm.set_zk_trace_enabled(true);
    vm.set_register(2, 0);
    vm.set_register(3, 1);
    vm.memory.clear_tracking();
    let budget = iroha_allocation::AllocationBudget::new(64 * 1024 * 1024);
    let mut recorder =
        ivm::execution_step_recorder::DiagnosticStepRecorder::try_new(7, &budget).unwrap();
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
    assert_eq!(recorder.records().len(), 7);
    let before_setup = initial - 8 - 9;
    for (index, step) in recorder.records()[..6].iter().enumerate() {
        assert_eq!(step.instruction, Some(body[index]));
        assert_eq!(
            step.outcome,
            ivm::execution_step_recorder::DiagnosticStepOutcome::Completed
        );
        assert_eq!(step.before.pc, u64::from(p.first_pc) + index as u64 * 4);
        assert_eq!(step.after.pc, step.before.pc + 4);
        assert_eq!(step.after.cycles, step.before.cycles + 1);
        let cost = if index < 4 { 1 } else { 3 };
        assert_eq!(step.before.gas_remaining - step.after.gas_remaining, cost);
        if index == 0 {
            assert_eq!(
                step.before.gas_remaining, before_setup,
                "root result+frame debits retained"
            );
        } else {
            assert_eq!(
                step.before.gas_remaining,
                recorder.records()[index - 1].after.gas_remaining
            );
        }
    }
    let step = &recorder.records()[6];
    assert_eq!(step.instruction, Some(call));
    assert_eq!(
        step.outcome,
        ivm::execution_step_recorder::DiagnosticStepOutcome::Trapped(
            ivm::error::VmTrapKind::OutOfGas
        )
    );
    assert_eq!(step.before.gas_remaining, post_frame + 2 + 9);
    assert_eq!(
        step.before.gas_remaining,
        recorder.records()[5].after.gas_remaining
    );
    // First NODE1/WORD8 succeeds and performs exactly one read. With nine
    // available gas the second NODE fails; with10..17 the second NODE succeeds
    // but WORD8 fails without debiting its unaffordable tariff or reading word2.
    let scalar_spent = if post_frame == 9 { 9 } else { 10 };
    let final_gas = post_frame - scalar_spent;
    assert_eq!(
        step.before.gas_remaining - step.after.gas_remaining,
        2 + 9 + scalar_spent
    );
    assert_eq!(step.after.gas_remaining, final_gas);
    assert_eq!(step.after.pc, step.before.pc);
    assert_eq!(step.after.cycles, step.before.cycles);
    assert_eq!(step.after.registers, step.before.registers);
    assert_eq!(step.after.tags, step.before.tags);
    assert_eq!(
        (vm.gas_remaining, vm.pc(), vm.get_cycle_count()),
        (final_gas, step.before.pc, step.before.cycles)
    );
    assert!(vm.call_result_word_count().is_err());
    let top = Memory::STACK_START + Memory::MIN_STACK_SIZE;
    let sp = top - 64;
    assert_eq!(
        [10, 11, 12, 13, 31].map(|r| step.before.registers[r]),
        [sp, 2, sp + 32, 1, sp]
    );
    assert_eq!(
        vm.memory
            .try_read_log_snapshot()
            .unwrap()
            .iter()
            .map(|r| (r.addr, r.len))
            .collect::<Vec<_>>(),
        vec![(sp, 8)]
    );
    assert_eq!(
        vm.memory
            .try_write_log_snapshot()
            .unwrap()
            .iter()
            .map(|w| (w.address(), w.bytes().to_vec()))
            .collect::<Vec<_>>(),
        vec![
            (sp, 0_u64.to_le_bytes().to_vec()),
            (sp + 8, 1_u64.to_le_bytes().to_vec())
        ]
    );
    let root_tables = [(10, 0), (11, 0), (12, Memory::HEAP_START), (13, 1)];
    let mut expected = root_tables
        .map(|(r, value)| (true, r, value, false))
        .to_vec();
    expected.extend(root_tables.map(|(r, value)| (false, r, value, false)));
    for (r, value) in [(31, top), (1, p.code_end())] {
        expected.extend([(true, r, value, false); 2]);
    }
    expected.extend([
        (false, 10, 0, false),
        (false, 12, Memory::HEAP_START, false),
        (false, 11, 0, false),
        (false, 13, 1, false),
    ]);
    for (index, setup) in recorder.records()[..4].iter().enumerate() {
        let target = [31, 10, 11, 12][index];
        let source = [31, 31, 0, 31][index];
        expected.push((false, source, setup.before.registers[source], false));
        expected.extend([(true, target, setup.after.registers[target], false); 2]);
    }
    expected.extend([
        (false, 31, sp, false),
        (false, 2, 0, false),
        (false, 31, sp, false),
        (false, 3, 1, false),
    ]);
    for r in [31, 10, 11, 12, 13, 10, 12, 11, 13] {
        expected.push((false, r, step.before.registers[r], false));
    }
    let snapshot = vm.try_diagnostic_snapshot(&budget).unwrap();
    assert_eq!(
        snapshot
            .register_events()
            .map(|event| (event.written, event.index, event.value, event.tag))
            .collect::<Vec<_>>(),
        expected,
        "complete root/setup/STORE/failed-CALL chronology has no link publication"
    );
}

#[test]
fn genuine_two_word_call_separates_second_node_word_failure_from_exact_completion() {
    for jals in [false, true] {
        for post_frame in [9, 10, 17] {
            native_second_word_gas_failure(jals, post_frame);
        }
        for post_frame in [18, 19] {
            assert_eq!(
                native_case(
                    jals,
                    &[boolean(), boolean()],
                    &[0, 1],
                    two_word_initial_gas(post_frame)
                ),
                post_frame
            );
        }
    }
}

#[test]
fn genuine_two_word_call_binds_node_and_word_across_every_integer_limb() {
    for jals in [false, true] {
        for limb_bits in [16, 32, 48] {
            let boundary = 1_u64 << limb_bits;
            // Each original NODE/WORD packet sees the exact limb boundary as
            // its BEFORE, at first NODE, first WORD, second NODE, second WORD.
            for offset in [0, 1, 9, 10] {
                let post_frame = boundary + offset;
                assert_eq!(
                    native_case(
                        jals,
                        &[boolean(), boolean()],
                        &[0, 1],
                        two_word_initial_gas(post_frame)
                    ),
                    post_frame
                );
            }
        }
        let post_frame = u64::MAX - 38;
        assert_eq!(two_word_initial_gas(post_frame), u64::MAX);
        assert_eq!(
            native_case(jals, &[boolean(), boolean()], &[0, 1], u64::MAX),
            post_frame
        );
    }
}
