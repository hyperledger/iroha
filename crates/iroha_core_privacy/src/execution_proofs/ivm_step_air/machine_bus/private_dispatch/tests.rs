//! Private fetch, source-port, gas, lifecycle and return-target adversaries.

use super::*;
use ivm::{ProgramMetadata, encoding::wide as enc};
use packet::{Event, Space};
use std::sync::Arc;

fn contract_artifact(body: &[u32], max_cycles: u64, mode: u8) -> Arc<[u8]> {
    contract_artifact_with_frame(body, max_cycles, mode, 0)
}

fn contract_artifact_with_frame(
    body: &[u32],
    max_cycles: u64,
    mode: u8,
    frame_bytes: u32,
) -> Arc<[u8]> {
    contract_artifact_with_frame_at(body, max_cycles, mode, frame_bytes, 0)
}

fn contract_artifact_with_frame_at(
    body: &[u32],
    max_cycles: u64,
    mode: u8,
    frame_bytes: u32,
    entry_pc: u64,
) -> Arc<[u8]> {
    use iroha_data_model::smart_contract::{
        entrypoint::{EntrypointValueTypeNodeV1, EntrypointValueTypeV1},
        manifest::EntryPointKind,
    };
    let mut roots = std::collections::BTreeSet::from([entry_pc]);
    for (index, &instruction) in body.iter().enumerate() {
        let offset = match wide::opcode(instruction) {
            wide::control::JAL if wide::rd(instruction) == 1 => i64::from(wide::imm16(instruction)),
            wide::control::JALS => i64::from(wide::imm24(instruction)),
            _ => continue,
        };
        let target = (index as u64 * 4).checked_add_signed(offset * 4).unwrap();
        roots.insert(target);
    }
    let interface = ivm::EmbeddedContractInterfaceV1 {
        events: Vec::new(),
        enum_types: Vec::new(),
        permissions: Vec::new(),
        callables: roots
            .into_iter()
            .map(|pc| {
                let mut callable = crate::ivm_test_support::unit_callable(pc);
                callable.frame_bytes = frame_bytes;
                callable
            })
            .collect(),
        seiyaku_name: "PrivateDispatchFixture".into(),
        compiler_fingerprint: "private-dispatch-test".into(),
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
            entry_pc,
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
    Arc::from(program)
}

pub(in crate::execution_proofs::ivm_step_air::machine_bus) fn contract(
    body: &[u32],
    max_cycles: u64,
    mode: u8,
) -> PreparedContract {
    ivm::prepare_contract(contract_artifact(body, max_cycles, mode))
        .expect("admitted V1 scalar fixture")
}

pub(super) fn contract_with_frame(
    body: &[u32],
    max_cycles: u64,
    mode: u8,
    frame_bytes: u32,
) -> PreparedContract {
    ivm::prepare_contract(contract_artifact_with_frame(
        body,
        max_cycles,
        mode,
        frame_bytes,
    ))
    .expect("admitted V1 fixture with its original declared frame")
}

/// Admit an explicit original entrypoint while retaining every direct-call root.
pub(super) fn contract_with_frame_at(
    body: &[u32],
    max_cycles: u64,
    mode: u8,
    frame_bytes: u32,
    entry_pc: u64,
) -> PreparedContract {
    ivm::prepare_contract(contract_artifact_with_frame_at(
        body,
        max_cycles,
        mode,
        frame_bytes,
        entry_pc,
    ))
    .expect("admitted V1 fixture with its original entrypoint and declared frame")
}

pub(super) fn bits(row: &mut [F], value: u64) {
    for (i, bit) in row.iter_mut().enumerate() {
        *bit = F((value >> i) & 1);
    }
}
pub(super) fn bytes(value: u64) -> [u8; 16] {
    (value as u128).to_le_bytes()
}
pub(super) fn event(
    space: Space,
    generation: u16,
    index: u32,
    before: u64,
    after: u64,
    write: bool,
    clock: u32,
    before_tag: bool,
    after_tag: bool,
) -> [F; packet::WIDTH] {
    Event {
        space,
        vm: 7,
        generation,
        index,
        write,
        before: bytes(before),
        after: bytes(after),
        before_private: u16::from(before_tag),
        after_private: u16::from(after_tag),
    }
    .fields(clock as usize)
}
pub(super) fn carries(row: &mut [F], left: u64, right: u64, subtract: bool) {
    let mut carry = 0u64;
    for i in 0..4 {
        let a = (left >> (16 * i)) & 0xffff;
        let b = (right >> (16 * i)) & 0xffff;
        carry = if subtract {
            u64::from(a < b + carry)
        } else {
            (a + b + carry) >> 16
        };
        row[i] = F(carry);
    }
}

#[derive(Clone)]
pub(super) struct Fixture {
    pub(super) schedule: Schedule,
    pub(super) row: [F; WIDTH],
    pub(super) packets: OriginalPackets,
}
impl Fixture {
    pub(super) fn new(program: &Program, slot: usize, root: bool, return_delta: u64) -> Self {
        Self::with_controls(program, slot, root, return_delta, 13, 100)
    }
    pub(super) fn with_controls(
        program: &Program,
        slot: usize,
        root: bool,
        return_delta: u64,
        gas: u64,
        cycles: u64,
    ) -> Self {
        let clocks = core::array::from_fn(|i| 100 + i as u32 * 10);
        let schedule = Schedule::new(7, clocks).unwrap();
        let mut row = [F::ZERO; WIDTH];
        row[SCALAR + scalar::COMPARE
            ..SCALAR + scalar::COMPARE + super::super::super::branch::BANK_WIDTH]
            .copy_from_slice(&super::super::super::branch::bank_witness(0, 0, 0));
        row[SCALAR + scalar::COUNT..SCALAR + scalar::MOVE].fill(F::ONE);
        row[SCALAR + scalar::MOVE] = F::ONE;
        row[SCALAR + scalar::SHIFT..].copy_from_slice(&super::super::super::shift::bank_witness(
            wide::arithmetic::SLL,
            0,
            0,
        ));
        let mut p = [[F::ZERO; packet::WIDTH]; PORTS];
        let w = program.words[slot];
        let role = role(w).unwrap();
        let child = role == Role::Child;
        let returning = role == Role::Return;
        let store = role == Role::Store;
        let load = role == Role::Load;
        let memory = store || load;
        let pc = u64::from(program.first_pc) + slot as u64 * 4;
        let cost = if memory { 3 } else { 2 };
        let target = if returning {
            if root {
                program.code_end()
            } else {
                u64::from(program.first_pc) + 4
            }
        } else {
            0
        };
        let raw_return = if returning { target + return_delta } else { 0 };
        let base = if memory {
            ivm::Memory::STACK_START + 64
        } else {
            0
        };
        let imm = if memory {
            i64::from(wide::imm8(w)) as u64
        } else {
            0
        };
        let address = base.wrapping_add(imm);
        let words = [
            pc,
            gas,
            gas - cost,
            cycles,
            cycles + 1,
            target,
            base,
            address,
            raw_return,
            program.cycle_limit - 1 - cycles,
        ];
        row[FETCH + slot] = F::ONE;
        for (i, word) in words.into_iter().enumerate() {
            bits(&mut row[WORDS + i * 64..WORDS + (i + 1) * 64], word);
        }
        carries(&mut row[CARRIES..CARRIES + 4], gas, cost, true);
        carries(&mut row[CARRIES + 4..CARRIES + 8], cycles, 1, false);
        carries(&mut row[CARRIES + 8..CARRIES + 12], base, imm, false);
        carries(
            &mut row[CARRIES + 12..CARRIES + 16],
            target,
            if returning { return_delta } else { 0 },
            false,
        );
        carries(
            &mut row[CARRIES + 16..CARRIES + 20],
            program.cycle_limit - 1,
            cycles,
            true,
        );
        bits(
            &mut row[RETURN_DELTA..SCALAR],
            if returning { return_delta } else { 0 },
        );
        for (slot, index, before, after, write) in [
            (PC_READ, PC_OWNER, pc, pc, false),
            (GAS_DEBIT, GAS_OWNER, gas, gas - cost, true),
            (CYCLE_WRITE, CYCLE_OWNER, cycles, cycles + 1, true),
        ] {
            p[slot] = event(
                Space::Owner,
                0,
                index,
                before,
                after,
                write,
                clocks[slot],
                false,
                false,
            );
        }
        let mut after_pc = pc + 4;
        if child || role == Role::Jump {
            let delta = if wide::opcode(w) == wide::control::JAL {
                i64::from(wide::imm16(w))
            } else {
                i64::from(wide::imm24(w))
            };
            after_pc = pc.wrapping_add_signed(delta * 4);
        }
        if child {
            row[CHILD_INVERSE] = F(3).inv().unwrap();
            for (slot, generation, index, before, after) in [
                (CHILD_COUNTER, 0, 1, 10, 11),
                (CHILD_ACTIVE, 0, 0, 3, 11),
                (CHILD_PARENT, 11, 2, 0, 3),
            ] {
                p[slot] = event(
                    Space::Owner,
                    generation,
                    index,
                    before,
                    after,
                    true,
                    clocks[slot],
                    false,
                    false,
                );
            }
            p[CHILD_PROTECTED_PC] = event(
                Space::Owner,
                11,
                RETURN_PC_OWNER,
                0,
                pc + 4,
                true,
                clocks[CHILD_PROTECTED_PC],
                false,
                false,
            );
            p[LINK_WRITE] = event(
                Space::Register,
                0,
                1,
                97,
                pc + 4,
                true,
                clocks[LINK_WRITE],
                true,
                false,
            );
        }
        if returning {
            after_pc = target;
            let parent = if root { 0 } else { 2 };
            row[RETURN_INVERSE] = F(3).inv().unwrap();
            row[PARENT_LIVE] = F(u64::from(!root));
            row[PARENT_INVERSE] = F(parent).inv().unwrap_or(F::ZERO);
            p[RETURN_REGISTER] = event(
                Space::Register,
                0,
                1,
                raw_return,
                raw_return,
                false,
                clocks[RETURN_REGISTER],
                false,
                false,
            );
            for (slot, generation, index, before, after, write) in [
                (RETURN_COUNTER, 0, 1, 10, 10, false),
                (RETURN_ACTIVE, 0, 0, 3, parent, true),
                (RETURN_PARENT, 3, 2, parent, parent, false),
            ] {
                p[slot] = event(
                    Space::Owner,
                    generation,
                    index,
                    before,
                    after,
                    write,
                    clocks[slot],
                    false,
                    false,
                );
            }
            p[RETURN_PROTECTED_PC] = event(
                Space::Owner,
                3,
                RETURN_PC_OWNER,
                target,
                target,
                false,
                clocks[RETURN_PROTECTED_PC],
                false,
                false,
            );
            let difference = F(target).sub(F(program.code_end()));
            row[HALT] = F(u64::from(target == program.code_end()));
            row[HALT_INVERSE] = difference.inv().unwrap_or(F::ZERO);
        }
        if memory {
            p[MEMORY_BASE] = event(
                Space::Register,
                0,
                if store { wide::rd(w) } else { wide::rs1(w) } as u32,
                base,
                base,
                false,
                clocks[MEMORY_BASE],
                false,
                false,
            );
        }
        if load && wide::rd(w) != 0 {
            // The memory effect owns the loaded value; this dispatcher-only
            // fixture still carries the sole atomic destination's exact shape.
            p[SCALAR_DESTINATION] = event(
                Space::Register,
                0,
                wide::rd(w) as u32,
                if wide::rd(w) == wide::rs1(w) { base } else { 0 },
                0,
                true,
                clocks[SCALAR_DESTINATION],
                false,
                false,
            );
        }
        if store {
            p[STORE_VALUE] = event(
                Space::Register,
                0,
                wide::rs1(w) as u32,
                u64::MAX - 3,
                u64::MAX - 3,
                false,
                clocks[STORE_VALUE],
                true,
                true,
            );
        }
        let depth = if returning && root { 0 } else { 3 };
        let depth_after = depth + u64::from(child) - u64::from(returning && !root);
        for (side, value) in [depth, depth_after].into_iter().enumerate() {
            bits(
                &mut row[DEPTH_BITS + side * DEPTH_BITS_PER_VALUE
                    ..DEPTH_BITS + (side + 1) * DEPTH_BITS_PER_VALUE],
                value,
            );
        }
        p[CALL_DEPTH] = event(
            Space::Owner,
            0,
            CALL_DEPTH_OWNER,
            depth,
            depth_after,
            child || returning,
            clocks[CALL_DEPTH],
            false,
            false,
        );
        p[PC_WRITE] = event(
            Space::Owner,
            0,
            PC_OWNER,
            pc,
            after_pc,
            true,
            clocks[PC_WRITE],
            false,
            false,
        );
        p[RUNNING_WRITE] = event(
            Space::Owner,
            0,
            RUNNING_OWNER,
            1,
            u64::from(row[HALT] == F::ZERO),
            true,
            clocks[RUNNING_WRITE],
            false,
            false,
        );
        Self {
            schedule,
            row,
            packets: OriginalPackets::candidate(p),
        }
    }
    pub(super) fn set_depth(&mut self, before: u64, after: u64) {
        for (side, value) in [before, after].into_iter().enumerate() {
            bits(
                &mut self.row[DEPTH_BITS + side * DEPTH_BITS_PER_VALUE
                    ..DEPTH_BITS + (side + 1) * DEPTH_BITS_PER_VALUE],
                value,
            );
        }
        let previous = self.packets.fields[CALL_DEPTH];
        self.packets.fields[CALL_DEPTH] = event(
            Space::Owner,
            0,
            CALL_DEPTH_OWNER,
            before,
            after,
            previous[packet::WRITE] == F::ONE,
            self.schedule.clocks[CALL_DEPTH],
            false,
            false,
        );
    }
    pub(super) fn padding() -> Self {
        let clocks = core::array::from_fn(|i| 100 + i as u32 * 10);
        let packets = [[F::ZERO; packet::WIDTH]; PORTS];
        Self {
            schedule: Schedule::new(7, clocks).unwrap(),
            row: {
                let mut row = [F::ZERO; WIDTH];
                row[SCALAR + scalar::COMPARE
                    ..SCALAR + scalar::COMPARE + super::super::super::branch::BANK_WIDTH]
                    .copy_from_slice(&super::super::super::branch::bank_witness(0, 0, 0));
                row[SCALAR + scalar::COUNT..SCALAR + scalar::MOVE].fill(F::ONE);
                row[SCALAR + scalar::MOVE] = F::ONE;
                row[SCALAR + scalar::SHIFT..].copy_from_slice(
                    &super::super::super::shift::bank_witness(wide::arithmetic::SLL, 0, 0),
                );
                row
            },
            packets: OriginalPackets::candidate(packets),
        }
    }
    pub(super) fn accepts(&self, program: &Program) -> bool {
        let mut out = Vec::new();
        let decoded = append_residues(&mut out, program, self.schedule, &self.row, &self.packets);
        assert!(core::ptr::eq(
            decoded.child_active,
            self.packets.producer(CHILD_ACTIVE).unwrap()
        ));
        assert!(core::ptr::eq(
            decoded.return_active,
            self.packets.producer(RETURN_ACTIVE).unwrap()
        ));
        assert!(core::ptr::eq(
            decoded.return_parent,
            self.packets.producer(RETURN_PARENT).unwrap()
        ));
        assert!(core::ptr::eq(
            decoded.store_value,
            self.packets.producer(STORE_VALUE).unwrap()
        ));
        assert!(core::ptr::eq(
            decoded.call_depth,
            self.packets.producer(CALL_DEPTH).unwrap()
        ));
        out.into_iter().all(|r| r == F::ZERO)
    }
}
fn program() -> Program {
    Program::new(contract(
        &[
            enc::encode_jump(wide::control::JAL, 1, 4),
            enc::encode_offset24(wide::control::JALS, 3),
            enc::encode_store(wide::memory::STORE64, 2, 3, -8),
            enc::encode_ri(wide::control::JALR, 0, 1, 0),
        ],
        1_000,
        ivm::ivm_mode::ZK,
    ))
    .unwrap()
}

#[test]
fn original_private_dispatch_owns_call_return_and_store_packets() {
    let program = program();
    assert!(!program.artifact().artifact().is_empty());
    for slot in 0..4 {
        for root in [false, true] {
            for delta in 0..4 {
                assert!(
                    Fixture::new(&program, slot, root, delta).accepts(&program),
                    "slot{slot} root{root} delta{delta}"
                );
            }
        }
    }
    assert!(Fixture::padding().accepts(&program));
}

#[test]
fn canonical_load_fixture_owns_one_atomic_destination_and_keeps_r0_memory_reads() {
    for destination in [0, 2, 3] {
        let program = Program::new(contract(
            &[enc::encode_load(wide::memory::LOAD64, destination, 2, 0)],
            1_000,
            ivm::ivm_mode::ZK,
        ))
        .unwrap();
        let fixture = Fixture::new(&program, 0, false, 0);
        assert!(fixture.accepts(&program));
        assert_eq!(fixture.packets.fields[MEMORY_BASE][ENABLED], F::ONE);
        let output = &fixture.packets.fields[SCALAR_DESTINATION];
        assert_eq!(output[ENABLED], F(u64::from(destination != 0)));
        if destination == 0 {
            assert!(output.iter().all(|field| *field == F::ZERO));
        } else {
            assert_eq!(output[INDEX], F(destination as u64));
            assert_eq!(output[WRITE], F::ONE);
            assert_eq!(output[AFTER_TAG], F::ZERO);
            if destination == 2 {
                assert_eq!(
                    &output[BEFORE..BEFORE + 4],
                    &fixture.packets.fields[MEMORY_BASE][BEFORE..BEFORE + 4]
                );
            }
        }
    }
}

#[test]
fn every_original_packet_field_mutation_and_activity_substitution_rejects() {
    let program = program();
    for fixture in (0..4)
        .map(|slot| Fixture::new(&program, slot, false, 3))
        .chain([Fixture::new(&program, 3, true, 0), Fixture::padding()])
    {
        for slot in 0..PORTS {
            for field in 0..packet::WIDTH {
                let mut bad = fixture.clone();
                bad.packets.fields[slot][field] = bad.packets.fields[slot][field].add(F::ONE);
                // A prior link-register value/tag and STORE value are original
                // history inputs, not constants selected by the instruction.
                let free = slot == LINK_WRITE
                    && (fixture.row[FETCH] == F::ONE || fixture.row[FETCH + 1] == F::ONE)
                    && ((packet::BEFORE..packet::BEFORE + 4).contains(&field)
                        || field == packet::BEFORE_TAG);
                if !free {
                    assert!(!bad.accepts(&program), "slot{slot} field{field}");
                }
            }
        }
    }
}

#[test]
fn unsupported_fetch_words_wrong_encoding_and_wrong_code_identity_reject() {
    let program = program();
    let original = Fixture::new(&program, 0, false, 0);
    for w in [
        enc::encode_jump(wide::control::JAL, 2, 2),
        enc::encode_ri(wide::control::JALR, 1, 1, 0),
        enc::encode_ri(wide::control::JALR, 0, 2, 0),
        enc::encode_ri(wide::control::JALR, 0, 1, 1),
        enc::encode_rr(wide::crypto::VADD64, 2, 3, 1),
    ] {
        assert!(role(w).is_none());
    }
    assert!(role(enc::encode_rr(wide::arithmetic::SLL, 2, 3, 1)) == Some(Role::Scalar));
    assert!(role(enc::encode_jump(wide::control::JAL, 0, 2)) == Some(Role::Jump));
    assert!(role(enc::encode_offset24(wide::control::JMP, -2)) == Some(Role::Jump));
    assert!(matches!(
        role(enc::encode_rr(wide::arithmetic::DIV_CEIL, 2, 3, 1)),
        Some(Role::Scalar)
    ));
    assert!(matches!(
        role(enc::encode_rr(wide::arithmetic::GCD, 2, 3, 1)),
        Some(Role::Scalar)
    ));
    assert!(matches!(
        role(enc::encode_ri(wide::memory::LOAD64, 2, 3, 0)),
        Some(Role::Load)
    ));
    let changed = Program::new(contract(
        &[enc::encode_ri(wide::arithmetic::ADDI, 2, 3, 1)],
        1_000,
        ivm::ivm_mode::ZK,
    ))
    .unwrap();
    assert!(!original.accepts(&changed));
    assert!(
        Program::new(contract(
            &[
                enc::encode_jump(wide::control::JAL, 1, 4),
                enc::encode_offset24(wide::control::JALS, 3),
                enc::encode_store(wide::memory::STORE64, 2, 3, -8),
                enc::encode_ri(wide::control::JALR, 0, 1, 0),
            ],
            1_000,
            0
        ))
        .is_none()
    );
}

#[test]
fn gaspacing_cycles_private_base_and_protected_return_have_no_fault_bypass() {
    let program = program();
    for (slot, role_port, field) in [
        (2, MEMORY_BASE, packet::BEFORE_TAG),
        (3, RETURN_REGISTER, packet::BEFORE_TAG),
        (3, RETURN_PROTECTED_PC, packet::BEFORE),
        (0, CHILD_PARENT, packet::AFTER),
    ] {
        let mut bad = Fixture::new(&program, slot, false, 0);
        bad.packets.fields[role_port][field] = bad.packets.fields[role_port][field].add(F::ONE);
        assert!(!bad.accepts(&program));
    }
    for slot in 0..4 {
        let original = Fixture::new(&program, slot, false, 0);
        for bit in 0..WIDTH {
            let mut bad = original.clone();
            bad.row[bit] = bad.row[bit].add(F::ONE);
            assert!(!bad.accepts(&program), "slot{slot} row{bit}");
        }
    }
}

#[test]
fn unique_global_clocks_and_exact_original_history_ports_are_required() {
    let program = program();
    let fixture = Fixture::new(&program, 0, false, 0);
    let mut clocks = fixture.schedule.clocks;
    clocks[9] = clocks[8];
    assert!(Schedule::new(7, clocks).is_none());
    clocks[9] -= 1;
    assert!(Schedule::new(7, clocks).is_none());
    assert!(fixture.packets.producer(PORTS).is_none());
    for slot in 0..PORTS {
        assert!(core::ptr::eq(
            fixture.packets.producer(slot).unwrap(),
            &fixture.packets.fields[slot]
        ));
    }
}

#[test]
fn private_dispatch_polynomials_remain_degree_two_over_original_columns() {
    use crate::execution_proofs::stark::proof_managed_note_stark::degree_audit::measured_maximum_affine_degree_v1;
    let program = program();
    let schedule = Schedule::new(7, core::array::from_fn(|i| i as u32)).unwrap();
    let measured = measured_maximum_affine_degree_v1(
        [0x9a; 32],
        [WIDTH + PORTS * packet::WIDTH, 0, 0, 0, 0],
        8,
        2,
        |row, _, _, _, _| {
            let original = OriginalPackets::candidate(core::array::from_fn(|slot| {
                row[WIDTH + slot * packet::WIDTH..WIDTH + (slot + 1) * packet::WIDTH]
                    .try_into()
                    .unwrap()
            }));
            let mut out = Vec::new();
            append_control_residues(
                &mut out,
                &program,
                schedule,
                row[..WIDTH].try_into().unwrap(),
                &original,
            );
            Ok::<_, core::convert::Infallible>(out)
        },
    );
    assert_eq!(measured, 2);
}

#[test]
fn every_owned_producer_is_joined_to_the_same_private_history_window() {
    use super::super::{
        E, NOTE_COPY_WIDTH_V1, ORDERED, PublicPacketBus, ROW_WIDTH, SORTED, permutation,
        private_history,
    };
    fn history_accepts(original: &OriginalPackets, after: u64, depth: Option<u64>) -> bool {
        let mut events = vec![None; PORTS];
        events[RUNNING_WRITE] = Some(Event {
            space: Space::Owner,
            vm: 7,
            generation: 0,
            index: RUNNING_OWNER,
            write: true,
            before: bytes(0),
            after: bytes(after),
            before_private: 0,
            after_private: 0,
        });
        if let Some(depth) = depth {
            events[CALL_DEPTH] = Some(Event {
                space: Space::Owner,
                vm: 7,
                generation: 0,
                index: CALL_DEPTH_OWNER,
                write: true,
                before: bytes(0),
                after: bytes(depth),
                before_private: 0,
                after_private: 0,
            });
        }
        let bus = PublicPacketBus::new(events).unwrap();
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
        let count = PORTS * super::super::PHASES;
        let rows = (0..=count)
            .map(|index| {
                core::array::from_fn::<_, ROW_WIDTH, _>(|column| {
                    columns[NOTE_COPY_WIDTH_V1 + column][index]
                })
            })
            .collect::<Vec<_>>();
        let aux_rows = (0..=count)
            .map(|index| aux.iter().map(|column| column[index]).collect::<Vec<_>>())
            .collect::<Vec<_>>();
        let schedule = private_history::Schedule::new(bus.trace_log2, 1).unwrap();
        let fixed = (0..count)
            .map(|index| schedule.fixed(index).unwrap())
            .collect::<Vec<_>>();
        let windows = core::array::from_fn(|index| HistoryRow {
            current: &rows[index],
            next: &rows[index + 1],
            aux: &aux_rows[index],
            next_aux: &aux_rows[index + 1],
            fixed: &fixed[index],
        });
        let mut out = Vec::new();
        original.append_history_residues(&mut out, &windows, &challenges);
        out.into_iter().all(|r| r == F::ZERO)
    }
    let mut fields = [[F::ZERO; packet::WIDTH]; PORTS];
    fields[RUNNING_WRITE] = event(
        Space::Owner,
        0,
        RUNNING_OWNER,
        0,
        0,
        true,
        RUNNING_WRITE as u32,
        false,
        false,
    );
    let original = OriginalPackets::candidate(fields);
    assert!(history_accepts(&original, 0, None));
    // Both separately sorted histories are well-typed zero-first writes; only
    // the complete original source join rejects this coherent substitution.
    assert!(!history_accepts(&original, 1, None));
    fields[RUNNING_WRITE][packet::AFTER] = F::ONE;
    assert!(history_accepts(
        &OriginalPackets::candidate(fields),
        1,
        None
    ));
    fields[CALL_DEPTH] = event(
        Space::Owner,
        0,
        CALL_DEPTH_OWNER,
        0,
        1,
        true,
        CALL_DEPTH as u32,
        false,
        false,
    );
    let with_depth = OriginalPackets::candidate(fields);
    assert!(history_accepts(&with_depth, 1, Some(1)));
    // Both depth histories satisfy their local zero-first range/write relation;
    // only the exact original tuple join rejects the substituted depth.
    assert!(!history_accepts(&with_depth, 1, Some(2)));
    assert!(!history_accepts(&with_depth, 1, None));
}

#[test]
fn actual_artifact_admission_keeps_helper_roots_disjoint_and_rejects_shared_fallthrough() {
    let valid = program();
    let callable_roots: Vec<_> = valid
        .artifact()
        .contract_interface()
        .callables
        .iter()
        .map(|entry| entry.entry_pc)
        .collect();
    assert_eq!(callable_roots, [0, 16]);
    assert_eq!(wide::imm16(valid.words[0]), 4);
    assert_eq!(wide::imm24(valid.words[1]), 3);
    let shared = contract_artifact(
        &[
            enc::encode_jump(wide::control::JAL, 1, 2),
            enc::encode_offset24(wide::control::JALS, -1),
            enc::encode_store(wide::memory::STORE64, 2, 3, -8),
            enc::encode_ri(wide::control::JALR, 0, 1, 0),
        ],
        1_000,
        ivm::ivm_mode::ZK,
    );
    assert!(ivm::prepare_contract(shared).is_err());
}

#[test]
fn dispatcher_witness_tail_uses_its_own_width_and_constrains_both_alignment_bits() {
    let program = program();
    for delta in 0..4 {
        let fixture = Fixture::new(&program, 3, false, delta);
        assert_eq!(fixture.row.get(RETURN_DELTA..SCALAR).unwrap().len(), 2);
        assert!(RETURN_DELTA > packet::WIDTH);
        assert!(fixture.accepts(&program));
        for index in RETURN_DELTA..WIDTH {
            let mut invalid = fixture.clone();
            invalid.row[index] = F(2);
            assert!(!invalid.accepts(&program), "tail column {index}");
        }
    }
}

#[test]
fn protected_depth_matches_every_native_push_pop_and_store_boundary() {
    let program = program();
    assert_eq!(MAX_CONTRACT_CALL_DEPTH, 1024);
    for before in 0..=MAX_CONTRACT_CALL_DEPTH as u64 {
        for slot in [0, 1] {
            let mut call = Fixture::new(&program, slot, false, 0);
            call.set_depth(before, before + 1);
            assert_eq!(
                call.accepts(&program),
                before < MAX_CONTRACT_CALL_DEPTH as u64
            );
        }
        let mut store = Fixture::new(&program, 2, false, 0);
        store.set_depth(before, before);
        assert!(store.accepts(&program));
        let mut returning = Fixture::new(&program, 3, false, 0);
        returning.set_depth(before, before.wrapping_sub(1));
        assert_eq!(returning.accepts(&program), before != 0);
        let mut root_return = Fixture::new(&program, 3, true, 0);
        root_return.set_depth(before, before);
        assert_eq!(root_return.accepts(&program), before == 0);
    }
    assert!(Fixture::padding().accepts(&program));
}

#[test]
fn protected_depth_refuses_coherent_overflow_underflow_and_wrong_root_identity() {
    let program = program();
    for (slot, root, before, after) in [
        (0, false, 1024, 1025),
        (1, false, 1025, 1026),
        (2, false, 1025, 1025),
        (3, false, 1025, 1024),
        (3, false, 0, u64::MAX),
        (3, true, 1, 1),
        (0, false, u64::MAX, 0),
        (0, false, 7, 7),
        (3, false, 7, 7),
        (2, false, 7, 8),
    ] {
        let mut invalid = Fixture::new(&program, slot, root, 0);
        invalid.set_depth(before, after);
        assert!(
            !invalid.accepts(&program),
            "slot={slot} root={root} {before}->{after}"
        );
    }
    for fixture in [Fixture::new(&program, 0, false, 0), Fixture::padding()] {
        for index in DEPTH_BITS..RETURN_DELTA {
            let mut invalid = fixture.clone();
            invalid.row[index] = F(2);
            assert!(!invalid.accepts(&program));
        }
    }
}

/// Original dispatch columns for the artifact-owned callable composition tests.
pub(in crate::execution_proofs::ivm_step_air::machine_bus) fn callable_lookup_witness(
    program: &Program,
    slot: Option<usize>,
    root: bool,
) -> ([F; WIDTH], [[F; packet::WIDTH]; PORTS]) {
    let fixture = slot.map_or_else(Fixture::padding, |slot| {
        Fixture::new(program, slot, root, 0)
    });
    (fixture.row, fixture.packets.fields)
}

/// Admitted original image for callable-composition adversarial fixtures.
pub(in crate::execution_proofs::ivm_step_air::machine_bus) fn callable_lookup_contract(
    body: &[u32],
) -> PreparedContract {
    contract(body, 1_000, ivm::ivm_mode::ZK)
}
