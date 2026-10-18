//! Integer witness construction, direct mutation checks and actual native stores.
use super::*;
use crate::execution_proofs::stark::proof_managed_note_stark::degree_audit::measured_maximum_affine_degree_v1;
use ivm::{IVM, Memory, Perm, ProgramMetadata, VMError, encoding::wide as enc, ivm_mode};
use packet::{AFTER, AFTER_TAG, BEFORE, BEFORE_TAG, ENABLED, Event, Space};

const LOW: u64 = 0x0123_4567_89ab_cdef;
const HIGH: u64 = 0xfedc_ba98_7654_3210;
const OLD: [u8; 16] = [0xa5; 16];

fn bytes(low: u64) -> [u8; 16] {
    let mut out = [0; 16];
    out[..8].copy_from_slice(&low.to_le_bytes());
    out
}
fn phase(word: u32, address: u64, outcome: MemoryOutcome) -> StorePhase {
    StorePhase::from_fixed_input(
        word,
        address,
        7,
        [10, 11, 12, 13],
        100,
        0,
        0,
        Memory::STACK_START + Memory::MIN_STACK_SIZE,
        0,
        true,
        true,
        false,
        outcome,
    )
    .unwrap()
}
fn scalar(address: u64, source: u8) -> StorePhase {
    phase(
        enc::encode_store(wide::memory::STORE64, 3, source, 0),
        address,
        MemoryOutcome::Ready,
    )
}
fn vector(address: u64, low: u8, high: u8) -> StorePhase {
    phase(
        enc::encode_store128(wide::memory::STORE128, 3, low, high),
        address,
        MemoryOutcome::Ready,
    )
}
fn registers(p: StorePhase) -> [u64; 256] {
    let mut values = [0; 256];
    values[1] = LOW;
    values[2] = HIGH;
    values[3] = p.base_value;
    values
}

#[derive(Clone)]
struct Fixture {
    phase: StorePhase,
    row: [F; WIDTH],
    reads: [[F; packet::WIDTH]; 3],
    memory: [F; packet::WIDTH],
    log: [F; WRITE_LOG_WIDTH],
    control: [F; CONTROL_WIDTH],
}
impl Fixture {
    // The Boolean/integer oracle is independent of the polynomial equations.
    fn new(p: StorePhase, mask: u16, values: [u64; 256], tags: [bool; 256]) -> Self {
        Self::with_memory(p, mask, values, tags, OLD)
    }
    fn with_memory(
        p: StorePhase,
        mask: u16,
        values: [u64; 256],
        tags: [bool; 256],
        before: [u8; 16],
    ) -> Self {
        let mut reads = [[F::ZERO; packet::WIDTH]; 3];
        for slot in 0..if p.wide { 3 } else { 2 } {
            let index = p.registers[slot];
            reads[slot] = Event {
                space: Space::Register,
                vm: p.vm,
                generation: 0,
                index: index as u32,
                write: false,
                before: bytes(values[index]),
                after: bytes(values[index]),
                before_private: u16::from(tags[index]),
                after_private: u16::from(tags[index]),
            }
            .fields(p.clocks[slot] as usize);
        }
        let low = tags[p.registers[1]];
        let high = tags[p.registers[2]];
        let private_error = (p.wide && low != high) || (low && !p.stack);
        let committed = !private_error && p.outcome == MemoryOutcome::Ready;
        let row = witness(mask, committed);
        let mut memory = [F::ZERO; packet::WIDTH];
        let mut log = [F::ZERO; WRITE_LOG_WIDTH];
        if committed {
            let start = if p.wide { 0 } else { (p.address & 8) as usize };
            let length = if p.wide { 16 } else { 8 };
            let mut payload = [0; 16];
            payload[..8].copy_from_slice(&values[p.registers[1]].to_le_bytes());
            if p.wide {
                payload[8..].copy_from_slice(&values[p.registers[2]].to_le_bytes());
            }
            let mut after = before;
            after[start..start + length].copy_from_slice(&payload[..length]);
            let selected = (((1_u32 << length) - 1) << start) as u16;
            let after_mask = (mask & !selected) | if low { selected } else { 0 };
            memory = Event {
                space: Space::Memory,
                vm: p.vm,
                generation: 0,
                index: (p.address >> 4) as u32,
                write: true,
                before,
                after,
                before_private: mask,
                after_private: after_mask,
            }
            .fields(p.clocks[3] as usize);
            log[..4].copy_from_slice(&[
                F(p.address & 0xffff_ffff),
                F(p.address >> 32),
                F(length as u64),
                F::ONE,
            ]);
            for (i, pair) in payload.chunks_exact(2).enumerate() {
                log[4 + i] = F(u64::from(u16::from_le_bytes([pair[0], pair[1]])));
            }
        }
        let mut control = [F::ZERO; CONTROL_WIDTH];
        for (offset, value) in [
            (0, p.gas_after),
            (2, p.pc.wrapping_add(if committed { 4 } else { 0 })),
            (4, p.cycles + u64::from(committed)),
            (
                6,
                if committed {
                    p.output_after
                } else {
                    p.output_before
                },
            ),
        ] {
            control[offset] = F(value & 0xffff_ffff);
            control[offset + 1] = F(value >> 32);
        }
        control[COMMIT] = F(u64::from(committed));
        control[PRIVACY_TRAP] = F(u64::from(private_error));
        control[ACCESS_TRAP] = F(u64::from(
            !private_error && p.outcome == MemoryOutcome::AccessRefused,
        ));
        control[LOCAL_DEFER] = F(u64::from(
            !private_error && p.outcome == MemoryOutcome::AllocationDeferred,
        ));
        Self {
            phase: p,
            row,
            reads,
            memory,
            log,
            control,
        }
    }
    fn residues(&self) -> Vec<F> {
        let mut out = Vec::new();
        append_residues(
            &mut out,
            self.phase,
            &self.row,
            [&self.reads[0], &self.reads[1], &self.reads[2]],
            &self.memory,
            &self.log,
            &self.control,
        );
        assert_eq!(out.len(), CONSTRAINTS);
        out
    }
    fn accepts(&self) -> bool {
        self.residues().into_iter().all(|v| v == F::ZERO)
    }
}

#[test]
fn store_truth_tables_preserve_half_masks_and_all_typed_effects() {
    for address in [Memory::HEAP_START, Memory::STACK_START] {
        for p in [
            scalar(address, 1),
            scalar(address + 8, 1),
            vector(address, 1, 2),
        ] {
            for outcome in [
                MemoryOutcome::Ready,
                MemoryOutcome::AccessRefused,
                MemoryOutcome::AllocationDeferred,
            ] {
                let p = StorePhase { outcome, ..p };
                for tag_bits in 0..4 {
                    let mut tags = [false; 256];
                    tags[1] = tag_bits & 1 != 0;
                    tags[2] = tag_bits & 2 != 0;
                    for mask in [0, 1, 0xff, 0xff00, 0xaaaa, 0xffff] {
                        let f = Fixture::new(p, mask, registers(p), tags);
                        assert!(f.accepts());
                        assert_eq!(
                            f.control[COMMIT]
                                .add(f.control[PRIVACY_TRAP])
                                .add(f.control[ACCESS_TRAP])
                                .add(f.control[LOCAL_DEFER]),
                            F::ONE
                        );
                        if f.control[COMMIT] == F::ZERO {
                            assert_eq!(f.memory, [F::ZERO; packet::WIDTH]);
                            assert_eq!(f.log, [F::ZERO; WRITE_LOG_WIDTH]);
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn every_store_mask_effect_log_control_and_read_tuple_mutation_is_rejected() {
    for p in [
        scalar(Memory::STACK_START, 1),
        scalar(Memory::STACK_START + 8, 1),
        vector(Memory::STACK_START, 1, 2),
    ] {
        for private in [false, true] {
            let mut tags = [false; 256];
            tags[1] = private;
            tags[2] = private;
            let f = Fixture::new(p, 0xa55a, registers(p), tags);
            assert!(f.accepts());
            for i in 0..WIDTH {
                let mut m = f.clone();
                m.row[i] = m.row[i].add(F::ONE);
                assert!(!m.accepts(), "mask {i}");
            }
            for i in 0..packet::WIDTH {
                let mut m = f.clone();
                m.memory[i] = m.memory[i].add(F::ONE);
                let replaced_old_limb = (BEFORE..BEFORE + 8).contains(&i)
                    && p.selected_bits().contains(&((i - BEFORE) * 2));
                // Overwritten prior bytes are linked by typed bus history, not
                // by the store arithmetic. Never claim that missing authority.
                assert_eq!(m.accepts(), replaced_old_limb, "memory {i}");
            }
            for i in 0..WRITE_LOG_WIDTH {
                let mut m = f.clone();
                m.log[i] = m.log[i].add(F::ONE);
                assert!(!m.accepts(), "log {i}");
            }
            for i in 0..CONTROL_WIDTH {
                let mut m = f.clone();
                m.control[i] = m.control[i].add(F::ONE);
                assert!(!m.accepts(), "control {i}");
            }
            for slot in 0..3 {
                for i in 0..packet::WIDTH {
                    let mut m = f.clone();
                    m.reads[slot][i] = m.reads[slot][i].add(F::ONE);
                    assert!(!m.accepts(), "read {slot}/{i}");
                }
            }
        }
    }
}

#[test]
fn rejected_stores_cannot_erase_operand_reads_or_commit_memory_register_pc_cycles() {
    for outcome in [
        MemoryOutcome::Ready,
        MemoryOutcome::AccessRefused,
        MemoryOutcome::AllocationDeferred,
    ] {
        for mixed in [false, true] {
            let mut p = vector(Memory::HEAP_START, 1, 2);
            p.outcome = outcome;
            let mut tags = [false; 256];
            tags[1] = true;
            tags[2] = !mixed;
            let f = Fixture::new(p, 0xffff, registers(p), tags);
            assert!(f.accepts());
            assert_eq!(f.control[PRIVACY_TRAP], F::ONE);
            assert_eq!(f.control[ACCESS_TRAP], F::ZERO);
            assert_eq!(f.control[LOCAL_DEFER], F::ZERO);
            for slot in 0..3 {
                let mut m = f.clone();
                m.reads[slot] = [F::ZERO; packet::WIDTH];
                assert!(!m.accepts());
            }
            for i in 0..packet::WIDTH {
                let mut m = f.clone();
                m.memory[i] = F::ONE;
                assert!(!m.accepts());
            }
            for i in [2, 4, 6, COMMIT, ACCESS_TRAP, LOCAL_DEFER] {
                let mut m = f.clone();
                m.control[i] = m.control[i].add(F::ONE);
                assert!(!m.accepts());
            }
            let mut m = f.clone();
            m.reads[1][packet::WRITE] = F::ONE;
            assert!(!m.accepts());
        }
    }
}

#[test]
fn source_aliases_r0_signed_immediates_and_fixed_boundary_cannot_be_substituted() {
    for low in 0..4 {
        for high in 0..4 {
            let p = vector(Memory::HEAP_START, low, high);
            let f = Fixture::new(p, 0, registers(p), [false; 256]);
            assert!(f.accepts());
            if low == high {
                let mut m = f.clone();
                m.reads[2][BEFORE] = m.reads[2][BEFORE].add(F::ONE);
                m.reads[2][AFTER] = m.reads[2][BEFORE];
                assert!(!m.accepts());
            }
        }
    }
    // Preserve the forged source's read-preservation tuple AND every derived
    // write/log byte. Only equality to the earlier same-register read may fail.
    let p = vector(Memory::HEAP_START, 1, 1);
    let original = Fixture::new(p, 0, registers(p), [false; 256]);
    assert!(original.accepts());
    let mut changed = original;
    changed.reads[2][BEFORE] = changed.reads[2][BEFORE].add(F::ONE);
    changed.reads[2][AFTER] = changed.reads[2][BEFORE];
    changed.memory[AFTER + 4] = changed.reads[2][BEFORE];
    changed.log[8] = changed.reads[2][BEFORE];
    let failed = changed
        .residues()
        .iter()
        .enumerate()
        .filter_map(|(index, value)| (*value != F::ZERO).then_some(index))
        .collect::<Vec<_>>();
    // Three read-port blocks and the five fixed-base equations precede the
    // three nine-field alias links. This is limb0 of the third (low/high) link.
    let alias_start = 3 * (8 + 26 + 4 + 9 + 1 + 9) + 5;
    assert_eq!(failed, [alias_start + 2 * 9]);
    assert!(!changed.accepts());
    for immediate in i8::MIN..=i8::MAX {
        let word = enc::encode_store(wide::memory::STORE64, 3, 1, immediate);
        let p = phase(word, Memory::HEAP_START, MemoryOutcome::Ready);
        assert_eq!(
            p.base_value
                .wrapping_add(i64::cast_unsigned(i64::from(immediate))),
            p.address
        );
        let f = Fixture::new(p, 0, registers(p), [false; 256]);
        assert!(f.accepts());
        let mut m = f;
        m.reads[0][BEFORE] = m.reads[0][BEFORE].add(F::ONE);
        m.reads[0][AFTER] = m.reads[0][BEFORE];
        assert!(!m.accepts());
    }
    let word = enc::encode_store128(wide::memory::STORE128, 3, 1, 2);
    let make = |address, gas, cycles, zk, vector, private, clocks, cursor| {
        StorePhase::from_fixed_input(
            word,
            address,
            7,
            clocks,
            gas,
            0,
            cycles,
            Memory::STACK_START + Memory::MIN_STACK_SIZE,
            cursor,
            zk,
            vector,
            private,
            MemoryOutcome::Ready,
        )
    };
    for (a, g, c, z, v, p, t, o) in [
        (
            Memory::HEAP_START + 1,
            100,
            0,
            true,
            true,
            false,
            [1, 2, 3, 4],
            0,
        ),
        (Memory::HEAP_START, 4, 0, true, true, false, [1, 2, 3, 4], 0),
        (
            Memory::HEAP_START,
            100,
            u64::MAX,
            true,
            true,
            false,
            [1, 2, 3, 4],
            0,
        ),
        (
            Memory::HEAP_START,
            100,
            0,
            false,
            true,
            false,
            [1, 2, 3, 4],
            0,
        ),
        (
            Memory::HEAP_START,
            100,
            0,
            true,
            false,
            false,
            [1, 2, 3, 4],
            0,
        ),
        (
            Memory::HEAP_START,
            100,
            0,
            true,
            true,
            true,
            [1, 2, 3, 4],
            0,
        ),
        (
            Memory::HEAP_START,
            100,
            0,
            true,
            true,
            false,
            [1, 2, 2, 4],
            0,
        ),
        (1 << 36, 100, 0, true, true, false, [1, 2, 3, 4], 0),
        (
            Memory::OUTPUT_START,
            100,
            0,
            true,
            true,
            false,
            [1, 2, 3, 4],
            16,
        ),
        (
            Memory::HEAP_START,
            100,
            0,
            true,
            true,
            false,
            [1, 2, 3, 4],
            Memory::OUTPUT_SIZE + 1,
        ),
    ] {
        assert!(make(a, g, c, z, v, p, t, o).is_none());
    }
}

fn native(words: &[u32], gas: u64, mode: u8) -> IVM {
    let mut program = ProgramMetadata {
        mode,
        max_cycles: 2,
        ..ProgramMetadata::default()
    }
    .encode();
    for word in words {
        program.extend_from_slice(&word.to_le_bytes());
    }
    let mut vm = IVM::new(gas);
    vm.load_program(&program).unwrap();
    vm.set_zk_trace_enabled(true);
    vm
}
fn assert_native_reads(vm: &IVM, fixture: &Fixture) {
    let budget = iroha_allocation::AllocationBudget::new(64 * 1024 * 1024);
    let snapshot = vm.try_diagnostic_snapshot(&budget).unwrap();
    let actual = snapshot
        .register_events()
        .map(|e| (e.written, e.index, e.value, e.tag))
        .collect::<Vec<_>>();
    let expected = fixture
        .reads
        .iter()
        .filter(|p| p[ENABLED] == F::ONE)
        .map(|p| {
            (
                false,
                p[packet::INDEX].0 as usize,
                packet::half(p, BEFORE, 0),
                p[BEFORE_TAG] == F::ONE,
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        actual, expected,
        "complete ordered RegEvent sequence, including r0 and aliases"
    );
}
fn assert_native_write(vm: &IVM, f: &Fixture) {
    let log = vm.memory.try_write_log_snapshot().unwrap();
    if f.control[COMMIT] == F::ONE {
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].address(), f.phase.address);
        let payload: Vec<u8> = f.log[4..]
            .iter()
            .flat_map(|v| (v.0 as u16).to_le_bytes())
            .collect();
        assert_eq!(
            log[0].bytes(),
            &payload[..if f.phase.wide { 16 } else { 8 }]
        );
    } else {
        assert!(log.is_empty());
    }
    assert!(
        !vm.memory
            .try_read_log_snapshot()
            .unwrap()
            .iter()
            .any(|r| r.addr == f.phase.address && r.len == if f.phase.wide { 16 } else { 8 })
    );
}

#[test]
fn native_stores_match_ordered_alias_reads_exact_write_bytes_and_unchanged_registers() {
    for low in 0..4_u8 {
        for high in 0..4_u8 {
            let word = enc::encode_store128(wide::memory::STORE128, 3, low, high);
            let p = vector(Memory::HEAP_START + 0x80, low, high);
            let values = registers(p);
            let f = Fixture::new(p, 0, values, [false; 256]);
            assert!(f.accepts());
            let mut vm = native(
                &[word, enc::encode_halt()],
                100,
                ivm_mode::ZK | ivm_mode::VECTOR,
            );
            vm.memory.store_bytes(p.address, &OLD).unwrap();
            for i in 0..4 {
                vm.set_register(i, values[i]);
            }
            let registers_before: [(u64, bool); 256] =
                std::array::from_fn(|i| (vm.registers.get(i), vm.registers.tag(i)));
            assert_eq!(registers_before[31], (vm.memory.stack_top(), false));
            vm.memory.clear_tracking();
            vm.run().unwrap();
            assert_native_reads(&vm, &f);
            assert_native_write(&vm, &f);
            for (i, (value, tag)) in registers_before.into_iter().enumerate() {
                assert_eq!(vm.registers.get(i), value, "unchanged register r{i}");
                assert_eq!(vm.registers.tag(i), tag, "unchanged register tag r{i}");
            }
            assert_eq!(
                vm.memory.load_u128(p.address).unwrap(),
                u128::from(values[low as usize]) | (u128::from(values[high as usize]) << 64)
            );
            assert_eq!(
                (vm.gas_remaining, vm.pc(), vm.get_cycle_count()),
                (95, 8, 2)
            );
        }
    }
    for half in [0_i8, 8] {
        for source in [0_u8, 1, 3] {
            let address = Memory::HEAP_START + 0x80;
            let word = enc::encode_store(wide::memory::STORE64, 3, source, half);
            let p = phase(word, address + half as u64, MemoryOutcome::Ready);
            let values = registers(p);
            let f = Fixture::new(p, 0, values, [false; 256]);
            assert!(f.accepts());
            let mut vm = native(&[word, enc::encode_halt()], 100, ivm_mode::ZK);
            vm.memory.store_bytes(address, &OLD).unwrap();
            for i in 0..4 {
                vm.set_register(i, values[i]);
            }
            vm.memory.clear_tracking();
            vm.run().unwrap();
            assert_native_reads(&vm, &f);
            assert_native_write(&vm, &f);
            let expected: Vec<u8> = f.memory[AFTER..AFTER + 8]
                .iter()
                .flat_map(|v| (v.0 as u16).to_le_bytes())
                .collect();
            assert_eq!(
                vm.memory
                    .load_u128(address)
                    .unwrap()
                    .to_le_bytes()
                    .as_slice(),
                expected.as_slice()
            );
            assert_eq!(
                (vm.gas_remaining, vm.pc(), vm.get_cycle_count()),
                (97, 8, 2)
            );
        }
    }
}

#[test]
fn native_late_privacy_and_permission_failures_keep_reads_but_no_store_effects() {
    for address in [Memory::STACK_START, Memory::HEAP_START] {
        for tag_bits in 0..4 {
            let p = vector(address, 1, 2);
            let word = enc::encode_store128(wide::memory::STORE128, 3, 1, 2);
            let mut tags = [false; 256];
            tags[1] = tag_bits & 1 != 0;
            tags[2] = tag_bits & 2 != 0;
            let values = registers(p);
            let f = Fixture::new(p, 0, values, tags);
            assert!(f.accepts());
            let mut vm = native(
                &[word, enc::encode_halt()],
                100,
                ivm_mode::ZK | ivm_mode::VECTOR,
            );
            vm.memory.store_bytes(address, &OLD).unwrap();
            for i in 0..4 {
                vm.set_register(i, values[i]);
                vm.registers.set_tag(i, tags[i]);
            }
            let registers_before: [(u64, bool); 256] =
                std::array::from_fn(|i| (vm.registers.get(i), vm.registers.tag(i)));
            assert_eq!(registers_before[31], (vm.memory.stack_top(), false));
            vm.memory.clear_tracking();
            let result = vm.run();
            let ok = f.control[COMMIT] == F::ONE;
            assert!(matches!(
                (ok, result),
                (true, Ok(())) | (false, Err(VMError::PrivacyViolation))
            ));
            assert_native_reads(&vm, &f);
            assert_native_write(&vm, &f);
            assert_eq!(
                (vm.gas_remaining, vm.pc(), vm.get_cycle_count()),
                (95, if ok { 8 } else { 0 }, if ok { 2 } else { 0 })
            );
            for (i, (value, tag)) in registers_before.into_iter().enumerate() {
                assert_eq!(vm.registers.get(i), value, "unchanged register r{i}");
                assert_eq!(vm.registers.tag(i), tag, "unchanged register tag r{i}");
            }
            if !ok {
                assert_eq!(vm.memory.load_u128(address).unwrap().to_le_bytes(), OLD);
            }
        }
    }
    let word = enc::encode_store(wide::memory::STORE64, 3, 1, 1);
    let p = phase(word, 0, MemoryOutcome::AccessRefused);
    assert_eq!(p.base_value, u64::MAX);
    let values = registers(p);
    let f = Fixture::new(p, 0, values, [false; 256]);
    assert!(f.accepts());
    let mut vm = native(&[word, enc::encode_halt()], 100, ivm_mode::ZK);
    let code_before = vm.memory.load_u64(0).unwrap();
    for i in 0..4 {
        vm.set_register(i, values[i]);
    }
    vm.memory.clear_tracking();
    assert!(match (
        &(vm.run()),
        &(VMError::MemoryAccessViolation {
            addr: 0,
            perm: Perm::WRITE
        })
    ) {
        (
            Err(VMError::MemoryAccessViolation {
                addr: actual_field_0,
                perm: actual_field_1,
            }),
            VMError::MemoryAccessViolation {
                addr: expected_field_0,
                perm: expected_field_1,
            },
        ) => actual_field_0 == expected_field_0 && actual_field_1 == expected_field_1,
        _ => false,
    });
    assert_native_reads(&vm, &f);
    assert!(vm.memory.try_write_log_snapshot().unwrap().is_empty());
    assert_eq!(vm.memory.load_u64(0).unwrap(), code_before);
    assert_eq!(
        (vm.gas_remaining, vm.pc(), vm.get_cycle_count()),
        (97, 0, 0)
    );
}

#[test]
fn native_public_half_overwrite_clears_only_selected_private_bytes_and_output_rewind_is_atomic() {
    for half in [0_i8, 8] {
        let words = [
            enc::encode_store128(wide::memory::STORE128, 3, 1, 2),
            enc::encode_halt(),
            enc::encode_store(wide::memory::STORE64, 3, 4, half),
            enc::encode_halt(),
            enc::encode_load(wide::memory::LOAD64, 5, 3, 0),
            enc::encode_halt(),
            enc::encode_load(wide::memory::LOAD64, 6, 3, 8),
            enc::encode_halt(),
        ];
        let mut vm = native(&words, 1000, ivm_mode::ZK | ivm_mode::VECTOR);
        vm.set_register(1, LOW);
        vm.set_register(2, HIGH);
        vm.set_register(3, Memory::STACK_START);
        vm.set_register(4, 7);
        vm.registers.set_tag(1, true);
        vm.registers.set_tag(2, true);
        vm.run().unwrap();
        let mut p = phase(
            words[2],
            Memory::STACK_START + half as u64,
            MemoryOutcome::Ready,
        );
        p.pc = 8;
        p.cycles = 0;
        p.gas_after = vm.gas_remaining - 3;
        let values = core::array::from_fn(|i| vm.registers.get(i));
        let tags = core::array::from_fn(|i| vm.registers.tag(i));
        let old_bytes = vm
            .memory
            .load_u128(Memory::STACK_START)
            .unwrap()
            .to_le_bytes();
        let f = Fixture::with_memory(p, u16::MAX, values, tags, old_bytes);
        assert!(f.accepts());
        let expected_mask = if half == 0 { 0xff00 } else { 0xff };
        assert_eq!(f.memory[AFTER_TAG], F(expected_mask));
        vm.set_program_counter(8).unwrap();
        vm.memory.clear_tracking();
        vm.run().unwrap();
        assert_native_reads(&vm, &f);
        assert_native_write(&vm, &f);
        vm.set_program_counter(16).unwrap();
        vm.run().unwrap();
        vm.set_program_counter(24).unwrap();
        vm.run().unwrap();
        assert_eq!(vm.registers.get(5), if half == 0 { 7 } else { LOW });
        assert_eq!(vm.registers.get(6), if half == 8 { 7 } else { HIGH });
        assert_eq!(vm.registers.tag(5), half != 0);
        assert_eq!(vm.registers.tag(6), half != 8);
    }
    let word = enc::encode_store(wide::memory::STORE64, 3, 1, 0);
    let mut vm = native(
        &[word, enc::encode_halt(), word, enc::encode_halt()],
        100,
        ivm_mode::ZK,
    );
    vm.set_register(1, LOW);
    vm.set_register(3, Memory::OUTPUT_START + 16);
    let forward = phase(word, Memory::OUTPUT_START + 16, MemoryOutcome::Ready);
    let forward_fixture = Fixture::with_memory(
        forward,
        0,
        core::array::from_fn(|i| vm.registers.get(i)),
        [false; 256],
        [0; 16],
    );
    assert!(forward_fixture.accepts());
    assert_eq!(forward_fixture.control[6], F(24));
    vm.memory.clear_tracking();
    vm.run().unwrap();
    assert_native_reads(&vm, &forward_fixture);
    assert_native_write(&vm, &forward_fixture);
    assert_eq!(vm.memory.output_used_len(), 24);
    assert_eq!(&vm.memory.read_output_used()[..16], &[0; 16]);
    let old = vm.memory.read_output_used().to_vec();
    vm.set_program_counter(8).unwrap();
    vm.set_register(3, Memory::OUTPUT_START + 8);
    let mut p = phase(word, Memory::OUTPUT_START + 8, MemoryOutcome::AccessRefused);
    p.output_before = 24;
    p.pc = 8;
    p.cycles = 0;
    p.gas_after = vm.gas_remaining - 3;
    let f = Fixture::new(
        p,
        0,
        core::array::from_fn(|i| vm.registers.get(i)),
        [false; 256],
    );
    assert!(f.accepts());
    vm.memory.clear_tracking();
    assert!(match (
        &(vm.run()),
        &(VMError::MemoryAccessViolation {
            addr: (Memory::OUTPUT_START + 8) as u32,
            perm: Perm::WRITE
        })
    ) {
        (
            Err(VMError::MemoryAccessViolation {
                addr: actual_field_0,
                perm: actual_field_1,
            }),
            VMError::MemoryAccessViolation {
                addr: expected_field_0,
                perm: expected_field_1,
            },
        ) => actual_field_0 == expected_field_0 && actual_field_1 == expected_field_1,
        _ => false,
    });
    assert_native_reads(&vm, &f);
    assert_native_write(&vm, &f);
    assert_eq!(vm.memory.read_output_used(), old.as_slice());
    assert_eq!(vm.memory.output_used_len(), 24);
    assert_eq!(
        (vm.gas_remaining, vm.pc(), vm.get_cycle_count()),
        (94, 8, 0)
    );
}

#[test]
fn store_bank_degree_and_geometry_are_explicit_without_complete_memory_admission() {
    assert_eq!(WIDTH, 16);
    let ports = 4 * packet::WIDTH + WRITE_LOG_WIDTH + CONTROL_WIDTH;
    for p in [
        vector(Memory::STACK_START, 1, 2),
        vector(Memory::HEAP_START, 1, 2),
    ] {
        assert_eq!(
            measured_maximum_affine_degree_v1(
                [u8::from(p.stack); 32],
                [WIDTH + ports, 0, 0, 0, 0],
                4,
                3,
                |row, _, _, _, _| {
                    let a = WIDTH;
                    let b = a + packet::WIDTH;
                    let c = b + packet::WIDTH;
                    let d = c + packet::WIDTH;
                    let e = d + packet::WIDTH;
                    let f = e + WRITE_LOG_WIDTH;
                    let mut out = Vec::new();
                    append_residues(
                        &mut out,
                        p,
                        row[..a].try_into().unwrap(),
                        [
                            row[a..b].try_into().unwrap(),
                            row[b..c].try_into().unwrap(),
                            row[c..d].try_into().unwrap(),
                        ],
                        row[d..e].try_into().unwrap(),
                        row[e..f].try_into().unwrap(),
                        row[f..].try_into().unwrap(),
                    );
                    Ok::<_, core::convert::Infallible>(out)
                }
            ),
            3
        );
    }
    assert_eq!(WIDTH * (136 * 2 * 8 + 2 * 32), 35_840);
    assert_eq!((WIDTH + ports) * (136 * 2 * 8 + 2 * 32), 322_560);
    assert!(
        (WIDTH + ports) * (136 * 2 * 8 + 2 * 32) > 41_152,
        "packet/log/control linkage is not free profile space"
    );
    // Two different fixed memory dispositions both admit their own exact
    // conditional outcomes. This is intentionally NOT proof of permission.
    let ready = scalar(Memory::HEAP_START, 1);
    let refused = StorePhase {
        outcome: MemoryOutcome::AccessRefused,
        ..ready
    };
    let a = Fixture::new(ready, 0, registers(ready), [false; 256]);
    let b = Fixture::new(refused, 0, registers(refused), [false; 256]);
    assert!(a.accepts() && b.accepts());
    assert_ne!(a.control, b.control);
    let mut mixed = a;
    mixed.phase = refused;
    assert!(!mixed.accepts());
}

#[test]
fn native_early_trap_priority_and_scalar_late_alignment_keep_exact_read_prefix() {
    let scalar = enc::encode_store(wide::memory::STORE64, 3, 1, 0);
    let vector = enc::encode_store128(wide::memory::STORE128, 3, 1, 2);
    let bad = Memory::HEAP_START + 1;
    for (word, vector_on, base_private, value_private, expected, reads, cost) in [
        (
            vector,
            false,
            true,
            true,
            VMError::VectorExtensionDisabled,
            0,
            5,
        ),
        (vector, true, true, true, VMError::PrivacyViolation, 0, 5),
        (
            vector,
            true,
            false,
            true,
            VMError::MisalignedAccess { addr: bad as u32 },
            1,
            5,
        ),
        (scalar, true, true, true, VMError::PrivacyViolation, 0, 3),
        (scalar, true, false, true, VMError::PrivacyViolation, 2, 3),
        (
            scalar,
            true,
            false,
            false,
            VMError::MisalignedAccess { addr: bad as u32 },
            2,
            3,
        ),
    ] {
        for out_of_gas in [false, true] {
            let gas = if out_of_gas { cost - 1 } else { 100 };
            let mut vm = native(
                &[word, enc::encode_halt()],
                gas,
                ivm_mode::ZK | if vector_on { ivm_mode::VECTOR } else { 0 },
            );
            vm.set_register(1, LOW);
            vm.set_register(2, HIGH);
            vm.set_register(3, bad);
            vm.registers.set_tag(1, value_private);
            vm.registers.set_tag(3, base_private);
            vm.memory.clear_tracking();
            let result = vm.run();
            if out_of_gas {
                assert!(matches!(result, Err(VMError::OutOfGas)));
            } else {
                assert!(match (result, &expected) {
                    (Err(VMError::VectorExtensionDisabled), VMError::VectorExtensionDisabled)
                    | (Err(VMError::PrivacyViolation), VMError::PrivacyViolation) => true,
                    (
                        Err(VMError::MisalignedAccess { addr: actual }),
                        VMError::MisalignedAccess { addr: expected },
                    ) => actual == *expected,
                    _ => false,
                });
            }
            let budget = iroha_allocation::AllocationBudget::new(64 * 1024 * 1024);
            let snapshot = vm.try_diagnostic_snapshot(&budget).unwrap();
            let actual = snapshot
                .register_events()
                .map(|e| (e.written, e.index, e.value, e.tag))
                .collect::<Vec<_>>();
            let prefix = [
                (false, 3, bad, base_private),
                (false, 1, LOW, value_private),
            ];
            assert_eq!(actual, prefix[..if out_of_gas { 0 } else { reads }]);
            assert_eq!((vm.pc(), vm.get_cycle_count()), (0, 0));
            assert_eq!(vm.gas_remaining, if out_of_gas { gas } else { gas - cost });
            assert!(vm.memory.try_write_log_snapshot().unwrap().is_empty());
            assert_eq!(vm.memory.output_used_len(), 0);
            assert_eq!(vm.memory.load_u128(Memory::HEAP_START).unwrap(), 0);
        }
    }
}
