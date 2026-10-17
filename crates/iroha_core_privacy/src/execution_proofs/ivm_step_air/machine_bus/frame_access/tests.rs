//! Exact owner/request joins, byte-level initialization, and access mutations.

use super::*;
use packet::{Event, Space};

fn field(value: bool) -> F {
    F(u64::from(value))
}
fn bits(target: &mut [F], value: u64) {
    for (i, target) in target.iter_mut().enumerate() {
        *target = F((value >> i) & 1);
    }
}
fn bytes(value: u64) -> [u8; 16] {
    let mut bytes = [0; 16];
    bytes[..8].copy_from_slice(&value.to_le_bytes());
    bytes
}
fn event(space: Space, generation: u16, index: u32, value: u64, slot: usize) -> [F; packet::WIDTH] {
    Event {
        space,
        vm: 7,
        generation,
        index,
        write: false,
        before: bytes(value),
        after: bytes(value),
        before_private: 0,
        after_private: 0,
    }
    .fields(slot)
}

#[derive(Clone)]
pub(in super::super) struct Fixture {
    pub(in super::super) schedule: Schedule,
    selected: F,
    address: [F; 4],
    pub(in super::super) ports: [[F; packet::WIDTH]; 12],
    pub(in super::super) row: [F; WIDTH],
}
impl Fixture {
    pub(in super::super) fn new(
        selected: bool,
        active: u16,
        address: u64,
        length: u8,
        write: bool,
        descriptors: [u64; 10],
        mask: u16,
    ) -> Self {
        let schedule = Schedule::new(7, length, write, core::array::from_fn(|i| i as u32)).unwrap();
        let address = if selected { address } else { 0 };
        let active = if selected { active } else { 0 };
        let live = active != 0;
        let descriptors = if live { descriptors } else { [0; 10] };
        let (end, overflow) = address.overflowing_add(u64::from(length));
        let contains =
            |start: usize| address >= descriptors[start] && end <= descriptors[start + 1];
        let stack = contains(0);
        let arguments = contains(2);
        let results = contains(4);
        let root_arg = address < descriptors[7] && descriptors[6] < end;
        let root_result = address < descriptors[9] && descriptors[8] < end;
        let below = address < ivm::Memory::STACK_START && end <= ivm::Memory::STACK_START;
        let init = live && !overflow && stack && !write;
        let mut ports = [[F::ZERO; packet::WIDTH]; 12];
        if selected {
            ports[0] = event(Space::Owner, 0, 0, u64::from(active), 0);
        }
        if live {
            for i in 0..10 {
                ports[i + 1] = event(
                    Space::Owner,
                    if i < 6 { active } else { 0 },
                    DESCRIPTOR_INDEXES[i],
                    descriptors[i],
                    i + 1,
                );
            }
        }
        if init {
            ports[11] = event(
                Space::Initialization,
                active,
                u32::try_from(address >> 4).unwrap(),
                u64::from(mask),
                11,
            );
        }
        let mut row = [F::ZERO; WIDTH];
        bits(&mut row[ADDRESS..END], address);
        bits(&mut row[END..CARRY], end);
        let mut carry = 0;
        for i in 0..64 {
            carry = (((address >> i) & 1) + ((u64::from(length) >> i) & 1) + carry) / 2;
            row[CARRY + i] = F(carry);
        }
        for (i, value) in descriptors.iter().copied().enumerate() {
            bits(&mut row[OWNERS + i * 64..OWNERS + (i + 1) * 64], value);
        }
        for i in 0..12 {
            let (left, right) = comparison_operands(&row, i);
            let bank =
                &mut row[COMPARISONS + i * COMPARE_WIDTH..COMPARISONS + (i + 1) * COMPARE_WIDTH];
            let mut borrow = 0_i64;
            for limb in 0..4 {
                let difference = u64::cast_signed(pack(&left[limb * 16..(limb + 1) * 16]).0)
                    - u64::cast_signed(pack(&right[limb * 16..(limb + 1) * 16]).0)
                    - borrow;
                borrow = i64::from(difference < 0);
                bits(
                    &mut bank[limb * 16..(limb + 1) * 16],
                    difference.rem_euclid(1 << 16) as u64,
                );
                bank[64 + limb] = F(i64::cast_unsigned(borrow));
            }
        }
        row[LIVE] = field(live);
        row[INVERSE] = F(u64::from(active)).inv().unwrap_or(F::ZERO);
        for (index, value) in [
            (STACK, stack),
            (ARGUMENTS, arguments),
            (RESULTS, results),
            (ROOT_ARG_OVERLAP, root_arg),
            (ROOT_RESULT_OVERLAP, root_result),
            (BELOW_STACK, below),
            (ORDINARY_NO_ARG, below && !root_arg),
            (ORDINARY, below && !root_arg && !root_result),
            (ARG_BRANCH, !stack && arguments),
            (RESULT_BASE, !stack && !arguments),
            (RESULT_BRANCH, !stack && !arguments && results),
            (FALLBACK, !stack && !arguments && !results),
            (INITIALIZED_ENABLED, init),
        ] {
            row[index] = field(value);
        }
        bits(
            &mut row[INITIALIZED..ALL_SET],
            u64::from(if init { mask } else { 0 }),
        );
        row[ALL_SET] = F::ONE;
        for byte in 0..16 {
            let selected_byte = length == 16 || (byte / 8 == ((address & 15) / 8) as usize);
            let present = !init || !selected_byte || mask & (1 << byte) != 0;
            row[ALL_SET + byte + 1] = row[ALL_SET + byte].mul(field(present));
        }
        let all_initialized = row[ALL_SET + 16] == F::ONE;
        row[STACK_GOOD] = field(stack && (write || all_initialized));
        // Native priority oracle uses branches, separately from the polynomial evaluator.
        let permission = if stack {
            write || all_initialized
        } else if arguments {
            !write
        } else if results {
            write
        } else {
            below && !root_arg && !root_result
        };
        row[ACTIVE_ALLOWED] = field(!overflow && permission);
        row[ALLOWED] = field(selected && (!live || (!overflow && permission)));
        row[RANGE_ERROR] = field(live && overflow);
        Self {
            schedule,
            selected: field(selected),
            address: core::array::from_fn(|i| F((address >> (16 * i)) & 0xffff)),
            ports,
            row,
        }
    }
    fn residues(&self) -> Vec<F> {
        let mut output = Vec::new();
        let decision = append_residues(
            &mut output,
            self.schedule,
            &self.row,
            Request {
                selected: self.selected,
                address: &self.address,
            },
            Ports {
                active: &self.ports[0],
                descriptors: core::array::from_fn(|i| &self.ports[i + 1]),
                initialized: &self.ports[11],
            },
        );
        assert_eq!(output.len(), CONSTRAINTS);
        assert_eq!(decision.permitted, self.row[ALLOWED]);
        assert_eq!(decision.range_error, self.row[RANGE_ERROR]);
        output
    }
    fn accepts(&self) -> bool {
        self.residues().into_iter().all(|x| x == F::ZERO)
    }
}

fn root() -> [u64; 10] {
    let stack = ivm::Memory::STACK_START;
    let heap = ivm::Memory::HEAP_START;
    [
        stack + 128,
        stack + 256,
        heap,
        heap + 16,
        heap + 128,
        heap + 144,
        heap,
        heap + 16,
        heap + 128,
        heap + 144,
    ]
}
fn child() -> [u64; 10] {
    let mut descriptors = root();
    let stack = ivm::Memory::STACK_START;
    descriptors[..6].copy_from_slice(&[
        stack,
        stack + 128,
        stack + 128,
        stack + 144,
        stack + 160,
        stack + 176,
    ]);
    descriptors
}

#[test]
fn private_top_frame_priority_matches_root_and_child_ownership() {
    let heap = ivm::Memory::HEAP_START;
    let stack = ivm::Memory::STACK_START;
    for (active, descriptor, address, write, expected) in [
        (1, root(), stack + 128, false, true),
        (1, root(), heap, false, true),
        (1, root(), heap, true, false),
        (1, root(), heap + 128, true, true),
        (1, root(), heap + 128, false, false),
        (1, root(), heap + 256, false, true),
        (1, root(), stack + 120, true, false),
        (2, child(), stack + 128, false, true),
        (2, child(), stack + 128, true, false),
        (2, child(), stack + 160, true, true),
        (2, child(), heap, false, false),
        (2, child(), heap + 128, true, false),
        (2, child(), stack + 256, false, false),
    ] {
        let fixture = Fixture::new(true, active, address, 8, write, descriptor, u16::MAX);
        assert!(
            fixture.accepts(),
            "active={active} address={address} write={write}"
        );
        assert_eq!(fixture.row[ALLOWED], field(expected));
        assert_eq!(fixture.row[RANGE_ERROR], F::ZERO);
    }
}

#[test]
fn stack_reads_check_every_selected_byte_and_the_correct_half() {
    let start = root()[0];
    for (offset, length, mask, expected) in [
        (0, 8, 0x00ff, true),
        (8, 8, 0xff00, true),
        (8, 8, 0x00ff, false),
        (0, 8, 0xff00, false),
        (0, 16, 0xffff, true),
        (0, 16, 0xfffe, false),
    ] {
        let fixture = Fixture::new(true, 1, start + offset, length, false, root(), mask);
        assert!(fixture.accepts());
        assert_eq!(fixture.row[ALLOWED], field(expected));
    }
    for bit in 0..16 {
        let fixture = Fixture::new(true, 1, start, 16, false, root(), u16::MAX ^ (1 << bit));
        assert!(fixture.accepts());
        assert_eq!(fixture.row[ALLOWED], F::ZERO);
    }
    let store = Fixture::new(true, 1, start, 16, true, root(), 0);
    assert!(store.accepts());
    assert_eq!(store.row[ALLOWED], F::ONE);
    assert_eq!(store.ports[11], [F::ZERO; packet::WIDTH]);
}

#[test]
fn inactive_no_frame_overflow_and_boundary_crossings_preserve_native_decisions() {
    for length in [8, 16] {
        for write in [false, true] {
            let inactive = Fixture::new(false, 1, root()[0], length, write, root(), 0);
            assert!(inactive.accepts());
            assert_eq!(inactive.ports, [[F::ZERO; packet::WIDTH]; 12]);
            let overflow_address = u64::MAX - u64::from(length) + 1;
            let active = Fixture::new(true, 1, overflow_address, length, write, root(), 0);
            assert!(active.accepts());
            assert_eq!(active.row[ALLOWED], F::ZERO);
            assert_eq!(active.row[RANGE_ERROR], F::ONE);
            let no_frame = Fixture::new(true, 0, overflow_address, length, write, root(), 0);
            assert!(no_frame.accepts());
            assert_eq!(no_frame.row[ALLOWED], F::ONE);
            assert_eq!(no_frame.row[RANGE_ERROR], F::ZERO);
        }
    }
    let mut descriptor = root();
    descriptor[2] += 8;
    descriptor[6] += 8;
    let partial = Fixture::new(true, 1, descriptor[2] - 8, 16, false, descriptor, 0);
    assert!(partial.accepts());
    assert_eq!(partial.row[ALLOWED], F::ZERO);
}

#[test]
fn original_owner_request_initialization_and_private_decision_mutations_fail() {
    let fixture = Fixture::new(true, 1, root()[0] + 8, 8, false, root(), 0xff00);
    assert!(fixture.accepts());
    for packet in 0..12 {
        for field in 0..packet::WIDTH {
            let mut changed = fixture.clone();
            changed.ports[packet][field] = changed.ports[packet][field].add(F::ONE);
            assert!(!changed.accepts(), "packet={packet} field={field}");
        }
    }
    for column in 0..WIDTH {
        let mut changed = fixture.clone();
        changed.row[column] = changed.row[column].add(F::ONE);
        assert!(!changed.accepts(), "private column={column}");
    }
    for limb in 0..4 {
        let mut changed = fixture.clone();
        changed.address[limb] = changed.address[limb].add(F::ONE);
        assert!(!changed.accepts());
    }
    let mut changed = fixture;
    changed.selected = F::ZERO;
    assert!(!changed.accepts());
}

#[test]
fn private_access_residues_have_bounded_polynomial_degree() {
    use crate::execution_proofs::stark::proof_managed_note_stark::degree_audit::measured_maximum_affine_degree_v1;
    let total = WIDTH + 5 + 12 * packet::WIDTH;
    for length in [8, 16] {
        for write in [false, true] {
            let schedule =
                Schedule::new(7, length, write, core::array::from_fn(|i| i as u32)).unwrap();
            let degree = measured_maximum_affine_degree_v1(
                [119; 32],
                [total, 0, 0, 0, 0],
                8,
                5,
                |row, _, _, _, _| {
                    let first = WIDTH + 5;
                    let packet = |i| {
                        row[first + i * packet::WIDTH..first + (i + 1) * packet::WIDTH]
                            .try_into()
                            .unwrap()
                    };
                    let mut output = Vec::new();
                    append_residues(
                        &mut output,
                        schedule,
                        row[..WIDTH].try_into().unwrap(),
                        Request {
                            selected: row[WIDTH],
                            address: row[WIDTH + 1..first].try_into().unwrap(),
                        },
                        Ports {
                            active: packet(0),
                            descriptors: core::array::from_fn(|i| packet(i + 1)),
                            initialized: packet(11),
                        },
                    );
                    Ok::<_, core::convert::Infallible>(output)
                },
            );
            assert!(degree <= 4);
        }
    }
}

#[test]
fn successful_store_decision_retains_original_generation_and_initialized_region() {
    let stack = ivm::Memory::STACK_START;
    let descriptors = [stack, stack + 1024, 128, 144, 256, 272, 128, 144, 256, 272];
    for active in [0, 3] {
        for (address, tracked) in [(stack + 8, true), (256, true), (512, false), (128, false)] {
            let fixture = Fixture::new(true, active, address, 8, true, descriptors, 0);
            let mut out = Vec::new();
            let address = core::array::from_fn(|i| F((address >> (16 * i)) & 0xffff));
            let decision = append_residues(
                &mut out,
                fixture.schedule,
                &fixture.row,
                Request {
                    selected: F::ONE,
                    address: &address,
                },
                Ports {
                    active: &fixture.ports[0],
                    descriptors: core::array::from_fn(|i| &fixture.ports[i + 1]),
                    initialized: &fixture.ports[11],
                },
            );
            assert!(out.iter().all(|r| *r == F::ZERO));
            assert_eq!(decision.active_generation, F(u64::from(active)));
            assert_eq!(
                decision.initialized_write,
                F(u64::from(active != 0 && tracked))
            );
            assert_eq!(
                fixture.ports[11],
                [F::ZERO; packet::WIDTH],
                "STORE never requests initialized-read permission"
            );
        }
    }
}
