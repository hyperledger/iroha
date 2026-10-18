//! Private canonical fetch and original call, memory, scalar and control producers.
//!
//! One original packet array owns architectural control, operand reads, both
//! lifecycle roles and protected return-PC state. The same references feed the
//! lifecycle bank and the private sorted history; no event digest substitutes
//! for these columns. All fetch choices and instruction activity are private.
// The callable_lookup component joins artifact-derived child descriptors and
// return operands/first-cell initialization through these original ports.
// CALL descriptor lookup, repeated table reads and frame-work gas are joined
// in their separate 47-port component. Typed argument/pointer work, local
// allocation and actual success remain mandatory unresolved owners.
// TODO: Compose general typed-word/full-initialization/copyback/memory effects and
// their dynamic gas between these fixed slots, then initialize and terminate
// the entire invocation in one masked STARK. This partial dispatcher has no
// production adapter, verifier registration or complete-State authority.

mod call_descriptor;
mod code_words;
mod load_success;
pub(super) mod native_witness;
mod scalar;
mod store_success;

use super::{F, bit, frame_lifecycle, packet, wide};
use ivm::{PreparedContract, limits::MAX_CONTRACT_CALL_DEPTH};
use packet::{
    AFTER, AFTER_TAG, BEFORE, BEFORE_TAG, CLOCK, ENABLED, GENERATION, INDEX, KEY, SPACE, Space, VM,
    WRITE,
};

/// Qualification geometry only; this is not a complete-program capacity claim.
pub(super) const MAX_WORDS: usize = 64;
const FETCH: usize = 0;
const WORDS: usize = FETCH + MAX_WORDS;
const CARRIES: usize = WORDS + 10 * 64;
const CHILD_INVERSE: usize = CARRIES + 20;
const RETURN_INVERSE: usize = CHILD_INVERSE + 1;
const PARENT_LIVE: usize = RETURN_INVERSE + 1;
const PARENT_INVERSE: usize = PARENT_LIVE + 1;
const HALT: usize = PARENT_INVERSE + 1;
const HALT_INVERSE: usize = HALT + 1;
// The canonical native bound is a power of two: ten low bits and one exact
// maximum bit encode 0..=1024. A changed bound requires the same AIR review.
const DEPTH_BITS_PER_VALUE: usize = 11;
const _: () = assert!(MAX_CONTRACT_CALL_DEPTH == 1 << (DEPTH_BITS_PER_VALUE - 1));
const DEPTH_BITS: usize = HALT_INVERSE + 1;
const RETURN_DELTA: usize = DEPTH_BITS + 2 * DEPTH_BITS_PER_VALUE;
/// One private fetch/control workspace shared by every original port.
const SCALAR: usize = RETURN_DELTA + 2;
/// Private source bits, ALU, comparison and shift cells follow control.
pub(super) const WIDTH: usize = SCALAR + scalar::WIDTH;
/// Exhaustive original producers owned by this dispatcher, in native order.
pub(super) const PORTS: usize = 21;
/// Architectural control owner indexes; frame/memory-policy owners 0..23 stay disjoint.
const PC_OWNER: u32 = 32;
const GAS_OWNER: u32 = 33;
const CYCLE_OWNER: u32 = 34;
const RUNNING_OWNER: u32 = 35;
const CALL_DEPTH_OWNER: u32 = 36;
const RETURN_PC_OWNER: u32 = 12;
const PC_READ: usize = 0;
const GAS_DEBIT: usize = 1;
const RETURN_REGISTER: usize = 2;
const RETURN_PROTECTED_PC: usize = 3;
const MEMORY_BASE: usize = 4;
const STORE_VALUE: usize = 5;
const CHILD_COUNTER: usize = 6;
const CHILD_ACTIVE: usize = 7;
const CHILD_PARENT: usize = 8;
const RETURN_COUNTER: usize = 9;
const RETURN_ACTIVE: usize = 10;
const RETURN_PARENT: usize = 11;
const CHILD_PROTECTED_PC: usize = 12;
const LINK_WRITE: usize = 13;
// Both native pushes and pops commit after successful frame effects. The same
// original depth cell also accompanies STORE so later invocation composition
// cannot supply a different private depth to each instruction.
const CALL_DEPTH: usize = 14;
const SCALAR_LEFT: usize = 15;
const SCALAR_RIGHT: usize = 16;
const SCALAR_DESTINATION: usize = 17;
const PC_WRITE: usize = 18;
const CYCLE_WRITE: usize = 19;
const RUNNING_WRITE: usize = 20;

/// Canonical artifact-owned fixed code; executed addresses remain witness data.
pub(super) struct Program {
    contract: PreparedContract,
    first_pc: u32,
    words: code_words::CodeWords,
    cycle_limit: u64,
    callables: super::callable_lookup::Callables,
}
impl Program {
    /// Parse only the original prepared artifact, never a caller instruction map.
    pub(super) fn new(contract: PreparedContract) -> Option<Self> {
        let metadata = contract.metadata();
        if metadata.abi_version != 1 || metadata.mode & ivm::ivm_mode::ZK == 0 {
            return None;
        }
        let cycle_limit = if metadata.max_cycles == 0 {
            ivm::zk::MAX_CYCLES
        } else {
            metadata.max_cycles
        };
        let first_pc =
            u32::try_from(contract.code_offset().checked_sub(contract.header_len())?).ok()?;
        let bytes = contract.artifact().get(contract.code_offset()..)?;
        if bytes.is_empty() || !bytes.len().is_multiple_of(4) || bytes.len() / 4 > MAX_WORDS {
            return None;
        }
        first_pc.checked_add(u32::try_from(bytes.len()).ok()?)?;
        let words = code_words::CodeWords::new(bytes)?;
        for instruction in words.iter().copied() {
            if role(instruction) == Some(Role::Literal)
                && contract
                    .scalar_literal(wide::literal_index(instruction) as u16)
                    .is_none()
            {
                return None;
            }
        }
        let callables = super::callable_lookup::Callables::new(&contract, first_pc, &words)?;
        Some(Self {
            contract,
            first_pc,
            words,
            cycle_limit,
            callables,
        })
    }

    pub(super) fn callables(&self) -> &super::callable_lookup::Callables {
        &self.callables
    }

    pub(super) fn fetch<'a>(&self, row: &'a [F; WIDTH]) -> &'a [F; MAX_WORDS] {
        row[FETCH..FETCH + MAX_WORDS].try_into().unwrap()
    }

    fn code_end(&self) -> u64 {
        u64::from(self.first_pc) + self.words.len() as u64 * 4
    }

    /// Retain the original authenticated-code candidate for the eventual adapter.
    pub(super) fn artifact(&self) -> &PreparedContract {
        &self.contract
    }
}

/// Shape-only unique clocks. The complete adapter must reserve the intervening
/// descriptor, result-scan and dynamic-gas work in this same global schedule.
#[derive(Clone, Copy)]
pub(super) struct Schedule {
    vm: u8,
    clocks: [u32; PORTS],
}
impl Schedule {
    pub(super) fn new(vm: u8, clocks: [u32; PORTS]) -> Option<Self> {
        clocks
            .windows(2)
            .all(|pair| pair[0] < pair[1])
            .then_some(Self { vm, clocks })
    }
}

/// The sole packet storage for these producers, not a second event copy.
#[cfg_attr(test, derive(Clone))]
pub(super) struct OriginalPackets {
    fields: [[F; packet::WIDTH]; PORTS],
}
impl OriginalPackets {
    /// Untrusted candidate columns; polynomial checks establish every role.
    pub(super) fn candidate(fields: [[F; packet::WIDTH]; PORTS]) -> Self {
        Self { fields }
    }

    /// Borrow the original packet for the same private permutation relation.
    pub(super) fn producer(&self, slot: usize) -> Option<&[F; packet::WIDTH]> {
        self.fields.get(slot)
    }
}

impl Drop for OriginalPackets {
    fn drop(&mut self) {
        for packet in &mut self.fields {
            for field in packet {
                field.zeroize_v1();
            }
        }
    }
}

/// Borrowed rows of the one global private history allocation. Every stage of
/// every owned producer is mandatory; the caller cannot choose a port subset.
pub(super) struct HistoryRow<'a> {
    pub(super) current: &'a [F; super::ROW_WIDTH],
    pub(super) next: &'a [F; super::ROW_WIDTH],
    pub(super) aux: &'a [F],
    pub(super) next_aux: &'a [F],
    pub(super) fixed: &'a [F; super::FIXED_WIDTH],
}
impl OriginalPackets {
    /// Join all original tuples exactly once (eight history stages each). The
    /// enclosing fixed adapter owns the global row placement and next-row links.
    pub(super) fn append_history_residues(
        &self,
        out: &mut impl crate::execution_proofs::ivm_step_air::residues::Sink,
        rows: &[HistoryRow<'_>; PORTS * super::PHASES],
        challenges: &super::permutation::Challenges,
    ) {
        for (index, history) in rows.iter().enumerate() {
            super::private_history::append_residues(
                out,
                history.current,
                history.next,
                history.aux,
                history.next_aux,
                history.fixed,
                &self.fields[index / super::PHASES],
                challenges,
            );
        }
    }
}

/// Derived selections and original ports for the remaining mandatory banks.
pub(super) struct Decoded<'a> {
    pub(super) child: F,
    pub(super) returning: F,
    pub(super) store: F,
    pub(super) load: F,
    pub(super) load_destination: F,
    pub(super) load_destination_index: F,
    pub(super) target: [F; 4],
    pub(super) memory_address: [F; 4],
    pub(super) destination: &'a [F; packet::WIDTH],
    pub(super) store_value: &'a [F; packet::WIDTH],
    pub(super) child_active: &'a [F; packet::WIDTH],
    pub(super) return_active: &'a [F; packet::WIDTH],
    pub(super) return_parent: &'a [F; packet::WIDTH],
    pub(super) call_depth: &'a [F; packet::WIDTH],
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Child,
    Return,
    Store,
    Load,
    Literal,
    Scalar,
    Branch,
    Jump,
}
fn role(instruction: u32) -> Option<Role> {
    match wide::opcode(instruction) {
        wide::control::JALS => Some(Role::Child),
        wide::control::JAL if wide::rd(instruction) == 1 => Some(Role::Child),
        wide::control::JAL if wide::rd(instruction) == 0 => Some(Role::Jump),
        wide::control::JMP => Some(Role::Jump),
        wide::control::JALR
            if wide::rd(instruction) == 0
                && wide::rs1(instruction) == 1
                && wide::imm8(instruction) == 0 =>
        {
            Some(Role::Return)
        }
        wide::memory::STORE64 => Some(Role::Store),
        wide::memory::LOAD64 => Some(Role::Load),
        wide::memory::LDI64 => Some(Role::Literal),
        _ if scalar::is_branch(instruction) => Some(Role::Branch),
        _ if scalar::is_supported(instruction) => Some(Role::Scalar),
        _ => None,
    }
}
fn limb(row: &[F; WIDTH], word: usize, limb: usize) -> F {
    row[WORDS + word * 64 + limb * 16..WORDS + word * 64 + (limb + 1) * 16]
        .iter()
        .enumerate()
        .fold(F::ZERO, |sum, (bit, value)| sum.add(value.mul(F(1 << bit))))
}
fn word32(row: &[F; WIDTH], word: usize) -> F {
    limb(row, word, 0).add(limb(row, word, 1).mul(F(1 << 16)))
}
fn constant_limb(value: u64, index: usize) -> F {
    F((value >> (16 * index)) & 0xffff)
}

/// Canonical typed source header and zero inactive payloads. Full range/first
/// state/alias continuity remains in the same shared private history, not here.
fn header(
    out: &mut impl crate::execution_proofs::ivm_step_air::residues::Sink,
    schedule: Schedule,
    packets: &OriginalPackets,
    slot: usize,
    space: packet::Space,
    index: F,
    generation: F,
    enabled: F,
    write: F,
) {
    let p = &packets.fields[slot];
    for (column, expected) in [
        (SPACE, enabled.mul(F(space as u64))),
        (VM, enabled.mul(F(u64::from(schedule.vm)))),
        (GENERATION, generation),
        (INDEX, index),
        (
            KEY,
            index
                .add(generation.mul(F(1 << 32)))
                .add(enabled.mul(F((u64::from(schedule.vm) << 48) + ((space as u64) << 56)))),
        ),
        (CLOCK, enabled.mul(F(u64::from(schedule.clocks[slot])))),
        (ENABLED, enabled),
        (WRITE, write),
    ] {
        out.push(p[column].sub(expected));
    }
    for value in p {
        out.push(F::ONE.sub(enabled).mul(*value));
    }
    for i in 4..8 {
        out.push(p[BEFORE + i]);
        out.push(p[AFTER + i]);
    }
    if space == Space::Owner {
        out.push(p[BEFORE_TAG]);
        out.push(p[AFTER_TAG]);
    } else {
        out.push(bit(p[BEFORE_TAG]));
        out.push(bit(p[AFTER_TAG]));
    }
    for i in (0..8)
        .map(|i| (BEFORE + i, AFTER + i))
        .chain([(BEFORE_TAG, AFTER_TAG)])
    {
        out.push(enabled.sub(write).mul(p[i.1].sub(p[i.0])));
    }
}

/// Constrain canonical private fetch, native base debit and exact-cycle commit,
/// exact source registers and artifact literals, CALL fresh-parent state, protected RETURN target and
/// the native bounded return-stack depth transition.
///
/// Successful-only rows force OOG/cycle/encoding guards to accept; no witness
/// fault selector may erase an effect. Descriptor/typed-word/memory semantics
/// are required consumers of Decoded and remain explicitly unimplemented here.
fn append_control_residues<'a>(
    out: &mut impl crate::execution_proofs::ivm_step_air::residues::Sink,
    program: &Program,
    schedule: Schedule,
    row: &[F; WIDTH],
    packets: &'a OriginalPackets,
) -> Decoded<'a> {
    let p = &packets.fields;
    let active = p[RUNNING_WRITE][BEFORE];
    out.push(bit(active));
    let select = |predicate: &dyn Fn(usize, u32) -> bool| {
        program
            .words
            .iter()
            .copied()
            .enumerate()
            .filter(|(i, w)| predicate(*i, *w))
            .fold(F::ZERO, |sum, (i, _)| sum.add(row[FETCH + i]))
    };
    let weighted = |value: &dyn Fn(usize, u32) -> F| {
        program
            .words
            .iter()
            .copied()
            .enumerate()
            .fold(F::ZERO, |sum, (i, w)| {
                sum.add(row[FETCH + i].mul(value(i, w)))
            })
    };
    let child = select(&|_, w| role(w) == Some(Role::Child));
    let returning = select(&|_, w| role(w) == Some(Role::Return));
    let store = select(&|_, w| role(w) == Some(Role::Store));
    let load = select(&|_, w| role(w) == Some(Role::Load));
    let literal = select(&|_, w| role(w) == Some(Role::Literal));
    let memory = store.add(load);
    let scalar = select(&|_, w| role(w) == Some(Role::Scalar));
    // GETGAS is a successful scalar state transition with the native zero
    // opcode tariff. Its cycle and register effects remain active at zero gas.
    let scalar_base_gas =
        select(&|_, w| role(w) == Some(Role::Scalar) && wide::opcode(w) != wide::system::GETGAS);
    let scalar_extra_gas = select(&|_, w| {
        scalar::is_rotate(w)
            || scalar::is_mean(w)
            || matches!(
                wide::opcode(w),
                wide::arithmetic::SLT
                    | wide::arithmetic::SLTU
                    | wide::arithmetic::SEQ
                    | wide::arithmetic::SNE
            )
    });
    let multiply_extra_gas = select(&|_, w| scalar::is_multiply(w)).mul(F(2));
    let bit_count_extra_gas = select(&|_, w| scalar::is_bit_count(w)).mul(F(5));
    let move_extra_gas = select(&|_, w| scalar::is_conditional_move(w)).mul(F(2));
    let division_extra_gas = select(&|_, w| scalar::is_division(w)).mul(F(9));
    let ceiling_selected = select(&|_, w| scalar::is_division_ceiling(w));
    let ceiling_extra_gas = ceiling_selected.mul(F(2));
    let ceiling_extra_cycles = ceiling_selected.mul(F(11));
    let square_extra_gas = select(&|_, w| scalar::is_square_root(w)).mul(F(5));
    let square_extra_cycles = square_extra_gas;
    let mean_extra_cycles = select(&|_, w| scalar::is_mean(w)).mul(F(2));
    let gcd_extra = select(&|_, w| scalar::is_gcd(w)).mul(F(11));
    let branching = select(&|_, w| role(w) == Some(Role::Branch));
    let jumping = select(&|_, w| role(w) == Some(Role::Jump));
    let mut fetched = F::ZERO;
    for i in 0..MAX_WORDS {
        out.push(bit(row[FETCH + i]));
        fetched = fetched.add(row[FETCH + i]);
        if i >= program.words.len() {
            out.push(row[FETCH + i]);
        }
    }
    out.push(fetched.sub(active));
    out.push(
        child
            .add(returning)
            .add(memory)
            .add(literal)
            .add(scalar)
            .add(branching)
            .add(jumping)
            .sub(active),
    );
    for value in &row[WORDS..CHILD_INVERSE] {
        out.push(bit(*value));
    }
    for value in &row[RETURN_DELTA..SCALAR] {
        out.push(bit(*value));
    }
    // The private PC must be one actual instruction address in the original image.
    for i in 0..4 {
        out.push(limb(row, 0, i).sub(weighted(&|n, _| {
            constant_limb(u64::from(program.first_pc) + n as u64 * 4, i)
        })));
    }
    header(
        out,
        schedule,
        packets,
        PC_READ,
        Space::Owner,
        active.mul(F(u64::from(PC_OWNER))),
        F::ZERO,
        active,
        F::ZERO,
    );
    header(
        out,
        schedule,
        packets,
        GAS_DEBIT,
        Space::Owner,
        active.mul(F(u64::from(GAS_OWNER))),
        F::ZERO,
        active,
        active,
    );
    header(
        out,
        schedule,
        packets,
        PC_WRITE,
        Space::Owner,
        active.mul(F(u64::from(PC_OWNER))),
        F::ZERO,
        active,
        active,
    );
    header(
        out,
        schedule,
        packets,
        CYCLE_WRITE,
        Space::Owner,
        active.mul(F(u64::from(CYCLE_OWNER))),
        F::ZERO,
        active,
        active,
    );
    // Inactive native windows have no state accesses, including running state.
    // Active instructions still own the exact native running transition.
    header(
        out,
        schedule,
        packets,
        RUNNING_WRITE,
        Space::Owner,
        active.mul(F(u64::from(RUNNING_OWNER))),
        F::ZERO,
        active,
        active,
    );
    for i in 1..4 {
        out.push(p[RUNNING_WRITE][BEFORE + i]);
        out.push(p[RUNNING_WRITE][AFTER + i]);
    }
    for i in 0..4 {
        out.push(p[PC_READ][BEFORE + i].sub(limb(row, 0, i)));
        out.push(p[PC_WRITE][BEFORE + i].sub(limb(row, 0, i)));
        for (port, offset, word) in [
            (GAS_DEBIT, BEFORE, 1),
            (GAS_DEBIT, AFTER, 2),
            (CYCLE_WRITE, BEFORE, 3),
            (CYCLE_WRITE, AFTER, 4),
        ] {
            out.push(p[port][offset + i].sub(limb(row, word, i)));
        }
        // Native base cost: zero for GETGAS, two for CALL/RETURN/direct jumps,
        // three for LOAD64/STORE64, one for LDI64 and other scalars/branches.
        // Comparisons/rotates/MEAN add one, multiply adds two, bit counts/ISQRT
        // add five, ordinary division adds nine and DIV_CEIL adds eleven.
        // GCD uses twelve gas/cycles, DIV_CEIL twelve cycles, ISQRT six and
        // MEAN three; all other roles consume one cycle.
        // The final borrow forbids underflow.
        let borrow_in = if i == 0 {
            F::ZERO
        } else {
            row[CARRIES + i - 1]
        };
        let cost = if i == 0 {
            child
                .add(returning)
                .add(jumping)
                .mul(F(2))
                .add(memory.mul(F(3)))
                .add(literal)
                .add(scalar_base_gas)
                .add(scalar_extra_gas)
                .add(multiply_extra_gas)
                .add(bit_count_extra_gas)
                .add(move_extra_gas)
                .add(division_extra_gas)
                .add(ceiling_extra_gas)
                .add(square_extra_gas)
                .add(gcd_extra)
                .add(branching)
        } else {
            F::ZERO
        };
        out.push(
            limb(row, 1, i)
                .sub(cost)
                .sub(borrow_in)
                .sub(limb(row, 2, i))
                .add(row[CARRIES + i].mul(F(1 << 16))),
        );
        let carry_in = if i == 0 {
            active
                .add(mean_extra_cycles)
                .add(square_extra_cycles)
                .add(ceiling_extra_cycles)
                .add(gcd_extra)
        } else {
            row[CARRIES + 4 + i - 1]
        };
        out.push(
            limb(row, 3, i)
                .add(carry_in)
                .sub(limb(row, 4, i))
                .sub(row[CARRIES + 4 + i].mul(F(1 << 16))),
        );
        let borrow_in = if i == 0 {
            F::ZERO
        } else {
            row[CARRIES + 16 + i - 1]
        };
        out.push(
            active
                .mul(constant_limb(program.cycle_limit - 1, i))
                .sub(limb(row, 3, i))
                .sub(borrow_in)
                .sub(limb(row, 9, i))
                .add(row[CARRIES + 16 + i].mul(F(1 << 16))),
        );
    }
    out.push(row[CARRIES + 3]);
    out.push(row[CARRIES + 7]);
    out.push(row[CARRIES + 19]);
    header(
        out,
        schedule,
        packets,
        RETURN_REGISTER,
        Space::Register,
        returning,
        F::ZERO,
        returning,
        F::ZERO,
    );
    header(
        out,
        schedule,
        packets,
        MEMORY_BASE,
        Space::Register,
        weighted(&|_, w| match role(w) {
            Some(Role::Store) => F(wide::rd(w) as u64),
            Some(Role::Load) => F(wide::rs1(w) as u64),
            _ => F::ZERO,
        }),
        F::ZERO,
        memory,
        F::ZERO,
    );
    header(
        out,
        schedule,
        packets,
        STORE_VALUE,
        Space::Register,
        weighted(&|_, w| {
            if role(w) == Some(Role::Store) {
                F(wide::rs1(w) as u64)
            } else {
                F::ZERO
            }
        }),
        F::ZERO,
        store,
        F::ZERO,
    );
    out.push(p[RETURN_REGISTER][BEFORE_TAG]);
    out.push(p[MEMORY_BASE][BEFORE_TAG]);
    for (slot, register) in [(MEMORY_BASE, false), (STORE_VALUE, true)] {
        let zero = select(&|_, w| match (role(w), register) {
            (Some(Role::Store), true) | (Some(Role::Load), false) => wide::rs1(w) == 0,
            (Some(Role::Store), false) => wide::rd(w) == 0,
            _ => false,
        });
        for field in (BEFORE..BEFORE + 4).chain([BEFORE_TAG]) {
            out.push(zero.mul(p[slot][field]));
        }
    }
    for i in 0..4 {
        out.push(p[MEMORY_BASE][BEFORE + i].sub(limb(row, 6, i)));
        out.push(p[RETURN_REGISTER][BEFORE + i].sub(limb(row, 8, i)));
        let immediate = weighted(&|_, w| {
            if matches!(role(w), Some(Role::Store | Role::Load)) {
                constant_limb(i64::cast_unsigned(i64::from(wide::imm8(w))), i)
            } else {
                F::ZERO
            }
        });
        let carry = if i == 0 {
            F::ZERO
        } else {
            row[CARRIES + 8 + i - 1]
        };
        out.push(
            limb(row, 6, i)
                .add(immediate)
                .add(carry)
                .sub(limb(row, 7, i))
                .sub(row[CARRIES + 8 + i].mul(F(1 << 16))),
        );
        // Exact native aligned return target: raw r1 = target + delta, 0<=delta<4.
        let delta = if i == 0 {
            row[RETURN_DELTA].add(row[RETURN_DELTA + 1].mul(F(2)))
        } else {
            row[CARRIES + 12 + i - 1]
        };
        out.push(
            limb(row, 5, i)
                .add(delta)
                .sub(limb(row, 8, i))
                .sub(row[CARRIES + 12 + i].mul(F(1 << 16))),
        );
    }
    out.push(row[CARRIES + 15]);
    for i in 0..2 {
        out.push(
            row[WORDS + 5 * 64 + i].sub(returning.mul(F((u64::from(program.first_pc) >> i) & 1))),
        );
    }
    for i in 32..64 {
        out.push(row[WORDS + 5 * 64 + i]);
    }
    for i in 0..4 {
        out.push(F::ONE.sub(returning).mul(limb(row, 5, i)));
    }
    let selection = [F::ZERO, child, returning];
    for (transition, first, inverse) in [
        (
            frame_lifecycle::Transition::ChildEntry,
            CHILD_COUNTER,
            CHILD_INVERSE,
        ),
        (
            frame_lifecycle::Transition::Return,
            RETURN_COUNTER,
            RETURN_INVERSE,
        ),
    ] {
        frame_lifecycle::append_residues(
            out,
            frame_lifecycle::Schedule::new(
                schedule.vm,
                transition,
                core::array::from_fn(|i| schedule.clocks[first + i]),
            )
            .unwrap(),
            &[row[inverse]],
            &selection,
            frame_lifecycle::Ports {
                counter: &p[first],
                active: &p[first + 1],
                parent: &p[first + 2],
            },
        );
    }
    let parent = p[RETURN_PARENT][BEFORE];
    out.push(bit(row[PARENT_LIVE]));
    out.push(parent.mul(row[PARENT_INVERSE]).sub(row[PARENT_LIVE]));
    out.push(parent.mul(returning.sub(row[PARENT_LIVE])));
    out.push(F::ONE.sub(row[PARENT_LIVE]).mul(row[PARENT_INVERSE]));
    let root_return = returning.sub(row[PARENT_LIVE]);
    // The root has a separate outer sentinel, so only a non-root return pops
    // the protected stack. Bounds on both states make a full-stack push and an
    // empty non-root pop impossible as integer equations, not modular aliases.
    header(
        out,
        schedule,
        packets,
        CALL_DEPTH,
        Space::Owner,
        active.mul(F(u64::from(CALL_DEPTH_OWNER))),
        F::ZERO,
        active,
        child.add(returning),
    );
    for (side, offset) in [BEFORE, AFTER].into_iter().enumerate() {
        let bits = &row[DEPTH_BITS + side * DEPTH_BITS_PER_VALUE
            ..DEPTH_BITS + (side + 1) * DEPTH_BITS_PER_VALUE];
        out.extend(bits.iter().copied().map(bit));
        let low = bits[..DEPTH_BITS_PER_VALUE - 1]
            .iter()
            .copied()
            .enumerate()
            .fold(F::ZERO, |sum, (index, value)| {
                sum.add(value.mul(F(1_u64 << index)))
            });
        let maximum = bits[DEPTH_BITS_PER_VALUE - 1];
        out.push(maximum.mul(low));
        out.push(
            p[CALL_DEPTH][offset]
                .sub(low)
                .sub(maximum.mul(F(MAX_CONTRACT_CALL_DEPTH as u64))),
        );
        for limb in 1..4 {
            out.push(p[CALL_DEPTH][offset + limb]);
        }
    }
    out.push(
        p[CALL_DEPTH][AFTER]
            .sub(p[CALL_DEPTH][BEFORE])
            .sub(child)
            .add(row[PARENT_LIVE]),
    );
    out.push(root_return.mul(p[CALL_DEPTH][BEFORE]));
    let call_return = |i| {
        weighted(&|n, w| {
            if role(w) == Some(Role::Child) {
                constant_limb(u64::from(program.first_pc) + n as u64 * 4 + 4, i)
            } else {
                F::ZERO
            }
        })
    };
    // Return target authentication precedes the lifecycle commit; call push
    // follows successful frame entry. Separate original slots preserve both.
    header(
        out,
        schedule,
        packets,
        CHILD_PROTECTED_PC,
        Space::Owner,
        child.mul(F(u64::from(RETURN_PC_OWNER))),
        p[CHILD_ACTIVE][AFTER],
        child,
        child,
    );
    header(
        out,
        schedule,
        packets,
        RETURN_PROTECTED_PC,
        Space::Owner,
        returning.mul(F(u64::from(RETURN_PC_OWNER))),
        p[RETURN_ACTIVE][BEFORE],
        returning,
        F::ZERO,
    );
    header(
        out,
        schedule,
        packets,
        LINK_WRITE,
        Space::Register,
        child,
        F::ZERO,
        child,
        child,
    );
    for i in 0..4 {
        out.push(p[CHILD_PROTECTED_PC][BEFORE + i]);
        out.push(p[CHILD_PROTECTED_PC][AFTER + i].sub(call_return(i)));
        out.push(p[RETURN_PROTECTED_PC][BEFORE + i].sub(limb(row, 5, i)));
        out.push(p[LINK_WRITE][AFTER + i].sub(call_return(i)));
        out.push(root_return.mul(limb(row, 5, i).sub(constant_limb(program.code_end(), i))));
        let direct_target = weighted(&|n, w| {
            let pc = u64::from(program.first_pc) + n as u64 * 4;
            match role(w) {
                Some(Role::Child | Role::Jump) => {
                    // Canonical preparation binds direct targets to instruction
                    // boundaries. JMP and JAL rd0 have no link/frame effects.
                    let delta =
                        if matches!(wide::opcode(w), wide::control::JALS | wide::control::JMP) {
                            i64::from(wide::imm24(w))
                        } else {
                            i64::from(wide::imm16(w))
                        };
                    constant_limb(pc.wrapping_add_signed(delta * 4), i)
                }
                Some(Role::Store | Role::Load | Role::Literal | Role::Scalar) => {
                    constant_limb(pc + 4, i)
                }
                Some(Role::Branch) => {
                    // PreparedContract has already checked both successors
                    // against its instruction boundaries. Native branches do
                    // not halt, even when their predicate is true.
                    let fallthrough = constant_limb(pc + 4, i);
                    let target =
                        constant_limb(pc.wrapping_add_signed(i64::from(wide::imm8(w)) * 4), i);
                    fallthrough.add(scalar::branch_taken(row).mul(target.sub(fallthrough)))
                }
                _ => F::ZERO,
            }
        });
        out.push(
            p[PC_WRITE][AFTER + i]
                .sub(direct_target)
                .sub(returning.mul(limb(row, 5, i))),
        );
    }
    out.push(p[LINK_WRITE][AFTER_TAG]);
    let end_difference = word32(row, 5).sub(returning.mul(F(program.code_end())));
    out.push(bit(row[HALT]));
    out.push(row[HALT].mul(F::ONE.sub(returning)));
    out.push(end_difference.mul(row[HALT]));
    out.push(
        end_difference
            .mul(row[HALT_INVERSE])
            .sub(returning.sub(row[HALT])),
    );
    out.push(row[HALT].add(F::ONE.sub(returning)).mul(row[HALT_INVERSE]));
    out.push(p[RUNNING_WRITE][AFTER].sub(active).add(row[HALT]));
    Decoded {
        child,
        returning,
        store,
        load,
        load_destination: select(&|_, w| role(w) == Some(Role::Load) && wide::rd(w) != 0),
        load_destination_index: weighted(&|_, w| {
            if role(w) == Some(Role::Load) {
                F(wide::rd(w) as u64)
            } else {
                F::ZERO
            }
        }),
        destination: &p[SCALAR_DESTINATION],
        target: core::array::from_fn(|i| p[PC_WRITE][AFTER + i]),
        memory_address: core::array::from_fn(|i| limb(row, 7, i)),
        store_value: &p[STORE_VALUE],
        child_active: &p[CHILD_ACTIVE],
        return_active: &p[RETURN_ACTIVE],
        return_parent: &p[RETURN_PARENT],
        call_depth: &p[CALL_DEPTH],
    }
}

/// Join the same canonical private fetch/control and scalar/branch register equations.
/// Direct jumps consume no register operands and leave every lifecycle port inactive.
/// Every original producer, including all three scalar ports, belongs to the
/// exhaustive private-history join. No public operand statement is introduced.
pub(super) fn append_residues<'a>(
    out: &mut impl crate::execution_proofs::ivm_step_air::residues::Sink,
    program: &Program,
    schedule: Schedule,
    row: &[F; WIDTH],
    packets: &'a OriginalPackets,
) -> Decoded<'a> {
    let decoded = append_control_residues(out, program, schedule, row, packets);
    scalar::append_residues(out, program, schedule, row, packets);
    decoded
}

#[cfg(test)]
pub(super) mod tests;

#[cfg(test)]
mod jump_tests;
