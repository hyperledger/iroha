//! Authenticated CALL descriptor, repeated table reads and frame-work debit.
//!
//! The prepared artifact owns every selected callable field and its bitmap
//! work price. One original gas owner joins the opcode debit to the later frame
//! debit. All 47 original packets share 376 fixed private-history stages.
//! Descriptor operands precede the native validation rereads; the frame debit
//! precedes fresh descriptor publication and the original lifecycle commit.
//! The first unchanged operand reads remain a semantic normalization, not the
//! literal native register-log ordering. No uninitialized argument is validated
//! here, and a successful frame debit does not establish successful CALL.
// TODO: Compose initialized typed argument words and their ordered word/pointer
// gas, fallible allocation/return-slot preflight, and all failed-call effects.
// Root/return/copyback, complete invocation and finalized-State authority remain
// unavailable. The zero-argument native diagnostic checks this partial tariff;
// it is not an invocation or allocation qualification.

use super::super::{frame_descriptor, packet, permutation, private_history};
use super::{F, OriginalPackets, Program};
#[cfg(test)]
use super::{Role, wide};
use packet::{AFTER, BEFORE, CLOCK};

mod scalar_arguments;

/// Original dispatch and descriptor producers; the lifecycle active tuple is shared.
pub(super) const PORTS: usize = super::PORTS + frame_descriptor::PORTS + 5;
/// Final gas bits and exact subtraction borrows; the opcode bank remains unchanged.
const FRAME_WORK_WIDTH: usize = 64 + 4;
/// Existing banks, frame-work witness and every unique original packet field.
pub(super) const WIDTH: usize =
    super::WIDTH + frame_descriptor::WIDTH + FRAME_WORK_WIDTH + PORTS * packet::WIDTH;
const _: () = assert!(PORTS == 47 && WIDTH == 4801);
const DESCRIPTOR_START: usize = 6;
const DESCRIPTOR_READS: usize = 9;
const VALIDATION_START: usize = DESCRIPTOR_START + DESCRIPTOR_READS;
const FRAME_DEBIT: usize = VALIDATION_START + 4;
// Actual validate_call_tables access order; the earlier descriptor operands are
// r10, r11, r12, r13. Neither phase can substitute a different retained value.
const VALIDATION_SOURCES: [usize; 4] = [0, 2, 1, 3];

/// Fixed padded record placement, never witness-dependent scheduling.
#[derive(Clone, Copy)]
pub(super) struct Schedule {
    vm: u8,
    clocks: [u32; PORTS],
}
impl Schedule {
    pub(super) fn new(vm: u8, first_clock: u32) -> Option<Self> {
        first_clock.checked_add(PORTS as u32 - 1)?;
        Self::with_clocks(vm, core::array::from_fn(|slot| first_clock + slot as u32))
    }
    fn with_clocks(vm: u8, clocks: [u32; PORTS]) -> Option<Self> {
        clocks
            .windows(2)
            .all(|pair| pair[0] < pair[1])
            .then_some(Self { vm, clocks })
    }
    fn clock(self, slot: usize) -> u32 {
        self.clocks[slot]
    }
    fn dispatch(self) -> super::Schedule {
        super::Schedule::new(
            self.vm,
            core::array::from_fn(|slot| self.clock(dispatch_slot(slot))),
        )
        .unwrap()
    }
    fn descriptor(self) -> frame_descriptor::Schedule {
        frame_descriptor::Schedule::new(
            self.vm,
            false,
            core::array::from_fn(|slot| self.clock(descriptor_slot(slot))),
        )
        .unwrap()
    }
}
fn dispatch_slot(slot: usize) -> usize {
    if slot < DESCRIPTOR_START {
        slot
    } else {
        slot + frame_descriptor::PORTS + 5
    }
}

fn descriptor_slot(slot: usize) -> usize {
    DESCRIPTOR_START + slot + if slot < DESCRIPTOR_READS { 0 } else { 5 }
}

/// Borrowed banks and unique original producers of one committed semantic row.
pub(super) struct Row<'a> {
    pub(super) dispatch: &'a [F; super::WIDTH],
    pub(super) descriptor: &'a [F; frame_descriptor::WIDTH],
    pub(super) frame_work: &'a [F; FRAME_WORK_WIDTH],
    pub(super) packets: [&'a [F; packet::WIDTH]; PORTS],
}

impl Row<'_> {
    fn producer(&self, slot: usize) -> &[F; packet::WIDTH] {
        self.packets[slot]
    }
}

/// Resolve a public instruction slot through the original prepared interface.
/// IVM targets are absolute; callable and descriptor entry PCs are code-relative.
#[cfg(test)]
fn callable(program: &Program, slot: usize) -> Option<&ivm::call::EmbeddedCallableV1> {
    let instruction = *program.words.get(slot)?;
    if super::role(instruction) != Some(Role::Child) {
        return None;
    }
    let offset = if wide::opcode(instruction) == wide::control::JAL {
        i64::from(wide::imm16(instruction))
    } else {
        i64::from(wide::imm24(instruction))
    };
    let relative = (slot as u64)
        .checked_mul(4)?
        .checked_add_signed(offset.checked_mul(4)?)?;
    let callables = &program.artifact().contract_interface().callables;
    let index = callables
        .binary_search_by_key(&relative, |callable| callable.entry_pc)
        .ok()?;
    callables.get(index)
}

/// Native V1 `call_gas::frame`: one byte per eight frame bytes, plus one
/// initialization byte per result word. This is derived from the authenticated
/// artifact, never from an unbounded prover-provided tariff. Prepared callable
/// validation bounds it by 532480; each selected 16-bit limb remains bounded.
#[cfg(test)]
fn frame_work(callable: &ivm::call::EmbeddedCallableV1) -> u64 {
    u64::from(callable.frame_bytes).div_ceil(8)
        + callable
            .result_word_count()
            .expect("admitted result schema") as u64
}

fn gas_limb(row: &[F; FRAME_WORK_WIDTH], index: usize) -> F {
    row[index * 16..(index + 1) * 16]
        .iter()
        .enumerate()
        .fold(F::ZERO, |sum, (bit, value)| sum.add(value.mul(F(1 << bit))))
}

/// Exact bounded subtraction and complete original header/value joins. Every
/// integer limb residual is below 2^18 in magnitude, excluding field wrap.
fn append_frame_work(
    out: &mut Vec<F>,
    schedule: Schedule,
    row: &Row<'_>,
    active: F,
    cost: &[F; 4],
) {
    for (index, source_slot) in VALIDATION_SOURCES.into_iter().enumerate() {
        let original = row.packets[descriptor_slot(source_slot)];
        let repeated = row.packets[VALIDATION_START + index];
        for field in 0..packet::WIDTH {
            let expected = if field == CLOCK {
                active.mul(F(u64::from(schedule.clock(VALIDATION_START + index))))
            } else {
                original[field]
            };
            out.push(repeated[field].sub(expected));
        }
    }
    let opcode = row.packets[dispatch_slot(super::GAS_DEBIT)];
    let debit = row.packets[FRAME_DEBIT];
    for value in row.frame_work {
        out.push(super::bit(*value));
        out.push(F::ONE.sub(active).mul(*value));
    }
    for field in 0..packet::WIDTH {
        let expected = match field {
            CLOCK => active.mul(F(u64::from(schedule.clock(FRAME_DEBIT)))),
            BEFORE..AFTER => opcode[AFTER + field - BEFORE],
            AFTER..=23 => {
                if field < AFTER + 4 {
                    gas_limb(row.frame_work, field - AFTER)
                } else {
                    F::ZERO
                }
            }
            _ => opcode[field],
        };
        out.push(debit[field].sub(expected));
    }
    for (limb, cost) in cost.iter().copied().enumerate() {
        let incoming = if limb == 0 {
            F::ZERO
        } else {
            row.frame_work[64 + limb - 1]
        };
        out.push(
            debit[BEFORE + limb]
                .sub(cost)
                .sub(incoming)
                .sub(gas_limb(row.frame_work, limb))
                .add(row.frame_work[64 + limb].mul(F(1 << 16))),
        );
    }
    out.push(row.frame_work[67]);
}

fn append_semantics(out: &mut Vec<F>, program: &Program, schedule: Schedule, row: &Row<'_>) {
    let originals = OriginalPackets::candidate(core::array::from_fn(|slot| {
        *row.packets[dispatch_slot(slot)]
    }));
    let decoded =
        super::append_residues(out, program, schedule.dispatch(), row.dispatch, &originals);
    // Active non-CALL rows cannot satisfy a descriptor-only record. Canonical
    // padding remains admitted by the existing dispatcher and descriptor banks.
    out.push(
        decoded
            .child
            .sub(originals.fields[super::RUNNING_WRITE][BEFORE]),
    );
    let (child, selected, absolute) = program
        .callables()
        .select_child(program.fetch(row.dispatch));
    let mut frame_cost = [F::ZERO; 4];
    for slot in 0..program.words.len() {
        let fetch = row.dispatch[super::FETCH + slot];
        if let Some(cost) = program.callables().child_frame_work(slot) {
            for limb in 0..4 {
                frame_cost[limb] =
                    frame_cost[limb].add(fetch.mul(super::constant_limb(cost, limb)));
            }
        }
    }
    out.push(selected.sub(decoded.child));
    for limb in 0..4 {
        out.push(absolute[limb].sub(decoded.target[limb]));
    }
    frame_descriptor::append_residues(
        out,
        schedule.descriptor(),
        row.descriptor,
        decoded.child,
        &child,
        frame_descriptor::Ports {
            active: decoded.child_active,
            packets: core::array::from_fn(|slot| row.packets[descriptor_slot(slot)]),
        },
    );
    append_frame_work(out, schedule, row, decoded.child, &frame_cost);
}

/// Constrain the banks and every field of every original through all history stages.
pub(super) fn append_residues(
    out: &mut Vec<F>,
    program: &Program,
    schedule: Schedule,
    row: &Row<'_>,
    history: &[super::HistoryRow<'_>; PORTS * super::super::PHASES],
    challenges: &permutation::Challenges,
) {
    append_semantics(out, program, schedule, row);
    for (index, history) in history.iter().enumerate() {
        out.push(
            history.fixed[super::super::SLOT]
                .sub(F(u64::from(schedule.clock(index / super::super::PHASES)))),
        );
        for phase in 0..super::super::PHASES {
            out.push(
                history.fixed[super::super::PHASE_OFFSET + phase]
                    .sub(F(u64::from(phase == index % super::super::PHASES))),
            );
        }
        private_history::append_residues(
            out,
            history.current,
            history.next,
            history.aux,
            history.next_aux,
            history.fixed,
            row.producer(index / super::super::PHASES),
            challenges,
        );
    }
}

#[cfg(test)]
mod tests;
