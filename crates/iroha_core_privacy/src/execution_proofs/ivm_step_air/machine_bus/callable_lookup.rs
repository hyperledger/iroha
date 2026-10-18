//! Artifact-owned callable selection and original CALL/RETURN column joins.
//!
//! Counts are derived once from the original admitted recursive schemas. Child
//! selection reuses canonical fetch columns; return selection reads the active
//! generation's original protected entry word. Executable-relative entries and
//! loaded-image instruction addresses are deliberately separate quantities.
// TODO: Complete typed traversal, TLV/privacy, staged gas/faults, invocation
// initialization/termination, multiple-window sizing and masked STARK composition.
// This unregistered component does not authorize root entry or authenticate a
// program against an execution statement or finalized State.

use super::{F, bit, frame_descriptor, packet, private_dispatch, return_copyback, wide};
use packet::BEFORE;

mod native_root;

const CAPACITY: usize = private_dispatch::MAX_WORDS;

#[derive(Clone, Copy, Default)]
struct Callable {
    entry: u64,
    absolute: u64,
    frame: u32,
    arguments: usize,
    results: usize,
}

/// Fixed public program data, owned only by the original prepared image.
pub(super) struct Callables {
    entries: [Callable; CAPACITY],
    len: usize,
    children: [Option<usize>; CAPACITY],
}

impl Callables {
    pub(super) fn new(
        contract: &ivm::PreparedContract,
        first_pc: u32,
        words: &[u32],
    ) -> Option<Self> {
        let interface = contract.contract_interface();
        if interface.callables.len() > CAPACITY || words.len() > CAPACITY {
            return None;
        }
        let mut entries = [Callable::default(); CAPACITY];
        for (entry, descriptor) in entries.iter_mut().zip(&interface.callables) {
            *entry = Callable {
                entry: descriptor.entry_pc,
                absolute: u64::from(first_pc).checked_add(descriptor.entry_pc)?,
                frame: descriptor.frame_bytes,
                arguments: descriptor.arguments.analyze()?.word_count(),
                results: descriptor.results.analyze()?.word_count(),
            };
        }
        let mut children = [None; CAPACITY];
        for (index, &instruction) in words.iter().enumerate() {
            let offset = match wide::opcode(instruction) {
                wide::control::JAL if wide::rd(instruction) == 1 => {
                    i64::from(wide::imm16(instruction))
                }
                wide::control::JALS => i64::from(wide::imm24(instruction)),
                _ => continue,
            };
            let target = (index as u64 * 4).checked_add_signed(offset.checked_mul(4)?)?;
            children[index] = Some(
                interface
                    .callables
                    .binary_search_by_key(&target, |callable| callable.entry_pc)
                    .ok()?,
            );
        }
        Some(Self {
            entries,
            len: interface.callables.len(),
            children,
        })
    }

    /// Original immutable instruction-to-callable mapping, never a supplied descriptor.
    pub(super) fn child_index(&self, slot: usize) -> Option<usize> {
        self.children.get(slot).copied().flatten()
    }
    /// Once-derived argument width of the original admitted callable.
    pub(super) fn argument_word_count(&self, index: usize) -> Option<usize> {
        (index < self.len).then(|| self.entries[index].arguments)
    }

    /// Native bitmap tariff from the original cached frame and result dimensions.
    pub(super) fn child_frame_work(&self, slot: usize) -> Option<u64> {
        let entry = self.entries.get(self.child_index(slot)?)?;
        u64::from(entry.frame)
            .div_ceil(8)
            .checked_add(u64::try_from(entry.results).ok()?)
    }

    /// Derive child fields and absolute targets from the same original fetch columns.
    pub(super) fn select_child(&self, fetch: &[F; CAPACITY]) -> (SelectedCallable, F, [F; 4]) {
        let mut child = SelectedCallable::zero();
        let mut absolute = [F::ZERO; 4];
        let mut selected = F::ZERO;
        for (index, &fetch) in fetch.iter().enumerate() {
            if let Some(callable) = self.children[index] {
                let callable = self.entries[callable];
                child.include(fetch, callable);
                selected = selected.add(fetch);
                for (index, limb) in absolute.iter_mut().enumerate() {
                    *limb = limb.add(fetch.mul(F((callable.absolute >> (16 * index)) & 0xffff)));
                }
            }
        }
        (child, selected, absolute)
    }
}

/// Derived columns only. There is no non-test constructor accepting claimed
/// counts, frame size or entry address independently from the original program.
pub(super) struct SelectedCallable {
    entry: [F; 4],
    frame: F,
    arguments: F,
    results: F,
}

impl SelectedCallable {
    fn zero() -> Self {
        Self {
            entry: [F::ZERO; 4],
            frame: F::ZERO,
            arguments: F::ZERO,
            results: F::ZERO,
        }
    }
    fn include(&mut self, selector: F, callable: Callable) {
        for (index, limb) in self.entry.iter_mut().enumerate() {
            *limb = limb.add(selector.mul(F((callable.entry >> (16 * index)) & 0xffff)));
        }
        self.frame = self.frame.add(selector.mul(F(u64::from(callable.frame))));
        self.arguments = self
            .arguments
            .add(selector.mul(F(callable.arguments as u64)));
        self.results = self.results.add(selector.mul(F(callable.results as u64)));
    }
    pub(super) fn entry_pc(&self) -> &[F; 4] {
        &self.entry
    }
    pub(super) fn frame_bytes(&self) -> F {
        self.frame
    }
    pub(super) fn argument_words(&self) -> F {
        self.arguments
    }
    pub(super) fn result_words(&self) -> F {
        self.results
    }

    /// Deliberately unbound local-bank/degree inputs, never a joined relation.
    #[cfg(test)]
    pub(super) fn unbound_diagnostic(entry: [F; 4], frame: F, arguments: F, results: F) -> Self {
        Self {
            entry,
            frame,
            arguments,
            results,
        }
    }
}

mod scan_storage;
use super::private_history;
use crate::execution_proofs::ivm_step_air::residues::{Scratch, Sink, Stream};
use scan_storage::Scan;

const DESCRIPTORS: usize = 0;
const OPERANDS: usize = DESCRIPTORS + frame_descriptor::PORTS;
const RESULT_START: usize = OPERANDS + return_copyback::OPERAND_PORTS;
const RESULT_END: usize = RESULT_START + 1;
/// Fixed original ports exclude every per-cell initialization/copyback packet.
pub(super) const EXTRA_PORTS: usize = RESULT_END + 1;
pub(super) const FIXED_PORTS: usize = private_dispatch::PORTS + EXTRA_PORTS;
/// Original producers, each owned once; reserved gaps are separately zero.
pub(super) const PORTS: usize = FIXED_PORTS + 2 * return_copyback::CELLS;
pub(super) const SELECTORS: usize = CAPACITY;
pub(super) const MAXIMUM_DEGREE: u8 = 4;
const SCAN_START: usize = 100;
/// The existing fixed geometry includes 54 mandatory inactive clock slots.
pub(super) const CLOCK_SLOTS: usize = SCAN_START + 2 * return_copyback::CELLS + 3;

#[derive(Clone, Copy)]
pub(super) struct Schedule {
    vm: u8,
    first: u32,
    dispatch: private_dispatch::Schedule,
    descriptor: frame_descriptor::Schedule,
    operands: return_copyback::OperandSchedule,
    clocks: [u32; FIXED_PORTS],
}
impl Schedule {
    pub(super) fn new(vm: u8, first: u32) -> Option<Self> {
        first.checked_add(CLOCK_SLOTS as u32)?;
        let scan_end = SCAN_START as u32 + (2 * return_copyback::CELLS - 1) as u32;
        let dispatch_offsets = [
            0,
            1,
            2,
            3,
            4,
            5,
            30,
            31,
            32,
            45,
            46,
            47,
            48,
            49,
            50,
            51,
            52,
            53,
            scan_end + 1,
            scan_end + 2,
            scan_end + 3,
        ];
        let descriptor_offsets = [
            6, 7, 8, 9, 10, 11, 12, 13, 14, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44,
        ];
        let mut clocks = [0; FIXED_PORTS];
        let (dispatch, extra) = clocks.split_at_mut(private_dispatch::PORTS);
        dispatch.copy_from_slice(&dispatch_offsets.map(|offset| first + offset));
        extra[..frame_descriptor::PORTS]
            .copy_from_slice(&descriptor_offsets.map(|offset| first + offset));
        for (index, offset) in [15, 16, 17, 18, 19, 20, 21].into_iter().enumerate() {
            extra[OPERANDS + index] = first + offset;
        }
        Some(Self {
            vm,
            first,
            dispatch: private_dispatch::Schedule::new(vm, (&*dispatch).try_into().unwrap())?,
            descriptor: frame_descriptor::Schedule::new(
                vm,
                false,
                extra[..frame_descriptor::PORTS].try_into().unwrap(),
            )?,
            operands: return_copyback::OperandSchedule::new(
                vm,
                extra[OPERANDS..RESULT_START].try_into().unwrap(),
            )?,
            clocks,
        })
    }
    fn scans(&self) -> impl ExactSizeIterator<Item = return_copyback::Schedule> {
        return_copyback::schedules(
            self.vm,
            [
                self.first + 46,
                self.first + 47,
                self.first + 20,
                self.first + 21,
            ],
            self.first + SCAN_START as u32,
        )
        .expect("validated fixed scan geometry")
    }
    /// No private selector can omit a slot or move a producer to another clock.
    fn producer_at_clock<'a>(
        &self,
        packets: &'a OriginalPackets,
        offset: usize,
    ) -> &'a [F; packet::WIDTH] {
        if (SCAN_START..SCAN_START + 2 * return_copyback::CELLS).contains(&offset) {
            let index = offset - SCAN_START;
            let cell = packets.scan.get(index / 2);
            return if index % 2 == 0 {
                &cell.child
            } else {
                &cell.copyback
            };
        }
        if let Some(index) = self
            .clocks
            .iter()
            .position(|clock| *clock == self.first + offset as u32)
        {
            return packets.producer(index).expect("fixed producer");
        }
        assert!(offset < CLOCK_SLOTS);
        &[F::ZERO; packet::WIDTH]
    }
}

/// Sole original packet and scan backing. Shared lifecycle ports are borrowed.
pub(super) struct OriginalPackets {
    dispatch: private_dispatch::OriginalPackets,
    extra: [[F; packet::WIDTH]; EXTRA_PORTS],
    scan: Scan,
}
impl OriginalPackets {
    pub(super) fn candidate(
        dispatch: private_dispatch::OriginalPackets,
        extra: [[F; packet::WIDTH]; EXTRA_PORTS],
        scan: Scan,
    ) -> Self {
        Self {
            dispatch,
            extra,
            scan,
        }
    }
    pub(super) fn producer(&self, index: usize) -> Option<&[F; packet::WIDTH]> {
        if index < private_dispatch::PORTS {
            self.dispatch.producer(index)
        } else if index < FIXED_PORTS {
            self.extra.get(index - private_dispatch::PORTS)
        } else if index < PORTS {
            let index = index - FIXED_PORTS;
            let cell = self.scan.get(index / 2);
            Some(if index % 2 == 0 {
                &cell.child
            } else {
                &cell.copyback
            })
        } else {
            None
        }
    }
}
impl Drop for OriginalPackets {
    fn drop(&mut self) {
        for packet in &mut self.extra {
            for field in packet {
                field.zeroize_v1();
            }
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct Witness<'a> {
    pub(super) dispatch: &'a [F; private_dispatch::WIDTH],
    pub(super) descriptor: &'a [F; frame_descriptor::WIDTH],
    pub(super) returning: &'a [F; SELECTORS],
}

/// Fixed row identity for streamed equation batches, never a private selector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Row {
    Control,
    Scan(usize),
    History(usize),
}
#[derive(Debug, PartialEq, Eq)]
pub(super) enum EvaluationError<E> {
    History(private_history::ShapeError),
    Consumer(E),
}

fn append_control_residues<'a>(
    out: &mut impl Sink,
    program: &private_dispatch::Program,
    schedule: &Schedule,
    witness: Witness<'_>,
    packets: &'a OriginalPackets,
) -> private_dispatch::Decoded<'a> {
    let decoded = private_dispatch::append_residues(
        out,
        program,
        schedule.dispatch,
        witness.dispatch,
        &packets.dispatch,
    );
    let callables = program.callables();
    let (child, selected, absolute) = callables.select_child(program.fetch(witness.dispatch));
    out.push(selected.sub(decoded.child));
    for (target, absolute) in decoded.target.iter().zip(absolute) {
        out.push(decoded.child.mul(*target).sub(absolute));
    }
    frame_descriptor::append_residues(
        out,
        schedule.descriptor,
        witness.descriptor,
        decoded.child,
        &child,
        frame_descriptor::Ports {
            active: decoded.child_active,
            packets: core::array::from_fn(|index| &packets.extra[DESCRIPTORS + index]),
        },
    );
    let mut returned = SelectedCallable::zero();
    let mut selected = F::ZERO;
    for (index, &selector) in witness.returning.iter().enumerate() {
        out.push(bit(selector));
        if index < callables.len {
            returned.include(selector, callables.entries[index]);
            selected = selected.add(selector);
        } else {
            out.push(selector);
        }
    }
    out.push(selected.sub(decoded.returning));
    // This is the same original Owner[11] read whose generation/header is
    // constrained below, not the return continuation in the PC write packet.
    for (index, &entry) in returned.entry_pc().iter().enumerate() {
        out.push(packets.extra[OPERANDS + 4][BEFORE + index].sub(entry));
    }
    return_copyback::append_operand_residues(
        out,
        schedule.operands,
        &packets.scan.get(0).row,
        &returned,
        return_copyback::OperandPorts {
            active: decoded.return_active,
            packets: core::array::from_fn(|index| &packets.extra[OPERANDS + index]),
        },
    );
    decoded
}

fn evaluate_scan<E>(
    schedule: &Schedule,
    decoded: &private_dispatch::Decoded<'_>,
    packets: &OriginalPackets,
    scratch: &mut Scratch,
    consume: &mut impl FnMut(Row, &[F]) -> Result<(), E>,
) -> Result<(), E> {
    for (index, cell_schedule) in schedule.scans().enumerate() {
        let cell = packets.scan.get(index);
        let mut emit = |values: &[F]| consume(Row::Scan(index), values);
        let mut out = Stream::new(scratch, &mut emit);
        return_copyback::append_residues(
            &mut out,
            cell_schedule,
            &cell.row,
            return_copyback::Ports {
                active: decoded.return_active,
                parent: decoded.return_parent,
                result_start: &packets.extra[RESULT_START],
                result_end: &packets.extra[RESULT_END],
                child: &cell.child,
                copyback: &cell.copyback,
            },
        );
        debug_assert_eq!(out.len(), return_copyback::CONSTRAINTS);
        out.finish()?;
    }
    Ok(())
}

/// Complete fixed scan and original-clock window consistency. Every original
/// packet joins its actual global history slot, including the reserved zeros.
/// This does not authenticate rows outside the window or initialize an invocation.
pub(super) fn evaluate<E>(
    program: &private_dispatch::Program,
    schedule: &Schedule,
    witness: Witness<'_>,
    packets: &OriginalPackets,
    history: &private_history::View<'_>,
    mut consume: impl FnMut(Row, &[F]) -> Result<(), E>,
) -> Result<(), EvaluationError<E>> {
    history
        .contains_window(schedule.first, CLOCK_SLOTS)
        .map_err(EvaluationError::History)?;
    let mut scratch = Scratch::new();
    let mut emit = |values: &[F]| consume(Row::Control, values);
    let mut out = Stream::new(&mut scratch, &mut emit);
    let decoded = append_control_residues(&mut out, program, schedule, witness, packets);
    out.finish().map_err(EvaluationError::Consumer)?;
    evaluate_scan(schedule, &decoded, packets, &mut scratch, &mut consume)
        .map_err(EvaluationError::Consumer)?;
    for offset in 0..CLOCK_SLOTS {
        let producer = schedule.producer_at_clock(packets, offset);
        for phase in 0..super::PHASES {
            let index = (schedule.first as usize + offset) * super::PHASES + phase;
            let mut emit = |values: &[F]| consume(Row::History(index), values);
            let mut out = Stream::new(&mut scratch, &mut emit);
            history.append_row(&mut out, index, producer);
            debug_assert_eq!(out.len(), super::CONSTRAINTS);
            out.finish().map_err(EvaluationError::Consumer)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
