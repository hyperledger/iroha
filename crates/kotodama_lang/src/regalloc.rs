//! Linear-scan register allocator and stack frame layout for Kotodama IR.
use super::ir::{BasicBlock, Function, Instr, Label, Temp, Terminator};
use std::{
    cmp::Reverse,
    collections::{BTreeMap, BTreeSet, BinaryHeap, HashMap, HashSet},
};
mod dead_operands;
mod rematerialized;
#[cfg(test)]
pub(crate) use dead_operands::with_conservative_host_operands;
#[cfg(test)]
pub(crate) use rematerialized::with_literal_homes;

/// Physical homes of a function's materialized temporaries.
/// Numeric literal references whose every use reloads the canonical literal
/// table have no home; their IR and literal validation remain intact.
#[derive(Debug, PartialEq)]
pub struct Allocation {
    /// Mapping from IR temporaries to physical registers.
    pub regs: HashMap<Temp, usize>,
    /// Mapping from spilled temporaries to stack offsets.
    pub stack: HashMap<Temp, usize>,
    /// Total frame size in bytes (16-byte aligned).
    pub frame_size: usize,
}
/// One register-resident slice of a temporary whose canonical home is a spill slot.
///
/// Split segments are read-only: code generation reloads the spill slot at
/// `start`, uses `register` through `end`, and keeps every definition writing
/// the canonical stack home. This makes control-flow joins and loop-carried
/// multi-definition temporaries safe without inserting edge copies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SplitSegment {
    temp: Temp,
    register: usize,
    start: usize,
    end: usize,
    use_count: usize,
}
/// Reload scheduled at the beginning of a split live segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SplitReload {
    /// Spilled temporary whose canonical stack home is reloaded.
    pub(crate) temp: Temp,
    /// Physical register holding this segment.
    pub(crate) register: usize,
}
/// Internal code-generation plan combining stable stack homes with split ranges.
///
/// The public [`Allocation`] shape remains the canonical home-location view.
/// Code generation uses this plan to give frequently reused spilled values a
/// deterministic second chance at a register after peak pressure has passed.
#[derive(Debug, PartialEq)]
pub(crate) struct AllocationPlan {
    home: Allocation,
    segments: HashMap<Temp, Vec<SplitSegment>>,
    reloads: BTreeMap<usize, Vec<SplitReload>>,
}
impl std::ops::Deref for AllocationPlan {
    type Target = Allocation;
    fn deref(&self) -> &Self::Target {
        &self.home
    }
}
impl AllocationPlan {
    /// Return the register containing `temp` at a source-use position.
    pub(crate) fn register_for_use(&self, temp: Temp, position: usize) -> Option<usize> {
        if let Some(segments) = self.segments.get(&temp) {
            let insertion = segments.partition_point(|segment| segment.start <= position);
            if let Some(segment) = insertion
                .checked_sub(1)
                .and_then(|index| segments.get(index))
                && position <= segment.end
            {
                return Some(segment.register);
            }
        }
        self.home.regs.get(&temp).copied()
    }
    /// Return deterministic spill reloads required before `position` executes.
    pub(crate) fn reloads_at(&self, position: usize) -> &[SplitReload] {
        self.reloads.get(&position).map_or(&[], Vec::as_slice)
    }
    /// Return every physical register used by a home or split interval.
    pub(crate) fn used_registers(&self) -> Vec<usize> {
        let mut registers = self.home.regs.values().copied().collect::<BTreeSet<_>>();
        for segments in self.segments.values() {
            registers.extend(segments.iter().map(|segment| segment.register));
        }
        registers.into_iter().collect()
    }
    #[cfg(test)]
    fn split_segments(&self, temp: Temp) -> &[SplitSegment] {
        self.segments.get(&temp).map_or(&[], Vec::as_slice)
    }
    #[cfg(test)]
    pub(crate) fn first_split_register(&self, temp: Temp) -> Option<usize> {
        self.segments
            .get(&temp)
            .and_then(|segments| segments.first())
            .map(|segment| segment.register)
    }
    #[cfg(test)]
    fn saved_reload_count(&self) -> usize {
        self.segments
            .values()
            .flatten()
            .map(|segment| segment.use_count.saturating_sub(1))
            .sum()
    }
}
/// Registers r10-r22 are clobbered by calls, syscalls, and fixed-register operations.
pub const CALLER_CLOBBERED_REGS: [usize; 13] = [10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22];
/// Maximum number of recursively flattened argument words in the V1 call ABI.
pub const MAX_ARGUMENT_VALUES: usize = ivm_abi::call::MAX_CALL_WORDS_V1;
/// r10 carries a syscall result or a completed call-table address.
pub const RET_REG: usize = 10;
/// ABI limit for flattened values in a result table.
pub const MAX_RETURN_VALUES: usize = ivm_abi::call::MAX_CALL_WORDS_V1;
/// r31 acts as the stack pointer.
pub const SP_REG: usize = 31;
// Pool of allocatable registers (see policy above)
const ALLOC_POOL: &[usize] = &[2, 3, 4, 5, 6, 7, 8, 9, 23, 24];
#[derive(Clone, Copy, Debug)]
struct Interval {
    temp: Temp,
    start: usize,
    end: usize,
}
fn instruction_preserves_argument_registers(instruction: &Instr) -> bool {
    matches!(
        instruction,
        Instr::Const { .. }
            | Instr::StringConst { .. }
            | Instr::DataRef { .. }
            | Instr::LoadVar { .. }
            | Instr::Copy { .. }
            | Instr::TuplePack { .. }
            | Instr::TupleGet { .. }
            | Instr::Binary { .. }
            | Instr::WrappingBinary { .. }
            | Instr::Unary { .. }
            | Instr::WrappingNeg { .. }
            | Instr::Min { .. }
            | Instr::Max { .. }
            | Instr::Abs { .. }
            | Instr::DivCeil { .. }
            | Instr::Gcd { .. }
            | Instr::Mean { .. }
            | Instr::Isqrt { .. }
            | Instr::Poseidon2 { .. }
            | Instr::Pubkgen { .. }
            | Instr::Valcom { .. }
            | Instr::PointerFromString { .. }
            | Instr::Load64Imm { .. }
            | Instr::Load64 { .. }
            | Instr::Store64Imm { .. }
            | Instr::Store64 { .. }
            | Instr::MapLoadPair { .. }
            | Instr::MapGet { .. }
            | Instr::MapSet { .. }
    )
}
#[derive(Debug)]
struct ArgumentRegisterClobber {
    position: usize,
    operands_staged_before_clobber: bool,
    uses: HashSet<Temp>,
    /// Temps whose current values are needed after this instruction on a
    /// control-flow path, including fields carried by virtual tuples.
    live_across: HashSet<Temp>,
}
fn update_tuple_definitions(tuple_defs: &mut HashMap<Temp, Vec<Temp>>, instruction: &Instr) {
    match instruction {
        Instr::TuplePack { dest, items } => {
            tuple_defs.insert(*dest, items.clone());
        }
        Instr::Copy { dest, src } => {
            if let Some(items) = tuple_defs.get(src).cloned() {
                tuple_defs.insert(*dest, items);
            } else {
                tuple_defs.remove(dest);
            }
        }
        Instr::TupleGet { dest, tuple, index } => {
            let child_items = tuple_defs
                .get(tuple)
                .and_then(|items| items.get(*index))
                .and_then(|item| tuple_defs.get(item))
                .cloned();
            if let Some(items) = child_items {
                tuple_defs.insert(*dest, items);
            } else {
                tuple_defs.remove(dest);
            }
        }
        _ => {}
    }
}
fn extend_virtual_tuple_liveness(live: &mut HashSet<Temp>, tuple_defs: &HashMap<Temp, Vec<Temp>>) {
    let mut pending = live.iter().copied().collect::<Vec<_>>();
    while let Some(tuple) = pending.pop() {
        if let Some(items) = tuple_defs.get(&tuple) {
            for item in items {
                if live.insert(*item) {
                    pending.push(*item);
                }
            }
        }
    }
}
fn collect_argument_register_clobbers(function: &Function) -> Vec<ArgumentRegisterClobber> {
    let mut label_to_idx = HashMap::with_capacity(function.blocks.len());
    for (idx, block) in function.blocks.iter().enumerate() {
        label_to_idx.insert(block.label, idx);
    }
    let mut tuple_defs = HashMap::new();
    let mut block_uses = Vec::with_capacity(function.blocks.len());
    let mut block_defs = Vec::with_capacity(function.blocks.len());
    let mut block_succs = Vec::with_capacity(function.blocks.len());
    for block in &function.blocks {
        for instruction in &block.instrs {
            update_tuple_definitions(&mut tuple_defs, instruction);
        }
        let (uses, defs) = block_uses_defs(block);
        block_uses.push(uses);
        block_defs.push(defs);
        block_succs.push(block_successors(block, &label_to_idx));
    }
    let (_, live_out) = compute_liveness(&block_uses, &block_defs, &block_succs);
    let mut clobbers = Vec::new();
    let mut position = 0usize;
    let mut block_starts = Vec::with_capacity(function.blocks.len());
    for block in &function.blocks {
        block_starts.push(position);
        position = position.saturating_add(block.instrs.len().saturating_add(1));
    }
    for (block_idx, block) in function.blocks.iter().enumerate() {
        let mut live = live_out[block_idx].clone();
        visit_terminator_uses(&block.terminator, |temp| {
            live.insert(temp);
        });
        for (instruction_idx, instruction) in block.instrs.iter().enumerate().rev() {
            let position = block_starts[block_idx].saturating_add(instruction_idx);
            let mut uses = HashSet::new();
            visit_instr_uses(instruction, |temp| {
                uses.insert(temp);
            });
            let mut defs = HashSet::new();
            visit_instr_defs(instruction, |temp| {
                defs.insert(temp);
            });
            if !instruction_preserves_argument_registers(instruction) {
                let mut live_across = live.difference(&defs).copied().collect();
                extend_virtual_tuple_liveness(&mut live_across, &tuple_defs);
                clobbers.push(ArgumentRegisterClobber {
                    position,
                    operands_staged_before_clobber: dead_operands::operands_staged_before_clobber(
                        instruction,
                    ),
                    uses: uses.clone(),
                    live_across,
                });
            }
            for temp in defs {
                live.remove(&temp);
            }
            live.extend(uses);
        }
    }
    clobbers.sort_unstable_by_key(|clobber| clobber.position);
    clobbers
}
fn interval_can_use_argument_registers(
    interval: Interval,
    clobbers: &[ArgumentRegisterClobber],
) -> bool {
    clobbers.iter().all(|clobber| {
        !clobber.live_across.contains(&interval.temp)
            && (clobber.operands_staged_before_clobber || !clobber.uses.contains(&interval.temp))
    })
}
fn reload_range_survives_clobber(
    start: usize,
    end: usize,
    clobbers: &[ArgumentRegisterClobber],
) -> bool {
    clobbers
        .iter()
        .any(|clobber| start <= clobber.position && clobber.position < end)
}
fn split_candidate_can_use_argument_registers(
    candidate: SplitCandidate,
    clobbers: &[ArgumentRegisterClobber],
) -> bool {
    !reload_range_survives_clobber(candidate.start, candidate.end, clobbers)
        && clobbers.iter().all(|clobber| {
            clobber.operands_staged_before_clobber
                || !clobber.uses.contains(&candidate.temp)
                || clobber.position < candidate.start
                || candidate.end < clobber.position
        })
}
/// Whether a direct function call can overwrite the return-address register.
pub(crate) fn has_internal_calls(function: &Function) -> bool {
    function.blocks.iter().any(|block| {
        block
            .instrs
            .iter()
            .any(|instruction| matches!(instruction, Instr::Call { .. } | Instr::CallMulti { .. }))
    })
}
/// Allocate registers for a function using a single-pass linear scan.
pub fn allocate(func: &Function) -> Allocation {
    let intervals = collect_live_intervals(func);
    allocate_intervals(func, &intervals)
}
/// Allocate canonical homes, then fill post-pressure register holes with
/// read-only slices of frequently reused spills.
pub(crate) fn allocate_with_splitting(func: &Function) -> AllocationPlan {
    let intervals = collect_live_intervals(func);
    let home = allocate_intervals(func, &intervals);
    let split_segments = build_split_segments(func, &intervals, &home);
    let mut segments: HashMap<Temp, Vec<SplitSegment>> = HashMap::new();
    let mut reloads: BTreeMap<usize, Vec<SplitReload>> = BTreeMap::new();
    for segment in split_segments {
        segments.entry(segment.temp).or_default().push(segment);
        reloads.entry(segment.start).or_default().push(SplitReload {
            temp: segment.temp,
            register: segment.register,
        });
    }
    for temp_segments in segments.values_mut() {
        temp_segments.sort_unstable_by_key(|segment| (segment.start, segment.end));
    }
    for position_reloads in reloads.values_mut() {
        position_reloads.sort_unstable_by_key(|reload| (reload.register, reload.temp.0));
    }
    if crate::dev_env::debug_regalloc_enabled() {
        let mut ordered = segments.values().flatten().copied().collect::<Vec<_>>();
        ordered.sort_unstable_by_key(|segment| (segment.start, segment.temp.0, segment.register));
        for segment in ordered {
            eprintln!(
                "  split {:?} start {} end {} uses {} => reg {}",
                segment.temp, segment.start, segment.end, segment.use_count, segment.register
            );
        }
    }
    AllocationPlan {
        home,
        segments,
        reloads,
    }
}
fn collect_live_intervals(func: &Function) -> Vec<Interval> {
    let mut intervals: HashMap<Temp, Interval> = HashMap::new();
    let mut tuple_defs: HashMap<Temp, Vec<Temp>> = HashMap::new();
    let mut position: usize = 0;
    let block_count = func.blocks.len();
    let mut label_to_idx: HashMap<Label, usize> = HashMap::new();
    for (idx, block) in func.blocks.iter().enumerate() {
        label_to_idx.insert(block.label, idx);
    }
    let mut block_uses: Vec<HashSet<Temp>> = Vec::with_capacity(block_count);
    let mut block_defs: Vec<HashSet<Temp>> = Vec::with_capacity(block_count);
    let mut block_succs: Vec<Vec<usize>> = Vec::with_capacity(block_count);
    for block in &func.blocks {
        let (uses, defs) = block_uses_defs(block);
        block_uses.push(uses);
        block_defs.push(defs);
        block_succs.push(block_successors(block, &label_to_idx));
    }
    let (live_in, _live_out) = compute_liveness(&block_uses, &block_defs, &block_succs);
    let mut block_end_pos: Vec<usize> = Vec::with_capacity(block_count);
    for block in &func.blocks {
        for instr in &block.instrs {
            visit_instr_uses(instr, |temp| add_use(&mut intervals, temp, position));
            visit_instr_defs(instr, |dest| add_def(&mut intervals, dest, position));
            update_tuple_definitions(&mut tuple_defs, instr);
            position = position.saturating_add(1);
        }
        visit_terminator_uses(&block.terminator, |temp| {
            add_use(&mut intervals, temp, position)
        });
        block_end_pos.push(position);
        position = position.saturating_add(1);
    }
    for (block_idx, succs) in block_succs.iter().enumerate() {
        for &succ in succs {
            if succ <= block_idx {
                let end_pos = block_end_pos[block_idx];
                for temp in &live_in[succ] {
                    intervals
                        .entry(*temp)
                        .and_modify(|iv| {
                            if iv.end < end_pos {
                                iv.end = end_pos;
                            }
                        })
                        .or_insert(Interval {
                            temp: *temp,
                            start: end_pos,
                            end: end_pos,
                        });
                }
            }
        }
    }
    extend_tuple_intervals(&mut intervals, &tuple_defs);
    let mut interval_list: Vec<Interval> = intervals.values().copied().collect();
    let rematerialized = rematerialized::numeric_literal_homes(func);
    interval_list.retain(|interval| !rematerialized.contains(&interval.temp));
    interval_list.sort_by_key(|iv| (iv.start, iv.temp.0));
    interval_list
}
fn register_allowed_for_interval(register: usize, can_use_argument_register: bool) -> bool {
    ALLOC_POOL.contains(&register)
        || can_use_argument_register && CALLER_CLOBBERED_REGS.contains(&register)
}
fn take_preferred_free_register(
    free_registers: &mut Vec<usize>,
    can_use_argument_register: bool,
) -> Option<usize> {
    let preferred = CALLER_CLOBBERED_REGS
        .iter()
        .rev()
        .filter(|_| can_use_argument_register)
        .chain(ALLOC_POOL.iter().rev());
    for register in preferred.copied() {
        if let Some(index) = free_registers
            .iter()
            .position(|candidate| *candidate == register)
        {
            return Some(free_registers.swap_remove(index));
        }
    }
    None
}
fn allocate_intervals(func: &Function, interval_list: &[Interval]) -> Allocation {
    let mut allocation = Allocation {
        regs: HashMap::new(),
        stack: HashMap::new(),
        frame_size: 0,
    };
    let clobbers = collect_argument_register_clobbers(func);
    let argument_register_temps = interval_list
        .iter()
        .copied()
        .filter(|interval| interval_can_use_argument_registers(*interval, &clobbers))
        .map(|interval| interval.temp)
        .collect::<HashSet<_>>();
    let mut active: Vec<(usize, Temp, usize)> = Vec::new();
    let mut free_regs = ALLOC_POOL
        .iter()
        .chain(CALLER_CLOBBERED_REGS.iter())
        .copied()
        .collect::<Vec<_>>();
    let mut spilled = HashSet::new();
    for interval in interval_list.iter().copied() {
        expire_old_intervals(interval.start, &mut active, &mut free_regs);
        let can_use_argument_register = argument_register_temps.contains(&interval.temp);
        if let Some(reg) = take_preferred_free_register(&mut free_regs, can_use_argument_register) {
            allocation.regs.insert(interval.temp, reg);
            active.push((interval.end, interval.temp, reg));
            active.sort_by_key(|(end, _, _)| *end);
            continue;
        }
        if let Some((idx, _, _, _)) = active
            .iter()
            .enumerate()
            .filter_map(|(index, (end, temp, register))| {
                register_allowed_for_interval(*register, can_use_argument_register)
                    .then_some((index, *end, *temp, *register))
            })
            .max_by_key(|(_, end, temp, register)| (*end, temp.0, *register))
        {
            let (spill_end, spill_temp, spill_reg) = active[idx];
            if spill_end > interval.end {
                spilled.insert(spill_temp);
                allocation.regs.remove(&spill_temp);
                active.remove(idx);
                allocation.regs.insert(interval.temp, spill_reg);
                active.push((interval.end, interval.temp, spill_reg));
                active.sort_by_key(|(end, _, _)| *end);
                continue;
            }
        }
        spilled.insert(interval.temp);
    }
    let (stack, mut next_slot) = assign_spill_slots(interval_list, &spilled);
    allocation.stack = stack;
    if !next_slot.is_multiple_of(16) {
        next_slot += 16 - (next_slot % 16);
    }
    allocation.frame_size = next_slot;
    if crate::dev_env::debug_regalloc_enabled() {
        eprintln!(
            "[regalloc] function {} frame {}",
            func.name, allocation.frame_size
        );
        for interval in interval_list {
            let reg = allocation.regs.get(&interval.temp).copied();
            let stack = allocation.stack.get(&interval.temp).copied();
            eprintln!(
                "  temp {:?} start {} end {} => reg {:?} stack {:?}",
                interval.temp, interval.start, interval.end, reg, stack
            );
        }
    }
    allocation
}
const MAX_SPLIT_USE_GAP: usize = 8;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SplitCandidate {
    temp: Temp,
    start: usize,
    end: usize,
    use_count: usize,
}
fn ranges_overlap(
    left_start: usize,
    left_end: usize,
    right_start: usize,
    right_end: usize,
) -> bool {
    left_start <= right_end && right_start <= left_end
}
fn split_candidate_uses<F: FnMut(Temp)>(instruction: &Instr, mut visit: F) {
    match instruction {
        Instr::Binary { left, right, .. }
        | Instr::WrappingBinary { left, right, .. }
        | Instr::NumericBinary { left, right, .. }
        | Instr::NumericCompare { left, right, .. } => {
            visit(*left);
            visit(*right);
        }
        Instr::NumericRound {
            dividend,
            multiplier,
            divisor,
            scale,
            mode,
            ..
        } => {
            visit(*dividend);
            if let Some(multiplier) = multiplier {
                visit(*multiplier);
            }
            visit(*divisor);
            visit(*scale);
            visit(*mode);
        }
        Instr::Unary { operand, .. } | Instr::WrappingNeg { operand, .. } => visit(*operand),
        Instr::IntFromI64 { value, .. }
        | Instr::IntFromU64 { value, .. }
        | Instr::IntToI64 { value, .. }
        | Instr::IntToU64 { value, .. }
        | Instr::NumericConvert { value, .. }
        | Instr::NumericTryConvert { value, .. }
        | Instr::NumericNeg { value, .. } => visit(*value),
        Instr::DecimalToInt { value, mode, .. } => {
            visit(*value);
            if let Some(mode) = mode {
                visit(*mode);
            }
        }
        Instr::Min { a, b, .. }
        | Instr::Max { a, b, .. }
        | Instr::Gcd { a, b, .. }
        | Instr::Mean { a, b, .. }
        | Instr::Poseidon2 { a, b, .. } => {
            visit(*a);
            visit(*b);
        }
        Instr::DivCeil { num, denom, .. } => {
            visit(*num);
            visit(*denom);
        }
        Instr::Abs { src, .. }
        | Instr::Isqrt { src, .. }
        | Instr::Pubkgen { src, .. }
        | Instr::Load64Imm { base: src, .. } => visit(*src),
        Instr::Load64 { address, .. } => visit(*address),
        Instr::Store64Imm { base, value, .. } => {
            visit(*base);
            visit(*value);
        }
        Instr::Store64 { address, value } => {
            visit(*address);
            visit(*value);
        }
        Instr::Poseidon6 { args, .. } => {
            for temp in args {
                visit(*temp);
            }
        }
        Instr::Valcom { value, blind, .. } | Instr::PrivateNumericValcom { value, blind, .. } => {
            visit(*value);
            visit(*blind);
        }
        Instr::DirectHelperSyscall { args, .. }
        | Instr::Call { args, .. }
        | Instr::CallMulti { args, .. } => {
            for temp in args {
                visit(*temp);
            }
        }
        Instr::CoreQueryGet { key, .. } => visit(*key),
        Instr::StateScan {
            base, after, limit, ..
        } => {
            visit(*base);
            visit(*after);
            visit(*limit);
        }
        Instr::CoreQueryPage {
            account,
            offset,
            limit,
            ..
        } => {
            if let Some(account) = account {
                visit(*account);
            }
            visit(*offset);
            visit(*limit);
        }
        Instr::MapGet { map, key, .. } => {
            visit(*map);
            visit(*key);
        }
        Instr::MapLoadPair { map, .. } => visit(*map),
        Instr::MapSet { map, key, value } => {
            visit(*map);
            visit(*key);
            visit(*value);
        }
        _ => {}
    }
}
fn split_candidate_terminator_uses<F: FnMut(Temp)>(terminator: &Terminator, mut visit: F) {
    match terminator {
        Terminator::Return(Some(temp)) => visit(*temp),
        Terminator::Return(None) | Terminator::Jump(_) => {}
        Terminator::Return2(left, right) => {
            visit(*left);
            visit(*right);
        }
        Terminator::ReturnN(values) => {
            for temp in values {
                visit(*temp);
            }
        }
        Terminator::Branch { cond, .. } => visit(*cond),
    }
}
fn fused_relational_operands(block: &BasicBlock) -> Option<(Temp, Temp)> {
    let Terminator::Branch { cond, .. } = &block.terminator else {
        return None;
    };
    let Some(Instr::Binary {
        dest,
        op,
        left,
        right,
    }) = block.instrs.last()
    else {
        return None;
    };
    if *dest == *cond
        && matches!(
            op,
            super::ast::BinaryOp::Lt
                | super::ast::BinaryOp::Le
                | super::ast::BinaryOp::Gt
                | super::ast::BinaryOp::Ge
        )
    {
        Some((*left, *right))
    } else {
        None
    }
}
fn push_split_clusters(
    candidates: &mut Vec<SplitCandidate>,
    temp: Temp,
    positions: &[usize],
    clobbers: &[ArgumentRegisterClobber],
) {
    let mut cluster_start = 0usize;
    while cluster_start < positions.len() {
        let mut cluster_end = cluster_start + 1;
        while cluster_end < positions.len()
            && positions[cluster_end].saturating_sub(positions[cluster_end - 1])
                <= MAX_SPLIT_USE_GAP
            && !reload_range_survives_clobber(
                positions[cluster_start],
                positions[cluster_end],
                clobbers,
            )
        {
            cluster_end += 1;
        }
        let cluster = &positions[cluster_start..cluster_end];
        if cluster.len() >= 2 {
            candidates.push(SplitCandidate {
                temp,
                start: cluster[0],
                end: cluster[cluster.len() - 1],
                use_count: cluster.len(),
            });
        }
        cluster_start = cluster_end;
    }
}
fn collect_split_candidates(func: &Function, home: &Allocation) -> Vec<SplitCandidate> {
    let mut candidates = Vec::new();
    let mut position = 0usize;
    let clobbers = collect_argument_register_clobbers(func);
    // Literal-like values may be materialized directly by code generation, so
    // their nominal IR use count is not proof of repeated spill traffic. Leave
    // them to the rematerialization paths instead of scheduling speculative
    // stack reads.
    let instructions = func
        .blocks
        .iter()
        .flat_map(|block| &block.instrs)
        .collect::<Vec<_>>();
    let mut rematerializable = instructions
        .iter()
        .filter_map(|instruction| match *instruction {
            Instr::Const { dest, .. }
            | Instr::StringConst { dest, .. }
            | Instr::DataRef { dest, .. }
            | Instr::TuplePack { dest, .. } => Some(*dest),
            _ => None,
        })
        .collect::<HashSet<_>>();
    loop {
        let mut changed = false;
        for instruction in &instructions {
            match *instruction {
                Instr::Copy { dest, src } | Instr::PointerFromString { dest, src, .. }
                    if rematerializable.contains(src) =>
                {
                    changed |= rematerializable.insert(*dest);
                }
                _ => {}
            }
        }
        if !changed {
            break;
        }
    }
    for block in &func.blocks {
        // A generation boundary after every definition prevents a read-only
        // segment from observing a stale register value after its stack home
        // has been updated. Generations reset at block boundaries so every
        // control-flow path reloads independently.
        let mut generation = HashMap::<Temp, usize>::new();
        let mut uses = HashMap::<(Temp, usize), Vec<usize>>::new();
        let fused = fused_relational_operands(block);
        for (instruction_index, instruction) in block.instrs.iter().enumerate() {
            let is_fused_compare = fused.is_some() && instruction_index + 1 == block.instrs.len();
            if !is_fused_compare {
                split_candidate_uses(instruction, |temp| {
                    if home.stack.contains_key(&temp) && !rematerializable.contains(&temp) {
                        let epoch = generation.get(&temp).copied().unwrap_or(0);
                        uses.entry((temp, epoch)).or_default().push(position);
                    }
                });
            }
            visit_instr_defs(instruction, |temp| {
                let epoch = generation.entry(temp).or_default();
                *epoch = epoch.saturating_add(1);
            });
            position = position.saturating_add(1);
        }
        if let Some((left, right)) = fused {
            for temp in [left, right] {
                if home.stack.contains_key(&temp) && !rematerializable.contains(&temp) {
                    let epoch = generation.get(&temp).copied().unwrap_or(0);
                    uses.entry((temp, epoch)).or_default().push(position);
                }
            }
        } else {
            split_candidate_terminator_uses(&block.terminator, |temp| {
                if home.stack.contains_key(&temp) && !rematerializable.contains(&temp) {
                    let epoch = generation.get(&temp).copied().unwrap_or(0);
                    uses.entry((temp, epoch)).or_default().push(position);
                }
            });
        }
        position = position.saturating_add(1);
        let mut block_uses = uses.into_iter().collect::<Vec<_>>();
        block_uses.sort_unstable_by_key(|((temp, epoch), _)| (temp.0, *epoch));
        for ((temp, _), positions) in block_uses {
            push_split_clusters(&mut candidates, temp, &positions, &clobbers);
        }
    }
    candidates
}
fn build_split_segments(
    func: &Function,
    intervals: &[Interval],
    home: &Allocation,
) -> Vec<SplitSegment> {
    if home.stack.is_empty() {
        return Vec::new();
    }
    let clobbers = collect_argument_register_clobbers(func);
    let home_registers = home.regs.values().copied().collect::<BTreeSet<_>>();
    // Reusing a preserved register that already has a home interval avoids
    // adding prologue/epilogue traffic merely to save reloads. Caller-saved
    // holes are always available to clobber-local segments.
    let preserved_register_pool = ALLOC_POOL
        .iter()
        .rev()
        .copied()
        .filter(|register| home_registers.contains(register))
        .collect::<Vec<_>>();
    let mut occupied: HashMap<usize, Vec<(usize, usize)>> = HashMap::new();
    for interval in intervals {
        if let Some(register) = home.regs.get(&interval.temp).copied() {
            occupied
                .entry(register)
                .or_default()
                .push((interval.start, interval.end));
        }
    }
    let mut candidates = collect_split_candidates(func, home);
    candidates.sort_unstable_by(|left, right| {
        right
            .use_count
            .cmp(&left.use_count)
            .then_with(|| {
                left.end
                    .saturating_sub(left.start)
                    .cmp(&right.end.saturating_sub(right.start))
            })
            .then_with(|| left.start.cmp(&right.start))
            .then_with(|| left.temp.0.cmp(&right.temp.0))
    });
    let mut segments = Vec::new();
    for candidate in candidates {
        let can_use_argument_register =
            split_candidate_can_use_argument_registers(candidate, &clobbers);
        let register_pool = CALLER_CLOBBERED_REGS
            .iter()
            .rev()
            .filter(|_| can_use_argument_register)
            .copied()
            .chain(preserved_register_pool.iter().copied());
        let register = register_pool.into_iter().find(|register| {
            occupied.get(register).is_none_or(|ranges| {
                ranges.iter().all(|(start, end)| {
                    !ranges_overlap(candidate.start, candidate.end, *start, *end)
                })
            })
        });
        let Some(register) = register else {
            continue;
        };
        occupied
            .entry(register)
            .or_default()
            .push((candidate.start, candidate.end));
        segments.push(SplitSegment {
            temp: candidate.temp,
            register,
            start: candidate.start,
            end: candidate.end,
            use_count: candidate.use_count,
        });
    }
    segments
}
fn expire_stack_intervals(
    current_start: usize,
    active: &mut Vec<(usize, usize)>,
    free_slots: &mut BinaryHeap<Reverse<usize>>,
) {
    // `active` is kept in descending end-position order, so expired slots are
    // removed from the end without shifting the remaining entries.
    while active.last().is_some_and(|(end, _)| *end < current_start) {
        let (_, slot) = active.pop().expect("active stack entry exists");
        free_slots.push(Reverse(slot));
    }
}
fn assign_spill_slots(
    intervals: &[Interval],
    spilled: &HashSet<Temp>,
) -> (HashMap<Temp, usize>, usize) {
    let mut slots = HashMap::with_capacity(spilled.len());
    let mut active: Vec<(usize, usize)> = Vec::new();
    let mut free_slots: BinaryHeap<Reverse<usize>> = BinaryHeap::new();
    let mut next_slot = 0usize;
    for interval in intervals
        .iter()
        .filter(|interval| spilled.contains(&interval.temp))
    {
        expire_stack_intervals(interval.start, &mut active, &mut free_slots);
        let slot = free_slots.pop().map_or_else(
            || {
                let slot = next_slot;
                next_slot = next_slot.saturating_add(8);
                slot
            },
            |Reverse(slot)| slot,
        );
        slots.insert(interval.temp, slot);
        active.push((interval.end, slot));
        active.sort_unstable_by(|left, right| {
            right.0.cmp(&left.0).then_with(|| right.1.cmp(&left.1))
        });
    }
    (slots, next_slot)
}
fn extend_tuple_intervals(
    intervals: &mut HashMap<Temp, Interval>,
    tuple_defs: &HashMap<Temp, Vec<Temp>>,
) {
    fn extend_tuple_items(
        tuple: Temp,
        tuple_end: usize,
        intervals: &mut HashMap<Temp, Interval>,
        tuple_defs: &HashMap<Temp, Vec<Temp>>,
        visiting: &mut HashSet<Temp>,
    ) {
        if !visiting.insert(tuple) {
            return;
        }
        if let Some(items) = tuple_defs.get(&tuple) {
            for item in items {
                intervals
                    .entry(*item)
                    .and_modify(|iv| {
                        if iv.end < tuple_end {
                            iv.end = tuple_end;
                        }
                    })
                    .or_insert(Interval {
                        temp: *item,
                        start: tuple_end,
                        end: tuple_end,
                    });
                extend_tuple_items(*item, tuple_end, intervals, tuple_defs, visiting);
            }
        }
        visiting.remove(&tuple);
    }
    let mut visiting: HashSet<Temp> = HashSet::new();
    let tuples: Vec<(Temp, usize)> = tuple_defs
        .keys()
        .filter_map(|tuple| intervals.get(tuple).map(|iv| (*tuple, iv.end)))
        .collect();
    for (tuple, tuple_end) in tuples {
        extend_tuple_items(tuple, tuple_end, intervals, tuple_defs, &mut visiting);
    }
}
fn add_def(intervals: &mut HashMap<Temp, Interval>, temp: Temp, pos: usize) {
    intervals
        .entry(temp)
        .and_modify(|iv| {
            iv.start = iv.start.min(pos);
            iv.end = iv.end.max(pos);
        })
        .or_insert(Interval {
            temp,
            start: pos,
            end: pos,
        });
}
fn add_use(intervals: &mut HashMap<Temp, Interval>, temp: Temp, pos: usize) {
    intervals
        .entry(temp)
        .and_modify(|iv| iv.end = iv.end.max(pos))
        .or_insert(Interval {
            temp,
            start: pos,
            end: pos,
        });
}
fn expire_old_intervals(
    current_start: usize,
    active: &mut Vec<(usize, Temp, usize)>,
    free_regs: &mut Vec<usize>,
) {
    let mut idx = 0;
    while idx < active.len() {
        if active[idx].0 < current_start {
            free_regs.push(active[idx].2);
            active.remove(idx);
        } else {
            idx += 1;
        }
    }
}
fn block_uses_defs(block: &BasicBlock) -> (HashSet<Temp>, HashSet<Temp>) {
    let mut uses = HashSet::new();
    let mut defs = HashSet::new();
    for instr in &block.instrs {
        visit_instr_uses(instr, |temp| {
            if !defs.contains(&temp) {
                uses.insert(temp);
            }
        });
        visit_instr_defs(instr, |temp| {
            defs.insert(temp);
        });
    }
    visit_terminator_uses(&block.terminator, |temp| {
        if !defs.contains(&temp) {
            uses.insert(temp);
        }
    });
    (uses, defs)
}
fn block_successors(block: &BasicBlock, label_to_idx: &HashMap<Label, usize>) -> Vec<usize> {
    match block.terminator {
        Terminator::Jump(label) => label_to_idx.get(&label).copied().into_iter().collect(),
        Terminator::Branch {
            then_bb, else_bb, ..
        } => {
            let mut out = Vec::with_capacity(2);
            if let Some(idx) = label_to_idx.get(&then_bb).copied() {
                out.push(idx);
            }
            if let Some(idx) = label_to_idx.get(&else_bb).copied() {
                out.push(idx);
            }
            out
        }
        Terminator::Return(_) | Terminator::Return2(_, _) | Terminator::ReturnN(_) => Vec::new(),
    }
}
fn compute_liveness(
    block_uses: &[HashSet<Temp>],
    block_defs: &[HashSet<Temp>],
    block_succs: &[Vec<usize>],
) -> (Vec<HashSet<Temp>>, Vec<HashSet<Temp>>) {
    let block_count = block_uses.len();
    let mut live_in: Vec<HashSet<Temp>> = vec![HashSet::new(); block_count];
    let mut live_out: Vec<HashSet<Temp>> = vec![HashSet::new(); block_count];
    let mut changed = true;
    while changed {
        changed = false;
        for idx in (0..block_count).rev() {
            let mut out = HashSet::new();
            for &succ in &block_succs[idx] {
                out.extend(live_in[succ].iter().copied());
            }
            let mut in_set = block_uses[idx].clone();
            for temp in out.iter() {
                if !block_defs[idx].contains(temp) {
                    in_set.insert(*temp);
                }
            }
            if out != live_out[idx] || in_set != live_in[idx] {
                live_out[idx] = out;
                live_in[idx] = in_set;
                changed = true;
            }
        }
    }
    (live_in, live_out)
}
pub(crate) fn visit_instr_uses<F: FnMut(Temp)>(instr: &Instr, mut f: F) {
    use Instr::*;
    match instr {
        Source(_) => {}
        Const { .. }
        | StringConst { .. }
        | LoadVar { .. }
        | MapNew { .. }
        | JsonObject { .. }
        | CreateNftsForAllUsers
        | SubscriptionBill
        | SubscriptionRecordUsage
        | DataRef { .. }
        | GetAuthority { .. }
        | SysvarAuthority { .. }
        | CurrentTimeMs { .. }
        | BlockHeight { .. }
        | BlockTimeMs { .. }
        | ChainId { .. }
        | ContractAddress { .. }
        | Entrypoint { .. }
        | NumericStatus { .. }
        | GetTriggerEvent { .. }
        | ExecutionSummary { .. }
        | TransferBatchBegin
        | TransferBatchEnd
        | CommitOutput => {}
        Binary { left, right, .. } | WrappingBinary { left, right, .. } => {
            f(*left);
            f(*right);
        }
        Unary { operand, .. } | WrappingNeg { operand, .. } => f(*operand),
        IntFromI64 { value, .. }
        | IntFromU64 { value, .. }
        | IntToI64 { value, .. }
        | IntToU64 { value, .. }
        | NumericConvert { value, .. }
        | NumericTryConvert { value, .. }
        | NumericNeg { value, .. } => f(*value),
        DecimalToInt { value, mode, .. } => {
            f(*value);
            if let Some(mode) = mode {
                f(*mode);
            }
        }
        NumericBinary { left, right, .. } | NumericCompare { left, right, .. } => {
            f(*left);
            f(*right);
        }
        NumericRound {
            dividend,
            multiplier,
            divisor,
            scale,
            mode,
            ..
        } => {
            f(*dividend);
            if let Some(multiplier) = multiplier {
                f(*multiplier);
            }
            f(*divisor);
            f(*scale);
            f(*mode);
        }
        DirectHelperSyscall { args, .. } => {
            for arg in args {
                f(*arg);
            }
        }
        Min { a, b, .. } | Max { a, b, .. } | Gcd { a, b, .. } | Mean { a, b, .. } => {
            f(*a);
            f(*b);
        }
        DivCeil { num, denom, .. } => {
            f(*num);
            f(*denom);
        }
        CallContract {
            contract,
            binding,
            payload,
            ..
        } => {
            f(*contract);
            f(*binding);
            f(*payload);
        }
        InvokeEntrypointAs {
            actor,
            entrypoint,
            payload,
            ..
        }
        | InvokeEntrypointAsMulti {
            actor,
            entrypoint,
            payload,
            ..
        } => {
            if let Some(actor) = actor {
                f(*actor);
            }
            f(*entrypoint);
            f(*payload);
        }
        ExpectRejectAs {
            actor,
            entrypoint,
            payload,
            expectation,
            ..
        } => {
            f(*actor);
            f(*entrypoint);
            f(*payload);
            f(*expectation);
        }
        ActorAccount { actor, .. } | ActorPublicKey { actor, .. } => f(*actor),
        ActorSign { actor, message, .. } => {
            f(*actor);
            f(*message);
        }
        ResolveAccountAlias { alias, .. } => f(*alias),
        Abs { src, .. } => f(*src),
        Isqrt { src, .. } => f(*src),
        Poseidon2 { a, b, .. } => {
            f(*a);
            f(*b);
        }
        Poseidon6 { args, .. } => {
            for temp in args {
                f(*temp);
            }
        }
        Pubkgen { src, .. } => f(*src),
        Valcom { value, blind, .. } | PrivateNumericValcom { value, blind, .. } => {
            f(*value);
            f(*blind);
        }
        RegisterAsset {
            asset,
            name,
            spec,
            mintable,
        } => {
            f(*asset);
            f(*name);
            f(*spec);
            f(*mintable);
        }
        TransferAsset {
            from,
            to,
            asset,
            amount,
            dataspace,
        } => {
            f(*from);
            f(*to);
            f(*asset);
            f(*amount);
            f(*dataspace);
        }
        TransferBatchAsset {
            from,
            to,
            asset,
            amount,
        } => {
            f(*from);
            f(*to);
            f(*asset);
            f(*amount);
        }
        EscrowOpenOffer {
            escrow,
            asset,
            amount,
            evidence_hashes,
        } => {
            f(*escrow);
            f(*asset);
            f(*amount);
            if let Some(evidence_hashes) = evidence_hashes {
                f(*evidence_hashes);
            }
        }
        EscrowResolveDispute {
            escrow,
            buyer_amount,
            seller_amount,
            evidence_hashes,
        } => {
            f(*escrow);
            f(*buyer_amount);
            f(*seller_amount);
            if let Some(evidence_hashes) = evidence_hashes {
                f(*evidence_hashes);
            }
        }
        EscrowAccept { escrow }
        | EscrowMarkPaymentSent { escrow }
        | EscrowRelease { escrow }
        | EscrowCancel { escrow } => f(*escrow),
        EscrowOpenDispute {
            escrow,
            evidence_hashes,
        } => {
            f(*escrow);
            if let Some(evidence_hashes) = evidence_hashes {
                f(*evidence_hashes);
            }
        }
        MintAsset {
            account,
            asset,
            amount,
        }
        | BurnAsset {
            account,
            asset,
            amount,
        } => {
            f(*account);
            f(*asset);
            f(*amount);
        }
        AssertEq { left, right } => {
            f(*left);
            f(*right);
        }
        Assert { cond } => f(*cond),
        AbortIf {
            cond,
            descriptor,
            code,
        } => {
            f(*cond);
            f(*descriptor);
            f(*code);
        }
        Info { msg } => f(*msg),
        DebugPrint { value } => f(*value),
        DebugLog { payload } => f(*payload),
        PointerFromString { src, .. } => f(*src),
        MapGet { map, key, .. } => {
            f(*map);
            f(*key);
        }
        MapLoadPair { map, .. } => f(*map),
        MapSet { map, key, value } => {
            f(*map);
            f(*key);
            f(*value);
        }
        Load64Imm { base, .. } => f(*base),
        Load64 { address, .. } => f(*address),
        Store64Imm { base, value, .. } => {
            f(*base);
            f(*value);
        }
        Store64 { address, value } => {
            f(*address);
            f(*value);
        }
        TuplePack { items, .. } => {
            for temp in items {
                f(*temp);
            }
        }
        TupleGet { tuple, .. } => f(*tuple),
        Copy { src, .. } => f(*src),
        SetExecutionDepth { value } => f(*value),
        SetVl { value } => f(*value),
        Call { args, .. } | CallMulti { args, .. } => {
            for arg in args {
                f(*arg);
            }
        }
        SetAccountDetail {
            account,
            key,
            value,
        } => {
            f(*account);
            f(*key);
            f(*value);
        }
        CreateNft { nft, owner } => {
            f(*nft);
            f(*owner);
        }
        SetNftData { nft, key, json } => {
            f(*nft);
            f(*key);
            f(*json);
        }
        BurnNft { nft } => f(*nft),
        TransferNft { from, nft, to } => {
            f(*from);
            f(*nft);
            f(*to);
        }
        RegisterDomain { domain } | UnregisterDomain { domain } => f(*domain),
        TransferDomain { domain, to } => {
            f(*domain);
            f(*to);
        }
        RegisterAccount { account } | UnregisterAccount { account } => f(*account),
        AddSignatory { account, signatory } | RemoveSignatory { account, signatory } => {
            f(*account);
            f(*signatory);
        }
        SetAccountQuorum { account, quorum } => {
            f(*account);
            f(*quorum);
        }
        GrantPermission { account, token } | RevokePermission { account, token } => {
            f(*account);
            f(*token);
        }
        GrantContractPermission {
            account,
            permission,
        }
        | RevokeContractPermission {
            account,
            permission,
        } => {
            f(*account);
            f(*permission);
        }
        GrantRole { account, name } | RevokeRole { account, name } => {
            f(*account);
            f(*name);
        }
        UnregisterAsset { asset } => f(*asset),
        RegisterPeer { json } | UnregisterPeer { json } | CreateTrigger { json } => f(*json),
        CreateRole { name, json } => {
            f(*name);
            f(*json);
        }
        RemoveTrigger { name } | DeleteRole { name } => f(*name),
        SetTriggerEnabled { name, enabled } => {
            f(*name);
            f(*enabled);
        }
        Instr::Sm3Hash { message, .. }
        | Instr::Sha256Hash { message, .. }
        | Instr::Sha3Hash { message, .. }
        | Instr::Blake2b256Hash { message, .. }
        | Instr::Keccak256Hash { message, .. }
        | Instr::IrohaHash { message, .. } => f(*message),
        Instr::Sm2Verify {
            message,
            signature,
            public_key,
            distid,
            ..
        } => {
            f(*message);
            f(*signature);
            f(*public_key);
            if let Some(d) = distid {
                f(*d);
            }
        }
        Instr::VerifySignature {
            message,
            signature,
            public_key,
            scheme,
            ..
        } => {
            f(*message);
            f(*signature);
            f(*public_key);
            f(*scheme);
        }
        Instr::Sm4GcmSeal {
            key,
            nonce,
            aad,
            plaintext,
            ..
        } => {
            f(*key);
            f(*nonce);
            f(*aad);
            f(*plaintext);
        }
        Instr::Sm4GcmOpen {
            key,
            nonce,
            aad,
            ciphertext_and_tag,
            ..
        } => {
            f(*key);
            f(*nonce);
            f(*aad);
            f(*ciphertext_and_tag);
        }
        Instr::Sm4CcmSeal {
            key,
            nonce,
            aad,
            plaintext,
            tag_len,
            ..
        } => {
            f(*key);
            f(*nonce);
            f(*aad);
            f(*plaintext);
            if let Some(t) = tag_len {
                f(*t);
            }
        }
        Instr::Sm4CcmOpen {
            key,
            nonce,
            aad,
            ciphertext_and_tag,
            tag_len,
            ..
        } => {
            f(*key);
            f(*nonce);
            f(*aad);
            f(*ciphertext_and_tag);
            if let Some(t) = tag_len {
                f(*t);
            }
        }
        Instr::ZkVerify { payload, .. }
        | Instr::VerifyProof { payload, .. }
        | Instr::VendorExecuteInstruction { payload, .. }
        | Instr::VendorExecuteQuery { payload, .. }
        | Instr::QueryExecuteNorito { payload, .. }
        | Instr::QueryGet { key: payload, .. }
        | Instr::CoreQueryGet { key: payload, .. }
        | Instr::SmartContractLifecycle { payload, .. }
        | Instr::ZkRootsGet { payload, .. }
        | Instr::ZkVoteGetTally { payload, .. }
        | Instr::VrfEpochSeed { epoch: payload, .. }
        | Instr::SoracloudHostCall {
            request: payload, ..
        } => f(*payload),
        Instr::CoreQueryPage {
            account,
            offset,
            limit,
            ..
        } => {
            if let Some(account) = account {
                f(*account);
            }
            f(*offset);
            f(*limit);
        }
        Instr::GetAccountBalance { account, asset, .. } => {
            f(*account);
            f(*asset);
        }
        Instr::Alloc { bytes, .. } => f(*bytes),
        Instr::GrowHeap { bytes, .. } => f(*bytes),
        Instr::GetMerklePath {
            address,
            output,
            root_output,
            ..
        } => {
            f(*address);
            f(*output);
            if let Some(root_output) = root_output {
                f(*root_output);
            }
        }
        Instr::GetMerkleCompact {
            address,
            output,
            max_depth,
            root_output,
            ..
        } => {
            f(*address);
            f(*output);
            if let Some(max_depth) = max_depth {
                f(*max_depth);
            }
            if let Some(root_output) = root_output {
                f(*root_output);
            }
        }
        Instr::GetRegisterMerkleCompact {
            register_index,
            output,
            max_depth,
            root_output,
            ..
        } => {
            f(*register_index);
            f(*output);
            if let Some(max_depth) = max_depth {
                f(*max_depth);
            }
            if let Some(root_output) = root_output {
                f(*root_output);
            }
        }
        Instr::GetPrivateInput { index, .. } => f(*index),
        Instr::GetPublicInput { key, .. } => f(*key),
        StateGet { path, .. } => f(*path),
        StateSet { path, value } => {
            f(*path);
            f(*value);
        }
        StateDel { path } => f(*path),
        StateScan {
            base, after, limit, ..
        } => {
            f(*base);
            f(*after);
            f(*limit);
        }
        StateMapKeyAt {
            page, base, index, ..
        } => {
            f(*page);
            f(*base);
            f(*index);
        }
        StateValueEncode { schema, words, .. } => {
            f(*schema);
            for word in words {
                f(*word);
            }
        }
        StateHas { path, .. } | StateLen { path, .. } => f(*path),
        StateCount { prefix, .. } => f(*prefix),
        JsonDecode { blob, .. } | NameDecode { blob, .. } => f(*blob),
        TlvLen { value, .. } => f(*value),
        JsonSetInt {
            json, key, value, ..
        }
        | JsonSetAccountId {
            json, key, value, ..
        } => {
            f(*json);
            f(*key);
            f(*value);
        }
        JsonGetNumeric { json, key, .. }
        | JsonGetJson { json, key, .. }
        | JsonGetName { json, key, .. }
        | JsonGetAccountId { json, key, .. }
        | JsonGetAssetDefinitionId { json, key, .. }
        | JsonGetNftId { json, key, .. }
        | JsonGetBlobHex { json, key, .. }
        | JsonGetString { json, key, .. }
        | JsonGetBool { json, key, .. } => {
            f(*json);
            f(*key);
        }
        SchemaDecode { schema, blob, .. } => {
            f(*schema);
            f(*blob);
        }
        PointerToNorito { value, .. } => f(*value),
        PointerFromNorito { blob, .. } => f(*blob),
        StatePathFromName { name, .. } => f(*name),
        PathMapKeyNorito { base, key_blob, .. } => {
            f(*base);
            f(*key_blob);
        }
        JsonEncode { json, .. } => f(*json),
        SchemaEncode { schema, json, .. } => {
            f(*schema);
            f(*json);
        }
        SchemaInfo { schema, .. } => f(*schema),
        BuildSubmitBallotInline {
            election_id,
            ciphertext,
            nullifier,
            backend,
            proof,
            vk,
            ..
        } => {
            f(*election_id);
            f(*ciphertext);
            f(*nullifier);
            f(*backend);
            f(*proof);
            f(*vk);
        }
        PointerEq { left, right, .. } => {
            f(*left);
            f(*right);
        }
        VrfVerify { request, .. } => f(*request),
        VrfVerifyBatch { batch, .. } => f(*batch),
        AxtBegin { descriptor } => f(*descriptor),
        StageAnchoredSpend { spend } => f(*spend),
        AxtTouch { dsid, manifest } => {
            f(*dsid);
            if let Some(m) = manifest {
                f(*m);
            }
        }
        VerifyDsProof { dsid, proof } => {
            f(*dsid);
            if let Some(p) = proof {
                f(*p);
            }
        }
        AxtCommit => {}
    }
}
pub(crate) fn visit_terminator_uses<F: FnMut(Temp)>(term: &Terminator, mut f: F) {
    match term {
        Terminator::Return(Some(temp)) => f(*temp),
        Terminator::Return2(t0, t1) => {
            f(*t0);
            f(*t1);
        }
        Terminator::ReturnN(vals) => {
            for temp in vals {
                f(*temp);
            }
        }
        Terminator::Branch { cond, .. } => f(*cond),
        Terminator::Return(None) | Terminator::Jump(_) => {}
    }
}
fn dest_temp(instr: &Instr) -> Option<Temp> {
    match instr {
        Instr::Source(_) => None,
        Instr::PointerEq { dest, .. }
        | Instr::Const { dest, .. }
        | Instr::StringConst { dest, .. }
        | Instr::DataRef { dest, .. }
        | Instr::Binary { dest, .. }
        | Instr::WrappingBinary { dest, .. }
        | Instr::Unary { dest, .. }
        | Instr::WrappingNeg { dest, .. }
        | Instr::Min { dest, .. }
        | Instr::Max { dest, .. }
        | Instr::Abs { dest, .. }
        | Instr::DivCeil { dest, .. }
        | Instr::Gcd { dest, .. }
        | Instr::Mean { dest, .. }
        | Instr::Isqrt { dest, .. }
        | Instr::LoadVar { dest, .. }
        | Instr::Poseidon2 { dest, .. }
        | Instr::Poseidon6 { dest, .. }
        | Instr::Pubkgen { dest, .. }
        | Instr::Valcom { dest, .. }
        | Instr::PrivateNumericValcom { dest, .. }
        | Instr::MapNew { dest }
        | Instr::GetAuthority { dest }
        | Instr::SysvarAuthority { dest }
        | Instr::CurrentTimeMs { dest }
        | Instr::BlockHeight { dest }
        | Instr::BlockTimeMs { dest }
        | Instr::ChainId { dest }
        | Instr::ContractAddress { dest }
        | Instr::Entrypoint { dest }
        | Instr::QueryExecuteNorito { dest, .. }
        | Instr::QueryGet { dest, .. }
        | Instr::GetAccountBalance { dest, .. }
        | Instr::Alloc { dest, .. }
        | Instr::GetPublicInput { dest, .. }
        | Instr::GetPrivateInput { dest, .. }
        | Instr::ZkRootsGet { dest, .. }
        | Instr::ZkVoteGetTally { dest, .. }
        | Instr::VrfEpochSeed { dest, .. }
        | Instr::SoracloudHostCall { dest, .. }
        | Instr::ResolveAccountAlias { dest, .. }
        | Instr::GetTriggerEvent { dest }
        | Instr::ActorAccount { dest, .. }
        | Instr::ActorPublicKey { dest, .. }
        | Instr::ActorSign { dest, .. }
        | Instr::Copy { dest, .. }
        | Instr::PointerFromString { dest, .. }
        | Instr::PointerToNorito { dest, .. }
        | Instr::PointerFromNorito { dest, .. }
        | Instr::Load64Imm { dest, .. }
        | Instr::Load64 { dest, .. }
        | Instr::StateGet { dest, .. }
        | Instr::StateMapKeyAt { dest, .. }
        | Instr::StateValueEncode { dest, .. }
        | Instr::StateHas { dest, .. }
        | Instr::StateLen { dest, .. }
        | Instr::StateCount { dest, .. }
        | Instr::IntFromI64 { dest, .. }
        | Instr::IntFromU64 { dest, .. }
        | Instr::IntToI64 { dest, .. }
        | Instr::IntToU64 { dest, .. }
        | Instr::NumericConvert { dest, .. }
        | Instr::NumericTryConvert { dest, .. }
        | Instr::NumericStatus { dest }
        | Instr::NumericNeg { dest, .. }
        | Instr::NumericBinary { dest, .. }
        | Instr::NumericRound { dest, .. }
        | Instr::DecimalToInt { dest, .. }
        | Instr::NumericCompare { dest, .. }
        | Instr::DirectHelperSyscall { dest, .. } => Some(*dest),
        Instr::SchemaInfo { dest, .. } | Instr::CoreQueryGet { dest, .. } => Some(*dest),
        Instr::Sm3Hash { dest, .. }
        | Instr::Sha256Hash { dest, .. }
        | Instr::Sha3Hash { dest, .. }
        | Instr::Blake2b256Hash { dest, .. }
        | Instr::Keccak256Hash { dest, .. }
        | Instr::IrohaHash { dest, .. } => Some(*dest),
        Instr::Sm2Verify { dest, .. } => Some(*dest),
        Instr::VerifySignature { dest, .. } => Some(*dest),
        Instr::ExecutionSummary { dest } => Some(*dest),
        Instr::GrowHeap { dest, .. } => Some(*dest),
        Instr::GetMerklePath { dest, .. }
        | Instr::GetMerkleCompact { dest, .. }
        | Instr::GetRegisterMerkleCompact { dest, .. } => Some(*dest),
        Instr::VerifyProof { dest, .. } => Some(*dest),
        Instr::Sm4GcmSeal { dest, .. } => Some(*dest),
        Instr::Sm4GcmOpen { dest, .. } => Some(*dest),
        Instr::Sm4CcmSeal { dest, .. } => Some(*dest),
        Instr::Sm4CcmOpen { dest, .. } => Some(*dest),
        Instr::VrfVerify { dest, .. } => Some(*dest),
        Instr::VrfVerifyBatch { dest, .. } => Some(*dest),
        Instr::MapGet { dest, .. } => Some(*dest),
        Instr::TlvLen { dest, .. } => Some(*dest),
        Instr::JsonObject { dest, .. } => Some(*dest),
        Instr::JsonSetInt { dest, .. } => Some(*dest),
        Instr::JsonSetAccountId { dest, .. } => Some(*dest),
        Instr::StatePathFromName { dest, .. } | Instr::PathMapKeyNorito { dest, .. } => Some(*dest),
        Instr::JsonEncode { dest, .. } => Some(*dest),
        Instr::JsonDecode { dest, .. } => Some(*dest),
        Instr::JsonGetNumeric { dest, .. }
        | Instr::JsonGetJson { dest, .. }
        | Instr::JsonGetName { dest, .. }
        | Instr::JsonGetAccountId { dest, .. }
        | Instr::JsonGetAssetDefinitionId { dest, .. }
        | Instr::JsonGetNftId { dest, .. }
        | Instr::JsonGetBlobHex { dest, .. }
        | Instr::JsonGetString { dest, .. }
        | Instr::JsonGetBool { dest, .. } => Some(*dest),
        Instr::NameDecode { dest, .. } => Some(*dest),
        Instr::SchemaEncode { dest, .. } => Some(*dest),
        Instr::SchemaDecode { dest, .. } => Some(*dest),
        Instr::TuplePack { dest, .. } => Some(*dest),
        Instr::TupleGet { dest, .. } => Some(*dest),
        Instr::BuildSubmitBallotInline { dest, .. } => Some(*dest),
        Instr::VendorExecuteQuery { dest, .. } => Some(*dest),
        Instr::Call { dest, .. } | Instr::InvokeEntrypointAs { dest, .. } => dest.as_ref().copied(),
        Instr::GrantPermission { .. }
        | Instr::RevokePermission { .. }
        | Instr::GrantContractPermission { .. }
        | Instr::RevokeContractPermission { .. }
        | Instr::RegisterAsset { .. }
        | Instr::TransferAsset { .. }
        | Instr::TransferBatchAsset { .. }
        | Instr::EscrowOpenOffer { .. }
        | Instr::EscrowAccept { .. }
        | Instr::EscrowMarkPaymentSent { .. }
        | Instr::EscrowRelease { .. }
        | Instr::EscrowCancel { .. }
        | Instr::EscrowOpenDispute { .. }
        | Instr::EscrowResolveDispute { .. }
        | Instr::MintAsset { .. }
        | Instr::BurnAsset { .. }
        | Instr::CreateNft { .. }
        | Instr::TransferNft { .. }
        | Instr::CreateNftsForAllUsers
        | Instr::SetExecutionDepth { .. }
        | Instr::SetVl { .. }
        | Instr::SetAccountDetail { .. }
        | Instr::RegisterDomain { .. }
        | Instr::RegisterAccount { .. }
        | Instr::AddSignatory { .. }
        | Instr::RemoveSignatory { .. }
        | Instr::SetAccountQuorum { .. }
        | Instr::UnregisterDomain { .. }
        | Instr::UnregisterAsset { .. }
        | Instr::UnregisterAccount { .. }
        | Instr::RegisterPeer { .. }
        | Instr::UnregisterPeer { .. }
        | Instr::CreateTrigger { .. }
        | Instr::RemoveTrigger { .. }
        | Instr::SetTriggerEnabled { .. }
        | Instr::CreateRole { .. }
        | Instr::DeleteRole { .. }
        | Instr::GrantRole { .. }
        | Instr::RevokeRole { .. }
        | Instr::ZkVerify { .. }
        | Instr::VendorExecuteInstruction { .. }
        | Instr::SubscriptionBill
        | Instr::SubscriptionRecordUsage
        | Instr::AssertEq { .. }
        | Instr::Assert { .. }
        | Instr::AbortIf { .. }
        | Instr::Info { .. }
        | Instr::DebugPrint { .. }
        | Instr::DebugLog { .. }
        | Instr::MapSet { .. }
        | Instr::Store64Imm { .. }
        | Instr::Store64 { .. }
        | Instr::SetNftData { .. }
        | Instr::BurnNft { .. }
        | Instr::TransferDomain { .. }
        | Instr::StateSet { .. }
        | Instr::StateDel { .. }
        | Instr::AxtBegin { .. }
        | Instr::AxtTouch { .. }
        | Instr::StageAnchoredSpend { .. }
        | Instr::VerifyDsProof { .. }
        | Instr::AxtCommit
        | Instr::TransferBatchBegin
        | Instr::TransferBatchEnd
        | Instr::CommitOutput
        | Instr::SmartContractLifecycle { .. }
        | Instr::ExpectRejectAs { .. } => None,
        Instr::CallMulti { .. }
        | Instr::CallContract { .. }
        | Instr::InvokeEntrypointAsMulti { .. }
        | Instr::MapLoadPair { .. }
        | Instr::StateScan { .. }
        | Instr::CoreQueryPage { .. } => None,
    }
}
/// Visit every temporary defined by one IR instruction.
pub(crate) fn visit_instr_defs<F: FnMut(Temp)>(instruction: &Instr, mut visit: F) {
    if let Some(dest) = dest_temp(instruction) {
        visit(dest);
    }
    match instruction {
        Instr::StateScan {
            page,
            next,
            count,
            examined,
            ..
        } => {
            visit(*page);
            visit(*next);
            visit(*count);
            visit(*examined);
        }
        Instr::MapLoadPair {
            dest_key, dest_val, ..
        } => {
            visit(*dest_key);
            visit(*dest_val);
        }
        Instr::CallMulti { dests, .. }
        | Instr::CallContract { dests, .. }
        | Instr::InvokeEntrypointAsMulti { dests, .. } => {
            for dest in dests {
                visit(*dest);
            }
        }
        Instr::CoreQueryPage {
            items_dest,
            next_offset_dest,
            ..
        } => {
            visit(*items_dest);
            visit(*next_offset_dest);
        }
        _ => {}
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{self, BasicBlock, Instr, Terminator};
    #[test]
    fn private_numeric_commitment_reports_each_pointer_operand_once() {
        let value = Temp(1);
        let blind = Temp(2);
        let instruction = Instr::PrivateNumericValcom {
            dest: Temp(3),
            value,
            blind,
        };
        let mut uses = Vec::new();
        visit_instr_uses(&instruction, |used| uses.push(used));
        assert_eq!(uses, vec![value, blind]);
    }
    #[test]
    fn private_numeric_instruction_visitors_preserve_aliased_uses_and_definitions() {
        let shared = Temp(1);
        let commitment_dest = Temp(2);
        let commitment = Instr::PrivateNumericValcom {
            dest: commitment_dest,
            value: shared,
            blind: shared,
        };
        let mut commitment_uses = Vec::new();
        let mut commitment_defs = Vec::new();
        visit_instr_uses(&commitment, |used| commitment_uses.push(used));
        visit_instr_defs(&commitment, |defined| commitment_defs.push(defined));
        assert_eq!(commitment_uses, vec![shared, shared]);
        assert_eq!(commitment_defs, vec![commitment_dest]);
        let private_input = Instr::GetPrivateInput {
            dest: shared,
            index: shared,
            kind: ivm_abi::private_input::PrivateInputKindV1::Quantity,
        };
        let mut private_input_uses = Vec::new();
        let mut private_input_defs = Vec::new();
        visit_instr_uses(&private_input, |used| private_input_uses.push(used));
        visit_instr_defs(&private_input, |defined| private_input_defs.push(defined));
        assert_eq!(private_input_uses, vec![shared]);
        assert_eq!(private_input_defs, vec![shared]);
    }
    #[test]
    fn rounded_decimal_conversion_reports_its_mode_operand_once() {
        let value = Temp(1);
        let mode = Temp(2);
        let instruction = Instr::DecimalToInt {
            dest: Temp(3),
            value,
            mode: Some(mode),
            op: ir::DecimalToIntOp::Round,
        };
        let mut uses = Vec::new();
        visit_instr_uses(&instruction, |used| uses.push(used));
        assert_eq!(uses, vec![value, mode]);
    }
    #[test]
    fn virtual_tuple_copy_keeps_constant_field_live_until_state_value_extraction() {
        let status = Temp(0);
        let nested_record = Temp(1);
        let record = Temp(2);
        let record_copy = Temp(3);
        let extracted_record = Temp(4);
        let extracted_status = Temp(5);
        let schema = Temp(6);
        let encoded = Temp(7);
        let function = Function {
            name: "aggregate_constant_state".into(),
            params: vec![],
            blocks: vec![BasicBlock {
                label: Label(0),
                instrs: vec![
                    Instr::DataRef {
                        dest: status,
                        kind: ir::DataRefKind::Int,
                        value: "1".into(),
                    },
                    Instr::TuplePack {
                        dest: nested_record,
                        items: vec![status],
                    },
                    Instr::TuplePack {
                        dest: record,
                        items: vec![nested_record],
                    },
                    Instr::Copy {
                        dest: record_copy,
                        src: record,
                    },
                    Instr::TupleGet {
                        dest: extracted_record,
                        tuple: record_copy,
                        index: 0,
                    },
                    Instr::TupleGet {
                        dest: extracted_status,
                        tuple: extracted_record,
                        index: 0,
                    },
                    Instr::DataRef {
                        dest: schema,
                        kind: ir::DataRefKind::NoritoBytes,
                        value: "0x00".into(),
                    },
                    Instr::StateValueEncode {
                        dest: encoded,
                        schema,
                        words: vec![extracted_status],
                    },
                ],
                terminator: Terminator::Return(Some(encoded)),
            }],
            entry: Label(0),
            location: crate::ast::SourceLocation { line: 1, column: 1 },
        };
        let intervals = collect_live_intervals(&function);
        let status_interval = intervals
            .iter()
            .find(|interval| interval.temp == status)
            .expect("constant status field interval");
        assert_eq!(
            status_interval.end, 5,
            "virtual tuple copies and nested projections must keep the source field live until TupleGet materializes it"
        );
    }
    #[test]
    fn virtual_tuple_fields_needed_after_a_call_use_preserved_homes() {
        let field = Temp(0);
        let tuple = Temp(1);
        let extracted = Temp(2);
        let function = Function {
            name: "tuple_across_call".into(),
            params: vec![],
            blocks: vec![BasicBlock {
                label: Label(0),
                instrs: vec![
                    Instr::Const {
                        dest: field,
                        value: 7,
                    },
                    Instr::TuplePack {
                        dest: tuple,
                        items: vec![field],
                    },
                    Instr::Call {
                        callee: "helper".into(),
                        args: Vec::new(),
                        dest: None,
                    },
                    Instr::TupleGet {
                        dest: extracted,
                        tuple,
                        index: 0,
                    },
                ],
                terminator: Terminator::Return(Some(extracted)),
            }],
            entry: Label(0),
            location: crate::ast::SourceLocation { line: 1, column: 1 },
        };
        let allocation = allocate(&function);
        assert!(
            ALLOC_POOL.contains(&allocation.regs[&field]),
            "a virtual tuple field materialized after the call must survive it: {allocation:#?}"
        );
    }
    #[test]
    fn reuse_registers_when_intervals_do_not_overlap() {
        let mut blocks = Vec::new();
        let mut instrs = Vec::new();
        for i in 0..35 {
            instrs.push(Instr::Const {
                dest: Temp(i),
                value: i as i64,
            });
        }
        blocks.push(BasicBlock {
            label: ir::Label(0),
            instrs,
            terminator: Terminator::Return(None),
        });
        let func = Function {
            name: "f".into(),
            params: vec![],
            blocks,
            entry: ir::Label(0),
            location: crate::ast::SourceLocation { line: 1, column: 1 },
        };
        let alloc = allocate(&func);
        assert!(alloc.stack.is_empty());
        assert_eq!(alloc.frame_size, 0);
        for &reg in alloc.regs.values() {
            assert!(CALLER_CLOBBERED_REGS.contains(&reg));
        }
    }
    #[test]
    fn table_parameters_use_ordinary_call_local_register_allocation() {
        let parameter = Temp(0);
        let func = Function {
            name: "identity".into(),
            params: vec!["value".into()],
            blocks: vec![BasicBlock {
                label: Label(0),
                instrs: vec![Instr::LoadVar {
                    dest: parameter,
                    name: "value".into(),
                }],
                terminator: Terminator::Return(Some(parameter)),
            }],
            entry: Label(0),
            location: crate::ast::SourceLocation { line: 1, column: 1 },
        };
        let alloc = allocate(&func);
        assert!(CALLER_CLOBBERED_REGS.contains(&alloc.regs[&parameter]));
        assert!(alloc.stack.is_empty());
        assert_eq!(alloc.frame_size, 0);
        assert!(!has_internal_calls(&func));
    }
    #[test]
    fn call_aware_allocation_preserves_only_values_live_across_the_call() {
        let carried = Temp(0);
        let argument = Temp(1);
        let call_result = Temp(2);
        let result = Temp(3);
        let function = Function {
            name: "call_aware".into(),
            params: Vec::new(),
            blocks: vec![BasicBlock {
                label: Label(0),
                instrs: vec![
                    Instr::Const {
                        dest: carried,
                        value: 7,
                    },
                    Instr::Const {
                        dest: argument,
                        value: 11,
                    },
                    Instr::Call {
                        callee: "helper".into(),
                        args: vec![argument],
                        dest: Some(call_result),
                    },
                    Instr::Binary {
                        dest: result,
                        op: crate::ast::BinaryOp::Add,
                        left: carried,
                        right: call_result,
                    },
                ],
                terminator: Terminator::Return(Some(result)),
            }],
            entry: Label(0),
            location: crate::ast::SourceLocation { line: 1, column: 1 },
        };
        let allocation = allocate(&function);
        assert!(ALLOC_POOL.contains(&allocation.regs[&carried]));
        assert!(CALLER_CLOBBERED_REGS.contains(&allocation.regs[&argument]));
        assert!(CALLER_CLOBBERED_REGS.contains(&allocation.regs[&call_result]));
        assert!(allocation.stack.is_empty());
    }
    #[test]
    fn table_parameters_use_preserved_registers_only_when_live_across_a_call() {
        let parameter = Temp(0);
        let call_result = Temp(1);
        let dead_at_call = Function {
            name: "dead_at_call".into(),
            params: vec!["value".into()],
            blocks: vec![BasicBlock {
                label: Label(0),
                instrs: vec![
                    Instr::LoadVar {
                        dest: parameter,
                        name: "value".into(),
                    },
                    Instr::Call {
                        callee: "helper".into(),
                        args: vec![parameter],
                        dest: Some(call_result),
                    },
                ],
                terminator: Terminator::Return(Some(call_result)),
            }],
            entry: Label(0),
            location: crate::ast::SourceLocation { line: 1, column: 1 },
        };
        assert!(CALLER_CLOBBERED_REGS.contains(&allocate(&dead_at_call).regs[&parameter]));
        let after_call = Temp(2);
        let live_across_call = Function {
            name: "live_across_call".into(),
            params: vec!["value".into()],
            blocks: vec![BasicBlock {
                label: Label(0),
                instrs: vec![
                    Instr::LoadVar {
                        dest: parameter,
                        name: "value".into(),
                    },
                    Instr::Call {
                        callee: "helper".into(),
                        args: Vec::new(),
                        dest: Some(call_result),
                    },
                    Instr::Binary {
                        dest: after_call,
                        op: crate::ast::BinaryOp::Add,
                        left: parameter,
                        right: call_result,
                    },
                ],
                terminator: Terminator::Return(Some(after_call)),
            }],
            entry: Label(0),
            location: crate::ast::SourceLocation { line: 1, column: 1 },
        };
        let allocation = allocate(&live_across_call);
        assert_ne!(allocation.regs[&parameter], RET_REG);
        assert!(ALLOC_POOL.contains(&allocation.regs[&parameter]));
    }
    #[test]
    fn values_between_multiple_calls_reuse_argument_registers() {
        let carried = Temp(0);
        let first_result = Temp(1);
        let second_result = Temp(2);
        let result = Temp(3);
        let function = Function {
            name: "multiple_calls".into(),
            params: Vec::new(),
            blocks: vec![BasicBlock {
                label: Label(0),
                instrs: vec![
                    Instr::Const {
                        dest: carried,
                        value: 5,
                    },
                    Instr::Call {
                        callee: "first".into(),
                        args: Vec::new(),
                        dest: Some(first_result),
                    },
                    Instr::Call {
                        callee: "second".into(),
                        args: vec![first_result],
                        dest: Some(second_result),
                    },
                    Instr::Binary {
                        dest: result,
                        op: crate::ast::BinaryOp::Add,
                        left: carried,
                        right: second_result,
                    },
                ],
                terminator: Terminator::Return(Some(result)),
            }],
            entry: Label(0),
            location: crate::ast::SourceLocation { line: 1, column: 1 },
        };
        let allocation = allocate(&function);
        assert!(ALLOC_POOL.contains(&allocation.regs[&carried]));
        assert!(CALLER_CLOBBERED_REGS.contains(&allocation.regs[&first_result]));
        assert!(CALLER_CLOBBERED_REGS.contains(&allocation.regs[&second_result]));
        assert_eq!(allocation, allocate(&function));
    }
    #[test]
    fn loop_carried_value_uses_a_preserved_home_across_calls() {
        let carried = Temp(0);
        let call_result = Temp(1);
        let function = Function {
            name: "call_in_loop".into(),
            params: Vec::new(),
            blocks: vec![
                BasicBlock {
                    label: Label(0),
                    instrs: vec![Instr::Const {
                        dest: carried,
                        value: 1,
                    }],
                    terminator: Terminator::Jump(Label(1)),
                },
                BasicBlock {
                    label: Label(1),
                    instrs: vec![Instr::Call {
                        callee: "tick".into(),
                        args: Vec::new(),
                        dest: Some(call_result),
                    }],
                    terminator: Terminator::Branch {
                        cond: carried,
                        then_bb: Label(1),
                        else_bb: Label(2),
                    },
                },
                BasicBlock {
                    label: Label(2),
                    instrs: Vec::new(),
                    terminator: Terminator::Return(Some(carried)),
                },
            ],
            entry: Label(0),
            location: crate::ast::SourceLocation { line: 1, column: 1 },
        };
        let allocation = allocate(&function);
        assert!(ALLOC_POOL.contains(&allocation.regs[&carried]));
        assert!(CALLER_CLOBBERED_REGS.contains(&allocation.regs[&call_result]));
    }
    #[test]
    fn join_live_value_uses_a_preserved_home_across_one_branch_call() {
        let carried = Temp(0);
        let call_result = Temp(1);
        let function = Function {
            name: "call_before_join".into(),
            params: Vec::new(),
            blocks: vec![
                BasicBlock {
                    label: Label(0),
                    instrs: vec![Instr::Const {
                        dest: carried,
                        value: 1,
                    }],
                    terminator: Terminator::Branch {
                        cond: carried,
                        then_bb: Label(1),
                        else_bb: Label(2),
                    },
                },
                BasicBlock {
                    label: Label(1),
                    instrs: vec![Instr::Call {
                        callee: "branch_call".into(),
                        args: Vec::new(),
                        dest: Some(call_result),
                    }],
                    terminator: Terminator::Jump(Label(3)),
                },
                BasicBlock {
                    label: Label(2),
                    instrs: Vec::new(),
                    terminator: Terminator::Jump(Label(3)),
                },
                BasicBlock {
                    label: Label(3),
                    instrs: Vec::new(),
                    terminator: Terminator::Return(Some(carried)),
                },
            ],
            entry: Label(0),
            location: crate::ast::SourceLocation { line: 1, column: 1 },
        };
        let allocation = allocate(&function);
        assert!(ALLOC_POOL.contains(&allocation.regs[&carried]));
    }
    #[test]
    fn disjoint_branch_liveness_does_not_create_false_call_crossings() {
        let condition = Temp(0);
        let branch_local = Temp(1);
        let short_value = Temp(2);
        let merged = Temp(3);
        let call_result = Temp(4);
        let rhs_value = Temp(5);
        let function = Function {
            name: "disjoint_branch_call".into(),
            params: Vec::new(),
            blocks: vec![
                BasicBlock {
                    label: Label(0),
                    instrs: vec![
                        Instr::Const {
                            dest: condition,
                            value: 1,
                        },
                        Instr::Const {
                            dest: branch_local,
                            value: 0,
                        },
                    ],
                    terminator: Terminator::Branch {
                        cond: condition,
                        then_bb: Label(1),
                        else_bb: Label(3),
                    },
                },
                BasicBlock {
                    label: Label(1),
                    instrs: vec![
                        Instr::Const {
                            dest: short_value,
                            value: 0,
                        },
                        Instr::Copy {
                            dest: merged,
                            src: short_value,
                        },
                    ],
                    terminator: Terminator::Jump(Label(2)),
                },
                BasicBlock {
                    label: Label(2),
                    instrs: vec![Instr::Call {
                        callee: "relay".into(),
                        args: vec![merged],
                        dest: Some(call_result),
                    }],
                    terminator: Terminator::Return(Some(call_result)),
                },
                BasicBlock {
                    label: Label(3),
                    instrs: vec![
                        Instr::Unary {
                            dest: rhs_value,
                            op: crate::ast::UnaryOp::Not,
                            operand: branch_local,
                        },
                        Instr::Copy {
                            dest: merged,
                            src: rhs_value,
                        },
                    ],
                    terminator: Terminator::Jump(Label(2)),
                },
            ],
            entry: Label(0),
            location: crate::ast::SourceLocation { line: 1, column: 1 },
        };
        let call_position = 6;
        let intervals = collect_live_intervals(&function);
        for temp in [branch_local, merged] {
            let interval = intervals
                .iter()
                .find(|interval| interval.temp == temp)
                .expect("branch-local interval");
            assert!(
                interval.start < call_position && call_position < interval.end,
                "the physical block layout must reproduce the conservative linear crossing"
            );
        }
        let allocation = allocate(&function);
        assert!(
            [branch_local, merged]
                .iter()
                .all(|temp| CALLER_CLOBBERED_REGS.contains(&allocation.regs[temp])),
            "values that cannot reach the call must stay in caller-saved registers: {allocation:#?}"
        );
        assert!(allocation.stack.is_empty(), "{allocation:#?}");
        assert_eq!(allocation.frame_size, 0);
    }
    #[test]
    fn host_call_operands_are_preserved_while_results_use_argument_registers() {
        let actor = Temp(0);
        let account = Temp(1);
        let function = Function {
            name: "host_operand".into(),
            params: Vec::new(),
            blocks: vec![BasicBlock {
                label: Label(0),
                instrs: vec![
                    Instr::Const {
                        dest: actor,
                        value: 1,
                    },
                    Instr::ActorAccount {
                        dest: account,
                        actor,
                    },
                ],
                terminator: Terminator::Return(Some(account)),
            }],
            entry: Label(0),
            location: crate::ast::SourceLocation { line: 1, column: 1 },
        };
        let allocation = allocate(&function);
        assert!(ALLOC_POOL.contains(&allocation.regs[&actor]));
        assert!(CALLER_CLOBBERED_REGS.contains(&allocation.regs[&account]));
    }
    #[test]
    fn call_local_pressure_uses_the_full_caller_saved_window_without_spills() {
        let carried = Temp(0);
        let warmup = Temp(1);
        let arguments = (0..CALLER_CLOBBERED_REGS.len())
            .map(|index| Temp(index + 2))
            .collect::<Vec<_>>();
        let call_result = Temp(CALLER_CLOBBERED_REGS.len() + 2);
        let result = Temp(CALLER_CLOBBERED_REGS.len() + 3);
        let mut instructions = vec![
            Instr::Const {
                dest: carried,
                value: 1,
            },
            Instr::Call {
                callee: "warmup".into(),
                args: Vec::new(),
                dest: Some(warmup),
            },
        ];
        instructions.extend(
            arguments
                .iter()
                .enumerate()
                .map(|(index, temp)| Instr::Const {
                    dest: *temp,
                    value: index as i64,
                }),
        );
        instructions.push(Instr::Call {
            callee: "consume".into(),
            args: arguments.clone(),
            dest: Some(call_result),
        });
        instructions.push(Instr::Binary {
            dest: result,
            op: crate::ast::BinaryOp::Add,
            left: carried,
            right: call_result,
        });
        let function = Function {
            name: "call_pressure".into(),
            params: Vec::new(),
            blocks: vec![BasicBlock {
                label: Label(0),
                instrs: instructions,
                terminator: Terminator::Return(Some(result)),
            }],
            entry: Label(0),
            location: crate::ast::SourceLocation { line: 1, column: 1 },
        };
        let allocation = allocate(&function);
        assert!(allocation.stack.is_empty(), "{allocation:#?}");
        assert!(ALLOC_POOL.contains(&allocation.regs[&carried]));
        assert!(
            arguments
                .iter()
                .all(|temp| CALLER_CLOBBERED_REGS.contains(&allocation.regs[temp]))
        );
        assert_eq!(allocation, allocate(&function));
    }
    #[test]
    fn spills_when_live_set_exceeds_pool() {
        let live = ALLOC_POOL.len() + CALLER_CLOBBERED_REGS.len() + 4;
        let mut blocks = Vec::new();
        let mut instrs = Vec::new();
        for i in 0..live {
            instrs.push(Instr::Const {
                dest: Temp(i),
                value: i as i64,
            });
        }
        instrs.push(Instr::TuplePack {
            dest: Temp(live),
            items: (0..live).map(Temp).collect(),
        });
        blocks.push(BasicBlock {
            label: ir::Label(0),
            instrs,
            terminator: Terminator::Return(None),
        });
        let func = Function {
            name: "g".into(),
            params: vec![],
            blocks,
            entry: ir::Label(0),
            location: crate::ast::SourceLocation { line: 1, column: 1 },
        };
        let alloc = allocate(&func);
        assert!(
            !alloc.stack.is_empty(),
            "expected spills when live set exceeds pool"
        );
        assert!(alloc.frame_size > 0);
        assert_eq!(alloc.frame_size % 16, 0);
    }
    #[test]
    fn splits_a_long_spill_into_one_reload_for_a_reuse_cluster() {
        let reused = Temp(0);
        let mut instructions = vec![Instr::LoadVar {
            dest: reused,
            name: "reused".into(),
        }];
        for index in 1..=ALLOC_POOL.len() {
            instructions.push(Instr::Const {
                dest: Temp(index),
                value: index as i64,
            });
        }
        // These effectful uses keep every short-lived value live during the
        // definition-pressure prefix, then release all registers before the
        // repeated uses of `reused`.
        for index in 1..=ALLOC_POOL.len() {
            instructions.push(Instr::DebugPrint { value: Temp(index) });
        }
        let first_result = Temp(ALLOC_POOL.len() + 1);
        let second_result = Temp(ALLOC_POOL.len() + 2);
        let first_use_position = instructions.len();
        instructions.push(Instr::Binary {
            dest: first_result,
            op: crate::ast::BinaryOp::Add,
            left: reused,
            right: reused,
        });
        instructions.push(Instr::Binary {
            dest: second_result,
            op: crate::ast::BinaryOp::Add,
            left: reused,
            right: reused,
        });
        let function = Function {
            name: "split_reuse".into(),
            params: vec!["reused".into()],
            blocks: vec![BasicBlock {
                label: Label(0),
                instrs: instructions,
                terminator: Terminator::Return(Some(second_result)),
            }],
            entry: Label(0),
            location: crate::ast::SourceLocation { line: 1, column: 1 },
        };
        let baseline = allocate(&function);
        assert!(
            baseline.stack.contains_key(&reused),
            "the long-lived value must be the initial spill: {baseline:#?}"
        );
        let plan = allocate_with_splitting(&function);
        let segments = plan.split_segments(reused);
        assert_eq!(segments.len(), 1, "expected one local reuse segment");
        assert_eq!(segments[0].start, first_use_position);
        assert_eq!(segments[0].end, first_use_position + 1);
        assert_eq!(segments[0].use_count, 4);
        assert!(
            CALLER_CLOBBERED_REGS.contains(&segments[0].register),
            "a clobber-local split should reuse a caller-saved hole"
        );
        assert_eq!(plan.frame_size, baseline.frame_size);
        assert_eq!(plan.reloads_at(first_use_position).len(), 1);
        assert_eq!(plan.saved_reload_count(), 3);
        assert_eq!(
            plan.register_for_use(reused, first_use_position),
            plan.register_for_use(reused, first_use_position + 1)
        );
        assert_eq!(
            plan,
            allocate_with_splitting(&function),
            "split allocation must be deterministic"
        );
    }
    #[test]
    fn split_candidates_reload_again_after_a_definition_epoch() {
        let value = Temp(0);
        let replacement = Temp(1);
        let function = Function {
            name: "split_definition_epoch".into(),
            params: vec![],
            blocks: vec![BasicBlock {
                label: Label(0),
                instrs: vec![
                    Instr::Binary {
                        dest: Temp(2),
                        op: crate::ast::BinaryOp::Add,
                        left: value,
                        right: value,
                    },
                    Instr::Copy {
                        dest: value,
                        src: replacement,
                    },
                    Instr::Binary {
                        dest: Temp(3),
                        op: crate::ast::BinaryOp::Add,
                        left: value,
                        right: value,
                    },
                ],
                terminator: Terminator::Return(None),
            }],
            entry: Label(0),
            location: crate::ast::SourceLocation { line: 1, column: 1 },
        };
        let home = Allocation {
            regs: HashMap::new(),
            stack: [(value, 0)].into_iter().collect(),
            frame_size: 16,
        };
        let mut candidates = collect_split_candidates(&function, &home);
        candidates.sort_unstable_by_key(|candidate| candidate.start);
        assert_eq!(
            candidates,
            vec![
                SplitCandidate {
                    temp: value,
                    start: 0,
                    end: 0,
                    use_count: 2,
                },
                SplitCandidate {
                    temp: value,
                    start: 2,
                    end: 2,
                    use_count: 2,
                },
            ],
            "a definition must terminate the prior read-only split segment"
        );
    }
    #[test]
    fn split_reload_segments_stop_at_internal_call_clobbers() {
        let value = Temp(0);
        let function = Function {
            name: "split_at_call".into(),
            params: Vec::new(),
            blocks: vec![BasicBlock {
                label: Label(0),
                instrs: vec![
                    Instr::Binary {
                        dest: Temp(1),
                        op: crate::ast::BinaryOp::Add,
                        left: value,
                        right: value,
                    },
                    Instr::Binary {
                        dest: Temp(2),
                        op: crate::ast::BinaryOp::Add,
                        left: value,
                        right: value,
                    },
                    Instr::Call {
                        callee: "clobber".into(),
                        args: vec![value],
                        dest: None,
                    },
                    Instr::Binary {
                        dest: Temp(3),
                        op: crate::ast::BinaryOp::Add,
                        left: value,
                        right: value,
                    },
                    Instr::Binary {
                        dest: Temp(4),
                        op: crate::ast::BinaryOp::Add,
                        left: value,
                        right: value,
                    },
                ],
                terminator: Terminator::Return(None),
            }],
            entry: Label(0),
            location: crate::ast::SourceLocation { line: 1, column: 1 },
        };
        let home = Allocation {
            regs: HashMap::new(),
            stack: [(value, 0)].into_iter().collect(),
            frame_size: 16,
        };
        let intervals = [Interval {
            temp: value,
            start: 0,
            end: 4,
        }];
        let mut segments = build_split_segments(&function, &intervals, &home);
        segments.sort_unstable_by_key(|segment| segment.start);
        assert_eq!(segments.len(), 2, "{segments:#?}");
        assert_eq!((segments[0].start, segments[0].end), (0, 2));
        assert_eq!((segments[1].start, segments[1].end), (3, 4));
        assert!(
            segments
                .iter()
                .all(|segment| CALLER_CLOBBERED_REGS.contains(&segment.register))
        );
        assert!(
            segments
                .iter()
                .all(|segment| { !(segment.start <= 2 && 2 < segment.end) })
        );
    }
    #[test]
    fn split_candidates_exclude_virtual_and_rematerialized_stack_homes() {
        let literal = Temp(0);
        let rematerialized_copy = Temp(1);
        let virtual_tuple = Temp(2);
        let function = Function {
            name: "split_rematerialization".into(),
            params: vec![],
            blocks: vec![BasicBlock {
                label: Label(0),
                instrs: vec![
                    Instr::Const {
                        dest: literal,
                        value: 7,
                    },
                    Instr::Copy {
                        dest: rematerialized_copy,
                        src: literal,
                    },
                    Instr::TuplePack {
                        dest: virtual_tuple,
                        items: vec![rematerialized_copy],
                    },
                    Instr::Binary {
                        dest: Temp(3),
                        op: crate::ast::BinaryOp::Add,
                        left: rematerialized_copy,
                        right: rematerialized_copy,
                    },
                    Instr::Binary {
                        dest: Temp(4),
                        op: crate::ast::BinaryOp::Add,
                        left: rematerialized_copy,
                        right: rematerialized_copy,
                    },
                ],
                terminator: Terminator::Return2(virtual_tuple, virtual_tuple),
            }],
            entry: Label(0),
            location: crate::ast::SourceLocation { line: 1, column: 1 },
        };
        let home = Allocation {
            regs: HashMap::new(),
            stack: [(rematerialized_copy, 0), (virtual_tuple, 8)]
                .into_iter()
                .collect(),
            frame_size: 16,
        };
        assert!(
            collect_split_candidates(&function, &home).is_empty(),
            "literal copies and metadata-only tuples must never trigger stack reloads"
        );
    }
    #[test]
    fn deterministic_allocation_for_equal_start_intervals() {
        let dest0 = Temp(0);
        let dest1 = Temp(1);
        let instrs = vec![Instr::CallMulti {
            callee: "f".into(),
            args: Vec::new(),
            dests: vec![dest0, dest1],
        }];
        let block = BasicBlock {
            label: ir::Label(0),
            instrs,
            terminator: Terminator::Return(None),
        };
        let func = Function {
            name: "f".into(),
            params: vec![],
            blocks: vec![block],
            entry: ir::Label(0),
            location: crate::ast::SourceLocation { line: 1, column: 1 },
        };
        let alloc = allocate(&func);
        let expected_first = *CALLER_CLOBBERED_REGS
            .last()
            .expect("argument register pool");
        let expected_second = CALLER_CLOBBERED_REGS[CALLER_CLOBBERED_REGS.len() - 2];
        assert_eq!(alloc.regs.get(&dest0), Some(&expected_first));
        assert_eq!(alloc.regs.get(&dest1), Some(&expected_second));
    }
    #[test]
    fn reuses_spill_slots_for_non_overlapping_pressure_phases() {
        fn pressure_phase(instrs: &mut Vec<Instr>, next_temp: &mut usize, live: usize) {
            let first = *next_temp;
            for _ in 0..live {
                let dest = Temp(*next_temp);
                *next_temp += 1;
                instrs.push(Instr::Const {
                    dest,
                    value: dest.0 as i64,
                });
            }
            let tuple = Temp(*next_temp);
            *next_temp += 1;
            instrs.push(Instr::TuplePack {
                dest: tuple,
                items: (first..first + live).map(Temp).collect(),
            });
        }
        let live = ALLOC_POOL.len() + CALLER_CLOBBERED_REGS.len() + 4;
        let mut one_phase = Vec::new();
        let mut next_temp = 0;
        pressure_phase(&mut one_phase, &mut next_temp, live);
        let one_phase = Function {
            name: "one_phase".into(),
            params: vec![],
            blocks: vec![BasicBlock {
                label: Label(0),
                instrs: one_phase,
                terminator: Terminator::Return(None),
            }],
            entry: Label(0),
            location: crate::ast::SourceLocation { line: 1, column: 1 },
        };
        let mut two_phases = Vec::new();
        let mut next_temp = 0;
        pressure_phase(&mut two_phases, &mut next_temp, live);
        pressure_phase(&mut two_phases, &mut next_temp, live);
        let two_phases = Function {
            name: "two_phases".into(),
            params: vec![],
            blocks: vec![BasicBlock {
                label: Label(0),
                instrs: two_phases,
                terminator: Terminator::Return(None),
            }],
            entry: Label(0),
            location: crate::ast::SourceLocation { line: 1, column: 1 },
        };
        let one = allocate(&one_phase);
        let two = allocate(&two_phases);
        assert!(!one.stack.is_empty());
        assert_eq!(
            two.frame_size, one.frame_size,
            "disjoint pressure phases must share the same stack-slot high-water mark"
        );
        assert!(two.stack.len() > one.stack.len());
        assert!(
            two.stack.values().any(|slot| two
                .stack
                .values()
                .filter(|other| *other == slot)
                .count()
                > 1),
            "at least one physical spill slot should be shared by disjoint intervals"
        );
    }
    #[test]
    fn spill_slot_coloring_preserves_full_interval_overlap() {
        let long = Temp(0);
        let early = Temp(1);
        let late = Temp(2);
        let intervals = [
            Interval {
                temp: long,
                start: 0,
                end: 10,
            },
            Interval {
                temp: early,
                start: 1,
                end: 4,
            },
            Interval {
                temp: late,
                start: 5,
                end: 6,
            },
        ];
        let spilled = [long, early, late].into_iter().collect();
        let (slots, high_water) = assign_spill_slots(&intervals, &spilled);
        assert_ne!(slots[&long], slots[&early]);
        assert_eq!(slots[&early], slots[&late]);
        assert_eq!(high_water, 16);
    }
}
