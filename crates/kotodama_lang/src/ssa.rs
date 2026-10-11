//! Strict SSA MIR construction, optimization, verification, and deterministic destruction.
//!
//! Kotodama's lowering IR deliberately retains mutable temporary names because those names are a
//! compact de-SSA transport for the existing code generator. This module makes the intervening
//! compiler invariant explicit: every instruction definition is assigned a unique [`Value`],
//! control-flow joins receive explicit [`Phi`] nodes, and every use is checked against dominance
//! before the transport form can reach register allocation.
//!
//! This is the canonical optimization authority. Sparse conditional constant
//! propagation tracks executable edges and Phi inputs, checked folds preserve
//! traps, and dead-value removal recognizes only explicitly non-trapping
//! operations. Whole-program pruning runs on the simplified SSA call graph.
//!
//! SSA deliberately reuses the exhaustive lowering opcode enum inside private [`ValueInstruction`]
//! and [`ValueTerminator`] brands. This is an implementation choice, not a mixed representation:
//! raw lowering operands are rewritten before branding, no parallel operation is retained, and the
//! opaque SSA API exposes only verified construction and consuming de-SSA.
use crate::{
    ir::{self, Label, Temp},
    regalloc::{visit_instr_defs, visit_instr_uses, visit_terminator_uses},
};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

mod literal_calls;
mod single_use_calls;
#[cfg(test)]
mod statement_source_tests;
#[cfg(test)]
pub(crate) use single_use_calls::with_private_calls_retained;
/// Maximum control-flow blocks accepted in one V1 function.
///
/// The bound keeps dominance construction and verification deterministic and
/// memory-bounded for adversarial compiler-service inputs. Critical-edge
/// splitting is checked against the same ceiling before de-SSA returns.
const MAX_SSA_BLOCKS_PER_FUNCTION: usize = 4_096;
/// Maximum lowering instructions accepted in one V1 function before SSA.
const MAX_SSA_INSTRUCTIONS_PER_FUNCTION: usize = 262_144;
/// One uniquely defined SSA value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Value(usize);
impl Value {
    /// Encode an SSA value in the exhaustive lowering-opcode register slot.
    ///
    /// The strict MIR owns these slots while this module is active: a `Temp`
    /// inside an SSA instruction denotes a `Value`, never a lowering variable.
    /// Reusing the opcode enum keeps effects and checked-operation kinds exact
    /// without retaining a second, mutable operation as semantic authority.
    fn encoded(self) -> Temp {
        Temp(self.0)
    }
    fn decode(encoded: Temp) -> Self {
        Self(encoded.0)
    }
}
/// One incoming value for a Phi node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PhiInput {
    predecessor: Label,
    value: Value,
}
/// An explicit control-flow merge for one lowering temporary.
#[derive(Debug, PartialEq, Eq)]
struct Phi {
    variable: Temp,
    destination: Value,
    inputs: Vec<PhiInput>,
}
/// One canonical opcode branded as using the SSA value namespace.
///
/// The payload reuses the exhaustive lowering opcode family so checked and effectful operation
/// kinds cannot drift. Construction is private to this module; unlike lowering [`Temp`]s, every
/// payload register is a [`Value`] encoded by [`Value::encoded`].
#[derive(Debug)]
struct ValueInstruction(ir::Instr, Option<crate::source::SourceRange>);
impl PartialEq for ValueInstruction {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl ValueInstruction {
    fn new(canonical: ir::Instr) -> Self {
        Self(canonical, None)
    }
    fn as_ir(&self) -> &ir::Instr {
        &self.0
    }
    fn as_ir_mut(&mut self) -> &mut ir::Instr {
        &mut self.0
    }
    fn into_ir(self) -> ir::Instr {
        self.0
    }
}
/// One canonical control transfer branded as using SSA values.
#[derive(Debug)]
struct ValueTerminator(ir::Terminator, Option<crate::source::SourceRange>);
impl PartialEq for ValueTerminator {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl ValueTerminator {
    fn new(canonical: ir::Terminator) -> Self {
        Self(canonical, None)
    }
    fn as_ir(&self) -> &ir::Terminator {
        &self.0
    }
    fn as_ir_mut(&mut self) -> &mut ir::Terminator {
        &mut self.0
    }
    fn into_ir(self) -> ir::Terminator {
        self.0
    }
}
/// One strict SSA basic block.
#[derive(Debug, PartialEq)]
struct BasicBlock {
    label: Label,
    phis: Vec<Phi>,
    /// Canonical typed opcodes whose register slots encode [`Value`]s.
    instructions: Vec<ValueInstruction>,
    /// Canonical control transfer whose operand slots encode [`Value`]s.
    terminator: ValueTerminator,
}
/// One strict SSA function.
#[derive(Debug, PartialEq)]
struct Function {
    name: String,
    params: Vec<String>,
    blocks: Vec<BasicBlock>,
    entry: Label,
    location: crate::ast::SourceLocation,
}
/// A compiler-owned strict SSA program.
#[derive(Debug, PartialEq)]
pub(crate) struct Program {
    functions: Vec<Function>,
}
impl Program {
    /// Construct and verify strict SSA MIR from lowering IR.
    pub(crate) fn from_ir(program: ir::Program) -> Result<Self, String> {
        let functions = program
            .functions
            .into_iter()
            .map(|function| {
                let name = function.name.clone();
                Function::from_ir(function).map_err(|error| format!("function `{name}`: {error}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let program = Self { functions };
        program.verify()?;
        Ok(program)
    }
    /// Optimize the strict SSA program and retain only executable functions.
    ///
    /// Constant propagation is driven by executable CFG edges and explicit Phi inputs. Checked
    /// operations are folded only when evaluation succeeds; an overflow or division-by-zero
    /// operation remains in the MIR so its deterministic trap cannot be optimized away. The final
    /// direct call graph is validated before any function is discarded. Numeric
    /// literal-call substitution requires the exact typed declaration whitelist;
    /// it cannot infer authority or secret-value eligibility from a leaf body.
    pub(crate) fn optimize_and_retain(
        &mut self,
        roots: &BTreeSet<String>,
        private_literals: &BTreeMap<String, ir::DataRefKind>,
    ) -> Result<(), String> {
        self.verify()?;
        for function in &mut self.functions {
            function.optimize()?;
        }
        self.fold_private_literal_calls(roots, private_literals);
        self.retain_reachable_functions(roots)?;
        self.verify()
    }
    fn retain_reachable_functions(&mut self, roots: &BTreeSet<String>) -> Result<(), String> {
        let mut function_indices = BTreeMap::new();
        for (index, function) in self.functions.iter().enumerate() {
            if function_indices
                .insert(function.name.as_str(), index)
                .is_some()
            {
                return Err(format!(
                    "duplicate SSA function symbol `{}` during whole-program DCE",
                    function.name
                ));
            }
        }
        // Validate every surviving direct call before graph pruning. This
        // prevents malformed, currently-dead helper functions from hiding an
        // unresolved symbol. Calls in CFG blocks proven unreachable by SCCP
        // have already been removed with those blocks.
        let mut call_graph = vec![BTreeSet::new(); self.functions.len()];
        for (caller_index, function) in self.functions.iter().enumerate() {
            for block in &function.blocks {
                for instruction in &block.instructions {
                    let callee = match instruction.as_ir() {
                        ir::Instr::Call { callee, .. } | ir::Instr::CallMulti { callee, .. } => {
                            Some(callee.as_str())
                        }
                        _ => None,
                    };
                    let Some(callee) = callee else {
                        continue;
                    };
                    let Some(callee_index) = function_indices.get(callee).copied() else {
                        return Err(format!(
                            "unresolved SSA callee `{callee}` from `{}` during whole-program DCE",
                            function.name
                        ));
                    };
                    call_graph[caller_index].insert(callee_index);
                }
            }
        }
        let mut pending = Vec::with_capacity(roots.len());
        for root in roots.iter().rev() {
            let Some(index) = function_indices.get(root.as_str()).copied() else {
                return Err(format!(
                    "missing SSA root function `{root}` during whole-program DCE"
                ));
            };
            pending.push(index);
        }
        let mut reachable = BTreeSet::new();
        while let Some(index) = pending.pop() {
            if !reachable.insert(index) {
                continue;
            }
            pending.extend(call_graph[index].iter().rev().copied());
        }
        let mut index = 0usize;
        self.functions.retain(|_| {
            let keep = reachable.contains(&index);
            index = index.saturating_add(1);
            keep
        });
        Ok(())
    }
    /// Verify definition uniqueness, Phi edges, and dominance for all uses.
    fn verify(&self) -> Result<(), String> {
        let mut names = HashSet::with_capacity(self.functions.len());
        for function in &self.functions {
            if !names.insert(function.name.as_str()) {
                return Err(format!("duplicate SSA function symbol `{}`", function.name));
            }
            function
                .verify()
                .map_err(|error| format!("function `{}`: {error}", function.name))?;
        }
        Ok(())
    }
    /// Deterministically destroy Phis and rewrite SSA values into temporaries.
    pub(crate) fn into_ir(self) -> Result<ir::Program, String> {
        self.verify()?;
        Ok(ir::Program {
            functions: self
                .functions
                .into_iter()
                .map(Function::into_ir)
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
    #[cfg(test)]
    fn phi_count(&self) -> usize {
        self.functions
            .iter()
            .flat_map(|function| &function.blocks)
            .map(|block| block.phis.len())
            .sum()
    }
}
impl Function {
    fn from_ir(mut function: ir::Function) -> Result<Self, String> {
        enforce_ssa_function_budget(&function)?;
        retain_reachable_lowering_blocks(&mut function)?;
        ensure_entry_preheader(&mut function)?;
        place_entry_first(&mut function)?;
        let cfg = Cfg::new(
            function.entry,
            function
                .blocks
                .iter()
                .map(|block| (block.label, &block.terminator)),
        )?;
        let phi_variables = place_phi_variables(&function.blocks, &cfg);
        let mut renamer = Renamer::new(cfg, phi_variables, function.blocks);
        renamer.rename()?;
        let blocks = renamer.finish()?;
        Ok(Self {
            name: function.name,
            params: function.params,
            blocks,
            entry: function.entry,
            location: function.location,
        })
    }
    fn optimize(&mut self) -> Result<(), String> {
        loop {
            let analysis = SccpAnalysis::analyze(self)?;
            let mut changed = self.apply_sccp(&analysis)?;
            changed |= self.coalesce_trivial_values()?;
            changed |= self.eliminate_dead_values()?;
            changed |= self.simplify_control_flow()?;
            self.verify()?;
            if !changed {
                return Ok(());
            }
        }
    }
    fn apply_sccp(&mut self, analysis: &SccpAnalysis) -> Result<bool, String> {
        let mut changed = false;
        for block in &mut self.blocks {
            let mut constant_phis = Vec::new();
            block.phis.retain(|phi| {
                let SccpValue::Integer(value) = analysis.value(phi.destination) else {
                    return true;
                };
                constant_phis.push((phi.destination, value));
                changed = true;
                false
            });
            constant_phis.sort_by_key(|(destination, _)| *destination);
            if !constant_phis.is_empty() {
                let mut materialized = constant_phis
                    .into_iter()
                    .map(|(destination, value)| {
                        ValueInstruction::new(ir::Instr::Const {
                            dest: destination.encoded(),
                            value,
                        })
                    })
                    .collect::<Vec<_>>();
                materialized.append(&mut block.instructions);
                block.instructions = materialized;
            }
            for instruction in &mut block.instructions {
                if let Some(replacement) = simplify_ssa_instruction(instruction.as_ir(), analysis)
                    && instruction.as_ir() != &replacement
                {
                    *instruction.as_ir_mut() = replacement;
                    changed = true;
                }
            }
            if let ir::Terminator::Branch {
                cond,
                then_bb,
                else_bb,
            } = *block.terminator.as_ir()
            {
                let target = if then_bb == else_bb {
                    Some(then_bb)
                } else {
                    match analysis.value(Value::decode(cond)) {
                        SccpValue::Integer(0) => Some(else_bb),
                        SccpValue::Integer(_) => Some(then_bb),
                        SccpValue::Unknown | SccpValue::Overdefined => None,
                    }
                };
                if let Some(target) = target {
                    *block.terminator.as_ir_mut() = ir::Terminator::Jump(target);
                    changed = true;
                }
            }
        }
        if analysis.executable_blocks.len() != self.blocks.len() {
            let mut index = 0usize;
            self.blocks.retain(|_| {
                let keep = analysis.executable_blocks.contains(&index);
                index = index.saturating_add(1);
                keep
            });
            changed = true;
        }
        reconcile_phi_predecessors(self)?;
        Ok(changed)
    }
    fn coalesce_trivial_values(&mut self) -> Result<bool, String> {
        let mut aliases = projection_and_copy_aliases(self)?;
        let mut equivalence = ValueEquivalence::default();
        for (destination, source) in &aliases {
            equivalence.union(*destination, *source);
        }

        let phi_locations = self
            .blocks
            .iter()
            .enumerate()
            .flat_map(|(block, body)| {
                (0..body.phis.len()).map(move |index| PhiLocation { block, index })
            })
            .collect::<Vec<_>>();
        let mut watchers = BTreeMap::<Value, BTreeSet<usize>>::new();
        let mut phi_class_counts = Vec::with_capacity(phi_locations.len());
        for (phi_id, location) in phi_locations.iter().enumerate() {
            let phi = &self.blocks[location.block].phis[location.index];
            let mut roots = BTreeSet::new();
            roots.insert(equivalence.find(phi.destination));
            roots.extend(phi.inputs.iter().map(|input| equivalence.find(input.value)));
            phi_class_counts.push(roots.len());
            for root in roots {
                watchers.entry(root).or_default().insert(phi_id);
            }
        }

        let mut pending = phi_class_counts
            .iter()
            .enumerate()
            .filter_map(|(phi, classes)| (*classes == 2).then_some(phi))
            .collect::<BTreeSet<_>>();
        let mut removed_phis = vec![false; phi_locations.len()];
        while let Some(phi_id) = pending.pop_first() {
            if removed_phis[phi_id] || phi_class_counts[phi_id] != 2 {
                continue;
            }
            let location = phi_locations[phi_id];
            let phi = &self.blocks[location.block].phis[location.index];
            let destination_root = equivalence.find(phi.destination);
            let mut source = None;
            let mut source_root = None;
            for input in &phi.inputs {
                let root = equivalence.find(input.value);
                if root != destination_root {
                    if source_root.is_some_and(|known| known != root) {
                        return Err(format!(
                            "SSA Phi {:?} class count drifted during coalescing",
                            phi.destination
                        ));
                    }
                    source_root = Some(root);
                    if source.is_none() {
                        source = Some(input.value);
                    }
                }
            }
            let source = source.ok_or_else(|| {
                format!(
                    "SSA Phi {:?} lost its non-self source during coalescing",
                    phi.destination
                )
            })?;
            if aliases.insert(phi.destination, source).is_some() {
                return Err(format!(
                    "SSA Phi destination {:?} is defined more than once",
                    phi.destination
                ));
            }
            removed_phis[phi_id] = true;
            let Some(merged) = equivalence.union(phi.destination, source) else {
                return Err(format!(
                    "trivial SSA Phi {:?} unexpectedly aliases its own equivalence class",
                    phi.destination
                ));
            };
            let left = watchers.remove(&merged.left).unwrap_or_default();
            let right = watchers.remove(&merged.right).unwrap_or_default();
            let (mut combined, smaller) = if left.len() >= right.len() {
                (left, right)
            } else {
                (right, left)
            };
            // Only a Phi mentioning both merged classes loses a distinct
            // class. Moving the smaller watcher set bounds membership work;
            // operand lists are rescanned only when the Phi becomes trivial.
            for phi in smaller {
                if !combined.insert(phi) {
                    if removed_phis[phi] {
                        continue;
                    }
                    phi_class_counts[phi] =
                        phi_class_counts[phi].checked_sub(1).ok_or_else(|| {
                            format!("SSA Phi {phi} class count underflow during coalescing")
                        })?;
                    if phi_class_counts[phi] == 2 {
                        pending.insert(phi);
                    }
                }
            }
            watchers.insert(merged.root, combined);
        }

        if aliases.is_empty() {
            return Ok(false);
        }
        compress_aliases(&mut aliases)?;
        let canonical = |value: Value| aliases.get(&value).copied().unwrap_or(value);
        let mut phi_id = 0usize;
        for block in &mut self.blocks {
            block.phis.retain_mut(|phi| {
                let remove = removed_phis[phi_id];
                phi_id = phi_id.saturating_add(1);
                if !remove {
                    for input in &mut phi.inputs {
                        input.value = canonical(input.value);
                    }
                }
                !remove
            });
            block.instructions.retain_mut(|instruction| {
                if matches!(instruction.as_ir(),
                    ir::Instr::Copy { dest, .. } | ir::Instr::TupleGet { dest, .. }
                        if aliases.contains_key(&Value::decode(*dest)))
                {
                    return false;
                }
                rewrite_instr_uses(instruction.as_ir_mut(), |encoded| {
                    *encoded = canonical(Value::decode(*encoded)).encoded();
                });
                true
            });
            rewrite_terminator_uses(block.terminator.as_ir_mut(), |encoded| {
                *encoded = canonical(Value::decode(*encoded)).encoded();
            });
        }
        Ok(true)
    }
    fn eliminate_dead_values(&mut self) -> Result<bool, String> {
        let mut definitions = BTreeMap::new();
        let mut live_phis = self
            .blocks
            .iter()
            .map(|block| vec![false; block.phis.len()])
            .collect::<Vec<_>>();
        let mut live_instructions = self
            .blocks
            .iter()
            .map(|block| vec![false; block.instructions.len()])
            .collect::<Vec<_>>();
        let mut pending = Vec::new();
        for (block_index, block) in self.blocks.iter().enumerate() {
            for (phi_index, phi) in block.phis.iter().enumerate() {
                if definitions
                    .insert(
                        phi.destination,
                        LiveDefinition::Phi {
                            block: block_index,
                            index: phi_index,
                        },
                    )
                    .is_some()
                {
                    return Err(format!(
                        "SSA value {:?} is defined more than once during dead-value elimination",
                        phi.destination
                    ));
                }
            }
            for (instruction_index, instruction) in block.instructions.iter().enumerate() {
                let mut instruction_definitions = Vec::new();
                visit_instr_defs(instruction.as_ir(), |value| {
                    instruction_definitions.push(Value::decode(value));
                });
                for definition in &instruction_definitions {
                    if definitions
                        .insert(
                            *definition,
                            LiveDefinition::Instruction {
                                block: block_index,
                                index: instruction_index,
                            },
                        )
                        .is_some()
                    {
                        return Err(format!(
                            "SSA value {definition:?} is defined more than once during dead-value elimination"
                        ));
                    }
                }
                if instruction_definitions.is_empty() || !is_ssa_dce_safe(instruction.as_ir()) {
                    live_instructions[block_index][instruction_index] = true;
                    visit_instr_uses(instruction.as_ir(), |value| {
                        pending.push(Value::decode(value));
                    });
                }
            }
            visit_terminator_uses(block.terminator.as_ir(), |value| {
                pending.push(Value::decode(value));
            });
        }

        let mut live_values = BTreeSet::new();
        while let Some(value) = pending.pop() {
            if !live_values.insert(value) {
                continue;
            }
            let definition = definitions.get(&value).copied().ok_or_else(|| {
                format!("SSA value {value:?} has no definition during dead-value elimination")
            })?;
            match definition {
                LiveDefinition::Phi { block, index } => {
                    if live_phis[block][index] {
                        continue;
                    }
                    live_phis[block][index] = true;
                    pending.extend(
                        self.blocks[block].phis[index]
                            .inputs
                            .iter()
                            .map(|input| input.value),
                    );
                }
                LiveDefinition::Instruction { block, index } => {
                    if live_instructions[block][index] {
                        continue;
                    }
                    live_instructions[block][index] = true;
                    visit_instr_uses(self.blocks[block].instructions[index].as_ir(), |used| {
                        pending.push(Value::decode(used))
                    });
                }
            }
        }

        let mut changed = false;
        for (block_index, block) in self.blocks.iter_mut().enumerate() {
            let mut phi_index = 0usize;
            block.phis.retain(|_| {
                let keep = live_phis[block_index][phi_index];
                phi_index = phi_index.saturating_add(1);
                changed |= !keep;
                keep
            });
            let mut instruction_index = 0usize;
            block.instructions.retain(|_| {
                let keep = live_instructions[block_index][instruction_index];
                instruction_index = instruction_index.saturating_add(1);
                changed |= !keep;
                keep
            });
        }
        Ok(changed)
    }
    fn simplify_control_flow(&mut self) -> Result<bool, String> {
        let phi_labels = self
            .blocks
            .iter()
            .filter(|block| !block.phis.is_empty())
            .map(|block| block.label)
            .collect::<HashSet<_>>();
        let trampolines = self
            .blocks
            .iter()
            .filter_map(|block| {
                let ir::Terminator::Jump(target) = block.terminator.as_ir() else {
                    return None;
                };
                (block.label != self.entry
                    && block.label != *target
                    && block.phis.is_empty()
                    && block.instructions.is_empty()
                    && !phi_labels.contains(target))
                .then_some((block.label, *target))
            })
            .collect::<HashMap<_, _>>();
        let entry_target = self
            .blocks
            .iter()
            .find(|block| block.label == self.entry)
            .and_then(|block| {
                let ir::Terminator::Jump(target) = block.terminator.as_ir() else {
                    return None;
                };
                let eligible = block.phis.is_empty()
                    && block.instructions.is_empty()
                    && *target != self.entry
                    && !phi_labels.contains(target);
                let resolved = resolve_ssa_trampoline(*target, &trampolines);
                (eligible && resolved != self.entry).then_some(resolved)
            });
        if trampolines.is_empty() && entry_target.is_none() {
            return Ok(false);
        }
        let mut changed = false;
        if let Some(entry_target) = entry_target {
            self.entry = entry_target;
            changed = true;
        }
        for block in &mut self.blocks {
            let source = block.label;
            let replacement = match block.terminator.as_ir() {
                ir::Terminator::Jump(target) => {
                    let mut resolved = resolve_ssa_trampoline(*target, &trampolines);
                    if resolved == source {
                        resolved = *target;
                    }
                    (resolved != *target).then_some(ir::Terminator::Jump(resolved))
                }
                ir::Terminator::Branch {
                    cond,
                    then_bb,
                    else_bb,
                } => {
                    let mut resolved_then = resolve_ssa_trampoline(*then_bb, &trampolines);
                    let mut resolved_else = resolve_ssa_trampoline(*else_bb, &trampolines);
                    if resolved_then == source {
                        resolved_then = *then_bb;
                    }
                    if resolved_else == source {
                        resolved_else = *else_bb;
                    }
                    if resolved_then == resolved_else {
                        Some(ir::Terminator::Jump(resolved_then))
                    } else if resolved_then != *then_bb || resolved_else != *else_bb {
                        Some(ir::Terminator::Branch {
                            cond: *cond,
                            then_bb: resolved_then,
                            else_bb: resolved_else,
                        })
                    } else {
                        None
                    }
                }
                ir::Terminator::Return(_)
                | ir::Terminator::Return2(_, _)
                | ir::Terminator::ReturnN(_) => None,
            };
            if let Some(replacement) = replacement {
                *block.terminator.as_ir_mut() = replacement;
                changed = true;
            }
        }
        if changed {
            retain_reachable_ssa_blocks(self)?;
            place_ssa_entry_first(self)?;
        }
        Ok(changed)
    }
    fn into_ir(self) -> Result<ir::Function, String> {
        let mut values = BTreeSet::new();
        for block in &self.blocks {
            for phi in &block.phis {
                values.insert(phi.destination);
                values.extend(phi.inputs.iter().map(|input| input.value));
            }
            for instruction in &block.instructions {
                visit_instr_uses(instruction.as_ir(), |encoded| {
                    values.insert(Value::decode(encoded));
                });
                visit_instr_defs(instruction.as_ir(), |encoded| {
                    values.insert(Value::decode(encoded));
                });
            }
            visit_terminator_uses(block.terminator.as_ir(), |encoded| {
                values.insert(Value::decode(encoded));
            });
        }
        let value_temps = values
            .into_iter()
            .enumerate()
            .map(|(index, value)| (value, Temp(index)))
            .collect::<BTreeMap<_, _>>();
        let mut next_temp = value_temps.len();
        let mut edge_copies = BTreeMap::<(usize, usize), Vec<(Temp, Temp)>>::new();
        for block in &self.blocks {
            for phi in &block.phis {
                let destination = value_temp(&value_temps, phi.destination)?;
                for input in &phi.inputs {
                    edge_copies
                        .entry((input.predecessor.0, block.label.0))
                        .or_default()
                        .push((destination, value_temp(&value_temps, input.value)?));
                }
            }
        }
        let mut blocks = self
            .blocks
            .into_iter()
            .map(|block| {
                let mut instructions = Vec::new();
                let mut source = None;
                for instruction in block.instructions {
                    if source != instruction.1 {
                        source = instruction.1;
                        instructions.push(ir::Instr::Source(source));
                    }
                    instructions.push(instruction.into_ir());
                }
                for instruction in &mut instructions {
                    rewrite_instruction_values(instruction, &value_temps)?;
                }
                if source != block.terminator.1 {
                    instructions.push(ir::Instr::Source(block.terminator.1));
                }
                let mut terminator = block.terminator.into_ir();
                rewrite_terminator_values(&mut terminator, &value_temps)?;
                Ok(ir::BasicBlock {
                    label: block.label,
                    instrs: instructions,
                    terminator,
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let mut label_to_index = blocks
            .iter()
            .enumerate()
            .map(|(index, block)| (block.label, index))
            .collect::<HashMap<_, _>>();
        let mut next_label = blocks
            .iter()
            .map(|block| block.label.0)
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| "SSA block-label space exhausted during Phi destruction".to_owned())?;
        for ((predecessor, target), copies) in edge_copies {
            let predecessor = Label(predecessor);
            let target = Label(target);
            let scheduled = schedule_parallel_copies(copies, &mut next_temp)?;
            if scheduled.is_empty() {
                continue;
            }
            let predecessor_index = label_to_index.get(&predecessor).copied().ok_or_else(|| {
                format!("missing Phi predecessor {predecessor:?} during SSA destruction")
            })?;
            if successor_labels(&blocks[predecessor_index].terminator).len() > 1 {
                let split = Label(next_label);
                next_label = next_label.checked_add(1).ok_or_else(|| {
                    "SSA block-label space exhausted during critical-edge splitting".to_owned()
                })?;
                retarget_edge(&mut blocks[predecessor_index].terminator, target, split)?;
                let split_index = blocks.len();
                blocks.push(ir::BasicBlock {
                    label: split,
                    instrs: scheduled,
                    terminator: ir::Terminator::Jump(target),
                });
                label_to_index.insert(split, split_index);
            } else {
                if !successor_labels(&blocks[predecessor_index].terminator).contains(&target) {
                    return Err(format!(
                        "Phi predecessor {predecessor:?} has no edge to {target:?}"
                    ));
                }
                // Phi copies are generated edge transport, not execution of the preceding
                // source statement. Restore the original terminator site after those copies.
                let source = blocks[predecessor_index]
                    .instrs
                    .iter()
                    .rev()
                    .find_map(|instruction| {
                        if let ir::Instr::Source(source) = instruction {
                            Some(*source)
                        } else {
                            None
                        }
                    })
                    .flatten();
                if source.is_some() {
                    blocks[predecessor_index]
                        .instrs
                        .push(ir::Instr::Source(None));
                }
                blocks[predecessor_index].instrs.extend(scheduled);
                if source.is_some() {
                    blocks[predecessor_index]
                        .instrs
                        .push(ir::Instr::Source(source));
                }
            }
        }
        Cfg::new(
            self.entry,
            blocks.iter().map(|block| (block.label, &block.terminator)),
        )?;
        Ok(ir::Function {
            name: self.name,
            params: self.params,
            blocks,
            entry: self.entry,
            location: self.location,
        })
    }
    fn verify(&self) -> Result<(), String> {
        let cfg = Cfg::new(
            self.entry,
            self.blocks
                .iter()
                .map(|block| (block.label, block.terminator.as_ir())),
        )?;
        let mut definitions = HashMap::<Value, DefinitionSite>::new();
        for (block_index, block) in self.blocks.iter().enumerate() {
            let mut phi_variables = HashSet::with_capacity(block.phis.len());
            let expected_predecessors = cfg.predecessor_labels(block_index);
            if expected_predecessors.is_empty() && !block.phis.is_empty() {
                return Err(format!(
                    "SSA entry block {:?} cannot define a zero-input Phi",
                    block.label
                ));
            }
            for phi in &block.phis {
                if !phi_variables.insert(phi.variable) {
                    return Err(format!(
                        "SSA block {:?} contains duplicate Phi variable {:?}",
                        block.label, phi.variable
                    ));
                }
                insert_definition(
                    &mut definitions,
                    phi.destination,
                    block_index,
                    DefinitionPosition::Phi,
                )?;
                let actual_predecessors = phi
                    .inputs
                    .iter()
                    .map(|input| input.predecessor)
                    .collect::<Vec<_>>();
                if actual_predecessors != expected_predecessors {
                    return Err(format!(
                        "SSA Phi {:?} in block {:?} has inputs {:?}, expected {:?}",
                        phi.variable, block.label, actual_predecessors, expected_predecessors
                    ));
                }
            }
            for (instruction_index, instruction) in block.instructions.iter().enumerate() {
                validate_ssa_instruction(instruction.as_ir())?;
                let mut failure = None;
                visit_instr_defs(instruction.as_ir(), |encoded| {
                    if failure.is_none() {
                        failure = insert_definition(
                            &mut definitions,
                            Value::decode(encoded),
                            block_index,
                            DefinitionPosition::Instruction(instruction_index),
                        )
                        .err();
                    }
                });
                if let Some(error) = failure {
                    return Err(error);
                }
            }
        }
        for (block_index, block) in self.blocks.iter().enumerate() {
            for phi in &block.phis {
                for input in &phi.inputs {
                    let predecessor = cfg.index(input.predecessor)?;
                    verify_use(
                        &definitions,
                        &cfg,
                        input.value,
                        predecessor,
                        UsePosition::Edge,
                    )?;
                }
            }
            for (instruction_index, instruction) in block.instructions.iter().enumerate() {
                let mut failure = None;
                visit_instr_uses(instruction.as_ir(), |encoded| {
                    if failure.is_none() {
                        failure = verify_use(
                            &definitions,
                            &cfg,
                            Value::decode(encoded),
                            block_index,
                            UsePosition::Instruction(instruction_index),
                        )
                        .err();
                    }
                });
                if let Some(error) = failure {
                    return Err(error);
                }
            }
            let mut failure = None;
            visit_terminator_uses(block.terminator.as_ir(), |encoded| {
                if failure.is_none() {
                    failure = verify_use(
                        &definitions,
                        &cfg,
                        Value::decode(encoded),
                        block_index,
                        UsePosition::Terminator,
                    )
                    .err();
                }
            });
            if let Some(error) = failure {
                return Err(error);
            }
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SccpValue {
    Unknown,
    Integer(i64),
    Overdefined,
}
fn merge_sccp_value(left: SccpValue, right: SccpValue) -> SccpValue {
    match (left, right) {
        (SccpValue::Unknown, value) | (value, SccpValue::Unknown) => value,
        (SccpValue::Integer(left), SccpValue::Integer(right)) if left == right => {
            SccpValue::Integer(left)
        }
        (SccpValue::Integer(_), SccpValue::Integer(_))
        | (SccpValue::Overdefined, _)
        | (_, SccpValue::Overdefined) => SccpValue::Overdefined,
    }
}
struct SccpAnalysis {
    values: BTreeMap<Value, SccpValue>,
    executable_blocks: BTreeSet<usize>,
    executable_edges: BTreeSet<(usize, usize)>,
}
impl SccpAnalysis {
    fn analyze(function: &Function) -> Result<Self, String> {
        let cfg = Cfg::new(
            function.entry,
            function
                .blocks
                .iter()
                .map(|block| (block.label, block.terminator.as_ir())),
        )?;
        let mut analysis = Self {
            values: BTreeMap::new(),
            executable_blocks: BTreeSet::from([cfg.entry]),
            executable_edges: BTreeSet::new(),
        };
        let mut value_users = BTreeMap::<Value, BTreeSet<usize>>::new();
        for (block_index, block) in function.blocks.iter().enumerate() {
            for phi in &block.phis {
                for input in &phi.inputs {
                    value_users
                        .entry(input.value)
                        .or_default()
                        .insert(block_index);
                }
            }
            for instruction in &block.instructions {
                visit_instr_uses(instruction.as_ir(), |encoded| {
                    value_users
                        .entry(Value::decode(encoded))
                        .or_default()
                        .insert(block_index);
                });
            }
            visit_terminator_uses(block.terminator.as_ir(), |encoded| {
                value_users
                    .entry(Value::decode(encoded))
                    .or_default()
                    .insert(block_index);
            });
        }
        let mut pending = BTreeSet::from([cfg.entry]);
        loop {
            while let Some(block_index) = pending.pop_first() {
                if !analysis.executable_blocks.contains(&block_index) {
                    continue;
                }
                let block = &function.blocks[block_index];
                for phi in &block.phis {
                    let mut state = SccpValue::Unknown;
                    for input in &phi.inputs {
                        let predecessor = cfg.index(input.predecessor)?;
                        if analysis
                            .executable_edges
                            .contains(&(predecessor, block_index))
                        {
                            state = merge_sccp_value(state, analysis.value(input.value));
                        }
                    }
                    if analysis.merge_definition(phi.destination, state)
                        && let Some(users) = value_users.get(&phi.destination)
                    {
                        pending.extend(
                            users
                                .iter()
                                .filter(|user| analysis.executable_blocks.contains(user))
                                .copied(),
                        );
                    }
                }
                for instruction in &block.instructions {
                    let evaluated = evaluate_ssa_instruction(instruction.as_ir(), &analysis);
                    let mut definitions = Vec::new();
                    visit_instr_defs(instruction.as_ir(), |encoded| {
                        definitions.push(Value::decode(encoded));
                    });
                    for definition in definitions {
                        let state = evaluated
                            .filter(|(destination, _)| *destination == definition)
                            .map_or(SccpValue::Overdefined, |(_, state)| state);
                        if analysis.merge_definition(definition, state)
                            && let Some(users) = value_users.get(&definition)
                        {
                            pending.extend(
                                users
                                    .iter()
                                    .filter(|user| analysis.executable_blocks.contains(user))
                                    .copied(),
                            );
                        }
                    }
                }
                let targets = match block.terminator.as_ir() {
                    ir::Terminator::Jump(target) => vec![*target],
                    ir::Terminator::Branch {
                        cond,
                        then_bb,
                        else_bb,
                    } => {
                        if then_bb == else_bb {
                            vec![*then_bb]
                        } else {
                            match analysis.value(Value::decode(*cond)) {
                                SccpValue::Integer(0) => vec![*else_bb],
                                SccpValue::Integer(_) => vec![*then_bb],
                                SccpValue::Overdefined => vec![*then_bb, *else_bb],
                                SccpValue::Unknown => Vec::new(),
                            }
                        }
                    }
                    ir::Terminator::Return(_)
                    | ir::Terminator::Return2(_, _)
                    | ir::Terminator::ReturnN(_) => Vec::new(),
                };
                for target in targets {
                    let target_index = cfg.index(target)?;
                    if analysis.mark_edge(&cfg, block_index, target)? {
                        pending.insert(target_index);
                    }
                }
            }
            // A verifier-valid cyclic Phi graph can remain lattice-bottom
            // without a concrete seed. Do not mistake that for proof that its
            // branch successors are unreachable: conservatively make both
            // edges executable once ordinary propagation reaches a fixed
            // point.
            let mut forced_edge = false;
            for (block_index, block) in function.blocks.iter().enumerate() {
                if !analysis.executable_blocks.contains(&block_index) {
                    continue;
                }
                let ir::Terminator::Branch {
                    cond,
                    then_bb,
                    else_bb,
                } = block.terminator.as_ir()
                else {
                    continue;
                };
                if then_bb == else_bb || analysis.value(Value::decode(*cond)) != SccpValue::Unknown
                {
                    continue;
                }
                for target in [*then_bb, *else_bb] {
                    let target_index = cfg.index(target)?;
                    if analysis.mark_edge(&cfg, block_index, target)? {
                        pending.insert(target_index);
                        forced_edge = true;
                    }
                }
            }
            if !forced_edge {
                return Ok(analysis);
            }
        }
    }
    fn value(&self, value: Value) -> SccpValue {
        self.values
            .get(&value)
            .copied()
            .unwrap_or(SccpValue::Unknown)
    }
    fn merge_definition(&mut self, destination: Value, state: SccpValue) -> bool {
        let previous = self.value(destination);
        let merged = merge_sccp_value(previous, state);
        if merged == previous {
            return false;
        }
        self.values.insert(destination, merged);
        true
    }
    fn mark_edge(&mut self, cfg: &Cfg, from: usize, target: Label) -> Result<bool, String> {
        let target = cfg.index(target)?;
        let edge_changed = self.executable_edges.insert((from, target));
        let block_changed = self.executable_blocks.insert(target);
        Ok(edge_changed || block_changed)
    }
}
fn evaluate_ssa_instruction(
    instruction: &ir::Instr,
    analysis: &SccpAnalysis,
) -> Option<(Value, SccpValue)> {
    let binary = |destination: Temp,
                  left: Temp,
                  right: Temp,
                  evaluate: fn(crate::ast::BinaryOp, i64, i64) -> Option<i64>,
                  op| {
        let state = match (
            analysis.value(Value::decode(left)),
            analysis.value(Value::decode(right)),
        ) {
            (SccpValue::Integer(left), SccpValue::Integer(right)) => {
                evaluate(op, left, right).map_or(SccpValue::Overdefined, SccpValue::Integer)
            }
            (SccpValue::Overdefined, _) | (_, SccpValue::Overdefined) => SccpValue::Overdefined,
            (SccpValue::Unknown, _) | (_, SccpValue::Unknown) => SccpValue::Unknown,
        };
        (Value::decode(destination), state)
    };
    Some(match instruction {
        ir::Instr::Const { dest, value } => (Value::decode(*dest), SccpValue::Integer(*value)),
        ir::Instr::Copy { dest, src } => {
            (Value::decode(*dest), analysis.value(Value::decode(*src)))
        }
        ir::Instr::Binary {
            dest,
            op,
            left,
            right,
        } => binary(*dest, *left, *right, checked_binary_constant, *op),
        ir::Instr::WrappingBinary {
            dest,
            op,
            left,
            right,
        } => binary(*dest, *left, *right, wrapping_binary_constant, *op),
        ir::Instr::Unary { dest, op, operand } => {
            let state = match analysis.value(Value::decode(*operand)) {
                SccpValue::Integer(value) => {
                    unary_constant(*op, value).map_or(SccpValue::Overdefined, SccpValue::Integer)
                }
                SccpValue::Unknown => SccpValue::Unknown,
                SccpValue::Overdefined => SccpValue::Overdefined,
            };
            (Value::decode(*dest), state)
        }
        ir::Instr::WrappingNeg { dest, operand } => {
            let state = match analysis.value(Value::decode(*operand)) {
                SccpValue::Integer(value) => SccpValue::Integer(value.wrapping_neg()),
                SccpValue::Unknown => SccpValue::Unknown,
                SccpValue::Overdefined => SccpValue::Overdefined,
            };
            (Value::decode(*dest), state)
        }
        _ => return None,
    })
}
fn checked_binary_constant(op: crate::ast::BinaryOp, left: i64, right: i64) -> Option<i64> {
    use crate::ast::BinaryOp;
    match op {
        BinaryOp::Add => left.checked_add(right),
        BinaryOp::Sub => left.checked_sub(right),
        BinaryOp::Mul => left.checked_mul(right),
        BinaryOp::Div => left.checked_div(right),
        BinaryOp::Mod => left.checked_rem(right),
        BinaryOp::And => Some(left & right),
        BinaryOp::Or => Some(left | right),
        BinaryOp::Eq => Some(i64::from(left == right)),
        BinaryOp::Ne => Some(i64::from(left != right)),
        BinaryOp::Lt => Some(i64::from(left < right)),
        BinaryOp::Le => Some(i64::from(left <= right)),
        BinaryOp::Gt => Some(i64::from(left > right)),
        BinaryOp::Ge => Some(i64::from(left >= right)),
    }
}
fn wrapping_binary_constant(op: crate::ast::BinaryOp, left: i64, right: i64) -> Option<i64> {
    use crate::ast::BinaryOp;
    match op {
        BinaryOp::Add => Some(left.wrapping_add(right)),
        BinaryOp::Sub => Some(left.wrapping_sub(right)),
        BinaryOp::Mul => Some(left.wrapping_mul(right)),
        BinaryOp::Div
        | BinaryOp::Mod
        | BinaryOp::And
        | BinaryOp::Or
        | BinaryOp::Eq
        | BinaryOp::Ne
        | BinaryOp::Lt
        | BinaryOp::Le
        | BinaryOp::Gt
        | BinaryOp::Ge => None,
    }
}
fn unary_constant(op: crate::ast::UnaryOp, operand: i64) -> Option<i64> {
    match op {
        crate::ast::UnaryOp::Neg => operand.checked_neg(),
        crate::ast::UnaryOp::Not => Some(i64::from(operand == 0)),
    }
}
fn integer_value(analysis: &SccpAnalysis, encoded: Temp) -> Option<i64> {
    match analysis.value(Value::decode(encoded)) {
        SccpValue::Integer(value) => Some(value),
        SccpValue::Unknown | SccpValue::Overdefined => None,
    }
}
fn simplify_ssa_instruction(instruction: &ir::Instr, analysis: &SccpAnalysis) -> Option<ir::Instr> {
    use crate::ast::BinaryOp;
    match instruction {
        ir::Instr::Copy { dest, src } => {
            integer_value(analysis, *src).map(|value| ir::Instr::Const { dest: *dest, value })
        }
        ir::Instr::Binary {
            dest,
            op,
            left,
            right,
        } => {
            let left_constant = integer_value(analysis, *left);
            let right_constant = integer_value(analysis, *right);
            if let (Some(left), Some(right)) = (left_constant, right_constant) {
                return checked_binary_constant(*op, left, right)
                    .map(|value| ir::Instr::Const { dest: *dest, value });
            }
            match op {
                // Checked addition is also used as the typed DataRef
                // materialization marker, so it is intentionally not erased.
                BinaryOp::Add => None,
                BinaryOp::Sub if right_constant == Some(0) => Some(ir::Instr::Copy {
                    dest: *dest,
                    src: *left,
                }),
                BinaryOp::Sub if left == right => Some(ir::Instr::Const {
                    dest: *dest,
                    value: 0,
                }),
                BinaryOp::Mul if left_constant == Some(0) || right_constant == Some(0) => {
                    Some(ir::Instr::Const {
                        dest: *dest,
                        value: 0,
                    })
                }
                BinaryOp::Mul if left_constant == Some(1) => Some(ir::Instr::Copy {
                    dest: *dest,
                    src: *right,
                }),
                BinaryOp::Mul if right_constant == Some(1) => Some(ir::Instr::Copy {
                    dest: *dest,
                    src: *left,
                }),
                BinaryOp::Div if right_constant == Some(1) => Some(ir::Instr::Copy {
                    dest: *dest,
                    src: *left,
                }),
                BinaryOp::And if left_constant == Some(0) || right_constant == Some(0) => {
                    Some(ir::Instr::Const {
                        dest: *dest,
                        value: 0,
                    })
                }
                BinaryOp::And if left_constant == Some(-1) => Some(ir::Instr::Copy {
                    dest: *dest,
                    src: *right,
                }),
                BinaryOp::And if right_constant == Some(-1) => Some(ir::Instr::Copy {
                    dest: *dest,
                    src: *left,
                }),
                BinaryOp::Or if left_constant == Some(0) => Some(ir::Instr::Copy {
                    dest: *dest,
                    src: *right,
                }),
                BinaryOp::Or if right_constant == Some(0) => Some(ir::Instr::Copy {
                    dest: *dest,
                    src: *left,
                }),
                BinaryOp::Or if left_constant == Some(-1) || right_constant == Some(-1) => {
                    Some(ir::Instr::Const {
                        dest: *dest,
                        value: -1,
                    })
                }
                BinaryOp::Eq | BinaryOp::Le | BinaryOp::Ge if left == right => {
                    Some(ir::Instr::Const {
                        dest: *dest,
                        value: 1,
                    })
                }
                BinaryOp::Ne | BinaryOp::Lt | BinaryOp::Gt if left == right => {
                    Some(ir::Instr::Const {
                        dest: *dest,
                        value: 0,
                    })
                }
                BinaryOp::Sub
                | BinaryOp::Mul
                | BinaryOp::Div
                | BinaryOp::Mod
                | BinaryOp::And
                | BinaryOp::Or
                | BinaryOp::Eq
                | BinaryOp::Ne
                | BinaryOp::Lt
                | BinaryOp::Le
                | BinaryOp::Gt
                | BinaryOp::Ge => None,
            }
        }
        ir::Instr::WrappingBinary {
            dest,
            op,
            left,
            right,
        } => {
            let left_constant = integer_value(analysis, *left);
            let right_constant = integer_value(analysis, *right);
            if let (Some(left), Some(right)) = (left_constant, right_constant) {
                return wrapping_binary_constant(*op, left, right)
                    .map(|value| ir::Instr::Const { dest: *dest, value });
            }
            match op {
                BinaryOp::Add if left_constant == Some(0) => Some(ir::Instr::Copy {
                    dest: *dest,
                    src: *right,
                }),
                BinaryOp::Add if right_constant == Some(0) => Some(ir::Instr::Copy {
                    dest: *dest,
                    src: *left,
                }),
                BinaryOp::Sub if right_constant == Some(0) => Some(ir::Instr::Copy {
                    dest: *dest,
                    src: *left,
                }),
                BinaryOp::Sub if left == right => Some(ir::Instr::Const {
                    dest: *dest,
                    value: 0,
                }),
                BinaryOp::Mul if left_constant == Some(0) || right_constant == Some(0) => {
                    Some(ir::Instr::Const {
                        dest: *dest,
                        value: 0,
                    })
                }
                BinaryOp::Mul if left_constant == Some(1) => Some(ir::Instr::Copy {
                    dest: *dest,
                    src: *right,
                }),
                BinaryOp::Mul if right_constant == Some(1) => Some(ir::Instr::Copy {
                    dest: *dest,
                    src: *left,
                }),
                BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul => None,
                BinaryOp::Div
                | BinaryOp::Mod
                | BinaryOp::And
                | BinaryOp::Or
                | BinaryOp::Eq
                | BinaryOp::Ne
                | BinaryOp::Lt
                | BinaryOp::Le
                | BinaryOp::Gt
                | BinaryOp::Ge => None,
            }
        }
        ir::Instr::Unary { dest, op, operand } => integer_value(analysis, *operand)
            .and_then(|operand| unary_constant(*op, operand))
            .map(|value| ir::Instr::Const { dest: *dest, value }),
        ir::Instr::WrappingNeg { dest, operand } => {
            integer_value(analysis, *operand).map(|value| ir::Instr::Const {
                dest: *dest,
                value: value.wrapping_neg(),
            })
        }
        _ => None,
    }
}
#[derive(Clone, Copy)]
struct PhiLocation {
    block: usize,
    index: usize,
}
#[derive(Clone, Copy)]
enum LiveDefinition {
    Phi { block: usize, index: usize },
    Instruction { block: usize, index: usize },
}
#[derive(Clone, Copy)]
struct EquivalenceMerge {
    left: Value,
    right: Value,
    root: Value,
}
#[derive(Default)]
struct ValueEquivalence {
    parents: BTreeMap<Value, Value>,
    ranks: BTreeMap<Value, u8>,
}
impl ValueEquivalence {
    fn find(&mut self, value: Value) -> Value {
        let mut root = value;
        while let Some(parent) = self.parents.get(&root).copied() {
            if parent == root {
                break;
            }
            root = parent;
        }
        self.parents.entry(root).or_insert(root);
        let mut current = value;
        while let Some(parent) = self.parents.get(&current).copied() {
            if parent == root {
                break;
            }
            self.parents.insert(current, root);
            current = parent;
        }
        self.parents.entry(value).or_insert(root);
        root
    }
    fn union(&mut self, left: Value, right: Value) -> Option<EquivalenceMerge> {
        let left = self.find(left);
        let right = self.find(right);
        if left == right {
            return None;
        }
        let left_rank = self.ranks.get(&left).copied().unwrap_or(0);
        let right_rank = self.ranks.get(&right).copied().unwrap_or(0);
        let (root, child, increment_rank) = if left_rank > right_rank {
            (left, right, false)
        } else if right_rank > left_rank {
            (right, left, false)
        } else if left <= right {
            (left, right, true)
        } else {
            (right, left, true)
        };
        self.parents.insert(child, root);
        if increment_rank {
            self.ranks.insert(root, left_rank.saturating_add(1));
        }
        Some(EquivalenceMerge { left, right, root })
    }
}
/// Products are immutable virtual collections of SSA values. Selecting a
/// known field therefore aliases the original value; materializing intermediate
/// projections only increases live ranges, spills, and stack-address code.
/// Resolve copy/projection chains in one memoized, iterative walk so deeply
/// nested records and repeated field updates do not require quadratic passes.
fn projection_and_copy_aliases(function: &Function) -> Result<BTreeMap<Value, Value>, String> {
    let mut definitions = BTreeMap::new();
    for instruction in function.blocks.iter().flat_map(|block| &block.instructions) {
        if let ir::Instr::Copy { dest, .. }
        | ir::Instr::TupleGet { dest, .. }
        | ir::Instr::TuplePack { dest, .. } = instruction.as_ir()
        {
            let destination = Value::decode(*dest);
            if definitions
                .insert(destination, instruction.as_ir())
                .is_some()
            {
                return Err(format!(
                    "SSA product/copy destination {destination:?} is defined more than once"
                ));
            }
        }
    }
    enum Pending {
        Visit(Value),
        Alias {
            destination: Value,
            source: Value,
        },
        Project {
            destination: Value,
            tuple: Value,
            index: usize,
        },
    }
    let mut resolved = BTreeMap::new();
    let mut active = BTreeSet::new();
    for &value in definitions.keys() {
        let mut pending = vec![Pending::Visit(value)];
        while let Some(operation) = pending.pop() {
            match operation {
                Pending::Visit(value) => {
                    if resolved.contains_key(&value) {
                        continue;
                    }
                    if !active.insert(value) {
                        return Err(format!("cyclic SSA product/copy alias at {value:?}"));
                    }
                    match definitions.get(&value).copied() {
                        Some(ir::Instr::Copy { src, .. }) => {
                            let source = Value::decode(*src);
                            pending.push(Pending::Alias {
                                destination: value,
                                source,
                            });
                            pending.push(Pending::Visit(source));
                        }
                        Some(ir::Instr::TupleGet { tuple, index, .. }) => {
                            let tuple = Value::decode(*tuple);
                            pending.push(Pending::Project {
                                destination: value,
                                tuple,
                                index: *index,
                            });
                            pending.push(Pending::Visit(tuple));
                        }
                        _ => {
                            resolved.insert(value, value);
                            active.remove(&value);
                        }
                    }
                }
                Pending::Alias {
                    destination,
                    source,
                } => {
                    let source = resolved[&source];
                    resolved.insert(destination, source);
                    active.remove(&destination);
                }
                Pending::Project {
                    destination,
                    tuple,
                    index,
                } => {
                    let tuple = resolved[&tuple];
                    if let Some(ir::Instr::TuplePack { items, .. }) =
                        definitions.get(&tuple).copied()
                    {
                        let source = items.get(index).copied().ok_or_else(|| {
                            format!(
                                "SSA product projection {index} exceeds tuple width {}",
                                items.len()
                            )
                        })?;
                        let source = Value::decode(source);
                        pending.push(Pending::Alias {
                            destination,
                            source,
                        });
                        pending.push(Pending::Visit(source));
                    } else {
                        // A nontrivial Phi or runtime value is not a known pack.
                        resolved.insert(destination, destination);
                        active.remove(&destination);
                    }
                }
            }
        }
    }
    Ok(resolved
        .into_iter()
        .filter(|(value, source)| value != source)
        .collect())
}
fn compress_aliases(aliases: &mut BTreeMap<Value, Value>) -> Result<(), String> {
    let destinations = aliases.keys().copied().collect::<Vec<_>>();
    for destination in destinations {
        let mut current = destination;
        let mut path = Vec::new();
        let mut visited = BTreeSet::new();
        while let Some(source) = aliases.get(&current).copied() {
            if !visited.insert(current) {
                return Err(format!(
                    "cyclic SSA value aliases include {current:?} during coalescing"
                ));
            }
            path.push(current);
            current = source;
        }
        for value in path {
            aliases.insert(value, current);
        }
    }
    Ok(())
}
fn is_ssa_dce_safe(instruction: &ir::Instr) -> bool {
    match instruction {
        ir::Instr::Const { .. }
        | ir::Instr::StringConst { .. }
        | ir::Instr::DataRef { .. }
        | ir::Instr::LoadVar { .. }
        | ir::Instr::Copy { .. }
        | ir::Instr::TuplePack { .. }
        | ir::Instr::TupleGet { .. }
        | ir::Instr::PointerFromString { .. }
        | ir::Instr::WrappingNeg { .. } => true,
        ir::Instr::WrappingBinary { op, .. } => matches!(
            op,
            crate::ast::BinaryOp::Add | crate::ast::BinaryOp::Sub | crate::ast::BinaryOp::Mul
        ),
        ir::Instr::Binary { op, .. } => matches!(
            op,
            crate::ast::BinaryOp::And
                | crate::ast::BinaryOp::Or
                | crate::ast::BinaryOp::Eq
                | crate::ast::BinaryOp::Ne
                | crate::ast::BinaryOp::Lt
                | crate::ast::BinaryOp::Le
                | crate::ast::BinaryOp::Gt
                | crate::ast::BinaryOp::Ge
        ),
        ir::Instr::Unary { op, .. } => matches!(op, crate::ast::UnaryOp::Not),
        _ => false,
    }
}
fn validate_ssa_instruction(instruction: &ir::Instr) -> Result<(), String> {
    if let ir::Instr::WrappingBinary { op, .. } = instruction
        && !matches!(
            op,
            crate::ast::BinaryOp::Add | crate::ast::BinaryOp::Sub | crate::ast::BinaryOp::Mul
        )
    {
        return Err(format!(
            "invalid wrapping binary opcode {op:?}; only add, sub, and mul are defined"
        ));
    }
    Ok(())
}
fn resolve_ssa_trampoline(mut label: Label, trampolines: &HashMap<Label, Label>) -> Label {
    let original = label;
    let mut visited = HashSet::new();
    while let Some(target) = trampolines.get(&label).copied() {
        if !visited.insert(label) {
            return original;
        }
        label = target;
    }
    label
}
fn retain_reachable_ssa_blocks(function: &mut Function) -> Result<(), String> {
    let mut label_to_index = HashMap::with_capacity(function.blocks.len());
    for (index, block) in function.blocks.iter().enumerate() {
        if label_to_index.insert(block.label, index).is_some() {
            return Err(format!("duplicate SSA block label {:?}", block.label));
        }
    }
    let Some(entry) = label_to_index.get(&function.entry).copied() else {
        return Err(format!("missing SSA entry block {:?}", function.entry));
    };
    for block in &function.blocks {
        for target in successor_labels(block.terminator.as_ir()) {
            if !label_to_index.contains_key(&target) {
                return Err(format!(
                    "SSA block {:?} targets missing block {target:?}",
                    block.label
                ));
            }
        }
    }
    let mut reachable = BTreeSet::new();
    let mut pending = vec![entry];
    while let Some(index) = pending.pop() {
        if !reachable.insert(index) {
            continue;
        }
        let mut successors = successor_labels(function.blocks[index].terminator.as_ir())
            .into_iter()
            .map(|target| {
                label_to_index.get(&target).copied().ok_or_else(|| {
                    format!(
                        "SSA block {:?} targets missing block {target:?}",
                        function.blocks[index].label
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        successors.reverse();
        pending.extend(successors);
    }
    let mut index = 0usize;
    function.blocks.retain(|_| {
        let keep = reachable.contains(&index);
        index = index.saturating_add(1);
        keep
    });
    reconcile_phi_predecessors(function)
}
fn place_ssa_entry_first(function: &mut Function) -> Result<(), String> {
    let entry_index = function
        .blocks
        .iter()
        .position(|block| block.label == function.entry)
        .ok_or_else(|| format!("missing SSA entry block {:?}", function.entry))?;
    if entry_index != 0 {
        let entry = function.blocks.remove(entry_index);
        function.blocks.insert(0, entry);
    }
    Ok(())
}
fn reconcile_phi_predecessors(function: &mut Function) -> Result<(), String> {
    let mut label_to_index = HashMap::with_capacity(function.blocks.len());
    for (index, block) in function.blocks.iter().enumerate() {
        if label_to_index.insert(block.label, index).is_some() {
            return Err(format!("duplicate SSA block label {:?}", block.label));
        }
    }
    let mut predecessors = vec![BTreeSet::new(); function.blocks.len()];
    for block in &function.blocks {
        for target in successor_labels(block.terminator.as_ir()) {
            let Some(target_index) = label_to_index.get(&target).copied() else {
                return Err(format!(
                    "SSA block {:?} targets missing block {target:?}",
                    block.label
                ));
            };
            predecessors[target_index].insert(block.label.0);
        }
    }
    for (block_index, block) in function.blocks.iter_mut().enumerate() {
        let expected = &predecessors[block_index];
        for phi in &mut block.phis {
            phi.inputs
                .retain(|input| expected.contains(&input.predecessor.0));
            phi.inputs.sort_by_key(|input| input.predecessor.0);
            let actual = phi
                .inputs
                .iter()
                .map(|input| input.predecessor.0)
                .collect::<Vec<_>>();
            let expected = expected.iter().copied().collect::<Vec<_>>();
            if actual != expected {
                return Err(format!(
                    "SSA Phi {:?} in block {:?} has inputs {:?}, expected {:?}",
                    phi.variable, block.label, actual, expected
                ));
            }
        }
    }
    Ok(())
}
fn retain_reachable_lowering_blocks(function: &mut ir::Function) -> Result<(), String> {
    let mut label_to_index = HashMap::with_capacity(function.blocks.len());
    for (index, block) in function.blocks.iter().enumerate() {
        if label_to_index.insert(block.label, index).is_some() {
            return Err(format!("duplicate lowering block label {:?}", block.label));
        }
    }
    let Some(entry) = label_to_index.get(&function.entry).copied() else {
        return Err(format!("missing lowering entry block {:?}", function.entry));
    };
    // Validate targets in all input blocks before pruning, including blocks
    // that turn out to be unreachable. Malformed lowering IR must never be
    // hidden by optimization.
    for block in &function.blocks {
        for target in successor_labels(&block.terminator) {
            if !label_to_index.contains_key(&target) {
                return Err(format!(
                    "lowering block {:?} targets missing block {target:?}",
                    block.label
                ));
            }
        }
    }
    let mut reachable = BTreeSet::new();
    let mut pending = vec![entry];
    while let Some(index) = pending.pop() {
        if !reachable.insert(index) {
            continue;
        }
        let mut successors = successor_labels(&function.blocks[index].terminator)
            .into_iter()
            .map(|target| {
                label_to_index.get(&target).copied().ok_or_else(|| {
                    format!(
                        "lowering block {:?} targets missing block {target:?}",
                        function.blocks[index].label
                    )
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        successors.reverse();
        pending.extend(successors);
    }
    let mut index = 0usize;
    function.blocks.retain(|_| {
        let keep = reachable.contains(&index);
        index = index.saturating_add(1);
        keep
    });
    Ok(())
}
fn enforce_ssa_function_budget(function: &ir::Function) -> Result<(), String> {
    let instructions = function.blocks.iter().try_fold(0usize, |total, block| {
        total
            .checked_add(
                block
                    .instrs
                    .iter()
                    .filter(|instruction| !matches!(instruction, ir::Instr::Source(_)))
                    .count(),
            )
            .ok_or_else(|| "SSA instruction count overflow".to_owned())
    })?;
    validate_ssa_budget_counts(function.blocks.len(), instructions)
}
fn validate_ssa_budget_counts(blocks: usize, instructions: usize) -> Result<(), String> {
    if blocks > MAX_SSA_BLOCKS_PER_FUNCTION {
        return Err(format!(
            "SSA function has {} blocks, exceeding the V1 limit of {MAX_SSA_BLOCKS_PER_FUNCTION}",
            blocks
        ));
    }
    if instructions > MAX_SSA_INSTRUCTIONS_PER_FUNCTION {
        return Err(format!(
            "SSA function has {instructions} instructions, exceeding the V1 limit of \
             {MAX_SSA_INSTRUCTIONS_PER_FUNCTION}"
        ));
    }
    Ok(())
}
fn place_entry_first(function: &mut ir::Function) -> Result<(), String> {
    let entry_index = function
        .blocks
        .iter()
        .position(|block| block.label == function.entry)
        .ok_or_else(|| format!("missing SSA entry block {:?}", function.entry))?;
    if entry_index != 0 {
        let entry = function.blocks.remove(entry_index);
        function.blocks.insert(0, entry);
    }
    Ok(())
}
fn ensure_entry_preheader(function: &mut ir::Function) -> Result<(), String> {
    if !function
        .blocks
        .iter()
        .any(|block| successor_labels(&block.terminator).contains(&function.entry))
    {
        return Ok(());
    }
    let label = Label(
        function
            .blocks
            .iter()
            .map(|block| block.label.0)
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| {
                "SSA block-label space exhausted adding an entry preheader".to_owned()
            })?,
    );
    let old_entry = function.entry;
    // Code generation lays out the first block at the function symbol, so a
    // real preheader must also be first in deterministic block order.
    function.blocks.insert(
        0,
        ir::BasicBlock {
            label,
            instrs: Vec::new(),
            terminator: ir::Terminator::Jump(old_entry),
        },
    );
    function.entry = label;
    Ok(())
}
fn value_temp(values: &BTreeMap<Value, Temp>, value: Value) -> Result<Temp, String> {
    values
        .get(&value)
        .copied()
        .ok_or_else(|| format!("missing lowering temporary for SSA value {value:?}"))
}
fn rewrite_instruction_values(
    instruction: &mut ir::Instr,
    values: &BTreeMap<Value, Temp>,
) -> Result<(), String> {
    let mut expected_uses = 0usize;
    let mut expected_definitions = 0usize;
    visit_instr_uses(instruction, |_| expected_uses += 1);
    visit_instr_defs(instruction, |_| expected_definitions += 1);
    let mut failure = None;
    let mut rewrite_value = |encoded: &mut Temp| {
        if failure.is_some() {
            return;
        }
        match value_temp(values, Value::decode(*encoded)) {
            Ok(temp) => *encoded = temp,
            Err(error) => failure = Some(error),
        }
    };
    let mut rewritten_uses = 0usize;
    rewrite_instr_uses(instruction, |encoded| {
        rewritten_uses += 1;
        rewrite_value(encoded);
    });
    let mut rewritten_definitions = 0usize;
    rewrite_instr_definitions(instruction, |encoded| {
        rewritten_definitions += 1;
        rewrite_value(encoded);
    });
    if expected_uses != rewritten_uses || expected_definitions != rewritten_definitions {
        return Err(format!(
            "SSA opcode projection drift: rewrote {rewritten_uses}/{expected_uses} uses and \
             {rewritten_definitions}/{expected_definitions} definitions"
        ));
    }
    failure.map_or(Ok(()), Err)
}
fn rewrite_terminator_values(
    terminator: &mut ir::Terminator,
    values: &BTreeMap<Value, Temp>,
) -> Result<(), String> {
    let mut expected = 0usize;
    visit_terminator_uses(terminator, |_| expected += 1);
    let mut failure = None;
    let mut rewritten = 0usize;
    rewrite_terminator_uses(terminator, |encoded| {
        rewritten += 1;
        if failure.is_some() {
            return;
        }
        match value_temp(values, Value::decode(*encoded)) {
            Ok(temp) => *encoded = temp,
            Err(error) => failure = Some(error),
        }
    });
    if expected != rewritten {
        return Err(format!(
            "SSA terminator projection drift: rewrote {rewritten}/{expected} uses"
        ));
    }
    failure.map_or(Ok(()), Err)
}
fn successor_labels(terminator: &ir::Terminator) -> Vec<Label> {
    let mut labels = match terminator {
        ir::Terminator::Jump(target) => vec![*target],
        ir::Terminator::Branch {
            then_bb, else_bb, ..
        } => vec![*then_bb, *else_bb],
        ir::Terminator::Return(_) | ir::Terminator::Return2(_, _) | ir::Terminator::ReturnN(_) => {
            Vec::new()
        }
    };
    labels.sort_by_key(|label| label.0);
    labels.dedup();
    labels
}
fn retarget_edge(terminator: &mut ir::Terminator, from: Label, to: Label) -> Result<(), String> {
    let mut rewritten = false;
    match terminator {
        ir::Terminator::Jump(target) => {
            if *target == from {
                *target = to;
                rewritten = true;
            }
        }
        ir::Terminator::Branch {
            then_bb, else_bb, ..
        } => {
            if *then_bb == from {
                *then_bb = to;
                rewritten = true;
            }
            if *else_bb == from {
                *else_bb = to;
                rewritten = true;
            }
        }
        ir::Terminator::Return(_) | ir::Terminator::Return2(_, _) | ir::Terminator::ReturnN(_) => {}
    }
    if rewritten {
        Ok(())
    } else {
        Err(format!("cannot retarget missing SSA edge to {from:?}"))
    }
}
fn schedule_parallel_copies(
    mut copies: Vec<(Temp, Temp)>,
    next_temp: &mut usize,
) -> Result<Vec<ir::Instr>, String> {
    copies.retain(|(destination, source)| destination != source);
    copies.sort_by_key(|(destination, source)| (destination.0, source.0));
    for pair in copies.windows(2) {
        if pair[0].0 == pair[1].0 {
            return Err(format!(
                "Phi destruction assigned lowering temporary {:?} more than once on one edge",
                pair[0].0
            ));
        }
    }
    let mut scheduled = Vec::with_capacity(copies.len());
    while !copies.is_empty() {
        let safe = copies
            .iter()
            .position(|(destination, _)| !copies.iter().any(|(_, source)| source == destination));
        if let Some(index) = safe {
            let (dest, src) = copies.remove(index);
            scheduled.push(ir::Instr::Copy { dest, src });
            continue;
        }
        // Every remaining destination is also a source, so at least one cycle
        // remains. Preserve the first destination's old value in a fresh
        // temporary and substitute that source before resuming the acyclic
        // scheduler. Sorting above makes cycle breaking reproducible.
        let cycle_destination = copies[0].0;
        let scratch = Temp(*next_temp);
        *next_temp = next_temp
            .checked_add(1)
            .ok_or_else(|| "lowering temporary space exhausted destroying SSA".to_owned())?;
        scheduled.push(ir::Instr::Copy {
            dest: scratch,
            src: cycle_destination,
        });
        for (_, source) in &mut copies {
            if *source == cycle_destination {
                *source = scratch;
            }
        }
    }
    Ok(scheduled)
}
#[derive(Clone, Copy)]
enum DefinitionPosition {
    Phi,
    Instruction(usize),
}
#[derive(Clone, Copy)]
struct DefinitionSite {
    block: usize,
    position: DefinitionPosition,
}
#[derive(Clone, Copy)]
enum UsePosition {
    Instruction(usize),
    Terminator,
    Edge,
}
fn insert_definition(
    definitions: &mut HashMap<Value, DefinitionSite>,
    value: Value,
    block: usize,
    position: DefinitionPosition,
) -> Result<(), String> {
    if definitions
        .insert(value, DefinitionSite { block, position })
        .is_some()
    {
        return Err(format!("SSA value {value:?} is defined more than once"));
    }
    Ok(())
}
fn verify_use(
    definitions: &HashMap<Value, DefinitionSite>,
    cfg: &Cfg,
    value: Value,
    use_block: usize,
    use_position: UsePosition,
) -> Result<(), String> {
    let Some(definition) = definitions.get(&value).copied() else {
        return Err(format!("SSA value {value:?} is used without a definition"));
    };
    if definition.block != use_block {
        if !cfg.dominators[use_block].contains(definition.block) {
            return Err(format!(
                "SSA value {value:?} does not dominate its use in block {:?}",
                cfg.labels[use_block]
            ));
        }
        return Ok(());
    }
    let ordered = match (definition.position, use_position) {
        (DefinitionPosition::Phi, _) => true,
        (DefinitionPosition::Instruction(definition), UsePosition::Instruction(usage)) => {
            definition < usage
        }
        (DefinitionPosition::Instruction(_), UsePosition::Terminator | UsePosition::Edge) => true,
    };
    if !ordered {
        return Err(format!(
            "SSA value {value:?} is used before its definition in block {:?}",
            cfg.labels[use_block]
        ));
    }
    Ok(())
}
/// Compact deterministic bit set used by dominance analysis.
///
/// A dense representation avoids cloning thousands of tree nodes per block while retaining
/// hardware-independent integer operations and iteration order.
#[derive(Clone, Debug, PartialEq, Eq)]
struct DominatorSet {
    words: Vec<u64>,
    len: usize,
}
impl DominatorSet {
    fn full(len: usize) -> Self {
        let word_count = len.div_ceil(u64::BITS as usize);
        let mut words = vec![u64::MAX; word_count];
        if let Some(last) = words.last_mut() {
            let used = len % u64::BITS as usize;
            if used != 0 {
                *last = (1_u64 << used) - 1;
            }
        }
        Self { words, len }
    }
    fn singleton(len: usize, index: usize) -> Self {
        let mut set = Self {
            words: vec![0; len.div_ceil(u64::BITS as usize)],
            len,
        };
        set.insert(index);
        set
    }
    fn insert(&mut self, index: usize) {
        debug_assert!(index < self.len);
        self.words[index / u64::BITS as usize] |= 1_u64 << (index % u64::BITS as usize);
    }
    fn contains(&self, index: usize) -> bool {
        index < self.len
            && self.words[index / u64::BITS as usize] & (1_u64 << (index % u64::BITS as usize)) != 0
    }
    fn intersect_with(&mut self, other: &Self) {
        debug_assert_eq!(self.len, other.len);
        for (word, other) in self.words.iter_mut().zip(&other.words) {
            *word &= *other;
        }
    }
    fn count(&self) -> usize {
        self.words
            .iter()
            .map(|word| word.count_ones() as usize)
            .sum()
    }
    fn iter(&self) -> impl Iterator<Item = usize> + '_ {
        (0..self.len).filter(|index| self.contains(*index))
    }
}
struct Cfg {
    labels: Vec<Label>,
    label_to_index: HashMap<Label, usize>,
    successors: Vec<Vec<usize>>,
    predecessors: Vec<Vec<usize>>,
    dominators: Vec<DominatorSet>,
    dominator_children: Vec<Vec<usize>>,
    dominance_frontier: Vec<BTreeSet<usize>>,
    entry: usize,
}
impl Cfg {
    fn new<'a>(
        entry: Label,
        blocks: impl IntoIterator<Item = (Label, &'a ir::Terminator)>,
    ) -> Result<Self, String> {
        let blocks = blocks.into_iter().collect::<Vec<_>>();
        if blocks.len() > MAX_SSA_BLOCKS_PER_FUNCTION {
            return Err(format!(
                "SSA function has {} blocks, exceeding the V1 limit of \
                 {MAX_SSA_BLOCKS_PER_FUNCTION}",
                blocks.len()
            ));
        }
        let labels = blocks.iter().map(|(label, _)| *label).collect::<Vec<_>>();
        let mut label_to_index = HashMap::with_capacity(labels.len());
        for (index, label) in labels.iter().copied().enumerate() {
            if label_to_index.insert(label, index).is_some() {
                return Err(format!("duplicate SSA block label {label:?}"));
            }
        }
        let Some(entry_index) = label_to_index.get(&entry).copied() else {
            return Err(format!("missing SSA entry block {entry:?}"));
        };
        let mut successors = vec![Vec::new(); blocks.len()];
        let mut predecessors = vec![Vec::new(); blocks.len()];
        for (index, (_, terminator)) in blocks.iter().enumerate() {
            let target_labels = match terminator {
                ir::Terminator::Jump(target) => vec![*target],
                ir::Terminator::Branch {
                    then_bb, else_bb, ..
                } => vec![*then_bb, *else_bb],
                ir::Terminator::Return(_)
                | ir::Terminator::Return2(_, _)
                | ir::Terminator::ReturnN(_) => Vec::new(),
            };
            for target in target_labels {
                let Some(target_index) = label_to_index.get(&target).copied() else {
                    return Err(format!(
                        "SSA block {:?} targets missing block {target:?}",
                        labels[index]
                    ));
                };
                if !successors[index].contains(&target_index) {
                    successors[index].push(target_index);
                    predecessors[target_index].push(index);
                }
            }
            successors[index].sort_by_key(|successor| labels[*successor].0);
        }
        for incoming in &mut predecessors {
            incoming.sort_by_key(|predecessor| labels[*predecessor].0);
        }
        if !predecessors[entry_index].is_empty() {
            return Err(format!(
                "SSA entry block {entry:?} must not have incoming CFG edges"
            ));
        }
        let mut reachable = BTreeSet::new();
        let mut pending = vec![entry_index];
        while let Some(block) = pending.pop() {
            if !reachable.insert(block) {
                continue;
            }
            for successor in successors[block].iter().rev() {
                pending.push(*successor);
            }
        }
        if reachable.len() != blocks.len() {
            let unreachable = labels
                .iter()
                .enumerate()
                .filter_map(|(index, label)| (!reachable.contains(&index)).then_some(*label))
                .collect::<Vec<_>>();
            return Err(format!("unreachable SSA blocks remain: {unreachable:?}"));
        }
        let all_blocks = DominatorSet::full(blocks.len());
        let mut dominators = vec![all_blocks; blocks.len()];
        dominators[entry_index] = DominatorSet::singleton(blocks.len(), entry_index);
        loop {
            let mut changed = false;
            for block in 0..blocks.len() {
                if block == entry_index {
                    continue;
                }
                let mut incoming = predecessors[block].iter().copied();
                let first = incoming.next().ok_or_else(|| {
                    format!("reachable SSA block {:?} has no predecessor", labels[block])
                })?;
                let mut next = dominators[first].clone();
                for predecessor in incoming {
                    next.intersect_with(&dominators[predecessor]);
                }
                next.insert(block);
                if next != dominators[block] {
                    dominators[block] = next;
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        let mut immediate_dominator = vec![None; blocks.len()];
        for block in 0..blocks.len() {
            if block == entry_index {
                continue;
            }
            let candidate = dominators[block]
                .iter()
                .filter(|dominator| *dominator != block)
                .max_by_key(|dominator| dominators[*dominator].count())
                .ok_or_else(|| format!("SSA block {:?} has no dominator", labels[block]))?;
            immediate_dominator[block] = Some(candidate);
        }
        let mut dominator_children = vec![Vec::new(); blocks.len()];
        for (block, parent) in immediate_dominator.iter().copied().enumerate() {
            if let Some(parent) = parent {
                dominator_children[parent].push(block);
            }
        }
        for children in &mut dominator_children {
            children.sort_by_key(|child| labels[*child].0);
        }
        let mut dominance_frontier = vec![BTreeSet::new(); blocks.len()];
        for block in 0..blocks.len() {
            if predecessors[block].len() < 2 {
                continue;
            }
            let Some(stop) = immediate_dominator[block] else {
                continue;
            };
            for predecessor in predecessors[block].iter().copied() {
                let mut runner = predecessor;
                while runner != stop {
                    dominance_frontier[runner].insert(block);
                    runner = immediate_dominator[runner].ok_or_else(|| {
                        format!(
                            "broken SSA dominator chain from {:?} to {:?}",
                            labels[predecessor], labels[block]
                        )
                    })?;
                }
            }
        }
        Ok(Self {
            labels,
            label_to_index,
            successors,
            predecessors,
            dominators,
            dominator_children,
            dominance_frontier,
            entry: entry_index,
        })
    }
    fn index(&self, label: Label) -> Result<usize, String> {
        self.label_to_index
            .get(&label)
            .copied()
            .ok_or_else(|| format!("missing SSA block {label:?}"))
    }
    fn predecessor_labels(&self, block: usize) -> Vec<Label> {
        self.predecessors[block]
            .iter()
            .map(|predecessor| self.labels[*predecessor])
            .collect()
    }
}
fn place_phi_variables(blocks: &[ir::BasicBlock], cfg: &Cfg) -> Vec<BTreeSet<usize>> {
    let live_in = lowering_liveness(blocks, cfg);
    let mut definition_blocks = BTreeMap::<usize, BTreeSet<usize>>::new();
    for (block_index, block) in blocks.iter().enumerate() {
        for instruction in &block.instrs {
            visit_instr_defs(instruction, |temp| {
                definition_blocks
                    .entry(temp.0)
                    .or_default()
                    .insert(block_index);
            });
        }
    }
    let mut result = vec![BTreeSet::new(); blocks.len()];
    for (variable, definitions) in definition_blocks {
        let mut work = definitions.clone();
        while let Some(block) = work.pop_first() {
            for frontier in cfg.dominance_frontier[block].iter().copied() {
                // Pruned SSA: a branch-local temporary that dies before the
                // join needs no Phi. Placing one would demand a fabricated
                // value from predecessors on which the temporary never
                // existed, masking malformed lowering as an SSA failure.
                if live_in[frontier].contains(&variable)
                    && result[frontier].insert(variable)
                    && !definitions.contains(&frontier)
                {
                    work.insert(frontier);
                }
            }
        }
    }
    result
}
fn lowering_liveness(blocks: &[ir::BasicBlock], cfg: &Cfg) -> Vec<BTreeSet<usize>> {
    let mut uses = vec![BTreeSet::new(); blocks.len()];
    let mut definitions = vec![BTreeSet::new(); blocks.len()];
    for (block_index, block) in blocks.iter().enumerate() {
        for instruction in &block.instrs {
            visit_instr_uses(instruction, |temp| {
                if !definitions[block_index].contains(&temp.0) {
                    uses[block_index].insert(temp.0);
                }
            });
            visit_instr_defs(instruction, |temp| {
                definitions[block_index].insert(temp.0);
            });
        }
        visit_terminator_uses(&block.terminator, |temp| {
            if !definitions[block_index].contains(&temp.0) {
                uses[block_index].insert(temp.0);
            }
        });
    }
    let mut live_in = vec![BTreeSet::new(); blocks.len()];
    let mut live_out = vec![BTreeSet::new(); blocks.len()];
    loop {
        let mut changed = false;
        // Reverse stable block order only affects convergence speed; all set
        // operations and the fixed point itself are deterministic.
        for block in (0..blocks.len()).rev() {
            let next_out = cfg.successors[block]
                .iter()
                .flat_map(|successor| live_in[*successor].iter().copied())
                .collect::<BTreeSet<_>>();
            let mut next_in = uses[block].clone();
            next_in.extend(
                next_out
                    .iter()
                    .filter(|variable| !definitions[block].contains(variable))
                    .copied(),
            );
            if next_out != live_out[block] || next_in != live_in[block] {
                live_out[block] = next_out;
                live_in[block] = next_in;
                changed = true;
            }
        }
        if !changed {
            return live_in;
        }
    }
}
fn rewrite_instr_uses<F: FnMut(&mut Temp)>(instr: &mut ir::Instr, mut f: F) {
    use ir::Instr::*;
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
            f(left);
            f(right);
        }
        Unary { operand, .. } | WrappingNeg { operand, .. } => f(operand),
        IntFromI64 { value, .. }
        | IntFromU64 { value, .. }
        | IntToI64 { value, .. }
        | IntToU64 { value, .. }
        | NumericConvert { value, .. }
        | NumericTryConvert { value, .. }
        | NumericNeg { value, .. } => f(value),
        DecimalToInt { value, mode, .. } => {
            f(value);
            if let Some(mode) = mode {
                f(mode);
            }
        }
        NumericBinary { left, right, .. } | NumericCompare { left, right, .. } => {
            f(left);
            f(right);
        }
        NumericRound {
            dividend,
            multiplier,
            divisor,
            scale,
            mode,
            ..
        } => {
            f(dividend);
            if let Some(multiplier) = multiplier {
                f(multiplier);
            }
            f(divisor);
            f(scale);
            f(mode);
        }
        DirectHelperSyscall { args, .. } => {
            for arg in args {
                f(arg);
            }
        }
        Min { a, b, .. } | Max { a, b, .. } | Gcd { a, b, .. } | Mean { a, b, .. } => {
            f(a);
            f(b);
        }
        DivCeil { num, denom, .. } => {
            f(num);
            f(denom);
        }
        CallContract {
            contract,
            binding,
            payload,
            ..
        } => {
            f(contract);
            f(binding);
            f(payload);
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
                f(actor);
            }
            f(entrypoint);
            f(payload);
        }
        ExpectRejectAs {
            actor,
            entrypoint,
            payload,
            expectation,
            ..
        } => {
            f(actor);
            f(entrypoint);
            f(payload);
            f(expectation);
        }
        ActorAccount { actor, .. } | ActorPublicKey { actor, .. } => f(actor),
        ActorSign { actor, message, .. } => {
            f(actor);
            f(message);
        }
        ResolveAccountAlias { alias, .. } => f(alias),
        Abs { src, .. } => f(src),
        Isqrt { src, .. } => f(src),
        Poseidon2 { a, b, .. } => {
            f(a);
            f(b);
        }
        Poseidon6 { args, .. } => {
            for temp in args {
                f(temp);
            }
        }
        Pubkgen { src, .. } => f(src),
        Valcom { value, blind, .. } => {
            f(value);
            f(blind);
        }
        RegisterAsset {
            asset,
            name,
            spec,
            mintable,
        } => {
            f(asset);
            f(name);
            f(spec);
            f(mintable);
        }
        TransferAsset {
            from,
            to,
            asset,
            amount,
            dataspace,
        } => {
            f(from);
            f(to);
            f(asset);
            f(amount);
            f(dataspace);
        }
        TransferBatchAsset {
            from,
            to,
            asset,
            amount,
        } => {
            f(from);
            f(to);
            f(asset);
            f(amount);
        }
        EscrowOpenOffer {
            escrow,
            asset,
            amount,
            evidence_hashes,
        } => {
            f(escrow);
            f(asset);
            f(amount);
            if let Some(evidence_hashes) = evidence_hashes {
                f(evidence_hashes);
            }
        }
        EscrowResolveDispute {
            escrow,
            buyer_amount,
            seller_amount,
            evidence_hashes,
        } => {
            f(escrow);
            f(buyer_amount);
            f(seller_amount);
            if let Some(evidence_hashes) = evidence_hashes {
                f(evidence_hashes);
            }
        }
        EscrowAccept { escrow }
        | EscrowMarkPaymentSent { escrow }
        | EscrowRelease { escrow }
        | EscrowCancel { escrow } => f(escrow),
        EscrowOpenDispute {
            escrow,
            evidence_hashes,
        } => {
            f(escrow);
            if let Some(evidence_hashes) = evidence_hashes {
                f(evidence_hashes);
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
            f(account);
            f(asset);
            f(amount);
        }
        AssertEq { left, right } => {
            f(left);
            f(right);
        }
        Assert { cond } => f(cond),
        AbortIf {
            cond,
            descriptor,
            code,
        } => {
            f(cond);
            f(descriptor);
            f(code);
        }
        Info { msg } => f(msg),
        DebugPrint { value } => f(value),
        DebugLog { payload } => f(payload),
        PointerFromString { src, .. } => f(src),
        MapGet { map, key, .. } => {
            f(map);
            f(key);
        }
        MapLoadPair { map, .. } => f(map),
        MapSet { map, key, value } => {
            f(map);
            f(key);
            f(value);
        }
        Load64Imm { base, .. } => f(base),
        Load64 { address, .. } => f(address),
        Store64Imm { base, value, .. } => {
            f(base);
            f(value);
        }
        Store64 { address, value } => {
            f(address);
            f(value);
        }
        TuplePack { items, .. } => {
            for temp in items {
                f(temp);
            }
        }
        TupleGet { tuple, .. } => f(tuple),
        Copy { src, .. } => f(src),
        SetExecutionDepth { value } => f(value),
        SetVl { value } => f(value),
        Call { args, .. } | CallMulti { args, .. } => {
            for arg in args {
                f(arg);
            }
        }
        SetAccountDetail {
            account,
            key,
            value,
        } => {
            f(account);
            f(key);
            f(value);
        }
        CreateNft { nft, owner } => {
            f(nft);
            f(owner);
        }
        SetNftData { nft, key, json } => {
            f(nft);
            f(key);
            f(json);
        }
        BurnNft { nft } => f(nft),
        TransferNft { from, nft, to } => {
            f(from);
            f(nft);
            f(to);
        }
        RegisterDomain { domain } | UnregisterDomain { domain } => f(domain),
        TransferDomain { domain, to } => {
            f(domain);
            f(to);
        }
        RegisterAccount { account } | UnregisterAccount { account } => f(account),
        AddSignatory { account, signatory } | RemoveSignatory { account, signatory } => {
            f(account);
            f(signatory);
        }
        SetAccountQuorum { account, quorum } => {
            f(account);
            f(quorum);
        }
        GrantPermission { account, token } | RevokePermission { account, token } => {
            f(account);
            f(token);
        }
        GrantContractPermission {
            account,
            permission,
        }
        | RevokeContractPermission {
            account,
            permission,
        } => {
            f(account);
            f(permission);
        }
        GrantRole { account, name } | RevokeRole { account, name } => {
            f(account);
            f(name);
        }
        UnregisterAsset { asset } => f(asset),
        RegisterPeer { json } | UnregisterPeer { json } | CreateTrigger { json } => f(json),
        CreateRole { name, json } => {
            f(name);
            f(json);
        }
        RemoveTrigger { name } | DeleteRole { name } => f(name),
        SetTriggerEnabled { name, enabled } => {
            f(name);
            f(enabled);
        }
        ir::Instr::Sm3Hash { message, .. }
        | ir::Instr::Sha256Hash { message, .. }
        | ir::Instr::Sha3Hash { message, .. }
        | ir::Instr::Blake2b256Hash { message, .. }
        | ir::Instr::Keccak256Hash { message, .. }
        | ir::Instr::IrohaHash { message, .. } => f(message),
        ir::Instr::Sm2Verify {
            message,
            signature,
            public_key,
            distid,
            ..
        } => {
            f(message);
            f(signature);
            f(public_key);
            if let Some(d) = distid {
                f(d);
            }
        }
        ir::Instr::VerifySignature {
            message,
            signature,
            public_key,
            scheme,
            ..
        } => {
            f(message);
            f(signature);
            f(public_key);
            f(scheme);
        }
        ir::Instr::Sm4GcmSeal {
            key,
            nonce,
            aad,
            plaintext,
            ..
        } => {
            f(key);
            f(nonce);
            f(aad);
            f(plaintext);
        }
        ir::Instr::Sm4GcmOpen {
            key,
            nonce,
            aad,
            ciphertext_and_tag,
            ..
        } => {
            f(key);
            f(nonce);
            f(aad);
            f(ciphertext_and_tag);
        }
        ir::Instr::Sm4CcmSeal {
            key,
            nonce,
            aad,
            plaintext,
            tag_len,
            ..
        } => {
            f(key);
            f(nonce);
            f(aad);
            f(plaintext);
            if let Some(t) = tag_len {
                f(t);
            }
        }
        ir::Instr::Sm4CcmOpen {
            key,
            nonce,
            aad,
            ciphertext_and_tag,
            tag_len,
            ..
        } => {
            f(key);
            f(nonce);
            f(aad);
            f(ciphertext_and_tag);
            if let Some(t) = tag_len {
                f(t);
            }
        }
        ir::Instr::ZkVerify { payload, .. }
        | ir::Instr::VerifyProof { payload, .. }
        | ir::Instr::VendorExecuteInstruction { payload, .. }
        | ir::Instr::VendorExecuteQuery { payload, .. }
        | ir::Instr::QueryExecuteNorito { payload, .. }
        | ir::Instr::QueryGet { key: payload, .. }
        | ir::Instr::CoreQueryGet { key: payload, .. }
        | ir::Instr::SmartContractLifecycle { payload, .. }
        | ir::Instr::ZkRootsGet { payload, .. }
        | ir::Instr::ZkVoteGetTally { payload, .. }
        | ir::Instr::VrfEpochSeed { epoch: payload, .. }
        | ir::Instr::SoracloudHostCall {
            request: payload, ..
        } => f(payload),
        ir::Instr::CoreQueryPage {
            account,
            offset,
            limit,
            ..
        } => {
            if let Some(account) = account {
                f(account);
            }
            f(offset);
            f(limit);
        }
        ir::Instr::GetAccountBalance { account, asset, .. } => {
            f(account);
            f(asset);
        }
        ir::Instr::Alloc { bytes, .. } => f(bytes),
        ir::Instr::GrowHeap { bytes, .. } => f(bytes),
        ir::Instr::GetMerklePath {
            address,
            output,
            root_output,
            ..
        } => {
            f(address);
            f(output);
            if let Some(root_output) = root_output {
                f(root_output);
            }
        }
        ir::Instr::GetMerkleCompact {
            address,
            output,
            max_depth,
            root_output,
            ..
        } => {
            f(address);
            f(output);
            if let Some(max_depth) = max_depth {
                f(max_depth);
            }
            if let Some(root_output) = root_output {
                f(root_output);
            }
        }
        ir::Instr::GetRegisterMerkleCompact {
            register_index,
            output,
            max_depth,
            root_output,
            ..
        } => {
            f(register_index);
            f(output);
            if let Some(max_depth) = max_depth {
                f(max_depth);
            }
            if let Some(root_output) = root_output {
                f(root_output);
            }
        }
        ir::Instr::GetPrivateInput { index, .. } => f(index),
        ir::Instr::PrivateNumericValcom { value, blind, .. } => {
            f(value);
            f(blind);
        }
        ir::Instr::GetPublicInput { key, .. } => f(key),
        StateGet { path, .. } => f(path),
        StateSet { path, value } => {
            f(path);
            f(value);
        }
        StateDel { path } => f(path),
        StateScan {
            base, after, limit, ..
        } => {
            f(base);
            f(after);
            f(limit);
        }
        StateMapKeyAt {
            page, base, index, ..
        } => {
            f(page);
            f(base);
            f(index);
        }
        StateValueEncode { schema, words, .. } => {
            f(schema);
            for word in words {
                f(word);
            }
        }
        StateHas { path, .. } | StateLen { path, .. } => f(path),
        StateCount { prefix, .. } => f(prefix),
        JsonDecode { blob, .. } | NameDecode { blob, .. } => f(blob),
        TlvLen { value, .. } => f(value),
        JsonSetInt {
            json, key, value, ..
        }
        | JsonSetAccountId {
            json, key, value, ..
        } => {
            f(json);
            f(key);
            f(value);
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
            f(json);
            f(key);
        }
        SchemaDecode { schema, blob, .. } => {
            f(schema);
            f(blob);
        }
        PointerToNorito { value, .. } => f(value),
        PointerFromNorito { blob, .. } => f(blob),
        StatePathFromName { name, .. } => f(name),
        PathMapKeyNorito { base, key_blob, .. } => {
            f(base);
            f(key_blob);
        }
        JsonEncode { json, .. } => f(json),
        SchemaEncode { schema, json, .. } => {
            f(schema);
            f(json);
        }
        SchemaInfo { schema, .. } => f(schema),
        BuildSubmitBallotInline {
            election_id,
            ciphertext,
            nullifier,
            backend,
            proof,
            vk,
            ..
        } => {
            f(election_id);
            f(ciphertext);
            f(nullifier);
            f(backend);
            f(proof);
            f(vk);
        }
        PointerEq { left, right, .. } => {
            f(left);
            f(right);
        }
        VrfVerify { request, .. } => f(request),
        VrfVerifyBatch { batch, .. } => f(batch),
        AxtBegin { descriptor } => f(descriptor),
        StageAnchoredSpend { spend } => f(spend),
        AxtTouch { dsid, manifest } => {
            f(dsid);
            if let Some(m) = manifest {
                f(m);
            }
        }
        VerifyDsProof { dsid, proof } => {
            f(dsid);
            if let Some(p) = proof {
                f(p);
            }
        }
        AxtCommit => {}
    }
}
fn dest_temp_mut(instr: &mut ir::Instr) -> Option<&mut Temp> {
    match instr {
        ir::Instr::Source(_) => None,
        ir::Instr::PointerEq { dest, .. }
        | ir::Instr::Const { dest, .. }
        | ir::Instr::StringConst { dest, .. }
        | ir::Instr::DataRef { dest, .. }
        | ir::Instr::Binary { dest, .. }
        | ir::Instr::WrappingBinary { dest, .. }
        | ir::Instr::Unary { dest, .. }
        | ir::Instr::WrappingNeg { dest, .. }
        | ir::Instr::Min { dest, .. }
        | ir::Instr::Max { dest, .. }
        | ir::Instr::Abs { dest, .. }
        | ir::Instr::DivCeil { dest, .. }
        | ir::Instr::Gcd { dest, .. }
        | ir::Instr::Mean { dest, .. }
        | ir::Instr::Isqrt { dest, .. }
        | ir::Instr::LoadVar { dest, .. }
        | ir::Instr::Poseidon2 { dest, .. }
        | ir::Instr::Poseidon6 { dest, .. }
        | ir::Instr::Pubkgen { dest, .. }
        | ir::Instr::Valcom { dest, .. }
        | ir::Instr::PrivateNumericValcom { dest, .. }
        | ir::Instr::MapNew { dest }
        | ir::Instr::GetAuthority { dest }
        | ir::Instr::SysvarAuthority { dest }
        | ir::Instr::CurrentTimeMs { dest }
        | ir::Instr::BlockHeight { dest }
        | ir::Instr::BlockTimeMs { dest }
        | ir::Instr::ChainId { dest }
        | ir::Instr::ContractAddress { dest }
        | ir::Instr::Entrypoint { dest }
        | ir::Instr::QueryExecuteNorito { dest, .. }
        | ir::Instr::QueryGet { dest, .. }
        | ir::Instr::GetAccountBalance { dest, .. }
        | ir::Instr::Alloc { dest, .. }
        | ir::Instr::GetPublicInput { dest, .. }
        | ir::Instr::GetPrivateInput { dest, .. }
        | ir::Instr::ZkRootsGet { dest, .. }
        | ir::Instr::ZkVoteGetTally { dest, .. }
        | ir::Instr::VrfEpochSeed { dest, .. }
        | ir::Instr::SoracloudHostCall { dest, .. }
        | ir::Instr::ResolveAccountAlias { dest, .. }
        | ir::Instr::GetTriggerEvent { dest }
        | ir::Instr::ActorAccount { dest, .. }
        | ir::Instr::ActorPublicKey { dest, .. }
        | ir::Instr::ActorSign { dest, .. }
        | ir::Instr::Copy { dest, .. }
        | ir::Instr::PointerFromString { dest, .. }
        | ir::Instr::PointerToNorito { dest, .. }
        | ir::Instr::PointerFromNorito { dest, .. }
        | ir::Instr::Load64Imm { dest, .. }
        | ir::Instr::Load64 { dest, .. }
        | ir::Instr::StateGet { dest, .. }
        | ir::Instr::StateMapKeyAt { dest, .. }
        | ir::Instr::StateValueEncode { dest, .. }
        | ir::Instr::StateHas { dest, .. }
        | ir::Instr::StateLen { dest, .. }
        | ir::Instr::StateCount { dest, .. }
        | ir::Instr::IntFromI64 { dest, .. }
        | ir::Instr::IntFromU64 { dest, .. }
        | ir::Instr::IntToI64 { dest, .. }
        | ir::Instr::IntToU64 { dest, .. }
        | ir::Instr::NumericConvert { dest, .. }
        | ir::Instr::NumericTryConvert { dest, .. }
        | ir::Instr::NumericStatus { dest }
        | ir::Instr::NumericNeg { dest, .. }
        | ir::Instr::NumericBinary { dest, .. }
        | ir::Instr::NumericRound { dest, .. }
        | ir::Instr::DecimalToInt { dest, .. }
        | ir::Instr::NumericCompare { dest, .. }
        | ir::Instr::DirectHelperSyscall { dest, .. } => Some(dest),
        ir::Instr::SchemaInfo { dest, .. } | ir::Instr::CoreQueryGet { dest, .. } => Some(dest),
        ir::Instr::Sm3Hash { dest, .. }
        | ir::Instr::Sha256Hash { dest, .. }
        | ir::Instr::Sha3Hash { dest, .. }
        | ir::Instr::Blake2b256Hash { dest, .. }
        | ir::Instr::Keccak256Hash { dest, .. }
        | ir::Instr::IrohaHash { dest, .. } => Some(dest),
        ir::Instr::Sm2Verify { dest, .. } => Some(dest),
        ir::Instr::VerifySignature { dest, .. } => Some(dest),
        ir::Instr::ExecutionSummary { dest } => Some(dest),
        ir::Instr::GrowHeap { dest, .. } => Some(dest),
        ir::Instr::GetMerklePath { dest, .. }
        | ir::Instr::GetMerkleCompact { dest, .. }
        | ir::Instr::GetRegisterMerkleCompact { dest, .. } => Some(dest),
        ir::Instr::VerifyProof { dest, .. } => Some(dest),
        ir::Instr::Sm4GcmSeal { dest, .. } => Some(dest),
        ir::Instr::Sm4GcmOpen { dest, .. } => Some(dest),
        ir::Instr::Sm4CcmSeal { dest, .. } => Some(dest),
        ir::Instr::Sm4CcmOpen { dest, .. } => Some(dest),
        ir::Instr::VrfVerify { dest, .. } => Some(dest),
        ir::Instr::VrfVerifyBatch { dest, .. } => Some(dest),
        ir::Instr::MapGet { dest, .. } => Some(dest),
        ir::Instr::TlvLen { dest, .. } => Some(dest),
        ir::Instr::JsonObject { dest, .. } => Some(dest),
        ir::Instr::JsonSetInt { dest, .. } => Some(dest),
        ir::Instr::JsonSetAccountId { dest, .. } => Some(dest),
        ir::Instr::StatePathFromName { dest, .. } | ir::Instr::PathMapKeyNorito { dest, .. } => {
            Some(dest)
        }
        ir::Instr::JsonEncode { dest, .. } => Some(dest),
        ir::Instr::JsonDecode { dest, .. } => Some(dest),
        ir::Instr::JsonGetNumeric { dest, .. }
        | ir::Instr::JsonGetJson { dest, .. }
        | ir::Instr::JsonGetName { dest, .. }
        | ir::Instr::JsonGetAccountId { dest, .. }
        | ir::Instr::JsonGetAssetDefinitionId { dest, .. }
        | ir::Instr::JsonGetNftId { dest, .. }
        | ir::Instr::JsonGetBlobHex { dest, .. }
        | ir::Instr::JsonGetString { dest, .. }
        | ir::Instr::JsonGetBool { dest, .. } => Some(dest),
        ir::Instr::NameDecode { dest, .. } => Some(dest),
        ir::Instr::SchemaEncode { dest, .. } => Some(dest),
        ir::Instr::SchemaDecode { dest, .. } => Some(dest),
        ir::Instr::TuplePack { dest, .. } => Some(dest),
        ir::Instr::TupleGet { dest, .. } => Some(dest),
        ir::Instr::BuildSubmitBallotInline { dest, .. } => Some(dest),
        ir::Instr::VendorExecuteQuery { dest, .. } => Some(dest),
        ir::Instr::Call { dest, .. } | ir::Instr::InvokeEntrypointAs { dest, .. } => dest.as_mut(),
        ir::Instr::GrantPermission { .. }
        | ir::Instr::RevokePermission { .. }
        | ir::Instr::GrantContractPermission { .. }
        | ir::Instr::RevokeContractPermission { .. }
        | ir::Instr::RegisterAsset { .. }
        | ir::Instr::TransferAsset { .. }
        | ir::Instr::TransferBatchAsset { .. }
        | ir::Instr::EscrowOpenOffer { .. }
        | ir::Instr::EscrowAccept { .. }
        | ir::Instr::EscrowMarkPaymentSent { .. }
        | ir::Instr::EscrowRelease { .. }
        | ir::Instr::EscrowCancel { .. }
        | ir::Instr::EscrowOpenDispute { .. }
        | ir::Instr::EscrowResolveDispute { .. }
        | ir::Instr::MintAsset { .. }
        | ir::Instr::BurnAsset { .. }
        | ir::Instr::CreateNft { .. }
        | ir::Instr::TransferNft { .. }
        | ir::Instr::CreateNftsForAllUsers
        | ir::Instr::SetExecutionDepth { .. }
        | ir::Instr::SetVl { .. }
        | ir::Instr::SetAccountDetail { .. }
        | ir::Instr::RegisterDomain { .. }
        | ir::Instr::RegisterAccount { .. }
        | ir::Instr::AddSignatory { .. }
        | ir::Instr::RemoveSignatory { .. }
        | ir::Instr::SetAccountQuorum { .. }
        | ir::Instr::UnregisterDomain { .. }
        | ir::Instr::UnregisterAsset { .. }
        | ir::Instr::UnregisterAccount { .. }
        | ir::Instr::RegisterPeer { .. }
        | ir::Instr::UnregisterPeer { .. }
        | ir::Instr::CreateTrigger { .. }
        | ir::Instr::RemoveTrigger { .. }
        | ir::Instr::SetTriggerEnabled { .. }
        | ir::Instr::CreateRole { .. }
        | ir::Instr::DeleteRole { .. }
        | ir::Instr::GrantRole { .. }
        | ir::Instr::RevokeRole { .. }
        | ir::Instr::ZkVerify { .. }
        | ir::Instr::VendorExecuteInstruction { .. }
        | ir::Instr::SubscriptionBill
        | ir::Instr::SubscriptionRecordUsage
        | ir::Instr::AssertEq { .. }
        | ir::Instr::Assert { .. }
        | ir::Instr::AbortIf { .. }
        | ir::Instr::Info { .. }
        | ir::Instr::DebugPrint { .. }
        | ir::Instr::DebugLog { .. }
        | ir::Instr::MapSet { .. }
        | ir::Instr::Store64Imm { .. }
        | ir::Instr::Store64 { .. }
        | ir::Instr::SetNftData { .. }
        | ir::Instr::BurnNft { .. }
        | ir::Instr::TransferDomain { .. }
        | ir::Instr::StateSet { .. }
        | ir::Instr::StateDel { .. }
        | ir::Instr::AxtBegin { .. }
        | ir::Instr::AxtTouch { .. }
        | ir::Instr::StageAnchoredSpend { .. }
        | ir::Instr::VerifyDsProof { .. }
        | ir::Instr::AxtCommit
        | ir::Instr::TransferBatchBegin
        | ir::Instr::TransferBatchEnd
        | ir::Instr::CommitOutput
        | ir::Instr::SmartContractLifecycle { .. }
        | ir::Instr::ExpectRejectAs { .. } => None,
        ir::Instr::CallMulti { .. }
        | ir::Instr::CallContract { .. }
        | ir::Instr::InvokeEntrypointAsMulti { .. }
        | ir::Instr::MapLoadPair { .. }
        | ir::Instr::StateScan { .. }
        | ir::Instr::CoreQueryPage { .. } => None,
    }
}
fn rewrite_instr_definitions<F: FnMut(&mut Temp)>(instruction: &mut ir::Instr, mut visit: F) {
    if let Some(destination) = dest_temp_mut(instruction) {
        visit(destination);
    }
    match instruction {
        ir::Instr::StateScan {
            page,
            next,
            count,
            examined,
            ..
        } => {
            visit(page);
            visit(next);
            visit(count);
            visit(examined);
        }
        ir::Instr::MapLoadPair {
            dest_key, dest_val, ..
        } => {
            visit(dest_key);
            visit(dest_val);
        }
        ir::Instr::CallMulti { dests, .. }
        | ir::Instr::CallContract { dests, .. }
        | ir::Instr::InvokeEntrypointAsMulti { dests, .. } => {
            for destination in dests {
                visit(destination);
            }
        }
        ir::Instr::CoreQueryPage {
            items_dest,
            next_offset_dest,
            ..
        } => {
            visit(items_dest);
            visit(next_offset_dest);
        }
        _ => {}
    }
}
fn rewrite_terminator_uses<F: FnMut(&mut Temp)>(terminator: &mut ir::Terminator, mut visit: F) {
    match terminator {
        ir::Terminator::Return(Some(value)) => visit(value),
        ir::Terminator::Return2(first, second) => {
            visit(first);
            visit(second);
        }
        ir::Terminator::ReturnN(values) => {
            for value in values {
                visit(value);
            }
        }
        ir::Terminator::Branch { cond, .. } => visit(cond),
        ir::Terminator::Return(None) | ir::Terminator::Jump(_) => {}
    }
}
struct Renamer {
    cfg: Cfg,
    phi_variables: Vec<BTreeSet<usize>>,
    raw_blocks: Vec<Option<ir::BasicBlock>>,
    blocks: Vec<Option<BasicBlock>>,
    stacks: BTreeMap<usize, Vec<Value>>,
    phi_destinations: Vec<BTreeMap<usize, Value>>,
    phi_inputs: Vec<BTreeMap<usize, Vec<PhiInput>>>,
    next_value: usize,
}
enum RenameEvent {
    Enter(usize),
    Exit(Vec<usize>),
}
impl Renamer {
    fn new(cfg: Cfg, phi_variables: Vec<BTreeSet<usize>>, blocks: Vec<ir::BasicBlock>) -> Self {
        let len = blocks.len();
        Self {
            cfg,
            phi_variables,
            raw_blocks: blocks.into_iter().map(Some).collect(),
            blocks: (0..len).map(|_| None).collect(),
            stacks: BTreeMap::new(),
            phi_destinations: vec![BTreeMap::new(); len],
            phi_inputs: vec![BTreeMap::new(); len],
            next_value: 0,
        }
    }
    fn rename(&mut self) -> Result<(), String> {
        let mut events = vec![RenameEvent::Enter(self.cfg.entry)];
        while let Some(event) = events.pop() {
            match event {
                RenameEvent::Enter(block_index) => {
                    let pushed = self.rename_block(block_index)?;
                    events.push(RenameEvent::Exit(pushed));
                    for child in self.cfg.dominator_children[block_index].iter().rev() {
                        events.push(RenameEvent::Enter(*child));
                    }
                }
                RenameEvent::Exit(pushed) => {
                    for variable in pushed.into_iter().rev() {
                        let stack = self.stacks.get_mut(&variable).ok_or_else(|| {
                            format!("missing SSA rename stack for lowering temporary {variable}")
                        })?;
                        stack.pop().ok_or_else(|| {
                            format!("empty SSA rename stack for lowering temporary {variable}")
                        })?;
                    }
                }
            }
        }
        Ok(())
    }
    fn rename_block(&mut self, block_index: usize) -> Result<Vec<usize>, String> {
        let raw = self.raw_blocks[block_index]
            .take()
            .ok_or_else(|| format!("SSA block {:?} visited twice", self.cfg.labels[block_index]))?;
        let mut pushed = Vec::<usize>::new();
        let phi_variables = self.phi_variables[block_index]
            .iter()
            .copied()
            .collect::<Vec<_>>();
        for variable in phi_variables {
            let value = self.new_value()?;
            self.stacks.entry(variable).or_default().push(value);
            self.phi_destinations[block_index].insert(variable, value);
            pushed.push(variable);
        }
        let mut instructions = Vec::with_capacity(raw.instrs.len());
        let mut source = None;
        for mut operation in raw.instrs {
            if let ir::Instr::Source(next) = operation {
                source = next;
                continue;
            }
            let mut expected_uses = 0usize;
            let mut expected_definitions = 0usize;
            visit_instr_uses(&operation, |_| expected_uses += 1);
            visit_instr_defs(&operation, |_| expected_definitions += 1);
            let mut failure = None;
            let mut rewritten_uses = 0usize;
            rewrite_instr_uses(&mut operation, |variable| {
                rewritten_uses += 1;
                if failure.is_some() {
                    return;
                }
                match self.current_value(*variable, raw.label) {
                    Ok(value) => *variable = value.encoded(),
                    Err(error) => failure = Some(error),
                }
            });
            if let Some(error) = failure {
                return Err(error);
            }
            let mut rewritten_definitions = 0usize;
            let mut definition_failure = None;
            rewrite_instr_definitions(&mut operation, |variable| {
                rewritten_definitions += 1;
                if definition_failure.is_some() {
                    return;
                }
                let lowering_variable = *variable;
                let value = match self.new_value() {
                    Ok(value) => value,
                    Err(error) => {
                        definition_failure = Some(error);
                        return;
                    }
                };
                self.stacks
                    .entry(lowering_variable.0)
                    .or_default()
                    .push(value);
                pushed.push(lowering_variable.0);
                *variable = value.encoded();
            });
            if let Some(error) = definition_failure {
                return Err(error);
            }
            if expected_uses != rewritten_uses || expected_definitions != rewritten_definitions {
                return Err(format!(
                    "lowering opcode projection drift in block {:?}: rewrote \
                     {rewritten_uses}/{expected_uses} uses and \
                     {rewritten_definitions}/{expected_definitions} definitions",
                    raw.label
                ));
            }
            instructions.push(ValueInstruction(operation, source));
        }
        let mut terminator = raw.terminator;
        let mut expected_terminator_uses = 0usize;
        visit_terminator_uses(&terminator, |_| expected_terminator_uses += 1);
        let mut failure = None;
        let mut rewritten_terminator_uses = 0usize;
        rewrite_terminator_uses(&mut terminator, |variable| {
            rewritten_terminator_uses += 1;
            if failure.is_some() {
                return;
            }
            match self.current_value(*variable, raw.label) {
                Ok(value) => *variable = value.encoded(),
                Err(error) => failure = Some(error),
            }
        });
        if let Some(error) = failure {
            return Err(error);
        }
        if expected_terminator_uses != rewritten_terminator_uses {
            return Err(format!(
                "lowering terminator projection drift in block {:?}: rewrote \
                 {rewritten_terminator_uses}/{expected_terminator_uses} uses",
                raw.label
            ));
        }
        for successor in self.cfg.successors[block_index].clone() {
            let variables = self.phi_variables[successor]
                .iter()
                .copied()
                .collect::<Vec<_>>();
            for variable in variables {
                let value = self.current_value(Temp(variable), raw.label)?;
                self.phi_inputs[successor]
                    .entry(variable)
                    .or_default()
                    .push(PhiInput {
                        predecessor: raw.label,
                        value,
                    });
            }
        }
        self.blocks[block_index] = Some(BasicBlock {
            label: raw.label,
            phis: Vec::new(),
            instructions,
            terminator: ValueTerminator(terminator, source),
        });
        Ok(pushed)
    }
    fn finish(mut self) -> Result<Vec<BasicBlock>, String> {
        for block_index in 0..self.blocks.len() {
            let mut phis = Vec::with_capacity(self.phi_variables[block_index].len());
            for variable in &self.phi_variables[block_index] {
                let destination = self.phi_destinations[block_index]
                    .remove(variable)
                    .ok_or_else(|| {
                        format!(
                            "missing SSA Phi destination for {:?} in block {:?}",
                            Temp(*variable),
                            self.cfg.labels[block_index]
                        )
                    })?;
                let mut inputs = self.phi_inputs[block_index]
                    .remove(variable)
                    .unwrap_or_default();
                inputs.sort_by_key(|input| input.predecessor.0);
                phis.push(Phi {
                    variable: Temp(*variable),
                    destination,
                    inputs,
                });
            }
            self.blocks[block_index]
                .as_mut()
                .ok_or_else(|| {
                    format!(
                        "SSA dominator traversal missed block {:?}",
                        self.cfg.labels[block_index]
                    )
                })?
                .phis = phis;
        }
        self.blocks
            .into_iter()
            .enumerate()
            .map(|(index, block)| {
                block.ok_or_else(|| {
                    format!("missing renamed SSA block {:?}", self.cfg.labels[index])
                })
            })
            .collect()
    }
    fn new_value(&mut self) -> Result<Value, String> {
        let value = Value(self.next_value);
        self.next_value = self
            .next_value
            .checked_add(1)
            .ok_or_else(|| "SSA value identity space exhausted".to_owned())?;
        Ok(value)
    }
    fn current_value(&self, variable: Temp, block: Label) -> Result<Value, String> {
        self.stacks
            .get(&variable.0)
            .and_then(|stack| stack.last())
            .copied()
            .ok_or_else(|| {
                format!(
                    "lowering temporary {variable:?} is used before definition in block {block:?}"
                )
            })
    }
}
#[cfg(test)]
mod tests {
    use super::{
        BasicBlock as SsaBlock, Cfg, Function as SsaFunction, MAX_SSA_BLOCKS_PER_FUNCTION,
        MAX_SSA_INSTRUCTIONS_PER_FUNCTION, Phi, PhiInput, Program, Renamer, Value,
        ValueInstruction, ValueTerminator, validate_ssa_budget_counts,
    };
    use crate::{
        ast::{BinaryOp, SourceLocation, UnaryOp},
        ir::{BasicBlock, Function, Instr, Label, Program as IrProgram, Temp, Terminator},
    };
    use std::collections::{BTreeMap, BTreeSet};
    fn function(blocks: Vec<BasicBlock>) -> Function {
        Function {
            name: "test".to_owned(),
            params: Vec::new(),
            blocks,
            entry: Label(0),
            location: SourceLocation {
                line: 7,
                column: 11,
            },
        }
    }
    fn named_function(name: &str, blocks: Vec<BasicBlock>) -> Function {
        let mut function = function(blocks);
        function.name = name.to_owned();
        function
    }
    fn branch_join_program() -> IrProgram {
        IrProgram {
            functions: vec![function(vec![
                BasicBlock {
                    label: Label(0),
                    instrs: vec![Instr::Const {
                        dest: Temp(0),
                        value: 1,
                    }],
                    terminator: Terminator::Branch {
                        cond: Temp(0),
                        then_bb: Label(1),
                        else_bb: Label(2),
                    },
                },
                BasicBlock {
                    label: Label(1),
                    instrs: vec![Instr::Const {
                        dest: Temp(1),
                        value: 10,
                    }],
                    terminator: Terminator::Jump(Label(3)),
                },
                BasicBlock {
                    label: Label(2),
                    instrs: vec![Instr::Const {
                        dest: Temp(1),
                        value: 20,
                    }],
                    terminator: Terminator::Jump(Label(3)),
                },
                BasicBlock {
                    label: Label(3),
                    instrs: vec![Instr::Binary {
                        dest: Temp(2),
                        op: BinaryOp::Add,
                        left: Temp(1),
                        right: Temp(1),
                    }],
                    terminator: Terminator::Return(Some(Temp(2))),
                },
            ])],
        }
    }
    fn loop_join_program() -> IrProgram {
        IrProgram {
            functions: vec![function(vec![
                BasicBlock {
                    label: Label(0),
                    instrs: vec![
                        Instr::Const {
                            dest: Temp(0),
                            value: 0,
                        },
                        Instr::Const {
                            dest: Temp(1),
                            value: 1,
                        },
                        Instr::Const {
                            dest: Temp(2),
                            value: 3,
                        },
                    ],
                    terminator: Terminator::Jump(Label(1)),
                },
                BasicBlock {
                    label: Label(1),
                    instrs: vec![Instr::Binary {
                        dest: Temp(3),
                        op: BinaryOp::Lt,
                        left: Temp(0),
                        right: Temp(2),
                    }],
                    terminator: Terminator::Branch {
                        cond: Temp(3),
                        then_bb: Label(2),
                        else_bb: Label(3),
                    },
                },
                BasicBlock {
                    label: Label(2),
                    instrs: vec![Instr::Binary {
                        dest: Temp(0),
                        op: BinaryOp::Add,
                        left: Temp(0),
                        right: Temp(1),
                    }],
                    terminator: Terminator::Jump(Label(1)),
                },
                BasicBlock {
                    label: Label(3),
                    instrs: Vec::new(),
                    terminator: Terminator::Return(Some(Temp(0))),
                },
            ])],
        }
    }
    fn nested_join_program() -> IrProgram {
        IrProgram {
            functions: vec![function(vec![
                BasicBlock {
                    label: Label(0),
                    instrs: vec![Instr::Const {
                        dest: Temp(0),
                        value: 1,
                    }],
                    terminator: Terminator::Branch {
                        cond: Temp(0),
                        then_bb: Label(1),
                        else_bb: Label(2),
                    },
                },
                BasicBlock {
                    label: Label(1),
                    instrs: vec![Instr::Const {
                        dest: Temp(3),
                        value: 1,
                    }],
                    terminator: Terminator::Branch {
                        cond: Temp(3),
                        then_bb: Label(3),
                        else_bb: Label(4),
                    },
                },
                BasicBlock {
                    label: Label(2),
                    instrs: vec![Instr::Const {
                        dest: Temp(1),
                        value: 30,
                    }],
                    terminator: Terminator::Jump(Label(5)),
                },
                BasicBlock {
                    label: Label(3),
                    instrs: vec![Instr::Const {
                        dest: Temp(1),
                        value: 10,
                    }],
                    terminator: Terminator::Jump(Label(6)),
                },
                BasicBlock {
                    label: Label(4),
                    instrs: vec![Instr::Const {
                        dest: Temp(1),
                        value: 20,
                    }],
                    terminator: Terminator::Jump(Label(6)),
                },
                BasicBlock {
                    label: Label(6),
                    instrs: Vec::new(),
                    terminator: Terminator::Jump(Label(5)),
                },
                BasicBlock {
                    label: Label(5),
                    instrs: Vec::new(),
                    terminator: Terminator::Return(Some(Temp(1))),
                },
            ])],
        }
    }
    fn critical_edge_program() -> IrProgram {
        IrProgram {
            functions: vec![function(vec![
                BasicBlock {
                    label: Label(0),
                    instrs: vec![Instr::Const {
                        dest: Temp(0),
                        value: 1,
                    }],
                    terminator: Terminator::Branch {
                        cond: Temp(0),
                        then_bb: Label(1),
                        else_bb: Label(2),
                    },
                },
                BasicBlock {
                    label: Label(1),
                    instrs: vec![Instr::Const {
                        dest: Temp(1),
                        value: 10,
                    }],
                    terminator: Terminator::Branch {
                        cond: Temp(0),
                        then_bb: Label(3),
                        else_bb: Label(4),
                    },
                },
                BasicBlock {
                    label: Label(2),
                    instrs: vec![Instr::Const {
                        dest: Temp(1),
                        value: 20,
                    }],
                    terminator: Terminator::Jump(Label(3)),
                },
                BasicBlock {
                    label: Label(3),
                    instrs: Vec::new(),
                    terminator: Terminator::Return(Some(Temp(1))),
                },
                BasicBlock {
                    label: Label(4),
                    instrs: Vec::new(),
                    terminator: Terminator::Return(None),
                },
            ])],
        }
    }
    fn cyclic_loop_ssa_program() -> Program {
        Program {
            functions: vec![SsaFunction {
                name: "cyclic_loop".to_owned(),
                params: Vec::new(),
                blocks: vec![
                    SsaBlock {
                        label: Label(0),
                        phis: Vec::new(),
                        instructions: vec![
                            ValueInstruction::new(Instr::Const {
                                dest: Value(2).encoded(),
                                value: 1,
                            }),
                            ValueInstruction::new(Instr::Const {
                                dest: Value(3).encoded(),
                                value: 2,
                            }),
                        ],
                        terminator: ValueTerminator::new(Terminator::Jump(Label(1))),
                    },
                    SsaBlock {
                        label: Label(1),
                        phis: vec![
                            Phi {
                                variable: Temp(10),
                                destination: Value(0),
                                inputs: vec![
                                    PhiInput {
                                        predecessor: Label(0),
                                        value: Value(2),
                                    },
                                    PhiInput {
                                        predecessor: Label(1),
                                        value: Value(1),
                                    },
                                ],
                            },
                            Phi {
                                variable: Temp(11),
                                destination: Value(1),
                                inputs: vec![
                                    PhiInput {
                                        predecessor: Label(0),
                                        value: Value(3),
                                    },
                                    PhiInput {
                                        predecessor: Label(1),
                                        value: Value(0),
                                    },
                                ],
                            },
                        ],
                        instructions: Vec::new(),
                        terminator: ValueTerminator::new(Terminator::Branch {
                            cond: Value(0).encoded(),
                            then_bb: Label(1),
                            else_bb: Label(2),
                        }),
                    },
                    SsaBlock {
                        label: Label(2),
                        phis: Vec::new(),
                        instructions: Vec::new(),
                        terminator: ValueTerminator::new(Terminator::Return(Some(
                            Value(0).encoded(),
                        ))),
                    },
                ],
                entry: Label(0),
                location: SourceLocation { line: 9, column: 4 },
            }],
        }
    }
    #[test]
    fn dead_value_elimination_retains_a_live_phi_cycle() {
        let mut program = cyclic_loop_ssa_program();
        program.verify().expect("verify live Phi cycle");

        assert!(
            !program.functions[0]
                .eliminate_dead_values()
                .expect("retain live Phi cycle")
        );
        program.verify().expect("verify retained Phi cycle");
        assert_eq!(program.functions[0].blocks[0].instructions.len(), 2);
        assert_eq!(program.functions[0].blocks[1].phis.len(), 2);
    }
    #[test]
    fn dead_value_elimination_removes_an_unrooted_phi_cycle() {
        let mut program = cyclic_loop_ssa_program();
        program.functions[0].blocks[0]
            .instructions
            .push(ValueInstruction::new(Instr::LoadVar {
                dest: Value(4).encoded(),
                name: "condition".to_owned(),
            }));
        program.functions[0].blocks[1].terminator = ValueTerminator::new(Terminator::Branch {
            cond: Value(4).encoded(),
            then_bb: Label(1),
            else_bb: Label(2),
        });
        program.functions[0].blocks[2].terminator = ValueTerminator::new(Terminator::Return(None));
        program.verify().expect("verify unrooted Phi cycle");

        assert!(
            program.functions[0]
                .eliminate_dead_values()
                .expect("remove unrooted Phi cycle")
        );
        program.verify().expect("verify removed Phi cycle");
        assert!(program.functions[0].blocks[1].phis.is_empty());
        assert!(matches!(
            program.functions[0].blocks[0].instructions.as_slice(),
            [ValueInstruction(Instr::LoadVar { name, .. }, _)] if name == "condition"
        ));
    }
    #[test]
    fn coalescing_collapses_a_self_referential_phi_with_one_seed() {
        let mut program = Program {
            functions: vec![SsaFunction {
                name: "self_phi".to_owned(),
                params: Vec::new(),
                blocks: vec![
                    SsaBlock {
                        label: Label(0),
                        phis: Vec::new(),
                        instructions: vec![
                            ValueInstruction::new(Instr::LoadVar {
                                dest: Value(1).encoded(),
                                name: "seed".to_owned(),
                            }),
                            ValueInstruction::new(Instr::LoadVar {
                                dest: Value(2).encoded(),
                                name: "condition".to_owned(),
                            }),
                        ],
                        terminator: ValueTerminator::new(Terminator::Jump(Label(1))),
                    },
                    SsaBlock {
                        label: Label(1),
                        phis: vec![Phi {
                            variable: Temp(0),
                            destination: Value(0),
                            inputs: vec![
                                PhiInput {
                                    predecessor: Label(0),
                                    value: Value(1),
                                },
                                PhiInput {
                                    predecessor: Label(1),
                                    value: Value(0),
                                },
                            ],
                        }],
                        instructions: Vec::new(),
                        terminator: ValueTerminator::new(Terminator::Branch {
                            cond: Value(2).encoded(),
                            then_bb: Label(1),
                            else_bb: Label(2),
                        }),
                    },
                    SsaBlock {
                        label: Label(2),
                        phis: Vec::new(),
                        instructions: Vec::new(),
                        terminator: ValueTerminator::new(Terminator::Return(Some(
                            Value(0).encoded(),
                        ))),
                    },
                ],
                entry: Label(0),
                location: SourceLocation { line: 9, column: 4 },
            }],
        };
        program.verify().expect("verify self-referential Phi");

        assert!(
            program.functions[0]
                .coalesce_trivial_values()
                .expect("coalesce self-referential Phi")
        );
        program.verify().expect("verify coalesced Phi");
        assert!(program.functions[0].blocks[1].phis.is_empty());
        assert!(matches!(
            program.functions[0].blocks[2].terminator.as_ir(),
            Terminator::Return(Some(value)) if *value == Value(1).encoded()
        ));
    }
    #[test]
    fn branch_join_has_one_explicit_phi() {
        let program = Program::from_ir(branch_join_program()).expect("construct branch SSA");
        program.verify().expect("verify branch SSA");
        assert_eq!(program.phi_count(), 1);
        let join = program.functions[0]
            .blocks
            .iter()
            .find(|block| block.label == Label(3))
            .expect("join block");
        assert_eq!(join.phis[0].variable, Temp(1));
        assert_eq!(
            join.phis[0]
                .inputs
                .iter()
                .map(|input| input.predecessor)
                .collect::<Vec<_>>(),
            vec![Label(1), Label(2)]
        );
    }
    #[test]
    fn branch_local_temporary_does_not_create_an_incomplete_phi() {
        let raw = IrProgram {
            functions: vec![function(vec![
                BasicBlock {
                    label: Label(0),
                    instrs: vec![Instr::Const {
                        dest: Temp(0),
                        value: 1,
                    }],
                    terminator: Terminator::Branch {
                        cond: Temp(0),
                        then_bb: Label(1),
                        else_bb: Label(2),
                    },
                },
                BasicBlock {
                    label: Label(1),
                    instrs: vec![
                        Instr::Const {
                            dest: Temp(1),
                            value: 7,
                        },
                        Instr::Copy {
                            dest: Temp(2),
                            src: Temp(1),
                        },
                    ],
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
                    terminator: Terminator::Return(None),
                },
            ])],
        };
        let program = Program::from_ir(raw).expect("dead branch-local values need no Phi");
        program.verify().expect("verify pruned branch SSA");
        assert_eq!(program.phi_count(), 0);
    }
    #[test]
    fn ssa_budget_rejects_counts_above_each_v1_ceiling() {
        validate_ssa_budget_counts(
            MAX_SSA_BLOCKS_PER_FUNCTION,
            MAX_SSA_INSTRUCTIONS_PER_FUNCTION,
        )
        .expect("exact V1 SSA ceilings are accepted");
        let block_error = validate_ssa_budget_counts(
            MAX_SSA_BLOCKS_PER_FUNCTION + 1,
            MAX_SSA_INSTRUCTIONS_PER_FUNCTION,
        )
        .expect_err("block count above the ceiling must fail");
        assert!(block_error.contains("4097 blocks"), "{block_error}");
        let instruction_error = validate_ssa_budget_counts(
            MAX_SSA_BLOCKS_PER_FUNCTION,
            MAX_SSA_INSTRUCTIONS_PER_FUNCTION + 1,
        )
        .expect_err("instruction count above the ceiling must fail");
        assert!(
            instruction_error.contains("262145 instructions"),
            "{instruction_error}"
        );
    }
    #[test]
    fn iterative_renaming_handles_a_deep_dominator_chain() {
        const BLOCKS: usize = 2_048;
        let blocks = (0..BLOCKS)
            .map(|index| BasicBlock {
                label: Label(index),
                instrs: Vec::new(),
                terminator: if index + 1 == BLOCKS {
                    Terminator::Return(None)
                } else {
                    Terminator::Jump(Label(index + 1))
                },
            })
            .collect();
        let program = Program::from_ir(IrProgram {
            functions: vec![function(blocks)],
        })
        .expect("deep bounded CFG must not recurse on the process stack");
        assert_eq!(program.functions[0].blocks.len(), BLOCKS);
    }
    #[test]
    fn ssa_value_identity_exhaustion_is_a_stable_error() {
        let blocks = vec![BasicBlock {
            label: Label(0),
            instrs: vec![Instr::Const {
                dest: Temp(0),
                value: 1,
            }],
            terminator: Terminator::Return(Some(Temp(0))),
        }];
        let cfg = Cfg::new(
            Label(0),
            blocks.iter().map(|block| (block.label, &block.terminator)),
        )
        .expect("single-block CFG");
        let mut renamer = Renamer::new(cfg, vec![Default::default()], blocks);
        renamer.next_value = usize::MAX;
        let error = renamer
            .rename()
            .expect_err("value identity wraparound must fail closed");
        assert_eq!(error, "SSA value identity space exhausted");
    }
    #[test]
    fn loop_header_phi_versions_loop_carried_value() {
        let program = Program::from_ir(loop_join_program()).expect("construct loop SSA");
        program.verify().expect("verify loop SSA");
        let header = program.functions[0]
            .blocks
            .iter()
            .find(|block| block.label == Label(1))
            .expect("loop header");
        assert_eq!(header.phis.len(), 1);
        assert_eq!(header.phis[0].variable, Temp(0));
        assert_eq!(
            header.phis[0]
                .inputs
                .iter()
                .map(|input| input.predecessor)
                .collect::<Vec<_>>(),
            vec![Label(0), Label(2)]
        );
    }
    #[test]
    fn entry_backedge_receives_a_deterministic_preheader() {
        let raw = IrProgram {
            functions: vec![function(vec![
                BasicBlock {
                    label: Label(0),
                    instrs: vec![Instr::Const {
                        dest: Temp(0),
                        value: 1,
                    }],
                    terminator: Terminator::Branch {
                        cond: Temp(0),
                        then_bb: Label(0),
                        else_bb: Label(1),
                    },
                },
                BasicBlock {
                    label: Label(1),
                    instrs: Vec::new(),
                    terminator: Terminator::Return(None),
                },
            ])],
        };
        let lowered = Program::from_ir(raw)
            .expect("construct entry-loop SSA")
            .into_ir()
            .expect("destroy entry-loop SSA");
        let function = &lowered.functions[0];
        assert_eq!(function.entry, Label(2));
        let preheader = function
            .blocks
            .iter()
            .find(|block| block.label == Label(2))
            .expect("synthetic entry preheader");
        assert!(preheader.instrs.is_empty());
        assert!(matches!(&preheader.terminator, Terminator::Jump(Label(0))));
    }
    #[test]
    fn nested_control_flow_places_inner_and_outer_phis() {
        let program = Program::from_ir(nested_join_program()).expect("construct nested SSA");
        program.verify().expect("verify nested SSA");
        assert_eq!(program.phi_count(), 2);
        let labels = program.functions[0]
            .blocks
            .iter()
            .filter(|block| !block.phis.is_empty())
            .map(|block| block.label)
            .collect::<Vec<_>>();
        assert_eq!(labels, vec![Label(6), Label(5)]);
    }
    #[test]
    fn de_ssa_splits_a_critical_edge_before_materializing_phi_copies() {
        let lowered = Program::from_ir(critical_edge_program())
            .expect("construct critical-edge SSA")
            .into_ir()
            .expect("destroy critical-edge SSA");
        let function = &lowered.functions[0];
        assert_eq!(function.blocks.len(), 6);
        let branch = function
            .blocks
            .iter()
            .find(|block| block.label == Label(1))
            .expect("critical predecessor");
        let split = match &branch.terminator {
            Terminator::Branch {
                then_bb,
                else_bb: Label(4),
                ..
            } => *then_bb,
            terminator => panic!("critical predecessor was not retargeted: {terminator:?}"),
        };
        assert_ne!(split, Label(3));
        let split_block = function
            .blocks
            .iter()
            .find(|block| block.label == split)
            .expect("split edge block");
        assert!(
            matches!(&split_block.terminator, Terminator::Jump(Label(3))),
            "split edge must rejoin the original Phi block"
        );
        assert_eq!(split_block.instrs.len(), 1);
        assert!(matches!(&split_block.instrs[0], Instr::Copy { .. }));
    }
    #[test]
    fn cyclic_loop_phi_copies_use_a_scratch_on_the_split_backedge() {
        let program = cyclic_loop_ssa_program();
        program.verify().expect("verify adversarial loop SSA");
        let lowered = program.into_ir().expect("destroy cyclic loop SSA");
        let function = &lowered.functions[0];
        let header = function
            .blocks
            .iter()
            .find(|block| block.label == Label(1))
            .expect("loop header");
        let split = match &header.terminator {
            Terminator::Branch {
                then_bb,
                else_bb: Label(2),
                ..
            } => *then_bb,
            terminator => panic!("loop backedge was not split: {terminator:?}"),
        };
        let backedge = function
            .blocks
            .iter()
            .find(|block| block.label == split)
            .expect("split loop backedge");
        assert!(matches!(&backedge.terminator, Terminator::Jump(Label(1))));
        assert_eq!(
            backedge.instrs,
            vec![
                Instr::Copy {
                    dest: Temp(4),
                    src: Temp(0),
                },
                Instr::Copy {
                    dest: Temp(0),
                    src: Temp(1),
                },
                Instr::Copy {
                    dest: Temp(1),
                    src: Temp(4),
                },
            ]
        );
    }
    #[test]
    fn join_and_critical_edge_destruction_is_byte_for_byte_stable() {
        let first = Program::from_ir(critical_edge_program())
            .expect("construct first SSA")
            .into_ir()
            .expect("destroy first SSA");
        let second = Program::from_ir(critical_edge_program())
            .expect("construct second SSA")
            .into_ir()
            .expect("destroy second SSA");
        assert_eq!(format!("{first:#?}"), format!("{second:#?}"));
    }
    #[test]
    fn verifier_rejects_duplicate_value_definition() {
        let mut program = Program::from_ir(branch_join_program()).expect("construct branch SSA");
        let duplicate = match program.functions[0].blocks[0].instructions[0].as_ir() {
            Instr::Const { dest, .. } => Value::decode(*dest),
            instruction => panic!("expected SSA const, got {instruction:?}"),
        };
        let join = program.functions[0]
            .blocks
            .iter_mut()
            .find(|block| block.label == Label(3))
            .expect("join block");
        join.phis[0].destination = duplicate;
        let error = program
            .verify()
            .expect_err("duplicate SSA definition must fail");
        assert!(error.contains("defined more than once"), "{error}");
    }
    #[test]
    fn verifier_rejects_same_instruction_use_before_definition() {
        let mut program = Program::from_ir(branch_join_program()).expect("construct branch SSA");
        let join = program.functions[0]
            .blocks
            .iter_mut()
            .find(|block| block.label == Label(3))
            .expect("join block");
        match join.instructions[0].as_ir_mut() {
            Instr::Binary { dest, left, .. } => *left = *dest,
            instruction => panic!("expected SSA binary, got {instruction:?}"),
        }
        let error = program
            .verify()
            .expect_err("same-instruction use must fail dominance ordering");
        assert!(error.contains("used before its definition"), "{error}");
    }
    #[test]
    fn construction_rejects_use_before_definition() {
        let program = IrProgram {
            functions: vec![function(vec![BasicBlock {
                label: Label(0),
                instrs: vec![Instr::Binary {
                    dest: Temp(1),
                    op: BinaryOp::Add,
                    left: Temp(0),
                    right: Temp(0),
                }],
                terminator: Terminator::Return(Some(Temp(1))),
            }])],
        };
        let error = Program::from_ir(program).expect_err("undefined use must fail");
        assert!(error.contains("function `test`"), "{error}");
        assert!(error.contains("used before definition"), "{error}");
    }
    #[test]
    fn private_numeric_instructions_version_aliased_sources_before_destinations() {
        let raw = IrProgram {
            functions: vec![function(vec![BasicBlock {
                label: Label(0),
                instrs: vec![
                    Instr::Const {
                        dest: Temp(0),
                        value: 7,
                    },
                    Instr::GetPrivateInput {
                        dest: Temp(0),
                        index: Temp(0),
                        kind: ivm_abi::private_input::PrivateInputKindV1::Decimal,
                    },
                    Instr::PrivateNumericValcom {
                        dest: Temp(0),
                        value: Temp(0),
                        blind: Temp(0),
                    },
                ],
                terminator: Terminator::Return(Some(Temp(0))),
            }])],
        };
        let program = Program::from_ir(raw).expect("construct aliased private-numeric SSA");
        program
            .verify()
            .expect("verify aliased private-numeric SSA");
        let instructions = &program.functions[0].blocks[0].instructions;
        let constant = match instructions[0].as_ir() {
            Instr::Const { dest, .. } => Value::decode(*dest),
            instruction => panic!("expected constant, got {instruction:?}"),
        };
        let private_input = match instructions[1].as_ir() {
            Instr::GetPrivateInput { dest, index, .. } => {
                assert_eq!(Value::decode(*index), constant);
                let destination = Value::decode(*dest);
                assert_ne!(destination, constant);
                destination
            }
            instruction => panic!("expected private input, got {instruction:?}"),
        };
        match instructions[2].as_ir() {
            Instr::PrivateNumericValcom { dest, value, blind } => {
                assert_eq!(Value::decode(*value), private_input);
                assert_eq!(Value::decode(*blind), private_input);
                assert_ne!(Value::decode(*dest), private_input);
            }
            instruction => panic!("expected private commitment, got {instruction:?}"),
        }
    }
    #[test]
    fn construction_rejects_malformed_private_numeric_uses() {
        let private_input = IrProgram {
            functions: vec![function(vec![BasicBlock {
                label: Label(0),
                instrs: vec![Instr::GetPrivateInput {
                    dest: Temp(0),
                    index: Temp(1),
                    kind: ivm_abi::private_input::PrivateInputKindV1::Int,
                }],
                terminator: Terminator::Return(None),
            }])],
        };
        let private_input_error =
            Program::from_ir(private_input).expect_err("undefined private-input index must fail");
        assert!(
            private_input_error.contains("Temp(1) is used before definition"),
            "{private_input_error}"
        );
        let private_commitment = IrProgram {
            functions: vec![function(vec![BasicBlock {
                label: Label(0),
                instrs: vec![
                    Instr::Const {
                        dest: Temp(0),
                        value: 1,
                    },
                    Instr::PrivateNumericValcom {
                        dest: Temp(2),
                        value: Temp(0),
                        blind: Temp(1),
                    },
                ],
                terminator: Terminator::Return(None),
            }])],
        };
        let commitment_error = Program::from_ir(private_commitment)
            .expect_err("undefined private commitment blind must fail");
        assert!(
            commitment_error.contains("Temp(1) is used before definition"),
            "{commitment_error}"
        );
    }
    #[test]
    fn deterministic_de_ssa_preserves_checked_effectful_operations_and_origin() {
        let raw = IrProgram {
            functions: vec![function(vec![BasicBlock {
                label: Label(0),
                instrs: vec![
                    Instr::Const {
                        dest: Temp(0),
                        value: 8,
                    },
                    Instr::Const {
                        dest: Temp(1),
                        value: 2,
                    },
                    Instr::Binary {
                        dest: Temp(2),
                        op: BinaryOp::Div,
                        left: Temp(0),
                        right: Temp(1),
                    },
                    Instr::StateSet {
                        path: Temp(0),
                        value: Temp(2),
                    },
                ],
                terminator: Terminator::Return(Some(Temp(2))),
            }])],
        };
        let before = format!("{raw:#?}");
        let ssa = Program::from_ir(raw).expect("construct effectful SSA");
        let first_ssa = format!("{ssa:#?}");
        ssa.verify().expect("verify effectful SSA");
        let lowered = ssa.into_ir().expect("destroy SSA");
        assert_eq!(format!("{lowered:#?}"), before);
        assert_eq!(lowered.functions[0].location.line, 7);
        assert_eq!(lowered.functions[0].location.column, 11);
        let second = Program::from_ir(IrProgram {
            functions: lowered.functions,
        })
        .expect("reconstruct deterministic SSA");
        assert_eq!(format!("{second:#?}"), first_ssa);
    }
    #[test]
    fn sccp_materializes_a_constant_phi_from_two_executable_edges() {
        let raw = IrProgram {
            functions: vec![function(vec![
                BasicBlock {
                    label: Label(0),
                    instrs: vec![Instr::LoadVar {
                        dest: Temp(0),
                        name: "condition".to_owned(),
                    }],
                    terminator: Terminator::Branch {
                        cond: Temp(0),
                        then_bb: Label(1),
                        else_bb: Label(2),
                    },
                },
                BasicBlock {
                    label: Label(1),
                    instrs: vec![Instr::Const {
                        dest: Temp(1),
                        value: 37,
                    }],
                    terminator: Terminator::Jump(Label(3)),
                },
                BasicBlock {
                    label: Label(2),
                    instrs: vec![Instr::Const {
                        dest: Temp(1),
                        value: 37,
                    }],
                    terminator: Terminator::Jump(Label(3)),
                },
                BasicBlock {
                    label: Label(3),
                    instrs: Vec::new(),
                    terminator: Terminator::Return(Some(Temp(1))),
                },
            ])],
        };
        let mut program = Program::from_ir(raw).expect("construct same-constant Phi SSA");
        program
            .optimize_and_retain(&BTreeSet::from(["test".to_owned()]), &BTreeMap::new())
            .expect("optimize same-constant Phi");
        let join = program.functions[0]
            .blocks
            .iter()
            .find(|block| block.label == Label(3))
            .expect("join block");
        assert!(join.phis.is_empty(), "constant Phi must be materialized");
        assert!(matches!(
            join.instructions.as_slice(),
            [ValueInstruction(Instr::Const { value: 37, .. }, _)]
        ));
    }
    #[test]
    fn branch_folding_prunes_inactive_phi_input_and_coalesces_the_join() {
        let raw = IrProgram {
            functions: vec![function(vec![
                BasicBlock {
                    label: Label(0),
                    instrs: vec![Instr::Const {
                        dest: Temp(0),
                        value: 1,
                    }],
                    terminator: Terminator::Branch {
                        cond: Temp(0),
                        then_bb: Label(1),
                        else_bb: Label(2),
                    },
                },
                BasicBlock {
                    label: Label(1),
                    instrs: vec![Instr::LoadVar {
                        dest: Temp(1),
                        name: "selected".to_owned(),
                    }],
                    terminator: Terminator::Jump(Label(3)),
                },
                BasicBlock {
                    label: Label(2),
                    instrs: vec![Instr::LoadVar {
                        dest: Temp(1),
                        name: "inactive".to_owned(),
                    }],
                    terminator: Terminator::Jump(Label(3)),
                },
                BasicBlock {
                    label: Label(3),
                    instrs: Vec::new(),
                    terminator: Terminator::Return(Some(Temp(1))),
                },
            ])],
        };
        let mut program = Program::from_ir(raw).expect("construct branch-dependent Phi SSA");
        program
            .optimize_and_retain(&BTreeSet::from(["test".to_owned()]), &BTreeMap::new())
            .expect("optimize branch-dependent Phi");
        let function = &program.functions[0];
        assert_eq!(
            function
                .blocks
                .iter()
                .map(|block| block.label)
                .collect::<Vec<_>>(),
            vec![Label(1), Label(3)]
        );
        assert_eq!(function.entry, Label(1));
        assert_eq!(program.phi_count(), 0);
        assert!(function.blocks.iter().all(|block| {
            block.instructions.iter().all(|instruction| {
                !matches!(
                    instruction.as_ir(),
                    Instr::LoadVar { name, .. } if name == "inactive"
                )
            })
        }));
    }
    #[test]
    fn checked_arithmetic_trap_boundaries_are_retained_when_dead() {
        let raw = IrProgram {
            functions: vec![function(vec![BasicBlock {
                label: Label(0),
                instrs: vec![
                    Instr::Const {
                        dest: Temp(0),
                        value: i64::MAX,
                    },
                    Instr::Const {
                        dest: Temp(1),
                        value: 1,
                    },
                    Instr::Const {
                        dest: Temp(2),
                        value: 0,
                    },
                    Instr::Const {
                        dest: Temp(3),
                        value: i64::MIN,
                    },
                    Instr::Const {
                        dest: Temp(4),
                        value: -1,
                    },
                    Instr::Binary {
                        dest: Temp(5),
                        op: BinaryOp::Add,
                        left: Temp(0),
                        right: Temp(1),
                    },
                    Instr::Binary {
                        dest: Temp(6),
                        op: BinaryOp::Div,
                        left: Temp(1),
                        right: Temp(2),
                    },
                    Instr::Binary {
                        dest: Temp(7),
                        op: BinaryOp::Div,
                        left: Temp(3),
                        right: Temp(4),
                    },
                    Instr::Unary {
                        dest: Temp(8),
                        op: UnaryOp::Neg,
                        operand: Temp(3),
                    },
                ],
                terminator: Terminator::Return(None),
            }])],
        };
        let mut program = Program::from_ir(raw).expect("construct trapping SSA");
        program
            .optimize_and_retain(&BTreeSet::from(["test".to_owned()]), &BTreeMap::new())
            .expect("optimize trapping SSA");
        let operations = program.functions[0].blocks[0]
            .instructions
            .iter()
            .filter_map(|instruction| match instruction.as_ir() {
                Instr::Binary { op, .. } => Some(*op),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            operations,
            vec![BinaryOp::Add, BinaryOp::Div, BinaryOp::Div]
        );
        assert!(
            program.functions[0].blocks[0]
                .instructions
                .iter()
                .any(|instruction| matches!(
                    instruction.as_ir(),
                    Instr::Unary {
                        op: UnaryOp::Neg,
                        ..
                    }
                ))
        );
    }
    #[test]
    fn algebraic_identity_is_simplified_and_the_copy_is_coalesced() {
        let raw = IrProgram {
            functions: vec![function(vec![BasicBlock {
                label: Label(0),
                instrs: vec![
                    Instr::LoadVar {
                        dest: Temp(0),
                        name: "value".to_owned(),
                    },
                    Instr::Const {
                        dest: Temp(1),
                        value: 1,
                    },
                    Instr::Binary {
                        dest: Temp(2),
                        op: BinaryOp::Mul,
                        left: Temp(0),
                        right: Temp(1),
                    },
                ],
                terminator: Terminator::Return(Some(Temp(2))),
            }])],
        };
        let mut program = Program::from_ir(raw).expect("construct algebraic SSA");
        program
            .optimize_and_retain(&BTreeSet::from(["test".to_owned()]), &BTreeMap::new())
            .expect("optimize algebraic SSA");
        let block = &program.functions[0].blocks[0];
        assert!(matches!(
            block.instructions.as_slice(),
            [ValueInstruction(Instr::LoadVar { name, .. }, _)] if name == "value"
        ));
        assert!(matches!(
            block.terminator.as_ir(),
            Terminator::Return(Some(_))
        ));
    }
    #[test]
    fn coalescing_rewrites_a_long_copy_chain_in_one_batch() {
        const COPIES: usize = 8_192;
        let mut instructions = Vec::with_capacity(COPIES + 1);
        instructions.push(Instr::LoadVar {
            dest: Temp(0),
            name: "input".to_owned(),
        });
        instructions.extend((1..=COPIES).map(|index| Instr::Copy {
            dest: Temp(index),
            src: Temp(index - 1),
        }));
        let mut program = Program::from_ir(IrProgram {
            functions: vec![function(vec![BasicBlock {
                label: Label(0),
                instrs: instructions,
                terminator: Terminator::Return(Some(Temp(COPIES))),
            }])],
        })
        .expect("construct long-copy SSA");
        assert!(
            program.functions[0]
                .coalesce_trivial_values()
                .expect("coalesce long copy chain")
        );
        program.verify().expect("verify coalesced copy chain");
        let block = &program.functions[0].blocks[0];
        assert!(matches!(
            block.instructions.as_slice(),
            [ValueInstruction(Instr::LoadVar { name, .. }, _)] if name == "input"
        ));
        let Terminator::Return(Some(result)) = block.terminator.as_ir() else {
            panic!("copy-chain result must remain the function return");
        };
        let Instr::LoadVar { dest, .. } = block.instructions[0].as_ir() else {
            unreachable!("matched the remaining input load")
        };
        assert_eq!(result, dest);
    }
    #[test]
    fn nested_product_projections_coalesce_in_one_batch() {
        const UPDATES: usize = 8_192;
        let mut instructions = vec![
            Instr::LoadVar {
                dest: Temp(0),
                name: "input".into(),
            },
            Instr::TuplePack {
                dest: Temp(1),
                items: vec![Temp(0)],
            },
        ];
        let mut product = Temp(1);
        for index in 0..UPDATES {
            let field = Temp(2 + index * 2);
            let next = Temp(3 + index * 2);
            instructions.push(Instr::TupleGet {
                dest: field,
                tuple: product,
                index: 0,
            });
            instructions.push(Instr::TuplePack {
                dest: next,
                items: vec![field],
            });
            product = next;
        }
        let result = Temp(2 + UPDATES * 2);
        instructions.push(Instr::TupleGet {
            dest: result,
            tuple: product,
            index: 0,
        });
        let mut program = Program::from_ir(IrProgram {
            functions: vec![function(vec![BasicBlock {
                label: Label(0),
                instrs: instructions,
                terminator: Terminator::Return(Some(result)),
            }])],
        })
        .expect("construct projection chain");
        assert!(
            program.functions[0]
                .coalesce_trivial_values()
                .expect("fold projections")
        );
        program
            .verify()
            .expect("projection aliases must preserve dominance");
        program.functions[0]
            .eliminate_dead_values()
            .expect("remove unused products");
        assert!(
            matches!(program.functions[0].blocks[0].instructions.as_slice(),
            [ValueInstruction(Instr::LoadVar { name, .. }, _)] if name == "input")
        );
    }
    #[test]
    fn known_product_projection_bounds_fail_closed() {
        let mut program = Program::from_ir(IrProgram {
            functions: vec![function(vec![BasicBlock {
                label: Label(0),
                instrs: vec![
                    Instr::TuplePack {
                        dest: Temp(0),
                        items: vec![],
                    },
                    Instr::TupleGet {
                        dest: Temp(1),
                        tuple: Temp(0),
                        index: 0,
                    },
                ],
                terminator: Terminator::Return(Some(Temp(1))),
            }])],
        })
        .expect("construct malformed projection fixture");
        let error = program.functions[0]
            .coalesce_trivial_values()
            .expect_err("reject invalid field");
        assert!(error.contains("exceeds tuple width"), "{error}");
    }
    #[test]
    fn dead_value_elimination_removes_a_long_unused_chain_in_one_mark_sweep() {
        const COPIES: usize = 8_192;
        let mut instructions = Vec::with_capacity(COPIES + 1);
        instructions.push(Instr::LoadVar {
            dest: Temp(0),
            name: "unused".to_owned(),
        });
        instructions.extend((1..=COPIES).map(|index| Instr::Copy {
            dest: Temp(index),
            src: Temp(index - 1),
        }));
        let mut program = Program::from_ir(IrProgram {
            functions: vec![function(vec![BasicBlock {
                label: Label(0),
                instrs: instructions,
                terminator: Terminator::Return(None),
            }])],
        })
        .expect("construct unused SSA chain");
        assert!(
            program.functions[0]
                .eliminate_dead_values()
                .expect("eliminate unused chain")
        );
        program.verify().expect("verify dead-value cleanup");
        assert!(program.functions[0].blocks[0].instructions.is_empty());
    }
    #[test]
    fn effectful_state_write_is_retained_with_an_unused_result_graph() {
        let raw = IrProgram {
            functions: vec![function(vec![BasicBlock {
                label: Label(0),
                instrs: vec![
                    Instr::Const {
                        dest: Temp(0),
                        value: 4,
                    },
                    Instr::Const {
                        dest: Temp(1),
                        value: 9,
                    },
                    Instr::StateSet {
                        path: Temp(0),
                        value: Temp(1),
                    },
                ],
                terminator: Terminator::Return(None),
            }])],
        };
        let mut program = Program::from_ir(raw).expect("construct state-write SSA");
        program
            .optimize_and_retain(&BTreeSet::from(["test".to_owned()]), &BTreeMap::new())
            .expect("optimize state-write SSA");
        assert!(
            program.functions[0].blocks[0]
                .instructions
                .iter()
                .any(|instruction| matches!(instruction.as_ir(), Instr::StateSet { .. }))
        );
    }
    #[test]
    fn unreachable_call_does_not_retain_a_helper_function() {
        let root = named_function(
            "root",
            vec![
                BasicBlock {
                    label: Label(0),
                    instrs: vec![Instr::Const {
                        dest: Temp(0),
                        value: 1,
                    }],
                    terminator: Terminator::Branch {
                        cond: Temp(0),
                        then_bb: Label(1),
                        else_bb: Label(2),
                    },
                },
                BasicBlock {
                    label: Label(1),
                    instrs: Vec::new(),
                    terminator: Terminator::Return(None),
                },
                BasicBlock {
                    label: Label(2),
                    instrs: vec![Instr::Call {
                        callee: "helper".to_owned(),
                        args: Vec::new(),
                        dest: None,
                    }],
                    terminator: Terminator::Return(None),
                },
            ],
        );
        let helper = named_function(
            "helper",
            vec![BasicBlock {
                label: Label(0),
                instrs: Vec::new(),
                terminator: Terminator::Return(None),
            }],
        );
        let mut program = Program::from_ir(IrProgram {
            functions: vec![helper, root],
        })
        .expect("construct dead-call SSA");
        program
            .optimize_and_retain(&BTreeSet::from(["root".to_owned()]), &BTreeMap::new())
            .expect("optimize dead-call graph");
        assert_eq!(
            program
                .functions
                .iter()
                .map(|function| function.name.as_str())
                .collect::<Vec<_>>(),
            ["root"]
        );
    }
    #[test]
    fn whole_program_ssa_dce_fails_closed_on_missing_and_unresolved_symbols() {
        let unresolved = named_function(
            "root",
            vec![BasicBlock {
                label: Label(0),
                instrs: vec![Instr::Call {
                    callee: "missing".to_owned(),
                    args: Vec::new(),
                    dest: None,
                }],
                terminator: Terminator::Return(None),
            }],
        );
        let mut program = Program::from_ir(IrProgram {
            functions: vec![unresolved],
        })
        .expect("construct unresolved graph");
        let error = program
            .optimize_and_retain(&BTreeSet::from(["root".to_owned()]), &BTreeMap::new())
            .expect_err("unresolved call must fail closed");
        assert!(error.contains("unresolved SSA callee `missing`"), "{error}");
        let mut program = Program::from_ir(IrProgram {
            functions: vec![named_function(
                "root",
                vec![BasicBlock {
                    label: Label(0),
                    instrs: Vec::new(),
                    terminator: Terminator::Return(None),
                }],
            )],
        })
        .expect("construct missing-root graph");
        let error = program
            .optimize_and_retain(&BTreeSet::from(["absent".to_owned()]), &BTreeMap::new())
            .expect_err("missing root must fail closed");
        assert!(
            error.contains("missing SSA root function `absent`"),
            "{error}"
        );
        let make_empty = |name: &str| {
            named_function(
                name,
                vec![BasicBlock {
                    label: Label(0),
                    instrs: Vec::new(),
                    terminator: Terminator::Return(None),
                }],
            )
        };
        let mut first_program = Program::from_ir(IrProgram {
            functions: vec![make_empty("first")],
        })
        .expect("construct first duplicate candidate");
        let mut second_program = Program::from_ir(IrProgram {
            functions: vec![make_empty("second")],
        })
        .expect("construct second duplicate candidate");
        let first = first_program.functions.remove(0);
        let mut second = second_program.functions.remove(0);
        second.name = "first".to_owned();
        let mut duplicate = Program {
            functions: vec![first, second],
        };
        let error = duplicate
            .optimize_and_retain(&BTreeSet::from(["first".to_owned()]), &BTreeMap::new())
            .expect_err("duplicate symbols must fail before optimization");
        assert!(
            error.contains("duplicate SSA function symbol `first`"),
            "{error}"
        );
    }
    #[test]
    fn optimized_ssa_output_is_deterministic_and_corruption_is_rejected() {
        let optimize = || {
            let mut program = Program::from_ir(branch_join_program()).expect("construct SSA");
            program
                .optimize_and_retain(&BTreeSet::from(["test".to_owned()]), &BTreeMap::new())
                .expect("optimize SSA");
            program.into_ir().expect("destroy optimized SSA")
        };
        assert_eq!(format!("{:#?}", optimize()), format!("{:#?}", optimize()));
        let mut corrupt = Program::from_ir(branch_join_program()).expect("construct corrupt SSA");
        corrupt.functions[0].blocks[0]
            .instructions
            .push(ValueInstruction::new(Instr::Const {
                dest: Value(0).encoded(),
                value: 99,
            }));
        let error = corrupt
            .optimize_and_retain(&BTreeSet::from(["test".to_owned()]), &BTreeMap::new())
            .expect_err("duplicate SSA definition must fail before optimization");
        assert!(error.contains("defined more than once"), "{error}");
    }
}
