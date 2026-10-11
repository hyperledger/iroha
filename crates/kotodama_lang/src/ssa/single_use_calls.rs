//! Move one private helper body to its sole verified direct call site.
//!
//! This pass consumes the original body once: it never duplicates effects or
//! reorders argument evaluation. Fresh SSA values and CFG labels keep every
//! loop, return edge and caller Phi verified before register allocation.

use super::{
    BasicBlock, Function, MAX_SSA_BLOCKS_PER_FUNCTION, MAX_SSA_INSTRUCTIONS_PER_FUNCTION, Phi,
    PhiInput, Program, Value, ValueInstruction, ValueTerminator, rewrite_instruction_values,
    rewrite_terminator_values,
};
use crate::{
    ir::{Instr, Label, Temp, Terminator},
    regalloc::{visit_instr_defs, visit_instr_uses, visit_terminator_uses},
};
use std::collections::{BTreeMap, BTreeSet};

#[cfg(test)]
std::thread_local! {
    static RETAIN_PRIVATE_CALLS: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Same-compiler comparison with the unchanged ordinary private call lowering.
#[cfg(test)]
pub(crate) fn with_private_calls_retained<R>(body: impl FnOnce() -> R) -> R {
    struct Restore(bool);
    impl Drop for Restore {
        fn drop(&mut self) {
            RETAIN_PRIVATE_CALLS.set(self.0);
        }
    }
    let _restore = Restore(RETAIN_PRIVATE_CALLS.replace(true));
    body()
}

struct Site {
    caller: String,
    block: usize,
    instruction: usize,
}

impl Program {
    /// Move typed private scalar bodies that have exactly one live call site.
    ///
    /// `private_candidates` binds each validated declaration to whether its
    /// result is Unit. Public/test roots and recursive cycles stay ordinary
    /// calls. Exceeding the existing SSA budget skips the optimization without
    /// changing source acceptance. No second DCE runs: even discarded literal
    /// results must still reach the canonical code-generation validator.
    pub(crate) fn inline_single_use_private_calls(
        &mut self,
        roots: &BTreeSet<String>,
        private_candidates: &BTreeMap<String, bool>,
    ) -> Result<(), String> {
        self.verify()?;
        // Check all symbols before any owned body disappears.
        self.retain_reachable_functions(roots)?;
        #[cfg(test)]
        if RETAIN_PRIVATE_CALLS.get() {
            return Ok(());
        }
        loop {
            let mut sites = BTreeMap::<String, Vec<Site>>::new();
            let mut edges = BTreeMap::<String, BTreeSet<String>>::new();
            for caller in &self.functions {
                for (block_index, block) in caller.blocks.iter().enumerate() {
                    for (instruction_index, instruction) in block.instructions.iter().enumerate() {
                        match instruction.as_ir() {
                            Instr::Call { callee, .. } | Instr::CallMulti { callee, .. } => {
                                edges
                                    .entry(caller.name.clone())
                                    .or_default()
                                    .insert(callee.clone());
                                sites.entry(callee.clone()).or_default().push(Site {
                                    caller: caller.name.clone(),
                                    block: block_index,
                                    instruction: instruction_index,
                                });
                            }
                            _ => {}
                        }
                    }
                }
            }
            let eligible = sites.iter().find_map(|(name, sites)| {
                let [site] = sites.as_slice() else {
                    return None;
                };
                let unit = *private_candidates.get(name)?;
                if roots.contains(name) || reaches(name, &site.caller, &edges) {
                    return None;
                }
                let caller_index = self.functions.iter().position(|f| f.name == site.caller)?;
                let callee_index = self.functions.iter().position(|f| &f.name == name)?;
                let caller = &self.functions[caller_index];
                let callee = &self.functions[callee_index];
                preflight(caller, callee, site, unit).then_some((
                    caller_index,
                    callee_index,
                    site.block,
                    site.instruction,
                    unit,
                ))
            });
            let Some((caller_index, callee_index, block, instruction, unit)) = eligible else {
                break;
            };
            let callee = self.functions.remove(callee_index);
            let caller_index = if callee_index < caller_index {
                caller_index - 1
            } else {
                caller_index
            };
            let caller = &mut self.functions[caller_index];
            move_body(caller, callee, block, instruction, unit)?;
            caller.verify()?;
            // Only aliases and empty trampolines are removed. Checked work,
            // host effects and canonical literal validation stay intact.
            caller.coalesce_trivial_values()?;
            caller.simplify_control_flow()?;
            caller.verify()?;
        }
        self.verify()
    }
}

fn reaches(start: &str, target: &str, edges: &BTreeMap<String, BTreeSet<String>>) -> bool {
    let mut pending = vec![start];
    let mut visited = BTreeSet::new();
    while let Some(name) = pending.pop() {
        if name == target {
            return true;
        }
        if visited.insert(name)
            && let Some(callees) = edges.get(name)
        {
            pending.extend(callees.iter().map(String::as_str));
        }
    }
    false
}

fn instruction_count(function: &Function) -> usize {
    function
        .blocks
        .iter()
        .map(|block| block.instructions.len())
        .sum()
}

fn all_values(function: &Function) -> BTreeSet<Value> {
    let mut values = BTreeSet::new();
    for block in &function.blocks {
        for phi in &block.phis {
            values.insert(phi.destination);
            values.extend(phi.inputs.iter().map(|input| input.value));
        }
        for instruction in &block.instructions {
            visit_instr_defs(instruction.as_ir(), |temp| {
                values.insert(Value::decode(temp));
            });
            visit_instr_uses(instruction.as_ir(), |temp| {
                values.insert(Value::decode(temp));
            });
        }
        visit_terminator_uses(block.terminator.as_ir(), |temp| {
            values.insert(Value::decode(temp));
        });
    }
    values
}

fn preflight(caller: &Function, callee: &Function, site: &Site, unit: bool) -> bool {
    let Instr::Call { args, .. } = caller.blocks[site.block].instructions[site.instruction].as_ir()
    else {
        return false;
    };
    if args.len() != callee.params.len() {
        return false;
    }
    let parameters = callee
        .params
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if parameters.len() != callee.params.len() {
        return false;
    }
    let mut returns = 0;
    for block in &callee.blocks {
        for instruction in &block.instructions {
            if let Instr::LoadVar { name, .. } = instruction.as_ir()
                && !parameters.contains(name.as_str())
            {
                return false;
            }
        }
        match block.terminator.as_ir() {
            Terminator::Return(Some(_)) => returns += 1,
            Terminator::Return(None) if unit => returns += 1,
            Terminator::Jump(_) | Terminator::Branch { .. } => {}
            _ => return false,
        }
    }
    if returns == 0 {
        return false;
    }
    let Some(blocks) = caller
        .blocks
        .len()
        .checked_add(callee.blocks.len())
        .and_then(|n| n.checked_add(1))
    else {
        return false;
    };
    let Some(instructions) = instruction_count(caller)
        .checked_add(instruction_count(callee))
        .and_then(|n| n.checked_add(returns))
    else {
        return false;
    };
    // Every distinct Phi edge can require at most one block at de-SSA.
    // Conservatively reserve all original Phi edges, even noncritical ones;
    // moving the sole call adds no branching return-to-continuation edge.
    let phi_edges = |function: &Function| {
        function
            .blocks
            .iter()
            .flat_map(|block| block.phis.iter())
            .flat_map(|phi| {
                phi.inputs
                    .iter()
                    .map(|input| (input.predecessor, phi.destination))
            })
            .count()
    };
    let Some(blocks_with_splits) = blocks
        .checked_add(phi_edges(caller))
        .and_then(|n| n.checked_add(phi_edges(callee)))
    else {
        return false;
    };
    if blocks_with_splits > MAX_SSA_BLOCKS_PER_FUNCTION
        || instructions > MAX_SSA_INSTRUCTIONS_PER_FUNCTION
    {
        return false;
    }
    let Some(next_label) = caller
        .blocks
        .iter()
        .map(|block| block.label.0)
        .max()
        .unwrap_or(0)
        .checked_add(1)
    else {
        return false;
    };
    if next_label
        .checked_add(callee.blocks.len())
        .and_then(|n| n.checked_add(1))
        .and_then(|n| n.checked_add(phi_edges(caller)))
        .and_then(|n| n.checked_add(phi_edges(callee)))
        .is_none()
    {
        return false;
    }
    let Some(next_value) = all_values(caller)
        .last()
        .map(|v| v.0)
        .unwrap_or(0)
        .checked_add(1)
    else {
        return false;
    };
    next_value
        .checked_add(all_values(callee).len())
        .and_then(|n| n.checked_add(returns))
        .is_some()
}

fn move_body(
    caller: &mut Function,
    mut callee: Function,
    block_index: usize,
    instruction_index: usize,
    unit: bool,
) -> Result<(), String> {
    let mut next_label = caller
        .blocks
        .iter()
        .map(|block| block.label.0)
        .max()
        .unwrap_or(0)
        + 1;
    let continuation_label = Label(next_label);
    next_label += 1;
    let labels = callee
        .blocks
        .iter()
        .map(|block| {
            let fresh = Label(next_label);
            next_label += 1;
            (block.label.0, fresh)
        })
        .collect::<BTreeMap<_, _>>();
    let mut next_value = all_values(caller).last().map(|value| value.0).unwrap_or(0) + 1;
    let values = all_values(&callee)
        .into_iter()
        .map(|value| {
            let fresh = Temp(next_value);
            next_value += 1;
            (value, fresh)
        })
        .collect::<BTreeMap<_, _>>();
    let source = caller.blocks[block_index].label;
    let after = caller.blocks[block_index]
        .instructions
        .split_off(instruction_index + 1);
    let call = caller.blocks[block_index]
        .instructions
        .pop()
        .expect("preflight call")
        .into_ir();
    let Instr::Call { args, dest, .. } = call else {
        unreachable!("preflight scalar call");
    };
    let argument_values = callee
        .params
        .iter()
        .zip(args)
        .map(|(name, value)| (name.as_str(), value))
        .collect::<BTreeMap<_, _>>();
    let continuation_terminator = std::mem::replace(
        &mut caller.blocks[block_index].terminator,
        ValueTerminator::new(Terminator::Jump(labels[&callee.entry.0])),
    );
    // The original successor edges now leave the continuation. This includes
    // caller-loop back edges whose target is the split prefix itself.
    for block in &mut caller.blocks {
        for phi in &mut block.phis {
            for input in &mut phi.inputs {
                if input.predecessor == source {
                    input.predecessor = continuation_label;
                }
            }
            phi.inputs.sort_by_key(|input| input.predecessor.0);
        }
    }
    let mut inputs = Vec::new();
    for block in &mut callee.blocks {
        block.label = labels[&block.label.0];
        for phi in &mut block.phis {
            phi.destination = Value::decode(values[&phi.destination]);
            // This is only the local Phi identity; actual uses refer to the
            // separately mapped SSA destination.
            phi.variable = phi.destination.encoded();
            for input in &mut phi.inputs {
                input.predecessor = labels[&input.predecessor.0];
                input.value = Value::decode(values[&input.value]);
            }
            phi.inputs.sort_by_key(|input| input.predecessor.0);
        }
        for instruction in &mut block.instructions {
            if let Instr::LoadVar { dest, name } = instruction.as_ir() {
                *instruction.as_ir_mut() = Instr::Copy {
                    dest: values[&Value::decode(*dest)],
                    src: argument_values[name.as_str()],
                };
            } else {
                rewrite_instruction_values(instruction.as_ir_mut(), &values)?;
            }
        }
        rewrite_terminator_values(block.terminator.as_ir_mut(), &values)?;
        match block.terminator.as_ir_mut() {
            Terminator::Jump(target) => *target = labels[&target.0],
            Terminator::Branch {
                then_bb, else_bb, ..
            } => {
                *then_bb = labels[&then_bb.0];
                *else_bb = labels[&else_bb.0];
            }
            Terminator::Return(result) => {
                if dest.is_some() {
                    let value = if result.is_none() && unit {
                        let value = Temp(next_value);
                        next_value += 1;
                        block.instructions.push(ValueInstruction::new(Instr::Const {
                            dest: value,
                            value: 0,
                        }));
                        value
                    } else {
                        result.expect("preflight value return")
                    };
                    inputs.push(PhiInput {
                        predecessor: block.label,
                        value: Value::decode(value),
                    });
                }
                block.terminator = ValueTerminator::new(Terminator::Jump(continuation_label));
            }
            Terminator::Return2(_, _) | Terminator::ReturnN(_) => {
                unreachable!("preflight scalar return")
            }
        }
    }
    inputs.sort_by_key(|input| input.predecessor.0);
    let phis = dest
        .map(|destination| Phi {
            variable: destination,
            destination: Value::decode(destination),
            inputs,
        })
        .into_iter()
        .collect();
    let continuation = BasicBlock {
        label: continuation_label,
        phis,
        instructions: after,
        terminator: continuation_terminator,
    };
    callee.blocks.push(continuation);
    caller
        .blocks
        .splice(block_index + 1..block_index + 1, callee.blocks);
    Ok(())
}

#[cfg(test)]
mod tests;
