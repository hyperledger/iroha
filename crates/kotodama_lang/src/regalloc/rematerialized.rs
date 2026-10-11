//! Numeric literals whose complete use graph reloads the canonical literal table.
//!
//! This is register-home selection, not dead-code elimination. Every DataRef
//! remains in IR and in codegen's literal validation/serialization inventory.

use std::collections::{HashMap, HashSet};

use super::{Function, Instr, Temp, Terminator, visit_instr_defs, visit_instr_uses};
use crate::ir::{DataRefKind, WideNumericKind};

/// Find single-definition numeric literals which never consume a physical home.
/// Unrecognized use positions keep their original allocation. In particular,
/// virtual tuples and scalar control operands are not inferred to be pointers.
pub(super) fn numeric_literal_homes(function: &Function) -> HashSet<Temp> {
    #[cfg(test)]
    if RETAIN_LITERAL_HOMES.get() {
        return HashSet::new();
    }
    let mut definitions = HashMap::<Temp, usize>::new();
    let mut candidates = HashMap::new();
    for instruction in function.blocks.iter().flat_map(|block| &block.instrs) {
        visit_instr_defs(instruction, |temp| {
            *definitions.entry(temp).or_default() += 1;
        });
        if let Instr::DataRef { dest, kind, .. } = instruction
            && matches!(
                kind,
                DataRefKind::Int | DataRefKind::Decimal | DataRefKind::Quantity
            )
        {
            candidates.insert(*dest, *kind);
        }
    }
    candidates.retain(|temp, _| definitions.get(temp) == Some(&1));
    for block in &function.blocks {
        for instruction in &block.instrs {
            visit_instr_uses(instruction, |temp| {
                if let Some(kind) = candidates.get(&temp).copied()
                    && !rematerializes_use(instruction, temp, kind)
                {
                    candidates.remove(&temp);
                }
            });
        }
        super::visit_terminator_uses(&block.terminator, |temp| {
            // Every result-table slot checks the literal map before src_reg.
            if !matches!(
                block.terminator,
                Terminator::Return(_) | Terminator::Return2(..) | Terminator::ReturnN(_)
            ) {
                candidates.remove(&temp);
            }
        });
    }
    candidates.into_keys().collect()
}

fn is_kind(literal: DataRefKind, numeric: WideNumericKind) -> bool {
    matches!(
        (literal, numeric),
        (DataRefKind::Int, WideNumericKind::Int)
            | (DataRefKind::Decimal, WideNumericKind::Decimal)
            | (DataRefKind::Quantity, WideNumericKind::Quantity)
    )
}

/// Keep this whitelist coupled to the corresponding codegen literal-map checks.
/// A temp appearing in two positions is eligible only when both positions are
/// rematerialized; a rounded-operation mode may alias its dividend in malformed
/// IR, so checking only the first matching operand would be unsound.
fn rematerializes_use(instruction: &Instr, temp: Temp, kind: DataRefKind) -> bool {
    match instruction {
        // These table/copy emitters check both dataref_kind_map and string_map
        // before consulting the allocation, for every input word.
        Instr::Call { .. }
        | Instr::CallMulti { .. }
        | Instr::Copy { .. }
        | Instr::StateValueEncode { .. } => true,
        Instr::NumericNeg { kind: numeric, .. } | Instr::NumericCompare { kind: numeric, .. } => {
            is_kind(kind, *numeric)
        }
        Instr::NumericBinary {
            left,
            right,
            left_kind,
            right_kind,
            ..
        } => {
            (*left != temp || is_kind(kind, *left_kind))
                && (*right != temp || is_kind(kind, *right_kind))
        }
        Instr::NumericConvert { source, .. } | Instr::NumericTryConvert { source, .. } => {
            is_kind(kind, *source)
        }
        Instr::IntToI64 { .. }
        | Instr::IntToU64 { .. }
        | Instr::WrappingBinary { .. }
        | Instr::WrappingNeg { .. } => kind == DataRefKind::Int,
        // The fused and non-fused emitters rematerialize all pointer operands.
        // The rounding mode remains a scalar even when the fused helper would
        // happen to accept a literal there; do not infer a pointer ABI for it.
        Instr::NumericRound { mode, .. } => *mode != temp,
        Instr::DecimalToInt { mode, .. } => kind == DataRefKind::Decimal && *mode != Some(temp),
        _ => false,
    }
}

#[cfg(test)]
std::thread_local! {
    static RETAIN_LITERAL_HOMES: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Run a same-compiler baseline without omitting literal homes. This test-only
/// scope never changes production compiler options, source validation or IR.
#[cfg(test)]
pub(crate) fn with_literal_homes<R>(action: impl FnOnce() -> R) -> R {
    struct Restore(bool);
    impl Drop for Restore {
        fn drop(&mut self) {
            RETAIN_LITERAL_HOMES.set(self.0);
        }
    }
    let _restore = Restore(RETAIN_LITERAL_HOMES.replace(true));
    action()
}

#[cfg(test)]
mod tests;
