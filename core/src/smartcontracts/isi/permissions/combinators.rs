//! Module with combinators for permission validators
// TODO: This module should be removed once common combinators API will be implemented (#2458)

use super::*;

/// Wraps validator to check nested permissions.
///
/// Pay attention to wrap only validators
/// that do not check nested instructions by themselves.
#[derive(Debug, Display)]
#[display(fmt = "`{}` with nested checking", validator)]
pub struct CheckNested<V: IsAllowed<Operation = Instruction>> {
    validator: V,
}

impl<V: IsAllowed<Operation = Instruction>> CheckNested<V> {
    /// Wraps `validator` to check nested permissions.
    pub fn new(validator: V) -> Self {
        CheckNested { validator }
    }
}

impl<V: IsAllowed<Operation = Instruction>> IsAllowed for CheckNested<V> {
    type Operation = Instruction;

    fn check(
        &self,
        authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView,
    ) -> ValidatorVerdict {
        match instruction {
            Instruction::Register(_)
            | Instruction::Unregister(_)
            | Instruction::Mint(_)
            | Instruction::Burn(_)
            | Instruction::SetKeyValue(_)
            | Instruction::RemoveKeyValue(_)
            | Instruction::Transfer(_)
            | Instruction::Grant(_)
            | Instruction::Revoke(_)
            | Instruction::Fail(_)
            | Instruction::ExecuteTrigger(_) => self.validator.check(authority, instruction, wsv),

            Instruction::If(if_box) => self
                .check(authority, &if_box.then, wsv)
                .least_permissive_with(|| {
                    if_box
                        .otherwise
                        .as_ref()
                        .map_or(ValidatorVerdict::Skip, |otherwise| {
                            self.check(authority, otherwise, wsv)
                        })
                }),
            Instruction::Pair(pair_box) => self
                .check(authority, &pair_box.left_instruction, wsv)
                .least_permissive_with(|| self.check(authority, &pair_box.right_instruction, wsv)),
            Instruction::Sequence(sequence_box) => {
                if sequence_box.instructions.is_empty() {
                    ValidatorVerdict::Skip
                } else {
                    let mut verdict = ValidatorVerdict::Allow;
                    for this_instruction in &sequence_box.instructions {
                        verdict = verdict
                            .least_permissive_with(|| self.check(authority, this_instruction, wsv));
                        if let ValidatorVerdict::Deny(_) = &verdict {
                            break;
                        }
                    }
                    verdict
                }
            }
        }
    }
}
