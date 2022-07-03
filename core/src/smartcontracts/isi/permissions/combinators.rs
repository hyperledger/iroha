//! Module with combinators for permission validators

use super::*;

/// Wraps validator to check nested permissions.  Pay attention to
/// wrap only validators that do not check nested instructions by
/// themselves.
#[derive(Debug)]
pub struct CheckNested {
    validator: IsInstructionAllowedBoxed,
}

impl CheckNested {
    /// Wraps `validator` to check nested permissions.
    pub fn new(validator: IsInstructionAllowedBoxed) -> Self {
        CheckNested { validator }
    }
}

impl GetValidatorType for CheckNested {
    fn get_validator_type(&self) -> ValidatorType {
        ValidatorType::Instruction
    }
}

impl IsAllowed for CheckNested {
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
                .least_permissive_with(|| match &if_box.otherwise {
                    Some(otherwise) => self.check(authority, otherwise, wsv),
                    None => ValidatorVerdict::Skip,
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
