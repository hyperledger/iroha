//! Module with combinators for permission validators
// TODO: This module should be removed once common combinators API will be implemented (#2458)

use super::*;

/// Trait for joining validators with `or` method, auto-implemented
/// for all types implementing [`IsAllowed`]
pub trait ValidatorApplyOr<O: NeedsPermission>: IsAllowed<Operation = O> + Sized {
    /// Combines two validators into [`Or`]
    ///
    /// Validators verdicts will be combined like using [`ValidatorVerdict::most_permissive_with()`]
    fn or<V: IsAllowed<Operation = O> + Sized>(self, another: V) -> Or<O, Self, V>;
}

impl<O: NeedsPermission, F: IsAllowed<Operation = O>> ValidatorApplyOr<O> for F {
    fn or<V: IsAllowed<Operation = O>>(self, another: V) -> Or<O, Self, V> {
        Or::new(self, another)
    }
}

/// *Or*-combinator for two validators
///
/// `check` succeeds if either `first` or `second` validator succeeds
#[derive(Debug, Clone, Serialize, Display)]
#[display(fmt = "`{}` || `{}`", first, second)]
pub struct Or<O: NeedsPermission, F: IsAllowed<Operation = O>, S: IsAllowed<Operation = O>> {
    first: F,
    second: S,
    #[serde(skip_serializing, default)]
    _phantom_operation: PhantomData<O>,
}

impl<O: NeedsPermission, F: IsAllowed<Operation = O>, S: IsAllowed<Operation = O>> Or<O, F, S> {
    /// Constructs new [`Or`]
    pub fn new(first: F, second: S) -> Self {
        Or {
            first,
            second,
            _phantom_operation: PhantomData,
        }
    }
}

impl<O, F, S> IsAllowed for Or<O, F, S>
where
    O: NeedsPermission,
    F: IsAllowed<Operation = O> + Display,
    S: IsAllowed<Operation = O> + Display,
{
    type Operation = O;

    fn check(
        &self,
        authority: &AccountId,
        operation: &Self::Operation,
        wsv: &WorldStateView,
    ) -> ValidatorVerdict {
        let first_verdict = self.first.check(authority, operation, wsv);
        if first_verdict == ValidatorVerdict::Allow {
            return first_verdict;
        }

        let second_verdict = self.second.check(authority, operation, wsv);
        if second_verdict == ValidatorVerdict::Allow {
            return second_verdict;
        }

        if let (ValidatorVerdict::Deny(first_reason), ValidatorVerdict::Deny(second_reason)) =
            (&first_verdict, &second_verdict)
        {
            return ValidatorVerdict::Deny(format!(
                "Neither the first validator `{}` succeeded: {first_reason}, \
                 nor the second validator `{}`: {second_reason}",
                self.first, self.second
            ));
        }

        first_verdict.most_permissive(second_verdict)
    }
}

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
