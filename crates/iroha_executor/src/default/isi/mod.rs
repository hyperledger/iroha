use iroha_executor_data_model::isi::multisig::MultisigInstructionBox;

use super::*;
use crate::prelude::{Execute, Vec, Visit};

pub fn visit_custom_instruction<V: Execute + Visit + ?Sized>(
    executor: &mut V,
    instruction: &CustomInstruction,
) {
    if let Ok(instruction) = MultisigInstructionBox::try_from(instruction.payload()) {
        return instruction.visit_execute(executor);
    };

    deny!(executor, "unexpected custom instruction");
}

trait VisitExecute: crate::data_model::isi::Instruction {
    fn visit_execute<V: Execute + Visit + ?Sized>(self, executor: &mut V) {
        let init_authority = executor.context().authority.clone();
        self.visit(executor);
        if executor.verdict().is_ok() {
            if let Err(err) = self.execute(executor) {
                executor.deny(err);
            }
        }
        executor.context_mut().authority = init_authority;
    }

    fn visit<V: Execute + Visit + ?Sized>(&self, _executor: &mut V) {
        unimplemented!("should be overridden unless `Self::visit_execute` is overridden")
    }

    fn execute<V: Execute + Visit + ?Sized>(self, _executor: &mut V) -> Result<(), ValidationFail> {
        unimplemented!("should be overridden unless `Self::visit_execute` is overridden")
    }
}

macro_rules! visit_seq {
    ($executor:ident.$visit:ident($instruction:expr)) => {
        $executor.$visit($instruction);
        if $executor.verdict().is_err() {
            return $executor.verdict().clone();
        }
    };
}

mod multisig;
