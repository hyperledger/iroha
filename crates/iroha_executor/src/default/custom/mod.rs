use iroha_executor_data_model::custom::multisig::MultisigInstructionBox;

use super::*;
use crate::prelude::{Execute, Vec, Visit};

mod multisig;

pub fn visit_custom_instructions<V: Execute + Visit + ?Sized>(
    executor: &mut V,
    instruction: &CustomInstruction,
) {
    if let Ok(instruction) = MultisigInstructionBox::try_from(instruction.payload()) {
        return instruction.visit_execute(executor);
    };

    deny!(executor, "unexpected custom instruction");
}

// TODO #5221 trait VisitExecute: CustomInstruction {
trait VisitExecute: crate::data_model::isi::Instruction {
    fn visit_execute<V: Execute + Visit + ?Sized>(self, executor: &mut V) {
        self.visit(executor);
        if executor.verdict().is_ok() {
            if let Err(err) = self.execute(executor) {
                executor.deny(err);
            }
        }
    }

    fn visit<V: Execute + Visit + ?Sized>(&self, _executor: &mut V) {
        unimplemented!("should be overridden unless `Self::visit_execute` is overridden")
    }

    fn execute<V: Execute + Visit + ?Sized>(self, _executor: &mut V) -> Result<(), ValidationFail> {
        unimplemented!("should be overridden unless `Self::visit_execute` is overridden")
    }
}
