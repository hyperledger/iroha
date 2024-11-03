use super::*;

mod account;
mod transaction;

impl VisitExecute for MultisigInstructionBox {
    fn visit_execute(self, executor: &mut Executor) {
        match self {
            MultisigInstructionBox::Register(instruction) => instruction.visit_execute(executor),
            MultisigInstructionBox::Propose(instruction) => instruction.visit_execute(executor),
            MultisigInstructionBox::Approve(instruction) => instruction.visit_execute(executor),
        }
    }
}

pub(super) use iroha_multisig_data_model::*;
