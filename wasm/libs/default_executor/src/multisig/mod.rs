use super::*;

mod account;
mod transaction;

impl VisitExecute for MultisigInstructionBox {
    fn visit(&self, executor: &mut Executor) {
        match self {
            MultisigInstructionBox::Register(instruction) => instruction.visit(executor),
            MultisigInstructionBox::Propose(instruction) => instruction.visit(executor),
            MultisigInstructionBox::Approve(instruction) => instruction.visit(executor),
        }
    }

    fn execute(
        self,
        executor: &mut Executor,
        init_authority: &AccountId,
    ) -> Result<(), ValidationFail> {
        match self {
            MultisigInstructionBox::Register(instruction) => {
                instruction.execute(executor, init_authority)
            }
            MultisigInstructionBox::Propose(instruction) => {
                instruction.execute(executor, init_authority)
            }
            MultisigInstructionBox::Approve(instruction) => {
                instruction.execute(executor, init_authority)
            }
        }
    }
}

pub(super) use iroha_multisig_data_model::*;
