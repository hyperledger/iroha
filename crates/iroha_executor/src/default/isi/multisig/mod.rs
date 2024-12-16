use iroha_executor_data_model::isi::multisig::*;

use super::*;
use crate::smart_contract::{DebugExpectExt as _, DebugUnwrapExt};

mod account;
mod transaction;

impl VisitExecute for MultisigInstructionBox {
    fn visit_execute<V: Execute + Visit + ?Sized>(self, executor: &mut V) {
        match self {
            MultisigInstructionBox::Register(instruction) => instruction.visit_execute(executor),
            MultisigInstructionBox::Propose(instruction) => instruction.visit_execute(executor),
            MultisigInstructionBox::Approve(instruction) => instruction.visit_execute(executor),
        }
    }
}

const DELIMITER: char = '/';
const MULTISIG: &str = "multisig";
const MULTISIG_SIGNATORY: &str = "MULTISIG_SIGNATORY";

fn spec_key() -> Name {
    format!("{MULTISIG}{DELIMITER}spec").parse().unwrap()
}

fn proposal_key(hash: &HashOf<Vec<InstructionBox>>) -> Name {
    format!("{MULTISIG}{DELIMITER}proposals{DELIMITER}{hash}")
        .parse()
        .unwrap()
}

fn multisig_role_for(account: &AccountId) -> RoleId {
    format!(
        "{MULTISIG_SIGNATORY}{DELIMITER}{}{DELIMITER}{}",
        account.domain(),
        account.signatory(),
    )
    .parse()
    .unwrap()
}
