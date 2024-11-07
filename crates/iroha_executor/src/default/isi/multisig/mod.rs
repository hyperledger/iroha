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
const SIGNATORIES: &str = "signatories";
const QUORUM: &str = "quorum";
const TRANSACTION_TTL_MS: &str = "transaction_ttl_ms";
const PROPOSALS: &str = "proposals";
const MULTISIG_SIGNATORY: &str = "MULTISIG_SIGNATORY";

fn instructions_key(hash: &HashOf<Vec<InstructionBox>>) -> Name {
    format!("{PROPOSALS}{DELIMITER}{hash}{DELIMITER}instructions")
        .parse()
        .unwrap()
}

fn proposed_at_ms_key(hash: &HashOf<Vec<InstructionBox>>) -> Name {
    format!("{PROPOSALS}{DELIMITER}{hash}{DELIMITER}proposed_at_ms")
        .parse()
        .unwrap()
}

fn expires_at_ms_key(hash: &HashOf<Vec<InstructionBox>>) -> Name {
    format!("{PROPOSALS}{DELIMITER}{hash}{DELIMITER}expires_at_ms")
        .parse()
        .unwrap()
}

fn approvals_key(hash: &HashOf<Vec<InstructionBox>>) -> Name {
    format!("{PROPOSALS}{DELIMITER}{hash}{DELIMITER}approvals")
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
