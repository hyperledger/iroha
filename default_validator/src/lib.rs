//! Iroha default validator.
#![no_std]

#[cfg(not(test))]
extern crate panic_halt;

use iroha_validator::prelude::*;

/// Entrypoint for smart contract
#[entrypoint(params = "[authority, operation]")]
pub fn validate(authority: AccountId, operation: NeedsValidationBox) -> Verdict {
    let mut validator = DefaultValidator::new();

    match operation {
        // NOTE: Invoked from Iroha
        NeedsValidationBox::Transaction(transaction) => {
            validator.validate_and_execute_transaction(&authority, transaction)
        }

        // NOTE: Invoked only from another Wasm
        NeedsValidationBox::Instruction(instruction) => {
            validator.validate_and_execute_instruction(&authority, &instruction)
        }

        // NOTE: Invoked only from another Wasm
        NeedsValidationBox::Query(query) => validator.validate_query(&authority, &query),
    }
}
