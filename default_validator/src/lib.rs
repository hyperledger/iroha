//! Iroha default validator.
#![no_std]

#[cfg(not(test))]
extern crate panic_halt;

use iroha_validator::prelude::*;

/// Migration entrypoint.
#[entrypoint]
pub fn migrate() -> MigrationResult {
    DefaultValidator::migrate()
}

/// Validation entrypoint.
#[entrypoint(params = "[authority, operation]")]
pub fn validate(authority: AccountId, operation: NeedsValidationBox) -> Result {
    let mut validator = DefaultValidator::new();

    match operation {
        // NOTE: Invoked from Iroha
        NeedsValidationBox::Transaction(transaction) => {
            validator.visit_transaction(&authority, &transaction)
        }

        // NOTE: Invoked only from another Wasm
        NeedsValidationBox::Instruction(instruction) => {
            validator.visit_instruction(&authority, &instruction);
        }

        // NOTE: Invoked only from another Wasm
        NeedsValidationBox::Query(query) => {
            validator.visit_query(&authority, &query);
        }
    }

    validator.verdict
}
