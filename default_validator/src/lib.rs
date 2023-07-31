//! Iroha default validator.

#![no_std]
#![allow(missing_docs, clippy::missing_errors_doc)]

#[cfg(not(test))]
extern crate panic_halt;

use iroha_validator::prelude::*;

#[entrypoint]
pub fn migrate() -> MigrationResult {
    DefaultValidator::migrate()
}

#[entrypoint]
pub fn validate_transaction(
    authority: AccountId,
    transaction: VersionedSignedTransaction,
) -> Result {
    let mut validator = DefaultValidator::new();

    validator.visit_transaction(&authority, &transaction);

    validator.verdict
}

#[entrypoint]
pub fn validate_instruction(authority: AccountId, instruction: InstructionBox) -> Result {
    let mut validator = DefaultValidator::new();

    validator.visit_instruction(&authority, &instruction);

    validator.verdict
}

#[entrypoint]
pub fn validate_query(authority: AccountId, query: QueryBox) -> Result {
    let mut validator = DefaultValidator::new();

    validator.visit_query(&authority, &query);

    validator.verdict
}
