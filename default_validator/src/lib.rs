//! Iroha default validator.

#![no_std]
#![allow(missing_docs, clippy::missing_errors_doc)]

#[cfg(not(test))]
extern crate panic_halt;

use iroha_validator::prelude::*;

#[entrypoint]
pub fn migrate(block_height: u64) -> MigrationResult {
    DefaultValidator::migrate(block_height)
}

#[entrypoint]
pub fn validate_transaction(
    authority: AccountId,
    transaction: VersionedSignedTransaction,
    block_height: u64,
) -> Result {
    let mut validator = DefaultValidator::new(block_height);

    validator.visit_transaction(&authority, &transaction);

    validator.verdict
}

#[entrypoint]
pub fn validate_instruction(
    authority: AccountId,
    instruction: InstructionBox,
    block_height: u64,
) -> Result {
    let mut validator = DefaultValidator::new(block_height);

    validator.visit_instruction(&authority, &instruction);

    validator.verdict
}

#[entrypoint]
pub fn validate_query(authority: AccountId, query: QueryBox, block_height: u64) -> Result {
    let mut validator = DefaultValidator::new(block_height);

    validator.visit_query(&authority, &query);

    validator.verdict
}
