//! Runtime Validator which allows any [`TransferBox`] instructions by `admin@admin` account.
//! If authority is not `admin@admin` then [`DefaultValidator`] is used as a backup.
#![no_std]

use iroha_validator::{parse, prelude::*, DefaultValidator};

#[cfg(not(test))]
extern crate panic_halt;

struct Validator(DefaultValidator);

impl Validate for Validator {
    fn validate_transfer(&mut self, authority: &AccountId, isi: &TransferBox) -> Verdict {
        if parse!("admin@admin" as <Account as Identifiable>::Id) == *authority {
            pass!()
        }

        self.0.validate_transfer(authority, isi)
    }
}

/// Allow operation if authority is `admin@admin` and if not,
/// fallback to [`DefaultValidator::validate()`].
#[entrypoint(params = "[authority, operation]")]
pub fn validate(authority: AccountId, operation: NeedsValidationBox) -> Verdict {
    let mut validator = Validator(DefaultValidator);

    match operation {
        // NOTE: Invoked from Iroha
        NeedsValidationBox::Transaction(transaction) => {
            validator.validate_transaction(&authority, transaction)
        }

        // NOTE: Invoked only from another Wasm
        NeedsValidationBox::Instruction(instruction) => {
            let verdict = validator.validate_instruction(&authority, &instruction);

            if verdict.is_ok() {
                instruction.execute();
            }

            verdict
        }

        // NOTE: Invoked only from another Wasm
        NeedsValidationBox::Query(query) => validator.validate_query(&authority, &query),
    }
}
