//! Runtime Validator which allows any [`TransferBox`] instructions by `admin@admin` account.
//! If authority is not `admin@admin` then [`DefaultValidator`] is used as a backup.
#![no_std]

use iroha_validator::{
    data_model::evaluate::{Error, ExpressionEvaluator},
    parse,
    prelude::*,
    DefaultValidator,
};

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

impl ExpressionEvaluator for Validator {
    fn evaluate<E: Evaluate>(&self, expression: &E) -> Result<E::Value, Error> {
        self.0.evaluate(expression)
    }
}

/// Allow operation if authority is `admin@admin` and if not,
/// fallback to [`DefaultValidator::validate()`].
#[entrypoint(params = "[authority, operation]")]
pub fn validate(authority: AccountId, operation: NeedsValidationBox) -> Verdict {
    let mut validator = Validator(DefaultValidator::new());

    match operation {
        NeedsValidationBox::Transaction(transaction) => {
            validator.validate_and_execute_transaction(&authority, transaction)
        }
        NeedsValidationBox::Instruction(instruction) => {
            validator.validate_and_execute_instruction(&authority, &instruction)
        }
        NeedsValidationBox::Query(query) => validator.validate_query(&authority, &query),
    }
}
