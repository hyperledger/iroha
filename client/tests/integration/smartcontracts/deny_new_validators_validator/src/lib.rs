//! This is a sample validator which forbids any new validator registration

#![no_std]
#![no_main]

extern crate alloc;

use alloc::borrow::ToOwned as _;

use iroha_wasm::data_model::{permission::validator::Verdict, prelude::*};

#[iroha_wasm::validator_entrypoint]
pub fn validate(instruction: Instruction) -> Verdict {
    if let Instruction::Register(register) = instruction {
        if let RegistrableBox::Validator(_) = register.object.evaluate() {
            return Verdict::Deny("New validators are not allowed".to_owned());
        }
    }

    Verdict::Pass
}
