//! This is a sample validator which forbids every new validator registration

#![no_std]
#![no_main]

extern crate alloc;

use alloc::borrow::ToOwned as _;

use iroha_wasm::{validator::prelude::*, DebugExpectExt as _};

/// Forbid every new validator registration
#[entrypoint]
pub fn validate(instruction: Instruction) -> Verdict {
    if let Instruction::Register(register) = instruction {
        if let RegistrableBox::Validator(_) = register
            .object
            .evaluate_on_host()
            .dbg_expect("Failed to evaluate `Register` expression as `RegistrableBox` value")
        {
            return Verdict::Deny("New validators are not allowed".to_owned());
        }
    }

    Verdict::Pass
}
