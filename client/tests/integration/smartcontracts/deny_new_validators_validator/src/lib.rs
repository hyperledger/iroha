//! This is a sample validator which forbids every new validator registration

#![no_std]
#![no_main]

extern crate alloc;
#[cfg(not(test))]
extern crate panic_halt;

use alloc::borrow::ToOwned as _;

/// Forbid every new validator registration
#[iroha_validator::entrypoint]
fn validate(instruction: Instruction) -> Verdict {
    if let Instruction::Register(register) = instruction {
        if let RegistrableBox::Validator(_) = register
            .object()
            .evaluate()
            .dbg_expect("Failed to evaluate `Register` expression as `RegistrableBox` value")
        {
            return Verdict::Deny("New validators are not allowed".to_owned());
        }
    }

    Verdict::Pass
}
