//! This module contains permissions related Iroha functionality.

use crate::prelude::*;
use iroha_data_model::prelude::*;
use std::iter;

/// Reason for prohibiting the execution of the particular instruction.
pub type DenialReason = String;

/// Implement this to provide custom permission checks for the Iroha based blockchain.
pub trait PermissionsValidator {
    /// Checks if the `authority` is allowed to perform `instruction` given the current state of `wsv`.
    fn check_instruction(
        &self,
        authority: AccountId,
        instruction: Instruction,
        wsv: &WorldStateView,
    ) -> Result<(), DenialReason>;
}

/// Box with `PermissionChecker`
pub type PermissionsValidatorBox = Box<dyn PermissionsValidator + Send + Sync>;

/// Wraps validator to check nested permissions.
/// Pay attention to wrap only validators that do not check nested intructions by themselves.
#[allow(missing_debug_implementations)]
pub struct RecursivePermissionsValidator {
    validator: PermissionsValidatorBox,
}

impl RecursivePermissionsValidator {
    /// Wraps `validator` to check nested permissions.
    pub fn new(validator: PermissionsValidatorBox) -> Self {
        RecursivePermissionsValidator { validator }
    }
}

impl PermissionsValidator for RecursivePermissionsValidator {
    fn check_instruction(
        &self,
        authority: AccountId,
        instruction: Instruction,
        wsv: &WorldStateView,
    ) -> Result<(), DenialReason> {
        match instruction {
            Instruction::Register(_)
            | Instruction::Unregister(_)
            | Instruction::Mint(_)
            | Instruction::Burn(_)
            | Instruction::Transfer(_)
            | Instruction::Fail(_) => self
                .validator
                .check_instruction(authority, instruction, wsv),
            Instruction::If(if_box) => self
                .check_instruction(authority.clone(), if_box.clone().then, wsv)
                .and_then(|_| match if_box.otherwise {
                    Some(instruction) => {
                        self.check_instruction(authority.clone(), instruction, wsv)
                    }
                    None => Ok(()),
                }),
            Instruction::Pair(pair_box) => self
                .check_instruction(authority.clone(), pair_box.left_instruction, wsv)
                .and(self.check_instruction(authority, pair_box.right_instruction, wsv)),
            Instruction::Sequence(sequence_box) => sequence_box
                .instructions
                .into_iter()
                .try_for_each(|instruction| {
                    self.check_instruction(authority.clone(), instruction, wsv)
                }),
        }
    }
}

impl From<RecursivePermissionsValidator> for PermissionsValidatorBox {
    fn from(validator: RecursivePermissionsValidator) -> Self {
        Box::new(validator)
    }
}

/// A container for multiple permissions validators. It will check all their conditions.
#[allow(missing_debug_implementations)]
pub struct CombinedPermissionsValidator {
    validators: Vec<PermissionsValidatorBox>,
}

impl PermissionsValidator for CombinedPermissionsValidator {
    fn check_instruction(
        &self,
        authority: AccountId,
        instruction: Instruction,
        wsv: &WorldStateView,
    ) -> Result<(), DenialReason> {
        for validator in &self.validators {
            validator.check_instruction(authority.clone(), instruction.clone(), wsv)?
        }
        Ok(())
    }
}

impl From<CombinedPermissionsValidator> for PermissionsValidatorBox {
    fn from(validator: CombinedPermissionsValidator) -> Self {
        Box::new(validator)
    }
}

/// Builder to combine multiple validation checks into one.
#[allow(missing_debug_implementations)]
#[derive(Default)]
pub struct PermissionsValidatorBuilder {
    validators: Vec<PermissionsValidatorBox>,
}

impl PermissionsValidatorBuilder {
    /// Returns new `PermissionValidatorBuilder`, with empty set of validator checks.
    pub fn new() -> Self {
        PermissionsValidatorBuilder {
            validators: Vec::new(),
        }
    }

    /// Adds a validator to the list.
    pub fn with_validator(self, validator: PermissionsValidatorBox) -> Self {
        PermissionsValidatorBuilder {
            validators: self
                .validators
                .into_iter()
                .chain(iter::once(validator))
                .collect(),
        }
    }

    /// Adds a validator to the list and wraps it with `RecursivePermissionValidator` to check nested permissions.
    pub fn with_recursive_validator(self, validator: PermissionsValidatorBox) -> Self {
        self.with_validator(RecursivePermissionsValidator::new(validator).into())
    }

    /// Returns a `CombinedPermissionsValidator` that will check all the checks of previously supplied validators.
    pub fn build(self) -> PermissionsValidatorBox {
        CombinedPermissionsValidator {
            validators: self.validators,
        }
        .into()
    }
}

/// Allows all ISI to be executed for all possible values. Mostly for tests and simple cases.
#[derive(Debug, Clone, Copy)]
pub struct AllowAll;

impl PermissionsValidator for AllowAll {
    fn check_instruction(
        &self,
        _authority: AccountId,
        _instruction: Instruction,
        _wsv: &WorldStateView,
    ) -> Result<(), DenialReason> {
        Ok(())
    }
}

impl From<AllowAll> for PermissionsValidatorBox {
    fn from(_: AllowAll) -> Self {
        Box::new(AllowAll)
    }
}

pub mod prelude {
    //! Exports common types for permissions.

    pub use super::{AllowAll, DenialReason, PermissionsValidatorBox};
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_data_model::isi::*;

    struct DenyBurn;

    impl PermissionsValidator for DenyBurn {
        fn check_instruction(
            &self,
            _authority: AccountId,
            instruction: Instruction,
            _wsv: &WorldStateView,
        ) -> Result<(), super::DenialReason> {
            match instruction {
                Instruction::Burn(_) => Err("Denying sequence isi.".to_string()),
                _ => Ok(()),
            }
        }
    }

    struct DenyAlice;

    impl PermissionsValidator for DenyAlice {
        fn check_instruction(
            &self,
            authority: AccountId,
            _instruction: Instruction,
            _wsv: &WorldStateView,
        ) -> Result<(), super::DenialReason> {
            if authority.name == "alice" {
                Err("Alice account is denied.".to_string())
            } else {
                Ok(())
            }
        }
    }

    #[test]
    pub fn multiple_validators_combined() {
        let permissions_validator = PermissionsValidatorBuilder::new()
            .with_validator(Box::new(DenyBurn))
            .with_validator(Box::new(DenyAlice))
            .build();
        let instruction_burn: Instruction = BurnBox::new(
            Value::U32(10),
            IdBox::AssetId(AssetId::from_names("xor", "test", "alice", "test")),
        )
        .into();
        let instruction_fail = Instruction::Fail(Box::new(Fail {
            message: "fail message".to_string(),
        }));
        let account_bob = <Account as Identifiable>::Id::new("bob", "test");
        let account_alice = <Account as Identifiable>::Id::new("alice", "test");
        let wsv = WorldStateView::new(World::new());
        assert!(permissions_validator
            .check_instruction(account_bob.clone(), instruction_burn.clone(), &wsv)
            .is_err());
        assert!(permissions_validator
            .check_instruction(account_alice.clone(), instruction_fail.clone(), &wsv)
            .is_err());
        assert!(permissions_validator
            .check_instruction(account_alice, instruction_burn, &wsv)
            .is_err());
        assert!(permissions_validator
            .check_instruction(account_bob, instruction_fail, &wsv)
            .is_ok());
    }

    #[test]
    pub fn recursive_validator() {
        let permissions_validator = PermissionsValidatorBuilder::new()
            .with_recursive_validator(Box::new(DenyBurn))
            .build();
        let instruction_burn: Instruction = BurnBox::new(
            Value::U32(10),
            IdBox::AssetId(AssetId::from_names("xor", "test", "alice", "test")),
        )
        .into();
        let instruction_fail = Instruction::Fail(Box::new(Fail {
            message: "fail message".to_string(),
        }));
        let nested_instruction_sequence =
            Instruction::If(If::new(true, instruction_burn.clone()).into());
        let account_alice = <Account as Identifiable>::Id::new("alice", "test");
        let wsv = WorldStateView::new(World::new());
        assert!(permissions_validator
            .check_instruction(account_alice.clone(), instruction_fail, &wsv)
            .is_ok());
        assert!(permissions_validator
            .check_instruction(account_alice.clone(), instruction_burn, &wsv)
            .is_err());
        assert!(permissions_validator
            .check_instruction(account_alice, nested_instruction_sequence, &wsv)
            .is_err());
    }
}
