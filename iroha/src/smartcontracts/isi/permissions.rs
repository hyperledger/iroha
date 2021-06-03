#![allow(clippy::module_name_repetitions)]

//! This module contains permissions related Iroha functionality.

use std::iter;

use iroha_data_model::prelude::*;
use iroha_error::Result;

#[cfg(feature = "roles")]
use super::Evaluate;
use crate::prelude::*;

/// Reason for prohibiting the execution of the particular instruction.
pub type DenialReason = String;

/// Implement this to provide custom permission checks for the Iroha based blockchain.
pub trait PermissionsValidator {
    /// Checks if the `authority` is allowed to perform `instruction` given the current state of `wsv`.
    ///
    /// # Errors
    /// In the case when the execution of `instruction` under given `authority` with the current state of `wsv`
    /// is unallowed.
    fn check_instruction(
        &self,
        authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView,
    ) -> Result<(), DenialReason>;
}

/// Box with `PermissionChecker`
pub type PermissionsValidatorBox = Box<dyn PermissionsValidator + Send + Sync>;

/// Trait for joining validators with `or` method, autoimplemented for all types which convert to `PermissionsValidatorBox`.
pub trait ValidatorApplyOr {
    /// Combines two validators into [`OrPermissionsValidator`].
    fn or(self, another: impl Into<PermissionsValidatorBox>) -> OrPermissionsValidator;
}

impl<V: Into<PermissionsValidatorBox>> ValidatorApplyOr for V {
    fn or(self, another: impl Into<PermissionsValidatorBox>) -> OrPermissionsValidator {
        OrPermissionsValidator {
            first: self.into(),
            second: another.into(),
        }
    }
}

/// `check_instruction` will succeed if either `first` or `second` validator succeeds.
#[allow(missing_debug_implementations)]
pub struct OrPermissionsValidator {
    first: PermissionsValidatorBox,
    second: PermissionsValidatorBox,
}

impl PermissionsValidator for OrPermissionsValidator {
    fn check_instruction(
        &self,
        authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView,
    ) -> Result<(), DenialReason> {
        self.first
            .check_instruction(authority, instruction, wsv)
            .or_else(|first_error| {
                self.second
                    .check_instruction(authority, instruction, wsv)
                    .map_err(|second_error| {
                        format!(
                            "Failed to pass first check with {} and second check with {}.",
                            first_error, second_error
                        )
                    })
            })
    }
}

impl From<OrPermissionsValidator> for PermissionsValidatorBox {
    fn from(validator: OrPermissionsValidator) -> Self {
        Box::new(validator)
    }
}

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
        authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView,
    ) -> Result<(), DenialReason> {
        match instruction {
            Instruction::Register(_)
            | Instruction::Unregister(_)
            | Instruction::Mint(_)
            | Instruction::Burn(_)
            | Instruction::SetKeyValue(_)
            | Instruction::RemoveKeyValue(_)
            | Instruction::Transfer(_)
            | Instruction::Grant(_)
            | Instruction::Fail(_) => self
                .validator
                .check_instruction(authority, instruction, wsv),
            Instruction::If(if_box) => self
                .check_instruction(authority, &if_box.then, wsv)
                .and_then(|_| match &if_box.otherwise {
                    Some(instruction) => self.check_instruction(authority, instruction, wsv),
                    None => Ok(()),
                }),
            Instruction::Pair(pair_box) => self
                .check_instruction(authority, &pair_box.left_instruction, wsv)
                .and(self.check_instruction(authority, &pair_box.right_instruction, wsv)),
            Instruction::Sequence(sequence_box) => sequence_box
                .instructions
                .iter()
                .try_for_each(|instruction| self.check_instruction(authority, instruction, wsv)),
        }
    }
}

impl From<RecursivePermissionsValidator> for PermissionsValidatorBox {
    fn from(validator: RecursivePermissionsValidator) -> Self {
        Box::new(validator)
    }
}

/// A container for multiple permissions validators. It will succeed if all validators succeed.
#[allow(missing_debug_implementations)]
pub struct AllShouldSucceed {
    validators: Vec<PermissionsValidatorBox>,
}

impl PermissionsValidator for AllShouldSucceed {
    fn check_instruction(
        &self,
        authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView,
    ) -> Result<(), DenialReason> {
        for validator in &self.validators {
            validator.check_instruction(authority, instruction, wsv)?
        }
        Ok(())
    }
}

impl From<AllShouldSucceed> for PermissionsValidatorBox {
    fn from(validator: AllShouldSucceed) -> Self {
        Box::new(validator)
    }
}

/// A container for multiple permissions validators. It will succeed if any validator succeeds.
#[allow(missing_debug_implementations)]
pub struct AnyShouldSucceed {
    name: String,
    validators: Vec<PermissionsValidatorBox>,
}

impl PermissionsValidator for AnyShouldSucceed {
    fn check_instruction(
        &self,
        authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView,
    ) -> Result<(), DenialReason> {
        for validator in &self.validators {
            if validator
                .check_instruction(authority, instruction, wsv)
                .is_ok()
            {
                return Ok(());
            }
        }
        Err(format!(
            "None of the instructions succeeded in Any permission check block with name: {}",
            self.name
        ))
    }
}

impl From<AnyShouldSucceed> for PermissionsValidatorBox {
    fn from(validator: AnyShouldSucceed) -> Self {
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
    pub fn with_validator(self, validator: impl Into<PermissionsValidatorBox>) -> Self {
        PermissionsValidatorBuilder {
            validators: self
                .validators
                .into_iter()
                .chain(iter::once(validator.into()))
                .collect(),
        }
    }

    /// Adds a validator to the list and wraps it with `RecursivePermissionValidator` to check nested permissions.
    pub fn with_recursive_validator(self, validator: impl Into<PermissionsValidatorBox>) -> Self {
        self.with_validator(RecursivePermissionsValidator::new(validator.into()))
    }

    /// Returns [`AllShouldSucceed`] that will check all the checks of previously supplied validators.
    pub fn all_should_succeed(self) -> PermissionsValidatorBox {
        AllShouldSucceed {
            validators: self.validators,
        }
        .into()
    }

    /// Returns [`AnyShouldSucceed`] that will succeed if any of the checks of previously supplied validators succeds.
    pub fn any_should_succeed(self, check_name: impl Into<String>) -> PermissionsValidatorBox {
        AnyShouldSucceed {
            name: check_name.into(),
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
        _authority: &AccountId,
        _instruction: &Instruction,
        _wsv: &WorldStateView,
    ) -> Result<(), DenialReason> {
        Ok(())
    }
}

impl From<AllowAll> for PermissionsValidatorBox {
    fn from(AllowAll: AllowAll) -> Self {
        Box::new(AllowAll)
    }
}

/// Boxed validator implementing [`GrantedTokenValidator`] trait.
pub type GrantedTokenValidatorBox = Box<dyn GrantedTokenValidator + Send + Sync>;

/// Trait that should be implemented by
pub trait GrantedTokenValidator {
    /// This function should return the token that `authority` should possess, given the `instruction`
    /// they are planning to execute on the current state of `wsv`
    ///
    /// # Errors
    /// In the case when it is impossible to deduce the required token given current data
    /// (e.g. unexistent account or unaplicable instruction).
    fn should_have_token(
        &self,
        authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView,
    ) -> Result<PermissionToken, String>;
}

impl PermissionsValidator for GrantedTokenValidatorBox {
    fn check_instruction(
        &self,
        authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView,
    ) -> Result<(), DenialReason> {
        let permission_token = self
            .should_have_token(authority, instruction, wsv)
            .map_err(|err| format!("Unable to identify corresponding permission token: {}", err))?;
        let contain = wsv
            .map_account(authority, |account| {
                account.permission_tokens.contains(&permission_token)
            })
            .map_err(|e| e.to_string())?;
        if contain {
            Ok(())
        } else {
            Err(format!(
                "Account does not have the needed permission token: {:?}.",
                permission_token
            ))
        }
    }
}

// TODO: rewrite when specialization reaches stable
// Currently we simply can't do the following:
// impl <T: GrantInstructionValidator> PermissionsValidator for T {}
// when we have
// impl <T: GrantedTokenValidator> PermissionsValidator for T {}
/// Boxed validator implementing [`GrantInstructionValidator`] trait.
pub type GrantInstructionValidatorBox = Box<dyn GrantInstructionValidator + Send + Sync>;

/// Checks the [`GrantBox`] instruction.
pub trait GrantInstructionValidator {
    /// Checks the [`GrantBox`] instruction.
    ///
    /// # Errors
    /// Should return error if this particular validator does not approve this Grant instruction.
    fn check_grant(
        &self,
        authority: &AccountId,
        instruction: &GrantBox,
        wsv: &WorldStateView,
    ) -> Result<(), DenialReason>;
}

impl PermissionsValidator for GrantInstructionValidatorBox {
    fn check_instruction(
        &self,
        authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView,
    ) -> Result<(), DenialReason> {
        if let Instruction::Grant(instruction) = instruction {
            self.check_grant(authority, instruction, wsv)
        } else {
            Ok(())
        }
    }
}

impl From<GrantInstructionValidatorBox> for PermissionsValidatorBox {
    fn from(validator: GrantInstructionValidatorBox) -> Self {
        Box::new(validator)
    }
}

/// Unpacks instruction if it is Grant of a Role into several Grants fo Permission Token.
/// If instruction is not Grant of Role, returns it as inly instruction inside the vec.
/// Should be called before permission checks by validators.
///
/// Semantically means that user can grant a role only if they can grant each of the permission tokens
/// that the role consists of.
///
/// # Errors
/// Evaluation failure of instruction fields.
#[cfg(feature = "roles")]
pub fn unpack_if_role_grant(
    instruction: Instruction,
    wsv: &WorldStateView,
) -> Result<Vec<Instruction>> {
    let grant = if let Instruction::Grant(grant) = &instruction {
        grant
    } else {
        return Ok(vec![instruction]);
    };
    let id = if let Value::Id(IdBox::RoleId(id)) = grant.object.evaluate(wsv, &Context::new())? {
        id
    } else {
        return Ok(vec![instruction]);
    };

    let instructions = if let Some(role) = wsv.world.roles.get(&id) {
        let destination_id = grant.destination_id.evaluate(wsv, &Context::new())?;
        role.permissions
            .iter()
            .cloned()
            .map(|permission_token| GrantBox::new(permission_token, destination_id.clone()).into())
            .collect()
    } else {
        Vec::new()
    };
    Ok(instructions)
}

pub mod prelude {
    //! Exports common types for permissions.

    pub use super::{
        AllowAll, DenialReason, GrantInstructionValidator, GrantInstructionValidatorBox,
        GrantedTokenValidatorBox, PermissionsValidatorBox,
    };
}

#[cfg(test)]
mod tests {
    #![allow(clippy::restriction)]

    use std::collections::BTreeMap;
    use std::collections::BTreeSet;

    use iroha_data_model::isi::*;

    use super::*;

    struct DenyBurn;

    impl From<DenyBurn> for PermissionsValidatorBox {
        fn from(permissions: DenyBurn) -> Self {
            Box::new(permissions)
        }
    }

    impl PermissionsValidator for DenyBurn {
        fn check_instruction(
            &self,
            _authority: &AccountId,
            instruction: &Instruction,
            _wsv: &WorldStateView,
        ) -> Result<(), super::DenialReason> {
            match instruction {
                Instruction::Burn(_) => Err("Denying sequence isi.".to_owned()),
                _ => Ok(()),
            }
        }
    }

    struct DenyAlice;

    impl From<DenyAlice> for PermissionsValidatorBox {
        fn from(permissions: DenyAlice) -> Self {
            Box::new(permissions)
        }
    }

    impl PermissionsValidator for DenyAlice {
        fn check_instruction(
            &self,
            authority: &AccountId,
            _instruction: &Instruction,
            _wsv: &WorldStateView,
        ) -> Result<(), super::DenialReason> {
            if authority.name == "alice" {
                Err("Alice account is denied.".to_owned())
            } else {
                Ok(())
            }
        }
    }

    struct GrantedToken;

    impl GrantedTokenValidator for GrantedToken {
        fn should_have_token(
            &self,
            _authority: &AccountId,
            _instruction: &Instruction,
            _wsv: &WorldStateView,
        ) -> Result<PermissionToken, String> {
            Ok(PermissionToken::new("token", BTreeMap::new()))
        }
    }

    #[test]
    pub fn multiple_validators_combined() {
        let permissions_validator = PermissionsValidatorBuilder::new()
            .with_validator(DenyBurn)
            .with_validator(DenyAlice)
            .all_should_succeed();
        let instruction_burn: Instruction = BurnBox::new(
            Value::U32(10),
            IdBox::AssetId(AssetId::from_names("xor", "test", "alice", "test")),
        )
        .into();
        let instruction_fail = Instruction::Fail(FailBox {
            message: "fail message".to_owned(),
        });
        let account_bob = <Account as Identifiable>::Id::new("bob", "test");
        let account_alice = <Account as Identifiable>::Id::new("alice", "test");
        let wsv = WorldStateView::new(World::new());
        assert!(permissions_validator
            .check_instruction(&account_bob, &instruction_burn, &wsv)
            .is_err());
        assert!(permissions_validator
            .check_instruction(&account_alice, &instruction_fail, &wsv)
            .is_err());
        assert!(permissions_validator
            .check_instruction(&account_alice, &instruction_burn, &wsv)
            .is_err());
        assert!(permissions_validator
            .check_instruction(&account_bob, &instruction_fail, &wsv)
            .is_ok());
    }

    #[test]
    pub fn recursive_validator() {
        let permissions_validator = PermissionsValidatorBuilder::new()
            .with_recursive_validator(DenyBurn)
            .all_should_succeed();
        let instruction_burn: Instruction = BurnBox::new(
            Value::U32(10),
            IdBox::AssetId(AssetId::from_names("xor", "test", "alice", "test")),
        )
        .into();
        let instruction_fail = Instruction::Fail(FailBox {
            message: "fail message".to_owned(),
        });
        let nested_instruction_sequence =
            Instruction::If(If::new(true, instruction_burn.clone()).into());
        let account_alice = <Account as Identifiable>::Id::new("alice", "test");
        let wsv = WorldStateView::new(World::new());
        assert!(permissions_validator
            .check_instruction(&account_alice, &instruction_fail, &wsv)
            .is_ok());
        assert!(permissions_validator
            .check_instruction(&account_alice, &instruction_burn, &wsv)
            .is_err());
        assert!(permissions_validator
            .check_instruction(&account_alice, &nested_instruction_sequence, &wsv)
            .is_err());
    }

    #[test]
    pub fn granted_permission() {
        let alice_id = <Account as Identifiable>::Id::new("alice", "test");
        let bob_id = <Account as Identifiable>::Id::new("bob", "test");
        let alice_xor_id = <Asset as Identifiable>::Id::from_names("xor", "test", "alice", "test");
        let instruction_burn: Instruction = BurnBox::new(Value::U32(10), alice_xor_id).into();
        let mut domain = Domain::new("test");
        let mut bob_account = Account::new(bob_id.clone());
        let _ = bob_account
            .permission_tokens
            .insert(PermissionToken::new("token", BTreeMap::default()));
        drop(domain.accounts.insert(bob_id.clone(), bob_account));
        let domains = vec![("test".to_string(), domain)];
        let wsv = WorldStateView::new(World::with(domains, BTreeSet::new()));
        let validator: GrantedTokenValidatorBox = Box::new(GrantedToken);
        assert!(validator
            .check_instruction(&alice_id, &instruction_burn, &wsv)
            .is_err());
        assert!(validator
            .check_instruction(&bob_id, &instruction_burn, &wsv)
            .is_ok());
    }
}
