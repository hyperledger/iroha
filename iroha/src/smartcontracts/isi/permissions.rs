#![allow(clippy::module_name_repetitions)]

//! This module contains permissions related Iroha functionality.

use std::iter;

use iroha_data_model::prelude::*;
use iroha_error::Result;

use super::prelude::WorldTrait;
#[cfg(feature = "roles")]
use super::Evaluate;
use crate::prelude::*;

/// Operation for which the permission should be checked.
pub trait NeedsPermission {}

impl NeedsPermission for Instruction {}

impl NeedsPermission for QueryBox {}

/// Reason for prohibiting the execution of the particular instruction.
pub type DenialReason = String;

/// Implement this to provide custom permission checks for the Iroha based blockchain.
pub trait PermissionsValidator<W: WorldTrait, O: NeedsPermission> {
    /// Checks if the `authority` is allowed to perform `instruction` given the current state of `wsv`.
    ///
    /// # Errors
    /// In the case when the execution of `instruction` under given `authority` with the current state of `wsv`
    /// is unallowed.
    fn check(
        &self,
        authority: &AccountId,
        operation: &O,
        wsv: &WorldStateView<W>,
    ) -> Result<(), DenialReason>;
}

/// Box with `PermissionsValidator`
pub type PermissionsValidatorBox<W, O> = Box<dyn PermissionsValidator<W, O> + Send + Sync>;

/// Box with `PermissionsValidator` for `Instruction`.
pub type InstructionPermissionsValidatorBox<W> = PermissionsValidatorBox<W, Instruction>;

/// Box with `PermissionsValidator` for `Query`.
pub type QueryPermissionsValidatorBox<W> = PermissionsValidatorBox<W, QueryBox>;

/// Trait for joining validators with `or` method, autoimplemented for all types which convert to `PermissionsValidatorBox`.
pub trait ValidatorApplyOr<W: WorldTrait, O: NeedsPermission> {
    /// Combines two validators into [`OrPermissionsValidator`].
    fn or(self, another: impl Into<PermissionsValidatorBox<W, O>>) -> OrPermissionsValidator<W, O>;
}

impl<W: WorldTrait, O: NeedsPermission, V: Into<PermissionsValidatorBox<W, O>>>
    ValidatorApplyOr<W, O> for V
{
    fn or(self, another: impl Into<PermissionsValidatorBox<W, O>>) -> OrPermissionsValidator<W, O> {
        OrPermissionsValidator {
            first: self.into(),
            second: another.into(),
        }
    }
}

/// `check` will succeed if either `first` or `second` validator succeeds.
#[allow(missing_debug_implementations)]
pub struct OrPermissionsValidator<W: WorldTrait, O: NeedsPermission> {
    first: PermissionsValidatorBox<W, O>,
    second: PermissionsValidatorBox<W, O>,
}

impl<W: WorldTrait, O: NeedsPermission> PermissionsValidator<W, O>
    for OrPermissionsValidator<W, O>
{
    fn check(
        &self,
        authority: &AccountId,
        operation: &O,
        wsv: &WorldStateView<W>,
    ) -> Result<(), DenialReason> {
        self.first
            .check(authority, operation, wsv)
            .or_else(|first_error| {
                self.second
                    .check(authority, operation, wsv)
                    .map_err(|second_error| {
                        format!(
                            "Failed to pass first check with {} and second check with {}.",
                            first_error, second_error
                        )
                    })
            })
    }
}

impl<W: WorldTrait, O: NeedsPermission + 'static> From<OrPermissionsValidator<W, O>>
    for PermissionsValidatorBox<W, O>
{
    fn from(validator: OrPermissionsValidator<W, O>) -> Self {
        Box::new(validator)
    }
}

/// Wraps validator to check nested permissions.
/// Pay attention to wrap only validators that do not check nested intructions by themselves.
#[allow(missing_debug_implementations)]
pub struct RecursivePermissionsValidator<W: WorldTrait> {
    validator: PermissionsValidatorBox<W, Instruction>,
}

impl<W: WorldTrait> RecursivePermissionsValidator<W> {
    /// Wraps `validator` to check nested permissions.
    pub fn new(validator: PermissionsValidatorBox<W, Instruction>) -> Self {
        RecursivePermissionsValidator { validator }
    }
}

impl<W: WorldTrait> PermissionsValidator<W, Instruction> for RecursivePermissionsValidator<W> {
    fn check(
        &self,
        authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView<W>,
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
            | Instruction::Fail(_) => self.validator.check(authority, instruction, wsv),
            Instruction::If(if_box) => {
                self.check(authority, &if_box.then, wsv)
                    .and_then(|_| match &if_box.otherwise {
                        Some(instruction) => self.check(authority, instruction, wsv),
                        None => Ok(()),
                    })
            }
            Instruction::Pair(pair_box) => self
                .check(authority, &pair_box.left_instruction, wsv)
                .and(self.check(authority, &pair_box.right_instruction, wsv)),
            Instruction::Sequence(sequence_box) => sequence_box
                .instructions
                .iter()
                .try_for_each(|instruction| self.check(authority, instruction, wsv)),
        }
    }
}

impl<W: WorldTrait> From<RecursivePermissionsValidator<W>>
    for InstructionPermissionsValidatorBox<W>
{
    fn from(validator: RecursivePermissionsValidator<W>) -> Self {
        Box::new(validator)
    }
}

/// A container for multiple permissions validators. It will succeed if all validators succeed.
#[allow(missing_debug_implementations)]
pub struct AllShouldSucceed<W: WorldTrait, O: NeedsPermission> {
    validators: Vec<PermissionsValidatorBox<W, O>>,
}

impl<W: WorldTrait, O: NeedsPermission> PermissionsValidator<W, O> for AllShouldSucceed<W, O> {
    fn check(
        &self,
        authority: &AccountId,
        operation: &O,
        wsv: &WorldStateView<W>,
    ) -> Result<(), DenialReason> {
        for validator in &self.validators {
            validator.check(authority, operation, wsv)?
        }
        Ok(())
    }
}

impl<W: WorldTrait, O: NeedsPermission + 'static> From<AllShouldSucceed<W, O>>
    for PermissionsValidatorBox<W, O>
{
    fn from(validator: AllShouldSucceed<W, O>) -> Self {
        Box::new(validator)
    }
}

/// A container for multiple permissions validators. It will succeed if any validator succeeds.
#[allow(missing_debug_implementations)]
pub struct AnyShouldSucceed<W: WorldTrait, O: NeedsPermission> {
    name: String,
    validators: Vec<PermissionsValidatorBox<W, O>>,
}

impl<W: WorldTrait, O: NeedsPermission> PermissionsValidator<W, O> for AnyShouldSucceed<W, O> {
    fn check(
        &self,
        authority: &AccountId,
        operation: &O,
        wsv: &WorldStateView<W>,
    ) -> Result<(), DenialReason> {
        for validator in &self.validators {
            if validator.check(authority, operation, wsv).is_ok() {
                return Ok(());
            }
        }
        Err(format!(
            "None of the instructions succeeded in Any permission check block with name: {}",
            self.name
        ))
    }
}

impl<W: WorldTrait, O: NeedsPermission + 'static> From<AnyShouldSucceed<W, O>>
    for PermissionsValidatorBox<W, O>
{
    fn from(validator: AnyShouldSucceed<W, O>) -> Self {
        Box::new(validator)
    }
}

/// Builder to combine multiple validation checks into one.
#[allow(missing_debug_implementations)]
#[derive(Default)]
pub struct PermissionsValidatorBuilder<W: WorldTrait, O: NeedsPermission> {
    validators: Vec<PermissionsValidatorBox<W, O>>,
}

impl<W: WorldTrait, O: NeedsPermission + 'static> PermissionsValidatorBuilder<W, O> {
    /// Returns new `PermissionValidatorBuilder`, with empty set of validator checks.
    pub fn new() -> Self {
        PermissionsValidatorBuilder {
            validators: Vec::new(),
        }
    }

    /// Adds a validator to the list.
    pub fn with_validator(self, validator: impl Into<PermissionsValidatorBox<W, O>>) -> Self {
        PermissionsValidatorBuilder {
            validators: self
                .validators
                .into_iter()
                .chain(iter::once(validator.into()))
                .collect(),
        }
    }

    /// Returns [`AllShouldSucceed`] that will check all the checks of previously supplied validators.
    pub fn all_should_succeed(self) -> PermissionsValidatorBox<W, O> {
        AllShouldSucceed {
            validators: self.validators,
        }
        .into()
    }

    /// Returns [`AnyShouldSucceed`] that will succeed if any of the checks of previously supplied validators succeds.
    pub fn any_should_succeed(
        self,
        check_name: impl Into<String>,
    ) -> PermissionsValidatorBox<W, O> {
        AnyShouldSucceed {
            name: check_name.into(),
            validators: self.validators,
        }
        .into()
    }
}

impl<W: WorldTrait> PermissionsValidatorBuilder<W, Instruction> {
    /// Adds a validator to the list and wraps it with `RecursivePermissionValidator` to check nested permissions.
    pub fn with_recursive_validator(
        self,
        validator: impl Into<InstructionPermissionsValidatorBox<W>>,
    ) -> Self {
        self.with_validator(RecursivePermissionsValidator::new(validator.into()))
    }
}

/// Allows all ISI to be executed for all possible values. Mostly for tests and simple cases.
#[derive(Debug, Clone, Copy)]
pub struct AllowAll;

impl<W: WorldTrait, O: NeedsPermission> PermissionsValidator<W, O> for AllowAll {
    fn check(
        &self,
        _authority: &AccountId,
        _instruction: &O,
        _wsv: &WorldStateView<W>,
    ) -> Result<(), DenialReason> {
        Ok(())
    }
}

impl<W: WorldTrait, O: NeedsPermission> From<AllowAll> for PermissionsValidatorBox<W, O> {
    fn from(AllowAll: AllowAll) -> Self {
        Box::new(AllowAll)
    }
}

/// Boxed validator implementing [`GrantedTokenValidator`] trait.
pub type GrantedTokenValidatorBox<W> = Box<dyn GrantedTokenValidator<W> + Send + Sync>;

/// Trait that should be implemented by
pub trait GrantedTokenValidator<W: WorldTrait> {
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
        wsv: &WorldStateView<W>,
    ) -> Result<PermissionToken, String>;
}

impl<W: WorldTrait> PermissionsValidator<W, Instruction> for GrantedTokenValidatorBox<W> {
    fn check(
        &self,
        authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView<W>,
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
pub type GrantInstructionValidatorBox<W> = Box<dyn GrantInstructionValidator<W> + Send + Sync>;

/// Checks the [`GrantBox`] instruction.
pub trait GrantInstructionValidator<W: WorldTrait> {
    /// Checks the [`GrantBox`] instruction.
    ///
    /// # Errors
    /// Should return error if this particular validator does not approve this Grant instruction.
    fn check_grant(
        &self,
        authority: &AccountId,
        instruction: &GrantBox,
        wsv: &WorldStateView<W>,
    ) -> Result<(), DenialReason>;
}

impl<W: WorldTrait> PermissionsValidator<W, Instruction> for GrantInstructionValidatorBox<W> {
    fn check(
        &self,
        authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView<W>,
    ) -> Result<(), DenialReason> {
        if let Instruction::Grant(instruction) = instruction {
            self.check_grant(authority, instruction, wsv)
        } else {
            Ok(())
        }
    }
}

impl<W: WorldTrait> From<GrantInstructionValidatorBox<W>>
    for InstructionPermissionsValidatorBox<W>
{
    fn from(validator: GrantInstructionValidatorBox<W>) -> Self {
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
pub fn unpack_if_role_grant<W: WorldTrait>(
    instruction: Instruction,
    wsv: &WorldStateView<W>,
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
    use crate::wsv::World;

    struct DenyBurn;

    impl<W: WorldTrait> From<DenyBurn> for InstructionPermissionsValidatorBox<W> {
        fn from(permissions: DenyBurn) -> Self {
            Box::new(permissions)
        }
    }

    impl<W: WorldTrait> PermissionsValidator<W, Instruction> for DenyBurn {
        fn check(
            &self,
            _authority: &AccountId,
            instruction: &Instruction,
            _wsv: &WorldStateView<W>,
        ) -> Result<(), super::DenialReason> {
            match instruction {
                Instruction::Burn(_) => Err("Denying sequence isi.".to_owned()),
                _ => Ok(()),
            }
        }
    }

    struct DenyAlice;

    impl<W: WorldTrait> From<DenyAlice> for InstructionPermissionsValidatorBox<W> {
        fn from(permissions: DenyAlice) -> Self {
            Box::new(permissions)
        }
    }

    impl<W: WorldTrait> PermissionsValidator<W, Instruction> for DenyAlice {
        fn check(
            &self,
            authority: &AccountId,
            _instruction: &Instruction,
            _wsv: &WorldStateView<W>,
        ) -> Result<(), super::DenialReason> {
            if authority.name == "alice" {
                Err("Alice account is denied.".to_owned())
            } else {
                Ok(())
            }
        }
    }

    struct GrantedToken;

    impl<W: WorldTrait> GrantedTokenValidator<W> for GrantedToken {
        fn should_have_token(
            &self,
            _authority: &AccountId,
            _instruction: &Instruction,
            _wsv: &WorldStateView<W>,
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
            .check(&account_bob, &instruction_burn, &wsv)
            .is_err());
        assert!(permissions_validator
            .check(&account_alice, &instruction_fail, &wsv)
            .is_err());
        assert!(permissions_validator
            .check(&account_alice, &instruction_burn, &wsv)
            .is_err());
        assert!(permissions_validator
            .check(&account_bob, &instruction_fail, &wsv)
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
            .check(&account_alice, &instruction_fail, &wsv)
            .is_ok());
        assert!(permissions_validator
            .check(&account_alice, &instruction_burn, &wsv)
            .is_err());
        assert!(permissions_validator
            .check(&account_alice, &nested_instruction_sequence, &wsv)
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
        let validator: GrantedTokenValidatorBox<_> = Box::new(GrantedToken);
        assert!(validator.check(&alice_id, &instruction_burn, &wsv).is_err());
        assert!(validator.check(&bob_id, &instruction_burn, &wsv).is_ok());
    }
}
