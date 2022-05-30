//! Contains traits and function related to roles permission checking

use super::{super::Evaluate, *};

// TODO: rewrite when specialization reaches stable
// Currently we simply can't do the following:
// impl <T: IsGrantAllowed> PermissionsValidator for T {}
// when we have
// impl <T: HasToken> PermissionsValidator for T {}
/// Boxed validator implementing [`IsGrantAllowed`] trait.
#[derive(Debug, Clone, FromVariant, Serialize)]
pub enum IsGrantAllowedBoxed {
    /// Validator for [`World`]
    World(#[skip_container] Box<dyn IsGrantAllowed<World> + Send + Sync>),
    /// Validator for [`MockWorld`]
    #[cfg(test)]
    Mock(#[skip_container] Box<dyn IsGrantAllowed<MockWorld> + Send + Sync>),
}

/// Checks the [`GrantBox`] instruction.
pub trait IsGrantAllowed<W: WorldTrait>:
    Debug + dyn_clone::DynClone + erased_serde::Serialize
{
    /// Checks the [`GrantBox`] instruction.
    ///
    /// # Errors
    /// If this validator doesn't approve this Grant instruction.
    fn check_grant(
        &self,
        authority: &AccountId,
        instruction: &GrantBox,
        wsv: &WorldStateView<W>,
    ) -> Result<()>;
}

dyn_clone::clone_trait_object!(<W> IsGrantAllowed<W> where W: WorldTrait);
erased_serde::serialize_trait_object!(<W> IsGrantAllowed<W> where W: WorldTrait);

#[allow(clippy::panic_in_result_fn, clippy::unimplemented)]
impl IsGrantAllowed<World> for IsGrantAllowedBoxed {
    fn check_grant(
        &self,
        authority: &AccountId,
        instruction: &GrantBox,
        wsv: &WorldStateView<World>,
    ) -> Result<()> {
        match self {
            IsGrantAllowedBoxed::World(world) => world.check_grant(authority, instruction, wsv),
            #[cfg(test)]
            IsGrantAllowedBoxed::Mock(_) => unimplemented!(),
        }
    }
}

/// Boxed validator implementing the [`IsRevokeAllowed`] trait.
#[derive(Debug, Clone, FromVariant, Serialize)]
pub enum IsRevokeAllowedBoxed {
    /// Validator for [`World`]
    World(#[skip_container] Box<dyn IsRevokeAllowed<World> + Send + Sync>),
    /// Validator for [`MockWorld`]
    #[cfg(test)]
    Mock(#[skip_container] Box<dyn IsRevokeAllowed<MockWorld> + Send + Sync>),
}

/// Checks the [`RevokeBox`] instruction.
pub trait IsRevokeAllowed<W: WorldTrait>:
    Debug + dyn_clone::DynClone + erased_serde::Serialize
{
    /// Checks the [`RevokeBox`] instruction.
    ///
    /// # Errors
    /// If this validator doesn't approve this Revoke instruction.
    fn check_revoke(
        &self,
        authority: &AccountId,
        instruction: &RevokeBox,
        wsv: &WorldStateView<W>,
    ) -> Result<()>;
}

dyn_clone::clone_trait_object!(<W> IsRevokeAllowed<W> where W: WorldTrait);
erased_serde::serialize_trait_object!(<W> IsRevokeAllowed<W> where W: WorldTrait);

#[allow(clippy::panic_in_result_fn, clippy::unimplemented)]
impl IsRevokeAllowed<World> for IsRevokeAllowedBoxed {
    fn check_revoke(
        &self,
        authority: &AccountId,
        instruction: &RevokeBox,
        wsv: &WorldStateView<World>,
    ) -> Result<()> {
        match self {
            IsRevokeAllowedBoxed::World(world) => world.check_revoke(authority, instruction, wsv),
            #[cfg(test)]
            IsRevokeAllowedBoxed::Mock(_) => unimplemented!(),
        }
    }
}

impl IsAllowed<World, Instruction> for IsGrantAllowedBoxed {
    fn check(
        &self,
        authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView<World>,
    ) -> Result<()> {
        if let Instruction::Grant(isi) = instruction {
            self.check_grant(authority, isi, wsv)
        } else {
            Ok(())
        }
    }
}

impl IsAllowed<World, Instruction> for IsRevokeAllowedBoxed {
    fn check(
        &self,
        authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView<World>,
    ) -> Result<()> {
        if let Instruction::Revoke(isi) = instruction {
            self.check_revoke(authority, isi, wsv)
        } else {
            Ok(())
        }
    }
}

/// Unpacks instruction if it is Grant of a Role into several Grants
/// fo Permission Token.  If instruction is not Grant of Role, returns
/// it as inly instruction inside the vec.  Should be called before
/// permission checks by validators.
///
/// Semantically means that user can grant a role only if they can
/// grant each of the permission tokens that the role consists of.
///
/// # Errors
/// Evaluation failure of instruction fields.
pub fn unpack_if_role_grant<W: WorldTrait>(
    instruction: Instruction,
    wsv: &WorldStateView<W>,
) -> eyre::Result<Vec<Instruction>> {
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
        role.permissions()
            .cloned()
            .map(|permission_token| GrantBox::new(permission_token, destination_id.clone()).into())
            .collect()
    } else {
        Vec::new()
    };
    Ok(instructions)
}

/// Unpack instruction if it is a Revoke of a Role, into several
/// Revocations of Permission Tokens. If the instruction is not a
/// Revoke of Role, returns it as an internal instruction inside the
/// vec.
///
/// This `fn` should be called before permission checks (by
/// validators).
///
/// Semantically: the user can revoke a role only if they can revoke
/// each of the permission tokens that the role consists of of.
///
/// # Errors
/// Evaluation failure of each of the instruction fields.
pub fn unpack_if_role_revoke<W: WorldTrait>(
    instruction: Instruction,
    wsv: &WorldStateView<W>,
) -> eyre::Result<Vec<Instruction>> {
    let revoke = if let Instruction::Revoke(revoke) = &instruction {
        revoke
    } else {
        return Ok(vec![instruction]);
    };
    let id = if let Value::Id(IdBox::RoleId(id)) = revoke.object.evaluate(wsv, &Context::new())? {
        id
    } else {
        return Ok(vec![instruction]);
    };

    let instructions = if let Some(role) = wsv.world.roles.get(&id) {
        let destination_id = revoke.destination_id.evaluate(wsv, &Context::new())?;
        role.permissions()
            .cloned()
            .map(|permission_token| RevokeBox::new(permission_token, destination_id.clone()).into())
            .collect()
    } else {
        Vec::new()
    };
    Ok(instructions)
}
