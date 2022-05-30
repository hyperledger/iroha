//! Contains [`HasToken`] trait and box container for it

use super::*;

/// Boxed validator implementing [`HasToken`] validator trait.
#[derive(Debug, Clone, FromVariant, Serialize)]
pub enum HasTokenBoxed {
    /// Validator for [`World`]
    World(#[skip_container] Box<dyn HasToken<World> + Send + Sync>),
    /// Validator for [`MockWorld`]
    #[cfg(test)]
    Mock(#[skip_container] Box<dyn HasToken<MockWorld> + Send + Sync>),
}

/// Trait that should be implemented by validator that checks the need to have permission token for a certain action.
pub trait HasToken<W: WorldTrait>: Debug + dyn_clone::DynClone + erased_serde::Serialize {
    /// This function should return the token that `authority` should
    /// possess, given the `instruction` they are planning to execute
    /// on the current state of `wsv`
    ///
    /// # Errors
    ///
    /// In the case when it is impossible to deduce the required token
    /// given current data (e.g. non-existent account or inapplicable
    /// instruction).
    fn token(
        &self,
        authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView<W>,
    ) -> std::result::Result<PermissionToken, String>;
}

#[allow(clippy::panic_in_result_fn, clippy::unimplemented)]
impl HasToken<World> for HasTokenBoxed {
    fn token(
        &self,
        authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView<World>,
    ) -> std::result::Result<PermissionToken, String> {
        match self {
            HasTokenBoxed::World(world) => world.token(authority, instruction, wsv),
            #[cfg(test)]
            HasTokenBoxed::Mock(_) => unimplemented!(),
        }
    }
}

dyn_clone::clone_trait_object!(<W> HasToken<W> where W: WorldTrait);
erased_serde::serialize_trait_object!(<W> HasToken<W> where W: WorldTrait);

impl IsAllowed<World, Instruction> for HasTokenBoxed {
    fn check(
        &self,
        authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView<World>,
    ) -> Result<()> {
        let permission_token = self
            .token(authority, instruction, wsv)
            .map_err(|err| format!("Unable to identify corresponding permission token: {}", err))?;
        let contain = wsv
            .map_account(authority, |account| {
                account.contains_permission(&permission_token)
            })
            .map_err(|e| e.to_string())?;
        if contain {
            Ok(())
        } else {
            Err(format!(
                "Account does not have the needed permission token: {:?}.",
                permission_token
            )
            .into())
        }
    }
}
