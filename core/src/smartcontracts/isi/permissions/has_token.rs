//! Contains [`HasToken`] trait and box container for it

use super::*;

/// Boxed validator implementing [`HasToken`] validator trait.
pub type HasTokenBoxed = Box<dyn HasToken + Send + Sync>;

/// Trait that should be implemented by validator that checks the need to have permission token for a certain action.
pub trait HasToken: Debug {
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
        wsv: &WorldStateView,
    ) -> std::result::Result<PermissionToken, String>;
}

impl IsAllowed for HasTokenBoxed {
    type Operation = Instruction;

    fn check(
        &self,
        authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView,
    ) -> ValidatorVerdict {
        let permission_token = match self.token(authority, instruction, wsv) {
            Ok(permission_token) => permission_token,
            Err(err) => {
                return ValidatorVerdict::Deny(
                    format!("Unable to identify corresponding permission token: {}", err).into(),
                );
            }
        };

        let contain = match wsv.map_account(authority, |account| {
            account.contains_permission(&permission_token)
        }) {
            Ok(contain) => contain,
            Err(err) => {
                return ValidatorVerdict::Deny(
                    format!("Unable to check if account has permission token: {}", err).into(),
                );
            }
        };

        if contain {
            ValidatorVerdict::Allow
        } else {
            ValidatorVerdict::Deny(
                format!(
                    "Account does not have the needed permission token: {:?}.",
                    permission_token
                )
                .into(),
            )
        }
    }
}
