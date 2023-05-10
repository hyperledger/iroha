//! Validation and tokens related to validator operations.

use super::*;

tokens!(
    pattern = {
        #[derive(Token, ValidateGrantRevoke)]
        #[validate(pass_conditions::OnlyGenesis)]
        pub struct _ {}
    },
    validator::tokens: [
        CanUpgradeValidator,
    ]
);

impl DefaultValidate for Upgrade<Validator> {
    fn default_validate<Q>(
        &self,
        authority: &<Account as Identifiable>::Id,
        _validate_query: Q,
    ) -> Verdict
    where
        Q: Fn(&<Account as Identifiable>::Id, QueryBox) -> Verdict + Copy,
    {
        pass_if!(tokens::CanUpgradeValidator {}.is_owned_by(authority));

        deny!("Can't upgrade validator")
    }
}
