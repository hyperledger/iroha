//! Module with permissions for registering.

use super::*;

declare_token!(
    /// Can register domains.
    CanRegisterDomains {},
    "can_register_domains"
);

/// Prohibits registering domains.
#[derive(Debug, Display, Copy, Clone, Serialize)]
#[display(fmt = "Prohibit register domains")]
pub struct ProhibitRegisterDomains;

impl IsAllowed for ProhibitRegisterDomains {
    type Operation = Instruction;

    fn check(
        &self,
        _authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView,
    ) -> ValidatorVerdict {
        if let Instruction::Register(register) = instruction {
            if let Ok(RegistrableBox::Domain(_)) = register.object.evaluate(wsv, &Context::new()) {
                return Deny("Domain registration is prohibited.".to_owned());
            }

            return Allow;
        }

        Skip
    }
}

/// Validator that allows to register domains for accounts with the corresponding permission token.
#[derive(Debug, Copy, Clone, Serialize)]
pub struct GrantedAllowedRegisterDomains;

impl HasToken for GrantedAllowedRegisterDomains {
    type Token = CanRegisterDomains;

    fn token(
        &self,
        _authority: &AccountId,
        _instruction: &Instruction,
        _wsv: &WorldStateView,
    ) -> Result<CanRegisterDomains, String> {
        Ok(CanRegisterDomains::new())
    }
}
