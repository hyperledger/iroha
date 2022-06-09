//! Module with permissions for registering.

use super::*;

declare_token!(
    /// Can register domains.
    CanRegisterDomains {},
    "can_register_domains"
);

/// Prohibits registering domains.
#[derive(Debug, Copy, Clone, Serialize)]
pub struct ProhibitRegisterDomains;

impl_from_item_for_instruction_validator_box!(ProhibitRegisterDomains);

impl IsAllowed<Instruction> for ProhibitRegisterDomains {
    fn check(
        &self,
        _authority: &AccountId,
        instruction: &Instruction,
        _wsv: &WorldStateView,
    ) -> Result<(), DenialReason> {
        let _register_box = if let Instruction::Register(register) = instruction {
            register
        } else {
            return Ok(());
        };
        Err("Domain registration is prohibited.".to_owned().into())
    }
}

/// Validator that allows to register domains for accounts with the corresponding permission token.
#[derive(Debug, Copy, Clone, Serialize)]
pub struct GrantedAllowedRegisterDomains;

impl_from_item_for_granted_token_validator_box!(GrantedAllowedRegisterDomains);

impl HasToken for GrantedAllowedRegisterDomains {
    fn token(
        &self,
        _authority: &AccountId,
        _instruction: &Instruction,
        _wsv: &WorldStateView,
    ) -> Result<PermissionToken, String> {
        Ok(CanRegisterDomains::new().into())
    }
}
