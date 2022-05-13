//! Module with permissions for registering.

use std::str::FromStr as _;

use super::*;

/// Can register domains permission token name.
#[allow(clippy::expect_used)]
pub static CAN_REGISTER_DOMAINS_TOKEN: Lazy<Name> =
    Lazy::new(|| Name::from_str("can_register_domains").expect("this mustn't panic"));

/// Prohibits registering domains.
#[derive(Debug, Copy, Clone)]
pub struct ProhibitRegisterDomains;

impl_from_item_for_instruction_validator_box!(ProhibitRegisterDomains);

impl<W: WorldTrait> IsAllowed<W, Instruction> for ProhibitRegisterDomains {
    fn check(
        &self,
        _authority: &AccountId,
        instruction: &Instruction,
        _wsv: &WorldStateView<W>,
    ) -> Result<(), DenialReason> {
        let _register_box = if let Instruction::Register(register) = instruction {
            register
        } else {
            return Ok(());
        };
        Err("Domain registration is prohibited.".to_owned())
    }
}

/// Validator that allows to register domains for accounts with the corresponding permission token.
#[derive(Debug, Clone, Copy)]
pub struct GrantedAllowedRegisterDomains;

impl_from_item_for_granted_token_validator_box!(GrantedAllowedRegisterDomains);

impl<W: WorldTrait> HasToken<W> for GrantedAllowedRegisterDomains {
    fn token(
        &self,
        _authority: &AccountId,
        _instruction: &Instruction,
        _wsv: &WorldStateView<W>,
    ) -> Result<PermissionToken, String> {
        Ok(PermissionToken::new(CAN_REGISTER_DOMAINS_TOKEN.clone()))
    }
}
