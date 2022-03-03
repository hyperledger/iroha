//! Module with permissions for registering.

use super::*;

/// Can register domains permission token name.
pub static CAN_REGISTER_DOMAINS_TOKEN: Lazy<Name> =
    Lazy::new(|| Name::test("can_register_domains"));

/// Prohibits registering domains.
#[derive(Debug, Copy, Clone)]
pub struct ProhibitRegisterDomains;

impl_from_item_for_instruction_validator_box!(ProhibitRegisterDomains);

impl<W: WorldTrait> IsAllowed<W, InstructionBox> for ProhibitRegisterDomains {
    fn check(
        &self,
        _authority: &AccountId,
        instruction: &InstructionBox,
        _wsv: &WorldStateView<W>,
    ) -> Result<(), DenialReason> {
        let _register_box = if let InstructionBox::Register(register) = instruction {
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
        _instruction: &InstructionBox,
        _wsv: &WorldStateView<W>,
    ) -> Result<PermissionToken, String> {
        Ok(PermissionToken::new(
            CAN_REGISTER_DOMAINS_TOKEN.clone(),
            BTreeMap::new(),
        ))
    }
}
