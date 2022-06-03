//! Permission checks associated with use cases that can be summarized as private blockchains (e.g. CBDC).

use super::*;

pub mod query;
pub mod register;

/// A preconfigured set of permissions for simple use cases.
pub fn default_instructions_permissions() -> IsInstructionAllowedBoxed {
    ValidatorBuilder::with_recursive_validator(
        register::ProhibitRegisterDomains.or(register::GrantedAllowedRegisterDomains),
    )
    .all_should_succeed()
}

/// A preconfigured set of permissions for simple use cases.
pub fn default_query_permissions() -> IsQueryAllowedBoxed {
    ValidatorBuilder::with_validator(AllowAll).all_should_succeed()
}

/// Prohibits using the [`Grant`] instruction at runtime.  This means
/// `Grant` instruction will only be used in genesis to specify
/// rights. The rationale is that we don't want to be able to create a
/// super-user in a blockchain.
#[derive(Debug, Copy, Clone, Serialize)]
pub struct ProhibitGrant;

impl_from_item_for_grant_instruction_validator_box!(ProhibitGrant);

impl<W: WorldTrait> IsGrantAllowed<W> for ProhibitGrant {
    fn check(
        &self,
        _authority: &AccountId,
        _instruction: &GrantBox,
        _wsv: &WorldStateView<W>,
    ) -> Result<(), DenialReason> {
        Err("Granting at runtime is prohibited.".to_owned().into())
    }
}
