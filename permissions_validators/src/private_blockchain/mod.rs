//! Permission checks associated with use cases that can be summarized as private blockchains (e.g. CBDC).

use super::*;

pub mod query;
pub mod register;
#[cfg(test)]
mod tests;

/// A preconfigured set of permissions for simple use cases.
pub fn default_instructions_permissions() -> InstructionJudgeBoxed {
    Box::new(
        JudgeBuilder::with_recursive_validator(
            register::ProhibitRegisterDomains
                .or(register::GrantedAllowedRegisterDomains.into_validator()),
        )
        .at_least_one_allow()
        .build(),
    )
}

/// A preconfigured set of permissions for simple use cases.
pub fn default_query_permissions() -> QueryJudgeBoxed {
    Box::new(
        JudgeBuilder::with_validator(AllowAll::new().into_validator())
            .at_least_one_allow()
            .build(),
    )
}

/// Prohibits using the [`Grant`] instruction at runtime.  This means
/// `Grant` instruction will only be used in genesis to specify
/// rights. The rationale is that we don't want to be able to create a
/// super-user in a blockchain.
#[derive(Debug, Copy, Clone, Serialize)]
pub struct ProhibitGrant;

impl IsGrantAllowed for ProhibitGrant {
    fn check(
        &self,
        _authority: &AccountId,
        _instruction: &GrantBox,
        _wsv: &WorldStateView,
    ) -> ValidatorVerdict {
        Deny("Granting at runtime is prohibited.".to_owned())
    }
}
