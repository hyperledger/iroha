//! Permission checks associated with use cases that can be summarized as private blockchains (e.g. CBDC).

use super::*;

pub mod query;
pub mod register;
#[cfg(test)]
mod tests;

/// List ids of all predefined permission tokens, e.g. for easier
/// registration in genesis block.
pub fn default_permission_token_definitions() -> [&'static PermissionTokenDefinition; 1] {
    [register::CanRegisterDomains::definition()]
}

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
#[derive(Debug, Display, Copy, Clone, Serialize)]
#[display(fmt = "Prohibit grant")]
pub struct ProhibitGrant;

impl IsAllowed for ProhibitGrant {
    type Operation = Instruction;

    fn check(
        &self,
        _authority: &AccountId,
        instruction: &Instruction,
        _wsv: &WorldStateView,
    ) -> ValidatorVerdict {
        if let Instruction::Grant(_) = instruction {
            return Deny("Granting operation is prohibited.".to_owned());
        }
        Skip
    }
}
