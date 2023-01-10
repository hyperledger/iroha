//! Module with permission for changing config parameters

use super::*;

declare_token!(
    /// Can change configuration parameters.
    CanChangeConfigParameters {
        /// Account id
        account_id ("account_id"): AccountId,
    },
    "can_change_config_parameters"
);

/// Prohibits changing configuration parameters.
#[derive(Debug, Display, Copy, Clone, Serialize)]
#[display(fmt = "prohibit change config parameters")]
pub struct ChangeParametersOnlyForSignerAccount;

impl IsAllowed for ChangeParametersOnlyForSignerAccount {
    type Operation = Instruction;

    fn check(
        &self,
        authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView,
    ) -> ValidatorVerdict {
        let param_box = if let Instruction::SetParameter(set_parameter) = instruction {
            set_parameter
        } else {
            return Skip;
        };
        let source_id: AccountId =
            ok_or_skip!(try_evaluate_or_deny!(param_box.source_id, wsv).try_into());
        if &source_id != authority {
            return Deny("Cannot change config parameters".to_owned());
        }
        Allow
    }
}

/// Validator that allows to change configuration parameters for accounts with the corresponding permission token.
#[derive(Debug, Copy, Clone, Serialize)]
pub struct GrantedChangeConfigParameters;

impl HasToken for GrantedChangeConfigParameters {
    type Token = CanChangeConfigParameters;

    fn token(
        &self,
        _authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView,
    ) -> Result<CanChangeConfigParameters> {
        let param_box = if let Instruction::SetParameter(set_parameter) = instruction {
            set_parameter
        } else {
            return Err("Instruction is not set parameter".to_owned());
        };
        let source_id = param_box
            .source_id
            .evaluate(wsv, &Context::new())
            .map_err(|e| e.to_string())?;
        let src_id: AccountId = if let Ok(src_id) = source_id.try_into() {
            src_id
        } else {
            return Err("Source id is not an AccountId".to_owned());
        };
        Ok(CanChangeConfigParameters::new(src_id))
    }
}
