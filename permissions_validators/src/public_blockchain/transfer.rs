//! Module with permission for transfering
use core::time::Duration;

use super::*;

declare_token!(
    /// Can transfer user's assets
    CanTransferUserAssets {
        /// Asset id
        asset_id ("asset_id"): AssetId,
    },
    "can_transfer_user_assets"
);

declare_token!(
    /// Can transfer only fixed number of times per some time period
    #[derive(Copy)]
    CanTransferOnlyFixedNumberOfTimesPerPeriod {
        /// Period in milliseconds
        period ("period"): u128,
        /// Number of times transfer is allowed per `[period]`
        count ("count"): u32,
    },
    "can_transfer_only_fixed_number_of_times_per_period"
);

/// Checks that account transfers only the assets that he owns.
#[derive(Debug, Display, Copy, Clone, Serialize)]
#[display(fmt = "Allow to transfer only the assets that are owned by the signer")]
pub struct OnlyOwnedAssets;

impl IsAllowed for OnlyOwnedAssets {
    type Operation = Instruction;

    fn check(
        &self,
        authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView,
    ) -> ValidatorVerdict {
        let transfer_box = if let Instruction::Transfer(transfer) = instruction {
            transfer
        } else {
            return Skip;
        };
        let source_id: AssetId =
            ok_or_skip!(try_evaluate_or_deny!(transfer_box.source_id, wsv).try_into());

        if &source_id.account_id != authority {
            return Deny("Cannot transfer assets of another account.".to_owned());
        }
        Allow
    }
}

/// Allows transfering user's assets from a different account if the
/// corresponding user granted this permission token.
#[derive(Debug, Copy, Clone, Serialize)]
pub struct GrantedByAssetOwner;

impl HasToken for GrantedByAssetOwner {
    type Token = CanTransferUserAssets;

    fn token(
        &self,
        _authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView,
    ) -> std::result::Result<Self::Token, String> {
        let transfer_box = if let Instruction::Transfer(transfer_box) = instruction {
            transfer_box
        } else {
            return Err("Instruction is not transfer.".to_owned());
        };
        let source_id = transfer_box
            .source_id
            .evaluate(wsv, &Context::new())
            .map_err(|e| e.to_string())?;
        let source_id: AssetId = if let Ok(id) = source_id.try_into() {
            id
        } else {
            return Err("Source id is not an AssetId.".to_owned());
        };
        Ok(CanTransferUserAssets::new(source_id))
    }
}

/// Validator that checks Grant instruction so that the access is
/// granted to the assets of the signer account.
#[derive(Debug, Display, Copy, Clone, Serialize)]
#[display(fmt = "the signer is the asset owner")]
pub struct GrantMyAssetAccess;

impl IsGrantAllowed for GrantMyAssetAccess {
    type Token = CanTransferUserAssets;

    fn check(
        &self,
        authority: &AccountId,
        token: Self::Token,
        _wsv: &WorldStateView,
    ) -> ValidatorVerdict {
        if &token.asset_id.account_id != authority {
            return Deny(
                "The signer does not own the asset specified in the permission token".to_owned(),
            );
        }

        Allow
    }
}

/// Validator that checks that `Transfer` instruction execution count
/// fits well in some time period
#[derive(Debug, Display, Copy, Clone, Serialize)]
#[display(fmt = "Allow to transfer if the account hasn't exceeded the limit")]
pub struct ExecutionCountFitsInLimit;

impl IsAllowed for ExecutionCountFitsInLimit {
    type Operation = Instruction;

    #[allow(clippy::expect_used, clippy::unwrap_in_result)]
    fn check(
        &self,
        authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView,
    ) -> ValidatorVerdict {
        if !matches!(instruction, Instruction::Transfer(_)) {
            return Skip;
        };

        let params = match retrieve_permission_params(wsv, authority) {
            Ok(params) => params,
            Err(err) => {
                return Deny(err);
            }
        };
        if params.is_empty() {
            return Allow;
        }

        let period = ok_or_deny!(retrieve_period(&params));
        let count = ok_or_deny!(retrieve_count(&params));
        let executions_count: u32 = count_executions(wsv, authority, period)
            .try_into()
            .expect("`usize` should always fit in `u32`");
        if executions_count >= count {
            return Deny("Transfer transaction limit for current period is exceeded".to_owned());
        }
        Allow
    }
}

/// Retrieve permission parameters for `ExecutionCountFitsInLimit` validator.
/// Returns empty collection if nothing found
///
/// # Errors
/// - Account doesn't exist
fn retrieve_permission_params(
    wsv: &WorldStateView,
    authority: &AccountId,
) -> Result<BTreeMap<Name, Value>> {
    wsv.map_account(authority, |account| {
        wsv.account_permission_tokens(account)
            .iter()
            .filter(|token| {
                token.definition_id() == CanTransferOnlyFixedNumberOfTimesPerPeriod::definition_id()
            })
            .flat_map(PermissionToken::params)
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect()
    })
    .map_err(|e| e.to_string())
}

/// Retrieve period from `params`
///
/// # Errors
/// - There is no period parameter
/// - Period has wrong value type
/// - Failed conversion from `u128` to `u64`
fn retrieve_period(params: &BTreeMap<Name, Value>) -> Result<Duration> {
    let period_param_name = CanTransferOnlyFixedNumberOfTimesPerPeriod::period();
    match params
        .get(period_param_name)
        .ok_or_else(|| format!("Expected `{period_param_name}` parameter",))?
    {
        Value::U128(period) => Ok(Duration::from_millis(
            u64::try_from(*period).map_err(|e| e.to_string())?,
        )),
        _ => Err(format!(
            "`{period_param_name}` parameter has wrong value type. Expected `u128`",
        )),
    }
}

/// Retrieve count from `params`
///
/// # Errors
/// - There is no count parameter
/// - Count has wrong value type
fn retrieve_count(params: &BTreeMap<Name, Value>) -> Result<u32> {
    let count_param_name = CanTransferOnlyFixedNumberOfTimesPerPeriod::count();
    match params
        .get(count_param_name)
        .ok_or_else(|| format!("Expected `{count_param_name}` parameter"))?
    {
        Value::U32(count) => Ok(*count),
        _ => Err(format!(
            "`{count_param_name}` parameter has wrong value type. Expected `u32`"
        )),
    }
}

/// Counts the number of `Transfer`s  which happened in the last `period`
fn count_executions(wsv: &WorldStateView, authority: &AccountId, period: Duration) -> usize {
    let period_start_ms = current_time().saturating_sub(period).as_millis();

    wsv.blocks()
        .rev()
        .take_while(|block| block.header().timestamp > period_start_ms)
        .map(|block| -> usize {
            block
                .as_v1()
                .transactions
                .iter()
                .filter_map(|tx| {
                    let payload = tx.payload();
                    if payload.account_id == *authority {
                        if let Executable::Instructions(instructions) = &payload.instructions {
                            return Some(
                                instructions
                                    .iter()
                                    .filter(|isi| matches!(isi, Instruction::Transfer(_)))
                                    .count(),
                            );
                        }
                    }
                    None
                })
                .sum()
        })
        .sum()
}
