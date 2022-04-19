//! Module with permission for transfering

use std::{str::FromStr as _, time::Duration};

use super::*;

#[allow(clippy::expect_used)]
/// Can transfer user's assets permission token name.
pub static CAN_TRANSFER_USER_ASSETS_TOKEN: Lazy<Name> =
    Lazy::new(|| Name::from_str("can_transfer_user_assets").expect("Valid")); // See #1978

#[allow(clippy::expect_used)]
/// Can transfer only fixed number of times per some time period
pub static CAN_TRANSFER_ONLY_FIXED_NUMBER_OF_TIMES_PER_PERIOD: Lazy<Name> = Lazy::new(|| {
    Name::from_str("can_transfer_only_fixed_number_of_times_per_period").expect("Valid")
});
#[allow(clippy::expect_used)]
/// Name of `period` param for `CAN_TRANSFER_ONLY_FIXED_NUMBER_OF_TIMES_PER_PERIOD`
pub static PERIOD_PARAM_NAME: Lazy<Name> = Lazy::new(|| Name::from_str("period").expect("Valid"));
#[allow(clippy::expect_used)]
/// Name of `count` param for `CAN_TRANSFER_ONLY_FIXED_NUMBER_OF_TIMES_PER_PERIOD`
pub static COUNT_PARAM_NAME: Lazy<Name> = Lazy::new(|| Name::from_str("count").expect("Valid"));

/// Checks that account transfers only the assets that he owns.
#[derive(Debug, Copy, Clone)]
pub struct OnlyOwnedAssets;

impl_from_item_for_instruction_validator_box!(OnlyOwnedAssets);

impl<W: WorldTrait> IsAllowed<W, Instruction> for OnlyOwnedAssets {
    fn check(
        &self,
        authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView<W>,
    ) -> Result<(), DenialReason> {
        let transfer_box = if let Instruction::Transfer(transfer) = instruction {
            transfer
        } else {
            return Ok(());
        };
        let source_id = transfer_box
            .source_id
            .evaluate(wsv, &Context::new())
            .map_err(|e| e.to_string())?;
        let source_id: AssetId = try_into_or_exit!(source_id);

        if &source_id.account_id != authority {
            return Err("Can't transfer assets of the other account.".to_owned());
        }
        Ok(())
    }
}

/// Allows transfering user's assets from a different account if the
/// corresponding user granted this permission token.
#[derive(Debug, Clone, Copy)]
pub struct GrantedByAssetOwner;

impl_from_item_for_granted_token_validator_box!(GrantedByAssetOwner);

impl<W: WorldTrait> HasToken<W> for GrantedByAssetOwner {
    fn token(
        &self,
        _authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView<W>,
    ) -> Result<PermissionToken, String> {
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
        Ok(PermissionToken::new(CAN_TRANSFER_USER_ASSETS_TOKEN.clone())
            .with_params([(ASSET_ID_TOKEN_PARAM_NAME.to_owned(), source_id.into())]))
    }
}

/// Validator that checks Grant instruction so that the access is
/// granted to the assets of the signer account.
#[derive(Debug, Clone, Copy)]
pub struct GrantMyAssetAccess;

impl_from_item_for_grant_instruction_validator_box!(GrantMyAssetAccess);

impl<W: WorldTrait> IsGrantAllowed<W> for GrantMyAssetAccess {
    fn check_grant(
        &self,
        authority: &AccountId,
        instruction: &GrantBox,
        wsv: &WorldStateView<W>,
    ) -> Result<(), DenialReason> {
        let permission_token: PermissionToken = instruction
            .object
            .evaluate(wsv, &Context::new())
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|e: ErrorTryFromEnum<_, _>| e.to_string())?;
        if permission_token.name() != &*CAN_TRANSFER_USER_ASSETS_TOKEN {
            return Err("Grant instruction is not for transfer permission.".to_owned());
        }
        check_asset_owner_for_token(&permission_token, authority)
    }
}

/// Validator that checks that `Transfer` instruction execution count
/// fits well in some time period
#[derive(Debug, Clone, Copy)]
pub struct ExecutionCountFitsInLimit;

impl_from_item_for_instruction_validator_box!(ExecutionCountFitsInLimit);

impl<W: WorldTrait> IsAllowed<W, Instruction> for ExecutionCountFitsInLimit {
    #[allow(clippy::expect_used, clippy::unwrap_in_result)]
    fn check(
        &self,
        authority: &AccountId,
        instruction: &Instruction,
        wsv: &WorldStateView<W>,
    ) -> Result<(), DenialReason> {
        if !matches!(instruction, Instruction::Transfer(_)) {
            return Ok(());
        };

        let params = retrieve_permission_params(wsv, authority)?;
        if params.is_empty() {
            return Ok(());
        }

        let period = retrieve_period(&params)?;
        let count = retrieve_count(&params)?;
        let executions_count: u32 = count_executions(wsv, authority, period)
            .try_into()
            .expect("`usize` should always fit in `u32`");
        if executions_count >= count {
            return Err(DenialReason::from(
                "Transfer transaction limit for current period is exceed",
            ));
        }
        Ok(())
    }
}

/// Retrieve permission parameters for `ExecutionCountFitsInLimit` validator.
/// Returns empty collection if nothing found
///
/// # Errors
/// - Account doesn't exist
fn retrieve_permission_params<W: WorldTrait>(
    wsv: &WorldStateView<W>,
    authority: &AccountId,
) -> Result<BTreeMap<Name, Value>, DenialReason> {
    wsv.map_account(authority, |account| {
        wsv.account_permission_tokens(account)
            .iter()
            .filter(|token| token.name() == &*CAN_TRANSFER_ONLY_FIXED_NUMBER_OF_TIMES_PER_PERIOD)
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
fn retrieve_period(params: &BTreeMap<Name, Value>) -> Result<Duration, DenialReason> {
    match params
        .get(&*PERIOD_PARAM_NAME)
        .ok_or_else(|| format!("Expected `{}` parameter", *PERIOD_PARAM_NAME))?
    {
        Value::U128(period) => Ok(Duration::from_millis(
            u64::try_from(*period).map_err(|e| e.to_string())?,
        )),
        _ => Err(format!(
            "`{}` parameter has wrong value type. Expected `u128`",
            *PERIOD_PARAM_NAME
        )),
    }
}

/// Retrieve count from `params`
///
/// # Errors
/// - There is no count parameter
/// - Count has wrong value type
fn retrieve_count(params: &BTreeMap<Name, Value>) -> Result<u32, DenialReason> {
    match params
        .get(&*COUNT_PARAM_NAME)
        .ok_or_else(|| format!("Expected `{}` parameter", *COUNT_PARAM_NAME))?
    {
        Value::U32(count) => Ok(*count),
        _ => Err(format!(
            "`{}` parameter has wrong value type. Expected `u32`",
            *COUNT_PARAM_NAME
        )),
    }
}

/// Counts the number of `Transfer`s  which happened in the last `period`
fn count_executions<W: WorldTrait>(
    wsv: &WorldStateView<W>,
    authority: &AccountId,
    period: Duration,
) -> usize {
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
