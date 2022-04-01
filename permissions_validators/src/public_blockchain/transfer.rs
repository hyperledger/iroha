//! Module with permission for transfering

use std::{str::FromStr as _, sync::RwLock, time::Duration};

use super::*;

#[allow(clippy::expect_used)]
/// Can transfer user's assets permission token name.
pub static CAN_TRANSFER_USER_ASSETS_TOKEN: Lazy<Name> =
    Lazy::new(|| Name::from_str("can_transfer_user_assets").expect("Tested. Works.")); // See #1978

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
        let mut params = BTreeMap::new();
        params.insert(ASSET_ID_TOKEN_PARAM_NAME.to_owned(), source_id.into());
        Ok(PermissionToken::new(
            CAN_TRANSFER_USER_ASSETS_TOKEN.clone(),
            params,
        ))
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
        if permission_token.name != CAN_TRANSFER_USER_ASSETS_TOKEN.clone() {
            return Err("Grant instruction is not for transfer permission.".to_owned());
        }
        check_asset_owner_for_token(&permission_token, authority)
    }
}

/// Validator that checks `Transfer` instruction so that it can be used fixed number of times per
/// set time. E.g. 5 times per day
#[derive(Debug)]
pub struct TransferOnlyFixedNumberOfTimesForPeriod {
    count: u32,
    period: Duration,
    last_execution_time: RwLock<Option<Duration>>,
    execution_count: RwLock<u32>,
}

impl_from_item_for_instruction_validator_box!(TransferOnlyFixedNumberOfTimesForPeriod);

impl<W: WorldTrait> IsAllowed<W, Instruction> for TransferOnlyFixedNumberOfTimesForPeriod {
    fn check(
        &self,
        _authority: &AccountId,
        instruction: &Instruction,
        _wsv: &WorldStateView<W>,
    ) -> Result<(), DenialReason> {
        if !matches!(instruction, Instruction::Transfer(_)) {
            return Ok(());
        };

        let cur_time = current_time();
        let execution_count = *self.execution_count.read().map_err(|e| e.to_string())?;
        let mut execution_count_write = self.execution_count.write().map_err(|e| e.to_string())?;
        if let Some(last) = *self.last_execution_time.read().map_err(|e| e.to_string())? {
            if execution_count >= self.count {
                if last + self.period < cur_time {
                    return Err(DenialReason::from(
                        "Transfer transaction limit for current period is exceed",
                    ));
                }
                *execution_count_write = 0;
            }
        }

        *execution_count_write += 1;
        *self
            .last_execution_time
            .write()
            .map_err(|e| e.to_string())? = Some(cur_time);
        Ok(())
    }
}

impl TransferOnlyFixedNumberOfTimesForPeriod {
    /// Create new `TransferOnlyFixedNumberOfTimesForPeriod`
    pub fn new(count: u32, period: Duration) -> Self {
        Self {
            count,
            period,
            last_execution_time: RwLock::new(None),
            execution_count: RwLock::new(0),
        }
    }
}
