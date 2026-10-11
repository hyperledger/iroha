//! Exact unsettled-wallet frontier for safe historical staking reward retirement.

use super::*;
use std::collections::BTreeMap;

const FRONTIER_PREFIX: &str = "retail_fee_control_v1/reward_month/";
const CLOSED_KEY: &str = "retail_fee_control_v1/reward_closed_through";

fn frontier_period(record: &RetailFeeAccountStateV1) -> Option<u64> {
    (record.closed_at_ms.is_none() || record.active_time_ms != 0)
        .then_some(record.billing_month_start_ms)
}

fn frontier_key(record: &RetailFeeAccountStateV1) -> Option<StatePath> {
    frontier_period(record).map(|period| {
        format!(
            "{FRONTIER_PREFIX}{period:020}/{}",
            hex::encode(Hash::new(record.account_id.to_string().as_bytes()).as_ref())
        )
        .parse()
        .expect("canonical retail reward frontier key")
    })
}

fn closed_key() -> StatePath {
    CLOSED_KEY
        .parse()
        .expect("canonical retail reward closure key")
}

fn read_u64(world: &impl WorldReadOnly, path: &StatePath) -> Result<Option<u64>, FeeReadError> {
    world
        .smart_contract_state()
        .get(path)
        .map(|bytes| {
            norito::decode_canonical(bytes)
                .map_err(|error| norito_decode_attempt_error(error, |error| error.to_string()))
        })
        .transpose()
}

/// Last earning month durably sealed against any further authentic fee credit.
pub(crate) fn reward_history_closed_through(
    world: &impl WorldReadOnly,
) -> Result<Option<u64>, FeeReadError> {
    read_u64(world, &closed_key())
}

/// Refuse any new fee credit or enrollment referring to retired earning history.
pub(crate) fn ensure_reward_history_open(
    world: &impl WorldReadOnly,
    period: u64,
) -> Result<(), FeeReadError> {
    if read_u64(world, &closed_key())?.is_some_and(|closed| period <= closed) {
        return Err("fee credit refers to permanently closed reward history"
            .to_owned()
            .into());
    }
    Ok(())
}

/// Maintain exactly one bounded frontier row per wallet that can still earn fees.
pub(super) fn update(
    world: &mut WorldTransaction<'_, '_>,
    previous: Option<&RetailFeeAccountStateV1>,
    next: Option<&RetailFeeAccountStateV1>,
) -> Result<(), InstructionExecutionError> {
    let old_key = previous.and_then(frontier_key);
    let new_key = next.and_then(frontier_key);
    if let Some(period) = next.and_then(frontier_period) {
        ensure_reward_history_open(world, period)
            .map_err(|error| world_read_error(world, error))?;
    }
    if let Some(old_key) = &old_key {
        if read_u64(world, old_key).map_err(|error| world_read_error(world, error))? != Some(1) {
            return Err(invalid("retail reward frontier is absent or malformed"));
        }
    }
    if old_key == new_key {
        return Ok(());
    }
    if let Some(new_key) = &new_key {
        if world.smart_contract_state.get(new_key).is_some() {
            return Err(invalid("retail reward frontier already exists"));
        }
    }
    let encoded = norito::to_bytes(&1u64)
        .map_err(|error| norito_decode_attempt_error(error, |error| error.to_string()))
        .map_err(|error| world_read_error(world, error))?;
    if let Some(old_key) = old_key {
        world.smart_contract_state.remove(old_key);
    }
    if let Some(new_key) = new_key {
        world.smart_contract_state.insert(new_key, encoded);
    }
    Ok(())
}

/// Permanently close a completed earning month only after every wallet has passed it.
///
/// The ordered index makes this constant work. New enrollment starts in the
/// current month; reopening settles its retained period first. Queued original-
/// month credits must be flushed before the durable closure seal can advance.
pub(crate) fn reward_history_is_closed(
    stx: &mut StateTransaction<'_, '_>,
    period: u64,
) -> Result<bool, InstructionExecutionError> {
    if honiara_month_bounds(period).map_err(invalid)?.0 != period {
        return Err(invalid(
            "reward history closure requires a canonical earning month",
        ));
    }
    if read_u64(&stx.world, &closed_key())
        .map_err(|error| world_read_error(&stx.world, error))?
        .is_some_and(|closed| period <= closed)
    {
        return Ok(true);
    }
    if period
        >= honiara_month_bounds(stx.block_unix_timestamp_ms())
            .map_err(invalid)?
            .0
        || stx
            .world
            .retail_fee_pending_credits
            .iter()
            .any(|(_, earning, _)| *earning <= period)
    {
        return Ok(false);
    }
    let start: StatePath = FRONTIER_PREFIX
        .parse()
        .expect("canonical retail frontier prefix");
    if let Some((path, _)) = stx
        .world
        .smart_contract_state
        .range(start..)
        .next()
        .filter(|(path, _)| path.as_ref().starts_with(FRONTIER_PREFIX))
    {
        let first = path
            .as_ref()
            .strip_prefix(FRONTIER_PREFIX)
            .and_then(|suffix| suffix.split('/').next())
            .and_then(|month| month.parse::<u64>().ok())
            .ok_or_else(|| invalid("malformed retail reward frontier month"))?;
        if read_u64(&stx.world, path).map_err(|error| world_read_error(&stx.world, error))?
            != Some(1)
        {
            return Err(invalid("malformed retail reward frontier value"));
        }
        if first <= period {
            return Ok(false);
        }
    }
    let encoded = norito::to_bytes(&period)
        .map_err(|error| norito_decode_attempt_error(error, |error| error.to_string()))
        .map_err(|error| world_read_error(&stx.world, error))?;
    stx.world.smart_contract_state.insert(closed_key(), encoded);
    Ok(true)
}

/// Reconcile the exact index and closure invariant on current and rollback restoration.
pub(crate) fn validate_reward_history_frontier(
    world: &impl WorldReadOnly,
) -> Result<(), FeeReadError> {
    let mut expected = BTreeMap::new();
    let mut actual = BTreeMap::new();
    let closed = read_u64(world, &closed_key())?;
    if let Some(period) = closed {
        if honiara_month_bounds(period)?.0 != period {
            return Err("noncanonical closed reward history month".to_owned().into());
        }
    }
    for (path, bytes) in world.smart_contract_state().iter() {
        if path.as_ref().starts_with(STATE_PREFIX) {
            let record: RetailFeeAccountStateV1 = norito::decode_canonical(bytes)
                .map_err(|error| norito_decode_attempt_error(error, |error| error.to_string()))?;
            if *path != key(&record.account_id) {
                return Err("retail reward frontier source has a noncanonical identity"
                    .to_owned()
                    .into());
            }
            if let Some(frontier) = frontier_key(&record) {
                if closed.is_some_and(|closed| record.billing_month_start_ms <= closed) {
                    return Err("unsettled wallet precedes closed reward history"
                        .to_owned()
                        .into());
                }
                expected.insert(frontier, 1u64);
            }
        } else if path.as_ref().starts_with(FRONTIER_PREFIX) {
            actual.insert(
                path.clone(),
                read_u64(world, path)?.ok_or("retail reward frontier disappeared")?,
            );
        }
    }
    if expected != actual {
        return Err(
            "retail reward history frontier differs from unsettled wallets"
                .to_owned()
                .into(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_data_model::IntoKeyValue;
    use iroha_test_samples::{ALICE_ID, BOB_ID};

    const OPENED: u64 = 1_793_451_600_000;

    #[test]
    fn original_month_history_waits_for_late_wallet_collection_and_credit_flush() {
        let period = honiara_month_bounds(OPENED).unwrap().0;
        let now = honiara_month_bounds(OPENED).unwrap().1 + 1_000;
        crate::retail_fee_tests::fixture(now, |stx, policy| {
            // The shared fixture registers deterministic accounts 2 through 14.
            // An asset row alone does not make an absent wallet's funds available.
            let owner = AccountId::new(
                iroha_crypto::KeyPair::from_seed(vec![3; 32], iroha_crypto::Algorithm::Ed25519)
                    .public_key()
                    .clone(),
            );
            let asset = AssetId::new(policy.ds_asset_id.clone(), owner.clone());
            let (_, balance) = Asset::new(asset.clone(), quantity(10_000)).into_key_value();
            stx.world.assets.insert(asset.clone(), balance);
            let record = RetailFeeAccountStateV1::enroll(owner.clone(), OPENED, 10_000).unwrap();
            write_account(&mut stx.world, &record).unwrap();
            assert!(!reward_history_is_closed(stx, period).unwrap());
            settle_balance_until(&mut stx.world, &asset, now).unwrap();
            assert!(
                stx.world
                    .retail_fee_pending_credits
                    .iter()
                    .any(|(_, earning, amount)| *earning == period && *amount > 0)
            );
            assert!(
                !reward_history_is_closed(stx, period).unwrap(),
                "unflushed original-month collection blocks closure"
            );
            finalize(stx).unwrap();
            assert!(stx.world.retail_fee_pending_credits.is_empty());
            assert!(reward_history_is_closed(stx, period).unwrap());
            assert!(ensure_reward_history_open(&stx.world, period).is_err());
            assert!(
                crate::validation_fee_rewards::credit_collected_fee(stx, &policy, period, 1)
                    .is_err(),
                "late authentic credits cannot silently recreate pruned history"
            );
            validate_reward_history_frontier(&stx.world).unwrap();
        });
    }

    #[test]
    fn wallet_recovery_and_closure_keep_exact_frontier_without_lifetime_rows() {
        let period = honiara_month_bounds(OPENED).unwrap().0;
        let now = honiara_month_bounds(OPENED).unwrap().1 + 1_000;
        crate::retail_fee_tests::fixture(now, |stx, _| {
            let record = RetailFeeAccountStateV1::enroll(ALICE_ID.clone(), OPENED, 0).unwrap();
            write_account(&mut stx.world, &record).unwrap();
            finish_rekey(stx, &ALICE_ID, &BOB_ID).unwrap();
            assert!(
                stx.world
                    .smart_contract_state
                    .get(&frontier_key(&record).unwrap())
                    .is_none()
            );
            let mut recovered = account_state(&stx.world, &BOB_ID).unwrap().unwrap();
            validate_reward_history_frontier(&stx.world).unwrap();
            assert!(!reward_history_is_closed(stx, period).unwrap());
            recovered.closed_at_ms = Some(OPENED);
            recovered.active_time_ms = 1;
            write_account(&mut stx.world, &recovered).unwrap();
            assert!(
                !reward_history_is_closed(stx, period).unwrap(),
                "unsettled closing month retains its frontier"
            );
            recovered.active_time_ms = 0;
            write_account(&mut stx.world, &recovered).unwrap();
            assert!(reward_history_is_closed(stx, period).unwrap());
            validate_reward_history_frontier(&stx.world).unwrap();
            assert!(
                write_account(&mut stx.world, &record).is_err(),
                "retired history cannot be enrolled again"
            );
        });
    }

    #[test]
    fn restart_rejects_missing_or_fabricated_unsettled_month_frontier() {
        crate::retail_fee_tests::fixture(OPENED, |stx, _| {
            let record = RetailFeeAccountStateV1::enroll(ALICE_ID.clone(), OPENED, 0).unwrap();
            write_account(&mut stx.world, &record).unwrap();
            let path = frontier_key(&record).unwrap();
            validate_reward_history_frontier(&stx.world).unwrap();
            stx.world.smart_contract_state.remove(path.clone());
            assert!(validate_reward_history_frontier(&stx.world).is_err());
            stx.world
                .smart_contract_state
                .insert(path.clone(), norito::to_bytes(&2u64).unwrap());
            assert!(validate_reward_history_frontier(&stx.world).is_err());
            stx.world
                .smart_contract_state
                .insert(path, norito::to_bytes(&1u64).unwrap());
            validate_reward_history_frontier(&stx.world).unwrap();
            stx.world.smart_contract_state.insert(
                closed_key(),
                norito::to_bytes(&record.billing_month_start_ms).unwrap(),
            );
            assert!(validate_reward_history_frontier(&stx.world).is_err());
        });
    }

    #[test]
    fn rejected_wallet_update_rolls_back_frontier_and_closure_seal() {
        let period = honiara_month_bounds(OPENED).unwrap().0;
        let now = honiara_month_bounds(OPENED).unwrap().1 + 1_000;
        crate::retail_fee_tests::fixture_block(now, |block, _| {
            let record = RetailFeeAccountStateV1::enroll(ALICE_ID.clone(), OPENED, 0).unwrap();
            {
                let mut stx = block.transaction();
                write_account(&mut stx.world, &record).unwrap();
                stx.apply();
            }
            {
                let mut stx = block.transaction();
                let mut advanced = record.clone();
                advanced
                    .settle_until(now, true, |_| Ok((1, RetailFeeScheduleV1::default())))
                    .unwrap();
                write_account(&mut stx.world, &advanced).unwrap();
                assert!(reward_history_is_closed(&mut stx, period).unwrap());
                // Dropping the rejected transaction restores wallet, frontier, and seal.
            }
            let mut stx = block.transaction();
            assert!(!reward_history_is_closed(&mut stx, period).unwrap());
            assert!(ensure_reward_history_open(&stx.world, period).is_ok());
            validate_reward_history_frontier(&stx.world).unwrap();
        });
    }
}
