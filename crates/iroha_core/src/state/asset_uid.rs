//! Additive native UID state in the existing consensus state map.
//!
//! No `World` field or pre-existing wire layout changes. Policy and membership
//! are owner-written; generic contract state access cannot write these roots.
use super::*;
use iroha_data_model::{
    asset::{
        AssetBalanceScope,
        uid::{AssetUidBindingV1, AssetUidPolicyV1, AssetUidUsageV1},
    },
    isi::error::{AssetTransferAdmissionError, InstructionExecutionError, MathError},
};
use iroha_primitives::numeric::Quantity;

pub(crate) const POLICY_ROOT: &str = "asset_uid_policy_v1/";
pub(crate) const BINDING_ROOT: &str = "asset_uid_binding_v1/";
pub(crate) const USAGE_ROOT: &str = "asset_uid_usage_v1/";
type Error = InstructionExecutionError;

fn reject(message: impl Into<String>) -> Error {
    Error::InvariantViolation(message.into().into())
}

fn digest(value: impl std::fmt::Display) -> String {
    hex::encode(Hash::new(value.to_string().as_bytes()).as_ref())
}

fn path(value: String) -> StatePath {
    value.parse().expect("fixed native asset UID path is valid")
}

pub(crate) fn policy_key(definition: &AssetDefinitionId, uid: &[u8; 32]) -> StatePath {
    path(format!(
        "{POLICY_ROOT}{}/{}",
        digest(definition),
        hex::encode(uid)
    ))
}

pub(crate) fn binding_key(definition: &AssetDefinitionId, account: &AccountId) -> StatePath {
    path(format!(
        "{BINDING_ROOT}{}/{}",
        digest(definition),
        digest(account)
    ))
}

pub(crate) fn usage_key(definition: &AssetDefinitionId, uid: &[u8; 32], day: u64) -> StatePath {
    path(format!(
        "{USAGE_ROOT}{}/{}/{day}",
        digest(definition),
        hex::encode(uid)
    ))
}

fn decode<T>(bytes: &[u8]) -> Result<T, Error>
where
    T: norito::NoritoSerialize,
    for<'de> T: norito::NoritoDeserialize<'de>,
{
    norito::decode_canonical(bytes).map_err(|e| reject(format!("invalid asset UID state: {e}")))
}

pub(crate) fn encode<T: norito::NoritoSerialize>(value: &T) -> Result<Vec<u8>, Error> {
    norito::encode_canonical(value)
        .map_err(|e| reject(format!("cannot encode asset UID state: {e}")))
}

pub(crate) fn policy(
    world: &impl WorldReadOnly,
    definition: &AssetDefinitionId,
    uid: &[u8; 32],
) -> Result<Option<AssetUidPolicyV1>, Error> {
    let Some(bytes) = world
        .smart_contract_state()
        .get(&policy_key(definition, uid))
    else {
        return Ok(None);
    };
    let value: AssetUidPolicyV1 = decode(bytes)?;
    value.validate_shape().map_err(reject)?;
    if &value.asset_definition_id != definition || &value.uid != uid {
        return Err(reject("asset UID policy differs from its canonical key"));
    }
    Ok(Some(value))
}

pub(crate) fn binding(
    world: &impl WorldReadOnly,
    definition: &AssetDefinitionId,
    account: &AccountId,
) -> Result<Option<AssetUidBindingV1>, Error> {
    let Some(bytes) = world
        .smart_contract_state()
        .get(&binding_key(definition, account))
    else {
        return Ok(None);
    };
    let value: AssetUidBindingV1 = decode(bytes)?;
    if &value.asset_definition_id != definition
        || &value.account_id != account
        || value.uid == [0; 32]
    {
        return Err(reject(
            "asset UID membership differs from its canonical key",
        ));
    }
    Ok(Some(value))
}

fn member_policy(
    world: &impl WorldReadOnly,
    definition: &AssetDefinitionId,
    account: &AccountId,
) -> Result<Option<AssetUidPolicyV1>, Error> {
    let Some(member) = binding(world, definition, account)? else {
        return Ok(None);
    };
    let value = policy(world, definition, &member.uid)?
        .ok_or_else(|| reject("asset UID membership has no policy"))?;
    if !value.accounts.contains(account) {
        return Err(reject("asset UID membership is absent from policy roster"));
    }
    Ok(Some(value))
}

/// Resolve beneficial ownership of retained native custody to its payer.
/// Native escrow admission separately seals who may debit that custody.
fn beneficial_policy(
    world: &impl WorldReadOnly,
    id: &AssetId,
) -> Result<Option<AssetUidPolicyV1>, Error> {
    if let Some(value) = member_policy(world, id.definition(), id.account())? {
        return Ok(Some(value));
    }
    for (_, escrow) in world.asset_escrows().iter() {
        if escrow.asset_definition == *id.definition()
            && escrow.custody == *id.account()
            && !escrow.remaining_amount.is_zero()
        {
            return member_policy(world, id.definition(), &escrow.seller);
        }
    }
    Ok(None)
}

fn balance(
    world: &impl WorldReadOnly,
    overrides: &BTreeMap<AssetId, Quantity>,
    id: &AssetId,
) -> Quantity {
    overrides.get(id).cloned().unwrap_or_else(|| {
        world
            .assets()
            .get(id)
            .map(|value| value.as_ref().clone())
            .unwrap_or_else(Quantity::zero)
    })
}

/// Sum exact member balances and retained payer-owned native escrow reserves.
/// Custody balances, rather than a pending record mutation, determine the amount
/// during release/refund. Thus returning funds to the payer has zero net effect.
pub(crate) fn holdings(
    world: &impl WorldReadOnly,
    policy: &AssetUidPolicyV1,
    overrides: &BTreeMap<AssetId, Quantity>,
) -> Result<Quantity, Error> {
    let mut total = Quantity::zero();
    for account in &policy.accounts {
        let id = AssetId::new(policy.asset_definition_id.clone(), account.clone());
        total = total
            .checked_add(&balance(world, overrides, &id))
            .map_err(|_| MathError::Overflow)?;
        for escrow_id in
            super::range_bounds::index_members(world.asset_escrows_by_seller(), account)
        {
            let escrow = world
                .asset_escrows()
                .get(escrow_id)
                .ok_or_else(|| reject("asset UID escrow index is inconsistent"))?;
            if escrow.asset_definition == policy.asset_definition_id
                && !escrow.remaining_amount.is_zero()
            {
                let id = AssetId::new(policy.asset_definition_id.clone(), escrow.custody.clone());
                total = total
                    .checked_add(&balance(world, overrides, &id))
                    .map_err(|_| MathError::Overflow)?;
            }
        }
    }
    Ok(total)
}

pub(crate) fn check_holdings(
    world: &impl WorldReadOnly,
    policy: &AssetUidPolicyV1,
    overrides: &BTreeMap<AssetId, Quantity>,
) -> Result<(), Error> {
    if let Some(limit) = &policy.holding_limit {
        let total = holdings(world, policy, overrides)?;
        // A policy reduction can leave existing holdings above its new cap.
        // Only an increase is refused: spending, same-UID moves and refunds
        // must remain possible without inventing receiving headroom.
        if total > *limit && total > holdings(world, policy, &BTreeMap::new())? {
            return Err(Error::AssetTransferAdmission(
                AssetTransferAdmissionError::HoldingLimitExceeded(
                    format!("identity-wide asset holding {total} exceeds {limit}").into(),
                ),
            ));
        }
    }
    Ok(())
}

/// Mint/other direct credit must use aggregate headroom, even outside Transfer.
pub(crate) fn check_credit(
    world: &impl WorldReadOnly,
    id: &AssetId,
    candidate: &Quantity,
) -> Result<(), Error> {
    if let Some(policy) = beneficial_policy(world, id)? {
        if id.scope() != &AssetBalanceScope::Global {
            return Err(reject("asset UID policy requires exact Global balances"));
        }
        check_holdings(
            world,
            &policy,
            &BTreeMap::from([(id.clone(), candidate.clone())]),
        )?;
    }
    Ok(())
}

fn usage(
    world: &impl WorldReadOnly,
    policy: &AssetUidPolicyV1,
    day: u64,
) -> Result<AssetUidUsageV1, Error> {
    let Some(bytes) =
        world
            .smart_contract_state()
            .get(&usage_key(&policy.asset_definition_id, &policy.uid, day))
    else {
        return Ok(AssetUidUsageV1 {
            asset_definition_id: policy.asset_definition_id.clone(),
            uid: policy.uid,
            daily_window: policy.daily_window,
            day_start_ms: day,
            amount: Quantity::zero(),
        });
    };
    let value: AssetUidUsageV1 = decode(bytes)?;
    if value.asset_definition_id != policy.asset_definition_id
        || value.uid != policy.uid
        || value.daily_window != policy.daily_window
        || value.day_start_ms != day
    {
        return Err(reject("asset UID activity differs from its canonical key"));
    }
    Ok(value)
}

/// One exact movement and whether its source consumes new activity.
/// Only sealed retained native custody releases may set `charge_activity=false`.
pub(crate) struct Movement<'a> {
    pub(crate) source: &'a AssetId,
    pub(crate) destination: &'a AssetId,
    pub(crate) amount: &'a Quantity,
    pub(crate) charge_activity: bool,
}

/// Validate a complete ordered occurrence against one exclusive World view.
///
/// Returning encoded writes lets the caller finish every fallible preflight
/// before writing balances. The state-map reads join sibling wallets to the
/// same native transaction conflict set; independent legs call this separately.
pub(crate) fn prepare_movements(
    world: &impl WorldReadOnly,
    movements: &[Movement<'_>],
    now_ms: u64,
) -> Result<Vec<(StatePath, Vec<u8>)>, Error> {
    let mut balances = BTreeMap::new();
    let mut activities = BTreeMap::<StatePath, AssetUidUsageV1>::new();
    for movement in movements {
        let source_policy = beneficial_policy(world, movement.source)?;
        let destination_policy = beneficial_policy(world, movement.destination)?;
        if (source_policy.is_some() || destination_policy.is_some())
            && (movement.source.definition() != movement.destination.definition()
                || movement.source.scope() != &AssetBalanceScope::Global
                || movement.destination.scope() != &AssetBalanceScope::Global)
        {
            return Err(reject(
                "asset UID movement requires one exact Global definition",
            ));
        }
        let destination_ceiling = destination_policy
            .as_ref()
            .map(|policy| {
                policy
                    .holding_limit
                    .as_ref()
                    .map(|limit| {
                        holdings(world, policy, &balances).map(|before| before.max(limit.clone()))
                    })
                    .transpose()
            })
            .transpose()?
            .flatten();
        let source_after = balance(world, &balances, movement.source)
            .checked_sub(movement.amount)
            .map_err(|_| MathError::NotEnoughQuantity)?;
        balances.insert(movement.source.clone(), source_after);
        let destination_after = balance(world, &balances, movement.destination)
            .checked_add(movement.amount)
            .map_err(|_| MathError::Overflow)?;
        balances.insert(movement.destination.clone(), destination_after);
        if let (Some(value), Some(ceiling)) = (&destination_policy, destination_ceiling) {
            if holdings(world, value, &balances)? > ceiling {
                return Err(Error::AssetTransferAdmission(
                    AssetTransferAdmissionError::HoldingLimitExceeded(
                        "identity-wide asset holding increase exceeds its current cap".into(),
                    ),
                ));
            }
        }
        if movement.charge_activity {
            // Only an actual wallet debit consumes activity. A conditional
            // custody source remains payer-owned but was charged when funded.
            if let Some(value) = member_policy(
                world,
                movement.source.definition(),
                movement.source.account(),
            )? {
                let day = value.daily_window.day_start_ms(now_ms).map_err(reject)?;
                let key = usage_key(&value.asset_definition_id, &value.uid, day);
                if !activities.contains_key(&key) {
                    activities.insert(key.clone(), usage(world, &value, day)?);
                }
                let current = activities.get_mut(&key).expect("activity inserted above");
                current.amount = current
                    .amount
                    .checked_add(movement.amount)
                    .map_err(|_| MathError::Overflow)?;
                if value
                    .daily_limit
                    .as_ref()
                    .is_some_and(|limit| current.amount > *limit)
                {
                    return Err(Error::AssetTransferAdmission(
                        AssetTransferAdmissionError::PolicyRejected(
                            "identity-wide asset calendar daily activity limit exceeded".into(),
                        ),
                    ));
                }
            }
        }
    }
    activities
        .into_iter()
        .map(|(key, value)| encode(&value).map(|bytes| (key, bytes)))
        .collect()
}

/// Retain the allowed beneficial holding ceiling before funding new custody.
pub(crate) fn opening_holding_ceiling(
    world: &impl WorldReadOnly,
    source: &AssetId,
) -> Result<Option<Quantity>, Error> {
    let Some(policy) = member_policy(world, source.definition(), source.account())? else {
        return Ok(None);
    };
    policy
        .holding_limit
        .as_ref()
        .map(|limit| {
            holdings(world, &policy, &BTreeMap::new()).map(|before| before.max(limit.clone()))
        })
        .transpose()
}

/// Check the newly funded escrow before retaining its payer-owned reserve.
/// This closes compound atomic settlements that both fund custody and credit
/// another wallet of the same UID before the escrow record is installed.
pub(crate) fn check_opening(
    world: &impl WorldReadOnly,
    escrow: &iroha_data_model::escrow::AssetEscrowRecord,
    holding_ceiling: Option<&Quantity>,
) -> Result<(), Error> {
    let Some(value) = member_policy(world, &escrow.asset_definition, &escrow.seller)? else {
        return Ok(());
    };
    if let Some(limit) = holding_ceiling {
        let total = holdings(world, &value, &BTreeMap::new())?
            .checked_add(&escrow.amount)
            .map_err(|_| MathError::Overflow)?;
        if total > *limit {
            return Err(Error::AssetTransferAdmission(
                AssetTransferAdmissionError::HoldingLimitExceeded(
                    "conditional escrow reserve exceeds identity-wide holding limit".into(),
                ),
            ));
        }
    }
    Ok(())
}

/// Materialize exact owner-query rows from the captured native state.
pub(crate) fn views(
    world: &impl WorldReadOnly,
    definition: &AssetDefinitionId,
    selected_uid: Option<&[u8; 32]>,
    ledger_time_ms: u64,
    as_of_height: u64,
) -> Result<Vec<iroha_data_model::asset::uid::AssetUidPolicyViewV1>, Error> {
    let mut policies = Vec::new();
    if let Some(uid) = selected_uid {
        if let Some(value) = policy(world, definition, uid)? {
            policies.push(value);
        }
    } else {
        let prefix = format!("{POLICY_ROOT}{}/", digest(definition));
        for (key, bytes) in world.smart_contract_state().iter() {
            if key.as_ref().starts_with(&prefix) {
                let value: AssetUidPolicyV1 = decode(bytes)?;
                if &value.asset_definition_id != definition
                    || key != &policy_key(definition, &value.uid)
                {
                    return Err(reject("asset UID query encountered a noncanonical policy"));
                }
                value.validate_shape().map_err(reject)?;
                policies.push(value);
            }
        }
    }
    policies
        .into_iter()
        .map(|policy| {
            let day_start_ms = policy
                .daily_window
                .day_start_ms(ledger_time_ms)
                .map_err(reject)?;
            let beneficial_holdings = holdings(world, &policy, &BTreeMap::new())?;
            let daily_usage = usage(world, &policy, day_start_ms)?.amount;
            Ok(iroha_data_model::asset::uid::AssetUidPolicyViewV1 {
                policy,
                beneficial_holdings,
                day_start_ms,
                daily_usage,
                ledger_time_ms,
                as_of_height,
            })
        })
        .collect()
}

fn in_root(key: &StatePath, root: &str) -> bool {
    key.as_ref() == root.trim_end_matches('/') || key.as_ref().starts_with(root)
}

/// Native policy retains definitions/accounts so delete-and-recreate cannot
/// discard membership or daily usage.
pub(crate) fn retained(
    world: &impl WorldReadOnly,
    definition: Option<&AssetDefinitionId>,
    account: Option<&AccountId>,
) -> Result<bool, Error> {
    for (key, bytes) in world.smart_contract_state().iter() {
        if in_root(key, POLICY_ROOT) {
            let value: AssetUidPolicyV1 = decode(bytes)?;
            if definition.is_some_and(|id| id == &value.asset_definition_id)
                || account.is_some_and(|id| value.accounts.contains(id))
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Validate additive state after restoring a snapshot, including old snapshots
/// with no UID roots. No defaults rewrite historical records or balances.
pub(crate) fn validate_persistence(world: &impl WorldReadOnly) -> Result<(), Error> {
    for (key, bytes) in world.smart_contract_state().iter() {
        if in_root(key, POLICY_ROOT) {
            let value: AssetUidPolicyV1 = decode(bytes)?;
            value.validate_shape().map_err(reject)?;
            if key != &policy_key(&value.asset_definition_id, &value.uid) {
                return Err(reject("noncanonical asset UID policy path"));
            }
            let definition = world.asset_definition(&value.asset_definition_id)?;
            if definition.balance_scope_policy()
                != iroha_data_model::asset::AssetBalancePolicy::Global
            {
                return Err(reject("asset UID policy requires a Global definition"));
            }
            for member in &value.accounts {
                world.account(member)?;
                if binding(world, &value.asset_definition_id, member)?
                    .is_none_or(|b| b.uid != value.uid)
                {
                    return Err(reject(
                        "asset UID policy is missing a reciprocal membership",
                    ));
                }
            }
        } else if in_root(key, BINDING_ROOT) {
            let value: AssetUidBindingV1 = decode(bytes)?;
            if key != &binding_key(&value.asset_definition_id, &value.account_id)
                || member_policy(world, &value.asset_definition_id, &value.account_id)?.is_none()
            {
                return Err(reject("orphan or noncanonical asset UID membership"));
            }
        } else if in_root(key, USAGE_ROOT) {
            let value: AssetUidUsageV1 = decode(bytes)?;
            if value
                .daily_window
                .day_start_ms(value.day_start_ms)
                .map_err(reject)?
                != value.day_start_ms
                || key != &usage_key(&value.asset_definition_id, &value.uid, value.day_start_ms)
                || policy(world, &value.asset_definition_id, &value.uid)?
                    .is_none_or(|policy| policy.daily_window != value.daily_window)
            {
                return Err(reject("orphan or noncanonical asset UID usage"));
            }
        }
    }
    Ok(())
}
