//! Exact controller grants and private beneficial-holdings quotes.

use super::*;
#[path = "asset_uid_reader/same_uid.rs"]
mod same_uid;
use crate::executor::ContractRuntimeExecutionContext;
use iroha_data_model::{
    asset::uid::{
        AssetUidBindingV1, AssetUidHoldingQuoteV1, AssetUidPolicyReaderV1, AssetUidPolicyV1,
    },
    isi::error::{InstructionExecutionError, MathError},
    query::error::QueryExecutionFail,
    smart_contract::ContractAddress,
};
use iroha_primitives::numeric::Quantity;
pub(crate) use same_uid::same_uid_for_contract;
#[cfg(test)]
pub(crate) use same_uid::tests::Fixture as SameUidReaderFixture;

pub(crate) const READER_ROOT: &str = "asset_uid_reader_v1/";
type Error = InstructionExecutionError;

fn reject(message: &str) -> Error {
    Error::InvariantViolation(message.into())
}

pub(crate) fn reader_key(
    definition: &AssetDefinitionId,
    controller: &ContractAddress,
) -> StatePath {
    format!(
        "{READER_ROOT}{}/{}",
        hex::encode(Hash::new(definition.to_string().as_bytes()).as_ref()),
        hex::encode(Hash::new(controller.subject_id().to_string().as_bytes()).as_ref())
    )
    .parse()
    .expect("fixed native UID reader path")
}

pub(crate) fn reader(
    world: &impl WorldReadOnly,
    definition: &AssetDefinitionId,
    controller: &ContractAddress,
) -> Result<Option<AssetUidPolicyReaderV1>, Error> {
    let Some(bytes) = world
        .smart_contract_state()
        .get(&reader_key(definition, controller))
    else {
        return Ok(None);
    };
    let value: AssetUidPolicyReaderV1 =
        norito::decode_canonical(bytes).map_err(|_| reject("invalid native UID reader grant"))?;
    if &value.asset_definition_id != definition
        || &value.controller != controller
        || value.revision == 0
    {
        return Err(reject(
            "native UID reader grant differs from its canonical key",
        ));
    }
    Ok(Some(value))
}

/// A native policy failure and a query resource refusal remain distinct.
#[derive(Debug)]
pub(crate) enum AssetUidHoldingQuoteError {
    Execution(InstructionExecutionError),
    Query(QueryExecutionFail),
    Local(crate::execution_attempt::ExecutionDeferred),
}
impl From<InstructionExecutionError> for AssetUidHoldingQuoteError {
    fn from(value: InstructionExecutionError) -> Self {
        Self::Execution(value)
    }
}
impl From<QueryExecutionFail> for AssetUidHoldingQuoteError {
    fn from(value: QueryExecutionFail) -> Self {
        Self::Query(value)
    }
}

fn metered_decode<T>(
    bytes: &[u8],
    budget: crate::smartcontracts::isi::query::QueryExecutionBudget,
    stats: &mut crate::smartcontracts::isi::query::QueryExecutionStats,
) -> Result<T, AssetUidHoldingQuoteError>
where
    T: norito::NoritoSerialize,
    for<'de> T: norito::NoritoDeserialize<'de>,
{
    let length = u64::try_from(bytes.len()).map_err(|_| QueryExecutionFail::GasBudgetExceeded)?;
    stats.record_preflighted_item(length, Some(budget))?;
    let allocation =
        usize::try_from(budget.remaining_bytes(stats.processed_items(), stats.processed_bytes())?)
            .map_err(|_| QueryExecutionFail::CapacityLimit)?;
    let elements = bytes
        .len()
        .checked_mul(8)
        .ok_or(QueryExecutionFail::CapacityLimit)?;
    let limits = norito::DecodeLimits::new(elements, bytes.len(), elements, allocation, 64);
    norito::decode_canonical_for_admission(bytes, limits).map_err(|error| {
        match error.into_local_refusal() {
            Ok(original) => AssetUidHoldingQuoteError::Local(original.into()),
            Err(error) if error.error().is_decode_resource_limit() => {
                AssetUidHoldingQuoteError::Query(QueryExecutionFail::GasBudgetExceeded)
            }
            Err(_) => {
                AssetUidHoldingQuoteError::Execution(reject("invalid canonical UID quote source"))
            }
        }
    })
}

fn clone_account(account: &AccountId) -> Result<AccountId, AssetUidHoldingQuoteError> {
    norito::core::classify_decode_attempt(|| account.try_clone_for_admission()).map_err(|error| {
        match error.into_local_refusal() {
            Ok(original) => AssetUidHoldingQuoteError::Local(original.into()),
            Err(_) => {
                AssetUidHoldingQuoteError::Execution(reject("invalid native account in UID quote"))
            }
        }
    })
}

/// Quote only to the exact authenticated, owner-granted controller within a shared query budget.
///
/// Every member and seller-index row is charged before inspection, including
/// terminal and other-asset escrows. Unknown policies fail without liquid fallback.
#[allow(clippy::too_many_arguments)]
pub(crate) fn quote_for_contract(
    world: &impl WorldReadOnly,
    authority: &AccountId,
    context: &ContractRuntimeExecutionContext,
    definition: &AssetDefinitionId,
    account: &AccountId,
    incoming: &Quantity,
    budget: crate::smartcontracts::isi::query::QueryExecutionBudget,
) -> Result<
    (
        AssetUidHoldingQuoteV1,
        crate::smartcontracts::isi::query::QueryExecutionStats,
    ),
    AssetUidHoldingQuoteError,
> {
    use crate::smartcontracts::isi::query::QueryExecutionStats;
    let mut stats = QueryExecutionStats::default();
    // The active-frame check touches a fixed number of exact native bindings.
    stats.record_item(&context.contract_address, Some(budget))?;
    if !crate::executor::valid_contract_runtime_subject_for_admission(
        world,
        authority,
        Some(context),
    )
    .map_err(AssetUidHoldingQuoteError::Local)?
    {
        return Err(reject("UID quote requires its exact active contract runtime").into());
    }
    let bytes = world
        .smart_contract_state()
        .get(&reader_key(definition, &context.contract_address))
        .ok_or_else(|| reject("contract has no asset-owner UID quote grant"))?;
    let grant: AssetUidPolicyReaderV1 = metered_decode(bytes, budget, &mut stats)?;
    if grant.asset_definition_id != *definition
        || grant.controller != context.contract_address
        || grant.revision == 0
        || !grant.enabled
    {
        return Err(reject("contract UID quote grant is invalid or revoked").into());
    }
    world
        .asset_definition(definition)
        .map_err(InstructionExecutionError::from)?
        .spec()
        .check(incoming.as_numeric())
        .map_err(|_| reject("UID quote incoming amount violates asset precision"))?;
    let bytes = world
        .smart_contract_state()
        .get(&super::asset_uid::binding_key(definition, account))
        .ok_or_else(|| reject("UID quote requires an installed account policy"))?;
    let binding: AssetUidBindingV1 = metered_decode(bytes, budget, &mut stats)?;
    if binding.asset_definition_id != *definition
        || binding.account_id != *account
        || binding.uid == [0; 32]
    {
        return Err(reject("UID quote membership differs from its native key").into());
    }
    let bytes = world
        .smart_contract_state()
        .get(&super::asset_uid::policy_key(definition, &binding.uid))
        .ok_or_else(|| reject("UID quote membership has no policy"))?;
    let policy: AssetUidPolicyV1 = metered_decode(bytes, budget, &mut stats)?;
    policy.validate_shape().map_err(reject)?;
    if policy.asset_definition_id != *definition
        || policy.uid != binding.uid
        || !policy.accounts.contains(account)
    {
        return Err(reject("UID quote policy differs from its native membership").into());
    }
    let mut beneficial_holdings = Quantity::zero();
    for member in &policy.accounts {
        stats.record_item(member, Some(budget))?;
        let asset = AssetId::new(definition.clone(), clone_account(member)?);
        if let Some(amount) = world.assets().get(&asset) {
            stats.record_item(amount.as_ref(), Some(budget))?;
            beneficial_holdings = beneficial_holdings
                .checked_add(amount.as_ref())
                .map_err(|_| InstructionExecutionError::from(MathError::Overflow))?;
        }
        for escrow_id in super::range_bounds::index_members(world.asset_escrows_by_seller(), member)
        {
            stats.record_item(escrow_id, Some(budget))?;
            let escrow = world
                .asset_escrows()
                .get(escrow_id)
                .ok_or_else(|| reject("UID quote escrow index is inconsistent"))?;
            stats.record_item(escrow, Some(budget))?;
            if escrow.asset_definition == *definition && !escrow.remaining_amount.is_zero() {
                let asset = AssetId::new(definition.clone(), clone_account(&escrow.custody)?);
                if let Some(amount) = world.assets().get(&asset) {
                    stats.record_item(amount.as_ref(), Some(budget))?;
                    beneficial_holdings = beneficial_holdings
                        .checked_add(amount.as_ref())
                        .map_err(|_| InstructionExecutionError::from(MathError::Overflow))?;
                }
            }
        }
    }
    let total = beneficial_holdings
        .checked_add(incoming)
        .map_err(|_| InstructionExecutionError::from(MathError::Overflow))?;
    let required_overflow = match &policy.holding_limit {
        Some(cap) if total > *cap => total
            .checked_sub(cap)
            .map_err(|_| InstructionExecutionError::from(MathError::Overflow))?,
        _ => Quantity::zero(),
    };
    let quote = AssetUidHoldingQuoteV1 {
        asset_definition_id: definition.clone(),
        account_id: clone_account(account)?,
        policy_revision: policy.revision,
        beneficial_holdings,
        holding_limit: policy.holding_limit,
        required_overflow,
    };
    stats.record_response(&quote, Some(budget))?;
    Ok((quote, stats))
}

pub(crate) fn retained(
    world: &impl WorldReadOnly,
    definition: Option<&AssetDefinitionId>,
    account: Option<&AccountId>,
) -> Result<bool, Error> {
    for (key, bytes) in world.smart_contract_state().iter() {
        if key.as_ref().starts_with(READER_ROOT) {
            let value: AssetUidPolicyReaderV1 = norito::decode_canonical(bytes)
                .map_err(|_| reject("invalid native UID reader grant"))?;
            if definition == Some(&value.asset_definition_id)
                || account == Some(&value.controller.subject_id())
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Revoked grants remain canonical state and never restore as an implicit grant.
pub(crate) fn validate_persistence(world: &impl WorldReadOnly) -> Result<(), Error> {
    for (key, bytes) in world.smart_contract_state().iter() {
        if key.as_ref() == READER_ROOT.trim_end_matches('/')
            || key.as_ref().starts_with(READER_ROOT)
        {
            let value: AssetUidPolicyReaderV1 = norito::decode_canonical(bytes)
                .map_err(|_| reject("invalid native UID reader grant"))?;
            if key != &reader_key(&value.asset_definition_id, &value.controller)
                || reader(world, &value.asset_definition_id, &value.controller)?.is_none()
                || world
                    .asset_definition(&value.asset_definition_id)?
                    .balance_scope_policy()
                    != iroha_data_model::asset::AssetBalancePolicy::Global
            {
                return Err(reject("orphan or noncanonical UID reader grant"));
            }
            world.account(&value.controller.subject_id())?;
        }
    }
    Ok(())
}
