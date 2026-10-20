//! Host execution for exact-consent atomic payments, bilateral settlements and native FX corridors.
use super::*;
mod atomic;
use crate::smartcontracts::isi::asset::isi::{
    assert_numeric_spec_with, execute_native_fx_numeric_asset_pair,
    validate_authorized_numeric_asset_pair, validate_native_fx_numeric_asset_pair,
};
#[cfg(test)]
use crate::smartcontracts::isi::error::MathError;
#[cfg(feature = "telemetry")]
use crate::status::SettlementOutcomeKind;
pub(in crate::smartcontracts::isi) use atomic::VerifiedSettlementNumericBatch;
pub(crate) use atomic::admission_validate_atomic;
#[cfg(any(feature = "telemetry", test))]
use iroha_data_model::isi::error::{AssetTransferAdmissionError, InstructionEvaluationError};
use iroha_data_model::isi::{ResolvedSettlementMovement, SettlementDetails};
use iroha_data_model::{
    asset::{AssetBalancePolicy, AssetBalanceScope, AssetId},
    events::data::prelude::{ConfigurationEvent, ParameterChanged},
    isi::{
        error::{InstructionExecutionError, InvalidParameterError},
        settlement::{
            DvpIsi, FundFxCorridorEscrow, FxCorridorPolicy, FxCorridorPolicyRegistry,
            FxCorridorUsage, PvpIsi, RefundFxCorridorEscrow, SetFxCorridorPolicy, SettleFxCorridor,
            SettlementExecutionOrder, SettlementInstructionBox, SettlementLeg,
        },
    },
    oracle::FeedEventOutcome,
    prelude::*,
};
use iroha_executor_data_model::permission::settlement::{
    CanExecuteSettlement, CanManageFxCorridors, CanSetFxCorridorPolicy,
};
use iroha_model_base::metadata::Metadata;
use iroha_model_base::name::Name;
use iroha_model_base::topology::DataSpaceId;
use iroha_primitives::{
    json::Json,
    numeric::{Numeric, NumericSpec, Quantity},
};
use std::collections::BTreeSet;
#[cfg_attr(not(feature = "telemetry"), allow(dead_code))]
pub(crate) const SETTLEMENT_KIND_DVP: &str = "dvp";
#[cfg_attr(not(feature = "telemetry"), allow(dead_code))]
pub(crate) const SETTLEMENT_KIND_PVP: &str = "pvp";
pub(crate) const CAN_SET_FX_CORRIDOR_POLICY: &str = "CanSetFxCorridorPolicy";
/// Non-reusable proof that bilateral consent selected two exact settlement legs.
pub(in crate::smartcontracts::isi) struct VerifiedSettlementNumericPair {
    authority: AccountId,
    binding: Vec<u8>,
    legs: [(AssetId, AssetId, Quantity); 2],
}
impl VerifiedSettlementNumericPair {
    fn new<T: norito::NoritoSerialize>(
        authority: AccountId,
        binding: &T,
        legs: [(AssetId, AssetId, Quantity); 2],
    ) -> Result<Self, Error> {
        let binding = norito::encode_canonical(binding).map_err(|error| {
            InstructionExecutionError::InvariantViolation(
                format!("failed to encode exact settlement movement binding: {error}").into(),
            )
        })?;
        Ok(Self {
            authority,
            binding,
            legs,
        })
    }
    pub(in crate::smartcontracts::isi) fn into_parts(
        self,
    ) -> (AccountId, Vec<u8>, [(AssetId, AssetId, Quantity); 2]) {
        (self.authority, self.binding, self.legs)
    }
}
impl Execute for SettlementInstructionBox {
    fn execute(
        self,
        authority: &AccountId,
        stx: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        match self {
            SettlementInstructionBox::Dvp(isi) => isi.execute(authority, stx),
            SettlementInstructionBox::Pvp(isi) => isi.execute(authority, stx),
            SettlementInstructionBox::Atomic(isi) => isi.execute(authority, stx),
            SettlementInstructionBox::SetFxCorridorPolicy(isi) => isi.execute(authority, stx),
            SettlementInstructionBox::FundFxCorridorEscrow(isi) => isi.execute(authority, stx),
            SettlementInstructionBox::RefundFxCorridorEscrow(isi) => isi.execute(authority, stx),
            SettlementInstructionBox::SettleFxCorridor(isi) => isi.execute(authority, stx),
        }
    }
}
#[cfg(any(feature = "telemetry", test))]
fn settlement_failure_reason(err: &Error) -> &'static str {
    match err {
        InstructionExecutionError::InvariantViolation(message) => {
            let msg = message.as_ref();
            if msg.contains("non-zero") {
                "zero_quantity"
            } else if msg.contains("reciprocal") {
                "counterparty_mismatch"
            } else if msg.contains("available") || msg.contains("requires") {
                "insufficient_funds"
            } else {
                "other"
            }
        }
        InstructionExecutionError::Find(_) => "missing_entity",
        InstructionExecutionError::Math(_) => "math_error",
        InstructionExecutionError::Evaluate(InstructionEvaluationError::Type(_)) => "type_error",
        InstructionExecutionError::AssetTransferAdmission(
            AssetTransferAdmissionError::HoldingLimitExceeded(_),
        ) => "holding_limit_exceeded",
        _ => "other",
    }
}
fn settlement_receipt(
    stx: &StateTransaction<'_, '_>,
    authority: &AccountId,
    metadata: Metadata,
    details: SettlementDetails,
) -> SettlementReceipt {
    SettlementReceipt {
        authority: authority.clone(),
        metadata,
        details,
        block_height: stx._curr_block.height().get(),
        block_hash: stx._curr_block.hash(),
        executed_at_ms: u64::try_from(stx._curr_block.creation_time().as_millis())
            .unwrap_or(u64::MAX),
    }
}
fn resolved_settlement_movement(
    assets: &(AssetId, AssetId),
    leg: &SettlementLeg,
) -> ResolvedSettlementMovement {
    ResolvedSettlementMovement {
        source: assets.0.clone(),
        destination: assets.1.clone(),
        quantity: leg.quantity().clone(),
        metadata: leg.metadata().clone(),
    }
}
fn has_exact_permission(
    stx: &StateTransaction<'_, '_>,
    authority: &AccountId,
    required: &Permission,
) -> bool {
    if stx
        .world
        .account_permissions
        .get(authority)
        .is_some_and(|permissions| permissions.contains(required))
    {
        return true;
    }
    stx.world
        .account_roles
        .iter()
        .filter_map(|(role_key, ())| {
            if &role_key.account == authority {
                stx.world.roles.get(&role_key.id)
            } else {
                None
            }
        })
        .any(|role| role.permissions().any(|permission| permission == required))
}
fn can_manage_fx_corridors(stx: &StateTransaction<'_, '_>, authority: &AccountId) -> bool {
    let manager: Permission = CanManageFxCorridors.into();
    has_exact_permission(stx, authority, &manager)
}
fn can_set_fx_corridor_policy(
    stx: &StateTransaction<'_, '_>,
    authority: &AccountId,
    policy_id: &Name,
) -> bool {
    let exact: Permission = CanSetFxCorridorPolicy {
        policy_id: policy_id.clone(),
    }
    .into();
    can_manage_fx_corridors(stx, authority) || has_exact_permission(stx, authority, &exact)
}
fn invalid_fx_parameter(message: impl Into<String>) -> Error {
    InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
        message.into(),
    ))
}
fn fx_policy_registry(stx: &StateTransaction<'_, '_>) -> Result<FxCorridorPolicyRegistry, Error> {
    let parameters = stx.world.parameters.get();
    let Some(custom) = parameters
        .custom()
        .get(&FxCorridorPolicyRegistry::parameter_id())
    else {
        return Ok(FxCorridorPolicyRegistry::default());
    };
    FxCorridorPolicyRegistry::from_custom_parameter(custom)
        .map_err(|err| invalid_fx_parameter(format!("invalid FX corridor policy registry: {err}")))?
        .ok_or_else(|| invalid_fx_parameter("FX corridor policy registry id mismatch"))
}
pub(in crate::smartcontracts::isi) fn fx_policy(
    stx: &StateTransaction<'_, '_>,
    policy_id: &Name,
) -> Result<FxCorridorPolicy, Error> {
    fx_policy_registry(stx)?
        .get(policy_id)
        .cloned()
        .ok_or_else(|| invalid_fx_parameter(format!("FX corridor policy `{policy_id}` not found")))
}
fn validate_fx_policy_entities(
    stx: &StateTransaction<'_, '_>,
    policy: &FxCorridorPolicy,
) -> Result<(), Error> {
    if let Some(message) = policy.invariant_error() {
        return Err(invalid_fx_parameter(message));
    }
    ensure_account_exists(stx, &policy.owner)?;
    let feed = stx
        .world
        .oracle_feeds
        .get(&policy.oracle_feed_id)
        .ok_or_else(|| {
            invalid_fx_parameter(format!(
                "FX corridor oracle feed `{}` is not registered",
                policy.oracle_feed_id
            ))
        })?;
    if feed.feed_id != policy.oracle_feed_id {
        return Err(invalid_fx_parameter(
            "FX corridor oracle feed key does not match its canonical feed identity",
        ));
    }
    stx.nexus
        .dataspace_catalog
        .by_id(policy.source_dataspace)
        .ok_or_else(|| {
            invalid_fx_parameter(format!(
                "FX corridor source dataspace {} is absent from the active catalog",
                policy.source_dataspace.as_u64()
            ))
        })?;
    let destination_dataspace = stx
        .nexus
        .dataspace_catalog
        .by_id(policy.destination_dataspace)
        .ok_or_else(|| {
            invalid_fx_parameter(format!(
                "FX corridor destination dataspace {} is absent from the active catalog",
                policy.destination_dataspace.as_u64()
            ))
        })?;
    if policy
        .allowed_destination_alias_domains
        .iter()
        .any(|domain| domain.dataspace().as_ref() != destination_dataspace.alias.as_str())
    {
        return Err(invalid_fx_parameter(format!(
            "FX corridor destination alias domains must use the `{}` dataspace scope",
            destination_dataspace.alias
        )));
    }
    for asset_definition_id in [
        &policy.source_asset_definition_id,
        &policy.destination_asset_definition_id,
    ] {
        let definition = stx.world.asset_definition(asset_definition_id)?;
        if definition.balance_scope_policy() != AssetBalancePolicy::DataspaceRestricted {
            return Err(invalid_fx_parameter(format!(
                "FX corridor asset `{asset_definition_id}` must use DataspaceRestricted balances"
            )));
        }
    }
    Ok(())
}
fn ensure_account_exists(stx: &StateTransaction<'_, '_>, account: &AccountId) -> Result<(), Error> {
    stx.world.account(account).map_err(Error::from)?;
    Ok(())
}
fn ensure_leg_accounts(stx: &StateTransaction<'_, '_>, leg: &SettlementLeg) -> Result<(), Error> {
    ensure_account_exists(stx, leg.from())?;
    ensure_account_exists(stx, leg.to())?;
    Ok(())
}
fn resolve_settlement_leg_source_asset_id(
    stx: &StateTransaction<'_, '_>,
    leg: &SettlementLeg,
) -> Result<AssetId, Error> {
    stx.world.resolve_asset_id_for_current_scope(&AssetId::new(
        leg.asset_definition_id().clone(),
        leg.from().clone(),
    ))
}
fn resolve_settlement_leg_asset_ids(
    stx: &StateTransaction<'_, '_>,
    leg: &SettlementLeg,
) -> Result<(AssetId, AssetId), Error> {
    let withdraw = resolve_settlement_leg_source_asset_id(stx, leg)?;
    let deposit = AssetId::with_scope(
        leg.asset_definition_id().clone(),
        leg.to().clone(),
        withdraw.scope().clone(),
    );
    Ok((withdraw, deposit))
}
fn resolve_authorized_settlement_leg_asset_ids(
    stx: &StateTransaction<'_, '_>,
    leg: &SettlementLeg,
    authorized_source: AssetId,
) -> Result<(AssetId, AssetId), Error> {
    if authorized_source.account() != leg.from()
        || authorized_source.definition() != leg.asset_definition_id()
    {
        return Err(InstructionExecutionError::InvariantViolation(
            "settlement consent asset does not match the debited leg".into(),
        ));
    }
    let definition = stx
        .world
        .asset_definition(authorized_source.definition())
        .map_err(Error::from)?;
    let dataspace_hint = match (definition.balance_scope_policy(), authorized_source.scope()) {
        (AssetBalancePolicy::Global, AssetBalanceScope::Global) => None,
        (AssetBalancePolicy::DataspaceRestricted, AssetBalanceScope::Dataspace(dataspace)) => {
            Some(*dataspace)
        }
        (AssetBalancePolicy::Global, AssetBalanceScope::Dataspace(_)) => {
            return Err(InstructionExecutionError::InvariantViolation(
                "settlement consent cannot attach a dataspace scope to a global asset".into(),
            ));
        }
        (AssetBalancePolicy::DataspaceRestricted, AssetBalanceScope::Global) => {
            return Err(InstructionExecutionError::InvariantViolation(
                "settlement consent must name the exact dataspace balance for a restricted asset"
                    .into(),
            ));
        }
    };
    let withdraw = stx
        .world
        .resolve_asset_id_for_scope_hint(&authorized_source, dataspace_hint)?;
    let deposit = AssetId::with_scope(
        leg.asset_definition_id().clone(),
        leg.to().clone(),
        withdraw.scope().clone(),
    );
    Ok((withdraw, deposit))
}
fn ensure_leg_quantity(leg: &SettlementLeg) -> Result<(), Error> {
    if leg.quantity().is_zero() {
        return Err(InstructionExecutionError::InvariantViolation(
            "settlement legs must specify non-zero quantities".into(),
        ));
    }
    Ok(())
}
fn scoped_fx_leg_asset_ids(leg: &SettlementLeg, dataspace: DataSpaceId) -> (AssetId, AssetId) {
    let scope = AssetBalanceScope::Dataspace(dataspace);
    (
        AssetId::with_scope(
            leg.asset_definition_id().clone(),
            leg.from().clone(),
            scope.clone(),
        ),
        AssetId::with_scope(leg.asset_definition_id().clone(), leg.to().clone(), scope),
    )
}
fn exact_fx_destination_amount(
    source_amount: &Quantity,
    destination_spec: NumericSpec,
    rate: iroha_data_model::oracle::ObservationValue,
) -> Result<Quantity, Error> {
    if rate.mantissa <= 0 {
        return Err(invalid_fx_parameter(
            "FX corridor oracle rate must be positive",
        ));
    }
    let destination_amount = source_amount
        .try_mul_div_decimal_exact(
            &Numeric::new(rate.mantissa, rate.scale),
            &Numeric::from(1_u32),
        )
        .map_err(|err| {
            invalid_fx_parameter(format!(
                "FX corridor rate does not produce an exact destination quantity: {err}"
            ))
        })?;
    assert_numeric_spec_with(destination_amount.as_numeric(), destination_spec)?;
    if destination_amount.is_zero() {
        return Err(invalid_fx_parameter(
            "FX corridor destination quantity must be non-zero",
        ));
    }
    Ok(destination_amount)
}
fn fx_corridor_escrow_account(
    stx: &StateTransaction<'_, '_>,
    policy: &FxCorridorPolicy,
) -> AccountId {
    iroha_data_model::isi::settlement::fx_corridor_escrow_account_id_v1(
        &stx.network_id,
        &policy.corridor_id(),
        &policy.destination_asset_definition_id,
    )
}
fn persist_fx_policy_registry(
    stx: &mut StateTransaction<'_, '_>,
    registry: FxCorridorPolicyRegistry,
) {
    let next = registry.into_custom_parameter();
    let previous = {
        let parameters = stx.world.parameters.get_mut();
        let previous = parameters.custom().get(next.id()).cloned();
        parameters
            .set_parameter(Parameter::Custom(next.clone()))
            .expect("FX corridor registry is not a pipeline fee parameter");
        previous.unwrap_or_else(|| next.clone())
    };
    stx.world
        .emit_events(Some(ConfigurationEvent::Changed(ParameterChanged {
            old_value: Parameter::Custom(previous),
            new_value: Parameter::Custom(next),
        })));
}
fn validate_fx_oracle_evidence(
    stx: &StateTransaction<'_, '_>,
    policy: &FxCorridorPolicy,
    instruction: &SettleFxCorridor,
) -> Result<(iroha_data_model::oracle::ObservationValue, u64), Error> {
    let feed = stx
        .world
        .oracle_feeds
        .get(&policy.oracle_feed_id)
        .ok_or_else(|| invalid_fx_parameter("FX corridor oracle feed is not registered"))?;
    let evidence = &instruction.oracle_evidence;
    if (&evidence.feed_id, evidence.feed_config_version)
        != (&policy.oracle_feed_id, feed.feed_config_version)
    {
        return Err(invalid_fx_parameter(
            "FX settlement oracle evidence does not match the active corridor feed version",
        ));
    }
    let record = stx
        .world
        .oracle_history
        .get(&policy.oracle_feed_id)
        .and_then(|history| history.last())
        .ok_or_else(|| invalid_fx_parameter("FX corridor oracle feed has no retained event"))?;
    let event = &record.event;
    if event.feed_id != evidence.feed_id
        || event.feed_config_version != evidence.feed_config_version
        || event.slot != evidence.slot
        || event.request_hash != evidence.request_hash
        || iroha_crypto::HashOf::new(event) != evidence.event_hash
    {
        return Err(invalid_fx_parameter(
            "FX settlement oracle evidence does not identify the latest retained event",
        ));
    }
    let now_ms = stx.block_unix_timestamp_ms();
    let age_ms = now_ms.checked_sub(record.recorded_at_ms).ok_or_else(|| {
        invalid_fx_parameter("FX corridor oracle event is dated after consensus time")
    })?;
    if age_ms > policy.max_oracle_age_ms {
        return Err(invalid_fx_parameter(format!(
            "FX corridor oracle event is stale by {age_ms}ms"
        )));
    }
    let FeedEventOutcome::Success(success) = &event.outcome else {
        return Err(invalid_fx_parameter(
            "FX corridor latest oracle event is not successful",
        ));
    };
    if success.value.mantissa <= 0 {
        return Err(invalid_fx_parameter(
            "FX corridor oracle rate must be positive",
        ));
    }
    Ok((success.value, record.recorded_at_ms))
}
fn next_fx_corridor_usage(
    registry: &FxCorridorPolicyRegistry,
    policy: &FxCorridorPolicy,
    now_ms: u64,
    source_amount: &Quantity,
    destination_amount: &Quantity,
) -> Result<FxCorridorUsage, Error> {
    if source_amount > &policy.max_source_amount_per_settlement
        || destination_amount > &policy.max_destination_amount_per_settlement
    {
        return Err(invalid_fx_parameter(
            "FX corridor per-settlement exposure limit exceeded",
        ));
    }
    let window_start_ms = now_ms - (now_ms % policy.velocity_window_ms);
    let mut usage = registry
        .usage(&policy.policy_id)
        .filter(|usage| usage.window_start_ms == window_start_ms)
        .cloned()
        .unwrap_or_else(|| FxCorridorUsage {
            window_start_ms,
            settlements: 0,
            source_amount: Quantity::zero(),
            destination_amount: Quantity::zero(),
        });
    usage.settlements = usage
        .settlements
        .checked_add(1)
        .ok_or_else(|| invalid_fx_parameter("FX corridor settlement counter overflow"))?;
    usage.source_amount = usage
        .source_amount
        .checked_add(source_amount)
        .map_err(|err| invalid_fx_parameter(format!("FX corridor source usage overflow: {err}")))?;
    usage.destination_amount = usage
        .destination_amount
        .checked_add(destination_amount)
        .map_err(|err| {
            invalid_fx_parameter(format!("FX corridor destination usage overflow: {err}"))
        })?;
    if usage.settlements > policy.max_settlements_per_window
        || usage.source_amount > policy.max_source_amount_per_window
        || usage.destination_amount > policy.max_destination_amount_per_window
    {
        return Err(invalid_fx_parameter(
            "FX corridor deterministic velocity limit exceeded",
        ));
    }
    Ok(usage)
}
fn ensure_settlement_id_unused(
    stx: &StateTransaction<'_, '_>,
    settlement_id: &SettlementId,
) -> Result<(), Error> {
    if stx.world.settlement_receipts.get(settlement_id).is_some() {
        return Err(InstructionExecutionError::InvariantViolation(
            format!("settlement id `{settlement_id}` has already been committed").into(),
        ));
    }
    Ok(())
}
fn ensure_settlement_namespace_owner(
    settlement_id: &SettlementId,
    debit_owners: &[&AccountId],
) -> Result<(), Error> {
    if !debit_owners.contains(&settlement_id.owner()) {
        return Err(InstructionExecutionError::InvariantViolation(
            "settlement id owner must participate as an authorized debit owner".into(),
        ));
    }
    Ok(())
}
fn ensure_bilateral_settlement_shape(
    first_leg: &SettlementLeg,
    second_leg: &SettlementLeg,
) -> Result<(), Error> {
    if first_leg.from() == first_leg.to() {
        return Err(InstructionExecutionError::InvariantViolation(
            "bilateral settlement requires two distinct counterparties".into(),
        ));
    }
    if first_leg.asset_definition_id() == second_leg.asset_definition_id() {
        return Err(InstructionExecutionError::InvariantViolation(
            "bilateral settlement legs must use distinct asset definitions".into(),
        ));
    }
    Ok(())
}
fn settlement_consent_sources(
    stx: &StateTransaction<'_, '_>,
    authority: &AccountId,
    settlement_id: &SettlementId,
    intent_hash: Hash,
) -> BTreeSet<AssetId> {
    let direct_permissions = stx
        .world
        .account_permissions
        .get(authority)
        .into_iter()
        .flat_map(BTreeSet::iter);
    let role_permissions = stx
        .world
        .account_roles
        .iter()
        .filter_map(|(role_key, ())| {
            (&role_key.account == authority)
                .then(|| stx.world.roles.get(&role_key.id))
                .flatten()
        })
        .flat_map(|role| role.permissions());
    direct_permissions
        .chain(role_permissions)
        .filter_map(|permission| CanExecuteSettlement::try_from(permission).ok())
        .filter(|consent| {
            consent.settlement_id == *settlement_id && consent.intent_hash == intent_hash
        })
        .map(|consent| consent.debited_asset)
        .collect::<BTreeSet<_>>()
}
/// Resolve one exact balance authorized by an owner-issued bilateral consent.
///
/// Grant/revoke validation permits only `debited_asset.account()` to issue the
/// capability. Callers additionally bind the capability to their own
/// domain-separated complete-intent hash and a one-shot settlement identifier.
pub(super) fn ensure_bilateral_counterparty_consent(
    stx: &StateTransaction<'_, '_>,
    authority: &AccountId,
    debited_account: &AccountId,
    asset_definition_id: &AssetDefinitionId,
    settlement_id: &SettlementId,
    intent_hash: Hash,
) -> Result<AssetId, Error> {
    let authorized_sources = settlement_consent_sources(stx, authority, settlement_id, intent_hash)
        .into_iter()
        .filter(|source| {
            source.account() == debited_account && source.definition() == asset_definition_id
        })
        .collect::<BTreeSet<_>>();
    let mut sources = authorized_sources.into_iter();
    let Some(source) = sources.next() else {
        return Err(InstructionExecutionError::InvariantViolation(
            format!(
                "bilateral settlement requires exact consent from debited account `{debited_account}`"
            )
            .into(),
        ));
    };
    if sources.next().is_some() {
        return Err(InstructionExecutionError::InvariantViolation(
            "bilateral settlement consent is ambiguous across multiple balance scopes".into(),
        ));
    }
    Ok(source)
}
fn validate_dvp_preconditions(
    authority: &AccountId,
    stx: &mut StateTransaction<'_, '_>,
    settlement_id: &SettlementId,
    intent_hash: Hash,
    delivery_leg: &SettlementLeg,
    payment_leg: &SettlementLeg,
) -> Result<((AssetId, AssetId), (AssetId, AssetId)), Error> {
    ensure_settlement_namespace_owner(settlement_id, &[delivery_leg.from(), payment_leg.from()])?;
    ensure_settlement_id_unused(stx, settlement_id)?;
    if delivery_leg.from() != authority {
        return Err(InstructionExecutionError::InvariantViolation(
            "DvP delivery leg must be authorised by the delivering account".into(),
        ));
    }
    if delivery_leg.to() != payment_leg.from() || payment_leg.to() != delivery_leg.from() {
        return Err(InstructionExecutionError::InvariantViolation(
            "DvP counterparties must be reciprocal across delivery and payment legs".into(),
        ));
    }
    ensure_bilateral_settlement_shape(delivery_leg, payment_leg)?;
    let payment_source = ensure_bilateral_counterparty_consent(
        stx,
        authority,
        payment_leg.from(),
        payment_leg.asset_definition_id(),
        settlement_id,
        intent_hash,
    )?;
    ensure_leg_quantity(delivery_leg)?;
    ensure_leg_quantity(payment_leg)?;
    ensure_leg_accounts(stx, delivery_leg)?;
    ensure_leg_accounts(stx, payment_leg)?;
    let delivery_assets = resolve_settlement_leg_asset_ids(stx, delivery_leg)?;
    let payment_assets =
        resolve_authorized_settlement_leg_asset_ids(stx, payment_leg, payment_source)?;
    validate_authorized_numeric_asset_pair(
        stx,
        authority,
        delivery_assets.0.clone(),
        delivery_assets.1.clone(),
        delivery_leg.quantity().clone(),
        payment_assets.0.clone(),
        payment_assets.1.clone(),
        payment_leg.quantity().clone(),
    )?;
    Ok((delivery_assets, payment_assets))
}
fn validate_pvp_preconditions(
    authority: &AccountId,
    stx: &mut StateTransaction<'_, '_>,
    settlement_id: &SettlementId,
    intent_hash: Hash,
    primary_leg: &SettlementLeg,
    counter_leg: &SettlementLeg,
) -> Result<((AssetId, AssetId), (AssetId, AssetId)), Error> {
    ensure_settlement_namespace_owner(settlement_id, &[primary_leg.from(), counter_leg.from()])?;
    ensure_settlement_id_unused(stx, settlement_id)?;
    if primary_leg.from() != authority {
        return Err(InstructionExecutionError::InvariantViolation(
            "PvP primary leg must be authorised by the initiating account".into(),
        ));
    }
    if primary_leg.to() != counter_leg.from() || counter_leg.to() != primary_leg.from() {
        return Err(InstructionExecutionError::InvariantViolation(
            "PvP counterparties must be reciprocal across primary and counter legs".into(),
        ));
    }
    ensure_bilateral_settlement_shape(primary_leg, counter_leg)?;
    let counter_source = ensure_bilateral_counterparty_consent(
        stx,
        authority,
        counter_leg.from(),
        counter_leg.asset_definition_id(),
        settlement_id,
        intent_hash,
    )?;
    ensure_leg_quantity(primary_leg)?;
    ensure_leg_quantity(counter_leg)?;
    ensure_leg_accounts(stx, primary_leg)?;
    ensure_leg_accounts(stx, counter_leg)?;
    let primary_assets = resolve_settlement_leg_asset_ids(stx, primary_leg)?;
    let counter_assets =
        resolve_authorized_settlement_leg_asset_ids(stx, counter_leg, counter_source)?;
    validate_authorized_numeric_asset_pair(
        stx,
        authority,
        primary_assets.0.clone(),
        primary_assets.1.clone(),
        primary_leg.quantity().clone(),
        counter_assets.0.clone(),
        counter_assets.1.clone(),
        counter_leg.quantity().clone(),
    )?;
    Ok((primary_assets, counter_assets))
}
struct ValidatedFxSettlement {
    policy: FxCorridorPolicy,
    source_leg: SettlementLeg,
    destination_leg: SettlementLeg,
    oracle_rate: iroha_data_model::oracle::ObservationValue,
    oracle_recorded_at_ms: u64,
    next_usage: FxCorridorUsage,
}
fn validate_fx_settlement_preconditions(
    authority: &AccountId,
    stx: &mut StateTransaction<'_, '_>,
    instruction: &SettleFxCorridor,
) -> Result<ValidatedFxSettlement, Error> {
    ensure_settlement_namespace_owner(&instruction.settlement_id, &[authority])?;
    ensure_settlement_id_unused(stx, &instruction.settlement_id)?;
    let policy = fx_policy(stx, &instruction.policy_id)?;
    validate_fx_policy_entities(stx, &policy)?;
    if !policy.enabled {
        return Err(InstructionExecutionError::InvariantViolation(
            format!("FX corridor policy `{}` is disabled", policy.policy_id).into(),
        ));
    }
    if authority == &policy.owner {
        return Err(invalid_fx_parameter(
            "FX corridor settlement source must differ from the corridor owner",
        ));
    }
    if instruction.expected_policy_revision != policy.revision {
        return Err(invalid_fx_parameter(format!(
            "FX corridor policy revision mismatch: expected {}, active {}",
            instruction.expected_policy_revision, policy.revision
        )));
    }
    if instruction.source_asset_definition_id != policy.source_asset_definition_id
        || instruction.destination_asset_definition_id != policy.destination_asset_definition_id
    {
        return Err(invalid_fx_parameter(
            "FX corridor instruction assets do not match the active policy",
        ));
    }
    let destination_escrow = fx_corridor_escrow_account(stx, &policy);
    if instruction.recipient == destination_escrow {
        return Err(invalid_fx_parameter(
            "FX corridor recipient must differ from the protocol escrow",
        ));
    }
    ensure_account_exists(stx, &destination_escrow)?;
    ensure_account_exists(stx, &instruction.recipient)?;
    let mut matched_domains = BTreeSet::new();
    for alias in stx.world.bound_account_aliases(&instruction.recipient) {
        let resolved = crate::sns::resolve_active_account_alias(
            &stx.world,
            &stx.nexus.dataspace_catalog,
            &alias,
            stx.block_unix_timestamp_ms(),
        )
        .map_err(|error| {
            match error.into_attempt_error(|error| {
                invalid_fx_parameter(format!("invalid FX recipient SNS alias state: {error}"))
            }) {
                crate::execution_attempt::ExecutionAttemptError::Rejected(error) => error,
                crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => {
                    let _ = stx.defer_execution(reason);
                    InstructionExecutionError::InvariantViolation(
                        "local SNS execution did not complete".into(),
                    )
                }
            }
        })?;
        if resolved.as_ref() != Some(&instruction.recipient)
            || alias.dataspace != policy.destination_dataspace
        {
            continue;
        }
        let domain = alias
            .domain_id(&stx.nexus.dataspace_catalog)
            .map_err(|err| {
                invalid_fx_parameter(format!("invalid FX recipient alias domain binding: {err}"))
            })?;
        if let Some(domain) = domain
            && policy.allowed_destination_alias_domains.contains(&domain)
        {
            matched_domains.insert(domain);
        }
    }
    match matched_domains.len() {
        1 => {}
        0 => {
            return Err(invalid_fx_parameter(
                "FX corridor recipient has no alias in an allowed destination domain",
            ));
        }
        _ => {
            return Err(invalid_fx_parameter(
                "FX corridor recipient alias domain is ambiguous",
            ));
        }
    }
    if instruction.source_amount.is_zero() {
        return Err(invalid_fx_parameter(
            "FX corridor source quantity must be positive",
        ));
    }
    let source_spec = stx
        .numeric_spec_for(&policy.source_asset_definition_id)
        .map_err(Error::from)?;
    let destination_spec = stx
        .numeric_spec_for(&policy.destination_asset_definition_id)
        .map_err(Error::from)?;
    assert_numeric_spec_with(instruction.source_amount.as_numeric(), source_spec)?;
    let (oracle_rate, oracle_recorded_at_ms) =
        validate_fx_oracle_evidence(stx, &policy, instruction)?;
    let destination_amount =
        exact_fx_destination_amount(&instruction.source_amount, destination_spec, oracle_rate)?;
    if destination_amount != instruction.expected_destination_amount {
        return Err(invalid_fx_parameter(
            "FX corridor oracle output does not match the signed expected destination amount",
        ));
    }
    let registry = fx_policy_registry(stx)?;
    let next_usage = next_fx_corridor_usage(
        &registry,
        &policy,
        stx.block_unix_timestamp_ms(),
        &instruction.source_amount,
        &destination_amount,
    )?;
    let source_leg = SettlementLeg::new(
        policy.source_asset_definition_id.clone(),
        instruction.source_amount.clone(),
        authority.clone(),
        policy.owner.clone(),
    );
    let destination_leg = SettlementLeg::new(
        policy.destination_asset_definition_id.clone(),
        destination_amount,
        destination_escrow,
        instruction.recipient.clone(),
    );
    let (source_id, source_destination_id) =
        scoped_fx_leg_asset_ids(&source_leg, policy.source_dataspace);
    let (destination_source_id, destination_id) =
        scoped_fx_leg_asset_ids(&destination_leg, policy.destination_dataspace);
    validate_native_fx_numeric_asset_pair(
        stx,
        authority,
        source_id,
        source_destination_id,
        source_leg.quantity().clone(),
        destination_source_id,
        destination_id,
        destination_leg.quantity().clone(),
        &policy,
    )?;
    Ok(ValidatedFxSettlement {
        policy,
        source_leg,
        destination_leg,
        oracle_rate,
        oracle_recorded_at_ms,
        next_usage,
    })
}
impl Execute for SetFxCorridorPolicy {
    fn execute(
        self,
        authority: &AccountId,
        stx: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        if !can_set_fx_corridor_policy(stx, authority, &self.policy.policy_id) {
            return Err(InstructionExecutionError::InvariantViolation(
                format!(
                    "not permitted: exact {CAN_SET_FX_CORRIDOR_POLICY} for policy `{}` is required",
                    self.policy.policy_id
                )
                .into(),
            ));
        }
        validate_fx_policy_entities(stx, &self.policy)?;
        let mut registry = fx_policy_registry(stx)?;
        let expected_revision = match registry.get(&self.policy.policy_id) {
            Some(previous) => {
                if previous.owner != self.policy.owner
                    || previous.corridor_id() != self.policy.corridor_id()
                {
                    return Err(invalid_fx_parameter(
                        "FX corridor owner and canonical corridor identity are immutable",
                    ));
                }
                previous
                    .revision
                    .checked_add(1)
                    .ok_or_else(|| invalid_fx_parameter("FX corridor policy revision overflow"))?
            }
            None => {
                let escrow = fx_corridor_escrow_account(stx, &self.policy);
                if stx.world.account(&escrow).is_ok() {
                    return Err(invalid_fx_parameter(
                        "FX corridor registration requires its deterministic protocol escrow account to be absent",
                    ));
                }
                1
            }
        };
        if self.policy.revision != expected_revision {
            return Err(invalid_fx_parameter(format!(
                "FX corridor policy revision must be {expected_revision}"
            )));
        }
        registry.upsert(self.policy);
        persist_fx_policy_registry(stx, registry);
        Ok(())
    }
}
fn validate_fx_escrow_instruction(
    authority: &AccountId,
    stx: &mut StateTransaction<'_, '_>,
    policy_id: &Name,
    expected_policy_revision: u64,
    destination_asset_definition_id: &AssetDefinitionId,
    amount: &Quantity,
    require_disabled: bool,
) -> Result<FxCorridorPolicy, Error> {
    let policy = fx_policy(stx, policy_id)?;
    validate_fx_policy_entities(stx, &policy)?;
    if authority != &policy.owner {
        return Err(InstructionExecutionError::InvariantViolation(
            "only the exact FX corridor owner may fund or refund its protocol escrow".into(),
        ));
    }
    if policy.revision != expected_policy_revision
        || &policy.destination_asset_definition_id != destination_asset_definition_id
    {
        return Err(invalid_fx_parameter(
            "FX escrow instruction does not match the active policy revision and destination asset",
        ));
    }
    if require_disabled && policy.enabled {
        return Err(invalid_fx_parameter(
            "FX corridor reserve may be refunded only while the policy is disabled",
        ));
    }
    if amount.is_zero() {
        return Err(invalid_fx_parameter(
            "FX corridor escrow amount must be positive",
        ));
    }
    let spec = stx
        .numeric_spec_for(destination_asset_definition_id)
        .map_err(Error::from)?;
    assert_numeric_spec_with(amount.as_numeric(), spec)?;
    Ok(policy)
}
impl Execute for FundFxCorridorEscrow {
    fn execute(
        self,
        authority: &AccountId,
        stx: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let policy = validate_fx_escrow_instruction(
            authority,
            stx,
            &self.policy_id,
            self.expected_policy_revision,
            &self.destination_asset_definition_id,
            &self.amount,
            false,
        )?;
        let escrow = fx_corridor_escrow_account(stx, &policy);
        crate::smartcontracts::isi::domain::isi::ensure_controller_capabilities(
            escrow.controller(),
            &stx.crypto.allowed_signing,
            &stx.crypto.allowed_curve_ids,
        )?;
        if stx.world.account(&escrow).is_err() {
            let account = Account::new(escrow.clone()).build(&escrow);
            let (id, account) = iroha_data_model::IntoKeyValue::into_key_value(account);
            stx.world.accounts.insert(id, account);
        }
        crate::smartcontracts::isi::asset::isi::execute_fx_corridor_owner_funding(
            stx,
            authority,
            &policy,
            self.amount,
        )
    }
}
impl Execute for RefundFxCorridorEscrow {
    fn execute(
        self,
        authority: &AccountId,
        stx: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let policy = validate_fx_escrow_instruction(
            authority,
            stx,
            &self.policy_id,
            self.expected_policy_revision,
            &self.destination_asset_definition_id,
            &self.amount,
            true,
        )?;
        crate::smartcontracts::isi::asset::isi::execute_fx_corridor_owner_refund(
            stx,
            authority,
            &policy,
            self.amount,
        )
    }
}
pub(crate) fn admission_validate_fx_corridor(
    authority: &AccountId,
    stx: &mut StateTransaction<'_, '_>,
    instruction: &SettleFxCorridor,
) -> Result<(), Error> {
    let _ = validate_fx_settlement_preconditions(authority, stx, instruction)?;
    Ok(())
}
impl Execute for SettleFxCorridor {
    fn execute(
        self,
        authority: &AccountId,
        stx: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let validated = validate_fx_settlement_preconditions(authority, stx, &self)?;
        let ValidatedFxSettlement {
            policy,
            source_leg,
            destination_leg,
            oracle_rate,
            oracle_recorded_at_ms,
            next_usage,
        } = validated;
        let (source_id, source_destination_id) =
            scoped_fx_leg_asset_ids(&source_leg, policy.source_dataspace);
        let (destination_source_id, destination_id) =
            scoped_fx_leg_asset_ids(&destination_leg, policy.destination_dataspace);
        let mut registry = fx_policy_registry(stx)?;
        let mut metadata = Metadata::default();
        metadata.insert(
            "fx_corridor_policy_id"
                .parse()
                .expect("valid FX corridor metadata key"),
            Json::new(policy.policy_id.to_string()),
        );
        metadata.insert(
            "fx_source_dataspace"
                .parse()
                .expect("valid FX source-dataspace metadata key"),
            Json::new(policy.source_dataspace.as_u64()),
        );
        metadata.insert(
            "fx_destination_dataspace"
                .parse()
                .expect("valid FX destination-dataspace metadata key"),
            Json::new(policy.destination_dataspace.as_u64()),
        );
        let receipt = settlement_receipt(
            stx,
            authority,
            metadata,
            SettlementDetails::FxCorridor(iroha_data_model::isi::FxCorridorSettlementDetails {
                source: resolved_settlement_movement(
                    &(source_id.clone(), source_destination_id.clone()),
                    &source_leg,
                ),
                destination: resolved_settlement_movement(
                    &(destination_source_id.clone(), destination_id.clone()),
                    &destination_leg,
                ),
                context: FxCorridorPricingContext {
                    policy_id: policy.policy_id.clone(),
                    policy_revision: policy.revision,
                    oracle_evidence: self.oracle_evidence.clone(),
                    oracle_recorded_at_ms,
                    oracle_rate,
                },
            }),
        );
        execute_native_fx_numeric_asset_pair(
            stx,
            authority,
            source_id,
            source_destination_id,
            source_leg.quantity().clone(),
            destination_source_id,
            destination_id,
            destination_leg.quantity().clone(),
            &policy,
        )?;
        registry.usage.insert(policy.policy_id.clone(), next_usage);
        persist_fx_policy_registry(stx, registry);
        stx.world
            .settlement_receipts
            .insert(self.settlement_id.clone(), receipt);
        iroha_logger::info!(
            settlement_id = %self.settlement_id,
            policy_id = %policy.policy_id,
            source_dataspace = policy.source_dataspace.as_u64(),
            destination_dataspace = policy.destination_dataspace.as_u64(),
            source_amount = %source_leg.quantity(),
            destination_amount = %destination_leg.quantity(),
            recipient = %self.recipient,
            "native FX corridor settlement executed"
        );
        Ok(())
    }
}
pub(crate) fn admission_validate_dvp(
    authority: &AccountId,
    stx: &mut StateTransaction<'_, '_>,
    instruction: &DvpIsi,
) -> Result<(), Error> {
    let _ = validate_dvp_preconditions(
        authority,
        stx,
        instruction.settlement_id(),
        instruction.intent_hash(),
        instruction.delivery_leg(),
        instruction.payment_leg(),
    )?;
    Ok(())
}
pub(crate) fn admission_validate_pvp(
    authority: &AccountId,
    stx: &mut StateTransaction<'_, '_>,
    instruction: &PvpIsi,
) -> Result<(), Error> {
    let _ = validate_pvp_preconditions(
        authority,
        stx,
        instruction.settlement_id(),
        instruction.intent_hash(),
        instruction.primary_leg(),
        instruction.counter_leg(),
    )?;
    Ok(())
}
#[allow(clippy::too_many_lines)]
impl Execute for DvpIsi {
    fn execute(
        self,
        authority: &AccountId,
        stx: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let intent_hash = self.intent_hash();
        let DvpIsi {
            settlement_id,
            delivery_leg,
            payment_leg,
            plan,
            metadata,
        } = self;
        let (delivery_assets, payment_assets) = match validate_dvp_preconditions(
            authority,
            stx,
            &settlement_id,
            intent_hash,
            &delivery_leg,
            &payment_leg,
        ) {
            Ok(specs) => specs,
            Err(err) => {
                #[cfg(feature = "telemetry")]
                {
                    let reason = settlement_failure_reason(&err);
                    stx.telemetry
                        .note_settlement_failure(SETTLEMENT_KIND_DVP, reason);
                    stx.telemetry.record_dvp_finality(
                        &settlement_id,
                        plan,
                        SettlementOutcomeKind::Failure,
                        Some(reason),
                        false,
                        false,
                    );
                }
                return Err(err);
            }
        };
        let receipt = settlement_receipt(
            stx,
            authority,
            metadata,
            SettlementDetails::Dvp(iroha_data_model::isi::DvpSettlementDetails {
                delivery: resolved_settlement_movement(&delivery_assets, &delivery_leg),
                payment: resolved_settlement_movement(&payment_assets, &payment_leg),
                order: plan.order(),
            }),
        );
        let first = match plan.order() {
            SettlementExecutionOrder::DeliveryThenPayment => (
                delivery_assets.0.clone(),
                delivery_assets.1.clone(),
                delivery_leg.quantity().clone(),
            ),
            SettlementExecutionOrder::PaymentThenDelivery => (
                payment_assets.0.clone(),
                payment_assets.1.clone(),
                payment_leg.quantity().clone(),
            ),
        };
        let second = match plan.order() {
            SettlementExecutionOrder::DeliveryThenPayment => (
                payment_assets.0,
                payment_assets.1,
                payment_leg.quantity().clone(),
            ),
            SettlementExecutionOrder::PaymentThenDelivery => (
                delivery_assets.0,
                delivery_assets.1,
                delivery_leg.quantity().clone(),
            ),
        };
        let movement = VerifiedSettlementNumericPair::new(
            authority.clone(),
            &(settlement_id.clone(), intent_hash, plan),
            [first, second],
        )?;
        match crate::smartcontracts::isi::asset::isi::execute_verified_settlement_numeric_pair(
            stx, movement,
        ) {
            Ok(()) => {
                stx.world
                    .settlement_receipts
                    .insert(settlement_id.clone(), receipt);
                #[cfg(feature = "telemetry")]
                {
                    stx.telemetry.record_dvp_finality(
                        &settlement_id,
                        plan,
                        SettlementOutcomeKind::Success,
                        None,
                        true,
                        true,
                    );
                    stx.telemetry.note_settlement_success(SETTLEMENT_KIND_DVP);
                }
                iroha_logger::info!(
                    %settlement_id,
                    delivery_from=%delivery_leg.from(),
                    delivery_to=%delivery_leg.to(),
                    payment_asset=%payment_leg.asset_definition_id(),
                    "DvP settlement executed"
                );
                Ok(())
            }
            Err(err) => {
                #[cfg(feature = "telemetry")]
                {
                    let reason = settlement_failure_reason(&err);
                    stx.telemetry
                        .note_settlement_failure(SETTLEMENT_KIND_DVP, reason);
                    stx.telemetry.record_dvp_finality(
                        &settlement_id,
                        plan,
                        SettlementOutcomeKind::Failure,
                        Some(reason),
                        false,
                        false,
                    );
                }
                Err(err)
            }
        }
    }
}
#[allow(clippy::too_many_lines)]
impl Execute for PvpIsi {
    fn execute(
        self,
        authority: &AccountId,
        stx: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let intent_hash = self.intent_hash();
        let PvpIsi {
            settlement_id,
            primary_leg,
            counter_leg,
            plan,
            metadata,
        } = self;
        let (primary_assets, counter_assets) = match validate_pvp_preconditions(
            authority,
            stx,
            &settlement_id,
            intent_hash,
            &primary_leg,
            &counter_leg,
        ) {
            Ok(specs) => specs,
            Err(err) => {
                #[cfg(feature = "telemetry")]
                {
                    let reason = settlement_failure_reason(&err);
                    stx.telemetry
                        .note_settlement_failure(SETTLEMENT_KIND_PVP, reason);
                    stx.telemetry.record_pvp_finality(
                        &settlement_id,
                        plan,
                        SettlementOutcomeKind::Failure,
                        Some(reason),
                        false,
                        false,
                        None,
                    );
                }
                return Err(err);
            }
        };
        let receipt = settlement_receipt(
            stx,
            authority,
            metadata,
            SettlementDetails::Pvp(iroha_data_model::isi::PvpSettlementDetails {
                primary: resolved_settlement_movement(&primary_assets, &primary_leg),
                counter: resolved_settlement_movement(&counter_assets, &counter_leg),
                order: plan.order(),
            }),
        );
        let first = match plan.order() {
            SettlementExecutionOrder::DeliveryThenPayment => (
                primary_assets.0.clone(),
                primary_assets.1.clone(),
                primary_leg.quantity().clone(),
            ),
            SettlementExecutionOrder::PaymentThenDelivery => (
                counter_assets.0.clone(),
                counter_assets.1.clone(),
                counter_leg.quantity().clone(),
            ),
        };
        let second = match plan.order() {
            SettlementExecutionOrder::DeliveryThenPayment => (
                counter_assets.0,
                counter_assets.1,
                counter_leg.quantity().clone(),
            ),
            SettlementExecutionOrder::PaymentThenDelivery => (
                primary_assets.0,
                primary_assets.1,
                primary_leg.quantity().clone(),
            ),
        };
        let movement = VerifiedSettlementNumericPair::new(
            authority.clone(),
            &(settlement_id.clone(), intent_hash, plan),
            [first, second],
        )?;
        match crate::smartcontracts::isi::asset::isi::execute_verified_settlement_numeric_pair(
            stx, movement,
        ) {
            Ok(()) => {
                stx.world
                    .settlement_receipts
                    .insert(settlement_id.clone(), receipt);
                #[cfg(feature = "telemetry")]
                {
                    stx.telemetry.record_pvp_finality(
                        &settlement_id,
                        plan,
                        SettlementOutcomeKind::Success,
                        None,
                        true,
                        true,
                        None,
                    );
                    stx.telemetry.note_settlement_success(SETTLEMENT_KIND_PVP);
                }
                iroha_logger::info!(
                    %settlement_id,
                    primary_from=%primary_leg.from(),
                    primary_to=%primary_leg.to(),
                    counter_asset=%counter_leg.asset_definition_id(),
                    "PvP settlement executed"
                );
                Ok(())
            }
            Err(err) => {
                #[cfg(feature = "telemetry")]
                {
                    let reason = settlement_failure_reason(&err);
                    stx.telemetry
                        .note_settlement_failure(SETTLEMENT_KIND_PVP, reason);
                    stx.telemetry.record_pvp_finality(
                        &settlement_id,
                        plan,
                        SettlementOutcomeKind::Failure,
                        Some(reason),
                        false,
                        false,
                        None,
                    );
                }
                Err(err)
            }
        }
    }
}
#[cfg(test)]
mod tests {
    #[path = "atomic_tests.rs"]
    mod atomic;
    #[path = "namespace_tests.rs"]
    mod namespace;
    use super::*;
    use crate::{kura::Kura, prelude::World, query::store::LiveQueryStore, state::State};
    use iroha_data_model::{
        account::{
            Account, AccountAddress, NewAccount,
            rekey::{AccountAlias, AccountAliasDomain, AccountRekeyRecord},
        },
        asset::{
            Asset, AssetBalancePolicy, AssetDefinition, AssetTransferAvailability,
            AssetTransferControlRecord,
            prelude::{AssetDefinitionId, AssetId},
        },
        block::BlockHeader,
        common::Owned,
        domain::Domain,
        events::data::oracle::FeedEventRecord,
        events::data::prelude::{AssetEvent, DataEvent},
        isi::{SetAssetHoldingLimit, SettlementAtomicity, SettlementPlan},
        nexus::{DataSpaceCatalog, DataSpaceMetadata},
        oracle::{FeedEvent, FeedEventOutcome, FeedSuccess, ObservationValue},
        sns::{NameControllerV1, NameRecordV1},
    };
    use iroha_model_base::domain::DomainId;
    use iroha_model_base::metadata::Metadata;
    use iroha_primitives::numeric::{Numeric, NumericSpec, Quantity};
    use iroha_test_samples::{ALICE_ID, BOB_ID, CARPENTER_ID, SAMPLE_GENESIS_ACCOUNT_ID};
    use nonzero_ext::nonzero;
    use std::collections::BTreeSet;
    fn quantity(value: &str) -> Quantity {
        value
            .parse::<Quantity>()
            .expect("settlement fixture quantity must be canonical and non-negative")
    }
    fn grant_exact_settlement_consent(
        stx: &mut StateTransaction<'_, '_>,
        initiator: &AccountId,
        debited_asset: AssetId,
        settlement_id: &SettlementId,
        intent_hash: Hash,
    ) {
        let permission: Permission = CanExecuteSettlement {
            debited_asset,
            settlement_id: settlement_id.clone(),
            intent_hash,
        }
        .into();
        let mut permissions = stx
            .world
            .account_permissions
            .get(initiator)
            .cloned()
            .unwrap_or_default();
        permissions.insert(permission);
        stx.world
            .account_permissions
            .insert(initiator.clone(), permissions);
    }
    fn grant_dvp_consent(
        stx: &mut StateTransaction<'_, '_>,
        initiator: &AccountId,
        instruction: &DvpIsi,
    ) {
        stx.tx_call_hash.get_or_insert_with(|| {
            iroha_crypto::Hash::prehashed([0xD7; iroha_crypto::Hash::LENGTH])
        });
        let leg = instruction.payment_leg();
        let debited_asset = stx
            .world
            .assets
            .iter()
            .find_map(|(asset_id, _)| {
                (asset_id.account() == leg.from()
                    && asset_id.definition() == leg.asset_definition_id())
                .then(|| asset_id.clone())
            })
            .unwrap_or_else(|| AssetId::new(leg.asset_definition_id().clone(), leg.from().clone()));
        grant_exact_settlement_consent(
            stx,
            initiator,
            debited_asset,
            instruction.settlement_id(),
            instruction.intent_hash(),
        );
    }
    fn grant_pvp_consent(
        stx: &mut StateTransaction<'_, '_>,
        initiator: &AccountId,
        instruction: &PvpIsi,
    ) {
        stx.tx_call_hash.get_or_insert_with(|| {
            iroha_crypto::Hash::prehashed([0xD8; iroha_crypto::Hash::LENGTH])
        });
        let leg = instruction.counter_leg();
        let debited_asset = stx
            .world
            .assets
            .iter()
            .find_map(|(asset_id, _)| {
                (asset_id.account() == leg.from()
                    && asset_id.definition() == leg.asset_definition_id())
                .then(|| asset_id.clone())
            })
            .unwrap_or_else(|| AssetId::new(leg.asset_definition_id().clone(), leg.from().clone()));
        grant_exact_settlement_consent(
            stx,
            initiator,
            debited_asset,
            instruction.settlement_id(),
            instruction.intent_hash(),
        );
    }
    fn assert_smart_contract_parameter_contains(error: InstructionExecutionError, expected: &str) {
        let InstructionExecutionError::InvalidParameter(InvalidParameterError::SmartContract(
            message,
        )) = error
        else {
            panic!("expected smart-contract parameter error, got {error:?}");
        };
        assert!(
            message.contains(expected),
            "expected `{message}` to contain `{expected}`"
        );
    }
    #[test]
    fn bilateral_settlement_requires_distinct_counterparties_and_assets() {
        let first = SettlementLeg::new(
            AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").expect("domain"),
                "first".parse().expect("asset name"),
            ),
            Quantity::one(),
            ALICE_ID.clone(),
            BOB_ID.clone(),
        );
        let second = SettlementLeg::new(
            AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").expect("domain"),
                "second".parse().expect("asset name"),
            ),
            Quantity::one(),
            BOB_ID.clone(),
            ALICE_ID.clone(),
        );
        super::ensure_bilateral_settlement_shape(&first, &second)
            .expect("distinct counterparties and asset definitions");
        let same_asset = SettlementLeg::new(
            first.asset_definition_id().clone(),
            Quantity::one(),
            BOB_ID.clone(),
            ALICE_ID.clone(),
        );
        let error = super::ensure_bilateral_settlement_shape(&first, &same_asset)
            .expect_err("identical assets are not bilateral settlement");
        assert!(error.to_string().contains("distinct asset definitions"));
        let same_account = SettlementLeg::new(
            first.asset_definition_id().clone(),
            Quantity::one(),
            ALICE_ID.clone(),
            ALICE_ID.clone(),
        );
        let error = super::ensure_bilateral_settlement_shape(&same_account, &second)
            .expect_err("self-transfer is not bilateral settlement");
        assert!(error.to_string().contains("distinct counterparties"));
    }
    fn settlement_state() -> (State, AssetDefinitionId, AssetDefinitionId) {
        settlement_state_with_balances(Quantity::from(10u32), Quantity::from(1_000u32))
    }
    fn set_test_holding_limit(
        stx: &mut StateTransaction<'_, '_>,
        account_id: &AccountId,
        asset_definition_id: &AssetDefinitionId,
        limit: Quantity,
    ) {
        SetAssetHoldingLimit::new(account_id.clone(), asset_definition_id.clone(), Some(limit))
            .execute(&ALICE_ID, stx)
            .expect("asset owner should set the test holding limit");
    }
    fn asset_balance_or_zero(stx: &StateTransaction<'_, '_>, id: &AssetId) -> Quantity {
        stx.world
            .assets
            .get(id)
            .map_or_else(Quantity::zero, |value| value.as_ref().clone())
    }
    fn assert_holding_limit_error(error: &InstructionExecutionError) {
        assert!(
            matches!(
                error,
                InstructionExecutionError::AssetTransferAdmission(
                    AssetTransferAdmissionError::HoldingLimitExceeded(_)
                )
            ),
            "expected typed holding-limit error, got {error:?}"
        );
    }
    fn fx_corridor_state(
        source_balance: u32,
        destination_balance: u32,
        oracle_rate_mantissa: u64,
        enabled: bool,
    ) -> (State, FxCorridorPolicy) {
        let domain_id = DomainId::try_new("fx", "universal").expect("FX domain");
        let source_asset_definition_id = AssetDefinitionId::derive_from_components(
            domain_id.clone(),
            "aed".parse().expect("AED name"),
        );
        let destination_asset_definition_id = AssetDefinitionId::derive_from_components(
            domain_id.clone(),
            "pkr".parse().expect("PKR name"),
        );
        let source_dataspace = DataSpaceId::new(10);
        let destination_dataspace = DataSpaceId::new(12);
        let policy_id: Name = "aed_to_pkr".parse().expect("policy id");
        let mut world = World::with_assets(
            [Domain::new(domain_id.clone()).build(&ALICE_ID)],
            [
                Account::new(ALICE_ID.clone()).build(&ALICE_ID),
                Account::new(BOB_ID.clone()).build(&ALICE_ID),
                Account::new(CARPENTER_ID.clone()).build(&ALICE_ID),
                Account::new(SAMPLE_GENESIS_ACCOUNT_ID.clone()).build(&ALICE_ID),
            ],
            [
                AssetDefinition::numeric(
                    source_asset_definition_id.clone(),
                    "aed".to_owned(),
                    AssetBalancePolicy::DataspaceRestricted,
                    Some(domain_id.clone()),
                )
                .build(&ALICE_ID),
                AssetDefinition::numeric(
                    destination_asset_definition_id.clone(),
                    "pkr".to_owned(),
                    AssetBalancePolicy::DataspaceRestricted,
                    Some(domain_id),
                )
                .build(&ALICE_ID),
            ],
            [
                Asset::new(
                    AssetId::with_scope(
                        source_asset_definition_id.clone(),
                        ALICE_ID.clone(),
                        AssetBalanceScope::Dataspace(source_dataspace),
                    ),
                    Quantity::from(source_balance),
                ),
                Asset::new(
                    AssetId::with_scope(
                        source_asset_definition_id.clone(),
                        BOB_ID.clone(),
                        AssetBalanceScope::Dataspace(source_dataspace),
                    ),
                    Quantity::from(source_balance),
                ),
                Asset::new(
                    AssetId::with_scope(
                        destination_asset_definition_id.clone(),
                        SAMPLE_GENESIS_ACCOUNT_ID.clone(),
                        AssetBalanceScope::Dataspace(destination_dataspace),
                    ),
                    Quantity::from(destination_balance),
                ),
            ],
            [],
        );
        world.account_permissions.insert(
            ALICE_ID.clone(),
            BTreeSet::from([Permission::from(CanSetFxCorridorPolicy {
                policy_id: policy_id.clone(),
            })]),
        );
        let recipient_alias = AccountAlias::new(
            "retail_recipient".parse().expect("recipient alias"),
            Some(AccountAliasDomain::new(
                "hbl".parse().expect("HBL alias domain"),
            )),
            destination_dataspace,
        );
        world
            .account_aliases
            .insert(recipient_alias.clone(), BOB_ID.clone());
        world
            .account_aliases_by_account
            .insert(BOB_ID.clone(), BTreeSet::from([recipient_alias.clone()]));
        let policy = FxCorridorPolicy {
            policy_id,
            revision: 1,
            owner: SAMPLE_GENESIS_ACCOUNT_ID.clone(),
            source_dataspace,
            source_asset_definition_id,
            destination_dataspace,
            destination_asset_definition_id,
            allowed_destination_alias_domains: BTreeSet::from([
                DomainId::try_new("hbl", "sbp").expect("HBL domain"),
                DomainId::try_new("ubl", "sbp").expect("UBL domain"),
            ]),
            oracle_feed_id: iroha_data_model::oracle::kits::price_xor_usd()
                .feed_config
                .feed_id,
            max_oracle_age_ms: 60_000,
            max_source_amount_per_settlement: Quantity::from(1_000_000_u32),
            max_destination_amount_per_settlement: Quantity::from(100_000_000_u32),
            velocity_window_ms: 60_000,
            max_settlements_per_window: 100,
            max_source_amount_per_window: Quantity::from(10_000_000_u32),
            max_destination_amount_per_window: Quantity::from(1_000_000_000_u32),
            enabled,
        };
        let mut feed = iroha_data_model::oracle::kits::price_xor_usd().feed_config;
        feed.feed_id = policy.oracle_feed_id.clone();
        let event = FeedEvent {
            feed_id: policy.oracle_feed_id.clone(),
            feed_config_version: feed.feed_config_version,
            slot: 1,
            request_hash: Hash::new(b"fx-corridor-test-rate"),
            outcome: FeedEventOutcome::Success(FeedSuccess {
                value: ObservationValue::new(i128::from(oracle_rate_mantissa), 0),
                entries: Vec::new(),
            }),
        };
        world
            .oracle_feeds
            .insert(policy.oracle_feed_id.clone(), feed);
        world.oracle_history.insert(
            policy.oracle_feed_id.clone(),
            vec![FeedEventRecord {
                event,
                recorded_at_ms: 0,
                evidence_hashes: Vec::new(),
            }],
        );
        let catalog = fx_catalog(&policy);
        let selector = crate::sns::selector_for_account_alias(&recipient_alias, &catalog)
            .expect("canonical FX recipient alias selector");
        let address = AccountAddress::from_account_id(&BOB_ID)
            .expect("FX recipient account must encode as an address");
        let record = NameRecordV1::new(
            selector.clone(),
            BOB_ID.clone(),
            vec![NameControllerV1::account(&address)],
            0,
            0,
            u64::MAX,
            u64::MAX,
            u64::MAX,
            Metadata::default(),
        );
        world
            .smart_contract_state
            .insert(crate::sns::record_storage_key(&selector), record.encode());
        world.replace_account_rekey_record_for_testing(AccountRekeyRecord::new(
            recipient_alias,
            BOB_ID.clone(),
        ));
        let state = State::new(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        (state, policy)
    }
    fn fx_catalog(policy: &FxCorridorPolicy) -> DataSpaceCatalog {
        DataSpaceCatalog::new(vec![
            DataSpaceMetadata::default(),
            DataSpaceMetadata {
                id: policy.source_dataspace,
                alias: "cbuae".to_owned(),
                description: None,
                fault_tolerance: 1,
            },
            DataSpaceMetadata {
                id: policy.destination_dataspace,
                alias: "sbp".to_owned(),
                description: None,
                fault_tolerance: 1,
            },
        ])
        .expect("FX dataspace catalog")
    }
    fn configure_fx_catalog(stx: &mut StateTransaction<'_, '_>, policy: &FxCorridorPolicy) {
        stx.nexus.dataspace_catalog = fx_catalog(policy);
    }
    fn insert_active_fx_alias(
        stx: &mut StateTransaction<'_, '_>,
        alias: AccountAlias,
        account_id: AccountId,
    ) {
        let selector = crate::sns::selector_for_account_alias(&alias, &stx.nexus.dataspace_catalog)
            .expect("canonical FX alias selector");
        let address = AccountAddress::from_account_id(&account_id)
            .expect("FX alias owner must encode as an address");
        let record = NameRecordV1::new(
            selector.clone(),
            account_id.clone(),
            vec![NameControllerV1::account(&address)],
            0,
            0,
            u64::MAX,
            u64::MAX,
            u64::MAX,
            Metadata::default(),
        );
        stx.world
            .smart_contract_state
            .insert(crate::sns::record_storage_key(&selector), record.encode());
        stx.world
            .replace_account_rekey_record(AccountRekeyRecord::new(
                alias.clone(),
                account_id.clone(),
            ));
        stx.world.insert_account_alias_binding(alias, account_id);
    }
    fn fx_settlement(policy: &FxCorridorPolicy, id: &str, source_amount: u32) -> SettleFxCorridor {
        let event = FeedEvent {
            feed_id: policy.oracle_feed_id.clone(),
            feed_config_version: iroha_data_model::oracle::FeedConfigVersion(1),
            slot: 1,
            request_hash: Hash::new(b"fx-corridor-test-rate"),
            outcome: FeedEventOutcome::Success(FeedSuccess {
                value: ObservationValue::new(76, 0),
                entries: Vec::new(),
            }),
        };
        SettleFxCorridor {
            policy_id: policy.policy_id.clone(),
            expected_policy_revision: policy.revision,
            source_asset_definition_id: policy.source_asset_definition_id.clone(),
            destination_asset_definition_id: policy.destination_asset_definition_id.clone(),
            settlement_id: SettlementId::new(ALICE_ID.clone(), id.parse().expect("settlement id")),
            recipient: BOB_ID.clone(),
            source_amount: Quantity::from(source_amount),
            expected_destination_amount: Quantity::from(source_amount * 76),
            oracle_evidence: iroha_data_model::isi::settlement::FxCorridorOracleEvidence {
                feed_id: event.feed_id.clone(),
                feed_config_version: event.feed_config_version,
                slot: event.slot,
                request_hash: event.request_hash,
                event_hash: iroha_crypto::HashOf::new(&event),
            },
        }
    }
    fn fund_fx_corridor(
        stx: &mut StateTransaction<'_, '_>,
        policy: &FxCorridorPolicy,
        amount: u32,
    ) {
        FundFxCorridorEscrow {
            policy_id: policy.policy_id.clone(),
            expected_policy_revision: policy.revision,
            destination_asset_definition_id: policy.destination_asset_definition_id.clone(),
            amount: Quantity::from(amount),
        }
        .execute(&policy.owner, stx)
        .expect("FX corridor owner funding succeeds");
    }
    #[test]
    fn fx_corridor_settles_exact_rate_atomically_and_rejects_replay() {
        let (state, policy) = fx_corridor_state(10, 1_000, 76, true);
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction_for_fastpq_testing(iroha_crypto::Hash::prehashed(
            [0xF1; iroha_crypto::Hash::LENGTH],
        ));
        configure_fx_catalog(&mut stx, &policy);
        SetFxCorridorPolicy {
            policy: policy.clone(),
        }
        .execute(&ALICE_ID, &mut stx)
        .expect("policy registration succeeds");
        fund_fx_corridor(&mut stx, &policy, 1_000);
        stx.tx_call_hash = Some(iroha_crypto::Hash::prehashed(
            [0xF1; iroha_crypto::Hash::LENGTH],
        ));
        let instruction = fx_settlement(&policy, "fx_001", 10);
        instruction
            .clone()
            .execute(&ALICE_ID, &mut stx)
            .expect("FX settlement succeeds");
        let balance = |id: AssetId| {
            stx.world
                .assets
                .get(&id)
                .map_or_else(Quantity::zero, |value| value.as_ref().clone())
        };
        assert_eq!(
            balance(AssetId::with_scope(
                policy.source_asset_definition_id.clone(),
                policy.owner.clone(),
                AssetBalanceScope::Dataspace(policy.source_dataspace),
            )),
            Quantity::from(10_u32)
        );
        assert_eq!(
            balance(AssetId::with_scope(
                policy.destination_asset_definition_id.clone(),
                super::fx_corridor_escrow_account(&stx, &policy),
                AssetBalanceScope::Dataspace(policy.destination_dataspace),
            )),
            Quantity::from(240_u32)
        );
        assert_eq!(
            balance(AssetId::with_scope(
                policy.destination_asset_definition_id.clone(),
                BOB_ID.clone(),
                AssetBalanceScope::Dataspace(policy.destination_dataspace),
            )),
            Quantity::from(760_u32)
        );
        let receipt = stx
            .world
            .settlement_receipts
            .get(&instruction.settlement_id)
            .expect("FX outcome recorded");
        let SettlementDetails::FxCorridor(iroha_data_model::isi::FxCorridorSettlementDetails {
            source,
            destination,
            context,
        }) = &receipt.details
        else {
            panic!("native FX typed receipt");
        };
        assert_eq!(context.policy_id, policy.policy_id);
        assert_eq!(context.policy_revision, policy.revision);
        assert_eq!(
            source.source.scope(),
            &AssetBalanceScope::Dataspace(policy.source_dataspace)
        );
        assert_eq!(
            destination.source.scope(),
            &AssetBalanceScope::Dataspace(policy.destination_dataspace)
        );
        assert_eq!(source.quantity, Quantity::from(10_u32));
        assert_eq!(destination.quantity, Quantity::from(760_u32));
        assert_eq!(destination.destination.account(), &*BOB_ID);
        assert_eq!(
            source.source.definition(),
            &policy.source_asset_definition_id
        );
        assert_eq!(
            destination.source.definition(),
            &policy.destination_asset_definition_id
        );
        let replay = instruction
            .execute(&ALICE_ID, &mut stx)
            .expect_err("settlement id replay must fail");
        assert!(replay.to_string().contains("already been committed"));
    }
    #[test]
    fn fx_corridor_debits_only_the_signing_source_account() {
        let (state, policy) = fx_corridor_state(10, 1_000, 76, true);
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction_for_fastpq_testing(iroha_crypto::Hash::prehashed(
            [0xF2; iroha_crypto::Hash::LENGTH],
        ));
        configure_fx_catalog(&mut stx, &policy);
        SetFxCorridorPolicy {
            policy: policy.clone(),
        }
        .execute(&ALICE_ID, &mut stx)
        .expect("policy registration succeeds");
        fund_fx_corridor(&mut stx, &policy, 1_000);
        stx.tx_call_hash = Some(iroha_crypto::Hash::prehashed(
            [0xF2; iroha_crypto::Hash::LENGTH],
        ));
        let mut instruction = fx_settlement(&policy, "fx_authority_source", 2);
        instruction.settlement_id.owner = BOB_ID.clone();
        instruction
            .clone()
            .execute(&BOB_ID, &mut stx)
            .expect("the signed source account may spend only its own balance");
        let source_balance = |account: &AccountId| {
            stx.world
                .assets
                .get(&AssetId::with_scope(
                    policy.source_asset_definition_id.clone(),
                    account.clone(),
                    AssetBalanceScope::Dataspace(policy.source_dataspace),
                ))
                .map_or_else(Quantity::zero, |value| value.as_ref().clone())
        };
        assert_eq!(source_balance(&BOB_ID), Quantity::from(8_u32));
        assert_eq!(source_balance(&ALICE_ID), Quantity::from(10_u32));
        let receipt = stx
            .world
            .settlement_receipts
            .get(&instruction.settlement_id)
            .expect("settlement receipt");
        assert_eq!(receipt.authority, BOB_ID.clone());
        let SettlementDetails::FxCorridor(iroha_data_model::isi::FxCorridorSettlementDetails {
            source,
            ..
        }) = &receipt.details
        else {
            panic!("FX details");
        };
        assert_eq!(source.source.account(), &*BOB_ID);
    }
    #[test]
    fn fx_corridor_recipient_alias_domain_is_required_and_unambiguous() {
        let (state, policy) = fx_corridor_state(10, 1_000, 76, true);
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction_for_fastpq_testing(Hash::new(
            b"fx_corridor_recipient_alias_domain_is_required_and_unambiguous",
        ));
        configure_fx_catalog(&mut stx, &policy);
        SetFxCorridorPolicy {
            policy: policy.clone(),
        }
        .execute(&ALICE_ID, &mut stx)
        .expect("policy registration succeeds");
        fund_fx_corridor(&mut stx, &policy, 1_000);
        stx.world.remove_account_alias_bindings_for_account(&BOB_ID);
        assert_smart_contract_parameter_contains(
            fx_settlement(&policy, "fx_missing_recipient_domain", 1)
                .execute(&ALICE_ID, &mut stx)
                .expect_err("recipient without an allowed alias must fail"),
            "no alias in an allowed destination domain",
        );
        for (label, domain) in [("hbl_recipient", "hbl"), ("ubl_recipient", "ubl")] {
            insert_active_fx_alias(
                &mut stx,
                AccountAlias::new(
                    label.parse().expect("alias label"),
                    Some(AccountAliasDomain::new(
                        domain.parse().expect("alias domain"),
                    )),
                    policy.destination_dataspace,
                ),
                BOB_ID.clone(),
            );
        }
        assert_smart_contract_parameter_contains(
            fx_settlement(&policy, "fx_ambiguous_recipient_domain", 1)
                .execute(&ALICE_ID, &mut stx)
                .expect_err("recipient bound to two allowed FIs must fail"),
            "alias domain is ambiguous",
        );
    }
    #[test]
    fn fx_corridor_rejects_recipient_bound_only_to_non_allowed_destination_domain() {
        let (state, policy) = fx_corridor_state(10, 1_000, 76, true);
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction_for_fastpq_testing(Hash::new(
            b"fx_corridor_rejects_recipient_bound_only_to_non_allowed_destination_domain",
        ));
        configure_fx_catalog(&mut stx, &policy);
        SetFxCorridorPolicy {
            policy: policy.clone(),
        }
        .execute(&ALICE_ID, &mut stx)
        .expect("policy registration succeeds");
        fund_fx_corridor(&mut stx, &policy, 1_000);
        stx.world.remove_account_alias_bindings_for_account(&BOB_ID);
        insert_active_fx_alias(
            &mut stx,
            AccountAlias::new(
                "other_recipient".parse().expect("alias label"),
                Some(AccountAliasDomain::new(
                    "other".parse().expect("alias domain"),
                )),
                policy.destination_dataspace,
            ),
            BOB_ID.clone(),
        );
        assert_smart_contract_parameter_contains(
            fx_settlement(&policy, "fx_non_allowed_recipient_domain", 1)
                .execute(&ALICE_ID, &mut stx)
                .expect_err("recipient bound only to other.sbp must fail"),
            "no alias in an allowed destination domain",
        );
    }
    #[test]
    fn fx_corridor_rejects_policy_and_signed_intent_mismatches() {
        let (state, policy) = fx_corridor_state(10, 1_000, 76, true);
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction_for_fastpq_testing(Hash::new(
            b"fx_corridor_rejects_policy_and_signed_intent_mismatches",
        ));
        configure_fx_catalog(&mut stx, &policy);
        SetFxCorridorPolicy {
            policy: policy.clone(),
        }
        .execute(&ALICE_ID, &mut stx)
        .expect("policy registration succeeds");
        fund_fx_corridor(&mut stx, &policy, 1_000);
        let mut wrong_revision = fx_settlement(&policy, "fx_wrong_revision", 1);
        wrong_revision.expected_policy_revision = 2;
        assert_smart_contract_parameter_contains(
            wrong_revision
                .execute(&ALICE_ID, &mut stx)
                .expect_err("revision mismatch must fail"),
            "revision mismatch",
        );
        let mut wrong_asset = fx_settlement(&policy, "fx_wrong_asset", 1);
        wrong_asset.source_asset_definition_id = policy.destination_asset_definition_id.clone();
        assert_smart_contract_parameter_contains(
            wrong_asset
                .execute(&ALICE_ID, &mut stx)
                .expect_err("asset mismatch must fail"),
            "do not match",
        );
        let mut reserve_recipient = fx_settlement(&policy, "fx_reserve_recipient", 1);
        reserve_recipient.recipient = super::fx_corridor_escrow_account(&stx, &policy);
        assert_smart_contract_parameter_contains(
            reserve_recipient
                .execute(&ALICE_ID, &mut stx)
                .expect_err("reserve recipient must fail"),
            "recipient",
        );
        let delegated_funding = FundFxCorridorEscrow {
            policy_id: policy.policy_id.clone(),
            expected_policy_revision: policy.revision,
            destination_asset_definition_id: policy.destination_asset_definition_id.clone(),
            amount: Quantity::one(),
        }
        .execute(&BOB_ID, &mut stx)
        .expect_err("a non-owner cannot fund corridor custody");
        assert!(
            delegated_funding
                .to_string()
                .contains("exact FX corridor owner")
        );
        let mut wrong_oracle = fx_settlement(&policy, "fx_wrong_oracle", 1);
        wrong_oracle.oracle_evidence.event_hash = iroha_crypto::HashOf::new(&FeedEvent {
            feed_id: policy.oracle_feed_id.clone(),
            feed_config_version: iroha_data_model::oracle::FeedConfigVersion(1),
            slot: 99,
            request_hash: Hash::new(b"wrong"),
            outcome: FeedEventOutcome::Missing,
        });
        assert_smart_contract_parameter_contains(
            wrong_oracle
                .execute(&ALICE_ID, &mut stx)
                .expect_err("wrong exact oracle event must fail"),
            "latest retained event",
        );
        let mut revision_two = policy.clone();
        revision_two.revision = 3;
        assert_smart_contract_parameter_contains(
            SetFxCorridorPolicy {
                policy: revision_two,
            }
            .execute(&ALICE_ID, &mut stx)
            .expect_err("policy revision must be monotonic"),
            "must be 2",
        );
        let mut redirected_owner = policy.clone();
        redirected_owner.revision = 2;
        redirected_owner.owner = ALICE_ID.clone();
        assert_smart_contract_parameter_contains(
            SetFxCorridorPolicy {
                policy: redirected_owner,
            }
            .execute(&ALICE_ID, &mut stx)
            .expect_err("a policy revision cannot redirect corridor custody ownership"),
            "immutable",
        );
        let mut disabled = policy.clone();
        disabled.revision = 2;
        disabled.enabled = false;
        SetFxCorridorPolicy {
            policy: disabled.clone(),
        }
        .execute(&ALICE_ID, &mut stx)
        .expect("disabled policy revision is a valid governance update");
        assert!(
            fx_settlement(&disabled, "fx_disabled", 1)
                .execute(&ALICE_ID, &mut stx)
                .expect_err("disabled policy must reject settlement")
                .to_string()
                .contains("disabled")
        );
        let refund = RefundFxCorridorEscrow {
            policy_id: disabled.policy_id.clone(),
            expected_policy_revision: disabled.revision,
            destination_asset_definition_id: disabled.destination_asset_definition_id.clone(),
            amount: Quantity::one(),
        };
        assert!(
            refund
                .clone()
                .execute(&ALICE_ID, &mut stx)
                .expect_err("a corridor manager cannot refund another owner's reserve")
                .to_string()
                .contains("exact FX corridor owner")
        );
        refund
            .execute(&disabled.owner, &mut stx)
            .expect("the exact owner may refund its disabled corridor reserve");
    }
    #[test]
    fn fx_corridor_protocol_escrow_rejects_generic_manager_drain_and_supply_changes() {
        let (state, policy) = fx_corridor_state(10, 1_000, 76, true);
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction_for_fastpq_testing(iroha_crypto::Hash::prehashed(
            [0xF3; iroha_crypto::Hash::LENGTH],
        ));
        configure_fx_catalog(&mut stx, &policy);
        SetFxCorridorPolicy {
            policy: policy.clone(),
        }
        .execute(&ALICE_ID, &mut stx)
        .expect("policy registration succeeds");
        let escrow_account = super::fx_corridor_escrow_account(&stx, &policy);
        assert!(
            Register::account(NewAccount::new(escrow_account.clone()))
                .execute(&ALICE_ID, &mut stx)
                .expect_err("ordinary registration cannot claim the reserved escrow identity")
                .to_string()
                .contains("reserved for deterministic FX corridor protocol escrow")
        );
        fund_fx_corridor(&mut stx, &policy, 1_000);
        stx.tx_call_hash = Some(iroha_crypto::Hash::prehashed(
            [0xF3; iroha_crypto::Hash::LENGTH],
        ));
        let escrow_asset = AssetId::with_scope(
            policy.destination_asset_definition_id.clone(),
            escrow_account.clone(),
            AssetBalanceScope::Dataspace(policy.destination_dataspace),
        );
        let exact_transfer: Permission =
            iroha_executor_data_model::permission::asset::CanTransferAsset {
                asset: escrow_asset.clone(),
            }
            .into();
        let mut manager_permissions = stx
            .world
            .account_permissions
            .get(&ALICE_ID)
            .cloned()
            .unwrap_or_default();
        manager_permissions.insert(exact_transfer);
        stx.world
            .account_permissions
            .insert(ALICE_ID.clone(), manager_permissions);
        for error in [
            Transfer::asset_quantity(escrow_asset.clone(), 1_u32, ALICE_ID.clone())
                .execute(&ALICE_ID, &mut stx)
                .expect_err("even an exact transfer grant cannot drain FX protocol escrow"),
            Burn::asset_quantity(1_u32, escrow_asset.clone())
                .execute(&ALICE_ID, &mut stx)
                .expect_err("ordinary burn cannot destroy FX protocol escrow backing"),
            Mint::asset_quantity(1_u32, escrow_asset.clone())
                .execute(&ALICE_ID, &mut stx)
                .expect_err("ordinary mint cannot inflate FX protocol escrow backing"),
        ] {
            assert!(
                error.to_string().contains("FX corridor escrow"),
                "unexpected escrow guard error: {error}"
            );
        }
        assert!(
            Unregister::account(escrow_account)
                .execute(&ALICE_ID, &mut stx)
                .expect_err("ordinary unregister cannot remove FX protocol escrow")
                .to_string()
                .contains("retained FX protocol escrow")
        );
        assert_eq!(
            **stx
                .world
                .assets
                .get(&escrow_asset)
                .expect("escrow balance remains present"),
            Quantity::from(1_000_u32),
        );
    }
    #[test]
    fn fx_corridor_requires_fresh_oracle_evidence_and_enforces_exposure_velocity() {
        let (state, policy) = fx_corridor_state(10, 1_000, 76, true);
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 60_001, 60_001);
        let mut block = state.block(header);
        let mut stx = block.transaction_for_fastpq_testing(iroha_crypto::Hash::prehashed(
            [0xF4; iroha_crypto::Hash::LENGTH],
        ));
        configure_fx_catalog(&mut stx, &policy);
        SetFxCorridorPolicy {
            policy: policy.clone(),
        }
        .execute(&ALICE_ID, &mut stx)
        .expect("policy registration succeeds");
        fund_fx_corridor(&mut stx, &policy, 1_000);
        assert_smart_contract_parameter_contains(
            fx_settlement(&policy, "fx_stale_oracle", 1)
                .execute(&ALICE_ID, &mut stx)
                .expect_err("oracle evidence older than the governed maximum must fail"),
            "stale",
        );
        let (state, mut policy) = fx_corridor_state(10, 1_000, 76, true);
        policy.max_source_amount_per_settlement = Quantity::one();
        policy.max_settlements_per_window = 1;
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction_for_fastpq_testing(iroha_crypto::Hash::prehashed(
            [0xF4; iroha_crypto::Hash::LENGTH],
        ));
        configure_fx_catalog(&mut stx, &policy);
        SetFxCorridorPolicy {
            policy: policy.clone(),
        }
        .execute(&ALICE_ID, &mut stx)
        .expect("limited policy registration succeeds");
        fund_fx_corridor(&mut stx, &policy, 1_000);
        assert_smart_contract_parameter_contains(
            fx_settlement(&policy, "fx_exposure_limit", 2)
                .execute(&ALICE_ID, &mut stx)
                .expect_err("per-settlement source exposure must be enforced"),
            "per-settlement exposure",
        );
        stx.tx_call_hash = Some(iroha_crypto::Hash::prehashed(
            [0xF4; iroha_crypto::Hash::LENGTH],
        ));
        fx_settlement(&policy, "fx_velocity_first", 1)
            .execute(&ALICE_ID, &mut stx)
            .expect("the first settlement in the window succeeds");
        assert_smart_contract_parameter_contains(
            fx_settlement(&policy, "fx_velocity_second", 1)
                .execute(&ALICE_ID, &mut stx)
                .expect_err("the deterministic settlement-count velocity limit must hold"),
            "velocity limit",
        );
    }
    #[test]
    fn fx_corridor_policy_static_invariants_fail_closed() {
        let (_, policy) = fx_corridor_state(1, 76, 76, true);
        let mut cases = Vec::new();
        let mut zero_revision = policy.clone();
        zero_revision.revision = 0;
        cases.push(zero_revision);
        let mut universal_source = policy.clone();
        universal_source.source_dataspace = DataSpaceId::UNIVERSAL;
        cases.push(universal_source);
        let mut same_dataspace = policy.clone();
        same_dataspace.destination_dataspace = same_dataspace.source_dataspace;
        cases.push(same_dataspace);
        let mut same_asset = policy.clone();
        same_asset.destination_asset_definition_id = same_asset.source_asset_definition_id.clone();
        cases.push(same_asset);
        let mut zero_oracle_age = policy;
        zero_oracle_age.max_oracle_age_ms = 0;
        cases.push(zero_oracle_age);
        assert!(
            cases
                .iter()
                .all(|candidate| candidate.invariant_error().is_some())
        );
    }
    #[test]
    fn fx_corridor_preflight_preserves_source_on_non_exact_or_unfunded_payout() {
        let (state, policy) = fx_corridor_state(10, 1, 76, true);
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction_for_fastpq_testing(Hash::new(
            b"fx_corridor_preflight_preserves_source_on_non_exact_or_unfunded_payout",
        ));
        configure_fx_catalog(&mut stx, &policy);
        SetFxCorridorPolicy {
            policy: policy.clone(),
        }
        .execute(&ALICE_ID, &mut stx)
        .expect("policy registration succeeds");
        fund_fx_corridor(&mut stx, &policy, 1);
        let mut wrong_output = fx_settlement(&policy, "fx_wrong_output", 1);
        wrong_output.expected_destination_amount = Quantity::from(75_u32);
        assert_smart_contract_parameter_contains(
            wrong_output
                .execute(&ALICE_ID, &mut stx)
                .expect_err("signed output mismatch must fail"),
            "signed expected destination amount",
        );
        let source_id = AssetId::with_scope(
            policy.source_asset_definition_id.clone(),
            ALICE_ID.clone(),
            AssetBalanceScope::Dataspace(policy.source_dataspace),
        );
        assert_eq!(
            **stx.world.assets.get(&source_id).expect("source unchanged"),
            Quantity::from(10_u32)
        );
        let mut policy_two = policy.clone();
        policy_two.revision = 2;
        SetFxCorridorPolicy {
            policy: policy_two.clone(),
        }
        .execute(&ALICE_ID, &mut stx)
        .expect("monotonic policy update succeeds");
        let error = fx_settlement(&policy_two, "fx_unfunded", 1)
            .execute(&ALICE_ID, &mut stx)
            .expect_err("reserve preflight must fail");
        assert!(matches!(
            error,
            InstructionExecutionError::Math(MathError::NotEnoughQuantity)
        ));
        assert_eq!(
            **stx.world.assets.get(&source_id).expect("source unchanged"),
            Quantity::from(10_u32)
        );
    }
    #[test]
    fn fx_corridor_rejects_wrong_dataspace_and_frozen_reserve_without_partial_effects() {
        let (state, policy) = fx_corridor_state(10, 1_000, 76, true);
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction_for_fastpq_testing(Hash::new(
            b"fx_corridor_rejects_wrong_dataspace_and_frozen_reserve_without_partial_effects",
        ));
        configure_fx_catalog(&mut stx, &policy);
        let mut wrong_scope = policy.clone();
        wrong_scope.source_dataspace = DataSpaceId::new(11);
        let error = SetFxCorridorPolicy {
            policy: wrong_scope.clone(),
        }
        .execute(&ALICE_ID, &mut stx)
        .expect_err("a corridor cannot name a source dataspace absent from the active catalog");
        assert_smart_contract_parameter_contains(error, "source dataspace");
        let actual_source_id = AssetId::with_scope(
            policy.source_asset_definition_id.clone(),
            ALICE_ID.clone(),
            AssetBalanceScope::Dataspace(policy.source_dataspace),
        );
        assert_eq!(
            **stx
                .world
                .assets
                .get(&actual_source_id)
                .expect("actual source remains funded"),
            Quantity::from(10_u32),
        );
        let (state, policy) = fx_corridor_state(10, 1_000, 76, true);
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction_for_fastpq_testing(Hash::new(
            b"fx_corridor_rejects_wrong_dataspace_and_frozen_reserve_without_partial_effects",
        ));
        configure_fx_catalog(&mut stx, &policy);
        SetFxCorridorPolicy {
            policy: policy.clone(),
        }
        .execute(&ALICE_ID, &mut stx)
        .expect("policy registration succeeds");
        fund_fx_corridor(&mut stx, &policy, 1_000);
        SetAssetTransferAvailability::new(
            super::fx_corridor_escrow_account(&stx, &policy),
            policy.destination_asset_definition_id.clone(),
            0,
            AssetTransferAvailability::Enabled,
            AssetTransferAvailability::Disabled,
            Some("reserve safety hold".to_owned()),
        )
        .execute(&ALICE_ID, &mut stx)
        .expect("asset owner may freeze the destination reserve");
        let frozen_instruction = fx_settlement(&policy, "fx_frozen_reserve", 1);
        frozen_instruction
            .clone()
            .execute(&ALICE_ID, &mut stx)
            .expect_err("ordinary transfer controls must gate the native payout leg");
        let source_id = AssetId::with_scope(
            policy.source_asset_definition_id.clone(),
            ALICE_ID.clone(),
            AssetBalanceScope::Dataspace(policy.source_dataspace),
        );
        let reserve_id = AssetId::with_scope(
            policy.destination_asset_definition_id.clone(),
            super::fx_corridor_escrow_account(&stx, &policy),
            AssetBalanceScope::Dataspace(policy.destination_dataspace),
        );
        let recipient_id = AssetId::with_scope(
            policy.destination_asset_definition_id.clone(),
            BOB_ID.clone(),
            AssetBalanceScope::Dataspace(policy.destination_dataspace),
        );
        assert_eq!(
            **stx.world.assets.get(&source_id).expect("source unchanged"),
            Quantity::from(10_u32),
        );
        assert_eq!(
            **stx
                .world
                .assets
                .get(&reserve_id)
                .expect("reserve unchanged"),
            Quantity::from(1_000_u32),
        );
        assert!(stx.world.assets.get(&recipient_id).is_none());
        assert!(
            stx.world
                .settlement_receipts
                .get(&frozen_instruction.settlement_id)
                .is_none(),
            "a preflight rejection must not record a committed settlement receipt",
        );
    }
    fn settlement_state_with_balances(
        delivery_balance: Quantity,
        payment_balance: Quantity,
    ) -> (State, AssetDefinitionId, AssetDefinitionId) {
        let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
        let domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
        let alice = Account::new(ALICE_ID.clone()).build(&ALICE_ID);
        let bob = Account::new(BOB_ID.clone()).build(&ALICE_ID);
        let delivery_asset_id: AssetDefinitionId =
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "bond".parse().unwrap(),
            );
        let payment_asset_id: AssetDefinitionId =
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "usd".parse().unwrap(),
            );
        let delivery_def = AssetDefinition::numeric(
            delivery_asset_id.clone(),
            "bond".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&ALICE_ID);
        let payment_def = AssetDefinition::numeric(
            payment_asset_id.clone(),
            "usd".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&ALICE_ID);
        let alice_delivery = Asset::new(
            AssetId::new(delivery_asset_id.clone(), ALICE_ID.clone()),
            delivery_balance,
        );
        let bob_payment = Asset::new(
            AssetId::new(payment_asset_id.clone(), BOB_ID.clone()),
            payment_balance,
        );
        let world = World::with_assets(
            [domain],
            [alice, bob],
            [delivery_def, payment_def],
            [alice_delivery, bob_payment],
            [],
        );
        let kura = Kura::blank_kura_for_testing();
        let query = LiveQueryStore::start_test();
        let state = State::new(world, kura, query);
        (state, delivery_asset_id, payment_asset_id)
    }
    fn settlement_state_with_payment_spec(
        payment_spec: NumericSpec,
    ) -> (State, AssetDefinitionId, AssetDefinitionId) {
        let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
        let domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
        let alice = Account::new(ALICE_ID.clone()).build(&ALICE_ID);
        let bob = Account::new(BOB_ID.clone()).build(&ALICE_ID);
        let delivery_asset_id: AssetDefinitionId =
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "bond".parse().unwrap(),
            );
        let payment_asset_id: AssetDefinitionId =
            iroha_data_model::asset::AssetDefinitionId::derive_from_components(
                DomainId::try_new("wonderland", "universal").unwrap(),
                "usd".parse().unwrap(),
            );
        let delivery_def = AssetDefinition::new(
            delivery_asset_id.clone(),
            "bond".to_owned(),
            NumericSpec::integer(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&ALICE_ID);
        let payment_def = AssetDefinition::new(
            payment_asset_id.clone(),
            "usd".to_owned(),
            payment_spec,
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&ALICE_ID);
        let alice_delivery = Asset::new(
            AssetId::new(delivery_asset_id.clone(), ALICE_ID.clone()),
            Quantity::from(5_u32),
        );
        let bob_payment = Asset::new(
            AssetId::new(payment_asset_id.clone(), BOB_ID.clone()),
            Quantity::from(2_u32),
        );
        let world = World::with_assets(
            [domain],
            [alice, bob],
            [delivery_def, payment_def],
            [alice_delivery, bob_payment],
            [],
        );
        let kura = Kura::blank_kura_for_testing();
        let query = LiveQueryStore::start_test();
        let state = State::new(world, kura, query);
        (state, delivery_asset_id, payment_asset_id)
    }
    #[test]
    fn dvp_rejects_unilateral_counterparty_debit() {
        let (state, delivery_def_id, payment_def_id) = settlement_state();
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction();
        let instruction = DvpIsi::new(
            SettlementId::new(
                ALICE_ID.clone(),
                "dvp_without_consent".parse().expect("settlement id"),
            ),
            SettlementLeg::new(
                delivery_def_id.clone(),
                Quantity::one(),
                ALICE_ID.clone(),
                BOB_ID.clone(),
            ),
            SettlementLeg::new(
                payment_def_id.clone(),
                Quantity::from(1_000_u32),
                BOB_ID.clone(),
                ALICE_ID.clone(),
            ),
            SettlementPlan::default(),
        );
        let error = instruction
            .execute(&ALICE_ID, &mut stx)
            .expect_err("initiator must not debit an unconsenting counterparty");
        assert!(
            error.to_string().contains("exact consent"),
            "unexpected error: {error}"
        );
        assert_eq!(
            asset_balance_or_zero(&stx, &AssetId::new(delivery_def_id, ALICE_ID.clone())),
            Quantity::from(10_u32)
        );
        assert_eq!(
            asset_balance_or_zero(&stx, &AssetId::new(payment_def_id, BOB_ID.clone())),
            Quantity::from(1_000_u32)
        );
    }
    #[test]
    fn pvp_rejects_unilateral_counterparty_debit() {
        let (state, primary_def_id, counter_def_id) = settlement_state();
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction();
        let instruction = PvpIsi::new(
            SettlementId::new(
                ALICE_ID.clone(),
                "pvp_without_consent".parse().expect("settlement id"),
            ),
            SettlementLeg::new(
                primary_def_id.clone(),
                Quantity::from(5_u32),
                ALICE_ID.clone(),
                BOB_ID.clone(),
            ),
            SettlementLeg::new(
                counter_def_id.clone(),
                Quantity::from(500_u32),
                BOB_ID.clone(),
                ALICE_ID.clone(),
            ),
            SettlementPlan::default(),
        );
        let error = instruction
            .execute(&ALICE_ID, &mut stx)
            .expect_err("initiator must not debit an unconsenting FX counterparty");
        assert!(
            error.to_string().contains("exact consent"),
            "unexpected error: {error}"
        );
        assert_eq!(
            asset_balance_or_zero(&stx, &AssetId::new(primary_def_id, ALICE_ID.clone())),
            Quantity::from(10_u32)
        );
        assert_eq!(
            asset_balance_or_zero(&stx, &AssetId::new(counter_def_id, BOB_ID.clone())),
            Quantity::from(1_000_u32)
        );
    }
    #[test]
    fn failed_bilateral_attempts_do_not_grow_consensus_state_or_pin_entities() {
        let (state, _delivery_def_id, payment_def_id) = settlement_state();
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction();
        let victim_account = CARPENTER_ID.clone();
        Register::account(NewAccount::new(victim_account.clone()))
            .execute(&ALICE_ID, &mut stx)
            .expect("register otherwise-unreferenced victim account");
        let victim_definition = AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").expect("domain id"),
            "pin_target".parse().expect("asset name"),
        );
        Register::asset_definition(AssetDefinition::numeric(
            victim_definition.clone(),
            "pin_target".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        ))
        .execute(&ALICE_ID, &mut stx)
        .expect("register otherwise-unreferenced victim asset definition");
        let settlement_id: SettlementId = SettlementId::new(
            ALICE_ID.clone(),
            "failed_pin_attempt".parse().expect("settlement id"),
        );
        let instruction = DvpIsi::new(
            settlement_id.clone(),
            SettlementLeg::new(
                victim_definition.clone(),
                Quantity::one(),
                ALICE_ID.clone(),
                victim_account.clone(),
            ),
            SettlementLeg::new(
                payment_def_id,
                Quantity::one(),
                victim_account.clone(),
                ALICE_ID.clone(),
            ),
            SettlementPlan::default(),
        );
        let receipts_before = stx.world.settlement_receipts.len();
        let events_before = stx.world.internal_event_buf.len();
        let transcripts_before = stx.pending_transfer_transcript_count_for_testing();
        for _ in 0..16 {
            let error = instruction
                .clone()
                .execute(&ALICE_ID, &mut stx)
                .expect_err("unconsented victim debit must fail");
            assert!(error.to_string().contains("exact consent"));
        }
        assert_eq!(
            stx.world.settlement_receipts.len(),
            receipts_before,
            "repeated failures must not grow the consensus receipt map"
        );
        assert!(stx.world.settlement_receipts.get(&settlement_id).is_none());
        assert_eq!(
            stx.world.internal_event_buf.len(),
            events_before,
            "failed attempts must not emit asset movement events"
        );
        assert_eq!(
            stx.pending_transfer_transcript_count_for_testing(),
            transcripts_before,
            "failed attempts must not stage transfer transcripts"
        );
        Unregister::asset_definition(victim_definition.clone())
            .execute(&ALICE_ID, &mut stx)
            .expect("failed settlement references must not pin an asset definition");
        Unregister::account(victim_account.clone())
            .execute(&ALICE_ID, &mut stx)
            .expect("failed settlement references must not pin an account");
        assert!(
            stx.world
                .asset_definitions
                .get(&victim_definition)
                .is_none()
        );
        assert!(stx.world.accounts.get(&victim_account).is_none());
    }
    #[test]
    fn dvp_consent_is_bound_to_exact_terms_and_settlement_id_is_one_shot() {
        let (state, delivery_def_id, payment_def_id) =
            settlement_state_with_balances(Quantity::from(20_u32), Quantity::from(2_000_u32));
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction_for_fastpq_testing(iroha_crypto::Hash::prehashed(
            [0xD7; iroha_crypto::Hash::LENGTH],
        ));
        let instruction = DvpIsi::new(
            SettlementId::new(
                ALICE_ID.clone(),
                "dvp_exact_consent".parse().expect("settlement id"),
            ),
            SettlementLeg::new(
                delivery_def_id,
                Quantity::from(5_u32),
                ALICE_ID.clone(),
                BOB_ID.clone(),
            ),
            SettlementLeg::new(
                payment_def_id,
                Quantity::from(500_u32),
                BOB_ID.clone(),
                ALICE_ID.clone(),
            ),
            SettlementPlan::default(),
        );
        grant_dvp_consent(&mut stx, &ALICE_ID, &instruction);
        let settlement_id = instruction.settlement_id().clone();
        let mut changed_terms = instruction.clone();
        changed_terms.payment_leg.quantity = Quantity::from(501_u32);
        let error = changed_terms
            .execute(&ALICE_ID, &mut stx)
            .expect_err("changed terms require fresh counterparty consent");
        assert!(error.to_string().contains("exact consent"));
        assert!(
            stx.world.settlement_receipts.get(&settlement_id).is_none(),
            "a rejected substitution must not consume or persist the settlement id"
        );
        instruction
            .clone()
            .execute(&ALICE_ID, &mut stx)
            .expect("the exactly authorized settlement must execute");
        let committed_receipt = stx
            .world
            .settlement_receipts
            .get(&settlement_id)
            .cloned()
            .expect("successful settlement records one receipt");
        let events_after_success = stx.world.internal_event_buf.len();
        let transcripts_after_success = stx.pending_transfer_transcript_count_for_testing();
        let error = instruction
            .execute(&ALICE_ID, &mut stx)
            .expect_err("a committed settlement id must not execute twice");
        assert!(error.to_string().contains("already been committed"));
        assert_eq!(
            stx.world.settlement_receipts.get(&settlement_id),
            Some(&committed_receipt),
            "replay must not replace or append to the committed receipt"
        );
        assert_eq!(
            stx.world.internal_event_buf.len(),
            events_after_success,
            "replay must not emit value-movement events"
        );
        assert_eq!(
            stx.pending_transfer_transcript_count_for_testing(),
            transcripts_after_success,
            "replay must not stage another transfer transcript"
        );
    }
    #[test]
    fn dvp_respects_counterparty_outgoing_freeze() {
        let (state, delivery_def_id, payment_def_id) = settlement_state();
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction();
        let instruction = DvpIsi::new(
            SettlementId::new(
                ALICE_ID.clone(),
                "dvp_frozen_counterparty".parse().expect("settlement id"),
            ),
            SettlementLeg::new(
                delivery_def_id.clone(),
                Quantity::from(5_u32),
                ALICE_ID.clone(),
                BOB_ID.clone(),
            ),
            SettlementLeg::new(
                payment_def_id.clone(),
                Quantity::from(500_u32),
                BOB_ID.clone(),
                ALICE_ID.clone(),
            ),
            SettlementPlan::default(),
        );
        grant_dvp_consent(&mut stx, &ALICE_ID, &instruction);
        let mut control = AssetTransferControlRecord::new(payment_def_id.clone());
        control.availability_revision = 1;
        control.outgoing_availability = AssetTransferAvailability::Disabled;
        crate::smartcontracts::isi::asset::isi::update_control_record(&mut stx, &BOB_ID, control)
            .expect("install outgoing freeze");
        let error = instruction
            .execute(&ALICE_ID, &mut stx)
            .expect_err("settlement must honor the counterparty freeze");
        assert!(matches!(
            error,
            InstructionExecutionError::AssetTransferAdmission(
                AssetTransferAdmissionError::OutgoingDisabled(_)
            )
        ));
        assert_eq!(
            asset_balance_or_zero(&stx, &AssetId::new(delivery_def_id, ALICE_ID.clone())),
            Quantity::from(10_u32)
        );
        assert_eq!(
            asset_balance_or_zero(&stx, &AssetId::new(payment_def_id, BOB_ID.clone())),
            Quantity::from(1_000_u32)
        );
    }
    #[test]
    fn dvp_moves_assets_after_exact_counterparty_consent() {
        let (state, delivery_def_id, payment_def_id) = settlement_state();
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction_for_fastpq_testing(iroha_crypto::Hash::prehashed(
            [0xD7; iroha_crypto::Hash::LENGTH],
        ));
        let settlement_id: SettlementId =
            SettlementId::new(ALICE_ID.clone(), "dvp_trade".parse().unwrap());
        let delivery_leg = SettlementLeg::new(
            delivery_def_id.clone(),
            Quantity::from(10_u32),
            ALICE_ID.clone(),
            BOB_ID.clone(),
        );
        let payment_leg = SettlementLeg::new(
            payment_def_id.clone(),
            Quantity::from(1_000_u32),
            BOB_ID.clone(),
            ALICE_ID.clone(),
        );
        let plan = SettlementPlan::new(
            SettlementExecutionOrder::PaymentThenDelivery,
            SettlementAtomicity::AllOrNothing,
        );
        let instruction = DvpIsi {
            settlement_id: settlement_id.clone(),
            delivery_leg,
            payment_leg,
            plan,
            metadata: Metadata::default(),
        };
        grant_dvp_consent(&mut stx, &ALICE_ID, &instruction);
        let internal_events_before = stx.world.internal_event_buf.len();
        let transcripts_before = stx.pending_transfer_transcript_count_for_testing();
        instruction
            .execute(&ALICE_ID, &mut stx)
            .expect("DvP execution succeeds");
        let emitted_events = &stx.world.internal_event_buf[internal_events_before..];
        assert_eq!(
            emitted_events.len(),
            8,
            "each bilateral leg creates its destination and emits Removed, Added, and Transferred"
        );
        assert_eq!(
            emitted_events
                .iter()
                .filter(|event| matches!(
                    event.as_ref(),
                    DataEvent::Asset(AssetEvent::Transferred(_))
                ))
                .count(),
            2,
            "each bilateral leg must emit one canonical transfer event"
        );
        assert_eq!(
            stx.pending_transfer_transcript_count_for_testing(),
            transcripts_before + 1,
            "both bilateral deltas must share one atomic FastPQ transcript"
        );
        let alice_bond = AssetId::new(delivery_def_id.clone(), ALICE_ID.clone());
        let bob_bond = AssetId::new(delivery_def_id.clone(), BOB_ID.clone());
        assert!(
            stx.world.assets.get(&alice_bond).is_none(),
            "delivery asset should leave the seller"
        );
        assert_eq!(
            **stx.world.assets.get(&bob_bond).expect("buyer bond balance"),
            Quantity::from(10_u32)
        );
        let alice_cash = AssetId::new(payment_def_id.clone(), ALICE_ID.clone());
        let bob_cash = AssetId::new(payment_def_id.clone(), BOB_ID.clone());
        assert_eq!(
            **stx
                .world
                .assets
                .get(&alice_cash)
                .expect("seller payment balance"),
            Quantity::from(1_000_u32)
        );
        assert!(
            stx.world.assets.get(&bob_cash).is_none(),
            "payment asset should be debited from the payer"
        );
        let receipt = stx
            .world
            .settlement_receipts
            .get(&settlement_id)
            .cloned()
            .expect("settlement receipt recorded");
        let SettlementDetails::Dvp(iroha_data_model::isi::DvpSettlementDetails {
            delivery,
            payment,
            order,
        }) = &receipt.details
        else {
            panic!("Dvp typed receipt");
        };
        assert_eq!(receipt.authority, ALICE_ID.clone());
        assert_eq!(*order, plan.order());
        assert_eq!(receipt.metadata, Metadata::default());
        assert_eq!(receipt.block_height, stx._curr_block.height().get());
        assert_eq!(receipt.block_hash, stx._curr_block.hash());
        assert_eq!(delivery.source.account(), &*ALICE_ID);
        assert_eq!(delivery.destination.account(), &*BOB_ID);
        assert_eq!(payment.source.account(), &*BOB_ID);
        assert_eq!(payment.destination.account(), &*ALICE_ID);
        assert!(
            receipt
                .details
                .movements()
                .all(|movement| movement.source.scope() == movement.destination.scope())
        );
    }
    #[test]
    fn dvp_persists_balances_after_commit_on_universal_coordinator() {
        let (state, delivery_def_id, payment_def_id) = settlement_state();
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut state_block = state.block(header);
        let mut stx = state_block.transaction_for_fastpq_testing(iroha_crypto::Hash::prehashed(
            [0xD7; iroha_crypto::Hash::LENGTH],
        ));
        let dataspace = DataSpaceId::UNIVERSAL;
        stx.current_dataspace_id = Some(dataspace);
        stx.world.current_dataspace_id = Some(dataspace);
        let instruction = DvpIsi {
            settlement_id: SettlementId::new(ALICE_ID.clone(), "dvp_persisted".parse().unwrap()),
            delivery_leg: SettlementLeg::new(
                delivery_def_id.clone(),
                Quantity::from(10_u32),
                ALICE_ID.clone(),
                BOB_ID.clone(),
            ),
            payment_leg: SettlementLeg::new(
                payment_def_id.clone(),
                Quantity::from(1_000_u32),
                BOB_ID.clone(),
                ALICE_ID.clone(),
            ),
            plan: SettlementPlan::new(
                SettlementExecutionOrder::PaymentThenDelivery,
                SettlementAtomicity::AllOrNothing,
            ),
            metadata: Metadata::default(),
        };
        grant_dvp_consent(&mut stx, &ALICE_ID, &instruction);
        instruction
            .execute(&ALICE_ID, &mut stx)
            .expect("DvP execution succeeds");
        stx.apply();
        state_block
            .commit_world_overlay_for_testing()
            .expect("commit state block");
        let view = state.view();
        let world = view.world();
        let alice_bond = AssetId::new(delivery_def_id.clone(), ALICE_ID.clone());
        let bob_bond = AssetId::new(delivery_def_id.clone(), BOB_ID.clone());
        let alice_cash = AssetId::new(payment_def_id.clone(), ALICE_ID.clone());
        let bob_cash = AssetId::new(payment_def_id.clone(), BOB_ID.clone());
        assert!(
            world.asset(&alice_bond).is_err(),
            "seller delivery balance should stay debited after commit"
        );
        assert_eq!(
            world
                .asset(&bob_bond)
                .expect("buyer bond balance")
                .value()
                .as_ref()
                .clone(),
            Quantity::from(10_u32),
        );
        assert_eq!(
            world
                .asset(&alice_cash)
                .expect("seller cash balance")
                .value()
                .as_ref()
                .clone(),
            Quantity::from(1_000_u32),
        );
        assert!(
            world.asset(&bob_cash).is_err(),
            "payer cash balance should stay debited after commit"
        );
    }
    #[test]
    fn dvp_persists_partial_debits_after_commit() {
        let (state, delivery_def_id, payment_def_id) =
            settlement_state_with_balances(Quantity::from(100u32), Quantity::from(200u32));
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut state_block = state.block(header);
        let mut stx = state_block.transaction_for_fastpq_testing(iroha_crypto::Hash::prehashed(
            [0xD7; iroha_crypto::Hash::LENGTH],
        ));
        stx.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        stx.world.current_dataspace_id = Some(DataSpaceId::UNIVERSAL);
        let instruction = DvpIsi {
            settlement_id: SettlementId::new(
                ALICE_ID.clone(),
                "dvp_partial_commit".parse().unwrap(),
            ),
            delivery_leg: SettlementLeg::new(
                delivery_def_id.clone(),
                Quantity::from(30_u32),
                ALICE_ID.clone(),
                BOB_ID.clone(),
            ),
            payment_leg: SettlementLeg::new(
                payment_def_id.clone(),
                Quantity::from(45_u32),
                BOB_ID.clone(),
                ALICE_ID.clone(),
            ),
            plan: SettlementPlan::new(
                SettlementExecutionOrder::DeliveryThenPayment,
                SettlementAtomicity::AllOrNothing,
            ),
            metadata: Metadata::default(),
        };
        grant_dvp_consent(&mut stx, &ALICE_ID, &instruction);
        instruction
            .execute(&ALICE_ID, &mut stx)
            .expect("DvP execution succeeds");
        stx.apply();
        state_block
            .commit_world_overlay_for_testing()
            .expect("commit state block");
        let view = state.view();
        let world = view.world();
        let alice_bond = AssetId::new(delivery_def_id.clone(), ALICE_ID.clone());
        let bob_bond = AssetId::new(delivery_def_id.clone(), BOB_ID.clone());
        let alice_cash = AssetId::new(payment_def_id.clone(), ALICE_ID.clone());
        let bob_cash = AssetId::new(payment_def_id.clone(), BOB_ID.clone());
        assert_eq!(
            world
                .asset(&alice_bond)
                .expect("seller delivery balance")
                .value()
                .as_ref()
                .clone(),
            Quantity::from(70_u32),
        );
        assert_eq!(
            world
                .asset(&bob_bond)
                .expect("buyer delivery balance")
                .value()
                .as_ref()
                .clone(),
            Quantity::from(30_u32),
        );
        assert_eq!(
            world
                .asset(&alice_cash)
                .expect("seller payment balance")
                .value()
                .as_ref()
                .clone(),
            Quantity::from(45_u32),
        );
        assert_eq!(
            world
                .asset(&bob_cash)
                .expect("buyer payment balance")
                .value()
                .as_ref()
                .clone(),
            Quantity::from(155_u32),
        );
    }
    #[test]
    fn dvp_rejects_counterparty_consent_outside_execution_dataspace() {
        let ds1 = DataSpaceId::new(7);
        let ds2 = DataSpaceId::new(11);
        let domain_id: DomainId = DomainId::try_new("wonderland", "universal").unwrap();
        let domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
        let alice = Account::new(ALICE_ID.clone()).build(&ALICE_ID);
        let bob = Account::new(BOB_ID.clone()).build(&ALICE_ID);
        let delivery_def_id = AssetDefinitionId::derive_from_components(
            domain_id.clone(),
            "bond".parse().expect("delivery asset name"),
        );
        let payment_def_id = AssetDefinitionId::derive_from_components(
            domain_id.clone(),
            "usd".parse().expect("payment asset name"),
        );
        let delivery_def = {
            let __asset_definition_id = delivery_def_id.clone();
            AssetDefinition::numeric(
                __asset_definition_id.clone(),
                "bond".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::DataspaceRestricted,
                Some(domain_id.clone()),
            )
        }
        .build(&ALICE_ID);
        let payment_def = {
            let __asset_definition_id = payment_def_id.clone();
            AssetDefinition::numeric(
                __asset_definition_id.clone(),
                "usd".to_owned(),
                iroha_data_model::asset::AssetBalancePolicy::DataspaceRestricted,
                Some(domain_id),
            )
        }
        .build(&ALICE_ID);
        let alice_delivery = Asset::new(
            AssetId::with_scope(
                delivery_def_id.clone(),
                ALICE_ID.clone(),
                iroha_data_model::asset::AssetBalanceScope::Dataspace(ds1),
            ),
            Quantity::from(10_u32),
        );
        let bob_payment = Asset::new(
            AssetId::with_scope(
                payment_def_id.clone(),
                BOB_ID.clone(),
                iroha_data_model::asset::AssetBalanceScope::Dataspace(ds2),
            ),
            Quantity::from(1_000_u32),
        );
        let world = World::with_assets(
            [domain],
            [alice, bob],
            [delivery_def, payment_def],
            [alice_delivery, bob_payment],
            [],
        );
        let kura = Kura::blank_kura_for_testing();
        let query = LiveQueryStore::start_test();
        let state = State::new(world, kura, query);
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction();
        stx.current_dataspace_id = Some(ds1);
        stx.world.current_dataspace_id = Some(ds1);
        let instruction = DvpIsi {
            settlement_id: SettlementId::new(ALICE_ID.clone(), "dvp_cross_scope".parse().unwrap()),
            delivery_leg: SettlementLeg::new(
                delivery_def_id.clone(),
                Quantity::from(10_u32),
                ALICE_ID.clone(),
                BOB_ID.clone(),
            ),
            payment_leg: SettlementLeg::new(
                payment_def_id.clone(),
                Quantity::from(1_000_u32),
                BOB_ID.clone(),
                ALICE_ID.clone(),
            ),
            plan: SettlementPlan::new(
                SettlementExecutionOrder::DeliveryThenPayment,
                SettlementAtomicity::AllOrNothing,
            ),
            metadata: Metadata::default(),
        };
        let mut wrong_scope_instruction = instruction.clone();
        wrong_scope_instruction.settlement_id = SettlementId::new(
            ALICE_ID.clone(),
            "dvp_cross_scope_wrong".parse().expect("settlement id"),
        );
        grant_exact_settlement_consent(
            &mut stx,
            &ALICE_ID,
            AssetId::with_scope(
                payment_def_id.clone(),
                BOB_ID.clone(),
                AssetBalanceScope::Dataspace(ds1),
            ),
            wrong_scope_instruction.settlement_id(),
            wrong_scope_instruction.intent_hash(),
        );
        wrong_scope_instruction
            .execute(&ALICE_ID, &mut stx)
            .expect_err("consent for an unfunded scope must not discover another private bucket");
        assert_eq!(
            asset_balance_or_zero(
                &stx,
                &AssetId::with_scope(
                    delivery_def_id.clone(),
                    ALICE_ID.clone(),
                    AssetBalanceScope::Dataspace(ds1),
                ),
            ),
            Quantity::from(10_u32),
        );
        assert_eq!(
            asset_balance_or_zero(
                &stx,
                &AssetId::with_scope(
                    payment_def_id.clone(),
                    BOB_ID.clone(),
                    AssetBalanceScope::Dataspace(ds2),
                ),
            ),
            Quantity::from(1_000_u32),
        );
        grant_dvp_consent(&mut stx, &ALICE_ID, &instruction);
        let events_before = stx.world.internal_event_buf.len();
        let transcripts_before = stx.pending_transfer_transcript_count_for_testing();
        let error = instruction
            .clone()
            .execute(&ALICE_ID, &mut stx)
            .expect_err("counterparty consent cannot authorize execution in a different dataspace");
        assert!(
            matches!(error,
                InstructionExecutionError::InvariantViolation(ref message)
                    if message.contains("committed public balance scope 11 does not match execution dataspace 7")
            ),
            "unexpected scope rejection: {error:?}"
        );
        for (definition, source, destination, dataspace, balance) in [
            (
                delivery_def_id,
                ALICE_ID.clone(),
                BOB_ID.clone(),
                ds1,
                10_u32,
            ),
            (
                payment_def_id,
                BOB_ID.clone(),
                ALICE_ID.clone(),
                ds2,
                1_000_u32,
            ),
        ] {
            assert_eq!(
                asset_balance_or_zero(
                    &stx,
                    &AssetId::with_scope(
                        definition.clone(),
                        source,
                        AssetBalanceScope::Dataspace(dataspace),
                    )
                ),
                Quantity::from(balance)
            );
            assert_eq!(
                asset_balance_or_zero(
                    &stx,
                    &AssetId::with_scope(
                        definition,
                        destination,
                        AssetBalanceScope::Dataspace(dataspace),
                    )
                ),
                Quantity::zero()
            );
        }
        assert_eq!(stx.world.internal_event_buf.len(), events_before);
        assert_eq!(
            stx.pending_transfer_transcript_count_for_testing(),
            transcripts_before
        );
        assert!(
            stx.world
                .settlement_receipts
                .get(instruction.settlement_id())
                .is_none()
        );
    }
    #[test]
    fn dvp_delivery_first_rejects_invalid_precision_without_moving_assets() {
        let (state, delivery_def_id, payment_def_id) =
            settlement_state_with_payment_spec(NumericSpec::fractional(2));
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction();
        let settlement_id: SettlementId = SettlementId::new(
            ALICE_ID.clone(),
            "dvp_precision_delivery_first".parse().unwrap(),
        );
        let instruction = DvpIsi {
            settlement_id: settlement_id.clone(),
            delivery_leg: SettlementLeg::new(
                delivery_def_id.clone(),
                Quantity::from(5_u32),
                ALICE_ID.clone(),
                BOB_ID.clone(),
            ),
            payment_leg: SettlementLeg::new(
                payment_def_id.clone(),
                quantity("1.001"),
                BOB_ID.clone(),
                ALICE_ID.clone(),
            ),
            plan: SettlementPlan::new(
                SettlementExecutionOrder::DeliveryThenPayment,
                SettlementAtomicity::AllOrNothing,
            ),
            metadata: Metadata::default(),
        };
        grant_dvp_consent(&mut stx, &ALICE_ID, &instruction);
        let err = instruction
            .execute(&ALICE_ID, &mut stx)
            .expect_err("invalid payment precision must reject the entire DvP");
        assert!(
            matches!(
                err,
                InstructionExecutionError::Evaluate(
                    iroha_data_model::isi::error::InstructionEvaluationError::Type(_)
                )
            ),
            "unexpected error: {err:?}"
        );
        let alice_delivery = AssetId::new(delivery_def_id.clone(), ALICE_ID.clone());
        let bob_delivery = AssetId::new(delivery_def_id.clone(), BOB_ID.clone());
        assert_eq!(
            **stx
                .world
                .assets
                .get(&alice_delivery)
                .expect("seller delivery balance"),
            Quantity::from(5_u32),
            "seller balance must remain unchanged"
        );
        assert!(stx.world.assets.get(&bob_delivery).is_none());
        let bob_cash = AssetId::new(payment_def_id.clone(), BOB_ID.clone());
        let alice_cash = AssetId::new(payment_def_id.clone(), ALICE_ID.clone());
        assert_eq!(
            **stx.world.assets.get(&bob_cash).expect("payer cash balance"),
            Quantity::from(2_u32),
            "payer cash must remain unchanged"
        );
        assert!(stx.world.assets.get(&alice_cash).is_none());
    }
    #[test]
    #[allow(clippy::too_many_lines)]
    fn dvp_payment_first_rejects_invalid_precision_without_moving_assets() {
        let (state, delivery_def_id, payment_def_id) =
            settlement_state_with_payment_spec(NumericSpec::fractional(2));
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction();
        let alice_delivery = AssetId::new(delivery_def_id.clone(), ALICE_ID.clone());
        let bob_delivery = AssetId::new(delivery_def_id.clone(), BOB_ID.clone());
        let bob_cash = AssetId::new(payment_def_id.clone(), BOB_ID.clone());
        let initial_alice_delivery = stx
            .world
            .assets
            .get(&alice_delivery)
            .cloned()
            .map(Owned::into_inner)
            .expect("seller delivery balance");
        let initial_bob_delivery = stx
            .world
            .assets
            .get(&bob_delivery)
            .cloned()
            .map_or_else(Quantity::zero, Owned::into_inner);
        let initial_bob_cash = stx
            .world
            .assets
            .get(&bob_cash)
            .cloned()
            .map(Owned::into_inner)
            .expect("payer cash balance");
        let settlement_id: SettlementId = SettlementId::new(
            ALICE_ID.clone(),
            "dvp_precision_payment_first".parse().unwrap(),
        );
        let instruction = DvpIsi {
            settlement_id: settlement_id.clone(),
            delivery_leg: SettlementLeg::new(
                delivery_def_id.clone(),
                Quantity::from(5_u32),
                ALICE_ID.clone(),
                BOB_ID.clone(),
            ),
            payment_leg: SettlementLeg::new(
                payment_def_id.clone(),
                quantity("1.001"),
                BOB_ID.clone(),
                ALICE_ID.clone(),
            ),
            plan: SettlementPlan::new(
                SettlementExecutionOrder::PaymentThenDelivery,
                SettlementAtomicity::AllOrNothing,
            ),
            metadata: Metadata::default(),
        };
        grant_dvp_consent(&mut stx, &ALICE_ID, &instruction);
        let err = instruction
            .execute(&ALICE_ID, &mut stx)
            .expect_err("invalid payment precision must reject the entire DvP");
        assert!(
            matches!(
                err,
                InstructionExecutionError::Evaluate(
                    iroha_data_model::isi::error::InstructionEvaluationError::Type(_)
                )
            ),
            "unexpected error: {err:?}"
        );
        let alice_after = stx
            .world
            .assets
            .get(&alice_delivery)
            .cloned()
            .map_or_else(Quantity::zero, Owned::into_inner);
        let bob_delivery_after = stx
            .world
            .assets
            .get(&bob_delivery)
            .cloned()
            .map_or_else(Quantity::zero, Owned::into_inner);
        let bob_cash_after = stx
            .world
            .assets
            .get(&bob_cash)
            .cloned()
            .map(Owned::into_inner)
            .expect("payer cash balance");
        assert_eq!(
            alice_after, initial_alice_delivery,
            "delivery balance must remain unchanged after invalid payment precision"
        );
        assert_eq!(
            bob_delivery_after, initial_bob_delivery,
            "buyer delivery balance should remain unchanged"
        );
        assert_eq!(
            bob_cash_after, initial_bob_cash,
            "payer cash balance should be unaffected"
        );
        assert!(
            stx.world.settlement_receipts.get(&settlement_id).is_none(),
            "a rejected DvP must not create consensus receipt state"
        );
    }
    #[test]
    fn dvp_holding_limit_rejects_first_leg_without_mutation() {
        let (state, delivery_def_id, payment_def_id) = settlement_state();
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction();
        set_test_holding_limit(&mut stx, &BOB_ID, &delivery_def_id, Quantity::zero());
        let alice_delivery = AssetId::new(delivery_def_id.clone(), ALICE_ID.clone());
        let bob_delivery = AssetId::new(delivery_def_id.clone(), BOB_ID.clone());
        let bob_payment = AssetId::new(payment_def_id.clone(), BOB_ID.clone());
        let alice_payment = AssetId::new(payment_def_id.clone(), ALICE_ID.clone());
        let external_events_before = stx.world.external_event_buf.len();
        let internal_events_before = stx.world.internal_event_buf.len();
        let settlement_id: SettlementId =
            SettlementId::new(ALICE_ID.clone(), "dvp_holding_first".parse().unwrap());
        let instruction = DvpIsi {
            settlement_id: settlement_id.clone(),
            delivery_leg: SettlementLeg::new(
                delivery_def_id,
                Quantity::from(5_u32),
                ALICE_ID.clone(),
                BOB_ID.clone(),
            ),
            payment_leg: SettlementLeg::new(
                payment_def_id,
                Quantity::from(100_u32),
                BOB_ID.clone(),
                ALICE_ID.clone(),
            ),
            plan: SettlementPlan::new(
                SettlementExecutionOrder::DeliveryThenPayment,
                SettlementAtomicity::AllOrNothing,
            ),
            metadata: Metadata::default(),
        };
        grant_dvp_consent(&mut stx, &ALICE_ID, &instruction);
        let error = instruction
            .execute(&ALICE_ID, &mut stx)
            .expect_err("first destination holding limit must reject DvP");
        assert_holding_limit_error(&error);
        assert_eq!(
            asset_balance_or_zero(&stx, &alice_delivery),
            Quantity::from(10_u32)
        );
        assert_eq!(asset_balance_or_zero(&stx, &bob_delivery), Quantity::zero());
        assert_eq!(
            asset_balance_or_zero(&stx, &bob_payment),
            Quantity::from(1_000_u32)
        );
        assert_eq!(
            asset_balance_or_zero(&stx, &alice_payment),
            Quantity::zero()
        );
        assert_eq!(stx.world.external_event_buf.len(), external_events_before);
        assert_eq!(stx.world.internal_event_buf.len(), internal_events_before);
        assert!(
            stx.world.settlement_receipts.get(&settlement_id).is_none(),
            "a rejected DvP must not create consensus receipt state"
        );
    }
    #[test]
    fn dvp_holding_limit_rolls_back_first_leg_for_atomic_plans() {
        {
            let atomicity = SettlementAtomicity::AllOrNothing;
            let (state, delivery_def_id, payment_def_id) = settlement_state();
            let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
            let mut block = state.block(header);
            let mut stx = block.transaction();
            set_test_holding_limit(&mut stx, &ALICE_ID, &delivery_def_id, Quantity::zero());
            set_test_holding_limit(&mut stx, &ALICE_ID, &payment_def_id, Quantity::zero());
            let alice_delivery = AssetId::new(delivery_def_id.clone(), ALICE_ID.clone());
            let bob_delivery = AssetId::new(delivery_def_id.clone(), BOB_ID.clone());
            let bob_payment = AssetId::new(payment_def_id.clone(), BOB_ID.clone());
            let alice_payment = AssetId::new(payment_def_id.clone(), ALICE_ID.clone());
            let mut delivery_metadata = Metadata::default();
            delivery_metadata.insert(
                "settlement_note".parse().expect("metadata key"),
                Json::new("restore on rollback".to_owned()),
            );
            stx.world
                .asset_metadata
                .insert(alice_delivery.clone(), delivery_metadata.clone());
            let external_events_before = stx.world.external_event_buf.len();
            let internal_events_before = stx.world.internal_event_buf.len();
            let settlement_id: SettlementId =
                SettlementId::new(ALICE_ID.clone(), "dvp_holding_second".parse().unwrap());
            let instruction = DvpIsi {
                settlement_id: settlement_id.clone(),
                delivery_leg: SettlementLeg::new(
                    delivery_def_id.clone(),
                    Quantity::from(10_u32),
                    ALICE_ID.clone(),
                    BOB_ID.clone(),
                ),
                payment_leg: SettlementLeg::new(
                    payment_def_id,
                    Quantity::from(100_u32),
                    BOB_ID.clone(),
                    ALICE_ID.clone(),
                ),
                plan: SettlementPlan::new(SettlementExecutionOrder::DeliveryThenPayment, atomicity),
                metadata: Metadata::default(),
            };
            grant_dvp_consent(&mut stx, &ALICE_ID, &instruction);
            let error = instruction
                .execute(&ALICE_ID, &mut stx)
                .expect_err("second destination holding limit must reject DvP");
            assert_holding_limit_error(&error);
            assert_eq!(
                asset_balance_or_zero(&stx, &alice_delivery),
                Quantity::from(10_u32),
                "rollback must restore a source even when its current limit is lower"
            );
            assert_eq!(
                stx.world.asset_metadata.get(&alice_delivery),
                Some(&delivery_metadata),
                "rollback must restore metadata removed by a full-balance debit"
            );
            assert_eq!(asset_balance_or_zero(&stx, &bob_delivery), Quantity::zero());
            assert_eq!(
                asset_balance_or_zero(&stx, &bob_payment),
                Quantity::from(1_000_u32)
            );
            assert_eq!(
                asset_balance_or_zero(&stx, &alice_payment),
                Quantity::zero()
            );
            assert_eq!(stx.world.external_event_buf.len(), external_events_before);
            assert_eq!(stx.world.internal_event_buf.len(), internal_events_before);
            assert!(
                stx.world
                    .asset_definition_assets
                    .get(&(delivery_def_id.clone(), bob_delivery.clone()))
                    .is_none(),
                "rollback must remove the created destination from holder indexes"
            );
            assert!(
                stx.world.settlement_receipts.get(&settlement_id).is_none(),
                "a rejected DvP must not create consensus receipt state"
            );
        }
    }
    #[test]
    fn dvp_failure_preserves_balances() {
        let (state, delivery_def_id, payment_def_id) = settlement_state();
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction();
        let alice_bond_id = AssetId::new(delivery_def_id.clone(), ALICE_ID.clone());
        let bob_cash_id = AssetId::new(payment_def_id.clone(), BOB_ID.clone());
        let initial_alice_bond = stx
            .world
            .assets
            .get(&alice_bond_id)
            .cloned()
            .map(Owned::into_inner)
            .expect("alice delivery balance");
        let initial_bob_cash = stx
            .world
            .assets
            .get(&bob_cash_id)
            .cloned()
            .map(Owned::into_inner)
            .expect("bob payment balance");
        let settlement_id: SettlementId =
            SettlementId::new(ALICE_ID.clone(), "dvp_fail".parse().unwrap());
        let instruction = DvpIsi {
            settlement_id: settlement_id.clone(),
            delivery_leg: SettlementLeg::new(
                delivery_def_id.clone(),
                Quantity::from(5_u32),
                ALICE_ID.clone(),
                BOB_ID.clone(),
            ),
            payment_leg: SettlementLeg::new(
                payment_def_id.clone(),
                Quantity::from(2_000_u32),
                BOB_ID.clone(),
                ALICE_ID.clone(),
            ),
            plan: SettlementPlan::default(),
            metadata: Metadata::default(),
        };
        grant_dvp_consent(&mut stx, &ALICE_ID, &instruction);
        let err = instruction
            .execute(&ALICE_ID, &mut stx)
            .expect_err("insufficient payment leg must fail");
        assert!(
            matches!(
                err,
                InstructionExecutionError::Math(MathError::NotEnoughQuantity)
            ),
            "unexpected error: {err:?}"
        );
        let alice_after = stx
            .world
            .assets
            .get(&alice_bond_id)
            .cloned()
            .map_or_else(Quantity::zero, Owned::into_inner);
        let bob_cash_after = stx
            .world
            .assets
            .get(&bob_cash_id)
            .cloned()
            .map_or_else(Quantity::zero, Owned::into_inner);
        assert_eq!(
            alice_after, initial_alice_bond,
            "seller bond balance changed"
        );
        assert_eq!(
            bob_cash_after, initial_bob_cash,
            "payer cash balance changed"
        );
        assert!(
            stx.world.settlement_receipts.get(&settlement_id).is_none(),
            "an insufficient-funds DvP must not create consensus receipt state"
        );
    }
    #[test]
    fn pvp_swaps_currencies_after_exact_counterparty_consent() {
        let (state, primary_def_id, counter_def_id) = settlement_state();
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction_for_fastpq_testing(iroha_crypto::Hash::prehashed(
            [0xD8; iroha_crypto::Hash::LENGTH],
        ));
        let settlement_id: SettlementId =
            SettlementId::new(ALICE_ID.clone(), "pvp_fx".parse().unwrap());
        let primary_leg = SettlementLeg::new(
            primary_def_id.clone(),
            Quantity::from(10_u32),
            ALICE_ID.clone(),
            BOB_ID.clone(),
        );
        let counter_leg = SettlementLeg::new(
            counter_def_id.clone(),
            Quantity::from(100_u32),
            BOB_ID.clone(),
            ALICE_ID.clone(),
        );
        let instruction = PvpIsi {
            settlement_id: settlement_id.clone(),
            primary_leg,
            counter_leg,
            plan: SettlementPlan::default(),
            metadata: Metadata::default(),
        };
        grant_pvp_consent(&mut stx, &ALICE_ID, &instruction);
        instruction
            .clone()
            .execute(&ALICE_ID, &mut stx)
            .expect("PvP execution succeeds");
        let alice_primary = AssetId::new(primary_def_id.clone(), ALICE_ID.clone());
        let bob_primary = AssetId::new(primary_def_id.clone(), BOB_ID.clone());
        assert!(
            stx.world.assets.get(&alice_primary).is_none(),
            "primary leg should debit initiating account"
        );
        assert_eq!(
            **stx
                .world
                .assets
                .get(&bob_primary)
                .expect("counterparty primary balance"),
            Quantity::from(10_u32)
        );
        let alice_counter = AssetId::new(counter_def_id.clone(), ALICE_ID.clone());
        let bob_counter = AssetId::new(counter_def_id.clone(), BOB_ID.clone());
        assert_eq!(
            **stx
                .world
                .assets
                .get(&alice_counter)
                .expect("initiator counter balance"),
            Quantity::from(100_u32)
        );
        let receipt = stx
            .world
            .settlement_receipts
            .get(&settlement_id)
            .cloned()
            .expect("settlement receipt recorded");
        let SettlementDetails::Pvp(iroha_data_model::isi::PvpSettlementDetails {
            primary,
            counter,
            order,
        }) = &receipt.details
        else {
            panic!("Pvp typed receipt");
        };
        assert_eq!(receipt.authority, ALICE_ID.clone());
        assert_eq!(*order, SettlementPlan::default().order());
        assert_eq!(receipt.block_height, stx._curr_block.height().get());
        assert_eq!(receipt.block_hash, stx._curr_block.hash());
        assert_eq!(primary.source.account(), &*ALICE_ID);
        assert_eq!(primary.destination.account(), &*BOB_ID);
        assert_eq!(counter.source.account(), &*BOB_ID);
        assert_eq!(counter.destination.account(), &*ALICE_ID);
        assert!(
            receipt
                .details
                .movements()
                .all(|movement| movement.source.scope() == movement.destination.scope())
        );
        assert_eq!(
            **stx
                .world
                .assets
                .get(&bob_counter)
                .expect("counterparty residual balance"),
            Quantity::from(900_u32)
        );
        let replay = instruction
            .execute(&ALICE_ID, &mut stx)
            .expect_err("a committed PvP settlement id must be one-shot");
        assert!(replay.to_string().contains("already been committed"));
        assert_eq!(
            stx.world.settlement_receipts.get(&settlement_id),
            Some(&receipt),
            "PvP replay must not replace or append to the committed receipt"
        );
    }
    #[test]
    fn pvp_component_refuses_unretained_invocation_before_balance_changes() {
        let (state, primary, counter) = settlement_state();
        let mut block = state.block(BlockHeader::new(nonzero!(1_u64), None, None, 0, 0));
        let mut transaction = block.transaction();
        let instruction = PvpIsi::new(
            SettlementId::new(ALICE_ID.clone(), "pvp_unretained_source".parse().unwrap()),
            SettlementLeg::new(
                primary.clone(),
                Quantity::from(10_u32),
                ALICE_ID.clone(),
                BOB_ID.clone(),
            ),
            SettlementLeg::new(
                counter.clone(),
                Quantity::from(100_u32),
                BOB_ID.clone(),
                ALICE_ID.clone(),
            ),
            SettlementPlan::default(),
        );
        grant_pvp_consent(&mut transaction, &ALICE_ID, &instruction);
        let transcripts = transaction.pending_transfer_transcript_count_for_testing();
        let error = instruction
            .clone()
            .execute(&ALICE_ID, &mut transaction)
            .expect_err("a hash alone cannot mint the retained finite source owner");
        assert!(
            error
                .to_string()
                .contains("FASTPQ source has no retained producer invocation")
        );
        assert_eq!(
            asset_balance_or_zero(&transaction, &AssetId::new(primary, ALICE_ID.clone())),
            Quantity::from(10_u32)
        );
        assert_eq!(
            asset_balance_or_zero(&transaction, &AssetId::new(counter, BOB_ID.clone())),
            Quantity::from(1_000_u32)
        );
        assert_eq!(
            transaction.pending_transfer_transcript_count_for_testing(),
            transcripts
        );
        assert!(
            transaction
                .world
                .settlement_receipts
                .get(instruction.settlement_id())
                .is_none()
        );
    }

    #[test]
    fn pvp_failure_preserves_balances() {
        let (state, primary_def_id, counter_def_id) = settlement_state();
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction();
        let alice_primary_id = AssetId::new(primary_def_id.clone(), ALICE_ID.clone());
        let bob_counter_id = AssetId::new(counter_def_id.clone(), BOB_ID.clone());
        let alice_primary_before = stx
            .world
            .assets
            .get(&alice_primary_id)
            .cloned()
            .map(Owned::into_inner)
            .expect("initiator primary balance");
        let bob_counter_before = stx
            .world
            .assets
            .get(&bob_counter_id)
            .cloned()
            .map(Owned::into_inner)
            .expect("counterparty counter balance");
        let settlement_id: SettlementId =
            SettlementId::new(ALICE_ID.clone(), "pvp_fail".parse().unwrap());
        let instruction = PvpIsi {
            settlement_id: settlement_id.clone(),
            primary_leg: SettlementLeg::new(
                primary_def_id.clone(),
                Quantity::from(500_u32),
                ALICE_ID.clone(),
                BOB_ID.clone(),
            ),
            counter_leg: SettlementLeg::new(
                counter_def_id.clone(),
                Quantity::from(5_000_u32),
                BOB_ID.clone(),
                ALICE_ID.clone(),
            ),
            plan: SettlementPlan::default(),
            metadata: Metadata::default(),
        };
        grant_pvp_consent(&mut stx, &ALICE_ID, &instruction);
        let err = instruction
            .execute(&ALICE_ID, &mut stx)
            .expect_err("insufficient counter leg must fail");
        assert!(
            matches!(
                err,
                InstructionExecutionError::Math(MathError::NotEnoughQuantity)
            ),
            "unexpected error: {err:?}"
        );
        let alice_primary_after = stx
            .world
            .assets
            .get(&alice_primary_id)
            .cloned()
            .map_or_else(Quantity::zero, Owned::into_inner);
        let bob_counter_after = stx
            .world
            .assets
            .get(&bob_counter_id)
            .cloned()
            .map_or_else(Quantity::zero, Owned::into_inner);
        assert_eq!(alice_primary_after, alice_primary_before);
        assert_eq!(bob_counter_after, bob_counter_before);
        assert!(
            stx.world.settlement_receipts.get(&settlement_id).is_none(),
            "an insufficient-funds PvP must not create consensus receipt state"
        );
    }
    #[test]
    fn pvp_holding_limit_rejects_first_leg_without_mutation() {
        let (state, primary_def_id, counter_def_id) = settlement_state();
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction();
        set_test_holding_limit(&mut stx, &BOB_ID, &primary_def_id, Quantity::zero());
        let alice_primary = AssetId::new(primary_def_id.clone(), ALICE_ID.clone());
        let bob_primary = AssetId::new(primary_def_id.clone(), BOB_ID.clone());
        let bob_counter = AssetId::new(counter_def_id.clone(), BOB_ID.clone());
        let alice_counter = AssetId::new(counter_def_id.clone(), ALICE_ID.clone());
        let settlement_id: SettlementId =
            SettlementId::new(ALICE_ID.clone(), "pvp_holding_first".parse().unwrap());
        let instruction = PvpIsi {
            settlement_id: settlement_id.clone(),
            primary_leg: SettlementLeg::new(
                primary_def_id,
                Quantity::from(5_u32),
                ALICE_ID.clone(),
                BOB_ID.clone(),
            ),
            counter_leg: SettlementLeg::new(
                counter_def_id,
                Quantity::from(100_u32),
                BOB_ID.clone(),
                ALICE_ID.clone(),
            ),
            plan: SettlementPlan::default(),
            metadata: Metadata::default(),
        };
        grant_pvp_consent(&mut stx, &ALICE_ID, &instruction);
        let error = instruction
            .execute(&ALICE_ID, &mut stx)
            .expect_err("first destination holding limit must reject PvP");
        assert_holding_limit_error(&error);
        assert_eq!(
            asset_balance_or_zero(&stx, &alice_primary),
            Quantity::from(10_u32)
        );
        assert_eq!(asset_balance_or_zero(&stx, &bob_primary), Quantity::zero());
        assert_eq!(
            asset_balance_or_zero(&stx, &bob_counter),
            Quantity::from(1_000_u32)
        );
        assert_eq!(
            asset_balance_or_zero(&stx, &alice_counter),
            Quantity::zero()
        );
        assert!(
            stx.world.settlement_receipts.get(&settlement_id).is_none(),
            "a rejected PvP must not create consensus receipt state"
        );
    }
    #[test]
    fn pvp_second_leg_holding_limit_rejects_without_moving_assets() {
        let (state, primary_def_id, counter_def_id) = settlement_state();
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction();
        set_test_holding_limit(&mut stx, &ALICE_ID, &counter_def_id, Quantity::zero());
        let alice_primary = AssetId::new(primary_def_id.clone(), ALICE_ID.clone());
        let bob_primary = AssetId::new(primary_def_id.clone(), BOB_ID.clone());
        let bob_counter = AssetId::new(counter_def_id.clone(), BOB_ID.clone());
        let alice_counter = AssetId::new(counter_def_id.clone(), ALICE_ID.clone());
        let settlement_id: SettlementId =
            SettlementId::new(ALICE_ID.clone(), "pvp_holding_second".parse().unwrap());
        let instruction = PvpIsi {
            settlement_id: settlement_id.clone(),
            primary_leg: SettlementLeg::new(
                primary_def_id,
                Quantity::from(5_u32),
                ALICE_ID.clone(),
                BOB_ID.clone(),
            ),
            counter_leg: SettlementLeg::new(
                counter_def_id,
                Quantity::from(100_u32),
                BOB_ID.clone(),
                ALICE_ID.clone(),
            ),
            plan: SettlementPlan::new(
                SettlementExecutionOrder::DeliveryThenPayment,
                SettlementAtomicity::AllOrNothing,
            ),
            metadata: Metadata::default(),
        };
        grant_pvp_consent(&mut stx, &ALICE_ID, &instruction);
        let error = instruction
            .execute(&ALICE_ID, &mut stx)
            .expect_err("second destination holding limit must reject the entire PvP");
        assert_holding_limit_error(&error);
        assert_eq!(
            asset_balance_or_zero(&stx, &alice_primary),
            Quantity::from(10_u32)
        );
        assert_eq!(asset_balance_or_zero(&stx, &bob_primary), Quantity::zero());
        assert_eq!(
            asset_balance_or_zero(&stx, &bob_counter),
            Quantity::from(1_000_u32)
        );
        assert_eq!(
            asset_balance_or_zero(&stx, &alice_counter),
            Quantity::zero()
        );
        assert!(
            stx.world.settlement_receipts.get(&settlement_id).is_none(),
            "a rejected PvP must not create consensus receipt state"
        );
    }
    #[test]
    fn admission_validate_dvp_rejects_insufficient_funds() {
        let (state, delivery_def_id, payment_def_id) = settlement_state();
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction();
        let instruction = DvpIsi {
            settlement_id: SettlementId::new(ALICE_ID.clone(), "dvp_insufficient".parse().unwrap()),
            delivery_leg: SettlementLeg::new(
                delivery_def_id,
                Quantity::from(5_u32),
                ALICE_ID.clone(),
                BOB_ID.clone(),
            ),
            payment_leg: SettlementLeg::new(
                payment_def_id,
                Quantity::from(2_000_u32),
                BOB_ID.clone(),
                ALICE_ID.clone(),
            ),
            plan: SettlementPlan::default(),
            metadata: Metadata::default(),
        };
        grant_dvp_consent(&mut stx, &ALICE_ID, &instruction);
        let err = super::admission_validate_dvp(&ALICE_ID, &mut stx, &instruction)
            .expect_err("admission guard should reject insufficient payment leg");
        assert!(
            matches!(
                err,
                InstructionExecutionError::Math(MathError::NotEnoughQuantity)
            ),
            "unexpected error: {err:?}"
        );
    }
    #[test]
    fn admission_validate_dvp_allows_funded_trade() {
        let (state, delivery_def_id, payment_def_id) = settlement_state();
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction();
        let instruction = DvpIsi {
            settlement_id: SettlementId::new(ALICE_ID.clone(), "dvp_ok".parse().unwrap()),
            delivery_leg: SettlementLeg::new(
                delivery_def_id,
                Quantity::from(5_u32),
                ALICE_ID.clone(),
                BOB_ID.clone(),
            ),
            payment_leg: SettlementLeg::new(
                payment_def_id,
                Quantity::from(500_u32),
                BOB_ID.clone(),
                ALICE_ID.clone(),
            ),
            plan: SettlementPlan::default(),
            metadata: Metadata::default(),
        };
        grant_dvp_consent(&mut stx, &ALICE_ID, &instruction);
        super::admission_validate_dvp(&ALICE_ID, &mut stx, &instruction)
            .expect("admission guard should allow funded trades");
    }
    #[test]
    fn admission_validate_pvp_rejects_insufficient_funds() {
        let (state, primary_def_id, counter_def_id) = settlement_state();
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction();
        let instruction = PvpIsi {
            settlement_id: SettlementId::new(ALICE_ID.clone(), "pvp_insufficient".parse().unwrap()),
            primary_leg: SettlementLeg::new(
                primary_def_id,
                Quantity::from(500_u32),
                ALICE_ID.clone(),
                BOB_ID.clone(),
            ),
            counter_leg: SettlementLeg::new(
                counter_def_id,
                Quantity::from(5_000_u32),
                BOB_ID.clone(),
                ALICE_ID.clone(),
            ),
            plan: SettlementPlan::default(),
            metadata: Metadata::default(),
        };
        grant_pvp_consent(&mut stx, &ALICE_ID, &instruction);
        let err = super::admission_validate_pvp(&ALICE_ID, &mut stx, &instruction)
            .expect_err("admission guard should reject insufficient counter leg");
        assert!(
            matches!(
                err,
                InstructionExecutionError::Math(MathError::NotEnoughQuantity)
            ),
            "unexpected error: {err:?}"
        );
    }
    #[test]
    fn admission_validate_pvp_allows_funded_fx() {
        let (state, primary_def_id, counter_def_id) = settlement_state();
        let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
        let mut block = state.block(header);
        let mut stx = block.transaction();
        let instruction = PvpIsi {
            settlement_id: SettlementId::new(ALICE_ID.clone(), "pvp_ok".parse().unwrap()),
            primary_leg: SettlementLeg::new(
                primary_def_id,
                Quantity::from(5_u32),
                ALICE_ID.clone(),
                BOB_ID.clone(),
            ),
            counter_leg: SettlementLeg::new(
                counter_def_id,
                Quantity::from(500_u32),
                BOB_ID.clone(),
                ALICE_ID.clone(),
            ),
            plan: SettlementPlan::default(),
            metadata: Metadata::default(),
        };
        grant_pvp_consent(&mut stx, &ALICE_ID, &instruction);
        super::admission_validate_pvp(&ALICE_ID, &mut stx, &instruction)
            .expect("admission guard should allow funded FX settlements");
    }
    #[test]
    fn settlement_failure_reason_classifies_errors() {
        use iroha_data_model::{isi::error::MathError, query::error::FindError};
        let insufficient = InstructionExecutionError::InvariantViolation(
            "settlement leg requires 10 but only 5 is available".into(),
        );
        assert_eq!(
            super::settlement_failure_reason(&insufficient),
            "insufficient_funds"
        );
        let zero_qty = InstructionExecutionError::InvariantViolation(
            "settlement legs must specify non-zero quantities".into(),
        );
        assert_eq!(super::settlement_failure_reason(&zero_qty), "zero_quantity");
        let mismatch = InstructionExecutionError::InvariantViolation(
            "DvP counterparties must be reciprocal across delivery and payment legs".into(),
        );
        assert_eq!(
            super::settlement_failure_reason(&mismatch),
            "counterparty_mismatch"
        );
        let find_missing = InstructionExecutionError::Find(FindError::Account(ALICE_ID.clone()));
        assert_eq!(
            super::settlement_failure_reason(&find_missing),
            "missing_entity"
        );
        let math = InstructionExecutionError::Math(MathError::Overflow);
        assert_eq!(super::settlement_failure_reason(&math), "math_error");
    }
    #[test]
    fn settlement_leg_quantity_boundaries_reject_negative_and_zero_values() {
        let definition_id = AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").expect("domain"),
            "usd".parse().expect("asset name"),
        );
        assert!(Quantity::try_from_numeric(Numeric::new(-1, 0)).is_err());
        let leg = SettlementLeg::new(
            definition_id,
            Quantity::zero(),
            ALICE_ID.clone(),
            BOB_ID.clone(),
        );
        assert!(matches!(
            super::ensure_leg_quantity(&leg),
            Err(InstructionExecutionError::InvariantViolation(_))
        ));
    }
}
