//! Strict first-release retail DAY records in the existing consensus state map.
//!
//! This namespace does not add fields to `WorldData`, so a pre-activation Taira
//! snapshot keeps its exact canonical world schema. Native code alone writes
//! these paths; the IVM host reserves all five roots from generic state calls.

use super::*;
use iroha_data_model::asset::{
    RetailDailyActivationV1, RetailDailyLimitPolicyV1, RetailDailyUsageKeyV1,
    RetailIdentityAttestationV1, RetailMonetaryPurposeV1,
    retail_daily_limit::{
        RETAIL_ACTIVATION_STATE_PREFIX_V1, RETAIL_POLICY_STATE_PREFIX_V1,
        retail_activation_state_path_v1, retail_policy_state_path_v1,
    },
};
use iroha_data_model::isi::retail_daily_limit::RetailMonetaryMovementV1;

pub(crate) const POLICY_ROOT: &str = RETAIL_POLICY_STATE_PREFIX_V1;
pub(crate) const ACTIVATION_ROOT: &str = RETAIL_ACTIVATION_STATE_PREFIX_V1;
pub(crate) const IDENTITY_ROOT: &str = "retail_day_identity_v1/";
pub(crate) const USAGE_ROOT: &str = "retail_day_usage_v1/";
pub(crate) const MONETARY_OPERATION_ROOT: &str = "retail_day_monetary_operation_v1/";
const DAY_MS: u64 = 86_400_000;

fn definition_digest(definition: &AssetDefinitionId) -> String {
    hex::encode(Hash::new(definition.to_string().as_bytes()).as_ref())
}

fn account_digest(account: &AccountId) -> String {
    hex::encode(Hash::new(account.to_string().as_bytes()).as_ref())
}

fn fixed_path(value: String) -> StatePath {
    value
        .parse()
        .expect("fixed-size native retail DAY state path must be valid")
}

pub(crate) fn policy_key(definition: &AssetDefinitionId, dataspace: DataSpaceId) -> StatePath {
    retail_policy_state_path_v1(definition, dataspace)
}

/// The immutable per-definition marker is also the exact governed-asset index.
/// Native admission can find it without scanning every installed policy.
pub(crate) fn activation_key(definition: &AssetDefinitionId) -> StatePath {
    retail_activation_state_path_v1(definition)
}

fn policy_digest(policy: &RetailDailyLimitPolicyV1) -> Result<[u8; 32], String> {
    let bytes = norito::encode_canonical(policy)
        .map_err(|error| format!("cannot encode retail DAY policy digest: {error}"))?;
    Ok(*Hash::new(bytes).as_ref())
}

pub(crate) fn activation_for_policy(
    policy: &RetailDailyLimitPolicyV1,
    activated_at_ms: u64,
) -> Result<RetailDailyActivationV1, String> {
    let enforce_from_day_start_ms = activated_at_ms
        .checked_div(DAY_MS)
        .and_then(|day| day.checked_add(1))
        .and_then(|next_day| next_day.checked_mul(DAY_MS))
        .ok_or_else(|| "retail DAY activation cannot represent the following UTC day".to_owned())?;
    Ok(RetailDailyActivationV1 {
        asset_definition_id: policy.asset_definition_id.clone(),
        physical_dataspace: policy.physical_dataspace,
        policy_digest: policy_digest(policy)?,
        activated_at_ms,
        enforce_from_day_start_ms,
    })
}

fn validate_activation(
    activation: &RetailDailyActivationV1,
    policy: &RetailDailyLimitPolicyV1,
) -> Result<(), String> {
    if activation != &activation_for_policy(policy, activation.activated_at_ms)? {
        return Err("retail DAY activation does not bind its policy and next UTC day".to_owned());
    }
    Ok(())
}

pub(crate) fn identity_key(
    definition: &AssetDefinitionId,
    dataspace: DataSpaceId,
    account: &AccountId,
) -> StatePath {
    fixed_path(format!(
        "{IDENTITY_ROOT}{}/{}/{}",
        definition_digest(definition),
        dataspace.as_u64(),
        account_digest(account)
    ))
}

pub(crate) fn usage_key(key: &RetailDailyUsageKeyV1) -> StatePath {
    fixed_path(format!(
        "{USAGE_ROOT}{}/{}/{}/{}",
        definition_digest(&key.asset_definition_id),
        key.physical_dataspace.as_u64(),
        hex::encode(key.identity.digest),
        key.utc_day_start_ms
    ))
}

pub(crate) fn monetary_operation_key(
    definition: &AssetDefinitionId,
    operation_digest: &[u8; 32],
) -> StatePath {
    fixed_path(format!(
        "{MONETARY_OPERATION_ROOT}{}/{}",
        definition_digest(definition),
        hex::encode(operation_digest)
    ))
}

pub(crate) fn monetary_operation_exists(
    world: &impl WorldReadOnly,
    definition: &AssetDefinitionId,
    operation_digest: &[u8; 32],
) -> bool {
    world
        .smart_contract_state()
        .get(&monetary_operation_key(definition, operation_digest))
        .is_some()
}

fn decode<T>(bytes: &[u8], kind: &str) -> Result<T, String>
where
    T: norito::NoritoSerialize,
    for<'de> T: norito::NoritoDeserialize<'de>,
{
    norito::decode_canonical(bytes).map_err(|error| format!("invalid retail DAY {kind}: {error}"))
}

fn validate_first_release_policy(policy: &RetailDailyLimitPolicyV1) -> Result<(), String> {
    policy.validate_shape().map_err(str::to_owned)?;
    if policy.revision != 1 || !policy.institutional_exceptions.is_empty() {
        return Err(
            "retail DAY first-release policy revision or exception roster is invalid".to_owned(),
        );
    }
    Ok(())
}

pub(crate) fn policy_for_exact(
    world: &impl WorldReadOnly,
    definition: &AssetDefinitionId,
    dataspace: DataSpaceId,
) -> Result<Option<RetailDailyLimitPolicyV1>, String> {
    let path = policy_key(definition, dataspace);
    let Some(bytes) = world.smart_contract_state().get(&path) else {
        return Ok(None);
    };
    let policy: RetailDailyLimitPolicyV1 = decode(bytes, "policy")?;
    if &policy.asset_definition_id != definition || policy.physical_dataspace != dataspace {
        return Err("retail DAY policy payload differs from its exact native key".to_owned());
    }
    validate_first_release_policy(&policy)?;
    Ok(Some(policy))
}

pub(crate) fn activation_for_exact(
    world: &impl WorldReadOnly,
    policy: &RetailDailyLimitPolicyV1,
) -> Result<RetailDailyActivationV1, String> {
    let path = activation_key(&policy.asset_definition_id);
    let bytes = world
        .smart_contract_state()
        .get(&path)
        .ok_or_else(|| "retail DAY policy has no exact activation marker".to_owned())?;
    let activation: RetailDailyActivationV1 = decode(bytes, "activation")?;
    validate_activation(&activation, policy)?;
    Ok(activation)
}

pub(crate) fn has_policy_for_definition(
    world: &impl WorldReadOnly,
    definition: &AssetDefinitionId,
) -> Result<bool, String> {
    let Some(bytes) = world
        .smart_contract_state()
        .get(&activation_key(definition))
    else {
        // An orphan policy is rejected by snapshot validation. Native activation
        // writes marker and policy atomically, and generic state calls cannot
        // mutate either reserved root.
        return Ok(false);
    };
    let activation: RetailDailyActivationV1 = decode(bytes, "activation")?;
    if &activation.asset_definition_id != definition {
        return Err("retail DAY activation differs from its native definition key".to_owned());
    }
    let policy = policy_for_exact(world, definition, activation.physical_dataspace)?
        .ok_or_else(|| "retail DAY activation has no exact policy".to_owned())?;
    validate_activation(&activation, &policy)?;
    Ok(true)
}

pub(crate) fn identity_for_exact(
    world: &impl WorldReadOnly,
    definition: &AssetDefinitionId,
    dataspace: DataSpaceId,
    account: &AccountId,
) -> Result<Option<RetailIdentityAttestationV1>, String> {
    let path = identity_key(definition, dataspace, account);
    let Some(bytes) = world.smart_contract_state().get(&path) else {
        return Ok(None);
    };
    let attestation: RetailIdentityAttestationV1 = decode(bytes, "identity attestation")?;
    if &attestation.body.asset_definition_id != definition
        || attestation.body.physical_dataspace != dataspace
        || &attestation.body.account_id != account
    {
        return Err("retail DAY identity payload differs from its exact native key".to_owned());
    }
    Ok(Some(attestation))
}

pub(crate) fn usage_for_exact(
    world: &impl WorldReadOnly,
    key: &RetailDailyUsageKeyV1,
) -> Result<Option<Quantity>, String> {
    let path = usage_key(key);
    let Some(bytes) = world.smart_contract_state().get(&path) else {
        return Ok(None);
    };
    let (stored_key, amount): (RetailDailyUsageKeyV1, Quantity) = decode(bytes, "usage")?;
    if &stored_key != key || amount.is_zero() {
        return Err("retail DAY usage payload differs from its exact native key".to_owned());
    }
    Ok(Some(amount))
}

pub(crate) fn encode_usage(
    key: &RetailDailyUsageKeyV1,
    amount: &Quantity,
) -> Result<Vec<u8>, String> {
    if amount.is_zero() {
        return Err("retail DAY usage must be positive".to_owned());
    }
    norito::encode_canonical(&(key.clone(), amount.clone()))
        .map_err(|error| format!("cannot encode retail DAY usage: {error}"))
}

pub(crate) fn put_usage(
    world: &mut WorldTransaction<'_, '_>,
    key: RetailDailyUsageKeyV1,
    amount: Quantity,
) -> Result<(), String> {
    let bytes = encode_usage(&key, &amount)?;
    world.smart_contract_state.insert(usage_key(&key), bytes);
    Ok(())
}

pub(crate) fn retained_definition(
    world: &impl WorldReadOnly,
    definitions: &BTreeSet<AssetDefinitionId>,
) -> Result<Option<AssetDefinitionId>, String> {
    for (path, bytes) in world.smart_contract_state().iter() {
        let definition = if in_root(path, POLICY_ROOT) {
            let policy: RetailDailyLimitPolicyV1 = decode(bytes, "policy")?;
            if path != &policy_key(&policy.asset_definition_id, policy.physical_dataspace) {
                return Err("retail DAY policy has a noncanonical native key".to_owned());
            }
            Some(policy.asset_definition_id)
        } else if in_root(path, ACTIVATION_ROOT) {
            let activation: RetailDailyActivationV1 = decode(bytes, "activation")?;
            if path != &activation_key(&activation.asset_definition_id) {
                return Err("retail DAY activation has a noncanonical native key".to_owned());
            }
            Some(activation.asset_definition_id)
        } else if in_root(path, IDENTITY_ROOT) {
            let attestation: RetailIdentityAttestationV1 = decode(bytes, "identity attestation")?;
            let body = attestation.body;
            if path
                != &identity_key(
                    &body.asset_definition_id,
                    body.physical_dataspace,
                    &body.account_id,
                )
            {
                return Err("retail DAY identity has a noncanonical native key".to_owned());
            }
            Some(body.asset_definition_id)
        } else if in_root(path, USAGE_ROOT) {
            let (key, _): (RetailDailyUsageKeyV1, Quantity) = decode(bytes, "usage")?;
            if path != &usage_key(&key) {
                return Err("retail DAY usage has a noncanonical native key".to_owned());
            }
            Some(key.asset_definition_id)
        } else if in_root(path, MONETARY_OPERATION_ROOT) {
            let operation: RetailMonetaryMovementV1 = decode(bytes, "monetary operation")?;
            if path
                != &monetary_operation_key(
                    &operation.asset_definition_id,
                    &operation.operation_digest,
                )
            {
                return Err(
                    "retail DAY monetary operation has a noncanonical native key".to_owned(),
                );
            }
            Some(operation.asset_definition_id)
        } else {
            None
        };
        if let Some(definition) = definition
            && definitions.contains(&definition)
        {
            return Ok(Some(definition));
        }
    }
    Ok(None)
}

pub(crate) fn account_is_retained(
    world: &impl WorldReadOnly,
    account: &AccountId,
) -> Result<bool, String> {
    for (path, bytes) in world.smart_contract_state().iter() {
        if in_root(path, POLICY_ROOT) {
            let policy: RetailDailyLimitPolicyV1 = decode(bytes, "policy")?;
            if path != &policy_key(&policy.asset_definition_id, policy.physical_dataspace) {
                return Err("retail DAY policy has a noncanonical native key".to_owned());
            }
            if &policy.identity_issuer == account
                || &policy.monetary_issuer_account == account
                || &policy.reserve_account == account
            {
                return Ok(true);
            }
        } else if in_root(path, IDENTITY_ROOT) {
            let attestation: RetailIdentityAttestationV1 = decode(bytes, "identity attestation")?;
            let body = attestation.body;
            if path
                != &identity_key(
                    &body.asset_definition_id,
                    body.physical_dataspace,
                    &body.account_id,
                )
            {
                return Err("retail DAY identity has a noncanonical native key".to_owned());
            }
            if &body.account_id == account {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn in_root(path: &StatePath, root: &str) -> bool {
    path.as_ref() == root.trim_end_matches('/') || path.as_ref().starts_with(root)
}

/// Preserve the exact policy and activation bytes across a committed transition.
///
/// This uses the actual World journal preimages after all deterministic writes,
/// rather than trusting instruction dispatch or a caller-provided change list.
/// Fresh entries must form one canonical pair and both must be absent in the
/// predecessor. Native activation remains responsible for owner and lane
/// authority. This guard neither authenticates a restored predecessor nor
/// establishes a consensus commitment to a local state-map root.
pub(in crate::state) fn validate_immutable_policy_transition(
    world: &WorldBlock<'_>,
) -> Result<(), String> {
    for entry in world.smart_contract_state.touched_entries() {
        let is_policy = in_root(entry.key, POLICY_ROOT);
        if !is_policy && !in_root(entry.key, ACTIVATION_ROOT) {
            continue;
        }
        if entry.before.is_some() {
            if entry.before != entry.after {
                return Err(
                    "retail DAY committed policy and activation cannot be replaced or removed"
                        .to_owned(),
                );
            }
            continue;
        }
        let Some(bytes) = entry.after else {
            // An absent-to-absent touch has no committed state effect.
            continue;
        };
        let (policy, activation) = if is_policy {
            let policy: RetailDailyLimitPolicyV1 = decode(bytes, "policy")?;
            if entry.key != &policy_key(&policy.asset_definition_id, policy.physical_dataspace) {
                return Err("retail DAY policy has a noncanonical native key".to_owned());
            }
            let activation = activation_for_exact(world, &policy)?;
            (policy, activation)
        } else {
            let activation: RetailDailyActivationV1 = decode(bytes, "activation")?;
            if entry.key != &activation_key(&activation.asset_definition_id) {
                return Err("retail DAY activation has a noncanonical native key".to_owned());
            }
            let policy = policy_for_exact(
                world,
                &activation.asset_definition_id,
                activation.physical_dataspace,
            )?
            .ok_or_else(|| "retail DAY activation has no exact policy".to_owned())?;
            (policy, activation)
        };
        validate_first_release_policy(&policy)?;
        validate_activation(&activation, &policy)?;
        if world
            .smart_contract_state
            .get_before_block(&policy_key(
                &policy.asset_definition_id,
                policy.physical_dataspace,
            ))
            .is_some()
            || world
                .smart_contract_state
                .get_before_block(&activation_key(&policy.asset_definition_id))
                .is_some()
        {
            return Err(
                "retail DAY activation pair must be absent in its committed predecessor".to_owned(),
            );
        }
    }
    Ok(())
}

fn snapshot_policy_for_exact(
    world: &World,
    definition: &AssetDefinitionId,
    dataspace: DataSpaceId,
) -> Result<Option<RetailDailyLimitPolicyV1>, String> {
    let state = world.smart_contract_state.view();
    let Some(bytes) = state.get(&policy_key(definition, dataspace)) else {
        return Ok(None);
    };
    let policy: RetailDailyLimitPolicyV1 = decode(bytes, "policy")?;
    if &policy.asset_definition_id != definition || policy.physical_dataspace != dataspace {
        return Err("retail DAY policy payload differs from its exact native key".to_owned());
    }
    validate_first_release_policy(&policy)?;
    Ok(Some(policy))
}

fn snapshot_activation_for_policy(
    world: &World,
    policy: &RetailDailyLimitPolicyV1,
) -> Result<RetailDailyActivationV1, String> {
    let path = activation_key(&policy.asset_definition_id);
    let state = world.smart_contract_state.view();
    let bytes = state
        .get(&path)
        .ok_or_else(|| "retail DAY policy has no exact activation marker".to_owned())?;
    let activation: RetailDailyActivationV1 = decode(bytes, "activation")?;
    validate_activation(&activation, policy)?;
    Ok(activation)
}

/// Validate the immutable pair's retained predecessor before snapshot admission.
///
/// Replacement-block execution consumes this undo image after restart. A valid
/// current pair alone cannot authorize a different prior pair or a half-born
/// policy. The exclusive storage history borrow observes both images without
/// consuming the journal or building a replacement World.
fn validate_immutable_policy_history(world: &mut World) -> Result<(), String> {
    let history = world.smart_contract_state.history();
    for (path, before) in history.revert_map().iter() {
        let is_policy = in_root(path, POLICY_ROOT);
        if !is_policy && !in_root(path, ACTIVATION_ROOT) {
            continue;
        }
        let after = history.current().get(path);
        if before.is_some() {
            if before.as_ref() != after {
                return Err(
                    "retail DAY snapshot undo replaces or removes an immutable policy or activation"
                        .to_owned(),
                );
            }
            continue;
        }
        let Some(bytes) = after else {
            continue;
        };
        let counterpart = if is_policy {
            let policy: RetailDailyLimitPolicyV1 = decode(bytes, "policy")?;
            activation_key(&policy.asset_definition_id)
        } else {
            let activation: RetailDailyActivationV1 = decode(bytes, "activation")?;
            policy_key(
                &activation.asset_definition_id,
                activation.physical_dataspace,
            )
        };
        if history.get_before_block(&counterpart).is_some() {
            return Err(
                "retail DAY snapshot undo must retain atomic policy and activation birth"
                    .to_owned(),
            );
        }
    }
    Ok(())
}

/// Validate current native records and immutable undo before accepting a snapshot.
pub(crate) fn validate_persistence(world: &mut World) -> Result<(), String> {
    let state = world.smart_contract_state.view();
    for (path, bytes) in state.iter() {
        if in_root(path, POLICY_ROOT) {
            let policy: RetailDailyLimitPolicyV1 = decode(bytes, "policy")?;
            if path != &policy_key(&policy.asset_definition_id, policy.physical_dataspace)
                || validate_first_release_policy(&policy).is_err()
                || !world
                    .asset_definitions
                    .view()
                    .get(&policy.asset_definition_id)
                    .is_some_and(|definition| {
                        definition.balance_scope_policy() == AssetBalancePolicy::DataspaceRestricted
                            && definition.spec().scale() == Some(2)
                            && definition
                                .owning_domain()
                                .as_ref()
                                .is_some_and(|domain| world.domains.view().get(domain).is_some())
                    })
                || world.accounts.view().get(&policy.identity_issuer).is_none()
                || world
                    .accounts
                    .view()
                    .get(&policy.monetary_issuer_account)
                    .is_none()
                || world.accounts.view().get(&policy.reserve_account).is_none()
            {
                return Err("retail DAY policy has invalid key, scope, issuer or shape".to_owned());
            }
            snapshot_activation_for_policy(world, &policy)?;
        } else if in_root(path, ACTIVATION_ROOT) {
            let activation: RetailDailyActivationV1 = decode(bytes, "activation")?;
            if path != &activation_key(&activation.asset_definition_id) {
                return Err("retail DAY activation has a noncanonical native key".to_owned());
            }
            let policy = snapshot_policy_for_exact(
                world,
                &activation.asset_definition_id,
                activation.physical_dataspace,
            )?
            .ok_or_else(|| "retail DAY activation has no exact policy".to_owned())?;
            validate_activation(&activation, &policy)?;
        } else if in_root(path, IDENTITY_ROOT) {
            let attestation: RetailIdentityAttestationV1 = decode(bytes, "identity attestation")?;
            let body = &attestation.body;
            if path
                != &identity_key(
                    &body.asset_definition_id,
                    body.physical_dataspace,
                    &body.account_id,
                )
                || world.accounts.view().get(&body.account_id).is_none()
            {
                return Err("retail DAY identity has invalid key or missing account".to_owned());
            }
            let policy = snapshot_policy_for_exact(
                world,
                &body.asset_definition_id,
                body.physical_dataspace,
            )?
            .ok_or_else(|| "retail DAY identity has no exact policy".to_owned())?;
            if body.account_id == policy.reserve_account {
                return Err("retail DAY reserve cannot carry a retail identity binding".to_owned());
            }
            attestation
                .verify_for(&policy, &body.account_id)
                .map_err(str::to_owned)?;
        } else if in_root(path, USAGE_ROOT) {
            let (key, amount): (RetailDailyUsageKeyV1, Quantity) = decode(bytes, "usage")?;
            if path != &usage_key(&key)
                || key.identity.digest == [0; 32]
                || key.utc_day_start_ms % DAY_MS != 0
                || amount.is_zero()
            {
                return Err("retail DAY usage has invalid key, bucket or policy".to_owned());
            }
            let policy =
                snapshot_policy_for_exact(world, &key.asset_definition_id, key.physical_dataspace)?
                    .ok_or_else(|| "retail DAY usage has no exact policy".to_owned())?;
            if key.utc_day_start_ms
                < snapshot_activation_for_policy(world, &policy)?.enforce_from_day_start_ms
            {
                return Err("retail DAY usage predates the first admitted UTC day".to_owned());
            }
        } else if in_root(path, MONETARY_OPERATION_ROOT) {
            let operation: RetailMonetaryMovementV1 = decode(bytes, "monetary operation")?;
            if path
                != &monetary_operation_key(
                    &operation.asset_definition_id,
                    &operation.operation_digest,
                )
                || operation.operation_digest == [0; 32]
                || operation.amount.is_zero()
            {
                return Err("retail DAY monetary operation has invalid key or amount".to_owned());
            }
            let activation_bytes = state
                .get(&activation_key(&operation.asset_definition_id))
                .ok_or_else(|| "retail DAY monetary operation has no activation".to_owned())?;
            let activation: RetailDailyActivationV1 = decode(activation_bytes, "activation")?;
            if activation.asset_definition_id != operation.asset_definition_id {
                return Err(
                    "retail DAY monetary operation activation differs from its definition"
                        .to_owned(),
                );
            }
            let policy = snapshot_policy_for_exact(
                world,
                &operation.asset_definition_id,
                activation.physical_dataspace,
            )?
            .ok_or_else(|| "retail DAY monetary operation has no policy".to_owned())?;
            snapshot_activation_for_policy(world, &policy)?;
            if !world
                .asset_definitions
                .view()
                .get(&operation.asset_definition_id)
                .is_some_and(|definition| {
                    definition
                        .spec()
                        .check(operation.amount.as_numeric())
                        .is_ok()
                })
            {
                return Err(
                    "retail DAY monetary operation violates the exact asset precision".to_owned(),
                );
            }
            match operation.purpose {
                RetailMonetaryPurposeV1::MintToReserve | RetailMonetaryPurposeV1::BurnReserve
                    if operation.retail_account.is_none() => {}
                RetailMonetaryPurposeV1::CreditRetail | RetailMonetaryPurposeV1::DefundRetail
                    if operation.retail_account.as_ref().is_some_and(|account| {
                        account != &policy.reserve_account
                            && world.accounts.view().get(account).is_some()
                    }) =>
                {
                    let retail_account = operation
                        .retail_account
                        .as_ref()
                        .expect("matched monetary retail endpoint");
                    let binding_key = identity_key(
                        &operation.asset_definition_id,
                        policy.physical_dataspace,
                        retail_account,
                    );
                    let binding_bytes = state.get(&binding_key).ok_or_else(|| {
                        "retail DAY monetary operation lacks an issuer-signed retail binding"
                            .to_owned()
                    })?;
                    let binding: RetailIdentityAttestationV1 =
                        decode(binding_bytes, "identity attestation")?;
                    if binding.body.asset_definition_id != operation.asset_definition_id
                        || binding.body.physical_dataspace != policy.physical_dataspace
                        || &binding.body.account_id != retail_account
                    {
                        return Err(
                            "retail DAY monetary operation has a mismatched retail binding"
                                .to_owned(),
                        );
                    }
                    binding
                        .verify_for(&policy, retail_account)
                        .map_err(str::to_owned)?;
                }
                _ => return Err("retail DAY monetary operation has invalid endpoint".to_owned()),
            }
        }
    }
    drop(state);
    validate_immutable_policy_history(world)
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::{account::Account, asset::AssetDefinition, domain::Domain};
    use iroha_model_base::domain::DomainId;
    use iroha_primitives::numeric::NumericSpec;
    use iroha_test_samples::{ALICE_ID, BOB_ID};

    fn snapshot_fixture() -> (World, RetailDailyLimitPolicyV1, KeyPair) {
        let domain_id = DomainId::try_new("retail", "bpng").expect("test domain");
        let definition_id = AssetDefinitionId::derive_from_components(
            domain_id.clone(),
            "kina".parse().expect("asset name"),
        );
        let issuer_key = KeyPair::try_from_seed(vec![0x73; 32], Algorithm::Ed25519)
            .expect("test-only issuer key");
        let policy = RetailDailyLimitPolicyV1 {
            asset_definition_id: definition_id.clone(),
            physical_dataspace: DataSpaceId::new(7),
            revision: 1,
            daily_cap: Quantity::from(5_u32),
            identity_issuer: ALICE_ID.clone(),
            identity_issuer_public_key: issuer_key.public_key().clone(),
            monetary_issuer_account: ALICE_ID.clone(),
            reserve_account: BOB_ID.clone(),
            institutional_exceptions: BTreeSet::new(),
        };
        let definition = AssetDefinition::new(
            definition_id.clone(),
            "Kina".to_owned(),
            NumericSpec::fractional(2),
            AssetBalancePolicy::DataspaceRestricted,
            Some(domain_id.clone()),
        )
        .build(&ALICE_ID);
        let world = World::with(
            [Domain::new(domain_id).build(&ALICE_ID)],
            [
                Account::new(ALICE_ID.clone()).build(&ALICE_ID),
                Account::new(BOB_ID.clone()).build(&ALICE_ID),
            ],
            [definition],
        );
        (world, policy, issuer_key)
    }

    #[test]
    fn snapshot_retail_undo_rejects_coherent_replacement_and_deleted_pair() {
        for remove in [false, true] {
            let (mut world, policy, _) = snapshot_fixture();
            let policy_path = policy_key(&policy.asset_definition_id, policy.physical_dataspace);
            let activation_path = activation_key(&policy.asset_definition_id);
            let activation = activation_for_policy(&policy, 1_000).unwrap();
            let policy_bytes = norito::encode_canonical(&policy).unwrap();
            let activation_bytes = norito::encode_canonical(&activation).unwrap();
            world
                .smart_contract_state
                .insert(policy_path.clone(), policy_bytes.clone());
            world
                .smart_contract_state
                .insert(activation_path.clone(), activation_bytes.clone());
            // Deliberately construct a hostile current/undo pair as a decoder
            // could receive it. The production World publication guard would
            // already reject this mutation before it became a snapshot.
            let mut storage = world.smart_contract_state.block();
            if remove {
                storage.remove(policy_path.clone());
                storage.remove(activation_path.clone());
            } else {
                let mut replacement = policy;
                replacement.daily_cap = Quantity::from(6_u32);
                let replacement_activation = activation_for_policy(&replacement, 1_000).unwrap();
                storage.insert(
                    policy_path.clone(),
                    norito::encode_canonical(&replacement).unwrap(),
                );
                storage.insert(
                    activation_path.clone(),
                    norito::encode_canonical(&replacement_activation).unwrap(),
                );
            }
            storage.commit();
            assert!(
                validate_persistence(&mut world)
                    .unwrap_err()
                    .contains("snapshot undo")
            );
            let history = world.smart_contract_state.history();
            assert_eq!(history.get_before_block(&policy_path), Some(&policy_bytes));
            assert_eq!(
                history.get_before_block(&activation_path),
                Some(&activation_bytes)
            );
        }
    }

    #[test]
    fn snapshot_retail_undo_requires_atomic_birth_and_preserves_exact_history() {
        // Initial presence: neither, both, policy alone, activation alone.
        for initial in 0..4 {
            let (mut world, policy, _) = snapshot_fixture();
            let policy_path = policy_key(&policy.asset_definition_id, policy.physical_dataspace);
            let activation_path = activation_key(&policy.asset_definition_id);
            let policy_bytes = norito::encode_canonical(&policy).unwrap();
            let activation_bytes =
                norito::encode_canonical(&activation_for_policy(&policy, 1_000).unwrap()).unwrap();
            if initial == 1 || initial == 2 {
                world
                    .smart_contract_state
                    .insert(policy_path.clone(), policy_bytes.clone());
            }
            if initial == 1 || initial == 3 {
                world
                    .smart_contract_state
                    .insert(activation_path.clone(), activation_bytes.clone());
            }
            let mut storage = world.smart_contract_state.block();
            storage.insert(policy_path.clone(), policy_bytes.clone());
            storage.insert(activation_path.clone(), activation_bytes.clone());
            storage.commit();
            if initial < 2 {
                validate_persistence(&mut world).expect("atomic birth or exact-byte retention");
            } else {
                assert!(
                    validate_persistence(&mut world)
                        .unwrap_err()
                        .contains("atomic")
                );
            }
            let history = world.smart_contract_state.history();
            assert_eq!(history.current().get(&policy_path), Some(&policy_bytes));
            assert_eq!(
                history.current().get(&activation_path),
                Some(&activation_bytes)
            );
            assert_eq!(
                history.get_before_block(&policy_path).is_some(),
                initial == 1 || initial == 2
            );
            assert_eq!(
                history.get_before_block(&activation_path).is_some(),
                initial == 1 || initial == 3
            );
        }
    }

    #[test]
    fn snapshot_rejects_missing_or_tampered_activation_marker() {
        let (mut world, policy, issuer_key) = snapshot_fixture();
        let definition_id = policy.asset_definition_id.clone();
        world.smart_contract_state.insert(
            policy_key(&definition_id, DataSpaceId::new(7)),
            norito::encode_canonical(&policy).expect("canonical test policy"),
        );
        assert!(
            validate_persistence(&mut world)
                .unwrap_err()
                .contains("activation marker")
        );
        let activation = activation_for_policy(&policy, 1_000).expect("next day marker");
        let marker_key = activation_key(&definition_id);
        world.smart_contract_state.insert(
            marker_key.clone(),
            norito::encode_canonical(&activation).expect("canonical test marker"),
        );
        validate_persistence(&mut world).expect("exact policy and marker restore");
        let operation = RetailMonetaryMovementV1 {
            asset_definition_id: definition_id.clone(),
            purpose: RetailMonetaryPurposeV1::MintToReserve,
            retail_account: None,
            amount: Quantity::one(),
            operation_digest: [0xC1; 32],
        };
        let operation_key = monetary_operation_key(&definition_id, &operation.operation_digest);
        world.smart_contract_state.insert(
            operation_key.clone(),
            norito::encode_canonical(&operation).expect("canonical monetary operation"),
        );
        validate_persistence(&mut world).expect("exact one-use monetary record restore");
        let mut retail_operation = operation.clone();
        retail_operation.purpose = RetailMonetaryPurposeV1::CreditRetail;
        retail_operation.retail_account = Some(ALICE_ID.clone());
        world.smart_contract_state.insert(
            operation_key.clone(),
            norito::encode_canonical(&retail_operation).expect("canonical retail operation"),
        );
        assert!(
            validate_persistence(&mut world)
                .unwrap_err()
                .contains("issuer-signed retail binding")
        );
        let body = iroha_data_model::asset::RetailIdentityAttestationBodyV1 {
            domain: iroha_data_model::asset::RETAIL_IDENTITY_ATTESTATION_DOMAIN_V1.to_owned(),
            asset_definition_id: definition_id.clone(),
            physical_dataspace: policy.physical_dataspace,
            policy_revision: policy.revision,
            account_id: ALICE_ID.clone(),
            identity: iroha_data_model::asset::RetailIdentityCommitmentV1 { digest: [0xA1; 32] },
            uniqueness_evidence_digest: [0xB1; 32],
        };
        let binding = RetailIdentityAttestationV1 {
            signature: iroha_crypto::SignatureOf::try_new(issuer_key.private_key(), &body)
                .expect("test-only issuer signature"),
            body,
        };
        let binding_key = identity_key(&definition_id, policy.physical_dataspace, &ALICE_ID);
        world.smart_contract_state.insert(
            binding_key.clone(),
            norito::encode_canonical(&binding).expect("canonical retail binding"),
        );
        validate_persistence(&mut world).expect("credit has its issuer-signed retail binding");
        retail_operation.purpose = RetailMonetaryPurposeV1::DefundRetail;
        world.smart_contract_state.insert(
            operation_key.clone(),
            norito::encode_canonical(&retail_operation).expect("canonical defund operation"),
        );
        validate_persistence(&mut world).expect("defund has its issuer-signed retail binding");
        retail_operation.amount = "0.001".parse().expect("over-precision test amount");
        world.smart_contract_state.insert(
            operation_key.clone(),
            norito::encode_canonical(&retail_operation)
                .expect("canonical over-precision operation"),
        );
        assert!(
            validate_persistence(&mut world)
                .unwrap_err()
                .contains("asset precision")
        );
        let mut forged_binding = binding.clone();
        forged_binding.body.identity.digest = [0xC2; 32];
        world.smart_contract_state.insert(
            binding_key.clone(),
            norito::encode_canonical(&forged_binding).expect("canonical forged binding"),
        );
        retail_operation.amount = Quantity::one();
        world.smart_contract_state.insert(
            operation_key.clone(),
            norito::encode_canonical(&retail_operation)
                .expect("canonical restored retail operation"),
        );
        assert!(validate_persistence(&mut world).is_err());
        world.smart_contract_state.insert(
            binding_key,
            norito::encode_canonical(&binding).expect("canonical restored retail binding"),
        );
        validate_persistence(&mut world).expect("restored issuer-signed binding");
        let mut forged_operation = operation;
        forged_operation.operation_digest = [0; 32];
        world.smart_contract_state.insert(
            operation_key.clone(),
            norito::encode_canonical(&forged_operation).expect("canonical forged operation"),
        );
        assert!(validate_persistence(&mut world).is_err());
        world.smart_contract_state.insert(
            operation_key,
            norito::encode_canonical(&RetailMonetaryMovementV1 {
                operation_digest: [0xC1; 32],
                ..forged_operation
            })
            .expect("canonical restored operation"),
        );
        let mut tampered = activation;
        tampered.policy_digest[0] ^= 1;
        world.smart_contract_state.insert(
            marker_key,
            norito::encode_canonical(&tampered).expect("canonical tampered marker"),
        );
        assert!(
            validate_persistence(&mut world)
                .unwrap_err()
                .contains("activation")
        );
    }
}
