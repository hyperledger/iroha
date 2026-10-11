//! Alias management service primitives.
//!
//! This module wires the data-model types into a runtime friendly storage container. Iroha v1
//! deliberately does not expose an OPRF/VOPRF service; a future privacy-preserving lookup protocol
//! must ship as a complete, keyed, verifiable construction rather than a hash-shaped placeholder.
use crate::state::WorldReadOnly;
use iroha_crypto::{HashOf, KeyPair, Signature};
use iroha_data_model::{
    account::{AccountId, rekey::AccountAlias},
    alias::{
        AliasAttestation, AliasEvent, AliasIndex, AliasRecord, AliasRecordedEvent, AliasTarget,
    },
    alias_setup::{AccountAliasName, ResolvedAccountAliasV1},
    asset::ResolvedAssetDefinitionAliasV1,
    permission::Permission,
};
use iroha_executor_data_model::permission::account::{
    AccountAliasPermissionScope, CanManageAccountAlias, CanResolveAccountAlias,
};
use iroha_executor_data_model::permission::asset_definition::{
    AssetDefinitionAliasPermissionScope, CanManageAssetDefinitionAlias,
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::name::Name;
use iroha_model_base::topology::DataSpaceId;
use iroha_telemetry::metrics::Metrics;
use mv::storage::StorageReadOnly;
use std::{
    collections::BTreeMap,
    fmt,
    sync::{Arc, RwLock},
};
use thiserror::Error;
use tracing::{Level, event, instrument};
const ALIAS_ATTESTATION_SIGNATURE_DOMAIN: &[u8] = b"iroha:alias:attestation:v1";
fn alias_attestation_signature_preimage(record: &AliasRecord, attester: &AccountId) -> Vec<u8> {
    let attester_bytes = norito::to_bytes(attester).expect("AccountId must encode");
    let record_hash = HashOf::<AliasRecord>::new(record);
    let attester_len = u64::try_from(attester_bytes.len()).expect("attester encoding length fits");
    let mut preimage = Vec::with_capacity(
        ALIAS_ATTESTATION_SIGNATURE_DOMAIN.len()
            + std::mem::size_of::<u64>()
            + attester_bytes.len()
            + record_hash.as_ref().len(),
    );
    preimage.extend_from_slice(ALIAS_ATTESTATION_SIGNATURE_DOMAIN);
    preimage.extend_from_slice(&attester_len.to_be_bytes());
    preimage.extend_from_slice(&attester_bytes);
    preimage.extend_from_slice(record_hash.as_ref());
    preimage
}
/// Signer used to attest alias storage updates.
#[derive(Clone, Debug)]
pub struct AliasAttester {
    account_id: AccountId,
    key_pair: KeyPair,
}
impl AliasAttester {
    /// Build an alias attester from a checked key pair.
    #[must_use]
    pub fn new(key_pair: KeyPair) -> Self {
        let account_id = AccountId::new(key_pair.public_key().clone());
        Self {
            account_id,
            key_pair,
        }
    }
    /// Account identity that will be recorded as the attester.
    pub fn account_id(&self) -> &AccountId {
        &self.account_id
    }
    fn sign_record(&self, record: &AliasRecord) -> Result<AliasAttestation, AliasError> {
        let preimage = alias_attestation_signature_preimage(record, &self.account_id);
        let signature = Signature::try_new(self.key_pair.private_key(), &preimage)
            .map_err(|err| AliasError::Signing(err.to_string()))?;
        Ok(AliasAttestation::new(
            record.alias.clone(),
            self.account_id.clone(),
            signature,
            ALIAS_ATTESTATION_SIGNATURE_DOMAIN.to_vec(),
        ))
    }
}
#[cfg(test)]
/// Verify that `attestation` signs the canonical alias-record preimage.
///
/// # Errors
/// Returns [`AliasError::InvalidAttestation`] for mismatched fields, unsupported
/// attester identities, or signature verification failures.
pub fn verify_alias_attestation(
    record: &AliasRecord,
    attestation: &AliasAttestation,
) -> Result<(), AliasError> {
    if attestation.alias != record.alias {
        return Err(AliasError::InvalidAttestation("alias mismatch"));
    }
    if attestation.context != ALIAS_ATTESTATION_SIGNATURE_DOMAIN {
        return Err(AliasError::InvalidAttestation("unsupported context"));
    }
    let Some(public_key) = attestation.attester.try_signatory() else {
        return Err(AliasError::InvalidAttestation(
            "attester must use a single signatory",
        ));
    };
    let preimage = alias_attestation_signature_preimage(record, &attestation.attester);
    attestation
        .signature
        .verify(public_key, &preimage)
        .map_err(|_| AliasError::InvalidAttestation("signature verification failed"))
}
fn authority_has_permission(
    world: &impl WorldReadOnly,
    authority: &AccountId,
    target: &Permission,
) -> bool {
    match world.account_permissions_iter(authority) {
        Ok(permissions) => {
            let direct_match = permissions
                .into_iter()
                .any(|permission| permission == target);
            if direct_match {
                return true;
            }
        }
        Err(error) => {
            iroha_logger::warn!(
                authority = %authority,
                target_name = %target.name(),
                target_payload = %target.payload().get(),
                ?error,
                "alias permission lookup could not load authority permissions"
            );
        }
    }
    if world.account_roles_iter(authority).any(|role_id| {
        world
            .roles()
            .get(role_id)
            .is_some_and(|role| role.permissions.contains(target))
    }) {
        return true;
    }
    let direct_permissions: Vec<String> = world
        .account_permissions()
        .get(authority)
        .map(|permissions| {
            permissions
                .iter()
                .map(|permission| format!("{}:{}", permission.name(), permission.payload().get()))
                .collect()
        })
        .unwrap_or_default();
    let roles: Vec<String> = world
        .account_roles_iter(authority)
        .map(|role_id| role_id.to_string())
        .collect();
    let account_present = world.accounts().get(authority).is_some();
    iroha_logger::warn!(
        authority = %authority,
        account_present,
        target_name = %target.name(),
        target_payload = %target.payload().get(),
        direct_permissions = ?direct_permissions,
        roles = ?roles,
        "alias permission lookup denied authority"
    );
    false
}
fn resolved_account_alias_from_numeric(
    world: &impl WorldReadOnly,
    alias: &AccountAlias,
) -> Option<ResolvedAccountAliasV1> {
    let literal = alias.to_literal(world.dataspace_catalog()).ok()?;
    let canonical_name = literal.parse::<AccountAliasName>().ok()?;
    Some(ResolvedAccountAliasV1::new(canonical_name, alias.dataspace))
}
/// Construct only the exact typed token while retaining any local JSON refusal.
fn permission_target<T: iroha_executor_data_model::permission::Permission>(
    permission: T,
) -> Result<Permission, crate::sns::SnsError> {
    let value = norito::json::to_value(&permission).map_err(|error| match error {
        norito::json::Error::DecodeResourceLimit
        | norito::json::Error::DecodeResource(
            norito::core::DecodeResourceError::ArchiveLengthExceeded { .. }
            | norito::core::DecodeResourceError::SequenceLengthExceeded { .. }
            | norito::core::DecodeResourceError::FieldLengthExceeded { .. }
            | norito::core::DecodeResourceError::TotalElementsExceeded { .. }
            | norito::core::DecodeResourceError::TotalAllocationExceeded { .. },
        ) => crate::sns::SnsError::Deferred(
            ivm::error::ExecutionDeferral::ActiveMemoryCapacity.into(),
        ),
        norito::json::Error::AllocationFailed
        | norito::json::Error::DecodeResource(
            norito::core::DecodeResourceError::AllocationFailed { .. },
        ) => crate::sns::SnsError::Deferred(
            ivm::error::ExecutionDeferral::AllocationUnavailable.into(),
        ),
        error => crate::sns::SnsError::Internal(format!(
            "exact alias permission cannot be encoded: {error}"
        )),
    })?;
    let payload = iroha_primitives::json::Json::from_norito_value_ref(&value).map_err(|error| {
        match crate::execution_attempt::norito_decode_attempt_error(error, |error| {
            crate::sns::SnsError::Internal(format!(
                "exact alias permission cannot be retained: {error}"
            ))
        }) {
            crate::execution_attempt::ExecutionAttemptError::Rejected(error) => error,
            crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => {
                crate::sns::SnsError::Deferred(reason)
            }
        }
    })?;
    Ok(Permission::new(T::name(), payload))
}
fn authority_has_exact_alias_permission<T>(
    world: &impl WorldReadOnly,
    authority: &AccountId,
    alias: &ResolvedAccountAliasV1,
    permission: impl FnOnce(AccountAliasPermissionScope) -> T,
) -> Result<bool, crate::sns::SnsError>
where
    T: iroha_executor_data_model::permission::Permission,
{
    let target = permission_target(permission(AccountAliasPermissionScope::Alias(
        alias.clone(),
    )))?;
    Ok(authority_has_permission(world, authority, &target))
}
/// Return `true` when the authority holds the exact permission required to resolve `alias`.
///
/// Domain-qualified aliases require their exact domain permission. Dataspace permission applies
/// only to domainless aliases, so a domain grant neither widens to sibling domains nor to the
/// enclosing dataspace.
///
/// # Errors
/// Returns the original local construction refusal or a malformed exact token error.
pub fn authority_can_resolve_account_alias(
    world: &impl WorldReadOnly,
    authority: &AccountId,
    alias: &AccountAlias,
) -> Result<bool, crate::sns::SnsError> {
    if let Some(resolved) = resolved_account_alias_from_numeric(world, alias)
        && authority_has_exact_alias_permission(world, authority, &resolved, |scope| {
            CanResolveAccountAlias { scope }
        })?
    {
        return Ok(true);
    }
    match alias.domain_id(world.dataspace_catalog()) {
        Ok(Some(domain_id)) => {
            let domain_permission = permission_target(CanResolveAccountAlias {
                scope: AccountAliasPermissionScope::Domain(domain_id),
            })?;
            Ok(authority_has_permission(
                world,
                authority,
                &domain_permission,
            ))
        }
        Ok(None) => {
            let dataspace_permission = permission_target(CanResolveAccountAlias {
                scope: AccountAliasPermissionScope::Dataspace(alias.dataspace),
            })?;
            Ok(authority_has_permission(
                world,
                authority,
                &dataspace_permission,
            ))
        }
        Err(_) => Ok(false),
    }
}
/// Return `true` when the authority may resolve an exact resolved account alias.
///
/// Exact alias permission is checked before applicable domain or dataspace scope.
///
/// # Errors
/// Returns the original local construction refusal or a malformed exact token error.
pub fn authority_can_resolve_resolved_account_alias(
    world: &impl WorldReadOnly,
    authority: &AccountId,
    alias: &ResolvedAccountAliasV1,
) -> Result<bool, crate::sns::SnsError> {
    if authority_has_exact_alias_permission(world, authority, alias, |scope| {
        CanResolveAccountAlias { scope }
    })? {
        return Ok(true);
    }
    let scope = match alias.canonical_name.domain_id() {
        Some(domain_id) => AccountAliasPermissionScope::Domain(domain_id),
        None => AccountAliasPermissionScope::Dataspace(alias.dataspace_id),
    };
    let target = permission_target(CanResolveAccountAlias { scope })?;
    Ok(authority_has_permission(world, authority, &target))
}
/// Return `true` when the authority holds the exact permissions required to mutate `alias`.
///
/// # Errors
/// Returns the original local construction refusal or a malformed exact token error.
pub fn authority_can_manage_account_alias(
    world: &impl WorldReadOnly,
    authority: &AccountId,
    alias: &AccountAlias,
) -> Result<bool, crate::sns::SnsError> {
    if let Some(resolved) = resolved_account_alias_from_numeric(world, alias)
        && authority_has_exact_alias_permission(world, authority, &resolved, |scope| {
            CanManageAccountAlias { scope }
        })?
    {
        return Ok(true);
    }
    match alias.domain_id(world.dataspace_catalog()) {
        Ok(domain_id) => authority_can_manage_account_alias_scope(
            world,
            authority,
            alias.dataspace,
            domain_id.as_ref(),
        ),
        Err(_) => Ok(false),
    }
}
/// Return `true` when the authority may mutate an exact resolved account alias.
///
/// Exact alias permission is checked before applicable domain or dataspace scope.
///
/// # Errors
/// Returns the original local construction refusal or a malformed exact token error.
pub fn authority_can_manage_resolved_account_alias(
    world: &impl WorldReadOnly,
    authority: &AccountId,
    alias: &ResolvedAccountAliasV1,
) -> Result<bool, crate::sns::SnsError> {
    if authority_has_exact_alias_permission(world, authority, alias, |scope| {
        CanManageAccountAlias { scope }
    })? {
        return Ok(true);
    }
    let scope = match alias.canonical_name.domain_id() {
        Some(domain_id) => AccountAliasPermissionScope::Domain(domain_id),
        None => AccountAliasPermissionScope::Dataspace(alias.dataspace_id),
    };
    let target = permission_target(CanManageAccountAlias { scope })?;
    Ok(authority_has_permission(world, authority, &target))
}
/// Return `true` when `authority` holds account-alias management permission for an explicit
/// dataspace/domain scope.
///
/// Domainful aliases require their exact domain permission. Dataspace permission applies only to
/// domainless aliases and cannot be combined with, or substituted for, domain authorization.
///
/// This variant remains usable while a dynamic dataspace alias is inactive, allowing a stale
/// binding to be cleared without trusting caller-supplied namespace metadata.
///
/// # Errors
/// Returns the original local construction refusal or a malformed exact token error.
pub fn authority_can_manage_account_alias_scope(
    world: &impl WorldReadOnly,
    authority: &AccountId,
    dataspace: DataSpaceId,
    domain: Option<&DomainId>,
) -> Result<bool, crate::sns::SnsError> {
    let permission = match domain {
        Some(domain_id) => permission_target(CanManageAccountAlias {
            scope: AccountAliasPermissionScope::Domain(domain_id.clone()),
        })?,
        None => permission_target(CanManageAccountAlias {
            scope: AccountAliasPermissionScope::Dataspace(dataspace),
        })?,
    };
    Ok(authority_has_permission(world, authority, &permission))
}
/// Return `true` when `authority` holds the asset-definition-alias capability for `alias`.
///
/// An exact alias-and-definition grant is checked first. A qualified alias otherwise requires its
/// exact domain scope, while a dataspace-root alias requires only its exact dataspace scope.
/// Account-alias permissions are intentionally not consulted.
///
/// # Errors
/// Returns the original local construction refusal or a malformed exact token error.
pub fn authority_can_manage_asset_definition_alias(
    world: &impl WorldReadOnly,
    authority: &AccountId,
    asset_definition_id: &iroha_data_model::asset::AssetDefinitionId,
    alias: &iroha_data_model::asset::AssetDefinitionAlias,
    dataspace: DataSpaceId,
    domain: Option<&DomainId>,
) -> Result<bool, crate::sns::SnsError> {
    let exact = permission_target(CanManageAssetDefinitionAlias {
        scope: AssetDefinitionAliasPermissionScope::Alias(ResolvedAssetDefinitionAliasV1::new(
            alias.clone(),
            dataspace,
            asset_definition_id.clone(),
        )),
    })?;
    if authority_has_permission(world, authority, &exact) {
        return Ok(true);
    }
    let scoped = match domain {
        Some(domain) => permission_target(CanManageAssetDefinitionAlias {
            scope: AssetDefinitionAliasPermissionScope::Domain(domain.clone()),
        })?,
        None => permission_target(CanManageAssetDefinitionAlias {
            scope: AssetDefinitionAliasPermissionScope::Dataspace(dataspace),
        })?,
    };
    Ok(authority_has_permission(world, authority, &scoped))
}
/// Return whether an exact asset-definition-alias permission targets a live binding.
///
/// This is a Core storage invariant, independent from whichever executor authorizes the grant.
/// Non-asset-alias permissions and wider asset-alias scopes pass unchanged. An exact permission
/// must pin the current catalog entry and the exact definition currently bound to the alias. A
/// binding whose grace window elapsed is not a valid grant root even if cleanup has not run yet.
pub(crate) fn asset_definition_alias_permission_targets_active_binding(
    world: &impl WorldReadOnly,
    permission: &Permission,
    now_ms: u64,
) -> bool {
    if permission.name() != "CanManageAssetDefinitionAlias" {
        return true;
    }
    let Ok(permission) = CanManageAssetDefinitionAlias::try_from(permission) else {
        return false;
    };
    match permission.scope {
        AssetDefinitionAliasPermissionScope::Alias(alias) => {
            alias.matches_catalog(world.dataspace_catalog())
                && alias.parent_domain().is_ok()
                && world
                    .asset_definition_alias_bindings()
                    .get(&alias.asset_definition_id)
                    .is_some_and(|binding| {
                        binding.alias == alias.canonical_name
                            && !binding.is_grace_expired_at(now_ms)
                    })
                && world
                    .asset_definitions()
                    .get(&alias.asset_definition_id)
                    .is_some()
        }
        AssetDefinitionAliasPermissionScope::Domain(_)
        | AssetDefinitionAliasPermissionScope::Dataspace(_) => true,
    }
}
/// Metric categories emitted by the alias service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AliasMetricKind {
    /// Tracks alias resolution operations for telemetry emission.
    Resolve,
}
impl AliasMetricKind {
    const fn as_label(self) -> &'static str {
        match self {
            Self::Resolve => "resolve",
        }
    }
}
/// Alias storage backed by a Merkle-friendly map.
#[derive(Clone)]
pub struct AliasStorage {
    inner: Arc<RwLock<BTreeMap<Name, AliasRecord>>>,
    index: Arc<RwLock<BTreeMap<AliasIndex, Name>>>,
    attester: AliasAttester,
    metrics: Option<Arc<Metrics>>,
}
impl fmt::Debug for AliasStorage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let alias_count = self.inner.read().map(|map| map.len()).unwrap_or(0);
        let index_count = self.index.read().map(|map| map.len()).unwrap_or(0);
        f.debug_struct("AliasStorage")
            .field("alias_count", &alias_count)
            .field("index_count", &index_count)
            .field("attester", &self.attester.account_id)
            .field("metrics_attached", &self.metrics.is_some())
            .finish()
    }
}
impl AliasStorage {
    /// Create an empty storage instance backed by `attester`.
    #[must_use]
    pub fn new(attester: AliasAttester) -> Self {
        Self {
            inner: Arc::default(),
            index: Arc::default(),
            attester,
            metrics: None,
        }
    }
    /// Create storage wired to the shared telemetry metrics registry.
    #[must_use]
    pub fn with_metrics(attester: AliasAttester, metrics: Arc<Metrics>) -> Self {
        let mut storage = Self::new(attester);
        storage.metrics = Some(metrics);
        storage
    }
    /// Insert or update an alias record.
    ///
    /// # Errors
    /// Returns [`AliasError::Poison`] when the alias or index map lock is poisoned.
    #[instrument(skip(self))]
    pub fn put(&self, record: AliasRecord) -> Result<AliasEvent, AliasError> {
        let attestation = self.attester.sign_record(&record)?;
        let index = record.index;
        let alias = record.alias.clone();
        {
            let mut by_alias = self
                .inner
                .write()
                .map_err(|_| AliasError::Poison("alias"))?;
            by_alias.insert(alias.clone(), record.clone());
        }
        {
            let mut by_index = self
                .index
                .write()
                .map_err(|_| AliasError::Poison("index"))?;
            by_index.insert(index, alias.clone());
        }
        Ok(AliasEvent::Recorded(AliasRecordedEvent {
            record,
            attestation,
        }))
    }
    /// Resolve alias by name.
    ///
    /// # Errors
    /// Returns [`AliasError::Poison`] if the alias map lock is poisoned.
    pub fn resolve(&self, alias: &Name) -> Result<Option<AliasRecord>, AliasError> {
        let guard = self.inner.read().map_err(|_| AliasError::Poison("alias"))?;
        Ok(guard.get(alias).cloned())
    }
    /// Resolve alias by Merkle index.
    ///
    /// # Errors
    /// Returns [`AliasError::Poison`] if the alias or index map lock is poisoned.
    pub fn resolve_index(&self, index: AliasIndex) -> Result<Option<AliasRecord>, AliasError> {
        let alias = self
            .index
            .read()
            .map_err(|_| AliasError::Poison("index"))?
            .get(&index)
            .cloned();
        alias.map_or_else(|| Ok(None), |name| self.resolve(&name))
    }
    #[cfg(any(test, feature = "iroha-core-tests"))]
    /// Record a Merkle attestation hash for an alias if present.
    ///
    /// # Errors
    /// Returns [`AliasError::Poison`] if the alias map lock is poisoned or
    /// [`AliasError::NotFound`] if the alias is unknown.
    pub fn push_attestation(
        &self,
        alias: &Name,
        hash: HashOf<AliasAttestation>,
    ) -> Result<(), AliasError> {
        let mut guard = self
            .inner
            .write()
            .map_err(|_| AliasError::Poison("alias"))?;
        let record = guard
            .get_mut(alias)
            .ok_or_else(|| AliasError::NotFound(alias.clone()))?;
        record.push_attestation(hash);
        Ok(())
    }
    /// Emit telemetry for alias usage (lookup, attestation, etc.).
    pub fn emit_metrics(&self, alias: &Name, lane: &'static str, kind: AliasMetricKind) {
        if let Some(metrics) = &self.metrics {
            metrics
                .alias_usage_total
                .with_label_values(&[lane, kind.as_label()])
                .inc();
        }
        event!(
            Level::INFO,
            alias = %alias.as_ref(),
            lane,
            event = kind.as_label(),
            data_source = "ds_placeholder",
            "alias_usage"
        );
    }
}
/// Errors returned by alias operations.
#[derive(Debug, Error)]
pub enum AliasError {
    /// Provided alias was not found.
    #[error("alias not found: {0}")]
    NotFound(Name),
    /// Storage lock poisoned.
    #[error("alias storage poisoned: {0}")]
    Poison(&'static str),
    /// Alias attestation signing failed.
    #[error("alias attestation signing failed: {0}")]
    Signing(String),
    /// Alias attestation failed verification.
    #[error("alias attestation invalid: {0}")]
    InvalidAttestation(&'static str),
}
/// Helper builder for CLI/SDK wiring. Keeps operations explicit.
#[derive(Debug)]
pub struct AliasService {
    storage: AliasStorage,
}
impl AliasService {
    /// Construct service with empty storage backed by `attester`.
    #[must_use]
    pub fn new(attester: AliasAttester) -> Self {
        Self {
            storage: AliasStorage::new(attester),
        }
    }
    /// Construct service with metrics instrumentation attached.
    #[must_use]
    pub fn with_metrics(attester: AliasAttester, metrics: Arc<Metrics>) -> Self {
        Self {
            storage: AliasStorage::with_metrics(attester, metrics),
        }
    }
    /// Access storage for read/write operations.
    pub fn storage(&self) -> &AliasStorage {
        &self.storage
    }
    /// Resolve alias to target, returning attestation hashes for auditing.
    ///
    /// # Errors
    /// Propagates [`AliasError::Poison`] from the storage backend and returns
    /// [`AliasError::NotFound`] when the alias is absent.
    pub fn resolve(
        &self,
        alias: &Name,
    ) -> Result<(AliasTarget, Vec<HashOf<AliasAttestation>>), AliasError> {
        let record = self
            .storage
            .resolve(alias)?
            .ok_or_else(|| AliasError::NotFound(alias.clone()))?;
        Ok((record.target, record.attestation_hashes))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use iroha_crypto::Algorithm;
    use iroha_data_model::{account::AccountId, alias::AliasIndex};
    use iroha_model_base::name::Name;
    use std::{
        panic::{AssertUnwindSafe, catch_unwind},
        str::FromStr,
        sync::Arc,
    };
    fn owner() -> AccountId {
        const SIGNATORY: &str =
            "ed0120EDF6D7B52C7032D03AEC696F2068BD53101528F3C7B6081BFF05A1662D7FC245";
        AccountId::new(SIGNATORY.parse().expect("public key"))
    }
    fn alias_attester(seed: u8) -> AliasAttester {
        AliasAttester::new(
            KeyPair::try_from_seed(vec![seed; 32], Algorithm::Ed25519)
                .expect("derive checked alias attester fixture key"),
        )
    }
    fn alias_service() -> AliasService {
        AliasService::new(alias_attester(0xA1))
    }
    fn alias_storage() -> AliasStorage {
        AliasStorage::new(alias_attester(0xA2))
    }
    #[test]
    fn original_alias_permission_construction_never_panics_under_local_json_refusal() {
        use iroha_data_model::{Registrable, account::Account};
        let owner = owner();
        let domain = DomainId::try_new("retail", "universal").unwrap();
        let alias = ResolvedAccountAliasV1::new(
            "alice@retail.universal".parse().unwrap(),
            DataSpaceId::UNIVERSAL,
        );
        let permission = Permission::from(CanManageAccountAlias {
            scope: AccountAliasPermissionScope::Domain(domain),
        });
        let mut world =
            crate::state::World::with([], [Account::new(owner.clone()).build(&owner)], []);
        world.account_permissions.insert(
            owner.clone(),
            std::collections::BTreeSet::from([permission.clone()]),
        );
        let view = world.view();
        assert!(authority_can_manage_resolved_account_alias(&view, &owner, &alias).unwrap());
        let result = catch_unwind(AssertUnwindSafe(|| {
            norito::with_decode_limits_scope(
                norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
                || authority_can_manage_resolved_account_alias(&view, &owner, &alias),
            )
        }));
        assert!(
            result.is_ok(),
            "original permission lookup may defer but cannot panic on local JSON refusal"
        );
        assert!(matches!(
            result.unwrap(),
            Err(crate::sns::SnsError::Deferred(_))
        ));
        assert!(
            view.account_permissions()
                .get(&owner)
                .unwrap()
                .contains(&permission)
        );
        assert!(authority_can_manage_resolved_account_alias(&view, &owner, &alias).unwrap());
    }
    #[test]
    fn all_alias_permission_readers_preserve_refusal_direct_role_and_revocation() {
        use iroha_data_model::{
            Registrable,
            account::Account,
            role::{Role, RoleId},
        };
        use std::collections::BTreeSet;
        let owner = owner();
        let domain = DomainId::try_new("retail", "universal").unwrap();
        let alias = ResolvedAccountAliasV1::new(
            "alice@retail.universal".parse().unwrap(),
            DataSpaceId::UNIVERSAL,
        );
        let numeric = AccountAlias::new(
            "alice".parse().unwrap(),
            Some(iroha_data_model::account::rekey::AccountAliasDomain::new(
                "retail".parse().unwrap(),
            )),
            DataSpaceId::UNIVERSAL,
        );
        let asset = iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            domain.clone(),
            "usd".parse().unwrap(),
        );
        let asset_alias = "usd#retail.universal".parse().unwrap();
        let permissions: BTreeSet<Permission> = [
            CanResolveAccountAlias {
                scope: AccountAliasPermissionScope::Domain(domain.clone()),
            }
            .into(),
            CanManageAccountAlias {
                scope: AccountAliasPermissionScope::Domain(domain.clone()),
            }
            .into(),
            CanManageAssetDefinitionAlias {
                scope: AssetDefinitionAliasPermissionScope::Domain(domain.clone()),
            }
            .into(),
        ]
        .into();
        let mut world =
            crate::state::World::with([], [Account::new(owner.clone()).build(&owner)], []);
        let check = |world: &crate::state::WorldView<'_>, index| match index {
            0 => authority_can_resolve_account_alias(world, &owner, &numeric),
            1 => authority_can_resolve_resolved_account_alias(world, &owner, &alias),
            2 => authority_can_manage_account_alias(world, &owner, &numeric),
            3 => authority_can_manage_resolved_account_alias(world, &owner, &alias),
            4 => authority_can_manage_account_alias_scope(
                world,
                &owner,
                DataSpaceId::UNIVERSAL,
                Some(&domain),
            ),
            5 => authority_can_manage_asset_definition_alias(
                world,
                &owner,
                &asset,
                &asset_alias,
                DataSpaceId::UNIVERSAL,
                Some(&domain),
            ),
            _ => unreachable!(),
        };
        world
            .account_permissions
            .insert(owner.clone(), permissions.clone());
        for index in 0..6 {
            let view = world.view();
            assert!(check(&view, index).unwrap(), "direct reader {index}");
            let refused = norito::with_decode_limits_scope(
                norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, 0, usize::MAX),
                || check(&view, index),
            );
            assert!(
                matches!(refused, Err(crate::sns::SnsError::Deferred(_))),
                "reader {index}: {refused:?}"
            );
            assert_eq!(
                view.account_permissions().get(&owner).unwrap(),
                &permissions
            );
            assert!(check(&view, index).unwrap(), "same original grant retries");
        }
        world
            .account_permissions
            .insert(owner.clone(), BTreeSet::new());
        let role_id: RoleId = "alias_permission_role".parse().unwrap();
        let mut role = Role::new(role_id.clone(), owner.clone());
        for permission in &permissions {
            role = role.add_permission(permission.clone());
        }
        world.roles.insert(role_id.clone(), role.build(&owner));
        let membership = crate::role::RoleIdWithOwner::new(owner.clone(), role_id);
        world.account_roles.insert(membership.clone(), ());
        for index in 0..6 {
            assert!(
                check(&world.view(), index).unwrap(),
                "assigned role {index}"
            );
        }
        {
            let mut roles = world.account_roles.block();
            assert_eq!(roles.remove(membership), Some(()));
            roles.commit();
        }
        for index in 0..6 {
            assert!(
                !check(&world.view(), index).unwrap(),
                "revoked role {index}"
            );
        }
        let malformed = permissions
            .iter()
            .map(|permission| {
                Permission::new(
                    permission.name().to_owned(),
                    iroha_primitives::json::Json::from_raw_json("null".to_owned()).unwrap(),
                )
            })
            .collect();
        world.account_permissions.insert(owner.clone(), malformed);
        for index in 0..6 {
            assert!(
                !check(&world.view(), index).unwrap(),
                "malformed grant {index}"
            );
        }
        let wrong_domain = DomainId::try_new("other", "universal").unwrap();
        world.account_permissions.insert(
            owner.clone(),
            BTreeSet::from([
                CanResolveAccountAlias {
                    scope: AccountAliasPermissionScope::Domain(wrong_domain.clone()),
                }
                .into(),
                CanManageAccountAlias {
                    scope: AccountAliasPermissionScope::Domain(wrong_domain.clone()),
                }
                .into(),
                CanManageAssetDefinitionAlias {
                    scope: AssetDefinitionAliasPermissionScope::Domain(wrong_domain),
                }
                .into(),
            ]),
        );
        for index in 0..6 {
            assert!(!check(&world.view(), index).unwrap(), "wrong scope {index}");
        }
    }
    #[test]
    fn storage_roundtrip() {
        let service = alias_service();
        let alias = Name::from_str("alias").expect("valid");
        let record = AliasRecord::new(
            alias.clone(),
            owner(),
            AliasTarget::Custom(vec![1, 2, 3]),
            AliasIndex(1),
        );
        let event = service
            .storage
            .put(record)
            .expect("put should succeed without poisoning");
        match event {
            AliasEvent::Recorded(payload) => {
                assert_eq!(payload.record.index, AliasIndex(1));
                let signature = payload.attestation.signature.payload();
                assert!(!signature.is_empty());
                assert!(!signature.iter().all(|byte| *byte == 0));
                verify_alias_attestation(&payload.record, &payload.attestation)
                    .expect("storage event attestation verifies");
            }
            _ => panic!("unexpected event"),
        }
        let resolved = service
            .storage
            .resolve(&alias)
            .expect("lock not poisoned")
            .expect("alias present");
        assert_eq!(resolved.index, AliasIndex(1));
        let resolved_by_index = service
            .storage
            .resolve_index(AliasIndex(1))
            .expect("lock not poisoned")
            .expect("alias present");
        assert_eq!(resolved_by_index.alias, alias);
    }
    #[test]
    fn service_resolve_success() {
        let service = alias_service();
        let alias = Name::from_str("alice").expect("valid");
        let target = AliasTarget::Custom(vec![4, 5, 6]);
        let record = AliasRecord::new(alias.clone(), owner(), target.clone(), AliasIndex(2));
        let expected_attestations = record.attestation_hashes.clone();
        service.storage.put(record).expect("put should succeed");
        let (resolved_target, attestations) = service.resolve(&alias).expect("should resolve");
        assert_eq!(resolved_target, target);
        assert_eq!(attestations, expected_attestations);
    }
    #[test]
    fn put_returns_error_when_alias_lock_poisoned() {
        let storage = alias_storage();
        let alias = Name::from_str("alias").expect("valid");
        let record = AliasRecord::new(
            alias.clone(),
            owner(),
            AliasTarget::Custom(vec![1, 2, 3]),
            AliasIndex(1),
        );
        let storage_clone = storage.clone();
        let _ = catch_unwind(AssertUnwindSafe(|| {
            let _guard = storage_clone
                .inner
                .write()
                .expect("poison setup should acquire alias lock");
            panic!("poison alias lock");
        }));
        let err = storage
            .put(record)
            .expect_err("alias lock poisoning should error");
        assert!(matches!(err, AliasError::Poison("alias")));
    }
    #[test]
    fn put_returns_error_when_index_lock_poisoned() {
        let storage = alias_storage();
        let alias = Name::from_str("alias").expect("valid");
        let record = AliasRecord::new(
            alias.clone(),
            owner(),
            AliasTarget::Custom(vec![1, 2, 3]),
            AliasIndex(1),
        );
        // Pre-populate alias map so alias lock isn't poisoned.
        storage
            .inner
            .write()
            .expect("setup should not be poisoned")
            .insert(alias.clone(), record.clone());
        let storage_clone = storage.clone();
        let _ = catch_unwind(AssertUnwindSafe(|| {
            let _guard = storage_clone
                .index
                .write()
                .expect("poison setup should acquire index lock");
            panic!("poison index lock");
        }));
        let err = storage
            .put(record)
            .expect_err("index lock poisoning should error");
        assert!(matches!(err, AliasError::Poison("index")));
    }
    #[test]
    fn service_resolve_poisoned_lock() {
        let service = alias_service();
        let alias = Name::from_str("bob").expect("valid");
        let _ = catch_unwind(AssertUnwindSafe(|| {
            let _guard = service
                .storage
                .inner
                .write()
                .expect("lock should be available");
            panic!("poisoning alias storage");
        }));
        let err = service.resolve(&alias).expect_err("lock is poisoned");
        assert!(matches!(err, AliasError::Poison("alias")));
    }
    #[test]
    fn emit_metrics_records_usage_counter() {
        let metrics = Arc::new(Metrics::default());
        let storage = AliasStorage::with_metrics(alias_attester(0xA3), Arc::clone(&metrics));
        let alias = Name::from_str("usage").expect("valid");
        storage.emit_metrics(&alias, "global", AliasMetricKind::Resolve);
        let counter = metrics
            .alias_usage_total
            .with_label_values(&["global", AliasMetricKind::Resolve.as_label()])
            .get();
        assert_eq!(counter, 1);
    }
    #[test]
    fn verify_alias_attestation_rejects_tampered_record() {
        let storage = alias_storage();
        let alias = Name::from_str("signedalias").expect("valid");
        let record = AliasRecord::new(
            alias,
            owner(),
            AliasTarget::Custom(vec![1, 2, 3]),
            AliasIndex(9),
        );
        let AliasEvent::Recorded(event) = storage.put(record).expect("put signs") else {
            panic!("unexpected event");
        };
        verify_alias_attestation(&event.record, &event.attestation).expect("valid attestation");
        let mut tampered = event.record.clone();
        tampered.index = AliasIndex(10);
        let err = verify_alias_attestation(&tampered, &event.attestation)
            .expect_err("tampered record must not verify");
        assert!(matches!(
            err,
            AliasError::InvalidAttestation("signature verification failed")
        ));
    }
}
