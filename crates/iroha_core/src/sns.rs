//! Ledger-backed SNS storage and mutation helpers.
//!
//! This module is the authoritative SNS read/write path used by account aliases,
//! domain-name lease checks, dataspace-name ownership checks, and the Torii SNS
//! HTTP API. SNS records and policies are stored in `World.smart_contract_state`
//! so the ledger-backed lifecycle model remains deterministic across peers.
#[cfg(test)]
use crate::state::{State, StateReadOnly};
use crate::state::{
    StateBlock, StateStorageAdmissionError, StateTransaction, World, WorldReadOnly,
};
use iroha_data_model::block::BlockHeader;
#[cfg(test)]
use iroha_data_model::nexus::DataSpaceMetadata;
use iroha_data_model::sns::pricing::{
    PricingError, enforce_policy_active, label_matches_tier, payment_asset_definition_id,
    pick_pricing_tier, required_payment_amount, tier_by_pricing_class, validate_term_bounds,
};
pub use iroha_data_model::sns::{
    ACCOUNT_ALIAS_SUFFIX_ID, DATASPACE_ALIAS_SUFFIX_ID, DOMAIN_NAME_SUFFIX_ID, record_storage_key,
};
#[cfg(test)]
use iroha_data_model::transaction::Executable;
use iroha_data_model::{
    Identifiable,
    account::{AccountAddress, AccountId, rekey::AccountAlias},
    alias_setup::{AccountAliasName, AliasAutoRenewConfigV1, AliasAutoRenewStateV1, AliasTargetV1},
    asset::{AssetDefinitionAlias, AssetDefinitionId, AssetId},
    isi::{alias_setup::EnsureAlias, register::RegisterBox},
    nexus::DataSpaceCatalogRead,
    permission::Permission,
    sns::{
        AuctionKind, ControllerType, NameAuctionStateV1, NameControllerV1, NameRecordV1,
        NameSelectorError, NameSelectorV1, NameStatus, NameTombstoneStateV1, PriceTierV1,
        ReservedNameV1, SuffixFeeSplitV1, SuffixId, SuffixPolicyV1, SuffixStatus, TokenValue,
        fixtures,
    },
};
use iroha_executor_data_model::permission::account::{
    AccountAliasPermissionScope, CanManageAccountAlias,
};
use iroha_model_base::domain::DomainId;
use iroha_model_base::metadata::Metadata;
use iroha_model_base::state_path::StatePath;
use iroha_model_base::topology::DataSpaceId;
#[cfg(test)]
use iroha_primitives::json::Json as IrohaJson;
use iroha_primitives::numeric::Quantity;
use mv::storage::StorageReadOnly;
use norito::codec::{Decode as _, Encode as _};
#[cfg(test)]
use std::time::SystemTime;
use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
};
use thiserror::Error;
const MS_PER_DAY: u64 = 86_400_000;
const MS_PER_YEAR: u64 = iroha_data_model::alias_setup::ALIAS_LEASE_YEAR_MS;
const EXPIRED_TOMBSTONE_REASON: &str = "expired";
/// Maximum indexed rekey-history occurrences examined by one lineage request.
pub(crate) const ACCOUNT_REKEY_LINEAGE_WORK_LIMIT: usize = 4_096;

#[derive(Default)]
struct AccountRekeyLineageWork {
    consumed: usize,
}

impl AccountRekeyLineageWork {
    fn charge(&mut self, units: usize) -> Result<(), SnsError> {
        self.consumed = self
            .consumed
            .checked_add(units)
            .filter(|consumed| *consumed <= ACCOUNT_REKEY_LINEAGE_WORK_LIMIT)
            .ok_or_else(|| {
                SnsError::Conflict(format!(
                    "account rekey lineage exceeds the deterministic {ACCOUNT_REKEY_LINEAGE_WORK_LIMIT}-occurrence work limit"
                ))
            })?;
        Ok(())
    }
}
fn default_namespace_lease_price() -> Quantity {
    "0.5"
        .parse()
        .expect("hard-coded SNS lease price is canonical")
}
/// Reserved dataspace alias that must stay permanently defined.
pub use iroha_data_model::sns::RESERVED_UNIVERSAL_DATASPACE_ALIAS;
/// Stable diagnostic code emitted when static and ledger-backed dataspace mappings disagree.
pub const ALIAS_CATALOG_MAPPING_CONFLICT_CODE: &str = "alias.catalog.mapping_conflict";
/// Name-record metadata key carrying the expected numeric id of a dataspace alias.
pub const SNS_DATASPACE_ID_METADATA_KEY: &str = "sns.dataspace_id";
#[cfg(test)]
const SNS_DYNAMIC_DATASPACE_FAULT_TOLERANCE: u32 = 1;
/// Maximum number of persisted alias auto-renew records examined in one block.
///
/// This consensus constant bounds native maintenance work. A durable cursor
/// advances through canonically ordered storage keys so larger registries remain fair.
pub const ALIAS_AUTO_RENEW_SWEEP_LIMIT: usize =
    iroha_data_model::parameter::FastpqSourcePolicyV1::NATIVE_MAINTENANCE_INVOCATIONS as usize;
/// Move-only source authority issued by the original bounded SNS sweep.
pub(crate) struct SnsNativeMaintenancePermit {
    network: iroha_data_model::NetworkId,
    proposal: iroha_crypto::HashOf<BlockHeader>,
    direct_slot: iroha_crypto::Hash,
    storage_key: StatePath,
    revision: u64,
    record_digest: iroha_crypto::Hash,
}
impl SnsNativeMaintenancePermit {
    fn issue(
        transaction: &StateTransaction<'_, '_>,
        scope: &crate::state::native_maintenance::NativeMaintenanceTimeScope,
        state: &AliasAutoRenewStateV1,
    ) -> Result<Self, SnsError> {
        scope
            .authenticate(transaction)
            .map_err(SnsError::Internal)?;
        Ok(Self {
            network: transaction.network_id,
            proposal: transaction._curr_block.hash(),
            direct_slot: transaction
                .direct_execution_identity()
                .map_err(|error| SnsError::Internal(error.to_owned()))?,
            storage_key: alias_auto_renew_storage_key(&state.target)?,
            revision: state.revision,
            record_digest: Self::record_digest(
                state,
                transaction.native_maintenance_binding_limit(),
            )
            .map_err(SnsError::Internal)?,
        })
    }
    fn record_digest(
        state: &AliasAutoRenewStateV1,
        limit: u64,
    ) -> Result<iroha_crypto::Hash, String> {
        let length =
            u64::try_from(norito::canonical_frame_len(state).map_err(|error| error.to_string())?)
                .map_err(|_| "SNS native record length exceeds u64")?;
        if length > limit {
            return Err("SNS native record exceeds its committed intrinsic source limit".into());
        }
        Ok(iroha_crypto::Hash::new(
            norito::encode_canonical(state).map_err(|error| error.to_string())?,
        ))
    }
    /// Canonical source facts included alongside the exact live renewal quote.
    pub(crate) fn binding(&self) -> Result<Vec<u8>, String> {
        norito::encode_canonical(&(
            "iroha:sns:native-maintenance-source:v1",
            self.network,
            self.proposal,
            self.direct_slot,
            self.storage_key.clone(),
            self.revision,
            self.record_digest,
        ))
        .map_err(|error| error.to_string())
    }
    /// Recheck the original proposal and persisted configuration before source admission.
    pub(crate) fn authenticate(
        &self,
        transaction: &StateTransaction<'_, '_>,
    ) -> Result<(), SnsError> {
        transaction
            .validate_native_maintenance_scope()
            .map_err(SnsError::Internal)?;
        self.authenticate_source_record(transaction)
    }
    fn authenticate_source_record(
        &self,
        transaction: &StateTransaction<'_, '_>,
    ) -> Result<(), SnsError> {
        if self.network != transaction.network_id
            || self.proposal != transaction._curr_block.hash()
            || self.direct_slot
                != transaction
                    .direct_execution_identity()
                    .map_err(|error| SnsError::Internal(error.to_owned()))?
        {
            return Err(SnsError::Internal(
                "SNS native source belongs to a foreign execution scope".into(),
            ));
        }
        let current = alias_auto_renew_state_by_storage_key(&transaction.world, &self.storage_key)?;
        if current.revision != self.revision
            || Self::record_digest(&current, transaction.native_maintenance_binding_limit())
                .map_err(SnsError::Internal)?
                != self.record_digest
        {
            return Err(SnsError::Internal(
                "SNS native source differs from the original record or configuration".into(),
            ));
        }
        Ok(())
    }
}
/// Non-reusable proof that the SNS maintenance sweep admitted one exact renewal charge.
pub(crate) struct VerifiedSnsAutoRenewalCharge {
    source: SnsNativeMaintenancePermit,
    selector: NameSelectorV1,
    owner: AccountId,
    current_expiry_ms: u64,
    target_expiry_ms: u64,
    source_id: AssetId,
    destination: AccountId,
    amount: Quantity,
}
impl VerifiedSnsAutoRenewalCharge {
    fn new(
        transaction: &StateTransaction<'_, '_>,
        scope: &crate::state::native_maintenance::NativeMaintenanceTimeScope,
        state: &AliasAutoRenewStateV1,
        selector: NameSelectorV1,
        owner: AccountId,
        current_expiry_ms: u64,
        target_expiry_ms: u64,
        source_id: AssetId,
        destination: AccountId,
        amount: Quantity,
    ) -> Result<Self, SnsError> {
        Ok(Self {
            source: SnsNativeMaintenancePermit::issue(transaction, scope, state)?,
            selector,
            owner,
            current_expiry_ms,
            target_expiry_ms,
            source_id,
            destination,
            amount,
        })
    }
    pub(crate) fn into_parts(
        self,
    ) -> (
        SnsNativeMaintenancePermit,
        NameSelectorV1,
        AccountId,
        u64,
        u64,
        AssetId,
        AccountId,
        Quantity,
    ) {
        (
            self.source,
            self.selector,
            self.owner,
            self.current_expiry_ms,
            self.target_expiry_ms,
            self.source_id,
            self.destination,
            self.amount,
        )
    }
}
/// Stable suspension code for a pinned SNS policy-version mismatch.
pub const ALIAS_AUTO_RENEW_POLICY_DRIFT_CODE: &str = "alias.auto_renew.policy_drift";
/// Stable suspension code for a pinned payment-asset mismatch.
pub const ALIAS_AUTO_RENEW_ASSET_DRIFT_CODE: &str = "alias.auto_renew.asset_drift";
/// Stable suspension code for a persisted/current resource-owner mismatch.
pub const ALIAS_AUTO_RENEW_OWNER_DRIFT_CODE: &str = "alias.auto_renew.owner_drift";
/// Stable suspension code for an invalid persisted auto-renew timing range.
pub const ALIAS_AUTO_RENEW_RANGE_INVALID_CODE: &str = "alias.auto_renew.range_invalid";
/// Stable suspension code after the configured consecutive-failure limit.
pub const ALIAS_AUTO_RENEW_FAILURES_EXHAUSTED_CODE: &str = "alias.auto_renew.failures_exhausted";
const ALIAS_AUTO_RENEW_CURSOR_VERSION: u8 = 1;
const ALIAS_AUTO_RENEW_STATE_PREFIX: &str = "sns/auto_renew/";
const ALIAS_AUTO_RENEW_CURSOR_KEY: &str = "sns/auto_renew_cursor/v1";
#[derive(norito::NoritoSchema)]
#[norito_schema(name = "iroha_core::sns::AliasAutoRenewCursorV1")]
#[derive(Debug, Clone, PartialEq, Eq, norito::codec::Encode, norito::codec::Decode)]
struct AliasAutoRenewCursorV1 {
    version: u8,
    last_storage_key: StatePath,
}
/// Internal record proving that Core already debited the exact lease quote.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LeasePayment {
    pub(crate) asset_id: String,
    pub(crate) gross_amount: Quantity,
    pub(crate) net_amount: Quantity,
}
/// Internal registrar input assembled only after native payment succeeds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RegisterNameInput {
    pub(crate) selector: NameSelectorV1,
    pub(crate) owner: AccountId,
    pub(crate) controllers: Vec<NameControllerV1>,
    pub(crate) term_years: u8,
    pub(crate) pricing_class_hint: Option<u8>,
    pub(crate) payment: LeasePayment,
    pub(crate) metadata: Metadata,
}
/// Errors returned by the ledger-backed SNS helpers.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SnsError {
    /// The original local attempt could not decode or fund authoritative state.
    /// This nonserializable owner is never an inactive-name or payment verdict.
    #[error("{0}")]
    Deferred(crate::execution_attempt::ExecutionDeferred),
    /// The exact canonical registration is absent from authoritative storage.
    #[error("registration `{label}` not found")]
    RegistrationNotFound {
        /// Fixed SNS namespace identifier.
        suffix_id: SuffixId,
        /// Canonical registration label.
        label: String,
    },
    /// The requested entity is missing from authoritative state.
    #[error("{0}")]
    NotFound(String),
    /// The caller provided an invalid selector or payload.
    #[error("{0}")]
    BadRequest(String),
    /// The requested mutation conflicts with the authoritative SNS state.
    #[error("{0}")]
    Conflict(String),
    /// The state mutation could not be committed.
    #[error("{0}")]
    Internal(String),
}
impl SnsError {
    /// Move the original local refusal without formatting or cloning its owner.
    pub fn into_attempt_error<E>(
        self,
        rejected: impl FnOnce(Self) -> E,
    ) -> crate::execution_attempt::ExecutionAttemptError<E> {
        match self {
            Self::Deferred(reason) => {
                crate::execution_attempt::ExecutionAttemptError::Deferred(reason)
            }
            completed => {
                crate::execution_attempt::ExecutionAttemptError::Rejected(rejected(completed))
            }
        }
    }

    /// Borrow the original operational refusal without interpreting diagnostic text.
    pub fn deferral(&self) -> Option<&crate::execution_attempt::ExecutionDeferred> {
        match self {
            Self::Deferred(reason) => Some(reason),
            _ => None,
        }
    }

    pub(crate) fn retain_in_instruction(
        self,
        state: &mut StateTransaction<'_, '_>,
    ) -> iroha_data_model::isi::error::InstructionExecutionError {
        if let Self::Deferred(reason) = self {
            let _ = state.defer_execution(reason);
            return iroha_data_model::isi::error::InstructionExecutionError::InvariantViolation(
                "local SNS execution did not complete".into(),
            );
        }
        iroha_data_model::isi::error::InstructionExecutionError::InvariantViolation(
            self.to_string().into(),
        )
    }
}

fn sns_decode_error(error: norito::Error, context: &'static str) -> SnsError {
    match crate::execution_attempt::norito_decode_attempt_error(error, |error| {
        SnsError::Internal(format!("{context}: {error}"))
    }) {
        crate::execution_attempt::ExecutionAttemptError::Rejected(error) => error,
        crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => {
            SnsError::Deferred(reason)
        }
    }
}

impl From<PricingError> for SnsError {
    fn from(error: PricingError) -> Self {
        match error {
            PricingError::BadRequest(message) => Self::BadRequest(message),
            PricingError::Conflict(message) => Self::Conflict(message),
        }
    }
}
/// SNS namespaces used by the authoritative name-record storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnsNamespace {
    /// Full account-alias key (`name@domain.dataspace` or `name@dataspace`).
    AccountAlias,
    /// Canonical `domain.dataspace` literal.
    Domain,
    /// Canonical dataspace alias.
    Dataspace,
}
/// Deterministic billing quote for a SNS lease operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseQuote {
    /// Canonical selector for the leased name.
    pub selector: NameSelectorV1,
    /// Pricing class that applies to the operation.
    pub pricing_class: u8,
    /// Canonical payment asset literal required by the policy.
    pub payment_asset_id: String,
    /// Asset definition charged for the operation.
    pub payment_asset_definition_id: AssetDefinitionId,
    /// Account receiving the lease payment.
    pub collector_account: AccountId,
    /// Exact non-negative gross/net charge for the operation.
    pub charge_amount: Quantity,
    /// Lease expiry after the operation succeeds.
    pub expires_at_ms: u64,
    /// Grace-period expiry after the operation succeeds.
    pub grace_expires_at_ms: u64,
    /// Redemption expiry after the operation succeeds.
    pub redemption_expires_at_ms: u64,
}
impl SnsNamespace {
    /// Stable suffix identifier assigned to this namespace.
    #[must_use]
    pub const fn suffix_id(self) -> SuffixId {
        match self {
            Self::AccountAlias => ACCOUNT_ALIAS_SUFFIX_ID,
            Self::Domain => DOMAIN_NAME_SUFFIX_ID,
            Self::Dataspace => DATASPACE_ALIAS_SUFFIX_ID,
        }
    }
    /// Canonical HTTP namespace literal.
    #[must_use]
    pub const fn as_path(self) -> &'static str {
        match self {
            Self::AccountAlias => "account-alias",
            Self::Domain => "domain",
            Self::Dataspace => "dataspace",
        }
    }
    /// Human-readable suffix string used by stored SNS policies.
    #[must_use]
    pub const fn policy_suffix(self) -> &'static str {
        match self {
            Self::AccountAlias => "account-alias",
            Self::Domain => "domain",
            Self::Dataspace => "dataspace",
        }
    }
    fn label_regex(self) -> &'static str {
        match self {
            Self::AccountAlias => r"^[a-z0-9_@.-]{3,255}$",
            Self::Domain => r"^[a-z0-9-]{1,63}\.[a-z0-9-]{1,63}$",
            Self::Dataspace => r"^[a-z0-9-]{1,63}$",
        }
    }
    fn current_policy_probe_label(self) -> &'static str {
        match self {
            Self::AccountAlias => "current_owner@current.universal",
            Self::Domain => "current.universal",
            Self::Dataspace => "current",
        }
    }
    /// Parse the canonical HTTP namespace literal.
    ///
    /// # Errors
    ///
    /// Returns [`SnsError::BadRequest`] when the namespace is unknown.
    pub fn from_path(path: &str) -> Result<Self, SnsError> {
        match path.trim().to_ascii_lowercase().as_str() {
            "account-alias" | "account_alias" => Ok(Self::AccountAlias),
            "domain" => Ok(Self::Domain),
            "dataspace" => Ok(Self::Dataspace),
            other => Err(SnsError::BadRequest(format!(
                "unknown SNS namespace `{other}`"
            ))),
        }
    }
    /// Resolve the namespace from its fixed suffix identifier.
    ///
    /// # Errors
    ///
    /// Returns [`SnsError::BadRequest`] when the suffix id is not one of the
    /// fixed on-chain namespace identifiers.
    pub fn from_suffix_id(suffix_id: SuffixId) -> Result<Self, SnsError> {
        match suffix_id {
            ACCOUNT_ALIAS_SUFFIX_ID => Ok(Self::AccountAlias),
            DOMAIN_NAME_SUFFIX_ID => Ok(Self::Domain),
            DATASPACE_ALIAS_SUFFIX_ID => Ok(Self::Dataspace),
            other => Err(SnsError::BadRequest(format!(
                "unsupported SNS suffix id `{other}`"
            ))),
        }
    }
}
/// Compute the durable smart-contract-state key for a SNS suffix policy.
#[must_use]
pub fn policy_storage_key(suffix_id: SuffixId) -> StatePath {
    StatePath::from_str(&format!("sns/policies/{suffix_id}"))
        .expect("static SNS policy storage key format is a valid StatePath")
}
/// Compute the durable key for one alias auto-renew configuration record.
///
/// # Errors
///
/// Returns [`SnsError`] if the resolved target is not canonical.
pub fn alias_auto_renew_storage_key(target: &AliasTargetV1) -> Result<StatePath, SnsError> {
    let selector = crate::alias_setup::selector_for_resolved_alias_target(target)
        .map_err(|error| SnsError::BadRequest(error.to_string()))?;
    StatePath::from_str(&format!(
        "sns/auto_renew/{}/{}",
        selector.suffix_id,
        hex::encode(selector.name_hash())
    ))
    .map_err(|error| SnsError::Internal(format!("invalid auto-renew storage key: {error}")))
}
/// Read and validate the persisted auto-renew state for a resolved target.
///
/// # Errors
///
/// Returns [`SnsError`] for malformed, unsupported, or mismatched persisted state.
pub fn alias_auto_renew_state(
    world: &impl WorldReadOnly,
    target: &AliasTargetV1,
) -> Result<Option<AliasAutoRenewStateV1>, SnsError> {
    let key = alias_auto_renew_storage_key(target)?;
    let Some(bytes) = world.smart_contract_state().get(&key) else {
        return Ok(None);
    };
    let mut cursor = bytes.as_slice();
    let state = AliasAutoRenewStateV1::decode(&mut cursor)
        .map_err(|error| sns_decode_error(error, "failed to decode alias auto-renew state"))?;
    if !cursor.is_empty() {
        return Err(SnsError::Internal(
            "alias auto-renew state contains trailing bytes".to_owned(),
        ));
    }
    if state.version != AliasAutoRenewStateV1::VERSION {
        return Err(SnsError::Conflict(format!(
            "unsupported alias auto-renew state version {}",
            state.version
        )));
    }
    if &state.target != target {
        return Err(SnsError::Conflict(
            "alias auto-renew storage key contains a different target".to_owned(),
        ));
    }
    Ok(Some(state))
}
fn alias_auto_renew_internal_key(literal: &str) -> StatePath {
    StatePath::from_str(literal).expect("hard-coded alias auto-renew key is a valid StatePath")
}
fn alias_auto_renew_cursor(
    world: &impl WorldReadOnly,
) -> Result<Option<AliasAutoRenewCursorV1>, SnsError> {
    let key = alias_auto_renew_internal_key(ALIAS_AUTO_RENEW_CURSOR_KEY);
    let Some(bytes) = world.smart_contract_state().get(&key) else {
        return Ok(None);
    };
    let mut cursor = bytes.as_slice();
    let state = AliasAutoRenewCursorV1::decode(&mut cursor)
        .map_err(|error| sns_decode_error(error, "failed to decode alias auto-renew cursor"))?;
    if !cursor.is_empty() {
        return Err(SnsError::Internal(
            "alias auto-renew cursor contains trailing bytes".to_owned(),
        ));
    }
    if state.version != ALIAS_AUTO_RENEW_CURSOR_VERSION {
        return Err(SnsError::Conflict(format!(
            "unsupported alias auto-renew cursor version {}",
            state.version
        )));
    }
    if !state
        .last_storage_key
        .as_ref()
        .starts_with(ALIAS_AUTO_RENEW_STATE_PREFIX)
    {
        return Err(SnsError::Conflict(
            "alias auto-renew cursor points outside the state namespace".to_owned(),
        ));
    }
    Ok(Some(state))
}
fn persist_alias_auto_renew_cursor(
    state_transaction: &mut StateTransaction<'_, '_>,
    last_storage_key: StatePath,
) {
    let key = alias_auto_renew_internal_key(ALIAS_AUTO_RENEW_CURSOR_KEY);
    state_transaction.world.smart_contract_state.insert(
        key,
        AliasAutoRenewCursorV1 {
            version: ALIAS_AUTO_RENEW_CURSOR_VERSION,
            last_storage_key,
        }
        .encode(),
    );
}
fn alias_auto_renew_candidate_keys(
    world: &impl WorldReadOnly,
    last_storage_key: Option<&StatePath>,
    limit: usize,
) -> Vec<StatePath> {
    if limit == 0 {
        return Vec::new();
    }
    let prefix = alias_auto_renew_internal_key(ALIAS_AUTO_RENEW_STATE_PREFIX);
    let start = last_storage_key.cloned().unwrap_or_else(|| prefix.clone());
    let mut keys = Vec::with_capacity(limit);
    for (key, _) in world.smart_contract_state().range(start..) {
        if !key.as_ref().starts_with(ALIAS_AUTO_RENEW_STATE_PREFIX) {
            break;
        }
        if last_storage_key.is_some_and(|last| last == key) {
            continue;
        }
        keys.push(key.clone());
        if keys.len() == limit {
            return keys;
        }
    }
    let Some(last_storage_key) = last_storage_key else {
        return keys;
    };
    for (key, _) in world.smart_contract_state().range(prefix..) {
        if !key.as_ref().starts_with(ALIAS_AUTO_RENEW_STATE_PREFIX) || key > last_storage_key {
            break;
        }
        keys.push(key.clone());
        if keys.len() == limit {
            break;
        }
    }
    keys
}
fn alias_auto_renew_state_by_storage_key(
    world: &impl WorldReadOnly,
    storage_key: &StatePath,
) -> Result<AliasAutoRenewStateV1, SnsError> {
    let bytes = world
        .smart_contract_state()
        .get(storage_key)
        .ok_or_else(|| {
            SnsError::NotFound(format!(
                "alias auto-renew state `{storage_key}` disappeared during maintenance"
            ))
        })?;
    decode_alias_auto_renew_state(bytes, storage_key)
}
fn decode_alias_auto_renew_state(
    bytes: &[u8],
    storage_key: &StatePath,
) -> Result<AliasAutoRenewStateV1, SnsError> {
    let mut cursor = bytes;
    let state = AliasAutoRenewStateV1::decode(&mut cursor)
        .map_err(|error| sns_decode_error(error, "failed to decode alias auto-renew state"))?;
    if !cursor.is_empty() {
        return Err(SnsError::Internal(format!(
            "alias auto-renew state `{storage_key}` contains trailing bytes"
        )));
    }
    if state.version != AliasAutoRenewStateV1::VERSION {
        return Err(SnsError::Conflict(format!(
            "unsupported alias auto-renew state version {} at `{storage_key}`",
            state.version
        )));
    }
    let expected_key = alias_auto_renew_storage_key(&state.target)?;
    if expected_key != *storage_key {
        return Err(SnsError::Conflict(format!(
            "alias auto-renew state target does not match storage key `{storage_key}`"
        )));
    }
    Ok(state)
}
/// Persist one validated alias auto-renew state record.
///
/// # Errors
///
/// Returns [`SnsError`] if the target cannot produce its canonical storage key.
pub(crate) fn persist_alias_auto_renew_state(
    state_transaction: &mut StateTransaction<'_, '_>,
    state: &AliasAutoRenewStateV1,
) -> Result<(), SnsError> {
    let key = alias_auto_renew_storage_key(&state.target)?;
    state_transaction
        .world
        .smart_contract_state
        .insert(key, state.encode());
    Ok(())
}
enum AliasAutoRenewAttempt {
    NotDue,
    Renewed,
    Retry(String),
    Suspend(&'static str),
    Deferred(crate::execution_attempt::ExecutionDeferred),
    Storage(StateStorageAdmissionError),
}
fn alias_auto_renew_attempt(
    state_transaction: &mut StateTransaction<'_, '_>,
    scope: &crate::state::native_maintenance::NativeMaintenanceTimeScope,
    state: &AliasAutoRenewStateV1,
    config: &AliasAutoRenewConfigV1,
    now_ms: u64,
) -> AliasAutoRenewAttempt {
    if crate::alias_setup::validate_alias_auto_renew_ranges(config).is_err() {
        return AliasAutoRenewAttempt::Suspend(ALIAS_AUTO_RENEW_RANGE_INVALID_CODE);
    }
    let selector = match crate::alias_setup::selector_for_resolved_alias_target(&state.target) {
        Ok(selector) => selector,
        Err(error) => {
            return match error.deferral() {
                Some(reason) => AliasAutoRenewAttempt::Deferred(reason.clone()),
                None => AliasAutoRenewAttempt::Retry(error.to_string()),
            };
        }
    };
    let policy = match policy_by_id(state_transaction.world(), selector.suffix_id) {
        Ok(Some(policy)) => policy,
        Ok(None) => {
            return AliasAutoRenewAttempt::Retry(format!(
                "SNS policy {} is missing",
                selector.suffix_id
            ));
        }
        Err(error) => {
            return match error.deferral() {
                Some(reason) => AliasAutoRenewAttempt::Deferred(reason.clone()),
                None => AliasAutoRenewAttempt::Retry(error.to_string()),
            };
        }
    };
    if policy.policy_version != config.policy_version {
        return AliasAutoRenewAttempt::Suspend(ALIAS_AUTO_RENEW_POLICY_DRIFT_CODE);
    }
    let policy_payment_asset = match payment_asset_definition_id(&policy) {
        Ok(asset) => asset,
        Err(error) => return AliasAutoRenewAttempt::Retry(error.to_string()),
    };
    if policy_payment_asset != config.payment_asset {
        return AliasAutoRenewAttempt::Suspend(ALIAS_AUTO_RENEW_ASSET_DRIFT_CODE);
    }
    if let Err(error) = crate::alias_setup::validate_resolved_alias_target(
        state_transaction.world(),
        &state_transaction.nexus.dataspace_catalog,
        &state.target,
        now_ms,
    ) {
        return match error.deferral() {
            Some(reason) => AliasAutoRenewAttempt::Deferred(reason.clone()),
            None => AliasAutoRenewAttempt::Retry(error.to_string()),
        };
    }
    let record = match get_name_record_by_selector(state_transaction.world(), &selector, now_ms) {
        Ok(record) => record,
        Err(error) => {
            return match error.deferral() {
                Some(reason) => AliasAutoRenewAttempt::Deferred(reason.clone()),
                None => AliasAutoRenewAttempt::Retry(error.to_string()),
            };
        }
    };
    if record.owner != state.owner {
        return AliasAutoRenewAttempt::Suspend(ALIAS_AUTO_RENEW_OWNER_DRIFT_CODE);
    }
    if now_ms
        < record
            .expires_at_ms
            .saturating_sub(config.renew_before_expiry_ms)
    {
        return AliasAutoRenewAttempt::NotDue;
    }
    if state
        .next_retry_at_ms
        .is_some_and(|next_retry_at_ms| now_ms < next_retry_at_ms)
    {
        return AliasAutoRenewAttempt::NotDue;
    }
    let target_expiry_ms = record
        .expires_at_ms
        .saturating_add(years_to_ms(config.term_years));
    let quote = match quote_resolved_name_renewal(
        state_transaction.world(),
        selector.clone(),
        record.expires_at_ms,
        target_expiry_ms,
        now_ms,
    ) {
        Ok(quote) => quote,
        Err(error) => {
            return match error.deferral() {
                Some(reason) => AliasAutoRenewAttempt::Deferred(reason.clone()),
                None => AliasAutoRenewAttempt::Retry(error.to_string()),
            };
        }
    };
    if quote.payment_asset_definition_id != config.payment_asset {
        return AliasAutoRenewAttempt::Suspend(ALIAS_AUTO_RENEW_ASSET_DRIFT_CODE);
    }
    if quote.charge_amount > config.max_amount {
        return AliasAutoRenewAttempt::Retry(format!(
            "exact renewal quote {} exceeds configured cap {}",
            quote.charge_amount, config.max_amount
        ));
    }
    let charge = match VerifiedSnsAutoRenewalCharge::new(
        state_transaction,
        scope,
        state,
        selector.clone(),
        state.owner.clone(),
        record.expires_at_ms,
        target_expiry_ms,
        AssetId::of(config.payment_asset.clone(), state.owner.clone()),
        quote.collector_account.clone(),
        quote.charge_amount.clone(),
    ) {
        Ok(charge) => charge,
        Err(error) => {
            return match error {
                SnsError::Deferred(reason) => AliasAutoRenewAttempt::Deferred(reason),
                error => AliasAutoRenewAttempt::Retry(error.to_string()),
            };
        }
    };
    if let Err(error) =
        crate::smartcontracts::isi::asset::isi::execute_verified_sns_auto_renewal_charge(
            state_transaction,
            charge,
        )
    {
        if let Err(refusal) = state_transaction.require_storage_admission() {
            return AliasAutoRenewAttempt::Storage(refusal);
        }
        if let Some(reason) = state_transaction.execution_deferral() {
            return AliasAutoRenewAttempt::Deferred(reason);
        }
        return AliasAutoRenewAttempt::Retry(error.to_string());
    }
    if let Err(error) = crate::retail_fee::finalize(state_transaction) {
        return AliasAutoRenewAttempt::Retry(error.to_string());
    }
    let payment = native_payment_for_quote(&quote);
    match renew_resolved_name(
        state_transaction,
        selector,
        record.expires_at_ms,
        target_expiry_ms,
        payment,
    ) {
        Ok(_) => AliasAutoRenewAttempt::Renewed,
        Err(error) => match error.deferral() {
            Some(reason) => AliasAutoRenewAttempt::Deferred(reason.clone()),
            None => AliasAutoRenewAttempt::Retry(error.to_string()),
        },
    }
}
fn advance_alias_auto_renew_revision(state: &mut AliasAutoRenewStateV1) {
    state.revision = state.revision.saturating_add(1);
}
fn suspend_alias_auto_renew(
    state_block: &mut StateBlock<'_>,
    mut state: AliasAutoRenewStateV1,
    reason: &'static str,
) -> Result<(), crate::execution_attempt::ExecutionAttemptError<StateStorageAdmissionError>> {
    advance_alias_auto_renew_revision(&mut state);
    state.next_retry_at_ms = None;
    state.suspended_reason = Some(reason.to_owned());
    let target = state.target.clone();
    let mut transaction = state_block.try_transaction()?;
    match persist_alias_auto_renew_state(&mut transaction, &state) {
        Ok(()) => {
            transaction.apply();
            iroha_logger::warn!(target = %target, reason, "alias auto-renew suspended");
        }
        Err(error) => {
            if let Some(reason) = error.deferral() {
                return Err(crate::execution_attempt::ExecutionAttemptError::Deferred(
                    reason.clone(),
                ));
            }
            iroha_logger::error!(target = %target, %error, "failed to persist alias auto-renew suspension");
        }
    }
    Ok(())
}
fn record_alias_auto_renew_failure(
    state_block: &mut StateBlock<'_>,
    mut state: AliasAutoRenewStateV1,
    config: &AliasAutoRenewConfigV1,
    now_ms: u64,
    error: &str,
) -> Result<(), crate::execution_attempt::ExecutionAttemptError<StateStorageAdmissionError>> {
    advance_alias_auto_renew_revision(&mut state);
    state.failure_count = state.failure_count.saturating_add(1);
    if state.failure_count >= config.max_failures {
        state.next_retry_at_ms = None;
        state.suspended_reason = Some(ALIAS_AUTO_RENEW_FAILURES_EXHAUSTED_CODE.to_owned());
    } else {
        state.next_retry_at_ms = Some(now_ms.saturating_add(config.retry_backoff_ms));
        state.suspended_reason = None;
    }
    let target = state.target.clone();
    let suspended = state.suspended_reason.is_some();
    let failure_count = state.failure_count;
    let mut transaction = state_block.try_transaction()?;
    match persist_alias_auto_renew_state(&mut transaction, &state) {
        Ok(()) => {
            transaction.apply();
            if suspended {
                iroha_logger::warn!(
                    target = %target,
                    failure_count,
                    error,
                    "alias auto-renew suspended after repeated failures"
                );
            } else {
                iroha_logger::info!(
                    target = %target,
                    failure_count,
                    error,
                    "alias auto-renew scheduled a deterministic retry"
                );
            }
        }
        Err(persist_error) => {
            if let Some(reason) = persist_error.deferral() {
                return Err(crate::execution_attempt::ExecutionAttemptError::Deferred(
                    reason.clone(),
                ));
            }
            iroha_logger::error!(
                target = %target,
                %persist_error,
                "failed to persist alias auto-renew failure state"
            );
        }
    }
    Ok(())
}
fn process_alias_auto_renew_storage_key(
    state_block: &mut StateBlock<'_>,
    scope: &crate::state::native_maintenance::NativeMaintenanceTimeScope,
    storage_key: &StatePath,
    now_ms: u64,
) -> Result<(), crate::execution_attempt::ExecutionAttemptError<StateStorageAdmissionError>> {
    let state = match alias_auto_renew_state_by_storage_key(&state_block.world, storage_key) {
        Ok(state) => state,
        Err(error) => {
            if let Some(reason) = error.deferral() {
                return Err(crate::execution_attempt::ExecutionAttemptError::Deferred(
                    reason.clone(),
                ));
            }
            iroha_logger::error!(%storage_key, %error, "malformed alias auto-renew state skipped");
            return Ok(());
        }
    };
    let Some(config) = state.config.clone() else {
        return Ok(());
    };
    if state.suspended_reason.is_some() {
        return Ok(());
    }
    let mut transaction = state_block.try_transaction()?;
    let attempt = alias_auto_renew_attempt(&mut transaction, scope, &state, &config, now_ms);
    transaction.require_storage_admission()?;
    if let Some(reason) = transaction.execution_deferral() {
        return Err(crate::execution_attempt::ExecutionAttemptError::Deferred(
            reason,
        ));
    }
    match attempt {
        AliasAutoRenewAttempt::Storage(refusal) => return Err(refusal.into()),
        AliasAutoRenewAttempt::Deferred(reason) => {
            return Err(crate::execution_attempt::ExecutionAttemptError::Deferred(
                reason,
            ));
        }
        AliasAutoRenewAttempt::NotDue => {}
        AliasAutoRenewAttempt::Renewed => {
            let mut updated = state;
            advance_alias_auto_renew_revision(&mut updated);
            updated.failure_count = 0;
            updated.next_retry_at_ms = None;
            updated.suspended_reason = None;
            let target = updated.target.clone();
            match persist_alias_auto_renew_state(&mut transaction, &updated) {
                Ok(()) => {
                    transaction.apply();
                    iroha_logger::info!(target = %target, now_ms, "alias lease auto-renewed");
                }
                Err(error) => {
                    if let SnsError::Deferred(reason) = error {
                        return Err(crate::execution_attempt::ExecutionAttemptError::Deferred(
                            reason,
                        ));
                    }
                    iroha_logger::error!(target = %target, %error, "failed to persist successful alias auto-renew state");
                }
            }
        }
        AliasAutoRenewAttempt::Suspend(reason) => {
            drop(transaction);
            suspend_alias_auto_renew(state_block, state, reason)?;
        }
        AliasAutoRenewAttempt::Retry(error) => {
            drop(transaction);
            record_alias_auto_renew_failure(state_block, state, &config, now_ms, &error)?;
        }
    }
    Ok(())
}
/// Process a bounded, fair slice of enabled alias auto-renew records at block time.
///
/// Individual payment failures update deterministic retry/suspension state;
/// a local World admission refusal returns to the original output owner.
pub(crate) fn process_alias_auto_renewals(
    state_block: &mut StateBlock<'_>,
    scope: &crate::state::native_maintenance::NativeMaintenanceTimeScope,
) -> Result<(), crate::execution_attempt::ExecutionAttemptError<StateStorageAdmissionError>> {
    let cursor = match alias_auto_renew_cursor(&state_block.world) {
        Ok(cursor) => cursor,
        Err(error) => {
            if let Some(reason) = error.deferral() {
                return Err(crate::execution_attempt::ExecutionAttemptError::Deferred(
                    reason.clone(),
                ));
            }
            iroha_logger::error!(%error, "alias auto-renew sweep skipped because its cursor is invalid");
            return Ok(());
        }
    };
    let storage_keys = alias_auto_renew_candidate_keys(
        &state_block.world,
        cursor.as_ref().map(|cursor| &cursor.last_storage_key),
        ALIAS_AUTO_RENEW_SWEEP_LIMIT.min(state_block.native_maintenance_invocation_limit()),
    );
    let now_ms =
        u64::try_from(state_block._curr_block.creation_time().as_millis()).unwrap_or(u64::MAX);
    for storage_key in &storage_keys {
        process_alias_auto_renew_storage_key(state_block, scope, storage_key, now_ms)?;
    }
    if let Some(last_storage_key) = storage_keys.last().cloned() {
        let mut transaction = state_block.try_transaction()?;
        persist_alias_auto_renew_cursor(&mut transaction, last_storage_key);
        transaction.apply();
    }
    Ok(())
}
/// Build the selector used for a full account-alias lease record.
pub fn selector_for_account_alias(
    alias: &AccountAlias,
    catalog: &impl DataSpaceCatalogRead,
) -> Result<NameSelectorV1, iroha_model_base::error::ParseError> {
    Ok(NameSelectorV1 {
        version: NameSelectorV1::VERSION,
        suffix_id: ACCOUNT_ALIAS_SUFFIX_ID,
        label: alias.to_literal(catalog)?,
    })
}
/// Build the selector used for a canonical domain-name lease record.
pub fn selector_for_domain(domain: &DomainId) -> Result<NameSelectorV1, NameSelectorError> {
    NameSelectorV1::new(DOMAIN_NAME_SUFFIX_ID, domain.to_string())
}
/// Build the selector used for a canonical dataspace-alias lease record.
pub fn selector_for_dataspace_alias(alias: &str) -> Result<NameSelectorV1, NameSelectorError> {
    NameSelectorV1::new(DATASPACE_ALIAS_SUFFIX_ID, alias)
}
/// Derive the deterministic dataspace id for a SNS dataspace alias.
///
/// Configured Nexus dataspaces keep their explicit catalog ids. SNS-only dataspaces use the same
/// stable name hash that keys the ledger record, so every peer can route a newly registered
/// dataspace without an out-of-band catalog update.
#[must_use]
pub fn dataspace_id_for_sns_alias(alias: &str) -> Option<DataSpaceId> {
    iroha_data_model::sns::dataspace_id_for_alias(alias)
}
fn selector_for_account_alias_literal(literal: &str) -> Result<NameSelectorV1, SnsError> {
    let alias = literal
        .parse::<AccountAliasName>()
        .map_err(|err| SnsError::BadRequest(err.to_string()))?;
    Ok(NameSelectorV1 {
        version: NameSelectorV1::VERSION,
        suffix_id: ACCOUNT_ALIAS_SUFFIX_ID,
        label: alias.canonical_text(),
    })
}
/// Canonicalize a namespace-scoped literal into the fixed SNS selector.
/// Registration names are textual SNS identities; a private dataspace does not need a
/// physical catalog entry to read its lease. Numeric routing and permission resolution
/// separately validate the active dataspace mapping.
///
/// # Errors
///
/// Returns [`SnsError::BadRequest`] when the namespace or literal is invalid.
pub fn selector_for_namespace_literal(
    namespace: SnsNamespace,
    literal: &str,
) -> Result<NameSelectorV1, SnsError> {
    match namespace {
        SnsNamespace::AccountAlias => selector_for_account_alias_literal(literal),
        SnsNamespace::Domain => {
            let domain = DomainId::parse_fully_qualified(literal.trim())
                .map_err(|err| SnsError::BadRequest(err.reason().to_owned()))?;
            selector_for_domain(&domain).map_err(|err| SnsError::BadRequest(err.to_string()))
        }
        SnsNamespace::Dataspace => selector_for_dataspace_alias(literal)
            .map_err(|err| SnsError::BadRequest(err.to_string())),
    }
}
/// Decode a SNS record from world state for the supplied selector.
///
/// # Errors
///
/// Returns [`SnsError`] when stored authoritative state is malformed. Missing
/// state is represented only by `Ok(None)` and is never conflated with a decode
/// or identity failure.
pub fn record_by_selector(
    world: &impl WorldReadOnly,
    selector: &NameSelectorV1,
) -> Result<Option<NameRecordV1>, SnsError> {
    let key = record_storage_key(selector);
    let Some(bytes) = world.smart_contract_state().get(&key) else {
        return Ok(None);
    };
    decode_record_for_selector(bytes, selector).map(Some)
}
/// Decode a SNS policy from world state for the supplied suffix id.
///
/// # Errors
///
/// Returns [`SnsError`] when stored authoritative state is malformed. Missing
/// state is represented only by `Ok(None)`.
pub fn policy_by_id(
    world: &impl WorldReadOnly,
    suffix_id: SuffixId,
) -> Result<Option<SuffixPolicyV1>, SnsError> {
    let key = policy_storage_key(suffix_id);
    let Some(bytes) = world.smart_contract_state().get(&key) else {
        return Ok(None);
    };
    decode_policy_for_suffix(bytes, suffix_id).map(Some)
}
fn decode_record_for_selector(
    bytes: &[u8],
    selector: &NameSelectorV1,
) -> Result<NameRecordV1, SnsError> {
    let decode = || {
        let record: NameRecordV1 = norito::codec::decode_adaptive(bytes)
            .map_err(|error| sns_decode_error(error, "failed to decode an SNS record"))?;
        if record.selector != *selector || record.name_hash != selector.name_hash() {
            return Err(SnsError::Internal(
                "SNS record identity mismatch".to_owned(),
            ));
        }
        Ok(record)
    };
    if !crate::smartcontracts::isi::query::singular_query_limits_active() {
        return decode();
    }
    let elements = bytes
        .len()
        .checked_mul(8)
        .ok_or_else(|| SnsError::Internal("SNS record exceeds query memory limits".to_owned()))?;
    let limits = crate::smartcontracts::isi::query::singular_query_decode_limits(
        bytes.len(),
        norito::DecodeLimits::new(elements, bytes.len(), elements, usize::MAX, 64),
    )
    .map_err(|_| SnsError::Internal("SNS record exceeds query memory limits".to_owned()))?;
    norito::with_decode_limits_scope(limits, decode)
}
fn decode_policy_for_suffix(bytes: &[u8], suffix_id: SuffixId) -> Result<SuffixPolicyV1, SnsError> {
    let mut slice = bytes;
    let policy = SuffixPolicyV1::decode(&mut slice)
        .map_err(|error| sns_decode_error(error, "failed to decode SNS suffix policy"))?;
    if !slice.is_empty() {
        return Err(SnsError::Internal(format!(
            "SNS suffix policy {suffix_id} contains trailing bytes"
        )));
    }
    let namespace = SnsNamespace::from_suffix_id(suffix_id)?;
    if policy.suffix_id != suffix_id || policy.suffix != namespace.policy_suffix() {
        return Err(SnsError::Internal(format!(
            "SNS suffix policy identity mismatch for {suffix_id}"
        )));
    }
    ensure_namespace_policy_is_current(namespace, &policy)?;
    Ok(policy)
}
fn bootstrap_steward_for_world(world: &impl WorldReadOnly) -> AccountId {
    world
        .domain(&iroha_genesis::GENESIS_DOMAIN_ID)
        .map(|domain| domain.owned_by().clone())
        .unwrap_or_else(|_| fixtures::steward_account())
}
fn active_account_alias_lease_record(
    state_transaction: &StateTransaction<'_, '_>,
    owner: &AccountId,
    label: &AccountAlias,
) -> Result<(StatePath, NameRecordV1), SnsError> {
    let selector = selector_for_account_alias(label, &state_transaction.nexus.dataspace_catalog)
        .map_err(|err| SnsError::BadRequest(err.to_string()))?;
    let storage_key = record_storage_key(&selector);
    let bytes = state_transaction
        .world
        .smart_contract_state
        .get(&storage_key)
        .ok_or_else(|| {
            SnsError::NotFound(format!(
                "active SNS lease required for account alias `{}`",
                selector.normalized_label()
            ))
        })?;
    let record = decode_record_for_selector(bytes, &selector)?;
    let now_ms = state_transaction.block_unix_timestamp_ms();
    if !matches!(effective_status(&record, now_ms), NameStatus::Active) {
        return Err(SnsError::Conflict(format!(
            "active SNS lease required for account alias `{}`",
            selector.normalized_label()
        )));
    }
    if record.owner != *owner {
        return Err(SnsError::Conflict(format!(
            "active SNS lease for account alias `{}` is owned by another account",
            selector.normalized_label()
        )));
    }
    Ok((storage_key, record))
}
/// Ensures an active SNS name lease exists and is owned by the exact alias target account.
pub fn ensure_account_alias_lease(
    state_transaction: &StateTransaction<'_, '_>,
    owner: &AccountId,
    label: &AccountAlias,
) -> Result<(), SnsError> {
    active_account_alias_lease_record(state_transaction, owner, label).map(|_| ())
}
fn prepare_account_alias_record_rekey(
    old_owner: &AccountId,
    new_owner: &AccountId,
    record: &mut NameRecordV1,
) -> Result<(), SnsError> {
    let old_address = AccountAddress::from_account_id(old_owner).map_err(|err| {
        SnsError::Internal(format!(
            "failed to derive current account-alias controller for `{}`: {err}",
            record.selector.normalized_label()
        ))
    })?;
    let new_address = AccountAddress::from_account_id(new_owner).map_err(|err| {
        SnsError::Internal(format!(
            "failed to derive replacement account-alias controller for `{}`: {err}",
            record.selector.normalized_label()
        ))
    })?;
    let mut owner_controller_count = 0_usize;
    for controller in &mut record.controllers {
        if controller.account_address.as_ref() == Some(&new_address) {
            return Err(SnsError::Conflict(format!(
                "SNS lease for account alias `{}` already contains the replacement account controller",
                record.selector.normalized_label()
            )));
        }
        if controller.account_address.as_ref() != Some(&old_address) {
            continue;
        }
        if controller.controller_type != ControllerType::Account {
            return Err(SnsError::Internal(format!(
                "SNS lease for account alias `{}` has an invalid owner controller type",
                record.selector.normalized_label()
            )));
        }
        controller.account_address = Some(new_address.clone());
        owner_controller_count = owner_controller_count.saturating_add(1);
    }
    if owner_controller_count != 1 {
        return Err(SnsError::Conflict(format!(
            "SNS lease for account alias `{}` must contain exactly one owner account controller (found {owner_controller_count})",
            record.selector.normalized_label(),
        )));
    }
    record.transfer_owner(new_owner.clone());
    Ok(())
}
/// Strictly enumerate and prepare every account-alias lease owned by `old_owner` for rekey.
///
/// Unlike the binding indexes, SNS ownership also covers acquired-but-unbound and previously
/// unbound leases. A controller replacement must migrate those records too or the old canonical
/// account id becomes an unrecoverable owner. Any malformed record in the account-alias namespace
/// rejects the entire rekey before state mutation.
pub(crate) fn prepare_all_account_alias_lease_rekeys(
    state_transaction: &StateTransaction<'_, '_>,
    old_owner: &AccountId,
    new_owner: &AccountId,
) -> Result<BTreeMap<AccountAlias, (StatePath, NameRecordV1)>, SnsError> {
    let prefix = StatePath::from_str(&format!("sns/records/{ACCOUNT_ALIAS_SUFFIX_ID}/"))
        .expect("static account-alias SNS record prefix is valid");
    let prefix_literal = prefix.as_ref().to_owned();
    let mut updates = BTreeMap::new();
    for (storage_key, bytes) in state_transaction
        .world
        .smart_contract_state
        .range(prefix.clone()..)
    {
        if !storage_key.as_ref().starts_with(&prefix_literal) {
            break;
        }
        let mut slice = bytes.as_slice();
        let mut record = NameRecordV1::decode(&mut slice).map_err(|error| {
            sns_decode_error(error, "failed to decode account-alias SNS record")
        })?;
        if !slice.is_empty() {
            return Err(SnsError::Internal(format!(
                "account-alias SNS record `{storage_key}` contains trailing bytes"
            )));
        }
        if record.selector.suffix_id != ACCOUNT_ALIAS_SUFFIX_ID
            || record.name_hash != record.selector.name_hash()
            || record_storage_key(&record.selector) != storage_key.clone()
        {
            return Err(SnsError::Internal(format!(
                "account-alias SNS record identity mismatch at `{storage_key}`"
            )));
        }
        let alias = AccountAlias::from_literal(
            record.selector.normalized_label(),
            &state_transaction.nexus.dataspace_catalog,
        )
        .map_err(|err| {
            SnsError::Internal(format!(
                "account-alias SNS record `{storage_key}` has a non-canonical selector: {err}"
            ))
        })?;
        let canonical_selector =
            selector_for_account_alias(&alias, &state_transaction.nexus.dataspace_catalog)
                .map_err(|err| SnsError::Internal(err.to_string()))?;
        if record.selector != canonical_selector {
            return Err(SnsError::Internal(format!(
                "account-alias SNS record `{storage_key}` has a non-canonical selector"
            )));
        }
        if record.owner != *old_owner {
            continue;
        }
        prepare_account_alias_record_rekey(old_owner, new_owner, &mut record)?;
        if updates
            .insert(alias, (storage_key.clone(), record))
            .is_some()
        {
            return Err(SnsError::Internal(
                "duplicate canonical account-alias SNS lease during rekey".to_owned(),
            ));
        }
    }
    Ok(updates)
}
fn seed_name_record_with_metadata_if_missing(
    world: &mut World,
    owner: &AccountId,
    selector: NameSelectorV1,
    metadata: Metadata,
) {
    let storage_key = record_storage_key(&selector);
    if world
        .smart_contract_state
        .view()
        .get(&storage_key)
        .is_some()
    {
        return;
    }
    let address = AccountAddress::from_account_id(owner)
        .expect("account id should convert to account address");
    let record = NameRecordV1::new(
        selector,
        owner.clone(),
        vec![NameControllerV1::account(&address)],
        0,
        0,
        u64::MAX,
        u64::MAX,
        u64::MAX,
        metadata,
    );
    world
        .smart_contract_state
        .insert(storage_key, record.encode());
}
fn seed_name_record_if_missing(world: &mut World, owner: &AccountId, selector: NameSelectorV1) {
    seed_name_record_with_metadata_if_missing(world, owner, selector, Metadata::default());
}
fn seed_alias_manage_permissions_if_missing(
    world: &mut World,
    authority: &AccountId,
    label: &AccountAlias,
    dataspace_catalog: &impl DataSpaceCatalogRead,
) {
    let mut permissions = world
        .account_permissions
        .view()
        .get(authority)
        .cloned()
        .unwrap_or_default();
    let dataspace_permission = Permission::from(CanManageAccountAlias {
        scope: AccountAliasPermissionScope::Dataspace(label.dataspace),
    });
    permissions.insert(dataspace_permission);
    if let Some(domain_id) = label
        .domain_id(dataspace_catalog)
        .expect("genesis alias dataspace must resolve")
    {
        let domain_permission = Permission::from(CanManageAccountAlias {
            scope: AccountAliasPermissionScope::Domain(domain_id),
        });
        permissions.insert(domain_permission);
    }
    world
        .account_permissions
        .insert(authority.clone(), permissions);
}
/// Seed bootstrap alias state required by aliases referenced directly in genesis instructions.
///
/// Genesis cannot rely on the normal registrar flow because the namespace policies and bootstrap
/// authority are only coming online while the block executes. This helper pre-seeds the leases and
/// alias-management permissions that the first block itself consumes, mirroring how operators would
/// pre-register those names before normal operation.
/// Private namespace pricing is initialized from the unique fee policy in the same authenticated
/// original genesis before State initialization can seed its global defaults. Existing policy
/// bytes are validated, never retargeted or repaired.
///
/// # Errors
/// Rejects unauthenticated genesis, invalid private fee authority, or conflicting namespace state.
pub fn seed_genesis_alias_bootstrap(
    world: &mut World,
    block: &iroha_data_model::block::SignedBlock,
    dataspace_catalog: &impl DataSpaceCatalogRead,
) -> Result<(), SnsError> {
    use iroha_data_model::{
        block::consensus::{PrivateRootFeePolicy, SumeragiRootScope},
        isi::SetParameter,
        parameter::Parameter,
    };

    iroha_data_model::sumeragi_finality::authenticated_genesis(block)
        .map(|genesis| genesis.into_parts().0)
        .map_err(sns_genesis_read_error)?;
    let metadata = iroha_data_model::sumeragi_finality::signed_genesis_consensus_metadata(block)
        .map_err(sns_genesis_read_error)?;
    if let SumeragiRootScope::Dataspace { .. } = metadata.sumeragi_context.root_scope {
        let mut policy = None;
        for transaction in block.external_transactions() {
            for instruction in transaction.instructions().explicit_instructions() {
                let Some(set) = instruction.as_any().downcast_ref::<SetParameter>() else {
                    continue;
                };
                let Parameter::Custom(custom) = set.inner() else {
                    continue;
                };
                if custom.id() != &PrivateRootFeePolicy::parameter_id() {
                    continue;
                }
                let decoded = PrivateRootFeePolicy::from_custom_parameter(custom)
                    .map_err(|error| SnsError::BadRequest(error.to_string()))?;
                if policy.replace(decoded).is_some() {
                    return Err(SnsError::BadRequest(
                        "private SNS bootstrap repeats its signed fee policy".into(),
                    ));
                }
            }
        }
        let policy = policy.ok_or_else(|| {
            SnsError::BadRequest("private SNS bootstrap omits its signed fee policy".into())
        })?;
        let payment_asset_id = policy.asset_definition_id.to_string();
        // Prevalidate all present namespaces before inserting any absent policy. A partial
        // retained world with another currency must fail without creating mixed state.
        for namespace in [
            SnsNamespace::AccountAlias,
            SnsNamespace::Domain,
            SnsNamespace::Dataspace,
        ] {
            if let Some(bytes) = world
                .smart_contract_state
                .view()
                .get(&policy_storage_key(namespace.suffix_id()))
            {
                let existing = decode_policy_for_suffix(bytes, namespace.suffix_id())?;
                ensure_namespace_policy_is_current(namespace, &existing)?;
                ensure_policy_payment_asset_literal(&existing, &payment_asset_id)?;
            }
        }
        try_seed_default_namespace_policies(world, &payment_asset_id)?;
    }
    seed_genesis_alias_records(world, block, dataspace_catalog);
    Ok(())
}

fn seed_genesis_alias_records(
    world: &mut World,
    block: &iroha_data_model::block::SignedBlock,
    dataspace_catalog: &impl DataSpaceCatalogRead,
) {
    for transaction in block.external_transactions() {
        let authority = transaction.authority();
        for instruction in transaction.instructions().explicit_instructions() {
            if let Some(register) = instruction.as_any().downcast_ref::<RegisterBox>() {
                match register {
                    RegisterBox::Domain(register) => {
                        let selector = selector_for_domain(&register.object().id)
                            .expect("genesis domain ids should be canonical");
                        seed_name_record_if_missing(world, authority, selector);
                    }
                    RegisterBox::Account(register) => {
                        if let Some(label) = register.object().label() {
                            seed_alias_manage_permissions_if_missing(
                                world,
                                authority,
                                label,
                                dataspace_catalog,
                            );
                            if let Ok(selector) =
                                selector_for_account_alias(label, dataspace_catalog)
                            {
                                seed_name_record_if_missing(
                                    world,
                                    register.object().id(),
                                    selector,
                                );
                            }
                        }
                    }
                    _ => {}
                }
            }
            if let Some(ensure) = instruction.as_any().downcast_ref::<EnsureAlias>() {
                let target = ensure.intent.target();
                if let Ok(selector) =
                    crate::alias_setup::selector_for_resolved_alias_target(&target)
                    && let Ok(metadata) = crate::alias_setup::alias_registration_metadata(&target)
                {
                    seed_name_record_with_metadata_if_missing(
                        world,
                        crate::alias_setup::alias_intent_owner(&ensure.intent),
                        selector,
                        metadata,
                    );
                }
            }
        }
    }
}
fn default_namespace_policy(
    namespace: SnsNamespace,
    steward: &AccountId,
    payment_asset_id: &str,
) -> SuffixPolicyV1 {
    SuffixPolicyV1 {
        suffix_id: namespace.suffix_id(),
        suffix: namespace.policy_suffix().to_owned(),
        steward: steward.clone(),
        status: SuffixStatus::Active,
        min_term_years: 1,
        max_term_years: 5,
        grace_period_days: 30,
        redemption_period_days: 60,
        referral_cap_bps: 0,
        reserved_labels: match namespace {
            SnsNamespace::Domain => vec![ReservedNameV1 {
                normalized_label: "treasury".to_owned(),
                assigned_to: Some(steward.clone()),
                release_at_ms: None,
                note: "Protocol reserved domain label".to_owned(),
            }],
            SnsNamespace::Dataspace => vec![iroha_data_model::sns::ReservedNameV1 {
                normalized_label: RESERVED_UNIVERSAL_DATASPACE_ALIAS.to_owned(),
                assigned_to: Some(steward.clone()),
                release_at_ms: None,
                note: "Protocol reserved dataspace alias".to_owned(),
            }],
            _ => Vec::new(),
        },
        payment_asset_id: payment_asset_id.to_owned(),
        pricing: vec![PriceTierV1 {
            tier_id: 0,
            label_regex: namespace.label_regex().to_owned(),
            base_price: TokenValue::new(payment_asset_id, default_namespace_lease_price()),
            auction_kind: AuctionKind::VickreyCommitReveal,
            dutch_floor: None,
            min_duration_years: 1,
            max_duration_years: 5,
        }],
        fee_split: SuffixFeeSplitV1 {
            treasury_bps: 7000,
            steward_bps: 3000,
            referral_max_bps: 0,
            escrow_bps: 0,
        },
        fund_splitter_account: steward.clone(),
        policy_version: 1,
        metadata: Metadata::default(),
    }
}
fn resolve_configured_payment_asset_literal(
    world: &impl WorldReadOnly,
    selector: &str,
) -> Option<String> {
    if selector.is_empty() || selector.trim() != selector {
        return None;
    }
    if let Ok(definition_id) = AssetDefinitionId::parse_address_literal(selector) {
        return Some(definition_id.to_string());
    }
    if selector == "xor#universal" {
        return Some(iroha_config::parameters::defaults::nexus::fees::fee_asset_id());
    }
    let alias = AssetDefinitionAlias::from_str(selector).ok()?;
    let definition_id = world.asset_definition_id_by_alias_at(&alias, 0)?;
    world
        .asset_definition(&definition_id)
        .is_ok()
        .then(|| definition_id.to_string())
}
fn ensure_namespace_policy_is_current(
    namespace: SnsNamespace,
    policy: &SuffixPolicyV1,
) -> Result<(), SnsError> {
    if policy.policy_version == 0 {
        return Err(SnsError::Conflict(format!(
            "SNS {} policy has a zero policy version",
            namespace.as_path()
        )));
    }
    if policy.pricing.is_empty() {
        return Err(SnsError::Conflict(format!(
            "SNS {} policy has no pricing tiers",
            namespace.as_path()
        )));
    }
    let probe = namespace.current_policy_probe_label();
    let mut covers_current_label = false;
    for tier in &policy.pricing {
        covers_current_label |= label_matches_tier(tier, probe)?;
    }
    if !covers_current_label {
        return Err(SnsError::Conflict(format!(
            "SNS {} policy does not cover the current first-release label grammar",
            namespace.as_path()
        )));
    }
    Ok(())
}
fn ensure_policy_matches_configured_payment_asset(
    world: &impl WorldReadOnly,
    policy: &SuffixPolicyV1,
    configured_fee_asset_selector: &str,
) -> Result<(), SnsError> {
    let namespace = SnsNamespace::from_suffix_id(policy.suffix_id)?;
    ensure_namespace_policy_is_current(namespace, policy)?;
    let configured_payment_asset_id =
        resolve_configured_payment_asset_literal(world, configured_fee_asset_selector)
            .ok_or_else(|| {
                SnsError::BadRequest(
                    "configured Nexus fee asset is not a canonical asset definition id or a registered alias"
                        .to_owned(),
                )
            })?;
    let configured_definition_id =
        AssetDefinitionId::parse_address_literal(&configured_payment_asset_id).map_err(|err| {
            SnsError::BadRequest(format!(
                "configured Nexus fee asset is not a canonical asset definition id: {err}"
            ))
        })?;
    ensure_policy_payment_asset_literal(policy, &configured_payment_asset_id)?;
    if world.asset_definition(&configured_definition_id).is_err() {
        return Err(SnsError::NotFound(format!(
            "configured Nexus fee asset `{configured_payment_asset_id}` is not registered"
        )));
    }
    Ok(())
}
fn ensure_policy_payment_asset_literal(
    policy: &SuffixPolicyV1,
    configured_payment_asset_id: &str,
) -> Result<(), SnsError> {
    if policy.payment_asset_id != configured_payment_asset_id {
        return Err(SnsError::Conflict(format!(
            "SNS policy payment asset `{}` does not match configured Nexus fee asset `{configured_payment_asset_id}`",
            policy.payment_asset_id
        )));
    }
    if policy
        .pricing
        .iter()
        .any(|tier| tier.base_price.asset_id != configured_payment_asset_id)
    {
        return Err(SnsError::Conflict(format!(
            "SNS policy pricing tiers do not match configured Nexus fee asset `{configured_payment_asset_id}`"
        )));
    }
    Ok(())
}
/// Ensure one namespace policy is exactly pinned to the configured, registered Nexus fee asset.
pub fn ensure_namespace_policy_payment_asset_matches_configured(
    world: &impl WorldReadOnly,
    namespace: SnsNamespace,
    configured_fee_asset_selector: &str,
) -> Result<(), SnsError> {
    let policy = policy_or_not_found(world, namespace.suffix_id())?;
    ensure_policy_matches_configured_payment_asset(world, &policy, configured_fee_asset_selector)
}
/// Validate every fixed namespace policy against the exact configured payment-asset selector.
///
/// This read-only boundary never repairs or retargets persisted policy state. A stale, malformed,
/// or pre-release policy must be replaced through an explicit ledger transition before startup or
/// configuration can continue.
///
/// # Errors
///
/// Returns [`SnsError`] when a policy is missing, malformed, non-current, or bound to a different
/// payment asset.
pub fn ensure_default_namespace_policies_match_configured(
    world: &impl WorldReadOnly,
    configured_fee_asset_selector: &str,
) -> Result<(), SnsError> {
    let configured_payment_asset_id =
        resolve_configured_payment_asset_literal(world, configured_fee_asset_selector)
            .ok_or_else(|| {
                SnsError::BadRequest(
                    "configured Nexus fee asset is not a canonical asset definition id or a registered alias"
                        .to_owned(),
                )
            })?;
    for namespace in [
        SnsNamespace::AccountAlias,
        SnsNamespace::Domain,
        SnsNamespace::Dataspace,
    ] {
        let policy = policy_or_not_found(world, namespace.suffix_id())?;
        ensure_namespace_policy_is_current(namespace, &policy)?;
        ensure_policy_payment_asset_literal(&policy, &configured_payment_asset_id)?;
    }
    Ok(())
}
/// Validate persisted namespace policies, then seed only namespaces that are absent.
///
/// Existing policy bytes are never rewritten. All persisted namespaces must use one payment
/// asset and cover the current first-release label grammar before any missing policy is inserted.
///
/// # Errors
///
/// Returns [`SnsError`] before mutation when persisted policy state or the fallback asset selector
/// is not current and canonical.
pub(crate) fn try_seed_default_namespace_policies(
    world: &mut World,
    fallback_payment_asset_selector: &str,
) -> Result<(), SnsError> {
    let fallback_payment_asset_id = resolve_configured_payment_asset_literal(
        &world.view(),
        fallback_payment_asset_selector,
    )
    .ok_or_else(|| {
        SnsError::BadRequest(
            "SNS namespace policy fallback asset is not an exact canonical asset definition id or current XOR alias"
                .to_owned(),
        )
    })?;
    let steward = bootstrap_steward_for_world(&world.view());
    let mut missing = Vec::new();
    let mut persisted_payment_asset_id: Option<String> = None;
    for namespace in [
        SnsNamespace::AccountAlias,
        SnsNamespace::Domain,
        SnsNamespace::Dataspace,
    ] {
        let key = policy_storage_key(namespace.suffix_id());
        let existing_policy = world
            .smart_contract_state
            .view()
            .get(&key)
            .map(|bytes| decode_policy_for_suffix(bytes, namespace.suffix_id()));
        match existing_policy {
            Some(Ok(existing_policy)) => {
                ensure_namespace_policy_is_current(namespace, &existing_policy)?;
                ensure_policy_payment_asset_literal(
                    &existing_policy,
                    &existing_policy.payment_asset_id,
                )?;
                if let Some(expected) = persisted_payment_asset_id.as_deref() {
                    if existing_policy.payment_asset_id != expected {
                        return Err(SnsError::Conflict(format!(
                            "SNS {} policy payment asset `{}` conflicts with the persisted namespace asset `{expected}`",
                            namespace.as_path(),
                            existing_policy.payment_asset_id
                        )));
                    }
                } else {
                    persisted_payment_asset_id = Some(existing_policy.payment_asset_id.clone());
                }
            }
            Some(Err(error)) => return Err(error),
            None => missing.push(namespace),
        }
    }
    let payment_asset_id = persisted_payment_asset_id
        .as_deref()
        .unwrap_or(fallback_payment_asset_id.as_str());
    for namespace in missing {
        let policy = default_namespace_policy(namespace, &steward, payment_asset_id);
        world
            .smart_contract_state
            .insert(policy_storage_key(policy.suffix_id), policy.encode());
    }
    Ok(())
}
#[cfg(any(test, feature = "iroha-core-tests"))]
/// Seed the current fixed namespace policies required by the on-chain SNS model.
///
/// Existing state is validated exactly and is never migrated or rewritten.
///
/// # Panics
///
/// Panics when authoritative policy state is present but not current and canonical. The fallible
/// State startup boundary calls the internal validator directly to preserve the diagnostic.
pub fn seed_default_namespace_policies(world: &mut World) {
    let payment_asset_id = iroha_config::parameters::defaults::nexus::fees::fee_asset_id();
    try_seed_default_namespace_policies(world, &payment_asset_id)
        .expect("persisted SNS namespace policies must use the current first-release layout");
}
#[cfg(test)]
/// Seed absent current namespace policies with a test fixture's explicit payment asset.
///
/// # Panics
///
/// Panics when the test fixture already contains non-current or conflicting namespace policy
/// state.
pub(crate) fn seed_default_namespace_policies_for_payment_asset(
    world: &mut World,
    payment_asset_id: &str,
) {
    try_seed_default_namespace_policies(world, payment_asset_id)
        .expect("test SNS namespace policies must use the requested current payment asset");
}
fn years_to_ms(years: u8) -> u64 {
    u64::from(years).saturating_mul(MS_PER_YEAR)
}
fn validate_payment_for_term(
    policy: &SuffixPolicyV1,
    tier: &PriceTierV1,
    term_years: u8,
    payment: &LeasePayment,
) -> Result<(), SnsError> {
    if payment.asset_id != policy.payment_asset_id {
        return Err(SnsError::BadRequest(format!(
            "payment asset `{}` does not match required asset `{}`",
            payment.asset_id, policy.payment_asset_id
        )));
    }
    if payment.net_amount > payment.gross_amount {
        return Err(SnsError::BadRequest(
            "net_amount must not exceed gross_amount".to_owned(),
        ));
    }
    let required = required_payment_amount(tier, term_years)?;
    if payment.gross_amount < required || payment.net_amount < required {
        return Err(SnsError::BadRequest(format!(
            "payment ({}/{} {}) does not meet required amount {} for term {term_years}",
            payment.net_amount, payment.gross_amount, payment.asset_id, required
        )));
    }
    Ok(())
}
fn lease_quote(
    selector: NameSelectorV1,
    policy: &SuffixPolicyV1,
    tier: &PriceTierV1,
    term_years: u8,
    base_expires_at_ms: u64,
) -> Result<LeaseQuote, SnsError> {
    validate_term_bounds(policy, tier, term_years)?;
    let charge_amount = required_payment_amount(tier, term_years)?;
    let payment_asset_definition_id = payment_asset_definition_id(policy)?;
    let expires_at_ms = base_expires_at_ms.saturating_add(years_to_ms(term_years));
    let grace_expires_at_ms =
        expires_at_ms.saturating_add(u64::from(policy.grace_period_days) * MS_PER_DAY);
    let redemption_expires_at_ms =
        grace_expires_at_ms.saturating_add(u64::from(policy.redemption_period_days) * MS_PER_DAY);
    Ok(LeaseQuote {
        selector,
        pricing_class: tier.tier_id,
        payment_asset_id: policy.payment_asset_id.clone(),
        payment_asset_definition_id,
        collector_account: policy.fund_splitter_account.clone(),
        charge_amount,
        expires_at_ms,
        grace_expires_at_ms,
        redemption_expires_at_ms,
    })
}
fn maybe_auction_state(tier: &PriceTierV1, now_ms: u64) -> Option<NameAuctionStateV1> {
    match tier.auction_kind {
        AuctionKind::VickreyCommitReveal => None,
        AuctionKind::DutchReopen => Some(NameAuctionStateV1 {
            kind: tier.auction_kind,
            opened_at_ms: now_ms,
            closes_at_ms: now_ms.saturating_add(3 * MS_PER_DAY),
            floor_price: tier
                .dutch_floor
                .clone()
                .unwrap_or_else(|| tier.base_price.clone()),
            highest_commitment: None,
            settlement_tx: None,
        }),
    }
}
fn refresh_lifecycle(record: &mut NameRecordV1, now_ms: u64) {
    if matches!(record.status, NameStatus::Tombstoned(_)) {
        return;
    }
    if let NameStatus::Frozen(frozen) = &record.status
        && now_ms < frozen.until_ms
    {
        return;
    }
    record.status = effective_status(record, now_ms);
}
/// Validate a controller set before any fee-bearing SNS mutation is attempted.
pub(crate) fn validate_name_controllers(controllers: &[NameControllerV1]) -> Result<(), SnsError> {
    if controllers.is_empty() {
        return Err(SnsError::BadRequest(
            "at least one controller must be provided".to_owned(),
        ));
    }
    for (index, controller) in controllers.iter().enumerate() {
        if controllers[..index].contains(controller) {
            return Err(SnsError::BadRequest(
                "controller list contains a duplicate entry".to_owned(),
            ));
        }
        let valid_shape = match controller.controller_type {
            ControllerType::Account | ControllerType::Multisig => {
                controller.account_address.is_some() && controller.resolver_template_id.is_none()
            }
            ControllerType::ResolverTemplate => {
                controller.account_address.is_none()
                    && controller
                        .resolver_template_id
                        .as_deref()
                        .is_some_and(|id| !id.trim().is_empty())
            }
            ControllerType::ExternalLink => {
                controller.account_address.is_none() && controller.resolver_template_id.is_none()
            }
        };
        if !valid_shape {
            return Err(SnsError::BadRequest(format!(
                "controller at index {index} does not match its controller type"
            )));
        }
    }
    Ok(())
}
fn registration_record(
    selector: NameSelectorV1,
    owner: AccountId,
    controllers: Vec<NameControllerV1>,
    term_years: u8,
    payment: &LeasePayment,
    metadata: Metadata,
    policy: &SuffixPolicyV1,
    tier: &PriceTierV1,
    now_ms: u64,
) -> Result<NameRecordV1, SnsError> {
    enforce_policy_active(policy)?;
    validate_name_controllers(&controllers)?;
    validate_term_bounds(policy, tier, term_years)?;
    validate_payment_for_term(policy, tier, term_years, payment)?;
    let expires_at_ms = now_ms.saturating_add(years_to_ms(term_years));
    let grace_expires_at_ms =
        expires_at_ms.saturating_add(u64::from(policy.grace_period_days) * MS_PER_DAY);
    let redemption_expires_at_ms =
        grace_expires_at_ms.saturating_add(u64::from(policy.redemption_period_days) * MS_PER_DAY);
    Ok(NameRecordV1 {
        selector: selector.clone(),
        name_hash: selector.name_hash(),
        owner,
        ownership_generation: 1,
        controllers,
        status: NameStatus::Active,
        pricing_class: tier.tier_id,
        registered_at_ms: now_ms,
        expires_at_ms,
        grace_expires_at_ms,
        redemption_expires_at_ms,
        metadata,
        auction: maybe_auction_state(tier, now_ms),
    })
}
fn reserved_label_key(namespace: SnsNamespace, selector: &NameSelectorV1) -> &str {
    let literal = selector.normalized_label();
    match namespace {
        SnsNamespace::AccountAlias => literal.split_once('@').map_or(literal, |(label, _)| label),
        SnsNamespace::Domain => literal.split_once('.').map_or(literal, |(label, _)| label),
        SnsNamespace::Dataspace => literal,
    }
}
fn find_active_reserved_label<'a>(
    namespace: SnsNamespace,
    policy: &'a SuffixPolicyV1,
    selector: &NameSelectorV1,
    now_ms: u64,
) -> Option<&'a ReservedNameV1> {
    let literal = selector.normalized_label();
    let label_key = reserved_label_key(namespace, selector);
    policy.reserved_labels.iter().find(|reserved| {
        reserved
            .release_at_ms
            .is_none_or(|release_at_ms| now_ms < release_at_ms)
            && (reserved.normalized_label == literal || reserved.normalized_label == label_key)
    })
}
fn enforce_reserved_label_assignment(
    namespace: SnsNamespace,
    policy: &SuffixPolicyV1,
    selector: &NameSelectorV1,
    owner: &AccountId,
    now_ms: u64,
) -> Result<(), SnsError> {
    let Some(reserved) = find_active_reserved_label(namespace, policy, selector, now_ms) else {
        return Ok(());
    };
    match &reserved.assigned_to {
        Some(assignee) if assignee == owner => Ok(()),
        Some(assignee) => Err(SnsError::Conflict(format!(
            "label `{}` is reserved for `{assignee}`",
            reserved.normalized_label
        ))),
        None => Err(SnsError::Conflict(format!(
            "label `{}` is reserved",
            reserved.normalized_label
        ))),
    }
}
fn is_reserved_universal_selector(selector: &NameSelectorV1) -> bool {
    selector.suffix_id == DATASPACE_ALIAS_SUFFIX_ID
        && selector.normalized_label() == RESERVED_UNIVERSAL_DATASPACE_ALIAS
}
fn ensure_selector_is_mutable(selector: &NameSelectorV1) -> Result<(), SnsError> {
    if is_reserved_universal_selector(selector) {
        return Err(SnsError::Conflict(
            "reserved dataspace alias `universal` is immutable".to_owned(),
        ));
    }
    Ok(())
}
fn canonicalize_resolved_selector(
    selector: NameSelectorV1,
) -> Result<(SnsNamespace, NameSelectorV1), SnsError> {
    if selector.version != NameSelectorV1::VERSION {
        return Err(SnsError::BadRequest(format!(
            "unsupported SNS selector version `{}`",
            selector.version
        )));
    }
    let namespace = SnsNamespace::from_suffix_id(selector.suffix_id)?;
    let canonical = match namespace {
        SnsNamespace::AccountAlias => {
            let alias = selector
                .label
                .parse::<AccountAliasName>()
                .map_err(|err| SnsError::BadRequest(err.to_string()))?;
            NameSelectorV1 {
                version: NameSelectorV1::VERSION,
                suffix_id: ACCOUNT_ALIAS_SUFFIX_ID,
                label: alias.canonical_text(),
            }
        }
        SnsNamespace::Domain => {
            let domain = DomainId::parse_fully_qualified(selector.label.trim())
                .map_err(|err| SnsError::BadRequest(err.reason().to_owned()))?;
            selector_for_domain(&domain).map_err(|err| SnsError::BadRequest(err.to_string()))?
        }
        SnsNamespace::Dataspace => selector_for_dataspace_alias(&selector.label)
            .map_err(|err| SnsError::BadRequest(err.to_string()))?,
    };
    Ok((namespace, canonical))
}
fn record_or_not_found(
    world: &impl WorldReadOnly,
    selector: &NameSelectorV1,
) -> Result<NameRecordV1, SnsError> {
    record_by_selector(world, selector)?.ok_or_else(|| SnsError::RegistrationNotFound {
        suffix_id: selector.suffix_id,
        label: selector.normalized_label().to_owned(),
    })
}
fn policy_or_not_found(
    world: &impl WorldReadOnly,
    suffix_id: SuffixId,
) -> Result<SuffixPolicyV1, SnsError> {
    policy_by_id(world, suffix_id)?
        .ok_or_else(|| SnsError::NotFound(format!("suffix policy {suffix_id} is not registered")))
}
/// Fetch a SNS record by namespace/literal and apply the current lifecycle view.
///
/// # Errors
///
/// Returns [`SnsError`] when the namespace or literal is invalid or the record
/// is missing from authoritative state.
pub fn get_name_record(
    world: &impl WorldReadOnly,
    namespace: SnsNamespace,
    literal: &str,
    now_ms: u64,
) -> Result<NameRecordV1, SnsError> {
    let selector = selector_for_namespace_literal(namespace, literal)?;
    get_name_record_by_selector(world, &selector, now_ms)
}
/// Fetch a SNS record by pre-canonicalized selector and apply the current lifecycle view.
///
/// # Errors
///
/// Returns [`SnsError`] when the record is missing from authoritative state.
pub fn get_name_record_by_selector(
    world: &impl WorldReadOnly,
    selector: &NameSelectorV1,
    now_ms: u64,
) -> Result<NameRecordV1, SnsError> {
    let mut record = record_or_not_found(world, selector)?;
    refresh_lifecycle(&mut record, now_ms);
    Ok(record)
}
/// Build the internal payment record after Core debits the exact quote.
#[must_use]
pub(crate) fn native_payment_for_quote(quote: &LeaseQuote) -> LeasePayment {
    LeasePayment {
        asset_id: quote.payment_asset_id.clone(),
        gross_amount: quote.charge_amount.clone(),
        net_amount: quote.charge_amount.clone(),
    }
}
/// Quote the cost and resulting lifecycle for acquiring an account-alias lease.
///
/// # Errors
///
/// Returns [`SnsError`] when the alias is invalid, already registered, or does
/// not satisfy the active suffix policy.
#[cfg(any(test, feature = "iroha-core-tests"))]
pub fn quote_account_alias_registration(
    world: &impl WorldReadOnly,
    catalog: &impl DataSpaceCatalogRead,
    alias: &AccountAlias,
    owner: &AccountId,
    term_years: u8,
    pricing_class_hint: Option<u8>,
    now_ms: u64,
) -> Result<LeaseQuote, SnsError> {
    quote_account_alias_registration_inner(
        world,
        catalog,
        alias,
        owner,
        term_years,
        pricing_class_hint,
        now_ms,
        None,
    )
}
/// Quote account-alias registration only when policy and configured fee asset agree exactly.
pub fn quote_account_alias_registration_with_configured_fee_asset(
    world: &impl WorldReadOnly,
    catalog: &impl DataSpaceCatalogRead,
    alias: &AccountAlias,
    owner: &AccountId,
    term_years: u8,
    pricing_class_hint: Option<u8>,
    now_ms: u64,
    configured_fee_asset_selector: &str,
) -> Result<LeaseQuote, SnsError> {
    quote_account_alias_registration_inner(
        world,
        catalog,
        alias,
        owner,
        term_years,
        pricing_class_hint,
        now_ms,
        Some(configured_fee_asset_selector),
    )
}
#[allow(clippy::too_many_arguments)]
fn quote_account_alias_registration_inner(
    world: &impl WorldReadOnly,
    catalog: &impl DataSpaceCatalogRead,
    alias: &AccountAlias,
    owner: &AccountId,
    term_years: u8,
    pricing_class_hint: Option<u8>,
    now_ms: u64,
    configured_fee_asset_selector: Option<&str>,
) -> Result<LeaseQuote, SnsError> {
    let selector = selector_for_account_alias(alias, catalog)
        .map_err(|err| SnsError::BadRequest(err.to_string()))?;
    ensure_selector_is_mutable(&selector)?;
    let policy = policy_or_not_found(world, selector.suffix_id)?;
    if let Some(configured) = configured_fee_asset_selector {
        ensure_policy_matches_configured_payment_asset(world, &policy, configured)?;
    }
    enforce_policy_active(&policy)?;
    enforce_reserved_label_assignment(
        SnsNamespace::AccountAlias,
        &policy,
        &selector,
        owner,
        now_ms,
    )?;
    if record_by_selector(world, &selector)?.is_some() {
        return Err(SnsError::Conflict(format!(
            "selector `{}` is already registered",
            selector.normalized_label()
        )));
    }
    let tier = pick_pricing_tier(&policy, &selector, pricing_class_hint)?;
    lease_quote(selector, &policy, &tier, term_years, now_ms)
}
/// Quote the cost and resulting lifecycle for renewing an account-alias lease.
///
/// # Errors
///
/// Returns [`SnsError`] when the alias is missing, immutable, or no longer eligible for renewal.
#[cfg(test)]
pub fn quote_account_alias_renewal(
    world: &impl WorldReadOnly,
    catalog: &impl DataSpaceCatalogRead,
    alias: &AccountAlias,
    term_years: u8,
    now_ms: u64,
) -> Result<LeaseQuote, SnsError> {
    quote_account_alias_renewal_inner(world, catalog, alias, term_years, now_ms, None)
}
/// Quote account-alias renewal only when policy and configured fee asset agree exactly.
pub fn quote_account_alias_renewal_with_configured_fee_asset(
    world: &impl WorldReadOnly,
    catalog: &impl DataSpaceCatalogRead,
    alias: &AccountAlias,
    term_years: u8,
    now_ms: u64,
    configured_fee_asset_selector: &str,
) -> Result<LeaseQuote, SnsError> {
    quote_account_alias_renewal_inner(
        world,
        catalog,
        alias,
        term_years,
        now_ms,
        Some(configured_fee_asset_selector),
    )
}
fn quote_account_alias_renewal_inner(
    world: &impl WorldReadOnly,
    catalog: &impl DataSpaceCatalogRead,
    alias: &AccountAlias,
    term_years: u8,
    now_ms: u64,
    configured_fee_asset_selector: Option<&str>,
) -> Result<LeaseQuote, SnsError> {
    let selector = selector_for_account_alias(alias, catalog)
        .map_err(|err| SnsError::BadRequest(err.to_string()))?;
    ensure_selector_is_mutable(&selector)?;
    let policy = policy_or_not_found(world, selector.suffix_id)?;
    if let Some(configured) = configured_fee_asset_selector {
        ensure_policy_matches_configured_payment_asset(world, &policy, configured)?;
    }
    enforce_policy_active(&policy)?;
    let mut record = record_or_not_found(world, &selector)?;
    refresh_lifecycle(&mut record, now_ms);
    match record.status {
        NameStatus::Tombstoned(_) => {
            return Err(SnsError::Conflict(format!(
                "registration `{}` is tombstoned",
                selector.normalized_label()
            )));
        }
        NameStatus::Frozen(_) => {
            return Err(SnsError::Conflict(format!(
                "registration `{}` is frozen",
                selector.normalized_label()
            )));
        }
        _ => {}
    }
    let tier = tier_by_pricing_class(&policy, &record.selector, record.pricing_class)?;
    lease_quote(selector, &policy, &tier, term_years, record.expires_at_ms)
}
/// Quote registration for a catalog-free, pre-resolved canonical selector.
///
/// Account aliases are parsed from their complete textual form and do not
/// require a static dataspace catalog. Callers
/// must separately validate the textual dataspace against its pinned numeric ID.
///
/// # Errors
///
/// Returns [`SnsError`] when the selector or lease terms are invalid, the
/// suffix policy is unavailable, the label is reserved, or the name exists.
pub fn quote_resolved_name_registration(
    world: &impl WorldReadOnly,
    selector: NameSelectorV1,
    owner: &AccountId,
    term_years: u8,
    pricing_class_hint: Option<u8>,
    now_ms: u64,
) -> Result<LeaseQuote, SnsError> {
    let (namespace, canonical_selector) = canonicalize_resolved_selector(selector)?;
    ensure_selector_is_mutable(&canonical_selector)?;
    let policy = policy_or_not_found(world, canonical_selector.suffix_id)?;
    enforce_policy_active(&policy)?;
    enforce_reserved_label_assignment(namespace, &policy, &canonical_selector, owner, now_ms)?;
    if record_by_selector(world, &canonical_selector)?.is_some() {
        return Err(SnsError::Conflict(format!(
            "selector `{}` is already registered",
            canonical_selector.normalized_label()
        )));
    }
    let tier = pick_pricing_tier(&policy, &canonical_selector, pricing_class_hint)?;
    lease_quote(canonical_selector, &policy, &tier, term_years, now_ms)
}
fn resolved_renewal_term_years(
    current_expiry_ms: u64,
    target_expiry_ms: u64,
) -> Result<u8, SnsError> {
    let extension_ms = target_expiry_ms
        .checked_sub(current_expiry_ms)
        .ok_or_else(|| {
            SnsError::BadRequest(
                "target lease expiry must be later than the current expiry".to_owned(),
            )
        })?;
    if extension_ms == 0 || extension_ms % MS_PER_YEAR != 0 {
        return Err(SnsError::BadRequest(format!(
            "target lease expiry must extend the current expiry by a whole number of {MS_PER_YEAR}ms years"
        )));
    }
    u8::try_from(extension_ms / MS_PER_YEAR)
        .map_err(|_| SnsError::BadRequest("target lease extension exceeds 255 years".to_owned()))
}
fn ensure_record_renewable(record: &NameRecordV1) -> Result<(), SnsError> {
    match &record.status {
        NameStatus::Tombstoned(_) => Err(SnsError::Conflict(format!(
            "registration `{}` is tombstoned",
            record.selector.normalized_label()
        ))),
        NameStatus::Frozen(_) => Err(SnsError::Conflict(format!(
            "registration `{}` is frozen",
            record.selector.normalized_label()
        ))),
        NameStatus::Active | NameStatus::GracePeriod | NameStatus::Redemption => Ok(()),
    }
}
/// Quote a catalog-free lease renewal using expiry compare-and-set and an absolute target.
///
/// # Errors
///
/// Returns [`SnsError`] when the selector or policy is invalid, the current expiry differs, the
/// record is frozen/tombstoned, or the target does not add an allowed whole-year term.
pub fn quote_resolved_name_renewal(
    world: &impl WorldReadOnly,
    selector: NameSelectorV1,
    expected_current_expiry_ms: u64,
    target_expiry_ms: u64,
    now_ms: u64,
) -> Result<LeaseQuote, SnsError> {
    let (_, canonical_selector) = canonicalize_resolved_selector(selector)?;
    ensure_selector_is_mutable(&canonical_selector)?;
    let policy = policy_or_not_found(world, canonical_selector.suffix_id)?;
    enforce_policy_active(&policy)?;
    let mut record = record_or_not_found(world, &canonical_selector)?;
    refresh_lifecycle(&mut record, now_ms);
    ensure_record_renewable(&record)?;
    if record.expires_at_ms != expected_current_expiry_ms {
        return Err(SnsError::Conflict(format!(
            "alias.lease.expiry_conflict: expected current expiry {expected_current_expiry_ms}, actual expiry is {}",
            record.expires_at_ms
        )));
    }
    let term_years = resolved_renewal_term_years(expected_current_expiry_ms, target_expiry_ms)?;
    let tier = tier_by_pricing_class(&policy, &record.selector, record.pricing_class)?;
    let quote = lease_quote(
        canonical_selector,
        &policy,
        &tier,
        term_years,
        expected_current_expiry_ms,
    )?;
    if quote.expires_at_ms != target_expiry_ms {
        return Err(SnsError::Conflict(
            "renewal quote did not reproduce the absolute target expiry".to_owned(),
        ));
    }
    Ok(quote)
}
fn persist_record(state_transaction: &mut StateTransaction<'_, '_>, record: &NameRecordV1) {
    state_transaction
        .world
        .smart_contract_state
        .insert(record_storage_key(&record.selector), record.encode());
}
/// Register a new SNS name in authoritative state.
///
/// # Errors
///
/// Returns [`SnsError`] when the selector is invalid, the policy is missing or
/// inactive, or a record already exists for the same canonical selector.
#[cfg(test)]
fn register_name(
    state_transaction: &mut StateTransaction<'_, '_>,
    request: RegisterNameInput,
) -> Result<NameRecordV1, SnsError> {
    register_resolved_name(state_transaction, request)
}
/// Register a catalog-free, pre-resolved SNS selector in authoritative state.
///
/// The caller must first revalidate the selector's textual dataspace against
/// the numeric ID carried by the resolved setup intent.
pub(crate) fn register_resolved_name(
    state_transaction: &mut StateTransaction<'_, '_>,
    request: RegisterNameInput,
) -> Result<NameRecordV1, SnsError> {
    register_name_with_selector(state_transaction, request)
}
/// Apply a catalog-free absolute-expiry renewal after exact payment was charged.
pub(crate) fn renew_resolved_name(
    state_transaction: &mut StateTransaction<'_, '_>,
    selector: NameSelectorV1,
    expected_current_expiry_ms: u64,
    target_expiry_ms: u64,
    payment: LeasePayment,
) -> Result<NameRecordV1, SnsError> {
    let (_, canonical_selector) = canonicalize_resolved_selector(selector)?;
    ensure_selector_is_mutable(&canonical_selector)?;
    let policy = policy_or_not_found(state_transaction.world(), canonical_selector.suffix_id)?;
    enforce_policy_active(&policy)?;
    let now_ms = state_transaction.block_unix_timestamp_ms();
    let mut record = record_or_not_found(state_transaction.world(), &canonical_selector)?;
    refresh_lifecycle(&mut record, now_ms);
    ensure_record_renewable(&record)?;
    if record.expires_at_ms != expected_current_expiry_ms {
        return Err(SnsError::Conflict(format!(
            "alias.lease.expiry_conflict: expected current expiry {expected_current_expiry_ms}, actual expiry is {}",
            record.expires_at_ms
        )));
    }
    let term_years = resolved_renewal_term_years(expected_current_expiry_ms, target_expiry_ms)?;
    let tier = tier_by_pricing_class(&policy, &record.selector, record.pricing_class)?;
    validate_term_bounds(&policy, &tier, term_years)?;
    validate_payment_for_term(&policy, &tier, term_years, &payment)?;
    record.expires_at_ms = target_expiry_ms;
    record.grace_expires_at_ms =
        target_expiry_ms.saturating_add(u64::from(policy.grace_period_days) * MS_PER_DAY);
    record.redemption_expires_at_ms = record
        .grace_expires_at_ms
        .saturating_add(u64::from(policy.redemption_period_days) * MS_PER_DAY);
    refresh_lifecycle(&mut record, now_ms);
    persist_record(state_transaction, &record);
    Ok(record)
}
fn register_name_with_selector(
    state_transaction: &mut StateTransaction<'_, '_>,
    request: RegisterNameInput,
) -> Result<NameRecordV1, SnsError> {
    let RegisterNameInput {
        selector,
        owner,
        controllers,
        term_years,
        pricing_class_hint,
        payment,
        metadata,
    } = request;
    let (namespace, canonical_selector) = canonicalize_resolved_selector(selector)?;
    ensure_selector_is_mutable(&canonical_selector)?;
    let policy = policy_or_not_found(state_transaction.world(), canonical_selector.suffix_id)?;
    enforce_policy_active(&policy)?;
    let now_ms = state_transaction.block_unix_timestamp_ms();
    enforce_reserved_label_assignment(namespace, &policy, &canonical_selector, &owner, now_ms)?;
    let key = record_storage_key(&canonical_selector);
    if state_transaction
        .world
        .smart_contract_state
        .get(&key)
        .is_some()
    {
        return Err(SnsError::Conflict(format!(
            "selector `{}` is already registered",
            canonical_selector.normalized_label()
        )));
    }
    let tier = pick_pricing_tier(&policy, &canonical_selector, pricing_class_hint)?;
    let record = registration_record(
        canonical_selector,
        owner,
        controllers,
        term_years,
        &payment,
        metadata,
        &policy,
        &tier,
        now_ms,
    )?;
    persist_record(state_transaction, &record);
    Ok(record)
}
/// Set the absolute lease expiry for an existing SNS name in authoritative state.
///
/// # Errors
///
/// Returns [`SnsError`] when the record or policy is missing, the selector is immutable, the
/// record is tombstoned, or the requested expiry is not in the future.
#[cfg(test)]
fn set_name_lease_expiry(
    state_transaction: &mut StateTransaction<'_, '_>,
    namespace: SnsNamespace,
    literal: &str,
    expires_at_ms: u64,
) -> Result<NameRecordV1, SnsError> {
    let selector = selector_for_namespace_literal(namespace, literal)?;
    ensure_selector_is_mutable(&selector)?;
    let policy = policy_or_not_found(state_transaction.world(), selector.suffix_id)?;
    enforce_policy_active(&policy)?;
    let mut record = record_or_not_found(state_transaction.world(), &selector)?;
    let now_ms = state_transaction.block_unix_timestamp_ms();
    refresh_lifecycle(&mut record, now_ms);
    if matches!(record.status, NameStatus::Tombstoned(_)) {
        return Err(SnsError::Conflict(format!(
            "registration `{}` is tombstoned",
            selector.normalized_label()
        )));
    }
    if expires_at_ms <= now_ms {
        return Err(SnsError::BadRequest(
            "lease_expiry_ms must be greater than the current block timestamp".to_owned(),
        ));
    }
    record.expires_at_ms = expires_at_ms;
    record.grace_expires_at_ms =
        expires_at_ms.saturating_add(u64::from(policy.grace_period_days) * MS_PER_DAY);
    record.redemption_expires_at_ms = record
        .grace_expires_at_ms
        .saturating_add(u64::from(policy.redemption_period_days) * MS_PER_DAY);
    refresh_lifecycle(&mut record, now_ms);
    persist_record(state_transaction, &record);
    Ok(record)
}
/// Apply a ledger-backed SNS mutation in a dedicated state block for unit tests.
///
/// # Errors
///
/// Returns [`SnsError`] when the mutation fails or the state block cannot be committed.
#[cfg(test)]
pub fn apply_with_state_block<T>(
    state: &State,
    mutation: impl FnOnce(&mut StateTransaction<'_, '_>) -> Result<T, SnsError>,
) -> Result<T, SnsError> {
    let latest_block = state.view().latest_block().map_err(|error| match error {
        crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => {
            SnsError::Deferred(reason)
        }
        crate::execution_attempt::ExecutionAttemptError::Rejected(error) => {
            SnsError::Internal(error.to_string())
        }
    })?;
    let next_height = latest_block
        .as_ref()
        .map(|block| block.header().height().get().saturating_add(1))
        .unwrap_or(1);
    let prev_hash = latest_block.as_ref().map(|block| block.as_ref().hash());
    let ledger_time_ms = latest_block
        .as_ref()
        .map(|block| u64::try_from(block.header().creation_time().as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0);
    let wall_clock_ms = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .unwrap_or(ledger_time_ms);
    let header = BlockHeader::new(
        next_height
            .try_into()
            .expect("block height must always fit into NonZeroU64"),
        prev_hash,
        None,
        wall_clock_ms.max(ledger_time_ms),
        0,
    );
    let mut block = state.block(header);
    let mut transaction = block.transaction();
    let out = mutation(&mut transaction)?;
    transaction.apply();
    block
        .commit_world_overlay_for_testing()
        .map_err(|err| SnsError::Internal(format!("failed to commit SNS state block: {err}")))?;
    Ok(out)
}
/// Compute the effective lifecycle for `record` using deterministic ledger time.
#[must_use]
pub fn effective_status(record: &NameRecordV1, now_ms: u64) -> NameStatus {
    if matches!(record.status, NameStatus::Tombstoned(_)) {
        return record.status.clone();
    }
    if let NameStatus::Frozen(frozen) = &record.status
        && now_ms < frozen.until_ms
    {
        return record.status.clone();
    }
    if now_ms >= record.redemption_expires_at_ms {
        NameStatus::Tombstoned(NameTombstoneStateV1 {
            reason: EXPIRED_TOMBSTONE_REASON.to_owned(),
        })
    } else if now_ms >= record.grace_expires_at_ms {
        NameStatus::Redemption
    } else if now_ms >= record.expires_at_ms {
        NameStatus::GracePeriod
    } else {
        NameStatus::Active
    }
}
/// Return the active owner for a SNS selector when the record lifecycle is `Active`.
///
/// # Errors
///
/// Returns [`SnsError`] when authoritative record state is malformed.
pub fn active_owner_by_selector(
    world: &impl WorldReadOnly,
    selector: &NameSelectorV1,
    now_ms: u64,
) -> Result<Option<AccountId>, SnsError> {
    let Some(record) = record_by_selector(world, selector)? else {
        return Ok(None);
    };
    Ok(matches!(effective_status(&record, now_ms), NameStatus::Active).then_some(record.owner))
}
/// Return the active owner for a full account-alias lease record.
///
/// # Errors
///
/// Returns [`SnsError`] when dataspace resolution fails or authoritative
/// record state is malformed.
pub fn active_account_alias_owner(
    world: &impl WorldReadOnly,
    catalog: &impl DataSpaceCatalogRead,
    alias: &AccountAlias,
    now_ms: u64,
) -> Result<Option<AccountId>, SnsError> {
    let selector = match active_account_alias_selector(world, catalog, alias, now_ms) {
        Ok(selector) => selector,
        Err(SnsError::NotFound(_)) => return Ok(None),
        Err(error) => return Err(error),
    };
    active_owner_by_selector(world, &selector, now_ms)
}
/// Resolve an account alias only when its authoritative lease and both canonical binding indexes
/// agree on an existing account at deterministic ledger time.
///
/// Missing, expired, frozen, grace-period, redemption, tombstoned, or split-brain state resolves
/// to `Ok(None)`. Malformed encoded state is never projected to absence.
///
/// # Errors
///
/// Returns [`SnsError`] when authoritative SNS state is malformed or conflicting.
pub fn resolve_active_account_alias(
    world: &impl WorldReadOnly,
    catalog: &impl DataSpaceCatalogRead,
    alias: &AccountAlias,
    now_ms: u64,
) -> Result<Option<AccountId>, SnsError> {
    let Some(lease_owner) = active_account_alias_owner(world, catalog, alias, now_ms)? else {
        return Ok(None);
    };
    let Some(indexed_owner) = world.account_aliases().get(alias) else {
        return Ok(None);
    };
    let Some(rekey_record) = world.account_rekey_records().get(alias) else {
        return Ok(None);
    };
    let rekey_owner = &rekey_record.active_account_id;
    if indexed_owner != rekey_owner || indexed_owner != &lease_owner {
        return Ok(None);
    }
    if world.account(indexed_owner).is_err() {
        return Ok(None);
    }
    // The canonical lease already owns exactly this checked controller graph.
    // Returning it preserves all three-way binding checks without a second copy.
    Ok(Some(lease_owner))
}
fn active_account_id_rekey_suffix_for_alias<'world>(
    world: &'world impl WorldReadOnly,
    catalog: &impl DataSpaceCatalogRead,
    alias: &AccountAlias,
    now_ms: u64,
    work: &mut AccountRekeyLineageWork,
) -> Result<Option<(AccountId, &'world [AccountId])>, SnsError> {
    work.charge(1)?;
    let Some(active_account_id) = resolve_active_account_alias(world, catalog, alias, now_ms)?
    else {
        return Ok(None);
    };
    let record = world.account_rekey_records().get(alias).ok_or_else(|| {
        SnsError::Internal("active alias is missing its account rekey record".to_owned())
    })?;
    if &record.label != alias || record.active_account_id != active_account_id {
        return Err(SnsError::Conflict(
            "active alias account rekey record does not match its canonical binding".to_owned(),
        ));
    }
    work.charge(record.previous_account_ids.len())?;
    let predecessors = record
        .active_account_id_rekey_predecessors()
        .map_err(|error| SnsError::Conflict(error.to_string()))?;
    let mut seen_predecessors = BTreeSet::new();
    for predecessor in predecessors {
        if predecessor == &active_account_id
            || !seen_predecessors.insert(predecessor)
            || world.account(predecessor).is_ok()
        {
            return Err(SnsError::Conflict(
                "account rekey lineage contains an active, duplicate, or cyclic predecessor"
                    .to_owned(),
            ));
        }
    }
    Ok(Some((active_account_id, predecessors)))
}
/// Resolve an account id through one exact alias's active, explicitly proven account-id rekey
/// suffix.
///
/// Legacy history and ordinary alias reassignment are permanently non-authorizing. The alias
/// lease, forward index, continuity record, and active account must agree at `now_ms`; every
/// predecessor in the active suffix must be unique and retired.
///
/// # Errors
///
/// Returns [`SnsError`] when the live lease or rekey state is malformed.
pub fn resolve_active_account_id_rekey_lineage_for_alias(
    world: &impl WorldReadOnly,
    catalog: &impl DataSpaceCatalogRead,
    alias: &AccountAlias,
    account_id: &AccountId,
    now_ms: u64,
) -> Result<Option<AccountId>, SnsError> {
    let mut work = AccountRekeyLineageWork::default();
    let Some((active_account_id, predecessors)) =
        active_account_id_rekey_suffix_for_alias(world, catalog, alias, now_ms, &mut work)?
    else {
        return Ok(None);
    };
    Ok(
        (account_id == &active_account_id || predecessors.contains(account_id))
            .then_some(active_account_id),
    )
}
/// Resolve an account id to its unique active account-id rekey target across connected aliases.
///
/// A currently registered account resolves to itself. Any malformed live suffix, reused retired
/// predecessor, cycle, or conflicting active target fails closed.
///
/// # Errors
///
/// Returns [`SnsError`] when a connected live lease or rekey record is malformed, exceeds the
/// deterministic request work limit, or maps the requested account to conflicting active targets.
pub fn resolve_active_account_id_rekey_lineage(
    world: &impl WorldReadOnly,
    catalog: &impl DataSpaceCatalogRead,
    account_id: &AccountId,
    now_ms: u64,
) -> Result<Option<AccountId>, SnsError> {
    let mut resolved = world.account(account_id).ok().map(|_| account_id.clone());
    let mut work = AccountRekeyLineageWork::default();
    let Some(aliases) = world.account_rekey_records_by_account().get(account_id) else {
        return Ok(resolved);
    };
    for alias in aliases {
        let Some((active_account_id, predecessors)) =
            active_account_id_rekey_suffix_for_alias(world, catalog, alias, now_ms, &mut work)?
        else {
            continue;
        };
        if account_id != &active_account_id && !predecessors.contains(account_id) {
            continue;
        }
        if resolved
            .as_ref()
            .is_some_and(|existing| existing != &active_account_id)
        {
            return Err(SnsError::Conflict(
                "account rekey lineage maps one account to conflicting active targets".to_owned(),
            ));
        }
        resolved = Some(active_account_id);
    }
    Ok(resolved)
}
/// Return the active owner for a domain-name lease record.
///
/// # Errors
///
/// Returns [`SnsError`] when the selector or authoritative record state is malformed.
pub fn active_domain_owner(
    world: &impl WorldReadOnly,
    domain: &DomainId,
    now_ms: u64,
) -> Result<Option<AccountId>, SnsError> {
    let selector =
        selector_for_domain(domain).map_err(|error| SnsError::BadRequest(error.to_string()))?;
    active_owner_by_selector(world, &selector, now_ms)
}
/// Return the active owner for a canonical dataspace alias.
///
/// # Errors
///
/// Returns [`SnsError`] when the alias or authoritative record state is malformed.
pub fn active_dataspace_owner_by_alias(
    world: &impl WorldReadOnly,
    alias: &str,
    now_ms: u64,
) -> Result<Option<AccountId>, SnsError> {
    Ok(
        active_dataspace_owner_and_generation_by_alias(world, alias, now_ms)?
            .map(|(owner, _)| owner),
    )
}
/// Return the active owner and monotonic ownership generation for a dataspace alias.
///
/// A malformed zero generation fails closed so a signed namespace delegation can never bind to
/// an inert or legacy-reset ownership epoch.
///
/// # Errors
///
/// Returns [`SnsError`] when the alias or authoritative record state is malformed.
pub fn active_dataspace_owner_and_generation_by_alias(
    world: &impl WorldReadOnly,
    alias: &str,
    now_ms: u64,
) -> Result<Option<(AccountId, u64)>, SnsError> {
    let selector = selector_for_dataspace_alias(alias)
        .map_err(|error| SnsError::BadRequest(error.to_string()))?;
    let Some(record) = record_by_selector(world, &selector)? else {
        return Ok(None);
    };
    Ok(
        (matches!(effective_status(&record, now_ms), NameStatus::Active)
            && record.ownership_generation != 0)
            .then_some((record.owner, record.ownership_generation)),
    )
}
fn active_dataspace_record_id(record: &NameRecordV1) -> Result<DataSpaceId, SnsError> {
    if let Some(encoded_id) = record.metadata.get(SNS_DATASPACE_ID_METADATA_KEY) {
        let raw = norito::json::from_str::<u64>(encoded_id.get()).map_err(|err| {
            SnsError::Conflict(format!(
                "{ALIAS_CATALOG_MAPPING_CONFLICT_CODE}: dataspace alias `{}` stores an invalid numeric id: {err}",
                record.selector.normalized_label()
            ))
        })?;
        return Ok(DataSpaceId::new(raw));
    }
    dataspace_id_for_sns_alias(record.selector.normalized_label()).ok_or_else(|| {
        SnsError::Internal(format!(
            "failed to derive dataspace id for canonical alias `{}`",
            record.selector.normalized_label()
        ))
    })
}
struct ActiveDataspaceResolution {
    alias: String,
}
fn resolve_active_dataspace_by_id(
    world: &impl WorldReadOnly,
    catalog: &impl DataSpaceCatalogRead,
    dataspace_id: DataSpaceId,
    now_ms: u64,
) -> Result<ActiveDataspaceResolution, SnsError> {
    let prefix = StatePath::from_str(&format!("sns/records/{DATASPACE_ALIAS_SUFFIX_ID}/"))
        .expect("static dataspace SNS record prefix is valid");
    let prefix_literal = prefix.as_ref().to_owned();
    let mut resolution = catalog
        .by_id(dataspace_id)
        .map(|entry| {
            if entry.alias.len() > iroha_model_base::name::MAX_NAME_BYTES {
                return Err(SnsError::Conflict(format!(
                    "{ALIAS_CATALOG_MAPPING_CONFLICT_CODE}: configured dataspace alias exceeds the canonical name limit"
                )));
            }
            Ok(ActiveDataspaceResolution {
                alias: entry.alias.clone(),
            })
        })
        .transpose()?;
    for (storage_key, bytes) in world.smart_contract_state().range(prefix..) {
        if !storage_key.as_ref().starts_with(&prefix_literal) {
            break;
        }
        let decode_candidate = || {
            let record: NameRecordV1 = norito::codec::decode_adaptive(bytes).map_err(|error| {
                sns_decode_error(error, "failed to decode a dataspace SNS record")
            })?;
            if record.selector.label.len() > iroha_model_base::name::MAX_NAME_BYTES {
                return Err(SnsError::Internal(
                    "dataspace SNS record label exceeds the canonical name limit".to_owned(),
                ));
            }
            if record.selector.suffix_id != DATASPACE_ALIAS_SUFFIX_ID
                || record.name_hash != record.selector.name_hash()
                || record_storage_key(&record.selector).as_ref() != storage_key.as_ref()
            {
                return Err(SnsError::Internal(
                    "dataspace SNS record identity mismatch".to_owned(),
                ));
            }
            if !matches!(effective_status(&record, now_ms), NameStatus::Active) {
                return Ok(None);
            }
            let dynamic_id = active_dataspace_record_id(&record)?;
            let alias = record.selector.normalized_label();
            if let Some(static_entry) = catalog.by_alias(alias)
                && static_entry.id != dynamic_id
                && (static_entry.id == dataspace_id || dynamic_id == dataspace_id)
            {
                return Err(SnsError::Conflict(format!(
                    "{ALIAS_CATALOG_MAPPING_CONFLICT_CODE}: active SNS and configured dataspace mappings disagree"
                )));
            }
            if dynamic_id != dataspace_id {
                return Ok(None);
            }
            Ok(Some(record.selector.label))
        };
        let candidate = if crate::smartcontracts::isi::query::singular_query_limits_active() {
            let elements = bytes.len().checked_mul(8).ok_or_else(|| {
                SnsError::Internal("dataspace SNS record exceeds query memory limits".to_owned())
            })?;
            let limits = crate::smartcontracts::isi::query::singular_query_decode_limits(
                bytes.len(),
                norito::DecodeLimits::new(elements, bytes.len(), elements, usize::MAX, 64),
            )
            .map_err(|_| {
                SnsError::Internal("dataspace SNS record exceeds query memory limits".to_owned())
            })?;
            norito::with_decode_limits_scope(limits, decode_candidate)
        } else {
            decode_candidate()
        }?;
        if let Some(alias) = candidate {
            match &mut resolution {
                None => {
                    resolution = Some(ActiveDataspaceResolution { alias });
                }
                Some(existing) if existing.alias == alias => {}
                Some(_) => {
                    return Err(SnsError::Conflict(format!(
                        "{ALIAS_CATALOG_MAPPING_CONFLICT_CODE}: dataspace id maps to multiple active aliases"
                    )));
                }
            }
        }
    }
    resolution.ok_or_else(|| SnsError::NotFound(format!("unknown dataspace id `{dataspace_id}`")))
}
/// Resolve a dataspace alias against both the static catalog and active SNS state.
///
/// Static and dynamic mappings are independent evidence for the same canonical
/// text-to-id pair. If both are present they must agree exactly; a caller must
/// never silently prefer one directory over the other.
///
/// # Errors
///
/// Returns [`SnsError::NotFound`] when neither directory knows the alias, [`SnsError::BadRequest`]
/// when the alias is not canonical, and [`SnsError::Conflict`] with
/// [`ALIAS_CATALOG_MAPPING_CONFLICT_CODE`] when the two directories disagree. Malformed
/// authoritative SNS state returns [`SnsError::Internal`].
pub fn resolve_active_dataspace_id_by_alias(
    world: &impl WorldReadOnly,
    catalog: &impl DataSpaceCatalogRead,
    alias: &str,
    now_ms: u64,
) -> Result<DataSpaceId, SnsError> {
    let alias = alias.trim();
    let selector =
        selector_for_dataspace_alias(alias).map_err(|err| SnsError::BadRequest(err.to_string()))?;
    let static_id = catalog
        .by_alias(selector.normalized_label())
        .map(|entry| entry.id);
    let dynamic_id = record_by_selector(world, &selector)?
        .filter(|record| matches!(effective_status(record, now_ms), NameStatus::Active))
        .map(|record| active_dataspace_record_id(&record))
        .transpose()?;
    let resolved_id = match (static_id, dynamic_id) {
        (Some(static_id), Some(dynamic_id)) if static_id != dynamic_id => {
            return Err(SnsError::Conflict(format!(
                "{ALIAS_CATALOG_MAPPING_CONFLICT_CODE}: dataspace alias `{}` maps to static id {static_id} and active SNS id {dynamic_id}",
                selector.normalized_label()
            )));
        }
        (Some(id), _) | (None, Some(id)) => id,
        (None, None) => {
            return Err(SnsError::NotFound(format!(
                "unknown dataspace alias `{}`",
                selector.normalized_label()
            )));
        }
    };
    let reverse_alias = resolve_active_dataspace_alias_by_id(world, catalog, resolved_id, now_ms)?;
    if reverse_alias != selector.normalized_label() {
        return Err(SnsError::Conflict(format!(
            "{ALIAS_CATALOG_MAPPING_CONFLICT_CODE}: dataspace alias `{}` maps to id {resolved_id}, whose canonical active name is `{reverse_alias}`",
            selector.normalized_label()
        )));
    }
    Ok(resolved_id)
}
/// Resolve a dataspace id to its unique canonical alias across the static catalog and active SNS.
///
/// Static and dynamic mappings must describe one exact text/id pair. Multiple active names for
/// the same numeric id, or a disagreement between the directories, fail closed instead of
/// selecting an arbitrary spelling.
///
/// # Errors
///
/// Returns [`SnsError::NotFound`] when neither directory knows the id,
/// [`SnsError::Conflict`] with [`ALIAS_CATALOG_MAPPING_CONFLICT_CODE`] when the id has multiple
/// canonical names or a static/dynamic mapping disagrees, and [`SnsError::Internal`] for malformed
/// authoritative SNS state.
pub fn resolve_active_dataspace_alias_by_id(
    world: &impl WorldReadOnly,
    catalog: &impl DataSpaceCatalogRead,
    dataspace_id: DataSpaceId,
    now_ms: u64,
) -> Result<String, SnsError> {
    resolve_active_dataspace_by_id(world, catalog, dataspace_id, now_ms)
        .map(|resolution| resolution.alias)
}
/// Render an account alias with the unique active dataspace name for its numeric id.
///
/// # Errors
///
/// Returns [`SnsError`] when the dataspace mapping is unknown, conflicting, or the resulting
/// account-alias literal is invalid.
pub fn active_account_alias_literal(
    world: &impl WorldReadOnly,
    catalog: &impl DataSpaceCatalogRead,
    alias: &AccountAlias,
    now_ms: u64,
) -> Result<String, SnsError> {
    let dataspace = resolve_active_dataspace_alias_by_id(world, catalog, alias.dataspace, now_ms)?;
    AccountAliasName::try_new(
        alias.label.as_ref(),
        alias.domain.as_ref().map(|domain| domain.name().as_ref()),
        dataspace,
    )
    .map(|name| name.to_string())
    .map_err(|error| SnsError::BadRequest(error.to_string()))
}
/// Build the authoritative selector for an account alias using live/static dataspace resolution.
///
/// # Errors
///
/// Returns [`SnsError`] when the dataspace mapping or account-alias literal is invalid.
pub fn active_account_alias_selector(
    world: &impl WorldReadOnly,
    catalog: &impl DataSpaceCatalogRead,
    alias: &AccountAlias,
    now_ms: u64,
) -> Result<NameSelectorV1, SnsError> {
    let literal = active_account_alias_literal(world, catalog, alias, now_ms)?;
    Ok(NameSelectorV1 {
        version: NameSelectorV1::VERSION,
        suffix_id: ACCOUNT_ALIAS_SUFFIX_ID,
        label: literal,
    })
}
/// Resolve an active dataspace alias to its canonical id.
///
/// Unknown mappings project to absence; conflicts and local refusals retain their category.
///
/// # Errors
/// Returns the original SNS error for conflicting, malformed, or locally deferred state.
pub fn active_dataspace_id_by_alias(
    world: &impl WorldReadOnly,
    catalog: &impl DataSpaceCatalogRead,
    alias: &str,
    now_ms: u64,
) -> Result<Option<DataSpaceId>, SnsError> {
    match resolve_active_dataspace_id_by_alias(world, catalog, alias, now_ms) {
        Ok(id) => Ok(Some(id)),
        Err(SnsError::NotFound(_)) => Ok(None),
        Err(error) => Err(error),
    }
}
#[cfg(test)]
/// Resolve active dataspace metadata from the bootstrap catalog or SNS.
///
/// # Errors
///
/// Returns [`SnsError`] when authoritative SNS state is malformed or conflicts
/// with the static catalog.
pub fn active_dataspace_metadata_by_alias(
    world: &impl WorldReadOnly,
    catalog: &impl DataSpaceCatalogRead,
    alias: &str,
    now_ms: u64,
) -> Result<Option<DataSpaceMetadata>, SnsError> {
    let alias = alias.trim();
    let resolved_id = match resolve_active_dataspace_id_by_alias(world, catalog, alias, now_ms) {
        Ok(resolved_id) => resolved_id,
        Err(SnsError::NotFound(_)) => return Ok(None),
        Err(error) => return Err(error),
    };
    if let Some(entry) = catalog.by_alias(alias) {
        return Ok(Some(entry.clone()));
    }
    let selector = selector_for_dataspace_alias(alias)
        .map_err(|error| SnsError::BadRequest(error.to_string()))?;
    if active_owner_by_selector(world, &selector, now_ms)?.is_none() {
        return Ok(None);
    }
    Ok(Some(DataSpaceMetadata {
        id: resolved_id,
        alias: selector.label,
        description: Some("ledger-backed SNS dataspace".to_owned()),
        fault_tolerance: SNS_DYNAMIC_DATASPACE_FAULT_TOLERANCE,
    }))
}
/// Resolve the active owner for the dataspace id using the current catalog alias.
///
/// # Errors
///
/// Returns [`SnsError`] when authoritative SNS state is malformed or conflicts
/// with the static catalog.
pub fn active_dataspace_owner_by_id(
    world: &impl WorldReadOnly,
    catalog: &impl DataSpaceCatalogRead,
    dataspace_id: DataSpaceId,
    now_ms: u64,
) -> Result<Option<AccountId>, SnsError> {
    let resolution = match resolve_active_dataspace_by_id(world, catalog, dataspace_id, now_ms) {
        Ok(resolution) => resolution,
        Err(SnsError::NotFound(_)) => return Ok(None),
        Err(error) => return Err(error),
    };
    active_dataspace_owner_by_alias(world, &resolution.alias, now_ms)
}
#[cfg(test)]
mod genesis_bootstrap_tests;
#[cfg(test)]
mod native_maintenance_tests;
#[cfg(test)]
mod tests;

fn sns_genesis_read_error(
    error: iroha_data_model::sumeragi_finality::GenesisReadError,
) -> SnsError {
    match crate::execution_attempt::genesis_read_attempt_error(error, |error| {
        SnsError::BadRequest(format!("invalid SNS bootstrap genesis: {error}"))
    }) {
        crate::execution_attempt::ExecutionAttemptError::Rejected(error) => error,
        crate::execution_attempt::ExecutionAttemptError::Deferred(reason) => {
            SnsError::Deferred(reason)
        }
    }
}
