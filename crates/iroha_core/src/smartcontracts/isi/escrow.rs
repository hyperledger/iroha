//! Native asset escrow instruction handlers.
use super::{Error, Execute, asset::isi::assert_numeric_spec_with};
use crate::smartcontracts::isi::helpers::ensure_custody_account;
use crate::smartcontracts::isi::query::json_predicate::intersect_candidate_ids;
use crate::{
    prelude::ValidSingularQuery,
    smartcontracts::ValidQuery,
    state::{StateReadOnly, StateTransaction, WorldReadOnly},
};
use eyre::Result;
use iroha_crypto::derive_non_signing_ed25519_public_key;
#[cfg(test)]
use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
#[cfg(test)]
use iroha_data_model::account::Account;
#[cfg(test)]
use iroha_data_model::fastpq::TransferDeltaTranscript;
use iroha_data_model::{
    account::AccountId,
    asset::{AssetDefinitionId, AssetId},
    escrow::{
        AssetEscrowKind, AssetEscrowRecord, AssetEscrowResolution, AssetEscrowStatus,
        ConditionalEscrowAttestation, ConditionalEscrowCondition, ConditionalEscrowConditionState,
        ConditionalEscrowPredicate, ConditionalEscrowValue, EscrowId,
    },
    events::data::escrow::{
        AssetEscrowDisputed, AssetEscrowResolved, ConditionalEscrowAttested, EscrowEvent,
    },
    isi::escrow::{
        AcceptAssetEscrow, AttestEscrowCondition, CancelAssetEscrow, CancelAssetLock,
        DrawdownAssetLock, ExpireAssetLock, ExpireConditionalEscrow, MarkEscrowPaymentSent,
        OpenAssetEscrow, OpenAssetLock, OpenConditionalEscrow, OpenEscrowDispute,
        ReleaseAssetEscrow, ResolveEscrowDispute,
    },
    permission::Permission,
    query::{
        dsl::{CompoundPredicate, EvaluatePredicate},
        error::{FindError, QueryExecutionFail},
        escrow::prelude::{
            FindAssetEscrowById, FindAssetEscrows, FindAssetEscrowsByBuyer,
            FindAssetEscrowsBySeller, FindAssetEscrowsByStatus,
        },
        json::PredicateJson,
    },
    sorafs::orderbook::{
        is_orderbook_order_escrow_id_v1, is_orderbook_settlement_escrow_id_v1,
        is_reserved_orderbook_escrow_id_v1,
    },
};
use iroha_model_base::state_path::StatePath;
use iroha_primitives::numeric::Quantity;
use mv::storage::StorageReadOnly;
use norito::json::Value;
use std::collections::{BTreeMap, BTreeSet};
/// Exact native-escrow purpose carried by a one-shot balance movement capability.
pub(in crate::smartcontracts::isi) enum VerifiedNativeEscrowPurpose {
    Funding {
        escrow_id: EscrowId,
        authority: AccountId,
    },
    Retained {
        escrow_id: EscrowId,
    },
    CustodyPartition {
        parent_id: EscrowId,
        child_id: EscrowId,
    },
}
/// Non-reusable proof that native escrow admission selected one exact movement.
pub(in crate::smartcontracts::isi) struct VerifiedNativeEscrowMovement {
    purpose: VerifiedNativeEscrowPurpose,
    source_id: AssetId,
    destination_id: AssetId,
    amount: Quantity,
}
/// Non-reusable proof for an exact multi-recipient orderbook custody settlement.
pub(in crate::smartcontracts::isi) struct VerifiedNativeEscrowBatch {
    escrow_id: EscrowId,
    authority: AccountId,
    legs: Vec<(AssetId, AssetId, Quantity)>,
}
impl VerifiedNativeEscrowBatch {
    fn orderbook_settlement(
        escrow_id: EscrowId,
        authority: AccountId,
        legs: Vec<(AssetId, AssetId, Quantity)>,
    ) -> Self {
        Self {
            escrow_id,
            authority,
            legs,
        }
    }
    pub(in crate::smartcontracts::isi) fn into_parts(
        self,
    ) -> (EscrowId, AccountId, Vec<(AssetId, AssetId, Quantity)>) {
        (self.escrow_id, self.authority, self.legs)
    }
}
impl VerifiedNativeEscrowMovement {
    fn funding(
        escrow_id: EscrowId,
        authority: AccountId,
        source_id: AssetId,
        destination_id: AssetId,
        amount: Quantity,
    ) -> Self {
        Self {
            purpose: VerifiedNativeEscrowPurpose::Funding {
                escrow_id,
                authority,
            },
            source_id,
            destination_id,
            amount,
        }
    }
    fn retained(
        escrow_id: EscrowId,
        source_id: AssetId,
        destination_id: AssetId,
        amount: Quantity,
    ) -> Self {
        Self {
            purpose: VerifiedNativeEscrowPurpose::Retained { escrow_id },
            source_id,
            destination_id,
            amount,
        }
    }
    fn custody_partition(
        parent_id: EscrowId,
        child_id: EscrowId,
        source_id: AssetId,
        destination_id: AssetId,
        amount: Quantity,
    ) -> Self {
        Self {
            purpose: VerifiedNativeEscrowPurpose::CustodyPartition {
                parent_id,
                child_id,
            },
            source_id,
            destination_id,
            amount,
        }
    }
    pub(in crate::smartcontracts::isi) fn into_parts(
        self,
    ) -> (VerifiedNativeEscrowPurpose, AssetId, AssetId, Quantity) {
        (
            self.purpose,
            self.source_id,
            self.destination_id,
            self.amount,
        )
    }
}
/// Permission name required to resolve disputed native escrows.
pub const CAN_RESOLVE_ESCROW_DISPUTE: &str = "CanResolveEscrowDispute";
const ESCROW_CUSTODY_ACCOUNT_DOMAIN: &str = "iroha-native-asset-escrow-v1";
const ORDERBOOK_ORDER_LOCK_MARKER_KEY_PREFIX: &str = "sorafs_orderbook_order_lock_marker_v1_";
const ORDERBOOK_ORDER_LOCK_MARKER_VALUE: &[u8] = b"v1";
const ORDERBOOK_CHANNEL_LOCK_MARKER_KEY_PREFIX: &str = "sorafs_orderbook_channel_lock_marker_v1_";
const ORDERBOOK_CHANNEL_LOCK_MARKER_VALUE: &[u8] = b"v1";
fn validation_err(message: impl Into<String>) -> Error {
    iroha_data_model::isi::error::InstructionExecutionError::InvariantViolation(
        message.into().into(),
    )
}
fn reject_reserved_orderbook_escrow_id(escrow_id: &EscrowId) -> Result<(), Error> {
    if is_reserved_orderbook_escrow_id_v1(escrow_id) {
        return Err(validation_err(
            "reserved SoraFS orderbook escrow ids require native orderbook execution",
        ));
    }
    Ok(())
}
fn ensure_positive(value: &Quantity) -> Result<(), Error> {
    if value.is_zero() {
        return Err(validation_err("escrow amount must be non-zero"));
    }
    Ok(())
}
fn ensure_resolution_split(
    total_amount: &Quantity,
    buyer_amount: &Quantity,
    seller_amount: &Quantity,
) -> Result<(), Error> {
    let split_total = buyer_amount
        .checked_add(seller_amount)
        .map_err(|_| validation_err("escrow resolution amount overflow"))?;
    if split_total != *total_amount {
        return Err(validation_err("court split must equal escrow amount"));
    }
    Ok(())
}
fn ensure_asset_lock(record: &AssetEscrowRecord) -> Result<(), Error> {
    if record.kind != AssetEscrowKind::Lock {
        return Err(validation_err("escrow is not a generic asset lock"));
    }
    Ok(())
}
fn ensure_conditional_escrow(record: &AssetEscrowRecord) -> Result<(), Error> {
    if record.kind != AssetEscrowKind::Conditional || record.conditions.is_empty() {
        return Err(validation_err("escrow is not a native conditional escrow"));
    }
    Ok(())
}
fn orderbook_channel_lock_marker_key(escrow_id: &EscrowId) -> StatePath {
    format!(
        "{ORDERBOOK_CHANNEL_LOCK_MARKER_KEY_PREFIX}{}",
        hex::encode(escrow_id.as_hash().as_ref())
    )
    .parse()
    .expect("static orderbook marker prefix plus lowercase hex is a valid state key")
}
fn orderbook_order_lock_marker_key(escrow_id: &EscrowId) -> StatePath {
    format!(
        "{ORDERBOOK_ORDER_LOCK_MARKER_KEY_PREFIX}{}",
        hex::encode(escrow_id.as_hash().as_ref())
    )
    .parse()
    .expect("static orderbook marker prefix plus lowercase hex is a valid state key")
}
pub(super) fn is_orderbook_order_lock(
    world: &impl WorldReadOnly,
    escrow_id: &EscrowId,
) -> Result<bool, Error> {
    let Some(marker) = world
        .smart_contract_state()
        .get(&orderbook_order_lock_marker_key(escrow_id))
    else {
        return Ok(false);
    };
    if marker != ORDERBOOK_ORDER_LOCK_MARKER_VALUE {
        return Err(validation_err(
            "orderbook order asset-lock marker is corrupt",
        ));
    }
    Ok(true)
}
pub(super) fn is_orderbook_channel_lock(
    world: &impl WorldReadOnly,
    escrow_id: &EscrowId,
) -> Result<bool, Error> {
    let Some(marker) = world
        .smart_contract_state()
        .get(&orderbook_channel_lock_marker_key(escrow_id))
    else {
        return Ok(false);
    };
    if marker != ORDERBOOK_CHANNEL_LOCK_MARKER_VALUE {
        return Err(validation_err(
            "orderbook channel asset-lock marker is corrupt",
        ));
    }
    Ok(true)
}
pub(super) fn mark_orderbook_channel_lock(
    state_transaction: &mut StateTransaction<'_, '_>,
    escrow_id: &EscrowId,
) -> Result<(), Error> {
    if !is_orderbook_settlement_escrow_id_v1(escrow_id) {
        return Err(validation_err(
            "orderbook settlement channel lock id is outside its reserved namespace",
        ));
    }
    if is_orderbook_order_lock(state_transaction.world(), escrow_id)? {
        return Err(validation_err(
            "orderbook settlement channel id already marks an order asset lock",
        ));
    }
    if is_orderbook_channel_lock(state_transaction.world(), escrow_id)? {
        return Err(validation_err(
            "orderbook settlement channel asset-lock marker already exists",
        ));
    }
    state_transaction.world.smart_contract_state.insert(
        orderbook_channel_lock_marker_key(escrow_id),
        ORDERBOOK_CHANNEL_LOCK_MARKER_VALUE.to_vec(),
    );
    Ok(())
}
pub(super) fn mark_orderbook_order_lock(
    state_transaction: &mut StateTransaction<'_, '_>,
    escrow_id: &EscrowId,
) -> Result<(), Error> {
    if !is_orderbook_order_escrow_id_v1(escrow_id) {
        return Err(validation_err(
            "orderbook order lock id is outside its reserved namespace",
        ));
    }
    if is_orderbook_channel_lock(state_transaction.world(), escrow_id)? {
        return Err(validation_err(
            "orderbook order id already marks a settlement channel asset lock",
        ));
    }
    if is_orderbook_order_lock(state_transaction.world(), escrow_id)? {
        return Err(validation_err(
            "orderbook order asset-lock marker already exists",
        ));
    }
    state_transaction.world.smart_contract_state.insert(
        orderbook_order_lock_marker_key(escrow_id),
        ORDERBOOK_ORDER_LOCK_MARKER_VALUE.to_vec(),
    );
    Ok(())
}
fn remove_orderbook_order_lock_marker(
    state_transaction: &mut StateTransaction<'_, '_>,
    escrow_id: &EscrowId,
) -> Result<(), Error> {
    if !is_orderbook_order_lock(state_transaction.world(), escrow_id)? {
        return Err(validation_err(
            "orderbook order asset-lock marker is missing",
        ));
    }
    state_transaction
        .world
        .smart_contract_state
        .remove(orderbook_order_lock_marker_key(escrow_id));
    Ok(())
}
fn remove_orderbook_channel_lock_marker(
    state_transaction: &mut StateTransaction<'_, '_>,
    escrow_id: &EscrowId,
) -> Result<(), Error> {
    if !is_orderbook_channel_lock(state_transaction.world(), escrow_id)? {
        return Err(validation_err(
            "orderbook settlement channel asset-lock marker is missing",
        ));
    }
    state_transaction
        .world
        .smart_contract_state
        .remove(orderbook_channel_lock_marker_key(escrow_id));
    Ok(())
}
fn reject_native_orderbook_lock(
    world: &impl WorldReadOnly,
    escrow_id: &EscrowId,
    operation: &str,
) -> Result<(), Error> {
    if is_orderbook_order_lock(world, escrow_id)? {
        return Err(validation_err(format!(
            "orderbook order asset locks cannot be {operation} outside native orderbook execution"
        )));
    }
    if is_orderbook_channel_lock(world, escrow_id)? {
        return Err(validation_err(format!(
            "orderbook channel asset locks cannot be {operation} outside native orderbook execution"
        )));
    }
    Ok(())
}
/// Derive the deterministic protocol custody account for an escrow.
pub fn escrow_custody_account_id(
    network_id: &iroha_data_model::NetworkId,
    escrow_id: &EscrowId,
    asset_definition: &AssetDefinitionId,
) -> Result<AccountId, Error> {
    let asset_definition = asset_definition.to_string();
    let public_key = derive_non_signing_ed25519_public_key(
        ESCROW_CUSTODY_ACCOUNT_DOMAIN.as_bytes(),
        &[
            network_id.as_bytes(),
            escrow_id.as_hash().as_ref(),
            asset_definition.as_bytes(),
        ],
    );
    Ok(AccountId::new(public_key))
}
fn has_permission(
    state_transaction: &StateTransaction<'_, '_>,
    authority: &AccountId,
    permission_name: &str,
) -> bool {
    let has_named_permission = |permission: &Permission| permission.name() == permission_name;
    if state_transaction
        .world
        .account_permissions
        .get(authority)
        .is_some_and(|permissions| permissions.iter().any(has_named_permission))
    {
        return true;
    }
    state_transaction
        .world
        .account_roles
        .iter()
        .filter_map(|(role_key, ())| {
            if &role_key.account == authority {
                state_transaction.world.roles.get(&role_key.id)
            } else {
                None
            }
        })
        .any(|role| role.permissions().any(has_named_permission))
}
fn custody_asset(record: &AssetEscrowRecord) -> AssetId {
    AssetId::new(record.asset_definition.clone(), record.custody.clone())
}
fn party_asset(record: &AssetEscrowRecord, account: &AccountId) -> AssetId {
    AssetId::new(record.asset_definition.clone(), account.clone())
}
fn transfer_numeric_asset_for_escrow(
    state_transaction: &mut StateTransaction<'_, '_>,
    authorization: VerifiedNativeEscrowMovement,
) -> Result<(), Error> {
    crate::smartcontracts::isi::asset::isi::execute_verified_native_escrow_movement(
        state_transaction,
        authorization,
    )
}
/// Atomically partition an admitted bid lock into one provider-bound channel lock.
///
/// The child lock is funded custody-to-custody; no matcher or relayer account
/// ever takes possession of the buyer's funds.
#[derive(Clone, Copy, PartialEq, Eq)]
enum NativeOrderbookLockKind {
    Order,
    Channel,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum NativeOrderbookClose {
    Cancelled,
    Expired,
    Filled,
}
pub(crate) fn open_orderbook_order_asset_lock(
    state_transaction: &mut StateTransaction<'_, '_>,
    escrow_id: EscrowId,
    owner: &AccountId,
    asset_definition: AssetDefinitionId,
    amount: Quantity,
    expires_at_ms: u64,
) -> Result<AssetEscrowRecord, Error> {
    if !is_orderbook_order_escrow_id_v1(&escrow_id) {
        return Err(validation_err(
            "native orderbook bid lock id is outside its reserved namespace",
        ));
    }
    if is_orderbook_order_lock(state_transaction.world(), &escrow_id)?
        || is_orderbook_channel_lock(state_transaction.world(), &escrow_id)?
    {
        return Err(validation_err(
            "native orderbook bid lock marker already exists",
        ));
    }
    let instruction = OpenAssetLock::with_options(
        escrow_id,
        asset_definition,
        owner.clone(),
        amount,
        Some(owner.clone()),
        Some(expires_at_ms),
        Vec::new(),
    );
    execute_open_asset_lock(instruction, owner, state_transaction, true)?;
    mark_orderbook_order_lock(state_transaction, &escrow_id)?;
    state_transaction
        .world
        .asset_escrows
        .get(&escrow_id)
        .cloned()
        .ok_or_else(|| validation_err("new native orderbook bid lock disappeared"))
}
fn validate_native_orderbook_lock_record(
    state_transaction: &StateTransaction<'_, '_>,
    escrow_id: &EscrowId,
    kind: NativeOrderbookLockKind,
) -> Result<AssetEscrowRecord, Error> {
    let (has_expected_marker, has_other_marker) = match kind {
        NativeOrderbookLockKind::Order => (
            is_orderbook_order_lock(state_transaction.world(), escrow_id)?,
            is_orderbook_channel_lock(state_transaction.world(), escrow_id)?,
        ),
        NativeOrderbookLockKind::Channel => (
            is_orderbook_channel_lock(state_transaction.world(), escrow_id)?,
            is_orderbook_order_lock(state_transaction.world(), escrow_id)?,
        ),
    };
    if !has_expected_marker || has_other_marker {
        return Err(validation_err(
            "native orderbook asset-lock marker binding is missing or ambiguous",
        ));
    }
    let record = state_transaction
        .world
        .asset_escrows
        .get(escrow_id)
        .cloned()
        .ok_or_else(|| validation_err("native orderbook asset lock not found"))?;
    ensure_asset_lock(&record)?;
    let expected_custody = escrow_custody_account_id(
        state_transaction.network_id(),
        escrow_id,
        &record.asset_definition,
    )?;
    if record.id != *escrow_id
        || record.custody != expected_custody
        || record.custody == record.seller
        || record.accepted_at_ms.is_some()
        || record.payment_sent_at_ms.is_some()
        || record.disputed_at_ms.is_some()
        || record.resolution.is_some()
        || record.remaining_amount > record.amount
        || record.amount.is_zero()
    {
        return Err(validation_err(
            "native orderbook asset-lock metadata is inconsistent",
        ));
    }
    let unresolved_custody_asset = custody_asset(&record);
    let resolved_custody_asset = state_transaction
        .world
        .resolve_asset_id_for_current_scope(&unresolved_custody_asset)?;
    let custody_balance = state_transaction
        .world
        .assets
        .get(&resolved_custody_asset)
        .map(|value| value.as_ref().clone())
        .unwrap_or_else(Quantity::zero);
    if custody_balance != record.remaining_amount {
        return Err(validation_err(
            "native orderbook custody balance does not match its asset-lock record",
        ));
    }
    Ok(record)
}
fn validate_orderbook_order_lock_binding(
    state_transaction: &StateTransaction<'_, '_>,
    escrow_id: &EscrowId,
    owner: &AccountId,
    asset_definition: &AssetDefinitionId,
    initial_amount: &Quantity,
    expires_at_ms: u64,
    allow_fully_drawn: bool,
) -> Result<AssetEscrowRecord, Error> {
    let record = validate_native_orderbook_lock_record(
        state_transaction,
        escrow_id,
        NativeOrderbookLockKind::Order,
    )?;
    let status_is_valid = record.status == AssetEscrowStatus::Locked
        || (allow_fully_drawn
            && record.status == AssetEscrowStatus::DrawnDown
            && record.remaining_amount.is_zero()
            && record.closed_at_ms.is_some());
    if !status_is_valid
        || (!allow_fully_drawn
            && (record.remaining_amount.is_zero() || record.closed_at_ms.is_some()))
        || record.seller != *owner
        || record.buyer.as_ref() != Some(owner)
        || record.release_authority.as_ref() != Some(owner)
        || record.asset_definition != *asset_definition
        || record.amount != *initial_amount
        || record.expires_at_ms != Some(expires_at_ms)
    {
        return Err(validation_err(
            "orderbook bid asset-lock binding is inconsistent",
        ));
    }
    Ok(record)
}
pub(crate) fn validate_active_orderbook_order_asset_lock(
    state_transaction: &StateTransaction<'_, '_>,
    escrow_id: &EscrowId,
    owner: &AccountId,
    asset_definition: &AssetDefinitionId,
    initial_amount: &Quantity,
    expires_at_ms: u64,
) -> Result<AssetEscrowRecord, Error> {
    validate_orderbook_order_lock_binding(
        state_transaction,
        escrow_id,
        owner,
        asset_definition,
        initial_amount,
        expires_at_ms,
        false,
    )
}
fn close_native_orderbook_asset_lock(
    state_transaction: &mut StateTransaction<'_, '_>,
    escrow_id: &EscrowId,
    kind: NativeOrderbookLockKind,
    close: NativeOrderbookClose,
) -> Result<AssetEscrowRecord, Error> {
    let mut record = validate_native_orderbook_lock_record(state_transaction, escrow_id, kind)?;
    let already_fully_drawn = close == NativeOrderbookClose::Filled
        && record.status == AssetEscrowStatus::DrawnDown
        && record.remaining_amount.is_zero()
        && record.closed_at_ms.is_some();
    if !already_fully_drawn {
        if record.status != AssetEscrowStatus::Locked
            || record.remaining_amount.is_zero()
            || record.closed_at_ms.is_some()
        {
            return Err(validation_err(
                "native orderbook asset lock is not refundable",
            ));
        }
        if close == NativeOrderbookClose::Expired {
            let expires_at_ms = record
                .expires_at_ms
                .ok_or_else(|| validation_err("native orderbook asset lock has no expiry"))?;
            if state_transaction.block_unix_timestamp_ms() < expires_at_ms {
                return Err(validation_err(
                    "native orderbook asset-lock expiry has not been reached",
                ));
            }
        }
        let custody_asset = custody_asset(&record);
        let seller_asset = party_asset(&record, &record.seller);
        transfer_numeric_asset_for_escrow(
            state_transaction,
            VerifiedNativeEscrowMovement::retained(
                record.id.clone(),
                custody_asset,
                seller_asset,
                record.remaining_amount.clone(),
            ),
        )?;
        record.remaining_amount = Quantity::zero();
        record.closed_at_ms = Some(state_transaction.block_unix_timestamp_ms());
        record.status = match close {
            NativeOrderbookClose::Cancelled => AssetEscrowStatus::Cancelled,
            NativeOrderbookClose::Expired => AssetEscrowStatus::Expired,
            NativeOrderbookClose::Filled => AssetEscrowStatus::DrawnDown,
        };
        state_transaction
            .world
            .insert_asset_escrow_entry(record.clone());
        let event = match close {
            NativeOrderbookClose::Cancelled => EscrowEvent::Cancelled(record.clone()),
            NativeOrderbookClose::Expired => EscrowEvent::Expired(record.clone()),
            NativeOrderbookClose::Filled => EscrowEvent::Released(record.clone()),
        };
        state_transaction.world.emit_events(Some(event));
    }
    match kind {
        NativeOrderbookLockKind::Order => {
            remove_orderbook_order_lock_marker(state_transaction, escrow_id)?;
        }
        NativeOrderbookLockKind::Channel => {
            remove_orderbook_channel_lock_marker(state_transaction, escrow_id)?;
        }
    }
    Ok(record)
}
pub(crate) fn cancel_orderbook_order_asset_lock(
    state_transaction: &mut StateTransaction<'_, '_>,
    escrow_id: &EscrowId,
    owner: &AccountId,
    asset_definition: &AssetDefinitionId,
    initial_amount: &Quantity,
    expires_at_ms: u64,
) -> Result<AssetEscrowRecord, Error> {
    validate_orderbook_order_lock_binding(
        state_transaction,
        escrow_id,
        owner,
        asset_definition,
        initial_amount,
        expires_at_ms,
        false,
    )?;
    close_native_orderbook_asset_lock(
        state_transaction,
        escrow_id,
        NativeOrderbookLockKind::Order,
        NativeOrderbookClose::Cancelled,
    )
}
pub(crate) fn expire_orderbook_order_asset_lock(
    state_transaction: &mut StateTransaction<'_, '_>,
    escrow_id: &EscrowId,
    owner: &AccountId,
    asset_definition: &AssetDefinitionId,
    initial_amount: &Quantity,
    expires_at_ms: u64,
) -> Result<AssetEscrowRecord, Error> {
    validate_orderbook_order_lock_binding(
        state_transaction,
        escrow_id,
        owner,
        asset_definition,
        initial_amount,
        expires_at_ms,
        false,
    )?;
    close_native_orderbook_asset_lock(
        state_transaction,
        escrow_id,
        NativeOrderbookLockKind::Order,
        NativeOrderbookClose::Expired,
    )
}
pub(crate) fn close_filled_orderbook_order_asset_lock(
    state_transaction: &mut StateTransaction<'_, '_>,
    escrow_id: &EscrowId,
    owner: &AccountId,
    asset_definition: &AssetDefinitionId,
    initial_amount: &Quantity,
    expires_at_ms: u64,
) -> Result<AssetEscrowRecord, Error> {
    validate_orderbook_order_lock_binding(
        state_transaction,
        escrow_id,
        owner,
        asset_definition,
        initial_amount,
        expires_at_ms,
        true,
    )?;
    close_native_orderbook_asset_lock(
        state_transaction,
        escrow_id,
        NativeOrderbookLockKind::Order,
        NativeOrderbookClose::Filled,
    )
}
pub(crate) fn expire_orderbook_channel_asset_lock(
    state_transaction: &mut StateTransaction<'_, '_>,
    escrow_id: &EscrowId,
) -> Result<AssetEscrowRecord, Error> {
    close_native_orderbook_asset_lock(
        state_transaction,
        escrow_id,
        NativeOrderbookLockKind::Channel,
        NativeOrderbookClose::Expired,
    )
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn partition_orderbook_asset_lock(
    state_transaction: &mut StateTransaction<'_, '_>,
    parent_id: &EscrowId,
    child_id: EscrowId,
    provider: AccountId,
    release_authority: AccountId,
    amount: Quantity,
    expires_at_ms: u64,
) -> Result<(AssetEscrowRecord, AssetEscrowRecord), Error> {
    ensure_positive(&amount)?;
    if !is_orderbook_order_escrow_id_v1(parent_id)
        || !is_orderbook_settlement_escrow_id_v1(&child_id)
    {
        return Err(validation_err(
            "orderbook partition ids are outside their reserved namespaces",
        ));
    }
    if parent_id == &child_id {
        return Err(validation_err(
            "orderbook parent and channel asset-lock ids must differ",
        ));
    }
    if state_transaction
        .world
        .asset_escrows
        .get(&child_id)
        .is_some()
    {
        return Err(validation_err(
            "orderbook settlement channel asset lock already exists",
        ));
    }
    if is_orderbook_channel_lock(state_transaction.world(), &child_id)? {
        return Err(validation_err(
            "orderbook settlement channel asset-lock marker already exists",
        ));
    }
    if is_orderbook_order_lock(state_transaction.world(), &child_id)? {
        return Err(validation_err(
            "orderbook settlement channel id already marks an order asset lock",
        ));
    }
    if !is_orderbook_order_lock(state_transaction.world(), parent_id)?
        || is_orderbook_channel_lock(state_transaction.world(), parent_id)?
    {
        return Err(validation_err(
            "orderbook bid asset lock has no unambiguous authoritative order marker",
        ));
    }
    let Some(mut parent) = state_transaction
        .world
        .asset_escrows
        .get(parent_id)
        .cloned()
    else {
        return Err(validation_err("orderbook bid asset lock not found"));
    };
    ensure_asset_lock(&parent)?;
    if parent.id != *parent_id
        || parent.status != AssetEscrowStatus::Locked
        || parent.closed_at_ms.is_some()
        || parent.remaining_amount.is_zero()
        || parent.remaining_amount > parent.amount
    {
        return Err(validation_err(
            "orderbook bid asset-lock metadata is inconsistent",
        ));
    }
    if parent.buyer.as_ref() != Some(&parent.seller)
        || parent.release_authority.as_ref() != Some(&parent.seller)
    {
        return Err(validation_err(
            "orderbook bid asset lock is not bound to its buyer",
        ));
    }
    let expected_parent_custody = escrow_custody_account_id(
        state_transaction.network_id(),
        parent_id,
        &parent.asset_definition,
    )?;
    if parent.custody != expected_parent_custody {
        return Err(validation_err(
            "orderbook bid asset-lock custody binding is invalid",
        ));
    }
    let parent_custody_asset = custody_asset(&parent);
    let resolved_parent_custody_asset = state_transaction
        .world
        .resolve_asset_id_for_current_scope(&parent_custody_asset)?;
    let parent_custody_balance = state_transaction
        .world
        .assets
        .get(&resolved_parent_custody_asset)
        .map(|value| value.as_ref().clone())
        .ok_or_else(|| validation_err("orderbook bid custody balance is missing"))?;
    if parent_custody_balance != parent.remaining_amount {
        return Err(validation_err(
            "orderbook bid custody balance does not match its asset-lock record",
        ));
    }
    if amount > parent.remaining_amount {
        return Err(validation_err(
            "orderbook channel partition exceeds remaining bid custody",
        ));
    }
    let now_ms = state_transaction.block_unix_timestamp_ms();
    if expires_at_ms <= now_ms
        || parent
            .expires_at_ms
            .is_some_and(|parent_expiry| expires_at_ms > parent_expiry)
    {
        return Err(validation_err(
            "orderbook channel expiry must be future and within bid-lock expiry",
        ));
    }
    state_transaction.world.account(&provider)?;
    state_transaction.world.account(&release_authority)?;
    let spec = state_transaction
        .numeric_spec_for(&parent.asset_definition)
        .map_err(Error::from)?;
    assert_numeric_spec_with(amount.as_numeric(), spec)?;
    let child_custody = escrow_custody_account_id(
        state_transaction.network_id(),
        &child_id,
        &parent.asset_definition,
    )?;
    if child_custody == parent.custody
        || child_custody == parent.seller
        || child_custody == provider
    {
        return Err(validation_err(
            "orderbook channel custody binding is invalid",
        ));
    }
    let source = AssetId::new(parent.asset_definition.clone(), parent.custody.clone());
    let destination = AssetId::new(parent.asset_definition.clone(), child_custody.clone());
    let custody_created = ensure_custody_account(&child_custody, state_transaction)?;
    let transfer = transfer_numeric_asset_for_escrow(
        state_transaction,
        VerifiedNativeEscrowMovement::custody_partition(
            parent.id.clone(),
            child_id.clone(),
            source,
            destination,
            amount.clone(),
        ),
    );
    if transfer.is_err() && custody_created {
        state_transaction
            .world
            .accounts
            .remove(child_custody.clone());
    }
    transfer?;
    parent.remaining_amount = parent
        .remaining_amount
        .checked_sub(&amount)
        .map_err(|_| validation_err("orderbook bid custody underflow"))?;
    if parent.remaining_amount.is_zero() {
        parent.status = AssetEscrowStatus::DrawnDown;
        parent.closed_at_ms = Some(now_ms);
    }
    let child = AssetEscrowRecord {
        id: child_id,
        seller: parent.seller.clone(),
        buyer: Some(provider),
        asset_definition: parent.asset_definition.clone(),
        amount: amount.clone(),
        custody: child_custody,
        status: AssetEscrowStatus::Locked,
        kind: AssetEscrowKind::Lock,
        remaining_amount: amount,
        release_authority: Some(release_authority),
        expires_at_ms: Some(expires_at_ms),
        evidence_hashes: Vec::new(),
        conditions: Vec::new(),
        created_at_ms: now_ms,
        accepted_at_ms: None,
        payment_sent_at_ms: None,
        disputed_at_ms: None,
        closed_at_ms: None,
        resolution: None,
    };
    state_transaction
        .world
        .insert_asset_escrow_entry(parent.clone());
    state_transaction
        .world
        .insert_asset_escrow_entry(child.clone());
    mark_orderbook_channel_lock(state_transaction, &child.id)?;
    state_transaction.world.emit_events([
        EscrowEvent::Released(parent.clone()),
        EscrowEvent::Opened(child.clone()),
    ]);
    Ok((parent, child))
}
/// Atomically settle provider credit and treasury fee from a funded generic asset lock.
///
/// The lock must name `authority` as its explicit release authority. Its seller is the buyer/funder
/// and its destination is the provider. All balance, numeric-spec, transfer-policy, expiry, and
/// overflow checks run before any asset or escrow record is mutated.
pub(crate) fn settle_orderbook_asset_lock(
    state_transaction: &mut StateTransaction<'_, '_>,
    escrow_id: &EscrowId,
    authority: &AccountId,
    fee_recipient: &AccountId,
    provider_credit: Quantity,
    fee_amount: Quantity,
) -> Result<AssetEscrowRecord, Error> {
    let total = provider_credit
        .checked_add(&fee_amount)
        .map_err(|_| validation_err("orderbook settlement amount overflow"))?;
    ensure_positive(&total)?;
    if state_transaction.tx_call_hash.is_none() {
        return Err(validation_err(
            "orderbook settlement requires a transaction call hash",
        ));
    }
    let Some(mut record) = state_transaction
        .world
        .asset_escrows
        .get(escrow_id)
        .cloned()
    else {
        return Err(validation_err("orderbook settlement asset lock not found"));
    };
    ensure_asset_lock(&record)?;
    if !is_orderbook_channel_lock(state_transaction.world(), escrow_id)? {
        return Err(validation_err(
            "orderbook settlement asset lock has no authoritative channel marker",
        ));
    }
    if &record.id != escrow_id
        || record.closed_at_ms.is_some()
        || record.accepted_at_ms.is_some()
        || record.payment_sent_at_ms.is_some()
        || record.disputed_at_ms.is_some()
        || record.resolution.is_some()
    {
        return Err(validation_err(
            "orderbook settlement asset-lock metadata is inconsistent",
        ));
    }
    if record.status != AssetEscrowStatus::Locked {
        return Err(validation_err(
            "orderbook settlement requires an active locked asset lock",
        ));
    }
    if record.release_authority.as_ref() != Some(authority) {
        return Err(validation_err(
            "orderbook settlement authority does not match asset-lock release authority",
        ));
    }
    let expected_custody = escrow_custody_account_id(
        state_transaction.network_id(),
        escrow_id,
        &record.asset_definition,
    )?;
    if record.custody != expected_custody
        || record.custody == record.seller
        || record.buyer.as_ref() == Some(&record.custody)
    {
        return Err(validation_err(
            "orderbook settlement asset-lock custody binding is invalid",
        ));
    }
    if record
        .expires_at_ms
        .is_some_and(|expires_at_ms| state_transaction.block_unix_timestamp_ms() >= expires_at_ms)
    {
        return Err(validation_err("orderbook settlement asset lock is expired"));
    }
    let provider = record
        .buyer
        .clone()
        .ok_or_else(|| validation_err("orderbook settlement asset lock destination is missing"))?;
    if provider == record.custody || fee_recipient == &record.custody {
        return Err(validation_err(
            "orderbook settlement destination must not be the custody account",
        ));
    }
    state_transaction.world.account(&provider)?;
    state_transaction.world.account(fee_recipient)?;
    let spec = state_transaction
        .numeric_spec_for(&record.asset_definition)
        .map_err(Error::from)?;
    assert_numeric_spec_with(record.amount.as_numeric(), spec)?;
    assert_numeric_spec_with(record.remaining_amount.as_numeric(), spec)?;
    assert_numeric_spec_with(provider_credit.as_numeric(), spec)?;
    assert_numeric_spec_with(fee_amount.as_numeric(), spec)?;
    assert_numeric_spec_with(total.as_numeric(), spec)?;
    ensure_positive(&record.amount)?;
    ensure_positive(&record.remaining_amount)?;
    if record.remaining_amount > record.amount {
        return Err(validation_err(
            "orderbook settlement asset-lock remaining amount exceeds original amount",
        ));
    }
    if total > record.remaining_amount {
        return Err(validation_err(
            "orderbook settlement debit exceeds remaining asset-lock custody",
        ));
    }
    let remaining_lock_amount = record
        .remaining_amount
        .checked_sub(&total)
        .map_err(|_| validation_err("orderbook asset-lock remaining amount underflow"))?;
    let mut allocations = BTreeMap::<AccountId, Quantity>::new();
    for (destination, amount) in [
        (provider, provider_credit),
        (fee_recipient.clone(), fee_amount),
    ] {
        if amount.is_zero() {
            continue;
        }
        if let Some(existing) = allocations.get_mut(&destination) {
            *existing = existing
                .checked_add(&amount)
                .map_err(|_| validation_err("orderbook destination amount overflow"))?;
        } else {
            allocations.insert(destination, amount);
        }
    }
    let event_source_id = custody_asset(&record);
    let mut plans = Vec::with_capacity(allocations.len());
    for (destination, amount) in allocations {
        let event_destination_id = party_asset(&record, &destination);
        plans.push((event_source_id.clone(), event_destination_id, amount));
    }
    if plans.is_empty() {
        return Err(validation_err(
            "orderbook settlement has no non-zero allocation",
        ));
    }
    let source_balance = state_transaction
        .world
        .assets
        .get(&event_source_id)
        .map(|value| value.as_ref().clone())
        .ok_or_else(|| validation_err("orderbook settlement custody balance is missing"))?;
    if source_balance != record.remaining_amount {
        return Err(validation_err(
            "orderbook settlement custody balance does not match the asset-lock record",
        ));
    }
    let _remaining_source = source_balance
        .checked_sub(&total)
        .map_err(|_| validation_err("orderbook settlement custody balance underflow"))?;
    for (_, destination_id, amount) in &plans {
        let destination_balance = state_transaction
            .world
            .assets
            .get(destination_id)
            .map(|value| value.as_ref().clone())
            .unwrap_or_else(Quantity::zero);
        destination_balance
            .checked_add(amount)
            .map_err(|_| validation_err("orderbook settlement destination balance overflow"))?;
    }
    let authorization = VerifiedNativeEscrowBatch::orderbook_settlement(
        record.id.clone(),
        authority.clone(),
        plans,
    );
    crate::smartcontracts::isi::asset::isi::execute_verified_native_escrow_batch(
        state_transaction,
        authorization,
    )?;
    record.remaining_amount = remaining_lock_amount;
    if record.remaining_amount.is_zero() {
        record.status = AssetEscrowStatus::DrawnDown;
        record.closed_at_ms = Some(state_transaction.block_unix_timestamp_ms());
    }
    state_transaction
        .world
        .insert_asset_escrow_entry(record.clone());
    state_transaction
        .world
        .emit_events(Some(EscrowEvent::Released(record.clone())));
    if record.remaining_amount.is_zero() {
        remove_orderbook_channel_lock_marker(state_transaction, escrow_id)?;
    }
    Ok(record)
}
/// Return whether the asset id points at a protocol custody account recorded by a native escrow.
///
/// The guard intentionally covers closed records too. Escrow ISIs should leave closed custody
/// balances at zero, and keeping the source permanently blocked preserves protocol-only custody
/// semantics independently of the account controller construction.
pub(crate) fn is_native_escrow_custody_asset(
    state_transaction: &StateTransaction<'_, '_>,
    source_id: &AssetId,
) -> Result<bool, Error> {
    let resolved_id = if matches!(
        source_id.scope(),
        iroha_data_model::asset::AssetBalanceScope::Dataspace(_)
    ) {
        source_id.clone()
    } else {
        state_transaction
            .world
            .resolve_asset_id_for_current_scope(source_id)?
    };
    Ok(state_transaction
        .world
        .sumeragi_amx_participant()
        .canonical()
        .is_some_and(|participant| participant.custody == *resolved_id.account())
        || state_transaction
            .world
            .game_custody_by_account
            .get(resolved_id.account())
            .and_then(|id| state_transaction.world.game_sessions.get(id))
            .is_some_and(|session| session.asset_definition == *resolved_id.definition())
        || state_transaction
            .world
            .asset_escrows
            .iter()
            .any(|(_, record)| {
                record.asset_definition == *resolved_id.definition()
                    && record.custody == *resolved_id.account()
            })
        || state_transaction
            .world
            .vpn_leases
            .iter()
            .any(|(_, record)| {
                record.asset_definition == *resolved_id.definition()
                    && record.custody_account_id == *resolved_id.account()
            }))
}
/// Return whether an account is retained as native-escrow or VPN-lease custody.
///
/// Closed records remain authoritative: removing their accounts would destroy audit history and
/// any unexpected residual balance instead of surfacing the violated zero-balance invariant.
pub(crate) fn is_protocol_escrow_custody_account(
    state_transaction: &StateTransaction<'_, '_>,
    account_id: &AccountId,
) -> bool {
    crate::sumeragi::amx::retained_account(&state_transaction.world, account_id)
        || state_transaction
            .world
            .game_custody_by_account
            .get(account_id)
            .is_some()
        || state_transaction
            .world
            .asset_escrows
            .iter()
            .any(|(_, record)| record.custody == *account_id)
        || state_transaction
            .world
            .vpn_leases
            .iter()
            .any(|(_, record)| record.custody_account_id == *account_id)
}
impl Execute for OpenAssetEscrow {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        reject_reserved_orderbook_escrow_id(&self.escrow_id)?;
        if state_transaction
            .world
            .asset_escrows
            .get(&self.escrow_id)
            .is_some()
        {
            return Err(validation_err("escrow already exists"));
        }
        ensure_positive(&self.amount)?;
        let spec = state_transaction
            .numeric_spec_for(&self.asset_definition)
            .map_err(Error::from)?;
        assert_numeric_spec_with(self.amount.as_numeric(), spec)?;
        state_transaction.world.account(authority)?;
        state_transaction
            .world
            .asset_definition(&self.asset_definition)?;
        let custody = escrow_custody_account_id(
            state_transaction.network_id(),
            &self.escrow_id,
            &self.asset_definition,
        )?;
        let seller_asset = AssetId::new(self.asset_definition.clone(), authority.clone());
        let custody_asset = AssetId::new(self.asset_definition.clone(), custody.clone());
        let custody_created = ensure_custody_account(&custody, state_transaction)?;
        let transfer_result = transfer_numeric_asset_for_escrow(
            state_transaction,
            VerifiedNativeEscrowMovement::funding(
                self.escrow_id.clone(),
                authority.clone(),
                seller_asset,
                custody_asset,
                self.amount.clone(),
            ),
        );
        if transfer_result.is_err() && custody_created {
            state_transaction.world.accounts.remove(custody.clone());
        }
        transfer_result?;
        let record = AssetEscrowRecord {
            id: self.escrow_id,
            seller: authority.clone(),
            buyer: None,
            asset_definition: self.asset_definition,
            amount: self.amount.clone(),
            custody,
            status: AssetEscrowStatus::Open,
            kind: AssetEscrowKind::Marketplace,
            remaining_amount: self.amount,
            release_authority: None,
            expires_at_ms: None,
            evidence_hashes: self.evidence_hashes,
            conditions: Vec::new(),
            created_at_ms: state_transaction.block_unix_timestamp_ms(),
            accepted_at_ms: None,
            payment_sent_at_ms: None,
            disputed_at_ms: None,
            closed_at_ms: None,
            resolution: None,
        };
        state_transaction
            .world
            .insert_asset_escrow_entry(record.clone());
        state_transaction
            .world
            .emit_events(Some(EscrowEvent::Opened(record)));
        Ok(())
    }
}
impl Execute for AcceptAssetEscrow {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        state_transaction.world.account(authority)?;
        let Some(mut record) = state_transaction
            .world
            .asset_escrows
            .get(&self.escrow_id)
            .cloned()
        else {
            return Err(validation_err("escrow not found"));
        };
        if record.status != AssetEscrowStatus::Open {
            return Err(validation_err("only open escrows can be accepted"));
        }
        if &record.seller == authority {
            return Err(validation_err("seller cannot accept own escrow"));
        }
        record.buyer = Some(authority.clone());
        record.status = AssetEscrowStatus::Accepted;
        record.accepted_at_ms = Some(state_transaction.block_unix_timestamp_ms());
        state_transaction
            .world
            .insert_asset_escrow_entry(record.clone());
        state_transaction
            .world
            .emit_events(Some(EscrowEvent::Accepted(record)));
        Ok(())
    }
}
impl Execute for MarkEscrowPaymentSent {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let Some(mut record) = state_transaction
            .world
            .asset_escrows
            .get(&self.escrow_id)
            .cloned()
        else {
            return Err(validation_err("escrow not found"));
        };
        if record.status != AssetEscrowStatus::Accepted {
            return Err(validation_err("only accepted escrows can be marked paid"));
        }
        if record.buyer.as_ref() != Some(authority) {
            return Err(validation_err("only accepted buyer may mark payment sent"));
        }
        record.status = AssetEscrowStatus::PaymentSent;
        record.payment_sent_at_ms = Some(state_transaction.block_unix_timestamp_ms());
        state_transaction
            .world
            .insert_asset_escrow_entry(record.clone());
        state_transaction
            .world
            .emit_events(Some(EscrowEvent::PaymentSent(record)));
        Ok(())
    }
}
impl Execute for ReleaseAssetEscrow {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let Some(mut record) = state_transaction
            .world
            .asset_escrows
            .get(&self.escrow_id)
            .cloned()
        else {
            return Err(validation_err("escrow not found"));
        };
        if record.status != AssetEscrowStatus::PaymentSent {
            return Err(validation_err("only paid escrows can be released"));
        }
        if &record.seller != authority {
            return Err(validation_err("only seller may release escrow"));
        }
        let buyer = record
            .buyer
            .clone()
            .ok_or_else(|| validation_err("escrow buyer missing"))?;
        let escrow_asset = custody_asset(&record);
        let buyer_asset = party_asset(&record, &buyer);
        transfer_numeric_asset_for_escrow(
            state_transaction,
            VerifiedNativeEscrowMovement::retained(
                record.id.clone(),
                escrow_asset,
                buyer_asset,
                record.amount.clone(),
            ),
        )?;
        record.status = AssetEscrowStatus::Released;
        record.remaining_amount = Quantity::zero();
        record.closed_at_ms = Some(state_transaction.block_unix_timestamp_ms());
        state_transaction
            .world
            .insert_asset_escrow_entry(record.clone());
        state_transaction
            .world
            .emit_events(Some(EscrowEvent::Released(record)));
        Ok(())
    }
}
impl Execute for CancelAssetEscrow {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let Some(mut record) = state_transaction
            .world
            .asset_escrows
            .get(&self.escrow_id)
            .cloned()
        else {
            return Err(validation_err("escrow not found"));
        };
        if !matches!(
            record.status,
            AssetEscrowStatus::Open | AssetEscrowStatus::Accepted
        ) {
            return Err(validation_err(
                "escrow can only be cancelled before payment is marked",
            ));
        }
        if &record.seller != authority {
            return Err(validation_err("only seller may cancel escrow"));
        }
        let escrow_asset = custody_asset(&record);
        let seller_asset = party_asset(&record, &record.seller);
        transfer_numeric_asset_for_escrow(
            state_transaction,
            VerifiedNativeEscrowMovement::retained(
                record.id.clone(),
                escrow_asset,
                seller_asset,
                record.amount.clone(),
            ),
        )?;
        record.status = AssetEscrowStatus::Cancelled;
        record.remaining_amount = Quantity::zero();
        record.closed_at_ms = Some(state_transaction.block_unix_timestamp_ms());
        state_transaction
            .world
            .insert_asset_escrow_entry(record.clone());
        state_transaction
            .world
            .emit_events(Some(EscrowEvent::Cancelled(record)));
        Ok(())
    }
}
impl Execute for OpenEscrowDispute {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let Some(mut record) = state_transaction
            .world
            .asset_escrows
            .get(&self.escrow_id)
            .cloned()
        else {
            return Err(validation_err("escrow not found"));
        };
        if !matches!(
            record.status,
            AssetEscrowStatus::Accepted | AssetEscrowStatus::PaymentSent
        ) {
            return Err(validation_err(
                "only accepted or paid escrows can enter dispute",
            ));
        }
        let is_seller = &record.seller == authority;
        let is_buyer = record.buyer.as_ref() == Some(authority);
        if !(is_seller || is_buyer) {
            return Err(validation_err(
                "only escrow buyer or seller may open dispute",
            ));
        }
        record.status = AssetEscrowStatus::Disputed;
        record.disputed_at_ms = Some(state_transaction.block_unix_timestamp_ms());
        record
            .evidence_hashes
            .extend(self.evidence_hashes.iter().copied());
        state_transaction
            .world
            .insert_asset_escrow_entry(record.clone());
        state_transaction
            .world
            .emit_events(Some(EscrowEvent::Disputed(AssetEscrowDisputed {
                escrow: record,
                opened_by: authority.clone(),
                evidence_hashes: self.evidence_hashes,
            })));
        Ok(())
    }
}
impl Execute for ResolveEscrowDispute {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        if !has_permission(state_transaction, authority, CAN_RESOLVE_ESCROW_DISPUTE) {
            return Err(validation_err("not permitted: CanResolveEscrowDispute"));
        }
        let Some(mut record) = state_transaction
            .world
            .asset_escrows
            .get(&self.escrow_id)
            .cloned()
        else {
            return Err(validation_err("escrow not found"));
        };
        if record.status != AssetEscrowStatus::Disputed {
            return Err(validation_err("only disputed escrows can be resolved"));
        }
        ensure_resolution_split(&record.amount, &self.buyer_amount, &self.seller_amount)?;
        let buyer = record
            .buyer
            .clone()
            .ok_or_else(|| validation_err("escrow buyer missing"))?;
        let escrow_asset = custody_asset(&record);
        if !self.buyer_amount.is_zero() {
            let buyer_asset = party_asset(&record, &buyer);
            transfer_numeric_asset_for_escrow(
                state_transaction,
                VerifiedNativeEscrowMovement::retained(
                    record.id.clone(),
                    escrow_asset.clone(),
                    buyer_asset,
                    self.buyer_amount.clone(),
                ),
            )?;
        }
        if !self.seller_amount.is_zero() {
            let seller_asset = party_asset(&record, &record.seller);
            transfer_numeric_asset_for_escrow(
                state_transaction,
                VerifiedNativeEscrowMovement::retained(
                    record.id.clone(),
                    escrow_asset.clone(),
                    seller_asset,
                    self.seller_amount.clone(),
                ),
            )?;
        }
        let resolved_at_ms = state_transaction.block_unix_timestamp_ms();
        record.status = AssetEscrowStatus::Resolved;
        record.remaining_amount = Quantity::zero();
        record.closed_at_ms = Some(resolved_at_ms);
        record.resolution = Some(AssetEscrowResolution {
            resolver: authority.clone(),
            buyer_amount: self.buyer_amount.clone(),
            seller_amount: self.seller_amount.clone(),
            evidence_hashes: self.evidence_hashes.clone(),
            resolved_at_ms,
        });
        state_transaction
            .world
            .insert_asset_escrow_entry(record.clone());
        state_transaction
            .world
            .emit_events(Some(EscrowEvent::Resolved(AssetEscrowResolved {
                escrow: record,
                resolver: authority.clone(),
                buyer_amount: self.buyer_amount,
                seller_amount: self.seller_amount,
            })));
        Ok(())
    }
}
fn execute_open_asset_lock(
    instruction: OpenAssetLock,
    authority: &AccountId,
    state_transaction: &mut StateTransaction<'_, '_>,
    allow_reserved_orderbook_id: bool,
) -> Result<(), Error> {
    if !allow_reserved_orderbook_id {
        reject_reserved_orderbook_escrow_id(&instruction.escrow_id)?;
    }
    if state_transaction
        .world
        .asset_escrows
        .get(&instruction.escrow_id)
        .is_some()
    {
        return Err(validation_err("escrow already exists"));
    }
    ensure_positive(&instruction.amount)?;
    let spec = state_transaction
        .numeric_spec_for(&instruction.asset_definition)
        .map_err(Error::from)?;
    assert_numeric_spec_with(instruction.amount.as_numeric(), spec)?;
    state_transaction.world.account(authority)?;
    state_transaction.world.account(&instruction.destination)?;
    if let Some(release_authority) = instruction.release_authority.as_ref() {
        state_transaction.world.account(release_authority)?;
    }
    state_transaction
        .world
        .asset_definition(&instruction.asset_definition)?;
    let custody = escrow_custody_account_id(
        state_transaction.network_id(),
        &instruction.escrow_id,
        &instruction.asset_definition,
    )?;
    let source_asset = AssetId::new(instruction.asset_definition.clone(), authority.clone());
    let custody_asset = AssetId::new(instruction.asset_definition.clone(), custody.clone());
    let custody_created = ensure_custody_account(&custody, state_transaction)?;
    let transfer_result = transfer_numeric_asset_for_escrow(
        state_transaction,
        VerifiedNativeEscrowMovement::funding(
            instruction.escrow_id.clone(),
            authority.clone(),
            source_asset,
            custody_asset,
            instruction.amount.clone(),
        ),
    );
    if transfer_result.is_err() && custody_created {
        state_transaction.world.accounts.remove(custody.clone());
    }
    transfer_result?;
    let record = AssetEscrowRecord {
        id: instruction.escrow_id,
        seller: authority.clone(),
        buyer: Some(instruction.destination),
        asset_definition: instruction.asset_definition,
        amount: instruction.amount.clone(),
        custody,
        status: AssetEscrowStatus::Locked,
        kind: AssetEscrowKind::Lock,
        remaining_amount: instruction.amount,
        release_authority: instruction.release_authority,
        expires_at_ms: instruction.expires_at_ms,
        evidence_hashes: instruction.evidence_hashes,
        conditions: Vec::new(),
        created_at_ms: state_transaction.block_unix_timestamp_ms(),
        accepted_at_ms: None,
        payment_sent_at_ms: None,
        disputed_at_ms: None,
        closed_at_ms: None,
        resolution: None,
    };
    state_transaction
        .world
        .insert_asset_escrow_entry(record.clone());
    state_transaction
        .world
        .emit_events(Some(EscrowEvent::Opened(record)));
    Ok(())
}
impl Execute for OpenAssetLock {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        execute_open_asset_lock(self, authority, state_transaction, false)
    }
}
impl Execute for DrawdownAssetLock {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        ensure_positive(&self.amount)?;
        let Some(mut record) = state_transaction
            .world
            .asset_escrows
            .get(&self.escrow_id)
            .cloned()
        else {
            return Err(validation_err("escrow not found"));
        };
        ensure_asset_lock(&record)?;
        reject_native_orderbook_lock(state_transaction.world(), &self.escrow_id, "drawn down")?;
        if record.status != AssetEscrowStatus::Locked {
            return Err(validation_err("only locked asset locks can be drawn down"));
        }
        if let Some(release_authority) = record.release_authority.as_ref() {
            if release_authority != authority {
                return Err(validation_err("only release authority may draw down lock"));
            }
        } else if record.buyer.as_ref() != Some(authority) {
            return Err(validation_err("only lock destination may draw down lock"));
        }
        let spec = state_transaction
            .numeric_spec_for(&record.asset_definition)
            .map_err(Error::from)?;
        assert_numeric_spec_with(self.amount.as_numeric(), spec)?;
        assert_numeric_spec_with(self.expected_remaining_amount.as_numeric(), spec)?;
        if record.remaining_amount != self.expected_remaining_amount {
            return Err(validation_err(
                "asset lock remaining amount changed since the drawdown was prepared",
            ));
        }
        if self.amount > record.remaining_amount {
            return Err(validation_err("lock drawdown exceeds remaining amount"));
        }
        let destination = record
            .buyer
            .clone()
            .ok_or_else(|| validation_err("lock destination missing"))?;
        let custody_asset = custody_asset(&record);
        let destination_asset = party_asset(&record, &destination);
        transfer_numeric_asset_for_escrow(
            state_transaction,
            VerifiedNativeEscrowMovement::retained(
                record.id.clone(),
                custody_asset,
                destination_asset,
                self.amount.clone(),
            ),
        )?;
        record.remaining_amount = record
            .remaining_amount
            .checked_sub(&self.amount)
            .map_err(|_| validation_err("lock remaining amount underflow"))?;
        if record.remaining_amount.is_zero() {
            record.status = AssetEscrowStatus::DrawnDown;
            record.closed_at_ms = Some(state_transaction.block_unix_timestamp_ms());
        }
        state_transaction
            .world
            .insert_asset_escrow_entry(record.clone());
        state_transaction
            .world
            .emit_events(Some(EscrowEvent::Released(record)));
        Ok(())
    }
}
impl Execute for CancelAssetLock {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        ensure_positive(&self.expected_remaining_amount)?;
        let Some(mut record) = state_transaction
            .world
            .asset_escrows
            .get(&self.escrow_id)
            .cloned()
        else {
            return Err(validation_err("escrow not found"));
        };
        ensure_asset_lock(&record)?;
        reject_native_orderbook_lock(state_transaction.world(), &self.escrow_id, "cancelled")?;
        if record.status != AssetEscrowStatus::Locked {
            return Err(validation_err("only locked asset locks can be cancelled"));
        }
        if &record.seller != authority {
            return Err(validation_err("only lock opener may cancel lock"));
        }
        let spec = state_transaction
            .numeric_spec_for(&record.asset_definition)
            .map_err(Error::from)?;
        assert_numeric_spec_with(self.expected_remaining_amount.as_numeric(), spec)?;
        if record.remaining_amount != self.expected_remaining_amount {
            return Err(validation_err(
                "asset lock remaining amount changed since the cancellation was prepared",
            ));
        }
        let custody_asset = custody_asset(&record);
        let seller_asset = party_asset(&record, &record.seller);
        transfer_numeric_asset_for_escrow(
            state_transaction,
            VerifiedNativeEscrowMovement::retained(
                record.id.clone(),
                custody_asset,
                seller_asset,
                record.remaining_amount.clone(),
            ),
        )?;
        record.status = AssetEscrowStatus::Cancelled;
        record.remaining_amount = Quantity::zero();
        record.closed_at_ms = Some(state_transaction.block_unix_timestamp_ms());
        state_transaction
            .world
            .insert_asset_escrow_entry(record.clone());
        state_transaction
            .world
            .emit_events(Some(EscrowEvent::Cancelled(record)));
        Ok(())
    }
}
impl Execute for ExpireAssetLock {
    fn execute(
        self,
        _authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let Some(mut record) = state_transaction
            .world
            .asset_escrows
            .get(&self.escrow_id)
            .cloned()
        else {
            return Err(validation_err("escrow not found"));
        };
        ensure_asset_lock(&record)?;
        reject_native_orderbook_lock(state_transaction.world(), &self.escrow_id, "expired")?;
        if record.status != AssetEscrowStatus::Locked {
            return Err(validation_err("only locked asset locks can expire"));
        }
        let expires_at_ms = record
            .expires_at_ms
            .ok_or_else(|| validation_err("asset lock has no expiry"))?;
        if state_transaction.block_unix_timestamp_ms() < expires_at_ms {
            return Err(validation_err("asset lock expiry has not been reached"));
        }
        let custody_asset = custody_asset(&record);
        let seller_asset = party_asset(&record, &record.seller);
        transfer_numeric_asset_for_escrow(
            state_transaction,
            VerifiedNativeEscrowMovement::retained(
                record.id.clone(),
                custody_asset,
                seller_asset,
                record.remaining_amount.clone(),
            ),
        )?;
        record.status = AssetEscrowStatus::Expired;
        record.remaining_amount = Quantity::zero();
        record.closed_at_ms = Some(state_transaction.block_unix_timestamp_ms());
        state_transaction
            .world
            .insert_asset_escrow_entry(record.clone());
        state_transaction
            .world
            .emit_events(Some(EscrowEvent::Expired(record)));
        Ok(())
    }
}
const MAX_CONDITIONAL_ESCROW_CONDITIONS: usize = 64;
const MAX_CONDITIONAL_ESCROW_EVIDENCE_HASHES: usize = 64;
const MAX_CONDITIONAL_ESCROW_TEXT_BYTES: usize = 1_024;
fn validate_conditional_escrow_value(value: &ConditionalEscrowValue) -> Result<(), Error> {
    if let ConditionalEscrowValue::Text(value) = value
        && (value.is_empty() || value.len() > MAX_CONDITIONAL_ESCROW_TEXT_BYTES)
    {
        return Err(validation_err(
            "conditional escrow text value must contain 1..=1024 UTF-8 bytes",
        ));
    }
    Ok(())
}
fn conditional_escrow_predicate_matches(
    predicate: &ConditionalEscrowPredicate,
    value: &ConditionalEscrowValue,
) -> bool {
    match (predicate, value) {
        (ConditionalEscrowPredicate::Equals(expected), actual) => expected == actual,
        (
            ConditionalEscrowPredicate::QuantityAtMost(maximum),
            ConditionalEscrowValue::Quantity(actual),
        ) => actual <= maximum,
        _ => false,
    }
}
impl Execute for OpenConditionalEscrow {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        reject_reserved_orderbook_escrow_id(&self.escrow_id)?;
        if state_transaction
            .world
            .asset_escrows
            .get(&self.escrow_id)
            .is_some()
        {
            return Err(validation_err("escrow already exists"));
        }
        ensure_positive(&self.amount)?;
        if self.conditions.is_empty() || self.conditions.len() > MAX_CONDITIONAL_ESCROW_CONDITIONS {
            return Err(validation_err(
                "conditional escrow must contain 1..=64 conditions",
            ));
        }
        if self.evidence_hashes.len() > MAX_CONDITIONAL_ESCROW_EVIDENCE_HASHES {
            return Err(validation_err(
                "conditional escrow may contain at most 64 opening evidence hashes",
            ));
        }
        let created_at_ms = state_transaction.block_unix_timestamp_ms();
        if self.expires_at_ms <= created_at_ms {
            return Err(validation_err(
                "conditional escrow expiry must be later than its committed creation time",
            ));
        }
        let mut condition_ids = BTreeSet::new();
        let mut oracle_sequences = BTreeSet::new();
        let mut oracle_count = 0_u32;
        let mut within_deadline_ms = None::<u64>;
        for condition in &self.conditions {
            if !condition_ids.insert(condition.id().clone()) {
                return Err(validation_err(
                    "conditional escrow condition ids must be unique",
                ));
            }
            match condition {
                ConditionalEscrowCondition::Oracle(condition) => {
                    oracle_count = oracle_count.checked_add(1).ok_or_else(|| {
                        validation_err("conditional escrow oracle count overflow")
                    })?;
                    if !oracle_sequences.insert(condition.sequence.get()) {
                        return Err(validation_err(
                            "conditional escrow oracle sequences must be unique",
                        ));
                    }
                    state_transaction.world.account(&condition.attestor)?;
                    if let ConditionalEscrowPredicate::Equals(value) = &condition.predicate {
                        validate_conditional_escrow_value(value)?;
                    }
                }
                ConditionalEscrowCondition::Within(condition) => {
                    if within_deadline_ms.is_some() {
                        return Err(validation_err(
                            "conditional escrow may contain at most one ledger-time window",
                        ));
                    }
                    let deadline = created_at_ms
                        .checked_add(condition.duration_ms.get())
                        .ok_or_else(|| {
                            validation_err("conditional escrow within deadline overflow")
                        })?;
                    within_deadline_ms = Some(deadline);
                }
            }
        }
        if oracle_count == 0 {
            return Err(validation_err(
                "conditional escrow must contain at least one oracle condition",
            ));
        }
        let expected_sequences = (1..=oracle_count).collect::<BTreeSet<_>>();
        if oracle_sequences != expected_sequences {
            return Err(validation_err(
                "conditional escrow oracle sequences must be contiguous starting at one",
            ));
        }
        let effective_expiry_ms = within_deadline_ms.map_or(self.expires_at_ms, |deadline| {
            deadline.min(self.expires_at_ms)
        });
        if effective_expiry_ms <= created_at_ms {
            return Err(validation_err(
                "conditional escrow effective expiry must be in the future",
            ));
        }
        let spec = state_transaction
            .numeric_spec_for(&self.asset_definition)
            .map_err(Error::from)?;
        assert_numeric_spec_with(self.amount.as_numeric(), spec)?;
        state_transaction.world.account(authority)?;
        state_transaction.world.account(&self.beneficiary)?;
        state_transaction
            .world
            .asset_definition(&self.asset_definition)?;
        let custody = escrow_custody_account_id(
            state_transaction.network_id(),
            &self.escrow_id,
            &self.asset_definition,
        )?;
        let source_asset = AssetId::new(self.asset_definition.clone(), authority.clone());
        let custody_asset = AssetId::new(self.asset_definition.clone(), custody.clone());
        let custody_created = ensure_custody_account(&custody, state_transaction)?;
        let transfer_result = transfer_numeric_asset_for_escrow(
            state_transaction,
            VerifiedNativeEscrowMovement::funding(
                self.escrow_id.clone(),
                authority.clone(),
                source_asset,
                custody_asset,
                self.amount.clone(),
            ),
        );
        if transfer_result.is_err() && custody_created {
            state_transaction.world.accounts.remove(custody.clone());
        }
        transfer_result?;
        let record = AssetEscrowRecord {
            id: self.escrow_id,
            seller: authority.clone(),
            buyer: Some(self.beneficiary),
            asset_definition: self.asset_definition,
            amount: self.amount.clone(),
            custody,
            status: AssetEscrowStatus::Locked,
            kind: AssetEscrowKind::Conditional,
            remaining_amount: self.amount,
            release_authority: None,
            expires_at_ms: Some(effective_expiry_ms),
            evidence_hashes: self.evidence_hashes,
            conditions: self
                .conditions
                .into_iter()
                .map(|condition| ConditionalEscrowConditionState {
                    condition,
                    attestation: None,
                    satisfied_at_ms: None,
                })
                .collect(),
            created_at_ms,
            accepted_at_ms: None,
            payment_sent_at_ms: None,
            disputed_at_ms: None,
            closed_at_ms: None,
            resolution: None,
        };
        state_transaction
            .world
            .insert_asset_escrow_entry(record.clone());
        state_transaction
            .world
            .emit_events(Some(EscrowEvent::Opened(record)));
        Ok(())
    }
}
impl Execute for AttestEscrowCondition {
    fn execute(
        self,
        authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let Some(mut record) = state_transaction
            .world
            .asset_escrows
            .get(&self.escrow_id)
            .cloned()
        else {
            return Err(validation_err("escrow not found"));
        };
        ensure_conditional_escrow(&record)?;
        if record.status != AssetEscrowStatus::Locked {
            return Err(validation_err(
                "only locked conditional escrows can be attested",
            ));
        }
        let now_ms = state_transaction.block_unix_timestamp_ms();
        let expires_at_ms = record
            .expires_at_ms
            .ok_or_else(|| validation_err("conditional escrow has no authoritative expiry"))?;
        if now_ms >= expires_at_ms {
            return Err(validation_err(
                "conditional escrow attestation is at or after its expiry",
            ));
        }
        validate_conditional_escrow_value(&self.value)?;
        let condition_index = record
            .conditions
            .iter()
            .position(|state| state.condition.id() == &self.condition_id)
            .ok_or_else(|| validation_err("conditional escrow condition not found"))?;
        let (attestor, predicate, sequence) =
            match record.conditions[condition_index].condition.clone() {
                ConditionalEscrowCondition::Oracle(condition) => (
                    condition.attestor,
                    condition.predicate,
                    condition.sequence.get(),
                ),
                ConditionalEscrowCondition::Within(_) => {
                    return Err(validation_err(
                        "ledger-time conditions cannot be attested by an account",
                    ));
                }
            };
        if &attestor != authority {
            return Err(validation_err(
                "only the exact configured attestor may attest this condition",
            ));
        }
        if record.conditions[condition_index].attestation.is_some()
            || record.conditions[condition_index].satisfied_at_ms.is_some()
        {
            return Err(validation_err(
                "conditional escrow condition is already satisfied",
            ));
        }
        let next_sequence = record
            .conditions
            .iter()
            .filter_map(|state| match &state.condition {
                ConditionalEscrowCondition::Oracle(condition)
                    if state.satisfied_at_ms.is_none() =>
                {
                    Some(condition.sequence.get())
                }
                _ => None,
            })
            .min()
            .ok_or_else(|| validation_err("conditional escrow has no pending oracle condition"))?;
        if sequence != next_sequence {
            return Err(validation_err(
                "conditional escrow conditions must be attested in exact sequence",
            ));
        }
        if !conditional_escrow_predicate_matches(&predicate, &self.value) {
            return Err(validation_err(
                "conditional escrow attestation does not satisfy its typed predicate",
            ));
        }
        record.conditions[condition_index].attestation = Some(ConditionalEscrowAttestation {
            attestor: authority.clone(),
            value: self.value,
            evidence_hash: self.evidence_hash,
            committed_at_ms: now_ms,
        });
        record.conditions[condition_index].satisfied_at_ms = Some(now_ms);
        let all_oracles_satisfied = record.conditions.iter().all(|state| {
            matches!(&state.condition, ConditionalEscrowCondition::Within(_))
                || state.satisfied_at_ms.is_some()
        });
        if all_oracles_satisfied {
            for state in &mut record.conditions {
                if matches!(&state.condition, ConditionalEscrowCondition::Within(_)) {
                    state.satisfied_at_ms = Some(now_ms);
                }
            }
        }
        let automatically_released = record
            .conditions
            .iter()
            .all(|state| state.satisfied_at_ms.is_some());
        if automatically_released {
            let destination = record
                .buyer
                .clone()
                .ok_or_else(|| validation_err("conditional escrow beneficiary missing"))?;
            let custody_asset = custody_asset(&record);
            let destination_asset = party_asset(&record, &destination);
            transfer_numeric_asset_for_escrow(
                state_transaction,
                VerifiedNativeEscrowMovement::retained(
                    record.id.clone(),
                    custody_asset,
                    destination_asset,
                    record.remaining_amount.clone(),
                ),
            )?;
            record.remaining_amount = Quantity::zero();
            record.status = AssetEscrowStatus::Released;
            record.closed_at_ms = Some(now_ms);
        }
        state_transaction
            .world
            .insert_asset_escrow_entry(record.clone());
        state_transaction
            .world
            .emit_events(Some(EscrowEvent::Attested(ConditionalEscrowAttested {
                escrow: record.clone(),
                condition_id: self.condition_id,
                attestor: authority.clone(),
                automatically_released,
            })));
        if automatically_released {
            state_transaction
                .world
                .emit_events(Some(EscrowEvent::Released(record)));
        }
        Ok(())
    }
}
impl Execute for ExpireConditionalEscrow {
    fn execute(
        self,
        _authority: &AccountId,
        state_transaction: &mut StateTransaction<'_, '_>,
    ) -> Result<(), Error> {
        let Some(mut record) = state_transaction
            .world
            .asset_escrows
            .get(&self.escrow_id)
            .cloned()
        else {
            return Err(validation_err("escrow not found"));
        };
        ensure_conditional_escrow(&record)?;
        if record.status != AssetEscrowStatus::Locked {
            return Err(validation_err("only locked conditional escrows can expire"));
        }
        let expires_at_ms = record
            .expires_at_ms
            .ok_or_else(|| validation_err("conditional escrow has no authoritative expiry"))?;
        let now_ms = state_transaction.block_unix_timestamp_ms();
        if now_ms < expires_at_ms {
            return Err(validation_err(
                "conditional escrow expiry has not been reached",
            ));
        }
        let custody_asset = custody_asset(&record);
        let seller_asset = party_asset(&record, &record.seller);
        transfer_numeric_asset_for_escrow(
            state_transaction,
            VerifiedNativeEscrowMovement::retained(
                record.id.clone(),
                custody_asset,
                seller_asset,
                record.remaining_amount.clone(),
            ),
        )?;
        record.status = AssetEscrowStatus::Expired;
        record.remaining_amount = Quantity::zero();
        record.closed_at_ms = Some(now_ms);
        state_transaction
            .world
            .insert_asset_escrow_entry(record.clone());
        state_transaction
            .world
            .emit_events(Some(EscrowEvent::Expired(record)));
        Ok(())
    }
}
#[derive(Clone, Copy)]
enum AssetEscrowAccountIndex {
    Seller,
    Buyer,
}
fn asset_escrow_account_index(field: &str) -> Option<AssetEscrowAccountIndex> {
    match field {
        "seller" => Some(AssetEscrowAccountIndex::Seller),
        "buyer" => Some(AssetEscrowAccountIndex::Buyer),
        _ => None,
    }
}
fn asset_escrow_id_from_value(value: &Value) -> Option<EscrowId> {
    norito::json::from_value(value.clone()).ok()
}
fn account_id_from_value(value: &Value) -> Option<AccountId> {
    norito::json::from_value(value.clone()).ok()
}
fn asset_escrow_status_from_value(value: &Value) -> Option<AssetEscrowStatus> {
    norito::json::from_value(value.clone()).ok()
}
fn asset_escrow_ids_for_accounts(
    world: &impl WorldReadOnly,
    index: AssetEscrowAccountIndex,
    accounts: impl IntoIterator<Item = AccountId>,
) -> BTreeSet<EscrowId> {
    let mut ids = BTreeSet::new();
    for account_id in accounts {
        let escrow_ids = match index {
            AssetEscrowAccountIndex::Seller => world.asset_escrows_by_seller().get(&account_id),
            AssetEscrowAccountIndex::Buyer => world.asset_escrows_by_buyer().get(&account_id),
        };
        if let Some(escrow_ids) = escrow_ids {
            ids.extend(escrow_ids.iter().copied());
        }
    }
    ids
}
fn asset_escrow_ids_for_statuses(
    world: &impl WorldReadOnly,
    statuses: impl IntoIterator<Item = AssetEscrowStatus>,
) -> BTreeSet<EscrowId> {
    let mut ids = BTreeSet::new();
    for status in statuses {
        if let Some(escrow_ids) = world.asset_escrows_by_status().get(&status) {
            ids.extend(escrow_ids.iter().copied());
        }
    }
    ids
}
fn asset_escrow_candidate_ids(
    predicate: &PredicateJson,
    world: &impl WorldReadOnly,
) -> Option<BTreeSet<EscrowId>> {
    let mut best = None;
    for cond in &predicate.equals {
        if cond.field == "id" {
            intersect_candidate_ids(
                &mut best,
                asset_escrow_id_from_value(&cond.value)
                    .into_iter()
                    .collect(),
            );
            continue;
        }
        if let Some(index) = asset_escrow_account_index(&cond.field) {
            intersect_candidate_ids(
                &mut best,
                asset_escrow_ids_for_accounts(world, index, account_id_from_value(&cond.value)),
            );
            continue;
        }
        if cond.field == "status" {
            intersect_candidate_ids(
                &mut best,
                asset_escrow_ids_for_statuses(world, asset_escrow_status_from_value(&cond.value)),
            );
        }
    }
    for cond in &predicate.r#in {
        if cond.field == "id" {
            intersect_candidate_ids(
                &mut best,
                cond.values
                    .iter()
                    .filter_map(asset_escrow_id_from_value)
                    .collect(),
            );
            continue;
        }
        if let Some(index) = asset_escrow_account_index(&cond.field) {
            intersect_candidate_ids(
                &mut best,
                asset_escrow_ids_for_accounts(
                    world,
                    index,
                    cond.values.iter().filter_map(account_id_from_value),
                ),
            );
            continue;
        }
        if cond.field == "status" {
            intersect_candidate_ids(
                &mut best,
                asset_escrow_ids_for_statuses(
                    world,
                    cond.values
                        .iter()
                        .filter_map(asset_escrow_status_from_value),
                ),
            );
        }
    }
    best
}
impl ValidQuery for FindAssetEscrows {
    fn execute(
        self,
        filter: CompoundPredicate<AssetEscrowRecord>,
        state_ro: &impl StateReadOnly,
    ) -> Result<impl Iterator<Item = AssetEscrowRecord>, QueryExecutionFail> {
        let world = state_ro.world();
        let predicate_json = filter
            .json_payload()
            .and_then(iroha_data_model::query::json::predicate_json_candidate_plan_for_execution);
        if let Some(candidate_ids) = predicate_json
            .as_ref()
            .and_then(|predicate| asset_escrow_candidate_ids(predicate, world))
        {
            let iter: Box<dyn Iterator<Item = AssetEscrowRecord> + '_> =
                Box::new(candidate_ids.into_iter().filter_map(move |escrow_id| {
                    world
                        .asset_escrows()
                        .get(&escrow_id)
                        .filter(|record| filter.applies(*record))
                        .cloned()
                }));
            return Ok(iter);
        }
        let iter: Box<dyn Iterator<Item = AssetEscrowRecord> + '_> = Box::new(
            world
                .asset_escrows()
                .iter()
                .filter_map(move |(_, record)| filter.applies(record).then(|| record.clone())),
        );
        Ok(iter)
    }
}
impl ValidSingularQuery for FindAssetEscrowById {
    fn execute(
        &self,
        state_ro: &impl StateReadOnly,
    ) -> Result<AssetEscrowRecord, QueryExecutionFail> {
        state_ro
            .world()
            .asset_escrows()
            .get(&self.escrow_id)
            .ok_or_else(|| QueryExecutionFail::Find(FindError::AssetEscrow(self.escrow_id)))
            .and_then(crate::smartcontracts::isi::query::own_singular_query_value)
    }
}
impl ValidQuery for FindAssetEscrowsBySeller {
    fn execute(
        self,
        filter: CompoundPredicate<AssetEscrowRecord>,
        state_ro: &impl StateReadOnly,
    ) -> Result<impl Iterator<Item = AssetEscrowRecord>, QueryExecutionFail> {
        let seller = self.seller;
        let world = state_ro.world();
        Ok(world
            .asset_escrows_by_seller()
            .get(&seller)
            .into_iter()
            .flat_map(BTreeSet::iter)
            .filter_map(move |escrow_id| world.asset_escrows().get(escrow_id).cloned())
            .filter(move |record| filter.applies(record)))
    }
}
impl ValidQuery for FindAssetEscrowsByBuyer {
    fn execute(
        self,
        filter: CompoundPredicate<AssetEscrowRecord>,
        state_ro: &impl StateReadOnly,
    ) -> Result<impl Iterator<Item = AssetEscrowRecord>, QueryExecutionFail> {
        let buyer = self.buyer;
        let world = state_ro.world();
        Ok(world
            .asset_escrows_by_buyer()
            .get(&buyer)
            .into_iter()
            .flat_map(BTreeSet::iter)
            .filter_map(move |escrow_id| world.asset_escrows().get(escrow_id).cloned())
            .filter(move |record| filter.applies(record)))
    }
}
impl ValidQuery for FindAssetEscrowsByStatus {
    fn execute(
        self,
        filter: CompoundPredicate<AssetEscrowRecord>,
        state_ro: &impl StateReadOnly,
    ) -> Result<impl Iterator<Item = AssetEscrowRecord>, QueryExecutionFail> {
        let status = self.status;
        let world = state_ro.world();
        Ok(world
            .asset_escrows_by_status()
            .get(&status)
            .into_iter()
            .flat_map(BTreeSet::iter)
            .filter_map(move |escrow_id| world.asset_escrows().get(escrow_id).cloned())
            .filter(move |record| filter.applies(record)))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{kura::Kura, query::store::LiveQueryStore, state::State};
    use iroha_data_model::{
        Registrable,
        asset::{
            ASSET_ISSUER_USAGE_POLICY_METADATA_KEY, Asset, AssetDefinition,
            AssetIssuerUsagePolicyV1, AssetSubjectBindingV1, AssetTransferAvailability,
            definition::AssetConfidentialPolicy,
        },
        domain::Domain,
        events::{EventBox, data::prelude as data_pre},
        isi::{
            Burn, SetAssetTransferAvailability, Transfer, Unregister,
            account_recovery::ReplaceAccountController, error::InstructionExecutionError,
        },
        permission::Permissions,
    };
    use iroha_executor_data_model::permission::{Permission as _, escrow::CanResolveEscrowDispute};
    use iroha_model_base::domain::DomainId;
    use iroha_primitives::{json::Json, numeric::Numeric};
    use std::collections::BTreeMap;
    fn fixture_account(label: &str) -> AccountId {
        let seed: Vec<u8> = label.as_bytes().iter().copied().cycle().take(32).collect();
        let (public_key, _) = KeyPair::try_from_seed(seed, Algorithm::Ed25519)
            .expect("derive escrow fixture account key")
            .into_parts();
        AccountId::new(public_key)
    }
    fn fixture_asset_definition_domain() -> DomainId {
        DomainId::try_new("aitai", "universal").expect("domain id")
    }
    fn fixture_asset_definition_id() -> AssetDefinitionId {
        AssetDefinitionId::derive_from_components(
            fixture_asset_definition_domain(),
            "xor".parse().expect("asset name"),
        )
    }
    fn fixture_escrow_id(label: &str) -> EscrowId {
        EscrowId::new(Hash::new(format!("native-escrow-test:{label}")))
    }
    fn escrow_test_network_id(seed: u8) -> iroha_data_model::NetworkId {
        iroha_data_model::NetworkId::from_genesis_hash(
            HashOf::<iroha_data_model::block::BlockHeader>::from_untyped_unchecked(
                Hash::prehashed([seed; Hash::LENGTH]),
            ),
        )
    }
    fn block_header(timestamp_ms: u64) -> iroha_data_model::block::BlockHeader {
        iroha_data_model::block::BlockHeader::new(
            nonzero_ext::nonzero!(1_u64),
            None,
            None,
            timestamp_ms,
            0,
        )
    }
    // Direct ISI component tests explicitly retain a bounded source invocation
    // before borrowing State. This grants no Network or publication authority;
    // executor_asset_lock_admission_tests exercises signed certified execution.
    fn state_with_parties(
        seller: &AccountId,
        buyer: &AccountId,
        court: &AccountId,
        asset_definition: &AssetDefinitionId,
        seller_balance: Quantity,
    ) -> State {
        let asset_definition_entry = AssetDefinition::numeric(
            asset_definition.clone(),
            "XOR".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(seller);
        state_with_parties_and_definition(
            seller,
            buyer,
            court,
            asset_definition,
            asset_definition_entry,
            seller_balance,
        )
    }
    fn state_with_parties_and_definition(
        seller: &AccountId,
        buyer: &AccountId,
        court: &AccountId,
        asset_definition: &AssetDefinitionId,
        asset_definition_entry: AssetDefinition,
        seller_balance: Quantity,
    ) -> State {
        let domain = Domain::new(fixture_asset_definition_domain()).build(seller);
        let seller_asset_id = AssetId::of(asset_definition.clone(), seller.clone());
        let seller_asset = Asset::new(seller_asset_id, seller_balance);
        let world = crate::state::World::with_assets(
            [domain],
            [
                Account::new(seller.clone()).build(seller),
                Account::new(buyer.clone()).build(buyer),
                Account::new(court.clone()).build(court),
            ],
            [asset_definition_entry],
            [seller_asset],
            [],
        );
        State::new_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        )
    }

    #[test]
    fn escrow_funding_requires_its_original_retained_invocation() {
        let seller = fixture_account("seller");
        let buyer = fixture_account("buyer");
        let court = fixture_account("court");
        let asset_definition = fixture_asset_definition_id();
        let escrow_id = fixture_escrow_id("retained-invocation");
        let state = state_with_parties(
            &seller,
            &buyer,
            &court,
            &asset_definition,
            Quantity::from(100_u32),
        );
        let call_hash = Hash::new(b"original-escrow-funding-invocation");
        let instruction = OpenAssetEscrow {
            escrow_id,
            asset_definition: asset_definition.clone(),
            amount: Quantity::from(40_u32),
            evidence_hashes: Vec::new(),
        };
        // Missing invocation custody poisons its carrier. Keep that refusal intact;
        // a successful independent component attempt needs its own pristine owner.
        {
            let mut block = state.block(block_header(1_000));
            let mut unretained = block.transaction();
            unretained.tx_call_hash = Some(call_hash);
            let error = instruction
                .clone()
                .execute(&seller, &mut unretained)
                .expect_err("a hash alone does not own its invocation");
            assert!(
                error
                    .to_string()
                    .contains("no retained producer invocation"),
                "unexpected source refusal: {error}"
            );
            assert_eq!(
                balance(&unretained, &seller, &asset_definition),
                Quantity::from(100_u32)
            );
            assert!(unretained.world.asset_escrows.get(&escrow_id).is_none());
            drop(unretained);
            assert_eq!(block.committed_fragment_count(), 0);
        }
        let mut block = state.block(block_header(1_000));
        let mut retained = block.transaction_for_fastpq_testing(call_hash);
        instruction
            .execute(&seller, &mut retained)
            .expect("original bounded invocation permits escrow funding");
        assert_eq!(
            balance(&retained, &seller, &asset_definition),
            Quantity::from(60_u32)
        );
        assert_eq!(
            escrow_record(&retained, &escrow_id).remaining_amount,
            Quantity::from(40_u32)
        );
    }
    fn balance(
        state_transaction: &StateTransaction<'_, '_>,
        account: &AccountId,
        asset_definition: &AssetDefinitionId,
    ) -> Quantity {
        let asset_id = AssetId::of(asset_definition.clone(), account.clone());
        state_transaction
            .world
            .assets
            .get(&asset_id)
            .map(|value| value.as_ref().clone())
            .unwrap_or_else(Quantity::zero)
    }
    fn asset_transfer_events(events: &[EventBox]) -> Vec<(&'static str, AssetId, Quantity)> {
        events
            .iter()
            .filter_map(|event| {
                let EventBox::Data(data_event) = event else {
                    return None;
                };
                let asset_event = match data_event.as_ref() {
                    data_pre::DataEvent::Asset(event) => event,
                    data_pre::DataEvent::Domain(data_pre::DomainEvent::Asset(scoped)) => {
                        &scoped.event
                    }
                    _ => return None,
                };
                match asset_event {
                    data_pre::AssetEvent::Removed(changed) => {
                        Some(("removed", changed.asset().clone(), changed.amount().clone()))
                    }
                    data_pre::AssetEvent::Added(changed) => {
                        Some(("added", changed.asset().clone(), changed.amount().clone()))
                    }
                    _ => None,
                }
            })
            .collect()
    }
    fn assert_asset_transfer_event(
        events: &[(&'static str, AssetId, Quantity)],
        kind: &'static str,
        asset: &AssetId,
        amount: &Quantity,
    ) {
        assert!(
            events
                .iter()
                .any(|(event_kind, event_asset, event_amount)| {
                    *event_kind == kind && event_asset == asset && event_amount == amount
                }),
            "missing {kind} event for {asset} amount {amount}; events: {events:?}"
        );
    }
    fn assert_transfer_delta(
        delta: &TransferDeltaTranscript,
        from: &AccountId,
        to: &AccountId,
        asset_definition: &AssetDefinitionId,
        amount: &Quantity,
    ) {
        assert_eq!(&delta.from_account, from);
        assert_eq!(&delta.to_account, to);
        assert_eq!(&delta.asset_definition, asset_definition);
        assert_eq!(&delta.amount, amount);
    }
    fn escrow_record(
        state_transaction: &StateTransaction<'_, '_>,
        escrow_id: &EscrowId,
    ) -> AssetEscrowRecord {
        state_transaction
            .world
            .asset_escrows
            .get(escrow_id)
            .cloned()
            .expect("escrow record")
    }
    fn query_asset_escrow_ids(
        state_transaction: &StateTransaction<'_, '_>,
        predicate: CompoundPredicate<AssetEscrowRecord>,
    ) -> Vec<EscrowId> {
        FindAssetEscrows
            .execute(predicate, state_transaction)
            .expect("query asset escrows")
            .map(|record| record.id)
            .collect()
    }
    fn parse_predicate_json<T>(
        predicate: &CompoundPredicate<T>,
    ) -> iroha_data_model::query::json::PredicateJson {
        predicate
            .json_payload()
            .and_then(|raw| {
                norito::json::from_str::<iroha_data_model::query::json::PredicateJson>(raw).ok()
            })
            .expect("predicate JSON")
    }
    fn asset_escrow_fixture(
        escrow_id: EscrowId,
        seller: AccountId,
        buyer: Option<AccountId>,
        asset_definition: AssetDefinitionId,
        status: AssetEscrowStatus,
    ) -> AssetEscrowRecord {
        AssetEscrowRecord {
            id: escrow_id,
            seller,
            buyer,
            asset_definition,
            amount: Quantity::one(),
            custody: fixture_account("asset-escrow-custody"),
            status,
            kind: AssetEscrowKind::Marketplace,
            remaining_amount: Quantity::one(),
            release_authority: None,
            expires_at_ms: None,
            evidence_hashes: Vec::new(),
            conditions: Vec::new(),
            created_at_ms: 1,
            accepted_at_ms: None,
            payment_sent_at_ms: None,
            disputed_at_ms: None,
            closed_at_ms: None,
            resolution: None,
        }
    }
    fn grant_court_permission(state_transaction: &mut StateTransaction<'_, '_>, court: &AccountId) {
        let mut permissions = Permissions::default();
        permissions.insert(CanResolveEscrowDispute.into());
        state_transaction
            .world
            .account_permissions
            .insert(court.clone(), permissions);
    }
    fn state_transaction_deposit_closed_custody_dust(
        state_transaction: &mut StateTransaction<'_, '_>,
        custody_asset: &AssetId,
        amount: Quantity,
    ) {
        crate::smartcontracts::isi::asset::isi::seed_numeric_asset_balance_for_test(
            &mut state_transaction.world,
            custody_asset,
            &amount,
        )
        .expect("deposit closed custody dust");
    }
    fn disable_outbound_asset_transfers(
        state_transaction: &mut StateTransaction<'_, '_>,
        authority: &AccountId,
        account: &AccountId,
        asset_definition: &AssetDefinitionId,
    ) {
        SetAssetTransferAvailability::new(
            account.clone(),
            asset_definition.clone(),
            0,
            AssetTransferAvailability::Enabled,
            AssetTransferAvailability::Disabled,
            Some("escrow custody hold".to_owned()),
        )
        .execute(authority, state_transaction)
        .expect("disable outbound asset transfers");
    }
    #[test]
    fn court_permission_constant_matches_typed_permission() {
        assert_eq!(
            CanResolveEscrowDispute::name().as_str(),
            CAN_RESOLVE_ESCROW_DISPUTE
        );
    }
    #[test]
    fn custody_account_derivation_is_stable() {
        let network_id = escrow_test_network_id(1);
        let asset_definition: AssetDefinitionId =
            "61CtjvNd9T3THAR65GsMVHr82Bjc".parse().expect("asset");
        let escrow_id = EscrowId::new(Hash::new("escrow"));
        let custody = escrow_custody_account_id(&network_id, &escrow_id, &asset_definition)
            .expect("custody account derivation succeeds");
        assert_eq!(
            custody,
            escrow_custody_account_id(&network_id, &escrow_id, &asset_definition)
                .expect("custody account derivation is repeatable")
        );
        assert_ne!(
            custody,
            escrow_custody_account_id(&escrow_test_network_id(2), &escrow_id, &asset_definition,)
                .expect("different exact network custody derivation succeeds"),
            "same-label deployments with different genesis hashes need disjoint custody",
        );
        let mut public_seed_material = Vec::new();
        public_seed_material.extend_from_slice(ESCROW_CUSTODY_ACCOUNT_DOMAIN.as_bytes());
        public_seed_material.extend_from_slice(network_id.as_bytes());
        public_seed_material.extend_from_slice(escrow_id.as_hash().as_ref());
        public_seed_material.extend_from_slice(asset_definition.to_string().as_bytes());
        let public_seed: [u8; Hash::LENGTH] = Hash::new(public_seed_material).into();
        let public_seed_keypair = KeyPair::try_from_seed(public_seed.to_vec(), Algorithm::Ed25519)
            .expect("public seed derives");
        assert_ne!(
            custody,
            AccountId::new(public_seed_keypair.public_key().clone()),
            "protocol custody must not expose a signing key through public seed derivation"
        );
    }
    #[test]
    fn every_public_escrow_creator_common_gate_rejects_both_orderbook_namespaces() {
        let order_lock = iroha_data_model::sorafs::orderbook::orderbook_order_escrow_id([0x41; 32]);
        let channel_lock =
            iroha_data_model::sorafs::orderbook::orderbook_settlement_escrow_id([0x42; 32]);
        for reserved in [order_lock, channel_lock] {
            let err = reject_reserved_orderbook_escrow_id(&reserved)
                .expect_err("reserved namespace must be native-only");
            assert!(
                err.to_string().contains("reserved SoraFS orderbook"),
                "unexpected error: {err}"
            );
        }
        assert!(
            reject_reserved_orderbook_escrow_id(&fixture_escrow_id("ordinary-public-escrow"))
                .is_ok()
        );
    }
    #[test]
    fn resolution_split_must_equal_escrow_amount() {
        let total = Quantity::from(100_u32);
        assert!(
            ensure_resolution_split(&total, &Quantity::from(40_u32), &Quantity::from(60_u32))
                .is_ok()
        );
        assert!(
            ensure_resolution_split(&total, &Quantity::from(40_u32), &Quantity::from(59_u32))
                .is_err()
        );
        assert!(
            Quantity::try_from_numeric(Numeric::new(-1_i32, 0)).is_err(),
            "negative escrow splits must fail at the nominal quantity boundary"
        );
    }
    #[test]
    fn escrow_open_rejects_shielded_only_asset() {
        let seller = fixture_account("seller");
        let buyer = fixture_account("buyer");
        let court = fixture_account("court");
        let asset_definition = fixture_asset_definition_id();
        let escrow_id = fixture_escrow_id("shielded-open");
        let mut asset_definition_entry = AssetDefinition::numeric(
            asset_definition.clone(),
            "XOR".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&seller);
        asset_definition_entry.set_confidential_policy(AssetConfidentialPolicy::shielded_only());
        let state = state_with_parties_and_definition(
            &seller,
            &buyer,
            &court,
            &asset_definition,
            asset_definition_entry,
            Quantity::from(100_u32),
        );
        let mut block = state.block(block_header(1_000));
        let mut tx = block.transaction();
        let err = OpenAssetEscrow {
            escrow_id,
            asset_definition: asset_definition.clone(),
            amount: Quantity::from(40_u32),
            evidence_hashes: Vec::new(),
        }
        .execute(&seller, &mut tx)
        .expect_err("shielded-only assets cannot enter transparent escrow custody");
        assert!(
            err.to_string()
                .contains("transparent transfer not permitted by policy"),
            "unexpected error: {err}"
        );
        assert!(tx.world.asset_escrows.get(&escrow_id).is_none());
        assert_eq!(
            balance(&tx, &seller, &asset_definition),
            Quantity::from(100_u32)
        );
        let custody = escrow_custody_account_id(tx.network_id(), &escrow_id, &asset_definition)
            .expect("custody account derivation succeeds");
        assert_eq!(balance(&tx, &custody, &asset_definition), Quantity::zero());
    }
    #[test]
    fn escrow_open_rejects_issuer_policy_without_custody_binding() {
        let seller = fixture_account("seller");
        let buyer = fixture_account("buyer");
        let court = fixture_account("court");
        let asset_definition = fixture_asset_definition_id();
        let escrow_id = fixture_escrow_id("issuer-policy-open");
        let mut asset_definition_entry = AssetDefinition::numeric(
            asset_definition.clone(),
            "XOR".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
        .build(&seller);
        let issuer_policy = AssetIssuerUsagePolicyV1 {
            require_subject_binding: true,
            subject_bindings: BTreeMap::from([(seller.clone(), AssetSubjectBindingV1::default())]),
        };
        asset_definition_entry.metadata_mut().insert(
            ASSET_ISSUER_USAGE_POLICY_METADATA_KEY
                .parse()
                .expect("metadata key"),
            Json::new(issuer_policy),
        );
        let state = state_with_parties_and_definition(
            &seller,
            &buyer,
            &court,
            &asset_definition,
            asset_definition_entry,
            Quantity::from(100_u32),
        );
        let mut block = state.block(block_header(1_000));
        let mut tx = block.transaction();
        let err = OpenAssetEscrow {
            escrow_id,
            asset_definition: asset_definition.clone(),
            amount: Quantity::from(40_u32),
            evidence_hashes: Vec::new(),
        }
        .execute(&seller, &mut tx)
        .expect_err("issuer policy must apply to escrow custody account");
        assert!(
            err.to_string()
                .contains("requires explicit subject binding"),
            "unexpected error: {err}"
        );
        assert!(tx.world.asset_escrows.get(&escrow_id).is_none());
        assert_eq!(
            balance(&tx, &seller, &asset_definition),
            Quantity::from(100_u32)
        );
    }
    #[test]
    fn escrow_open_rejects_disabled_outbound_asset() {
        let seller = fixture_account("seller");
        let buyer = fixture_account("buyer");
        let court = fixture_account("court");
        let asset_definition = fixture_asset_definition_id();
        let escrow_id = fixture_escrow_id("disabled-outbound-open");
        let state = state_with_parties(
            &seller,
            &buyer,
            &court,
            &asset_definition,
            Quantity::from(100_u32),
        );
        let mut block = state.block(block_header(1_000));
        let mut tx = block.transaction();
        SetAssetTransferAvailability::new(
            seller.clone(),
            asset_definition.clone(),
            0,
            AssetTransferAvailability::Enabled,
            AssetTransferAvailability::Disabled,
            Some("compliance hold".to_owned()),
        )
        .execute(&seller, &mut tx)
        .expect("outbound disable succeeds");
        let err = OpenAssetEscrow {
            escrow_id,
            asset_definition: asset_definition.clone(),
            amount: Quantity::from(40_u32),
            evidence_hashes: Vec::new(),
        }
        .execute(&seller, &mut tx)
        .expect_err("outbound transfer controls must apply to escrow opening");
        assert!(
            matches!(
                err,
                InstructionExecutionError::AssetTransferAdmission(
                    iroha_data_model::isi::error::AssetTransferAdmissionError::OutgoingDisabled(_)
                )
            ),
            "unexpected error: {err}"
        );
        assert!(tx.world.asset_escrows.get(&escrow_id).is_none());
        assert_eq!(
            balance(&tx, &seller, &asset_definition),
            Quantity::from(100_u32)
        );
    }
    #[test]
    fn escrow_open_accept_mark_and_release_moves_custody_to_buyer() {
        let seller = fixture_account("seller");
        let buyer = fixture_account("buyer");
        let court = fixture_account("court");
        let asset_definition = fixture_asset_definition_id();
        let escrow_id = fixture_escrow_id("release");
        let amount = Quantity::from(40_u32);
        let state = state_with_parties(
            &seller,
            &buyer,
            &court,
            &asset_definition,
            Quantity::from(100_u32),
        );
        let mut block = state.block(block_header(1_000));
        let mut tx = block.transaction_for_fastpq_testing(Hash::prehashed([0xA2; Hash::LENGTH]));
        OpenAssetEscrow {
            escrow_id,
            asset_definition: asset_definition.clone(),
            amount: amount.clone(),
            evidence_hashes: Vec::new(),
        }
        .execute(&seller, &mut tx)
        .expect("open escrow");
        let record = escrow_record(&tx, &escrow_id);
        assert_eq!(record.status, AssetEscrowStatus::Open);
        assert_eq!(
            balance(&tx, &seller, &asset_definition),
            Quantity::from(60_u32)
        );
        assert_eq!(balance(&tx, &record.custody, &asset_definition), amount);
        AcceptAssetEscrow { escrow_id }
            .execute(&buyer, &mut tx)
            .expect("accept escrow");
        MarkEscrowPaymentSent { escrow_id }
            .execute(&buyer, &mut tx)
            .expect("mark payment sent");
        ReleaseAssetEscrow { escrow_id }
            .execute(&seller, &mut tx)
            .expect("release escrow");
        let record = escrow_record(&tx, &escrow_id);
        assert_eq!(record.status, AssetEscrowStatus::Released);
        assert_eq!(
            balance(&tx, &buyer, &asset_definition),
            Quantity::from(40_u32)
        );
        assert_eq!(
            balance(&tx, &record.custody, &asset_definition),
            Quantity::zero()
        );
    }
    #[test]
    fn asset_lock_drawdown_respects_release_authority_and_tracks_remaining() {
        let source = fixture_account("lock-source");
        let destination = fixture_account("lock-destination");
        let release_authority = fixture_account("lock-release-authority");
        let asset_definition = fixture_asset_definition_id();
        let escrow_id = fixture_escrow_id("lock-drawdown-authority");
        let amount = Quantity::from(40_u32);
        let state = state_with_parties(
            &source,
            &destination,
            &release_authority,
            &asset_definition,
            Quantity::from(100_u32),
        );
        let mut block = state.block(block_header(1_000));
        let mut tx = block.transaction_for_fastpq_testing(Hash::prehashed([0xC1; Hash::LENGTH]));
        OpenAssetLock::with_options(
            escrow_id,
            asset_definition.clone(),
            destination.clone(),
            amount.clone(),
            Some(release_authority.clone()),
            None,
            vec![Hash::new("lock-open-evidence")],
        )
        .execute(&source, &mut tx)
        .expect("open asset lock");
        let record = escrow_record(&tx, &escrow_id);
        assert_eq!(record.kind, AssetEscrowKind::Lock);
        assert_eq!(record.status, AssetEscrowStatus::Locked);
        assert_eq!(record.remaining_amount, amount);
        assert_eq!(record.buyer, Some(destination.clone()));
        assert_eq!(record.release_authority, Some(release_authority.clone()));
        assert_eq!(
            balance(&tx, &source, &asset_definition),
            Quantity::from(60_u32)
        );
        assert_eq!(balance(&tx, &record.custody, &asset_definition), amount);
        let err = DrawdownAssetLock::new(escrow_id, Quantity::from(15_u32), Quantity::from(40_u32))
            .execute(&destination, &mut tx)
            .expect_err("destination cannot draw down when release authority is set");
        assert!(
            err.to_string().contains("release authority"),
            "unexpected error: {err}"
        );
        DrawdownAssetLock::new(escrow_id, Quantity::from(15_u32), Quantity::from(40_u32))
            .execute(&release_authority, &mut tx)
            .expect("release authority draws down partial amount");
        let record = escrow_record(&tx, &escrow_id);
        assert_eq!(record.status, AssetEscrowStatus::Locked);
        assert_eq!(record.remaining_amount, Quantity::from(25_u32));
        assert_eq!(
            balance(&tx, &destination, &asset_definition),
            Quantity::from(15_u32)
        );
        assert_eq!(
            balance(&tx, &record.custody, &asset_definition),
            Quantity::from(25_u32)
        );
        DrawdownAssetLock::new(escrow_id, Quantity::from(25_u32), Quantity::from(25_u32))
            .execute(&release_authority, &mut tx)
            .expect("release authority draws down remaining amount");
        let record = escrow_record(&tx, &escrow_id);
        assert_eq!(record.status, AssetEscrowStatus::DrawnDown);
        assert_eq!(record.remaining_amount, Quantity::zero());
        assert_eq!(record.closed_at_ms, Some(1_000));
        assert_eq!(
            balance(&tx, &destination, &asset_definition),
            Quantity::from(40_u32)
        );
        assert_eq!(
            balance(&tx, &record.custody, &asset_definition),
            Quantity::zero()
        );
    }
    #[test]
    fn asset_lock_requires_restricted_definition_home_route_and_bucket() {
        let source = fixture_account("lock-home-source");
        let destination = fixture_account("lock-home-destination");
        let observer = fixture_account("lock-home-observer");
        let asset_definition = fixture_asset_definition_id();
        let escrow_id = fixture_escrow_id("lock-definition-home");
        let home_dataspace = iroha_model_base::topology::DataSpaceId::new(7);
        let home_domain = DomainId::try_new("aitai", "paynet").expect("home domain");
        let asset_definition_entry = AssetDefinition::numeric(
            asset_definition.clone(),
            "XOR".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::DataspaceRestricted,
            Some(home_domain.clone()),
        )
        .build(&source);
        let source_asset_id = AssetId::with_scope(
            asset_definition.clone(),
            source.clone(),
            iroha_data_model::asset::AssetBalanceScope::Dataspace(home_dataspace),
        );
        let source_asset = Asset::new(source_asset_id.clone(), Quantity::from(100_u32));
        let mut world = crate::state::World::with_assets(
            [Domain::new(home_domain).build(&source)],
            [
                Account::new(source.clone()).build(&source),
                Account::new(destination.clone()).build(&destination),
                Account::new(observer.clone()).build(&observer),
            ],
            [asset_definition_entry],
            [source_asset],
            [],
        );
        let alias: iroha_data_model::asset::AssetDefinitionAlias =
            "xor#paynet".parse().expect("asset alias");
        world
            .asset_definition_aliases
            .insert(alias.clone(), asset_definition.clone());
        world.asset_definition_alias_bindings.insert(
            asset_definition.clone(),
            crate::state::AssetDefinitionAliasBindingRecord {
                alias,
                lease_expiry_ms: None,
                grace_until_ms: None,
                bound_at_ms: 0,
            },
        );
        let state = State::new_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        );
        let catalog = iroha_data_model::nexus::DataSpaceCatalog::new(vec![
            iroha_data_model::nexus::DataSpaceMetadata::default(),
            iroha_data_model::nexus::DataSpaceMetadata {
                id: home_dataspace,
                alias: "paynet".to_owned(),
                description: None,
                fault_tolerance: 1,
            },
        ])
        .expect("dataspace catalog");
        let mut block = state.block(block_header(1_000));
        block.nexus.dataspace_catalog = catalog.clone();
        let mut tx = block.transaction_for_fastpq_testing(Hash::prehashed([0xC9; Hash::LENGTH]));
        tx.nexus.dataspace_catalog = catalog.clone();
        tx.world.dataspace_catalog = catalog;
        tx.current_dataspace_id = Some(iroha_model_base::topology::DataSpaceId::UNIVERSAL);
        tx.world.current_dataspace_id = Some(iroha_model_base::topology::DataSpaceId::UNIVERSAL);
        OpenAssetLock::new(
            escrow_id,
            asset_definition.clone(),
            destination.clone(),
            Quantity::from(40_u32),
        )
        .execute(&source, &mut tx)
        .expect_err("a confined asset cannot open escrow through the universal route");
        assert_eq!(
            tx.world.asset(&source_asset_id).unwrap().value().as_ref(),
            &Quantity::from(100_u32),
        );
        tx.current_dataspace_id = Some(home_dataspace);
        tx.world.current_dataspace_id = Some(home_dataspace);
        OpenAssetLock::new(
            escrow_id,
            asset_definition.clone(),
            destination.clone(),
            Quantity::from(40_u32),
        )
        .execute(&source, &mut tx)
        .expect("open restricted asset lock through its definition home route");
        let record = escrow_record(&tx, &escrow_id);
        let custody_asset_id = AssetId::with_scope(
            asset_definition.clone(),
            record.custody.clone(),
            iroha_data_model::asset::AssetBalanceScope::Dataspace(home_dataspace),
        );
        assert_eq!(
            tx.world
                .asset(&source_asset_id)
                .expect("source balance remains in definition home dataspace")
                .value()
                .clone()
                .into_inner(),
            Quantity::from(60_u32)
        );
        assert_eq!(
            tx.world
                .asset(&custody_asset_id)
                .expect("custody balance is created in definition home dataspace")
                .value()
                .clone()
                .into_inner(),
            Quantity::from(40_u32)
        );
        let universal_custody_asset_id = AssetId::with_scope(
            asset_definition.clone(),
            record.custody.clone(),
            iroha_data_model::asset::AssetBalanceScope::Dataspace(
                iroha_model_base::topology::DataSpaceId::UNIVERSAL,
            ),
        );
        assert!(
            tx.world.asset(&universal_custody_asset_id).is_err(),
            "native lock custody must not fall back to universal dataspace"
        );
        DrawdownAssetLock::new(escrow_id, Quantity::from(40_u32), Quantity::from(40_u32))
            .execute(&destination, &mut tx)
            .expect("draw down restricted asset lock");
        let destination_asset_id = AssetId::with_scope(
            asset_definition,
            destination,
            iroha_data_model::asset::AssetBalanceScope::Dataspace(home_dataspace),
        );
        assert_eq!(
            tx.world
                .asset(&destination_asset_id)
                .expect("destination balance is settled in definition home dataspace")
                .value()
                .clone()
                .into_inner(),
            Quantity::from(40_u32)
        );
        assert_eq!(
            tx.world
                .asset(&custody_asset_id)
                .map(|asset| asset.as_ref().clone())
                .unwrap_or_else(|_| Quantity::zero()),
            Quantity::zero()
        );
    }
    #[test]
    fn asset_lock_stale_cancel_rejects_after_drawdown_before_exact_refund() {
        let source = fixture_account("lock-cancel-source");
        let destination = fixture_account("lock-cancel-destination");
        let observer = fixture_account("lock-cancel-observer");
        let asset_definition = fixture_asset_definition_id();
        let escrow_id = fixture_escrow_id("lock-cancel-after-drawdown");
        let state = state_with_parties(
            &source,
            &destination,
            &observer,
            &asset_definition,
            Quantity::from(100_u32),
        );
        let mut block = state.block(block_header(2_000));
        let mut tx = block.transaction_for_fastpq_testing(Hash::prehashed([0xC2; Hash::LENGTH]));
        OpenAssetLock::new(
            escrow_id,
            asset_definition.clone(),
            destination.clone(),
            Quantity::from(40_u32),
        )
        .execute(&source, &mut tx)
        .expect("open destination-drawn lock");
        let stale_cancel = CancelAssetLock::new(escrow_id, Quantity::from(40_u32));
        DrawdownAssetLock::new(escrow_id, Quantity::from(15_u32), Quantity::from(40_u32))
            .execute(&destination, &mut tx)
            .expect("destination draws down when no release authority is set");
        let err = stale_cancel
            .execute(&source, &mut tx)
            .expect_err("stale cancellation must not refund a changed amount");
        assert!(
            err.to_string().contains("remaining amount changed"),
            "unexpected error: {err}"
        );
        let record = escrow_record(&tx, &escrow_id);
        assert_eq!(record.status, AssetEscrowStatus::Locked);
        assert_eq!(record.remaining_amount, Quantity::from(25_u32));
        assert_eq!(
            balance(&tx, &record.custody, &asset_definition),
            Quantity::from(25_u32),
            "rejected stale cancellation must preserve custody"
        );
        assert_eq!(
            balance(&tx, &source, &asset_definition),
            Quantity::from(60_u32),
            "rejected stale cancellation must not credit the opener"
        );
        let err = CancelAssetLock::new(escrow_id, Quantity::from(25_u32))
            .execute(&destination, &mut tx)
            .expect_err("destination cannot cancel source-opened lock");
        assert!(
            err.to_string().contains("lock opener"),
            "unexpected error: {err}"
        );
        CancelAssetLock::new(escrow_id, Quantity::from(25_u32))
            .execute(&source, &mut tx)
            .expect("source cancels remaining lock");
        let record = escrow_record(&tx, &escrow_id);
        assert_eq!(record.status, AssetEscrowStatus::Cancelled);
        assert_eq!(record.remaining_amount, Quantity::zero());
        assert_eq!(record.closed_at_ms, Some(2_000));
        assert_eq!(
            balance(&tx, &source, &asset_definition),
            Quantity::from(85_u32)
        );
        assert_eq!(
            balance(&tx, &destination, &asset_definition),
            Quantity::from(15_u32)
        );
        assert_eq!(
            balance(&tx, &record.custody, &asset_definition),
            Quantity::zero()
        );
    }
    #[test]
    fn asset_lock_expire_requires_deadline_and_refunds_after_deadline() {
        let source = fixture_account("lock-expire-source");
        let destination = fixture_account("lock-expire-destination");
        let observer = fixture_account("lock-expire-observer");
        let asset_definition = fixture_asset_definition_id();
        let no_deadline_id = fixture_escrow_id("lock-expire-no-deadline");
        let future_id = fixture_escrow_id("lock-expire-future");
        let expired_id = fixture_escrow_id("lock-expire-past");
        let state = state_with_parties(
            &source,
            &destination,
            &observer,
            &asset_definition,
            Quantity::from(100_u32),
        );
        let mut block = state.block(block_header(3_000));
        let mut tx = block.transaction_for_fastpq_testing(Hash::prehashed([0xC3; Hash::LENGTH]));
        OpenAssetLock::new(
            no_deadline_id,
            asset_definition.clone(),
            destination.clone(),
            Quantity::from(10_u32),
        )
        .execute(&source, &mut tx)
        .expect("open lock without deadline");
        OpenAssetLock::with_options(
            future_id,
            asset_definition.clone(),
            destination.clone(),
            Quantity::from(20_u32),
            None,
            Some(4_000),
            Vec::new(),
        )
        .execute(&source, &mut tx)
        .expect("open future-expiring lock");
        OpenAssetLock::with_options(
            expired_id,
            asset_definition.clone(),
            destination.clone(),
            Quantity::from(30_u32),
            None,
            Some(2_000),
            Vec::new(),
        )
        .execute(&source, &mut tx)
        .expect("open already-expirable lock");
        let err = ExpireAssetLock::new(no_deadline_id)
            .execute(&observer, &mut tx)
            .expect_err("lock without deadline cannot expire");
        assert!(
            err.to_string().contains("no expiry"),
            "unexpected error: {err}"
        );
        let err = ExpireAssetLock::new(future_id)
            .execute(&observer, &mut tx)
            .expect_err("future deadline cannot expire");
        assert!(
            err.to_string().contains("has not been reached"),
            "unexpected error: {err}"
        );
        ExpireAssetLock::new(expired_id)
            .execute(&observer, &mut tx)
            .expect("any account expires a past-deadline lock");
        let record = escrow_record(&tx, &expired_id);
        assert_eq!(record.status, AssetEscrowStatus::Expired);
        assert_eq!(record.remaining_amount, Quantity::zero());
        assert_eq!(record.closed_at_ms, Some(3_000));
        assert_eq!(
            balance(&tx, &source, &asset_definition),
            Quantity::from(70_u32)
        );
        assert_eq!(
            balance(&tx, &destination, &asset_definition),
            Quantity::zero()
        );
        assert_eq!(
            balance(&tx, &record.custody, &asset_definition),
            Quantity::zero()
        );
        assert_eq!(
            escrow_record(&tx, &no_deadline_id).status,
            AssetEscrowStatus::Locked
        );
        assert_eq!(
            escrow_record(&tx, &future_id).status,
            AssetEscrowStatus::Locked
        );
    }
    #[test]
    fn asset_lock_open_rejects_invalid_inputs_without_state_changes() {
        let source = fixture_account("lock-open-source");
        let destination = fixture_account("lock-open-destination");
        let observer = fixture_account("lock-open-observer");
        let asset_definition = fixture_asset_definition_id();
        let state = state_with_parties(
            &source,
            &destination,
            &observer,
            &asset_definition,
            Quantity::from(40_u32),
        );
        let mut block = state.block(block_header(3_100));
        let mut tx = block.transaction_for_fastpq_testing(Hash::prehashed([0xC4; Hash::LENGTH]));
        let zero_id = fixture_escrow_id("lock-open-zero");
        let err = OpenAssetLock::new(
            zero_id,
            asset_definition.clone(),
            destination.clone(),
            Quantity::zero(),
        )
        .execute(&source, &mut tx)
        .expect_err("zero lock amount must be rejected");
        assert!(
            err.to_string().contains("non-zero"),
            "unexpected error: {err}"
        );
        assert!(tx.world.asset_escrows.get(&zero_id).is_none());
        let negative_id = fixture_escrow_id("lock-open-negative");
        let err = Quantity::try_from_numeric(Numeric::new(-1_i32, 0))
            .expect_err("negative lock amount must not construct a quantity");
        assert!(
            err.to_string().contains("negative"),
            "unexpected error: {err}"
        );
        assert!(tx.world.asset_escrows.get(&negative_id).is_none());
        let missing_destination_id = fixture_escrow_id("lock-open-missing-destination");
        let missing_destination = fixture_account("lock-open-missing-destination-account");
        assert!(
            OpenAssetLock::new(
                missing_destination_id,
                asset_definition.clone(),
                missing_destination,
                Quantity::from(5_u32),
            )
            .execute(&source, &mut tx)
            .is_err(),
            "missing destination account must be rejected"
        );
        assert!(
            tx.world
                .asset_escrows
                .get(&missing_destination_id)
                .is_none()
        );
        let missing_authority_id = fixture_escrow_id("lock-open-missing-authority");
        let missing_authority = fixture_account("lock-open-missing-authority-account");
        assert!(
            OpenAssetLock::with_options(
                missing_authority_id,
                asset_definition.clone(),
                destination.clone(),
                Quantity::from(5_u32),
                Some(missing_authority),
                None,
                Vec::new(),
            )
            .execute(&source, &mut tx)
            .is_err(),
            "missing release authority account must be rejected"
        );
        assert!(tx.world.asset_escrows.get(&missing_authority_id).is_none());
        let over_balance_id = fixture_escrow_id("lock-open-over-balance");
        assert!(
            OpenAssetLock::new(
                over_balance_id,
                asset_definition.clone(),
                destination.clone(),
                Quantity::from(41_u32),
            )
            .execute(&source, &mut tx)
            .is_err(),
            "insufficient source balance must be rejected"
        );
        let custody =
            escrow_custody_account_id(tx.network_id(), &over_balance_id, &asset_definition)
                .expect("custody account derivation succeeds");
        assert!(tx.world.asset_escrows.get(&over_balance_id).is_none());
        assert!(tx.world.account(&custody).is_err());
        assert_eq!(
            balance(&tx, &source, &asset_definition),
            Quantity::from(40_u32)
        );
        assert_eq!(
            balance(&tx, &destination, &asset_definition),
            Quantity::zero()
        );
    }
    #[test]
    fn asset_lock_drawdown_rejects_wrong_kind_status_and_amounts() {
        let source = fixture_account("lock-drawdown-negative-source");
        let destination = fixture_account("lock-drawdown-negative-destination");
        let observer = fixture_account("lock-drawdown-negative-observer");
        let asset_definition = fixture_asset_definition_id();
        let state = state_with_parties(
            &source,
            &destination,
            &observer,
            &asset_definition,
            Quantity::from(100_u32),
        );
        let mut block = state.block(block_header(3_200));
        let mut tx = block.transaction_for_fastpq_testing(Hash::prehashed([0xC5; Hash::LENGTH]));
        let marketplace_id = fixture_escrow_id("lock-drawdown-marketplace");
        OpenAssetEscrow {
            escrow_id: marketplace_id,
            asset_definition: asset_definition.clone(),
            amount: Quantity::from(10_u32),
            evidence_hashes: Vec::new(),
        }
        .execute(&source, &mut tx)
        .expect("open marketplace escrow");
        let err = DrawdownAssetLock::new(marketplace_id, Quantity::one(), Quantity::from(10_u32))
            .execute(&destination, &mut tx)
            .expect_err("marketplace escrow cannot be drawn down as a lock");
        assert!(
            err.to_string().contains("generic asset lock"),
            "unexpected error: {err}"
        );
        let missing_id = fixture_escrow_id("lock-drawdown-missing");
        let err = DrawdownAssetLock::new(missing_id, Quantity::one(), Quantity::one())
            .execute(&destination, &mut tx)
            .expect_err("missing lock cannot be drawn down");
        assert!(
            err.to_string().contains("not found"),
            "unexpected error: {err}"
        );
        let lock_id = fixture_escrow_id("lock-drawdown-negative");
        OpenAssetLock::new(
            lock_id,
            asset_definition.clone(),
            destination.clone(),
            Quantity::from(30_u32),
        )
        .execute(&source, &mut tx)
        .expect("open lock");
        let custody = escrow_record(&tx, &lock_id).custody;
        let err = DrawdownAssetLock::new(lock_id, Quantity::zero(), Quantity::from(30_u32))
            .execute(&destination, &mut tx)
            .expect_err("zero drawdown must be rejected");
        assert!(
            err.to_string().contains("non-zero"),
            "unexpected error: {err}"
        );
        let err = Quantity::try_from_numeric(Numeric::new(-1_i32, 0))
            .expect_err("negative drawdown must not construct a quantity");
        assert!(
            err.to_string().contains("negative"),
            "unexpected error: {err}"
        );
        let err = DrawdownAssetLock::new(lock_id, Quantity::from(31_u32), Quantity::from(30_u32))
            .execute(&destination, &mut tx)
            .expect_err("overdraw must be rejected");
        assert!(
            err.to_string().contains("exceeds remaining"),
            "unexpected error: {err}"
        );
        let err = DrawdownAssetLock::new(lock_id, Quantity::one(), Quantity::from(30_u32))
            .execute(&observer, &mut tx)
            .expect_err("observer cannot draw down destination-controlled lock");
        assert!(
            err.to_string().contains("destination"),
            "unexpected error: {err}"
        );
        assert_eq!(
            escrow_record(&tx, &lock_id).status,
            AssetEscrowStatus::Locked
        );
        assert_eq!(
            escrow_record(&tx, &lock_id).remaining_amount,
            Quantity::from(30_u32)
        );
        assert_eq!(
            balance(&tx, &custody, &asset_definition),
            Quantity::from(30_u32)
        );
        assert_eq!(
            balance(&tx, &destination, &asset_definition),
            Quantity::zero()
        );
        let err = CancelAssetLock::new(lock_id, Quantity::zero())
            .execute(&source, &mut tx)
            .expect_err("zero cancellation precondition must be rejected");
        assert!(
            err.to_string().contains("non-zero"),
            "unexpected error: {err}"
        );
        DrawdownAssetLock::new(lock_id, Quantity::from(30_u32), Quantity::from(30_u32))
            .execute(&destination, &mut tx)
            .expect("draw down all funds");
        assert_eq!(
            escrow_record(&tx, &lock_id).status,
            AssetEscrowStatus::DrawnDown
        );
        assert!(
            DrawdownAssetLock::new(lock_id, Quantity::one(), Quantity::zero())
                .execute(&destination, &mut tx)
                .is_err(),
            "closed lock cannot be drawn down again"
        );
        assert!(
            CancelAssetLock::new(lock_id, Quantity::from(30_u32))
                .execute(&source, &mut tx)
                .is_err(),
            "closed lock cannot be cancelled"
        );
        assert!(
            ExpireAssetLock::new(lock_id)
                .execute(&observer, &mut tx)
                .is_err(),
            "closed lock cannot expire"
        );
        assert_eq!(
            balance(&tx, &destination, &asset_definition),
            Quantity::from(30_u32)
        );
        assert_eq!(balance(&tx, &custody, &asset_definition), Quantity::zero());
    }
    #[test]
    fn disabled_custody_outbound_blocks_drawdown_cancel_and_expire() {
        let source = fixture_account("lock-disabled-source");
        let destination = fixture_account("lock-disabled-destination");
        let observer = fixture_account("lock-disabled-observer");
        let asset_definition = fixture_asset_definition_id();
        let drawdown_id = fixture_escrow_id("lock-disabled-drawdown");
        let cancel_id = fixture_escrow_id("lock-disabled-cancel");
        let expire_id = fixture_escrow_id("lock-disabled-expire");
        let state = state_with_parties(
            &source,
            &destination,
            &observer,
            &asset_definition,
            Quantity::from(100_u32),
        );
        let mut block = state.block(block_header(3_300));
        let mut tx = block.transaction_for_fastpq_testing(Hash::prehashed([0xC6; Hash::LENGTH]));
        OpenAssetLock::new(
            drawdown_id,
            asset_definition.clone(),
            destination.clone(),
            Quantity::from(10_u32),
        )
        .execute(&source, &mut tx)
        .expect("open drawdown lock");
        OpenAssetLock::new(
            cancel_id,
            asset_definition.clone(),
            destination.clone(),
            Quantity::from(20_u32),
        )
        .execute(&source, &mut tx)
        .expect("open cancel lock");
        OpenAssetLock::with_options(
            expire_id,
            asset_definition.clone(),
            destination.clone(),
            Quantity::from(30_u32),
            None,
            Some(3_000),
            Vec::new(),
        )
        .execute(&source, &mut tx)
        .expect("open expired lock");
        let drawdown_custody = escrow_record(&tx, &drawdown_id).custody;
        disable_outbound_asset_transfers(&mut tx, &source, &drawdown_custody, &asset_definition);
        let err =
            DrawdownAssetLock::new(drawdown_id, Quantity::from(5_u32), Quantity::from(10_u32))
                .execute(&destination, &mut tx)
                .expect_err("disabled custody outbound must block drawdown");
        assert!(
            matches!(
                err,
                InstructionExecutionError::AssetTransferAdmission(
                    iroha_data_model::isi::error::AssetTransferAdmissionError::OutgoingDisabled(_)
                )
            ),
            "unexpected error: {err}"
        );
        let cancel_custody = escrow_record(&tx, &cancel_id).custody;
        disable_outbound_asset_transfers(&mut tx, &source, &cancel_custody, &asset_definition);
        let err = CancelAssetLock::new(cancel_id, Quantity::from(20_u32))
            .execute(&source, &mut tx)
            .expect_err("disabled custody outbound must block cancellation refund");
        assert!(
            matches!(
                err,
                InstructionExecutionError::AssetTransferAdmission(
                    iroha_data_model::isi::error::AssetTransferAdmissionError::OutgoingDisabled(_)
                )
            ),
            "unexpected error: {err}"
        );
        let expire_custody = escrow_record(&tx, &expire_id).custody;
        disable_outbound_asset_transfers(&mut tx, &source, &expire_custody, &asset_definition);
        let err = ExpireAssetLock::new(expire_id)
            .execute(&observer, &mut tx)
            .expect_err("disabled custody outbound must block expiry refund");
        assert!(
            matches!(
                err,
                InstructionExecutionError::AssetTransferAdmission(
                    iroha_data_model::isi::error::AssetTransferAdmissionError::OutgoingDisabled(_)
                )
            ),
            "unexpected error: {err}"
        );
        assert_eq!(
            escrow_record(&tx, &drawdown_id).status,
            AssetEscrowStatus::Locked
        );
        assert_eq!(
            escrow_record(&tx, &cancel_id).status,
            AssetEscrowStatus::Locked
        );
        assert_eq!(
            escrow_record(&tx, &expire_id).status,
            AssetEscrowStatus::Locked
        );
        assert_eq!(
            balance(&tx, &drawdown_custody, &asset_definition),
            Quantity::from(10_u32)
        );
        assert_eq!(
            balance(&tx, &cancel_custody, &asset_definition),
            Quantity::from(20_u32)
        );
        assert_eq!(
            balance(&tx, &expire_custody, &asset_definition),
            Quantity::from(30_u32)
        );
        assert_eq!(
            balance(&tx, &destination, &asset_definition),
            Quantity::zero()
        );
        assert_eq!(
            balance(&tx, &source, &asset_definition),
            Quantity::from(40_u32)
        );
    }
    #[test]
    fn asset_lock_adversarial_ordering_keeps_balances_consistent() {
        let source = fixture_account("lock-order-source");
        let destination = fixture_account("lock-order-destination");
        let observer = fixture_account("lock-order-observer");
        let asset_definition = fixture_asset_definition_id();
        let escrow_id = fixture_escrow_id("lock-order");
        let state = state_with_parties(
            &source,
            &destination,
            &observer,
            &asset_definition,
            Quantity::from(100_u32),
        );
        let mut block = state.block(block_header(3_400));
        let mut tx = block.transaction_for_fastpq_testing(Hash::prehashed([0xC7; Hash::LENGTH]));
        OpenAssetLock::new(
            escrow_id,
            asset_definition.clone(),
            destination.clone(),
            Quantity::from(30_u32),
        )
        .execute(&source, &mut tx)
        .expect("open lock");
        let custody = escrow_record(&tx, &escrow_id).custody;
        assert!(
            CancelAssetLock::new(escrow_id, Quantity::from(30_u32))
                .execute(&destination, &mut tx)
                .is_err(),
            "destination cannot cancel source-opened lock"
        );
        DrawdownAssetLock::new(escrow_id, Quantity::from(10_u32), Quantity::from(30_u32))
            .execute(&destination, &mut tx)
            .expect("destination draws down partial amount");
        let stale = DrawdownAssetLock::new(escrow_id, Quantity::one(), Quantity::from(30_u32))
            .execute(&destination, &mut tx)
            .expect_err("stale drawdown precondition must fail");
        assert!(
            stale.to_string().contains("remaining amount changed"),
            "unexpected error: {stale}"
        );
        assert!(
            ExpireAssetLock::new(escrow_id)
                .execute(&observer, &mut tx)
                .is_err(),
            "lock without deadline cannot expire"
        );
        assert!(
            DrawdownAssetLock::new(escrow_id, Quantity::from(25_u32), Quantity::from(20_u32),)
                .execute(&destination, &mut tx)
                .is_err(),
            "cannot draw down more than remaining amount"
        );
        CancelAssetLock::new(escrow_id, Quantity::from(20_u32))
            .execute(&source, &mut tx)
            .expect("source cancels remaining funds");
        assert!(
            DrawdownAssetLock::new(escrow_id, Quantity::one(), Quantity::zero())
                .execute(&destination, &mut tx)
                .is_err(),
            "closed lock must reject drawdown"
        );
        assert!(
            CancelAssetLock::new(escrow_id, Quantity::from(20_u32))
                .execute(&source, &mut tx)
                .is_err(),
            "closed lock must reject cancellation"
        );
        assert!(
            ExpireAssetLock::new(escrow_id)
                .execute(&observer, &mut tx)
                .is_err(),
            "closed lock must reject expiry"
        );
        let record = escrow_record(&tx, &escrow_id);
        assert_eq!(record.status, AssetEscrowStatus::Cancelled);
        assert_eq!(record.remaining_amount, Quantity::zero());
        assert_eq!(
            balance(&tx, &source, &asset_definition),
            Quantity::from(90_u32)
        );
        assert_eq!(
            balance(&tx, &destination, &asset_definition),
            Quantity::from(10_u32)
        );
        assert_eq!(balance(&tx, &custody, &asset_definition), Quantity::zero());
    }
    #[test]
    fn asset_escrow_indexes_track_seller_buyer_and_status_updates() {
        let seller = fixture_account("seller");
        let buyer = fixture_account("buyer");
        let court = fixture_account("court");
        let asset_definition = fixture_asset_definition_id();
        let escrow_id = fixture_escrow_id("indexed-query");
        let amount = Quantity::from(40_u32);
        let state = state_with_parties(
            &seller,
            &buyer,
            &court,
            &asset_definition,
            Quantity::from(100_u32),
        );
        let mut block = state.block(block_header(1_000));
        let mut tx = block.transaction_for_fastpq_testing(Hash::prehashed([0xA3; Hash::LENGTH]));
        OpenAssetEscrow {
            escrow_id,
            asset_definition: asset_definition.clone(),
            amount,
            evidence_hashes: Vec::new(),
        }
        .execute(&seller, &mut tx)
        .expect("open escrow");
        AcceptAssetEscrow { escrow_id }
            .execute(&buyer, &mut tx)
            .expect("accept escrow");
        MarkEscrowPaymentSent { escrow_id }
            .execute(&buyer, &mut tx)
            .expect("mark payment sent");
        assert!(
            tx.world
                .asset_escrows_by_seller
                .get(&seller)
                .expect("seller index entry")
                .contains(&escrow_id)
        );
        assert!(
            tx.world
                .asset_escrows_by_buyer
                .get(&buyer)
                .expect("buyer index entry")
                .contains(&escrow_id)
        );
        assert!(
            tx.world
                .asset_escrows_by_status
                .get(&AssetEscrowStatus::PaymentSent)
                .expect("payment-sent index entry")
                .contains(&escrow_id)
        );
        let stale_open_entry = tx
            .world
            .asset_escrows_by_status
            .get(&AssetEscrowStatus::Open)
            .is_some_and(|escrows| escrows.contains(&escrow_id));
        assert!(
            !stale_open_entry,
            "status update should remove stale open index entry"
        );
        let stale_accepted_entry = tx
            .world
            .asset_escrows_by_status
            .get(&AssetEscrowStatus::Accepted)
            .is_some_and(|escrows| escrows.contains(&escrow_id));
        assert!(
            !stale_accepted_entry,
            "status update should remove stale accepted index entry"
        );
        let by_seller = FindAssetEscrowsBySeller {
            seller: seller.clone(),
        }
        .execute(CompoundPredicate::PASS, &tx)
        .expect("query escrows by seller")
        .map(|record| record.id)
        .collect::<Vec<_>>();
        assert_eq!(by_seller, vec![escrow_id]);
        let by_buyer = FindAssetEscrowsByBuyer {
            buyer: buyer.clone(),
        }
        .execute(CompoundPredicate::PASS, &tx)
        .expect("query escrows by buyer")
        .map(|record| record.id)
        .collect::<Vec<_>>();
        assert_eq!(by_buyer, vec![escrow_id]);
        let by_status = FindAssetEscrowsByStatus {
            status: AssetEscrowStatus::PaymentSent,
        }
        .execute(CompoundPredicate::PASS, &tx)
        .expect("query escrows by status")
        .map(|record| record.id)
        .collect::<Vec<_>>();
        assert_eq!(by_status, vec![escrow_id]);
        let by_generic_id = query_asset_escrow_ids(
            &tx,
            CompoundPredicate::<AssetEscrowRecord>::build(|predicate| {
                predicate.equals("id", escrow_id)
            }),
        );
        assert_eq!(by_generic_id, vec![escrow_id]);
        let by_generic_seller = query_asset_escrow_ids(
            &tx,
            CompoundPredicate::<AssetEscrowRecord>::build(|predicate| {
                predicate.equals("seller", seller.clone())
            }),
        );
        assert_eq!(by_generic_seller, vec![escrow_id]);
        let by_generic_buyer = query_asset_escrow_ids(
            &tx,
            CompoundPredicate::<AssetEscrowRecord>::build(|predicate| {
                predicate.equals("buyer", buyer.clone())
            }),
        );
        assert_eq!(by_generic_buyer, vec![escrow_id]);
        let by_generic_status = query_asset_escrow_ids(
            &tx,
            CompoundPredicate::<AssetEscrowRecord>::build(|predicate| {
                predicate.in_values(
                    "status",
                    [AssetEscrowStatus::Open, AssetEscrowStatus::PaymentSent],
                )
            }),
        );
        assert_eq!(by_generic_status, vec![escrow_id]);
        let missing_buyer = fixture_account("missing-escrow-buyer");
        let missing = query_asset_escrow_ids(
            &tx,
            CompoundPredicate::<AssetEscrowRecord>::build(|predicate| {
                predicate
                    .equals("status", AssetEscrowStatus::PaymentSent)
                    .equals("buyer", missing_buyer)
            }),
        );
        assert!(missing.is_empty());
    }
    #[test]
    fn asset_escrow_candidates_intersect_status_and_buyer_indexes() {
        let seller = fixture_account("candidate-seller");
        let buyer = fixture_account("candidate-buyer");
        let wrong_buyer = fixture_account("candidate-wrong-buyer");
        let wrong_seller = fixture_account("candidate-wrong-seller");
        let court = fixture_account("candidate-court");
        let asset_definition = fixture_asset_definition_id();
        let state = state_with_parties(
            &seller,
            &buyer,
            &court,
            &asset_definition,
            Quantity::from(100_u32),
        );
        let mut block = state.block(block_header(1_000));
        let mut tx = block.transaction();
        let target = fixture_escrow_id("asset-candidate-target");
        let same_status = fixture_escrow_id("asset-candidate-same-status");
        let same_buyer = fixture_escrow_id("asset-candidate-same-buyer");
        for record in [
            asset_escrow_fixture(
                target,
                seller.clone(),
                Some(buyer.clone()),
                asset_definition.clone(),
                AssetEscrowStatus::PaymentSent,
            ),
            asset_escrow_fixture(
                same_status,
                seller,
                Some(wrong_buyer),
                asset_definition.clone(),
                AssetEscrowStatus::PaymentSent,
            ),
            asset_escrow_fixture(
                same_buyer,
                wrong_seller,
                Some(buyer.clone()),
                asset_definition,
                AssetEscrowStatus::Accepted,
            ),
        ] {
            tx.world.insert_asset_escrow_entry(record);
        }
        let predicate = CompoundPredicate::<AssetEscrowRecord>::build(|predicate| {
            predicate
                .equals("status", AssetEscrowStatus::PaymentSent)
                .equals("buyer", buyer)
        });
        let predicate_json = parse_predicate_json(&predicate);
        let candidate_ids = asset_escrow_candidate_ids(&predicate_json, &tx.world)
            .expect("indexed asset escrow candidates");
        assert_eq!(candidate_ids, std::collections::BTreeSet::from([target]));
    }
    #[test]
    fn escrow_open_and_release_record_transfer_artifacts() {
        let seller = fixture_account("seller");
        let buyer = fixture_account("buyer");
        let court = fixture_account("court");
        let asset_definition = fixture_asset_definition_id();
        let escrow_id = fixture_escrow_id("release-artifacts");
        let amount = Quantity::from(40_u32);
        let state = state_with_parties(
            &seller,
            &buyer,
            &court,
            &asset_definition,
            Quantity::from(100_u32),
        );
        let mut block = state.block(block_header(1_000));
        let call_hash = Hash::prehashed([0xA1; Hash::LENGTH]);
        let mut tx = block.transaction_for_fastpq_testing(call_hash);
        OpenAssetEscrow {
            escrow_id,
            asset_definition: asset_definition.clone(),
            amount: amount.clone(),
            evidence_hashes: Vec::new(),
        }
        .execute(&seller, &mut tx)
        .expect("open escrow");
        let record = escrow_record(&tx, &escrow_id);
        let custody = record.custody.clone();
        let seller_asset = AssetId::of(asset_definition.clone(), seller.clone());
        let custody_asset = AssetId::of(asset_definition.clone(), custody.clone());
        let open_events = asset_transfer_events(&tx.world.take_external_events());
        assert_asset_transfer_event(&open_events, "removed", &seller_asset, &amount);
        assert_asset_transfer_event(&open_events, "added", &custody_asset, &amount);
        AcceptAssetEscrow { escrow_id }
            .execute(&buyer, &mut tx)
            .expect("accept escrow");
        MarkEscrowPaymentSent { escrow_id }
            .execute(&buyer, &mut tx)
            .expect("mark payment sent");
        ReleaseAssetEscrow { escrow_id }
            .execute(&seller, &mut tx)
            .expect("release escrow");
        let buyer_asset = AssetId::of(asset_definition.clone(), buyer.clone());
        let release_events = asset_transfer_events(&tx.world.take_external_events());
        assert_asset_transfer_event(&release_events, "removed", &custody_asset, &amount);
        assert_asset_transfer_event(&release_events, "added", &buyer_asset, &amount);
        tx.apply();
        let transcripts = block.drain_transfer_transcripts();
        let entry = transcripts
            .get(&call_hash)
            .expect("escrow transfer transcripts");
        assert_eq!(entry.len(), 2);
        assert_eq!(entry[0].deltas.len(), 1);
        assert_eq!(entry[1].deltas.len(), 1);
        assert_transfer_delta(
            &entry[0].deltas[0],
            &seller,
            &custody,
            &asset_definition,
            &amount,
        );
        assert_transfer_delta(
            &entry[1].deltas[0],
            &custody,
            &buyer,
            &asset_definition,
            &amount,
        );
    }
    #[test]
    fn escrow_release_rechecks_transparent_transfer_policy() {
        let seller = fixture_account("seller");
        let buyer = fixture_account("buyer");
        let court = fixture_account("court");
        let asset_definition = fixture_asset_definition_id();
        let escrow_id = fixture_escrow_id("release-policy");
        let amount = Quantity::from(40_u32);
        let state = state_with_parties(
            &seller,
            &buyer,
            &court,
            &asset_definition,
            Quantity::from(100_u32),
        );
        let mut block = state.block(block_header(1_000));
        let mut tx = block.transaction_for_fastpq_testing(Hash::prehashed([0xB1; Hash::LENGTH]));
        OpenAssetEscrow {
            escrow_id,
            asset_definition: asset_definition.clone(),
            amount: amount.clone(),
            evidence_hashes: Vec::new(),
        }
        .execute(&seller, &mut tx)
        .expect("open escrow");
        AcceptAssetEscrow { escrow_id }
            .execute(&buyer, &mut tx)
            .expect("accept escrow");
        MarkEscrowPaymentSent { escrow_id }
            .execute(&buyer, &mut tx)
            .expect("mark payment sent");
        tx.world
            .asset_definition_mut(&asset_definition)
            .expect("asset definition")
            .set_confidential_policy(AssetConfidentialPolicy::shielded_only());
        let err = ReleaseAssetEscrow { escrow_id }
            .execute(&seller, &mut tx)
            .expect_err("release must obey current transparent transfer policy");
        assert!(
            err.to_string()
                .contains("transparent transfer not permitted by policy"),
            "unexpected error: {err}"
        );
        let record = escrow_record(&tx, &escrow_id);
        assert_eq!(record.status, AssetEscrowStatus::PaymentSent);
        assert_eq!(balance(&tx, &record.custody, &asset_definition), amount);
        assert_eq!(balance(&tx, &buyer, &asset_definition), Quantity::zero());
    }
    #[test]
    fn escrow_release_rejects_disabled_custody_outbound_asset() {
        let seller = fixture_account("seller");
        let buyer = fixture_account("buyer");
        let court = fixture_account("court");
        let asset_definition = fixture_asset_definition_id();
        let escrow_id = fixture_escrow_id("release-custody-disabled");
        let amount = Quantity::from(40_u32);
        let state = state_with_parties(
            &seller,
            &buyer,
            &court,
            &asset_definition,
            Quantity::from(100_u32),
        );
        let mut block = state.block(block_header(1_000));
        let mut tx = block.transaction_for_fastpq_testing(Hash::prehashed([0xB2; Hash::LENGTH]));
        OpenAssetEscrow {
            escrow_id,
            asset_definition: asset_definition.clone(),
            amount: amount.clone(),
            evidence_hashes: Vec::new(),
        }
        .execute(&seller, &mut tx)
        .expect("open escrow");
        let custody = escrow_record(&tx, &escrow_id).custody;
        disable_outbound_asset_transfers(&mut tx, &seller, &custody, &asset_definition);
        AcceptAssetEscrow { escrow_id }
            .execute(&buyer, &mut tx)
            .expect("accept escrow");
        MarkEscrowPaymentSent { escrow_id }
            .execute(&buyer, &mut tx)
            .expect("mark payment sent");
        let err = ReleaseAssetEscrow { escrow_id }
            .execute(&seller, &mut tx)
            .expect_err("disabled custody outbound must block release");
        assert!(
            matches!(
                err,
                InstructionExecutionError::AssetTransferAdmission(
                    iroha_data_model::isi::error::AssetTransferAdmissionError::OutgoingDisabled(_)
                )
            ),
            "unexpected error: {err}"
        );
        let record = escrow_record(&tx, &escrow_id);
        assert_eq!(record.status, AssetEscrowStatus::PaymentSent);
        assert_eq!(balance(&tx, &record.custody, &asset_definition), amount);
        assert_eq!(balance(&tx, &buyer, &asset_definition), Quantity::zero());
    }
    #[test]
    fn escrow_cancel_before_payment_refunds_seller() {
        let seller = fixture_account("seller");
        let buyer = fixture_account("buyer");
        let court = fixture_account("court");
        let asset_definition = fixture_asset_definition_id();
        let escrow_id = fixture_escrow_id("cancel");
        let state = state_with_parties(
            &seller,
            &buyer,
            &court,
            &asset_definition,
            Quantity::from(100_u32),
        );
        let mut block = state.block(block_header(2_000));
        let mut tx = block.transaction_for_fastpq_testing(Hash::prehashed([0xB3; Hash::LENGTH]));
        OpenAssetEscrow {
            escrow_id,
            asset_definition: asset_definition.clone(),
            amount: Quantity::from(40_u32),
            evidence_hashes: Vec::new(),
        }
        .execute(&seller, &mut tx)
        .expect("open escrow");
        AcceptAssetEscrow { escrow_id }
            .execute(&buyer, &mut tx)
            .expect("accept escrow");
        CancelAssetEscrow { escrow_id }
            .execute(&seller, &mut tx)
            .expect("cancel escrow");
        let record = escrow_record(&tx, &escrow_id);
        assert_eq!(record.status, AssetEscrowStatus::Cancelled);
        assert_eq!(
            balance(&tx, &seller, &asset_definition),
            Quantity::from(100_u32)
        );
        assert_eq!(balance(&tx, &buyer, &asset_definition), Quantity::zero());
    }
    #[test]
    fn escrow_cancel_rejects_disabled_custody_outbound_asset() {
        let seller = fixture_account("seller");
        let buyer = fixture_account("buyer");
        let court = fixture_account("court");
        let asset_definition = fixture_asset_definition_id();
        let escrow_id = fixture_escrow_id("cancel-custody-disabled");
        let amount = Quantity::from(40_u32);
        let state = state_with_parties(
            &seller,
            &buyer,
            &court,
            &asset_definition,
            Quantity::from(100_u32),
        );
        let mut block = state.block(block_header(2_000));
        let mut tx = block.transaction_for_fastpq_testing(Hash::prehashed([0xB4; Hash::LENGTH]));
        OpenAssetEscrow {
            escrow_id,
            asset_definition: asset_definition.clone(),
            amount: amount.clone(),
            evidence_hashes: Vec::new(),
        }
        .execute(&seller, &mut tx)
        .expect("open escrow");
        let custody = escrow_record(&tx, &escrow_id).custody;
        disable_outbound_asset_transfers(&mut tx, &seller, &custody, &asset_definition);
        let err = CancelAssetEscrow { escrow_id }
            .execute(&seller, &mut tx)
            .expect_err("disabled custody outbound must block cancellation");
        assert!(
            matches!(
                err,
                InstructionExecutionError::AssetTransferAdmission(
                    iroha_data_model::isi::error::AssetTransferAdmissionError::OutgoingDisabled(_)
                )
            ),
            "unexpected error: {err}"
        );
        let record = escrow_record(&tx, &escrow_id);
        assert_eq!(record.status, AssetEscrowStatus::Open);
        assert_eq!(balance(&tx, &record.custody, &asset_definition), amount);
        assert_eq!(
            balance(&tx, &seller, &asset_definition),
            Quantity::from(60_u32)
        );
    }
    #[test]
    fn escrow_dispute_requires_court_permission_and_valid_split() {
        let seller = fixture_account("seller");
        let buyer = fixture_account("buyer");
        let court = fixture_account("court");
        let asset_definition = fixture_asset_definition_id();
        let escrow_id = fixture_escrow_id("dispute");
        let state = state_with_parties(
            &seller,
            &buyer,
            &court,
            &asset_definition,
            Quantity::from(100_u32),
        );
        let mut block = state.block(block_header(3_000));
        let mut tx = block.transaction_for_fastpq_testing(Hash::prehashed([0xB5; Hash::LENGTH]));
        OpenAssetEscrow {
            escrow_id,
            asset_definition: asset_definition.clone(),
            amount: Quantity::from(40_u32),
            evidence_hashes: vec![Hash::new("open-evidence")],
        }
        .execute(&seller, &mut tx)
        .expect("open escrow");
        AcceptAssetEscrow { escrow_id }
            .execute(&buyer, &mut tx)
            .expect("accept escrow");
        OpenEscrowDispute {
            escrow_id,
            evidence_hashes: vec![Hash::new("dispute-evidence")],
        }
        .execute(&buyer, &mut tx)
        .expect("open dispute");
        assert!(
            ResolveEscrowDispute {
                escrow_id,
                buyer_amount: Quantity::from(20_u32),
                seller_amount: Quantity::from(20_u32),
                evidence_hashes: Vec::new(),
            }
            .execute(&seller, &mut tx)
            .is_err(),
            "seller cannot resolve dispute without court permission"
        );
        grant_court_permission(&mut tx, &court);
        assert!(
            ResolveEscrowDispute {
                escrow_id,
                buyer_amount: Quantity::from(20_u32),
                seller_amount: Quantity::from(19_u32),
                evidence_hashes: Vec::new(),
            }
            .execute(&court, &mut tx)
            .is_err(),
            "court split must exactly match held amount"
        );
        ResolveEscrowDispute {
            escrow_id,
            buyer_amount: Quantity::from(25_u32),
            seller_amount: Quantity::from(15_u32),
            evidence_hashes: vec![Hash::new("resolution-evidence")],
        }
        .execute(&court, &mut tx)
        .expect("resolve dispute");
        let record = escrow_record(&tx, &escrow_id);
        assert_eq!(record.status, AssetEscrowStatus::Resolved);
        assert_eq!(
            balance(&tx, &buyer, &asset_definition),
            Quantity::from(25_u32)
        );
        assert_eq!(
            balance(&tx, &seller, &asset_definition),
            Quantity::from(75_u32)
        );
        assert_eq!(
            balance(&tx, &record.custody, &asset_definition),
            Quantity::zero()
        );
    }
    #[test]
    fn escrow_resolution_records_each_ordered_transfer_leg() {
        let seller = fixture_account("seller");
        let buyer = fixture_account("buyer");
        let court = fixture_account("court");
        let asset_definition = fixture_asset_definition_id();
        let escrow_id = fixture_escrow_id("resolution-artifacts");
        let amount = Quantity::from(40_u32);
        let buyer_amount = Quantity::from(25_u32);
        let seller_amount = Quantity::from(15_u32);
        let state = state_with_parties(
            &seller,
            &buyer,
            &court,
            &asset_definition,
            Quantity::from(100_u32),
        );
        let mut block = state.block(block_header(3_000));
        let call_hash = Hash::prehashed([0xA2; Hash::LENGTH]);
        let mut tx = block.transaction_for_fastpq_testing(call_hash);
        OpenAssetEscrow {
            escrow_id,
            asset_definition: asset_definition.clone(),
            amount,
            evidence_hashes: Vec::new(),
        }
        .execute(&seller, &mut tx)
        .expect("open escrow");
        let custody = escrow_record(&tx, &escrow_id).custody;
        AcceptAssetEscrow { escrow_id }
            .execute(&buyer, &mut tx)
            .expect("accept escrow");
        OpenEscrowDispute {
            escrow_id,
            evidence_hashes: Vec::new(),
        }
        .execute(&buyer, &mut tx)
        .expect("open dispute");
        grant_court_permission(&mut tx, &court);
        ResolveEscrowDispute {
            escrow_id,
            buyer_amount: buyer_amount.clone(),
            seller_amount: seller_amount.clone(),
            evidence_hashes: Vec::new(),
        }
        .execute(&court, &mut tx)
        .expect("resolve dispute");
        tx.apply();
        let transcripts = block.drain_transfer_transcripts();
        let entry = transcripts
            .get(&call_hash)
            .expect("escrow transfer transcripts");
        assert_eq!(entry.len(), 3);
        let resolution = &entry[1..];
        for transcript in resolution {
            assert_eq!(transcript.deltas.len(), 1);
            assert_eq!(
                transcript.poseidon_preimage_digest,
                Some(crate::fastpq::poseidon_preimage_digest(
                    &transcript.deltas[0],
                    &transcript.batch_hash,
                ))
            );
        }
        assert_transfer_delta(
            &resolution[0].deltas[0],
            &custody,
            &buyer,
            &asset_definition,
            &buyer_amount,
        );
        assert_transfer_delta(
            &resolution[1].deltas[0],
            &custody,
            &seller,
            &asset_definition,
            &seller_amount,
        );
    }
    #[test]
    fn escrow_resolution_rejects_disabled_custody_outbound_asset() {
        let seller = fixture_account("seller");
        let buyer = fixture_account("buyer");
        let court = fixture_account("court");
        let asset_definition = fixture_asset_definition_id();
        let escrow_id = fixture_escrow_id("resolution-custody-disabled");
        let amount = Quantity::from(40_u32);
        let state = state_with_parties(
            &seller,
            &buyer,
            &court,
            &asset_definition,
            Quantity::from(100_u32),
        );
        let mut block = state.block(block_header(3_000));
        let mut tx = block.transaction_for_fastpq_testing(Hash::prehashed([0xB6; Hash::LENGTH]));
        OpenAssetEscrow {
            escrow_id,
            asset_definition: asset_definition.clone(),
            amount: amount.clone(),
            evidence_hashes: Vec::new(),
        }
        .execute(&seller, &mut tx)
        .expect("open escrow");
        let custody = escrow_record(&tx, &escrow_id).custody;
        AcceptAssetEscrow { escrow_id }
            .execute(&buyer, &mut tx)
            .expect("accept escrow");
        OpenEscrowDispute {
            escrow_id,
            evidence_hashes: Vec::new(),
        }
        .execute(&buyer, &mut tx)
        .expect("open dispute");
        grant_court_permission(&mut tx, &court);
        disable_outbound_asset_transfers(&mut tx, &seller, &custody, &asset_definition);
        let err = ResolveEscrowDispute {
            escrow_id,
            buyer_amount: Quantity::from(25_u32),
            seller_amount: Quantity::from(15_u32),
            evidence_hashes: Vec::new(),
        }
        .execute(&court, &mut tx)
        .expect_err("disabled custody outbound must block resolution");
        assert!(
            matches!(
                err,
                InstructionExecutionError::AssetTransferAdmission(
                    iroha_data_model::isi::error::AssetTransferAdmissionError::OutgoingDisabled(_)
                )
            ),
            "unexpected error: {err}"
        );
        let record = escrow_record(&tx, &escrow_id);
        assert_eq!(record.status, AssetEscrowStatus::Disputed);
        assert_eq!(balance(&tx, &record.custody, &asset_definition), amount);
        assert_eq!(balance(&tx, &buyer, &asset_definition), Quantity::zero());
        assert_eq!(
            balance(&tx, &seller, &asset_definition),
            Quantity::from(60_u32)
        );
    }
    #[test]
    fn generic_debits_from_native_escrow_custody_are_rejected() {
        let seller = fixture_account("seller");
        let buyer = fixture_account("buyer");
        let court = fixture_account("court");
        let asset_definition = fixture_asset_definition_id();
        let escrow_id = fixture_escrow_id("direct-transfer");
        let state = state_with_parties(
            &seller,
            &buyer,
            &court,
            &asset_definition,
            Quantity::from(100_u32),
        );
        let mut block = state.block(block_header(4_000));
        let mut tx = block.transaction_for_fastpq_testing(Hash::prehashed([0xB7; Hash::LENGTH]));
        OpenAssetEscrow {
            escrow_id,
            asset_definition: asset_definition.clone(),
            amount: Quantity::from(40_u32),
            evidence_hashes: Vec::new(),
        }
        .execute(&seller, &mut tx)
        .expect("open escrow");
        let record = escrow_record(&tx, &escrow_id);
        let custody = record.custody.clone();
        let custody_asset = AssetId::of(asset_definition.clone(), record.custody.clone());
        let replacement = fixture_account("custody-controller-replacement");
        let rekey_error = ReplaceAccountController {
            account: custody.clone(),
            new_controller: replacement.controller().clone(),
        }
        .execute(&custody, &mut tx)
        .expect_err("protocol custody account must not be rekeyed");
        assert!(
            rekey_error
                .to_string()
                .contains("native escrow or VPN lease custody"),
            "unexpected error: {rekey_error}"
        );
        let unregister_error = Unregister::account(custody.clone())
            .execute(&custody, &mut tx)
            .expect_err("protocol custody account must not be unregistered");
        assert!(
            unregister_error
                .to_string()
                .contains("native escrow or VPN lease custody"),
            "unexpected error: {unregister_error}"
        );
        assert!(
            tx.world.accounts.get(&custody).is_some(),
            "rejected unregister must retain the custody account"
        );
        assert!(
            Transfer::asset_quantity(custody_asset.clone(), 1_u32, buyer.clone())
                .execute(&seller, &mut tx)
                .is_err(),
            "generic asset transfer must not drain active native escrow custody"
        );
        assert!(
            Burn::asset_quantity(1_u32, custody_asset.clone())
                .execute(&seller, &mut tx)
                .is_err(),
            "generic asset burn must not drain active native escrow custody"
        );
        AcceptAssetEscrow { escrow_id }
            .execute(&buyer, &mut tx)
            .expect("accept escrow");
        MarkEscrowPaymentSent { escrow_id }
            .execute(&buyer, &mut tx)
            .expect("mark payment sent");
        ReleaseAssetEscrow { escrow_id }
            .execute(&seller, &mut tx)
            .expect("release escrow");
        state_transaction_deposit_closed_custody_dust(
            &mut tx,
            &custody_asset,
            Quantity::from(1_u32),
        );
        assert!(
            Transfer::asset_quantity(custody_asset.clone(), 1_u32, buyer)
                .execute(&seller, &mut tx)
                .is_err(),
            "generic asset transfer must not drain recorded native escrow custody after close"
        );
        assert!(
            Burn::asset_quantity(1_u32, custody_asset.clone())
                .execute(&seller, &mut tx)
                .is_err(),
            "generic asset burn must not drain recorded native escrow custody after close"
        );
    }
    #[test]
    fn generic_debits_from_native_asset_lock_custody_are_rejected() {
        let source = fixture_account("lock-direct-source");
        let destination = fixture_account("lock-direct-destination");
        let observer = fixture_account("lock-direct-observer");
        let asset_definition = fixture_asset_definition_id();
        let escrow_id = fixture_escrow_id("lock-direct-transfer");
        let state = state_with_parties(
            &source,
            &destination,
            &observer,
            &asset_definition,
            Quantity::from(100_u32),
        );
        let mut block = state.block(block_header(4_100));
        let mut tx = block.transaction_for_fastpq_testing(Hash::prehashed([0xC8; Hash::LENGTH]));
        OpenAssetLock::new(
            escrow_id,
            asset_definition.clone(),
            destination.clone(),
            Quantity::from(40_u32),
        )
        .execute(&source, &mut tx)
        .expect("open asset lock");
        let record = escrow_record(&tx, &escrow_id);
        let custody_asset = AssetId::of(asset_definition.clone(), record.custody.clone());
        assert!(
            Transfer::asset_quantity(custody_asset.clone(), 1_u32, destination.clone())
                .execute(&source, &mut tx)
                .is_err(),
            "generic asset transfer must not drain active native lock custody"
        );
        assert!(
            Burn::asset_quantity(1_u32, custody_asset.clone())
                .execute(&source, &mut tx)
                .is_err(),
            "generic asset burn must not drain active native lock custody"
        );
        DrawdownAssetLock::new(escrow_id, Quantity::from(40_u32), Quantity::from(40_u32))
            .execute(&destination, &mut tx)
            .expect("draw down lock");
        state_transaction_deposit_closed_custody_dust(
            &mut tx,
            &custody_asset,
            Quantity::from(1_u32),
        );
        assert!(
            Transfer::asset_quantity(custody_asset.clone(), 1_u32, destination.clone())
                .execute(&source, &mut tx)
                .is_err(),
            "generic asset transfer must not drain recorded native lock custody after close"
        );
        assert!(
            Burn::asset_quantity(1_u32, custody_asset.clone())
                .execute(&source, &mut tx)
                .is_err(),
            "generic asset burn must not drain recorded native lock custody after close"
        );
    }
}
