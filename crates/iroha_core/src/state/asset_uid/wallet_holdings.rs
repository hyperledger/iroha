//! Exact requested-wallet amounts from one original UID query snapshot.
//!
//! Only a caller carrying the native query's finite source-work meter may use
//! this collector. It scans the complete canonical escrow table and checks both
//! reciprocal indexes; a refused scan never produces an amount or partial row.
use super::{binding_key, range_bounds};
use crate::state::WorldReadOnly;
use iroha_data_model::{
    NetworkId,
    account::AccountId,
    asset::{
        AssetBalancePolicy, AssetBalanceScope, AssetId,
        uid::{AssetUidBindingV1, AssetUidPolicyV1, AssetUidWalletHoldingsV1},
    },
    escrow::{AssetEscrowKind, AssetEscrowStatus},
    query::error::QueryExecutionFail as Error,
};
use iroha_primitives::numeric::Quantity;
use mv::storage::StorageReadOnly as _;

fn inconsistent(message: &'static str) -> Error {
    Error::Conversion(message.into())
}
fn add(target: &mut Quantity, amount: &Quantity) -> Result<(), Error> {
    *target = target
        .checked_add(amount)
        .map_err(|_| Error::CapacityLimit)?;
    Ok(())
}
fn increment(value: &mut usize) -> Result<(), Error> {
    *value = value.checked_add(1).ok_or(Error::CapacityLimit)?;
    Ok(())
}
fn global_asset(policy: &AssetUidPolicyV1, account: &AccountId) -> Result<AssetId, Error> {
    Ok(AssetId::with_scope(
        policy.asset_definition_id.clone(),
        account
            .try_clone_for_admission()
            .map_err(|_| Error::CapacityLimit)?,
        AssetBalanceScope::Global,
    ))
}

/// Collect exact Global amounts for one reciprocally enrolled retail wallet.
///
/// `now` and `network` belong to the same original State snapshot as `world`.
/// The caller supplies that query's existing finite meter, including both
/// preflight and retained-row passes. Absence of a balance after account,
/// definition and membership validation is the ledger's canonical zero.
#[allow(clippy::too_many_arguments)]
pub(crate) fn collect(
    world: &impl WorldReadOnly,
    network: &NetworkId,
    policy: &AssetUidPolicyV1,
    account: &AccountId,
    now: u64,
    maximum: usize,
    decode_limits: norito::DecodeLimits,
    mut meter: impl FnMut() -> Result<(), Error>,
) -> Result<AssetUidWalletHoldingsV1, Error> {
    policy
        .validate_shape()
        .map_err(|message| Error::Conversion(message.into()))?;
    meter()?;
    if !policy.accounts.contains(account) || world.accounts().get(account).is_none() {
        return Err(inconsistent("requested wallet is not a current UID member"));
    }
    meter()?;
    let definition = world
        .asset_definitions()
        .get(&policy.asset_definition_id)
        .ok_or_else(|| inconsistent("requested wallet asset definition is unavailable"))?;
    if definition.balance_scope_policy() != AssetBalancePolicy::Global {
        return Err(inconsistent(
            "UID wallet holdings require the native Global asset scope",
        ));
    }
    meter()?;
    let bytes = world
        .smart_contract_state()
        .get(&binding_key(&policy.asset_definition_id, account))
        .ok_or_else(|| inconsistent("requested wallet has no reciprocal UID binding"))?;
    if bytes.len() > maximum {
        return Err(Error::CapacityLimit);
    }
    let binding = norito::decode_canonical_with_limits::<AssetUidBindingV1>(bytes, decode_limits)
        .map_err(|_| Error::CapacityLimit)?;
    if binding.asset_definition_id != policy.asset_definition_id
        || binding.account_id != *account
        || binding.uid != policy.uid
        || binding.uid == [0; 32]
    {
        return Err(inconsistent(
            "requested wallet UID binding differs from selected policy",
        ));
    }
    let asset_id = global_asset(policy, account)?;
    meter()?;
    let mut spendable = Quantity::zero();
    if let Some(amount) = world.assets().get(&asset_id) {
        add(&mut spendable, amount.as_ref())?;
    }
    let mut locked = Quantity::zero();
    let mut pending_incoming = Quantity::zero();
    let mut sellers = 0usize;
    let mut buyers = 0usize;
    // Deliberately no take()/pagination: completion is part of each returned amount.
    for (id, escrow) in world.asset_escrows().iter() {
        meter()?;
        if escrow.custody == *account {
            return Err(inconsistent(
                "native escrow custody cannot be a requested UID wallet",
            ));
        }
        let seller = escrow.seller == *account;
        let buyer = escrow.buyer.as_ref() == Some(account);
        if seller {
            increment(&mut sellers)?;
        }
        if buyer {
            increment(&mut buyers)?;
        }
        if !seller && !buyer {
            continue;
        }
        if escrow.id != *id {
            return Err(inconsistent("wallet escrow differs from canonical key"));
        }
        if escrow.asset_definition != policy.asset_definition_id {
            continue;
        }
        let unresolved = match (escrow.kind, escrow.status) {
            (
                AssetEscrowKind::Marketplace,
                AssetEscrowStatus::Open
                | AssetEscrowStatus::Accepted
                | AssetEscrowStatus::PaymentSent
                | AssetEscrowStatus::Disputed,
            ) => true,
            (AssetEscrowKind::Lock | AssetEscrowKind::Conditional, AssetEscrowStatus::Locked) => {
                true
            }
            (
                _,
                AssetEscrowStatus::Released
                | AssetEscrowStatus::Cancelled
                | AssetEscrowStatus::Resolved
                | AssetEscrowStatus::DrawnDown
                | AssetEscrowStatus::Expired,
            ) => false,
            _ => {
                return Err(inconsistent(
                    "wallet escrow kind and status are inconsistent",
                ));
            }
        };
        if !unresolved {
            continue;
        }
        if escrow.closed_at_ms.is_some() {
            return Err(inconsistent(
                "unresolved wallet escrow has a closed timestamp",
            ));
        }
        let expected = crate::smartcontracts::isi::escrow::escrow_custody_account_id(
            network,
            id,
            &escrow.asset_definition,
        );
        meter()?;
        if escrow.custody != expected
            || escrow.custody == *account
            || world.accounts().get(&escrow.custody).is_none()
        {
            return Err(inconsistent(
                "wallet escrow custody is unavailable or noncanonical",
            ));
        }
        let custody_asset = global_asset(policy, &escrow.custody)?;
        meter()?;
        let actual = world.assets().get(&custody_asset);
        if seller {
            // Expiry does not return custody: an unresolved refund remains locked.
            if let Some(amount) = actual {
                add(&mut locked, amount.as_ref())?;
            }
        }
        if buyer && escrow.kind == AssetEscrowKind::Conditional {
            let expiry = escrow
                .expires_at_ms
                .ok_or_else(|| inconsistent("conditional escrow has no effective expiry"))?;
            if expiry <= escrow.created_at_ms || escrow.conditions.is_empty() {
                return Err(inconsistent(
                    "conditional escrow expiry or condition state is invalid",
                ));
            }
            // Opening already stored min(explicit expiry, created + Within).
            // Native attestation rejects now >= expiry; do not recompute it here.
            if now < expiry {
                if let Some(amount) = actual {
                    add(&mut pending_incoming, amount.as_ref())?;
                }
            }
        }
    }
    let mut indexed_sellers = 0usize;
    for id in range_bounds::index_members(world.asset_escrows_by_seller(), account) {
        meter()?;
        let escrow = world
            .asset_escrows()
            .get(id)
            .ok_or_else(|| inconsistent("wallet seller index references a missing escrow"))?;
        if escrow.id != *id || escrow.seller != *account {
            return Err(inconsistent("wallet seller index is not reciprocal"));
        }
        increment(&mut indexed_sellers)?;
    }
    let mut indexed_buyers = 0usize;
    for id in range_bounds::index_members(world.asset_escrows_by_buyer(), account) {
        meter()?;
        let escrow = world
            .asset_escrows()
            .get(id)
            .ok_or_else(|| inconsistent("wallet buyer index references a missing escrow"))?;
        if escrow.id != *id || escrow.buyer.as_ref() != Some(account) {
            return Err(inconsistent("wallet buyer index is not reciprocal"));
        }
        increment(&mut indexed_buyers)?;
    }
    if sellers != indexed_sellers || buyers != indexed_buyers {
        return Err(inconsistent("wallet escrow indexes omit canonical records"));
    }
    let total = spendable
        .checked_add(&locked)
        .map_err(|_| Error::CapacityLimit)?;
    Ok(AssetUidWalletHoldingsV1 {
        account_id: account
            .try_clone_for_admission()
            .map_err(|_| Error::CapacityLimit)?,
        asset_id,
        spendable,
        locked,
        total,
        pending_incoming,
    })
}

#[cfg(test)]
#[path = "wallet_holdings/tests.rs"]
mod tests;
