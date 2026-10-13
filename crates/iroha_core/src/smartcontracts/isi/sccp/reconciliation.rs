//! Quarantine reconciliation (§4.10): one proof window, immutable rate and exact settlement.
//!
//! Proofs bind an authenticated destination finalization to its canonical payload preimage.
//! Window close and claim accounting touch one fixed-size retained record; proof ids have
//! separate original-pool custody, and the scheduler reads an ordered deadline index.

use super::{Error, light_clients, reconciliation_store as records, store};
use crate::state::{StateReadOnly, StateTransaction, WorldReadOnly};
use iroha_data_model::{
    account::AccountId,
    bridge::SccpNetworkV1,
    isi::sccp::ProveSccpForgedMintV1,
    sccp::{
        events::{
            SccpEvent, SccpForgedMintProvenV1, SccpReconciledClaimSettledV1,
            SccpReconciliationOpenedV1, SccpReconciliationSettledV1,
        },
        reconciliation::{SccpReconciliationRatioV1, SccpReconciliationStateV1},
    },
};
use iroha_sccp::{
    light_client::proof::SccpNormalizedEventV1,
    v1::{hashes, network, payload::SccpTransferPayloadRefV1},
};

fn refuse(reason: impl core::fmt::Display) -> Error {
    Error::InvariantViolation(format!("SCCP reconciliation: {reason}").into())
}

/// Whether the sole reconciliation window has fixed its permanent rate.
#[must_use]
pub fn is_reconciled(
    world: &(impl WorldReadOnly + ?Sized),
    network: SccpNetworkV1,
    revision: u32,
) -> bool {
    records::get(world, &(network, revision)).is_some_and(|record| record.rho.is_some())
}

/// Enact Parliament's opening of the sole proof window of a quarantined revision.
/// # Errors
/// Refuses absent quarantine, an existing window, empty duration or timestamp overflow.
pub fn open(
    state: &mut StateTransaction<'_, '_>,
    network: SccpNetworkV1,
    revision: u32,
    window_ms: u64,
) -> Result<(), Error> {
    let key = (network, revision);
    let world = &*state.world;
    if !store::routes::get(world, &network)
        .and_then(|route| route.revisions.get(&revision))
        .is_some_and(|record| record.quarantine.is_some())
    {
        return Err(refuse("revision is not quarantined"));
    }
    if records::get(world, &key).is_some() || window_ms == 0 {
        return Err(refuse("window exists or duration is zero"));
    }
    let opened_at_ms = state.block_unix_timestamp_ms();
    let closes_at_ms = opened_at_ms
        .checked_add(window_ms)
        .ok_or_else(|| refuse("window deadline overflow"))?;
    records::put(
        state,
        key,
        SccpReconciliationStateV1 {
            opened_at_ms,
            closes_at_ms,
            forged_supply: 0,
            rho: None,
            settled_face: 0,
        },
    )?;
    state
        .world
        .emit_events(Some(SccpEvent::ReconciliationOpened(
            SccpReconciliationOpenedV1 {
                network,
                revision,
                opened_at_ms,
                closes_at_ms,
            },
        )));
    Ok(())
}

/// Permissionless forged-mint proof during a quarantined revision's open proof window.
/// # Errors
/// Refuses a closed window, invalid source proof or payload binding, a genuine or repeated
/// message id, or forged-supply overflow. Original local resource refusals abort publication.
pub fn execute_prove(
    instruction: ProveSccpForgedMintV1,
    _authority: &AccountId,
    state: &mut StateTransaction<'_, '_>,
) -> Result<(), Error> {
    let (network, revision) = (instruction.network, instruction.revision);
    let key = (network, revision);
    let mut record = records::get(&*state.world, &key)
        .copied()
        .ok_or_else(|| refuse("window is absent"))?;
    if record.rho.is_some() || state.block_unix_timestamp_ms() >= record.closes_at_ms {
        return Err(refuse("proof window is closed"));
    }
    let route = store::routes::get(&*state.world, &network)
        .and_then(|route| route.revisions.get(&revision))
        .filter(|route| route.quarantine.is_some())
        .ok_or_else(|| refuse("revision is not quarantined"))?;
    let deployment = route.deployment;
    let liability = route.liability;
    // Borrowed canonical parsing allocates no scratch payload or variable fields.
    let bytes = instruction.proof.payload.as_bytes();
    let payload = SccpTransferPayloadRefV1::decode(bytes)
        .map_err(|error| refuse(format_args!("payload: {error}")))?;
    if !payload.is_outbound()
        || payload.target() != Some(network)
        || payload.route_revision != revision
    {
        return Err(refuse("payload belongs to another lane or revision"));
    }
    let lane = network::lane_bytes(
        SccpNetworkV1::SoraTaira,
        network,
        state.network_id().as_bytes(),
    )
    .ok_or_else(|| refuse("invalid external lane"))?;
    let message_id = hashes::message_id(&lane, &hashes::payload_hash(bytes));
    if store::outbound_messages::get(&*state.world, &message_id)
        .is_some_and(|original| original.network == network && original.revision == revision)
    {
        return Err(refuse("message was genuinely recorded on Taira"));
    }
    if records::proven(&*state.world, key, &message_id) {
        return Err(refuse("forged mint was already proven"));
    }
    let next_supply = record
        .forged_supply
        .checked_add(payload.amount)
        .filter(|sum| liability.checked_add(*sum).is_some())
        .ok_or_else(|| refuse("liability plus forged supply overflows"))?;
    let verified = light_clients::verify_source_proof(state, network, &instruction.proof.source)?;
    let SccpNormalizedEventV1::Finalized {
        emitter,
        message_id: proven_id,
        nonce,
        amount,
        ..
    } = verified.event
    else {
        return Err(refuse("proof does not authenticate a finalization"));
    };
    bind_finalization(
        &deployment,
        &emitter,
        message_id,
        payload.nonce,
        payload.amount,
        proven_id,
        nonce,
        amount,
    )?;
    records::prove(state, key, message_id, payload.amount)?;
    record.forged_supply = next_supply;
    records::put(state, key, record)?;
    state
        .world
        .emit_events(Some(SccpEvent::ForgedMintProven(SccpForgedMintProvenV1 {
            network,
            revision,
            message_id,
            amount: payload.amount,
        })));
    Ok(())
}

/// Bind the authenticated event to its registered deployment and canonical payload.
fn bind_finalization(
    deployment: &iroha_data_model::sccp::deployment::SccpDeploymentV1,
    emitter: &iroha_sccp::light_client::proof::SccpSourceEmitterV1,
    message_id: [u8; 32],
    payload_nonce: u64,
    payload_amount: u128,
    proven_id: [u8; 32],
    nonce: u64,
    amount: Option<u128>,
) -> Result<(), Error> {
    if !cfg!(all(test, sumeragi_core_mutation = "HC287"))
        && (!emitter.matches(deployment)
            || proven_id != message_id
            || nonce != payload_nonce
            || amount.is_some_and(|amount| amount != payload_amount))
    {
        return Err(refuse(
            "finalization differs from its deployment or payload",
        ));
    }
    Ok(())
}

/// Close one due window in constant work at block start, reserving all pending refunds.
/// # Errors
/// Refuses missing route liability, overflow or original local State admission failure.
/// Returns false if the window is absent, already closed or not yet due.
pub fn end_one(
    state: &mut StateTransaction<'_, '_>,
    network: SccpNetworkV1,
    revision: u32,
) -> Result<bool, Error> {
    let key = (network, revision);
    let Some(mut record) = records::get(&*state.world, &key).copied() else {
        return Ok(false);
    };
    if record.rho.is_some() || state.block_unix_timestamp_ms() < record.closes_at_ms {
        return Ok(false);
    }
    let liability = store::routes::get(&*state.world, &network)
        .and_then(|route| route.revisions.get(&revision))
        .map(|route| route.liability)
        .ok_or_else(|| refuse("unknown revision"))?;
    let backing = liability.saturating_sub(records::pending_refunds(&*state.world, &key));
    let denominator = backing
        .checked_add(record.forged_supply)
        .ok_or_else(|| refuse("fixed rate overflow"))?
        .max(1);
    record.rho = Some(SccpReconciliationRatioV1 {
        backing,
        denominator,
    });
    records::put(state, key, record)?;
    state
        .world
        .emit_events(Some(SccpEvent::ReconciliationSettled(
            SccpReconciliationSettledV1 {
                network,
                revision,
                backing,
                forged_supply: record.forged_supply,
            },
        )));
    Ok(true)
}

/// The exact payout for a reconciled claim, absent for ordinary settlement.
/// # Errors
/// Refuses structurally corrupt stored ratios; valid rates always yield a u128 payout.
pub(super) fn claim_payout(
    world: &(impl WorldReadOnly + ?Sized),
    network: SccpNetworkV1,
    revision: u32,
    amount: u128,
    liability: u128,
) -> Result<Option<u128>, Error> {
    let key = (network, revision);
    let Some(record) = records::get(world, &key) else {
        return Ok(None);
    };
    let Some(rate) = record.rho else {
        return Ok(None);
    };
    let available = if cfg!(all(test, sumeragi_core_mutation = "HC289")) {
        liability
    } else {
        liability.saturating_sub(records::pending_refunds(world, &key))
    };
    iroha_sccp::v1::reconciliation::payout(
        rate.backing,
        rate.denominator,
        record.settled_face,
        amount,
        available,
    )
    .map(Some)
    .ok_or_else(|| refuse("invalid stored settlement rate"))
}

/// Advance face accounting only after a claim has actually left Pending in this transaction.
/// # Errors
/// Refuses original local State admission failure; ordinary claims have no reconciliation effect.
pub(super) fn claim_settled(
    state: &mut StateTransaction<'_, '_>,
    network: SccpNetworkV1,
    revision: u32,
    message_id: [u8; 32],
    amount: u128,
    payout: u128,
) -> Result<(), Error> {
    let key = (network, revision);
    let Some(mut record) = records::get(&*state.world, &key)
        .copied()
        .filter(|record| record.rho.is_some())
    else {
        return Ok(());
    };
    record.settled_face = record.settled_face.saturating_add(amount);
    records::put(state, key, record)?;
    state
        .world
        .emit_events(Some(SccpEvent::ReconciledClaimSettled(
            SccpReconciledClaimSettledV1 {
                network,
                revision,
                message_id,
                amount,
                payout,
            },
        )));
    Ok(())
}

#[cfg(test)]
mod tests;
