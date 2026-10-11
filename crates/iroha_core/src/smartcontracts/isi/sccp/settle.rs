//! Settlement: inbound release and bounce, outbound refunds and `SettleSccpV1` retries
//! (`specs/sccp.md` §4.12.3, §4.12.5, §4.16). Owner: ws41.
//!
//! A proven inbound message settles when SCCP is enabled and its revision is `Bidirectional`
//! or `InboundOnly`; otherwise it stays `Pending` with a reason. A creditable recipient is
//! released `amount − fee_due` (the fee goes to the Nexus fee sink); a recipient that can never
//! be credited bounces the value back to the source-chain sender through a new outbound
//! message. A voided outbound record is refunded to its sender, or moved to `stranded(route)`
//! when the sender is the escrow (a bounce) or can never be credited. Every path keeps
//! `balance(escrow) = Σ liability + stranded`.
//!
//! **Deterministic refusals hold, they never fail.** Every refusal a settlement step can meet
//! is checked without mutating state before the step's effects run: a credit the release
//! movement refuses now (`CreditRefused`), a fee sink that cannot receive the fee
//! (`FeeSinkUnavailable`) and a bounce without a free commitment leaf (`BlockLeavesFull`) keep
//! the record `Pending`, and a refund the movement refuses keeps the record voided with its
//! refund pending. So the proof or void that triggered settlement is still recorded, and one
//! refusal never aborts a void range. Only an execution invariant violation fails, besides a
//! local fee-sink read that did not complete, which defers the transaction.

use super::{
    Error, escrow, leaves,
    outbound::{self, OutboundRecordArgsV1},
    recipients::{self, SccpRecipientClassV1},
    store,
};
use crate::state::{StateTransaction, WorldReadOnly};
use iroha_data_model::{
    account::AccountId,
    bridge::SccpNetworkV1,
    isi::sccp::{SccpSettleTargetV1, SettleSccpV1},
    sccp::{
        events::{
            SccpBounceReasonV1, SccpEvent, SccpInboundBouncedV1, SccpInboundLiabilityShortfallV1,
            SccpInboundReleasedV1, SccpOutboundRefundedV1, SccpOutboundStrandedV1,
            SccpRecipientRegisteredV1,
        },
        inbound::{
            SccpBounceStatusV1, SccpInboundRecordV1, SccpInboundStatusV1, SccpPendingReasonV1,
        },
        outbound::{SccpOutboundStatusV1, SccpStatusHeightV1},
        registry::SccpRouteActivationV1,
    },
};
use iroha_sccp::v1::payload::SccpTransferPayloadV1;

fn refuse(reason: impl core::fmt::Display) -> Error {
    Error::InvariantViolation(format!("SCCP settlement: {reason}").into())
}

/// Add `(inbound, refund)` to the pending counts of `(network, revision)`.
pub(super) fn adjust_pending(
    state_transaction: &mut StateTransaction<'_, '_>,
    key: (SccpNetworkV1, u32),
    inbound: i64,
    refund: i64,
) -> Result<(), Error> {
    let (current_inbound, current_refund) = store::pending_count(&*state_transaction.world, &key);
    let add = |value: u64, delta: i64| {
        value
            .checked_add_signed(delta)
            .ok_or_else(|| refuse("pending count underflows"))
    };
    let counts = (add(current_inbound, inbound)?, add(current_refund, refund)?);
    store::set_pending_counts(state_transaction, key, counts);
    Ok(())
}

/// Add `delta` to `liability(revision)` of `network`.
pub(super) fn adjust_liability(
    state_transaction: &mut StateTransaction<'_, '_>,
    network: SccpNetworkV1,
    revision: u32,
    delta: i128,
) -> Result<(), Error> {
    let mut route = store::routes::get(&*state_transaction.world, &network)
        .cloned()
        .ok_or_else(|| refuse("the route is unknown"))?;
    let record = route
        .revisions
        .get_mut(&revision)
        .ok_or_else(|| refuse(format_args!("revision {revision} is unknown")))?;
    record.liability = record
        .liability
        .checked_add_signed(delta)
        .ok_or_else(|| refuse("liability out of range"))?;
    store::routes::insert(state_transaction, network, route)?;
    Ok(())
}

fn activation(
    world: &(impl WorldReadOnly + ?Sized),
    network: SccpNetworkV1,
    revision: u32,
) -> Option<(SccpRouteActivationV1, u128)> {
    store::routes::get(world, &network)
        .and_then(|route| route.revisions.get(&revision))
        .map(|record| (record.activation, record.liability))
}

/// Return whether settling the `Pending` inbound `record` of `amount` Taira units can release
/// or bounce it against `world` (§4.12.4): SCCP is enabled, the revision settles and its
/// liability covers the amount.
///
/// These are the holds a settlement decides before any effect (`Disabled`,
/// `RevisionNotSettleable`, `LiabilityShortfall`), so a `false` is certain. The holds the
/// release itself decides (`CreditRefused`, `FeeSinkUnavailable`, `BlockLeavesFull`) are not
/// predicted; an attempt that meets one and changes nothing fails.
#[must_use]
pub fn inbound_settlement_may_progress(
    world: &(impl WorldReadOnly + ?Sized),
    record: &SccpInboundRecordV1,
    amount: u128,
) -> bool {
    let enabled = store::parameters::get(world)
        .as_ref()
        .is_some_and(|params| params.enabled);
    enabled
        && record.status.is_pending()
        && activation(world, record.network, record.revision)
            .is_some_and(|(activation, liability)| activation.settles() && liability >= amount)
}

fn set_inbound_status(
    state_transaction: &mut StateTransaction<'_, '_>,
    message_id: [u8; 32],
    mut record: SccpInboundRecordV1,
    status: SccpInboundStatusV1,
) -> Result<(), Error> {
    record.status = status;
    store::inbound_messages::insert(state_transaction, message_id, record)?;
    Ok(())
}

/// Keep the `Pending` inbound record `message_id` held with `reason` and return whether the
/// attempt changed state: the reason changed, or the attempt already registered the recipient
/// (`registered`).
fn hold_inbound(
    state_transaction: &mut StateTransaction<'_, '_>,
    message_id: [u8; 32],
    record: SccpInboundRecordV1,
    reason: SccpPendingReasonV1,
    registered: bool,
) -> Result<bool, Error> {
    let SccpInboundStatusV1::Pending(pending) = record.status else {
        return Err(refuse("the inbound message is not pending"));
    };
    let changed = pending.reason != reason;
    if changed {
        set_inbound_status(
            state_transaction,
            message_id,
            record,
            SccpInboundStatusV1::pending(reason),
        )?;
    }
    Ok(changed || registered)
}

/// Resolve the Nexus fee sink account under the executing block; `Ok(None)` when the
/// configured literal names no account.
///
/// # Errors
///
/// Fails, deferring the transaction, when the local alias read did not complete.
fn fee_sink(state_transaction: &StateTransaction<'_, '_>) -> Result<Option<AccountId>, Error> {
    match crate::block::parse_account_literal_with_world(
        &*state_transaction.world,
        &state_transaction.nexus.dataspace_catalog,
        &state_transaction.nexus.fees.fee_sink_account_id,
        state_transaction.block_unix_timestamp_ms(),
    ) {
        Ok(sink) => Ok(sink),
        Err(crate::sns::SnsError::Deferred(reason)) => {
            let _ = state_transaction.world.defer_execution(reason);
            Err(refuse("the local fee sink read did not complete"))
        }
        Err(_) => Ok(None),
    }
}

/// Attempt to settle the `Pending` inbound message `message_id` (§4.12.3, §4.12.5) and return
/// whether its record or its recipient changed.
///
/// A deterministic refusal keeps the record `Pending` with its reason and succeeds.
///
/// # Errors
///
/// Fails when the record is missing or not `Pending`, or on an execution invariant violation
/// (an undecodable stored payload, an unknown revision, an effect failing after its precheck).
pub fn settle_inbound(
    state_transaction: &mut StateTransaction<'_, '_>,
    message_id: [u8; 32],
) -> Result<bool, Error> {
    let world = &*state_transaction.world;
    let record = store::inbound_messages::get(world, &message_id)
        .cloned()
        .ok_or_else(|| refuse("unknown inbound message"))?;
    if !record.status.is_pending() {
        return Err(refuse("the inbound message is not pending"));
    }
    let (network, revision) = (record.network, record.revision);
    let enabled = store::parameters::get(world)
        .as_ref()
        .is_some_and(|params| params.enabled);
    let (activation, liability) =
        activation(world, network, revision).ok_or_else(|| refuse("the revision is unknown"))?;
    let hold = if !enabled {
        Some(SccpPendingReasonV1::Disabled)
    } else if !activation.settles() {
        Some(SccpPendingReasonV1::RevisionNotSettleable)
    } else {
        None
    };
    if let Some(reason) = hold {
        return hold_inbound(state_transaction, message_id, record, reason, false);
    }
    let payload = SccpTransferPayloadV1::decode(&record.payload)
        .map_err(|error| refuse(format_args!("stored payload: {error}")))?;
    let amount = payload.amount;
    if liability < amount {
        state_transaction
            .world
            .emit_events(Some(SccpEvent::InboundLiabilityShortfall(
                SccpInboundLiabilityShortfallV1 {
                    message_id,
                    network,
                    revision,
                    amount,
                    liability,
                },
            )));
        return hold_inbound(
            state_transaction,
            message_id,
            record,
            SccpPendingReasonV1::LiabilityShortfall,
            false,
        );
    }
    match recipients::classify_recipient(state_transaction, &payload.recipient.bytes) {
        SccpRecipientClassV1::Creditable {
            account,
            registered,
        } => release_inbound(
            state_transaction,
            message_id,
            record,
            amount,
            (account, registered),
        ),
        SccpRecipientClassV1::Uncreditable { reason, .. } => {
            bounce_inbound(state_transaction, message_id, record, &payload, reason)
        }
        SccpRecipientClassV1::Undecodable => bounce_inbound(
            state_transaction,
            message_id,
            record,
            &payload,
            SccpBounceReasonV1::UndecodableRecipient,
        ),
    }
}

/// Release the inbound message `message_id` of `amount` Taira units to the creditable
/// `recipient` `(account, registered)` (§4.12.3 steps 4–7), or hold it when the fee sink
/// or the release movement refuses a credit.
fn release_inbound(
    state_transaction: &mut StateTransaction<'_, '_>,
    message_id: [u8; 32],
    record: SccpInboundRecordV1,
    amount: u128,
    (account, registered): (AccountId, bool),
) -> Result<bool, Error> {
    let (network, revision) = (record.network, record.revision);
    let fee = record.fee_due.min(amount);
    let net = amount - fee;
    let sink = if fee == 0 {
        None
    } else {
        match fee_sink(state_transaction)? {
            Some(sink) if state_transaction.world.account(&sink).is_ok() => Some(sink),
            _ => {
                return hold_inbound(
                    state_transaction,
                    message_id,
                    record,
                    SccpPendingReasonV1::FeeSinkUnavailable,
                    false,
                );
            }
        }
    };
    // The classification ran the identity precheck of `Register<Account>`, so this is an
    // ordinary registration that cannot be refused; the movement is prechecked against the
    // registered account below.
    let registered_now = if net > 0 && !registered {
        recipients::register_recipient(state_transaction, &account, network, Some(message_id))?
    } else {
        false
    };
    let credits = release_credits(&account, net, sink.as_ref(), fee);
    for (to, value, reason) in &credits {
        if escrow::precheck_release(state_transaction, network, to, *value).is_err() {
            return hold_inbound(
                state_transaction,
                message_id,
                record,
                *reason,
                registered_now,
            );
        }
    }
    for (to, value, _) in credits {
        escrow::release(state_transaction, network, &to, value, message_id)?;
    }
    adjust_liability(state_transaction, network, revision, -to_i128(amount)?)?;
    adjust_pending(state_transaction, (network, revision), -1, 0)?;
    let height = state_transaction._curr_block.height().get();
    set_inbound_status(
        state_transaction,
        message_id,
        record,
        SccpInboundStatusV1::Released(SccpStatusHeightV1 { height }),
    )?;
    state_transaction
        .world
        .emit_events(Some(SccpEvent::InboundReleased(SccpInboundReleasedV1 {
            message_id,
            network,
            revision,
            recipient: account,
            amount,
            fee,
        })));
    Ok(true)
}

/// The escrow credits of a release of `net` to `account` and `fee` to the fee `sink`, each
/// with the hold reason its refusal maps to. Zero credits are skipped, and a sink that is the
/// recipient itself receives one combined credit.
fn release_credits(
    account: &AccountId,
    net: u128,
    sink: Option<&AccountId>,
    fee: u128,
) -> Vec<(AccountId, u128, SccpPendingReasonV1)> {
    let mut credits = Vec::with_capacity(2);
    if sink == Some(account) {
        credits.push((
            account.clone(),
            net.saturating_add(fee),
            SccpPendingReasonV1::CreditRefused,
        ));
        return credits;
    }
    if net > 0 {
        credits.push((account.clone(), net, SccpPendingReasonV1::CreditRefused));
    }
    if let Some(sink) = sink.filter(|_| fee > 0) {
        credits.push((sink.clone(), fee, SccpPendingReasonV1::FeeSinkUnavailable));
    }
    credits
}

/// Bounce the inbound message `message_id` back to its source-chain sender (§4.12.5), or hold
/// it when the executing block has no free commitment leaf.
fn bounce_inbound(
    state_transaction: &mut StateTransaction<'_, '_>,
    message_id: [u8; 32],
    record: SccpInboundRecordV1,
    payload: &SccpTransferPayloadV1,
    reason: SccpBounceReasonV1,
) -> Result<bool, Error> {
    let (network, revision, amount) = (record.network, record.revision, payload.amount);
    let height = state_transaction._curr_block.height().get();
    if leaves::leaf_count_at(&*state_transaction.world, height)
        >= leaves::MAX_LEAVES_PER_BLOCK as usize
    {
        return hold_inbound(
            state_transaction,
            message_id,
            record,
            SccpPendingReasonV1::BlockLeavesFull,
            false,
        );
    }
    let bounce_revision = bounce_target(&*state_transaction.world, network, revision, amount);
    let escrow_account = store::routes::get(&*state_transaction.world, &network)
        .map(|route| route.escrow.clone())
        .ok_or_else(|| refuse("the route is unknown"))?;
    let args = OutboundRecordArgsV1 {
        network,
        revision: bounce_revision,
        amount,
        sender: escrow_account,
        recipient: payload.sender.bytes.clone(),
    };
    // Plan before any effect. The source sender is a valid account of the route's own codec,
    // so a plan that fails is an invariant violation, never a partial bounce.
    let planned = outbound::plan(state_transaction, &args)?;
    adjust_liability(state_transaction, network, revision, -to_i128(amount)?)?;
    adjust_liability(
        state_transaction,
        network,
        bounce_revision,
        to_i128(amount)?,
    )?;
    let bounce_message_id = outbound::write_planned(state_transaction, &args, planned)?;
    adjust_pending(state_transaction, (network, revision), -1, 0)?;
    set_inbound_status(
        state_transaction,
        message_id,
        record,
        SccpInboundStatusV1::Bounced(SccpBounceStatusV1 { bounce_message_id }),
    )?;
    state_transaction
        .world
        .emit_events(Some(SccpEvent::InboundBounced(SccpInboundBouncedV1 {
            message_id,
            network,
            revision,
            bounce_message_id,
            bounce_revision,
            amount,
            reason,
        })));
    Ok(true)
}

fn to_i128(amount: u128) -> Result<i128, Error> {
    i128::try_from(amount).map_err(|_| refuse("amount out of range"))
}

/// The bounce target revision: the route's `Bidirectional` revision when its cap has room,
/// else the inbound revision itself (§4.12.5).
///
/// TODO(ws41): skip a paused, frozen or broken-chain target and hold the message when none is
/// usable, and re-bounce a voided bounce instead of stranding it (`specs/sccp.md` §13, Q10).
fn bounce_target(
    world: &(impl WorldReadOnly + ?Sized),
    network: SccpNetworkV1,
    revision: u32,
    amount: u128,
) -> u32 {
    store::routes::get(world, &network)
        .and_then(|route| route.bidirectional_revision())
        .filter(|live| {
            live.liability
                .checked_add(amount)
                .is_some_and(|liability| liability <= live.max_wrapped_supply)
        })
        .map_or(revision, |live| live.revision)
}

/// Outcome of one refund attempt of a voided outbound message (§4.16).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SccpRefundOutcomeV1 {
    /// The refund still waits for `SettleSccpV1::Refund`: SCCP is disabled, the revision is
    /// paused, the release movement refuses the credit now, or the void releases no value
    /// inline to this sender (its inline release budget is spent, or the sender is a multisig
    /// account).
    ///
    /// TODO(ws41): the voided record keeps only `refund_pending: bool`, so the hold reason is
    /// not recorded; the `Voided` status reshaping (WP7) should carry it.
    Held {
        /// Whether the attempt still changed state (it registered the absent sender).
        changed: bool,
    },
    /// The sender was credited.
    Refunded,
    /// The amount moved to `stranded(route)`: the sender is the escrow or can never be
    /// credited.
    Stranded,
}

impl SccpRefundOutcomeV1 {
    /// Return whether the attempt changed state.
    #[must_use]
    pub const fn changed(self) -> bool {
        !matches!(self, Self::Held { changed: false })
    }

    /// Return whether the refund still waits for `SettleSccpV1::Refund`.
    #[must_use]
    pub const fn is_held(self) -> bool {
        matches!(self, Self::Held { .. })
    }
}

/// Attempt the refund of the voided outbound message `message_id` (§4.16), emit the events of
/// its effects, and return the outcome.
///
/// A refund proceeds when SCCP is enabled and the revision is not `Paused`; otherwise it waits
/// for `SettleSccpV1::Refund`.
///
/// # Errors
///
/// Fails when the record is missing or has no pending refund, or on an execution invariant
/// violation.
pub fn attempt_refund(
    state_transaction: &mut StateTransaction<'_, '_>,
    message_id: [u8; 32],
) -> Result<SccpRefundOutcomeV1, Error> {
    let mut events = Vec::new();
    let outcome = refund(state_transaction, message_id, &mut events, true)?;
    state_transaction.world.emit_events(events);
    Ok(outcome)
}

/// Attempt the refund of the voided outbound message `message_id` (§4.16), appending the
/// events of its effects to `events` instead of emitting them, so a void reports its own event
/// first.
///
/// When `may_release` is false the attempt moves no value: a sender that can never be credited
/// still strands, and a creditable sender's refund stays pending (a void past its inline release
/// budget, or a multisig sender that a void never releases inline).
///
/// # Errors
///
/// See [`attempt_refund`].
pub(super) fn refund(
    state_transaction: &mut StateTransaction<'_, '_>,
    message_id: [u8; 32],
    events: &mut Vec<SccpEvent>,
    may_release: bool,
) -> Result<SccpRefundOutcomeV1, Error> {
    let world = &*state_transaction.world;
    let mut record = store::outbound_messages::get(world, &message_id)
        .cloned()
        .ok_or_else(|| refuse("unknown outbound message"))?;
    if !record.status.is_refund_pending() {
        return Err(refuse("the outbound message has no pending refund"));
    }
    let (network, revision, amount) = (record.network, record.revision, record.amount);
    let enabled = store::parameters::get(world)
        .as_ref()
        .is_some_and(|params| params.enabled);
    let (activation, _) =
        activation(world, network, revision).ok_or_else(|| refuse("the revision is unknown"))?;
    if !enabled || activation == SccpRouteActivationV1::Paused {
        return Ok(SccpRefundOutcomeV1::Held { changed: false });
    }
    let target = if escrow::is_escrow(world, &record.sender) {
        None
    } else {
        match recipients::classify_account(state_transaction, record.sender.clone()) {
            SccpRecipientClassV1::Creditable {
                account,
                registered,
            } => Some((account, registered)),
            SccpRecipientClassV1::Uncreditable { .. } | SccpRecipientClassV1::Undecodable => None,
        }
    };
    let height = state_transaction._curr_block.height().get();
    let outcome = if let Some((account, registered)) = target {
        if !may_release {
            return Ok(SccpRefundOutcomeV1::Held { changed: false });
        }
        let registered_now =
            !registered && recipients::ensure_registered(state_transaction, &account)?;
        if registered_now {
            events.push(SccpEvent::RecipientRegistered(SccpRecipientRegisteredV1 {
                account: account.clone(),
                network,
                message_id: Some(message_id),
            }));
        }
        if escrow::precheck_release(state_transaction, network, &account, amount).is_err() {
            return Ok(SccpRefundOutcomeV1::Held {
                changed: registered_now,
            });
        }
        escrow::release(state_transaction, network, &account, amount, message_id)?;
        record.status = SccpOutboundStatusV1::Refunded(SccpStatusHeightV1 { height });
        events.push(SccpEvent::OutboundRefunded(SccpOutboundRefundedV1 {
            message_id,
            network,
            revision,
            nonce: record.nonce,
            recipient: account,
            amount,
        }));
        SccpRefundOutcomeV1::Refunded
    } else {
        escrow::strand(state_transaction, network, amount)?;
        record.status = SccpOutboundStatusV1::Stranded(SccpStatusHeightV1 { height });
        events.push(SccpEvent::OutboundStranded(SccpOutboundStrandedV1 {
            message_id,
            network,
            revision,
            nonce: record.nonce,
            amount,
        }));
        SccpRefundOutcomeV1::Stranded
    };
    adjust_liability(state_transaction, network, revision, -to_i128(amount)?)?;
    adjust_pending(state_transaction, (network, revision), 0, -1)?;
    store::outbound_messages::insert(state_transaction, message_id, record)?;
    Ok(outcome)
}

/// Execute `SettleSccpV1`: retry a `Pending` inbound settlement or outbound refund without a
/// proof (§4.12.1). An exempt self-claim settle makes the self-claim fee due once, at release
/// (§4.12.4); a settle that pays the ordinary fee adds no fee.
///
/// # Errors
///
/// Fails when the target is unknown or not pending, or when the retry changes nothing.
pub fn execute_settle(
    instruction: SettleSccpV1,
    authority: &AccountId,
    state_transaction: &mut StateTransaction<'_, '_>,
) -> Result<(), Error> {
    let changed = match instruction.target {
        SccpSettleTargetV1::Inbound(target) => {
            super::inbound::charge_self_claim_fee(state_transaction, target.message_id, authority)?;
            settle_inbound(state_transaction, target.message_id)?
        }
        SccpSettleTargetV1::Refund(target) => {
            let message_id = *store::outbound_by_nonce::get(
                &*state_transaction.world,
                &(target.network, target.revision, target.nonce),
            )
            .ok_or_else(|| refuse("unknown outbound nonce"))?;
            attempt_refund(state_transaction, message_id)?.changed()
        }
    };
    if changed {
        Ok(())
    } else {
        Err(refuse("nothing changed"))
    }
}

#[cfg(test)]
mod tests;
