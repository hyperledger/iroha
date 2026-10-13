//! Outbound voids: `SubmitSccpOutboundVoidV1` (`specs/sccp.md` §4.16). Owner: ws41.
//!
//! A recorded outbound message that is never minted is recovered by voiding its nonce on the
//! destination and proving the void to Taira. Each voided `Recorded` nonce becomes `Voided`
//! and its refund is attempted through `settle::refund`: it is refunded, stranded, or
//! left pending for `SettleSccpV1::Refund`, and no single refusal aborts the range. A void
//! releases escrow value inline for at most [`inline_refund_budget`] single-key senders
//! ([`releases_inline`]), so a full frozen range stays within one transaction's FASTPQ source
//! capacity. A frozen void also drains the revision to `InboundOnly`. No refund depends on
//! Taira observing an absence.

use super::{Error, light_clients, registry, settle, store};
use crate::state::StateTransaction;
use iroha_data_model::{
    account::AccountId,
    bridge::SccpNetworkV1,
    isi::sccp::SubmitSccpOutboundVoidV1,
    sccp::{
        events::{SccpEvent, SccpOutboundVoidedV1},
        outbound::{SccpOutboundStatusV1, SccpVoidKindV1, SccpVoidStatusV1},
        registry::SccpRouteActivationV1,
    },
};
use iroha_sccp::{light_client::proof::SccpNormalizedEventV1, v1::network::max_void_frozen_range};

fn refuse(reason: impl core::fmt::Display) -> Error {
    Error::InvariantViolation(format!("SCCP void: {reason}").into())
}

/// A proven destination void of `count` consecutive nonces from `first_nonce` (§4.16).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SccpProvenVoidV1 {
    /// `voidExpired` (one nonce) or `voidFrozen` (a range).
    pub kind: SccpVoidKindV1,
    /// First voided nonce.
    pub first_nonce: u64,
    /// Number of consecutive voided nonces.
    pub count: u64,
    /// The voided message id (`voidExpired`), or zero (`voidFrozen`).
    pub message_id_or_zero: [u8; 32],
}

/// Check the nonce range of a proven void against `network`'s destination bounds: a
/// `voidExpired` names exactly one nonce, and a `voidFrozen` range is `1..=` the destination's
/// bound (256 on ETH and BSC, one 512-nonce bucket on TON).
///
/// # Errors
///
/// Fails when the range is out of bounds.
pub fn check_void_range(network: SccpNetworkV1, void: &SccpProvenVoidV1) -> Result<(), Error> {
    let max = match void.kind {
        SccpVoidKindV1::Expired => Some(1),
        SccpVoidKindV1::Frozen => max_void_frozen_range(network),
    };
    if void.count == 0 || max.is_none_or(|max| void.count > max) {
        return Err(refuse(format_args!(
            "void range {} is out of bounds for {}",
            void.count,
            network.profile_key()
        )));
    }
    Ok(())
}

/// Most escrow releases one void performs inline: half the per-transaction FASTPQ source
/// transcript and delta limit frozen at block start (8 under the bootstrap profile), at least
/// one.
///
/// Every release is one FASTPQ transfer transcript, and a transaction that exceeds its source
/// capacity is rejected as a whole, so a void of a full range (256 or 512 nonces) cannot refund
/// every sender at once. The remaining creditable refunds stay pending for
/// `SettleSccpV1::Refund`; strands and holds move no value and are not limited. The half left
/// over covers the transaction's other movements. Only single-key senders are released inline
/// ([`releases_inline`]).
#[must_use]
pub fn inline_refund_budget(state_transaction: &StateTransaction<'_, '_>) -> u32 {
    let limits = state_transaction.fastpq_intrinsic_source_limits();
    (limits.max_transcripts.min(limits.max_deltas) / 2).max(1)
}

/// Return whether a void may refund `sender` inline, within its [`inline_refund_budget`]: only
/// a single-key sender.
///
/// The transcript bytes of a release grow with the credited identity. The intrinsic byte limits
/// cover sixteen transfers between single-key accounts (ML-DSA included) but only one transfer
/// of a large multisig identity, so a void releasing inline to several multisig senders could
/// exceed its source capacity and be rejected as a whole; a frozen destination cannot void those
/// nonces again, so the refunds of the whole range would be lost. A multisig sender's refund
/// therefore stays pending for `SettleSccpV1::Refund`, which releases it alone (§4.16).
#[must_use]
pub fn releases_inline(sender: &AccountId) -> bool {
    sender.multisig_policy().is_none()
}

/// Execute `SubmitSccpOutboundVoidV1` (§4.16).
///
/// # Errors
///
/// Fails when SCCP is absent, the revision is unknown or `Staged`, the proof does not verify
/// or does not prove a void of this deployment, or [`apply_void`] fails.
pub fn execute_submit_void(
    instruction: SubmitSccpOutboundVoidV1,
    _authority: &AccountId,
    state_transaction: &mut StateTransaction<'_, '_>,
) -> Result<(), Error> {
    let (network, revision) = (instruction.network, instruction.revision);
    let world = &*state_transaction.world;
    if store::parameters::get(world).is_none() {
        return Err(refuse("SCCP does not exist on this network"));
    }
    let deployment = store::routes::get(world, &network)
        .and_then(|route| route.revisions.get(&revision))
        .filter(|record| record.activation != SccpRouteActivationV1::Staged)
        .map(|record| record.deployment.clone())
        .ok_or_else(|| refuse(format_args!("revision {revision} does not accept proofs")))?;
    let verified =
        light_clients::verify_source_proof(state_transaction, network, &instruction.proof)?;
    let SccpNormalizedEventV1::Void {
        emitter,
        kind,
        first_nonce,
        count,
        message_id_or_zero,
        ..
    } = verified.event
    else {
        return Err(refuse("the proof does not prove a void"));
    };
    if !emitter.matches(&deployment) {
        return Err(refuse("the void was not emitted by this deployment"));
    }
    apply_void(
        state_transaction,
        network,
        revision,
        SccpProvenVoidV1 {
            kind,
            first_nonce,
            count,
            message_id_or_zero,
        },
    )
}

/// Apply the proven `void` of `(network, revision)` (§4.16): every voided `Recorded` nonce
/// becomes `Voided`, emits `SccpOutboundVoided` and has its refund attempted; a frozen void
/// also freezes and drains the revision.
///
/// `SccpOutboundVoided.refund_pending` reports whether the refund still waits after this
/// attempt. A refund the movement refuses, one past the void's [`inline_refund_budget`] and one
/// to a multisig sender ([`releases_inline`]) stay pending, and a sender that can never be
/// credited strands, so one nonce never aborts the range.
///
/// # Errors
///
/// Fails when the range is out of bounds, a voided message id disagrees with the record, or
/// the void changes nothing (a replay).
pub fn apply_void(
    state_transaction: &mut StateTransaction<'_, '_>,
    network: SccpNetworkV1,
    revision: u32,
    void: SccpProvenVoidV1,
) -> Result<(), Error> {
    check_void_range(network, &void)?;
    let height = state_transaction._curr_block.height().get();
    let mut releases = inline_refund_budget(state_transaction);
    let mut changed = false;
    for nonce in void.first_nonce..void.first_nonce.saturating_add(void.count) {
        let Some(message_id) =
            store::outbound_by_nonce::get(&*state_transaction.world, &(network, revision, nonce))
                .copied()
        else {
            continue;
        };
        let mut record = store::outbound_messages::get(&*state_transaction.world, &message_id)
            .cloned()
            .ok_or_else(|| refuse("an outbound index entry has no record"))?;
        if !record.status.is_recorded() {
            continue;
        }
        if void.message_id_or_zero != [0; 32] && void.message_id_or_zero != message_id {
            return Err(refuse("the voided message id differs from the record"));
        }
        let may_release = releases > 0 && releases_inline(&record.sender);
        record.status = SccpOutboundStatusV1::Voided(SccpVoidStatusV1 {
            kind: void.kind,
            proven_at_height: height,
            refund_pending: Some(
                iroha_data_model::sccp::inbound::SccpPendingReasonV1::RefundDeferred,
            ),
        });
        super::reconciliation_store::add_pending_refund(
            state_transaction,
            (network, revision),
            record.amount,
        )?;
        store::outbound_messages::insert(state_transaction, message_id, record)?;
        settle::adjust_pending(state_transaction, (network, revision), 0, 1)?;
        let mut events = Vec::new();
        let outcome = settle::refund(state_transaction, message_id, &mut events, may_release)?;
        if outcome == settle::SccpRefundOutcomeV1::Refunded {
            releases -= 1;
        }
        state_transaction
            .world
            .emit_events(Some(SccpEvent::OutboundVoided(SccpOutboundVoidedV1 {
                message_id,
                network,
                revision,
                nonce,
                kind: void.kind,
                refund_pending: outcome.is_held(),
            })));
        state_transaction.world.emit_events(events);
        changed = true;
    }
    if void.kind == SccpVoidKindV1::Frozen {
        changed |= registry::apply_frozen_void(state_transaction, network, revision)?;
    }
    if changed {
        Ok(())
    } else {
        Err(refuse("the void changes nothing"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smartcontracts::isi::sccp::test_support::{
        SampleInstructions, authority, blank_state, header,
    };

    #[test]
    fn voids_need_sccp() {
        let state = blank_state();
        let mut block = state.block(header(3));
        let mut stx = block.transaction();
        let error = execute_submit_void(SampleInstructions::void(), &authority(1), &mut stx)
            .expect_err("no SCCP");
        assert!(error.to_string().contains("does not exist"), "{error}");
    }

    #[test]
    fn the_inline_refund_budget_is_half_the_transaction_source_capacity() {
        let state = blank_state();
        let mut block = state.block(header(3));
        let stx = block.transaction();
        let limits = stx.fastpq_intrinsic_source_limits();
        assert_eq!((limits.max_transcripts, limits.max_deltas), (16, 16));
        assert_eq!(inline_refund_budget(&stx), 8);
    }

    #[test]
    fn only_single_key_senders_are_released_inline() {
        use iroha_data_model::account::controller::{MultisigMember, MultisigPolicy};
        assert!(releases_inline(&authority(1)));
        let members = [2_u8, 3]
            .into_iter()
            .map(|seed| {
                let key = iroha_crypto::KeyPair::try_from_seed(
                    vec![seed; 32],
                    iroha_crypto::Algorithm::Ed25519,
                )
                .expect("seed");
                MultisigMember::new(key.public_key().clone(), 1).expect("member")
            })
            .collect();
        let multisig = AccountId::new_multisig(MultisigPolicy::new(1, members).expect("policy"));
        assert!(!releases_inline(&multisig));
    }

    #[test]
    fn void_ranges_follow_the_destination_bounds() {
        let void = |kind, count| SccpProvenVoidV1 {
            kind,
            first_nonce: 7,
            count,
            message_id_or_zero: [0; 32],
        };
        let (expired, frozen) = (SccpVoidKindV1::Expired, SccpVoidKindV1::Frozen);
        for network in [
            SccpNetworkV1::EthereumMainnet,
            SccpNetworkV1::BscMainnet,
            SccpNetworkV1::TonMainnet,
        ] {
            check_void_range(network, &void(expired, 1)).expect("one expired nonce");
            check_void_range(network, &void(expired, 2)).expect_err("expired voids one nonce");
            check_void_range(network, &void(frozen, 0)).expect_err("an empty range");
            check_void_range(network, &void(frozen, 1)).expect("one frozen nonce");
            check_void_range(network, &void(frozen, 256)).expect("the EVM bound");
        }
        for network in [SccpNetworkV1::EthereumMainnet, SccpNetworkV1::BscMainnet] {
            check_void_range(network, &void(frozen, 257)).expect_err("past the EVM bound");
        }
        check_void_range(SccpNetworkV1::TonMainnet, &void(frozen, 512)).expect("one TON bucket");
        check_void_range(SccpNetworkV1::TonMainnet, &void(frozen, 513))
            .expect_err("past one TON bucket");
        check_void_range(SccpNetworkV1::SoraTaira, &void(frozen, 1)).expect_err("no route");
    }
}
