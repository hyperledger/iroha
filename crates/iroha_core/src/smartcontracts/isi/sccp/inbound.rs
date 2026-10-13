//! Inbound value path: `SubmitSccpInboundMessageV1` (`specs/sccp.md` §4.12.1). Owner: ws41.
//!
//! A burn on the source chain is proven once and settled separately, so a proven burn never
//! becomes unprovable: the proof verifies against the network's light client, binds the
//! payload to the normalized source event, records the message `Pending` and then attempts
//! settlement (§4.12.3). Proving works while SCCP is disabled or the revision is paused, and a
//! settlement that cannot complete leaves the record `Pending` with its reason while the proof
//! still succeeds.

use super::{Error, light_clients, settle, store};
use crate::state::{StateReadOnly, StateTransaction};
use iroha_data_model::{
    account::{AccountAddress, AccountId},
    bridge::SccpNetworkV1,
    isi::sccp::SubmitSccpInboundMessageV1,
    sccp::{
        events::{SccpEvent, SccpInboundProvenV1},
        inbound::{
            SccpInboundRecordV1, SccpInboundStatusV1, SccpPendingReasonV1, SccpSourceLocatorV1,
        },
        registry::SccpRouteActivationV1,
    },
};
use iroha_sccp::{
    light_client::proof::{SccpNormalizedEventV1, SccpVerifiedProofV1},
    v1::{network::domain, payload::SccpTransferPayloadV1},
};

fn refuse(reason: impl core::fmt::Display) -> Error {
    Error::InvariantViolation(format!("SCCP inbound: {reason}").into())
}

/// Return the Taira recipient `AccountId` of an inbound `payload` (codec 3), if it decodes.
#[must_use]
pub fn recipient_account(payload: &SccpTransferPayloadV1) -> Option<AccountId> {
    AccountAddress::from_canonical_bytes(&payload.recipient.bytes)
        .and_then(|address| address.to_account_id())
        .ok()
}

/// Decode `bytes` as an inbound payload of `(network, revision)` (§4.12.1 step 2).
///
/// # Errors
///
/// Fails when the payload does not decode or names another lane, revision or a deadline.
pub fn decode_inbound_payload(
    network: iroha_data_model::bridge::SccpNetworkV1,
    revision: u32,
    bytes: &[u8],
) -> Result<SccpTransferPayloadV1, Error> {
    let payload = SccpTransferPayloadV1::decode(bytes)
        .map_err(|error| refuse(format_args!("payload: {error}")))?;
    if payload.source_domain != domain(network)
        || payload.dest_domain != 0
        || payload.route_revision != revision
        || payload.deadline_ms != 0
    {
        return Err(refuse(
            "the payload is not an inbound payload of this route revision",
        ));
    }
    Ok(payload)
}

/// Check that the verified proof's event is the burn of `payload` by `deployment`
/// (§4.12.1 step 4, §4.12.2): a transfer event carrying the payload's message id, sender,
/// nonce and hash.
///
/// # Errors
///
/// Fails when the event is not a transfer to Taira of this payload from this deployment.
pub fn bind_transfer_event(
    verified: &SccpVerifiedProofV1,
    deployment: &iroha_data_model::sccp::deployment::SccpDeploymentV1,
    payload: &SccpTransferPayloadV1,
    message_id: &[u8; 32],
) -> Result<iroha_data_model::sccp::inbound::SccpSourceLocatorV1, Error> {
    let mismatch = || refuse("the proven event does not match the payload");
    match &verified.event {
        SccpNormalizedEventV1::TransferToTaira {
            emitter,
            message_id: event_message_id,
            sender,
            nonce,
            payload_hash,
            locator,
        } => {
            let expected_hash = payload
                .payload_hash()
                .map_err(|error| refuse(format_args!("payload: {error}")))?;
            if !emitter.matches(deployment)
                || event_message_id != message_id
                || *sender != payload.sender
                || *nonce != payload.nonce
                || *payload_hash != expected_hash
            {
                return Err(mismatch());
            }
            Ok(*locator)
        }
        SccpNormalizedEventV1::Void { .. } | SccpNormalizedEventV1::Finalized { .. } => {
            Err(refuse("the proof does not prove a transfer to Taira"))
        }
    }
}

/// Return the self-claim fee due at release on an inbound message of `amount` Taira units
/// (§4.12.4): `fee` clamped strictly below the amount, so a release always credits the
/// recipient something. Eligibility already requires `amount > fee`; the clamp holds even if
/// the fee changes before release.
#[must_use]
pub const fn self_claim_fee_due(fee: u128, amount: u128) -> u128 {
    let ceiling = amount.saturating_sub(1);
    if fee < ceiling { fee } else { ceiling }
}

/// Return whether `authority` executes the current transaction as a fee-exempt SCCP
/// self-claim (§4.12.4); the executor records this before the body runs.
fn executes_exempt_self_claim(
    state_transaction: &StateTransaction<'_, '_>,
    authority: &AccountId,
) -> bool {
    state_transaction.sccp_exempt_self_claim.as_ref() == Some(authority)
}

/// Return the self-claim fee due at release on `payload` proven by `authority` in the current
/// transaction (§4.12.4): [`self_claim_fee_due`] of `fee` for an exempt self-claim by the
/// payload's recipient, and zero otherwise. A relayer, or a recipient paying the ordinary fee,
/// is not charged twice.
fn proof_fee_due(
    state_transaction: &StateTransaction<'_, '_>,
    authority: &AccountId,
    payload: &SccpTransferPayloadV1,
    fee: u128,
) -> u128 {
    if executes_exempt_self_claim(state_transaction, authority)
        && recipient_account(payload).as_ref() == Some(authority)
    {
        self_claim_fee_due(fee, payload.amount)
    } else {
        0
    }
}

/// Make the self-claim fee due on the `Pending` inbound message `message_id` when the current
/// transaction is an exempt self-claim of its recipient `authority` (§4.12.4): the fee is due
/// once, at release, clamped below the amount ([`self_claim_fee_due`]). A settle that pays the
/// ordinary fee, by the recipient or anyone else, adds no fee.
///
/// # Errors
///
/// Fails when the stored record cannot be rewritten.
pub fn charge_self_claim_fee(
    state_transaction: &mut StateTransaction<'_, '_>,
    message_id: [u8; 32],
    authority: &AccountId,
) -> Result<(), Error> {
    if !executes_exempt_self_claim(state_transaction, authority) {
        return Ok(());
    }
    let world = &*state_transaction.world;
    let Some(mut record) = store::inbound_messages::get(world, &message_id).cloned() else {
        return Ok(());
    };
    let fee = store::parameters::get(world)
        .as_ref()
        .map_or(0, |params| params.inbound_self_claim_fee);
    let Some(amount) = SccpTransferPayloadV1::decode(&record.payload)
        .ok()
        .filter(|payload| recipient_account(payload).as_ref() == Some(authority))
        .map(|payload| payload.amount)
    else {
        return Ok(());
    };
    let due = self_claim_fee_due(fee, amount);
    if record.status.is_pending() && record.fee_due < due {
        record.fee_due = due;
        store::inbound_messages::insert(state_transaction, message_id, record)?;
    }
    Ok(())
}

/// A verified inbound burn, ready to be recorded (§4.12.1 effect).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SccpProvenInboundV1 {
    /// External source network.
    pub network: SccpNetworkV1,
    /// Route revision whose deployment emitted the burn.
    pub revision: u32,
    /// Canonical §3.2 payload bytes.
    pub payload: Vec<u8>,
    /// Payload amount in Taira units.
    pub amount: u128,
    /// §3.3 message id under the live `NetworkId`.
    pub message_id: [u8; 32],
    /// Source-chain position of the burn event.
    pub source_locator: SccpSourceLocatorV1,
    /// Self-claim fee due at release.
    pub fee_due: u128,
}

/// Execute `SubmitSccpInboundMessageV1` (§4.12.1).
///
/// # Errors
///
/// Fails when SCCP is absent, the revision is unknown or `Staged`, the payload does not bind
/// to the route, the message is already proven, or the proof does not verify. A settlement
/// that cannot complete does not fail the proof (see [`record_proven`]).
pub fn execute_submit_inbound(
    instruction: SubmitSccpInboundMessageV1,
    authority: &AccountId,
    state_transaction: &mut StateTransaction<'_, '_>,
) -> Result<(), Error> {
    let (network, revision) = (instruction.network, instruction.revision);
    let world = &*state_transaction.world;
    let params = store::parameters::get(world)
        .clone()
        .ok_or_else(|| refuse("SCCP does not exist on this network"))?;
    let deployment = store::routes::get(world, &network)
        .and_then(|route| route.revisions.get(&revision))
        .filter(|record| record.activation != SccpRouteActivationV1::Staged)
        .map(|record| record.deployment.clone())
        .ok_or_else(|| refuse(format_args!("revision {revision} does not accept proofs")))?;
    let payload = decode_inbound_payload(network, revision, &instruction.payload)?;
    let message_id = payload
        .message_id(state_transaction.network_id().as_bytes())
        .map_err(|error| refuse(format_args!("payload: {error}")))?;
    if store::inbound_messages::contains(world, &message_id) {
        return Err(refuse("the message is already proven"));
    }
    let verified =
        light_clients::verify_source_proof(state_transaction, network, &instruction.proof)?;
    let source_locator = bind_transfer_event(&verified, &deployment, &payload, &message_id)?;
    let fee_due = proof_fee_due(
        state_transaction,
        authority,
        &payload,
        params.inbound_self_claim_fee,
    );
    record_proven(
        state_transaction,
        SccpProvenInboundV1 {
            network,
            revision,
            payload: instruction.payload,
            amount: payload.amount,
            message_id,
            source_locator,
            fee_due,
        },
    )
}

/// Record the verified inbound burn `proven` as `Pending`, emit `SccpInboundProven` and
/// attempt its settlement (§4.12.1 effect, §4.12.3).
///
/// Settlement refusals are holds: the record stays `Pending` with its reason (SCCP disabled,
/// revision not settleable, liability shortfall, credit refused, fee sink unavailable, block
/// leaves full) and the proof still succeeds.
///
/// # Errors
///
/// Fails when the message is already recorded, or on an execution invariant violation.
pub fn record_proven(
    state_transaction: &mut StateTransaction<'_, '_>,
    proven: SccpProvenInboundV1,
) -> Result<(), Error> {
    let SccpProvenInboundV1 {
        network,
        revision,
        payload,
        amount,
        message_id,
        source_locator,
        fee_due,
    } = proven;
    if store::inbound_messages::contains(&*state_transaction.world, &message_id) {
        return Err(refuse("the message is already proven"));
    }
    let height = state_transaction._curr_block.height().get();
    store::inbound_messages::insert(
        state_transaction,
        message_id,
        SccpInboundRecordV1 {
            network,
            revision,
            payload,
            source_locator,
            proven_at_height: height,
            fee_due,
            status: SccpInboundStatusV1::pending(SccpPendingReasonV1::Disabled),
        },
    )?;
    settle::adjust_pending(state_transaction, (network, revision), 1, 0)?;
    state_transaction
        .world
        .emit_events(Some(SccpEvent::InboundProven(SccpInboundProvenV1 {
            message_id,
            network,
            revision,
            amount,
            source_locator,
            fee_due,
        })));
    settle::settle_inbound(state_transaction, message_id).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smartcontracts::isi::sccp::test_support::{
        SampleInstructions, authority, blank_state, header,
    };
    fn inbound_payload(revision: u32, recipient: Vec<u8>) -> SccpTransferPayloadV1 {
        SccpTransferPayloadV1::inbound(
            SccpNetworkV1::EthereumMainnet,
            3,
            revision,
            2_000_000_000,
            vec![0x44; 20],
            recipient,
        )
        .expect("payload")
    }

    fn address_bytes(account: &AccountId) -> Vec<u8> {
        AccountAddress::from_account_id(account)
            .and_then(|address| address.canonical_bytes())
            .expect("address")
    }

    #[test]
    fn inbound_payloads_bind_to_their_lane_and_revision() {
        let payload = inbound_payload(1, address_bytes(&authority(1)));
        let bytes = payload.encode().expect("encode");
        assert_eq!(
            decode_inbound_payload(SccpNetworkV1::EthereumMainnet, 1, &bytes).expect("decode"),
            payload
        );
        decode_inbound_payload(SccpNetworkV1::EthereumMainnet, 2, &bytes).expect_err("revision");
        decode_inbound_payload(SccpNetworkV1::BscMainnet, 1, &bytes).expect_err("network");
        assert_eq!(recipient_account(&payload), Some(authority(1)));
    }

    #[test]
    fn a_transfer_event_binds_only_its_own_payload_and_deployment() {
        use iroha_data_model::sccp::{
            deployment::{SccpDeploymentV1, SccpEvmDeploymentV1},
            outbound::SccpVoidKindV1,
        };
        use iroha_sccp::light_client::proof::SccpSourceEmitterV1;

        let payload = inbound_payload(1, address_bytes(&authority(1)));
        let message_id = [0x5a; 32];
        let locator = SccpSourceLocatorV1 {
            source_height: 9,
            block_hash: [3; 32],
            index_in_block: 2,
        };
        let deployment = SccpDeploymentV1::Evm(SccpEvmDeploymentV1 {
            address: [0x11; 20],
            runtime_code_hash: [0x22; 32],
        });
        let transfer = |emitter: [u8; 20], nonce: u64| SccpVerifiedProofV1 {
            event: SccpNormalizedEventV1::TransferToTaira {
                emitter: SccpSourceEmitterV1::Evm(emitter),
                message_id,
                sender: payload.sender.clone(),
                nonce,
                payload_hash: payload.payload_hash().expect("hash"),
                locator,
            },
            checkpoints: Vec::new(),
        };
        let bind = |verified: &SccpVerifiedProofV1, id: &[u8; 32]| {
            bind_transfer_event(verified, &deployment, &payload, id)
        };
        assert_eq!(
            bind(&transfer([0x11; 20], payload.nonce), &message_id).expect("bound"),
            locator
        );
        bind(&transfer([0x12; 20], payload.nonce), &message_id).expect_err("another contract");
        bind(&transfer([0x11; 20], payload.nonce + 1), &message_id).expect_err("another nonce");
        bind(&transfer([0x11; 20], payload.nonce), &[0x5b; 32]).expect_err("another message");
        let void = SccpVerifiedProofV1 {
            event: SccpNormalizedEventV1::Void {
                emitter: SccpSourceEmitterV1::Evm([0x11; 20]),
                kind: SccpVoidKindV1::Expired,
                first_nonce: payload.nonce,
                count: 1,
                message_id_or_zero: message_id,
                locator,
            },
            checkpoints: Vec::new(),
        };
        let error = bind(&void, &message_id).expect_err("a void is not a transfer");
        assert!(error.to_string().contains("transfer to Taira"), "{error}");
    }

    #[test]
    fn the_self_claim_fee_stays_strictly_below_the_amount() {
        assert_eq!(self_claim_fee_due(10, 11), 10);
        assert_eq!(self_claim_fee_due(10, 10), 9);
        assert_eq!(self_claim_fee_due(10, 1), 0);
        assert_eq!(self_claim_fee_due(10, 0), 0);
        assert_eq!(self_claim_fee_due(0, 5), 0);
    }

    #[test]
    fn only_an_exempt_self_claim_by_the_recipient_owes_the_fee() {
        let state = blank_state();
        let mut block = state.block(header(3));
        let mut stx = block.transaction();
        let recipient = authority(1);
        let payload = inbound_payload(1, address_bytes(&recipient));
        assert_eq!(
            proof_fee_due(&stx, &recipient, &payload, 10),
            0,
            "a recipient paying the ordinary fee is not charged twice"
        );
        assert_eq!(
            proof_fee_due(&stx, &authority(2), &payload, 10),
            0,
            "a relayer owes nothing"
        );
        stx.sccp_exempt_self_claim = Some(recipient.clone());
        assert_eq!(proof_fee_due(&stx, &recipient, &payload, 10), 10);
        assert_eq!(
            proof_fee_due(&stx, &authority(2), &payload, 10),
            0,
            "the marker names another authority"
        );
        let to_other = inbound_payload(1, address_bytes(&authority(3)));
        assert_eq!(proof_fee_due(&stx, &recipient, &to_other, 10), 0);
        assert!(executes_exempt_self_claim(&stx, &recipient));
    }

    #[test]
    fn proofs_need_sccp_and_an_unstaged_revision() {
        let state = blank_state();
        let mut block = state.block(header(3));
        let mut stx = block.transaction();
        let error = execute_submit_inbound(SampleInstructions::inbound(), &authority(1), &mut stx)
            .expect_err("no SCCP");
        assert!(error.to_string().contains("does not exist"), "{error}");
    }
}
