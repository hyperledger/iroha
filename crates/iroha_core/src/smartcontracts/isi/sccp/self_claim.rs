//! Recipient self-claims (`specs/sccp.md` §4.12.4). Owner: ws41.
//!
//! A recipient that holds no XOR claims alone and fee-exempt; the self-claim fee is deducted
//! from the proceeds at release. [`eligible`] is the self-claim arm of the shared eligibility
//! predicate ([`super::fees::exempt_class`]): a pure function of the committed parent World and its original time,
//! the authority and the instructions. A claim that is not eligible (a relayer, a third-party
//! settle, an amount at or below the fee, a settle that cannot progress) is not refused: it
//! pays the ordinary fee. Admission pre-verifies an eligible claim ([`preverify`]) and rejects
//! it only when it is invalid.
//!
//! TODO(ws41): make `[Register<Account>(self)?, AdvanceSccpLightClientV1+,
//! SubmitSccpInboundMessageV1]` eligible by verifying its proof against the light client with
//! the bundled advances applied; until then that shape pays the ordinary fee.

use super::{
    admission::{SccpAdmissionKeysV1, SccpAdmissionRejectV1, SccpAdmissionView, SccpExemptClassV1},
    inbound::{bind_transfer_event, decode_inbound_payload, recipient_account},
    light_clients::{WorldLightClientView, admission_profiles},
    store,
};
use crate::state::WorldReadOnly;
use iroha_data_model::{
    account::{Account, AccountId},
    isi::{
        InstructionBox, Register, RegisterBox,
        sccp::{SccpSettleTargetV1, SettleSccpV1, SubmitSccpInboundMessageV1},
    },
    sccp::registry::SccpRouteActivationV1,
    transaction::{Executable, SignedTransaction},
};
use iroha_sccp::v1::payload::SccpTransferPayloadV1;

fn reject(reason: impl Into<String>) -> SccpAdmissionRejectV1 {
    SccpAdmissionRejectV1::new(reason)
}

fn keys(authority: &AccountId, message_id: &[u8; 32]) -> SccpAdmissionKeysV1 {
    SccpAdmissionKeysV1::new(SccpExemptClassV1::SelfClaim)
        .with_exclusive(authority)
        .with_exclusive(message_id)
}

/// What an eligible self-claim shape claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Claim<'a> {
    /// `[Register<Account>(Account::new(authority))?, SubmitSccpInboundMessageV1]`: prove,
    /// then settle.
    Prove(&'a SubmitSccpInboundMessageV1),
    /// `[SettleSccpV1::Inbound]`: settle the `Pending` record of this message id.
    Settle([u8; 32]),
}

/// Return whether `instruction` registers exactly `Account::new(authority)`: the authority's
/// own id with no metadata, label, UAID or opaque identifiers. Only that bare registration can
/// lead an eligible self-claim, so an exempt claim never carries other registration effects.
fn registers_bare_authority(instruction: &InstructionBox, authority: &AccountId) -> bool {
    let registration = instruction
        .as_any()
        .downcast_ref::<Register<Account>>()
        .map(|register| &register.object)
        .or_else(
            || match instruction.as_any().downcast_ref::<RegisterBox>() {
                Some(RegisterBox::Account(register)) => Some(&register.object),
                _ => None,
            },
        );
    registration.is_some_and(|account| {
        account.id == *authority
            && account.metadata.is_empty()
            && account.label.is_none()
            && account.uaid.is_none()
            && account.opaque_ids.is_empty()
    })
}

/// Return the claim of a self-claim shape without light-client advances, or `None` for any
/// other instruction layout. The optional leading registration must be the bare
/// `Account::new(authority)` ([`registers_bare_authority`]).
fn claim_of<'a>(executable: &'a Executable, authority: &AccountId) -> Option<Claim<'a>> {
    let Executable::Instructions(instructions) = executable else {
        return None;
    };
    let instructions: &[InstructionBox] = instructions;
    if let [only] = instructions
        && let Some(settle) = only.as_any().downcast_ref::<SettleSccpV1>()
    {
        return match &settle.target {
            SccpSettleTargetV1::Inbound(target) => Some(Claim::Settle(target.message_id)),
            SccpSettleTargetV1::Refund(_) => None,
        };
    }
    let rest = match instructions {
        [first, rest @ ..] if registers_bare_authority(first, authority) => rest,
        _ => instructions,
    };
    let [only] = rest else {
        return None;
    };
    only.as_any()
        .downcast_ref::<SubmitSccpInboundMessageV1>()
        .map(Claim::Prove)
}

/// Return whether `authority` claims `payload` as its recipient, for more than the self-claim
/// fee `fee`.
fn recipient_claims(payload: &SccpTransferPayloadV1, authority: &AccountId, fee: u128) -> bool {
    payload.amount > fee && recipient_account(payload).as_ref() == Some(authority)
}

/// Return whether `instructions` from `authority` are an eligible self-claim against the
/// committed parent World `world` (§4.12.4). All of the following hold:
///
/// * SCCP exists;
/// * the instructions are `[Register<Account>(Account::new(authority))?,
///   SubmitSccpInboundMessageV1]` (a bare self-registration, [`registers_bare_authority`]) or
///   `[SettleSccpV1::Inbound]` (a claim with light-client advances is not eligible yet,
///   TODO(ws41));
/// * the payload (decoded from the proof submission, or from the stored record of a settle)
///   names `authority` as its recipient and its amount exceeds `inbound_self_claim_fee`;
/// * for a settle, the record is `Pending` and settlement can progress
///   ([`super::settle::inbound_settlement_may_progress`]).
///
/// Nothing here verifies a proof; admission does that in [`preverify`].
#[must_use]
pub fn eligible(
    world: &(impl WorldReadOnly + ?Sized),
    authority: &AccountId,
    instructions: &Executable,
    committed_time_ms: Option<u64>,
) -> bool {
    eligible_from(
        &super::eligibility::Current(world),
        authority,
        instructions,
        committed_time_ms,
    )
}

/// Shared actual eligibility kernel for current and acquired original preimages.
pub(super) fn eligible_from(
    source: &(impl super::eligibility::EligibilityRead + ?Sized),
    authority: &AccountId,
    instructions: &Executable,
    committed_time_ms: Option<u64>,
) -> bool {
    let Some(fee) = source
        .parameters()
        .map(|params| params.inbound_self_claim_fee)
    else {
        return false;
    };
    match claim_of(instructions, authority) {
        None => false,
        Some(Claim::Prove(submit)) => {
            decode_inbound_payload(submit.network, submit.revision, &submit.payload)
                .is_ok_and(|payload| recipient_claims(&payload, authority, fee))
        }
        Some(Claim::Settle(message_id)) => source.inbound(&message_id).is_some_and(|record| {
            record.status.is_pending()
                && SccpTransferPayloadV1::decode(&record.payload).is_ok_and(|payload| {
                    recipient_claims(&payload, authority, fee)
                        && super::eligibility::inbound_may_progress(
                            source,
                            record,
                            payload.amount,
                            committed_time_ms,
                        )
                })
        }),
    }
}

/// Pre-verify an [`eligible`] self-claim against committed state and return its admission
/// keys (one pending self-claim per authority and per message id).
///
/// A settle needs a `Pending` record. A proof needs a revision that accepts proofs, a message
/// that is not yet proven, a proof that verifies against the light client at `view`'s
/// committed time under the profiles active at `next_block_height`, and an event that binds
/// the payload.
///
/// # Errors
///
/// Rejects a transaction that is not a self-claim or whose claim is invalid.
pub fn preverify(
    world: &(impl WorldReadOnly + ?Sized),
    view: &(impl SccpAdmissionView + ?Sized),
    next_block_height: u64,
    authority: &AccountId,
    transaction: &SignedTransaction,
) -> Result<SccpAdmissionKeysV1, SccpAdmissionRejectV1> {
    let claim = claim_of(&transaction.payload().instructions, authority)
        .ok_or_else(|| reject("not a self-claim"))?;
    let submit = match claim {
        Claim::Settle(message_id) => {
            return store::inbound_messages::get(world, &message_id)
                .filter(|record| record.status.is_pending())
                .map(|_| keys(authority, &message_id))
                .ok_or_else(|| reject("the inbound message is not pending"));
        }
        Claim::Prove(submit) => submit,
    };
    let payload = decode_inbound_payload(submit.network, submit.revision, &submit.payload)
        .map_err(|error| reject(error.to_string()))?;
    let message_id = payload
        .message_id(view.taira_network_id().as_bytes())
        .map_err(|error| reject(format!("payload: {error}")))?;
    if store::inbound_messages::contains(world, &message_id) {
        return Err(reject("the message is already proven"));
    }
    let deployment = store::routes::get(world, &submit.network)
        .and_then(|route| route.revisions.get(&submit.revision))
        .filter(|record| record.activation != SccpRouteActivationV1::Staged)
        .map(|record| record.deployment.clone())
        .ok_or_else(|| reject("the revision does not accept proofs"))?;
    let profiles = admission_profiles(world, next_block_height)?;
    let verified = iroha_sccp::light_client::verify_proof_with_profiles(
        &profiles,
        &WorldLightClientView(world),
        submit.network,
        &submit.proof,
        view.committed_time_ms(),
    )
    .map_err(|error| reject(format!("proof: {error}")))?;
    bind_transfer_event(&verified, &deployment, &payload, &message_id)
        .map_err(|error| reject(error.to_string()))?;
    Ok(keys(authority, &message_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smartcontracts::isi::sccp::test_support::{
        SampleInstructions, authority, blank_state, sample_signed_transaction,
    };

    fn instructions(instructions: Vec<InstructionBox>) -> Executable {
        Executable::Instructions(instructions.into())
    }

    fn self_registration(account: &AccountId) -> InstructionBox {
        iroha_data_model::isi::Register::account(iroha_data_model::account::Account::new(
            account.clone(),
        ))
        .into()
    }

    #[test]
    fn ordinary_transactions_are_not_self_claims() {
        let state = blank_state();
        let view = state.view();
        let reject = preverify(
            &*view.world(),
            &view,
            1,
            &authority(1),
            &sample_signed_transaction(),
        )
        .expect_err("not a self-claim");
        assert!(!reject.reason.is_empty());
        assert!(!eligible(
            &*view.world(),
            &authority(1),
            sample_signed_transaction().instructions(),
            None
        ));
    }

    #[test]
    fn claims_are_exact_layouts_without_advances() {
        let me = authority(1);
        let submit = SampleInstructions::inbound();
        assert_eq!(
            claim_of(&instructions(vec![submit.clone().into()]), &me),
            Some(Claim::Prove(&submit))
        );
        assert_eq!(
            claim_of(
                &instructions(vec![self_registration(&me), submit.clone().into()]),
                &me
            ),
            Some(Claim::Prove(&submit))
        );
        assert_eq!(
            claim_of(
                &instructions(vec![SampleInstructions::settle().into()]),
                &me
            ),
            Some(Claim::Settle([6; 32]))
        );
        let mut metadata = iroha_model_base::metadata::Metadata::default();
        metadata.insert(
            "note".parse().expect("metadata key"),
            iroha_primitives::json::Json::new("free storage"),
        );
        let decorated: InstructionBox =
            Register::account(Account::new(me.clone()).with_metadata(metadata)).into();
        assert!(registers_bare_authority(&self_registration(&me), &me));
        assert!(!registers_bare_authority(&decorated, &me));
        assert!(!registers_bare_authority(
            &self_registration(&authority(2)),
            &me
        ));
        for not_a_claim in [
            vec![decorated, submit.clone().into()],
            vec![
                self_registration(&me),
                SampleInstructions::advance().into(),
                submit.clone().into(),
            ],
            vec![SampleInstructions::advance().into(), submit.clone().into()],
            vec![self_registration(&authority(2)), submit.clone().into()],
            vec![SettleSccpV1::refund(submit.network, 1, 0).into()],
            vec![
                SampleInstructions::settle().into(),
                SampleInstructions::settle().into(),
            ],
            vec![SampleInstructions::record().into()],
            Vec::new(),
        ] {
            assert_eq!(claim_of(&instructions(not_a_claim), &me), None);
        }
    }

    #[test]
    fn a_claim_needs_the_recipient_and_an_amount_above_the_fee() {
        let me = authority(1);
        let address = iroha_data_model::account::AccountAddress::from_account_id(&me)
            .and_then(|address| address.canonical_bytes())
            .expect("address");
        let payload = |amount| {
            SccpTransferPayloadV1::inbound(
                iroha_data_model::bridge::SccpNetworkV1::EthereumMainnet,
                1,
                1,
                amount,
                vec![0x44; 20],
                address.clone(),
            )
            .expect("payload")
        };
        assert!(recipient_claims(&payload(11), &me, 10));
        assert!(!recipient_claims(&payload(10), &me, 10), "amount = fee");
        assert!(
            !recipient_claims(&payload(11), &authority(2), 10),
            "relayer"
        );
    }
}
