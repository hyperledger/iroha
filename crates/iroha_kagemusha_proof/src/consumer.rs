//! Native consumer checks of a step statement (spec section 3.2; the G1
//! `KagemushaWalletStatementV1::validate_against_lineage` and Payment
//! checks): what a package consumer compares before mutation, the relation
//! whose verifying key it then selects, and the public input it verifies the
//! step proof against.
//!
//! A package carries its statement in canonical form ([`StatementV1`]); the
//! step proof's public input is the statement digest. A consumer never takes
//! a field from the statement on trust:
//!
//! - the relation identity must be the scheme's (Ω(pred) exposes it for a
//!   Send);
//! - for `sigma_send`, the predecessor, credential digest, scheme,
//!   lifecycle, enabled-controls mask, `burned_total` and pending-outgoing
//!   root must equal the predecessor's lineage proof Ω(pred)
//!   ([`LineageView`]); the mask selects the verifying key
//!   ([`Accepted::relation`]);
//! - the scheme, asset, wallets, send ordinal, amount and fee must equal the
//!   Request body the consumer holds, and `credit_id` is recomputed from
//!   that body, never read from the statement.
//!
//! A Receive statement is matched to its Request by `credit_id`, whose
//! preimage holds the receiver `wallet_id` that `sigma_recv` equates with
//! the receiver's core wallet. Its credential digest is the receiver's
//! current credential and is never compared with the Request's receiver
//! credential digest (owner answer Q8): a Request quoted before a renewal
//! stays receivable after it. The receiver's `payment_key` is matched by the
//! receipt and credential checks outside this crate (G1
//! `KagemushaWalletPaymentV1::receive_effect`) and by `Λ_recv`.
//!
//! Only then does the consumer verify the proof with the selected key. A
//! statement that claims another credential, wallet, credit or
//! `burned_total` than Ω(pred) and the Request therefore fails here. A
//! statement that passes here but is not what the prover's predecessor
//! opened (for example another asset, which Ω does not expose) fails
//! verification.

use iroha_pasta::poseidon::PoseidonField;
use iroha_plonk_gadgets::statement::{StatementV1, StepRelation, digest_fields};

use crate::witness::{
    LIFECYCLE_ACTIVE, LIFECYCLE_RETIRING, RECEIVE_EFFECT_FIELDS, RequestBody, SEND_EFFECT_FIELDS,
    SigmaRelation, StepPublic,
};

/// The public outputs of the predecessor's lineage proof Ω(pred) that a
/// `sigma_send` consumer compares (spec section 3.2; the G1
/// `KagemushaWalletLineagePublicV1` fields).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LineageView<F> {
    /// The head commitment (the predecessor state commitment).
    pub head: F,
    /// The scheme identifier.
    pub scheme_id: [u8; 32],
    /// The scheme-level relation identity.
    pub relation_id: [u8; 32],
    /// The `wallet_id`.
    pub wallet_id: [u8; 32],
    /// The credential digest.
    pub credential_digest: [u8; 32],
    /// The lifecycle tag of the head.
    pub lifecycle: u8,
    /// The enabled-controls mask.
    pub enabled_controls: u32,
    /// The lineage-adjusted `burned_total`.
    pub burned_total: u128,
    /// The lineage-adjusted pending-outgoing root.
    pub pending_outgoing_root: F,
}

/// Why a consumer rejects a statement before verifying its proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConsumerError {
    /// The step or the relation identity is not the expected one.
    Relation,
    /// The lifecycle is not Ω(pred)'s, or neither Active nor Retiring.
    Lifecycle,
    /// The predecessor is not Ω(pred)'s head.
    Predecessor,
    /// The credential digest differs from Ω(pred)'s.
    Credential,
    /// The scheme differs from Ω(pred)'s or the Request's.
    Scheme,
    /// The asset differs from the Request's.
    Asset,
    /// The enabled-controls mask differs from Ω(pred)'s.
    Controls,
    /// The lineage `burned_total` input differs from Ω(pred)'s, or a
    /// Receive statement carries lineage inputs.
    BurnedTotal,
    /// The lineage pending-outgoing input differs from Ω(pred)'s.
    PendingOutgoing,
    /// The Request's payer is not Ω(pred)'s wallet.
    Payer,
    /// The Request's payer and receiver wallets are equal.
    SelfPayment,
    /// The effect does not match the Request body.
    Effect,
}

impl core::fmt::Display for ConsumerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let what = match self {
            Self::Relation => "relation identity",
            Self::Lifecycle => "lifecycle",
            Self::Predecessor => "predecessor head",
            Self::Credential => "credential digest",
            Self::Scheme => "scheme",
            Self::Asset => "asset",
            Self::Controls => "enabled-controls mask",
            Self::BurnedTotal => "lineage burned_total input",
            Self::PendingOutgoing => "lineage pending-outgoing input",
            Self::Payer => "payer wallet",
            Self::SelfPayment => "payer equals receiver",
            Self::Effect => "effect",
        };
        write!(f, "statement rejected: {what}")
    }
}

impl std::error::Error for ConsumerError {}

/// What a consumer verifies after its checks pass: the relation whose
/// verifying key the allowlist selects, and the public input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Accepted<F> {
    /// The relation (the G1 verifying-key selector `(tag, mask)`).
    pub relation: SigmaRelation,
    /// The public input of the step proof.
    pub public: StepPublic<F>,
}

/// Fails with `error` unless `ok`.
const fn require(ok: bool, error: ConsumerError) -> Result<(), ConsumerError> {
    if ok { Ok(()) } else { Err(error) }
}

/// The effect prefix a Request body determines: `credit_id`, the
/// counterparty limbs, then the step's amounts (the Send effect's Request
/// digest and accepted interval are compared by the G1 Payment checks).
fn expected_effect<F: PoseidonField>(step: StepRelation, request: &RequestBody) -> Vec<F> {
    let credit = request.credit_id::<F>();
    let amount = F::from_u128(request.terms.amount);
    match step {
        StepRelation::Send => {
            let [receiver_lo, receiver_hi] = digest_fields::<F>(&request.receiver_wallet);
            vec![
                credit,
                receiver_lo,
                receiver_hi,
                F::from_u128(request.send_ordinal),
                amount,
                F::from_u128(request.terms.fee),
            ]
        }
        StepRelation::Receive => {
            let [payer_lo, payer_hi] = digest_fields::<F>(&request.payer_wallet);
            vec![credit, payer_lo, payer_hi, amount]
        }
    }
}

/// The checks both steps share: step and relation identity, a valid
/// lifecycle, scheme and asset against the Request, distinct wallets and the
/// effect.
fn check_common<F: PoseidonField>(
    step: StepRelation,
    relation_id: &[u8; 32],
    request: &RequestBody,
    statement: &StatementV1<F>,
) -> Result<(), ConsumerError> {
    require(request.canonical_digests::<F>(), ConsumerError::Effect)?;
    require(
        (request.terms.receiver_blacklist_version == 0)
            == (request.terms.receiver_blacklist_root == [0; 32]),
        ConsumerError::Controls,
    )?;
    require(
        statement.step == step && statement.relation_id == *relation_id,
        ConsumerError::Relation,
    )?;
    require(
        statement.lifecycle == LIFECYCLE_ACTIVE || statement.lifecycle == LIFECYCLE_RETIRING,
        ConsumerError::Lifecycle,
    )?;
    require(
        statement.scheme_id == request.scheme_id,
        ConsumerError::Scheme,
    )?;
    require(
        statement.asset_digest == request.asset_digest,
        ConsumerError::Asset,
    )?;
    require(
        request.payer_wallet != request.receiver_wallet,
        ConsumerError::SelfPayment,
    )?;
    let effect_len = match step {
        StepRelation::Send => SEND_EFFECT_FIELDS,
        StepRelation::Receive => RECEIVE_EFFECT_FIELDS,
    };
    let expected = expected_effect::<F>(step, request);
    require(
        statement.effect.len() == effect_len && statement.effect.starts_with(&expected),
        ConsumerError::Effect,
    )
}

/// The checks of a `sigma_send` statement against Ω(pred) (`view`) and the
/// Request body the consumer holds (its own, for a receiver). Returns the
/// relation whose verifying key Ω(pred)'s mask selects and the public input
/// to verify the proof against.
///
/// # Errors
///
/// The first [`ConsumerError`] found.
pub fn check_send<F: PoseidonField>(
    view: &LineageView<F>,
    request: &RequestBody,
    statement: &StatementV1<F>,
) -> Result<Accepted<F>, ConsumerError> {
    check_common(StepRelation::Send, &view.relation_id, request, statement)?;
    require(
        statement.predecessor == view.head,
        ConsumerError::Predecessor,
    )?;
    require(
        statement.credential_digest == view.credential_digest,
        ConsumerError::Credential,
    )?;
    require(statement.scheme_id == view.scheme_id, ConsumerError::Scheme)?;
    require(
        statement.lifecycle == view.lifecycle,
        ConsumerError::Lifecycle,
    )?;
    require(
        statement.enabled_controls == view.enabled_controls,
        ConsumerError::Controls,
    )?;
    require(
        statement.lineage_burned_total == view.burned_total,
        ConsumerError::BurnedTotal,
    )?;
    require(
        statement.lineage_pending_outgoing_root == view.pending_outgoing_root,
        ConsumerError::PendingOutgoing,
    )?;
    require(request.payer_wallet == view.wallet_id, ConsumerError::Payer)?;
    let statement_digest = statement.digest().ok_or(ConsumerError::Effect)?;
    Ok(Accepted {
        relation: SigmaRelation::send(view.enabled_controls),
        public: StepPublic {
            statement: statement_digest,
        },
    })
}

/// The checks of a `sigma_recv` statement (for example Credited evidence)
/// against the scheme's relation identity and the Request body the consumer
/// holds. The receiver's credential digest is not compared with the
/// Request's (owner answer Q8). Returns the `sigma_recv` relation the
/// Request's recorded blacklist version selects (B6: `(4, version != 0)`) and the
/// public input to verify the proof against.
///
/// # Errors
///
/// The first [`ConsumerError`] found.
pub fn check_receive<F: PoseidonField>(
    relation_id: &[u8; 32],
    request: &RequestBody,
    statement: &StatementV1<F>,
) -> Result<Accepted<F>, ConsumerError> {
    check_common(StepRelation::Receive, relation_id, request, statement)?;
    require(
        statement.enabled_controls & !crate::witness::CONTROLS_DEFINED == 0,
        ConsumerError::Controls,
    )?;
    require(
        statement.lineage_burned_total == 0 && statement.lineage_pending_outgoing_root == F::ZERO,
        ConsumerError::BurnedTotal,
    )?;
    let statement_digest = statement.digest().ok_or(ConsumerError::Effect)?;
    Ok(Accepted {
        relation: crate::proof::selector_for(
            StepRelation::Receive,
            statement.enabled_controls,
            request.terms.receiver_blacklist_version,
        ),
        public: StepPublic {
            statement: statement_digest,
        },
    })
}

/// The Ω(pred) view of the predecessor of an honest `sigma_send` witness
/// (test and measurement support).
#[must_use]
pub fn lineage_view_of<F: PoseidonField>(
    witness: &crate::witness::StepWitness<F>,
) -> Option<LineageView<F>> {
    let crate::witness::StepInputs::Send(send) = &witness.inputs else {
        return None;
    };
    let core = &witness.predecessor.core;
    Some(LineageView {
        head: witness.predecessor.commitment(),
        scheme_id: core.identity.scheme_id,
        relation_id: witness.relation_id,
        wallet_id: core.identity.wallet_id,
        credential_digest: core.identity.credential_digest,
        lifecycle: core.lifecycle,
        enabled_controls: core.controls.enabled,
        burned_total: send.lineage.burned_total,
        pending_outgoing_root: send.lineage.pending_outgoing_root,
    })
}

#[cfg(test)]
mod tests {
    use iroha_pasta::Fp;

    use super::*;
    use crate::{
        vectors::{Mutation, sample_witness},
        witness::{CONTROL_BLACKLIST, StepInputs},
    };

    #[test]
    fn receive_selects_the_recorded_blacklist_independently_of_current_controls() {
        for relation in [
            SigmaRelation::RECEIVE,
            SigmaRelation::receive(CONTROL_BLACKLIST),
        ] {
            let receive = sample_witness::<Fp>(2, relation, Mutation::None);
            let request = receive.request_body();
            let mut statement = receive.statement(relation).expect("statement");
            for mask in 0..=crate::witness::CONTROLS_DEFINED {
                statement.enabled_controls = mask;
                let accepted = check_receive(&receive.relation_id, &request, &statement);
                assert_eq!(
                    accepted.expect("recorded blacklist selector").relation,
                    relation
                );
            }
            for mask in [crate::witness::CONTROLS_DEFINED + 1, u32::MAX] {
                statement.enabled_controls = mask;
                assert_eq!(
                    check_receive(&receive.relation_id, &request, &statement),
                    Err(ConsumerError::Controls),
                );
            }
        }
    }

    #[test]
    fn honest_statements_pass_and_yield_the_proof_inputs() {
        for relation in [SigmaRelation::SEND, SigmaRelation::send(CONTROL_BLACKLIST)] {
            let send = sample_witness::<Fp>(2, relation, Mutation::None);
            let statement = send.statement(relation).expect("statement");
            let view = lineage_view_of(&send).expect("send witness");
            let accepted = check_send(&view, &send.request_body(), &statement).expect("accepted");
            assert_eq!(accepted.public, send.evaluate(relation).public());
            // Ω(pred)'s mask selects the relation's verifying key.
            assert_eq!(accepted.relation, relation);
        }
        let receive = sample_witness::<Fp>(2, SigmaRelation::RECEIVE, Mutation::None);
        let statement = receive
            .statement(SigmaRelation::RECEIVE)
            .expect("statement");
        let accepted = check_receive(&receive.relation_id, &receive.request_body(), &statement)
            .expect("accepted");
        assert_eq!(
            accepted.public,
            receive.evaluate(SigmaRelation::RECEIVE).public()
        );
        assert_eq!(accepted.relation, SigmaRelation::RECEIVE);
        assert!(lineage_view_of(&receive).is_none());
    }

    /// A statement edit of [`every_bound_field_is_compared`].
    type Edit = fn(&mut StatementV1<Fp>);

    #[test]
    fn every_bound_field_is_compared() {
        let send = sample_witness::<Fp>(3, SigmaRelation::SEND, Mutation::None);
        let view = lineage_view_of(&send).expect("send witness");
        let request = send.request_body();
        let honest = send.statement(SigmaRelation::SEND).expect("statement");
        let edits: [(Edit, ConsumerError); 12] = [
            (|s| s.relation_id[0] ^= 1, ConsumerError::Relation),
            (|s| s.step = StepRelation::Receive, ConsumerError::Relation),
            (|s| s.lifecycle = 3, ConsumerError::Lifecycle),
            (
                |s| s.lifecycle = LIFECYCLE_RETIRING,
                ConsumerError::Lifecycle,
            ),
            (
                |s| s.predecessor += Fp::from(1u64),
                ConsumerError::Predecessor,
            ),
            (|s| s.credential_digest[0] ^= 1, ConsumerError::Credential),
            (|s| s.scheme_id[0] ^= 1, ConsumerError::Scheme),
            (|s| s.asset_digest[0] ^= 1, ConsumerError::Asset),
            (|s| s.enabled_controls = 1, ConsumerError::Controls),
            (|s| s.lineage_burned_total = 0, ConsumerError::BurnedTotal),
            (
                |s| s.lineage_pending_outgoing_root += Fp::from(1u64),
                ConsumerError::PendingOutgoing,
            ),
            (|s| s.effect[0] += Fp::from(1u64), ConsumerError::Effect),
        ];
        for (edit, error) in edits {
            let mut statement = honest.clone();
            edit(&mut statement);
            assert_eq!(
                check_send(&view, &request, &statement),
                Err(error),
                "{error}"
            );
        }
        // A Request whose payer is another wallet, or the receiver itself.
        let mut other = request;
        other.payer_wallet[0] ^= 1;
        assert!(check_send(&view, &other, &honest).is_err());
        let mut own = request;
        own.receiver_wallet = own.payer_wallet;
        assert!(check_send(&view, &own, &honest).is_err());
        assert!(!ConsumerError::Payer.to_string().is_empty());
    }

    #[test]
    fn a_receiver_is_matched_by_wallet_not_by_credential_digest() {
        let mut receive = sample_witness::<Fp>(4, SigmaRelation::RECEIVE, Mutation::None);
        // The Request was quoted under the credential before a renewal.
        if let StepInputs::Receive(inputs) = &mut receive.inputs {
            inputs.receiver_credential_digest[0] ^= 0x77;
        }
        let request = receive.request_body();
        assert_ne!(
            request.receiver_credential_digest,
            receive.predecessor.core.identity.credential_digest
        );
        let statement = receive
            .statement(SigmaRelation::RECEIVE)
            .expect("statement");
        assert!(check_receive(&receive.relation_id, &request, &statement).is_ok());
        // Another relation identity or lineage inputs are rejected.
        assert_eq!(
            check_receive(&[0; 32], &request, &statement),
            Err(ConsumerError::Relation)
        );
        let mut lineage = statement.clone();
        lineage.lineage_burned_total = 1;
        assert_eq!(
            check_receive(&receive.relation_id, &request, &lineage),
            Err(ConsumerError::BurnedTotal)
        );
        // A Request for another receiver wallet has another credit_id.
        let mut other = request;
        other.receiver_wallet[0] ^= 1;
        assert_eq!(
            check_receive(&receive.relation_id, &other, &statement),
            Err(ConsumerError::Effect)
        );
    }
}
