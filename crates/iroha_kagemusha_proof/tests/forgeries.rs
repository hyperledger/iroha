//! Consistent-forgery (malicious-witness) tests of the step relations.
//!
//! The per-cell tamper suite changes one cell and keeps every other cell
//! honest, so a free witness that is only copied into a hash looks pinned.
//! These tests instead let the forger choose a value *consistently*: the
//! forged witness goes through the real circuit, which recomputes every
//! copy and every downstream digest. Each test then asks the question a
//! verifier asks: can the forger make a statement that a consumer accepts
//! (the spec section 3.2 checks of `iroha_kagemusha_proof::consumer`) and
//! that the circuit of the selected verifying key proves?
//!
//! - **Identity** (credential, asset, scheme, wallet): the identity limbs
//!   are opened core cells, so a forged identity changes the predecessor
//!   commitment. A statement that keeps the real head with another identity
//!   is unsatisfiable; the asset, which the lineage proof does not expose,
//!   is caught by the circuit alone.
//! - **Receiver binding** (owner answer Q8): `sigma_recv` matches the
//!   Request's receiver by `wallet_id` inside `credit_id`; a Request quoted
//!   under the credential before a renewal stays receivable, a Request for
//!   another wallet is not.
//! - **Credit identifier**: it is `P(kgwcrdt1, Request body)` in circuit, so
//!   a statement with any other credit is unsatisfiable, and the consumer
//!   recomputes it from the Request.
//! - **Request accounts**: substituting either account digest changes the
//!   credit and statement while keeping the predecessor. The consumer
//!   rejects it for the signed Request, and the circuit cannot prove the
//!   original statement using the substituted account.
//! - **`burned_total`**: the lineage input is checked against the balance
//!   and bound in the statement, so dropping it to free burned value fails
//!   the consumer's comparison with the lineage proof.
//! - **Blacklist age** (owner answer Q5): a stale list is unprovable under
//!   the blacklist relation, and Ω(pred)'s mask selects that relation, so
//!   neither the control-free relation nor a rewritten mask or issue time
//!   escapes it.
//! - **Self-payment**: payer and receiver wallets must differ.
//! - **Accepted time**: the successor's floor is the accepted lower time, so
//!   a later Send cannot accept an earlier time.
//! - **Commitments and relation identity**: the statement's predecessor is
//!   the opened commitment, and the scheme-level relation identity is bound
//!   by the statement digest.

mod common;

use common::{
    CHECK_SEED, RELATIONS, SEND_BLACKLIST, check_claim, check_witness, folded, smallest_shape,
};
use ff::Field;
use iroha_kagemusha_proof::{
    CONTROL_BLACKLIST, ConsumerError, Mutation, RequestBody, SigmaRelation, SigmaShape,
    StatementV1, StepInputs, StepPublic, StepRelation, StepWitness, Violation, check_receive,
    check_send, lineage_view_of, sample_witness,
};
use iroha_pasta::Fp;
use iroha_plonk::check::CheckFailure;

fn shape(relation: SigmaRelation) -> SigmaShape {
    smallest_shape(folded(relation))
}

/// The public input a consumer derives from a (claimed) statement.
fn claimed(statement: &StatementV1<Fp>) -> StepPublic<Fp> {
    StepPublic {
        statement: statement.digest().expect("statement digest"),
    }
}

fn honest(relation: SigmaRelation) -> StepWitness<Fp> {
    sample_witness::<Fp>(CHECK_SEED, relation, Mutation::None)
}

/// The consumer's verdict on a statement of `relation`'s step.
fn consume(
    witness: &StepWitness<Fp>,
    request: &RequestBody,
    statement: &StatementV1<Fp>,
) -> Result<SigmaRelation, ConsumerError> {
    match statement.step {
        StepRelation::Send => {
            let view = lineage_view_of(witness).expect("a send witness");
            check_send(&view, request, statement).map(|accepted| accepted.relation)
        }
        StepRelation::Receive => check_receive(&witness.relation_id, request, statement)
            .map(|accepted| accepted.relation),
    }
}

/// An identity field of the core, with a substitute value.
type IdentityEdit = (&'static str, fn(&mut StepWitness<Fp>));

/// Substitutions of each identity field (another credential, asset, scheme
/// or wallet), applied to the predecessor state: the circuit recomputes
/// everything downstream.
fn identity_edits() -> [IdentityEdit; 4] {
    [
        ("credential", |w| {
            w.predecessor.core.identity.credential_digest[0] ^= 0x5a;
        }),
        ("asset", |w| {
            w.predecessor.core.identity.asset_digest[7] ^= 0x5a;
        }),
        ("scheme", |w| {
            w.predecessor.core.identity.scheme_id[3] ^= 0x5a;
        }),
        ("wallet", |w| {
            w.predecessor.core.identity.wallet_id[9] ^= 0x5a;
        }),
    ]
}

/// A forged credential, asset, scheme or payer wallet cannot be claimed for
/// the real head.
#[test]
fn identity_substitution_cannot_keep_the_real_head() {
    for relation in [SigmaRelation::SEND, SEND_BLACKLIST] {
        let honest = honest(relation);
        let view = lineage_view_of(&honest).expect("send witness");
        let shape = shape(relation);
        for (name, edit) in identity_edits() {
            let mut forged = honest.clone();
            edit(&mut forged);
            // The forged witness is a valid step from another state: the
            // circuit accepts it for its own statement.
            assert!(forged.evaluate(relation).is_honest(), "{name}");
            assert!(check_witness(&shape, &forged).is_satisfied(), "{name}");
            let own = forged.statement(relation).expect("statement");
            assert_ne!(own.predecessor, view.head, "{name}: the head moved");
            let request = forged.request_body();
            assert_eq!(
                check_send(&view, &request, &own),
                Err(ConsumerError::Predecessor),
                "{name}"
            );
            // The forger's claim: the forged identity with the real head.
            let mut claim = own.clone();
            claim.predecessor = view.head;
            let verdict = check_send(&view, &request, &claim);
            match name {
                "credential" => assert_eq!(verdict, Err(ConsumerError::Credential)),
                "scheme" => assert_eq!(verdict, Err(ConsumerError::Scheme)),
                "wallet" => assert_eq!(verdict, Err(ConsumerError::Payer)),
                // The lineage proof exposes no asset: only the circuit binds it.
                _ => assert_eq!(verdict.map(|accepted| accepted.relation), Ok(relation)),
            }
            // Neither the forged nor the honest opening proves the claim.
            let public = claimed(&claim);
            for witness in [&forged, &honest] {
                let report = check_claim(&shape, witness, &public);
                assert!(!report.is_satisfied(), "{name}: claim accepted");
                assert!(
                    report
                        .failures()
                        .iter()
                        .all(|failure| matches!(failure, CheckFailure::CopyMismatch { .. }))
                );
            }
        }
    }
}

/// The receive side: a receiver statement over another asset, scheme or
/// wallet than the Request it answers is rejected. A substituted
/// credential digest is a step from another head: `sigma_recv` and the
/// consumer never compare the credential digest with the Request's (owner
/// answer Q8), so credential continuity and the `payment_key` are bound by
/// the receipt and `Λ_recv`, and the moved head by the receiver's lineage.
#[test]
fn receive_identity_substitution_is_rejected() {
    let relation = SigmaRelation::RECEIVE;
    let honest = honest(relation);
    let request = honest.request_body();
    let shape = shape(relation);
    let statement = honest.statement(relation).expect("statement");
    assert_eq!(consume(&honest, &request, &statement), Ok(relation));
    for (name, edit) in identity_edits() {
        let mut forged = honest.clone();
        edit(&mut forged);
        assert!(check_witness(&shape, &forged).is_satisfied(), "{name}");
        let own = forged.statement(relation).expect("statement");
        assert_ne!(own.predecessor, statement.predecessor, "{name}");
        let verdict = consume(&forged, &request, &own);
        match name {
            "credential" => {
                // Q8: accepted against the Request; the head moved.
                assert_eq!(verdict, Ok(relation));
                continue;
            }
            "asset" => assert_eq!(verdict, Err(ConsumerError::Asset)),
            "scheme" => assert_eq!(verdict, Err(ConsumerError::Scheme)),
            // Another receiver wallet is another credit_id.
            _ => assert_eq!(verdict, Err(ConsumerError::Effect)),
        }
        // The forger's statement with the honest Request's identity fields
        // and effect.
        let mut claim = own.clone();
        claim.asset_digest = request.asset_digest;
        claim.scheme_id = request.scheme_id;
        claim.effect.clone_from(&statement.effect);
        assert_eq!(consume(&forged, &request, &claim), Ok(relation), "{name}");
        assert!(
            !check_claim(&shape, &forged, &claimed(&claim)).is_satisfied(),
            "{name}"
        );
    }
}

/// Owner answer Q8: a Request quoted under the receiver's credential before
/// a renewal stays receivable after it; a Request addressed to another
/// wallet is not receivable by this wallet's state.
#[test]
fn the_receiver_is_bound_by_wallet_not_by_credential_digest() {
    let relation = SigmaRelation::RECEIVE;
    let shape = shape(relation);
    let mut renewed = honest(relation);
    let StepInputs::Receive(inputs) = &mut renewed.inputs else {
        panic!("receive");
    };
    // The Request names the credential before the renewal; the core holds
    // the renewed one.
    inputs.receiver_credential_digest[0] ^= 0x33;
    let request = renewed.request_body();
    assert_ne!(
        request.receiver_credential_digest,
        renewed.predecessor.core.identity.credential_digest
    );
    assert!(renewed.evaluate(relation).is_honest());
    assert!(check_witness(&shape, &renewed).is_satisfied());
    let statement = renewed.statement(relation).expect("statement");
    assert_eq!(
        statement.credential_digest,
        renewed.predecessor.core.identity.credential_digest
    );
    assert_eq!(consume(&renewed, &request, &statement), Ok(relation));
    // The payer's Request addressed another wallet: the payer recomputes
    // its credit_id, which this state cannot reach.
    let mut elsewhere = request;
    elsewhere.receiver_wallet[0] ^= 1;
    assert_eq!(
        consume(&renewed, &elsewhere, &statement),
        Err(ConsumerError::Effect)
    );
    let mut claim = statement;
    claim.effect[0] = elsewhere.credit_id::<Fp>();
    assert_eq!(consume(&renewed, &elsewhere, &claim), Ok(relation));
    assert!(!check_claim(&shape, &renewed, &claimed(&claim)).is_satisfied());
}

/// `credit_id` is the in-circuit Request digest (one element) in the chain,
/// the effect and the statement digest.
#[test]
fn credit_identifier_is_the_in_circuit_request_digest() {
    for relation in RELATIONS {
        let honest = honest(relation);
        let shape = shape(relation);
        let request = honest.request_body();
        let native = honest.evaluate(relation);
        let credit = request.credit_id::<Fp>();
        assert_eq!(native.digests.credit, credit);
        // The chain entry and the effect carry it as one element.
        assert_eq!(native.chain_entry[1], credit);
        assert_eq!(native.statement[17], credit);
        let statement = honest.statement(relation).expect("statement");
        // Any other credit: one the wallet already used, or a neighbour.
        let used = sample_witness::<Fp>(CHECK_SEED + 1, relation, Mutation::None)
            .request_body()
            .credit_id::<Fp>();
        for other in [used, credit + Fp::ONE] {
            let mut claim = statement.clone();
            claim.effect[0] = other;
            assert_eq!(
                consume(&honest, &request, &claim),
                Err(ConsumerError::Effect),
                "{relation:?}"
            );
            assert!(
                !check_claim(&shape, &honest, &claimed(&claim)).is_satisfied(),
                "{relation:?}"
            );
        }
    }
}

/// Both account digests are bound to the signed Request through the credit
/// identifier; consistently substituting one cannot prove the original step.
#[test]
fn request_account_substitution_cannot_keep_the_signed_request() {
    for relation in RELATIONS {
        let honest = honest(relation);
        let shape = shape(relation);
        let request = honest.request_body();
        let statement = honest.statement(relation).expect("statement");
        assert_eq!(consume(&honest, &request, &statement), Ok(relation));
        for (name, payer) in [("payer account", true), ("receiver account", false)] {
            let mut forged = honest.clone();
            let account = match &mut forged.inputs {
                StepInputs::Send(send) if payer => &mut send.payer_account_digest,
                StepInputs::Send(send) => &mut send.receiver_account_digest,
                StepInputs::Receive(receive) if payer => &mut receive.payer_account_digest,
                StepInputs::Receive(receive) => &mut receive.receiver_account_digest,
            };
            account[16] ^= 1;
            let own = forged.statement(relation).expect("forged statement");
            assert_eq!(own.predecessor, statement.predecessor, "{name}");
            assert_ne!(own.effect[0], statement.effect[0], "{name}");
            // A proof of the substituted Request cannot be used for the
            // signed Request the consumer actually received.
            assert!(check_witness(&shape, &forged).is_satisfied(), "{name}");
            assert_eq!(
                consume(&forged, &request, &own),
                Err(ConsumerError::Effect),
                "{name}"
            );
            assert!(
                !check_claim(&shape, &forged, &claimed(&statement)).is_satisfied(),
                "{name}"
            );
        }
    }
}

/// `sigma_send` takes the lineage `burned_total`: a balance of 100 whose
/// lineage burned 40 cannot send 100.
#[test]
fn burned_value_cannot_be_spent() {
    let relation = SigmaRelation::SEND;
    let shape = shape(relation);
    let mut witness = honest(relation);
    witness.predecessor.core.balance = 100;
    witness.predecessor.core.burned_total = 0;
    let StepInputs::Send(send) = &mut witness.inputs else {
        panic!("send");
    };
    send.lineage.burned_total = 40;
    send.request.amount = 100;
    send.request.fee = 0;
    // The honest witness (the lineage input is Ω(pred)'s 40) overdraws.
    assert_eq!(
        witness.evaluate(relation).violations,
        vec![Violation::Overdraft]
    );
    let report = check_witness(&shape, &witness);
    assert!(!report.is_satisfied());
    assert!(
        report
            .failures()
            .iter()
            .all(|failure| matches!(failure, CheckFailure::LookupInputMissing { lookup: 0, .. }))
    );
    // 60 is spendable.
    let mut sixty = witness.clone();
    if let StepInputs::Send(send) = &mut sixty.inputs {
        send.request.amount = 60;
    }
    let native = sixty.evaluate(relation);
    assert!(native.is_honest());
    let successor = native.successor_state.expect("successor");
    assert_eq!(
        (successor.core.balance, successor.core.burned_total),
        (40, 40)
    );
    assert!(check_witness(&shape, &sixty).is_satisfied());
    // The forger drops burned_total to 0: the step is valid, but its
    // statement carries 0, which the consumer compares with Ω(pred)'s 40.
    let view = lineage_view_of(&witness).expect("send witness");
    let mut forged = witness.clone();
    if let StepInputs::Send(send) = &mut forged.inputs {
        send.lineage.burned_total = 0;
    }
    assert!(forged.evaluate(relation).is_honest());
    assert!(check_witness(&shape, &forged).is_satisfied());
    let own = forged.statement(relation).expect("statement");
    let request = forged.request_body();
    assert_eq!(
        check_send(&view, &request, &own),
        Err(ConsumerError::BurnedTotal)
    );
    // The statement the consumer would accept (burned_total 40) is not
    // provable from the forged witness.
    let mut claim = own;
    claim.lineage_burned_total = 40;
    let accepted = check_send(&view, &request, &claim).expect("consumer view");
    assert!(!check_claim(&shape, &forged, &accepted.public).is_satisfied());
}

/// Owner answer Q5: a stale blacklist cannot be sent past. Ω(pred)'s mask
/// selects the blacklist relation, which rejects the list; the control-free
/// relation refuses the masked core; rewriting the mask or the issue time
/// moves the head.
#[test]
fn a_stale_blacklist_cannot_be_sent_past() {
    let blacklist = shape(SEND_BLACKLIST);
    let control_free = shape(SigmaRelation::SEND);
    let stale = sample_witness::<Fp>(CHECK_SEED, SEND_BLACKLIST, Mutation::StaleBlacklist);
    let view = lineage_view_of(&stale).expect("send witness");
    assert_eq!(view.enabled_controls, CONTROL_BLACKLIST);
    // The consumer selects the blacklist relation from Ω(pred)'s mask.
    assert_eq!(
        stale.evaluate(SEND_BLACKLIST).violations,
        vec![Violation::BlacklistTooOld]
    );
    let report = check_witness(&blacklist, &stale);
    assert!(!report.is_satisfied());
    assert!(
        report
            .failures()
            .iter()
            .all(|failure| matches!(failure, CheckFailure::LookupInputMissing { lookup: 0, .. }))
    );
    // The control-free relation does not enforce the age, but refuses a
    // core whose mask enables the control.
    assert_eq!(
        stale.evaluate(SigmaRelation::SEND).violations,
        vec![Violation::ControlsMismatch]
    );
    assert!(!check_witness(&control_free, &stale).is_satisfied());
    // A forger clears the mask (or freshens the issue time): a valid step
    // from another head, rejected against Ω(pred).
    let mut unmasked = stale.clone();
    unmasked.predecessor.core.controls.enabled = 0;
    let mut fresh = stale.clone();
    let StepInputs::Send(send) = &stale.inputs else {
        panic!("send");
    };
    fresh.predecessor.core.controls.blacklist_issued_at_ms = send.accepted_upper;
    for (name, forged, relation, shape) in [
        ("unmasked", &unmasked, SigmaRelation::SEND, &control_free),
        ("fresh", &fresh, SEND_BLACKLIST, &blacklist),
    ] {
        assert!(forged.evaluate(relation).is_honest(), "{name}");
        assert!(check_witness(shape, forged).is_satisfied(), "{name}");
        let own = forged.statement(relation).expect("statement");
        let request = forged.request_body();
        assert_eq!(
            check_send(&view, &request, &own),
            Err(ConsumerError::Predecessor),
            "{name}"
        );
        // The claim for the real head (and Ω(pred)'s mask) is unprovable.
        let mut claim = own;
        claim.predecessor = view.head;
        claim.enabled_controls = view.enabled_controls;
        let accepted = check_send(&view, &request, &claim).expect("consumer view");
        assert_eq!(accepted.relation, SEND_BLACKLIST, "{name}");
        assert!(
            !check_claim(shape, forged, &accepted.public).is_satisfied(),
            "{name}"
        );
        assert!(
            !check_claim(&blacklist, &stale, &accepted.public).is_satisfied(),
            "{name}"
        );
    }
}

/// Payer and receiver wallets must differ.
#[test]
fn self_payment_has_no_witness() {
    for relation in RELATIONS {
        let witness = sample_witness::<Fp>(CHECK_SEED, relation, Mutation::SelfPayment);
        assert_eq!(
            witness.evaluate(relation).violations,
            vec![Violation::SelfPayment]
        );
        let report = check_witness(&shape(relation), &witness);
        assert!(!report.is_satisfied(), "{relation:?}");
        assert!(
            report
                .failures()
                .iter()
                .all(|failure| matches!(failure, CheckFailure::CopyMismatch { .. })),
            "{relation:?}: {:?}",
            report.failures()
        );
    }
}

/// The successor's floor is the accepted lower time: a second Send cannot
/// accept a time before the first one's lower bound.
#[test]
fn accepted_time_never_goes_back() {
    let relation = SigmaRelation::SEND;
    let shape = shape(relation);
    let first = honest(relation);
    let StepInputs::Send(first_send) = &first.inputs else {
        panic!("send");
    };
    let lower = first_send.accepted_lower;
    assert!(lower > first.predecessor.core.accepted_time_floor_ms);
    let after = first
        .evaluate(relation)
        .successor_state
        .expect("honest successor");
    assert_eq!(after.core.accepted_time_floor_ms, lower);
    // The second Send, from the first one's successor.
    let mut second = sample_witness::<Fp>(CHECK_SEED + 2, relation, Mutation::None);
    second.predecessor = after;
    let StepInputs::Send(send) = &mut second.inputs else {
        panic!("send");
    };
    send.lineage.burned_total = after.core.burned_total;
    send.receiver_wallet = first_send.receiver_wallet;
    send.request.policy_epoch = after.core.policy_epoch;
    send.request.request_time = lower - 10;
    send.accepted_lower = lower - 1;
    send.accepted_upper = lower + 600;
    assert_eq!(
        second.evaluate(relation).violations,
        vec![Violation::AcceptedTimeBelowFloor]
    );
    assert!(!check_witness(&shape, &second).is_satisfied());
    // At the first one's lower bound it is accepted.
    if let StepInputs::Send(send) = &mut second.inputs {
        send.accepted_lower = lower;
    }
    assert!(second.evaluate(relation).is_honest());
    assert!(check_witness(&shape, &second).is_satisfied());
}

/// The statement carries only the opened commitments.
#[test]
fn the_statement_predecessor_is_the_opened_commitment() {
    for relation in RELATIONS {
        let witness = honest(relation);
        let shape = shape(relation);
        let statement = witness.statement(relation).expect("statement");
        assert_eq!(statement.predecessor, witness.predecessor.commitment());
        let edits: [fn(&mut StatementV1<Fp>); 2] =
            [|s| s.predecessor += Fp::ONE, |s| s.successor += Fp::ONE];
        for edit in edits {
            let mut claim = statement.clone();
            edit(&mut claim);
            assert!(!check_claim(&shape, &witness, &claimed(&claim)).is_satisfied());
        }
    }
}

/// The scheme-level relation identity is a witness bound by the statement
/// digest: a statement relabelled with another identity is neither
/// accepted by a consumer of the scheme nor provable from the honest
/// witness, and a witness carrying another identity proves only a statement
/// the consumer rejects.
#[test]
fn the_relation_identity_is_bound_by_the_statement() {
    for relation in RELATIONS {
        let witness = honest(relation);
        let shape = shape(relation);
        let request = witness.request_body();
        let statement = witness.statement(relation).expect("statement");
        let mut relabelled = statement.clone();
        relabelled.relation_id[0] ^= 1;
        assert_eq!(
            consume(&witness, &request, &relabelled),
            Err(ConsumerError::Relation)
        );
        assert!(!check_claim(&shape, &witness, &claimed(&relabelled)).is_satisfied());
        let mut foreign = witness.clone();
        foreign.relation_id[0] ^= 1;
        assert!(check_witness(&shape, &foreign).is_satisfied());
        let own = foreign.statement(relation).expect("statement");
        assert_eq!(own, relabelled);
        assert_eq!(
            consume(&witness, &request, &own),
            Err(ConsumerError::Relation)
        );
    }
}
