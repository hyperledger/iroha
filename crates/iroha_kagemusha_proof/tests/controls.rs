//! The regulatory controls in circuit (proposal sections 3.2 and 7, owner
//! answers A4 and A5; wire record sections 3.3 and 3.4): every enabled
//! control of `sigma_send` and the receiver's blacklist of `sigma_recv`,
//! honest and forged, in the strict constraint checker.
//!
//! - **Blacklist.** With a held list, the counterparty's account digest must
//!   have a gap opening in the committed list (the receiver's in
//!   `sigma_send`, the payer's in `sigma_recv`): a listed account, a gap of
//!   another account, a forged sibling and a gap against another root are
//!   rejected; with no list held (version 0) nothing is refused. The Receive
//!   relation is selected by the Request's recorded blacklist version.
//! - **Lease.** `U < lease_expires_at_ms`, exactly at the boundary.
//! - **Quotas.** Every touched window is charged within its limit and every
//!   defined kind is touched, against the committed window tree; the usage
//!   array is updated at its aligned slot against the committed usage root, and the
//!   successor commits the root after the charges. A raised limit, a
//!   segment that skips a touched window, an untouched kind, an exceeded
//!   limit, a misaligned or repeated slot, a wrong prior usage and
//!   a forged usage root are rejected.

mod common;

use std::time::Instant;

use common::{
    CHECK_SEED, RECEIVE_BLACKLIST, SEND_BLACKLIST, SEND_EVERY, SEND_LEASE, SEND_QUOTAS,
    check_claim, check_witness, folded, smallest_shape,
};
use ff::PrimeField;
use iroha_kagemusha_proof::{
    CONTROL_BLACKLIST, ConsumerError, Mutation, RelationShape, SigmaRelation, SigmaShape,
    StepInputs, StepWitness, Violation, check_receive, check_send, lineage_view_of, sample_witness,
};
use iroha_pasta::Fp;

fn shape(relation: SigmaRelation) -> SigmaShape {
    smallest_shape(folded(relation))
}

fn witness(relation: SigmaRelation, mutation: Mutation) -> StepWitness<Fp> {
    sample_witness::<Fp>(CHECK_SEED, relation, mutation)
}

/// Whether the strict checker accepts `witness` under `shape`, after
/// checking the native verdict is `honest`.
fn accepted(shape: &SigmaShape, witness: &StepWitness<Fp>, violations: &[Violation]) -> bool {
    let relation = shape.params.relation().relation;
    assert_eq!(
        witness.evaluate(relation).violations,
        violations,
        "{}",
        relation.label()
    );
    let started = Instant::now();
    let report = check_witness(shape, witness);
    println!(
        "CONTROL_CHECK case={} k={} lanes={} satisfied={} failures={} ms={}",
        relation.label(),
        shape.k,
        shape.params.lanes(),
        report.is_satisfied(),
        report.failures().len(),
        started.elapsed().as_millis()
    );
    report.is_satisfied()
}

fn send_inputs(
    witness: &mut StepWitness<Fp>,
) -> &mut iroha_kagemusha_proof::witness::SendInputs<Fp> {
    match &mut witness.inputs {
        StepInputs::Send(send) => send,
        StepInputs::Receive(_) => panic!("a send witness"),
    }
}

fn receive_inputs(
    witness: &mut StepWitness<Fp>,
) -> &mut iroha_kagemusha_proof::witness::ReceiveInputs<Fp> {
    match &mut witness.inputs {
        StepInputs::Receive(receive) => receive,
        StepInputs::Send(_) => panic!("a receive witness"),
    }
}

#[test]
fn honest_control_witnesses_satisfy_their_relations() {
    for relation in [SEND_BLACKLIST, SEND_LEASE, RECEIVE_BLACKLIST] {
        let shape = shape(relation);
        assert!(accepted(&shape, &witness(relation, Mutation::None), &[]));
    }
}

/// The blacklist rule of both steps: a listed counterparty, a gap of
/// another account, a forged sibling and a list root other than the head's
/// are refused; no held list refuses nothing.
#[test]
fn a_listed_counterparty_is_refused_by_both_steps() {
    for relation in [SEND_BLACKLIST, RECEIVE_BLACKLIST] {
        let shape = shape(relation);
        let listed = witness(relation, Mutation::Listed);
        assert!(!accepted(&shape, &listed, &[Violation::BlacklistListed]));
        // No list held: the same account is not refused (owner answer A5).
        let mut unheld = listed.clone();
        unheld.predecessor.core.controls.blacklist_version = 0;
        if let StepInputs::Receive(receive) = &mut unheld.inputs {
            receive.request.receiver_blacklist_version = 0;
            receive.request.receiver_blacklist_root = [0; 32];
            assert!(accepted(&shape_of(SigmaRelation::RECEIVE), &unheld, &[]));
        } else {
            assert!(accepted(&shape, &unheld, &[]));
        }
        // An honest gap opening of another account.
        let honest = witness(relation, Mutation::None);
        let mut other = honest.clone();
        match &mut other.inputs {
            StepInputs::Send(send) => send.receiver_account_digest = send.blacklist.lower,
            StepInputs::Receive(receive) => receive.payer_account_digest = receive.blacklist.lower,
        }
        assert!(!accepted(&shape, &other, &[Violation::BlacklistListed]));
        // A forged sibling, and a list root other than the committed one.
        let mut forged = honest.clone();
        match &mut forged.inputs {
            StepInputs::Send(send) => send.blacklist.siblings[3] += Fp::from(1_u64),
            StepInputs::Receive(receive) => receive.blacklist.siblings[3] += Fp::from(1_u64),
        }
        assert!(!accepted(&shape, &forged, &[Violation::BlacklistListed]));
        let mut rooted = honest;
        if let StepInputs::Receive(receive) = &mut rooted.inputs {
            let root: Fp = Option::from(Fp::from_repr(receive.request.receiver_blacklist_root))
                .expect("field");
            receive.request.receiver_blacklist_root = (root + Fp::from(1_u64)).to_repr();
        } else {
            rooted.predecessor.core.controls.blacklist_root += Fp::from(1_u64);
        }
        assert!(!accepted(&shape, &rooted, &[Violation::BlacklistListed]));
    }
}

/// The Receive relation is selected by the Request's recorded blacklist version:
/// a nonzero recorded version requires the blacklist relation, and a zero
/// recorded version requires the relation without the bit.
#[test]
fn the_receive_relation_follows_the_request_recorded_blacklist() {
    let enabled = witness(RECEIVE_BLACKLIST, Mutation::None);
    let control_free = shape(SigmaRelation::RECEIVE);
    assert!(!accepted(
        &control_free,
        &enabled,
        &[Violation::ControlsMismatch]
    ));
    let disabled = witness(SigmaRelation::RECEIVE, Mutation::None);
    assert!(!accepted(
        &shape(RECEIVE_BLACKLIST),
        &disabled,
        &[Violation::ControlsMismatch]
    ));
    // The consumer selects by the statement's blacklist bit, and a
    // statement claiming the bit off for a receiver whose control is on is
    // unprovable (the mask is the opened core cell).
    let statement = enabled.statement(RECEIVE_BLACKLIST).expect("statement");
    let accepted_relation =
        check_receive(&enabled.relation_id, &enabled.request_body(), &statement).expect("consumer");
    assert_eq!(accepted_relation.relation, RECEIVE_BLACKLIST);
    let mut cleared = statement.clone();
    cleared.enabled_controls &= !CONTROL_BLACKLIST;
    let selected =
        check_receive(&enabled.relation_id, &enabled.request_body(), &cleared).expect("consumer");
    assert_eq!(selected.relation, RECEIVE_BLACKLIST);
    assert!(!check_claim(&shape(RECEIVE_BLACKLIST), &enabled, &selected.public).is_satisfied());
    let mut relabelled = statement;
    relabelled.relation_id[0] ^= 1;
    assert_eq!(
        check_receive(&enabled.relation_id, &enabled.request_body(), &relabelled),
        Err(ConsumerError::Relation)
    );
    // Other receiver controls do not change the selector.
    let mut quotas = enabled.clone();
    quotas.predecessor.core.controls.enabled |= iroha_kagemusha_proof::CONTROL_QUOTAS;
    assert!(accepted(&shape(RECEIVE_BLACKLIST), &quotas, &[]));
}

/// The consumer's verdict on a forged Send: the forged witness is a valid
/// step of `relation` (accepted in circuit for its own statement), but its
/// statement fails the consumer checks against the honest Ω(pred) and
/// Request with `error`, and the statement the consumer would accept for
/// the real head and Request is unprovable from it.
fn forgery_is_refused(
    honest: &StepWitness<Fp>,
    forged: &StepWitness<Fp>,
    relation: SigmaRelation,
    error: ConsumerError,
) {
    let label = relation.label();
    assert!(forged.evaluate(relation).is_honest(), "{label}");
    let shape = shape(relation);
    assert!(check_witness(&shape, forged).is_satisfied(), "{label}");
    let view = lineage_view_of(honest).expect("send witness");
    let request = honest.request_body();
    let own = forged.statement(relation).expect("statement");
    assert_eq!(check_send(&view, &request, &own), Err(error), "{label}");
    // The consumer selects the honest head's relation by Ω(pred)'s mask.
    let mut claim = honest
        .statement(SigmaRelation::send(view.enabled_controls))
        .unwrap_or(own);
    claim.predecessor = view.head;
    claim.enabled_controls = view.enabled_controls;
    if let Ok(accepted) = check_send(&view, &request, &claim) {
        assert_eq!(
            accepted.relation,
            SigmaRelation::send(view.enabled_controls)
        );
        let selected = smallest_shape(folded(accepted.relation));
        assert!(
            !check_claim(&selected, forged, &accepted.public).is_satisfied(),
            "{label}"
        );
    }
}

/// A payer cannot pay a receiver its committed list contains: Ω(pred)'s
/// mask selects the blacklist relation, which has no witness; clearing the
/// mask or dropping the held list moves the head, and naming another
/// receiver account changes `credit_id`.
#[test]
fn a_listed_receiver_cannot_be_paid_by_a_consistent_forgery() {
    let listed = witness(SEND_BLACKLIST, Mutation::Listed);
    assert_eq!(
        listed.evaluate(SEND_BLACKLIST).violations,
        vec![Violation::BlacklistListed]
    );
    let mut unmasked = listed.clone();
    unmasked.predecessor.core.controls.enabled = 0;
    forgery_is_refused(
        &listed,
        &unmasked,
        SigmaRelation::SEND,
        ConsumerError::Predecessor,
    );
    let mut dropped = listed.clone();
    dropped.predecessor.core.controls.blacklist_version = 0;
    forgery_is_refused(
        &listed,
        &dropped,
        SEND_BLACKLIST,
        ConsumerError::Predecessor,
    );
    let mut renamed = listed.clone();
    let honest_gap = witness(SEND_BLACKLIST, Mutation::None);
    if let (StepInputs::Send(forged), StepInputs::Send(honest)) =
        (&mut renamed.inputs, &honest_gap.inputs)
    {
        forged.receiver_account_digest = honest.receiver_account_digest;
        forged.blacklist = honest.blacklist;
    }
    renamed.predecessor.core.controls.blacklist_root =
        honest_gap.predecessor.core.controls.blacklist_root;
    // The list without the listed account is another head.
    forgery_is_refused(
        &listed,
        &renamed,
        SEND_BLACKLIST,
        ConsumerError::Predecessor,
    );
}

/// A payer past its lease cannot Send: clearing the lease control or
/// extending the expiry moves the head.
#[test]
fn an_expired_lease_cannot_be_sent_past() {
    let expired = witness(SEND_LEASE, Mutation::LeaseExpired);
    let mut unmasked = expired.clone();
    unmasked.predecessor.core.controls.enabled = 0;
    forgery_is_refused(
        &expired,
        &unmasked,
        SigmaRelation::SEND,
        ConsumerError::Predecessor,
    );
    let mut extended = expired.clone();
    extended.predecessor.core.controls.lease_expires_at_ms += 1;
    forgery_is_refused(&expired, &extended, SEND_LEASE, ConsumerError::Predecessor);
}

/// A payer over its quota cannot Send: clearing the quota control, raising
/// the committed window root or rewriting the committed usage root moves the
/// head; the successor's usage root is computed in circuit, so no statement
/// with another successor is provable.
#[test]
fn an_exceeded_quota_cannot_be_sent_past() {
    let exceeded = witness(SEND_QUOTAS, Mutation::QuotaExceeded);
    let mut unmasked = exceeded.clone();
    unmasked.predecessor.core.controls.enabled = 0;
    forgery_is_refused(
        &exceeded,
        &unmasked,
        SigmaRelation::SEND,
        ConsumerError::Predecessor,
    );
    let honest = witness(SEND_QUOTAS, Mutation::None);
    let shape = shape(SEND_QUOTAS);
    let statement = honest.statement(SEND_QUOTAS).expect("statement");
    let mut other = statement;
    other.successor += Fp::from(1_u64);
    let claimed = iroha_kagemusha_proof::StepPublic {
        statement: other.digest().expect("digest"),
    };
    assert!(!check_claim(&shape, &honest, &claimed).is_satisfied());
}

/// The lease rule: `U < lease_expires_at_ms`, exactly.
#[test]
fn the_lease_expiry_is_enforced_exactly() {
    let shape = shape(SEND_LEASE);
    let expired = witness(SEND_LEASE, Mutation::LeaseExpired);
    assert!(!accepted(&shape, &expired, &[Violation::LeaseExpired]));
    let mut last = expired.clone();
    last.predecessor.core.controls.lease_expires_at_ms += 1;
    assert!(accepted(&shape, &last, &[]));
    // The relation without the control does not read the lease.
    assert!(accepted(
        &smallest_shape(RelationShape::new(
            SigmaRelation::SEND,
            iroha_kagemusha_proof::PrefixMode::Folded
        )),
        &{
            let mut free = expired;
            free.predecessor.core.controls.enabled = 0;
            free
        },
        &[]
    ));
}

/// The quota rule on the quota relation and on the full mask.
#[test]
fn quota_witnesses_are_charged_and_forgeries_refused() {
    let shape = shape(SEND_QUOTAS);
    for seed in [CHECK_SEED, CHECK_SEED + 1] {
        let honest = sample_witness::<Fp>(seed, SEND_QUOTAS, Mutation::None);
        assert!(accepted(&shape, &honest, &[]), "seed {seed}");
    }
    let exceeded = witness(SEND_QUOTAS, Mutation::QuotaExceeded);
    assert!(!accepted(&shape, &exceeded, &[Violation::QuotaExceeded]));
    let untouched = witness(SEND_QUOTAS, Mutation::QuotaUntouched);
    assert!(!accepted(
        &shape,
        &untouched,
        &[Violation::QuotaKindUntouched]
    ));
    let honest = witness(SEND_QUOTAS, Mutation::None);
    // A raised window limit (the opening no longer reaches the root).
    let mut raised = honest.clone();
    send_inputs(&mut raised).quota.segments[0].slots[1]
        .window
        .limit += 1;
    assert!(!accepted(&shape, &raised, &[Violation::QuotaWindowOpening]));
    // An insertion claimed for the present monthly key.
    let mut present = honest.clone();
    send_inputs(&mut present).quota.charges[2].slot =
        send_inputs(&mut present).quota.charges[0].slot;
    assert!(!accepted(&shape, &present, &[Violation::QuotaUsageOpening]));
    // A lower prior usage of the monthly window.
    let mut understated = honest.clone();
    send_inputs(&mut understated).quota.charges[2].used -= 1;
    assert!(!accepted(
        &shape,
        &understated,
        &[Violation::QuotaUsageOpening]
    ));
    // A forged committed usage root.
    let mut rooted = honest;
    rooted.predecessor.core.roots.quota_usage += Fp::from(1_u64);
    assert!(!accepted(&shape, &rooted, &[Violation::QuotaUsageOpening]));
    // A segment moved past the first touched day of an interval that
    // crosses a day boundary (two daily charges): the day it skips is
    // touched, so the segment's lower boundary fails.
    let mut skipped = witness(SEND_QUOTAS, Mutation::None);
    let send = send_inputs(&mut skipped);
    let (lower, upper) = (send.accepted_lower, send.accepted_upper);
    let [daily, monthly] = send.quota.segments;
    assert!(
        daily.slots[1].window.touches(lower, upper) && daily.slots[2].window.touches(lower, upper),
        "the check seed crosses a day boundary"
    );
    // Slots `base .. base + 3`: the daily segment's last three and the
    // monthly window.
    send.quota.segments[0].base = daily.base + 1;
    send.quota.segments[0].slots = [
        daily.slots[1],
        daily.slots[2],
        daily.slots[3],
        monthly.slots[1],
    ];
    let violations = skipped.evaluate(SEND_QUOTAS).violations;
    assert!(
        violations.contains(&Violation::QuotaWindowSkipped),
        "{violations:?}"
    );
    assert!(!accepted(&shape, &skipped, &violations));
    let every = shape_of(SEND_EVERY);
    assert!(accepted(&every, &witness(SEND_EVERY, Mutation::None), &[]));
}

fn shape_of(relation: SigmaRelation) -> SigmaShape {
    shape(relation)
}

/// A receiver-side forgery: the receiver's own Request names a listed payer;
/// claiming the list empty (version 0) moves the head, and naming another
/// payer account changes `credit_id`, which the payer's Credited check
/// recomputes from the Request it holds.
#[test]
fn a_listed_payer_cannot_be_received_by_a_consistent_forgery() {
    let listed = witness(RECEIVE_BLACKLIST, Mutation::Listed);
    let request = listed.request_body();
    // Updating or clearing the current list cannot admit a payer listed at Request time.
    let mut changed_head = listed.clone();
    changed_head.predecessor.core.controls.blacklist_version = 0;
    assert!(!accepted(
        &shape(RECEIVE_BLACKLIST),
        &changed_head,
        &[Violation::BlacklistListed]
    ));
    // Forging no enforcement rewrites the signed Request, so it changes credit_id.
    let mut dropped = listed.clone();
    receive_inputs(&mut dropped)
        .request
        .receiver_blacklist_version = 0;
    receive_inputs(&mut dropped).request.receiver_blacklist_root = [0; 32];
    assert!(accepted(&shape(SigmaRelation::RECEIVE), &dropped, &[]));
    let own = dropped
        .statement(SigmaRelation::RECEIVE)
        .expect("statement");
    assert_eq!(own.predecessor, listed.predecessor.commitment());
    assert_eq!(
        check_receive(&listed.relation_id, &request, &own),
        Err(ConsumerError::Effect)
    );
    let mut renamed = listed;
    receive_inputs(&mut renamed).payer_account_digest[0] ^= 0x01;
    assert_ne!(
        renamed.request_body().credit_id::<Fp>(),
        request.credit_id::<Fp>()
    );
}

/// Expiry and interval width are authenticated core fields and enforced by `σ_send`.
#[test]
fn quota_expiry_and_send_span_are_enforced_at_the_exact_boundaries() {
    let shape = shape(SEND_QUOTAS);
    let honest = witness(SEND_QUOTAS, Mutation::None);
    let StepInputs::Send(send) = &honest.inputs else {
        panic!("send")
    };
    let upper = send.accepted_upper;
    let span = upper - send.accepted_lower;
    let mut boundary = honest.clone();
    boundary.predecessor.core.controls.quota_share_expires_at_ms = upper + 1;
    boundary
        .predecessor
        .core
        .controls
        .time_anchor_max_response_ms = span;
    assert!(accepted(&shape, &boundary, &[]));
    let mut expired = boundary.clone();
    expired.predecessor.core.controls.quota_share_expires_at_ms = upper;
    assert!(!accepted(&shape, &expired, &[Violation::QuotaShareExpired]));
    let mut too_wide = boundary;
    too_wide
        .predecessor
        .core
        .controls
        .time_anchor_max_response_ms = span - 1;
    assert!(!accepted(&shape, &too_wide, &[Violation::SendSpan]));
    // Altering authenticated controls can satisfy a different head, never the original one.
    forgery_is_refused(&expired, &honest, SEND_QUOTAS, ConsumerError::Predecessor);
    forgery_is_refused(&too_wide, &honest, SEND_QUOTAS, ConsumerError::Predecessor);
}

/// A newer receiver list cannot strand the already committed Payment.
#[test]
fn receive_uses_the_recorded_list_after_the_current_list_changes() {
    let honest = witness(RECEIVE_BLACKLIST, Mutation::None);
    let mut renewed = honest.clone();
    renewed.predecessor.core.controls.enabled = 0;
    renewed.predecessor.core.controls.blacklist_version += 1;
    renewed.predecessor.core.controls.blacklist_root += Fp::from(1_u64);
    assert!(accepted(&shape(RECEIVE_BLACKLIST), &renewed, &[]));
    assert_eq!(renewed.request_body(), honest.request_body());
    let statement = renewed.statement(RECEIVE_BLACKLIST).expect("statement");
    assert_eq!(
        check_receive(&renewed.relation_id, &renewed.request_body(), &statement)
            .expect("consumer")
            .relation,
        RECEIVE_BLACKLIST
    );
}

/// A quota opening is tied to the touched window slot, and every candidate has six index bits.
#[test]
fn quota_array_rejects_misaligned_repeated_and_out_of_range_slots() {
    let shape = shape(SEND_QUOTAS);
    let honest = witness(SEND_QUOTAS, Mutation::None);
    for replacement in [0, 63, 64] {
        let mut forged = honest.clone();
        let charges = &mut send_inputs(&mut forged).quota.charges;
        assert_ne!(charges[2].slot, replacement);
        charges[2].slot = replacement;
        assert!(!accepted(&shape, &forged, &[Violation::QuotaUsageOpening]));
    }
    let mut repeated = honest.clone();
    let charges = &mut send_inputs(&mut repeated).quota.charges;
    charges[1].slot = charges[0].slot;
    assert!(!accepted(
        &shape,
        &repeated,
        &[Violation::QuotaUsageOpening]
    ));
}

/// B6 gives the zero version exactly one encoding: the zero root.
#[test]
fn request_blacklist_zero_version_and_root_must_agree() {
    let relation = SigmaRelation::SEND;
    let shape = shape(relation);
    for (version, root) in [(0, Fp::from(1).to_repr()), (1, [0; 32])] {
        let mut invalid = witness(relation, Mutation::None);
        let request = &mut send_inputs(&mut invalid).request;
        request.receiver_blacklist_version = version;
        request.receiver_blacklist_root = root;
        assert!(!accepted(&shape, &invalid, &[Violation::RequestBlacklist]));
    }
}

/// Byte encodings of P values are never reduced or interpreted as limb pairs.
#[test]
fn noncanonical_poseidon_digests_are_refused_before_synthesis() {
    use iroha_kagemusha_proof::SigmaCircuit;
    use iroha_plonk::check::{CheckMode, check_circuit};
    use iroha_plonk::frontend::Error;
    let relation = SigmaRelation::SEND;
    let shape = shape(relation);
    let honest = witness(relation, Mutation::None);
    let mut modulus = (-Fp::from(1)).to_repr();
    for byte in &mut modulus {
        let (next, carry) = byte.overflowing_add(1);
        *byte = next;
        if !carry {
            break;
        }
    }
    for malformed in [modulus, [0xff; 32]] {
        for slot in 0..13 {
            let mut invalid = honest.clone();
            let bytes = match slot {
                0 => &mut invalid.predecessor.core.identity.credential_digest,
                1 => &mut invalid.predecessor.rest.scheme_policy,
                2 => &mut invalid.predecessor.rest.fee_schedule,
                3 => &mut invalid.predecessor.rest.blacklist,
                4 => &mut invalid.predecessor.rest.quota_share,
                5 => &mut invalid.predecessor.rest.time_anchor,
                6 => &mut invalid.predecessor.rest.blacklist_history_root,
                7 => &mut send_inputs(&mut invalid).receiver_credential_digest,
                8 => &mut send_inputs(&mut invalid).request.fee_schedule,
                9 => &mut send_inputs(&mut invalid).request.scheme_policy,
                10 => &mut send_inputs(&mut invalid).request.certificates,
                11 => &mut send_inputs(&mut invalid).request.receiver_blacklist_root,
                12 => &mut send_inputs(&mut invalid).request_digest,
                _ => unreachable!(),
            };
            *bytes = malformed;
            let evaluated = invalid.evaluate(relation);
            assert!(
                evaluated
                    .violations
                    .contains(&Violation::NoncanonicalDigest),
                "slot {slot}"
            );
            assert!(invalid.statement(relation).is_none(), "slot {slot}");
            let circuit = SigmaCircuit::new(shape.params, invalid);
            assert!(
                matches!(
                    check_circuit(
                        &circuit,
                        shape.k,
                        &[evaluated.public().instance()],
                        CheckMode::Strict
                    ),
                    Err(Error::Synthesis)
                ),
                "slot {slot}"
            );
        }
    }
}
