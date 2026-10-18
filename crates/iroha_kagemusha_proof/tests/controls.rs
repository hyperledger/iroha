//! The regulatory controls in circuit (proposal sections 3.2 and 7; wire
//! record sections 3.3 and 3.4): every enabled control of `sigma_send`,
//! honest and forged, in the strict constraint checker. A wallet's blacklist
//! is local only and no relation reads it.
//!
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
    CHECK_SEED, SEND_EVERY, SEND_LEASE, SEND_QUOTAS, check_claim, check_witness, folded,
    smallest_shape,
};
use ff::PrimeField;
use iroha_kagemusha_proof::{
    ConsumerError, Mutation, RelationShape, SigmaRelation, SigmaShape, StepInputs, StepWitness,
    Violation, check_send, lineage_view_of, sample_witness,
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

#[test]
fn honest_control_witnesses_satisfy_their_relations() {
    let shape = shape(SEND_LEASE);
    assert!(accepted(&shape, &witness(SEND_LEASE, Mutation::None), &[]));
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
        for slot in 0..10 {
            let mut invalid = honest.clone();
            let bytes = match slot {
                0 => &mut invalid.predecessor.core.identity.credential_digest,
                1 => &mut invalid.predecessor.rest.scheme_policy,
                2 => &mut invalid.predecessor.rest.fee_schedule,
                3 => &mut invalid.predecessor.rest.quota_share,
                4 => &mut invalid.predecessor.rest.time_anchor,
                5 => &mut send_inputs(&mut invalid).receiver_credential_digest,
                6 => &mut send_inputs(&mut invalid).request.fee_schedule,
                7 => &mut send_inputs(&mut invalid).request.scheme_policy,
                8 => &mut send_inputs(&mut invalid).request.certificates,
                9 => &mut send_inputs(&mut invalid).request_digest,
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
