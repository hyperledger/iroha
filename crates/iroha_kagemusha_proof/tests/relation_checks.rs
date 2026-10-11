//! The relation checks in the strict constraint checker, on every relation
//! shape: `sigma_send` without and with the blacklist control, `sigma_recv`,
//! and both Poseidon prefix modes (the analogue of M7's two Poseidon
//! backends: two different circuits computing identical digests).
//!
//! - The 20 range-check cases (`RELATION_CASES`): each honest witness is
//!   accepted; an overdraft, a balance that covers `amount + fee` only while
//!   ignoring the lineage `burned_total`, a newer Request policy epoch, an
//!   accepted time below the floor, a blacklist older than the maximum age
//!   or issued after the accepted upper time, and a `u128` overflow are
//!   rejected, and every rejection is a limb lookup of a range check (the
//!   relation's checked arithmetic), never a digest or copy mismatch.
//! - Every other relation rule, broken alone, is rejected, and the integer
//!   boundaries are accepted exactly up to the limit, on all six shapes.
//! - A wrong public input is rejected by the instance copy.
//!
//! The per-cell tamper suite (`iroha_plonk_gadgets::tamper`) runs on every
//! honest case in release (ignored here). It shows that every assigned
//! advice cell is pinned by a gate, a lookup or a copy; it does not show
//! that the relation binds what the spec requires. The consistent-forgery
//! tests of `tests/forgeries.rs` do that.

mod common;

use common::{
    CHECK_SEED, RELATION_CASES, RELATION_CHECK_CASES, SEND_BLACKLIST, case_label, check_witness,
    check_witness_of, folded, relation_shapes, smallest_shape,
};
use iroha_kagemusha_proof::{
    CONTROL_BLACKLIST, LIFECYCLE_RETIRING, Mutation, RelationShape, SigmaCircuit, SigmaRelation,
    StepInputs, StepRelation, StepWitness, Violation, sample_witness,
};
use iroha_pasta::{Fp, Fq, poseidon::PoseidonField};
use iroha_plonk::check::CheckFailure;
use iroha_plonk_gadgets::tamper::undetected_tampers;

/// The violation the native reference must report for a mutation.
const fn expected_violation(mutation: Mutation) -> Option<Violation> {
    match mutation {
        Mutation::None => None,
        Mutation::Overdraft | Mutation::Burned => Some(Violation::Overdraft),
        Mutation::Overflow => Some(Violation::BalanceOverflow),
        Mutation::StaleEpoch => Some(Violation::PolicyEpochNewer),
        Mutation::EarlyTime => Some(Violation::AcceptedTimeBelowFloor),
        Mutation::SelfPayment => Some(Violation::SelfPayment),
        Mutation::ControlsMismatch => Some(Violation::ControlsMismatch),
        Mutation::StaleBlacklist | Mutation::FutureBlacklist => Some(Violation::BlacklistTooOld),
    }
}

/// Runs the range-check cases on field `F` and returns how many were
/// checked.
fn relation_checks<F: PoseidonField>() -> usize {
    let mut cases = 0;
    for relation in relation_shapes() {
        let shape = smallest_shape(relation);
        for (case, mutation, expected) in RELATION_CASES {
            if case != relation.relation {
                continue;
            }
            let witness = sample_witness::<F>(CHECK_SEED, case, mutation);
            let native = witness.evaluate(case);
            assert_eq!(
                native.is_honest(),
                expected,
                "{}",
                case_label(relation, mutation)
            );
            if let Some(violation) = expected_violation(mutation) {
                assert_eq!(native.violations, vec![violation]);
            }
            let report = check_witness(&shape, &witness);
            println!(
                "M12_CHECK case={} k={} lanes={} mutation={mutation:?} accepted={} expected={expected} failures={}",
                relation.label(),
                shape.k,
                shape.params.lanes(),
                report.is_satisfied(),
                report.failures().len()
            );
            assert_eq!(
                report.is_satisfied(),
                expected,
                "{}: {:?}",
                case_label(relation, mutation),
                report.failures()
            );
            for failure in report.failures() {
                assert!(
                    matches!(failure, CheckFailure::LookupInputMissing { lookup: 0, .. }),
                    "{}: {failure}",
                    case_label(relation, mutation)
                );
            }
            cases += 1;
        }
    }
    cases
}

#[test]
fn relation_checks_in_the_constraint_checker() {
    assert_eq!(relation_checks::<Fp>(), RELATION_CHECK_CASES);
}

#[test]
#[ignore = "the 20 cases on the Pallas scalar field; run in release"]
fn relation_checks_on_the_other_field() {
    assert_eq!(relation_checks::<Fq>(), RELATION_CHECK_CASES);
}

/// A witness edit of [`rule_sweep`].
type Edit = fn(&mut StepWitness<Fp>);

/// The `sigma_send` inputs of a witness.
fn send_inputs(
    witness: &mut StepWitness<Fp>,
) -> &mut iroha_kagemusha_proof::witness::SendInputs<Fp> {
    match &mut witness.inputs {
        StepInputs::Send(send) => send,
        StepInputs::Receive(_) => panic!("a send witness"),
    }
}

/// The `sigma_recv` inputs of a witness.
fn receive_inputs(
    witness: &mut StepWitness<Fp>,
) -> &mut iroha_kagemusha_proof::witness::ReceiveInputs<Fp> {
    match &mut witness.inputs {
        StepInputs::Receive(receive) => receive,
        StepInputs::Send(_) => panic!("a receive witness"),
    }
}

/// Rule edits of `sigma_send`: each breaks the named rules alone.
fn send_rule_edits() -> Vec<(&'static str, Vec<Violation>, Edit)> {
    vec![
        ("lifecycle 0", vec![Violation::Lifecycle], |w| {
            w.predecessor.core.lifecycle = 0;
        }),
        ("lifecycle 3", vec![Violation::Lifecycle], |w| {
            w.predecessor.core.lifecycle = 3;
        }),
        ("sequence", vec![Violation::SequenceOverflow], |w| {
            w.predecessor.core.sequence = u128::MAX;
        }),
        ("ordinal", vec![Violation::SendOrdinalOverflow], |w| {
            w.predecessor.core.next_send = u128::MAX;
        }),
        ("amount", vec![Violation::ZeroAmount], |w| {
            send_inputs(w).request.amount = 0;
        }),
        (
            "request time",
            vec![Violation::AcceptedTimeBelowRequest],
            |w| {
                let send = send_inputs(w);
                send.request.request_time = send.accepted_lower + 1;
            },
        ),
        ("window", vec![Violation::AcceptedWindowInverted], |w| {
            let send = send_inputs(w);
            send.accepted_upper = send.accepted_lower - 1;
        }),
        ("self payment", vec![Violation::SelfPayment], |w| {
            let own = w.predecessor.core.identity.wallet_id;
            send_inputs(w).receiver_wallet = own;
        }),
        ("wallets equal in the low limb only", vec![], |w| {
            // Wallets equal in one limb only are distinct.
            let mut receiver = w.predecessor.core.identity.wallet_id;
            receiver[31] ^= 1;
            send_inputs(w).receiver_wallet = receiver;
        }),
        ("controls", vec![Violation::ControlsMismatch], |w| {
            w.predecessor.core.controls.enabled ^= 4;
        }),
        (
            "debit overflow",
            vec![Violation::DebitOverflow, Violation::Overdraft],
            |w| {
                w.predecessor.core.balance = u128::MAX;
                let send = send_inputs(w);
                send.lineage.burned_total = 0;
                send.request.amount = u128::MAX;
                send.request.fee = 1;
            },
        ),
        (
            "burned above the balance",
            vec![Violation::Overdraft],
            |w| {
                let balance = w.predecessor.core.balance;
                send_inputs(w).lineage.burned_total = balance + 1;
            },
        ),
        (
            "debit one above the spendable",
            vec![Violation::Overdraft],
            |w| {
                let send = send_inputs(w);
                let debit = send.request.amount + send.request.fee;
                w.predecessor.core.balance = send.lineage.burned_total + debit - 1;
            },
        ),
    ]
}

/// Edits of `sigma_send` at the integer limits that stay honest.
fn send_boundary_edits() -> Vec<(&'static str, Edit)> {
    vec![
        ("debit equals the spendable", |w| {
            let send = send_inputs(w);
            let debit = send.request.amount + send.request.fee;
            w.predecessor.core.balance = send.lineage.burned_total + debit;
        }),
        ("next_send = 2^128 - 2", |w| {
            w.predecessor.core.next_send = u128::MAX - 1;
        }),
        ("sequence = 2^128 - 2", |w| {
            w.predecessor.core.sequence = u128::MAX - 1;
        }),
        ("debit = 2^128 - 1", |w| {
            w.predecessor.core.balance = u128::MAX;
            let send = send_inputs(w);
            send.lineage.burned_total = 0;
            send.request.amount = u128::MAX - 1;
            send.request.fee = 1;
        }),
        ("floor = request time = lower = upper", |w| {
            let floor = w.predecessor.core.accepted_time_floor_ms;
            let send = send_inputs(w);
            send.request.request_time = floor;
            send.accepted_lower = floor;
            send.accepted_upper = floor;
        }),
        ("epochs equal", |w| {
            let epoch = w.predecessor.core.policy_epoch;
            send_inputs(w).request.policy_epoch = epoch;
        }),
        ("a Retiring payer", |w| {
            w.predecessor.core.lifecycle = LIFECYCLE_RETIRING;
        }),
    ]
}

/// Rule edits of the blacklist control's maximum-age rule (on the
/// blacklist relation only; the relation without the control accepts them
/// unless they also change its mask).
fn blacklist_rule_edits() -> Vec<(&'static str, Vec<Violation>, Edit)> {
    vec![
        (
            "one millisecond too old",
            vec![Violation::BlacklistTooOld],
            |w| {
                let upper = send_inputs(w).accepted_upper;
                let controls = &mut w.predecessor.core.controls;
                controls.blacklist_issued_at_ms = upper - controls.blacklist_max_age_ms - 1;
            },
        ),
        (
            "issued one millisecond after the upper time",
            vec![Violation::BlacklistTooOld],
            |w| {
                let upper = send_inputs(w).accepted_upper;
                w.predecessor.core.controls.blacklist_issued_at_ms = upper + 1;
            },
        ),
        (
            "issued at u64::MAX under the largest age",
            vec![Violation::BlacklistTooOld],
            |w| {
                let controls = &mut w.predecessor.core.controls;
                controls.blacklist_issued_at_ms = u64::MAX;
                controls.blacklist_max_age_ms = u64::MAX;
            },
        ),
    ]
}

/// Edits of the blacklist relation at the age limits that stay honest.
fn blacklist_boundary_edits() -> Vec<(&'static str, Edit)> {
    vec![
        ("age exactly the maximum", |w| {
            let upper = send_inputs(w).accepted_upper;
            let controls = &mut w.predecessor.core.controls;
            controls.blacklist_issued_at_ms = upper - controls.blacklist_max_age_ms;
        }),
        ("issued at the upper time", |w| {
            let upper = send_inputs(w).accepted_upper;
            w.predecessor.core.controls.blacklist_issued_at_ms = upper;
        }),
        ("no list held", |w| {
            let controls = &mut w.predecessor.core.controls;
            controls.blacklist_version = 0;
            controls.blacklist_issued_at_ms = u64::MAX;
        }),
        ("no age rule", |w| {
            let controls = &mut w.predecessor.core.controls;
            controls.blacklist_max_age_ms = 0;
            controls.blacklist_issued_at_ms = 0;
        }),
        ("the largest age", |w| {
            let controls = &mut w.predecessor.core.controls;
            controls.blacklist_issued_at_ms = 0;
            controls.blacklist_max_age_ms = u64::MAX;
        }),
    ]
}

/// Rule edits of `sigma_recv`.
fn receive_rule_edits() -> Vec<(&'static str, Vec<Violation>, Edit)> {
    vec![
        ("lifecycle", vec![Violation::Lifecycle], |w| {
            w.predecessor.core.lifecycle = 0;
        }),
        ("sequence", vec![Violation::SequenceOverflow], |w| {
            w.predecessor.core.sequence = u128::MAX;
        }),
        ("amount", vec![Violation::ZeroAmount], |w| {
            receive_inputs(w).request.amount = 0;
        }),
        ("self payment", vec![Violation::SelfPayment], |w| {
            let own = w.predecessor.core.identity.wallet_id;
            receive_inputs(w).payer_wallet = own;
        }),
        ("balance overflow", vec![Violation::BalanceOverflow], |w| {
            let amount = receive_inputs(w).request.amount;
            w.predecessor.core.balance = u128::MAX - amount + 1;
        }),
    ]
}

/// Edits of `sigma_recv` at the integer limits that stay honest.
fn receive_boundary_edits() -> Vec<(&'static str, Edit)> {
    vec![
        ("balance + amount = 2^128 - 1", |w| {
            let amount = receive_inputs(w).request.amount;
            w.predecessor.core.balance = u128::MAX - amount;
        }),
        ("sequence = 2^128 - 2", |w| {
            w.predecessor.core.sequence = u128::MAX - 1;
        }),
        ("controls enabled", |w| {
            // A Receive carries the mask; only Send enforces it.
            w.predecessor.core.controls.enabled = CONTROL_BLACKLIST;
        }),
        ("a Retiring receiver", |w| {
            w.predecessor.core.lifecycle = LIFECYCLE_RETIRING;
        }),
        ("a Request quoted under the renewed credential", |w| {
            // Owner answer Q8: the receiver is matched by wallet_id.
            receive_inputs(w).receiver_credential_digest[0] ^= 0x5a;
        }),
    ]
}

/// Every rule edit is rejected and every boundary edit accepted on
/// `relation`; returns the number of checks.
fn rule_sweep(relation: RelationShape) -> usize {
    let shape = smallest_shape(relation);
    let case = relation.relation;
    let honest = check_witness_of(case, Mutation::None);
    let (mut rules, mut boundaries) = match case.step() {
        StepRelation::Send => (send_rule_edits(), send_boundary_edits()),
        StepRelation::Receive => (receive_rule_edits(), receive_boundary_edits()),
    };
    if case.enforces(CONTROL_BLACKLIST) {
        rules.extend(blacklist_rule_edits());
        boundaries.extend(blacklist_boundary_edits());
    } else if case.step() == StepRelation::Send {
        // Without the control, the age rule's rejections are honest.
        boundaries.extend(
            blacklist_rule_edits()
                .into_iter()
                .map(|(name, _, edit)| (name, edit)),
        );
    }
    let mut checks = 0;
    for (name, violations, edit) in rules {
        let mut witness = honest.clone();
        edit(&mut witness);
        assert_eq!(
            witness.evaluate(case).violations,
            violations,
            "{} {name}",
            relation.label()
        );
        let report = check_witness(&shape, &witness);
        assert_eq!(
            report.is_satisfied(),
            violations.is_empty(),
            "{} {name}: {:?}",
            relation.label(),
            report.failures()
        );
        checks += 1;
    }
    for (name, edit) in boundaries {
        let mut witness = honest.clone();
        edit(&mut witness);
        assert!(
            witness.evaluate(case).is_honest(),
            "{} {name}",
            relation.label()
        );
        let report = check_witness(&shape, &witness);
        assert!(
            report.is_satisfied(),
            "{} {name}: {:?}",
            relation.label(),
            report.failures()
        );
        checks += 1;
    }
    checks
}

#[test]
fn every_relation_rule_is_enforced_on_every_shape() {
    let checks: usize = relation_shapes().into_iter().map(rule_sweep).sum();
    println!("M12_RULES checks={checks}");
    // Per prefix mode: sigma_send 13 rules + 7 boundaries + 3 unenforced age
    // edits; with the blacklist control 16 + 12; sigma_recv 5 + 5.
    assert_eq!(checks, 2 * ((13 + 7 + 3) + (16 + 12) + (5 + 5)));
}

#[test]
fn rule_failures_have_their_kinds() {
    let shape = smallest_shape(folded(SigmaRelation::SEND));
    let honest = check_witness_of(SigmaRelation::SEND, Mutation::None);
    // An enabled control the relation does not enforce and a self payment
    // fail a constant copy, not a lookup.
    let edits: [Edit; 2] = [
        |w| w.predecessor.core.controls.enabled = CONTROL_BLACKLIST,
        |w| {
            let own = w.predecessor.core.identity.wallet_id;
            send_inputs(w).receiver_wallet = own;
        },
    ];
    for edit in edits {
        let mut witness = honest.clone();
        edit(&mut witness);
        assert!(
            check_witness(&shape, &witness)
                .failures()
                .iter()
                .any(|failure| matches!(failure, CheckFailure::CopyMismatch { .. }))
        );
    }
    // A lifecycle other than Active or Retiring fails the boolean gate.
    let mut lifecycle = honest.clone();
    lifecycle.predecessor.core.lifecycle = 3;
    let report = check_witness(&shape, &lifecycle);
    assert!(
        report
            .failures()
            .iter()
            .all(|failure| matches!(failure, CheckFailure::ConstraintNotSatisfied { .. })),
        "{report:?}"
    );
    // The blacklist relation refuses a core whose mask lacks the control.
    let blacklist = smallest_shape(folded(SEND_BLACKLIST));
    let mut unmasked = check_witness_of(SEND_BLACKLIST, Mutation::None);
    unmasked.predecessor.core.controls.enabled = 0;
    let report = check_witness(&blacklist, &unmasked);
    assert!(
        report
            .failures()
            .iter()
            .any(|failure| matches!(failure, CheckFailure::CopyMismatch { .. }))
    );
    // A zero amount fails the nonzero gate.
    let receive = smallest_shape(folded(SigmaRelation::RECEIVE));
    let mut zero = check_witness_of(SigmaRelation::RECEIVE, Mutation::None);
    receive_inputs(&mut zero).request.amount = 0;
    let report = check_witness(&receive, &zero);
    assert!(
        report
            .failures()
            .iter()
            .any(|failure| matches!(failure, CheckFailure::ConstraintNotSatisfied { .. })),
        "{report:?}"
    );
}

/// A wrong public input is rejected by the instance copy.
#[test]
fn wrong_public_inputs_are_rejected() {
    use ff::Field;
    use iroha_plonk::check::{CheckMode, check_circuit};
    let shape = smallest_shape(folded(SigmaRelation::SEND));
    let witness = check_witness_of(SigmaRelation::SEND, Mutation::None);
    let public = witness.evaluate(SigmaRelation::SEND).public().instance();
    let circuit = SigmaCircuit::new(shape.params, witness);
    for index in 0..public.len() {
        let mut wrong = public.clone();
        wrong[index] += Fp::ONE;
        let report =
            check_circuit(&circuit, shape.k, &[wrong], CheckMode::Strict).expect("synthesis");
        assert!(!report.is_satisfied(), "input {index}");
    }
}

/// One tamper sweep result: the case, its assigned cells and the free ones.
type TamperResult = (String, usize, Vec<(usize, usize)>);

/// The per-cell tamper suite on every honest case: each assigned advice
/// cell, shifted alone, makes the strict checker fail. This shows every
/// cell is pinned; `tests/forgeries.rs` shows what the pinned values are
/// bound to.
#[test]
#[ignore = "one synthesis and check per assigned cell (about 8-13k per case); run in release"]
fn honest_cases_have_no_unpinned_cells() {
    use rayon::prelude::*;
    let honest: Vec<RelationShape> = relation_shapes();
    let results: Vec<TamperResult> = honest
        .par_iter()
        .map(|relation| {
            let shape = smallest_shape(*relation);
            let witness = sample_witness::<Fp>(CHECK_SEED, relation.relation, Mutation::None);
            let public = witness.evaluate(relation.relation).public().instance();
            let circuit = SigmaCircuit::new(shape.params, witness);
            let cells = iroha_plonk_gadgets::tamper::assigned_advice_cells(
                &circuit,
                shape.k,
                core::slice::from_ref(&public),
            )
            .expect("cells");
            let undetected =
                undetected_tampers(&circuit, shape.k, &[public]).expect("tamper sweep");
            (relation.label(), cells.len(), undetected)
        })
        .collect();
    for (label, cells, undetected) in results {
        println!(
            "M12_TAMPER case={label} cells={cells} undetected={}",
            undetected.len()
        );
        assert!(
            undetected.is_empty(),
            "{label}: unpinned cells {undetected:?}"
        );
    }
}
