//! Journal, reducer, digest and progress tests, including the shared canonical byte vectors.

use norito::json::Value;

use super::{
    contract::{
        AttemptEvidenceKindV1, MAX_CUSTODY_REFERENCE_BYTES_V1, MAX_DISPATCHES_PER_IDENTITY_V1,
        MAX_ROUND_PARTICIPANTS_V1, MAX_ROUND_TRANSCRIPT_BYTES_V1, MAX_WORKFLOW_JOURNAL_BYTES_V1,
        MAX_WORKFLOW_STEPS_V1, MAX_WORKFLOW_TRANSACTION_BYTES_V1, RoundStateV1, StepKindV1,
        TransactionStateV1, WorkflowErrorCode, WorkflowKindV1, WorkflowStatusV1,
    },
    journal::{
        CustodyHandleV1, Digest32, DriverIdentityV1, RoundInputV1, RoundRecordV1, StepDescriptorV1,
        TransactionIdentityV1, TransactionInputV1, TransactionOperationV1, WorkflowBindingV1,
        WorkflowIdentityV1, WorkflowJournalRecordV1, WorkflowJournalV1, WorkflowPlanV1,
        WorkflowRequest, record_digest, round_identity, transcript_digest,
    },
    testing::fixture_digest,
};

type PlanChange = Box<dyn Fn(&mut WorkflowPlanV1)>;
type JournalChange = Box<dyn Fn(&mut WorkflowJournalV1)>;

#[test]
fn journal_decode_refusal_survives_retired_and_equal_foreign_scopes() {
    let mut journal = WorkflowJournalV1::new(&plan(), &binding(), 7).expect("journal");
    journal.sequence = 1;
    let bytes = journal.encode_record().expect("canonical stored record");
    let limits =
        |allocation| norito::DecodeLimits::new(usize::MAX, usize::MAX, usize::MAX, allocation, 64);
    let (decoded, usage) = norito::core::with_decode_limits_measured(limits(usize::MAX), || {
        WorkflowJournalV1::decode_record(&bytes)
    });
    assert_eq!(decoded.expect("measured read"), journal);
    assert!(usage.total_allocated_bytes() > 0);
    for allocation in [0, usage.total_allocated_bytes() - 1] {
        let error = norito::with_decode_limits_scope(limits(allocation), || {
            WorkflowJournalV1::decode_record(&bytes).expect_err("original allocation refusal")
        });
        assert_eq!(error.code, WorkflowErrorCode::LocalResourceUnavailable);
        assert!(error.is_resumable());
        assert!(
            error.progress.is_none(),
            "unread state supplies no progress"
        );
        norito::with_decode_limits_scope(limits(allocation), || {
            assert_eq!(error.code, WorkflowErrorCode::LocalResourceUnavailable);
            assert!(
                error.is_resumable(),
                "a later equal scope changes no verdict"
            );
        });
        assert_eq!(WorkflowJournalV1::decode_record(&bytes).unwrap(), journal);
    }
    let mut malformed = bytes;
    malformed.push(0);
    let error = WorkflowJournalV1::decode_record(&malformed).expect_err("trailing original bytes");
    assert_eq!(error.code, WorkflowErrorCode::StorageCorrupted);
    assert!(!error.is_resumable());
}

#[test]
fn cumulative_round_transcripts_must_fit_before_the_plan_starts() {
    let mut value = plan();
    value.steps = (0..17)
        .map(|index| {
            StepDescriptorV1::offchain_round(
                format!("round-{index}"),
                fixture_digest(&format!("round-{index}")),
                true,
                1,
                0,
            )
        })
        .collect();
    assert!(value.journal_bytes_bound() > MAX_WORKFLOW_JOURNAL_BYTES_V1);
    assert_eq!(
        value.validate().expect_err("unstoreable plan").code,
        WorkflowErrorCode::ResourceLimitExceeded
    );
    assert!(WorkflowJournalV1::new(&value, &binding(), 0).is_err());
    for step in &mut value.steps {
        step.max_transcript_bytes = 1;
    }
    assert!(value.journal_bytes_bound() <= MAX_WORKFLOW_JOURNAL_BYTES_V1);
    value.validate().expect("bounded transcripts fit");
    WorkflowJournalV1::new(&value, &binding(), 0).expect("admissible journal");
}

pub(super) fn binding() -> WorkflowBindingV1 {
    WorkflowBindingV1 {
        network: "fixture-network".to_owned(),
        authority: "fixture-authority".to_owned(),
    }
}

pub(super) fn plan() -> WorkflowPlanV1 {
    WorkflowPlanV1 {
        kind: WorkflowKindV1::Dkg,
        instance: "vector".to_owned(),
        driver: DriverIdentityV1 {
            id: "fixture-driver".to_owned(),
            schema_version: 1,
        },
        request_context_digest: fixture_digest("context:vector"),
        steps: vec![
            StepDescriptorV1::transaction("register", fixture_digest("intent:register"))
                .with_max_transaction_identities(2),
            StepDescriptorV1::offchain_round("deal", fixture_digest("intent:deal"), true, 2, 1),
            StepDescriptorV1::transaction("publish", fixture_digest("intent:publish")),
        ],
    }
}

fn identity(label: &str) -> TransactionIdentityV1 {
    TransactionIdentityV1 {
        signed_transaction_hash: fixture_digest(&format!("signed:{label}")),
        entrypoint_hash: fixture_digest(&format!("entrypoint:{label}")),
    }
}

fn signed(label: &str) -> TransactionInputV1 {
    TransactionInputV1::Signed {
        signed_transaction: format!("signed:{label}").into_bytes(),
        identity: identity(label),
    }
}

fn journal() -> WorkflowJournalV1 {
    let mut journal = WorkflowJournalV1::new(&plan(), &binding(), 1_000_000).expect("journal");
    journal.sequence = 1;
    journal
}

/// Drive step 0 to `pending` with one accepted dispatch.
fn to_pending(journal: &mut WorkflowJournalV1, step: usize, label: &str) {
    for input in [
        TransactionInputV1::OpenAttempt,
        TransactionInputV1::BuildStarted,
        TransactionInputV1::PayloadBuilt {
            payload: format!("payload:{label}").into_bytes(),
        },
        signed(label),
        TransactionInputV1::DispatchIntent {
            retransmission_after_exact_absence: false,
        },
        TransactionInputV1::DispatchAccepted,
    ] {
        journal.apply_transaction(step, input).expect("transition");
    }
}

fn participants(names: &[&str]) -> Vec<Digest32> {
    let mut all = names
        .iter()
        .map(|name| fixture_digest(&format!("participant:{name}")))
        .collect::<Vec<_>>();
    all.sort_unstable();
    all
}

fn custody(count: usize) -> Vec<CustodyHandleV1> {
    (0..count)
        .map(|index| CustodyHandleV1 {
            label: format!("share-{index}"),
            reference: format!("custody-ref:{index}").into_bytes(),
        })
        .collect()
}

fn completed_round(journal: &mut WorkflowJournalV1, step: usize) {
    let round_id = round_identity(&journal.id(), u32::try_from(step).expect("index"));
    journal
        .apply_round(step, RoundInputV1::Intent { round_id })
        .expect("intent");
    journal
        .apply_round(
            step,
            RoundInputV1::Completed {
                participants: participants(&["p1", "p2"]),
                transcript: b"transcript:deal".to_vec(),
                custody_handles: custody(1),
            },
        )
        .expect("completed");
}

#[test]
fn plan_validation_rejects_malformed_labels_kinds_and_bounds() {
    assert!(plan().validate().is_ok());
    let cases: Vec<(&str, PlanChange, WorkflowErrorCode)> = vec![
        (
            "empty instance",
            Box::new(|plan| plan.instance.clear()),
            WorkflowErrorCode::InvalidInput,
        ),
        (
            "space in label",
            Box::new(|plan| plan.steps[0].label = "has space".to_owned()),
            WorkflowErrorCode::InvalidInput,
        ),
        (
            "label too long",
            Box::new(|plan| plan.steps[0].label = "x".repeat(65)),
            WorkflowErrorCode::InvalidInput,
        ),
        (
            "driver label",
            Box::new(|plan| plan.driver.id = "bad/driver".to_owned()),
            WorkflowErrorCode::InvalidInput,
        ),
        (
            "no steps",
            Box::new(|plan| plan.steps.clear()),
            WorkflowErrorCode::InvalidInput,
        ),
        (
            "repeated label",
            Box::new(|plan| plan.steps[2].label = "register".to_owned()),
            WorkflowErrorCode::InvalidInput,
        ),
        (
            "reversible transaction",
            Box::new(|plan| plan.steps[0].irreversible = false),
            WorkflowErrorCode::InvalidInput,
        ),
        (
            "zero identities",
            Box::new(|plan| plan.steps[0].max_transaction_identities = 0),
            WorkflowErrorCode::InvalidInput,
        ),
        (
            "too many identities",
            Box::new(|plan| plan.steps[0].max_transaction_identities = 9),
            WorkflowErrorCode::InvalidInput,
        ),
        (
            "transaction with participants",
            Box::new(|plan| plan.steps[0].participants_required = 1),
            WorkflowErrorCode::InvalidInput,
        ),
        (
            "round with identities",
            Box::new(|plan| plan.steps[1].max_transaction_identities = 1),
            WorkflowErrorCode::InvalidInput,
        ),
        (
            "round participant bound",
            Box::new(|plan| {
                plan.steps[1].participants_required =
                    u32::try_from(MAX_ROUND_PARTICIPANTS_V1 + 1).expect("bound");
            }),
            WorkflowErrorCode::InvalidInput,
        ),
        (
            "too many steps",
            Box::new(|plan| {
                plan.steps = (0..=MAX_WORKFLOW_STEPS_V1)
                    .map(|index| {
                        StepDescriptorV1::transaction(format!("s{index}"), fixture_digest("i"))
                    })
                    .collect();
            }),
            WorkflowErrorCode::ResourceLimitExceeded,
        ),
    ];
    for (name, change, code) in cases {
        let mut changed = plan();
        change(&mut changed);
        let error = changed.validate().expect_err(name);
        assert_eq!(error.code, code, "{name}");
    }
    let too_many = WorkflowPlanV1 {
        steps: (0..=MAX_WORKFLOW_STEPS_V1)
            .map(|index| StepDescriptorV1::transaction(format!("s{index}"), fixture_digest("i")))
            .collect(),
        ..plan()
    };
    let bounds = too_many
        .validate()
        .expect_err("bound")
        .bounds
        .expect("bounds");
    assert_eq!(
        (bounds.actual, bounds.maximum),
        (
            MAX_WORKFLOW_STEPS_V1 as u64 + 1,
            MAX_WORKFLOW_STEPS_V1 as u64
        )
    );
}

#[test]
fn workflow_identifier_commits_to_every_bound_field() {
    let base = WorkflowIdentityV1::new(&plan(), &binding())
        .expect("identity")
        .workflow_id()
        .expect("id");
    assert_eq!(
        base,
        WorkflowIdentityV1::new(&plan(), &binding())
            .expect("identity")
            .workflow_id()
            .expect("id"),
        "the identifier is deterministic so a handle can be rebuilt after a restart"
    );
    assert_eq!(base.to_string(), base.to_hex());
    assert_eq!(base.to_hex().len(), 64);

    let mut variants: Vec<(WorkflowPlanV1, WorkflowBindingV1)> = Vec::new();
    let mut changed = plan();
    changed.kind = WorkflowKindV1::ThresholdOpening;
    variants.push((changed, binding()));
    let mut changed = plan();
    changed.instance = "other".to_owned();
    variants.push((changed, binding()));
    let mut changed = plan();
    changed.driver.schema_version = 2;
    variants.push((changed, binding()));
    let mut changed = plan();
    changed.driver.id = "other-driver".to_owned();
    variants.push((changed, binding()));
    let mut changed = plan();
    changed.request_context_digest = fixture_digest("context:other");
    variants.push((changed, binding()));
    let mut changed = plan();
    changed.steps[0].intent_digest = fixture_digest("intent:other");
    variants.push((changed, binding()));
    let mut changed = plan();
    changed.steps[1].participants_required = 3;
    variants.push((changed, binding()));
    let mut changed = plan();
    changed.steps.pop();
    variants.push((changed, binding()));
    variants.push((
        plan(),
        WorkflowBindingV1 {
            network: "other-network".to_owned(),
            ..binding()
        },
    ));
    variants.push((
        plan(),
        WorkflowBindingV1 {
            authority: "other-authority".to_owned(),
            ..binding()
        },
    ));
    let mut seen = vec![base];
    for (plan, binding) in variants {
        let id = WorkflowIdentityV1::new(&plan, &binding)
            .expect("identity")
            .workflow_id()
            .expect("id");
        assert!(
            !seen.contains(&id),
            "every bound field changes the identifier"
        );
        seen.push(id);
    }
    // Canonical account text is not ASCII (I105 uses half-width kana) and is accepted.
    assert!(
        WorkflowIdentityV1::new(
            &plan(),
            &WorkflowBindingV1 {
                authority: "sora\u{ff72}\u{ff9b}\u{ff8a}9".to_owned(),
                ..binding()
            },
        )
        .is_ok()
    );
    for bad in ["", "has space", "line\nbreak", &"n".repeat(257)] {
        let error = WorkflowIdentityV1::new(
            &plan(),
            &WorkflowBindingV1 {
                network: bad.to_owned(),
                ..binding()
            },
        )
        .expect_err("binding");
        assert_eq!(error.code, WorkflowErrorCode::InvalidInput);
    }
    let request = WorkflowRequest {
        instance: "vector".to_owned(),
        driver: plan().driver,
        request_context_digest: plan().request_context_digest,
        steps: plan().steps,
    };
    assert_eq!(request.into_plan(WorkflowKindV1::Dkg), plan());
}

#[test]
fn transaction_reducer_persists_identity_before_dispatch_and_drops_bytes_when_closed() {
    let mut operation = TransactionOperationV1::default();
    assert_eq!(operation.state, TransactionStateV1::Planned);
    assert!(operation.current().is_none());
    assert!(operation.validate(2).is_ok());

    operation
        .apply(TransactionInputV1::OpenAttempt, 2)
        .expect("open");
    operation
        .apply(TransactionInputV1::BuildStarted, 2)
        .expect("proving");
    // A failed build returns the slot to `prepared`; nothing was computed.
    operation
        .apply(TransactionInputV1::BuildFailed, 2)
        .expect("failed");
    assert_eq!(operation.state, TransactionStateV1::Prepared);
    operation
        .apply(TransactionInputV1::BuildStarted, 2)
        .expect("proving");
    operation
        .apply(
            TransactionInputV1::PayloadBuilt {
                payload: b"payload:0#1".to_vec(),
            },
            2,
        )
        .expect("built");
    assert_eq!(
        operation.unsigned_payload.as_deref(),
        Some(&b"payload:0#1"[..])
    );
    assert!(operation.current_identity().is_none());
    operation.apply(signed("0#1"), 2).expect("signed");
    assert!(
        operation.unsigned_payload.is_none(),
        "replaced by signed bytes"
    );
    assert_eq!(operation.current_identity(), Some(identity("0#1")));
    assert!(operation.validate(2).is_ok());

    // The dispatch ordinal is recorded by the intent, before any result.
    operation
        .apply(
            TransactionInputV1::DispatchIntent {
                retransmission_after_exact_absence: false,
            },
            2,
        )
        .expect("intent");
    let current = operation.current().expect("slot");
    assert_eq!(
        (current.dispatch_ordinal, current.possible_admissions),
        (1, 0)
    );
    assert_eq!(operation.state, TransactionStateV1::Submitting);
    assert!(operation.validate(2).is_ok());

    operation
        .apply(TransactionInputV1::DispatchAmbiguous, 2)
        .expect("ambiguous");
    assert_eq!(operation.state, TransactionStateV1::OutcomeUnknown);
    assert_eq!(operation.current().expect("slot").possible_admissions, 1);
    // Without authorization nothing but reconciliation is possible.
    for input in [
        TransactionInputV1::OpenAttempt,
        TransactionInputV1::Cancel,
        TransactionInputV1::DispatchIntent {
            retransmission_after_exact_absence: false,
        },
        signed("0#2"),
    ] {
        let before = operation.clone();
        let error = operation.apply(input, 2).expect_err("not while unresolved");
        assert_eq!(error.code, WorkflowErrorCode::InvalidInput);
        assert_eq!(operation, before, "a rejected input changes nothing");
    }
    operation
        .apply(TransactionInputV1::ObservedInPipeline, 2)
        .expect("observed");
    assert_eq!(operation.state, TransactionStateV1::Pending);
    operation
        .apply(
            TransactionInputV1::ReconciledRejected {
                detail: "x".repeat(2_000),
            },
            2,
        )
        .expect("rejected");
    assert_eq!(operation.state, TransactionStateV1::Rejected);
    assert!(
        operation.signed_transaction.is_none(),
        "closed bytes are dropped"
    );
    let evidence = operation
        .current()
        .expect("slot")
        .evidence
        .clone()
        .expect("evidence");
    assert_eq!(evidence.kind, AttemptEvidenceKindV1::LedgerRejected);
    assert_eq!(evidence.detail.len(), 512, "diagnostics are bounded");
    assert!(operation.validate(2).is_ok());
    assert!(!operation.identities_exhausted(2));
    assert!(operation.identities_exhausted(1));

    // A replacement identity is a new slot and must be a new transaction.
    operation
        .apply(TransactionInputV1::OpenAttempt, 2)
        .expect("replacement");
    operation
        .apply(TransactionInputV1::BuildStarted, 2)
        .expect("proving");
    operation
        .apply(
            TransactionInputV1::PayloadBuilt {
                payload: b"payload:0#2".to_vec(),
            },
            2,
        )
        .expect("built");
    let before = operation.clone();
    let error = operation
        .apply(signed("0#1"), 2)
        .expect_err("same identity");
    assert_eq!(error.code, WorkflowErrorCode::BindingMismatch);
    assert_eq!(operation, before);
    operation.apply(signed("0#2"), 2).expect("signed");
    assert_eq!(operation.attempts.len(), 2);
    assert_eq!(operation.attempts[0].identity, Some(identity("0#1")));
    assert!(operation.validate(2).is_ok());
    // No third identity: the bound is part of the plan.
    operation
        .apply(
            TransactionInputV1::DispatchIntent {
                retransmission_after_exact_absence: false,
            },
            2,
        )
        .expect("intent");
    operation
        .apply(
            TransactionInputV1::DispatchRefused {
                detail: "refused".to_owned(),
            },
            2,
        )
        .expect("refused");
    assert_eq!(operation.state, TransactionStateV1::Rejected);
    assert_eq!(
        operation
            .current()
            .expect("slot")
            .evidence
            .as_ref()
            .map(|e| e.kind),
        Some(AttemptEvidenceKindV1::AdmissionRefused)
    );
    assert!(operation.identities_exhausted(2));
    assert!(operation.apply(TransactionInputV1::OpenAttempt, 2).is_err());
    assert!(operation.validate(2).is_ok());
}

#[test]
fn cancellation_drops_bytes_when_the_in_flight_dispatch_admitted_nothing() {
    for outcome in [
        TransactionInputV1::DispatchNotAdmitted,
        TransactionInputV1::DispatchRefused {
            detail: "refused".to_owned(),
        },
    ] {
        let mut journal = journal();
        for input in [
            TransactionInputV1::OpenAttempt,
            TransactionInputV1::BuildStarted,
            TransactionInputV1::PayloadBuilt {
                payload: b"payload:0#1".to_vec(),
            },
            signed("0#1"),
            TransactionInputV1::DispatchIntent {
                retransmission_after_exact_absence: false,
            },
        ] {
            journal.apply_transaction(0, input).expect("transition");
        }
        assert!(journal.request_cancel());
        assert_eq!(journal.status, WorkflowStatusV1::Cancelling);
        journal.apply_transaction(0, outcome).expect("response");
        assert_eq!(journal.status, WorkflowStatusV1::Cancelled);
        let bytes = journal.encode_record().expect("record");
        let retained = WorkflowJournalV1::decode_record(&bytes).expect("read record");
        let operation = retained.steps[0].transaction.as_ref().expect("transaction");
        assert!(operation.unsigned_payload.is_none());
        assert!(operation.signed_transaction.is_none());
        assert_eq!(operation.current().expect("attempt").possible_admissions, 0);
        assert!(
            !bytes
                .windows(b"signed:0#1".len())
                .any(|window| window == b"signed:0#1")
        );
    }
}

#[test]
fn a_refusal_after_a_possible_admission_keeps_the_identity_unknown() {
    let mut journal = journal();
    for input in [
        TransactionInputV1::OpenAttempt,
        TransactionInputV1::BuildStarted,
        TransactionInputV1::PayloadBuilt {
            payload: b"payload:0#1".to_vec(),
        },
        signed("0#1"),
        TransactionInputV1::DispatchIntent {
            retransmission_after_exact_absence: false,
        },
        // Backpressure on the first dispatch: provably not admitted, bytes are kept.
        TransactionInputV1::DispatchNotAdmitted,
    ] {
        journal.apply_transaction(0, input).expect("transition");
    }
    let operation = journal.steps[0].transaction.clone().expect("operation");
    assert_eq!(operation.state, TransactionStateV1::Signed);
    assert_eq!(operation.current().expect("slot").dispatch_ordinal, 0);
    assert!(operation.signed_transaction.is_some());

    for input in [
        TransactionInputV1::DispatchIntent {
            retransmission_after_exact_absence: false,
        },
        TransactionInputV1::DispatchInterrupted,
    ] {
        journal.apply_transaction(0, input).expect("transition");
    }
    // Retransmission needs explicit authorization.
    assert!(
        journal
            .apply_transaction(
                0,
                TransactionInputV1::DispatchIntent {
                    retransmission_after_exact_absence: false
                }
            )
            .is_err()
    );
    journal
        .apply_transaction(
            0,
            TransactionInputV1::DispatchIntent {
                retransmission_after_exact_absence: true,
            },
        )
        .expect("authorized retransmission");
    // The retransmission is refused, but the interrupted dispatch may have been admitted.
    journal
        .apply_transaction(
            0,
            TransactionInputV1::DispatchRefused {
                detail: "already expired".to_owned(),
            },
        )
        .expect("refused");
    let operation = journal.steps[0].transaction.clone().expect("operation");
    assert_eq!(operation.state, TransactionStateV1::OutcomeUnknown);
    assert!(operation.current().expect("slot").evidence.is_none());
    assert!(operation.signed_transaction.is_some());
    assert_eq!(journal.status, WorkflowStatusV1::InProgress);
    assert!(journal.validate().is_ok());

    // The dispatch bound is separate from the identity bound.
    let mut bounded = operation;
    assert_eq!(bounded.current().expect("slot").dispatch_ordinal, 2);
    for _ in 3..MAX_DISPATCHES_PER_IDENTITY_V1 {
        bounded
            .apply(
                TransactionInputV1::DispatchIntent {
                    retransmission_after_exact_absence: true,
                },
                2,
            )
            .expect("intent");
        bounded
            .apply(TransactionInputV1::DispatchAmbiguous, 2)
            .expect("ambiguous");
    }
    assert_eq!(
        bounded.current().expect("slot").dispatch_ordinal,
        MAX_DISPATCHES_PER_IDENTITY_V1 - 1
    );
    bounded
        .apply(
            TransactionInputV1::DispatchIntent {
                retransmission_after_exact_absence: true,
            },
            2,
        )
        .expect("last dispatch");
    bounded
        .apply(TransactionInputV1::DispatchAmbiguous, 2)
        .expect("ambiguous");
    assert!(
        bounded
            .apply(
                TransactionInputV1::DispatchIntent {
                    retransmission_after_exact_absence: true
                },
                2
            )
            .is_err(),
        "no dispatch beyond the bound"
    );
}

#[test]
fn transaction_reducer_bounds_retained_bytes() {
    let mut operation = TransactionOperationV1::new();
    operation
        .apply(TransactionInputV1::OpenAttempt, 1)
        .expect("open");
    operation
        .apply(TransactionInputV1::BuildStarted, 1)
        .expect("proving");
    let before = operation.clone();
    let error = operation
        .apply(
            TransactionInputV1::PayloadBuilt {
                payload: Vec::new(),
            },
            1,
        )
        .expect_err("empty");
    assert_eq!(error.code, WorkflowErrorCode::InvalidInput);
    let error = operation
        .apply(
            TransactionInputV1::PayloadBuilt {
                payload: vec![0; MAX_WORKFLOW_TRANSACTION_BYTES_V1 + 1],
            },
            1,
        )
        .expect_err("oversized");
    assert_eq!(error.code, WorkflowErrorCode::ResourceLimitExceeded);
    let bounds = error.bounds.expect("bounds");
    assert_eq!(
        (bounds.actual, bounds.maximum),
        (
            MAX_WORKFLOW_TRANSACTION_BYTES_V1 as u64 + 1,
            MAX_WORKFLOW_TRANSACTION_BYTES_V1 as u64
        )
    );
    assert_eq!(operation, before);
    operation
        .apply(
            TransactionInputV1::PayloadBuilt {
                payload: vec![7; MAX_WORKFLOW_TRANSACTION_BYTES_V1],
            },
            1,
        )
        .expect("exactly at the bound");
    assert!(operation.validate(1).is_ok());
}

#[test]
fn round_reducer_requires_canonical_growing_participants_and_exact_custody() {
    let descriptor = plan().steps[1].clone();
    let round_id = fixture_digest("round");
    let mut round = RoundRecordV1::default();
    assert!(round.validate(&descriptor, &round_id).is_ok());
    // Nothing but the intent is valid in `planned`.
    assert!(
        round
            .apply(
                RoundInputV1::Waiting {
                    participants: Vec::new()
                },
                &descriptor,
                false
            )
            .is_err()
    );
    round
        .apply(RoundInputV1::Intent { round_id }, &descriptor, false)
        .expect("intent");
    assert_eq!(round.state, RoundStateV1::RoundStarted);
    round
        .apply(
            RoundInputV1::Waiting {
                participants: participants(&["p1"]),
            },
            &descriptor,
            false,
        )
        .expect("waiting");
    assert!(round.validate(&descriptor, &round_id).is_ok());

    let mut reordered = participants(&["p1", "p2"]);
    reordered.reverse();
    let duplicated = vec![participants(&["p1"])[0]; 2];
    let complete = |participants: Vec<Digest32>, custody_count: usize, transcript: Vec<u8>| {
        RoundInputV1::Completed {
            participants,
            transcript,
            custody_handles: custody(custody_count),
        }
    };
    let cases = [
        (
            complete(reordered, 1, b"t".to_vec()),
            WorkflowErrorCode::NonCanonicalEncoding,
        ),
        (
            complete(duplicated, 1, b"t".to_vec()),
            WorkflowErrorCode::NonCanonicalEncoding,
        ),
        // A participant recorded earlier disappeared: a withdrawal must be a failure.
        (
            complete(participants(&["p2", "p3"]), 1, b"t".to_vec()),
            WorkflowErrorCode::BindingMismatch,
        ),
        (
            complete(participants(&["p1"]), 1, b"t".to_vec()),
            WorkflowErrorCode::InvalidInput,
        ),
        (
            complete(participants(&["p1", "p2"]), 1, Vec::new()),
            WorkflowErrorCode::InvalidInput,
        ),
        (
            complete(
                participants(&["p1", "p2"]),
                1,
                vec![0; MAX_ROUND_TRANSCRIPT_BYTES_V1 + 1],
            ),
            WorkflowErrorCode::ResourceLimitExceeded,
        ),
        // Missing custody is a local resource problem, never invented.
        (
            complete(participants(&["p1", "p2"]), 0, b"t".to_vec()),
            WorkflowErrorCode::LocalResourceUnavailable,
        ),
        (
            complete(participants(&["p1", "p2"]), 2, b"t".to_vec()),
            WorkflowErrorCode::InvalidInput,
        ),
    ];
    for (input, code) in cases {
        let before = round.clone();
        let error = round
            .apply(input, &descriptor, false)
            .expect_err("rejected");
        assert_eq!(error.code, code);
        assert_eq!(round, before, "a rejected report changes nothing");
    }
    let oversized_reference = RoundInputV1::Completed {
        participants: participants(&["p1", "p2"]),
        transcript: b"t".to_vec(),
        custody_handles: vec![CustodyHandleV1 {
            label: "share-0".to_owned(),
            reference: vec![1; MAX_CUSTODY_REFERENCE_BYTES_V1 + 1],
        }],
    };
    assert_eq!(
        round
            .apply(oversized_reference, &descriptor, false)
            .expect_err("reference bound")
            .code,
        WorkflowErrorCode::ResourceLimitExceeded
    );
    // `round_not_started` exists only for a cancelling workflow and only before waiting.
    assert!(
        round
            .apply(RoundInputV1::NotStarted, &descriptor, true)
            .is_err()
    );

    round
        .apply(
            complete(participants(&["p1", "p2", "p3"]), 1, b"transcript".to_vec()),
            &descriptor,
            false,
        )
        .expect("completed");
    assert_eq!(round.state, RoundStateV1::RoundCompleted);
    assert_eq!(
        round.transcript_digest,
        Some(transcript_digest(&round_id, b"transcript"))
    );
    assert!(round.validate(&descriptor, &round_id).is_ok());
    assert!(
        round
            .validate(&descriptor, &fixture_digest("other"))
            .is_err()
    );
    assert!(
        round
            .apply(
                RoundInputV1::Failed {
                    code: WorkflowErrorCode::Expired
                },
                &descriptor,
                false
            )
            .is_err(),
        "a completed round is terminal"
    );

    let mut never_started = RoundRecordV1::new();
    assert!(
        never_started
            .apply(RoundInputV1::Intent { round_id }, &descriptor, true)
            .is_err(),
        "cancellation prevents the first start intent"
    );
    never_started
        .apply(RoundInputV1::Intent { round_id }, &descriptor, false)
        .expect("intent");
    assert!(
        never_started
            .apply(RoundInputV1::NotStarted, &descriptor, false)
            .is_err()
    );
    never_started
        .apply(RoundInputV1::NotStarted, &descriptor, true)
        .expect("only while cancelling");
    assert_eq!(never_started, RoundRecordV1::new());
}

#[test]
fn record_round_trips_and_every_damage_is_detected() {
    let mut journal = journal();
    to_pending(&mut journal, 0, "0#1");
    let record = journal.encode_record().expect("record");
    assert_eq!(
        WorkflowJournalV1::decode_record(&record).expect("decode"),
        journal
    );
    assert_ne!(record_digest(&record), journal.digest().expect("digest"));

    // The digest covers the sequence and the version.
    let mut later = journal.clone();
    later.sequence += 1;
    assert_ne!(
        later.digest().expect("digest"),
        journal.digest().expect("digest")
    );

    // Every single-bit flip, every truncation and any trailing byte is detected.
    for index in 0..record.len() {
        let mut damaged = record.clone();
        damaged[index] ^= 0x01;
        let error =
            WorkflowJournalV1::decode_record(&damaged).expect_err("a flipped bit must be detected");
        assert_eq!(
            error.code,
            WorkflowErrorCode::StorageCorrupted,
            "byte {index}"
        );
        assert!(
            error.progress.is_none(),
            "no snapshot from corrupted storage"
        );
    }
    for length in [0, 1, record.len() / 2, record.len() - 1] {
        assert_eq!(
            WorkflowJournalV1::decode_record(&record[..length])
                .expect_err("truncated")
                .code,
            WorkflowErrorCode::StorageCorrupted
        );
    }
    let mut trailing = record.clone();
    trailing.push(0);
    assert_eq!(
        WorkflowJournalV1::decode_record(&trailing)
            .expect_err("trailing byte")
            .code,
        WorkflowErrorCode::StorageCorrupted
    );
    assert_eq!(
        WorkflowJournalV1::decode_record(&vec![0; MAX_WORKFLOW_JOURNAL_BYTES_V1 + 1])
            .expect_err("oversized")
            .code,
        WorkflowErrorCode::StorageCorrupted
    );
}

/// Encode a record without the invariant check, as damaged or hostile storage could hold it.
pub(super) fn encode_unchecked(journal: &WorkflowJournalV1) -> Vec<u8> {
    norito::encode_canonical(&WorkflowJournalRecordV1 {
        digest: journal.digest().expect("digest"),
        journal: journal.clone(),
    })
    .expect("record")
}

#[test]
fn a_well_formed_record_that_violates_an_invariant_is_corrupted() {
    let mut base = journal();
    to_pending(&mut base, 0, "0#1");
    assert!(WorkflowJournalV1::decode_record(&encode_unchecked(&base)).is_ok());

    let damages: Vec<(&str, JournalChange)> = vec![
        ("zero sequence", Box::new(|journal| journal.sequence = 0)),
        ("unknown version", Box::new(|journal| journal.version = 2)),
        (
            "status without steps",
            Box::new(|journal| journal.status = WorkflowStatusV1::Completed),
        ),
        (
            "failure without failed status",
            Box::new(|journal| journal.failure_code = Some(WorkflowErrorCode::Rejected)),
        ),
        (
            "cancelled while unresolved",
            Box::new(|journal| {
                journal.cancel_requested = true;
                journal.status = WorkflowStatusV1::Cancelled;
            }),
        ),
        (
            "cancelled step in a running workflow",
            Box::new(|journal| {
                let operation = journal.steps[2].transaction.as_mut().expect("operation");
                operation.state = TransactionStateV1::CancelledBeforeSubmission;
            }),
        ),
        (
            "foreign workflow identifier",
            Box::new(|journal| journal.workflow_id = fixture_digest("other")),
        ),
        (
            "changed plan",
            Box::new(|journal| journal.steps[2].descriptor.label = "other".to_owned()),
        ),
        (
            "later step progressed first",
            Box::new(|journal| {
                journal.steps[2]
                    .transaction
                    .as_mut()
                    .expect("operation")
                    .apply(TransactionInputV1::OpenAttempt, 1)
                    .expect("open");
            }),
        ),
        (
            "pending without signed bytes",
            Box::new(|journal| {
                journal.steps[0]
                    .transaction
                    .as_mut()
                    .expect("operation")
                    .signed_transaction = None;
            }),
        ),
        (
            "pending without possible admission",
            Box::new(|journal| {
                journal.steps[0]
                    .transaction
                    .as_mut()
                    .expect("operation")
                    .attempts[0]
                    .possible_admissions = 0;
            }),
        ),
        (
            "finalized without evidence",
            Box::new(|journal| {
                let operation = journal.steps[0].transaction.as_mut().expect("operation");
                operation.state = TransactionStateV1::Finalized;
                operation.signed_transaction = None;
            }),
        ),
        (
            "record of the wrong kind",
            Box::new(|journal| {
                journal.steps[1].transaction = Some(TransactionOperationV1::new());
            }),
        ),
        (
            "round with a foreign identity",
            Box::new(|journal| {
                let round = journal.steps[1].round.as_mut().expect("round");
                round.round_id = Some(fixture_digest("foreign"));
            }),
        ),
    ];
    for (name, damage) in damages {
        let mut broken = base.clone();
        damage(&mut broken);
        let error = WorkflowJournalV1::decode_record(&encode_unchecked(&broken)).expect_err(name);
        assert_eq!(error.code, WorkflowErrorCode::StorageCorrupted, "{name}");
        // The engine never stores such a journal either.
        if broken.sequence != 0 {
            assert_eq!(
                broken.encode_record().expect_err(name).code,
                WorkflowErrorCode::InvalidInput,
                "{name}"
            );
        }
    }
    let mut zero = base.clone();
    zero.sequence = 0;
    assert!(zero.encode_record().is_err());
    // A digest that does not match is corruption even when the journal is valid.
    let record = WorkflowJournalRecordV1 {
        digest: [0; 32],
        journal: base,
    };
    assert_eq!(
        WorkflowJournalV1::decode_record(&norito::encode_canonical(&record).expect("record"))
            .expect_err("digest")
            .code,
        WorkflowErrorCode::StorageCorrupted
    );
}

#[test]
fn cancellation_never_rolls_back_and_separates_unresolved_from_confirmed() {
    // A cancelled step exists only in a cancelled workflow.
    let mut inconsistent = journal();
    inconsistent.steps[0]
        .transaction
        .as_mut()
        .expect("operation")
        .state = TransactionStateV1::CancelledBeforeSubmission;
    assert_eq!(
        inconsistent
            .validate()
            .expect_err("cancelled step invariant")
            .detail,
        "a step is cancelled while the workflow is not"
    );
    // A step that is still planned can be cancelled: it never opened an identity slot.
    let mut untouched = journal();
    assert!(untouched.request_cancel());
    assert_eq!(untouched.steps[0].state_id(), "cancelled_before_submission");
    assert!(
        untouched.steps[0]
            .transaction
            .as_ref()
            .expect("operation")
            .attempts
            .is_empty()
    );
    assert!(untouched.validate().is_ok());
    assert!(WorkflowJournalV1::decode_record(&untouched.encode_record().expect("record")).is_ok());

    // Before any dispatch: cancelled, the step is cancelled before submission.
    let mut early = journal();
    early
        .apply_transaction(0, TransactionInputV1::OpenAttempt)
        .expect("open");
    assert!(early.request_cancel());
    assert_eq!(early.status, WorkflowStatusV1::Cancelled);
    assert_eq!(early.steps[0].state_id(), "cancelled_before_submission");
    assert!(!early.request_cancel(), "cancellation is idempotent");
    assert!(early.validate().is_ok());
    let progress = early.progress();
    assert!(!progress.is_partially_complete());
    assert_eq!(progress.partial_completion.not_started_steps, [0, 1, 2]);

    // While a transaction may still commit: cancelling, nothing changes in the step.
    let mut flying = journal();
    to_pending(&mut flying, 0, "0#1");
    assert!(flying.request_cancel());
    assert_eq!(flying.status, WorkflowStatusV1::Cancelling);
    assert_eq!(flying.steps[0].state_id(), "pending");
    assert!(flying.validate().is_ok());
    let progress = flying.progress();
    assert!(progress.is_partially_complete());
    assert_eq!(progress.partial_completion.unresolved_steps, [0]);
    assert!(progress.partial_completion.confirmed_steps.is_empty());
    // It then commits: the workflow is cancelled with that step confirmed and not undone.
    flying
        .apply_transaction(
            0,
            TransactionInputV1::ReconciledApplied {
                block_height: Some(9),
            },
        )
        .expect("applied");
    assert_eq!(flying.status, WorkflowStatusV1::Cancelled);
    let progress = flying.progress();
    assert_eq!(progress.partial_completion.confirmed_steps, [0]);
    assert_eq!(progress.partial_completion.irreversible_steps, [0]);
    assert!(progress.partial_completion.unresolved_steps.is_empty());
    assert_eq!(progress.partial_completion.not_started_steps, [1, 2]);
    assert!(progress.partial_completion.rolled_back_steps.is_empty());
    assert_eq!(progress.atomicity, "per_transaction_only");
    assert!(flying.validate().is_ok());

    // After irreversible progress: later cancellation keeps every confirmed step.
    let mut late = journal();
    to_pending(&mut late, 0, "0#1");
    late.apply_transaction(
        0,
        TransactionInputV1::ReconciledApplied { block_height: None },
    )
    .expect("applied");
    completed_round(&mut late, 1);
    assert_eq!(late.current_step(), Some(2));
    assert!(late.request_cancel());
    assert_eq!(late.status, WorkflowStatusV1::Cancelled);
    let progress = late.progress();
    assert_eq!(progress.partial_completion.confirmed_steps, [0, 1]);
    assert_eq!(progress.partial_completion.irreversible_steps, [0, 1]);
    assert_eq!(progress.steps[1].participants_received, 2);
    assert_eq!(progress.steps[1].custody_handles, 1);
    assert_eq!(progress.steps[2].state, "cancelled_before_submission");
    assert!(late.validate().is_ok());

    // An unresolved round is cancelling too.
    let mut round = journal();
    to_pending(&mut round, 0, "0#1");
    round
        .apply_transaction(
            0,
            TransactionInputV1::ReconciledApplied { block_height: None },
        )
        .expect("applied");
    let round_id = round_identity(&round.id(), 1);
    round
        .apply_round(1, RoundInputV1::Intent { round_id })
        .expect("intent");
    assert!(round.request_cancel());
    assert_eq!(round.status, WorkflowStatusV1::Cancelling);
    round
        .apply_round(1, RoundInputV1::NotStarted)
        .expect("recovered as never started");
    assert_eq!(round.status, WorkflowStatusV1::Cancelled);
    assert_eq!(round.steps[1].state_id(), "planned");
    assert!(round.validate().is_ok());

    // The last step commits while cancelling: every step is done, the workflow completed.
    let mut last = journal();
    to_pending(&mut last, 0, "0#1");
    last.apply_transaction(
        0,
        TransactionInputV1::ReconciledApplied { block_height: None },
    )
    .expect("applied");
    completed_round(&mut last, 1);
    to_pending(&mut last, 2, "2#1");
    assert!(last.request_cancel());
    last.apply_transaction(
        2,
        TransactionInputV1::ReconciledApplied { block_height: None },
    )
    .expect("applied");
    assert_eq!(last.status, WorkflowStatusV1::Completed);
    assert!(!last.progress().is_partially_complete());
    assert!(last.validate().is_ok());
    assert!(
        !last.request_cancel(),
        "a completed workflow cannot be cancelled"
    );
}

#[test]
fn a_closed_identity_fails_the_workflow_only_when_none_remain() {
    let mut journal = journal();
    to_pending(&mut journal, 0, "0#1");
    journal
        .apply_transaction(0, TransactionInputV1::ReconciledExpired)
        .expect("expired");
    // Step 0 allows two identities: still in progress, the decision is the caller's.
    assert_eq!(journal.status, WorkflowStatusV1::InProgress);
    assert_eq!(journal.progress().partial_completion.failed_steps, [0]);
    assert!(journal.validate().is_ok());
    for input in [
        TransactionInputV1::OpenAttempt,
        TransactionInputV1::BuildStarted,
        TransactionInputV1::PayloadBuilt {
            payload: b"payload:0#2".to_vec(),
        },
        signed("0#2"),
        TransactionInputV1::DispatchIntent {
            retransmission_after_exact_absence: false,
        },
        TransactionInputV1::DispatchAccepted,
        TransactionInputV1::ReconciledExpired,
    ] {
        journal.apply_transaction(0, input).expect("transition");
    }
    assert_eq!(journal.status, WorkflowStatusV1::Failed);
    assert_eq!(journal.failure_code, Some(WorkflowErrorCode::Expired));
    assert_eq!(journal.failure_step, Some(0));
    assert!(journal.validate().is_ok());
    let progress = journal.progress();
    assert_eq!(progress.failure_code, Some(WorkflowErrorCode::Expired));
    assert_eq!(progress.steps[0].identities.len(), 2);
    assert!(!journal.request_cancel(), "a failed workflow is terminal");

    // A failed round fails the workflow with the driver's code; earlier steps stay confirmed.
    let mut round = self::journal();
    to_pending(&mut round, 0, "0#1");
    round
        .apply_transaction(
            0,
            TransactionInputV1::ReconciledApplied { block_height: None },
        )
        .expect("applied");
    let round_id = round_identity(&round.id(), 1);
    round
        .apply_round(1, RoundInputV1::Intent { round_id })
        .expect("intent");
    round
        .apply_round(
            1,
            RoundInputV1::Failed {
                code: WorkflowErrorCode::AuthorizationDenied,
            },
        )
        .expect("failed");
    assert_eq!(round.status, WorkflowStatusV1::Failed);
    assert_eq!(
        round.failure_code,
        Some(WorkflowErrorCode::AuthorizationDenied)
    );
    let progress = round.progress();
    assert!(progress.is_partially_complete());
    assert_eq!(progress.partial_completion.confirmed_steps, [0]);
    assert_eq!(progress.partial_completion.failed_steps, [1]);
    assert!(round.validate().is_ok());
    // Inputs for a step of another kind or outside the plan are rejected.
    assert!(round.apply_round(0, RoundInputV1::NotStarted).is_err());
    assert!(
        round
            .apply_transaction(1, TransactionInputV1::OpenAttempt)
            .is_err()
    );
    assert!(
        round
            .apply_transaction(9, TransactionInputV1::OpenAttempt)
            .is_err()
    );
}

#[test]
fn progress_json_states_partial_completion_and_never_a_rollback() {
    let mut journal = journal();
    to_pending(&mut journal, 0, "0#1");
    let rendered = journal.progress().to_json();
    let root = rendered.as_object().expect("object");
    assert_eq!(
        root.get("atomicity").and_then(Value::as_str),
        Some("per_transaction_only")
    );
    assert_eq!(
        root.get("status").and_then(Value::as_str),
        Some("in_progress")
    );
    assert_eq!(
        root.get("partially_complete").and_then(Value::as_bool),
        Some(true)
    );
    let partial = root
        .get("partial_completion")
        .and_then(Value::as_object)
        .expect("partial completion");
    for (key, expected) in [
        ("confirmed_steps", vec![]),
        ("irreversible_steps", vec![]),
        ("unresolved_steps", vec![0_u64]),
        ("failed_steps", vec![]),
        ("not_started_steps", vec![1, 2]),
        ("rolled_back_steps", vec![]),
    ] {
        let actual = partial
            .get(key)
            .and_then(Value::as_array)
            .expect(key)
            .iter()
            .map(|value| value.as_u64().expect("index"))
            .collect::<Vec<_>>();
        assert_eq!(actual, expected, "{key}");
    }
    let step = root
        .get("steps")
        .and_then(Value::as_array)
        .expect("steps")
        .first()
        .and_then(Value::as_object)
        .expect("step");
    assert_eq!(step.get("state").and_then(Value::as_str), Some("pending"));
    let slot = step
        .get("identities")
        .and_then(Value::as_array)
        .expect("identities")
        .first()
        .and_then(Value::as_object)
        .expect("identity");
    assert_eq!(
        slot.get("signed_transaction_hash").and_then(Value::as_str),
        Some(hex::encode(identity("0#1").signed_transaction_hash).as_str())
    );
    assert_eq!(slot.get("dispatches").and_then(Value::as_u64), Some(1));
    assert_eq!(journal.plan(), plan());
    assert_eq!(journal.steps[1].descriptor.kind, StepKindV1::OffchainRound);
}

fn vector_states() -> Vec<(&'static str, WorkflowJournalV1)> {
    let created = journal();
    let mut pending = journal();
    to_pending(&mut pending, 0, "0#1");
    pending.sequence = 7;
    let mut round_done = pending.clone();
    round_done
        .apply_transaction(
            0,
            TransactionInputV1::ReconciledApplied {
                block_height: Some(42),
            },
        )
        .expect("applied");
    completed_round(&mut round_done, 1);
    round_done.sequence = 10;
    let mut cancelling = pending.clone();
    cancelling.request_cancel();
    cancelling.sequence = 8;
    vec![
        ("created", created),
        ("step_0_pending", pending),
        ("step_1_round_completed", round_done),
        ("cancelling_while_pending", cancelling),
    ]
}

// Test-only semantic inputs accompany the binary fixture for independent SDK ports.
macro_rules! vector_object {
    ({$($key:literal : $value:expr),* $(,)?}) => {{
        let mut map = norito::json::Map::new();
        $(map.insert($key.to_owned(), norito::json::to_value(&$value).expect("fixture value"));)*
        Value::Object(map)
    }};
}

fn vector_step(step: &StepDescriptorV1) -> Value {
    vector_object!({
        "label": step.label,
        "kind": step.kind.id(),
        "intent_digest": hex::encode(step.intent_digest),
        "irreversible": step.irreversible,
        "max_transaction_identities": step.max_transaction_identities,
        "participants_required": step.participants_required,
        "custody_handles_required": step.custody_handles_required,
        "max_transcript_bytes": step.max_transcript_bytes,
    })
}

fn vector_identity(identity: &WorkflowIdentityV1) -> Value {
    vector_object!({
        "kind": identity.kind.id(),
        "network": identity.network,
        "authority": identity.authority,
        "instance": identity.instance,
        "driver": vector_object!({
            "id": identity.driver.id,
            "schema_version": identity.driver.schema_version,
        }),
        "request_context_digest": hex::encode(identity.request_context_digest),
        "plan_digest": hex::encode(identity.plan_digest),
    })
}

fn vector_journal(journal: &WorkflowJournalV1) -> Value {
    let steps = journal
        .steps
        .iter()
        .map(|step| {
            let transaction = step.transaction.as_ref().map(|operation| {
                let attempts = operation.attempts.iter().map(|attempt| {
                vector_object!({
                    "ordinal": attempt.ordinal,
                    "identity": attempt.identity.map(|identity| vector_object!({
                        "signed_transaction_hash": hex::encode(identity.signed_transaction_hash),
                        "entrypoint_hash": hex::encode(identity.entrypoint_hash),
                    })),
                    "dispatch_ordinal": attempt.dispatch_ordinal,
                    "possible_admissions": attempt.possible_admissions,
                    "evidence": attempt.evidence.as_ref().map(|evidence| vector_object!({
                        "kind": evidence.kind.id(),
                        "block_height": evidence.block_height,
                        "detail": evidence.detail,
                    })),
                })
            }).collect::<Vec<_>>();
                vector_object!({
                    "state": operation.state.id(),
                    "attempts": attempts,
                    "unsigned_payload": operation.unsigned_payload.as_ref().map(hex::encode),
                    "signed_transaction": operation.signed_transaction.as_ref().map(hex::encode),
                })
            });
            let round = step.round.as_ref().map(|round| {
                vector_object!({
                    "state": round.state.id(),
                    "round_id": round.round_id.map(hex::encode),
                    "start_ordinal": round.start_ordinal,
                    "participants": round.participants.iter().map(hex::encode).collect::<Vec<_>>(),
                    "transcript": round.transcript.as_ref().map(hex::encode),
                    "transcript_digest": round.transcript_digest.map(hex::encode),
                    "custody_handles": round.custody_handles.iter().map(|handle| vector_object!({
                        "label": handle.label,
                        "reference": hex::encode(&handle.reference),
                    })).collect::<Vec<_>>(),
                    "failure": round.failure.map(WorkflowErrorCode::id),
                })
            });
            vector_object!({
                "descriptor": vector_step(&step.descriptor),
                "transaction": transaction,
                "round": round,
            })
        })
        .collect::<Vec<_>>();
    vector_object!({
        "version": journal.version,
        "sequence": journal.sequence,
        "workflow_id": hex::encode(journal.workflow_id),
        "identity": vector_identity(&journal.identity),
        "status": journal.status.id(),
        "cancel_requested": journal.cancel_requested,
        "failure_code": journal.failure_code.map(WorkflowErrorCode::id),
        "failure_step": journal.failure_step,
        "created_at_ms": journal.created_at_ms,
        "updated_at_ms": journal.updated_at_ms,
        "steps": steps,
    })
}

fn rendered_vectors() -> Value {
    fn object(entries: Vec<(&str, Value)>) -> Value {
        let mut map = norito::json::Map::new();
        for (key, value) in entries {
            map.insert(key.to_owned(), value);
        }
        Value::Object(map)
    }
    let text = |value: String| Value::String(value);
    let identity = WorkflowIdentityV1::new(&plan(), &binding()).expect("identity");
    let id = identity.workflow_id().expect("id");
    let records = vector_states()
        .into_iter()
        .map(|(name, journal)| {
            let record = journal.encode_record().expect("record");
            object(vec![
                ("name", text(name.to_owned())),
                ("sequence", Value::from(journal.sequence)),
                (
                    "journal_digest",
                    text(hex::encode(journal.digest().expect("digest"))),
                ),
                ("record_digest", text(hex::encode(record_digest(&record)))),
                ("record_hex", text(hex::encode(&record))),
                ("journal", vector_journal(&journal)),
                (
                    "journal_hex",
                    text(hex::encode(
                        norito::encode_canonical(&journal).expect("journal"),
                    )),
                ),
                ("progress", journal.progress().to_json()),
            ])
        })
        .collect();
    object(vec![
        (
            "schema",
            text("iroha.durable_workflow.vectors.v1".to_owned()),
        ),
        (
            "what",
            text(
                "Canonical Norito records and their complete semantic inputs. All byte arrays are lowercase hexadecimal; optional fields are null when absent. Enum names use state_machine.json. plan_hex, identity_hex and journal_hex are canonical Norito frames, including their headers, before the corresponding digest domain is prepended."
                    .to_owned(),
            ),
        ),
        ("network", text(binding().network)),
        ("authority", text(binding().authority)),
        ("plan", vector_object!({
            "kind": plan().kind.id(),
            "instance": plan().instance,
            "driver": vector_object!({"id": plan().driver.id, "schema_version": plan().driver.schema_version}),
            "request_context_digest": hex::encode(plan().request_context_digest),
            "steps": plan().steps.iter().map(vector_step).collect::<Vec<_>>(),
        })),
        ("plan_hex", text(hex::encode(norito::encode_canonical(&plan()).expect("plan")))),
        ("identity", vector_identity(&identity)),
        ("identity_hex", text(hex::encode(norito::encode_canonical(&identity).expect("identity")))),
        (
            "plan_digest",
            text(hex::encode(plan().digest().expect("digest"))),
        ),
        ("workflow_id", text(id.to_hex())),
        (
            "round_identity_step_1",
            text(hex::encode(round_identity(&id, 1))),
        ),
        (
            "transcript_digest_step_1",
            text(hex::encode(transcript_digest(
                &round_identity(&id, 1),
                b"transcript:deal",
            ))),
        ),
        ("records", Value::Array(records)),
    ])
}

pub(super) fn fixture_path(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/zk/workflow_v1")
        .join(name)
}

pub(super) fn pretty(value: &Value) -> String {
    let mut text = norito::json::to_string_pretty(value).expect("JSON");
    text.push('\n');
    text
}

#[test]
fn canonical_byte_vectors_match_the_tracked_fixture() {
    let tracked = std::fs::read_to_string(fixture_path("vectors.json")).expect("vectors.json");
    assert_eq!(
        tracked,
        pretty(&rendered_vectors()),
        "fixtures/zk/workflow_v1/vectors.json differs from the journal encoding; regenerate with \
         `cargo test -p iroha --lib workflow:: -- --ignored`"
    );
    // The tracked bytes decode to journals whose progress equals the tracked progress.
    let parsed: Value = norito::json::from_str(&tracked).expect("JSON");
    let root = parsed.as_object().expect("root");
    let frame =
        |key| hex::decode(root.get(key).and_then(Value::as_str).expect("frame")).expect("hex");
    let decoded_plan: WorkflowPlanV1 = norito::decode_canonical(&frame("plan_hex")).expect("plan");
    assert_eq!(decoded_plan, plan());
    let decoded_identity: WorkflowIdentityV1 =
        norito::decode_canonical(&frame("identity_hex")).expect("identity");
    assert_eq!(
        decoded_identity,
        WorkflowIdentityV1::new(&plan(), &binding()).expect("identity")
    );
    assert_eq!(
        Some(&vector_identity(&decoded_identity)),
        root.get("identity")
    );
    for record in parsed
        .as_object()
        .and_then(|root| root.get("records"))
        .and_then(Value::as_array)
        .expect("records")
    {
        let record = record.as_object().expect("record");
        let bytes = hex::decode(
            record
                .get("record_hex")
                .and_then(Value::as_str)
                .expect("hex"),
        )
        .expect("hex");
        let journal = WorkflowJournalV1::decode_record(&bytes).expect("tracked record decodes");
        let journal_frame = hex::decode(
            record
                .get("journal_hex")
                .and_then(Value::as_str)
                .expect("journal frame"),
        )
        .expect("hex");
        let decoded_journal: WorkflowJournalV1 =
            norito::decode_canonical(&journal_frame).expect("journal");
        assert_eq!(decoded_journal, journal);
        assert_eq!(Some(&vector_journal(&journal)), record.get("journal"));
        assert_eq!(Some(&journal.progress().to_json()), record.get("progress"));
        assert_eq!(
            Some(hex::encode(record_digest(&bytes)).as_str()),
            record.get("record_digest").and_then(Value::as_str)
        );
    }
}

#[test]
#[ignore = "writes fixtures/zk/workflow_v1/vectors.json"]
fn regenerate_canonical_byte_vectors() {
    std::fs::write(fixture_path("vectors.json"), pretty(&rendered_vectors())).expect("write");
}
