//! Reservation boundaries exercised through actual queued, certified native Checks.

use super::*;
use iroha_data_model::transaction::Executable;
use std::sync::atomic::{AtomicBool, Ordering};

struct PreparedReview {
    body: StreamTokenBodyV1,
    payload: Vec<u8>,
    reviewed: StreamTokenReviewedV1,
    custody: VerifiedSignerCustodyV1,
}

impl PreparedReview {
    fn new(source: &NativeStreamTokenSourceV1) -> Self {
        let snapshot = source.observe_signing_state(&source.binding).unwrap();
        let custody = verify_signer_custody_use_v1(
            &source.custody_record,
            &source.binding,
            &source.custody_trust,
            &snapshot.custody,
        )
        .unwrap();
        let now = now_ms() / 1000;
        let body = StreamTokenBodyV1 {
            token_id: "b2".repeat(16),
            manifest_cid: sorafs_manifest::canonical_manifest_root_cid([3; 32]),
            provider_id: match source.binding.purpose {
                sorafs_manifest::signer::protocol::SignerPurposeBindingV1::StreamToken {
                    provider_id,
                } => provider_id,
                _ => unreachable!(),
            },
            profile_handle: "sorafs.sf1@1.0.0".into(),
            max_streams: 2,
            ttl_epoch: now + 60,
            rate_limit_bytes: 1024,
            issued_at: now - 1,
            requests_per_minute: 60,
            token_pk_version: 1,
        };
        let expected = SignerStreamTokenExpectedV1::new(&body, &source.binding).unwrap();
        let request = SignerStreamTokenRequestV1::new(&custody, &expected, &body).unwrap();
        let intent = SignerOperationIntentV1 {
            action: SignerOperationActionV1::Sign,
            operation_id: request.operation_id,
            request_digest: request.digest().unwrap(),
            previous_audit: snapshot.audit_head,
        };
        Self {
            payload: body.signing_payload_bytes().unwrap(),
            body,
            reviewed: StreamTokenReviewedV1 { request, intent },
            custody,
        }
    }

    fn reserve(
        &self,
        source: &NativeStreamTokenSourceV1,
    ) -> Result<SignerOperationReservationV1, SignerOperationErrorV1> {
        source.reserve_stream_token(
            &SignerOperationReservationRequestV1 {
                intent: &self.reviewed.intent,
                intent_digest: self.reviewed.intent.digest().unwrap(),
                custody: &self.custody,
            },
            &SignerStreamTokenReservationReviewV1 {
                body: &self.body,
                signing_payload: &self.payload,
                reviewed: &self.reviewed,
            },
        )
    }
}

struct NativeAttempt {
    result: Result<SignerOperationReservationV1, SignerOperationErrorV1>,
    actions: Vec<Action>,
    fixture: Fixture,
    reviewed: StreamTokenReviewedV1,
}

fn attempt_reservation(substitute_local_record: bool) -> NativeAttempt {
    let mut fixture = Fixture::new_at(now_ms() - 5_000);
    let (_directory, _) = config(&fixture);
    let queue = queue();
    let mut source = source_with_timeout(&fixture, queue.clone(), Duration::from_secs(10));
    let review = PreparedReview::new(&source);
    if substitute_local_record {
        // The request retains valid verified custody. Only this source's local attestation
        // bytes change; native State, body, intent, permissions and finality stay genuine.
        let mut record: sorafs_manifest::signer::custody::SignerCustodyRecordV1 =
            norito::decode_from_bytes(&source.custody_record).unwrap();
        record.attestation[0] ^= 1;
        source.custody_record = norito::encode_canonical(&record).unwrap();
    }
    let state = fixture.state.clone();
    let stopped = Arc::new(AtomicBool::new(false));
    let worker_stopped = stopped.clone();
    let worker = std::thread::spawn(move || {
        let mut applied = std::collections::HashSet::new();
        let mut actions = Vec::new();
        while !worker_stopped.load(Ordering::Acquire) {
            let transactions = {
                let view = state.view();
                queue.all_transactions(&view).collect::<Vec<_>>()
            };
            for tx in transactions {
                let signed = tx.external().unwrap().clone();
                if applied.insert(signed.hash()) {
                    let Executable::Instructions(instructions) = signed.instructions() else {
                        panic!("native reservation submitted a non-instruction transaction");
                    };
                    assert_eq!(instructions.len(), 1);
                    let native = instructions[0]
                        .as_any()
                        .downcast_ref::<MutateSorafsStreamTokenAuthority>()
                        .expect("the real source must submit the exact native instruction");
                    let action = native.request.action.clone();
                    assert!(fixture.commit_signed(signed, now_ms()));
                    actions.push(action);
                }
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        (fixture, actions)
    });
    // No role-key provider is constructed or called. Only the operator and observer sign
    // actual native transactions; no token or completed receipt can be produced here.
    let result = review.reserve(&source);
    stopped.store(true, Ordering::Release);
    let (fixture, actions) = worker.join().unwrap();
    NativeAttempt {
        result,
        actions,
        fixture,
        reviewed: review.reviewed,
    }
}

#[test]
fn finalized_current_check_cannot_reserve_with_substituted_local_custody() {
    let attempt = attempt_reservation(true);
    assert!(matches!(
        attempt.result,
        Err(SignerOperationErrorV1::Custody(_))
    ));
    let [Action::Check(check)] = attempt.actions.as_slice() else {
        panic!("exactly the Current Check must finalize; Reserve must never be submitted");
    };
    assert_eq!(check.reviewed, attempt.reviewed);
    assert_eq!(
        check.phase,
        Phase::Current(attempt.reviewed.intent.previous_audit)
    );
    let current = capture_stream_token_authority_v1(
        &attempt.fixture.state.view(),
        &attempt.fixture.policy.binding,
        attempt.reviewed.request.operation_id,
    )
    .unwrap();
    assert!(
        current.operation.is_none(),
        "no durable reservation may be created"
    );
    assert_eq!(current.head.audit, attempt.reviewed.intent.previous_audit);
    assert!(current.head.active_operation.is_none());
}

#[test]
fn reservation_returns_only_after_its_distinct_finalized_before_provider_check() {
    let attempt = attempt_reservation(false);
    let reservation = attempt.result.unwrap();
    let [
        Action::Check(current),
        Action::Reserve(reviewed),
        Action::Check(before),
    ] = attempt.actions.as_slice()
    else {
        panic!("reservation requires exactly Current, Reserve and a fresh BeforeProvider Check");
    };
    assert_eq!(current.reviewed, attempt.reviewed);
    assert_eq!(*reviewed, attempt.reviewed);
    assert_eq!(before.reviewed, attempt.reviewed);
    assert_eq!(
        current.phase,
        Phase::Current(attempt.reviewed.intent.previous_audit)
    );
    assert_ne!(current.challenge, before.challenge);
    let Phase::BeforeProvider(row) = &before.phase else {
        panic!("a Current or later-phase Check cannot stand in for BeforeProvider");
    };
    assert_eq!(row.operation.reservation, reservation);
    assert_eq!(row.operation.outcome, StreamTokenOutcomeV1::Reserved);
    let current = capture_stream_token_authority_v1(
        &attempt.fixture.state.view(),
        &attempt.fixture.policy.binding,
        attempt.reviewed.request.operation_id,
    )
    .unwrap();
    assert_eq!(current.operation.unwrap().operation, *row);
    assert_eq!(current.head.audit, attempt.reviewed.intent.previous_audit);
}

#[test]
fn checked_context_rejects_a_genuine_capability_after_its_original_deadline() {
    let mut fixture = Fixture::new_at(now_ms() - 5_000);
    let source = source_with_timeout(&fixture, queue(), Duration::from_secs(5));
    let reviewed = reviewed(&source);
    let started = std::time::Instant::now();
    let prepared = source
        .prepare_check(&reviewed, Phase::Current(reviewed.intent.previous_audit))
        .unwrap();
    let signed = source
        .transactions
        .sign(prepared.instruction(), true, prepared.deadline())
        .unwrap();
    let pending = prepared.bind_signed_transaction(signed.clone()).unwrap();
    assert!(fixture.commit_signed(signed, now_ms()));
    let checked = pending
        .verify_finalized(|| {
            source.time().map_err(|_| {
        iroha_core::query::stream_token_authority::observation::StreamTokenObservationErrorV1::Clock
    })
        })
        .unwrap();
    source.checked_context(&checked).unwrap();
    // Wait out this genuine capability's original interval. No refreshed challenge,
    // clock injection, private capability constructor or deadline mutation is used.
    while checked.ensure_live().is_ok() {
        assert!(started.elapsed() < Duration::from_secs(6));
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(matches!(
        source.checked_context(&checked),
        Err(SignerOperationErrorV1::StateUnavailable)
    ));
}

mod expiry;
