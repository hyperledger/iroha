//! Local attestation expiry across a genuine finalized `BeforeProvider` Check.

use super::*;
use iroha_crypto::Signature;
use iroha_data_model::{
    isi::sorafs::MutateSorafsStreamTokenCustody,
    sorafs::stream_token_custody::SorafsStreamTokenCustodyActionV1,
};
use sorafs_manifest::signer::custody::{SignerCustodyErrorV1, SignerCustodyRecordV1};
use std::time::Instant;

const POSITIVE_RECORD_LIFETIME_MS: u64 = 45_000;
const EXPIRING_RECORD_LIFETIME_MS: u64 = 8_000;
const ATTEMPT_BOUND: Duration = Duration::from_secs(35);

fn enroll_record_with_lifetime(fixture: &mut Fixture, lifetime_ms: u64) -> u64 {
    let current =
        capture_stream_token_authority_v1(&fixture.state.view(), &fixture.policy.binding, [0; 32])
            .unwrap();
    let mut record: SignerCustodyRecordV1 = norito::decode_canonical(&fixture.record).unwrap();
    let issued = now_ms();
    let expiry = issued.checked_add(lifetime_ms).unwrap();
    record.statement.anchor = current.anchor;
    record.statement.sequence = current.control.next_sequence;
    record.statement.predecessor_digest = current.control.predecessor_digest;
    record.statement.issued_at_unix_ms = issued;
    record.statement.expires_at_unix_ms = expiry;
    record.attestation = Signature::try_new(
        Fixture::key(7).private_key(),
        &record.statement.signing_payload().unwrap(),
    )
    .unwrap()
    .payload()
    .try_into()
    .unwrap();
    let bytes = norito::encode_canonical(&record).unwrap();
    let enrollment = MutateSorafsStreamTokenCustody {
        provider_id: fixture.provider,
        expected_revision: current.control_revision,
        expected_digest: current.anchor.state_digest,
        action: SorafsStreamTokenCustodyActionV1::Enroll(bytes.clone()),
    };
    assert!(fixture.commit_instruction(enrollment.into(), 1, issued));
    // Retain only the exact independently signed record actually enrolled by native execution.
    fixture.record = bytes;
    assert!(
        now_ms() < expiry,
        "renewal must still be live after finalization"
    );
    expiry
}

fn renewal_record_attempt(delay_before_provider: bool) {
    let mut fixture = Fixture::new_at(now_ms() - 5_000);
    let (_directory, _) = config(&fixture);
    let queue = queue();
    // Successful renewal covers enrollment and all three finalized native transactions.
    // Only the negative case deliberately expires its genuine enrolled record mid-attempt.
    let lifetime_ms = if delay_before_provider {
        EXPIRING_RECORD_LIFETIME_MS
    } else {
        POSITIVE_RECORD_LIFETIME_MS
    };
    let expiry = enroll_record_with_lifetime(&mut fixture, lifetime_ms);
    // The existing native reservation controls use this same original ten-second timeout.
    // It is fixed before preparing any Check; no deadline or capability is modified.
    let source = source_with_timeout(&fixture, queue.clone(), Duration::from_secs(10));
    let review = PreparedReview::new(&source);
    assert!(now_ms() < expiry);
    assert!(expiry < fixture.policy.active_until_unix_ms);
    assert!(expiry < review.reviewed.request.expires_at_unix_ms);
    let state = fixture.state.clone();
    let stopped = Arc::new(AtomicBool::new(false));
    let worker_stopped = stopped.clone();
    let started = Instant::now();
    let worker = std::thread::spawn(move || {
        let mut applied = std::collections::HashSet::new();
        let mut actions = Vec::new();
        while !worker_stopped.load(Ordering::Acquire) {
            assert!(started.elapsed() < ATTEMPT_BOUND);
            let transactions = {
                let view = state.view();
                queue.all_transactions(&view).collect::<Vec<_>>()
            };
            for tx in transactions {
                let signed = tx.external().unwrap().clone();
                if !applied.insert(signed.hash()) {
                    continue;
                }
                let Executable::Instructions(instructions) = signed.instructions() else {
                    panic!("native source must submit instructions");
                };
                assert_eq!(instructions.len(), 1);
                let native = instructions[0]
                    .as_any()
                    .downcast_ref::<MutateSorafsStreamTokenAuthority>()
                    .unwrap();
                let action = native.request.action.clone();
                let before = matches!(&action, Action::Check(check) if matches!(check.phase, Phase::BeforeProvider(_)));
                if before && delay_before_provider {
                    while now_ms() < expiry && !worker_stopped.load(Ordering::Acquire) {
                        assert!(started.elapsed() < ATTEMPT_BOUND);
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    if worker_stopped.load(Ordering::Acquire) {
                        break;
                    }
                }
                let transaction_deadline = signed.creation_time() + signed.time_to_live().unwrap();
                let committed_at = now_ms();
                assert!(fixture.commit_signed(signed, committed_at));
                let finalized_at = now_ms();
                assert!(u128::from(finalized_at) < transaction_deadline.as_millis());
                if before {
                    let Action::Check(check) = &action else {
                        unreachable!()
                    };
                    let Phase::BeforeProvider(row) = &check.phase else {
                        unreachable!()
                    };
                    assert!(finalized_at < fixture.policy.active_until_unix_ms);
                    assert!(finalized_at < check.reviewed.request.expires_at_unix_ms);
                    assert!(finalized_at < row.operation.reservation.expires_at_unix_ms);
                    if delay_before_provider {
                        assert!(committed_at >= expiry);
                    } else {
                        assert!(finalized_at < expiry);
                    }
                } else {
                    assert!(
                        finalized_at < expiry,
                        "Current and Reserve must finalize while local custody is live"
                    );
                }
                actions.push((action, committed_at, finalized_at));
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        (fixture, actions)
    });
    let result = review.reserve(&source);
    let returned_at = now_ms();
    stopped.store(true, Ordering::Release);
    let (fixture, actions) = worker.join().unwrap();
    assert!(started.elapsed() < ATTEMPT_BOUND);
    let [
        (Action::Check(current), _, _),
        (Action::Reserve(reserved), _, _),
        (Action::Check(before), before_commit, before_finalized),
    ] = actions.as_slice()
    else {
        panic!("exactly Current, Reserve and BeforeProvider must successfully finalize");
    };
    assert_eq!(current.reviewed, review.reviewed);
    assert_eq!(*reserved, review.reviewed);
    assert_eq!(before.reviewed, review.reviewed);
    assert_eq!(
        current.phase,
        Phase::Current(review.reviewed.intent.previous_audit)
    );
    assert_ne!(current.challenge, before.challenge);
    let Phase::BeforeProvider(row) = &before.phase else {
        panic!("wrong final Check phase")
    };
    if delay_before_provider {
        assert!(*before_commit >= expiry);
        // This exact error can occur only after checked() has verified native finality and
        // its original deadline, and checked_context has also passed ensure_live().
        assert!(matches!(
            result,
            Err(SignerOperationErrorV1::Custody(
                SignerCustodyErrorV1::Freshness
            ))
        ));
    } else {
        assert!(
            returned_at < expiry,
            "renewal expired before return: lifetime_ms={lifetime_ms}, expiry={expiry}, \
             before_commit={before_commit}, before_finalized={before_finalized}, \
             returned_at={returned_at}, result={result:?}"
        );
        assert_eq!(result.unwrap(), row.operation.reservation);
    }
    let retained = capture_stream_token_authority_v1(
        &fixture.state.view(),
        &fixture.policy.binding,
        review.reviewed.request.operation_id,
    )
    .unwrap();
    assert_eq!(retained.operation.unwrap().operation, *row);
    assert_eq!(retained.head.audit, review.reviewed.intent.previous_audit);
    assert_eq!(
        retained.head.active_operation,
        Some(review.reviewed.request.operation_id)
    );
    // No role-key provider, completed receipt, response token or Complete action is created.
}

#[test]
fn signed_renewal_remains_usable_when_before_provider_finishes_before_expiry() {
    renewal_record_attempt(false);
}

#[test]
fn expired_local_record_rejects_after_successful_finalized_before_provider() {
    renewal_record_attempt(true);
}
