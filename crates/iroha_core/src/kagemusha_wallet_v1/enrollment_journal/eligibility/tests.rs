//! Genuine test-key middleware signatures and real private-journal restart/replay controls.

use super::*;
use crate::kagemusha_wallet_v1::enrollment_journal::{permit_tests, tests::initialized};
use iroha_crypto::{Algorithm, KeyPair, Signature};
use iroha_data_model::kagemusha::{
    KagemushaEligibilityAuthorityV1, KagemushaEligibilityResponseBodyV1,
};

fn signer() -> KeyPair {
    KeyPair::from_seed(vec![32; 32], Algorithm::Ed25519)
}
fn fixture(
    dispatch: &PreKeyDispatchV1,
    attempt: &EnrollmentAttemptV1,
) -> (KagemushaEligibilityPolicyV1, KagemushaEligibilityRequestV1) {
    let policy = KagemushaEligibilityPolicyV1 {
        version: 1,
        network_id: dispatch.scheme.network_id,
        scheme_id: dispatch.scheme.scheme_id(),
        asset_digest: dispatch.asset.asset_digest(),
        revision: 1,

        authority: KagemushaEligibilityAuthorityV1::Bank {
            fi_digest: dispatch.fi_digest,
        },
        public_key: signer().public_key().to_bytes().1.try_into().unwrap(),
        maximum_response_ms: 1000,
    };
    let request = KagemushaEligibilityRequestV1 {
        version: 1,
        policy_digest: policy.policy_digest().unwrap(),
        account_digest: attempt.selection().challenge.account_digest,
        actor_digest: dispatch.actor_digest,
        attempt_id: attempt.selection().attempt_id,
        nonce: [34; 32],
        operation_digest: [35; 32],
        purpose: KagemushaEligibilityPurposeV1::PreKeyPermit,
        requested_at_ms: 1000,
        expires_at_ms: 2000,
    };
    (policy, request)
}
fn response(
    policy: &KagemushaEligibilityPolicyV1,
    request: &KagemushaEligibilityRequestV1,
    decision: KagemushaEligibilityDecisionV1,
) -> Vec<u8> {
    let body = KagemushaEligibilityResponseBodyV1 {
        version: 1,
        request_digest: request.request_digest(policy).unwrap(),
        decision,
        source_revision: 8,
        observed_at_ms: 1100,
        valid_until_ms: 2000,
    };
    KagemushaEligibilityResponseV1 {
        signature: Signature::new(signer().private_key(), &body.signing_message().unwrap())
            .payload()
            .try_into()
            .unwrap(),
        body,
    }
    .encode_canonical()
    .unwrap()
}

#[test]
fn consumed_e5_recovery_requires_its_own_live_eligibility_observation() {
    let (_temp, _parent, mut journal) = initialized();
    let (dispatch, mut attempt, signer) = permit_tests::fixture(&mut journal);
    let permit = permit_tests::signed(&dispatch, permit_tests::body(&dispatch, &attempt), &signer);
    journal.retain_permit(&attempt, &dispatch, permit).unwrap();
    let original = permit_tests::account_request(&dispatch, &attempt);
    journal
        .select_verification(&mut attempt, original, [31; 32], 1_001)
        .unwrap();
    let (policy, mut request) = fixture(&dispatch, &attempt);
    request.purpose = KagemushaEligibilityPurposeV1::VerifyEvidence;
    journal
        .retain_eligibility_request(&mut attempt, &dispatch, &policy, &request, 1_100)
        .unwrap();
    let signed_payload = response(
        &policy,
        &request,
        KagemushaEligibilityDecisionV1::ApprovedUnfrozen,
    );
    journal
        .retain_eligibility_response(&mut attempt, &request.nonce, &signed_payload, 1_200)
        .unwrap();
    journal
        .consume_eligibility(&mut attempt, &dispatch, &policy, &request, 1_200)
        .unwrap();
    assert_eq!(attempt.phase(), EnrollmentJournalPhaseV1::Verifying);
    assert!(
        journal
            .consume_eligibility(&mut attempt, &dispatch, &policy, &request, 1_201)
            .is_err()
    );
    request.nonce = [99; 32];
    request.requested_at_ms = attempt.selection().expires_at_ms;
    request.expires_at_ms = request.requested_at_ms + 1;
    assert!(
        journal
            .retain_eligibility_request(
                &mut attempt,
                &dispatch,
                &policy,
                &request,
                request.requested_at_ms
            )
            .is_err()
    );
}

#[test]
fn request_and_original_response_survive_restart_and_nonce_consumes_exactly_once() {
    let (temp, _parent, mut journal) = initialized();
    let (dispatch, mut attempt, _) = permit_tests::fixture(&mut journal);
    let (policy, request) = fixture(&dispatch, &attempt);
    journal
        .retain_eligibility_request(&mut attempt, &dispatch, &policy, &request, 1000)
        .unwrap();
    journal
        .retain_eligibility_request(&mut attempt, &dispatch, &policy, &request, 1001)
        .unwrap();
    let original = response(
        &policy,
        &request,
        KagemushaEligibilityDecisionV1::ApprovedUnfrozen,
    );
    assert!(
        journal
            .consume_eligibility(&mut attempt, &dispatch, &policy, &request, 1001)
            .is_err()
    );
    journal
        .retain_eligibility_response(&mut attempt, &request.nonce, &original, 1200)
        .unwrap();
    journal
        .retain_eligibility_response(&mut attempt, &request.nonce, &original, 1300)
        .unwrap();
    assert_eq!(
        journal
            .read_eligibility(&attempt, &request.nonce)
            .unwrap()
            .unwrap()
            .received_at_ms,
        1200
    );
    assert_eq!(
        journal.retain_eligibility_response(&mut attempt, &request.nonce, &original, 1199),
        Err(Conflict)
    );
    assert_eq!(
        journal.retain_eligibility_request(&mut attempt, &dispatch, &policy, &request, 1199),
        Err(Conflict)
    );
    assert!(
        std::fs::read_dir(temp.path().join("issuer"))
            .unwrap()
            .all(|entry| !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("eligibility-"))
    );
    drop(journal);
    let mut journal =
        EnrollmentJournalV1::open(&temp.path().join("issuer"), b"approved scope DATA").unwrap();
    let mut attempt = journal.read(&attempt.selection().key).unwrap().unwrap();
    journal
        .consume_eligibility(&mut attempt, &dispatch, &policy, &request, 1300)
        .unwrap();
    assert_eq!(
        journal.consume_eligibility(&mut attempt, &dispatch, &policy, &request, 1300),
        Err(Conflict)
    );
    drop(journal);
    let mut journal =
        EnrollmentJournalV1::open(&temp.path().join("issuer"), b"approved scope DATA").unwrap();
    assert_eq!(
        journal.consume_eligibility(&mut attempt, &dispatch, &policy, &request, 1400),
        Err(Conflict)
    );
    assert_eq!(
        journal.retain_eligibility_request(&mut attempt, &dispatch, &policy, &request, 1400),
        Err(Conflict)
    );
    let record = journal
        .read_eligibility(&attempt, &request.nonce)
        .unwrap()
        .unwrap();
    assert_eq!(record.response, original);
    assert_eq!(record.consumed_at_ms, 1300);
}

#[test]
fn a_pre_issuance_denial_is_retained_unconsumed_as_the_attempts_terminal_refusal() {
    for decision in [
        KagemushaEligibilityDecisionV1::Frozen,
        KagemushaEligibilityDecisionV1::NotApproved,
    ] {
        let refusal = if decision == KagemushaEligibilityDecisionV1::Frozen {
            iroha_data_model::kagemusha::KagemushaWalletEnrollmentRefusalV1::AccountFrozen
        } else {
            iroha_data_model::kagemusha::KagemushaWalletEnrollmentRefusalV1::AccountNotApproved
        };
        let (temp, _parent, mut journal) = initialized();
        let (dispatch, mut attempt, _) = permit_tests::fixture(&mut journal);
        let (policy, request) = fixture(&dispatch, &attempt);
        journal
            .retain_eligibility_request(&mut attempt, &dispatch, &policy, &request, 1000)
            .unwrap();
        let original = response(&policy, &request, decision);
        journal
            .retain_eligibility_response(&mut attempt, &request.nonce, &original, 1200)
            .unwrap();
        assert_eq!(attempt.refusal(), None);
        assert_eq!(
            journal.consume_eligibility(&mut attempt, &dispatch, &policy, &request, 1200),
            Err(EnrollmentJournalErrorV1::Ineligible(refusal))
        );
        assert_eq!(attempt.refusal(), Some(refusal));
        assert_eq!(
            journal
                .read_eligibility(&attempt, &request.nonce)
                .unwrap()
                .unwrap()
                .consumed_at_ms,
            0,
            "a denial is never consumed"
        );
        // Terminal: no later response, request, consumption or permit changes the attempt.
        let before = attempt.original.clone();
        let approved = response(
            &policy,
            &request,
            KagemushaEligibilityDecisionV1::ApprovedUnfrozen,
        );
        assert_eq!(
            journal.retain_eligibility_response(&mut attempt, &request.nonce, &approved, 1300),
            Err(Conflict)
        );
        let mut next = request;
        next.nonce = [77; 32];
        assert_eq!(
            journal.retain_eligibility_request(&mut attempt, &dispatch, &policy, &next, 1300),
            Err(Conflict)
        );
        assert_eq!(
            journal.consume_eligibility(&mut attempt, &dispatch, &policy, &request, 1300),
            Err(Conflict)
        );
        drop(journal);
        let journal =
            EnrollmentJournalV1::open(&temp.path().join("issuer"), b"approved scope DATA").unwrap();
        let reread = journal.read(&attempt.selection().key).unwrap().unwrap();
        assert_eq!(reread.original, before);
        assert_eq!(reread.refusal(), Some(refusal));
    }
}

#[test]
fn changed_current_authority_bank_or_operation_refuses_a_previously_approved_response() {
    let (_temp, _parent, mut journal) = initialized();
    let (dispatch, mut attempt, _) = permit_tests::fixture(&mut journal);
    let (policy, request) = fixture(&dispatch, &attempt);
    journal
        .retain_eligibility_request(&mut attempt, &dispatch, &policy, &request, 1000)
        .unwrap();
    journal
        .retain_eligibility_response(
            &mut attempt,
            &request.nonce,
            &response(
                &policy,
                &request,
                KagemushaEligibilityDecisionV1::ApprovedUnfrozen,
            ),
            1200,
        )
        .unwrap();
    let mut rotated = policy;
    rotated.revision += 1;
    assert!(
        journal
            .consume_eligibility(&mut attempt, &dispatch, &rotated, &request, 1200)
            .is_err()
    );
    let mut routed = dispatch.clone();
    routed.fi_digest = [99; 32];
    assert!(
        journal
            .consume_eligibility(&mut attempt, &routed, &policy, &request, 1200)
            .is_err()
    );
    let mut tampered_value = request;
    tampered_value.operation_digest = [99; 32];
    assert_eq!(
        journal.consume_eligibility(&mut attempt, &dispatch, &policy, &tampered_value, 1200),
        Err(Conflict)
    );
    tampered_value = request;
    tampered_value.purpose = KagemushaEligibilityPurposeV1::VerifyEvidence;
    assert_eq!(
        journal.consume_eligibility(&mut attempt, &dispatch, &policy, &tampered_value, 1200),
        Err(Conflict)
    );
    assert_eq!(
        journal
            .read_eligibility(&attempt, &request.nonce)
            .unwrap()
            .unwrap()
            .consumed_at_ms,
        0
    );
}

#[test]
fn changed_attempt_cursor_cannot_consume_old_observation() {
    let (_temp, _parent, mut journal) = initialized();
    let (dispatch, mut attempt, _) = permit_tests::fixture(&mut journal);
    let (policy, request) = fixture(&dispatch, &attempt);
    journal
        .retain_eligibility_request(&mut attempt, &dispatch, &policy, &request, 1000)
        .unwrap();
    journal
        .retain_eligibility_response(
            &mut attempt,
            &request.nonce,
            &response(
                &policy,
                &request,
                KagemushaEligibilityDecisionV1::ApprovedUnfrozen,
            ),
            1200,
        )
        .unwrap();
    let mut record = attempt.record.clone();
    // A genuine durable phase change invalidates an observation of the preceding cursor.
    record.phase = EnrollmentJournalPhaseV1::Verifying;
    record.request = vec![1];
    record.worker_request = vec![2];
    record.verification_time_ms = 1200;
    record.worker_configuration = [41; 32];
    record.worker_preparation.as_mut().unwrap().configuration = [41; 32];
    journal.advance(&mut attempt, record).unwrap();
    assert_eq!(
        journal.consume_eligibility(&mut attempt, &dispatch, &policy, &request, 1300),
        Err(Conflict)
    );
}

#[test]
fn wrong_scope_bank_actor_phase_and_enrollment_deadline_never_create_a_request() {
    let (_temp, _parent, mut journal) = initialized();
    let (dispatch, mut attempt, _) = permit_tests::fixture(&mut journal);
    let (policy, request) = fixture(&dispatch, &attempt);
    let changes: [fn(&mut KagemushaEligibilityRequestV1); 6] = [
        |r| r.account_digest = [99; 32],
        |r| r.actor_digest = [99; 32],
        |r| r.attempt_id = [99; 32],
        |r| r.requested_at_ms = 999,
        |r| r.purpose = KagemushaEligibilityPurposeV1::DeliverCredential,
        |r| r.purpose = KagemushaEligibilityPurposeV1::IssueCredential,
    ];
    for change in changes {
        let mut tampered_value = request;
        change(&mut tampered_value);
        assert!(
            journal
                .retain_eligibility_request(&mut attempt, &dispatch, &policy, &tampered_value, 1000)
                .is_err()
        );
    }
    let mut wrong = policy;
    wrong.authority = KagemushaEligibilityAuthorityV1::Bank {
        fi_digest: [99; 32],
    };
    let mut tampered_value = request;
    tampered_value.policy_digest = wrong.policy_digest().unwrap();
    assert_eq!(
        journal.retain_eligibility_request(&mut attempt, &dispatch, &wrong, &tampered_value, 1000),
        Err(Conflict)
    );
    wrong = policy;
    wrong.maximum_response_ms = 1_000_000;
    tampered_value = request;
    tampered_value.policy_digest = wrong.policy_digest().unwrap();
    tampered_value.expires_at_ms = attempt.selection().expires_at_ms + 1;
    assert_eq!(
        journal.retain_eligibility_request(&mut attempt, &dispatch, &wrong, &tampered_value, 1000),
        Err(Conflict)
    );
    assert!(
        journal
            .read_eligibility(&attempt, &request.nonce)
            .unwrap()
            .is_none()
    );
}

#[test]
fn unavailable_or_lost_original_never_reconstructs_authority_and_expiry_blocks_consumption() {
    let (temp, _parent, mut journal) = initialized();
    let (dispatch, mut attempt, _) = permit_tests::fixture(&mut journal);
    let (policy, request) = fixture(&dispatch, &attempt);
    let original = response(
        &policy,
        &request,
        KagemushaEligibilityDecisionV1::ApprovedUnfrozen,
    );
    assert_eq!(
        journal.retain_eligibility_response(&mut attempt, &request.nonce, &original, 1200),
        Err(Conflict)
    );
    journal
        .retain_eligibility_request(&mut attempt, &dispatch, &policy, &request, 1000)
        .unwrap();
    journal
        .retain_eligibility_response(&mut attempt, &request.nonce, &original, 1200)
        .unwrap();
    assert!(
        journal
            .consume_eligibility(&mut attempt, &dispatch, &policy, &request, 1199)
            .is_err()
    );
    assert!(
        journal
            .consume_eligibility(&mut attempt, &dispatch, &policy, &request, 2000)
            .is_err()
    );
    std::fs::write(
        temp.path()
            .join("issuer")
            .join(filename(&attempt.selection().key).unwrap()),
        b"corrupt DATA",
    )
    .unwrap();
    assert!(
        journal
            .consume_eligibility(&mut attempt, &dispatch, &policy, &request, 1300)
            .is_err()
    );
    assert!(
        journal
            .retain_eligibility_request(&mut attempt, &dispatch, &policy, &request, 1300)
            .is_err()
    );
}

#[test]
fn loss_of_the_attempt_record_never_recreates_a_consumed_or_new_nonce() {
    let (temp, _parent, mut journal) = initialized();
    let (dispatch, mut attempt, _) = permit_tests::fixture(&mut journal);
    let (policy, request) = fixture(&dispatch, &attempt);
    journal
        .retain_eligibility_request(&mut attempt, &dispatch, &policy, &request, 1000)
        .unwrap();
    journal
        .retain_eligibility_response(
            &mut attempt,
            &request.nonce,
            &response(
                &policy,
                &request,
                KagemushaEligibilityDecisionV1::ApprovedUnfrozen,
            ),
            1200,
        )
        .unwrap();
    journal
        .consume_eligibility(&mut attempt, &dispatch, &policy, &request, 1300)
        .unwrap();
    let path = temp
        .path()
        .join("issuer")
        .join(filename(&attempt.selection().key).unwrap());
    std::fs::remove_file(&path).unwrap();
    for nonce in [request.nonce, [98; 32]] {
        let mut retry = request;
        retry.nonce = nonce;
        assert_eq!(
            journal.retain_eligibility_request(&mut attempt, &dispatch, &policy, &retry, 1400),
            Err(Conflict)
        );
        assert!(!path.exists());
    }
    drop(journal);
    let mut journal =
        EnrollmentJournalV1::open(&temp.path().join("issuer"), b"approved scope DATA").unwrap();
    assert_eq!(
        journal.consume_eligibility(&mut attempt, &dispatch, &policy, &request, 1400),
        Err(Conflict)
    );
    assert_eq!(
        journal.retain_eligibility_request(&mut attempt, &dispatch, &policy, &request, 1400),
        Err(Conflict)
    );
    assert!(!path.exists());
}

#[test]
fn exchange_index_is_append_only_and_rejects_duplicate_or_foreign_entries() {
    let (_temp, _parent, mut journal) = initialized();
    let (dispatch, mut attempt, _) = permit_tests::fixture(&mut journal);
    let (policy, request) = fixture(&dispatch, &attempt);
    journal
        .retain_eligibility_request(&mut attempt, &dispatch, &policy, &request, 1000)
        .unwrap();
    journal
        .retain_eligibility_response(
            &mut attempt,
            &request.nonce,
            &response(
                &policy,
                &request,
                KagemushaEligibilityDecisionV1::ApprovedUnfrozen,
            ),
            1200,
        )
        .unwrap();
    journal
        .consume_eligibility(&mut attempt, &dispatch, &policy, &request, 1300)
        .unwrap();
    let consumed = attempt.record.eligibility[0].clone();
    let mut next = request;
    next.nonce = [97; 32];
    journal
        .retain_eligibility_request(&mut attempt, &dispatch, &policy, &next, 1400)
        .unwrap();
    assert_eq!(attempt.record.eligibility.len(), 2);
    assert!(attempt.record.eligibility[0] == consumed);
    assert_eq!(
        journal.consume_eligibility(&mut attempt, &dispatch, &policy, &request, 1400),
        Err(Conflict)
    );
    for kind in 0..7 {
        let mut record = attempt.record.clone();
        match kind {
            0 => record.eligibility.push(consumed.clone()),
            1 => record.eligibility[0].scope = [99; 32],
            2 => record.eligibility[0].key = [99; 32],
            3 => record.eligibility[0].nonce = [99; 32],
            4 => record.eligibility[0].attempt_cursor = [0; 32],
            5 => record.eligibility[0].consumed_at_ms = 1199,
            _ => record.eligibility[0].response.clear(),
        }
        assert!(matches!(encode(&record), Err(Invalid)), "mutation {kind}");
    }
}

#[test]
fn total_canonical_record_bound_limits_retries_without_eviction_or_a_count_limit() {
    let (_temp, _parent, mut journal) = initialized();
    let (dispatch, mut attempt, _) = permit_tests::fixture(&mut journal);
    let (policy, mut request) = fixture(&dispatch, &attempt);
    journal
        .retain_eligibility_request(&mut attempt, &dispatch, &policy, &request, 1000)
        .unwrap();
    let original = attempt.original.clone();
    let mut record = attempt.record.clone();
    let template = record.eligibility[0].clone();
    // The bound is the actual canonical complete record length. Over 64 exchanges are valid;
    // no historical nonce can be evicted to create room for a fresh request.
    for index in 1_u32..=65 {
        request.nonce = [90; 32];
        request.nonce[..4].copy_from_slice(&index.to_le_bytes());
        let mut exchange = template.clone();
        exchange.nonce = request.nonce;
        exchange.request = request.encode_canonical(&policy).unwrap();
        record.eligibility.push(exchange);
    }
    assert!(encode(&record).is_ok());
    // Build a structurally valid oversized index directly, avoiding thousands of disk writes.
    let count = RECORD_MAX / norito::encode_canonical(&template).unwrap().len() + 1024;
    for index in 66..u32::try_from(count).unwrap() {
        request.nonce[..4].copy_from_slice(&index.to_le_bytes());
        let mut exchange = template.clone();
        exchange.nonce = request.nonce;
        exchange.request = request.encode_canonical(&policy).unwrap();
        record.eligibility.push(exchange);
    }
    assert!(norito::encode_canonical(&record).unwrap().len() > RECORD_MAX);
    assert_eq!(journal.advance(&mut attempt, record), Err(Invalid));
    assert_eq!(attempt.original, original);
    assert_eq!(
        journal
            .read(&attempt.selection().key)
            .unwrap()
            .unwrap()
            .original,
        original
    );
}

#[test]
fn publication_uncertainty_never_returns_consumption_and_reopen_recovers_one_atomic_index() {
    for transition in 0..3 {
        for publish_first in [false, true] {
            let (temp, _parent, mut journal) = initialized();
            let (dispatch, mut attempt, _) = permit_tests::fixture(&mut journal);
            let (policy, request) = fixture(&dispatch, &attempt);
            let original = response(
                &policy,
                &request,
                KagemushaEligibilityDecisionV1::ApprovedUnfrozen,
            );
            if transition > 0 {
                journal
                    .retain_eligibility_request(&mut attempt, &dispatch, &policy, &request, 1000)
                    .unwrap();
            }
            if transition > 1 {
                journal
                    .retain_eligibility_response(&mut attempt, &request.nonce, &original, 1200)
                    .unwrap();
            }
            let before = attempt.original.clone();
            let mut candidate = attempt.record.clone();
            match transition {
                0 => candidate.eligibility.push(EligibilityRecord {
                    version: 1,
                    scope: journal.scope,
                    key: attempt.selection().key,
                    nonce: request.nonce,
                    attempt_cursor: attempt_digest(&attempt).unwrap(),
                    scheme: dispatch.scheme.to_canonical_bytes().unwrap(),
                    policy: policy.encode_canonical().unwrap(),
                    request: request.encode_canonical(&policy).unwrap(),
                    response: Vec::new(),
                    received_at_ms: 0,
                    consumed_at_ms: 0,
                }),
                1 => {
                    candidate.eligibility[0].response = original.clone();
                    candidate.eligibility[0].received_at_ms = 1200;
                }
                _ => candidate.eligibility[0].consumed_at_ms = 1300,
            }
            let after = encode(&candidate).unwrap();
            let outcome = journal.publish_with(
                &filename(&attempt.selection().key).unwrap(),
                &after,
                PublishMode::Replace,
                |directory, name, bytes, mode| {
                    if publish_first {
                        directory.write_atomic(name, bytes, mode)?;
                    }
                    // The actual shared journal publication primitive fails before or after
                    // rename. This deterministic boundary test is not physical crash evidence.
                    Err(io::Error::other(
                        "injected eligibility publication uncertainty",
                    ))
                },
            );
            assert_eq!(outcome, Err(Uncertain));
            assert_eq!(attempt.original, before);
            assert_eq!(
                journal.consume_eligibility(&mut attempt, &dispatch, &policy, &request, 1300),
                Err(Uncertain)
            );
            drop(journal);
            let mut journal =
                EnrollmentJournalV1::open(&temp.path().join("issuer"), b"approved scope DATA")
                    .unwrap();
            let mut restored = journal.read(&attempt.selection().key).unwrap().unwrap();
            assert_eq!(
                restored.original,
                if publish_first { after } else { before }
            );
            if transition == 2 && publish_first {
                assert_eq!(
                    journal.consume_eligibility(&mut restored, &dispatch, &policy, &request, 1400),
                    Err(Conflict)
                );
            } else {
                journal
                    .retain_eligibility_request(&mut restored, &dispatch, &policy, &request, 1400)
                    .unwrap();
                journal
                    .retain_eligibility_response(&mut restored, &request.nonce, &original, 1400)
                    .unwrap();
                journal
                    .consume_eligibility(&mut restored, &dispatch, &policy, &request, 1400)
                    .unwrap();
                assert_eq!(
                    journal.consume_eligibility(&mut restored, &dispatch, &policy, &request, 1400),
                    Err(Conflict)
                );
            }
        }
    }
}

#[test]
fn retained_issuance_and_delivery_recover_after_e1_expiry_with_fresh_observations() {
    use EnrollmentJournalPhaseV1 as Phase;
    for (phase, purpose) in [
        (
            Phase::Evidence,
            KagemushaEligibilityPurposeV1::IssueCredential,
        ),
        (
            Phase::Signing,
            KagemushaEligibilityPurposeV1::IssueCredential,
        ),
        (
            Phase::Issued,
            KagemushaEligibilityPurposeV1::DeliverCredential,
        ),
    ] {
        let (_temp, _parent, mut journal) = initialized();
        let (dispatch, mut attempt, _) = permit_tests::fixture(&mut journal);
        let mut record = attempt.record.clone();
        // Journal phase DATA only: this does not manufacture worker or signer authority.
        // Existing genuine worker-result/signature suites test admission into these phases.
        record.phase = phase;
        record.request = vec![1];
        record.worker_request = vec![2];
        record.worker_result = vec![3];
        record.verification_time_ms = 1200;
        record.worker_result_time_ms = 1300;
        record.worker_configuration = record.worker_preparation.as_ref().unwrap().configuration;
        if matches!(phase, Phase::Signing | Phase::Issued) {
            record.credential_body = vec![4];
        }
        if phase == Phase::Issued {
            record.issued = vec![5];
        }
        journal.advance(&mut attempt, record).unwrap();
        let (policy, mut request) = fixture(&dispatch, &attempt);
        request.purpose = purpose;
        request.requested_at_ms = attempt.selection().expires_at_ms + 100;
        request.expires_at_ms = request.requested_at_ms + 1000;
        journal
            .retain_eligibility_request(
                &mut attempt,
                &dispatch,
                &policy,
                &request,
                request.requested_at_ms,
            )
            .unwrap();
        let mut signed_payload = KagemushaEligibilityResponseBodyV1 {
            version: 1,
            request_digest: request.request_digest(&policy).unwrap(),
            decision: KagemushaEligibilityDecisionV1::ApprovedUnfrozen,
            source_revision: 9,
            observed_at_ms: request.requested_at_ms + 10,
            valid_until_ms: request.expires_at_ms,
        };
        let original = KagemushaEligibilityResponseV1 {
            signature: Signature::new(
                signer().private_key(),
                &signed_payload.signing_message().unwrap(),
            )
            .payload()
            .try_into()
            .unwrap(),
            body: signed_payload,
        }
        .encode_canonical()
        .unwrap();
        journal
            .retain_eligibility_response(
                &mut attempt,
                &request.nonce,
                &original,
                signed_payload.observed_at_ms,
            )
            .unwrap();
        journal
            .consume_eligibility(
                &mut attempt,
                &dispatch,
                &policy,
                &request,
                signed_payload.observed_at_ms + 1,
            )
            .unwrap();
        assert_eq!(attempt.phase(), phase);
        assert_eq!(
            journal.consume_eligibility(
                &mut attempt,
                &dispatch,
                &policy,
                &request,
                request.expires_at_ms
            ),
            Err(Conflict)
        );
        for early in [
            KagemushaEligibilityPurposeV1::PreKeyPermit,
            KagemushaEligibilityPurposeV1::VerifyEvidence,
        ] {
            let mut too_late = request;
            too_late.purpose = early;
            too_late.nonce = [96; 32];
            assert_eq!(
                journal.retain_eligibility_request(
                    &mut attempt,
                    &dispatch,
                    &policy,
                    &too_late,
                    too_late.requested_at_ms
                ),
                Err(Conflict)
            );
        }
        // A new response cannot stretch current policy's lifetime merely because E1 expired.
        signed_payload.valid_until_ms += 1;
        assert!(
            KagemushaEligibilityResponseV1 {
                signature: Signature::new(
                    signer().private_key(),
                    &signed_payload.signing_message().unwrap()
                )
                .payload()
                .try_into()
                .unwrap(),
                body: signed_payload,
            }
            .verify(&policy, &request, signed_payload.observed_at_ms)
            .is_err()
        );
    }
}

#[test]
fn historical_index_rejects_self_consistent_foreign_policy_and_extended_early_deadline() {
    let (_temp, _parent, mut journal) = initialized();
    let (dispatch, mut attempt, _) = permit_tests::fixture(&mut journal);
    let (policy, request) = fixture(&dispatch, &attempt);
    journal
        .retain_eligibility_request(&mut attempt, &dispatch, &policy, &request, 1000)
        .unwrap();
    for kind in 0..6 {
        let mut record = attempt.record.clone();
        let mut policy = policy;
        let mut request = request;
        match kind {
            0 => policy.network_id = [99; 32],
            1 => policy.scheme_id = [99; 32],
            2 => policy.asset_digest = [99; 32],
            3 => {
                request.requested_at_ms = 999;
                request.expires_at_ms = 1999;
            }
            4 => {
                policy.maximum_response_ms = 1_000_000;
                request.expires_at_ms = record.selection.expires_at_ms + 1;
            }
            _ => {
                let mut scheme = dispatch.scheme;
                scheme.relation_id = [99; 32];
                policy.scheme_id = scheme.scheme_id();
                record.eligibility[0].scheme = scheme.to_canonical_bytes().unwrap();
            }
        }
        request.policy_digest = policy.policy_digest().unwrap();
        record.eligibility[0].policy = policy.encode_canonical().unwrap();
        record.eligibility[0].request = request.encode_canonical(&policy).unwrap();
        assert!(matches!(encode(&record), Err(Invalid)), "mutation {kind}");
    }
}

#[test]
fn nonce_namespace_is_attempt_owned_but_responses_cannot_cross_attempts() {
    let (_temp, _parent, mut journal) = initialized();
    let (dispatch, mut first, _) = permit_tests::fixture(&mut journal);
    let mut selected = first.selection().clone();
    selected.key = [94; 32];
    selected.attempt_id = [95; 32];
    let mut second = journal.select(selected).unwrap();
    let (policy, request) = fixture(&dispatch, &first);
    let (_, other) = fixture(&dispatch, &second);
    assert_eq!(request.nonce, other.nonce);
    journal
        .retain_eligibility_request(&mut first, &dispatch, &policy, &request, 1000)
        .unwrap();
    journal
        .retain_eligibility_request(&mut second, &dispatch, &policy, &other, 1000)
        .unwrap();
    let original = response(
        &policy,
        &request,
        KagemushaEligibilityDecisionV1::ApprovedUnfrozen,
    );
    assert_eq!(
        journal.retain_eligibility_response(&mut second, &other.nonce, &original, 1200),
        Err(Invalid)
    );
    journal
        .retain_eligibility_response(&mut first, &request.nonce, &original, 1200)
        .unwrap();
    journal
        .retain_eligibility_response(
            &mut second,
            &other.nonce,
            &response(
                &policy,
                &other,
                KagemushaEligibilityDecisionV1::ApprovedUnfrozen,
            ),
            1200,
        )
        .unwrap();
    journal
        .consume_eligibility(&mut first, &dispatch, &policy, &request, 1300)
        .unwrap();
    journal
        .consume_eligibility(&mut second, &dispatch, &policy, &other, 1300)
        .unwrap();
    assert_eq!(
        journal.consume_eligibility(&mut second, &dispatch, &policy, &request, 1400),
        Err(Conflict)
    );
}

#[test]
fn scheme_operator_is_exactly_scoped_and_uses_the_same_durable_one_use_observation() {
    let (_temp, _parent, mut journal) = initialized();
    let (dispatch, mut attempt, _) = permit_tests::fixture(&mut journal);
    let (mut policy, mut request) = fixture(&dispatch, &attempt);
    policy.authority = KagemushaEligibilityAuthorityV1::SchemeOperator {
        operator_digest: [99; 32],
    };
    request.policy_digest = policy.policy_digest().unwrap();
    assert_eq!(
        journal.retain_eligibility_request(&mut attempt, &dispatch, &policy, &request, 1_000),
        Err(Conflict)
    );
    policy.authority = KagemushaEligibilityAuthorityV1::SchemeOperator {
        operator_digest: dispatch.fi_digest,
    };
    request.policy_digest = policy.policy_digest().unwrap();
    journal
        .retain_eligibility_request(&mut attempt, &dispatch, &policy, &request, 1_000)
        .unwrap();
    let original = response(
        &policy,
        &request,
        KagemushaEligibilityDecisionV1::ApprovedUnfrozen,
    );
    journal
        .retain_eligibility_response(&mut attempt, &request.nonce, &original, 1_100)
        .unwrap();
    journal
        .consume_eligibility(&mut attempt, &dispatch, &policy, &request, 1_200)
        .unwrap();
    assert!(
        journal
            .consume_eligibility(&mut attempt, &dispatch, &policy, &request, 1_201)
            .is_err()
    );
}

#[cfg(unix)]
#[test]
fn an_interrupted_refusal_or_permit_is_adopted_on_a_fresh_inode_before_it_is_exposed() {
    // Deterministic injection between the replacing rename and the parent synchronization:
    // the record is visible but not known durable. The fresh-inode republication (with its
    // own parent synchronization) is what makes it durable; physical power loss is not
    // simulated on the real filesystem.
    use crate::kagemusha_wallet_v1::enrollment_journal::fault::{
        ADOPTION_FAILS, UNCERTAIN_AFTER_RENAME,
    };
    use std::os::unix::fs::MetadataExt as _;
    let (temp, _parent, mut journal) = initialized();
    let directory = temp.path().join("issuer");
    let reopen = |journal: EnrollmentJournalV1| {
        drop(journal);
        EnrollmentJournalV1::open(&directory, b"approved scope DATA").unwrap()
    };
    let inode = |path: &std::path::Path| std::fs::metadata(path).unwrap().ino();
    let (dispatch, attempt, signer) = permit_tests::fixture(&mut journal);
    let key = attempt.selection().key;
    let record = directory.join(filename(&key).unwrap());
    // 1. The permit original is renamed into place without its parent synchronization.
    let permit = permit_tests::signed(&dispatch, permit_tests::body(&dispatch, &attempt), &signer);
    UNCERTAIN_AFTER_RENAME.with(|armed| armed.set(true));
    assert_eq!(
        journal.retain_permit(&attempt, &dispatch, permit.clone()),
        Err(Uncertain)
    );
    let journal = reopen(journal);
    let permits: Vec<_> = std::fs::read_dir(&directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("permit-"))
        })
        .collect();
    assert_eq!(permits.len(), 1, "{permits:?}");
    let before = inode(&permits[0]);
    let attempt = journal.read(&key).unwrap().unwrap();
    ADOPTION_FAILS.with(|fails| fails.set(true));
    assert!(
        journal.permit(&attempt, &dispatch).is_err(),
        "nothing exposed"
    );
    ADOPTION_FAILS.with(|fails| fails.set(false));
    assert_eq!(inode(&permits[0]), before, "nothing republished");
    assert_eq!(journal.permit(&attempt, &dispatch).unwrap(), Some(permit));
    assert_ne!(inode(&permits[0]), before, "adopted on a fresh inode");
    // 2. The terminal refusal is renamed into place without its parent synchronization.
    let mut journal = journal;
    let mut attempt = attempt;
    let (policy, request) = fixture(&dispatch, &attempt);
    journal
        .retain_eligibility_request(&mut attempt, &dispatch, &policy, &request, 1000)
        .unwrap();
    let denial = response(&policy, &request, KagemushaEligibilityDecisionV1::Frozen);
    journal
        .retain_eligibility_response(&mut attempt, &request.nonce, &denial, 1200)
        .unwrap();
    UNCERTAIN_AFTER_RENAME.with(|armed| armed.set(true));
    assert_eq!(
        journal.consume_eligibility(&mut attempt, &dispatch, &policy, &request, 1200),
        Err(Uncertain)
    );
    let journal = reopen(journal);
    let before = inode(&record);
    // An unknown adoption exposes no outcome and republishes nothing.
    ADOPTION_FAILS.with(|fails| fails.set(true));
    assert!(matches!(journal.read(&key), Err(Uncertain)));
    ADOPTION_FAILS.with(|fails| fails.set(false));
    assert_eq!(inode(&record), before);
    // A successful adoption republishes the exact record on a fresh inode, then exposes it.
    let adopted = journal.read(&key).unwrap().unwrap();
    assert_eq!(
        adopted.refusal(),
        Some(iroha_data_model::kagemusha::KagemushaWalletEnrollmentRefusalV1::AccountFrozen)
    );
    let after = inode(&record);
    assert_ne!(after, before, "adopted on a fresh inode");
    journal.read(&key).unwrap().unwrap();
    assert_eq!(inode(&record), after, "adopted once per owner");
    // The adopted refusal is what a later owner reads.
    let journal = reopen(journal);
    assert_eq!(
        journal.read(&key).unwrap().unwrap().refusal(),
        adopted.refusal()
    );
}
