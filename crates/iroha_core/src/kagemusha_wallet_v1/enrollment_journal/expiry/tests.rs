//! Genuine issuer signatures over exact retained test permits; no platform qualification claim.

use super::*;
use crate::kagemusha_wallet_v1::enrollment_journal::{permit_tests, tests::initialized};
use iroha_data_model::kagemusha::KagemushaEnrollmentPermitPurposeV1;
use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};

fn prepared(
    journal: &mut EnrollmentJournalV1,
) -> (PreKeyDispatchV1, EnrollmentAttemptV1, SigningKey) {
    let (mut dispatch, attempt, key) = permit_tests::fixture(journal);
    let permit = permit_tests::signed(&dispatch, permit_tests::body(&dispatch, &attempt), &key);
    journal
        .retain_permit(&attempt, &dispatch, permit.clone())
        .unwrap();
    dispatch.purpose = KagemushaEnrollmentPermitPurposeV1::Resume;
    dispatch.previous_permit = Some(permit);
    dispatch.native_dispatch_nonce = [27; 32];
    (dispatch, attempt, key)
}

fn signed(
    dispatch: &PreKeyDispatchV1,
    body: KagemushaEnrollmentExpiryProofBodyV1,
    signer: &SigningKey,
) -> Vec<u8> {
    let signature: Signature = signer.sign(&body.signing_message().unwrap());
    KagemushaEnrollmentExpiryProofV1::from_issuer_der(
        body,
        &dispatch.enrollment_certificate,
        signature.to_der().as_bytes(),
    )
    .unwrap()
    .encode_canonical()
    .unwrap()
}

#[test]
fn expiry_proof_replays_exact_original_after_restart_without_changing_attempt() {
    let (temp, _parent, mut journal) = initialized();
    let (dispatch, attempt, signer) = prepared(&mut journal);
    let before = attempt.original.clone();
    let body = journal
        .expiry_statement(&attempt, &dispatch, attempt.selection().expires_at_ms)
        .unwrap();
    let original = signed(&dispatch, body, &signer);
    assert_eq!(journal.expiry_proof(&attempt, &dispatch).unwrap(), None);
    journal
        .retain_expiry_proof(&attempt, &dispatch, original.clone())
        .unwrap();
    journal
        .retain_expiry_proof(&attempt, &dispatch, original.clone())
        .unwrap();
    assert_eq!(
        journal.expiry_proof(&attempt, &dispatch).unwrap(),
        Some(original.clone())
    );
    assert_eq!(
        journal
            .read(&attempt.selection().key)
            .unwrap()
            .unwrap()
            .original,
        before
    );
    drop(journal);
    let mut journal =
        EnrollmentJournalV1::open(&temp.path().join("issuer"), b"approved scope DATA").unwrap();
    let restored = journal.read(&attempt.selection().key).unwrap().unwrap();
    assert_eq!(
        journal.expiry_proof(&restored, &dispatch).unwrap(),
        Some(original)
    );
    let mut changed = body;
    changed.observed_at_ms += 1;
    assert_eq!(
        journal.retain_expiry_proof(&restored, &dispatch, signed(&dispatch, changed, &signer)),
        Err(Conflict)
    );
    assert_eq!(restored.original, before);
}

#[test]
fn expiry_statement_requires_expired_retained_fresh_permit_and_exact_resume() {
    let (_temp, _parent, mut journal) = initialized();
    let (dispatch, attempt, signer) = prepared(&mut journal);
    let expiry = attempt.selection().expires_at_ms;
    assert!(
        journal
            .expiry_statement(&attempt, &dispatch, expiry - 1)
            .is_err()
    );
    for changed in 0..4 {
        let mut altered = dispatch.clone();
        match changed {
            0 => {
                altered.purpose = KagemushaEnrollmentPermitPurposeV1::Fresh;
                altered.previous_permit = None;
            }
            1 => {
                altered.native_dispatch_nonce =
                    iroha_data_model::kagemusha::KagemushaEnrollmentPermitV1::decode_canonical(
                        altered.previous_permit.as_deref().unwrap(),
                        &altered.scheme,
                        &altered.enrollment_certificate,
                    )
                    .unwrap()
                    .body
                    .native_dispatch_nonce
            }
            2 => altered.actor_digest[0] ^= 1,
            _ => {
                let previous =
                    iroha_data_model::kagemusha::KagemushaEnrollmentPermitV1::decode_canonical(
                        altered.previous_permit.as_deref().unwrap(),
                        &altered.scheme,
                        &altered.enrollment_certificate,
                    )
                    .unwrap();
                let mut body = previous.body;
                body.observed_at_ms += 1;
                altered.previous_permit = Some(permit_tests::signed(&altered, body, &signer));
            }
        }
        assert!(
            journal
                .expiry_statement(&attempt, &altered, expiry)
                .is_err(),
            "mutation {changed}"
        );
    }
}

#[test]
fn expiry_proof_rejects_foreign_signature_dispatch_and_corrupt_retained_record() {
    let (_temp, _parent, mut journal) = initialized();
    let (dispatch, attempt, signer) = prepared(&mut journal);
    let body = journal
        .expiry_statement(&attempt, &dispatch, attempt.selection().expires_at_ms)
        .unwrap();
    let foreign = SigningKey::from_slice(&[77; 32]).unwrap();
    assert!(
        journal
            .retain_expiry_proof(&attempt, &dispatch, signed(&dispatch, body, &foreign))
            .is_err()
    );
    let mut other = body;
    other.dispatch_sha256[0] ^= 1;
    assert!(
        journal
            .retain_expiry_proof(&attempt, &dispatch, signed(&dispatch, other, &signer))
            .is_err()
    );
    let original = signed(&dispatch, body, &signer);
    journal
        .retain_expiry_proof(&attempt, &dispatch, original.clone())
        .unwrap();
    let filename = name(&attempt.selection().key, &dispatch.encode().unwrap());
    let record = ExpiryRecord {
        version: 1,
        scope: journal.scope,
        key: attempt.selection().key,
        dispatch: dispatch.encode().unwrap(),
        proof: signed(&dispatch, other, &signer),
    };
    journal
        .directory
        .write_atomic(
            &filename,
            &norito::encode_canonical(&record).unwrap(),
            PublishMode::Replace,
        )
        .unwrap();
    assert!(journal.expiry_proof(&attempt, &dispatch).is_err());
}

#[cfg(unix)]
#[test]
fn uncertain_expiry_publication_needs_reopen_and_durable_adoption() {
    let (temp, _parent, mut journal) = initialized();
    let (dispatch, attempt, signer) = prepared(&mut journal);
    let body = journal
        .expiry_statement(&attempt, &dispatch, attempt.selection().expires_at_ms)
        .unwrap();
    let original = signed(&dispatch, body, &signer);
    fault::UNCERTAIN_AFTER_RENAME.with(|armed| armed.set(true));
    assert_eq!(
        journal.retain_expiry_proof(&attempt, &dispatch, original.clone()),
        Err(Uncertain)
    );
    assert_eq!(journal.expiry_proof(&attempt, &dispatch), Err(Uncertain));
    drop(journal);
    let journal =
        EnrollmentJournalV1::open(&temp.path().join("issuer"), b"approved scope DATA").unwrap();
    let attempt = journal.read(&attempt.selection().key).unwrap().unwrap();
    // Pre-adopt the permit so this fault targets the newly visible expiry record.
    journal.expiry_permit(&attempt, &dispatch).unwrap();
    fault::ADOPTION_FAILS.with(|armed| armed.set(true));
    let result = journal.expiry_proof(&attempt, &dispatch);
    fault::ADOPTION_FAILS.with(|armed| armed.set(false));
    assert_eq!(result, Err(Uncertain));
    assert_eq!(
        journal.expiry_proof(&attempt, &dispatch).unwrap(),
        Some(original)
    );
}
