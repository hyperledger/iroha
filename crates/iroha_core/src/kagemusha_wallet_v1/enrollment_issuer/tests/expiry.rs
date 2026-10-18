//! Nonmonetary expiry issuance and exact recovery over the real issuer journal.

use super::*;

fn resume(dispatch: &PreKeyDispatchV1, permit: Vec<u8>) -> PreKeyDispatchV1 {
    let mut value = dispatch.clone();
    value.purpose = KagemushaEnrollmentPermitPurposeV1::Resume;
    value.previous_permit = Some(permit);
    value.native_dispatch_nonce = [27; 32];
    value
}

fn authenticate_expiry(
    owner: &mut EnrollmentIssuerV1<Runtime>,
    dispatch: &PreKeyDispatchV1,
) -> EnrollmentIssuerSessionV1 {
    let original = dispatch.encode().unwrap();
    owner.authenticate_expiry(&original, &original).unwrap()
}

#[test]
fn expiry_proof_requires_actual_deadline_and_exact_account_authenticated_resume() {
    let (_temp, mut owner, dispatch) = fixture();
    let mut first = authenticate(&mut owner, &dispatch);
    let permit = owner.pre_key_permit(&mut first).unwrap();
    let resumed = resume(&dispatch, permit);
    let mut session = authenticate_expiry(&mut owner, &resumed);
    let bank_calls = owner.runtime.bank_calls;
    let worker_calls = owner.runtime.worker_actions.len();
    owner.runtime.clock = first.attempt.selection().expires_at_ms - 1;
    assert!(owner.expiry_proof(&mut session).is_err());
    assert_eq!(owner.runtime.signatures, 1);
    assert_eq!(owner.runtime.bank_calls, bank_calls);
    assert_eq!(owner.runtime.worker_actions.len(), worker_calls);
    let original = resumed.encode().unwrap();
    owner.runtime.authenticated = false;
    assert!(owner.authenticate_expiry(&original, &original).is_err());
    owner.runtime.authenticated = true;
    assert!(
        owner
            .authenticate_expiry(b"changed HTTP envelope", &original)
            .is_err()
    );
    assert!(
        owner
            .authenticate_expiry(&dispatch.encode().unwrap(), &dispatch.encode().unwrap())
            .is_err()
    );
    let mut changed = resumed.clone();
    changed.request_id = [99; 32];
    let original = changed.encode().unwrap();
    assert!(owner.authenticate_expiry(&original, &original).is_err());
    session.issuer = [0; 32];
    assert!(owner.expiry_proof(&mut session).is_err());
}

#[test]
fn expiry_proof_exact_replay_after_reopen_survives_live_dependency_loss() {
    let (_temp, mut owner, dispatch) = fixture();
    let mut first = authenticate(&mut owner, &dispatch);
    let permit = owner.pre_key_permit(&mut first).unwrap();
    let resumed = resume(&dispatch, permit.clone());
    owner.runtime.clock = first.attempt.selection().expires_at_ms;
    owner.runtime.fail_bank = true;
    owner.runtime.fail_worker = true;
    let bank_calls = owner.runtime.bank_calls;
    let worker_calls = owner.runtime.worker_actions.len();
    let mut session = authenticate_expiry(&mut owner, &resumed);
    let original = owner.expiry_proof(&mut session).unwrap();
    let proof = KagemushaEnrollmentExpiryProofV1::decode_canonical(&original).unwrap();
    proof
        .verify(&dispatch.scheme, &dispatch.enrollment_certificate)
        .unwrap();
    assert_eq!(
        proof.body.dispatch_sha256,
        <[u8; 32]>::from(Sha256::digest(resumed.encode().unwrap()))
    );
    assert_eq!(
        proof.body.permit_sha256,
        <[u8; 32]>::from(Sha256::digest(permit))
    );
    assert_eq!(
        proof.body.observed_at_ms,
        first.attempt.selection().expires_at_ms
    );
    assert_eq!(owner.runtime.bank_calls, bank_calls);
    assert_eq!(owner.runtime.worker_actions.len(), worker_calls);
    assert_eq!(owner.runtime.signatures, 2);
    // Service startup still requires its configured dependencies and a valid clock.
    // This exercises exact proof replay after a successful reopen and subsequent loss.
    let mut owner = reopened(owner);
    owner.runtime.dependencies_unavailable = true;
    owner.runtime.lose_signature_reply = true;
    owner.runtime.clock = 0;
    let mut session = authenticate_expiry(&mut owner, &resumed);
    assert_eq!(owner.expiry_proof(&mut session).unwrap(), original);
    assert_eq!(owner.expiry_proof(&mut session).unwrap(), original);
    assert_eq!(owner.runtime.signatures, 2);
    assert_eq!(owner.runtime.bank_calls, bank_calls);
    assert_eq!(owner.runtime.worker_actions.len(), worker_calls);
}

#[test]
fn expiry_statement_preserves_consumed_refused_and_issued_attempts_without_new_authority() {
    for phase in 0..5 {
        let (_temp, mut owner, dispatch) = fixture();
        let mut initial = authenticate(&mut owner, &dispatch);
        let permit = owner.pre_key_permit(&mut initial).unwrap();
        if (1..=3).contains(&phase) {
            let request = permit_tests::account_request(&dispatch, &initial.attempt);
            if phase >= 2 {
                owner.runtime.fixture_evidence = Some(request.clone());
            }
            let result = owner.verify_evidence(&mut initial, &request.encode().unwrap());
            if phase == 1 {
                assert!(matches!(result, Err(Pending)));
            } else {
                result.unwrap();
            }
            if phase == 3 {
                owner.issue_credential(&mut initial).unwrap();
            }
        } else if phase == 4 {
            owner.runtime.observation = KagemushaEligibilityDecisionV1::Frozen;
            assert!(matches!(
                owner.pre_key_permit(&mut initial),
                Err(Refused(_))
            ));
        }
        let before = (
            initial.attempt.phase(),
            initial.attempt.refusal(),
            initial.attempt.issued().map(<[u8]>::to_vec),
        );
        let bank_calls = owner.runtime.bank_calls;
        let worker_calls = owner.runtime.worker_actions.len();
        let signatures = owner.runtime.signatures;
        owner.runtime.clock = initial.attempt.selection().expires_at_ms + 1;
        owner.runtime.fail_bank = true;
        owner.runtime.fail_worker = true;
        let resumed = resume(&dispatch, permit);
        let mut session = authenticate_expiry(&mut owner, &resumed);
        owner.expiry_proof(&mut session).unwrap();
        let current = owner
            .journal
            .read(&session.attempt.selection().key)
            .unwrap()
            .unwrap();
        assert_eq!(
            (
                current.phase(),
                current.refusal(),
                current.issued().map(<[u8]>::to_vec)
            ),
            before
        );
        assert_eq!(owner.runtime.bank_calls, bank_calls);
        assert_eq!(owner.runtime.worker_actions.len(), worker_calls);
        assert_eq!(owner.runtime.signatures, signatures + 1);
        assert!(
            owner.pre_key_permit(&mut session).is_err(),
            "expiry grants no fresh E1"
        );
    }
}

#[test]
fn new_expiry_proof_requires_current_selected_issuer_and_actual_signature() {
    for revoke in [false, true] {
        let (_temp, mut owner, dispatch) = fixture();
        let mut first = authenticate(&mut owner, &dispatch);
        let permit = owner.pre_key_permit(&mut first).unwrap();
        owner.runtime.clock = first.attempt.selection().expires_at_ms;
        let resumed = resume(&dispatch, permit);
        let mut session = authenticate_expiry(&mut owner, &resumed);
        if revoke {
            let mut configuration = owner.runtime.config.as_ref().clone();
            configuration.providers.clear();
            owner.runtime.config = Arc::new(configuration);
        } else {
            owner.runtime.signer = p256::ecdsa::SigningKey::from_slice(&[77; 32]).unwrap();
        }
        assert!(owner.expiry_proof(&mut session).is_err());
        assert_eq!(owner.runtime.signatures, if revoke { 1 } else { 2 });
        assert_eq!(
            owner
                .journal
                .expiry_proof(&session.attempt, &resumed)
                .unwrap(),
            None
        );
        assert_eq!(session.attempt.phase(), Phase::Selected);
    }
}
