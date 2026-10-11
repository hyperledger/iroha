//! Genuine test-scalar signatures exercise journal binding, not an installed issuer or device.
use super::{tests::initialized, *};
use iroha_core_zk::kagemusha_wallet_enrollment_v1::PreKeyDispatchV1;
use iroha_crypto::{Algorithm, Hash, KeyPair};
use iroha_data_model::{account::AccountId, kagemusha::*};
use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};

fn public(key: &SigningKey) -> KagemushaDevicePublicKeyV1 {
    KagemushaDevicePublicKeyV1::from_sec1_bytes(
        key.verifying_key().to_encoded_point(false).as_bytes(),
    )
    .unwrap()
}
pub(super) fn fixture(
    journal: &mut EnrollmentJournalV1,
) -> (PreKeyDispatchV1, EnrollmentAttemptV1, SigningKey) {
    let (dispatch, mut attempt, signer) = unprepared_fixture(journal);
    preparation::tests::prepare(journal, &mut attempt, &dispatch);
    (dispatch, attempt, signer)
}
pub(crate) fn unprepared_fixture(
    journal: &mut EnrollmentJournalV1,
) -> (PreKeyDispatchV1, EnrollmentAttemptV1, SigningKey) {
    let root = SigningKey::from_slice(&[1; 32]).unwrap();
    let signer = SigningKey::from_slice(&[2; 32]).unwrap();
    let scheme = KagemushaWalletSchemeV1 {
        version: 1,
        network_id: *Hash::new(b"journal test network DATA").as_ref(),
        scheme_root_key: public(&root),
        relation_id: [3; 32],
        provider_contract: kagemusha_wallet_provider_contract_v1(),
    };
    let body = KagemushaWalletSignerCertificateBodyV1 {
        version: 1,
        scheme_id: scheme.scheme_id(),
        role: KagemushaWalletSignerRoleV1::Enrollment,
        key: public(&signer),
        serial: 1,
    };
    let signature: Signature = root.sign(&body.signing_message());
    let enrollment_certificate = KagemushaWalletSignerCertificateV1::sign(
        body,
        &scheme,
        KagemushaWalletSignerOutputV1::Raw(signature.to_bytes().as_slice().try_into().unwrap()),
    )
    .unwrap();
    let asset = crate::kagemusha_wallet_v1::tests::Memory::new()
        .registration
        .asset;
    let account = AccountId::new(
        KeyPair::from_seed(vec![4; 32], Algorithm::Ed25519)
            .public_key()
            .clone(),
    );
    let app = KagemushaWalletAppPolicyV1 {
        version: 1,
        scheme_id: scheme.scheme_id(),
        identity: KagemushaWalletAppIdentityV1::Apple {
            app_id: "TEAM.org.example.wallet".into(),
        },
    };
    let policy = KagemushaWalletEnrollmentPolicyV1 {
        version: 1,
        scheme_id: scheme.scheme_id(),
        asset_digest: asset.asset_digest(),
        app_policy: app.policy_digest().unwrap(),
        platform: KagemushaWalletEnrollmentPlatformV1::Apple {
            attestation_root_sha256: [5; 32],
        },
        regulatory_policy: KagemushaWalletRegulatoryPolicyV1::default(),
        challenge_lifetime_ms: 600_001,
        attestation_lease_lifetime_ms: 0,
    };
    let dispatch = PreKeyDispatchV1 {
        version: 1,
        request_id: [6; 32],
        platform: KagemushaEnrollmentPermitPlatformV1::Apple,
        purpose: KagemushaEnrollmentPermitPurposeV1::Fresh,
        client_nonce: [7; 32],
        native_dispatch_nonce: [8; 32],
        manifest_digest: [9; 32],
        release_digest: [10; 32],
        service_origin_digest: [11; 32],
        fi_digest: [12; 32],
        actor_digest: [13; 32],
        scheme,
        app,
        policy: policy.clone(),
        enrollment_certificate,
        account,
        asset,
        previous_permit: None,
    };
    let challenge = KagemushaWalletEnrollmentChallengeV1 {
        version: 1,
        scheme_id: scheme.scheme_id(),
        asset_digest: dispatch.asset.asset_digest(),
        account_digest: kagemusha_wallet_account_digest_v1(&dispatch.account).unwrap(),
        app_policy: policy.app_policy,
        enrollment_policy: policy.policy_digest().unwrap(),
        issuer_nonce: [14; 32],
    };
    let attempt = journal
        .select(EnrollmentSelectionV1 {
            key: journal
                .request_key(&challenge.account_digest, &dispatch.request_id)
                .unwrap(),
            attempt_id: [15; 32],
            challenge,
            created_at_ms: 1_000,
            expires_at_ms: 601_001,
            stable_selection: dispatch.stable_selection().unwrap(),
        })
        .unwrap();
    (dispatch, attempt, signer)
}
pub(super) fn body(
    dispatch: &PreKeyDispatchV1,
    attempt: &EnrollmentAttemptV1,
) -> KagemushaEnrollmentPermitBodyV1 {
    let selected = attempt.selection();
    KagemushaEnrollmentPermitBodyV1 {
        version: 1,
        platform: dispatch.platform,
        purpose: dispatch.purpose,
        challenge: selected.challenge,
        network_id: dispatch.scheme.network_id,
        manifest_digest: dispatch.manifest_digest,
        release_digest: dispatch.release_digest,
        service_origin_digest: dispatch.service_origin_digest,
        fi_digest: dispatch.fi_digest,
        actor_digest: dispatch.actor_digest,
        attempt_id: selected.attempt_id,
        client_nonce: dispatch.client_nonce,
        native_dispatch_nonce: dispatch.native_dispatch_nonce,
        originals_digest: dispatch.originals_digest(&selected.challenge).unwrap(),
        enrollment_certificate: dispatch.enrollment_certificate.certificate_digest(),
        created_at_ms: selected.created_at_ms,
        expires_at_ms: selected.expires_at_ms,
        observed_at_ms: 2_000,
    }
}
pub(super) fn signed(
    dispatch: &PreKeyDispatchV1,
    body: KagemushaEnrollmentPermitBodyV1,
    key: &SigningKey,
) -> Vec<u8> {
    let signature: Signature = key.sign(&body.signing_message().unwrap());
    KagemushaEnrollmentPermitV1::from_issuer_der(
        body,
        &dispatch.scheme,
        &dispatch.enrollment_certificate,
        signature.to_der().as_bytes(),
    )
    .unwrap()
    .encode_canonical()
    .unwrap()
}

#[test]
fn permit_retry_recovers_exact_signed_original_after_restart() {
    let (temp, _parent, mut journal) = initialized();
    let (dispatch, attempt, key) = fixture(&mut journal);
    assert!(journal.permit(&attempt, &dispatch).unwrap().is_none());
    let original = signed(&dispatch, body(&dispatch, &attempt), &key);
    journal
        .retain_permit(&attempt, &dispatch, original.clone())
        .unwrap();
    journal
        .retain_permit(&attempt, &dispatch, original.clone())
        .unwrap();
    assert_eq!(
        journal.permit(&attempt, &dispatch).unwrap(),
        Some(original.clone())
    );
    drop(journal);
    let mut journal =
        EnrollmentJournalV1::open(&temp.path().join("issuer"), b"approved scope DATA").unwrap();
    let restored = journal.read(&attempt.selection().key).unwrap().unwrap();
    assert_eq!(
        journal.permit(&restored, &dispatch).unwrap(),
        Some(original)
    );
    let mut changed = body(&dispatch, &restored);
    changed.observed_at_ms += 1;
    assert_eq!(
        journal.retain_permit(&restored, &dispatch, signed(&dispatch, changed, &key)),
        Err(Conflict)
    );
}

#[test]
fn resume_requires_actual_journaled_previous_permit_and_fresh_nonce() {
    let (_temp, _parent, mut journal) = initialized();
    let (mut dispatch, attempt, key) = fixture(&mut journal);
    let original = signed(&dispatch, body(&dispatch, &attempt), &key);
    let fresh = dispatch.clone();
    dispatch.previous_permit = Some(original.clone());
    dispatch.purpose = KagemushaEnrollmentPermitPurposeV1::Resume;
    dispatch.native_dispatch_nonce = [27; 32];
    assert_eq!(journal.permit(&attempt, &dispatch), Err(Conflict));
    journal
        .retain_permit(&attempt, &fresh, original.clone())
        .unwrap();
    assert!(journal.permit(&attempt, &dispatch).unwrap().is_none());
    let resume = signed(&dispatch, body(&dispatch, &attempt), &key);
    journal
        .retain_permit(&attempt, &dispatch, resume.clone())
        .unwrap();
    assert_eq!(
        journal.permit(&attempt, &dispatch).unwrap(),
        Some(resume.clone())
    );
    // Even a genuinely signed and retained Resume cannot replace the first Fresh original.
    let mut second_resume = dispatch.clone();
    second_resume.previous_permit = Some(resume);
    second_resume.native_dispatch_nonce = [28; 32];
    assert_eq!(journal.permit(&attempt, &second_resume), Err(Invalid));
    dispatch.native_dispatch_nonce = fresh.native_dispatch_nonce;
    assert_eq!(journal.permit(&attempt, &dispatch), Err(Conflict));
}

#[test]
fn signed_wrong_attempt_window_scope_and_nonce_cannot_enter_journal() {
    let (_temp, _parent, mut journal) = initialized();
    let (dispatch, attempt, key) = fixture(&mut journal);
    let correct = body(&dispatch, &attempt);
    let mut mutations = Vec::new();
    let mut value = correct;
    value.attempt_id[0] ^= 1;
    mutations.push(value);
    let mut value = correct;
    value.created_at_ms += 1;
    value.expires_at_ms += 1;
    mutations.push(value);
    let mut value = correct;
    value.native_dispatch_nonce[0] ^= 1;
    mutations.push(value);
    let mut value = correct;
    value.fi_digest[0] ^= 1;
    mutations.push(value);
    for changed in mutations {
        assert!(
            journal
                .retain_permit(&attempt, &dispatch, signed(&dispatch, changed, &key))
                .is_err()
        );
        assert!(journal.permit(&attempt, &dispatch).unwrap().is_none());
    }
    let original = signed(&dispatch, correct, &key);
    let mut corrupted = original.clone();
    let last = corrupted.len() - 1;
    corrupted[last] ^= 1;
    assert!(
        journal
            .retain_permit(&attempt, &dispatch, corrupted)
            .is_err()
    );
    journal
        .retain_permit(&attempt, &dispatch, original)
        .unwrap();
    let mut changed = dispatch.clone();
    changed.request_id[0] ^= 1;
    assert_eq!(journal.permit(&attempt, &changed), Err(Conflict));
}

pub(crate) fn account_request(
    dispatch: &PreKeyDispatchV1,
    attempt: &EnrollmentAttemptV1,
) -> iroha_core_zk::kagemusha_wallet_enrollment_v1::RequestV1 {
    use iroha_core_zk::kagemusha_wallet_enrollment_v1::{
        PlatformEvidenceV1, RequestBodyV1, RequestV1,
    };
    let body = RequestBodyV1 {
        version: 1,
        challenge: attempt.selection().challenge,
        marker: KagemushaWalletMarkerV1::enrollment(
            &attempt.selection().challenge,
            public(&SigningKey::from_slice(&[29; 32]).unwrap()),
        )
        .unwrap(),
        app: dispatch.app.clone(),
        policy: dispatch.policy.clone(),
        account: dispatch.account.clone(),
        asset: dispatch.asset.clone(),
        evidence: norito::encode_canonical(&PlatformEvidenceV1::Apple {
            key_id: [30; 32],
            attestation: b"DATA attestation".to_vec(),
            key_binding_assertion: b"DATA assertion".to_vec(),
        })
        .unwrap(),
    };
    let account = KeyPair::from_seed(vec![4; 32], Algorithm::Ed25519);
    RequestV1 {
        account_signature: iroha_crypto::Signature::try_new(
            account.private_key(),
            &body.account_challenge().unwrap(),
        )
        .unwrap()
        .payload()
        .try_into()
        .unwrap(),
        body,
    }
}

#[test]
fn verification_dispatch_derives_private_original_from_exact_account_signed_request() {
    let (_temp, _parent, mut journal) = initialized();
    let (dispatch, mut attempt, _key) = fixture(&mut journal);
    let request = account_request(&dispatch, &attempt);
    assert_eq!(attempt.worker_configuration(), None);
    let mut forged = request.clone();
    forged.account_signature[0] ^= 1;
    assert!(matches!(
        journal.select_verification(&mut attempt, forged, [31; 32], 2_000),
        Err(Invalid)
    ));
    assert!(matches!(
        journal.select_verification(&mut attempt, request.clone(), [0; 32], 2_000),
        Err(Invalid)
    ));
    let mut changed = request.clone();
    changed.body.challenge.issuer_nonce[0] ^= 1;
    assert!(matches!(
        journal.select_verification(&mut attempt, changed, [31; 32], 2_000),
        Err(Conflict)
    ));
    let packet = journal
        .select_verification(&mut attempt, request.clone(), [31; 32], 2_000)
        .unwrap()
        .into_original();
    let (e5, private, time) = attempt.verification().unwrap();
    assert_eq!(e5, request.encode().unwrap());
    assert_eq!(private, packet);
    assert_eq!(time, 2_000);
    assert_eq!(attempt.worker_configuration(), Some([31; 32]));
    let expected = iroha_core_zk::kagemusha_wallet_enrollment_v1::issuer_worker::VerifierRequestV1::from_prepared(
        request.clone(), &journal.worker_preparation(&attempt, [31; 32]).unwrap(), 2_000,
    ).unwrap();
    assert_eq!(packet, expected.original());
    assert!(matches!(
        journal.select_verification(&mut attempt, request, [31; 32], 2_000),
        Err(Conflict)
    ));
}

#[test]
fn recovery_keeps_original_worker_configuration_time_and_exact_request() {
    let (temp, _parent, mut journal) = initialized();
    let (dispatch, mut attempt, _key) = fixture(&mut journal);
    assert!(matches!(
        journal.retained_worker_request(&attempt, [31; 32]),
        Err(Conflict)
    ));
    let request = account_request(&dispatch, &attempt);
    let expected = journal
        .select_verification(&mut attempt, request, [31; 32], 2_000)
        .unwrap()
        .into_original();
    drop(journal);
    let journal =
        EnrollmentJournalV1::open(&temp.path().join("issuer"), b"approved scope DATA").unwrap();
    let attempt = journal.read(&attempt.selection().key).unwrap().unwrap();
    assert_eq!(attempt.worker_configuration(), Some([31; 32]));
    assert_eq!(
        journal
            .retained_worker_request(&attempt, [31; 32])
            .unwrap()
            .original(),
        expected
    );
    for foreign in [[0; 32], [32; 32]] {
        assert!(matches!(
            journal.retained_worker_request(&attempt, foreign),
            Err(Conflict)
        ));
    }
    let mut changed = attempt.record.clone();
    changed.worker_configuration = [0; 32];
    assert!(matches!(encode(&changed), Err(Invalid)));
    changed = attempt.record.clone();
    // Even semantically equivalent private JSON cannot replace the selected original bytes.
    changed.worker_request.push(b' ');
    journal
        .directory
        .write_atomic(
            filename(&attempt.selection().key).unwrap(),
            &encode(&changed).unwrap(),
            PublishMode::Replace,
        )
        .unwrap();
    assert!(matches!(
        journal.retained_worker_request(&attempt, [31; 32]),
        Err(Conflict)
    ));
    let altered = journal.read(&attempt.selection().key).unwrap().unwrap();
    assert!(matches!(
        journal.retained_worker_request(&altered, [31; 32]),
        Err(Invalid)
    ));
}
