//! SOURCE DATA controls only. Deterministic software keys are test scalars, never custody,
//! physical attestation, signer installation, Native admission or release qualification.
use super::*;
use crate::kagemusha::kagemusha_wallet_v1::*;
use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};

fn public(signing: &SigningKey) -> KagemushaDevicePublicKeyV1 {
    KagemushaDevicePublicKeyV1::from_sec1_bytes(
        signing.verifying_key().to_encoded_point(false).as_bytes(),
    )
    .unwrap()
}
fn raw(signing: &SigningKey, message: &[u8]) -> KagemushaWalletSignerOutputV1<'static> {
    let signature: Signature = signing.sign(message);
    KagemushaWalletSignerOutputV1::Raw(signature.to_bytes().as_slice().try_into().unwrap())
}
fn fixture(
    role: KagemushaWalletSignerRoleV1,
) -> (
    KagemushaWalletSchemeV1,
    KagemushaWalletSignerCertificateV1,
    SigningKey,
    KagemushaEnrollmentPermitBodyV1,
) {
    let root = SigningKey::from_bytes((&[1; 32]).into()).unwrap();
    let signer = SigningKey::from_bytes((&[2; 32]).into()).unwrap();
    let scheme = KagemushaWalletSchemeV1 {
        version: 1,
        network_id: [11; 32],
        scheme_root_key: public(&root),
        relation_id: kagemusha_wallet_relation_id_v1(
            &[0x21; 32],
            &[0x22; 32],
            &[0x23; 32],
            &[0x24; 32],
            &[0x25; 32],
        ),
        provider_contract: kagemusha_wallet_provider_contract_v1(),
    };
    let certificate_body = KagemushaWalletSignerCertificateBodyV1 {
        version: 1,
        scheme_id: scheme.scheme_id(),
        role,
        key: public(&signer),
        serial: 1,
    };
    let certificate = KagemushaWalletSignerCertificateV1::sign(
        certificate_body,
        &scheme,
        raw(&root, &certificate_body.signing_message()),
    )
    .unwrap();
    let body = KagemushaEnrollmentPermitBodyV1 {
        version: 1,
        platform: KagemushaEnrollmentPermitPlatformV1::Android,
        purpose: KagemushaEnrollmentPermitPurposeV1::Fresh,
        challenge: KagemushaWalletEnrollmentChallengeV1 {
            version: 1,
            scheme_id: scheme.scheme_id(),
            asset_digest: [3; 32],
            account_digest: [4; 32],
            app_policy: [5; 32],
            enrollment_policy: [6; 32],
            issuer_nonce: [7; 32],
        },
        network_id: scheme.network_id,
        manifest_digest: [8; 32],
        release_digest: [9; 32],
        service_origin_digest: [10; 32],
        fi_digest: [12; 32],
        actor_digest: [13; 32],
        attempt_id: [14; 32],
        client_nonce: [15; 32],
        native_dispatch_nonce: [16; 32],
        originals_digest: [17; 32],
        enrollment_certificate: certificate.certificate_digest(),
        created_at_ms: 1000,
        expires_at_ms: 121_000,
        observed_at_ms: 2000,
    };
    (scheme, certificate, signer, body)
}
fn signed(
    scheme: &KagemushaWalletSchemeV1,
    certificate: &KagemushaWalletSignerCertificateV1,
    signer: &SigningKey,
    body: &KagemushaEnrollmentPermitBodyV1,
) -> KagemushaEnrollmentPermitV1 {
    let signature: Signature = signer.sign(&body.signing_message().unwrap());
    KagemushaEnrollmentPermitV1::from_issuer_der(
        *body,
        scheme,
        certificate,
        signature.to_der().as_bytes(),
    )
    .unwrap()
}

#[test]
fn canonical_roundtrip_both_platforms_and_dispatch_roles() {
    let (scheme, certificate, signer, original) = fixture(KagemushaWalletSignerRoleV1::Enrollment);
    for platform in [
        KagemushaEnrollmentPermitPlatformV1::Android,
        KagemushaEnrollmentPermitPlatformV1::Apple,
    ] {
        for purpose in [
            KagemushaEnrollmentPermitPurposeV1::Fresh,
            KagemushaEnrollmentPermitPurposeV1::Resume,
        ] {
            let value = signed(
                &scheme,
                &certificate,
                &signer,
                &KagemushaEnrollmentPermitBodyV1 {
                    platform,
                    purpose,
                    ..original
                },
            );
            let bytes = value.encode_canonical().unwrap();
            assert_eq!(
                KagemushaEnrollmentPermitV1::decode_canonical(&bytes, &scheme, &certificate)
                    .unwrap(),
                value
            );
            assert_eq!(
                norito::decode_canonical::<KagemushaEnrollmentPermitBodyV1>(
                    &norito::encode_canonical(&value.body).unwrap()
                )
                .unwrap(),
                value.body
            );
        }
    }
}
#[test]
fn exact_new_transcript_and_message_are_distinct_from_certificate_domain() {
    let (_, certificate, _, body) = fixture(KagemushaWalletSignerRoleV1::Enrollment);
    let bytes = body.transcript().unwrap();
    assert_eq!(bytes.len(), 574);
    assert_eq!(&bytes[..4], &[1, 0, 1, 1]);
    assert_eq!(&bytes[4..198], &body.challenge.transcript());
    assert_eq!(
        &bytes[550..],
        &[1000u64, 121_000, 2000]
            .into_iter()
            .flat_map(u64::to_le_bytes)
            .collect::<Vec<_>>()
    );
    assert_ne!(
        body.signing_message().unwrap(),
        certificate.body.signing_message()
    );
}
#[test]
fn fresh_retry_has_actual_observation_and_never_extends_original_window() {
    let (_, _, _, mut body) = fixture(KagemushaWalletSignerRoleV1::Enrollment);
    assert!(body.validate().is_ok()); // Fresh observed is2000, original created is1000.
    body.observed_at_ms = body.expires_at_ms;
    assert!(body.validate().is_err());
    body.observed_at_ms = body.created_at_ms - 1;
    assert!(body.validate().is_err());
    body.observed_at_ms = body.created_at_ms;
    assert!(body.validate().is_ok());
    body.created_at_ms = 0;
    assert!(body.validate().is_err());
    let (_, _, _, mut body) = fixture(KagemushaWalletSignerRoleV1::Enrollment);
    body.version = 2;
    assert!(body.validate().is_err());
    body.version = 1;
    body.native_dispatch_nonce = [0; 32];
    assert!(body.validate().is_err());
}
#[test]
fn every_signed_identity_nonce_and_time_change_rejects_original_signature() {
    let (scheme, certificate, signer, body) = fixture(KagemushaWalletSignerRoleV1::Enrollment);
    let value = signed(&scheme, &certificate, &signer, &body);
    let mut changes = Vec::new();
    macro_rules! change {
        ($field:ident) => {{
            let mut v = value;
            v.body.$field[0] ^= 1;
            changes.push(v);
        }};
    }
    let mut v = value;
    v.body.purpose = KagemushaEnrollmentPermitPurposeV1::Resume;
    changes.push(v);
    let mut other = value;
    other.body.platform = KagemushaEnrollmentPermitPlatformV1::Apple;
    changes.push(other);
    change!(network_id);
    change!(manifest_digest);
    change!(release_digest);
    change!(service_origin_digest);
    change!(fi_digest);
    change!(actor_digest);
    change!(attempt_id);
    change!(client_nonce);
    change!(native_dispatch_nonce);
    change!(originals_digest);
    change!(enrollment_certificate);
    for select in 0..3 {
        let mut v = value;
        match select {
            0 => v.body.created_at_ms += 1,
            1 => v.body.expires_at_ms += 1,
            _ => v.body.observed_at_ms += 1,
        }
        changes.push(v);
    }
    for select in 0..6 {
        let mut v = value;
        match select {
            0 => v.body.challenge.scheme_id[0] ^= 1,
            1 => v.body.challenge.asset_digest[0] ^= 1,
            2 => v.body.challenge.account_digest[0] ^= 1,
            3 => v.body.challenge.app_policy[0] ^= 1,
            4 => v.body.challenge.enrollment_policy[0] ^= 1,
            _ => v.body.challenge.issuer_nonce[0] ^= 1,
        }
        changes.push(v);
    }
    for changed in changes {
        assert!(changed.verify(&scheme, &certificate).is_err());
    }
}
#[test]
fn rooted_wrong_role_and_wrong_message_do_not_authorize_pre_key() {
    let (scheme, certificate, signer, body) = fixture(KagemushaWalletSignerRoleV1::Enrollment);
    let value = signed(&scheme, &certificate, &signer, &body);
    let (_, wrong_role, _, _) = fixture(KagemushaWalletSignerRoleV1::RegulatoryPolicy);
    assert!(value.verify(&scheme, &wrong_role).is_err());
    let signature: Signature = signer.sign(&certificate.body.signing_message());
    assert!(
        KagemushaEnrollmentPermitV1::from_issuer_der(
            body,
            &scheme,
            &certificate,
            signature.to_der().as_bytes()
        )
        .is_err()
    );
    let other = SigningKey::from_bytes((&[3; 32]).into()).unwrap();
    let signature: Signature = other.sign(&body.signing_message().unwrap());
    assert!(
        KagemushaEnrollmentPermitV1::from_issuer_der(
            body,
            &scheme,
            &certificate,
            signature.to_der().as_bytes()
        )
        .is_err()
    );
}
#[test]
fn truncated_oversized_and_trailing_canonical_originals_refuse() {
    let (scheme, certificate, signer, body) = fixture(KagemushaWalletSignerRoleV1::Enrollment);
    let bytes = signed(&scheme, &certificate, &signer, &body)
        .encode_canonical()
        .unwrap();
    for end in 0..bytes.len() {
        assert!(
            KagemushaEnrollmentPermitV1::decode_canonical(&bytes[..end], &scheme, &certificate)
                .is_err()
        );
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(
        KagemushaEnrollmentPermitV1::decode_canonical(&trailing, &scheme, &certificate).is_err()
    );
    assert!(
        KagemushaEnrollmentPermitV1::decode_canonical(&vec![0; 2049], &scheme, &certificate)
            .is_err()
    );
}
#[test]
fn scope_roles_and_original_frame_order_are_separate_and_bounded() {
    use KagemushaEnrollmentPermitScopeRoleV1 as R;
    assert_ne!(
        kagemusha_enrollment_permit_scope_digest_v1(R::Fi, b"same").unwrap(),
        kagemusha_enrollment_permit_scope_digest_v1(R::Actor, b"same").unwrap()
    );
    assert!(kagemusha_enrollment_permit_scope_digest_v1(R::Fi, b"").is_err());
    assert!(kagemusha_enrollment_permit_scope_digest_v1(R::Release, &vec![1; 16385]).is_err());
    let originals: [&[u8]; 7] = [
        b"E1",
        b"Scheme",
        b"App",
        b"Enrollment",
        b"Certificate",
        b"Account",
        b"Asset",
    ];
    let digest = kagemusha_enrollment_permit_originals_digest_v1(originals).unwrap();
    let mut reordered = originals;
    reordered.swap(0, 1);
    assert_ne!(
        digest,
        kagemusha_enrollment_permit_originals_digest_v1(reordered).unwrap()
    );
    let mut missing = originals;
    missing[6] = b"";
    assert!(kagemusha_enrollment_permit_originals_digest_v1(missing).is_err());
}
