//! Fresh permitted E6 issued before admission; retained default credentials are never relabelled.
use super::*;

pub(super) fn enroll(device: &HostDevice, f: &Fixture) -> [Vec<u8>; 4] {
    let mut owner: HostEnrollment = EnrollmentOwnerV1::new(
        device.provider(f.config.scheme.scheme_id()),
        f.config.clone(),
    )
    .unwrap_or_else(|(_, error)| panic!("{error}"));
    let dispatch = PreKeyDispatchV1::decode(
        &owner
            .begin(
                &[11; 32],
                &norito::encode_canonical(&f.account).unwrap(),
                &norito::encode_canonical(&f.asset).unwrap(),
            )
            .unwrap(),
    )
    .unwrap();
    let challenge = owner
        .accept_permit(&permit(f, &dispatch).encode_canonical().unwrap())
        .unwrap();
    assert!(matches!(
        owner.authorize(&sign(f, &challenge)).unwrap(),
        EnrollmentProgressV1::Evidence { .. }
    ));
    let RequestPreparationV1::AccountChallenge(challenge) =
        owner.prepare_request(&f.evidence).unwrap()
    else {
        panic!("fresh E5 challenge")
    };
    let request = RequestV1::decode(&owner.retain_request(&sign(f, &challenge)).unwrap()).unwrap();
    owner
        .accept_credential(&controlled_result(f, &request).encode().unwrap())
        .unwrap();
    let frames = owner.open_originals().unwrap();
    drop(owner);
    frames
}

fn controlled_result(f: &Fixture, request: &RequestV1) -> ResultV1 {
    use p256::ecdsa::{Signature as P256Signature, signature::Signer as _};
    fn output(
        key: &p256::ecdsa::SigningKey,
        message: &[u8],
    ) -> KagemushaWalletSignerOutputV1<'static> {
        let signed: P256Signature = key.sign(message);
        KagemushaWalletSignerOutputV1::Raw(signed.to_bytes().into())
    }
    let root = signing_key(17);
    let issuer = signing_key(79);
    let certificate_body = KagemushaWalletSignerCertificateBodyV1 {
        version: 1,
        scheme_id: f.config.scheme.scheme_id(),
        role: KagemushaWalletSignerRoleV1::Enrollment,
        key: public_key(&issuer),
        serial: 1,
    };
    let certificate = KagemushaWalletSignerCertificateV1::sign(
        certificate_body,
        &f.config.scheme,
        output(&root, &certificate_body.signing_message()),
    )
    .unwrap();
    let evidence = IssuerEvidenceV1::Android {
        certificates: vec![b"original leaf".to_vec(), b"original CA".to_vec()],
    };
    let kind = KagemushaWalletEvidenceKindV1::AndroidKeyMintTee;
    let event = KagemushaWalletEvidenceV1 {
        digest: evidence.digest(&request.body, kind).unwrap(),
        time_ms: 1000,
        facts: KAGEMUSHA_WALLET_ANDROID_REQUIRED_FACTS_V1,
        os_patch_level: 202_608,
        vendor_patch_level: 202_608,
        boot_patch_level: 202_608,
    };
    let body = KagemushaWalletCredentialBodyV1 {
        version: 1,
        scheme_id: f.config.scheme.scheme_id(),
        asset_digest: f.asset.asset_digest(),
        wallet_id: request.body.marker.wallet_id,
        account_digest: f.challenge.account_digest,
        payment_key: request.body.marker.payment_key,
        provider_contract: f.config.scheme.provider_contract,
        evidence_kind: kind,
        enrollment_evidence: event,
        fresh_evidence: event,
        app_policy: f.challenge.app_policy,
        regulatory_policy: f.config.policy.regulatory_policy,
        enrollment_id: f.challenge.enrollment_id(&request.body.marker.payment_key),
        issued_at_ms: 2000,
        renewal_sequence: 0,
        lease_expires_at_ms: f.config.policy.lease_expires_at(2000).unwrap(),
        issuer_certificate: certificate.certificate_digest(),
    };
    let credential = KagemushaWalletCredentialV1::sign(
        body,
        &certificate,
        output(&issuer, &body.signing_message()),
    )
    .unwrap();
    ResultV1 {
        version: 1,
        credential: credential.to_canonical_bytes().unwrap(),
        certificates: norito::encode_canonical(
            &KagemushaWalletCertificateSetV1::new(vec![certificate]).unwrap(),
        )
        .unwrap(),
        evidence,
    }
}
#[test]
fn fresh_permitted_enrollment_binds_lease_and_reopens_exact_originals() {
    let root = tempfile::tempdir().unwrap();
    let f = permitted(fixture());
    let device = HostDevice::create(&root.path().join("wallet"), CONTROL_A_SEED);
    let frames = enroll(&device, &f);
    let credential =
        KagemushaWalletCredentialV1::decode_canonical(&frames[0], &f.config.scheme.scheme_id())
            .unwrap();
    let certificates: KagemushaWalletCertificateSetV1 = decode(&frames[1]);
    let issuer = certificates
        .certificate(
            &credential.body.issuer_certificate,
            KagemushaWalletSignerRoleV1::Enrollment,
        )
        .unwrap();
    credential.verify(&f.config.scheme, issuer).unwrap();
    assert_eq!(
        credential.body.regulatory_policy,
        f.config.policy.regulatory_policy
    );
    assert_eq!(credential.body.regulatory_policy.permitted_controls, ALL);
    assert_eq!(credential.body.lease_expires_at_ms, LEASE_EXPIRES);
    assert_eq!(credential.body.renewal_sequence, 0);
    let counts = device
        .platform
        .with(|state| (state.generate_calls, state.sign_calls));
    let mut owner: HostEnrollment = EnrollmentOwnerV1::new(
        device.provider(f.config.scheme.scheme_id()),
        f.config.clone(),
    )
    .unwrap_or_else(|(_, error)| panic!("{error}"));
    assert_eq!(owner.open_originals().unwrap(), frames);
    assert_eq!(
        device
            .platform
            .with(|state| (state.generate_calls, state.sign_calls)),
        counts
    );
}
