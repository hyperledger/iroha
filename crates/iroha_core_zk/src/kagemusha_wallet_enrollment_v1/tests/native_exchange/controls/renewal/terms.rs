//! Explicit fixture-issued replacement credentials and signed half-open quota windows.
//! These signatures exercise native authority checks, not a remote attestation service.
use super::*;
use p256::ecdsa::{Signature as P256Signature, signature::Signer as _};

fn signature(seed: u8, message: &[u8]) -> KagemushaWalletSignerOutputV1<'static> {
    let value: P256Signature = signing_key(seed).sign(message);
    KagemushaWalletSignerOutputV1::Raw(value.to_bytes().into())
}

pub(super) fn issue(
    body: KagemushaWalletCredentialBodyV1,
    certificate: &KagemushaWalletSignerCertificateV1,
) -> KagemushaWalletCredentialV1 {
    assert_eq!(certificate.body.key, public_key(&signing_key(79)));
    KagemushaWalletCredentialV1::sign(body, certificate, signature(79, &body.signing_message()))
        .unwrap()
}

pub(super) fn renewal(
    previous: &KagemushaWalletCredentialV1,
    certificate: &KagemushaWalletSignerCertificateV1,
    time: u64,
) -> KagemushaWalletCredentialV1 {
    let mut body = previous.body;
    body.renewal_sequence += 1;
    body.issued_at_ms = time;
    body.lease_expires_at_ms = time + 10000;
    // Explicit engineering observation. No Android verifier or remote renewal service
    // is called; immutable enrollment evidence and all authority identity stay exact.
    body.fresh_evidence.time_ms = time;
    body.fresh_evidence.digest = *iroha_crypto::Hash::new(
        format!("engineering-renewal:{}:{time}", body.renewal_sequence).as_bytes(),
    )
    .as_ref();
    body.issuer_certificate = certificate.certificate_digest();
    let next = issue(body, certificate);
    next.validate_replacement_of(previous).unwrap();
    next
}

pub(super) fn windows(
    daily_two_limit: u128,
    monthly_two_limit: u128,
) -> Vec<KagemushaWalletQuotaWindowV1> {
    use KagemushaWalletQuotaWindowKindV1::{Daily, Monthly};
    [
        (Daily, 20000, 21000, 30),
        (Daily, 21000, 22000, daily_two_limit),
        (Daily, 22000, 23000, 80),
        (Monthly, 20000, 22000, 60),
        (Monthly, 22000, 23000, monthly_two_limit),
    ]
    .into_iter()
    .map(
        |(kind, start_ms, end_ms, limit)| KagemushaWalletQuotaWindowV1 {
            kind,
            start_ms,
            end_ms,
            limit,
        },
    )
    .collect()
}

pub(super) fn share(
    credential: &KagemushaWalletCredentialV1,
    certificate: &KagemushaWalletSignerCertificateV1,
    id: u64,
    issued_at_ms: u64,
    windows: Vec<KagemushaWalletQuotaWindowV1>,
) -> KagemushaWalletQuotaShareV1 {
    let body = KagemushaWalletQuotaShareBodyV1 {
        version: 1,
        scheme_id: credential.body.scheme_id,
        asset_digest: credential.body.asset_digest,
        wallet_id: credential.body.wallet_id,
        share_id: id,
        issued_at_ms,
        expires_at_ms: 24000,
        windows_root: kagemusha_wallet_quota_windows_root_v1(&windows).unwrap(),
        window_count: windows.len().try_into().unwrap(),
        signer_certificate: certificate.certificate_digest(),
    };
    KagemushaWalletQuotaShareV1::sign(
        body,
        windows,
        certificate,
        signature(115, &body.signing_message()),
    )
    .unwrap()
}

#[test]
fn fixture_signed_renewal_preserves_enrollment_and_quota_signatures_bind_boundaries() {
    let directory = tempfile::tempdir().unwrap();
    let f = permitted(fixture());
    let device = HostDevice::create(&directory.path().join("wallet"), CONTROL_B_SEED);
    let frames = enrollment::enroll(&device, &f);
    let old: KagemushaWalletCredentialV1 = decode(&frames[0]);
    let certificates: KagemushaWalletCertificateSetV1 = decode(&frames[1]);
    let issuer = certificates
        .certificate(
            &old.body.issuer_certificate,
            KagemushaWalletSignerRoleV1::Enrollment,
        )
        .unwrap();
    let first = renewal(&old, issuer, 20000);
    let second = renewal(&first, issuer, 20950);
    for credential in [&first, &second] {
        credential.verify(&f.config.scheme, issuer).unwrap();
    }
    assert_eq!(
        second.body.enrollment_evidence,
        old.body.enrollment_evidence
    );
    assert_eq!(second.body.payment_key, old.body.payment_key);
    assert_eq!(second.body.wallet_id, old.body.wallet_id);
    assert_eq!(second.body.regulatory_policy, old.body.regulatory_policy);
    assert!(second.validate_replacement_of(&old).is_err());
    let mut body = first.body;
    body.regulatory_policy.time_anchor_max_response_ms += 1;
    let foreign = issue(body, issuer);
    foreign.verify(&f.config.scheme, issuer).unwrap();
    assert!(foreign.validate_replacement_of(&old).is_err());
    let regulator = super::super::terms::certificate(
        &f.config.scheme,
        KagemushaWalletSignerRoleV1::RegulatoryPolicy,
    );
    let original = share(&first, &regulator, 1, 20000, windows(40, 50));
    original.verify(&f.config.scheme, &regulator).unwrap();
    let mut changed = original;
    changed.windows[0].end_ms -= 1;
    assert!(changed.verify(&f.config.scheme, &regulator).is_err());
}
