//! Signed engineering policy originals used only by the genuine installed-proof journey.
use super::*;
use p256::ecdsa::{Signature as P256Signature, signature::Signer as _};

const REGULATOR: u8 = 115;
const TIME_SIGNER: u8 = 116;

fn signed(seed: u8, message: &[u8]) -> KagemushaWalletSignerOutputV1<'static> {
    let signature: P256Signature = signing_key(seed).sign(message);
    KagemushaWalletSignerOutputV1::Raw(signature.to_bytes().into())
}

pub(super) fn certificate(
    scheme: &KagemushaWalletSchemeV1,
    role: KagemushaWalletSignerRoleV1,
) -> KagemushaWalletSignerCertificateV1 {
    let seed = match role {
        KagemushaWalletSignerRoleV1::RegulatoryPolicy => REGULATOR,
        KagemushaWalletSignerRoleV1::TimeAnchor => TIME_SIGNER,
        _ => panic!("only the two explicit engineering policy roles"),
    };
    let body = KagemushaWalletSignerCertificateBodyV1 {
        version: 1,
        scheme_id: scheme.scheme_id(),
        role,
        key: public_key(&signing_key(seed)),
        serial: u64::from(seed),
    };
    let result =
        KagemushaWalletSignerCertificateV1::sign(body, scheme, signed(17, &body.signing_message()))
            .unwrap();
    result.verify_role(scheme, role).unwrap();
    result
}

pub(super) fn policy(
    certificate: &KagemushaWalletSignerCertificateV1,
    asset: [u8; 32],
    epoch: u64,
    mask: u32,
) -> KagemushaWalletSchemePolicyV1 {
    let body = KagemushaWalletSchemePolicyBodyV1 {
        version: 1,
        scheme_id: certificate.body.scheme_id,
        asset_digest: asset,
        policy_epoch: epoch,
        enabled_controls: mask,
        fee_schedule: [0; 32],
        signer_certificate: certificate.certificate_digest(),
    };
    KagemushaWalletSchemePolicyV1::sign(
        body,
        certificate,
        signed(REGULATOR, &body.signing_message()),
    )
    .unwrap()
}

pub(super) fn blacklist(
    certificate: &KagemushaWalletSignerCertificateV1,
    version: u64,
    issued: u64,
    blocked: Option<[u8; 32]>,
) -> KagemushaWalletBlacklistV1 {
    let entries = blocked
        .into_iter()
        .map(|account_digest| KagemushaWalletBlacklistEntryV1 { account_digest })
        .collect::<Vec<_>>();
    let body = KagemushaWalletBlacklistBodyV1 {
        version: 1,
        scheme_id: certificate.body.scheme_id,
        list_version: version,
        issued_at_ms: issued,
        entry_count: entries.len().try_into().unwrap(),
        entries_root: kagemusha_wallet_blacklist_root_v1(&entries).unwrap(),
        signer_certificate: certificate.certificate_digest(),
    };
    KagemushaWalletBlacklistV1::sign(
        body,
        entries,
        certificate,
        signed(REGULATOR, &body.signing_message()),
    )
    .unwrap()
}

pub(super) fn quota(
    certificate: &KagemushaWalletSignerCertificateV1,
    asset: [u8; 32],
    wallet: [u8; 32],
    id: u64,
    limit: u128,
) -> KagemushaWalletQuotaShareV1 {
    // Both supported window kinds are active. Identity/end stay fixed on refresh;
    // a new signed limit must preserve the genuine previously consumed quota.
    let windows = KagemushaWalletQuotaWindowKindV1::ALL
        .into_iter()
        .map(|kind| KagemushaWalletQuotaWindowV1 {
            kind,
            start_ms: 3000,
            end_ms: 30000,
            limit,
        })
        .collect::<Vec<_>>();
    let body = KagemushaWalletQuotaShareBodyV1 {
        version: 1,
        scheme_id: certificate.body.scheme_id,
        asset_digest: asset,
        wallet_id: wallet,
        share_id: id,
        issued_at_ms: 3000,
        expires_at_ms: 30000,
        windows_root: kagemusha_wallet_quota_windows_root_v1(&windows).unwrap(),
        window_count: windows.len().try_into().unwrap(),
        signer_certificate: certificate.certificate_digest(),
    };
    KagemushaWalletQuotaShareV1::sign(
        body,
        windows,
        certificate,
        signed(REGULATOR, &body.signing_message()),
    )
    .unwrap()
}

pub(super) fn anchor(
    certificate: &KagemushaWalletSignerCertificateV1,
    wallet: [u8; 32],
    nonce: [u8; 32],
    time: u64,
) -> KagemushaWalletTimeAnchorV1 {
    let body = KagemushaWalletTimeAnchorBodyV1 {
        version: 1,
        scheme_id: certificate.body.scheme_id,
        wallet_id: wallet,
        nonce,
        issuer_time_ms: time,
        signer_certificate: certificate.certificate_digest(),
    };
    KagemushaWalletTimeAnchorV1::sign(
        body,
        certificate,
        signed(TIME_SIGNER, &body.signing_message()),
    )
    .unwrap()
}

#[test]
fn controls_signatures_bind_masks_lists_both_quota_windows_and_anchor_nonce() {
    let f = permitted(fixture());
    f.config.policy.validate().unwrap();
    let scheme = &f.config.scheme;
    let regulator = certificate(scheme, KagemushaWalletSignerRoleV1::RegulatoryPolicy);
    let time = certificate(scheme, KagemushaWalletSignerRoleV1::TimeAnchor);
    for mask in 0..=ALL {
        let original = policy(&regulator, f.asset.asset_digest(), 1, mask);
        original.verify(scheme, &regulator).unwrap();
        let mut changed = original;
        changed.body.enabled_controls ^= 1;
        assert!(changed.verify(scheme, &regulator).is_err());
    }
    let mut list = blacklist(&regulator, 1, 3000, Some(f.challenge.account_digest));
    list.verify(scheme, &regulator).unwrap();
    assert!(list.contains(&f.challenge.account_digest));
    list.body.list_version += 1;
    assert!(list.verify(scheme, &regulator).is_err());
    let share = quota(&regulator, f.asset.asset_digest(), [9; 32], 1, 40);
    share.verify(scheme, &regulator).unwrap();
    assert_eq!(share.windows.len(), 2);
    assert_eq!(
        share.windows[0].kind,
        KagemushaWalletQuotaWindowKindV1::Daily
    );
    assert_eq!(
        share.windows[1].kind,
        KagemushaWalletQuotaWindowKindV1::Monthly
    );
    let mut changed = share;
    changed.windows[0].limit += 1;
    assert!(changed.verify(scheme, &regulator).is_err());
    let mut clock = anchor(&time, [9; 32], [8; 32], 3000);
    clock.verify(scheme, &time).unwrap();
    clock.body.nonce[0] ^= 1;
    assert!(clock.verify(scheme, &time).is_err());
}
