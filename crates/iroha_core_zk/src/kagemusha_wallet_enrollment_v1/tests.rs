//! Account/original custody tests using the explicit provider simulator; no device or issuer attestation claim.
use super::test_support::{DeviceV1, FakePlatformV1, public_key, signing_key, test_options};
use super::*;
use crate::kagemusha_wallet_enrollment_v1::*;
use iroha_crypto::{Algorithm, Hash, KeyPair, Signature};
use iroha_data_model::{
    account::AccountId, asset::AssetDefinitionId, kagemusha::*, nexus::AxtAssetIncarnationV1,
};
use sha2::Sha256;

type Owner = EnrollmentOwnerV1<KagemushaWalletSimFsV1, FakePlatformV1>;
#[path = "tests/multischeme_custody.rs"]
mod multischeme_custody;
#[path = "tests/native_exchange.rs"]
mod native_exchange;
struct Fixture {
    config: EnrollmentConfigV1,
    challenge: KagemushaWalletEnrollmentChallengeV1,
    account_key: KeyPair,
    account: AccountId,
    asset: KagemushaWalletAssetScopeV1,
    evidence: Vec<u8>,
}
fn fixture() -> Fixture {
    let scheme = KagemushaWalletSchemeV1 {
        version: 1,
        network_id: *Hash::new(b"enrollment component network").as_ref(),
        scheme_root_key: public_key(&signing_key(17)),
        relation_id: [23; 32],
        provider_contract: kagemusha_wallet_provider_contract_v1(),
    };
    let asset = KagemushaWalletAssetScopeV1::new(
        AssetDefinitionId::from_uuid_bytes([
            0x2f, 0x17, 0xc7, 0x24, 0x66, 0xf8, 0x4a, 0x4b, 0xb8, 0xa8, 0xe2, 0x48, 0x84, 0xfd,
            0xcd, 0x2f,
        ])
        .unwrap(),
        &AxtAssetIncarnationV1::try_from_bytes(*Hash::new(b"enrollment component asset").as_ref())
            .unwrap(),
        2,
    )
    .unwrap();
    let account_key = KeyPair::from_seed(vec![41; 32], Algorithm::Ed25519);
    let account = AccountId::new(account_key.public_key().clone());
    let app = KagemushaWalletAppPolicyV1 {
        version: 1,
        scheme_id: scheme.scheme_id(),
        identity: KagemushaWalletAppIdentityV1::Android {
            package_name: "org.example.wallet".into(),
            minimum_package_version: 7,
            signer_set: vec![[5; 32]],
        },
    };
    // Opaque DATA originals test byte custody only; no attestation verifier admits these.
    let policy = KagemushaWalletEnrollmentPolicyV1 {
        version: 1,
        scheme_id: scheme.scheme_id(),
        asset_digest: asset.asset_digest(),
        app_policy: app.policy_digest().unwrap(),
        platform: KagemushaWalletEnrollmentPlatformV1::Android {
            root_set: vec![KagemushaWalletAndroidRootV1 {
                family: KagemushaWalletAndroidRootFamilyV1::GoogleRsa,
                spki_sha256: *Hash::new(b"component root key").as_ref(),
                revocation_source: KagemushaWalletRevocationSourceV1::GoogleAttestationStatus,
            }],
            patch_floor_yyyymm: 202_608,
        },
        regulatory_policy: KagemushaWalletRegulatoryPolicyV1::default(),
        challenge_lifetime_ms: 120_000,
        attestation_lease_lifetime_ms: 0,
    };
    let challenge = KagemushaWalletEnrollmentChallengeV1 {
        version: 1,
        scheme_id: scheme.scheme_id(),
        asset_digest: asset.asset_digest(),
        account_digest: kagemusha_wallet_account_digest_v1(&account).unwrap(),
        app_policy: app.policy_digest().unwrap(),
        enrollment_policy: policy.policy_digest().unwrap(),
        issuer_nonce: [47; 32],
    };
    let evidence = norito::encode_canonical(&PlatformEvidenceV1::Android {
        certificates: vec![b"original leaf".to_vec(), b"original CA".to_vec()],
    })
    .unwrap();
    let enrollment_certificate = enrollment_certificate(&scheme);
    Fixture {
        config: EnrollmentConfigV1 {
            installation: crate::kagemusha_wallet_artifacts_v1::InstallationV1 {
                scheme_id: scheme.scheme_id(),
                manifest_digest: [29; 32],
            },
            enrollment_certificate,
            service_origin: b"https://issuer.example".to_vec(),
            fi: b"approved FI".to_vec(),
            actor: b"authenticated account actor".to_vec(),
            release: b"approved release".to_vec(),
            session_valid_from_ms: 0,
            session_expires_at_ms: 600_000,
            scheme,
            app,
            policy,
            attestation_root_der: None,
        },
        challenge,
        account_key,
        account,
        asset,
        evidence,
    }
}
fn owner(f: &Fixture, d: &DeviceV1) -> Owner {
    let provider = KagemushaWalletProviderV1::open(
        d.fs.clone(),
        d.platform.clone(),
        f.config.scheme.scheme_id(),
        test_options(),
    )
    .unwrap();
    EnrollmentOwnerV1::new(provider, f.config.clone())
        .unwrap_or_else(|(_, error)| panic!("{error}"))
}
fn enrollment_certificate(scheme: &KagemushaWalletSchemeV1) -> KagemushaWalletSignerCertificateV1 {
    use p256::ecdsa::{Signature as P256Signature, signature::Signer as _};
    let body = KagemushaWalletSignerCertificateBodyV1 {
        version: 1,
        scheme_id: scheme.scheme_id(),
        role: KagemushaWalletSignerRoleV1::Enrollment,
        key: public_key(&signing_key(79)),
        serial: 1,
    };
    let signature: P256Signature = signing_key(17).sign(&body.signing_message());
    KagemushaWalletSignerCertificateV1::sign(
        body,
        scheme,
        KagemushaWalletSignerOutputV1::Raw(signature.to_bytes().into()),
    )
    .unwrap()
}
fn permit(f: &Fixture, dispatch: &PreKeyDispatchV1) -> KagemushaEnrollmentPermitV1 {
    use p256::ecdsa::{Signature as P256Signature, signature::Signer as _};
    let previous = dispatch.previous_permit.as_ref().map(|bytes| {
        KagemushaEnrollmentPermitV1::decode_canonical(
            bytes,
            &f.config.scheme,
            &f.config.enrollment_certificate,
        )
        .unwrap()
    });
    let challenge = previous.as_ref().map_or(f.challenge, |p| p.body.challenge);
    let body = KagemushaEnrollmentPermitBodyV1 {
        version: 1,
        platform: dispatch.platform,
        purpose: dispatch.purpose,
        challenge,
        network_id: f.config.scheme.network_id,
        manifest_digest: dispatch.manifest_digest,
        release_digest: dispatch.release_digest,
        service_origin_digest: dispatch.service_origin_digest,
        fi_digest: dispatch.fi_digest,
        actor_digest: dispatch.actor_digest,
        attempt_id: previous.as_ref().map_or([31; 32], |p| p.body.attempt_id),
        client_nonce: dispatch.client_nonce,
        native_dispatch_nonce: dispatch.native_dispatch_nonce,
        originals_digest: dispatch.originals_digest(&challenge).unwrap(),
        enrollment_certificate: f.config.enrollment_certificate.certificate_digest(),
        created_at_ms: 1000,
        expires_at_ms: 1000 + f.config.policy.challenge_lifetime_ms,
        observed_at_ms: 2000,
    };
    let signature: P256Signature = signing_key(79).sign(&body.signing_message().unwrap());
    KagemushaEnrollmentPermitV1::from_issuer_der(
        body,
        &f.config.scheme,
        &f.config.enrollment_certificate,
        signature.to_der().as_bytes(),
    )
    .unwrap()
}
fn dispatch(f: &Fixture, owner: &mut Owner) -> PreKeyDispatchV1 {
    PreKeyDispatchV1::decode(
        &owner
            .begin(
                &[11; 32],
                &norito::encode_canonical(&f.account).unwrap(),
                &norito::encode_canonical(&f.asset).unwrap(),
            )
            .unwrap(),
    )
    .unwrap()
}
fn begin(f: &Fixture, owner: &mut Owner) -> [u8; 32] {
    let dispatch = dispatch(f, owner);
    owner
        .accept_permit(&permit(f, &dispatch).encode_canonical().unwrap())
        .unwrap()
}

fn sign(f: &Fixture, message: &[u8]) -> Vec<u8> {
    Signature::try_new(f.account_key.private_key(), message)
        .unwrap()
        .payload()
        .to_vec()
}
fn enrolled(f: &Fixture, d: &DeviceV1) -> Owner {
    let mut owner = owner(f, d);
    let message = begin(f, &mut owner);
    assert!(matches!(
        owner.authorize(&sign(f, &message)).unwrap(),
        EnrollmentProgressV1::Evidence { .. }
    ));
    owner
}
fn request(f: &Fixture, owner: &mut Owner) -> Vec<u8> {
    let RequestPreparationV1::AccountChallenge(message) =
        owner.prepare_request(&f.evidence).unwrap()
    else {
        panic!("fresh challenge")
    };
    owner.retain_request(&sign(f, &message)).unwrap()
}
#[test]
fn enrollment_owner_requires_exact_account_before_hardware_and_consumes_failed_challenge() {
    let f = fixture();
    let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 53);
    let mut owner = owner(&f, &d);
    let first = begin(&f, &mut owner);
    assert!(owner.authorize(&[0; 64]).is_err());
    assert!(owner.authorize(&sign(&f, &first)).is_err());
    d.platform.with(|s| assert_eq!(s.generate_calls, 0));
    let second = begin(&f, &mut owner);
    assert_ne!(first, second);
    assert!(matches!(
        owner.authorize(&sign(&f, &second)).unwrap(),
        EnrollmentProgressV1::Evidence { .. }
    ));
    d.platform.with(|s| {
        assert_eq!(s.generate_calls, 1);
        assert_eq!(
            s.last_generation.unwrap().profile,
            KagemushaWalletKeyProfileV1::SecureElementOrTee
        );
    });
    let third = begin(&f, &mut owner);
    owner.authorize(&sign(&f, &third)).unwrap();
    d.platform.with(|s| assert_eq!(s.generate_calls, 1));
}
#[test]
fn enrollment_owner_retains_exact_e5_across_restart_and_refuses_changed_signature_originals() {
    let f = fixture();
    let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 59);
    let mut owner = enrolled(&f, &d);
    assert!(owner.retained_request().unwrap().is_none());
    assert!(owner.retained_result().unwrap().is_none());
    let RequestPreparationV1::AccountChallenge(message) =
        owner.prepare_request(&f.evidence).unwrap()
    else {
        panic!("challenge")
    };
    assert!(owner.retain_request(&[0; 64]).is_err());
    let original = owner.retain_request(&sign(&f, &message)).unwrap();
    assert_eq!(owner.retained_request().unwrap(), Some(original.clone()));
    assert!(owner.retained_result().unwrap().is_none());
    let decoded = RequestV1::decode(&original).unwrap();
    assert_eq!(decoded.body.evidence, f.evidence);
    let mut changed = decoded.clone();
    changed.body.marker.payment_key = public_key(&signing_key(61));
    assert!(changed.validate().is_err());
    let mut trailing = original.clone();
    trailing.push(0);
    assert!(RequestV1::decode(&trailing).is_err());
    drop(owner.into_provider());
    let mut recovered = enrolled(&f, &d);
    assert_eq!(
        recovered.retained_request().unwrap(),
        Some(original.clone())
    );
    assert!(
        matches!(recovered.prepare_request(b"changed").unwrap(),RequestPreparationV1::Retained(bytes) if bytes==original)
    );
    assert_eq!(recovered.retain_request(&[]).unwrap(), original);
    d.platform.with(|s| assert_eq!(s.generate_calls, 1));
}
#[test]
fn enrollment_unavailable_never_becomes_absence_or_a_second_key_attempt() {
    let f = fixture();
    let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 67);
    d.platform
        .with(|s| s.generation_policy = KagemushaWalletKeyGenerationPolicyV1::FreshEnrollmentOnly);
    let mut owner = owner(&f, &d);
    let message = begin(&f, &mut owner);
    d.platform.with(|s| s.generate_unavailable = Some(false));
    assert!(owner.authorize(&sign(&f, &message)).is_err());
    d.platform.with(|s| s.generate_unavailable = None);
    let message = begin(&f, &mut owner);
    assert!(matches!(
        owner.authorize(&sign(&f, &message)),
        Err(Error::Provider(
            KagemushaWalletProviderErrorV1::Unavailable(KagemushaWalletUnavailableV1::Platform(10))
        ))
    ));
    d.platform.with(|s| assert_eq!(s.generate_calls, 1));
    assert!(owner.prepare_request(&f.evidence).is_err());
    assert!(owner.retained_request().is_err());
    assert!(owner.retained_result().is_err());
}
#[test]
fn enrollment_issuer_evidence_digest_is_the_exact_e5_chain_only() {
    let f = fixture();
    let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 71);
    let mut owner = enrolled(&f, &d);
    let requested = RequestV1::decode(&request(&f, &mut owner)).unwrap();
    let proof = IssuerEvidenceV1::Android {
        certificates: vec![b"original leaf".to_vec(), b"original CA".to_vec()],
    };
    for kind in [
        KagemushaWalletEvidenceKindV1::AndroidKeyMintTee,
        KagemushaWalletEvidenceKindV1::AndroidKeyMintStrongBox,
    ] {
        assert_eq!(
            proof.digest(&requested.body, kind).unwrap(),
            kagemusha_wallet_evidence_digest_v1(kind, &[b"original leaf", b"original CA"]).unwrap()
        );
    }
    let kind = KagemushaWalletEvidenceKindV1::AndroidKeyMintTee;
    for change in 0..3 {
        let mut changed = proof.clone();
        let IssuerEvidenceV1::Android { certificates } = &mut changed else {
            unreachable!()
        };
        match change {
            0 => certificates[0][0] ^= 1,
            1 => certificates.push(b"appended original".to_vec()),
            _ => {
                certificates.pop();
            }
        }
        assert!(changed.digest(&requested.body, kind).is_err());
    }
    assert!(
        proof
            .digest(
                &requested.body,
                KagemushaWalletEvidenceKindV1::AppleAppAttest
            )
            .is_err()
    );
}

fn issuer_result(f: &Fixture, request: &RequestV1) -> ResultV1 {
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
        lease_expires_at_ms: 0,
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
fn enrollment_e6_retains_full_signed_result_and_never_recreates_lost_selected_originals() {
    let f = fixture();
    let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 73);
    let mut owner = enrolled(&f, &d);
    let request_bytes = request(&f, &mut owner);
    let requested = RequestV1::decode(&request_bytes).unwrap();
    let result = issuer_result(&f, &requested);
    let bytes = result.encode().unwrap();
    let mut altered = result.clone();
    if let IssuerEvidenceV1::Android { certificates } = &mut altered.evidence {
        certificates[1][0] ^= 1;
    }
    assert!(owner.accept_credential(&altered.encode().unwrap()).is_err());
    assert_eq!(owner.accept_credential(&bytes).unwrap(), bytes);
    assert_eq!(owner.accept_credential(b"wrong retry").unwrap(), bytes);
    let originals = owner.open_originals().unwrap();
    assert_eq!(originals[0], result.credential);
    assert_eq!(originals[1], result.certificates);
    assert_eq!(originals[2], norito::encode_canonical(&f.account).unwrap());
    assert_eq!(originals[3], norito::encode_canonical(&f.asset).unwrap());
    assert_eq!(owner.retained_result().unwrap(), Some(bytes.clone()));
    drop(owner.into_provider());
    // The Native E6 winner survives lost app delivery. This does not request fresh
    // platform evidence or a new issuer permit and never regenerates the selected key.
    let mut reopened = self::owner(&f, &d);
    let resumed = dispatch(&f, &mut reopened);
    assert!(resumed.previous_permit.is_some());
    assert_eq!(reopened.retained_result().unwrap(), Some(bytes.clone()));
    assert_eq!(reopened.open_originals().unwrap(), originals);
    d.platform.with(|s| assert_eq!(s.generate_calls, 1));
    let mut provider = reopened.into_provider();
    let slot = provider.slots().unwrap()[0];
    let key = kagemusha_wallet_provider_digest_v1("enrollment-issuer-result", &request_bytes);
    provider
        .with_archive(&slot, |archive| archive.remove_record(&key))
        .unwrap();
    drop(provider);
    let mut restored = enrolled(&f, &d);
    assert!(restored.accept_credential(&bytes).is_err());
    assert!(restored.open_originals().is_err());
    assert!(restored.retained_result().is_err());
}
#[test]
fn enrollment_approved_native_configuration_cannot_select_an_android_root_original() {
    for substitute in [Some(b"component root original".to_vec()), Some(Vec::new())] {
        let mut f = fixture();
        let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 83);
        let provider = KagemushaWalletProviderV1::open(
            d.fs.clone(),
            d.platform.clone(),
            f.config.scheme.scheme_id(),
            test_options(),
        )
        .unwrap();
        f.config.attestation_root_der = substitute;
        let (provider, error) = match EnrollmentOwnerV1::new(provider, f.config) {
            Ok(_) => panic!("Android root original accepted"),
            Err(parts) => parts,
        };
        assert!(matches!(error, Error::Original("approved root original")));
        assert!(provider.slots().unwrap().is_empty());
        d.platform.with(|s| assert_eq!(s.generate_calls, 0));
    }
}

#[test]
fn enrollment_apple_configuration_requires_its_exact_pinned_root_original() {
    let f = apple_collection_fixture();
    for (root, accepted) in [
        (f.config.attestation_root_der.clone(), true),
        (None, false),
        (Some(Vec::new()), false),
        (Some(b"substituted root".to_vec()), false),
        (Some(vec![1; 16_385]), false),
    ] {
        let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 84);
        let provider = KagemushaWalletProviderV1::open(
            d.fs.clone(),
            d.platform.clone(),
            f.config.scheme.scheme_id(),
            test_options(),
        )
        .unwrap();
        let mut config = f.config.clone();
        config.attestation_root_der = root;
        assert_eq!(EnrollmentOwnerV1::new(provider, config).is_ok(), accepted);
    }
}

#[test]
fn enrollment_owner_refuses_unknown_or_unqualified_vendor_adapter_before_any_challenge() {
    for adapter in ["huawei", "unknown-vendor"] {
        let mut f = fixture();
        let KagemushaWalletEnrollmentPlatformV1::Android { root_set, .. } =
            &mut f.config.policy.platform
        else {
            unreachable!()
        };
        root_set.push(KagemushaWalletAndroidRootV1 {
            family: KagemushaWalletAndroidRootFamilyV1::Vendor {
                adapter_id: adapter.into(),
            },
            spki_sha256: [0xff; 32],
            revocation_source: KagemushaWalletRevocationSourceV1::OperatorDenylist,
        });
        f.config.policy.validate_for_app(&f.config.app).unwrap();
        let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 85);
        let provider = KagemushaWalletProviderV1::open(
            d.fs.clone(),
            d.platform.clone(),
            f.config.scheme.scheme_id(),
            test_options(),
        )
        .unwrap();
        let Err((provider, error)) = EnrollmentOwnerV1::new(provider, f.config) else {
            panic!("{adapter} adapter accepted")
        };
        assert!(matches!(
            error,
            Error::Original("approved Android adapter profile")
        ));
        assert!(provider.slots().unwrap().is_empty());
    }
}

#[test]
fn enrollment_android_chain_and_complete_e6_bounds_cover_exact_maximal_encoding() {
    let f = fixture();
    let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 89);
    let mut owner = enrolled(&f, &d);
    let mut requested = RequestV1::decode(&request(&f, &mut owner)).unwrap();
    // The largest admitted chain: eight certificates totalling 65,536 bytes.
    let certificates =
        vec![vec![7; ANDROID_CHAIN_MAX_BYTES / ANDROID_CHAIN_MAX]; ANDROID_CHAIN_MAX];
    requested.body.evidence = norito::encode_canonical(&PlatformEvidenceV1::Android {
        certificates: certificates.clone(),
    })
    .unwrap();
    assert!(requested.body.evidence.len() <= EVIDENCE_MAX_BYTES);
    PlatformEvidenceV1::decode(&requested.body.evidence, &requested.body.policy).unwrap();
    let kind = KagemushaWalletEvidenceKindV1::AndroidKeyMintTee;
    let evidence = IssuerEvidenceV1::Android {
        certificates: certificates.clone(),
    };
    assert!(evidence.digest(&requested.body, kind).is_ok());
    let result = ResultV1 {
        version: 1,
        credential: vec![1; KAGEMUSHA_WALLET_CREDENTIAL_MAX_BYTES_V1],
        certificates: vec![2; KAGEMUSHA_WALLET_MESSAGE_MAX_BYTES_V1],
        evidence,
    };
    let encoded = result.encode().unwrap();
    eprintln!(
        "ENROLLMENT_BOUND mobile={} result={} limit={RESULT_MAX_BYTES}",
        requested.body.evidence.len(),
        encoded.len()
    );
    assert_eq!(ResultV1::decode(&encoded).unwrap(), result);
    let mut over_total = certificates.clone();
    over_total[0].push(7);
    let one = vec![vec![7; 16]];
    let nine = vec![vec![7; 16]; ANDROID_CHAIN_MAX + 1];
    let oversized = vec![vec![7; ANDROID_CERTIFICATE_MAX_BYTES + 1], vec![7; 16]];
    let empty = vec![vec![7; 16], Vec::new()];
    for chain in [over_total, one, nine, oversized, empty] {
        let bytes = norito::encode_canonical(&PlatformEvidenceV1::Android {
            certificates: chain.clone(),
        })
        .unwrap();
        assert!(PlatformEvidenceV1::decode(&bytes, &requested.body.policy).is_err());
        assert!(
            IssuerEvidenceV1::Android {
                certificates: chain
            }
            .digest(&requested.body, kind)
            .is_err()
        );
    }
}

#[test]
fn enrollment_failed_native_handoff_preserves_exact_private_selection_and_e5() {
    let f = fixture();
    let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 97);
    let mut owner = enrolled(&f, &d);
    let bytes = request(&f, &mut owner);
    let (mut owner, error) =
        match owner.try_handoff::<(), _>(|provider| Err((provider, "loader unavailable"))) {
            Ok(()) => panic!("failed loader admitted"),
            Err(parts) => parts,
        };
    assert_eq!(error, "loader unavailable");
    assert_eq!(owner.retain_request(&[]).unwrap(), bytes);
    d.platform.with(|state| assert_eq!(state.generate_calls, 1));
}

fn resign_permit(
    f: &Fixture,
    body: KagemushaEnrollmentPermitBodyV1,
) -> KagemushaEnrollmentPermitV1 {
    use p256::ecdsa::{Signature as P256Signature, signature::Signer as _};
    let signature: P256Signature = signing_key(79).sign(&body.signing_message().unwrap());
    KagemushaEnrollmentPermitV1::from_issuer_der(
        body,
        &f.config.scheme,
        &f.config.enrollment_certificate,
        signature.to_der().as_bytes(),
    )
    .unwrap()
}
#[test]
fn prekey_cancellation_survives_restart_and_refuses_late_permit_without_key_effects() {
    let f = fixture();
    let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 191);
    let mut current = owner(&f, &d);
    let first = dispatch(&f, &mut current);
    let late = permit(&f, &first).encode_canonical().unwrap();
    assert_eq!(
        current.abandon().unwrap(),
        EnrollmentAbandonmentV1::LocalAbandoned
    );
    assert_eq!(current.abandonment_ledger_instruction().unwrap(), None);
    assert!(current.accept_permit(&late).is_err());
    assert!(current.authorize(&[1; 64]).is_err());
    drop(current);
    let mut current = owner(&f, &d);
    let resumed = dispatch(&f, &mut current);
    assert_eq!(
        resumed.stable_selection().unwrap(),
        first.stable_selection().unwrap()
    );
    assert_eq!(
        current.abandon().unwrap(),
        EnrollmentAbandonmentV1::LocalAbandoned
    );
    assert!(
        current
            .accept_permit(&permit(&f, &resumed).encode_canonical().unwrap())
            .is_err()
    );
    d.platform.with(|state| assert_eq!(state.generate_calls, 0));
    // A different request may start, while the cancelled identity remains terminal.
    current
        .begin(
            &[12; 32],
            &norito::encode_canonical(&f.account).unwrap(),
            &norito::encode_canonical(&f.asset).unwrap(),
        )
        .unwrap();
    assert_eq!(
        current.abandon().unwrap(),
        EnrollmentAbandonmentV1::LocalAbandoned
    );
}

#[test]
fn prekey_cancellation_loses_to_accepted_permit_under_exclusive_owner() {
    let f = fixture();
    let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 199);
    let mut current = owner(&f, &d);
    let first = dispatch(&f, &mut current);
    current
        .accept_permit(&permit(&f, &first).encode_canonical().unwrap())
        .unwrap();
    assert!(current.abandon().is_err());
    drop(current);
    let mut current = owner(&f, &d);
    let resumed = dispatch(&f, &mut current);
    assert_eq!(resumed.purpose, KagemushaEnrollmentPermitPurposeV1::Resume);
    assert!(current.abandonment_ledger_instruction().is_err());
    assert!(
        !d.fs
            .visible_names(&KagemushaWalletCustodyDirV1::root())
            .iter()
            .any(|name| name.ends_with("-cancelled.norito"))
    );
    d.platform.with(|state| assert_eq!(state.generate_calls, 0));
}

#[test]
fn prekey_cancellation_uncertain_publication_is_adopted_before_terminal_retry() {
    let f = fixture();
    let baseline = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 197);
    let mut current = owner(&f, &baseline);
    dispatch(&f, &mut current);
    let start = baseline.fs.steps();
    current.abandon().unwrap();
    let trace = baseline.fs.trace_since(start);
    let rename = trace
        .iter()
        .rposition(|step| *step == KagemushaWalletSimStepV1::RenameNoReplace)
        .unwrap();
    let sync = rename
        + trace[rename..]
            .iter()
            .position(|step| *step == KagemushaWalletSimStepV1::SyncDir)
            .unwrap();
    let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 197);
    let mut current = owner(&f, &d);
    let first = dispatch(&f, &mut current);
    d.fs.inject(
        d.fs.steps() + u64::try_from(sync).unwrap(),
        KagemushaWalletSimFaultV1::Error,
    );
    assert!(current.abandon().is_err());
    d.fs.clear_faults();
    let before = d.fs.steps();
    assert_eq!(
        current.abandon().unwrap(),
        EnrollmentAbandonmentV1::LocalAbandoned
    );
    assert!(
        d.fs.trace_since(before)
            .contains(&KagemushaWalletSimStepV1::SyncDir)
    );
    drop(current);
    d.fs.restart();
    let mut current = owner(&f, &d);
    dispatch(&f, &mut current);
    assert_eq!(
        current.abandon().unwrap(),
        EnrollmentAbandonmentV1::LocalAbandoned
    );
    assert!(
        current
            .accept_permit(&permit(&f, &first).encode_canonical().unwrap())
            .is_err()
    );
    d.platform.with(|state| assert_eq!(state.generate_calls, 0));
}

#[test]
fn prekey_cancellation_refuses_missing_client_corrupt_binding_and_uncertain_publication() {
    let f = fixture();
    for fault in 0..3 {
        let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 193 + fault);
        let mut current = owner(&f, &d);
        let first = dispatch(&f, &mut current);
        let root = KagemushaWalletCustodyDirV1::root();
        let client =
            d.fs.visible_names(&root)
                .into_iter()
                .find(|name| name.ends_with("-client.norito"))
                .unwrap();
        match fault {
            0 => {
                d.fs.unlink(&root, &client).unwrap();
            }
            1 => {
                d.fs.place_unsynced(&root, &client, b"changed client");
            }
            _ => {
                d.fs.inject(d.fs.steps(), KagemushaWalletSimFaultV1::Error);
            }
        }
        assert!(current.abandon().is_err());
        d.fs.clear_faults();
        d.platform.with(|state| assert_eq!(state.generate_calls, 0));
        if fault == 2 {
            dispatch(&f, &mut current);
            current.abandon().unwrap();
            let cancelled =
                d.fs.visible_names(&root)
                    .into_iter()
                    .find(|name| name.ends_with("-cancelled.norito"))
                    .unwrap();
            d.fs.place_unsynced(&root, &cancelled, &[0; 32]);
            assert!(current.abandon().is_err());
            assert!(
                current
                    .accept_permit(&permit(&f, &first).encode_canonical().unwrap())
                    .is_err()
            );
        }
    }
}

#[test]
fn prekey_stable_selection_preserves_originals_and_excludes_only_dispatch_fields() {
    let f = fixture();
    let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 101);
    let mut owner = owner(&f, &d);
    let first = dispatch(&f, &mut owner);
    let original = permit(&f, &first).encode_canonical().unwrap();
    owner.accept_permit(&original).unwrap();
    let resume = dispatch(&f, &mut owner);
    assert_eq!(resume.purpose, KagemushaEnrollmentPermitPurposeV1::Resume);
    assert_eq!(resume.previous_permit.as_ref(), Some(&original));
    assert_ne!(first.native_dispatch_nonce, resume.native_dispatch_nonce);
    assert_eq!(first.client_nonce, resume.client_nonce);
    assert_eq!(
        first.stable_selection().unwrap(),
        resume.stable_selection().unwrap()
    );
    for field in 0..7 {
        let mut changed = first.clone();
        match field {
            0 => changed.request_id[0] ^= 1,
            1 => changed.client_nonce[0] ^= 1,
            2 => changed.manifest_digest[0] ^= 1,
            3 => changed.release_digest[0] ^= 1,
            4 => changed.service_origin_digest[0] ^= 1,
            5 => changed.fi_digest[0] ^= 1,
            _ => changed.actor_digest[0] ^= 1,
        }
        assert_ne!(
            first.stable_selection().unwrap(),
            changed.stable_selection().unwrap()
        );
    }
    let mut invalid = resume;
    invalid.previous_permit = Some(permit(&f, &invalid).encode_canonical().unwrap());
    assert!(
        invalid.validate().is_err(),
        "Resume cannot replace first Fresh permit"
    );
}
#[test]
fn prekey_permit_rejects_wrong_scope_nonce_attempt_and_consumes_failed_dispatch() {
    let f = fixture();
    let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 103);
    let mut owner = owner(&f, &d);
    for field in 0..8 {
        let dispatch = dispatch(&f, &mut owner);
        let mut body = permit(&f, &dispatch).body;
        match field {
            0 => body.native_dispatch_nonce[0] ^= 1,
            1 => body.client_nonce[0] ^= 1,
            2 => body.manifest_digest[0] ^= 1,
            3 => body.release_digest[0] ^= 1,
            4 => body.service_origin_digest[0] ^= 1,
            5 => body.fi_digest[0] ^= 1,
            6 => body.actor_digest[0] ^= 1,
            _ => body.originals_digest[0] ^= 1,
        }
        let wrong = resign_permit(&f, body).encode_canonical().unwrap();
        assert!(owner.accept_permit(&wrong).is_err());
        assert!(
            owner
                .accept_permit(&permit(&f, &dispatch).encode_canonical().unwrap())
                .is_err()
        );
    }
    let first = dispatch(&f, &mut owner);
    let signed = permit(&f, &first).encode_canonical().unwrap();
    let message = owner.accept_permit(&signed).unwrap();
    assert_eq!(owner.accept_permit(&signed).unwrap(), message);
    let resume = dispatch(&f, &mut owner);
    let mut wrong = permit(&f, &resume).body;
    wrong.attempt_id[0] ^= 1;
    assert!(
        owner
            .accept_permit(&resign_permit(&f, wrong).encode_canonical().unwrap())
            .is_err()
    );
    d.platform.with(|state| assert_eq!(state.generate_calls, 0));
}
#[test]
fn prekey_live_exchange_does_not_require_a_readable_custody_boot_identity() {
    let f = fixture();
    let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 106);
    d.platform.with(|state| {
        state.boot = Err(KagemushaWalletUnavailableV1::Io(1));
        state.monotonic = Err(KagemushaWalletUnavailableV1::Io(1));
        state.live_enrollment_native_clock = true;
    });
    let mut current = owner(&f, &d);
    let selected = dispatch(&f, &mut current);
    let original = permit(&f, &selected).encode_canonical().unwrap();
    let message = current.accept_permit(&original).unwrap();
    assert!(matches!(
        current.authorize(&sign(&f, &message)).unwrap(),
        EnrollmentProgressV1::Evidence { .. }
    ));
    let provider = current.into_provider();
    assert!(matches!(
        provider.live_enrollment_reading().unwrap(),
        LiveEnrollmentReadingV1::Native(_)
    ));
    assert_eq!(
        provider.monotonic_reading(),
        Err(KagemushaWalletProviderErrorV1::Unavailable(
            KagemushaWalletUnavailableV1::Io(1)
        ))
    );
    d.platform.with(|state| {
        assert_eq!(state.boot, Err(KagemushaWalletUnavailableV1::Io(1)));
        assert_eq!(state.generate_calls, 1);
        assert_eq!(state.sign_calls, 0);
        assert_eq!(state.delete_calls, 0);
    });
}

#[test]
fn prekey_clock_deadline_is_checked_again_after_account_authorization() {
    for (index, time) in [
        Ok(120_000),
        Ok(999),
        Err(KagemushaWalletUnavailableV1::Busy),
    ]
    .into_iter()
    .enumerate()
    {
        let f = fixture();
        let d = DeviceV1::new(
            KagemushaWalletAnchorPolicyV1::NotRequired,
            107 + index as u8,
        );
        let mut owner = owner(&f, &d);
        let message = begin(&f, &mut owner);
        d.platform.with(|state| state.monotonic = time);
        assert!(owner.authorize(&sign(&f, &message)).is_err());
        d.platform.with(|state| assert_eq!(state.generate_calls, 0));
    }
    let f = fixture();
    let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 113);
    let mut owner = owner(&f, &d);
    let message = begin(&f, &mut owner);
    d.platform
        .with(|state| state.live_enrollment_clock_domain = [99; 32]);
    assert!(owner.authorize(&sign(&f, &message)).is_err());
    d.platform.with(|state| assert_eq!(state.generate_calls, 0));
}
#[test]
fn prekey_elapsed_expiry_after_durable_intent_cannot_reach_hardware_generation() {
    let f = fixture();
    let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 127);
    d.platform.with(|state| {
        state.generation_policy = KagemushaWalletKeyGenerationPolicyV1::FreshEnrollmentOnly
    });
    let mut owner = owner(&f, &d);
    let message = begin(&f, &mut owner);
    // Owner authorization, grant check, begin check, pre-intent check, actual key dispatch.
    d.platform.with(|state| {
        state.monotonic_script = [Ok(1000), Ok(1000), Ok(1000), Ok(1000), Ok(120_000)].into()
    });
    assert!(owner.authorize(&sign(&f, &message)).is_err());
    d.platform.with(|state| assert_eq!(state.generate_calls, 0));
    assert_eq!(
        owner.into_provider().slots().unwrap().len(),
        1,
        "intent was actually retained"
    );
}
#[test]
fn prekey_restart_preserves_client_and_attempt_and_never_recreates_lost_selection() {
    let f = fixture();
    let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 131);
    let mut current = owner(&f, &d);
    let first = dispatch(&f, &mut current);
    let original = permit(&f, &first).encode_canonical().unwrap();
    current.accept_permit(&original).unwrap();
    drop(current.into_provider());
    let mut current = owner(&f, &d);
    let resume = dispatch(&f, &mut current);
    assert_eq!(resume.client_nonce, first.client_nonce);
    assert_eq!(resume.previous_permit, Some(original));
    let message = current
        .accept_permit(&permit(&f, &resume).encode_canonical().unwrap())
        .unwrap();
    current.authorize(&sign(&f, &message)).unwrap();
    let root = KagemushaWalletCustodyDirV1::root();
    let selected =
        d.fs.visible_names(&root)
            .into_iter()
            .find(|name| name.starts_with("prekey-") && name.ends_with("-accepted.norito"))
            .unwrap();
    d.fs.unlink(&root, &selected).unwrap();
    assert!(
        current
            .begin(
                &[11; 32],
                &norito::encode_canonical(&f.account).unwrap(),
                &norito::encode_canonical(&f.asset).unwrap()
            )
            .is_err()
    );
    d.platform.with(|state| assert_eq!(state.generate_calls, 1));
}
#[test]
fn prekey_corrupt_client_and_unavailable_storage_never_generate_replacement_identity() {
    let f = fixture();
    let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 137);
    let mut owner = owner(&f, &d);
    let _ = dispatch(&f, &mut owner);
    let root = KagemushaWalletCustodyDirV1::root();
    let client =
        d.fs.visible_names(&root)
            .into_iter()
            .find(|name| name.starts_with("prekey-") && name.ends_with("-client.norito"))
            .unwrap();
    d.fs.place_unsynced(&root, &client, b"corrupt selected client");
    assert!(
        owner
            .begin(
                &[11; 32],
                &norito::encode_canonical(&f.account).unwrap(),
                &norito::encode_canonical(&f.asset).unwrap()
            )
            .is_err()
    );
    d.platform.with(|state| assert_eq!(state.generate_calls, 0));
}

#[test]
fn prekey_uncertain_client_publication_adopts_exact_identity_before_new_dispatch() {
    let f = fixture();
    let baseline = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 139);
    let mut current = owner(&f, &baseline);
    let start = baseline.fs.steps();
    let _ = dispatch(&f, &mut current);
    let boundary = baseline
        .fs
        .trace_since(start)
        .iter()
        .rposition(|step| *step == KagemushaWalletSimStepV1::SyncDir)
        .unwrap() as u64;
    let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 149);
    let mut current = owner(&f, &d);
    d.fs.inject(d.fs.steps() + boundary, KagemushaWalletSimFaultV1::Error);
    let account = norito::encode_canonical(&f.account).unwrap();
    let asset = norito::encode_canonical(&f.asset).unwrap();
    assert!(current.begin(&[11; 32], &account, &asset).is_err());
    let root = KagemushaWalletCustodyDirV1::root();
    let name =
        d.fs.visible_names(&root)
            .into_iter()
            .find(|name| name.starts_with("prekey-") && name.ends_with("-client.norito"))
            .unwrap();
    let original = d.fs.visible_file(&root, &name).unwrap();
    let selected = PreKeyDispatchV1::decode(&original).unwrap();
    d.fs.clear_faults();
    let recovered = dispatch(&f, &mut current);
    assert_eq!(
        selected.stable_selection().unwrap(),
        recovered.stable_selection().unwrap()
    );
    assert_ne!(
        selected.native_dispatch_nonce,
        recovered.native_dispatch_nonce
    );
    assert_eq!(d.fs.visible_file(&root, &name).unwrap(), original);
    d.platform.with(|state| assert_eq!(state.generate_calls, 0));
}

#[test]
fn failed_new_dispatch_cannot_silently_use_previous_enrollment_selection() {
    let f = fixture();
    let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 151);
    let mut current = enrolled(&f, &d);
    assert!(
        current
            .begin(&[0; 32], b"bad account", b"bad asset")
            .is_err()
    );
    assert!(current.progress().is_err());
    assert!(current.prepare_request(&f.evidence).is_err());
    let message = begin(&f, &mut current);
    assert!(matches!(
        current.authorize(&sign(&f, &message)).unwrap(),
        EnrollmentProgressV1::Evidence { .. }
    ));
    d.platform.with(|state| assert_eq!(state.generate_calls, 1));
}

#[test]
fn enrollment_e6_requires_the_exact_prekey_selected_enrollment_certificate() {
    use p256::ecdsa::{Signature as P256Signature, signature::Signer as _};
    let f = fixture();
    let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 157);
    let mut current = enrolled(&f, &d);
    let request = RequestV1::decode(&request(&f, &mut current)).unwrap();
    let expected = issuer_result(&f, &request);
    let decoded = expected
        .verify_for(&f.config.scheme, &f.config.enrollment_certificate, &request)
        .unwrap();
    let certificate_body = KagemushaWalletSignerCertificateBodyV1 {
        version: 1,
        scheme_id: f.config.scheme.scheme_id(),
        role: KagemushaWalletSignerRoleV1::Enrollment,
        key: public_key(&signing_key(83)),
        serial: 2,
    };
    let signature: P256Signature = signing_key(17).sign(&certificate_body.signing_message());
    let foreign = KagemushaWalletSignerCertificateV1::sign(
        certificate_body,
        &f.config.scheme,
        KagemushaWalletSignerOutputV1::Raw(signature.to_bytes().into()),
    )
    .unwrap();
    let mut body = decoded.body;
    body.issuer_certificate = foreign.certificate_digest();
    let signature: P256Signature = signing_key(83).sign(&body.signing_message());
    let credential = KagemushaWalletCredentialV1::sign(
        body,
        &foreign,
        KagemushaWalletSignerOutputV1::Raw(signature.to_bytes().into()),
    )
    .unwrap();
    let altered = ResultV1 {
        credential: credential.to_canonical_bytes().unwrap(),
        certificates: norito::encode_canonical(
            &KagemushaWalletCertificateSetV1::new(vec![foreign]).unwrap(),
        )
        .unwrap(),
        ..expected.clone()
    };
    assert!(
        altered
            .verify_for(&f.config.scheme, &foreign, &request)
            .is_ok(),
        "independently valid same-scheme issuer"
    );
    assert!(
        altered
            .verify_for(&f.config.scheme, &f.config.enrollment_certificate, &request)
            .is_err()
    );
    assert!(
        current
            .accept_credential(&altered.encode().unwrap())
            .is_err()
    );
    let mut changed = request.clone();
    changed.account_signature[0] ^= 1;
    assert!(
        expected
            .verify_for(&f.config.scheme, &f.config.enrollment_certificate, &changed)
            .is_err()
    );
    assert_eq!(
        current
            .accept_credential(&expected.encode().unwrap())
            .unwrap(),
        expected.encode().unwrap()
    );
}

#[test]
fn enrollment_signed_abandonment_is_explicit_terminal_and_exact_across_restart() {
    let f = fixture();
    let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 163);
    let mut current = enrolled(&f, &d);
    let EnrollmentAbandonmentV1::Abandonment(frame) = current.abandon().unwrap() else {
        panic!("a current enrollment marker uses the signed marker form")
    };
    let original = EnrollmentAbandonmentV1::Abandonment(frame.clone());
    assert!(frame.len() <= KAGEMUSHA_WALLET_ABANDONMENT_MAX_BYTES_V1);
    let calls = d.platform.with(|state| state.sign_calls);
    assert_eq!(current.abandon().unwrap(), original);
    let instruction = current.abandonment_ledger_instruction().unwrap().unwrap();
    let expected = iroha_data_model::isi::kagemusha_wallet::KagemushaWalletLedgerV1::new(
        f.config.scheme.scheme_id(),
        iroha_data_model::isi::kagemusha_wallet::KagemushaWalletLedgerActionV1::Abandon(frame),
    );
    assert_eq!(instruction, norito::encode_canonical(&expected).unwrap());
    assert!(matches!(
        current.progress().unwrap(),
        EnrollmentProgressV1::Abandoned
    ));
    assert!(current.prepare_request(&f.evidence).is_err());
    drop(current.into_provider());
    let mut current = owner(&f, &d);
    dispatch(&f, &mut current);
    assert_eq!(current.abandon().unwrap(), original);
    assert_eq!(
        current.abandonment_ledger_instruction().unwrap(),
        Some(instruction)
    );
    assert!(
        current.authorize(&[0; 64]).is_err(),
        "abandon consumes pending dispatch"
    );
    d.platform.with(|state| assert_eq!(state.sign_calls, calls));
}
fn begin_with_id(f: &Fixture, owner: &mut Owner, id: [u8; 32]) -> [u8; 32] {
    let dispatch = PreKeyDispatchV1::decode(
        &owner
            .begin(
                &id,
                &norito::encode_canonical(&f.account).unwrap(),
                &norito::encode_canonical(&f.asset).unwrap(),
            )
            .unwrap(),
    )
    .unwrap();
    owner
        .accept_permit(&permit(f, &dispatch).encode_canonical().unwrap())
        .unwrap()
}

/// Every file name in every slot directory, read from the simulated filesystem only (the
/// owner under test keeps exclusive custody, so no second provider is opened).
fn slot_names(d: &DeviceV1) -> Vec<String> {
    d.fs.visible_names(&super::layout::kagemusha_wallet_slots_dir_v1())
        .iter()
        .filter_map(|name| KagemushaWalletSlotIdV1::parse(name))
        .flat_map(|slot| {
            d.fs.visible_names(&super::layout::kagemusha_wallet_slot_dir_v1(&slot))
        })
        .collect()
}

#[test]
fn local_abandonment_from_pending_returns_no_ledger_bytes_and_never_probes_an_unknown_key() {
    // Pre-E2 (Slot published, no intent) and intent-only slots. An unknown lookup is the
    // fresh-generation-only platform (Android API 26–30), where a missing result is unknown.
    // The durable phase decides, so local abandonment never probes a key.
    for intent_only in [false, true] {
        for unknown_lookup in [false, true] {
            for restart in [false, true] {
                let mut f = fixture();
                let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 211);
                if unknown_lookup {
                    d.platform.with(|s| {
                        s.generation_policy =
                            KagemushaWalletKeyGenerationPolicyV1::FreshEnrollmentOnly;
                    });
                }
                let mut current = interrupted_prekey_before_marker(&f, &d, intent_only);
                d.platform.with(|s| s.probe_unavailable = unknown_lookup);
                if restart {
                    drop(current.into_provider());
                    d.fs.restart();
                    current = owner(&f, &d);
                    dispatch(&f, &mut current);
                }
                let probes = d.platform.with(|s| s.probe_calls);
                if intent_only && unknown_lookup {
                    assert!(matches!(current.progress(), Err(Error::Provider(_))));
                } else if !intent_only {
                    // `PreIntent` proves that no key exists: no probe, still pending.
                    assert!(matches!(
                        current.progress().unwrap(),
                        EnrollmentProgressV1::Pending
                    ));
                    d.platform.with(|s| assert_eq!(s.probe_calls, probes));
                }
                let probes = d.platform.with(|s| s.probe_calls);
                assert_eq!(
                    current.abandon().unwrap(),
                    EnrollmentAbandonmentV1::LocalAbandoned
                );
                let expected_probes = probes;
                d.platform
                    .with(|s| assert_eq!(s.probe_calls, expected_probes, "probes"));
                assert_eq!(
                    current.abandon().unwrap(),
                    EnrollmentAbandonmentV1::LocalAbandoned,
                    "an existing local abandonment stands"
                );
                assert_eq!(current.abandonment_ledger_instruction().unwrap(), None);
                assert!(matches!(
                    current.progress().unwrap(),
                    EnrollmentProgressV1::Abandoned
                ));
                assert!(current.prepare_request(&f.evidence).is_err());
                d.platform.with(|s| {
                    assert_eq!(
                        s.probe_calls, expected_probes,
                        "an abandoned slot reconciles without a key probe"
                    );
                    assert_eq!(s.generate_calls, 0);
                    assert_eq!(s.sign_calls, 0, "no ledger-control bytes are signed");
                });
                // The same attempt never resumes or regenerates under the abandoned slot.
                drop(current.into_provider());
                d.fs.restart();
                let mut reopened = owner(&f, &d);
                let resumed = dispatch(&f, &mut reopened);
                let message = reopened
                    .accept_permit(&permit(&f, &resumed).encode_canonical().unwrap())
                    .unwrap();
                assert!(matches!(
                    reopened.authorize(&sign(&f, &message)).unwrap(),
                    EnrollmentProgressV1::Abandoned
                ));
                d.platform.with(|s| {
                    assert_eq!(s.generate_calls, 0);
                    assert_eq!(s.fresh_generation_calls, 0);
                });
                // A fresh enrollment needs no ledger acceptance: a new challenge, request
                // identity, slot and key start at once.
                d.platform.with(|s| s.probe_unavailable = false);
                f.challenge.issuer_nonce = [48; 32];
                let message = begin_with_id(&f, &mut reopened, [12; 32]);
                assert!(matches!(
                    reopened.authorize(&sign(&f, &message)).unwrap(),
                    EnrollmentProgressV1::Evidence { .. }
                ));
                d.platform.with(|s| assert_eq!(s.generate_calls, 1));
            }
        }
    }
}

#[test]
fn local_abandonment_after_a_spent_fresh_grant_drops_the_retained_reply_without_adoption() {
    let f = fixture();
    let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 213);
    d.platform
        .with(|s| s.generation_policy = KagemushaWalletKeyGenerationPolicyV1::FreshEnrollmentOnly);
    let mut current = owner(&f, &d);
    let message = begin(&f, &mut current);
    // The vendor created the key, but its reply was lost: the one-shot grant is spent.
    d.platform.with(|s| {
        s.generate_unavailable = Some(true);
        s.probe_unavailable = true;
    });
    assert!(matches!(
        current.authorize(&sign(&f, &message)),
        Err(Error::Provider(_))
    ));
    d.platform.with(|s| {
        assert_eq!(s.fresh_generation_calls, 1);
        s.generate_unavailable = None;
    });
    let probes = d.platform.with(|s| s.probe_calls);
    assert_eq!(
        current.abandon().unwrap(),
        EnrollmentAbandonmentV1::LocalAbandoned
    );
    d.platform.with(|s| assert_eq!(s.probe_calls, probes));
    // The key now answers, but the abandoned slot never adopts it or publishes a marker.
    d.platform.with(|s| s.probe_unavailable = false);
    assert!(matches!(
        current.progress().unwrap(),
        EnrollmentProgressV1::Abandoned
    ));
    assert!(current.prepare_request(&f.evidence).is_err());
    let mut provider = current.into_provider();
    let slot = provider.slots().unwrap()[0];
    assert_eq!(
        provider.status(&slot).unwrap(),
        KagemushaWalletSlotStatusV1::SlotAbandoned
    );
    assert!(!provider.has_retained_generation(&slot));
    assert!(!provider.has_enrollment_marker(&slot).unwrap());
    assert_eq!(
        provider.read_abandoned_record(&slot).unwrap(),
        KagemushaWalletSlotAbandonReasonV1::HolderAbandoned
    );
    d.platform.with(|s| {
        assert_eq!(s.generate_calls, 1);
        assert_eq!(
            s.fresh_generation_calls, 1,
            "the spent grant is never reissued"
        );
    });
}

#[test]
fn local_abandonment_refuses_lost_originals_and_uncertain_storage_and_writes_nothing() {
    for intent_only in [false, true] {
        // A missing Client, Accepted permit or Slot original is lost custody.
        for role in ["client", "accepted", "slot"] {
            let f = fixture();
            let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 215);
            let mut current = interrupted_prekey_before_marker(&f, &d, intent_only);
            let root = KagemushaWalletCustodyDirV1::root();
            let name =
                d.fs.visible_names(&root)
                    .into_iter()
                    .find(|name| {
                        name.starts_with("prekey-") && name.ends_with(&format!("-{role}.norito"))
                    })
                    .unwrap();
            d.fs.unlink(&root, &name).unwrap();
            let before = slot_names(&d);
            assert!(current.abandon().is_err(), "{role}");
            assert_eq!(slot_names(&d), before, "{role}: nothing written");
        }
        // Unavailable protected storage never counts as "no marker".
        let f = fixture();
        let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 217);
        let mut current = interrupted_prekey_before_marker(&f, &d, intent_only);
        d.platform
            .with(|s| s.storage = Err(KagemushaWalletUnavailableV1::BeforeFirstUnlock));
        assert!(matches!(current.abandon(), Err(Error::Provider(_))));
        d.platform.with(|s| s.storage = Ok(()));
        assert!(!slot_names(&d).contains(&"abandoned.norito".to_owned()));
        // A filesystem read fault is unavailable, never absence; a later clean call succeeds.
        d.fs.inject(d.fs.steps(), KagemushaWalletSimFaultV1::Error);
        assert!(current.abandon().is_err());
        d.fs.clear_faults();
        assert!(!slot_names(&d).contains(&"abandoned.norito".to_owned()));
        assert_eq!(
            current.abandon().unwrap(),
            EnrollmentAbandonmentV1::LocalAbandoned
        );
    }
}

#[test]
fn a_lost_selected_intent_is_restored_from_the_phase_and_never_regenerates_a_key() {
    for policy in [
        KagemushaWalletKeyGenerationPolicyV1::DefinitiveAbsence,
        KagemushaWalletKeyGenerationPolicyV1::FreshEnrollmentOnly,
    ] {
        for expired in [false, true] {
            let f = fixture();
            let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 219);
            d.platform.with(|s| s.generation_policy = policy);
            let mut current = owner(&f, &d);
            let message = begin(&f, &mut current);
            d.platform.with(|s| s.generate_unavailable = Some(false));
            assert!(current.authorize(&sign(&f, &message)).is_err());
            d.platform.with(|s| {
                s.generate_unavailable = None;
                s.probe_unavailable = true;
                if expired {
                    // The issuer challenge (created 1000, lifetime 120000) has elapsed.
                    s.monotonic = Ok(130_000);
                }
            });
            let generated = d
                .platform
                .with(|s| (s.generate_calls, s.fresh_generation_calls));
            let slot = current.into_provider().slots().unwrap()[0];
            d.fs.restart();
            let dir = super::layout::kagemusha_wallet_slot_dir_v1(&slot);
            let intent = d.fs.visible_file(&dir, "intent.norito").unwrap();
            d.fs.unlink(&dir, "intent.norito").unwrap();
            // The selected intent is rebuilt from the authenticated phase, checked against its
            // exact digest and restored create-new, also after E1 expiry; no generation grant
            // or key effect follows from it.
            let mut current = owner(&f, &d);
            dispatch(&f, &mut current);
            let probes = d.platform.with(|s| s.probe_calls);
            assert_eq!(
                current.abandon().unwrap(),
                EnrollmentAbandonmentV1::LocalAbandoned,
                "{policy:?} expired {expired}"
            );
            assert_eq!(d.fs.visible_file(&dir, "intent.norito").unwrap(), intent);
            d.platform.with(|s| {
                assert_eq!(s.probe_calls, probes);
                assert_eq!(
                    (s.generate_calls, s.fresh_generation_calls),
                    generated,
                    "no new generation or fresh grant"
                );
            });
        }
    }
}

#[test]
fn a_selected_slot_without_its_durable_phase_is_lost_custody_never_pre_intent() {
    for intent_only in [false, true] {
        let f = fixture();
        let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 233);
        let mut current = interrupted_prekey_before_marker(&f, &d, intent_only);
        let root = KagemushaWalletCustodyDirV1::root();
        let name =
            d.fs.visible_names(&root)
                .into_iter()
                .find(|name| name.starts_with("prekey-") && name.ends_with("-phase.norito"))
                .unwrap();
        d.fs.unlink(&root, &name).unwrap();
        let before = slot_names(&d);
        assert!(matches!(
            current.abandon(),
            Err(Error::Provider(
                KagemushaWalletProviderErrorV1::UnavailableCustodyData { .. }
            ))
        ));
        assert_eq!(slot_names(&d), before);
        drop(current.into_provider());
        d.fs.restart();
        let mut reopened = owner(&f, &d);
        let resumed = dispatch(&f, &mut reopened);
        let message = reopened
            .accept_permit(&permit(&f, &resumed).encode_canonical().unwrap())
            .unwrap();
        assert!(reopened.authorize(&sign(&f, &message)).is_err());
        d.platform.with(|s| assert_eq!(s.generate_calls, 0));
    }
}

#[test]
fn abandonment_after_bootstrap_selection_or_with_a_marker_never_takes_the_local_form() {
    let f = fixture();
    let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 221);
    let mut current = enrolled(&f, &d);
    let mut provider = current.into_provider();
    let slot = provider.slots().unwrap()[0];
    assert!(provider.has_enrollment_marker(&slot).unwrap());
    // The provider itself refuses a local abandonment of a marked slot.
    assert!(matches!(
        provider.abandon_unmarked_enrollment(&slot, &[11; 32]),
        Err(KagemushaWalletProviderErrorV1::Invalid {
            field: "abandon.marker"
        })
    ));
    assert!(
        !d.fs
            .visible_names(&super::layout::kagemusha_wallet_slot_dir_v1(&slot))
            .contains(&"abandoned.norito".to_owned())
    );
    current = EnrollmentOwnerV1::new(provider, f.config.clone())
        .unwrap_or_else(|(_, error)| panic!("{error}"));
    dispatch(&f, &mut current);
    assert!(matches!(
        current.abandon().unwrap(),
        EnrollmentAbandonmentV1::Abandonment(_)
    ));
}

#[test]
fn local_abandonment_never_treats_a_lost_marker_as_no_marker() {
    let f = fixture();
    let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 225);
    let slot = enrolled(&f, &d).into_provider().slots().unwrap()[0];
    let mut current = enrolled_again(&f, &d);
    // The generation-zero marker disappears after this owner verified it.
    let markers = super::layout::kagemusha_wallet_markers_dir_v1(&slot);
    for name in d.fs.visible_names(&markers) {
        d.fs.unlink(&markers, &name).unwrap();
    }
    // The committed phase proves the marker existed: never absence, never reconstructed.
    for _ in 0..2 {
        assert!(matches!(
            current.abandon(),
            Err(Error::Provider(
                KagemushaWalletProviderErrorV1::UnavailableCustodyData {
                    object: "committed enrollment marker"
                }
            ))
        ));
        assert!(current.progress().is_err());
    }
    drop(current.into_provider());
    d.fs.restart();
    let mut reopened = owner(&f, &d);
    dispatch(&f, &mut reopened);
    assert!(reopened.abandon().is_err());
    assert!(reopened.progress().is_err());
    assert!(
        !d.fs
            .visible_names(&super::layout::kagemusha_wallet_slot_dir_v1(&slot))
            .contains(&"abandoned.norito".to_owned())
    );
    d.platform.with(|s| assert_eq!(s.sign_calls, 0));
}

/// Reopen the same device and select its existing attempt again (Resume dispatch).
fn enrolled_again(f: &Fixture, d: &DeviceV1) -> Owner {
    let mut current = owner(f, d);
    let resumed = dispatch(f, &mut current);
    let message = current
        .accept_permit(&permit(f, &resumed).encode_canonical().unwrap())
        .unwrap();
    assert!(matches!(
        current.authorize(&sign(f, &message)).unwrap(),
        EnrollmentProgressV1::Evidence { .. }
    ));
    current
}

#[test]
fn a_tombstone_only_pre_e2_slot_does_not_break_a_later_attempts_recovery() {
    let mut f = fixture();
    let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 227);
    let mut current = interrupted_prekey_before_marker(&f, &d, false);
    assert_eq!(
        current.abandon().unwrap(),
        EnrollmentAbandonmentV1::LocalAbandoned
    );
    // Attempt B accepts its permit, then the process stops before B's Slot publication.
    f.challenge.issuer_nonce = [49; 32];
    begin_with_id(&f, &mut current, [13; 32]);
    drop(current.into_provider());
    d.fs.restart();
    let mut reopened = owner(&f, &d);
    let resumed = PreKeyDispatchV1::decode(
        &reopened
            .begin(
                &[13; 32],
                &norito::encode_canonical(&f.account).unwrap(),
                &norito::encode_canonical(&f.asset).unwrap(),
            )
            .unwrap(),
    )
    .unwrap();
    assert!(resumed.previous_permit.is_some());
    let probes = d.platform.with(|s| s.probe_calls);
    assert_eq!(reopened.retained_request().unwrap(), None);
    d.platform.with(|s| assert_eq!(s.probe_calls, probes));
}

#[test]
fn a_cached_marker_beside_an_abandoned_slot_record_is_conflicting_custody() {
    let f = fixture();
    let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 235);
    let mut provider = enrolled(&f, &d).into_provider();
    let slot = provider.slots().unwrap()[0];
    assert!(matches!(
        provider.status(&slot).unwrap(),
        KagemushaWalletSlotStatusV1::Enrollment(_)
    ));
    provider
        .abandon_slot(&slot, KagemushaWalletSlotAbandonReasonV1::KeyWithoutMarker)
        .unwrap();
    assert!(matches!(
        provider.status(&slot),
        Err(KagemushaWalletProviderErrorV1::UnavailableCustodyData {
            object: "abandoned slot custody conflict"
        })
    ));
}

#[test]
fn an_abandoned_slot_record_beside_a_marker_is_conflicting_custody() {
    let f = fixture();
    let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 229);
    let mut provider = enrolled(&f, &d).into_provider();
    let slot = provider.slots().unwrap()[0];
    provider
        .abandon_slot(&slot, KagemushaWalletSlotAbandonReasonV1::KeyWithoutMarker)
        .unwrap();
    drop(provider);
    d.fs.restart();
    let mut provider: KagemushaWalletProviderV1<KagemushaWalletSimFsV1, FakePlatformV1> =
        KagemushaWalletProviderV1::open(
            d.fs.clone(),
            d.platform.clone(),
            f.config.scheme.scheme_id(),
            test_options(),
        )
        .unwrap();
    assert!(matches!(
        provider.status(&slot),
        Err(KagemushaWalletProviderErrorV1::UnavailableCustodyData {
            object: "abandoned slot custody conflict"
        })
    ));
}

#[test]
fn an_uncertain_local_abandonment_record_is_terminal_only_once_it_is_durable() {
    use super::store::{KagemushaWalletSimFaultV1, KagemushaWalletSimStepV1};
    // Learn the deterministic step trace of one successful local abandonment.
    let trace = {
        let f = fixture();
        let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 231);
        let mut current = interrupted_prekey_before_marker(&f, &d, true);
        let from = d.fs.steps();
        current.abandon().unwrap();
        d.fs.trace_since(from)
    };
    let rename = trace
        .iter()
        .rposition(|step| *step == KagemushaWalletSimStepV1::RenameNoReplace)
        .unwrap();
    let sync = rename
        + trace[rename..]
            .iter()
            .position(|step| *step == KagemushaWalletSimStepV1::SyncDir)
            .unwrap();
    let f = fixture();
    let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 231);
    let mut current = interrupted_prekey_before_marker(&f, &d, true);
    let from = d.fs.steps();
    // The record becomes visible, but its directory sync fails: not yet terminal.
    d.fs.inject(
        from + u64::try_from(sync).unwrap(),
        KagemushaWalletSimFaultV1::Error,
    );
    assert!(current.abandon().is_err());
    d.fs.clear_faults();
    // The next observation makes that exact record durable before reporting it terminal.
    let syncs = d.fs.steps();
    assert!(matches!(
        current.progress().unwrap(),
        EnrollmentProgressV1::Abandoned
    ));
    assert!(
        d.fs.trace_since(syncs)
            .contains(&KagemushaWalletSimStepV1::SyncDir)
    );
    assert_eq!(
        current.abandon().unwrap(),
        EnrollmentAbandonmentV1::LocalAbandoned
    );
    d.platform.with(|s| assert_eq!(s.generate_calls, 0));
}

/// Durable phase of the fixture attempt (request identity `[11; 32]`) as custody shows it now.
fn fixture_phase(
    provider: &KagemushaWalletProviderV1<KagemushaWalletSimFsV1, FakePlatformV1>,
) -> Option<KagemushaWalletEnrollmentPhaseStateV1> {
    provider.enrollment_phase(&[11; 32]).unwrap()
}

/// Every visible slot original is named by the durable phase: an intent by its exact selected
/// digest, a marker by a selected marker phase.
fn assert_phase_covers_custody(
    provider: &mut KagemushaWalletProviderV1<KagemushaWalletSimFsV1, FakePlatformV1>,
    label: &str,
) {
    let phase = fixture_phase(provider);
    for slot in provider.slots().unwrap() {
        if provider.is_abandoned_without_marker(&slot).unwrap() {
            continue;
        }
        let state = phase
            .as_ref()
            .filter(|state| state.binding.slot == slot.0)
            .unwrap_or_else(|| panic!("{label}: a slot without its phase"));
        if let Some(intent) = provider.read_intent(&slot).unwrap() {
            assert_eq!(
                state.phase.intent_digest(),
                Some(super::enrollment_phase::kagemusha_wallet_intent_digest_v1(&intent).unwrap()),
                "{label}: intent named by the phase"
            );
        }
        if provider.has_enrollment_marker(&slot).unwrap() {
            assert!(
                state.phase.marker_selected(),
                "{label}: marker named by the phase"
            );
        }
    }
}

#[test]
fn prekey_phase_crash_matrix_keeps_every_selected_original_and_the_abandonment_form() {
    use super::store::{
        KagemushaWalletSimFaultV1 as Fault, KagemushaWalletSimPowerLossV1 as PowerLoss,
        KagemushaWalletSimStepV1 as Step,
    };
    let f = fixture();
    let mut cases = 0_usize;
    for (anchor, policy, seed) in [
        (
            KagemushaWalletAnchorPolicyV1::NotRequired,
            KagemushaWalletKeyGenerationPolicyV1::DefinitiveAbsence,
            241,
        ),
        (
            KagemushaWalletAnchorPolicyV1::Keychain,
            KagemushaWalletKeyGenerationPolicyV1::DefinitiveAbsence,
            242,
        ),
        (
            KagemushaWalletAnchorPolicyV1::NotRequired,
            KagemushaWalletKeyGenerationPolicyV1::FreshEnrollmentOnly,
            243,
        ),
    ] {
        let base = DeviceV1::new(anchor, seed);
        base.platform.with(|s| s.generation_policy = policy);
        // Every mutating step of one authorization: the binding and Slot selection, every
        // phase transition and publication, generation, the marker, its commit and the anchor.
        let trace = {
            let d = base.fork();
            let mut current = owner(&f, &d);
            let message = begin(&f, &mut current);
            let from = d.fs.steps();
            assert!(matches!(
                current.authorize(&sign(&f, &message)).unwrap(),
                EnrollmentProgressV1::Evidence { .. }
            ));
            d.fs.trace_since(from)
        };
        for (at, step) in trace.iter().enumerate() {
            if matches!(step, Step::Read | Step::List | Step::Statvfs | Step::Lock) {
                continue;
            }
            // A crash just after the step with power loss (only durable state survives), an
            // uncertain step answered by a restart, a lost writeback with power loss, and a lost
            // writeback followed by a successful same-process retry and only then power loss
            // (what the retry relied on must have been made durable again).
            for (fault, power_loss, retry) in [
                (Fault::CrashAfter, true, false),
                (Fault::Error, false, false),
                (Fault::LostWriteback, true, false),
                (Fault::LostWriteback, true, true),
            ] {
                {
                    let label = format!(
                        "{anchor:?}/{policy:?} step {at} {step:?} {fault:?} power loss {power_loss} retry {retry}"
                    );
                    let d = base.fork();
                    let mut current = owner(&f, &d);
                    let message = begin(&f, &mut current);
                    d.fs.inject(d.fs.steps() + u64::try_from(at).unwrap(), fault);
                    let _ = current.authorize(&sign(&f, &message));
                    d.fs.clear_faults();
                    if retry && !d.fs.crashed() {
                        let resumed = dispatch(&f, &mut current);
                        if let Ok(message) =
                            current.accept_permit(&permit(&f, &resumed).encode_canonical().unwrap())
                        {
                            let _ = current.authorize(&sign(&f, &message));
                        }
                    }
                    drop(current.into_provider());
                    if power_loss {
                        d.power_loss(PowerLoss::DropUnsynced, super::test_support::BOOT_B);
                    } else {
                        d.fs.restart();
                    }
                    // Recovery: custody stays consistent with the phase, the attempt resumes
                    // without lost-custody errors, and abandonment takes the form the phase
                    // demands.
                    let mut provider = owner(&f, &d).into_provider();
                    assert_phase_covers_custody(&mut provider, &label);
                    let mut current = EnrollmentOwnerV1::new(provider, f.config.clone())
                        .unwrap_or_else(|(_, error)| panic!("{label}: {error}"));
                    let resumed = dispatch(&f, &mut current);
                    let message = current
                        .accept_permit(&permit(&f, &resumed).encode_canonical().unwrap())
                        .unwrap_or_else(|error| panic!("{label}: accept {error}"));
                    match current.authorize(&sign(&f, &message)) {
                        Ok(_)
                        | Err(Error::Provider(KagemushaWalletProviderErrorV1::Unavailable(_))) => {}
                        Err(error) => panic!("{label}: authorize {error:?}"),
                    }
                    let mut provider = current.into_provider();
                    assert_phase_covers_custody(&mut provider, &label);
                    let marked =
                        fixture_phase(&provider).is_some_and(|state| state.phase.marker_selected());
                    let mut current = EnrollmentOwnerV1::new(provider, f.config.clone())
                        .unwrap_or_else(|(_, error)| panic!("{label}: {error}"));
                    dispatch(&f, &mut current);
                    match current.abandon() {
                        Ok(EnrollmentAbandonmentV1::Abandonment(_)) => {
                            assert!(marked, "{label}: marker form without a selected marker");
                        }
                        Ok(EnrollmentAbandonmentV1::LocalAbandoned) => {
                            assert!(!marked, "{label}: local form after a selected marker");
                        }
                        Err(error) => panic!("{label}: abandon {error:?}"),
                    }
                    assert!(
                        matches!(current.progress(), Ok(EnrollmentProgressV1::Abandoned)),
                        "{label}"
                    );
                    d.platform.with(|s| {
                        // Generation only into an intent-only, unmarked, unabandoned slot
                        // without a key (the platform's signing and deletion guards decode the
                        // simulator's own scheme, not this fixture's, so only this one applies).
                        assert!(
                            !s.violations.iter().any(|v| v.starts_with("key generated")),
                            "{label}: {:?}",
                            s.violations
                        );
                        assert!(s.fresh_generation_calls <= 1, "{label}: one fresh grant");
                    });
                    cases += 1;
                }
            }
        }
    }
    assert!(cases > 300, "{cases} cases");
}

/// Stop an authorization immediately before the generation-zero marker's own publication: the
/// durable phase is `MarkerSelected`, the key exists and no marker is visible.
fn marker_selected_without_marker(
    f: &Fixture,
    anchor: KagemushaWalletAnchorPolicyV1,
    seed: u8,
) -> (DeviceV1, KagemushaWalletSlotIdV1) {
    use super::store::{KagemushaWalletSimFaultV1 as Fault, KagemushaWalletSimStepV1 as Step};
    let base = DeviceV1::new(anchor, seed);
    let trace = {
        let d = base.fork();
        let mut current = owner(f, &d);
        let message = begin(f, &mut current);
        let from = d.fs.steps();
        current.authorize(&sign(f, &message)).unwrap();
        d.fs.trace_since(from)
    };
    for (at, step) in trace.iter().enumerate() {
        if *step != Step::RenameNoReplace {
            continue;
        }
        let d = base.fork();
        let mut current = owner(f, &d);
        let message = begin(f, &mut current);
        d.fs.inject(
            d.fs.steps() + u64::try_from(at).unwrap(),
            Fault::CrashBefore,
        );
        let _ = current.authorize(&sign(f, &message));
        d.fs.clear_faults();
        drop(current.into_provider());
        d.fs.restart();
        let provider = owner(f, &d).into_provider();
        let selected = fixture_phase(&provider).is_some_and(|state| {
            matches!(
                state.phase,
                KagemushaWalletEnrollmentPhaseV1::MarkerSelected { .. }
            )
        });
        let slots = provider.slots().unwrap();
        if selected && !provider.has_enrollment_marker(&slots[0]).unwrap() {
            assert!(d.platform.key_of(&slots[0]).is_some());
            return (d, slots[0]);
        }
    }
    panic!("no marker-selected boundary");
}

#[test]
fn a_selected_marker_lost_before_publication_is_restored_only_with_its_exact_present_key() {
    let f = fixture();
    for case in ["matching", "absent", "different", "unavailable", "abandon"] {
        let (d, slot) =
            marker_selected_without_marker(&f, KagemushaWalletAnchorPolicyV1::NotRequired, 245);
        match case {
            "absent" => d.platform.with(|s| {
                s.keys.remove(&slot);
            }),
            "different" => d.platform.with(|s| {
                s.keys.insert(slot, signing_key(99));
            }),
            "unavailable" => d.platform.with(|s| s.probe_unavailable = true),
            _ => {}
        }
        let mut current = owner(&f, &d);
        dispatch(&f, &mut current);
        let generated = d.platform.with(|s| s.generate_calls);
        let before = slot_names(&d);
        if case == "abandon" {
            // Either marker phase prohibits the local form: the restored marker signs the frame.
            assert!(matches!(
                current.abandon().unwrap(),
                EnrollmentAbandonmentV1::Abandonment(_)
            ));
            continue;
        }
        let progress = current.progress();
        match case {
            "matching" => {
                assert!(
                    matches!(progress, Ok(EnrollmentProgressV1::Evidence { .. })),
                    "{progress:?}"
                );
                let provider = current.into_provider();
                assert!(matches!(
                    fixture_phase(&provider).unwrap().phase,
                    KagemushaWalletEnrollmentPhaseV1::MarkerCommitted { .. }
                ));
            }
            "absent" | "different" => {
                assert!(
                    matches!(
                        progress,
                        Err(Error::Provider(KagemushaWalletProviderErrorV1::KeyLost))
                    ),
                    "{case}: {progress:?}"
                );
                assert!(current.abandon().is_err(), "{case}: never the local form");
                assert_eq!(slot_names(&d), before, "{case}: nothing published");
            }
            _ => {
                assert!(
                    matches!(
                        progress,
                        Err(Error::Provider(
                            KagemushaWalletProviderErrorV1::Unavailable(_)
                        ))
                    ),
                    "{progress:?}"
                );
                assert_eq!(slot_names(&d), before, "unavailable: nothing published");
                d.platform.with(|s| s.probe_unavailable = false);
                assert!(matches!(
                    current.progress(),
                    Ok(EnrollmentProgressV1::Evidence { .. })
                ));
            }
        }
        d.platform
            .with(|s| assert_eq!(s.generate_calls, generated, "{case}: no generation"));
    }
}

#[test]
fn a_named_anchor_never_authorizes_restoring_a_selected_marker() {
    let f = fixture();
    let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::Keychain, 247);
    let slot = enrolled(&f, &d).into_provider().slots().unwrap()[0];
    d.fs.restart();
    // A phase that reads `MarkerSelected` (never committed) and no marker file: the raised
    // keychain anchor still binds the exact lost marker file, so nothing may replace it.
    let root = KagemushaWalletCustodyDirV1::root();
    let name =
        d.fs.visible_names(&root)
            .into_iter()
            .find(|name| name.ends_with("-phase.norito"))
            .unwrap();
    let mut state = super::enrollment_phase::test_decode_phase_record(
        &d.fs.visible_file(&root, &name).unwrap(),
    );
    let KagemushaWalletEnrollmentPhaseV1::MarkerCommitted {
        intent_digest,
        marker_digest,
        payment_key,
        ..
    } = state.phase
    else {
        panic!("committed phase");
    };
    state.phase = KagemushaWalletEnrollmentPhaseV1::MarkerSelected {
        intent_digest,
        marker_digest,
        payment_key,
    };
    d.fs.unlink(&root, &name).unwrap();
    d.fs.place_unsynced(
        &root,
        &name,
        &super::enrollment_phase::test_phase_record(&state),
    );
    let markers = super::layout::kagemusha_wallet_markers_dir_v1(&slot);
    for name in d.fs.visible_names(&markers) {
        d.fs.unlink(&markers, &name).unwrap();
    }
    for restart in [false, true] {
        if restart {
            d.fs.restart();
        }
        let mut current = owner(&f, &d);
        dispatch(&f, &mut current);
        assert!(matches!(
            current.progress(),
            Err(Error::Provider(
                KagemushaWalletProviderErrorV1::UnavailableCustodyData {
                    object: "anchored enrollment marker"
                }
            ))
        ));
        assert!(current.abandon().is_err());
        assert!(d.fs.visible_names(&markers).is_empty(), "never republished");
        drop(current.into_provider());
    }
}

#[test]
fn corrupt_or_foreign_phase_records_are_unavailable_custody_everywhere() {
    for intent_only in [false, true] {
        for mutation in ["corrupt", "foreign"] {
            let f = fixture();
            let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 249);
            let mut current = interrupted_prekey_before_marker(&f, &d, intent_only);
            let root = KagemushaWalletCustodyDirV1::root();
            let name =
                d.fs.visible_names(&root)
                    .into_iter()
                    .find(|name| name.starts_with("prekey-") && name.ends_with("-phase.norito"))
                    .unwrap();
            let bytes = d.fs.visible_file(&root, &name).unwrap();
            let replacement = if mutation == "foreign" {
                // A well-formed phase of this request whose binding names another slot: a
                // scope mismatch against the authenticated Slot selection.
                let mut state = super::enrollment_phase::test_decode_phase_record(&bytes);
                state.binding.slot = [9; 32];
                super::enrollment_phase::test_phase_record(&state)
            } else {
                let mut corrupt = bytes;
                let last = corrupt.len() - 1;
                corrupt[last] ^= 1;
                corrupt
            };
            d.fs.unlink(&root, &name).unwrap();
            d.fs.place_unsynced(&root, &name, &replacement);
            let before = slot_names(&d);
            let label = format!("{mutation} intent_only {intent_only}");
            // Repeated abandonment, intervening reconciliation and a restart all fail closed.
            for round in 0..3 {
                if round == 2 {
                    drop(current.into_provider());
                    d.fs.restart();
                    current = owner(&f, &d);
                    dispatch(&f, &mut current);
                }
                let abandoned = current.abandon();
                assert!(
                    matches!(
                        abandoned,
                        Err(Error::Provider(
                            KagemushaWalletProviderErrorV1::UnavailableCustodyData { .. }
                        ))
                    ),
                    "{label} round {round}: {abandoned:?}"
                );
                assert!(
                    matches!(
                        current.progress(),
                        Err(Error::Provider(
                            KagemushaWalletProviderErrorV1::UnavailableCustodyData { .. }
                        ))
                    ),
                    "{label} round {round}"
                );
                assert_eq!(slot_names(&d), before, "{label}: nothing written");
            }
            d.platform.with(|s| {
                assert_eq!(s.generate_calls, 0);
                assert_eq!(s.sign_calls, 0);
            });
        }
    }
}

#[test]
fn a_lost_phase_never_downgrades_custody_to_absence_or_reconstruction() {
    // After E2 (intent and key effect pending) and after E4 (committed marker), losing the
    // mandatory phase together with the original it witnesses fails closed.
    for after_marker in [false, true] {
        let f = fixture();
        let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 251);
        let current = if after_marker {
            enrolled(&f, &d)
        } else {
            interrupted_prekey_before_marker(&f, &d, true)
        };
        let slot = current.into_provider().slots().unwrap()[0];
        d.fs.restart();
        let root = KagemushaWalletCustodyDirV1::root();
        let phase =
            d.fs.visible_names(&root)
                .into_iter()
                .find(|name| name.ends_with("-phase.norito"))
                .unwrap();
        d.fs.unlink(&root, &phase).unwrap();
        let dir = super::layout::kagemusha_wallet_slot_dir_v1(&slot);
        let markers = super::layout::kagemusha_wallet_markers_dir_v1(&slot);
        if after_marker {
            for name in d.fs.visible_names(&markers) {
                d.fs.unlink(&markers, &name).unwrap();
            }
        } else {
            d.fs.unlink(&dir, "intent.norito").unwrap();
        }
        let before = slot_names(&d);
        let mut current = owner(&f, &d);
        dispatch(&f, &mut current);
        for _ in 0..2 {
            assert!(current.abandon().is_err(), "after marker {after_marker}");
            assert!(current.progress().is_err(), "after marker {after_marker}");
        }
        let mut provider = current.into_provider();
        assert!(provider.status(&slot).is_err());
        assert_eq!(slot_names(&d), before, "nothing restored or abandoned");
        assert!(d.fs.visible_names(&markers).is_empty() || !after_marker);
        d.platform
            .with(|s| assert_eq!(s.generate_calls, usize::from(after_marker)));
    }
}

#[test]
fn a_retained_reply_never_republishes_a_committed_marker() {
    use super::test_support::AnchorWriteV1;
    let f = fixture();
    let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::Keychain, 253);
    let mut current = owner(&f, &d);
    let message = begin(&f, &mut current);
    // E4 and its commit succeed; raising the keychain anchor fails, so this owner keeps the
    // actual generation reply.
    // Anchor writes: the unnamed anchor at E2, then the raise after the committed E4.
    d.platform
        .with(|s| s.anchor_fault_at = Some((s.anchor_writes + 1, AnchorWriteV1::Refused)));
    assert!(current.authorize(&sign(&f, &message)).is_err());
    let mut provider = current.into_provider();
    let slot = provider.slots().unwrap()[0];
    assert!(provider.has_retained_generation(&slot));
    assert!(matches!(
        fixture_phase(&provider).unwrap().phase,
        KagemushaWalletEnrollmentPhaseV1::MarkerCommitted { .. }
    ));
    let markers = super::layout::kagemusha_wallet_markers_dir_v1(&slot);
    for name in d.fs.visible_names(&markers) {
        d.fs.unlink(&markers, &name).unwrap();
    }
    for _ in 0..2 {
        assert!(matches!(
            provider.status(&slot),
            Err(KagemushaWalletProviderErrorV1::UnavailableCustodyData {
                object: "committed enrollment marker"
            })
        ));
        assert!(
            d.fs.visible_names(&markers).is_empty(),
            "generation zero is never republished"
        );
    }
    let mut current = EnrollmentOwnerV1::new(provider, f.config.clone())
        .unwrap_or_else(|(_, error)| panic!("{error}"));
    dispatch(&f, &mut current);
    assert!(current.progress().is_err());
    assert!(current.abandon().is_err());
    assert!(d.fs.visible_names(&markers).is_empty());
}

#[test]
fn phase_corruption_is_caught_with_a_populated_cache_and_after_restart() {
    let f = fixture();
    let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 65);
    let mut current = enrolled(&f, &d);
    // Populate the verified cache.
    for _ in 0..2 {
        assert!(matches!(
            current.progress().unwrap(),
            EnrollmentProgressV1::Evidence { .. }
        ));
    }
    let root = KagemushaWalletCustodyDirV1::root();
    let name =
        d.fs.visible_names(&root)
            .into_iter()
            .find(|name| name.ends_with("-phase.norito"))
            .unwrap();
    let mut corrupt = d.fs.visible_file(&root, &name).unwrap();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 1;
    d.fs.unlink(&root, &name).unwrap();
    d.fs.place_unsynced(&root, &name, &corrupt);
    let mut provider = current.into_provider();
    let slot = provider.slots().unwrap()[0];
    for _ in 0..2 {
        assert!(matches!(
            provider.status(&slot),
            Err(KagemushaWalletProviderErrorV1::UnavailableCustodyData { .. })
        ));
    }
    drop(provider);
    d.fs.restart();
    let mut current = owner(&f, &d);
    dispatch(&f, &mut current);
    assert!(current.progress().is_err());
    assert!(current.abandon().is_err());
}

#[test]
fn a_missing_accepted_permit_stops_selected_marker_restoration_before_any_write() {
    let f = fixture();
    let (d, slot) =
        marker_selected_without_marker(&f, KagemushaWalletAnchorPolicyV1::NotRequired, 61);
    let root = KagemushaWalletCustodyDirV1::root();
    let accepted =
        d.fs.visible_names(&root)
            .into_iter()
            .find(|name| name.starts_with("prekey-") && name.ends_with("-accepted.norito"))
            .unwrap();
    d.fs.unlink(&root, &accepted).unwrap();
    let before = slot_names(&d);
    let mut provider = owner(&f, &d).into_provider();
    assert!(matches!(
        provider.status(&slot),
        Err(KagemushaWalletProviderErrorV1::UnavailableCustodyData {
            object: "selected pre-key originals"
        })
    ));
    let mut current = EnrollmentOwnerV1::new(provider, f.config.clone())
        .unwrap_or_else(|(_, error)| panic!("{error}"));
    // The owner cannot even resume the attempt without its accepted permit.
    assert!(
        current
            .begin(
                &[11; 32],
                &norito::encode_canonical(&f.account).unwrap(),
                &norito::encode_canonical(&f.asset).unwrap(),
            )
            .is_err()
    );
    assert!(current.progress().is_err());
    assert!(current.abandon().is_err());
    assert_eq!(slot_names(&d), before, "no marker is restored");
}

#[test]
fn a_valid_but_foreign_intent_is_never_probed_or_abandoned_under() {
    let f = fixture();
    let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 63);
    let current = interrupted_prekey_before_marker(&f, &d, true);
    let mut provider = current.into_provider();
    let slot = provider.slots().unwrap()[0];
    // A well-formed intent of the same slot with other dates, and a key under the slot.
    let mut foreign = provider.read_intent(&slot).unwrap().unwrap();
    foreign.dates.expires_at_ms += 1;
    let dir = super::layout::kagemusha_wallet_slot_dir_v1(&slot);
    d.fs.unlink(&dir, "intent.norito").unwrap();
    d.fs.place_unsynced(
        &dir,
        "intent.norito",
        &super::encode_envelope_v1(
            &foreign,
            super::enrollment::KAGEMUSHA_WALLET_INTENT_MAX_BYTES_V1,
        )
        .unwrap(),
    );
    d.platform.with(|s| {
        s.keys.insert(slot, signing_key(5));
    });
    let probes = d.platform.with(|s| s.probe_calls);
    let before = slot_names(&d);
    for _ in 0..2 {
        assert!(matches!(
            provider.status(&slot),
            Err(KagemushaWalletProviderErrorV1::UnavailableCustodyData {
                object: "enrollment phase intent"
            })
        ));
    }
    let mut current = EnrollmentOwnerV1::new(provider, f.config.clone())
        .unwrap_or_else(|(_, error)| panic!("{error}"));
    dispatch(&f, &mut current);
    assert!(current.abandon().is_err());
    assert_eq!(
        slot_names(&d),
        before,
        "never KeyWithoutMarker, never a local abandonment"
    );
    d.platform.with(|s| assert_eq!(s.probe_calls, probes));
}

#[test]
fn a_replaced_client_before_the_first_authorization_has_no_effect() {
    for foreign in [false, true] {
        let f = fixture();
        let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 67);
        let mut current = owner(&f, &d);
        let message = begin(&f, &mut current);
        let root = KagemushaWalletCustodyDirV1::root();
        let name =
            d.fs.visible_names(&root)
                .into_iter()
                .find(|name| name.starts_with("prekey-") && name.ends_with("-client.norito"))
                .unwrap();
        let bytes = d.fs.visible_file(&root, &name).unwrap();
        let replacement = if foreign {
            // A well-formed Fresh dispatch of the same request with another client nonce.
            let mut other = PreKeyDispatchV1::decode(&bytes).unwrap();
            other.client_nonce = [77; 32];
            other.encode().unwrap()
        } else {
            let mut malformed = bytes;
            let last = malformed.len() - 1;
            malformed[last] ^= 1;
            malformed
        };
        d.fs.unlink(&root, &name).unwrap();
        d.fs.place_unsynced(&root, &name, &replacement);
        assert!(
            current.authorize(&sign(&f, &message)).is_err(),
            "foreign {foreign}"
        );
        let names = d.fs.visible_names(&root);
        assert!(
            !names
                .iter()
                .any(|name| name.ends_with("-phase.norito") || name.ends_with("-slot.norito")),
            "foreign {foreign}: no phase or Slot selection: {names:?}"
        );
        assert!(
            slot_names(&d).is_empty(),
            "foreign {foreign}: no slot custody"
        );
        d.platform.with(|s| {
            assert_eq!(s.generate_calls, 0);
            assert_eq!(s.fresh_generation_calls, 0);
        });
    }
}

#[test]
fn a_lost_slot_selection_of_an_enrolled_attempt_is_never_rebuilt() {
    let f = fixture();
    let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 69);
    let slot = enrolled(&f, &d).into_provider().slots().unwrap()[0];
    d.fs.restart();
    let root = KagemushaWalletCustodyDirV1::root();
    let name =
        d.fs.visible_names(&root)
            .into_iter()
            .find(|name| name.starts_with("prekey-") && name.ends_with("-slot.norito"))
            .unwrap();
    d.fs.unlink(&root, &name).unwrap();
    for _ in 0..2 {
        let mut current = owner(&f, &d);
        let resumed = dispatch(&f, &mut current);
        let message = current
            .accept_permit(&permit(&f, &resumed).encode_canonical().unwrap())
            .unwrap();
        assert!(matches!(
            current.authorize(&sign(&f, &message)),
            Err(Error::Provider(
                KagemushaWalletProviderErrorV1::UnavailableCustodyData {
                    object: "selected pre-key slot"
                }
            ))
        ));
        assert!(
            !d.fs.visible_names(&root).contains(&name),
            "the Slot selection is never republished"
        );
        let mut provider = current.into_provider();
        assert!(provider.status(&slot).is_err());
        drop(provider);
        d.fs.restart();
    }
    d.platform.with(|s| assert_eq!(s.generate_calls, 1));
}

#[test]
fn retained_generation_recovery_authenticates_originals_before_asking_the_platform() {
    for reply in [false, true] {
        let f = fixture();
        let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 71);
        d.platform.with(|s| {
            s.generation_policy = KagemushaWalletKeyGenerationPolicyV1::FreshEnrollmentOnly;
        });
        let mut current = owner(&f, &d);
        let message = begin(&f, &mut current);
        if reply {
            // The actual reply is retained: storage locks right after the vendor returns.
            d.platform.with(|s| s.lock_after_generation = true);
        } else {
            // Only the dispatch is retained: the vendor created the key, its reply was lost.
            d.platform.with(|s| s.generate_unavailable = Some(true));
        }
        assert!(current.authorize(&sign(&f, &message)).is_err());
        d.platform.with(|s| {
            s.lock_after_generation = false;
            s.generate_unavailable = None;
            s.storage = Ok(());
            // Any platform recovery call would answer Busy instead of the custody refusal.
            s.generation_readback_unavailable = true;
        });
        let mut provider = current.into_provider();
        let slot = provider.slots().unwrap()[0];
        assert!(provider.has_retained_generation(&slot), "reply {reply}");
        let root = KagemushaWalletCustodyDirV1::root();
        let accepted =
            d.fs.visible_names(&root)
                .into_iter()
                .find(|name| name.starts_with("prekey-") && name.ends_with("-accepted.norito"))
                .unwrap();
        d.fs.unlink(&root, &accepted).unwrap();
        let probes = d.platform.with(|s| s.probe_calls);
        let before = slot_names(&d);
        for _ in 0..2 {
            assert!(
                matches!(
                    provider.status(&slot),
                    Err(KagemushaWalletProviderErrorV1::UnavailableCustodyData {
                        object: "selected pre-key originals"
                    })
                ),
                "reply {reply}"
            );
        }
        d.platform
            .with(|s| assert_eq!(s.probe_calls, probes, "reply {reply}: no probe"));
        assert_eq!(slot_names(&d), before, "reply {reply}: nothing published");
        assert!(
            provider.has_retained_generation(&slot),
            "reply {reply}: retained"
        );
    }
}

#[test]
#[ignore = "requires the independently pinned, complete generated wallet catalog and finality metadata"]
fn persisted_complete_sources_open_real_bootstrap_and_reopen_exact_output() {
    use crate::{
        kagemusha_wallet_artifacts_v1::{
            InstallationV1,
            producer_inventory::{
                DirectoryOriginalsV1, PROVING_KEY_MAX_BYTES_V1,
                open_pinned_engineering_wallet_sources,
            },
        },
        kagemusha_wallet_state_v1::{Completion, NativeWalletRuntimeV1},
    };
    use iroha_pasta::msm::MemoryBudget;
    use iroha_plonk::keys::pk::{CosetCachePolicy, artifact::ReadConfig};
    use std::{path::PathBuf, sync::Arc};

    // These are engineering source artifacts and explicit simulated hardware. The complete
    // grant, pinned native genesis, original keys and Bootstrap proof use production owners.
    // This test establishes neither mobile attestation nor a phone performance qualification.
    let output = PathBuf::from(
        std::env::var_os("KAGEMUSHA_WALLET_NATIVE_OUTPUT").expect("fresh native owner output"),
    );
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let parent = output.parent().unwrap().canonicalize().unwrap();
    assert!(parent.starts_with(root.join("target/qualification")));
    assert!(
        !output.exists(),
        "never replace retained qualification output"
    );
    let (installed, sources, genesis, originals) = open_pinned_engineering_wallet_sources(&output);
    let genesis = Arc::new(genesis);
    let mut f = fixture();
    f.config.scheme = *installed.verifier().scheme();
    assert_eq!(
        f.config.scheme.scheme_root_key,
        public_key(&signing_key(17))
    );
    let (scheme_id, manifest_digest) = sources.installation();
    assert_eq!(scheme_id, f.config.scheme.scheme_id());
    f.config.installation = InstallationV1 {
        scheme_id,
        manifest_digest,
    };
    f.config.app.scheme_id = scheme_id;
    f.config.policy.scheme_id = scheme_id;
    f.config.policy.app_policy = f.config.app.policy_digest().unwrap();
    f.config.enrollment_certificate = enrollment_certificate(&f.config.scheme);
    f.challenge.scheme_id = scheme_id;
    f.challenge.app_policy = f.config.app.policy_digest().unwrap();
    f.challenge.enrollment_policy = f.config.policy.policy_digest().unwrap();

    let device = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 83);
    let mut enrollment = enrolled(&f, &device);
    let request = RequestV1::decode(&request(&f, &mut enrollment)).unwrap();
    let result = issuer_result(&f, &request).encode().unwrap();
    enrollment.accept_credential(&result).unwrap();
    let frames = enrollment.open_originals().unwrap();
    let read = ReadConfig {
        maximum_bytes: PROVING_KEY_MAX_BYTES_V1,
        maximum_rows: 1 << 16,
        coset_cache: CosetCachePolicy::OnDemand,
        msm_budget: MemoryBudget::DEFAULT,
    };
    let runtime = NativeWalletRuntimeV1::new(
        enrollment.into_provider(),
        Arc::clone(&installed),
        Arc::clone(&sources),
        Arc::clone(&genesis),
        originals,
        read,
        MemoryBudget::DEFAULT,
    );
    let pending = runtime
        .begin(&frames[0], &frames[1], &frames[2], &frames[3])
        .unwrap();
    let first_challenge = pending.challenge().to_vec();
    let failure = match pending.finish(&[0; 64]) {
        Ok(_) => panic!("invalid account signature admitted"),
        Err(failure) => failure,
    };
    let (runtime, _) = failure.into_parts();
    let mut changed_account = frames[2].clone();
    changed_account.push(0);
    let failure = match runtime.begin(&frames[0], &frames[1], &changed_account, &frames[3]) {
        Ok(_) => panic!("pending account originals changed"),
        Err(failure) => failure,
    };
    let (runtime, _) = failure.into_parts();
    let pending = runtime
        .begin(&frames[0], &frames[1], &frames[2], &frames[3])
        .unwrap();
    assert_eq!(pending.challenge(), first_challenge);
    let signature = sign(&f, pending.challenge());
    let mut wallet = pending.finish(&signature).unwrap();
    let before = device.platform.with(|state| state.sign_calls);
    let completed = wallet.bootstrap().unwrap();
    let Completion::Complete(bytes) = &completed else {
        panic!("actual Bootstrap must reach durable completion");
    };
    assert!(!bytes.is_empty());
    let signed = device.platform.with(|state| state.sign_calls);
    assert_eq!(signed, before + 1);
    assert_eq!(wallet.bootstrap().unwrap(), completed);
    assert_eq!(device.platform.with(|state| state.sign_calls), signed);
    let snapshot = wallet.snapshot().unwrap();
    assert_eq!(snapshot.sequence, 0);
    assert_eq!(snapshot.balance, 0);
    assert_eq!(snapshot.fold_backlog, 1);
    assert!(snapshot.folded_balance.is_none());
    std::fs::write(output.join("bootstrap-original.norito"), bytes).unwrap();
    drop(wallet);

    let provider = KagemushaWalletProviderV1::open(
        device.fs.clone(),
        device.platform.clone(),
        scheme_id,
        test_options(),
    )
    .unwrap();
    let originals =
        DirectoryOriginalsV1::open_existing(output.join("originals"), PROVING_KEY_MAX_BYTES_V1)
            .unwrap();
    let runtime = NativeWalletRuntimeV1::new(
        provider,
        installed,
        sources,
        genesis,
        originals,
        read,
        MemoryBudget::DEFAULT,
    );
    let pending = runtime
        .begin(&frames[0], &frames[1], &frames[2], &frames[3])
        .unwrap();
    assert_ne!(pending.challenge(), first_challenge);
    let signature = sign(&f, pending.challenge());
    let mut recovered = pending.finish(&signature).unwrap();
    assert_eq!(recovered.bootstrap().unwrap(), completed);
    assert_eq!(recovered.snapshot().unwrap(), snapshot);
    assert_eq!(device.platform.with(|state| state.sign_calls), signed);
}

#[test]
fn enrollment_owner_preserves_signed_policy_dates_above_ten_minutes_across_restart() {
    let mut f = fixture();
    f.config.policy.challenge_lifetime_ms = 600_001;
    f.challenge.enrollment_policy = f.config.policy.policy_digest().unwrap();
    let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 137);
    let mut current = owner(&f, &d);
    let original_dispatch = dispatch(&f, &mut current);
    let signed = permit(&f, &original_dispatch);
    let message = current
        .accept_permit(&signed.encode_canonical().unwrap())
        .unwrap();
    current.authorize(&sign(&f, &message)).unwrap();
    let provider = current.into_provider();
    let slots = provider.slots().unwrap();
    let dates = KagemushaWalletEnrollmentDatesV1 {
        issued_at_ms: signed.body.created_at_ms,
        expires_at_ms: signed.body.expires_at_ms,
    };
    assert_eq!(
        provider.read_intent(&slots[0]).unwrap().unwrap().dates,
        dates
    );
    drop(provider);
    d.fs.restart();
    let mut restored = enrolled(&f, &d);
    request(&f, &mut restored);
    let provider = restored.into_provider();
    assert_eq!(provider.slots().unwrap(), slots);
    assert_eq!(
        provider.read_intent(&slots[0]).unwrap().unwrap().dates,
        dates
    );
    d.platform.with(|state| assert_eq!(state.generate_calls, 1));
}

#[test]
fn enrollment_e6_requires_issuance_and_evidence_inside_original_permit_dates() {
    use p256::ecdsa::{Signature as P256Signature, signature::Signer as _};
    let f = fixture();
    let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 139);
    let mut current = enrolled(&f, &d);
    let requested = RequestV1::decode(&request(&f, &mut current)).unwrap();
    let valid = issuer_result(&f, &requested);
    for (issued, evidence) in [(999, 1000), (121_000, 1000), (2000, 999), (2000, 121_000)] {
        let mut altered = valid.clone();
        let mut body = KagemushaWalletCredentialV1::decode_canonical(
            &valid.credential,
            &f.config.scheme.scheme_id(),
        )
        .unwrap()
        .body;
        body.issued_at_ms = issued;
        body.enrollment_evidence.time_ms = evidence;
        body.fresh_evidence = body.enrollment_evidence;
        let signature: P256Signature = signing_key(79).sign(&body.signing_message());
        altered.credential = KagemushaWalletCredentialV1::sign(
            body,
            &f.config.enrollment_certificate,
            KagemushaWalletSignerOutputV1::Raw(signature.to_bytes().into()),
        )
        .unwrap()
        .to_canonical_bytes()
        .unwrap();
        // These are genuine signatures bound to the selected request; only the original
        // permit interval makes them unsuitable for this enrollment attempt.
        altered
            .verify_for(
                &f.config.scheme,
                &f.config.enrollment_certificate,
                &requested,
            )
            .unwrap();
        assert!(
            current
                .accept_credential(&altered.encode().unwrap())
                .is_err()
        );
    }
    assert_eq!(
        current.accept_credential(&valid.encode().unwrap()).unwrap(),
        valid.encode().unwrap()
    );
}

#[test]
fn transient_prekey_clock_failure_retains_exact_dispatch_and_account_challenge() {
    let f = fixture();
    let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 161);
    let mut owner = owner(&f, &d);
    let dispatch = dispatch(&f, &mut owner);
    let permit = permit(&f, &dispatch).encode_canonical().unwrap();
    d.platform
        .with(|state| state.monotonic = Err(KagemushaWalletUnavailableV1::Busy));
    assert!(matches!(
        owner.accept_permit(&permit),
        Err(crate::kagemusha_wallet_enrollment_v1::Error::Provider(_))
    ));
    d.platform.with(|state| state.monotonic = Ok(1000));
    let challenge = owner.accept_permit(&permit).unwrap();
    d.platform
        .with(|state| state.monotonic = Err(KagemushaWalletUnavailableV1::Busy));
    let signature = sign(&f, &challenge);
    assert!(matches!(
        owner.authorize(&signature),
        Err(crate::kagemusha_wallet_enrollment_v1::Error::Provider(_))
    ));
    d.platform.with(|state| {
        assert_eq!(state.generate_calls, 0);
        state.monotonic = Ok(1000);
    });
    assert!(matches!(
        owner.authorize(&signature).unwrap(),
        EnrollmentProgressV1::Evidence { .. }
    ));
    d.platform.with(|state| assert_eq!(state.generate_calls, 1));
}
#[test]
fn authenticated_session_expiry_reaches_final_key_generation_check() {
    let mut f = fixture();
    f.config.session_expires_at_ms = 2005;
    let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 163);
    let mut owner = owner(&f, &d);
    let challenge = begin(&f, &mut owner);
    d.platform.with(|state| {
        state.monotonic_script = [Ok(1000), Ok(1000), Ok(1000), Ok(1000), Ok(1004)].into()
    });
    assert!(owner.authorize(&sign(&f, &challenge)).is_err());
    d.platform.with(|state| assert_eq!(state.generate_calls, 0));
}

#[test]
fn shortened_signed_permit_still_requires_live_session_and_immediate_key_effect() {
    // An issuer may narrow the exact policy lifetime to its authenticated session.
    // Native still intersects that signed deadline with its independent session and
    // rechecks elapsed time immediately before the actual hardware generation.
    for (index, (session_expires, effect_time, succeeds)) in [
        (600_000, 1000, true),
        (600_000, 1010, false),
        (2007, 1007, false),
    ]
    .into_iter()
    .enumerate()
    {
        let mut f = fixture();
        f.config.session_expires_at_ms = session_expires;
        let d = DeviceV1::new(
            KagemushaWalletAnchorPolicyV1::NotRequired,
            181 + index as u8,
        );
        d.platform.with(|s| {
            s.generation_policy = KagemushaWalletKeyGenerationPolicyV1::FreshEnrollmentOnly
        });
        let mut current = owner(&f, &d);
        let selected = dispatch(&f, &mut current);
        let mut body = permit(&f, &selected).body;
        body.expires_at_ms = 2010;
        let signed = resign_permit(&f, body).encode_canonical().unwrap();
        let message = current.accept_permit(&signed).unwrap();
        d.platform.with(|s| {
            s.monotonic_script = [Ok(1000), Ok(1000), Ok(1000), Ok(1000), Ok(effect_time)].into()
        });
        assert_eq!(current.authorize(&sign(&f, &message)).is_ok(), succeeds);
        d.platform
            .with(|s| assert_eq!(s.generate_calls, if succeeds { 1 } else { 0 }));
        assert_eq!(current.into_provider().slots().unwrap().len(), 1);
    }
}

#[test]
fn shortened_signed_permit_never_accepts_a_foreign_session_observation() {
    let mut f = fixture();
    f.config.session_valid_from_ms = 2001;
    let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 185);
    let mut current = owner(&f, &d);
    let selected = dispatch(&f, &mut current);
    let mut body = permit(&f, &selected).body;
    body.expires_at_ms = 2010;
    assert!(
        current
            .accept_permit(&resign_permit(&f, body).encode_canonical().unwrap())
            .is_err()
    );
    d.platform.with(|s| assert_eq!(s.generate_calls, 0));
}

#[test]
fn expired_authorize_archives_its_actual_generated_reply_but_still_refuses_live_authority() {
    let f = fixture();
    let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 181);
    let mut owner = owner(&f, &d);
    let challenge = begin(&f, &mut owner);
    let signature = sign(&f, &challenge);
    d.platform.with(|state| state.lock_after_generation = true);
    assert!(matches!(
        owner.authorize(&signature),
        Err(Error::Provider(
            KagemushaWalletProviderErrorV1::Unavailable(KagemushaWalletUnavailableV1::Locked)
        ))
    ));
    let (slot, key, request) = d.platform.with(|state| {
        assert_eq!(state.generate_calls, 1);
        let (slot, key) = state.keys.iter().next().unwrap();
        (*slot, public_key(key), state.last_generation.unwrap())
    });
    d.platform.clear_faults();
    d.platform.with(|state| state.monotonic = Ok(700_000));
    // This retry must first archive the already returned key, then retain the expiry refusal.
    assert!(matches!(
        owner.authorize(&signature),
        Err(Error::Original("pre-key permit elapsed deadline"))
    ));
    let provider = owner.into_provider();
    assert!(!provider.has_retained_generation(&slot));
    let mut provider = provider;
    let KagemushaWalletSlotStatusV1::Enrollment(marker) = provider.status(&slot).unwrap() else {
        panic!("archived exact result");
    };
    assert_eq!(*marker.payment_key(), key);
    d.platform.with(|state| {
        assert_eq!(state.generate_calls, 1);
        assert_eq!(state.last_generation, Some(request));
        assert_eq!(state.delete_calls, 0);
    });
}

#[test]
fn retained_original_absence_requires_a_real_begun_dispatch_and_available_client_custody() {
    let f = fixture();
    let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 187);
    let mut current = owner(&f, &d);
    assert!(matches!(current.retained_request(), Err(Error::Phase)));
    assert!(matches!(current.retained_result(), Err(Error::Phase)));
    let first = dispatch(&f, &mut current);
    assert!(current.retained_request().unwrap().is_none());
    assert!(current.retained_result().unwrap().is_none());
    d.platform.with(|s| assert_eq!(s.generate_calls, 0));
    drop(current.into_provider());
    d.fs.restart();
    let mut restored = owner(&f, &d);
    let again = dispatch(&f, &mut restored);
    assert_eq!(first.client_nonce, again.client_nonce);
    assert!(restored.retained_request().unwrap().is_none());
    assert!(restored.retained_result().unwrap().is_none());
    for result in [false, true] {
        d.fs.inject(d.fs.steps(), KagemushaWalletSimFaultV1::Error);
        let refused = if result {
            restored.retained_result()
        } else {
            restored.retained_request()
        };
        assert!(matches!(refused, Err(Error::Provider(_))));
        d.fs.clear_faults();
    }
    let root = KagemushaWalletCustodyDirV1::root();
    let client =
        d.fs.visible_names(&root)
            .into_iter()
            .find(|name| name.starts_with("prekey-") && name.ends_with("-client.norito"))
            .unwrap();
    d.fs.unlink(&root, &client).unwrap();
    assert!(restored.retained_request().is_err());
    assert!(restored.retained_result().is_err());
    d.platform.with(|s| assert_eq!(s.generate_calls, 0));
}

#[test]
fn accepted_permit_before_slot_can_report_request_absence_without_a_generation_grant() {
    let f = fixture();
    let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 189);
    let mut current = owner(&f, &d);
    let selected = dispatch(&f, &mut current);
    current
        .accept_permit(&permit(&f, &selected).encode_canonical().unwrap())
        .unwrap();
    drop(current.into_provider());
    d.fs.restart();
    let mut restored = owner(&f, &d);
    let resumed = dispatch(&f, &mut restored);
    assert!(resumed.previous_permit.is_some());
    assert!(restored.retained_request().unwrap().is_none());
    assert!(restored.retained_result().unwrap().is_none());
    d.platform.with(|s| assert_eq!(s.generate_calls, 0));
    // Only the actual new signed live permit and existing-account authorization can
    // proceed through the original Native generation owner; these reads grant nothing.
    let message = restored
        .accept_permit(&permit(&f, &resumed).encode_canonical().unwrap())
        .unwrap();
    assert!(matches!(
        restored.authorize(&sign(&f, &message)).unwrap(),
        EnrollmentProgressV1::Evidence { .. }
    ));
    d.platform.with(|s| assert_eq!(s.generate_calls, 1));
}

#[path = "tests/expired_prekey.rs"]
mod expired_prekey;

#[test]
fn lost_prekey_slot_with_actual_intent_never_becomes_optional_request_absence() {
    let f = fixture();
    let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 191);
    let mut current = enrolled(&f, &d);
    let slot =
        KagemushaWalletSlotIdV1(fixture_phase(current.test_provider()).unwrap().binding.slot);
    request(&f, &mut current);
    drop(current.into_provider());
    let root = KagemushaWalletCustodyDirV1::root();
    let selected =
        d.fs.visible_names(&root)
            .into_iter()
            .find(|name| name.starts_with("prekey-") && name.ends_with("-slot.norito"))
            .unwrap();
    d.fs.unlink(&root, &selected).unwrap();
    d.fs.restart();
    let mut restored = owner(&f, &d);
    assert!(dispatch(&f, &mut restored).previous_permit.is_some());
    let key = d.platform.key_of(&slot);
    let effects = d
        .platform
        .with(|s| (s.generate_calls, s.delete_calls, s.sign_calls));
    let originals = slot_names(&d);
    // Inventory authenticates Phase/Slot agreement before the owner can treat this as
    // request absence. The missing Slot is therefore an earlier typed custody refusal.
    let request = restored.retained_request();
    assert!(
        matches!(
            request,
            Err(Error::Provider(
                KagemushaWalletProviderErrorV1::UnavailableCustodyData {
                    object: "selected pre-key originals"
                }
            ))
        ),
        "{request:?}"
    );
    let result = restored.retained_result();
    assert!(
        matches!(
            result,
            Err(Error::Provider(
                KagemushaWalletProviderErrorV1::UnavailableCustodyData {
                    object: "selected pre-key originals"
                }
            ))
        ),
        "{result:?}"
    );
    assert_eq!(d.platform.key_of(&slot), key);
    assert_eq!(slot_names(&d), originals);
    assert!(d.fs.visible_file(&root, &selected).is_none());
    d.platform.with(|s| {
        assert_eq!(s.generate_calls, 1);
        assert_eq!((s.generate_calls, s.delete_calls, s.sign_calls), effects);
    });
}

fn apple_collection_fixture() -> Fixture {
    let mut f = fixture();
    f.config.app.identity = KagemushaWalletAppIdentityV1::Apple {
        app_id: "TEAM123456.org.example.wallet".into(),
    };
    f.config.policy.app_policy = f.config.app.policy_digest().unwrap();
    let root = b"component Apple root original".to_vec();
    f.config.policy.platform = KagemushaWalletEnrollmentPlatformV1::Apple {
        attestation_root_sha256: Sha256::digest(&root).into(),
    };
    f.config.attestation_root_der = Some(root);
    f.challenge.app_policy = f.config.policy.app_policy;
    f.challenge.enrollment_policy = f.config.policy.policy_digest().unwrap();
    f
}
#[test]
fn apple_collection_dispatch_is_once_and_every_vendor_return_survives_restart() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let f = apple_collection_fixture();
    let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 181);
    let mut current = enrolled(&f, &d);
    assert_eq!(
        current.apple_collection_originals().unwrap(),
        [Vec::<u8>::new(), vec![], vec![]]
    );
    let key = STANDARD.encode([7; 32]).into_bytes();
    current.begin_apple_effect(1).unwrap();
    assert!(current.begin_apple_effect(1).is_err());
    current.retain_apple_effect(1, &key).unwrap();
    current.begin_apple_effect(2).unwrap();
    current
        .retain_apple_effect(2, b"public attestation DATA")
        .unwrap();
    current.begin_apple_effect(3).unwrap();
    current
        .retain_apple_effect(3, b"public assertion DATA")
        .unwrap();
    current.complete_apple_collection().unwrap();
    let originals = current.apple_collection_originals().unwrap();
    drop(current);
    let mut recovered = enrolled(&f, &d);
    assert_eq!(recovered.apple_collection_originals().unwrap(), originals);
    for stage in 1..=3 {
        assert!(recovered.begin_apple_effect(stage).is_err());
    }
    recovered.complete_apple_collection().unwrap();
    d.platform.with(|state| state.monotonic = Ok(999_999));
    assert!(recovered.complete_apple_collection().is_err());
    assert_eq!(recovered.apple_collection_originals().unwrap(), originals);
}
#[test]
fn apple_collection_retries_never_publish_an_undispatched_return() {
    let f = apple_collection_fixture();
    let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 183);
    let mut current = enrolled(&f, &d);
    assert!(current.retain_apple_effect(1, b"unsolicited DATA").is_err());
    assert!(current.apple_collection_originals().is_err());
    assert!(current.begin_apple_effect(1).is_err());
}
#[test]
fn apple_collection_storage_failure_retains_actual_return_before_any_liveness_check() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let f = apple_collection_fixture();
    let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 185);
    let mut current = enrolled(&f, &d);
    current.begin_apple_effect(1).unwrap();
    let original = STANDARD.encode([9; 32]).into_bytes();
    d.fs.inject(d.fs.steps(), KagemushaWalletSimFaultV1::Error);
    assert!(current.retain_apple_effect(1, &original).is_err());
    d.fs.clear_faults();
    d.platform.with(|state| state.monotonic = Ok(999_999));
    assert_eq!(current.apple_collection_originals().unwrap()[0], original);
    assert!(current.begin_apple_effect(2).is_err());
}

#[test]
fn expired_authorize_recovers_actual_platform_return_before_refusing_live_authority() {
    let f = fixture();
    let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 187);
    let mut owner = owner(&f, &d);
    let challenge = begin(&f, &mut owner);
    let signature = sign(&f, &challenge);
    d.platform
        .with(|state| state.generation_readback_unavailable = true);
    assert!(matches!(
        owner.authorize(&signature),
        Err(Error::Provider(
            KagemushaWalletProviderErrorV1::Unavailable(KagemushaWalletUnavailableV1::Busy)
        ))
    ));
    let (slot, key, request) = d.platform.with(|state| {
        assert_eq!(state.generate_calls, 1);
        let (slot, key) = state.keys.iter().next().unwrap();
        (*slot, public_key(key), state.last_generation.unwrap())
    });
    d.platform.with(|state| state.monotonic = Ok(700_000));
    assert!(matches!(
        owner.authorize(&signature),
        Err(Error::Provider(
            KagemushaWalletProviderErrorV1::Unavailable(KagemushaWalletUnavailableV1::Busy)
        ))
    ));
    d.platform
        .with(|state| state.generation_readback_unavailable = false);
    assert!(matches!(
        owner.authorize(&signature),
        Err(Error::Original("pre-key permit elapsed deadline"))
    ));
    let mut provider = owner.into_provider();
    assert!(!provider.has_retained_generation(&slot));
    let KagemushaWalletSlotStatusV1::Enrollment(marker) = provider.status(&slot).unwrap() else {
        panic!("archived actual returned key");
    };
    assert_eq!(*marker.payment_key(), key);
    d.platform.with(|state| {
        assert_eq!(state.generate_calls, 1);
        assert_eq!(state.last_generation, Some(request));
        assert_eq!(state.delete_calls, 0);
    });
}

fn interrupted_prekey_before_marker(f: &Fixture, d: &DeviceV1, intent_only: bool) -> Owner {
    let mut current = owner(f, d);
    let message = begin(f, &mut current);
    // Stop after the actual selected-slot publication, either before E2 or
    // immediately before the hardware effect after its durable intent exists.
    let successful_clocks = if intent_only { 4 } else { 1 };
    d.platform.with(|state| {
        state.monotonic_script = std::iter::repeat_n(Ok(1000), successful_clocks)
            .chain([Err(KagemushaWalletUnavailableV1::Busy)])
            .collect();
    });
    assert!(matches!(
        current.authorize(&sign(f, &message)),
        Err(Error::Provider(_))
    ));
    d.platform.with(|state| {
        assert!(state.monotonic_script.is_empty());
        assert_eq!(state.generate_calls, 0);
    });
    current
}

#[test]
fn selected_pre_e5_absence_allows_same_id_authorized_retry_without_generating_on_read() {
    for intent_only in [false, true] {
        for restart in [false, true] {
            let f = fixture();
            let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 195);
            let mut current = interrupted_prekey_before_marker(&f, &d, intent_only);
            if restart {
                drop(current.into_provider());
                d.fs.restart();
                current = owner(&f, &d);
            }
            let resumed = dispatch(&f, &mut current);
            assert!(resumed.previous_permit.is_some());
            assert!(current.retained_request().unwrap().is_none());
            assert!(current.retained_result().unwrap().is_none());
            assert!(matches!(
                current.progress().unwrap(),
                EnrollmentProgressV1::Pending
            ));
            d.platform.with(|state| assert_eq!(state.generate_calls, 0));
            let message = current
                .accept_permit(&permit(&f, &resumed).encode_canonical().unwrap())
                .unwrap();
            assert!(matches!(
                current.authorize(&sign(&f, &message)).unwrap(),
                EnrollmentProgressV1::Evidence { .. }
            ));
            let original = request(&f, &mut current);
            assert_eq!(current.retained_request().unwrap(), Some(original));
            d.platform.with(|state| {
                assert_eq!(state.generate_calls, 1);
                assert_eq!(state.delete_calls, 0);
            });
        }
    }
}

#[test]
fn selected_pre_e5_absence_preserves_unavailable_storage_and_key_answers() {
    for intent_only in [false, true] {
        let f = fixture();
        let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 197);
        let mut current = interrupted_prekey_before_marker(&f, &d, intent_only);
        dispatch(&f, &mut current);
        d.platform.with(|state| state.probe_unavailable = true);
        if intent_only {
            assert!(matches!(
                current.retained_request(),
                Err(Error::Provider(_))
            ));
            assert!(matches!(current.retained_result(), Err(Error::Provider(_))));
        } else {
            // A durable `PreIntent` phase proves that no key exists: nothing is probed.
            let probes = d.platform.with(|state| state.probe_calls);
            assert!(current.retained_request().unwrap().is_none());
            assert!(current.retained_result().unwrap().is_none());
            d.platform
                .with(|state| assert_eq!(state.probe_calls, probes));
        }
        d.platform.with(|state| {
            state.probe_unavailable = false;
            state.storage = Err(KagemushaWalletUnavailableV1::Locked);
        });
        assert!(matches!(
            current.retained_request(),
            Err(Error::Provider(_))
        ));
        assert!(matches!(current.retained_result(), Err(Error::Provider(_))));
        d.platform.with(|state| state.storage = Ok(()));
        for result in [false, true] {
            d.fs.inject(d.fs.steps(), KagemushaWalletSimFaultV1::Error);
            let read = if result {
                current.retained_result()
            } else {
                current.retained_request()
            };
            assert!(matches!(read, Err(Error::Provider(_))));
            d.fs.clear_faults();
        }
        assert!(current.retained_result().unwrap().is_none());
        d.platform.with(|state| assert_eq!(state.generate_calls, 0));
    }
}

#[test]
fn selected_pre_e5_absence_requires_all_original_prekey_records() {
    for intent_only in [false, true] {
        for role in ["client", "accepted", "slot"] {
            let f = fixture();
            let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 199);
            let mut current = interrupted_prekey_before_marker(&f, &d, intent_only);
            dispatch(&f, &mut current);
            let root = KagemushaWalletCustodyDirV1::root();
            let name =
                d.fs.visible_names(&root)
                    .into_iter()
                    .find(|name| {
                        name.starts_with("prekey-") && name.ends_with(&format!("-{role}.norito"))
                    })
                    .unwrap();
            d.fs.unlink(&root, &name).unwrap();
            assert!(current.retained_request().is_err());
            assert!(current.retained_result().is_err());
            d.platform.with(|state| assert_eq!(state.generate_calls, 0));
        }
    }
}

#[test]
fn session_renewal_reauthenticates_same_attempt_without_extending_its_permit_dates() {
    let mut f = fixture();
    // Allow the conservative one-millisecond ceiling at acceptance, then expire
    // after the next monotonic tick before account authorization.
    f.config.session_expires_at_ms = 2002;
    let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 201);
    let mut current = owner(&f, &d);
    let selected = dispatch(&f, &mut current);
    let first = permit(&f, &selected).encode_canonical().unwrap();
    let message = current.accept_permit(&first).unwrap();
    d.platform.with(|s| s.monotonic = Ok(1001));
    assert!(current.authorize(&sign(&f, &message)).is_err());
    let mut renewed = f.config.clone();
    renewed.session_expires_at_ms = 600_000;
    current.renew_session(renewed).unwrap();
    assert!(matches!(
        current.authorize(&sign(&f, &message)),
        Err(Error::Phase)
    ));
    let resumed = dispatch(&f, &mut current);
    assert_eq!(resumed.previous_permit, Some(first.clone()));
    assert_eq!(resumed.client_nonce, selected.client_nonce);
    assert_ne!(
        resumed.native_dispatch_nonce,
        selected.native_dispatch_nonce
    );
    let signed = permit(&f, &resumed);
    let initial = KagemushaEnrollmentPermitV1::decode_canonical(
        &first,
        &f.config.scheme,
        &f.config.enrollment_certificate,
    )
    .unwrap();
    assert_eq!(signed.body.created_at_ms, initial.body.created_at_ms);
    assert_eq!(signed.body.expires_at_ms, initial.body.expires_at_ms);
    let message = current
        .accept_permit(&signed.encode_canonical().unwrap())
        .unwrap();
    assert!(matches!(
        current.authorize(&sign(&f, &message)).unwrap(),
        EnrollmentProgressV1::Evidence { .. }
    ));
    // A new session never extends the immutable permit's final effect deadline.
    let resumed = dispatch(&f, &mut current);
    let message = current
        .accept_permit(&permit(&f, &resumed).encode_canonical().unwrap())
        .unwrap();
    d.platform.with(|s| s.monotonic = Ok(500_000));
    assert!(current.authorize(&sign(&f, &message)).is_err());
    d.platform.with(|s| assert_eq!(s.generate_calls, 1));
}

#[test]
fn session_renewal_rejects_every_changed_immutable_selection_without_consuming_challenge() {
    let f = fixture();
    let changes: &[fn(&mut EnrollmentConfigV1)] = &[
        |c| c.scheme.network_id[0] ^= 1,
        |c| c.app.version += 1,
        |c| c.policy.version += 1,
        |c| c.attestation_root_der = Some(b"substituted root".to_vec()),
        |c| c.installation.manifest_digest[0] ^= 1,
        |c| c.enrollment_certificate.body.serial += 1,
        |c| c.service_origin.push(1),
        |c| c.fi.push(1),
        |c| c.actor.push(1),
        |c| c.release.push(1),
        |c| c.session_valid_from_ms = c.session_expires_at_ms,
    ];
    for change in changes {
        let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 203);
        let mut current = owner(&f, &d);
        let message = begin(&f, &mut current);
        let mut candidate = f.config.clone();
        change(&mut candidate);
        assert!(current.renew_session(candidate).is_err());
        assert!(matches!(
            current.authorize(&sign(&f, &message)).unwrap(),
            EnrollmentProgressV1::Evidence { .. }
        ));
        d.platform.with(|s| assert_eq!(s.generate_calls, 1));
    }
}

#[test]
fn session_renewal_keeps_actual_generated_custody_across_storage_and_readback_failures() {
    for readback in [false, true] {
        let f = fixture();
        let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 205);
        let mut current = owner(&f, &d);
        let message = begin(&f, &mut current);
        d.platform.with(|s| {
            s.lock_after_generation = !readback;
            s.generation_readback_unavailable = readback;
        });
        assert!(matches!(
            current.authorize(&sign(&f, &message)),
            Err(Error::Provider(_))
        ));
        let original = d.platform.with(|s| {
            assert_eq!(s.generate_calls, 1);
            let (slot, key) = s.keys.iter().next().unwrap();
            (*slot, public_key(key), s.last_generation.unwrap())
        });
        let mut renewed = f.config.clone();
        renewed.session_expires_at_ms += 1000;
        current.renew_session(renewed).unwrap();
        d.platform.clear_faults();
        d.platform.with(|s| {
            s.generation_readback_unavailable = false;
            s.lock_after_generation = false;
        });
        let resumed = dispatch(&f, &mut current);
        assert!(current.retained_result().unwrap().is_none());
        let message = current
            .accept_permit(&permit(&f, &resumed).encode_canonical().unwrap())
            .unwrap();
        assert!(matches!(
            current.authorize(&sign(&f, &message)).unwrap(),
            EnrollmentProgressV1::Evidence { .. }
        ));
        let mut provider = current.into_provider();
        assert!(!provider.has_retained_generation(&original.0));
        let KagemushaWalletSlotStatusV1::Enrollment(marker) = provider.status(&original.0).unwrap()
        else {
            panic!("same generated original")
        };
        assert_eq!(*marker.payment_key(), original.1);
        d.platform.with(|s| {
            assert_eq!(s.generate_calls, 1);
            assert_eq!(s.last_generation, Some(original.2));
            assert_eq!(s.delete_calls, 0);
        });
    }
}

#[test]
fn session_renewal_flushes_apple_returns_and_requires_new_live_authorization() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let f = apple_collection_fixture();
    let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 207);
    let mut current = enrolled(&f, &d);
    current.begin_apple_effect(1).unwrap();
    let actual_return = STANDARD.encode([9; 32]).into_bytes();
    d.fs.inject(d.fs.steps(), KagemushaWalletSimFaultV1::Error);
    assert!(current.retain_apple_effect(1, &actual_return).is_err());
    d.fs.clear_faults();
    d.fs.inject(d.fs.steps(), KagemushaWalletSimFaultV1::Error);
    assert!(current.renew_session(f.config.clone()).is_err());
    d.fs.clear_faults();
    current.renew_session(f.config.clone()).unwrap();
    assert_eq!(
        current.apple_collection_originals().unwrap()[0],
        actual_return
    );
    assert!(current.begin_apple_effect(1).is_err());
    assert!(current.begin_apple_effect(2).is_err());
    let resumed = dispatch(&f, &mut current);
    let message = current
        .accept_permit(&permit(&f, &resumed).encode_canonical().unwrap())
        .unwrap();
    current.authorize(&sign(&f, &message)).unwrap();
    assert!(current.begin_apple_effect(1).is_err());
    current.begin_apple_effect(2).unwrap();
    assert_eq!(
        current.apple_collection_originals().unwrap()[0],
        actual_return
    );
    d.platform.with(|s| assert_eq!(s.generate_calls, 1));
}

#[test]
fn session_renewal_preserves_exact_retained_e5_and_e6() {
    let f = fixture();
    let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 209);
    let mut current = enrolled(&f, &d);
    let e5 = request(&f, &mut current);
    current.renew_session(f.config.clone()).unwrap();
    dispatch(&f, &mut current);
    assert_eq!(current.retained_request().unwrap(), Some(e5.clone()));
    let e6 = issuer_result(&f, &RequestV1::decode(&e5).unwrap())
        .encode()
        .unwrap();
    current.accept_credential(&e6).unwrap();
    current.renew_session(f.config.clone()).unwrap();
    dispatch(&f, &mut current);
    assert_eq!(current.retained_request().unwrap(), Some(e5));
    assert_eq!(current.retained_result().unwrap(), Some(e6));
    d.platform.with(|s| {
        assert_eq!(s.generate_calls, 1);
        assert_eq!(s.delete_calls, 0);
    });
}

#[test]
fn prekey_definitive_absence_rechecks_deadline_after_intent_phase_selection() {
    let f = fixture();
    let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::NotRequired, 164);
    let mut owner = owner(&f, &d);
    let message = begin(&f, &mut owner);
    // Owner authorization, grant, begin, pre-intent and pre-phase checks all pass.
    // Time expires during the phase's filesystem work, before the hardware dispatch.
    d.platform.with(|state| {
        state.monotonic_script = std::iter::repeat_n(Ok(1000), 5)
            .chain([Ok(120_000)])
            .collect();
    });
    let result = owner.authorize(&sign(&f, &message));
    d.platform.with(|state| {
        assert_eq!(
            state.generate_calls, 0,
            "expired phase must not generate a key"
        );
        assert_eq!(state.sign_calls, 0);
        assert_eq!(state.delete_calls, 0);
        assert!(
            state.monotonic_script.is_empty(),
            "final dispatch check must run"
        );
    });
    assert!(result.is_err());
    let mut provider = owner.into_provider();
    let slots = provider.slots().unwrap();
    assert_eq!(slots.len(), 1, "retain the already durable intent");
    assert!(matches!(
        provider.status(&slots[0]).unwrap(),
        KagemushaWalletSlotStatusV1::IntentOnly
    ));
}

#[test]
fn enrollment_owner_fresh_apple_incarnation_preserves_old_orphan_custody() {
    let f = apple_collection_fixture();
    let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::Keychain, 171);
    let orphan = KagemushaWalletSlotIdV1([170; 32]);
    d.platform.with(|s| {
        s.keys.insert(orphan, signing_key(170));
    });
    let old_key = d.platform.key_of(&orphan).unwrap();
    d.platform.with(|s| {
        s.anchors.insert(orphan, b"old retained anchor".to_vec());
    });
    let old_anchor = d.platform.with(|s| s.anchors[&orphan].clone());
    let lost = Err(KagemushaWalletProviderErrorV1::LostCustody(
        KagemushaWalletLostCustodyV1::KeyWithoutMarker,
    ));
    let mut current = owner(&f, &d);
    assert_eq!(current.test_provider().status(&orphan), lost);
    let message = begin(&f, &mut current);
    let EnrollmentProgressV1::Evidence { slot, marker, .. } = current
        .authorize(&sign(&f, &message))
        .expect("distinct fresh incarnation")
    else {
        panic!("fresh hardware-key enrollment")
    };
    let selected = KagemushaWalletSlotIdV1(slot);
    assert_ne!(selected, orphan);
    assert_ne!(marker.payment_key, old_key);
    assert_eq!(current.test_provider().status(&orphan), lost);
    assert!(
        d.fs.visible_names(&super::layout::kagemusha_wallet_slot_dir_v1(&orphan))
            .is_empty()
    );
    assert_eq!(d.platform.key_of(&orphan), Some(old_key));
    assert!(
        current
            .test_provider()
            .credential(&selected, 0)
            .unwrap()
            .is_none()
    );
    let selected_key = d.platform.key_of(&selected).unwrap();
    drop(current);
    d.fs.restart();
    let mut resumed = owner(&f, &d);
    let message = begin(&f, &mut resumed);
    assert!(matches!(resumed.authorize(&sign(&f, &message)).unwrap(),
        EnrollmentProgressV1::Evidence { slot: same, .. } if same == slot));
    assert_eq!(resumed.test_provider().status(&orphan), lost);
    assert_eq!(d.platform.key_of(&orphan), Some(old_key));
    assert_eq!(d.platform.key_of(&selected), Some(selected_key));
    d.platform.with(|s| {
        assert_eq!(s.anchors[&orphan], old_anchor);
        assert_eq!(s.generate_calls, 1);
        assert_eq!(s.delete_calls, 0);
        assert_eq!(s.sign_calls, 0);
        assert_eq!(
            s.last_generation.unwrap().profile,
            KagemushaWalletKeyProfileV1::SecureElement
        );
        assert!(s.violations.is_empty());
    });
}

#[test]
fn enrollment_owner_fresh_apple_incarnation_preserves_unknown_inventory_and_key_answers() {
    for enumeration in [false, true] {
        let f = apple_collection_fixture();
        let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::Keychain, 172);
        let orphan = KagemushaWalletSlotIdV1([170; 32]);
        d.platform.with(|s| {
            s.keys.insert(orphan, signing_key(170));
        });
        let mut current = owner(&f, &d);
        let message = begin(&f, &mut current);
        d.platform.with(|s| {
            if enumeration {
                s.enumerate_override = Some(Err(KagemushaWalletUnavailableV1::Locked));
            } else {
                s.probe_unavailable = true;
            }
        });
        assert!(matches!(
            current.authorize(&sign(&f, &message)),
            Err(Error::Provider(
                KagemushaWalletProviderErrorV1::Unavailable(_)
            ))
        ));
        assert!(
            d.fs.visible_names(&super::layout::kagemusha_wallet_slot_dir_v1(&orphan))
                .is_empty()
        );
        d.platform.with(|s| {
            assert_eq!(s.generate_calls, 0);
            assert_eq!(s.delete_calls, 0);
            assert_eq!(s.sign_calls, 0);
            assert_eq!(s.keys.len(), 1);
        });
    }
}

#[test]
fn enrollment_owner_lost_selected_apple_incarnation_never_becomes_fresh() {
    let f = apple_collection_fixture();
    let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::Keychain, 173);
    let mut current = enrolled(&f, &d);
    let slot =
        KagemushaWalletSlotIdV1(fixture_phase(current.test_provider()).unwrap().binding.slot);
    let key = d.platform.key_of(&slot).unwrap();
    drop(current);
    // Keep only Client and Accepted for the selected request, and the surviving key.
    // In particular, an absent Slot+Phase may not synthesize a new binding for this E1.
    let root = KagemushaWalletCustodyDirV1::root();
    for name in d.fs.visible_names(&root) {
        if name.starts_with("prekey-")
            && (name.ends_with("-slot.norito") || name.ends_with("-phase.norito"))
        {
            d.fs.unlink(&root, &name).unwrap();
        }
    }
    let dir = super::layout::kagemusha_wallet_slot_dir_v1(&slot);
    d.fs.unlink(&dir, "intent.norito").unwrap();
    let markers = super::layout::kagemusha_wallet_markers_dir_v1(&slot);
    for name in d.fs.visible_names(&markers) {
        d.fs.unlink(&markers, &name).unwrap();
    }
    for name in d.fs.visible_names(&dir) {
        d.fs.remove_dir(&dir, &name).unwrap();
    }
    d.fs.remove_dir(
        &super::layout::kagemusha_wallet_slots_dir_v1(),
        slot.dir_name().as_str(),
    )
    .unwrap();
    assert!(!d.fs.visible_dir(&dir));
    d.fs.sync_dir(&root).unwrap();
    d.fs.sync_dir(&super::layout::kagemusha_wallet_slots_dir_v1())
        .unwrap();
    d.fs.restart();
    assert!(!d.fs.visible_dir(&dir));
    let mut resumed = owner(&f, &d);
    let dispatch = dispatch(&f, &mut resumed);
    assert!(resumed.retained_request().is_err());
    let message = resumed
        .accept_permit(&permit(&f, &dispatch).encode_canonical().unwrap())
        .unwrap();
    assert!(resumed.authorize(&sign(&f, &message)).is_err());
    assert_eq!(d.platform.key_of(&slot), Some(key));
    d.platform.with(|s| {
        assert_eq!(s.generate_calls, 1);
        assert_eq!(s.delete_calls, 0);
        assert_eq!(s.sign_calls, 0);
        assert_eq!(s.keys.len(), 1);
    });
}

#[test]
fn enrollment_owner_fresh_apple_incarnation_refuses_orphan_with_any_slot_directory() {
    for journal in [false, true] {
        let f = apple_collection_fixture();
        let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::Keychain, 174);
        let orphan = KagemushaWalletSlotIdV1([170; 32]);
        d.platform.with(|s| {
            s.keys.insert(orphan, signing_key(170));
        });
        let mut current = owner(&f, &d);
        super::layout::kagemusha_wallet_prepare_slot_dirs_v1(
            current.test_provider().store(),
            &orphan,
        )
        .unwrap();
        if journal {
            let dir = super::layout::kagemusha_wallet_slot_dir_v1(&orphan);
            d.fs.place_unsynced(&dir, "intent.norito", b"lost original");
        }
        let before = slot_names(&d);
        let message = begin(&f, &mut current);
        assert!(current.authorize(&sign(&f, &message)).is_err());
        assert_eq!(slot_names(&d), before);
        d.platform.with(|s| {
            assert_eq!(s.generate_calls, 0);
            assert_eq!(s.delete_calls, 0);
            assert_eq!(s.sign_calls, 0);
            assert_eq!(s.keys.len(), 1);
        });
    }
}

#[test]
fn enrollment_owner_fresh_apple_incarnation_refuses_selected_alias_collision() {
    let f = apple_collection_fixture();
    let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::Keychain, 175);
    let orphan = KagemushaWalletSlotIdV1([170; 32]);
    d.platform.with(|s| {
        s.keys.insert(orphan, signing_key(170));
    });
    let mut current = owner(&f, &d);
    let message = begin(&f, &mut current);
    let client = current
        .test_provider()
        .prekey_read(&[11; 32], PreKeyRecordV1::Client)
        .unwrap()
        .unwrap();
    let client_digest = kagemusha_wallet_prekey_client_digest_v1(&client);
    let client = PreKeyDispatchV1::decode(&client).unwrap();
    let accepted = current
        .test_provider()
        .prekey_read(&[11; 32], PreKeyRecordV1::Accepted)
        .unwrap()
        .unwrap();
    let initial = KagemushaEnrollmentPermitV1::decode_canonical(
        &accepted,
        &f.config.scheme,
        &f.config.enrollment_certificate,
    )
    .unwrap();
    current
        .test_provider()
        .select_enrollment_binding(&KagemushaWalletEnrollmentBindingV1::new(
            [11; 32],
            orphan.0,
            client_digest,
            client.client_nonce,
            kagemusha_wallet_prekey_permit_digest_v1(&accepted),
            initial.body.challenge,
            KagemushaWalletEnrollmentDatesV1 {
                issued_at_ms: initial.body.created_at_ms,
                expires_at_ms: initial.body.expires_at_ms,
            },
            KagemushaWalletKeyProfileV1::SecureElement,
            KagemushaWalletKeyGenerationPolicyV1::DefinitiveAbsence,
            KagemushaWalletAnchorPolicyV1::Keychain,
        ))
        .unwrap();
    assert!(matches!(
        current.authorize(&sign(&f, &message)),
        Err(Error::Provider(
            KagemushaWalletProviderErrorV1::UnavailableCustodyData {
                object: "selected pre-key slot"
            }
        ))
    ));
    assert!(
        !d.fs
            .visible_dir(&super::layout::kagemusha_wallet_slot_dir_v1(&orphan))
    );
    d.platform.with(|s| {
        assert_eq!(s.generate_calls, 0);
        assert_eq!(s.delete_calls, 0);
        assert_eq!(s.sign_calls, 0);
    });
}

#[test]
fn enrollment_owner_accepted_before_slot_with_orphan_remains_ambiguous() {
    let f = apple_collection_fixture();
    let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::Keychain, 176);
    let orphan = KagemushaWalletSlotIdV1([170; 32]);
    d.platform.with(|s| {
        s.keys.insert(orphan, signing_key(170));
    });
    let mut current = owner(&f, &d);
    begin(&f, &mut current);
    drop(current);
    d.fs.restart();
    let mut resumed = owner(&f, &d);
    let dispatch = dispatch(&f, &mut resumed);
    assert!(resumed.retained_request().is_err());
    let message = resumed
        .accept_permit(&permit(&f, &dispatch).encode_canonical().unwrap())
        .unwrap();
    assert!(resumed.authorize(&sign(&f, &message)).is_err());
    assert!(
        resumed
            .test_provider()
            .enrollment_phase(&[11; 32])
            .unwrap()
            .is_none()
    );
    assert!(
        resumed
            .test_provider()
            .prekey_read(&[11; 32], PreKeyRecordV1::Slot)
            .unwrap()
            .is_none()
    );
    d.platform.with(|s| {
        assert_eq!(s.generate_calls, 0);
        assert_eq!(s.delete_calls, 0);
        assert_eq!(s.sign_calls, 0);
    });
}

#[test]
fn enrollment_owner_same_owner_erased_selection_never_rebinds_after_generation() {
    let f = apple_collection_fixture();
    let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::Keychain, 177);
    let mut current = owner(&f, &d);
    let message = begin(&f, &mut current);
    let signature = sign(&f, &message);
    d.platform
        .with(|s| s.generation_readback_unavailable = true);
    assert!(current.authorize(&signature).is_err());
    let slot =
        KagemushaWalletSlotIdV1(fixture_phase(current.test_provider()).unwrap().binding.slot);
    let old_key = d.platform.key_of(&slot).unwrap();
    let root = KagemushaWalletCustodyDirV1::root();
    for name in d.fs.visible_names(&root) {
        if name.starts_with("prekey-")
            && (name.ends_with("-slot.norito") || name.ends_with("-phase.norito"))
        {
            d.fs.unlink(&root, &name).unwrap();
        }
    }
    let dir = super::layout::kagemusha_wallet_slot_dir_v1(&slot);
    d.fs.unlink(&dir, "intent.norito").unwrap();
    for name in d.fs.visible_names(&dir) {
        d.fs.remove_dir(&dir, &name).unwrap();
    }
    d.fs.remove_dir(
        &super::layout::kagemusha_wallet_slots_dir_v1(),
        slot.dir_name().as_str(),
    )
    .unwrap();
    d.platform
        .with(|s| s.generation_readback_unavailable = false);
    let before = d.fs.visible_names(&root);
    assert!(current.authorize(&signature).is_err());
    assert_eq!(
        d.fs.visible_names(&root),
        before,
        "no replacement Phase or Slot"
    );
    assert!(!d.fs.visible_dir(&dir));
    assert_eq!(d.platform.key_of(&slot), Some(old_key));
    d.platform.with(|s| {
        assert_eq!(s.generate_calls, 1);
        assert_eq!(s.delete_calls, 0);
        assert_eq!(s.keys.len(), 1);
    });
}

#[test]
fn enrollment_owner_orphan_does_not_block_authenticated_enrolled_source_opening() {
    // Signed issuer originals and real provider custody exercise the exact intake selection
    // path. This component fixture does not claim device attestation or a monetary proof.
    let f = fixture();
    let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::Keychain, 178);
    let mut current = enrolled(&f, &d);
    let slot =
        KagemushaWalletSlotIdV1(fixture_phase(current.test_provider()).unwrap().binding.slot);
    let issued = issuer_result(&f, &RequestV1::decode(&request(&f, &mut current)).unwrap());
    current
        .accept_credential(&issued.encode().unwrap())
        .unwrap();
    let credential = KagemushaWalletCredentialV1::decode_canonical(
        &issued.credential,
        &f.config.scheme.scheme_id(),
    )
    .unwrap();
    credential
        .verify(&f.config.scheme, &f.config.enrollment_certificate)
        .unwrap();
    let mut provider = current.into_provider();
    let before = crate::kagemusha_wallet_intake_v1::select_enrolled_source(
        &mut provider,
        &credential,
        &issued.credential,
        None,
    )
    .unwrap();
    assert_eq!(before.0, slot);
    let orphan = KagemushaWalletSlotIdV1([170; 32]);
    d.platform.with(|s| {
        s.keys.insert(orphan, signing_key(170));
        s.anchors.insert(orphan, b"old anchor".to_vec());
    });
    let old_key = d.platform.key_of(&orphan).unwrap();
    assert_eq!(
        crate::kagemusha_wallet_intake_v1::select_enrolled_source(
            &mut provider,
            &credential,
            &issued.credential,
            None
        )
        .unwrap(),
        before
    );
    assert_eq!(
        crate::kagemusha_wallet_intake_v1::select_enrolled_source(
            &mut provider,
            &credential,
            &issued.credential,
            Some(before)
        )
        .unwrap(),
        before
    );
    assert_eq!(
        provider.status(&orphan),
        Err(KagemushaWalletProviderErrorV1::LostCustody(
            KagemushaWalletLostCustodyV1::KeyWithoutMarker
        ))
    );
    assert_eq!(d.platform.key_of(&orphan), Some(old_key));
    assert!(
        !d.fs
            .visible_dir(&super::layout::kagemusha_wallet_slot_dir_v1(&orphan))
    );
    d.platform.with(|s| {
        assert_eq!(s.generate_calls, 1);
        assert_eq!(s.delete_calls, 0);
        assert_eq!(s.anchors[&orphan], b"old anchor");
    });
}

#[test]
fn enrollment_owner_opening_preserves_matching_pinned_owned_and_unknown_orphan_refusals() {
    for case in [
        "matching-key",
        "pinned-slot",
        "directory",
        "unknown-key",
        "unknown-inventory",
    ] {
        let f = fixture();
        let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::Keychain, 179);
        let mut current = enrolled(&f, &d);
        let selected =
            KagemushaWalletSlotIdV1(fixture_phase(current.test_provider()).unwrap().binding.slot);
        let issued = issuer_result(&f, &RequestV1::decode(&request(&f, &mut current)).unwrap());
        current
            .accept_credential(&issued.encode().unwrap())
            .unwrap();
        let credential = KagemushaWalletCredentialV1::decode_canonical(
            &issued.credential,
            &f.config.scheme.scheme_id(),
        )
        .unwrap();
        credential
            .verify(&f.config.scheme, &f.config.enrollment_certificate)
            .unwrap();
        let mut provider = current.into_provider();
        let orphan = KagemushaWalletSlotIdV1([170; 32]);
        d.platform.with(|s| {
            let key = if case == "matching-key" {
                s.keys[&selected].clone()
            } else {
                signing_key(170)
            };
            s.keys.insert(orphan, key);
            if case == "unknown-key" {
                s.probe_unavailable = true;
            }
            if case == "unknown-inventory" {
                s.enumerate_override = Some(Err(KagemushaWalletUnavailableV1::Locked));
            }
        });
        if case == "directory" {
            super::layout::kagemusha_wallet_prepare_slot_dirs_v1(provider.store(), &orphan)
                .unwrap();
        }
        let pinned = (case == "pinned-slot").then_some((orphan, [3; 32]));
        let result = crate::kagemusha_wallet_intake_v1::select_enrolled_source(
            &mut provider,
            &credential,
            &issued.credential,
            pinned,
        );
        if case.starts_with("unknown-") {
            assert!(
                matches!(
                    result,
                    Err(crate::kagemusha_wallet_intake_v1::Error::Provider(
                        KagemushaWalletProviderErrorV1::Unavailable(_)
                    ))
                ),
                "{case}: {result:?}"
            );
        } else {
            assert!(
                matches!(
                    result,
                    Err(crate::kagemusha_wallet_intake_v1::Error::Provider(
                        KagemushaWalletProviderErrorV1::LostCustody(
                            KagemushaWalletLostCustodyV1::KeyWithoutMarker
                        )
                    ))
                ),
                "{case}: {result:?}"
            );
        }
        d.platform.with(|s| {
            assert_eq!(s.generate_calls, 1);
            assert_eq!(s.delete_calls, 0);
        });
    }
}

#[test]
fn enrollment_owner_same_owner_prekey_erasure_cannot_select_a_second_slot() {
    let f = apple_collection_fixture();
    let d = DeviceV1::new(KagemushaWalletAnchorPolicyV1::Keychain, 180);
    let orphan = KagemushaWalletSlotIdV1([170; 32]);
    d.platform.with(|s| {
        s.keys.insert(orphan, signing_key(170));
    });
    let mut current = owner(&f, &d);
    let message = begin(&f, &mut current);
    let signature = sign(&f, &message);
    d.platform.with(|s| s.probe_unavailable = true);
    assert!(current.authorize(&signature).is_err());
    let selected =
        KagemushaWalletSlotIdV1(fixture_phase(current.test_provider()).unwrap().binding.slot);
    assert_ne!(selected, orphan);
    assert!(!current.test_provider().has_retained_generation(&selected));
    assert!(
        !d.fs
            .visible_dir(&super::layout::kagemusha_wallet_slot_dir_v1(&selected))
    );
    d.platform.with(|s| assert_eq!(s.generate_calls, 0));
    let root = KagemushaWalletCustodyDirV1::root();
    for name in d.fs.visible_names(&root) {
        if name.starts_with("prekey-")
            && (name.ends_with("-slot.norito") || name.ends_with("-phase.norito"))
        {
            d.fs.unlink(&root, &name).unwrap();
        }
    }
    d.platform.with(|s| s.probe_unavailable = false);
    let before = d.fs.visible_names(&root);
    assert!(current.authorize(&signature).is_err());
    assert_eq!(
        d.fs.visible_names(&root),
        before,
        "no replacement Phase or Slot"
    );
    d.platform.with(|s| {
        assert_eq!(s.generate_calls, 0);
        assert_eq!(s.delete_calls, 0);
        assert_eq!(s.sign_calls, 0);
        assert_eq!(s.keys.len(), 1);
    });
}
