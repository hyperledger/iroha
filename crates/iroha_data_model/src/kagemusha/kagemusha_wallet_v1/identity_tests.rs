//! Scheme, signer, enrollment, credential, renewal and artifact identity tests.
//!
//! The fixtures are visible to the other wallet test modules so later areas build on the
//! same scheme, certificates and credentials.

use iroha_crypto::{Algorithm, KeyPair};
use p256::ecdsa::{Signature as P256Signature, SigningKey, signature::Signer as _};

use super::*;
use crate::kagemusha::kagemusha_wallet_v1::{
    KAGEMUSHA_WALLET_ARTIFACT_MANIFEST_MAX_BYTES_V1, KAGEMUSHA_WALLET_CERTIFICATE_MAX_BYTES_V1,
    KAGEMUSHA_WALLET_CREDENTIAL_MAX_BYTES_V1, KAGEMUSHA_WALLET_RENEWAL_REQUEST_MAX_BYTES_V1,
    KAGEMUSHA_WALLET_SCHEME_MAX_BYTES_V1, KAGEMUSHA_WALLET_VERSION_V1,
    KagemushaWalletValidationErrorV1,
    codec_tests::{assert_every_flip_rejected_or_rebound, norito_tag},
};

/// Relation stand-in bindings; the real values come from the G3 artifact set.
const EQ: [u8; 32] = [0x21; 32];
const EP: [u8; 32] = [0x22; 32];
const NATIVE: [u8; 32] = [0x23; 32];
const VK_SET: [u8; 32] = [0x24; 32];
const INVENTORY: [u8; 32] = [0x25; 32];
const ISSUED_AT_MS: u64 = 1_790_000_000_000;

/// Deterministic P-256 test key from a fixed scalar.
pub(in crate::kagemusha::kagemusha_wallet_v1) fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes((&[seed; 32]).into()).expect("fixed test scalar")
}

/// Canonical wallet key of a test signer.
pub(in crate::kagemusha::kagemusha_wallet_v1) fn public_key(
    signing: &SigningKey,
) -> KagemushaDevicePublicKeyV1 {
    KagemushaDevicePublicKeyV1::from_sec1_bytes(
        signing.verifying_key().to_encoded_point(false).as_bytes(),
    )
    .expect("canonical key")
}

/// RFC 6979 raw signer output over an exact signing message.
pub(in crate::kagemusha::kagemusha_wallet_v1) fn raw_output(
    signing: &SigningKey,
    message: &[u8],
) -> KagemushaWalletSignerOutputV1<'static> {
    let signature: P256Signature = signing.sign(message);
    let mut raw = [0; 64];
    raw.copy_from_slice(&signature.to_bytes());
    KagemushaWalletSignerOutputV1::Raw(raw)
}

/// Test scheme under `root` with stand-in relation bindings.
pub(in crate::kagemusha::kagemusha_wallet_v1) fn test_scheme(
    root: &SigningKey,
) -> KagemushaWalletSchemeV1 {
    KagemushaWalletSchemeV1 {
        version: KAGEMUSHA_WALLET_VERSION_V1,
        network_id: *Hash::prehashed([11; 32]).as_ref(),
        scheme_root_key: public_key(root),
        relation_id: kagemusha_wallet_relation_id_v1(&EQ, &EP, &NATIVE, &VK_SET, &INVENTORY),
        provider_contract: kagemusha_wallet_provider_contract_v1(),
    }
}

/// Root-signed certificate delegating `role` to `signer`.
pub(in crate::kagemusha::kagemusha_wallet_v1) fn test_certificate(
    scheme: &KagemushaWalletSchemeV1,
    root: &SigningKey,
    role: KagemushaWalletSignerRoleV1,
    signer: &SigningKey,
    serial: u64,
) -> KagemushaWalletSignerCertificateV1 {
    let body = KagemushaWalletSignerCertificateBodyV1 {
        version: KAGEMUSHA_WALLET_VERSION_V1,
        scheme_id: scheme.scheme_id(),
        role,
        key: public_key(signer),
        serial,
    };
    KagemushaWalletSignerCertificateV1::sign(
        body,
        scheme,
        raw_output(root, &body.signing_message()),
    )
    .expect("certificate")
}

/// Test asset scope.
pub(in crate::kagemusha::kagemusha_wallet_v1) fn test_asset() -> KagemushaWalletAssetScopeV1 {
    KagemushaWalletAssetScopeV1::new(
        AssetDefinitionId::from_uuid_bytes([
            0x2f, 0x17, 0xc7, 0x24, 0x66, 0xf8, 0x4a, 0x4b, 0xb8, 0xa8, 0xe2, 0x48, 0x84, 0xfd,
            0xcd, 0x2f,
        ])
        .expect("asset"),
        &AxtAssetIncarnationV1::try_from_bytes(*Hash::new(b"wallet-fixture-incarnation").as_ref())
            .expect("incarnation"),
        2,
    )
    .expect("asset scope")
}

/// Test account from a fixed Ed25519 seed.
pub(in crate::kagemusha::kagemusha_wallet_v1) fn test_account(seed: u8) -> AccountId {
    AccountId::new(
        KeyPair::from_seed(vec![seed; 32], Algorithm::Ed25519)
            .public_key()
            .clone(),
    )
}

/// Valid enrollment evidence of `kind`.
pub(in crate::kagemusha::kagemusha_wallet_v1) fn test_evidence(
    kind: KagemushaWalletEvidenceKindV1,
) -> KagemushaWalletEvidenceV1 {
    let (items, facts, patch): (&[&[u8]], u32, u32) = match kind {
        KagemushaWalletEvidenceKindV1::AndroidKeyMintTee => (
            &[b"tee-leaf-der", b"tee-intermediate-der"],
            KAGEMUSHA_WALLET_ANDROID_REQUIRED_FACTS_V1
                | KAGEMUSHA_WALLET_FACT_PATCH_POLICY_MET_V1
                | KAGEMUSHA_WALLET_FACT_REVOCATION_LIST_CLEAR_V1,
            202_609,
        ),
        KagemushaWalletEvidenceKindV1::AndroidKeyMintStrongBox => (
            &[b"strongbox-leaf-der", b"strongbox-intermediate-der"],
            KAGEMUSHA_WALLET_ANDROID_REQUIRED_FACTS_V1
                | KAGEMUSHA_WALLET_FACT_STRONGBOX_V1
                | KAGEMUSHA_WALLET_FACT_PLAY_INTEGRITY_SIGNAL_V1,
            202_608,
        ),
        KagemushaWalletEvidenceKindV1::AppleAppAttest => (
            &[b"attestation-object", b"assertion"],
            KAGEMUSHA_WALLET_APPLE_REQUIRED_FACTS_V1
                | KAGEMUSHA_WALLET_FACT_APP_ATTEST_PRODUCTION_V1
                | KAGEMUSHA_WALLET_FACT_LOCAL_COMPROMISE_CHECKS_CLEAR_V1,
            0,
        ),
    };
    KagemushaWalletEvidenceV1 {
        digest: kagemusha_wallet_evidence_digest_v1(kind, items).expect("evidence digest"),
        time_ms: ISSUED_AT_MS - 1_000,
        facts,
        os_patch_level: patch,
        vendor_patch_level: patch,
        boot_patch_level: patch,
    }
}

/// Complete enrolled identity of one wallet.
pub(in crate::kagemusha::kagemusha_wallet_v1) struct IdentityFixture {
    /// Scheme root signer.
    pub(in crate::kagemusha::kagemusha_wallet_v1) root: SigningKey,
    /// Scheme.
    pub(in crate::kagemusha::kagemusha_wallet_v1) scheme: KagemushaWalletSchemeV1,
    /// Enrollment-role signer.
    pub(in crate::kagemusha::kagemusha_wallet_v1) enrollment_signer: SigningKey,
    /// Enrollment-role certificate.
    pub(in crate::kagemusha::kagemusha_wallet_v1) enrollment_certificate:
        KagemushaWalletSignerCertificateV1,
    /// Hardware payment key.
    pub(in crate::kagemusha::kagemusha_wallet_v1) payment: SigningKey,
    /// Asset scope.
    pub(in crate::kagemusha::kagemusha_wallet_v1) asset: KagemushaWalletAssetScopeV1,
    /// Enrollment challenge.
    pub(in crate::kagemusha::kagemusha_wallet_v1) challenge: KagemushaWalletEnrollmentChallengeV1,
    /// Issued credential.
    pub(in crate::kagemusha::kagemusha_wallet_v1) credential: KagemushaWalletCredentialV1,
}

/// Enrolled identity whose payment key derives from `payment_seed`.
pub(in crate::kagemusha::kagemusha_wallet_v1) fn identity_fixture(
    kind: KagemushaWalletEvidenceKindV1,
    payment_seed: u8,
) -> IdentityFixture {
    let root = signing_key(0x11);
    let scheme = test_scheme(&root);
    let enrollment_signer = signing_key(0x22);
    let enrollment_certificate = test_certificate(
        &scheme,
        &root,
        KagemushaWalletSignerRoleV1::Enrollment,
        &enrollment_signer,
        1,
    );
    let payment = signing_key(payment_seed);
    let payment_key = public_key(&payment);
    let asset = test_asset();
    let challenge = KagemushaWalletEnrollmentChallengeV1 {
        version: KAGEMUSHA_WALLET_VERSION_V1,
        scheme_id: scheme.scheme_id(),
        asset_digest: asset.asset_digest(),
        account_digest: kagemusha_wallet_account_digest_v1(&test_account(payment_seed))
            .expect("account digest"),
        app_policy: [0x31; 32],
        enrollment_policy: [0x32; 32],
        issuer_nonce: [payment_seed; 32],
    };
    let evidence = test_evidence(kind);
    let body = KagemushaWalletCredentialBodyV1 {
        version: KAGEMUSHA_WALLET_VERSION_V1,
        scheme_id: challenge.scheme_id,
        asset_digest: challenge.asset_digest,
        wallet_id: challenge.wallet_id(&payment_key),
        account_digest: challenge.account_digest,
        payment_key,
        provider_contract: scheme.provider_contract,
        evidence_kind: kind,
        enrollment_evidence: evidence,
        fresh_evidence: evidence,
        app_policy: challenge.app_policy,
        regulatory_policy: KagemushaWalletRegulatoryPolicyV1::default(),
        enrollment_id: challenge.enrollment_id(&payment_key),
        issued_at_ms: ISSUED_AT_MS,
        renewal_sequence: 0,
        lease_expires_at_ms: 0,
        issuer_certificate: enrollment_certificate.certificate_digest(),
    };
    let credential = KagemushaWalletCredentialV1::sign(
        body,
        &enrollment_certificate,
        raw_output(&enrollment_signer, &body.signing_message()),
    )
    .expect("credential");
    IdentityFixture {
        root,
        scheme,
        enrollment_signer,
        enrollment_certificate,
        payment,
        asset,
        challenge,
        credential,
    }
}

impl IdentityFixture {
    /// Sign `body` with the fixture's Enrollment-role signer.
    pub(in crate::kagemusha::kagemusha_wallet_v1) fn issue(
        &self,
        body: &KagemushaWalletCredentialBodyV1,
    ) -> WalletResult<KagemushaWalletCredentialV1> {
        KagemushaWalletCredentialV1::sign(
            *body,
            &self.enrollment_certificate,
            raw_output(&self.enrollment_signer, &body.signing_message()),
        )
    }
}

fn is_invalid(result: WalletResult<()>, expected: &str) -> bool {
    matches!(
        result.err(),
        Some(KagemushaWalletValidationErrorV1::InvalidField { field }) if field == expected
    )
}

/// One mutation of a credential body.
type BodyMutation = fn(&mut KagemushaWalletCredentialBodyV1);

fn android() -> IdentityFixture {
    identity_fixture(KagemushaWalletEvidenceKindV1::AndroidKeyMintTee, 0x44)
}

fn apple() -> IdentityFixture {
    identity_fixture(KagemushaWalletEvidenceKindV1::AppleAppAttest, 0x45)
}

fn artifact_body(
    scheme: &KagemushaWalletSchemeV1,
    certificate: &KagemushaWalletSignerCertificateV1,
) -> KagemushaWalletArtifactManifestBodyV1 {
    KagemushaWalletArtifactManifestBodyV1 {
        version: KAGEMUSHA_WALLET_VERSION_V1,
        network_id: scheme.network_id,
        relation_id: scheme.relation_id,
        eq_protocol_digest: EQ,
        ep_protocol_digest: EP,
        native_profile_digest: NATIVE,
        verifying_key_set_digest: VK_SET,
        artifact_inventory_digest: INVENTORY,
        provider_contract: scheme.provider_contract,
        signer_certificate: certificate.certificate_digest(),
    }
}

fn android_chain() -> Vec<KagemushaWalletDerCertificateV1> {
    vec![
        KagemushaWalletDerCertificateV1 {
            der: b"renewal-leaf-der".to_vec(),
        },
        KagemushaWalletDerCertificateV1 {
            der: b"renewal-intermediate-der".to_vec(),
        },
    ]
}

fn android_renewal(f: &IdentityFixture, challenge: [u8; 32]) -> KagemushaWalletRenewalRequestV1 {
    let new_key = signing_key(0x55);
    let credential = &f.credential;
    let binding = kagemusha_wallet_renewal_key_binding_transcript_v1(
        &credential.body.scheme_id,
        &credential.body.wallet_id,
        &challenge,
        &public_key(&new_key),
    );
    let evidence = KagemushaWalletRenewalEvidenceV1::android_signed(
        credential,
        &challenge,
        public_key(&new_key),
        raw_output(
            &f.payment,
            &kagemusha_wallet_signing_message_v1(Domain::RenewalKeyBinding, &binding),
        ),
        android_chain(),
    )
    .expect("android evidence");
    let possession = kagemusha_wallet_renewal_challenge_transcript_v1(
        &credential.body.scheme_id,
        &credential.body.wallet_id,
        &credential.credential_digest(),
        &challenge,
    );
    KagemushaWalletRenewalRequestV1::sign(
        credential,
        challenge,
        raw_output(
            &f.payment,
            &kagemusha_wallet_signing_message_v1(Domain::RenewalChallenge, &possession),
        ),
        evidence,
    )
    .expect("android renewal")
}

fn apple_renewal(f: &IdentityFixture, challenge: [u8; 32]) -> KagemushaWalletRenewalRequestV1 {
    let credential = &f.credential;
    let possession = kagemusha_wallet_renewal_challenge_transcript_v1(
        &credential.body.scheme_id,
        &credential.body.wallet_id,
        &credential.credential_digest(),
        &challenge,
    );
    KagemushaWalletRenewalRequestV1::sign(
        credential,
        challenge,
        raw_output(
            &f.payment,
            &kagemusha_wallet_signing_message_v1(Domain::RenewalChallenge, &possession),
        ),
        KagemushaWalletRenewalEvidenceV1::Apple {
            assertion: b"app-attest-assertion".to_vec(),
        },
    )
    .expect("apple renewal")
}

#[test]
fn kagemusha_wallet_v1_identity_transcript_lengths_are_pinned() {
    let f = android();
    for (constant, expected) in [
        (KAGEMUSHA_WALLET_PROVIDER_CONTRACT_TRANSCRIPT_BYTES_V1, 66),
        (KAGEMUSHA_WALLET_RELATION_TRANSCRIPT_BYTES_V1, 162),
        (KAGEMUSHA_WALLET_SCHEME_TRANSCRIPT_BYTES_V1, 163),
        (KAGEMUSHA_WALLET_ASSET_SCOPE_TRANSCRIPT_BYTES_V1, 54),
        (KAGEMUSHA_WALLET_CERTIFICATE_BODY_TRANSCRIPT_BYTES_V1, 108),
        (
            KAGEMUSHA_WALLET_ENROLLMENT_CHALLENGE_TRANSCRIPT_BYTES_V1,
            194,
        ),
        (KAGEMUSHA_WALLET_ENROLLMENT_KEY_TRANSCRIPT_BYTES_V1, 97),
        (KAGEMUSHA_WALLET_ID_TRANSCRIPT_BYTES_V1, 161),
        (KAGEMUSHA_WALLET_EVIDENCE_TRANSCRIPT_BYTES_V1, 56),
        (KAGEMUSHA_WALLET_REGULATORY_POLICY_TRANSCRIPT_BYTES_V1, 20),
        (KAGEMUSHA_WALLET_CREDENTIAL_BODY_TRANSCRIPT_BYTES_V1, 476),
        (KAGEMUSHA_WALLET_RENEWAL_CHALLENGE_TRANSCRIPT_BYTES_V1, 130),
        (
            KAGEMUSHA_WALLET_RENEWAL_KEY_BINDING_TRANSCRIPT_BYTES_V1,
            163,
        ),
        (
            KAGEMUSHA_WALLET_ARTIFACT_MANIFEST_BODY_TRANSCRIPT_BYTES_V1,
            290,
        ),
    ] {
        assert_eq!(constant, expected);
    }
    let key = f.credential.body.payment_key;
    for (transcript, expected) in [
        (
            kagemusha_wallet_provider_contract_transcript_v1(),
            KAGEMUSHA_WALLET_PROVIDER_CONTRACT_TRANSCRIPT_BYTES_V1,
        ),
        (
            kagemusha_wallet_relation_transcript_v1(&EQ, &EP, &NATIVE, &VK_SET, &INVENTORY),
            KAGEMUSHA_WALLET_RELATION_TRANSCRIPT_BYTES_V1,
        ),
        (
            f.scheme.transcript(),
            KAGEMUSHA_WALLET_SCHEME_TRANSCRIPT_BYTES_V1,
        ),
        (
            f.asset.transcript(),
            KAGEMUSHA_WALLET_ASSET_SCOPE_TRANSCRIPT_BYTES_V1,
        ),
        (
            f.enrollment_certificate.body.transcript(),
            KAGEMUSHA_WALLET_CERTIFICATE_BODY_TRANSCRIPT_BYTES_V1,
        ),
        (
            f.challenge.transcript(),
            KAGEMUSHA_WALLET_ENROLLMENT_CHALLENGE_TRANSCRIPT_BYTES_V1,
        ),
        (
            kagemusha_wallet_enrollment_key_transcript_v1(&[1; 32], &key),
            KAGEMUSHA_WALLET_ENROLLMENT_KEY_TRANSCRIPT_BYTES_V1,
        ),
        (
            kagemusha_wallet_id_transcript_v1(&[1; 32], &[2; 32], &key, &[3; 32]),
            KAGEMUSHA_WALLET_ID_TRANSCRIPT_BYTES_V1,
        ),
        (
            f.credential.body.enrollment_evidence.transcript(),
            KAGEMUSHA_WALLET_EVIDENCE_TRANSCRIPT_BYTES_V1,
        ),
        (
            f.credential.body.regulatory_policy.transcript(),
            KAGEMUSHA_WALLET_REGULATORY_POLICY_TRANSCRIPT_BYTES_V1,
        ),
        (
            f.credential.body.transcript(),
            KAGEMUSHA_WALLET_CREDENTIAL_BODY_TRANSCRIPT_BYTES_V1,
        ),
        (
            kagemusha_wallet_renewal_challenge_transcript_v1(
                &[1; 32], &[2; 32], &[3; 32], &[4; 32],
            ),
            KAGEMUSHA_WALLET_RENEWAL_CHALLENGE_TRANSCRIPT_BYTES_V1,
        ),
        (
            kagemusha_wallet_renewal_key_binding_transcript_v1(&[1; 32], &[2; 32], &[3; 32], &key),
            KAGEMUSHA_WALLET_RENEWAL_KEY_BINDING_TRANSCRIPT_BYTES_V1,
        ),
    ] {
        assert_eq!(transcript.len(), expected);
    }
}

#[test]
fn kagemusha_wallet_v1_provider_contract_and_relation_layouts() {
    let transcript = kagemusha_wallet_provider_contract_transcript_v1();
    assert_eq!(&transcript[..2], &[1, 0]);
    let name = KAGEMUSHA_WALLET_PROVIDER_CONTRACT_NAME_V1.as_bytes();
    assert_eq!(name.len(), 35);
    assert_eq!(&transcript[2..37], name);
    assert!(transcript[37..].iter().all(|byte| *byte == 0));
    assert_eq!(
        hex::encode(kagemusha_wallet_provider_contract_v1()),
        "52b501e3344547c36579684aafb2b15eb0caf3393e77aebdfbaa14ac57d0cc8d"
    );

    let relation = kagemusha_wallet_relation_transcript_v1(&EQ, &EP, &NATIVE, &VK_SET, &INVENTORY);
    let mut expected = vec![1, 0];
    for digest in [EQ, EP, NATIVE, VK_SET, INVENTORY] {
        expected.extend_from_slice(&digest);
    }
    assert_eq!(relation, expected);
    let id = kagemusha_wallet_relation_id_v1(&EQ, &EP, &NATIVE, &VK_SET, &INVENTORY);
    assert_eq!(id, kagemusha_wallet_digest_v1(Role::Relation, &relation));
    assert_ne!(
        id,
        kagemusha_wallet_relation_id_v1(&EP, &EQ, &NATIVE, &VK_SET, &INVENTORY)
    );
    assert_ne!(
        id,
        kagemusha_wallet_relation_id_v1(&EQ, &EP, &NATIVE, &VK_SET, &[0x26; 32])
    );
}

#[test]
fn kagemusha_wallet_v1_scheme_identity_and_validation() {
    let f = android();
    let scheme = f.scheme;
    let mut expected = vec![1, 0];
    expected.extend_from_slice(&scheme.network_id);
    expected.extend_from_slice(scheme.scheme_root_key.as_sec1_bytes());
    expected.extend_from_slice(&scheme.relation_id);
    expected.extend_from_slice(&scheme.provider_contract);
    assert_eq!(scheme.transcript(), expected);
    assert_eq!(
        scheme.scheme_id(),
        kagemusha_wallet_digest_v1(Role::Scheme, &expected)
    );
    scheme.validate().expect("valid scheme");

    let mut bad = scheme;
    bad.version = 2;
    assert!(matches!(
        bad.validate(),
        Err(KagemushaWalletValidationErrorV1::UnsupportedVersion { version: 2, .. })
    ));
    let mut bad = scheme;
    bad.network_id[31] &= !1;
    assert!(is_invalid(bad.validate(), "network_id"));
    let mut bad = scheme;
    bad.network_id = *Hash::prehashed([0; 32]).as_ref();
    assert!(is_invalid(bad.validate(), "network_id"));
    let mut bad = scheme;
    bad.relation_id = [0; 32];
    assert!(is_invalid(bad.validate(), "scheme.relation_id"));
    let mut bad = scheme;
    bad.provider_contract = [0x99; 32];
    assert!(is_invalid(bad.validate(), "scheme.provider_contract"));
}

#[test]
fn kagemusha_wallet_v1_scheme_decode_order() {
    let scheme = android().scheme;
    let id = scheme.scheme_id();
    let frame = scheme.to_canonical_bytes().expect("frame");
    assert!(frame.len() <= KAGEMUSHA_WALLET_SCHEME_MAX_BYTES_V1);
    assert_eq!(
        KagemushaWalletSchemeV1::decode_canonical(&frame, &id).expect("decode"),
        scheme
    );
    let oversized = vec![0; KAGEMUSHA_WALLET_SCHEME_MAX_BYTES_V1 + 1];
    assert!(matches!(
        KagemushaWalletSchemeV1::decode_canonical(&oversized, &id),
        Err(KagemushaWalletValidationErrorV1::EncodedSizeExceeded { .. })
    ));
    let mut noncanonical = frame.clone();
    noncanonical.push(0);
    assert!(matches!(
        KagemushaWalletSchemeV1::decode_canonical(&noncanonical, &id),
        Err(KagemushaWalletValidationErrorV1::Codec(_))
    ));
    let mut wrong_version = scheme;
    wrong_version.version = 2;
    let wrong_version = norito::encode_canonical(&wrong_version).expect("encode");
    assert!(matches!(
        KagemushaWalletSchemeV1::decode_canonical(&wrong_version, &id),
        Err(KagemushaWalletValidationErrorV1::UnsupportedVersion { .. })
    ));
    assert!(matches!(
        KagemushaWalletSchemeV1::decode_canonical(&frame, &[7; 32]),
        Err(KagemushaWalletValidationErrorV1::SchemeMismatch { .. })
    ));
    let mut invalid = scheme;
    invalid.relation_id = [0; 32];
    let invalid_frame = norito::encode_canonical(&invalid).expect("encode");
    assert!(matches!(
        KagemushaWalletSchemeV1::decode_canonical(&invalid_frame, &invalid.scheme_id()),
        Err(KagemushaWalletValidationErrorV1::InvalidField { .. })
    ));
    assert!(invalid.to_canonical_bytes().is_err());
}

#[test]
fn kagemusha_wallet_v1_asset_scope_and_account_digest() {
    let asset = test_asset();
    let mut expected = vec![1, 0];
    expected.extend_from_slice(&asset.asset.aid_bytes());
    expected.extend_from_slice(&asset.asset_incarnation);
    expected.extend_from_slice(&2_u32.to_le_bytes());
    assert_eq!(asset.transcript(), expected);
    assert_eq!(
        asset.asset_digest(),
        kagemusha_wallet_digest_v1(Role::AssetScope, &expected)
    );
    asset.validate().expect("valid scope");
    let mut bad = asset.clone();
    bad.scale = KAGEMUSHA_WALLET_ASSET_SCALE_MAX_V1 + 1;
    assert!(is_invalid(bad.validate(), "asset_scope.scale"));
    let mut edge = asset.clone();
    edge.scale = KAGEMUSHA_WALLET_ASSET_SCALE_MAX_V1;
    assert!(edge.validate().is_ok());
    let mut bad = asset.clone();
    bad.asset_incarnation = [0; 32];
    assert!(is_invalid(bad.validate(), "asset_incarnation"));
    let mut bad = asset.clone();
    bad.asset_incarnation[31] &= !1;
    assert!(is_invalid(bad.validate(), "asset_incarnation"));
    let mut bad = asset.clone();
    bad.version = 0;
    assert!(bad.validate().is_err());
    let decoded: KagemushaWalletAssetScopeV1 =
        norito::decode_canonical(&norito::encode_canonical(&asset).expect("encode"))
            .expect("decode");
    assert_eq!(decoded, asset);

    let account = test_account(12);
    let digest = kagemusha_wallet_account_digest_v1(&account).expect("digest");
    assert_eq!(
        digest,
        kagemusha_wallet_digest_v1(
            Role::Account,
            &norito::encode_canonical(&account).expect("account frame")
        )
    );
    assert_ne!(
        digest,
        kagemusha_wallet_account_digest_v1(&test_account(13)).expect("digest")
    );
}

#[test]
fn kagemusha_wallet_v1_evidence_digest_layout() {
    let kind = KagemushaWalletEvidenceKindV1::AndroidKeyMintStrongBox;
    let transcript =
        kagemusha_wallet_evidence_transcript_v1(kind, &[b"leaf", b"ca"]).expect("transcript");
    let mut expected = vec![2];
    expected.extend_from_slice(&2_u32.to_le_bytes());
    expected.extend_from_slice(&4_u32.to_le_bytes());
    expected.extend_from_slice(b"leaf");
    expected.extend_from_slice(&2_u32.to_le_bytes());
    expected.extend_from_slice(b"ca");
    assert_eq!(transcript, expected);
    assert_eq!(
        kagemusha_wallet_evidence_digest_v1(kind, &[b"leaf", b"ca"]).expect("digest"),
        kagemusha_wallet_digest_v1(Role::Evidence, &expected)
    );
    assert_ne!(
        kagemusha_wallet_evidence_digest_v1(kind, &[b"leaf", b"ca"]).expect("digest"),
        kagemusha_wallet_evidence_digest_v1(kind, &[b"lea", b"fca"]).expect("digest")
    );
    assert!(kagemusha_wallet_evidence_transcript_v1(kind, &[]).is_err());
    assert!(kagemusha_wallet_evidence_digest_v1(kind, &[b"leaf", b""]).is_err());
}

#[test]
fn kagemusha_wallet_v1_enum_tags_equal_norito_tags() {
    for role in KagemushaWalletSignerRoleV1::ALL {
        assert_eq!(norito_tag(&role), u32::from(role.tag()));
    }
    for kind in KagemushaWalletEvidenceKindV1::ALL {
        assert_eq!(norito_tag(&kind), u32::from(kind.tag()));
    }
    let android = KagemushaWalletRenewalEvidenceV1::Android {
        new_attested_key: public_key(&signing_key(0x55)),
        key_binding_signature: android().credential.signature,
        chain: android_chain(),
    };
    let apple = KagemushaWalletRenewalEvidenceV1::Apple { assertion: vec![1] };
    assert_eq!(norito_tag(&android), u32::from(android.tag()));
    assert_eq!(norito_tag(&apple), u32::from(apple.tag()));
    assert_eq!((android.tag(), apple.tag()), (1, 2));
}

#[test]
fn kagemusha_wallet_v1_signer_certificate_sign_verify_and_decode() {
    let f = android();
    let certificate = f.enrollment_certificate;
    certificate.verify(&f.scheme).expect("verify");
    certificate
        .verify_role(&f.scheme, KagemushaWalletSignerRoleV1::Enrollment)
        .expect("role");
    assert!(is_invalid(
        certificate.verify_role(&f.scheme, KagemushaWalletSignerRoleV1::Artifact),
        "certificate.role"
    ));
    let mut expected = vec![1, 0];
    expected.extend_from_slice(&f.scheme.scheme_id());
    expected.push(1);
    expected.extend_from_slice(public_key(&f.enrollment_signer).as_sec1_bytes());
    expected.extend_from_slice(&1_u64.to_le_bytes());
    assert_eq!(certificate.body.transcript(), expected);
    assert_eq!(
        certificate.body.signing_message(),
        kagemusha_wallet_signing_message_v1(Domain::Certificate, &expected)
    );
    assert_eq!(
        certificate.certificate_digest(),
        kagemusha_wallet_signed_object_digest_v1(
            Role::Certificate,
            &kagemusha_wallet_signing_message_v1(Domain::Certificate, &expected),
            &certificate.signature
        )
    );
    assert_eq!(
        certificate.body.signing_message(),
        kagemusha_wallet_signing_message_v1(Domain::Certificate, &expected)
    );

    let mut other_scheme = f.scheme;
    other_scheme.relation_id = [0x77; 32];
    assert!(matches!(
        certificate.verify(&other_scheme),
        Err(KagemushaWalletValidationErrorV1::SchemeMismatch { .. })
    ));
    let mut tampered = certificate;
    tampered.body.serial = 2;
    assert!(matches!(
        tampered.verify(&f.scheme),
        Err(KagemushaWalletValidationErrorV1::InvalidSignature {
            domain: Domain::Certificate
        })
    ));
    let not_root = KagemushaWalletSignerCertificateV1::sign(
        certificate.body,
        &f.scheme,
        raw_output(&f.enrollment_signer, &certificate.body.signing_message()),
    );
    assert!(matches!(
        not_root,
        Err(KagemushaWalletValidationErrorV1::InvalidSignature { .. })
    ));
    let mut zero_scheme = certificate.body;
    zero_scheme.scheme_id = [0; 32];
    assert!(is_invalid(zero_scheme.validate(), "certificate.scheme_id"));

    let frame = certificate.to_canonical_bytes().expect("frame");
    assert!(frame.len() <= KAGEMUSHA_WALLET_CERTIFICATE_MAX_BYTES_V1);
    assert_eq!(
        KagemushaWalletSignerCertificateV1::decode_canonical(&frame, &f.scheme).expect("decode"),
        certificate
    );
    assert!(matches!(
        KagemushaWalletSignerCertificateV1::decode_canonical(&frame, &other_scheme),
        Err(KagemushaWalletValidationErrorV1::SchemeMismatch { .. })
    ));
    let mut wrong_version = certificate;
    wrong_version.body.version = 2;
    assert!(matches!(
        KagemushaWalletSignerCertificateV1::decode_canonical(
            &norito::encode_canonical(&wrong_version).expect("encode"),
            &f.scheme
        ),
        Err(KagemushaWalletValidationErrorV1::UnsupportedVersion { .. })
    ));
    assert_every_flip_rejected_or_rebound(&frame, certificate.certificate_digest(), |bytes| {
        KagemushaWalletSignerCertificateV1::decode_canonical(bytes, &f.scheme)
            .ok()
            .map(|certificate| certificate.certificate_digest())
    });
}

#[test]
fn kagemusha_wallet_v1_certificate_set_order_digest_and_selection() {
    let f = android();
    let regulatory = test_certificate(
        &f.scheme,
        &f.root,
        KagemushaWalletSignerRoleV1::RegulatoryPolicy,
        &signing_key(0x66),
        1,
    );
    let artifact = test_certificate(
        &f.scheme,
        &f.root,
        KagemushaWalletSignerRoleV1::Artifact,
        &signing_key(0x33),
        1,
    );
    let time = test_certificate(
        &f.scheme,
        &f.root,
        KagemushaWalletSignerRoleV1::TimeAnchor,
        &signing_key(0x67),
        1,
    );
    let mut certificates = vec![f.enrollment_certificate, regulatory, artifact];
    certificates.sort_by_key(|certificate| core::cmp::Reverse(certificate.certificate_digest()));
    let set = KagemushaWalletCertificateSetV1::new(certificates).expect("set");
    assert_eq!(set.len(), 3);
    assert!(!set.is_empty());
    let digests = set.digests();
    assert!(digests.windows(2).all(|pair| pair[0] < pair[1]));
    let mut transcript = 3_u32.to_le_bytes().to_vec();
    for digest in &digests {
        transcript.extend_from_slice(digest);
    }
    assert_eq!(set.transcript().expect("transcript"), transcript);
    assert_eq!(
        set.digest().expect("digest"),
        kagemusha_wallet_digest_v1(Role::CertificateSet, &transcript)
    );
    set.verify(&f.scheme).expect("verify");
    assert_eq!(
        set.certificate(
            &regulatory.certificate_digest(),
            KagemushaWalletSignerRoleV1::RegulatoryPolicy
        )
        .expect("select"),
        &regulatory
    );
    assert!(
        set.certificate(
            &regulatory.certificate_digest(),
            KagemushaWalletSignerRoleV1::Enrollment
        )
        .is_err()
    );
    assert!(
        set.certificate(
            &time.certificate_digest(),
            KagemushaWalletSignerRoleV1::TimeAnchor
        )
        .is_err()
    );
    let decoded: KagemushaWalletCertificateSetV1 =
        norito::decode_canonical(&norito::encode_canonical(&set).expect("encode")).expect("decode");
    assert_eq!(decoded, set);

    assert!(KagemushaWalletCertificateSetV1::new(vec![regulatory, regulatory]).is_err());
    assert!(
        KagemushaWalletCertificateSetV1::new(vec![
            f.enrollment_certificate,
            regulatory,
            artifact,
            time
        ])
        .is_err()
    );
    let mut unsorted = set.clone();
    unsorted.certificates.swap(0, 1);
    assert!(is_invalid(unsorted.validate(), "certificates.order"));
    let mut other_scheme = f.scheme;
    other_scheme.relation_id = [0x77; 32];
    assert!(set.verify(&other_scheme).is_err());

    let empty = KagemushaWalletCertificateSetV1::default();
    assert!(empty.is_empty());
    assert_eq!(empty.len(), 0);
    assert_eq!(
        empty.digest().expect("digest"),
        kagemusha_wallet_digest_v1(Role::CertificateSet, &[0, 0, 0, 0])
    );
    assert!(empty.validate().is_ok());
}

#[test]
fn kagemusha_wallet_v1_enrollment_challenge_and_wallet_identity() {
    let f = android();
    let challenge = f.challenge;
    challenge.validate().expect("valid challenge");
    let mut expected = vec![1, 0];
    for digest in [
        challenge.scheme_id,
        challenge.asset_digest,
        challenge.account_digest,
        challenge.app_policy,
        challenge.enrollment_policy,
        challenge.issuer_nonce,
    ] {
        expected.extend_from_slice(&digest);
    }
    assert_eq!(challenge.transcript(), expected);
    let challenge_digest = challenge.challenge_digest();
    assert_eq!(
        challenge_digest,
        kagemusha_wallet_digest_v1(Role::EnrollmentChallenge, &expected)
    );
    let key = public_key(&f.payment);
    let mut key_body = challenge_digest.to_vec();
    key_body.extend_from_slice(key.as_sec1_bytes());
    assert_eq!(
        kagemusha_wallet_enrollment_key_transcript_v1(&challenge_digest, &key),
        key_body
    );
    let enrollment_id = kagemusha_wallet_enrollment_id_v1(&challenge_digest, &key);
    assert_eq!(
        enrollment_id,
        kagemusha_wallet_digest_v1(Role::EnrollmentId, &key_body)
    );
    assert_eq!(challenge.enrollment_id(&key), enrollment_id);
    let binding = kagemusha_wallet_enrollment_key_binding_v1(&challenge_digest, &key);
    assert_eq!(
        binding,
        kagemusha_wallet_digest_v1(Role::EnrollmentKeyBinding, &key_body)
    );
    assert_ne!(binding, enrollment_id);
    let mut wallet_body = challenge.scheme_id.to_vec();
    wallet_body.extend_from_slice(&challenge.asset_digest);
    wallet_body.extend_from_slice(key.as_sec1_bytes());
    wallet_body.extend_from_slice(&enrollment_id);
    assert_eq!(
        kagemusha_wallet_id_transcript_v1(
            &challenge.scheme_id,
            &challenge.asset_digest,
            &key,
            &enrollment_id
        ),
        wallet_body
    );
    let wallet_id = kagemusha_wallet_id_v1(
        &challenge.scheme_id,
        &challenge.asset_digest,
        &key,
        &enrollment_id,
    );
    assert_eq!(
        wallet_id,
        kagemusha_wallet_digest_v1(Role::WalletId, &wallet_body)
    );
    assert_eq!(challenge.wallet_id(&key), wallet_id);
    assert_eq!(f.credential.body.wallet_id, wallet_id);
    let other_key = public_key(&signing_key(0x46));
    assert_ne!(challenge.wallet_id(&other_key), wallet_id);

    let mut bad = challenge;
    bad.issuer_nonce = [0; 32];
    assert!(is_invalid(
        bad.validate(),
        "enrollment_challenge.issuer_nonce"
    ));
    let mut bad = challenge;
    bad.version = 2;
    assert!(bad.validate().is_err());
    let mut bad = challenge;
    bad.enrollment_policy = [0; 32];
    assert!(bad.validate().is_err());
}

#[test]
fn kagemusha_wallet_v1_evidence_fact_rules() {
    use KagemushaWalletEvidenceKindV1::{
        AndroidKeyMintStrongBox, AndroidKeyMintTee, AppleAppAttest,
    };
    assert_eq!(KAGEMUSHA_WALLET_FACTS_DEFINED_MASK_V1, 0x0fff);
    assert_eq!(KAGEMUSHA_WALLET_ANDROID_FORBIDDEN_FACTS_V1, 0x01c0);
    assert_eq!(KAGEMUSHA_WALLET_APPLE_FORBIDDEN_FACTS_V1, 0x023f);
    assert_eq!(KAGEMUSHA_WALLET_ANDROID_REQUIRED_FACTS_V1, 0x002d);
    assert_eq!(KAGEMUSHA_WALLET_APPLE_REQUIRED_FACTS_V1, 0x00c0);
    assert!(AndroidKeyMintTee.is_android() && AndroidKeyMintStrongBox.is_android());
    assert!(!AppleAppAttest.is_android());
    assert_eq!(
        AndroidKeyMintStrongBox.required_enrollment_facts(),
        0x002d | KAGEMUSHA_WALLET_FACT_STRONGBOX_V1
    );
    for kind in KagemushaWalletEvidenceKindV1::ALL {
        let evidence = test_evidence(kind);
        evidence.validate_enrollment_for_kind(kind).expect("valid");
        let mut undefined = evidence;
        undefined.facts |= 1 << 12;
        assert!(is_invalid(
            undefined.validate_for_kind(kind),
            "evidence.facts"
        ));
        let mut zero = evidence;
        zero.digest = [0; 32];
        assert!(is_invalid(zero.validate_for_kind(kind), "evidence.digest"));
        let mut missing = evidence;
        missing.facts &= !kind.required_enrollment_facts();
        assert!(
            missing.validate_for_kind(kind).is_ok(),
            "fresh facts are not required"
        );
        assert!(is_invalid(
            missing.validate_enrollment_for_kind(kind),
            "evidence.required_facts"
        ));
        let mut wrong_platform = evidence;
        wrong_platform.facts |= kind.forbidden_facts() & KAGEMUSHA_WALLET_FACTS_DEFINED_MASK_V1;
        assert!(is_invalid(
            wrong_platform.validate_for_kind(kind),
            "evidence.facts"
        ));
    }
    let mut tee = test_evidence(AndroidKeyMintTee);
    tee.facts |= KAGEMUSHA_WALLET_FACT_STRONGBOX_V1;
    assert!(tee.validate_for_kind(AndroidKeyMintTee).is_ok());
    assert!(is_invalid(
        tee.validate_enrollment_for_kind(AndroidKeyMintTee),
        "evidence.strongbox"
    ));
    let mut strongbox = test_evidence(AndroidKeyMintStrongBox);
    strongbox.facts &= !KAGEMUSHA_WALLET_FACT_STRONGBOX_V1;
    assert!(
        strongbox
            .validate_enrollment_for_kind(AndroidKeyMintStrongBox)
            .is_err()
    );
    let mut apple = test_evidence(AppleAppAttest);
    apple.facts |= KAGEMUSHA_WALLET_FACT_HARDWARE_BACKED_KEY_V1;
    assert!(is_invalid(
        apple.validate_for_kind(AppleAppAttest),
        "evidence.facts"
    ));
    let mut apple = test_evidence(AppleAppAttest);
    apple.boot_patch_level = 1;
    assert!(is_invalid(
        apple.validate_for_kind(AppleAppAttest),
        "evidence.patch_level"
    ));
    let evidence = test_evidence(AndroidKeyMintTee);
    let mut expected = evidence.digest.to_vec();
    expected.extend_from_slice(&evidence.time_ms.to_le_bytes());
    for value in [
        evidence.facts,
        evidence.os_patch_level,
        evidence.vendor_patch_level,
        evidence.boot_patch_level,
    ] {
        expected.extend_from_slice(&value.to_le_bytes());
    }
    assert_eq!(evidence.transcript(), expected);
}

#[test]
fn kagemusha_wallet_v1_regulatory_policy_rules() {
    let policy = |permitted_controls, blacklist_max_age_ms, time_anchor_max_response_ms| {
        KagemushaWalletRegulatoryPolicyV1 {
            permitted_controls,
            blacklist_max_age_ms,
            time_anchor_max_response_ms,
        }
    };
    let disabled = KagemushaWalletRegulatoryPolicyV1::default();
    assert!(disabled.validate().is_ok());
    assert!(!disabled.permits(0));
    assert!(!disabled.requires_time_anchor());
    let blacklist = KAGEMUSHA_WALLET_CONTROL_BLACKLIST_V1;
    let quotas = KAGEMUSHA_WALLET_CONTROL_QUOTAS_V1;
    let lease = KAGEMUSHA_WALLET_CONTROL_ATTESTATION_LEASE_V1;
    assert_eq!(KAGEMUSHA_WALLET_CONTROLS_DEFINED_MASK_V1, 0b111);
    for (value, valid) in [
        (policy(blacklist, 0, 0), true),
        (policy(blacklist, 60_000, 0), false),
        (policy(blacklist, 60_000, 5_000), true),
        (policy(blacklist, 0, 5_000), false),
        (policy(0, 60_000, 5_000), false),
        (policy(quotas, 0, 0), false),
        (policy(quotas, 0, 5_000), true),
        (policy(lease, 0, 5_000), true),
        (policy(lease, 0, 0), false),
        (policy(blacklist | quotas | lease, 86_400_000, 5_000), true),
        (policy(1 << 3, 0, 0), false),
    ] {
        assert_eq!(value.validate().is_ok(), valid, "{value:?}");
    }
    let all = policy(blacklist | quotas | lease, 1, 2);
    assert!(all.permits(blacklist | lease));
    assert!(!policy(blacklist, 0, 0).permits(blacklist | quotas));
    let mut expected = (blacklist | quotas | lease).to_le_bytes().to_vec();
    expected.extend_from_slice(&1_u64.to_le_bytes());
    expected.extend_from_slice(&2_u64.to_le_bytes());
    assert_eq!(all.transcript(), expected);
}

#[test]
fn kagemusha_wallet_v1_credential_sign_verify_decode_for_every_kind() {
    for (kind, seed) in [
        (KagemushaWalletEvidenceKindV1::AndroidKeyMintTee, 0x44),
        (KagemushaWalletEvidenceKindV1::AndroidKeyMintStrongBox, 0x47),
        (KagemushaWalletEvidenceKindV1::AppleAppAttest, 0x45),
    ] {
        let f = identity_fixture(kind, seed);
        let credential = f.credential;
        credential
            .verify(&f.scheme, &f.enrollment_certificate)
            .expect("verify");
        let transcript = credential.body.transcript();
        assert_eq!(&transcript[..2], &[1, 0]);
        assert_eq!(transcript[2 + 4 * 32 + 65 + 32], kind.tag());
        assert_eq!(
            credential.body.signing_message(),
            kagemusha_wallet_signing_message_v1(Domain::Credential, &transcript)
        );
        assert_eq!(
            credential.credential_digest(),
            kagemusha_wallet_signed_object_digest_v1(
                Role::Credential,
                &credential.body.signing_message(),
                &credential.signature
            )
        );
        let frame = credential.to_canonical_bytes().expect("frame");
        assert!(frame.len() <= KAGEMUSHA_WALLET_CREDENTIAL_MAX_BYTES_V1);
        let scheme_id = f.scheme.scheme_id();
        assert_eq!(
            KagemushaWalletCredentialV1::decode_canonical(&frame, &scheme_id).expect("decode"),
            credential
        );
        if kind == KagemushaWalletEvidenceKindV1::AndroidKeyMintTee {
            assert_every_flip_rejected_or_rebound(
                &frame,
                credential.credential_digest(),
                |bytes| {
                    KagemushaWalletCredentialV1::decode_canonical(bytes, &scheme_id)
                        .ok()
                        .filter(|decoded| {
                            decoded.verify(&f.scheme, &f.enrollment_certificate).is_ok()
                        })
                        .map(|decoded| decoded.credential_digest())
                },
            );
        }
    }
}

#[test]
fn kagemusha_wallet_v1_credential_body_rules() {
    let f = android();
    let body = f.credential.body;
    body.validate().expect("valid body");
    let cases: [(BodyMutation, &str); 10] = [
        (|b| b.wallet_id[0] ^= 1, "credential.wallet_id"),
        (
            |b| b.provider_contract = [0x99; 32],
            "credential.provider_contract",
        ),
        (|b| b.account_digest = [0; 32], "credential.account_digest"),
        (
            |b| b.issuer_certificate = [0; 32],
            "credential.issuer_certificate",
        ),
        (
            |b| b.fresh_evidence.time_ms += 1,
            "credential.fresh_evidence",
        ),
        (
            |b| {
                b.renewal_sequence = 1;
                b.fresh_evidence.time_ms = b.enrollment_evidence.time_ms - 1;
            },
            "credential.fresh_evidence.time_ms",
        ),
        (
            |b| b.lease_expires_at_ms = 1,
            "credential.lease_expires_at_ms",
        ),
        (
            |b| {
                b.regulatory_policy.permitted_controls =
                    KAGEMUSHA_WALLET_CONTROL_ATTESTATION_LEASE_V1;
                b.regulatory_policy.time_anchor_max_response_ms = 5_000;
            },
            "credential.lease_expires_at_ms",
        ),
        (
            |b| b.regulatory_policy.time_anchor_max_response_ms = 5_000,
            "regulatory_policy.time_anchor_max_response_ms",
        ),
        (
            |b| b.enrollment_evidence.facts &= !KAGEMUSHA_WALLET_FACT_VERIFIED_BOOT_V1,
            "evidence.required_facts",
        ),
    ];
    for (mutate, field) in cases {
        let mut bad = body;
        mutate(&mut bad);
        assert!(is_invalid(bad.validate(), field), "{field}");
        assert!(f.issue(&bad).is_err(), "{field}");
    }
    let mut version = body;
    version.version = 2;
    assert!(matches!(
        version.validate(),
        Err(KagemushaWalletValidationErrorV1::UnsupportedVersion { .. })
    ));
    let mut leased = body;
    leased.regulatory_policy.permitted_controls = KAGEMUSHA_WALLET_CONTROL_ATTESTATION_LEASE_V1;
    leased.regulatory_policy.time_anchor_max_response_ms = 5_000;
    leased.lease_expires_at_ms = ISSUED_AT_MS + 86_400_000;
    leased.validate().expect("lease permitted and set");
    let mut renewed = body;
    renewed.renewal_sequence = 1;
    renewed.fresh_evidence.time_ms = renewed.enrollment_evidence.time_ms;
    renewed.fresh_evidence.digest = [0x51; 32];
    renewed.validate().expect("renewal evidence");
}

#[test]
fn kagemusha_wallet_v1_credential_issuer_verification() {
    let f = android();
    let credential = f.credential;
    let mut other_scheme = f.scheme;
    other_scheme.relation_id = [0x77; 32];
    assert!(matches!(
        credential.verify(&other_scheme, &f.enrollment_certificate),
        Err(KagemushaWalletValidationErrorV1::SchemeMismatch { .. })
    ));
    let second_enrollment = test_certificate(
        &f.scheme,
        &f.root,
        KagemushaWalletSignerRoleV1::Enrollment,
        &signing_key(0x23),
        2,
    );
    assert!(is_invalid(
        credential.verify(&f.scheme, &second_enrollment),
        "credential.issuer_certificate"
    ));
    let regulatory_signer = signing_key(0x66);
    let regulatory = test_certificate(
        &f.scheme,
        &f.root,
        KagemushaWalletSignerRoleV1::RegulatoryPolicy,
        &regulatory_signer,
        1,
    );
    let mut body = credential.body;
    body.issuer_certificate = regulatory.certificate_digest();
    assert!(is_invalid(
        KagemushaWalletCredentialV1::sign(
            body,
            &regulatory,
            raw_output(&regulatory_signer, &body.signing_message())
        )
        .map(|_| ()),
        "certificate.role"
    ));
    // A RegulatoryPolicy-role key cannot issue credentials even with a valid signature.
    let forged = KagemushaWalletCredentialV1 {
        body,
        signature: kagemusha_wallet_freeze_signature_v1(
            &regulatory.body.key,
            Domain::Credential,
            &body.signing_message(),
            raw_output(&regulatory_signer, &body.signing_message()),
        )
        .expect("regulatory-key signature"),
    };
    assert!(is_invalid(
        forged.verify(&f.scheme, &regulatory),
        "certificate.role"
    ));
    let mut by_root = credential;
    let root_signature: P256Signature = f.root.sign(&credential.body.signing_message());
    let mut root_raw = [0; 64];
    root_raw.copy_from_slice(
        &root_signature
            .normalize_s()
            .unwrap_or(root_signature)
            .to_bytes(),
    );
    by_root.signature = KagemushaDeviceSignatureV1::from_raw_bytes(&root_raw).expect("low-S");
    assert!(matches!(
        by_root.verify(&f.scheme, &f.enrollment_certificate),
        Err(KagemushaWalletValidationErrorV1::InvalidSignature {
            domain: Domain::Credential
        })
    ));
    let mut mismatched = credential.body;
    mismatched.issuer_certificate = second_enrollment.certificate_digest();
    assert!(is_invalid(
        f.issue(&mismatched).map(|_| ()),
        "credential.issuer_certificate"
    ));
}

#[test]
fn kagemusha_wallet_v1_credential_decode_order() {
    let f = android();
    let scheme_id = f.scheme.scheme_id();
    let frame = f.credential.to_canonical_bytes().expect("frame");
    assert!(matches!(
        KagemushaWalletCredentialV1::decode_canonical(
            &vec![0; KAGEMUSHA_WALLET_CREDENTIAL_MAX_BYTES_V1 + 1],
            &scheme_id
        ),
        Err(KagemushaWalletValidationErrorV1::EncodedSizeExceeded { .. })
    ));
    let mut noncanonical = frame.clone();
    noncanonical.push(0);
    assert!(matches!(
        KagemushaWalletCredentialV1::decode_canonical(&noncanonical, &scheme_id),
        Err(KagemushaWalletValidationErrorV1::Codec(_))
    ));
    let mut wrong_version = f.credential;
    wrong_version.body.version = 2;
    wrong_version.body.scheme_id = [9; 32];
    assert!(matches!(
        KagemushaWalletCredentialV1::decode_canonical(
            &norito::encode_canonical(&wrong_version).expect("encode"),
            &scheme_id
        ),
        Err(KagemushaWalletValidationErrorV1::UnsupportedVersion { .. })
    ));
    assert!(matches!(
        KagemushaWalletCredentialV1::decode_canonical(&frame, &[9; 32]),
        Err(KagemushaWalletValidationErrorV1::SchemeMismatch { .. })
    ));
    let mut invalid = f.credential;
    invalid.body.lease_expires_at_ms = 1;
    assert!(is_invalid(
        KagemushaWalletCredentialV1::decode_canonical(
            &norito::encode_canonical(&invalid).expect("encode"),
            &scheme_id
        )
        .map(|_| ()),
        "credential.lease_expires_at_ms"
    ));
    assert!(invalid.to_canonical_bytes().is_err());
}

#[test]
fn kagemusha_wallet_v1_credential_replacement_rules() {
    let f = android();
    let previous = f.credential;
    let renewal_signer = signing_key(0x24);
    let renewal_certificate = test_certificate(
        &f.scheme,
        &f.root,
        KagemushaWalletSignerRoleV1::Enrollment,
        &renewal_signer,
        2,
    );
    let mut body = previous.body;
    body.renewal_sequence = 1;
    body.fresh_evidence.digest = [0x52; 32];
    body.fresh_evidence.time_ms = ISSUED_AT_MS + 10_000;
    body.issued_at_ms = ISSUED_AT_MS + 20_000;
    body.issuer_certificate = renewal_certificate.certificate_digest();
    let replacement = KagemushaWalletCredentialV1::sign(
        body,
        &renewal_certificate,
        raw_output(&renewal_signer, &body.signing_message()),
    )
    .expect("replacement");
    replacement
        .verify(&f.scheme, &renewal_certificate)
        .expect("verify replacement");
    replacement
        .validate_replacement_of(&previous)
        .expect("replacement rules");
    assert!(is_invalid(
        previous.validate_replacement_of(&replacement),
        "credential.renewal_sequence"
    ));
    let cases: [BodyMutation; 4] = [
        |b| b.renewal_sequence = 2,
        |b| b.account_digest = [0x61; 32],
        |b| b.app_policy = [0x62; 32],
        |b| b.regulatory_policy.permitted_controls = KAGEMUSHA_WALLET_CONTROL_BLACKLIST_V1,
    ];
    for mutate in cases {
        let mut changed = replacement.body;
        mutate(&mut changed);
        let changed = KagemushaWalletCredentialV1::sign(
            changed,
            &renewal_certificate,
            raw_output(&renewal_signer, &changed.signing_message()),
        )
        .expect("valid standalone credential");
        assert!(changed.validate_replacement_of(&previous).is_err());
    }
    let mut saturated = previous;
    saturated.body.renewal_sequence = u32::MAX;
    saturated.body.fresh_evidence.digest = [0x53; 32];
    assert!(matches!(
        replacement.validate_replacement_of(&saturated),
        Err(KagemushaWalletValidationErrorV1::ArithmeticOverflow { .. })
    ));
}

#[test]
fn kagemusha_wallet_v1_android_renewal_request() {
    let f = android();
    let challenge = [0x71; 32];
    let request = android_renewal(&f, challenge);
    request.verify(&f.credential).expect("verify");
    assert_eq!(request.wallet_id, f.credential.body.wallet_id);
    assert_eq!(request.credential_digest, f.credential.credential_digest());
    let possession = request.possession_transcript();
    let mut expected = vec![1, 0];
    for digest in [
        request.scheme_id,
        request.wallet_id,
        request.credential_digest,
        challenge,
    ] {
        expected.extend_from_slice(&digest);
    }
    assert_eq!(possession, expected);
    assert_eq!(
        request.assertion_client_data_hash(),
        kagemusha_wallet_digest_v1(Role::RenewalAssertion, &expected)
    );
    assert_ne!(
        request.assertion_client_data_hash(),
        kagemusha_wallet_signing_message_v1(Domain::RenewalChallenge, &expected)
    );
    let KagemushaWalletRenewalEvidenceV1::Android {
        new_attested_key, ..
    } = &request.evidence
    else {
        panic!("android evidence");
    };
    let mut binding = vec![1, 0];
    binding.extend_from_slice(&request.scheme_id);
    binding.extend_from_slice(&request.wallet_id);
    binding.extend_from_slice(&challenge);
    binding.extend_from_slice(new_attested_key.as_sec1_bytes());
    assert_eq!(
        kagemusha_wallet_renewal_key_binding_transcript_v1(
            &request.scheme_id,
            &request.wallet_id,
            &challenge,
            new_attested_key
        ),
        binding
    );
    let kind = f.credential.body.evidence_kind;
    assert_eq!(
        request.evidence.evidence_digest(kind).expect("digest"),
        kagemusha_wallet_evidence_digest_v1(
            kind,
            &[b"renewal-leaf-der", b"renewal-intermediate-der"]
        )
        .expect("digest")
    );
    assert!(
        request
            .evidence
            .evidence_digest(KagemushaWalletEvidenceKindV1::AppleAppAttest)
            .is_err()
    );

    let frame = request.to_canonical_bytes().expect("frame");
    assert!(frame.len() <= KAGEMUSHA_WALLET_RENEWAL_REQUEST_MAX_BYTES_V1);
    let scheme_id = f.scheme.scheme_id();
    assert_eq!(
        KagemushaWalletRenewalRequestV1::decode_canonical(&frame, &scheme_id).expect("decode"),
        request
    );
    assert!(matches!(
        KagemushaWalletRenewalRequestV1::decode_canonical(&frame, &[3; 32]),
        Err(KagemushaWalletValidationErrorV1::SchemeMismatch { .. })
    ));
    assert!(matches!(
        KagemushaWalletRenewalRequestV1::decode_canonical(
            &vec![0; KAGEMUSHA_WALLET_RENEWAL_REQUEST_MAX_BYTES_V1 + 1],
            &scheme_id
        ),
        Err(KagemushaWalletValidationErrorV1::EncodedSizeExceeded { .. })
    ));
    let mut wrong_version = request.clone();
    wrong_version.version = 2;
    assert!(matches!(
        KagemushaWalletRenewalRequestV1::decode_canonical(
            &norito::encode_canonical(&wrong_version).expect("encode"),
            &scheme_id
        ),
        Err(KagemushaWalletValidationErrorV1::UnsupportedVersion { .. })
    ));

    let mut tampered = request.clone();
    tampered.challenge = [0x72; 32];
    assert!(matches!(
        tampered.verify(&f.credential),
        Err(KagemushaWalletValidationErrorV1::InvalidSignature {
            domain: Domain::RenewalChallenge
        })
    ));
    let mut stale = request.clone();
    stale.credential_digest = [0x73; 32];
    assert!(is_invalid(
        stale.verify(&f.credential),
        "renewal.credential_digest"
    ));
    let mut swapped_key = request.clone();
    if let KagemushaWalletRenewalEvidenceV1::Android {
        new_attested_key, ..
    } = &mut swapped_key.evidence
    {
        *new_attested_key = public_key(&signing_key(0x56));
    }
    assert!(matches!(
        swapped_key.verify(&f.credential),
        Err(KagemushaWalletValidationErrorV1::InvalidSignature {
            domain: Domain::RenewalKeyBinding
        })
    ));
    let mut wrong_platform = request.clone();
    wrong_platform.evidence = KagemushaWalletRenewalEvidenceV1::Apple { assertion: vec![1] };
    assert!(is_invalid(
        wrong_platform.verify(&f.credential),
        "renewal.evidence"
    ));
    for chain_len in [1, KAGEMUSHA_WALLET_RENEWAL_ANDROID_CHAIN_MAX_V1 + 1] {
        let mut bad = request.clone();
        if let KagemushaWalletRenewalEvidenceV1::Android { chain, .. } = &mut bad.evidence {
            chain.resize(
                chain_len,
                KagemushaWalletDerCertificateV1 { der: vec![0x30] },
            );
        }
        assert!(is_invalid(bad.validate(), "renewal.chain"));
    }
    for der in [
        Vec::new(),
        vec![0x30; KAGEMUSHA_WALLET_DER_CERTIFICATE_MAX_BYTES_V1 + 1],
    ] {
        let mut bad = request.clone();
        if let KagemushaWalletRenewalEvidenceV1::Android { chain, .. } = &mut bad.evidence {
            chain[0].der = der;
        }
        assert!(is_invalid(bad.validate(), "renewal.chain.der"));
    }
    let mut max_chain = request.clone();
    if let KagemushaWalletRenewalEvidenceV1::Android { chain, .. } = &mut max_chain.evidence {
        chain.resize(
            KAGEMUSHA_WALLET_RENEWAL_ANDROID_CHAIN_MAX_V1,
            KagemushaWalletDerCertificateV1 {
                der: vec![0x30; KAGEMUSHA_WALLET_DER_CERTIFICATE_MAX_BYTES_V1],
            },
        );
    }
    // Eight certificates at the per-certificate maximum exceed the chain total, which keeps
    // every request that validates within the frame cap.
    assert!(is_invalid(max_chain.validate(), "renewal.chain.bytes"));
    assert!(
        norito::encode_canonical(&max_chain).expect("encode").len()
            > KAGEMUSHA_WALLET_RENEWAL_REQUEST_MAX_BYTES_V1
    );
    let apple = apple();
    assert!(is_invalid(
        KagemushaWalletRenewalEvidenceV1::android_signed(
            &apple.credential,
            &challenge,
            public_key(&signing_key(0x55)),
            KagemushaWalletSignerOutputV1::Raw([1; 64]),
            android_chain(),
        )
        .map(|_| ()),
        "renewal.evidence"
    ));
}

#[test]
fn kagemusha_wallet_v1_worst_case_renewal_fits_its_frame_cap() {
    let f = android();
    let scheme_id = f.scheme.scheme_id();
    let request = android_renewal(&f, [0x71; 32]);
    let with_chain = |sizes: &[usize]| {
        let mut renewal = request.clone();
        if let KagemushaWalletRenewalEvidenceV1::Android { chain, .. } = &mut renewal.evidence {
            *chain = sizes
                .iter()
                .map(|&len| KagemushaWalletDerCertificateV1 {
                    der: vec![0x30; len],
                })
                .collect();
        }
        renewal
    };
    let even = KAGEMUSHA_WALLET_RENEWAL_ANDROID_CHAIN_MAX_BYTES_V1
        / KAGEMUSHA_WALLET_RENEWAL_ANDROID_CHAIN_MAX_V1;
    let widest = KAGEMUSHA_WALLET_RENEWAL_ANDROID_CHAIN_MAX_BYTES_V1
        / KAGEMUSHA_WALLET_DER_CERTIFICATE_MAX_BYTES_V1;
    for sizes in [
        vec![even; KAGEMUSHA_WALLET_RENEWAL_ANDROID_CHAIN_MAX_V1],
        vec![KAGEMUSHA_WALLET_DER_CERTIFICATE_MAX_BYTES_V1; widest],
    ] {
        let worst = with_chain(&sizes);
        worst.verify(&f.credential).expect("worst case verifies");
        let frame = worst.to_canonical_bytes().expect("worst case fits");
        println!(
            "kagemusha wallet v1 worst-case renewal ({} certificates): {} bytes (cap {})",
            sizes.len(),
            frame.len(),
            KAGEMUSHA_WALLET_RENEWAL_REQUEST_MAX_BYTES_V1
        );
        assert!(frame.len() <= KAGEMUSHA_WALLET_RENEWAL_REQUEST_MAX_BYTES_V1);
        assert_eq!(
            KagemushaWalletRenewalRequestV1::decode_canonical(&frame, &scheme_id).expect("decode"),
            worst
        );
    }
    let mut over = vec![even; KAGEMUSHA_WALLET_RENEWAL_ANDROID_CHAIN_MAX_V1];
    over[0] += 1;
    assert!(is_invalid(
        with_chain(&over).validate(),
        "renewal.chain.bytes"
    ));
}

#[test]
fn kagemusha_wallet_v1_apple_renewal_request() {
    let f = apple();
    let request = apple_renewal(&f, [0x74; 32]);
    request.verify(&f.credential).expect("verify");
    let kind = f.credential.body.evidence_kind;
    assert_eq!(
        request.evidence.evidence_digest(kind).expect("digest"),
        kagemusha_wallet_evidence_digest_v1(kind, &[b"app-attest-assertion"]).expect("digest")
    );
    assert!(
        request
            .evidence
            .evidence_digest(KagemushaWalletEvidenceKindV1::AndroidKeyMintTee)
            .is_err()
    );
    let frame = request.to_canonical_bytes().expect("frame");
    assert_eq!(
        KagemushaWalletRenewalRequestV1::decode_canonical(&frame, &f.scheme.scheme_id())
            .expect("decode"),
        request
    );
    for assertion in [
        Vec::new(),
        vec![1; KAGEMUSHA_WALLET_RENEWAL_APPLE_ASSERTION_MAX_BYTES_V1 + 1],
    ] {
        let mut bad = request.clone();
        bad.evidence = KagemushaWalletRenewalEvidenceV1::Apple { assertion };
        assert!(is_invalid(bad.validate(), "renewal.assertion"));
    }
    let android_fixture = android();
    let android_request = android_renewal(&android_fixture, [0x75; 32]);
    let mut wrong_platform = request.clone();
    wrong_platform.evidence = android_request.evidence;
    assert!(is_invalid(
        wrong_platform.verify(&f.credential),
        "renewal.evidence"
    ));
    let mut zero_challenge = request;
    zero_challenge.challenge = [0; 32];
    assert!(is_invalid(zero_challenge.validate(), "renewal.challenge"));
}

#[test]
fn kagemusha_wallet_v1_artifact_manifest_binds_the_scheme() {
    let f = android();
    let signer = signing_key(0x33);
    let certificate = test_certificate(
        &f.scheme,
        &f.root,
        KagemushaWalletSignerRoleV1::Artifact,
        &signer,
        1,
    );
    let body = artifact_body(&f.scheme, &certificate);
    let manifest = KagemushaWalletArtifactManifestV1::sign(
        body,
        &certificate,
        raw_output(&signer, &body.signing_message()),
    )
    .expect("manifest");
    manifest.verify(&f.scheme, &certificate).expect("verify");
    let transcript = body.transcript();
    assert_eq!(
        transcript.len(),
        KAGEMUSHA_WALLET_ARTIFACT_MANIFEST_BODY_TRANSCRIPT_BYTES_V1
    );
    assert_eq!(&transcript[..2], &[1, 0]);
    assert_eq!(&transcript[2..34], &f.scheme.network_id);
    assert_eq!(&transcript[258..290], &certificate.certificate_digest());
    assert_eq!(body.recomputed_relation_id(), f.scheme.relation_id);
    assert_eq!(
        body.signing_message(),
        kagemusha_wallet_signing_message_v1(Domain::ArtifactManifest, &transcript)
    );
    assert_eq!(
        manifest.manifest_digest(),
        kagemusha_wallet_signed_object_digest_v1(
            Role::ArtifactManifest,
            &body.signing_message(),
            &manifest.signature
        )
    );

    let mut bad = body;
    bad.native_profile_digest = [0x26; 32];
    assert!(is_invalid(bad.validate(), "artifact_manifest.relation_id"));
    let mut bad = body;
    bad.provider_contract = [0x99; 32];
    assert!(is_invalid(
        bad.validate(),
        "artifact_manifest.provider_contract"
    ));
    let mut bad = body;
    bad.signer_certificate = [0; 32];
    assert!(is_invalid(
        bad.validate(),
        "artifact_manifest.signer_certificate"
    ));
    let mut bad = body;
    bad.network_id[31] &= !1;
    assert!(is_invalid(bad.validate(), "network_id"));

    let mut other_scheme = f.scheme;
    other_scheme.relation_id = [0x77; 32];
    assert!(matches!(
        manifest.verify(&other_scheme, &certificate),
        Err(KagemushaWalletValidationErrorV1::SchemeMismatch {
            field: "artifact_manifest.relation_id"
        })
    ));
    assert!(is_invalid(
        manifest.verify(&f.scheme, &f.enrollment_certificate),
        "artifact_manifest.signer_certificate"
    ));
    let mut enrollment_body = body;
    enrollment_body.signer_certificate = f.enrollment_certificate.certificate_digest();
    assert!(is_invalid(
        KagemushaWalletArtifactManifestV1::sign(
            enrollment_body,
            &f.enrollment_certificate,
            raw_output(&f.enrollment_signer, &enrollment_body.signing_message()),
        )
        .map(|_| ()),
        "certificate.role"
    ));

    let frame = manifest.to_canonical_bytes().expect("frame");
    assert!(frame.len() <= KAGEMUSHA_WALLET_ARTIFACT_MANIFEST_MAX_BYTES_V1);
    assert_eq!(
        KagemushaWalletArtifactManifestV1::decode_canonical(&frame, &f.scheme).expect("decode"),
        manifest
    );
    assert!(matches!(
        KagemushaWalletArtifactManifestV1::decode_canonical(&frame, &other_scheme),
        Err(KagemushaWalletValidationErrorV1::SchemeMismatch { .. })
    ));
    let mut wrong_version = manifest;
    wrong_version.body.version = 2;
    assert!(matches!(
        KagemushaWalletArtifactManifestV1::decode_canonical(
            &norito::encode_canonical(&wrong_version).expect("encode"),
            &f.scheme
        ),
        Err(KagemushaWalletValidationErrorV1::UnsupportedVersion { .. })
    ));
    assert_every_flip_rejected_or_rebound(&frame, manifest.manifest_digest(), |bytes| {
        KagemushaWalletArtifactManifestV1::decode_canonical(bytes, &f.scheme)
            .ok()
            .filter(|decoded| decoded.verify(&f.scheme, &certificate).is_ok())
            .map(|decoded| decoded.manifest_digest())
    });
}

#[test]
fn kagemusha_wallet_v1_identity_frames_fit_their_caps() {
    let android = android();
    let apple = apple();
    let signer = signing_key(0x33);
    let artifact = test_certificate(
        &android.scheme,
        &android.root,
        KagemushaWalletSignerRoleV1::Artifact,
        &signer,
        1,
    );
    let body = artifact_body(&android.scheme, &artifact);
    let manifest = KagemushaWalletArtifactManifestV1::sign(
        body,
        &artifact,
        raw_output(&signer, &body.signing_message()),
    )
    .expect("manifest");
    let regulatory = test_certificate(
        &android.scheme,
        &android.root,
        KagemushaWalletSignerRoleV1::RegulatoryPolicy,
        &signing_key(0x66),
        1,
    );
    let set = KagemushaWalletCertificateSetV1::new(vec![
        android.enrollment_certificate,
        regulatory,
        artifact,
    ])
    .expect("set");
    let measured = [
        (
            "scheme",
            android.scheme.to_canonical_bytes().expect("scheme").len(),
            KAGEMUSHA_WALLET_SCHEME_MAX_BYTES_V1,
        ),
        (
            "certificate",
            artifact.to_canonical_bytes().expect("certificate").len(),
            KAGEMUSHA_WALLET_CERTIFICATE_MAX_BYTES_V1,
        ),
        (
            "certificate set (3)",
            norito::encode_canonical(&set).expect("set").len(),
            3 * KAGEMUSHA_WALLET_CERTIFICATE_MAX_BYTES_V1,
        ),
        (
            "credential (android)",
            android
                .credential
                .to_canonical_bytes()
                .expect("credential")
                .len(),
            KAGEMUSHA_WALLET_CREDENTIAL_MAX_BYTES_V1,
        ),
        (
            "credential (apple)",
            apple
                .credential
                .to_canonical_bytes()
                .expect("credential")
                .len(),
            KAGEMUSHA_WALLET_CREDENTIAL_MAX_BYTES_V1,
        ),
        (
            "artifact manifest",
            manifest.to_canonical_bytes().expect("manifest").len(),
            KAGEMUSHA_WALLET_ARTIFACT_MANIFEST_MAX_BYTES_V1,
        ),
        (
            "renewal (android, 2 short certificates)",
            android_renewal(&android, [0x71; 32])
                .to_canonical_bytes()
                .expect("renewal")
                .len(),
            KAGEMUSHA_WALLET_RENEWAL_REQUEST_MAX_BYTES_V1,
        ),
        (
            "renewal (apple, short assertion)",
            apple_renewal(&apple, [0x74; 32])
                .to_canonical_bytes()
                .expect("renewal")
                .len(),
            KAGEMUSHA_WALLET_RENEWAL_REQUEST_MAX_BYTES_V1,
        ),
    ];
    for (name, actual, cap) in measured {
        println!("kagemusha wallet v1 frame {name}: {actual} bytes (cap {cap})");
        assert!(actual <= cap, "{name}: {actual} > {cap}");
    }
}
