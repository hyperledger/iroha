//! Initial credentials remain bound to the signed policy and actual wallet incarnation.

use super::owner::Error;
use crate::kagemusha_wallet_advance_v1::KagemushaWalletKeyProfileV1;
use iroha_data_model::kagemusha::*;

fn invalid() -> Error {
    Error::Original("initial enrollment credential binding")
}

/// One hardware profile per platform: Android generates in StrongBox where the phone declares
/// it and in the TEE otherwise, and the attested level chooses the evidence kind; Apple uses
/// the Secure Enclave. No policy selects or refuses a hardware level.
pub(super) fn evidence_matches_policy(
    platform: &KagemushaWalletEnrollmentPlatformV1,
    profile: KagemushaWalletKeyProfileV1,
    evidence: KagemushaWalletEvidenceKindV1,
) -> bool {
    use KagemushaWalletEnrollmentPlatformV1 as Platform;
    use KagemushaWalletEvidenceKindV1 as Evidence;
    use KagemushaWalletKeyProfileV1 as Profile;
    matches!(
        (platform, profile, evidence),
        (
            Platform::Android { .. },
            Profile::SecureElementOrTee,
            Evidence::AndroidKeyMintTee | Evidence::AndroidKeyMintStrongBox
        ) | (
            Platform::Apple { .. },
            Profile::SecureElement,
            Evidence::AppleAppAttest
        )
    )
}

/// The single key profile of a platform.
pub(super) fn platform_key_profile(
    platform: &KagemushaWalletEnrollmentPlatformV1,
) -> KagemushaWalletKeyProfileV1 {
    match platform {
        KagemushaWalletEnrollmentPlatformV1::Android { .. } => {
            KagemushaWalletKeyProfileV1::SecureElementOrTee
        }
        KagemushaWalletEnrollmentPlatformV1::Apple { .. } => {
            KagemushaWalletKeyProfileV1::SecureElement
        }
    }
}

// A later monetary marker must still name the exact original wallet incarnation. Enrollment
// verification binds issuer/E1/key; these checks also bind the current durable marker's scope.
pub(super) fn verify_initial_credential_marker(
    credential: &KagemushaWalletCredentialV1,
    scheme: &KagemushaWalletSchemeV1,
    certificate: &KagemushaWalletSignerCertificateV1,
    challenge: &KagemushaWalletEnrollmentChallengeV1,
    marker: &KagemushaWalletMarkerV1,
) -> Result<(), Error> {
    if marker.scheme_id != challenge.scheme_id
        || marker.asset_digest != challenge.asset_digest
        || marker.wallet_id != challenge.wallet_id(&marker.payment_key)
        || marker.wallet_id != credential.body.wallet_id
    {
        return Err(invalid());
    }
    credential
        .verify_enrollment(scheme, certificate, challenge, &marker.payment_key)
        .map_err(|_| invalid())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_evidence_requires_the_single_platform_profile_and_attested_kind() {
        use KagemushaWalletEnrollmentPlatformV1 as Platform;
        use KagemushaWalletEvidenceKindV1 as Evidence;
        use KagemushaWalletKeyProfileV1 as Profile;
        let android = Platform::Android {
            root_set: vec![KagemushaWalletAndroidRootV1 {
                family: KagemushaWalletAndroidRootFamilyV1::GoogleRsa,
                spki_sha256: [1; 32],
                revocation_source: KagemushaWalletRevocationSourceV1::GoogleAttestationStatus,
            }],
            patch_floor_yyyymm: 202_610,
        };
        let apple = Platform::Apple {
            attestation_root_sha256: [1; 32],
        };
        assert_eq!(platform_key_profile(&android), Profile::SecureElementOrTee);
        assert_eq!(platform_key_profile(&apple), Profile::SecureElement);
        for (platform, profile, allowed) in [
            (
                &android,
                Profile::SecureElementOrTee,
                vec![
                    Evidence::AndroidKeyMintTee,
                    Evidence::AndroidKeyMintStrongBox,
                ],
            ),
            (
                &apple,
                Profile::SecureElement,
                vec![Evidence::AppleAppAttest],
            ),
        ] {
            for evidence in Evidence::ALL {
                for offered in [Profile::SecureElement, Profile::SecureElementOrTee] {
                    assert_eq!(
                        evidence_matches_policy(platform, offered, evidence),
                        offered == profile && allowed.contains(&evidence),
                        "{platform:?}, {offered:?}, {evidence:?}",
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod credential_retry_tests {
    use super::*;
    use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};

    fn fixture<T>(name: &str) -> T
    where
        T: norito::NoritoSerialize,
        for<'de> T: norito::NoritoDeserialize<'de>,
    {
        let vectors: norito::json::Value = norito::json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/kagemusha/wallet_v1_vectors.json"
        )))
        .unwrap();
        let row = vectors["objects"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["type"].as_str() == Some(name))
            .unwrap();
        let bytes = hex::decode(row["canonical_hex"].as_str().unwrap()).unwrap();
        norito::decode_canonical_with_limits(&bytes, norito::canonical_decode_limits(bytes.len()))
            .unwrap()
    }

    fn enrollment_issuer(
        credential: &KagemushaWalletCredentialV1,
    ) -> KagemushaWalletSignerCertificateV1 {
        let vectors: norito::json::Value = norito::json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/kagemusha/wallet_v1_vectors.json"
        )))
        .unwrap();
        let companion: KagemushaWalletPayerCompanionV1 = fixture("KagemushaWalletPayerCompanionV1");
        if let Some(certificate) = companion
            .certificates
            .certificates
            .iter()
            .find(|certificate| {
                certificate.certificate_digest() == credential.body.issuer_certificate
            })
        {
            return *certificate;
        }
        for row in vectors["envelopes"].as_array().unwrap() {
            let bytes = hex::decode(row["canonical_hex"].as_str().unwrap()).unwrap();
            let envelope: KagemushaWalletEnvelopeV1 = norito::decode_canonical_with_limits(
                &bytes,
                norito::canonical_decode_limits(bytes.len()),
            )
            .unwrap();
            let certificates = match envelope.message {
                KagemushaWalletMessageV1::Request { request } => request.certificates,
                _ => continue,
            };
            if let Some(certificate) = certificates.certificates.iter().find(|certificate| {
                certificate.certificate_digest() == credential.body.issuer_certificate
            }) {
                return *certificate;
            }
        }
        panic!("original enrollment issuer fixture");
    }

    fn original_attempt() -> (
        KagemushaWalletSchemeV1,
        KagemushaWalletSignerCertificateV1,
        KagemushaWalletEnrollmentChallengeV1,
        KagemushaWalletCredentialV1,
        SigningKey,
    ) {
        // Public Model fixture keys sign test DATA only; no Native owner or financial proof
        // is constructed. The certificate is the original rooted Enrollment-role certificate.
        let scheme = fixture("KagemushaWalletSchemeV1");
        let original: KagemushaWalletCredentialV1 = fixture("KagemushaWalletCredentialV1");
        let issuer = enrollment_issuer(&original);
        let vectors: norito::json::Value = norito::json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/kagemusha/wallet_v1_vectors.json"
        )))
        .unwrap();
        let signing = vectors["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| {
                SigningKey::from_slice(&hex::decode(row["scalar_hex"].as_str().unwrap()).unwrap())
                    .unwrap()
            })
            .find(|key| {
                key.verifying_key().to_encoded_point(false).as_bytes()
                    == issuer.body.key.as_sec1_bytes()
            })
            .expect("public original Enrollment fixture signer");
        let challenge = KagemushaWalletEnrollmentChallengeV1 {
            version: KAGEMUSHA_WALLET_VERSION_V1,
            scheme_id: original.body.scheme_id,
            asset_digest: original.body.asset_digest,
            account_digest: original.body.account_digest,
            app_policy: original.body.app_policy,
            enrollment_policy: [0x71; 32],
            issuer_nonce: [0x72; 32],
        };
        let credential = signed_attempt(original.body, &issuer, &challenge, &signing);
        (scheme, issuer, challenge, credential, signing)
    }

    fn signed_attempt(
        mut body: KagemushaWalletCredentialBodyV1,
        issuer: &KagemushaWalletSignerCertificateV1,
        challenge: &KagemushaWalletEnrollmentChallengeV1,
        key: &SigningKey,
    ) -> KagemushaWalletCredentialV1 {
        body.enrollment_id = challenge.enrollment_id(&body.payment_key);
        body.wallet_id = challenge.wallet_id(&body.payment_key);
        let signature: Signature = key.sign(&body.signing_message());
        KagemushaWalletCredentialV1::sign(
            body,
            issuer,
            KagemushaWalletSignerOutputV1::Raw(signature.to_bytes().into()),
        )
        .unwrap()
    }

    #[test]
    fn retry_verifies_exact_rooted_credential_e1_and_current_marker_scope() {
        let (scheme, issuer, challenge, credential, signing) = original_attempt();
        let marker =
            KagemushaWalletMarkerV1::enrollment(&challenge, credential.body.payment_key).unwrap();
        assert!(
            verify_initial_credential_marker(&credential, &scheme, &issuer, &challenge, &marker)
                .is_ok()
        );
        for field in 0..4 {
            let mut changed = marker;
            match field {
                0 => changed.scheme_id[0] ^= 1,
                1 => changed.asset_digest[0] ^= 1,
                2 => changed.wallet_id[0] ^= 1,
                _ => {
                    let another = SigningKey::from_slice(&[0x73; 32]).unwrap();
                    changed.payment_key = KagemushaDevicePublicKeyV1::from_sec1_bytes(
                        another.verifying_key().to_encoded_point(false).as_bytes(),
                    )
                    .unwrap();
                }
            }
            assert!(
                verify_initial_credential_marker(
                    &credential,
                    &scheme,
                    &issuer,
                    &challenge,
                    &changed
                )
                .is_err()
            );
        }
        let mut other_e1 = challenge;
        other_e1.issuer_nonce[0] ^= 1;
        assert!(
            verify_initial_credential_marker(&credential, &scheme, &issuer, &other_e1, &marker)
                .is_err()
        );
        let other_credential = signed_attempt(credential.body, &issuer, &other_e1, &signing);
        other_credential.verify(&scheme, &issuer).unwrap();
        assert!(
            verify_initial_credential_marker(
                &other_credential,
                &scheme,
                &issuer,
                &challenge,
                &marker
            )
            .is_err()
        );
        let mut bad_signature = credential;
        bad_signature.body.account_digest[0] ^= 1;
        assert!(
            verify_initial_credential_marker(&bad_signature, &scheme, &issuer, &challenge, &marker)
                .is_err()
        );
    }
}
