//! Deterministic provider DATA for server custody tests; no actual enrollment admission.

use iroha_config::parameters::actual::KagemushaEnrollmentProvider;
use iroha_crypto::{Algorithm, KeyPair};
use iroha_data_model::kagemusha::*;
use p256::ecdsa::{Signature, SigningKey, signature::Signer as _};
use std::path::PathBuf;

pub(super) fn public(key: &SigningKey) -> KagemushaDevicePublicKeyV1 {
    KagemushaDevicePublicKeyV1::from_sec1_bytes(
        key.verifying_key().to_encoded_point(false).as_bytes(),
    )
    .unwrap()
}

pub(super) fn certificate(
    scheme: &KagemushaWalletSchemeV1,
    key: &SigningKey,
    role: KagemushaWalletSignerRoleV1,
    serial: u64,
) -> KagemushaWalletSignerCertificateV1 {
    let root = SigningKey::from_slice(&[1; 32]).unwrap();
    let body = KagemushaWalletSignerCertificateBodyV1 {
        version: 1,
        scheme_id: scheme.scheme_id(),
        role,
        key: public(key),
        serial,
    };
    let signature: Signature = root.sign(&body.signing_message());
    KagemushaWalletSignerCertificateV1::sign(
        body,
        scheme,
        KagemushaWalletSignerOutputV1::Der(signature.to_der().as_bytes()),
    )
    .unwrap()
}

pub(super) fn provider(path: PathBuf) -> KagemushaEnrollmentProvider {
    let root = SigningKey::from_slice(&[1; 32]).unwrap();
    let key = SigningKey::from_slice(&[2; 32]).unwrap();
    let scheme = KagemushaWalletSchemeV1 {
        version: 1,
        network_id: [3; 32],
        scheme_root_key: public(&root),
        relation_id: [4; 32],
        provider_contract: kagemusha_wallet_provider_contract_v1(),
    };
    let app = KagemushaWalletAppPolicyV1 {
        version: 1,
        scheme_id: scheme.scheme_id(),
        identity: KagemushaWalletAppIdentityV1::Apple {
            app_id: "TEAM.org.example.wallet".into(),
        },
    };
    let enrollment = KagemushaWalletEnrollmentPolicyTemplateV1 {
        version: 1,
        scheme_id: scheme.scheme_id(),
        app_policy: app.policy_digest().unwrap(),
        platform: KagemushaWalletEnrollmentPlatformV1::Apple {
            attestation_root_sha256: [6; 32],
        },
        regulatory_policy: KagemushaWalletRegulatoryPolicyV1::default(),
        challenge_lifetime_ms: 600_001,
        attestation_lease_lifetime_ms: 0,
    };
    let observer = KeyPair::from_seed(vec![7; 32], Algorithm::Ed25519);
    let eligibility = KagemushaEligibilityPolicyTemplateV1 {
        version: 1,
        network_id: scheme.network_id,
        scheme_id: scheme.scheme_id(),
        revision: 1,

        authority: KagemushaEligibilityAuthorityV1::Bank { fi_digest: [8; 32] },
        public_key: observer.public_key().to_bytes().1.try_into().unwrap(),
        maximum_response_ms: 1000,
    };
    eligibility.validate().unwrap();
    KagemushaEnrollmentProvider {
        eligibility,
        scheme,
        app,
        enrollment,
        certificate: certificate(&scheme, &key, KagemushaWalletSignerRoleV1::Enrollment, 1),
        manifest_digest: [9; 32],
        release_digest: [10; 32],
        service_origin_digest: [11; 32],
        observation_endpoint: "https://provider.example/eligibility".parse().unwrap(),
        observation_credential: path.with_file_name("transport"),
        worker: iroha_config::parameters::actual::KagemushaEnrollmentWorker {
            python_executable: "/opt/issuer/python".into(),
            python_sha256: [41; 32],
            verifier_archive: "/opt/issuer/verifier.pyz".into(),
            verifier_sha256: [42; 32],
            openssl_executable: "/opt/issuer/openssl".into(),
            openssl_sha256: [43; 32],
            attestation_root: Some("/opt/issuer/root.pem".into()),
            store_directory: "/private/issuer/worker".into(),
            exchange_timeout: std::time::Duration::from_secs(60),
        },
        signer_private_key: path,
    }
}

/// Arbitrary canonical UUID asset DATA for deriving concrete test policies.
pub(super) fn asset(seed: u8, scale: u32) -> KagemushaWalletAssetScopeV1 {
    let mut id = [seed; 16];
    id[6] = 0x40 | (id[6] & 15);
    id[8] = 0x80 | (id[8] & 63);
    KagemushaWalletAssetScopeV1::new(
        iroha_data_model::asset::AssetDefinitionId::from_uuid_bytes(id).unwrap(),
        &iroha_data_model::nexus::AxtAssetIncarnationV1::try_from_bytes(
            *iroha_crypto::Hash::new([seed; 32]).as_ref(),
        )
        .unwrap(),
        scale,
    )
    .unwrap()
}
