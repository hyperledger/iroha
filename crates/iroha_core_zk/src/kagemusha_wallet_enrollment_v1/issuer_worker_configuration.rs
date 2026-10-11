//! Exact private verifier configuration derived from selected Model policy originals.
//!
//! These are consistency-checked bytes, not operator approval or runtime custody. The node
//! must independently admit the policies, root originals, runtime and inherited descriptors.

use super::*;

const CONFIG_SCHEMA: &str = "iroha.kagemusha.wallet-e1-verifier-config.v1";
const MAX_CONFIG: usize = 128 * 1024;
const MAX_ROOT: usize = 16 * 1024;

/// Android vendor adapter profiles this Native issuer knows, with their qualification state.
/// A profile is reviewed issuer code (enrollment policy, Adapter profiles); it is qualified
/// only by genuine device chains and enrollment tests, in a reviewed release. Every vendor
/// adapter that is unknown here, or known but unqualified, fails issuer configuration.
pub const ANDROID_VENDOR_ADAPTER_PROFILES_V1: &[(&str, bool)] = &[
    // Implemented in the issuer verifier; no genuine post-2019 no-GMS chain has qualified it.
    ("huawei", false),
];

/// Refuse a platform selection that names a vendor adapter which is not implemented and
/// qualified. Google root families use the implemented `google` profile. This is a
/// configuration failure before any E1 challenge can name the policy, never an E1 outcome;
/// every owner that selects a policy (issuer configuration, Native installed selection and the
/// operator service) calls it before creating a challenge.
/// # Errors
/// An unknown or unqualified vendor adapter identifier.
pub fn require_qualified_android_adapters_v1(
    platform: &KagemushaWalletEnrollmentPlatformV1,
) -> Result<(), Error> {
    let KagemushaWalletEnrollmentPlatformV1::Android { root_set, .. } = platform else {
        return Ok(());
    };
    for root in root_set {
        if let KagemushaWalletAndroidRootFamilyV1::Vendor { adapter_id } = &root.family {
            match ANDROID_VENDOR_ADAPTER_PROFILES_V1
                .iter()
                .find(|(known, _)| *known == adapter_id.as_str())
            {
                Some((_, true)) => {}
                Some((_, false)) => return Err(Error("unqualified Android adapter profile")),
                None => return Err(Error("unknown Android adapter profile")),
            }
        }
    }
    Ok(())
}

/// Public runtime locations already selected by the node's private process owner.
/// The worker is Linux-only. These strings do not open files or establish path custody.
pub struct VerifierRuntimeSelectionV1<'a> {
    /// Canonical absolute Linux path of the retained public OpenSSL executable.
    pub openssl_path: &'a str,
    /// Independently selected executable digest, also checked against inherited FD21.
    pub openssl_sha256: [u8; 32],
    /// Canonical absolute private directory path, also checked against inherited FD17.
    pub store_directory: &'a str,
}

/// Immutable private configuration bytes with their exact policy and digest bindings.
/// This object grants no enrollment, worker, signer, KYC or filesystem authority.
pub struct VerifierConfigurationV1 {
    original: Vec<u8>,
    digest: [u8; 32],
    app: KagemushaWalletAppPolicyV1,
    policy: KagemushaWalletEnrollmentPolicyV1,
}

fn linux_path(value: &str) -> Result<(), Error> {
    // Check spelling only. Actual descriptor/path identities and loaded dependencies belong
    // to the admitted process owner; no canonicalize-and-reopen operation is performed here.
    if value.len() > MAX_CONFIG
        || !value.starts_with('/')
        || value.as_bytes().contains(&0)
        || value[1..]
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(Error("private runtime path spelling"));
    }
    Ok(())
}

fn root_projection(root: &KagemushaWalletAndroidRootV1) -> Value {
    let source = match root.revocation_source {
        KagemushaWalletRevocationSourceV1::GoogleAttestationStatus => "google_attestation_status",
        KagemushaWalletRevocationSourceV1::OperatorDenylist => "operator_denylist",
    };
    let spki = hex::encode(root.spki_sha256);
    match &root.family {
        KagemushaWalletAndroidRootFamilyV1::GoogleRsa => norito::json!({
            "family": "google_rsa", "spki_sha256": (spki), "revocation_source": (source),
        }),
        KagemushaWalletAndroidRootFamilyV1::GoogleCa1 => norito::json!({
            "family": "google_ca1", "spki_sha256": (spki), "revocation_source": (source),
        }),
        KagemushaWalletAndroidRootFamilyV1::Vendor { adapter_id } => norito::json!({
            "family": "vendor", "adapter_id": (adapter_id.clone()), "spki_sha256": (spki),
            "revocation_source": (source),
        }),
    }
}

impl VerifierConfigurationV1 {
    /// Derive the sole private worker projection from selected policy and public originals.
    /// Android selects no root original: its chain carries its root, matched by SPKI against
    /// the policy's root set. Apple requires its selected root DER, checked against the pin.
    /// The operator denylist is not configuration: it changes without a policy digest change,
    /// and the worker authenticates its active custody at every verification.
    /// # Errors
    /// Rejects invalid/mismatched policies, an unqualified vendor adapter, a root original on
    /// Android or a missing/substituted Apple root, path spelling, zero runtime pins or
    /// oversized configuration. It never reads secrets or a filesystem.
    pub fn from_selected(
        app: &KagemushaWalletAppPolicyV1,
        policy: &KagemushaWalletEnrollmentPolicyV1,
        apple_root_original: Option<&[u8]>,
        runtime: VerifierRuntimeSelectionV1<'_>,
    ) -> Result<Self, Error> {
        policy
            .validate_for_app(app)
            .map_err(|_| Error("selected policy binding"))?;
        require_qualified_android_adapters_v1(&policy.platform)?;
        linux_path(runtime.openssl_path)?;
        linux_path(runtime.store_directory)?;
        if runtime.openssl_sha256 == [0; 32] {
            return Err(Error("empty runtime pin"));
        }
        let regulator = norito::json!({
            "permitted_controls": (policy.regulatory_policy.permitted_controls),
            "blacklist_max_age_ms": (policy.regulatory_policy.blacklist_max_age_ms),
            "time_anchor_max_response_ms": (policy.regulatory_policy.time_anchor_max_response_ms),
        });
        let mut selected = norito::json!({
            "scheme_id_hex": (hex::encode(policy.scheme_id)),
            "asset_digest_hex": (hex::encode(policy.asset_digest)),
            "regulatory_policy": (regulator),
            "challenge_lifetime_ms": (policy.challenge_lifetime_ms),
            "attestation_lease_lifetime_ms": (policy.attestation_lease_lifetime_ms),
        });
        let object = selected.as_object_mut().ok_or(Error("policy projection"))?;
        let platform = match (&app.identity, &policy.platform, apple_root_original) {
            (
                KagemushaWalletAppIdentityV1::Apple { app_id },
                KagemushaWalletEnrollmentPlatformV1::Apple {
                    attestation_root_sha256,
                },
                Some(root),
            ) => {
                if root.is_empty()
                    || root.len() > MAX_ROOT
                    || <[u8; 32]>::from(Sha256::digest(root)) != *attestation_root_sha256
                {
                    return Err(Error("selected root original"));
                }
                object.insert("root_base64".into(), Value::from(STANDARD.encode(root)));
                object.insert(
                    "root_sha256".into(),
                    Value::from(hex::encode(attestation_root_sha256)),
                );
                object.insert("app_id".into(), Value::from(app_id.clone()));
                "apple"
            }
            (
                KagemushaWalletAppIdentityV1::Android {
                    package_name,
                    minimum_package_version,
                    signer_set,
                },
                KagemushaWalletEnrollmentPlatformV1::Android {
                    root_set,
                    patch_floor_yyyymm,
                },
                None,
            ) => {
                let extra = norito::json!({
                    "package_name": (package_name.clone()),
                    "minimum_package_version": (*minimum_package_version),
                    "app_signer_sha256": (signer_set.iter().map(hex::encode).collect::<Vec<_>>()),
                    "roots": (root_set.iter().map(root_projection).collect::<Vec<_>>()),
                    "patch_floor_yyyymm": (*patch_floor_yyyymm),
                });
                for (name, value) in extra.as_object().ok_or(Error("policy projection"))? {
                    object.insert(name.clone(), value.clone());
                }
                "android"
            }
            (_, KagemushaWalletEnrollmentPlatformV1::Android { .. }, Some(_)) => {
                return Err(Error("Android root original"));
            }
            _ => return Err(Error("selected verifier platform")),
        };
        let original = encode(
            &norito::json!({
                "schema": (CONFIG_SCHEMA), "version": (1_u16), "platform": (platform),
                "app_policy_hex": (hex::encode(app.policy_digest().map_err(|_| Error("app policy"))?)),
                "enrollment_policy_hex": (hex::encode(policy.policy_digest().map_err(|_| Error("enrollment policy"))?)),
                "openssl_path": (runtime.openssl_path),
                "openssl_sha256": (hex::encode(runtime.openssl_sha256)),
                "store_directory": (runtime.store_directory), "policy": (selected),
            }),
            MAX_CONFIG,
        )?;
        Ok(Self {
            digest: Sha256::digest(&original).into(),
            original,
            app: app.clone(),
            policy: policy.clone(),
        })
    }

    /// Exact private configuration for retention and inherited FD20. Never regenerate on retry.
    pub fn original(&self) -> &[u8] {
        &self.original
    }

    /// SHA-256 of the exact retained configuration, not a proof of its admission.
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Observe the configured private worker's journal with a fresh exchange identity.
    /// # Errors
    /// Empty exchange identity or packet bounds; this establishes no runtime authority.
    pub fn journal(&self, exchange: [u8; 32]) -> Result<VerifierExchangeV1, Error> {
        VerifierExchangeV1::journal(self.digest, exchange)
    }

    /// Bind a pre-key preparation to this exact selected app, enrollment policy and configuration.
    /// # Errors
    /// Foreign selection, invalid challenge/account originals or challenge time.
    pub fn preparation(
        &self,
        dispatch: &PreKeyDispatchV1,
        challenge: KagemushaWalletEnrollmentChallengeV1,
        created_at_ms: u64,
    ) -> Result<VerifierPreparationV1, Error> {
        if dispatch.app != self.app || dispatch.policy != self.policy {
            return Err(Error("approved configuration binding"));
        }
        VerifierPreparationV1::from_selected(dispatch, challenge, created_at_ms, self.digest)
    }

    /// Bind account-signed E5 to a previously selected preparation under this exact configuration.
    /// # Errors
    /// Changed preparation/configuration/policies, invalid E5 or captured challenge time.
    pub fn request(
        &self,
        request: RequestV1,
        preparation: &VerifierPreparationV1,
        verification_time_ms: u64,
    ) -> Result<VerifierRequestV1, Error> {
        if preparation.configuration() != self.digest
            || request.body.app != self.app
            || request.body.policy != self.policy
        {
            return Err(Error("approved configuration binding"));
        }
        VerifierRequestV1::from_prepared(request, preparation, verification_time_ms)
    }
}
