//! NEW first-release E1 policy preimages. These unsigned identities select verifier inputs;
//! they never authenticate operator policy, delegate a signer or admit an enrollment.

use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

use super::{
    WalletResult, WalletVersionsV1, decode_frame_v1,
    digest::{KagemushaWalletDigestRoleV1 as Role, WalletTranscriptV1, kagemusha_wallet_digest_v1},
    encode_frame_v1,
    identity::{
        KAGEMUSHA_WALLET_CONTROL_ATTESTATION_LEASE_V1, KagemushaWalletEnrollmentChallengeV1,
        KagemushaWalletRegulatoryPolicyV1,
    },
    invalid_v1, overflow_v1, require_nonzero_v1, require_scheme_v1, require_version_v1,
};

mod template;
pub use template::KagemushaWalletEnrollmentPolicyTemplateV1;

#[cfg(test)]
#[path = "enrollment_policy_tests.rs"]
pub(super) mod enrollment_policy_tests;

/// Complete canonical Norito frame cap for either NEW policy; checked before decoding.
pub const KAGEMUSHA_WALLET_ENROLLMENT_POLICY_MAX_BYTES_V1: usize = 1024;
// NEW frames contain no u128. Keep zero type padding under the current native frame contract;
// these shipping-library assertions qualify layout only, not actual native/device operation.
const _: () = {
    assert!(
        norito::core::Header::SIZE.is_multiple_of(norito::core::archived_payload_align::<
            KagemushaWalletAppPolicyV1,
        >())
    );
    assert!(
        norito::core::Header::SIZE.is_multiple_of(norito::core::archived_payload_align::<
            KagemushaWalletEnrollmentPolicyV1,
        >())
    );
};

/// Current Android package and Apple App ID UTF-8 bound, without normalization.
pub const KAGEMUSHA_WALLET_APP_IDENTIFIER_MAX_BYTES_V1: usize = 255;
/// Most app-signing certificate digests one Android app policy admits.
pub const KAGEMUSHA_WALLET_ANDROID_SIGNERS_MAX_V1: usize = 4;
/// Most pinned roots one Android enrollment policy admits.
pub const KAGEMUSHA_WALLET_ANDROID_ROOTS_MAX_V1: usize = 8;
/// Longest Android vendor adapter identifier, in ASCII bytes.
pub const KAGEMUSHA_WALLET_ANDROID_ADAPTER_ID_MAX_BYTES_V1: usize = 16;

/// Exact app identity selected at initial enrollment. It stays historical across renewal.
// On 32-bit targets the inline Android signer set and minimum version outweigh the smaller
// String-only Apple identity. Keep the canonical fields and encoding unchanged.
#[cfg_attr(target_pointer_width = "32", allow(variant_size_differences))]
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletAppIdentityV1"
)]
pub enum KagemushaWalletAppIdentityV1 {
    /// Transcript tag 1: package, minimum package version and the released signer set.
    #[codec(index = 1)]
    Android {
        /// Dotted ASCII Android package name; at most 255 bytes.
        package_name: String,
        /// An attested `versionCode` at or above this passes; zero is representable.
        minimum_package_version: u64,
        /// 1–4 nonzero SHA-256 digests of app-signing certificate DER, strictly ascending.
        /// Every released distribution channel's signer and any rotation history is listed.
        signer_set: Vec<[u8; 32]>,
    },
    /// Transcript tag 2: exact UTF-8 App ID used by the production App Attest verifier.
    #[codec(index = 2)]
    Apple {
        /// Nonempty App ID of at most 255 UTF-8 bytes.
        app_id: String,
    },
}

/// NEW `H("app-policy", transcript)` preimage. No approval or signature is implied.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletAppPolicyV1"
)]
pub struct KagemushaWalletAppPolicyV1 {
    /// Exactly version 1.
    pub version: u16,
    /// Nonzero scheme identity.
    pub scheme_id: [u8; 32],
    /// Exactly one platform app identity; no disabled/development variant.
    pub identity: KagemushaWalletAppIdentityV1,
}

fn package_valid(value: &str) -> bool {
    value.len() <= KAGEMUSHA_WALLET_APP_IDENTIFIER_MAX_BYTES_V1
        && value.split('.').count() >= 2
        && value.split('.').all(|part| {
            let mut bytes = part.bytes();
            bytes
                .next()
                .is_some_and(|first| first.is_ascii_alphabetic() || first == b'_')
                && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        })
}

impl KagemushaWalletAppPolicyV1 {
    /// Validate version, scheme and the actual current verifier's exact app grammar.
    ///
    /// # Errors
    /// Rejects invalid identifiers, an empty, oversized, unsorted or zero signer set.
    pub fn validate(&self) -> WalletResult<()> {
        self.require_versions()?;
        require_nonzero_v1("app_policy.scheme_id", &self.scheme_id)?;
        match &self.identity {
            KagemushaWalletAppIdentityV1::Android {
                package_name,
                signer_set,
                ..
            } => {
                if !package_valid(package_name) {
                    return Err(invalid_v1("app_policy.package_name"));
                }
                if !(1..=KAGEMUSHA_WALLET_ANDROID_SIGNERS_MAX_V1).contains(&signer_set.len())
                    || !signer_set.windows(2).all(|pair| pair[0] < pair[1])
                {
                    return Err(invalid_v1("app_policy.signer_set"));
                }
                for signer in signer_set {
                    require_nonzero_v1("app_policy.signer_set", signer)?;
                }
            }
            KagemushaWalletAppIdentityV1::Apple { app_id } => {
                if app_id.is_empty() || app_id.len() > KAGEMUSHA_WALLET_APP_IDENTIFIER_MAX_BYTES_V1
                {
                    return Err(invalid_v1("app_policy.app_id"));
                }
            }
        }
        Ok(())
    }

    /// Exact NEW transcript; text is LE32 byte length followed by unchanged UTF-8 and the
    /// signer count is one byte. Android is `48 + package + 32 × signers` bytes (≤ 431).
    ///
    /// # Errors
    /// Rejects an invalid policy before writing any transcript.
    pub fn transcript(&self) -> WalletResult<Vec<u8>> {
        self.validate()?;
        let base = WalletTranscriptV1::with_capacity(431)
            .u16(self.version)
            .digest(&self.scheme_id);
        Ok(match &self.identity {
            KagemushaWalletAppIdentityV1::Android {
                package_name,
                minimum_package_version,
                signer_set,
            } => signer_set
                .iter()
                .fold(
                    base.u8(1)
                        .u32(u32::try_from(package_name.len()).expect("validated length"))
                        .bytes(package_name.as_bytes())
                        .u64(*minimum_package_version)
                        .u8(u8::try_from(signer_set.len()).expect("validated count")),
                    WalletTranscriptV1::digest,
                )
                .finish(),
            KagemushaWalletAppIdentityV1::Apple { app_id } => base
                .u8(2)
                .u32(u32::try_from(app_id.len()).expect("validated length"))
                .bytes(app_id.as_bytes())
                .finish(),
        })
    }

    /// NEW app-policy identity, distinct from every existing digest role.
    ///
    /// # Errors
    /// Rejects an invalid policy; this digest does not approve it.
    pub fn policy_digest(&self) -> WalletResult<[u8; 32]> {
        Ok(kagemusha_wallet_digest_v1(
            Role::AppPolicy,
            &self.transcript()?,
        ))
    }

    /// Encode a validated canonical Norito frame under the complete-frame cap.
    ///
    /// # Errors
    /// Rejects invalid fields or an oversized frame.
    pub fn encode_canonical(&self) -> WalletResult<Vec<u8>> {
        self.validate()?;
        encode_frame_v1(self, KAGEMUSHA_WALLET_ENROLLMENT_POLICY_MAX_BYTES_V1)
    }

    /// Decode under the byte cap, then version, expected scheme, and structural rules.
    ///
    /// # Errors
    /// Rejects noncanonical bytes, unsupported versions, wrong scheme or invalid fields.
    pub fn decode_canonical(bytes: &[u8], expected_scheme: &[u8; 32]) -> WalletResult<Self> {
        let value: Self = decode_frame_v1(bytes, KAGEMUSHA_WALLET_ENROLLMENT_POLICY_MAX_BYTES_V1)?;
        value.require_versions()?;
        require_scheme_v1("app_policy.scheme_id", &value.scheme_id, expected_scheme)?;
        value.validate()?;
        Ok(value)
    }
}

impl WalletVersionsV1 for KagemushaWalletAppPolicyV1 {
    fn require_versions(&self) -> WalletResult<()> {
        require_version_v1("app_policy.version", self.version)
    }
}

/// Family of one pinned Android attestation root. The family selects the reviewed issuer
/// adapter profile that validates a chain to that root; it is not a model or device list.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletAndroidRootFamilyV1"
)]
pub enum KagemushaWalletAndroidRootFamilyV1 {
    /// Transcript tag 1: Google's RSA hardware attestation root key (`google` profile).
    #[codec(index = 1)]
    GoogleRsa,
    /// Transcript tag 2: Google's ECDSA P-384 "Key Attestation CA1" root (`google` profile).
    #[codec(index = 2)]
    GoogleCa1,
    /// Transcript tag 3: a vendor's own root under the adapter profile this identifier names.
    /// The Model checks grammar only; the issuer refuses a policy naming an adapter it has not
    /// implemented and qualified, before any E1 challenge names the policy.
    #[codec(index = 3)]
    Vendor {
        /// 1–16 ASCII bytes matching `[a-z][a-z0-9-]*`, for example `huawei`.
        adapter_id: String,
    },
}

/// Revocation source named by one pinned root. The operator denylist is checked for every
/// root whatever its named source; for a Vendor root it is the only source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletRevocationSourceV1"
)]
pub enum KagemushaWalletRevocationSourceV1 {
    /// Transcript tag 1: Google's attestation status list; required by both Google families.
    #[codec(index = 1)]
    GoogleAttestationStatus,
    /// Transcript tag 2: the operator denylist only; required by Vendor roots.
    #[codec(index = 2)]
    OperatorDenylist,
}

/// One pinned Android attestation root, matched by the SHA-256 of its DER
/// `SubjectPublicKeyInfo` so every re-issued certificate of the same key matches.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletAndroidRootV1"
)]
pub struct KagemushaWalletAndroidRootV1 {
    /// Root family and, for Vendor, its adapter identifier.
    pub family: KagemushaWalletAndroidRootFamilyV1,
    /// Nonzero SHA-256 of the root certificate's DER `SubjectPublicKeyInfo`.
    pub spki_sha256: [u8; 32],
    /// Revocation source this root names.
    pub revocation_source: KagemushaWalletRevocationSourceV1,
}

fn adapter_id_valid(value: &str) -> bool {
    let mut bytes = value.bytes();
    value.len() <= KAGEMUSHA_WALLET_ANDROID_ADAPTER_ID_MAX_BYTES_V1
        && bytes.next().is_some_and(|first| first.is_ascii_lowercase())
        && bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

impl KagemushaWalletAndroidRootV1 {
    /// Validate one entry's grammar and family/source pairing.
    ///
    /// # Errors
    /// Rejects a zero pin, an invalid adapter identifier or a source the family forbids.
    pub fn validate(&self) -> WalletResult<()> {
        require_nonzero_v1("enrollment_policy.root.spki_sha256", &self.spki_sha256)?;
        let paired = match &self.family {
            KagemushaWalletAndroidRootFamilyV1::GoogleRsa
            | KagemushaWalletAndroidRootFamilyV1::GoogleCa1 => {
                self.revocation_source == KagemushaWalletRevocationSourceV1::GoogleAttestationStatus
            }
            KagemushaWalletAndroidRootFamilyV1::Vendor { adapter_id } => {
                if !adapter_id_valid(adapter_id) {
                    return Err(invalid_v1("enrollment_policy.root.adapter_id"));
                }
                self.revocation_source == KagemushaWalletRevocationSourceV1::OperatorDenylist
            }
        };
        if !paired {
            return Err(invalid_v1("enrollment_policy.root.revocation_source"));
        }
        Ok(())
    }

    fn write(&self, transcript: WalletTranscriptV1) -> WalletTranscriptV1 {
        let transcript = match &self.family {
            KagemushaWalletAndroidRootFamilyV1::GoogleRsa => transcript.u8(1),
            KagemushaWalletAndroidRootFamilyV1::GoogleCa1 => transcript.u8(2),
            KagemushaWalletAndroidRootFamilyV1::Vendor { adapter_id } => transcript
                .u8(3)
                .u32(u32::try_from(adapter_id.len()).expect("validated length"))
                .bytes(adapter_id.as_bytes()),
        };
        transcript
            .digest(&self.spki_sha256)
            .u8(match self.revocation_source {
                KagemushaWalletRevocationSourceV1::GoogleAttestationStatus => 1,
                KagemushaWalletRevocationSourceV1::OperatorDenylist => 2,
            })
    }
}

/// Mandatory platform verification inputs. Root DER originals remain issuer inputs: Android
/// chains carry their own root, matched by SPKI; the Apple root DER is selected separately.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletEnrollmentPlatformV1"
)]
pub enum KagemushaWalletEnrollmentPlatformV1 {
    /// Transcript tag 1: a `KeyMint` chain to one pinned root, under that root's adapter
    /// profile, with mandatory revocation. No hardware selector or vendor online verdict.
    #[codec(index = 1)]
    Android {
        /// 1–8 pinned roots, strictly ascending by `spki_sha256`.
        root_set: Vec<KagemushaWalletAndroidRootV1>,
        /// Exact YYYYMM; meeting it sets the patch-policy fact, failing it never rejects E1.
        patch_floor_yyyymm: u32,
    },
    /// Transcript tag 2: production App Attest plus a durable fresh key-binding assertion.
    #[codec(index = 2)]
    Apple {
        /// Nonzero SHA-256 pin of the genuine selected Apple root DER.
        attestation_root_sha256: [u8; 32],
    },
}

impl KagemushaWalletEnrollmentPlatformV1 {
    /// Validate self-contained platform inputs, without approving any root or adapter.
    ///
    /// # Errors
    /// Rejects an empty, oversized, unsorted or invalid root set, an invalid patch floor or a
    /// zero Apple root pin.
    pub fn validate(&self) -> WalletResult<()> {
        match self {
            Self::Android {
                root_set,
                patch_floor_yyyymm,
            } => {
                if !(1..=KAGEMUSHA_WALLET_ANDROID_ROOTS_MAX_V1).contains(&root_set.len())
                    || !root_set
                        .windows(2)
                        .all(|pair| pair[0].spki_sha256 < pair[1].spki_sha256)
                {
                    return Err(invalid_v1("enrollment_policy.root_set"));
                }
                for root in root_set {
                    root.validate()?;
                }
                let year = patch_floor_yyyymm / 100;
                let month = patch_floor_yyyymm % 100;
                if !(1900..=9999).contains(&year) || !(1..=12).contains(&month) {
                    return Err(invalid_v1("enrollment_policy.patch_floor_yyyymm"));
                }
                Ok(())
            }
            Self::Apple {
                attestation_root_sha256,
            } => require_nonzero_v1(
                "enrollment_policy.attestation_root_sha256",
                attestation_root_sha256,
            ),
        }
    }
}

/// NEW `H("enrollment-policy", transcript)` preimage; not a signer or policy approval.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletEnrollmentPolicyV1"
)]
pub struct KagemushaWalletEnrollmentPolicyV1 {
    /// Exactly version 1.
    pub version: u16,
    /// Nonzero scheme identity.
    pub scheme_id: [u8; 32],
    /// Nonzero asset scope; regulatory and lease decisions cannot cross asset scopes.
    pub asset_digest: [u8; 32],
    /// Exact NEW app-policy digest.
    pub app_policy: [u8; 32],
    /// Exactly one platform verifier input set.
    pub platform: KagemushaWalletEnrollmentPlatformV1,
    /// Existing inline credential regulatory policy, unchanged by these NEW identities.
    pub regulatory_policy: KagemushaWalletRegulatoryPolicyV1,
    /// Positive server-owned single-use E1 challenge lifetime. No implicit value.
    pub challenge_lifetime_ms: u64,
    /// Zero iff the regulator does not permit a lease; otherwise positive.
    pub attestation_lease_lifetime_ms: u64,
}

impl KagemushaWalletEnrollmentPolicyV1 {
    /// Validate all self-contained fields; policy selection still needs genuine owner approval.
    ///
    /// # Errors
    /// Rejects zero bindings, invalid platform inputs, inconsistent regulators/lease.
    pub fn validate(&self) -> WalletResult<()> {
        self.require_versions()?;
        require_nonzero_v1("enrollment_policy.asset_digest", &self.asset_digest)?;
        self.template().validate()
    }

    /// Extract asset-independent policy DATA; this does not authenticate template approval.
    #[must_use]
    pub fn template(&self) -> KagemushaWalletEnrollmentPolicyTemplateV1 {
        KagemushaWalletEnrollmentPolicyTemplateV1 {
            version: self.version,
            scheme_id: self.scheme_id,
            app_policy: self.app_policy,
            platform: self.platform.clone(),
            regulatory_policy: self.regulatory_policy,
            challenge_lifetime_ms: self.challenge_lifetime_ms,
            attestation_lease_lifetime_ms: self.attestation_lease_lifetime_ms,
        }
    }

    /// Validate the exact app/scheme/platform pairing, without authenticating its approval.
    ///
    /// # Errors
    /// Rejects invalid policies or app/scheme/platform substitutions.
    pub fn validate_for_app(&self, app: &KagemushaWalletAppPolicyV1) -> WalletResult<()> {
        self.validate()?;
        self.template().validate_for_app(app)
    }

    /// Exact NEW transcript; regulator bytes and durations follow the selected platform.
    /// Android is `140 + Σ root entries` bytes (a Google entry 34, a Vendor entry
    /// `38 + adapter_id`); Apple is exactly 167.
    ///
    /// # Errors
    /// Rejects invalid fields before writing the transcript.
    pub fn transcript(&self) -> WalletResult<Vec<u8>> {
        self.validate()?;
        let base = WalletTranscriptV1::with_capacity(572)
            .u16(self.version)
            .digest(&self.scheme_id)
            .digest(&self.asset_digest)
            .digest(&self.app_policy);
        let selected = match &self.platform {
            KagemushaWalletEnrollmentPlatformV1::Android {
                root_set,
                patch_floor_yyyymm,
            } => root_set
                .iter()
                .fold(
                    base.u8(1)
                        .u8(u8::try_from(root_set.len()).expect("validated count")),
                    |transcript, root| root.write(transcript),
                )
                .u32(*patch_floor_yyyymm),
            KagemushaWalletEnrollmentPlatformV1::Apple {
                attestation_root_sha256,
            } => base.u8(2).digest(attestation_root_sha256),
        };
        Ok(selected
            .bytes(&self.regulatory_policy.transcript())
            .u64(self.challenge_lifetime_ms)
            .u64(self.attestation_lease_lifetime_ms)
            .finish())
    }

    /// NEW policy identity; an existing opaque digest has no implied mapping to it.
    ///
    /// # Errors
    /// Rejects invalid fields; this digest grants no authority.
    pub fn policy_digest(&self) -> WalletResult<[u8; 32]> {
        Ok(kagemusha_wallet_digest_v1(
            Role::EnrollmentPolicy,
            &self.transcript()?,
        ))
    }

    /// Check the exact policy identities and selected scheme/asset in an E1 challenge.
    ///
    /// # Errors
    /// Rejects any substitution. Account authorization, freshness and use require the issuer.
    pub fn verify_challenge(
        &self,
        app: &KagemushaWalletAppPolicyV1,
        challenge: &KagemushaWalletEnrollmentChallengeV1,
    ) -> WalletResult<()> {
        self.validate_for_app(app)?;
        challenge.validate()?;
        require_scheme_v1(
            "enrollment_challenge.scheme_id",
            &challenge.scheme_id,
            &self.scheme_id,
        )?;
        if challenge.asset_digest != self.asset_digest
            || challenge.app_policy != self.app_policy
            || challenge.enrollment_policy != self.policy_digest()?
        {
            return Err(invalid_v1("enrollment_challenge.policy"));
        }
        Ok(())
    }

    /// Enforce NEW `[created, created + lifetime)` using genuine server-owned timestamps.
    ///
    /// # Errors
    /// Rejects absent/future creation, expiry and overflow. This does not consume the challenge.
    pub fn require_live_challenge(&self, created_at_ms: u64, now_ms: u64) -> WalletResult<()> {
        self.validate()?;
        let expires = created_at_ms
            .checked_add(self.challenge_lifetime_ms)
            .ok_or_else(|| overflow_v1("enrollment_policy.challenge_expiry"))?;
        if created_at_ms == 0 || now_ms < created_at_ms || now_ms >= expires {
            return Err(invalid_v1("enrollment_policy.challenge_time"));
        }
        Ok(())
    }

    /// Produce the exact NEW issuance lease value from the permitted duration.
    ///
    /// # Errors
    /// Rejects absent issuance or overflow. Only the Enrollment-role owner may sign the result.
    pub fn lease_expires_at(&self, issued_at_ms: u64) -> WalletResult<u64> {
        self.validate()?;
        if issued_at_ms == 0 {
            return Err(invalid_v1("enrollment_policy.issued_at_ms"));
        }
        if self.attestation_lease_lifetime_ms == 0 {
            return Ok(0);
        }
        issued_at_ms
            .checked_add(self.attestation_lease_lifetime_ms)
            .ok_or_else(|| overflow_v1("enrollment_policy.lease_expiry"))
    }

    /// Encode a validated canonical Norito frame under its complete-frame cap.
    ///
    /// # Errors
    /// Rejects invalid fields or an oversized frame.
    pub fn encode_canonical(&self) -> WalletResult<Vec<u8>> {
        self.validate()?;
        encode_frame_v1(self, KAGEMUSHA_WALLET_ENROLLMENT_POLICY_MAX_BYTES_V1)
    }

    /// Decode under the cap, then version, expected scheme and structural checks.
    ///
    /// # Errors
    /// Rejects noncanonical bytes, unsupported versions, wrong scheme or invalid fields.
    pub fn decode_canonical(bytes: &[u8], expected_scheme: &[u8; 32]) -> WalletResult<Self> {
        let value: Self = decode_frame_v1(bytes, KAGEMUSHA_WALLET_ENROLLMENT_POLICY_MAX_BYTES_V1)?;
        value.require_versions()?;
        require_scheme_v1(
            "enrollment_policy.scheme_id",
            &value.scheme_id,
            expected_scheme,
        )?;
        value.validate()?;
        Ok(value)
    }
}

impl WalletVersionsV1 for KagemushaWalletEnrollmentPolicyV1 {
    fn require_versions(&self) -> WalletResult<()> {
        require_version_v1("enrollment_policy.version", self.version)
    }
}
