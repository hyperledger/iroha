//! Scheme, signer, enrollment, credential, renewal and artifact identities (§§2.1–2.5).
//!
//! These values bind a wallet incarnation to one scheme, asset incarnation, account and
//! hardware-backed payment key. A signer certificate is signed directly by the scheme root
//! (fixed depth one, §3.3); no validity period or revocation lookup is evaluated offline.

use iroha_crypto::Hash;
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

use super::{
    KAGEMUSHA_WALLET_ARTIFACT_MANIFEST_MAX_BYTES_V1, KAGEMUSHA_WALLET_CERTIFICATE_MAX_BYTES_V1,
    KAGEMUSHA_WALLET_CERTIFICATE_SET_MAX_V1, KAGEMUSHA_WALLET_CREDENTIAL_MAX_BYTES_V1,
    KAGEMUSHA_WALLET_RENEWAL_REQUEST_MAX_BYTES_V1, KAGEMUSHA_WALLET_SCHEME_MAX_BYTES_V1,
    KAGEMUSHA_WALLET_VERSION_V1, KagemushaWalletValidationErrorV1, WalletResult, WalletVersionsV1,
    decode_frame_v1,
    digest::{
        KagemushaWalletDigestRoleV1 as Role, KagemushaWalletSignerOutputV1,
        KagemushaWalletSigningDomainV1 as Domain, WalletTranscriptV1, kagemusha_wallet_digest_v1,
        kagemusha_wallet_freeze_signature_v1, kagemusha_wallet_signed_object_digest_v1,
        kagemusha_wallet_signing_message_v1, kagemusha_wallet_verify_signature_v1,
    },
    encode_frame_v1, invalid_v1,
    keys::{KagemushaDevicePublicKeyV1, KagemushaDeviceSignatureV1},
    overflow_v1, require_nonzero_v1, require_scheme_v1, require_version_v1,
};
use crate::{account::AccountId, asset::AssetDefinitionId, nexus::AxtAssetIncarnationV1};

#[cfg(test)]
#[path = "identity_tests.rs"]
pub(super) mod identity_tests;

/// ASCII name of the single V1 provider contract: the §4 Advance journal-and-marker contract
/// and its receipt format.
pub const KAGEMUSHA_WALLET_PROVIDER_CONTRACT_NAME_V1: &str = "kagemusha-advance-journal-marker-v1";
/// Exact `provider-contract` transcript bytes: `LE16 version || name zero-padded to 64`.
pub const KAGEMUSHA_WALLET_PROVIDER_CONTRACT_TRANSCRIPT_BYTES_V1: usize =
    2 + PROVIDER_CONTRACT_NAME_FIELD_BYTES;
/// Exact `relation` transcript bytes.
pub const KAGEMUSHA_WALLET_RELATION_TRANSCRIPT_BYTES_V1: usize = 2 + 5 * 32;
/// Exact `scheme` transcript bytes.
pub const KAGEMUSHA_WALLET_SCHEME_TRANSCRIPT_BYTES_V1: usize = 2 + 32 + KEY_BYTES + 32 + 32;
/// Exact `asset-scope` transcript bytes.
pub const KAGEMUSHA_WALLET_ASSET_SCOPE_TRANSCRIPT_BYTES_V1: usize = 2 + 16 + 32 + 4;
/// Maximum authoritative asset scale.
pub const KAGEMUSHA_WALLET_ASSET_SCALE_MAX_V1: u32 = 28;
/// Exact `certificate-body` transcript bytes.
pub const KAGEMUSHA_WALLET_CERTIFICATE_BODY_TRANSCRIPT_BYTES_V1: usize = 2 + 32 + 1 + KEY_BYTES + 8;
/// Exact `enrollment-challenge` transcript bytes.
pub const KAGEMUSHA_WALLET_ENROLLMENT_CHALLENGE_TRANSCRIPT_BYTES_V1: usize = 2 + 6 * 32;
/// Exact `enrollment-id` and `enrollment-key-binding` transcript bytes:
/// `challenge_digest || payment_key`.
pub const KAGEMUSHA_WALLET_ENROLLMENT_KEY_TRANSCRIPT_BYTES_V1: usize = 32 + KEY_BYTES;
/// Exact `wallet-id` transcript bytes.
pub const KAGEMUSHA_WALLET_ID_TRANSCRIPT_BYTES_V1: usize = 32 + 32 + KEY_BYTES + 32;
/// Exact inline transcript bytes of one evidence record.
pub const KAGEMUSHA_WALLET_EVIDENCE_TRANSCRIPT_BYTES_V1: usize = 32 + 8 + 4 * 4;
/// Exact inline transcript bytes of one regulatory policy.
pub const KAGEMUSHA_WALLET_REGULATORY_POLICY_TRANSCRIPT_BYTES_V1: usize = 4 + 8 + 8;
/// Exact `credential-body` transcript bytes.
pub const KAGEMUSHA_WALLET_CREDENTIAL_BODY_TRANSCRIPT_BYTES_V1: usize = 2
    + 4 * 32
    + KEY_BYTES
    + 32
    + 1
    + 2 * KAGEMUSHA_WALLET_EVIDENCE_TRANSCRIPT_BYTES_V1
    + 32
    + KAGEMUSHA_WALLET_REGULATORY_POLICY_TRANSCRIPT_BYTES_V1
    + 32
    + 8
    + 4
    + 8
    + 32;
/// Exact `renewal-challenge` and `renewal-assertion` transcript bytes.
pub const KAGEMUSHA_WALLET_RENEWAL_CHALLENGE_TRANSCRIPT_BYTES_V1: usize = 2 + 4 * 32;
/// Exact `renewal-key-binding` transcript bytes.
pub const KAGEMUSHA_WALLET_RENEWAL_KEY_BINDING_TRANSCRIPT_BYTES_V1: usize = 2 + 3 * 32 + KEY_BYTES;
/// Exact `artifact-manifest-body` transcript bytes.
pub const KAGEMUSHA_WALLET_ARTIFACT_MANIFEST_BODY_TRANSCRIPT_BYTES_V1: usize = 2 + 9 * 32;
/// Minimum certificates in an Android renewal attestation chain (leaf and one issuer).
pub const KAGEMUSHA_WALLET_RENEWAL_ANDROID_CHAIN_MIN_V1: usize = 2;
/// Maximum certificates in an Android renewal attestation chain.
pub const KAGEMUSHA_WALLET_RENEWAL_ANDROID_CHAIN_MAX_V1: usize = 8;
/// Maximum DER bytes of one Android attestation certificate.
pub const KAGEMUSHA_WALLET_DER_CERTIFICATE_MAX_BYTES_V1: usize = 16_384;
/// Maximum total DER bytes of one Android renewal attestation chain (design §2.5: at most
/// 65,536 original evidence bytes).
///
/// It keeps every request that validates within
/// [`KAGEMUSHA_WALLET_RENEWAL_REQUEST_MAX_BYTES_V1`]: eight certificates of
/// [`KAGEMUSHA_WALLET_DER_CERTIFICATE_MAX_BYTES_V1`] each would not fit.
pub const KAGEMUSHA_WALLET_RENEWAL_ANDROID_CHAIN_MAX_BYTES_V1: usize = 65_536;
/// Maximum original bytes of one App Attest renewal assertion.
pub const KAGEMUSHA_WALLET_RENEWAL_APPLE_ASSERTION_MAX_BYTES_V1: usize = 4_096;

/// The attested key is hardware backed.
pub const KAGEMUSHA_WALLET_FACT_HARDWARE_BACKED_KEY_V1: u32 = 1 << 0;
/// The attested key lives in `StrongBox`.
pub const KAGEMUSHA_WALLET_FACT_STRONGBOX_V1: u32 = 1 << 1;
/// The attestation records a locked bootloader.
pub const KAGEMUSHA_WALLET_FACT_BOOTLOADER_LOCKED_V1: u32 = 1 << 2;
/// The attestation records verified vendor boot.
pub const KAGEMUSHA_WALLET_FACT_VERIFIED_BOOT_V1: u32 = 1 << 3;
/// The recorded patch levels met the enrollment patch policy.
pub const KAGEMUSHA_WALLET_FACT_PATCH_POLICY_MET_V1: u32 = 1 << 4;
/// The attestation records the expected app signing identity.
pub const KAGEMUSHA_WALLET_FACT_APP_SIGNING_IDENTITY_V1: u32 = 1 << 5;
/// App Attest chained to Apple's App Attestation root for this App ID.
pub const KAGEMUSHA_WALLET_FACT_APP_ATTEST_GENUINE_DEVICE_V1: u32 = 1 << 6;
/// The App Attest assertion bound the payment key to the enrollment challenge.
pub const KAGEMUSHA_WALLET_FACT_APP_ATTEST_KEY_BINDING_V1: u32 = 1 << 7;
/// The App Attest environment is production.
pub const KAGEMUSHA_WALLET_FACT_APP_ATTEST_PRODUCTION_V1: u32 = 1 << 8;
/// A Play Integrity enrollment-time signal was recorded.
pub const KAGEMUSHA_WALLET_FACT_PLAY_INTEGRITY_SIGNAL_V1: u32 = 1 << 9;
/// No chain certificate was on the attestation revocation status list at the check.
pub const KAGEMUSHA_WALLET_FACT_REVOCATION_LIST_CLEAR_V1: u32 = 1 << 10;
/// Local root/jailbreak checks were negative at the check.
pub const KAGEMUSHA_WALLET_FACT_LOCAL_COMPROMISE_CHECKS_CLEAR_V1: u32 = 1 << 11;
/// Every defined fact bit; bits 12..=31 are zero.
pub const KAGEMUSHA_WALLET_FACTS_DEFINED_MASK_V1: u32 = (1 << 12) - 1;
/// Fact bits an Android evidence record never carries (App Attest facts).
pub const KAGEMUSHA_WALLET_ANDROID_FORBIDDEN_FACTS_V1: u32 =
    KAGEMUSHA_WALLET_FACT_APP_ATTEST_GENUINE_DEVICE_V1
        | KAGEMUSHA_WALLET_FACT_APP_ATTEST_KEY_BINDING_V1
        | KAGEMUSHA_WALLET_FACT_APP_ATTEST_PRODUCTION_V1;
/// Fact bits an Apple evidence record never carries: Android key/boot/patch facts, Play
/// Integrity, and a hardware-backed claim about the separately generated payment key.
pub const KAGEMUSHA_WALLET_APPLE_FORBIDDEN_FACTS_V1: u32 =
    KAGEMUSHA_WALLET_FACT_HARDWARE_BACKED_KEY_V1
        | KAGEMUSHA_WALLET_FACT_STRONGBOX_V1
        | KAGEMUSHA_WALLET_FACT_BOOTLOADER_LOCKED_V1
        | KAGEMUSHA_WALLET_FACT_VERIFIED_BOOT_V1
        | KAGEMUSHA_WALLET_FACT_PATCH_POLICY_MET_V1
        | KAGEMUSHA_WALLET_FACT_APP_SIGNING_IDENTITY_V1
        | KAGEMUSHA_WALLET_FACT_PLAY_INTEGRITY_SIGNAL_V1;
/// Facts every Android enrollment evidence record must carry (design C5).
pub const KAGEMUSHA_WALLET_ANDROID_REQUIRED_FACTS_V1: u32 =
    KAGEMUSHA_WALLET_FACT_HARDWARE_BACKED_KEY_V1
        | KAGEMUSHA_WALLET_FACT_BOOTLOADER_LOCKED_V1
        | KAGEMUSHA_WALLET_FACT_VERIFIED_BOOT_V1
        | KAGEMUSHA_WALLET_FACT_APP_SIGNING_IDENTITY_V1;
/// Facts every Apple enrollment evidence record must carry (design C5).
pub const KAGEMUSHA_WALLET_APPLE_REQUIRED_FACTS_V1: u32 =
    KAGEMUSHA_WALLET_FACT_APP_ATTEST_GENUINE_DEVICE_V1
        | KAGEMUSHA_WALLET_FACT_APP_ATTEST_KEY_BINDING_V1;

/// Recipient blacklist control (§7).
pub const KAGEMUSHA_WALLET_CONTROL_BLACKLIST_V1: u32 = 1 << 0;
/// Daily/monthly sending quota control (§7).
pub const KAGEMUSHA_WALLET_CONTROL_QUOTAS_V1: u32 = 1 << 1;
/// Attestation lease control (§7).
pub const KAGEMUSHA_WALLET_CONTROL_ATTESTATION_LEASE_V1: u32 = 1 << 2;
/// Every defined regulatory control bit.
pub const KAGEMUSHA_WALLET_CONTROLS_DEFINED_MASK_V1: u32 = KAGEMUSHA_WALLET_CONTROL_BLACKLIST_V1
    | KAGEMUSHA_WALLET_CONTROL_QUOTAS_V1
    | KAGEMUSHA_WALLET_CONTROL_ATTESTATION_LEASE_V1;

const KEY_BYTES: usize = 65;
const PROVIDER_CONTRACT_NAME_FIELD_BYTES: usize = 64;

// ---------------------------------------------------------------------------------------
// Scheme, relation, provider contract, asset and account (§2.1)
// ---------------------------------------------------------------------------------------

/// Exact `provider-contract` transcript: `LE16 1 || name zero-padded to 64 bytes`.
#[must_use]
pub fn kagemusha_wallet_provider_contract_transcript_v1() -> Vec<u8> {
    let name = KAGEMUSHA_WALLET_PROVIDER_CONTRACT_NAME_V1.as_bytes();
    let mut field = [0_u8; PROVIDER_CONTRACT_NAME_FIELD_BYTES];
    field[..name.len()].copy_from_slice(name);
    WalletTranscriptV1::with_capacity(KAGEMUSHA_WALLET_PROVIDER_CONTRACT_TRANSCRIPT_BYTES_V1)
        .u16(KAGEMUSHA_WALLET_VERSION_V1)
        .bytes(&field)
        .finish()
}

/// Identity of the single V1 provider contract, fixed for a scheme's lifetime (§2.2).
#[must_use]
pub fn kagemusha_wallet_provider_contract_v1() -> [u8; 32] {
    kagemusha_wallet_digest_v1(
        Role::ProviderContract,
        &kagemusha_wallet_provider_contract_transcript_v1(),
    )
}

/// Exact `relation` transcript over the runtime bindings of the signed artifact manifest.
#[allow(
    clippy::similar_names,
    reason = "the Eq and Ep protocol digests are the design's names for the paired curves"
)]
#[must_use]
pub fn kagemusha_wallet_relation_transcript_v1(
    eq_protocol_digest: &[u8; 32],
    ep_protocol_digest: &[u8; 32],
    native_profile_digest: &[u8; 32],
    verifying_key_set_digest: &[u8; 32],
    artifact_inventory_digest: &[u8; 32],
) -> Vec<u8> {
    WalletTranscriptV1::with_capacity(KAGEMUSHA_WALLET_RELATION_TRANSCRIPT_BYTES_V1)
        .u16(KAGEMUSHA_WALLET_VERSION_V1)
        .digest(eq_protocol_digest)
        .digest(ep_protocol_digest)
        .digest(native_profile_digest)
        .digest(verifying_key_set_digest)
        .digest(artifact_inventory_digest)
        .finish()
}

/// Frozen relation identity of a scheme (§§2.1, 3.3).
///
/// `verifying_key_set_digest` and `artifact_inventory_digest` are defined by the G3
/// artifact set.
// TODO(G3): bind the concrete verifying-key-set and inventory preimages of the artifact set.
#[allow(
    clippy::similar_names,
    reason = "the Eq and Ep protocol digests are the design's names for the paired curves"
)]
#[must_use]
pub fn kagemusha_wallet_relation_id_v1(
    eq_protocol_digest: &[u8; 32],
    ep_protocol_digest: &[u8; 32],
    native_profile_digest: &[u8; 32],
    verifying_key_set_digest: &[u8; 32],
    artifact_inventory_digest: &[u8; 32],
) -> [u8; 32] {
    kagemusha_wallet_digest_v1(
        Role::Relation,
        &kagemusha_wallet_relation_transcript_v1(
            eq_protocol_digest,
            ep_protocol_digest,
            native_profile_digest,
            verifying_key_set_digest,
            artifact_inventory_digest,
        ),
    )
}

/// Validate a raw genesis `NetworkId`: it carries the Iroha hash marker and is not the
/// marked all-zero sentinel.
fn validate_network_id_v1(network_id: &[u8; 32]) -> WalletResult<()> {
    let marked = Hash::prehashed(*network_id);
    let zero = Hash::prehashed([0; 32]);
    if marked.as_ref() != network_id || zero.as_ref() == network_id {
        return Err(invalid_v1("network_id"));
    }
    Ok(())
}

/// One offline payment scheme: network, scheme root, frozen relation and provider contract.
///
/// `relation_id` and `provider_contract` are fixed for the scheme's lifetime; a breaking
/// relation is a different scheme (§3.3). The root key signs signer certificates only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletSchemeV1")]
pub struct KagemushaWalletSchemeV1 {
    /// Wire version; exactly [`KAGEMUSHA_WALLET_VERSION_V1`].
    pub version: u16,
    /// Raw 32-byte genesis `NetworkId`.
    pub network_id: [u8; 32],
    /// Preinstalled scheme root key.
    pub scheme_root_key: KagemushaDevicePublicKeyV1,
    /// Frozen relation identity ([`kagemusha_wallet_relation_id_v1`]).
    pub relation_id: [u8; 32],
    /// Provider contract identity ([`kagemusha_wallet_provider_contract_v1`]).
    pub provider_contract: [u8; 32],
}

impl KagemushaWalletSchemeV1 {
    /// Exact `scheme` transcript.
    #[must_use]
    pub fn transcript(&self) -> Vec<u8> {
        WalletTranscriptV1::with_capacity(KAGEMUSHA_WALLET_SCHEME_TRANSCRIPT_BYTES_V1)
            .u16(self.version)
            .digest(&self.network_id)
            .key(&self.scheme_root_key)
            .digest(&self.relation_id)
            .digest(&self.provider_contract)
            .finish()
    }

    /// Scheme identity `H("scheme", transcript)`.
    #[must_use]
    pub fn scheme_id(&self) -> [u8; 32] {
        kagemusha_wallet_digest_v1(Role::Scheme, &self.transcript())
    }

    /// Validate the scheme's fields.
    ///
    /// # Errors
    ///
    /// Rejects another version, a network without the hash marker, a zero relation, or a
    /// provider contract other than the single V1 contract.
    pub fn validate(&self) -> WalletResult<()> {
        require_version_v1("scheme.version", self.version)?;
        validate_network_id_v1(&self.network_id)?;
        self.scheme_root_key.validate()?;
        require_nonzero_v1("scheme.relation_id", &self.relation_id)?;
        if self.provider_contract != kagemusha_wallet_provider_contract_v1() {
            return Err(invalid_v1("scheme.provider_contract"));
        }
        Ok(())
    }

    /// Validate and encode the bounded canonical frame.
    ///
    /// # Errors
    ///
    /// Rejects an invalid scheme or an oversized frame.
    pub fn to_canonical_bytes(&self) -> WalletResult<Vec<u8>> {
        self.validate()?;
        encode_frame_v1(self, KAGEMUSHA_WALLET_SCHEME_MAX_BYTES_V1)
    }

    /// Decode one canonical scheme frame whose identity must equal `expected_scheme_id`.
    ///
    /// # Errors
    ///
    /// Rejects, in order, an oversized frame, a noncanonical frame, another version, another
    /// scheme identity, and invalid fields.
    pub fn decode_canonical(bytes: &[u8], expected_scheme_id: &[u8; 32]) -> WalletResult<Self> {
        let scheme: Self = decode_frame_v1(bytes, KAGEMUSHA_WALLET_SCHEME_MAX_BYTES_V1)?;
        scheme.require_versions()?;
        require_scheme_v1("scheme", &scheme.scheme_id(), expected_scheme_id)?;
        scheme.validate()?;
        Ok(scheme)
    }
}

/// Asset scope of a wallet: asset, exact asset incarnation and authoritative scale (§2.1).
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletAssetScopeV1"
)]
pub struct KagemushaWalletAssetScopeV1 {
    /// Wire version; exactly [`KAGEMUSHA_WALLET_VERSION_V1`].
    pub version: u16,
    /// Canonical asset definition.
    pub asset: AssetDefinitionId,
    /// Raw 32 bytes of the exact `AxtAssetIncarnationV1`.
    pub asset_incarnation: [u8; 32],
    /// Authoritative asset scale, at most [`KAGEMUSHA_WALLET_ASSET_SCALE_MAX_V1`].
    pub scale: u32,
}

impl KagemushaWalletAssetScopeV1 {
    /// Construct and validate a V1 asset scope.
    ///
    /// # Errors
    ///
    /// Rejects an invalid asset identifier or a scale above the maximum.
    pub fn new(
        asset: AssetDefinitionId,
        asset_incarnation: &AxtAssetIncarnationV1,
        scale: u32,
    ) -> WalletResult<Self> {
        let scope = Self {
            version: KAGEMUSHA_WALLET_VERSION_V1,
            asset,
            asset_incarnation: *asset_incarnation.as_bytes(),
            scale,
        };
        scope.validate()?;
        Ok(scope)
    }

    /// Exact `asset-scope` transcript.
    #[must_use]
    pub fn transcript(&self) -> Vec<u8> {
        WalletTranscriptV1::with_capacity(KAGEMUSHA_WALLET_ASSET_SCOPE_TRANSCRIPT_BYTES_V1)
            .u16(self.version)
            .bytes(&self.asset.aid_bytes())
            .digest(&self.asset_incarnation)
            .u32(self.scale)
            .finish()
    }

    /// Asset digest `H("asset-scope", transcript)`.
    #[must_use]
    pub fn asset_digest(&self) -> [u8; 32] {
        kagemusha_wallet_digest_v1(Role::AssetScope, &self.transcript())
    }

    /// Validate the scope's fields.
    ///
    /// # Errors
    ///
    /// Rejects another version, a non-`UUIDv4` asset, an invalid incarnation, or a scale
    /// above [`KAGEMUSHA_WALLET_ASSET_SCALE_MAX_V1`].
    pub fn validate(&self) -> WalletResult<()> {
        require_version_v1("asset_scope.version", self.version)?;
        AssetDefinitionId::from_uuid_bytes(self.asset.aid_bytes())
            .map_err(|_| invalid_v1("asset_scope.asset"))?;
        AxtAssetIncarnationV1::try_from_bytes(self.asset_incarnation)?;
        if self.scale > KAGEMUSHA_WALLET_ASSET_SCALE_MAX_V1 {
            return Err(invalid_v1("asset_scope.scale"));
        }
        Ok(())
    }
}

/// Account digest `H("account", canonical AccountId frame)`.
///
/// # Errors
///
/// Returns a codec error when the account cannot be encoded.
pub fn kagemusha_wallet_account_digest_v1(account: &AccountId) -> WalletResult<[u8; 32]> {
    let frame = norito::encode_canonical(account)?;
    Ok(kagemusha_wallet_digest_v1(Role::Account, &frame))
}

// ---------------------------------------------------------------------------------------
// Signer certificates and certificate sets (§§2.3, 3.3)
// ---------------------------------------------------------------------------------------

/// Separated signing role delegated by the scheme root (§2.3).
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Decode,
    Encode,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletSignerRoleV1"
)]
pub enum KagemushaWalletSignerRoleV1 {
    /// Issues wallet credentials.
    #[codec(index = 1)]
    Enrollment,
    /// Signs load vouchers after ledger finality.
    #[codec(index = 2)]
    LoadAuthorization,
    /// Signs scheme policies, fee schedules, blacklists, quota shares and charge quotes.
    #[codec(index = 3)]
    RegulatoryPolicy,
    /// Signs time anchors.
    #[codec(index = 4)]
    TimeAnchor,
    /// Signs artifact manifests.
    #[codec(index = 5)]
    Artifact,
}

impl KagemushaWalletSignerRoleV1 {
    /// Every signer role, in tag order.
    pub const ALL: [Self; 5] = [
        Self::Enrollment,
        Self::LoadAuthorization,
        Self::RegulatoryPolicy,
        Self::TimeAnchor,
        Self::Artifact,
    ];

    /// Transcript tag; equal to the Norito wire tag.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Enrollment => 1,
            Self::LoadAuthorization => 2,
            Self::RegulatoryPolicy => 3,
            Self::TimeAnchor => 4,
            Self::Artifact => 5,
        }
    }
}

/// Body of a signer certificate, signed by the scheme root under `kgwcert1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletSignerCertificateBodyV1"
)]
pub struct KagemushaWalletSignerCertificateBodyV1 {
    /// Wire version; exactly [`KAGEMUSHA_WALLET_VERSION_V1`].
    pub version: u16,
    /// Scheme whose root signs this certificate.
    pub scheme_id: [u8; 32],
    /// The only role this key may sign for.
    pub role: KagemushaWalletSignerRoleV1,
    /// Delegated signing key.
    pub key: KagemushaDevicePublicKeyV1,
    /// Issuer-assigned serial for planned rotation.
    pub serial: u64,
}

impl KagemushaWalletSignerCertificateBodyV1 {
    /// Exact `certificate-body` transcript.
    #[must_use]
    pub fn transcript(&self) -> Vec<u8> {
        WalletTranscriptV1::with_capacity(KAGEMUSHA_WALLET_CERTIFICATE_BODY_TRANSCRIPT_BYTES_V1)
            .u16(self.version)
            .digest(&self.scheme_id)
            .u8(self.role.tag())
            .key(&self.key)
            .u64(self.serial)
            .finish()
    }

    /// Canonical 32-byte signing message `m = P_bytes(d, transcript)` (§8).
    #[must_use]
    pub fn signing_message(&self) -> [u8; 32] {
        kagemusha_wallet_signing_message_v1(Domain::Certificate, &self.transcript())
    }

    /// Validate the body's fields.
    ///
    /// # Errors
    ///
    /// Rejects another version, a zero scheme, or a non-canonical key.
    pub fn validate(&self) -> WalletResult<()> {
        require_version_v1("certificate.version", self.version)?;
        require_nonzero_v1("certificate.scheme_id", &self.scheme_id)?;
        self.key.validate()?;
        Ok(())
    }
}

/// Signer certificate signed directly by the scheme root (fixed depth one, §3.3).
///
/// No validity period or revocation lookup is evaluated offline; a consumer checks that the
/// role equals the role it requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletSignerCertificateV1"
)]
pub struct KagemushaWalletSignerCertificateV1 {
    /// Signed body.
    pub body: KagemushaWalletSignerCertificateBodyV1,
    /// Scheme-root signature over the `kgwcert1` signing message.
    pub signature: KagemushaDeviceSignatureV1,
}

impl KagemushaWalletSignerCertificateV1 {
    /// Freeze a scheme-root signature over `body`.
    ///
    /// # Errors
    ///
    /// Rejects an invalid body, a body for another scheme, or a signature that does not
    /// verify under the scheme root.
    pub fn sign(
        body: KagemushaWalletSignerCertificateBodyV1,
        scheme: &KagemushaWalletSchemeV1,
        signer_output: KagemushaWalletSignerOutputV1<'_>,
    ) -> WalletResult<Self> {
        body.validate()?;
        scheme.validate()?;
        require_scheme_v1(
            "certificate.scheme_id",
            &body.scheme_id,
            &scheme.scheme_id(),
        )?;
        let signature = kagemusha_wallet_freeze_signature_v1(
            &scheme.scheme_root_key,
            Domain::Certificate,
            &body.signing_message(),
            signer_output,
        )?;
        Ok(Self { body, signature })
    }

    /// Certificate digest `H("certificate", m || signature)`.
    #[must_use]
    pub fn certificate_digest(&self) -> [u8; 32] {
        kagemusha_wallet_signed_object_digest_v1(
            Role::Certificate,
            &self.body.signing_message(),
            &self.signature,
        )
    }

    /// Validate the certificate's structure without a scheme root.
    ///
    /// # Errors
    ///
    /// Rejects an invalid body or a non-canonical signature encoding.
    pub fn validate(&self) -> WalletResult<()> {
        self.body.validate()?;
        self.signature.validate()?;
        Ok(())
    }

    /// Verify the certificate under `scheme`'s root.
    ///
    /// # Errors
    ///
    /// Rejects an invalid certificate, another scheme, or a root signature that does not
    /// verify.
    pub fn verify(&self, scheme: &KagemushaWalletSchemeV1) -> WalletResult<()> {
        self.validate()?;
        require_scheme_v1(
            "certificate.scheme_id",
            &self.body.scheme_id,
            &scheme.scheme_id(),
        )?;
        kagemusha_wallet_verify_signature_v1(
            &scheme.scheme_root_key,
            Domain::Certificate,
            &self.body.signing_message(),
            &self.signature,
        )
    }

    /// Verify the certificate under `scheme` and require `role`.
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::verify`] rejects and a certificate for another role.
    pub fn verify_role(
        &self,
        scheme: &KagemushaWalletSchemeV1,
        role: KagemushaWalletSignerRoleV1,
    ) -> WalletResult<()> {
        self.verify(scheme)?;
        if self.body.role != role {
            return Err(invalid_v1("certificate.role"));
        }
        Ok(())
    }

    /// Validate and encode the bounded canonical frame.
    ///
    /// # Errors
    ///
    /// Rejects an invalid certificate or an oversized frame.
    pub fn to_canonical_bytes(&self) -> WalletResult<Vec<u8>> {
        self.validate()?;
        encode_frame_v1(self, KAGEMUSHA_WALLET_CERTIFICATE_MAX_BYTES_V1)
    }

    /// Decode and verify one canonical certificate frame under `scheme`.
    ///
    /// # Errors
    ///
    /// Rejects, in order, an oversized frame, a noncanonical frame, another version, another
    /// scheme, invalid fields, and a root signature that does not verify.
    pub fn decode_canonical(bytes: &[u8], scheme: &KagemushaWalletSchemeV1) -> WalletResult<Self> {
        let certificate: Self = decode_frame_v1(bytes, KAGEMUSHA_WALLET_CERTIFICATE_MAX_BYTES_V1)?;
        certificate.require_versions()?;
        require_scheme_v1(
            "certificate.scheme_id",
            &certificate.body.scheme_id,
            &scheme.scheme_id(),
        )?;
        certificate.verify(scheme)?;
        Ok(certificate)
    }
}

/// Signer certificates carried by a message, sorted by strictly ascending certificate digest.
///
/// At most [`KAGEMUSHA_WALLET_CERTIFICATE_SET_MAX_V1`] certificates. Its digest is
/// `H("certificate-set", LE32 count || digests in order)` (design C3).
#[derive(
    Debug, Clone, PartialEq, Eq, Default, Decode, Encode, IntoSchema, norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletCertificateSetV1"
)]
pub struct KagemushaWalletCertificateSetV1 {
    /// Certificates in strictly ascending certificate-digest order.
    pub certificates: Vec<KagemushaWalletSignerCertificateV1>,
}

impl KagemushaWalletCertificateSetV1 {
    /// Sort `certificates` canonically and validate the resulting set.
    ///
    /// # Errors
    ///
    /// Rejects duplicates, more than the maximum, or an invalid certificate.
    pub fn new(mut certificates: Vec<KagemushaWalletSignerCertificateV1>) -> WalletResult<Self> {
        if certificates.len() > KAGEMUSHA_WALLET_CERTIFICATE_SET_MAX_V1 {
            return Err(invalid_v1("certificates"));
        }
        certificates.sort_by_cached_key(KagemushaWalletSignerCertificateV1::certificate_digest);
        let set = Self { certificates };
        set.validate()?;
        Ok(set)
    }

    /// Number of certificates.
    #[must_use]
    pub fn len(&self) -> usize {
        self.certificates.len()
    }

    /// Whether the set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.certificates.is_empty()
    }

    /// Certificate digests in set order.
    #[must_use]
    pub fn digests(&self) -> Vec<[u8; 32]> {
        self.certificates
            .iter()
            .map(KagemushaWalletSignerCertificateV1::certificate_digest)
            .collect()
    }

    /// Exact `certificate-set` transcript: `LE32 count || digests in order`.
    ///
    /// # Errors
    ///
    /// Rejects a count that does not fit `u32`.
    pub fn transcript(&self) -> WalletResult<Vec<u8>> {
        let count = u32::try_from(self.certificates.len()).map_err(|_| {
            KagemushaWalletValidationErrorV1::ArithmeticOverflow {
                field: "certificates",
            }
        })?;
        let capacity = self
            .certificates
            .len()
            .checked_mul(32)
            .and_then(|bytes| bytes.checked_add(4))
            .ok_or(KagemushaWalletValidationErrorV1::ArithmeticOverflow {
                field: "certificates",
            })?;
        let mut transcript = WalletTranscriptV1::with_capacity(capacity).u32(count);
        for digest in self.digests() {
            transcript = transcript.digest(&digest);
        }
        Ok(transcript.finish())
    }

    /// Set digest `H("certificate-set", transcript)`.
    ///
    /// # Errors
    ///
    /// Rejects a count that does not fit `u32`.
    pub fn digest(&self) -> WalletResult<[u8; 32]> {
        Ok(kagemusha_wallet_digest_v1(
            Role::CertificateSet,
            &self.transcript()?,
        ))
    }

    /// Validate size, order, uniqueness and each certificate's structure.
    ///
    /// # Errors
    ///
    /// Rejects more than the maximum, unsorted or duplicate digests, or an invalid
    /// certificate.
    pub fn validate(&self) -> WalletResult<()> {
        if self.certificates.len() > KAGEMUSHA_WALLET_CERTIFICATE_SET_MAX_V1 {
            return Err(invalid_v1("certificates"));
        }
        let mut previous: Option<[u8; 32]> = None;
        for certificate in &self.certificates {
            certificate.validate()?;
            let digest = certificate.certificate_digest();
            if previous.is_some_and(|previous| previous >= digest) {
                return Err(invalid_v1("certificates.order"));
            }
            previous = Some(digest);
        }
        Ok(())
    }

    /// Validate the set and verify every certificate under `scheme`.
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::validate`] and [`KagemushaWalletSignerCertificateV1::verify`]
    /// reject.
    pub fn verify(&self, scheme: &KagemushaWalletSchemeV1) -> WalletResult<()> {
        self.validate()?;
        for certificate in &self.certificates {
            certificate.verify(scheme)?;
        }
        Ok(())
    }

    /// Select the certificate with `digest` and require `role`.
    ///
    /// # Errors
    ///
    /// Rejects a missing certificate or one for another role.
    pub fn certificate(
        &self,
        digest: &[u8; 32],
        role: KagemushaWalletSignerRoleV1,
    ) -> WalletResult<&KagemushaWalletSignerCertificateV1> {
        let certificate = self
            .certificates
            .iter()
            .find(|certificate| certificate.certificate_digest() == *digest)
            .ok_or_else(|| invalid_v1("certificates.missing"))?;
        if certificate.body.role != role {
            return Err(invalid_v1("certificate.role"));
        }
        Ok(certificate)
    }
}

// ---------------------------------------------------------------------------------------
// Enrollment challenge and wallet identity (§2.2)
// ---------------------------------------------------------------------------------------

/// Fresh issuer enrollment challenge binding scheme, asset, account and policies (§2.2).
///
/// Android: `challenge_digest` is the `KeyMint` attestation challenge of the generated payment
/// key. iPhone: it is the App Attest attestation `clientDataHash`; the assertion's
/// `clientDataHash` is [`kagemusha_wallet_enrollment_key_binding_v1`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletEnrollmentChallengeV1"
)]
pub struct KagemushaWalletEnrollmentChallengeV1 {
    /// Wire version; exactly [`KAGEMUSHA_WALLET_VERSION_V1`].
    pub version: u16,
    /// Enrolled scheme.
    pub scheme_id: [u8; 32],
    /// Enrolled asset scope digest.
    pub asset_digest: [u8; 32],
    /// Digest of the canonical domainless `AccountId`.
    pub account_digest: [u8; 32],
    /// Issuer-defined app identity policy digest.
    // TODO(G5): define the app-policy preimage with the Torii enrollment family.
    pub app_policy: [u8; 32],
    /// Issuer-defined enrollment policy digest.
    // TODO(G5): define the enrollment-policy preimage with the Torii enrollment family.
    pub enrollment_policy: [u8; 32],
    /// Fresh issuer nonce.
    pub issuer_nonce: [u8; 32],
}

impl KagemushaWalletEnrollmentChallengeV1 {
    /// Exact `enrollment-challenge` transcript.
    #[must_use]
    pub fn transcript(&self) -> Vec<u8> {
        WalletTranscriptV1::with_capacity(KAGEMUSHA_WALLET_ENROLLMENT_CHALLENGE_TRANSCRIPT_BYTES_V1)
            .u16(self.version)
            .digest(&self.scheme_id)
            .digest(&self.asset_digest)
            .digest(&self.account_digest)
            .digest(&self.app_policy)
            .digest(&self.enrollment_policy)
            .digest(&self.issuer_nonce)
            .finish()
    }

    /// Challenge digest `H("enrollment-challenge", transcript)`.
    #[must_use]
    pub fn challenge_digest(&self) -> [u8; 32] {
        kagemusha_wallet_digest_v1(Role::EnrollmentChallenge, &self.transcript())
    }

    /// Enrollment identity of `payment_key` under this challenge.
    #[must_use]
    pub fn enrollment_id(&self, payment_key: &KagemushaDevicePublicKeyV1) -> [u8; 32] {
        kagemusha_wallet_enrollment_id_v1(&self.challenge_digest(), payment_key)
    }

    /// Wallet identity of `payment_key` under this challenge.
    #[must_use]
    pub fn wallet_id(&self, payment_key: &KagemushaDevicePublicKeyV1) -> [u8; 32] {
        kagemusha_wallet_id_v1(
            &self.scheme_id,
            &self.asset_digest,
            payment_key,
            &self.enrollment_id(payment_key),
        )
    }

    /// Validate the challenge's fields.
    ///
    /// # Errors
    ///
    /// Rejects another version or any all-zero binding.
    pub fn validate(&self) -> WalletResult<()> {
        require_version_v1("enrollment_challenge.version", self.version)?;
        require_nonzero_v1("enrollment_challenge.scheme_id", &self.scheme_id)?;
        require_nonzero_v1("enrollment_challenge.asset_digest", &self.asset_digest)?;
        require_nonzero_v1("enrollment_challenge.account_digest", &self.account_digest)?;
        require_nonzero_v1("enrollment_challenge.app_policy", &self.app_policy)?;
        require_nonzero_v1(
            "enrollment_challenge.enrollment_policy",
            &self.enrollment_policy,
        )?;
        require_nonzero_v1("enrollment_challenge.issuer_nonce", &self.issuer_nonce)?;
        Ok(())
    }
}

/// Exact `enrollment-id` / `enrollment-key-binding` transcript: `challenge_digest || payment_key`.
#[must_use]
pub fn kagemusha_wallet_enrollment_key_transcript_v1(
    challenge_digest: &[u8; 32],
    payment_key: &KagemushaDevicePublicKeyV1,
) -> Vec<u8> {
    WalletTranscriptV1::with_capacity(KAGEMUSHA_WALLET_ENROLLMENT_KEY_TRANSCRIPT_BYTES_V1)
        .digest(challenge_digest)
        .key(payment_key)
        .finish()
}

/// Enrollment identity `H("enrollment-id", challenge_digest || payment_key)`.
#[must_use]
pub fn kagemusha_wallet_enrollment_id_v1(
    challenge_digest: &[u8; 32],
    payment_key: &KagemushaDevicePublicKeyV1,
) -> [u8; 32] {
    kagemusha_wallet_digest_v1(
        Role::EnrollmentId,
        &kagemusha_wallet_enrollment_key_transcript_v1(challenge_digest, payment_key),
    )
}

/// App Attest enrollment assertion `clientDataHash`:
/// `H("enrollment-key-binding", challenge_digest || payment_key)`.
#[must_use]
pub fn kagemusha_wallet_enrollment_key_binding_v1(
    challenge_digest: &[u8; 32],
    payment_key: &KagemushaDevicePublicKeyV1,
) -> [u8; 32] {
    kagemusha_wallet_digest_v1(
        Role::EnrollmentKeyBinding,
        &kagemusha_wallet_enrollment_key_transcript_v1(challenge_digest, payment_key),
    )
}

/// Exact `wallet-id` transcript.
#[must_use]
pub fn kagemusha_wallet_id_transcript_v1(
    scheme_id: &[u8; 32],
    asset_digest: &[u8; 32],
    payment_key: &KagemushaDevicePublicKeyV1,
    enrollment_id: &[u8; 32],
) -> Vec<u8> {
    WalletTranscriptV1::with_capacity(KAGEMUSHA_WALLET_ID_TRANSCRIPT_BYTES_V1)
        .digest(scheme_id)
        .digest(asset_digest)
        .key(payment_key)
        .digest(enrollment_id)
        .finish()
}

/// Wallet incarnation identity
/// `H("wallet-id", scheme_id || asset_digest || payment_key || enrollment_id)`.
#[must_use]
pub fn kagemusha_wallet_id_v1(
    scheme_id: &[u8; 32],
    asset_digest: &[u8; 32],
    payment_key: &KagemushaDevicePublicKeyV1,
    enrollment_id: &[u8; 32],
) -> [u8; 32] {
    kagemusha_wallet_digest_v1(
        Role::WalletId,
        &kagemusha_wallet_id_transcript_v1(scheme_id, asset_digest, payment_key, enrollment_id),
    )
}

// ---------------------------------------------------------------------------------------
// Platform evidence, regulatory policy and credential (§§2.2, 7; design C3, C5)
// ---------------------------------------------------------------------------------------

/// Platform evidence family of a wallet's payment key (§2.2).
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Decode,
    Encode,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletEvidenceKindV1"
)]
pub enum KagemushaWalletEvidenceKindV1 {
    /// Android `KeyMint` key in the TEE.
    #[codec(index = 1)]
    AndroidKeyMintTee,
    /// Android `KeyMint` key in `StrongBox`.
    #[codec(index = 2)]
    AndroidKeyMintStrongBox,
    /// Secure Enclave payment key bound by Apple App Attest.
    #[codec(index = 3)]
    AppleAppAttest,
}

impl KagemushaWalletEvidenceKindV1 {
    /// Every evidence kind, in tag order.
    pub const ALL: [Self; 3] = [
        Self::AndroidKeyMintTee,
        Self::AndroidKeyMintStrongBox,
        Self::AppleAppAttest,
    ];

    /// Transcript tag; equal to the Norito wire tag.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::AndroidKeyMintTee => 1,
            Self::AndroidKeyMintStrongBox => 2,
            Self::AppleAppAttest => 3,
        }
    }

    /// Whether this is an Android `KeyMint` kind.
    #[must_use]
    pub const fn is_android(self) -> bool {
        matches!(
            self,
            Self::AndroidKeyMintTee | Self::AndroidKeyMintStrongBox
        )
    }

    /// Fact bits this kind never carries.
    #[must_use]
    pub const fn forbidden_facts(self) -> u32 {
        if self.is_android() {
            KAGEMUSHA_WALLET_ANDROID_FORBIDDEN_FACTS_V1
        } else {
            KAGEMUSHA_WALLET_APPLE_FORBIDDEN_FACTS_V1
        }
    }

    /// Fact bits this kind's enrollment evidence must carry.
    #[must_use]
    pub const fn required_enrollment_facts(self) -> u32 {
        match self {
            Self::AndroidKeyMintTee => KAGEMUSHA_WALLET_ANDROID_REQUIRED_FACTS_V1,
            Self::AndroidKeyMintStrongBox => {
                KAGEMUSHA_WALLET_ANDROID_REQUIRED_FACTS_V1 | KAGEMUSHA_WALLET_FACT_STRONGBOX_V1
            }
            Self::AppleAppAttest => KAGEMUSHA_WALLET_APPLE_REQUIRED_FACTS_V1,
        }
    }
}

/// Exact `evidence` transcript over original platform items (design C3).
///
/// Layout: `u8 kind || LE32 count || for each item: LE32 len || bytes`. Android items are the
/// attestation certificate DER chain, leaf first; Apple items are the attestation object then
/// the assertion. Raw bytes are never rewritten.
///
/// # Errors
///
/// Rejects an empty item list, an empty item, or a count or length that does not fit `u32`.
pub fn kagemusha_wallet_evidence_transcript_v1(
    kind: KagemushaWalletEvidenceKindV1,
    items: &[&[u8]],
) -> WalletResult<Vec<u8>> {
    if items.is_empty() || items.iter().any(|item| item.is_empty()) {
        return Err(invalid_v1("evidence_items"));
    }
    let count = u32::try_from(items.len()).map_err(|_| overflow_v1("evidence_items"))?;
    let mut capacity: usize = 5;
    for item in items {
        capacity = capacity
            .checked_add(4)
            .and_then(|value| value.checked_add(item.len()))
            .ok_or_else(|| overflow_v1("evidence_items"))?;
    }
    let mut transcript = WalletTranscriptV1::with_capacity(capacity)
        .u8(kind.tag())
        .u32(count);
    for item in items {
        let length = u32::try_from(item.len()).map_err(|_| overflow_v1("evidence_items"))?;
        transcript = transcript.u32(length).bytes(item);
    }
    Ok(transcript.finish())
}

/// Evidence digest `H("evidence", transcript)` recorded in a credential.
///
/// # Errors
///
/// Rejects what [`kagemusha_wallet_evidence_transcript_v1`] rejects.
pub fn kagemusha_wallet_evidence_digest_v1(
    kind: KagemushaWalletEvidenceKindV1,
    items: &[&[u8]],
) -> WalletResult<[u8; 32]> {
    Ok(kagemusha_wallet_digest_v1(
        Role::Evidence,
        &kagemusha_wallet_evidence_transcript_v1(kind, items)?,
    ))
}

/// One verified platform evidence event recorded in a credential (§2.2, R10).
///
/// The facts describe the attested event, not a live examination of every payment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletEvidenceV1"
)]
pub struct KagemushaWalletEvidenceV1 {
    /// Evidence digest ([`kagemusha_wallet_evidence_digest_v1`]).
    pub digest: [u8; 32],
    /// Unix milliseconds at which the issuer verified the evidence.
    pub time_ms: u64,
    /// Verified fact bits (`KAGEMUSHA_WALLET_FACT_*`).
    pub facts: u32,
    /// Recorded OS patch level; zero for Apple.
    pub os_patch_level: u32,
    /// Recorded vendor patch level; zero for Apple.
    pub vendor_patch_level: u32,
    /// Recorded boot patch level; zero for Apple.
    pub boot_patch_level: u32,
}

impl KagemushaWalletEvidenceV1 {
    /// Append the inline transcript.
    fn write(&self, transcript: WalletTranscriptV1) -> WalletTranscriptV1 {
        transcript
            .digest(&self.digest)
            .u64(self.time_ms)
            .u32(self.facts)
            .u32(self.os_patch_level)
            .u32(self.vendor_patch_level)
            .u32(self.boot_patch_level)
    }

    /// Exact inline transcript bytes.
    #[must_use]
    pub fn transcript(&self) -> Vec<u8> {
        self.write(WalletTranscriptV1::with_capacity(
            KAGEMUSHA_WALLET_EVIDENCE_TRANSCRIPT_BYTES_V1,
        ))
        .finish()
    }

    /// Validate the per-kind fact mask of any evidence record of `kind`.
    ///
    /// # Errors
    ///
    /// Rejects a zero digest, undefined fact bits, facts the kind never carries, or Apple
    /// patch levels.
    pub fn validate_for_kind(&self, kind: KagemushaWalletEvidenceKindV1) -> WalletResult<()> {
        require_nonzero_v1("evidence.digest", &self.digest)?;
        if self.facts & !KAGEMUSHA_WALLET_FACTS_DEFINED_MASK_V1 != 0
            || self.facts & kind.forbidden_facts() != 0
        {
            return Err(invalid_v1("evidence.facts"));
        }
        if !kind.is_android()
            && (self.os_patch_level != 0
                || self.vendor_patch_level != 0
                || self.boot_patch_level != 0)
        {
            return Err(invalid_v1("evidence.patch_level"));
        }
        Ok(())
    }

    /// Validate an enrollment evidence record of `kind`, including its required facts.
    ///
    /// # Errors
    ///
    /// Rejects what [`Self::validate_for_kind`] rejects, a missing required fact, and a
    /// `StrongBox` fact on TEE evidence.
    pub fn validate_enrollment_for_kind(
        &self,
        kind: KagemushaWalletEvidenceKindV1,
    ) -> WalletResult<()> {
        self.validate_for_kind(kind)?;
        let required = kind.required_enrollment_facts();
        if self.facts & required != required {
            return Err(invalid_v1("evidence.required_facts"));
        }
        if kind == KagemushaWalletEvidenceKindV1::AndroidKeyMintTee
            && self.facts & KAGEMUSHA_WALLET_FACT_STRONGBOX_V1 != 0
        {
            return Err(invalid_v1("evidence.strongbox"));
        }
        Ok(())
    }
}

/// Regulatory controls permitted by a credential and their activation semantics (§7).
///
/// A control is active only when permitted here and enabled by the held scheme policy.
/// The default permits nothing.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, Decode, Encode, IntoSchema, norito::NoritoSchema,
)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletRegulatoryPolicyV1"
)]
pub struct KagemushaWalletRegulatoryPolicyV1 {
    /// Permitted control bits (`KAGEMUSHA_WALLET_CONTROL_*`).
    pub permitted_controls: u32,
    /// Maximum blacklist age in milliseconds; zero means no list-age rule.
    pub blacklist_max_age_ms: u64,
    /// Maximum time-anchor response age on the monotonic clock; zero when no permitted rule
    /// is time dependent.
    pub time_anchor_max_response_ms: u64,
}

impl KagemushaWalletRegulatoryPolicyV1 {
    /// Append the inline transcript.
    fn write(&self, transcript: WalletTranscriptV1) -> WalletTranscriptV1 {
        transcript
            .u32(self.permitted_controls)
            .u64(self.blacklist_max_age_ms)
            .u64(self.time_anchor_max_response_ms)
    }

    /// Exact inline transcript bytes.
    #[must_use]
    pub fn transcript(&self) -> Vec<u8> {
        self.write(WalletTranscriptV1::with_capacity(
            KAGEMUSHA_WALLET_REGULATORY_POLICY_TRANSCRIPT_BYTES_V1,
        ))
        .finish()
    }

    /// Whether every bit of `control` is permitted.
    #[must_use]
    pub const fn permits(&self, control: u32) -> bool {
        control != 0 && self.permitted_controls & control == control
    }

    /// Whether a permitted rule depends on trusted time.
    #[must_use]
    pub const fn requires_time_anchor(&self) -> bool {
        self.permits(KAGEMUSHA_WALLET_CONTROL_QUOTAS_V1)
            || self.permits(KAGEMUSHA_WALLET_CONTROL_ATTESTATION_LEASE_V1)
            || self.blacklist_max_age_ms > 0
    }

    /// Validate the policy's consistency rules.
    ///
    /// # Errors
    ///
    /// Rejects undefined control bits, a list-age rule without the blacklist control, and a
    /// response bound that is present exactly when no permitted rule is time dependent.
    pub fn validate(&self) -> WalletResult<()> {
        if self.permitted_controls & !KAGEMUSHA_WALLET_CONTROLS_DEFINED_MASK_V1 != 0 {
            return Err(invalid_v1("regulatory_policy.permitted_controls"));
        }
        if self.blacklist_max_age_ms > 0 && !self.permits(KAGEMUSHA_WALLET_CONTROL_BLACKLIST_V1) {
            return Err(invalid_v1("regulatory_policy.blacklist_max_age_ms"));
        }
        if (self.time_anchor_max_response_ms > 0) != self.requires_time_anchor() {
            return Err(invalid_v1("regulatory_policy.time_anchor_max_response_ms"));
        }
        Ok(())
    }
}

/// Body of a wallet credential, signed by an Enrollment-role key under `kgwcred1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletCredentialBodyV1"
)]
pub struct KagemushaWalletCredentialBodyV1 {
    /// Wire version; exactly [`KAGEMUSHA_WALLET_VERSION_V1`].
    pub version: u16,
    /// Enrolled scheme.
    pub scheme_id: [u8; 32],
    /// Enrolled asset scope digest.
    pub asset_digest: [u8; 32],
    /// Wallet incarnation identity.
    pub wallet_id: [u8; 32],
    /// Digest of the canonical domainless `AccountId`.
    pub account_digest: [u8; 32],
    /// Hardware-backed payment key; it alone signs receipts and wallet-domain messages.
    pub payment_key: KagemushaDevicePublicKeyV1,
    /// Provider contract of the scheme.
    pub provider_contract: [u8; 32],
    /// Platform evidence kind.
    pub evidence_kind: KagemushaWalletEvidenceKindV1,
    /// Historical evidence about the payment key's generation.
    pub enrollment_evidence: KagemushaWalletEvidenceV1,
    /// Evidence verified at the last renewal; equal to `enrollment_evidence` at renewal 0.
    pub fresh_evidence: KagemushaWalletEvidenceV1,
    /// Issuer-defined app identity policy digest.
    pub app_policy: [u8; 32],
    /// Permitted regulatory controls; byte-identical across renewals.
    pub regulatory_policy: KagemushaWalletRegulatoryPolicyV1,
    /// Enrollment incarnation identity.
    pub enrollment_id: [u8; 32],
    /// Issuance time in Unix milliseconds.
    pub issued_at_ms: u64,
    /// Renewal sequence; zero at enrollment and increased by exactly one per renewal.
    pub renewal_sequence: u32,
    /// Attestation lease expiry in Unix milliseconds; nonzero iff the lease is permitted.
    pub lease_expires_at_ms: u64,
    /// Certificate digest of the Enrollment-role signer.
    pub issuer_certificate: [u8; 32],
}

impl KagemushaWalletCredentialBodyV1 {
    /// Exact `credential-body` transcript.
    #[must_use]
    pub fn transcript(&self) -> Vec<u8> {
        let transcript =
            WalletTranscriptV1::with_capacity(KAGEMUSHA_WALLET_CREDENTIAL_BODY_TRANSCRIPT_BYTES_V1)
                .u16(self.version)
                .digest(&self.scheme_id)
                .digest(&self.asset_digest)
                .digest(&self.wallet_id)
                .digest(&self.account_digest)
                .key(&self.payment_key)
                .digest(&self.provider_contract)
                .u8(self.evidence_kind.tag());
        let transcript = self.enrollment_evidence.write(transcript);
        let transcript = self
            .fresh_evidence
            .write(transcript)
            .digest(&self.app_policy);
        self.regulatory_policy
            .write(transcript)
            .digest(&self.enrollment_id)
            .u64(self.issued_at_ms)
            .u32(self.renewal_sequence)
            .u64(self.lease_expires_at_ms)
            .digest(&self.issuer_certificate)
            .finish()
    }

    /// Canonical 32-byte signing message `m = P_bytes(d, transcript)` (§8).
    #[must_use]
    pub fn signing_message(&self) -> [u8; 32] {
        kagemusha_wallet_signing_message_v1(Domain::Credential, &self.transcript())
    }

    /// Validate the body's self-contained rules (§2.4, design C5).
    ///
    /// # Errors
    ///
    /// Rejects another version, zero bindings, a provider contract other than the V1
    /// contract, a `wallet_id` that does not recompute, invalid evidence facts, inconsistent
    /// renewal evidence, an invalid regulatory policy, or a lease that disagrees with it.
    pub fn validate(&self) -> WalletResult<()> {
        require_version_v1("credential.version", self.version)?;
        require_nonzero_v1("credential.scheme_id", &self.scheme_id)?;
        require_nonzero_v1("credential.asset_digest", &self.asset_digest)?;
        require_nonzero_v1("credential.account_digest", &self.account_digest)?;
        require_nonzero_v1("credential.app_policy", &self.app_policy)?;
        require_nonzero_v1("credential.enrollment_id", &self.enrollment_id)?;
        require_nonzero_v1("credential.issuer_certificate", &self.issuer_certificate)?;
        self.payment_key.validate()?;
        if self.provider_contract != kagemusha_wallet_provider_contract_v1() {
            return Err(invalid_v1("credential.provider_contract"));
        }
        let wallet_id = kagemusha_wallet_id_v1(
            &self.scheme_id,
            &self.asset_digest,
            &self.payment_key,
            &self.enrollment_id,
        );
        if wallet_id != self.wallet_id {
            return Err(invalid_v1("credential.wallet_id"));
        }
        self.enrollment_evidence
            .validate_enrollment_for_kind(self.evidence_kind)?;
        self.fresh_evidence.validate_for_kind(self.evidence_kind)?;
        if self.renewal_sequence == 0 {
            if self.fresh_evidence != self.enrollment_evidence {
                return Err(invalid_v1("credential.fresh_evidence"));
            }
        } else if self.fresh_evidence.time_ms < self.enrollment_evidence.time_ms {
            return Err(invalid_v1("credential.fresh_evidence.time_ms"));
        }
        self.regulatory_policy.validate()?;
        let lease_permitted = self
            .regulatory_policy
            .permits(KAGEMUSHA_WALLET_CONTROL_ATTESTATION_LEASE_V1);
        if (self.lease_expires_at_ms != 0) != lease_permitted {
            return Err(invalid_v1("credential.lease_expires_at_ms"));
        }
        Ok(())
    }
}

/// Issuer-signed wallet credential consumed by every transition proof (§2.2, R10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletCredentialV1"
)]
pub struct KagemushaWalletCredentialV1 {
    /// Signed body.
    pub body: KagemushaWalletCredentialBodyV1,
    /// Enrollment-role signature over the `kgwcred1` signing message.
    pub signature: KagemushaDeviceSignatureV1,
}

impl KagemushaWalletCredentialV1 {
    /// Freeze an Enrollment-role signature over `body`.
    ///
    /// # Errors
    ///
    /// Rejects an invalid body, an issuer certificate that is not the body's Enrollment-role
    /// signer for its scheme, or a signature that does not verify under it.
    pub fn sign(
        body: KagemushaWalletCredentialBodyV1,
        issuer_certificate: &KagemushaWalletSignerCertificateV1,
        signer_output: KagemushaWalletSignerOutputV1<'_>,
    ) -> WalletResult<Self> {
        body.validate()?;
        issuer_certificate.validate()?;
        if issuer_certificate.certificate_digest() != body.issuer_certificate {
            return Err(invalid_v1("credential.issuer_certificate"));
        }
        if issuer_certificate.body.role != KagemushaWalletSignerRoleV1::Enrollment {
            return Err(invalid_v1("certificate.role"));
        }
        require_scheme_v1(
            "credential.scheme_id",
            &body.scheme_id,
            &issuer_certificate.body.scheme_id,
        )?;
        let signature = kagemusha_wallet_freeze_signature_v1(
            &issuer_certificate.body.key,
            Domain::Credential,
            &body.signing_message(),
            signer_output,
        )?;
        Ok(Self { body, signature })
    }

    /// Credential digest `H("credential", m || signature)`.
    #[must_use]
    pub fn credential_digest(&self) -> [u8; 32] {
        kagemusha_wallet_signed_object_digest_v1(
            Role::Credential,
            &self.body.signing_message(),
            &self.signature,
        )
    }

    /// Validate the credential's self-contained rules.
    ///
    /// # Errors
    ///
    /// Rejects an invalid body or a non-canonical signature encoding.
    pub fn validate(&self) -> WalletResult<()> {
        self.body.validate()?;
        self.signature.validate()?;
        Ok(())
    }

    /// Verify the credential under `scheme` and its Enrollment-role `issuer_certificate`.
    ///
    /// # Errors
    ///
    /// Rejects an invalid credential, another scheme or provider contract, an issuer
    /// certificate that is not the credential's Enrollment-role signer under `scheme`, or an
    /// issuer signature that does not verify.
    pub fn verify(
        &self,
        scheme: &KagemushaWalletSchemeV1,
        issuer_certificate: &KagemushaWalletSignerCertificateV1,
    ) -> WalletResult<()> {
        self.validate()?;
        require_scheme_v1(
            "credential.scheme_id",
            &self.body.scheme_id,
            &scheme.scheme_id(),
        )?;
        if self.body.provider_contract != scheme.provider_contract {
            return Err(KagemushaWalletValidationErrorV1::SchemeMismatch {
                field: "credential.provider_contract",
            });
        }
        if issuer_certificate.certificate_digest() != self.body.issuer_certificate {
            return Err(invalid_v1("credential.issuer_certificate"));
        }
        issuer_certificate.verify_role(scheme, KagemushaWalletSignerRoleV1::Enrollment)?;
        kagemusha_wallet_verify_signature_v1(
            &issuer_certificate.body.key,
            Domain::Credential,
            &self.body.signing_message(),
            &self.signature,
        )
    }

    /// Validate `self` as the replacement of `previous` (`RefreshPolicy` Credential, design C5).
    ///
    /// Only `fresh_evidence`, `issued_at_ms`, `lease_expires_at_ms` and `issuer_certificate`
    /// may change, and `renewal_sequence` must be exactly `previous + 1`.
    ///
    /// # Errors
    ///
    /// Rejects an invalid credential, a renewal sequence other than the successor, or a
    /// change to any other field.
    pub fn validate_replacement_of(&self, previous: &Self) -> WalletResult<()> {
        self.validate()?;
        previous.validate()?;
        let successor = previous
            .body
            .renewal_sequence
            .checked_add(1)
            .ok_or_else(|| overflow_v1("credential.renewal_sequence"))?;
        if self.body.renewal_sequence != successor {
            return Err(invalid_v1("credential.renewal_sequence"));
        }
        let mut unchanged = self.body;
        unchanged.fresh_evidence = previous.body.fresh_evidence;
        unchanged.issued_at_ms = previous.body.issued_at_ms;
        unchanged.lease_expires_at_ms = previous.body.lease_expires_at_ms;
        unchanged.issuer_certificate = previous.body.issuer_certificate;
        unchanged.renewal_sequence = previous.body.renewal_sequence;
        if unchanged != previous.body {
            return Err(invalid_v1("credential.replacement"));
        }
        Ok(())
    }

    /// Validate and encode the bounded canonical frame.
    ///
    /// # Errors
    ///
    /// Rejects an invalid credential or an oversized frame.
    pub fn to_canonical_bytes(&self) -> WalletResult<Vec<u8>> {
        self.validate()?;
        encode_frame_v1(self, KAGEMUSHA_WALLET_CREDENTIAL_MAX_BYTES_V1)
    }

    /// Decode one canonical credential frame for `expected_scheme_id`.
    ///
    /// The issuer signature is checked separately by [`Self::verify`].
    ///
    /// # Errors
    ///
    /// Rejects, in order, an oversized frame, a noncanonical frame, another version, another
    /// scheme, and invalid fields.
    pub fn decode_canonical(bytes: &[u8], expected_scheme_id: &[u8; 32]) -> WalletResult<Self> {
        let credential: Self = decode_frame_v1(bytes, KAGEMUSHA_WALLET_CREDENTIAL_MAX_BYTES_V1)?;
        credential.require_versions()?;
        require_scheme_v1(
            "credential.scheme_id",
            &credential.body.scheme_id,
            expected_scheme_id,
        )?;
        credential.validate()?;
        Ok(credential)
    }
}

// ---------------------------------------------------------------------------------------
// Attestation-lease renewal (§2.2, design §2.5 and C9)
// ---------------------------------------------------------------------------------------

/// Exact `renewal-challenge` transcript signed by the payment key for possession; the same
/// layout is hashed under `renewal-assertion` for App Attest.
#[must_use]
pub fn kagemusha_wallet_renewal_challenge_transcript_v1(
    scheme_id: &[u8; 32],
    wallet_id: &[u8; 32],
    credential_digest: &[u8; 32],
    challenge: &[u8; 32],
) -> Vec<u8> {
    WalletTranscriptV1::with_capacity(KAGEMUSHA_WALLET_RENEWAL_CHALLENGE_TRANSCRIPT_BYTES_V1)
        .u16(KAGEMUSHA_WALLET_VERSION_V1)
        .digest(scheme_id)
        .digest(wallet_id)
        .digest(credential_digest)
        .digest(challenge)
        .finish()
}

/// Exact `renewal-key-binding` transcript signed by the payment key over a newly attested
/// Android key.
#[must_use]
pub fn kagemusha_wallet_renewal_key_binding_transcript_v1(
    scheme_id: &[u8; 32],
    wallet_id: &[u8; 32],
    challenge: &[u8; 32],
    new_attested_key: &KagemushaDevicePublicKeyV1,
) -> Vec<u8> {
    WalletTranscriptV1::with_capacity(KAGEMUSHA_WALLET_RENEWAL_KEY_BINDING_TRANSCRIPT_BYTES_V1)
        .u16(KAGEMUSHA_WALLET_VERSION_V1)
        .digest(scheme_id)
        .digest(wallet_id)
        .digest(challenge)
        .key(new_attested_key)
        .finish()
}

/// App Attest renewal assertion `clientDataHash`, passed unchanged to the platform:
/// `H("renewal-assertion", renewal-challenge transcript)`.
#[must_use]
pub fn kagemusha_wallet_renewal_assertion_client_data_hash_v1(
    scheme_id: &[u8; 32],
    wallet_id: &[u8; 32],
    credential_digest: &[u8; 32],
    challenge: &[u8; 32],
) -> [u8; 32] {
    kagemusha_wallet_digest_v1(
        Role::RenewalAssertion,
        &kagemusha_wallet_renewal_challenge_transcript_v1(
            scheme_id,
            wallet_id,
            credential_digest,
            challenge,
        ),
    )
}

/// One original DER attestation certificate.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletDerCertificateV1"
)]
pub struct KagemushaWalletDerCertificateV1 {
    /// Original DER bytes, at most [`KAGEMUSHA_WALLET_DER_CERTIFICATE_MAX_BYTES_V1`].
    pub der: Vec<u8>,
}

/// Fresh platform evidence carried by a renewal request (design C9).
///
/// Android attests a newly generated key whose attestation challenge is the renewal
/// challenge; iPhone supplies an assertion by the enrolled App Attest key.
// Android carries a fixed key and signature inline beside its chain; boxing them would add
// an allocation to a bounded, rarely built online request.
#[allow(variant_size_differences)]
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletRenewalEvidenceV1"
)]
pub enum KagemushaWalletRenewalEvidenceV1 {
    /// Android `KeyMint` renewal evidence.
    #[codec(index = 1)]
    Android {
        /// Newly generated attested key.
        new_attested_key: KagemushaDevicePublicKeyV1,
        /// Payment-key signature over the `kgwrnkb1` signing message.
        key_binding_signature: KagemushaDeviceSignatureV1,
        /// Original attestation chain, leaf first.
        chain: Vec<KagemushaWalletDerCertificateV1>,
    },
    /// Apple App Attest renewal evidence.
    #[codec(index = 2)]
    Apple {
        /// Original App Attest assertion over the renewal `clientDataHash`.
        assertion: Vec<u8>,
    },
}

impl KagemushaWalletRenewalEvidenceV1 {
    /// Freeze Android renewal evidence: the payment key signs the newly attested key.
    ///
    /// # Errors
    ///
    /// Rejects a non-Android credential, invalid chain bounds, or a key-binding signature
    /// that does not verify under the payment key.
    pub fn android_signed(
        credential: &KagemushaWalletCredentialV1,
        challenge: &[u8; 32],
        new_attested_key: KagemushaDevicePublicKeyV1,
        key_binding_output: KagemushaWalletSignerOutputV1<'_>,
        chain: Vec<KagemushaWalletDerCertificateV1>,
    ) -> WalletResult<Self> {
        if !credential.body.evidence_kind.is_android() {
            return Err(invalid_v1("renewal.evidence"));
        }
        let key_binding_signature = kagemusha_wallet_freeze_signature_v1(
            &credential.body.payment_key,
            Domain::RenewalKeyBinding,
            &kagemusha_wallet_signing_message_v1(
                Domain::RenewalKeyBinding,
                &kagemusha_wallet_renewal_key_binding_transcript_v1(
                    &credential.body.scheme_id,
                    &credential.body.wallet_id,
                    challenge,
                    &new_attested_key,
                ),
            ),
            key_binding_output,
        )?;
        let evidence = Self::Android {
            new_attested_key,
            key_binding_signature,
            chain,
        };
        evidence.validate()?;
        Ok(evidence)
    }

    /// Transcript tag; equal to the Norito wire tag.
    #[must_use]
    pub const fn tag(&self) -> u8 {
        match self {
            Self::Android { .. } => 1,
            Self::Apple { .. } => 2,
        }
    }

    /// Validate the evidence bounds.
    ///
    /// # Errors
    ///
    /// Rejects a chain outside `2..=8` certificates, an empty or oversized certificate, a chain
    /// above [`KAGEMUSHA_WALLET_RENEWAL_ANDROID_CHAIN_MAX_BYTES_V1`] DER bytes in total, or an
    /// empty or oversized assertion.
    pub fn validate(&self) -> WalletResult<()> {
        match self {
            Self::Android {
                new_attested_key,
                key_binding_signature,
                chain,
            } => {
                new_attested_key.validate()?;
                key_binding_signature.validate()?;
                if !(KAGEMUSHA_WALLET_RENEWAL_ANDROID_CHAIN_MIN_V1
                    ..=KAGEMUSHA_WALLET_RENEWAL_ANDROID_CHAIN_MAX_V1)
                    .contains(&chain.len())
                {
                    return Err(invalid_v1("renewal.chain"));
                }
                if chain.iter().any(|certificate| {
                    certificate.der.is_empty()
                        || certificate.der.len() > KAGEMUSHA_WALLET_DER_CERTIFICATE_MAX_BYTES_V1
                }) {
                    return Err(invalid_v1("renewal.chain.der"));
                }
                let total = chain.iter().try_fold(0_usize, |total, certificate| {
                    total
                        .checked_add(certificate.der.len())
                        .ok_or_else(|| overflow_v1("renewal.chain.bytes"))
                })?;
                if total > KAGEMUSHA_WALLET_RENEWAL_ANDROID_CHAIN_MAX_BYTES_V1 {
                    return Err(invalid_v1("renewal.chain.bytes"));
                }
            }
            Self::Apple { assertion } => {
                if assertion.is_empty()
                    || assertion.len() > KAGEMUSHA_WALLET_RENEWAL_APPLE_ASSERTION_MAX_BYTES_V1
                {
                    return Err(invalid_v1("renewal.assertion"));
                }
            }
        }
        Ok(())
    }

    /// Evidence digest of the original fresh platform bytes, for the renewed credential.
    ///
    /// # Errors
    ///
    /// Rejects evidence whose platform differs from `kind`, or what
    /// [`kagemusha_wallet_evidence_digest_v1`] rejects.
    pub fn evidence_digest(&self, kind: KagemushaWalletEvidenceKindV1) -> WalletResult<[u8; 32]> {
        match self {
            Self::Android { chain, .. } if kind.is_android() => {
                let items: Vec<&[u8]> = chain
                    .iter()
                    .map(|certificate| certificate.der.as_slice())
                    .collect();
                kagemusha_wallet_evidence_digest_v1(kind, &items)
            }
            Self::Apple { assertion } if !kind.is_android() => {
                kagemusha_wallet_evidence_digest_v1(kind, &[assertion.as_slice()])
            }
            _ => Err(invalid_v1("renewal.evidence")),
        }
    }
}

/// Online attestation-lease renewal request (§2.2, design §2.5 and C9).
///
/// It carries payment-key possession over the issuer's fresh challenge and the fresh platform
/// evidence. The issuer verifies the platform evidence (including that a new Android
/// attestation challenge equals `challenge`) and applies its current enrollment policy.
// TODO(G5): the Torii renewal family verifies the original platform chain or assertion.
#[derive(Debug, Clone, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletRenewalRequestV1"
)]
pub struct KagemushaWalletRenewalRequestV1 {
    /// Wire version; exactly [`KAGEMUSHA_WALLET_VERSION_V1`].
    pub version: u16,
    /// Credential scheme.
    pub scheme_id: [u8; 32],
    /// Renewing wallet.
    pub wallet_id: [u8; 32],
    /// Digest of the credential being renewed.
    pub credential_digest: [u8; 32],
    /// Fresh issuer renewal challenge.
    pub challenge: [u8; 32],
    /// Payment-key signature over the `kgwrnch1` signing message.
    pub possession_signature: KagemushaDeviceSignatureV1,
    /// Fresh platform evidence.
    pub evidence: KagemushaWalletRenewalEvidenceV1,
}

impl KagemushaWalletRenewalRequestV1 {
    /// Freeze a renewal request for `credential` with the payment key's possession signature.
    ///
    /// # Errors
    ///
    /// Rejects an invalid credential, mismatched evidence, or signatures that do not verify.
    pub fn sign(
        credential: &KagemushaWalletCredentialV1,
        challenge: [u8; 32],
        possession_output: KagemushaWalletSignerOutputV1<'_>,
        evidence: KagemushaWalletRenewalEvidenceV1,
    ) -> WalletResult<Self> {
        credential.validate()?;
        let credential_digest = credential.credential_digest();
        let possession_signature = kagemusha_wallet_freeze_signature_v1(
            &credential.body.payment_key,
            Domain::RenewalChallenge,
            &kagemusha_wallet_signing_message_v1(
                Domain::RenewalChallenge,
                &kagemusha_wallet_renewal_challenge_transcript_v1(
                    &credential.body.scheme_id,
                    &credential.body.wallet_id,
                    &credential_digest,
                    &challenge,
                ),
            ),
            possession_output,
        )?;
        let request = Self {
            version: KAGEMUSHA_WALLET_VERSION_V1,
            scheme_id: credential.body.scheme_id,
            wallet_id: credential.body.wallet_id,
            credential_digest,
            challenge,
            possession_signature,
            evidence,
        };
        request.verify(credential)?;
        Ok(request)
    }

    /// Exact `renewal-challenge` transcript of this request.
    #[must_use]
    pub fn possession_transcript(&self) -> Vec<u8> {
        kagemusha_wallet_renewal_challenge_transcript_v1(
            &self.scheme_id,
            &self.wallet_id,
            &self.credential_digest,
            &self.challenge,
        )
    }

    /// App Attest `clientDataHash` the Apple assertion must cover.
    #[must_use]
    pub fn assertion_client_data_hash(&self) -> [u8; 32] {
        kagemusha_wallet_renewal_assertion_client_data_hash_v1(
            &self.scheme_id,
            &self.wallet_id,
            &self.credential_digest,
            &self.challenge,
        )
    }

    /// Validate the request's self-contained fields.
    ///
    /// # Errors
    ///
    /// Rejects another version, zero bindings, or invalid evidence bounds.
    pub fn validate(&self) -> WalletResult<()> {
        require_version_v1("renewal.version", self.version)?;
        require_nonzero_v1("renewal.scheme_id", &self.scheme_id)?;
        require_nonzero_v1("renewal.wallet_id", &self.wallet_id)?;
        require_nonzero_v1("renewal.credential_digest", &self.credential_digest)?;
        require_nonzero_v1("renewal.challenge", &self.challenge)?;
        self.possession_signature.validate()?;
        self.evidence.validate()
    }

    /// Verify the request against the credential it renews.
    ///
    /// # Errors
    ///
    /// Rejects an invalid request or credential, another scheme, wallet or credential digest,
    /// evidence for another platform, or payment-key signatures that do not verify.
    pub fn verify(&self, credential: &KagemushaWalletCredentialV1) -> WalletResult<()> {
        self.validate()?;
        credential.validate()?;
        require_scheme_v1(
            "renewal.scheme_id",
            &self.scheme_id,
            &credential.body.scheme_id,
        )?;
        if self.wallet_id != credential.body.wallet_id {
            return Err(invalid_v1("renewal.wallet_id"));
        }
        if self.credential_digest != credential.credential_digest() {
            return Err(invalid_v1("renewal.credential_digest"));
        }
        let payment_key = &credential.body.payment_key;
        kagemusha_wallet_verify_signature_v1(
            payment_key,
            Domain::RenewalChallenge,
            &kagemusha_wallet_signing_message_v1(
                Domain::RenewalChallenge,
                &self.possession_transcript(),
            ),
            &self.possession_signature,
        )?;
        match (&self.evidence, credential.body.evidence_kind.is_android()) {
            (
                KagemushaWalletRenewalEvidenceV1::Android {
                    new_attested_key,
                    key_binding_signature,
                    ..
                },
                true,
            ) => kagemusha_wallet_verify_signature_v1(
                payment_key,
                Domain::RenewalKeyBinding,
                &kagemusha_wallet_signing_message_v1(
                    Domain::RenewalKeyBinding,
                    &kagemusha_wallet_renewal_key_binding_transcript_v1(
                        &self.scheme_id,
                        &self.wallet_id,
                        &self.challenge,
                        new_attested_key,
                    ),
                ),
                key_binding_signature,
            ),
            (KagemushaWalletRenewalEvidenceV1::Apple { .. }, false) => Ok(()),
            _ => Err(invalid_v1("renewal.evidence")),
        }
    }

    /// Validate and encode the bounded canonical frame.
    ///
    /// # Errors
    ///
    /// Rejects an invalid request or an oversized frame.
    pub fn to_canonical_bytes(&self) -> WalletResult<Vec<u8>> {
        self.validate()?;
        encode_frame_v1(self, KAGEMUSHA_WALLET_RENEWAL_REQUEST_MAX_BYTES_V1)
    }

    /// Decode one canonical renewal request frame for `expected_scheme_id`.
    ///
    /// # Errors
    ///
    /// Rejects, in order, an oversized frame, a noncanonical frame, another version, another
    /// scheme, and invalid fields.
    pub fn decode_canonical(bytes: &[u8], expected_scheme_id: &[u8; 32]) -> WalletResult<Self> {
        let request: Self = decode_frame_v1(bytes, KAGEMUSHA_WALLET_RENEWAL_REQUEST_MAX_BYTES_V1)?;
        request.require_versions()?;
        require_scheme_v1("renewal.scheme_id", &request.scheme_id, expected_scheme_id)?;
        request.validate()?;
        Ok(request)
    }
}

// ---------------------------------------------------------------------------------------
// Artifact manifest (§§2.3, 3.2, 9; design C4)
// ---------------------------------------------------------------------------------------

/// Body of the signed artifact manifest carrying every runtime binding of the frozen
/// artifact set.
///
/// Verifiers require `relation_id` to equal the scheme's and every statement's, and
/// `provider_contract` to equal the scheme's.
// TODO(G3/G6): the reworked release install path carries this manifest, and every runtime
// comparison of native profile, Eq/Ep protocol, relation and inventory digests moves here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletArtifactManifestBodyV1"
)]
pub struct KagemushaWalletArtifactManifestBodyV1 {
    /// Wire version; exactly [`KAGEMUSHA_WALLET_VERSION_V1`].
    pub version: u16,
    /// Raw 32-byte genesis `NetworkId`.
    pub network_id: [u8; 32],
    /// Relation identity recomputed from the five bindings below.
    pub relation_id: [u8; 32],
    /// Eq protocol digest.
    pub eq_protocol_digest: [u8; 32],
    /// Ep protocol digest.
    pub ep_protocol_digest: [u8; 32],
    /// Native profile digest.
    pub native_profile_digest: [u8; 32],
    /// Verifying-key-set digest of the G3 artifact set.
    pub verifying_key_set_digest: [u8; 32],
    /// Artifact inventory digest of the G3 artifact set.
    pub artifact_inventory_digest: [u8; 32],
    /// Provider contract of the scheme.
    pub provider_contract: [u8; 32],
    /// Certificate digest of the Artifact-role signer.
    pub signer_certificate: [u8; 32],
}

impl KagemushaWalletArtifactManifestBodyV1 {
    /// Exact `artifact-manifest-body` transcript.
    #[must_use]
    pub fn transcript(&self) -> Vec<u8> {
        WalletTranscriptV1::with_capacity(
            KAGEMUSHA_WALLET_ARTIFACT_MANIFEST_BODY_TRANSCRIPT_BYTES_V1,
        )
        .u16(self.version)
        .digest(&self.network_id)
        .digest(&self.relation_id)
        .digest(&self.eq_protocol_digest)
        .digest(&self.ep_protocol_digest)
        .digest(&self.native_profile_digest)
        .digest(&self.verifying_key_set_digest)
        .digest(&self.artifact_inventory_digest)
        .digest(&self.provider_contract)
        .digest(&self.signer_certificate)
        .finish()
    }

    /// Canonical 32-byte signing message `m = P_bytes(d, transcript)` (§8).
    #[must_use]
    pub fn signing_message(&self) -> [u8; 32] {
        kagemusha_wallet_signing_message_v1(Domain::ArtifactManifest, &self.transcript())
    }

    /// Relation identity recomputed from this body's bindings.
    #[must_use]
    pub fn recomputed_relation_id(&self) -> [u8; 32] {
        kagemusha_wallet_relation_id_v1(
            &self.eq_protocol_digest,
            &self.ep_protocol_digest,
            &self.native_profile_digest,
            &self.verifying_key_set_digest,
            &self.artifact_inventory_digest,
        )
    }

    /// Validate the body's self-contained rules.
    ///
    /// # Errors
    ///
    /// Rejects another version, an invalid network, zero bindings, a relation that does not
    /// recompute, or a provider contract other than the V1 contract.
    pub fn validate(&self) -> WalletResult<()> {
        require_version_v1("artifact_manifest.version", self.version)?;
        validate_network_id_v1(&self.network_id)?;
        for (field, digest) in [
            (
                "artifact_manifest.eq_protocol_digest",
                &self.eq_protocol_digest,
            ),
            (
                "artifact_manifest.ep_protocol_digest",
                &self.ep_protocol_digest,
            ),
            (
                "artifact_manifest.native_profile_digest",
                &self.native_profile_digest,
            ),
            (
                "artifact_manifest.verifying_key_set_digest",
                &self.verifying_key_set_digest,
            ),
            (
                "artifact_manifest.artifact_inventory_digest",
                &self.artifact_inventory_digest,
            ),
            (
                "artifact_manifest.signer_certificate",
                &self.signer_certificate,
            ),
        ] {
            require_nonzero_v1(field, digest)?;
        }
        if self.relation_id != self.recomputed_relation_id() {
            return Err(invalid_v1("artifact_manifest.relation_id"));
        }
        if self.provider_contract != kagemusha_wallet_provider_contract_v1() {
            return Err(invalid_v1("artifact_manifest.provider_contract"));
        }
        Ok(())
    }

    fn require_scheme(&self, scheme: &KagemushaWalletSchemeV1) -> WalletResult<()> {
        require_scheme_v1(
            "artifact_manifest.network_id",
            &self.network_id,
            &scheme.network_id,
        )?;
        require_scheme_v1(
            "artifact_manifest.relation_id",
            &self.relation_id,
            &scheme.relation_id,
        )?;
        require_scheme_v1(
            "artifact_manifest.provider_contract",
            &self.provider_contract,
            &scheme.provider_contract,
        )
    }
}

/// Artifact manifest signed by an Artifact-role key under `kgwartf1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(
    name = "iroha_data_model::kagemusha::kagemusha_wallet_v1::KagemushaWalletArtifactManifestV1"
)]
pub struct KagemushaWalletArtifactManifestV1 {
    /// Signed body.
    pub body: KagemushaWalletArtifactManifestBodyV1,
    /// Artifact-role signature over the `kgwartf1` signing message.
    pub signature: KagemushaDeviceSignatureV1,
}

impl KagemushaWalletArtifactManifestV1 {
    /// Freeze an Artifact-role signature over `body`.
    ///
    /// # Errors
    ///
    /// Rejects an invalid body, a signer certificate that is not the body's Artifact-role
    /// signer, or a signature that does not verify under it.
    pub fn sign(
        body: KagemushaWalletArtifactManifestBodyV1,
        signer_certificate: &KagemushaWalletSignerCertificateV1,
        signer_output: KagemushaWalletSignerOutputV1<'_>,
    ) -> WalletResult<Self> {
        body.validate()?;
        signer_certificate.validate()?;
        if signer_certificate.certificate_digest() != body.signer_certificate {
            return Err(invalid_v1("artifact_manifest.signer_certificate"));
        }
        if signer_certificate.body.role != KagemushaWalletSignerRoleV1::Artifact {
            return Err(invalid_v1("certificate.role"));
        }
        let signature = kagemusha_wallet_freeze_signature_v1(
            &signer_certificate.body.key,
            Domain::ArtifactManifest,
            &body.signing_message(),
            signer_output,
        )?;
        Ok(Self { body, signature })
    }

    /// Manifest digest `H("artifact-manifest", m || signature)`.
    #[must_use]
    pub fn manifest_digest(&self) -> [u8; 32] {
        kagemusha_wallet_signed_object_digest_v1(
            Role::ArtifactManifest,
            &self.body.signing_message(),
            &self.signature,
        )
    }

    /// Validate the manifest's self-contained rules.
    ///
    /// # Errors
    ///
    /// Rejects an invalid body or a non-canonical signature encoding.
    pub fn validate(&self) -> WalletResult<()> {
        self.body.validate()?;
        self.signature.validate()?;
        Ok(())
    }

    /// Verify the manifest for `scheme` under its Artifact-role `signer_certificate`.
    ///
    /// # Errors
    ///
    /// Rejects an invalid manifest, another network, relation or provider contract, a
    /// certificate that is not the manifest's Artifact-role signer under `scheme`, or a
    /// signature that does not verify.
    pub fn verify(
        &self,
        scheme: &KagemushaWalletSchemeV1,
        signer_certificate: &KagemushaWalletSignerCertificateV1,
    ) -> WalletResult<()> {
        self.validate()?;
        self.body.require_scheme(scheme)?;
        if signer_certificate.certificate_digest() != self.body.signer_certificate {
            return Err(invalid_v1("artifact_manifest.signer_certificate"));
        }
        signer_certificate.verify_role(scheme, KagemushaWalletSignerRoleV1::Artifact)?;
        kagemusha_wallet_verify_signature_v1(
            &signer_certificate.body.key,
            Domain::ArtifactManifest,
            &self.body.signing_message(),
            &self.signature,
        )
    }

    /// Validate and encode the bounded canonical frame.
    ///
    /// # Errors
    ///
    /// Rejects an invalid manifest or an oversized frame.
    pub fn to_canonical_bytes(&self) -> WalletResult<Vec<u8>> {
        self.validate()?;
        encode_frame_v1(self, KAGEMUSHA_WALLET_ARTIFACT_MANIFEST_MAX_BYTES_V1)
    }

    /// Decode one canonical manifest frame bound to `scheme`.
    ///
    /// The Artifact-role signature is checked separately by [`Self::verify`].
    ///
    /// # Errors
    ///
    /// Rejects, in order, an oversized frame, a noncanonical frame, another version, another
    /// network, relation or provider contract, and invalid fields.
    pub fn decode_canonical(bytes: &[u8], scheme: &KagemushaWalletSchemeV1) -> WalletResult<Self> {
        let manifest: Self =
            decode_frame_v1(bytes, KAGEMUSHA_WALLET_ARTIFACT_MANIFEST_MAX_BYTES_V1)?;
        manifest.require_versions()?;
        manifest.body.require_scheme(scheme)?;
        manifest.validate()?;
        Ok(manifest)
    }
}

// ---------------------------------------------------------------------------------------
// Version fields (design §0 decode order)
// ---------------------------------------------------------------------------------------

impl WalletVersionsV1 for KagemushaWalletSchemeV1 {
    fn require_versions(&self) -> WalletResult<()> {
        require_version_v1("scheme.version", self.version)
    }
}

impl WalletVersionsV1 for KagemushaWalletAssetScopeV1 {
    fn require_versions(&self) -> WalletResult<()> {
        require_version_v1("asset_scope.version", self.version)
    }
}

impl WalletVersionsV1 for KagemushaWalletSignerCertificateV1 {
    fn require_versions(&self) -> WalletResult<()> {
        require_version_v1("certificate.version", self.body.version)
    }
}

impl WalletVersionsV1 for KagemushaWalletCertificateSetV1 {
    fn require_versions(&self) -> WalletResult<()> {
        self.certificates
            .iter()
            .try_for_each(WalletVersionsV1::require_versions)
    }
}

impl WalletVersionsV1 for KagemushaWalletCredentialV1 {
    fn require_versions(&self) -> WalletResult<()> {
        require_version_v1("credential.version", self.body.version)
    }
}

impl WalletVersionsV1 for KagemushaWalletRenewalRequestV1 {
    fn require_versions(&self) -> WalletResult<()> {
        require_version_v1("renewal.version", self.version)
    }
}

impl WalletVersionsV1 for KagemushaWalletArtifactManifestV1 {
    fn require_versions(&self) -> WalletResult<()> {
        require_version_v1("artifact_manifest.version", self.body.version)
    }
}
