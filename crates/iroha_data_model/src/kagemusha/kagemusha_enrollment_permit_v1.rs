//! NEW issuer-authenticated pre-key authorization, separate from monetary wallet objects.
//!
//! An Enrollment-role signer authenticates the original E1, attempt and selected originals
//! before payment-key generation. This record is not a Credential, provider receipt, proof,
//! hardware qualification or a Native generation capability. The independently installed
//! Scheme and expected service/release/account selection remain required verifier inputs.
//! Its new signature grammar never reuses a monetary Poseidon signing domain or sigma slot.

use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};
use sha2::{Digest as _, Sha256};

use super::kagemusha_wallet_v1::{
    KAGEMUSHA_WALLET_CERTIFICATE_MAX_BYTES_V1, KAGEMUSHA_WALLET_SCHEME_MAX_BYTES_V1,
    KagemushaDeviceSignatureV1, KagemushaWalletEnrollmentChallengeV1, KagemushaWalletSchemeV1,
    KagemushaWalletSignerCertificateV1, KagemushaWalletSignerRoleV1,
    KagemushaWalletValidationErrorV1,
};

/// The complete canonical frame cap, checked before decoding.
pub const KAGEMUSHA_ENROLLMENT_PERMIT_MAX_BYTES_V1: usize = 2048;
/// Exact new fixed-layout signed body length.
pub const KAGEMUSHA_ENROLLMENT_PERMIT_TRANSCRIPT_BYTES_V1: usize = 574;
/// New nonmonetary message domain. No existing Credential/Certificate domain is reused.
pub const KAGEMUSHA_ENROLLMENT_PERMIT_MESSAGE_DOMAIN_V1: &[u8] =
    b"iroha:kagemusha:pre-key-permit:v1\0";
/// New nonmonetary message domain for an issuer-authenticated expired E1 proof.
pub const KAGEMUSHA_ENROLLMENT_EXPIRY_PROOF_MESSAGE_DOMAIN_V1: &[u8] =
    b"iroha:kagemusha:pre-key-expired:v1\0";
const ORIGINALS_DOMAIN: &[u8] = b"iroha:kagemusha:pre-key-originals:v1\0";
const SCOPE_DOMAIN: &[u8] = b"iroha:kagemusha:pre-key-scope:v1\0";

type Result<T> = core::result::Result<T, KagemushaWalletValidationErrorV1>;
fn invalid(field: &'static str) -> KagemushaWalletValidationErrorV1 {
    KagemushaWalletValidationErrorV1::InvalidField { field }
}
fn nonzero(field: &'static str, value: &[u8; 32]) -> Result<()> {
    if *value == [0; 32] {
        Err(invalid(field))
    } else {
        Ok(())
    }
}

/// Actual platform selected by the issuer's independently approved policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(name = "iroha.kagemusha.enrollment.permit.platform.v1")]
pub enum KagemushaEnrollmentPermitPlatformV1 {
    /// Android `KeyMint` TEE/`StrongBox` policy; it is not a finite-use-key requirement.
    #[codec(index = 1)]
    Android,
    /// Apple production App Attest policy, distinct from Android DER evidence.
    #[codec(index = 2)]
    Apple,
}
impl KagemushaEnrollmentPermitPlatformV1 {
    /// Fixed transcript tag.
    pub const fn tag(self) -> u8 {
        match self {
            Self::Android => 1,
            Self::Apple => 2,
        }
    }
}

/// The role of a fresh Native dispatch. It never resets an original attempt or deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(name = "iroha.kagemusha.enrollment.permit.purpose.v1")]
pub enum KagemushaEnrollmentPermitPurposeV1 {
    /// An explicitly requested original enrollment; retry keeps the original E1/deadline.
    #[codec(index = 1)]
    Fresh,
    /// Fresh observation of the unchanged original attempt before any resumed mutation.
    #[codec(index = 2)]
    Resume,
}
impl KagemushaEnrollmentPermitPurposeV1 {
    /// Fixed transcript tag.
    pub const fn tag(self) -> u8 {
        match self {
            Self::Fresh => 1,
            Self::Resume => 2,
        }
    }
}

/// Closed labels for exact independently selected scope preimages. These hashes are DATA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KagemushaEnrollmentPermitScopeRoleV1 {
    /// Exact approved HTTPS service origin bytes, with no caller-selected normalization.
    ServiceOrigin,
    /// Exact authenticated FI identity bytes.
    Fi,
    /// Exact authenticated actor identity bytes.
    Actor,
    /// Exact approved release selection original, distinct from the installed manifest.
    Release,
}
impl KagemushaEnrollmentPermitScopeRoleV1 {
    fn label(self) -> &'static [u8] {
        match self {
            Self::ServiceOrigin => b"service-origin",
            Self::Fi => b"fi",
            Self::Actor => b"actor",
            Self::Release => b"release",
        }
    }
}

/// Hash exact scope DATA with a closed purpose label; a hash alone grants no selection.
/// # Errors
/// Rejects an empty or oversized original. Native must independently hold the selected one.
pub fn kagemusha_enrollment_permit_scope_digest_v1(
    role: KagemushaEnrollmentPermitScopeRoleV1,
    original: &[u8],
) -> Result<[u8; 32]> {
    if original.is_empty() || original.len() > 16_384 {
        return Err(invalid("permit.scope_original"));
    }
    let mut hash = Sha256::new();
    hash.update(SCOPE_DOMAIN);
    hash.update(role.label());
    hash.update([0]);
    hash.update((original.len() as u64).to_le_bytes());
    hash.update(original);
    Ok(hash.finalize().into())
}

/// Bind the exact seven original canonical frames in this fixed order: E1, Scheme, app
/// policy, enrollment policy, Enrollment certificate, existing `AccountId`, asset scope.
/// No DER root, Play token, private key or bearer credential is carried here.
/// # Errors
/// Rejects missing or oversized originals. This does not decode or authenticate a frame.
pub fn kagemusha_enrollment_permit_originals_digest_v1(originals: [&[u8]; 7]) -> Result<[u8; 32]> {
    let bounds = [
        1024,
        KAGEMUSHA_WALLET_SCHEME_MAX_BYTES_V1,
        1024,
        1024,
        KAGEMUSHA_WALLET_CERTIFICATE_MAX_BYTES_V1,
        4096,
        1024,
    ];
    let mut hash = Sha256::new();
    hash.update(ORIGINALS_DOMAIN);
    for (tag, (original, bound)) in (1u8..=7).zip(originals.into_iter().zip(bounds)) {
        if original.is_empty() || original.len() > bound {
            return Err(invalid("permit.original_bound"));
        }
        hash.update([tag]);
        hash.update((original.len() as u64).to_le_bytes());
        hash.update(original);
    }
    Ok(hash.finalize().into())
}

/// NEW exact signed pre-key body. Original service time is authenticated by the issuer;
/// Native freshness additionally requires its live unpredictable dispatch nonce and actual
/// sleep-inclusive elapsed budget. A decoded body is never a generation capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(name = "iroha.kagemusha.enrollment.permit.body.v1")]
pub struct KagemushaEnrollmentPermitBodyV1 {
    /// Exactly1; this is a new grammar, not a retired enrollment format.
    pub version: u16,
    /// Exact selected platform.
    pub platform: KagemushaEnrollmentPermitPlatformV1,
    /// Exact Native dispatch role.
    pub purpose: KagemushaEnrollmentPermitPurposeV1,
    /// The unchanged original issuer E1, including original issuer nonce and all six digests.
    pub challenge: KagemushaWalletEnrollmentChallengeV1,
    /// Raw genesis `NetworkId`, independently selected through the held Scheme.
    pub network_id: [u8; 32],
    /// Actual immutable installed manifest identity.
    pub manifest_digest: [u8; 32],
    /// Exact approved release-selection scope digest.
    pub release_digest: [u8; 32],
    /// Exact independently selected service-origin scope digest.
    pub service_origin_digest: [u8; 32],
    /// Authenticated FI identity scope digest.
    pub fi_digest: [u8; 32],
    /// Authenticated actor identity scope digest.
    pub actor_digest: [u8; 32],
    /// Original server-selected attempt, unchanged across retries and observations.
    pub attempt_id: [u8; 32],
    /// Original Native client nonce used by the stable attempt; never replaced on resume.
    pub client_nonce: [u8; 32],
    /// Fresh unpredictable Native dispatch nonce; never restored as a live capability.
    pub native_dispatch_nonce: [u8; 32],
    /// Exact seven original frames, in the fixed order above.
    pub originals_digest: [u8; 32],
    /// Exact rooted current Enrollment-role certificate digest.
    pub enrollment_certificate: [u8; 32],
    /// Original issuer creation time; retry never refreshes it.
    pub created_at_ms: u64,
    /// Original issuer deadline; no observation or resume extends it.
    pub expires_at_ms: u64,
    /// Fresh actual issuer clock sampled for THIS nonce/signature, including Fresh retries.
    pub observed_at_ms: u64,
}

/// Exact issuer statement that a retained E1 challenge is terminally expired.
///
/// This proof authorizes only Native's narrow pre-E2 cleanup path. It does not
/// authorize a permit, key generation, E5, E6 or any ledger action. Every field
/// binds the proof to one retained dispatch and permit original.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(name = "iroha.kagemusha.enrollment.expiry-proof.body.v1")]
pub struct KagemushaEnrollmentExpiryProofBodyV1 {
    /// Wire version; exactly 1.
    pub version: u16,
    /// Closed refusal code; exactly `ChallengeExpired` (10).
    pub refusal_code: u16,
    /// Native Client request identity.
    pub request_id: [u8; 32],
    /// SHA-256 of the exact dispatch original.
    pub dispatch_sha256: [u8; 32],
    /// SHA-256 of the exact Accepted permit original.
    pub permit_sha256: [u8; 32],
    /// Issuer attempt identity.
    pub attempt_id: [u8; 32],
    /// Challenge digest in the accepted permit.
    pub challenge_digest: [u8; 32],
    /// The immutable E1 deadline that the issuer evaluated.
    pub expires_at_ms: u64,
    /// Issuer observation proving the deadline had passed.
    pub observed_at_ms: u64,
}

impl KagemushaEnrollmentExpiryProofBodyV1 {
    /// Construct the fixed refusal statement for one exact attempt.
    #[must_use]
    pub const fn new(
        request_id: [u8; 32],
        dispatch_sha256: [u8; 32],
        permit_sha256: [u8; 32],
        attempt_id: [u8; 32],
        challenge_digest: [u8; 32],
        expires_at_ms: u64,
        observed_at_ms: u64,
    ) -> Self {
        Self {
            version: 1,
            refusal_code: 10,
            request_id,
            dispatch_sha256,
            permit_sha256,
            attempt_id,
            challenge_digest,
            expires_at_ms,
            observed_at_ms,
        }
    }

    /// Canonical signer message. Expiry proof uses SHA-256 and a distinct nonmonetary domain.
    ///
    /// # Errors
    /// Returns an error if canonical encoding of the proof body fails.
    pub fn signing_message(&self) -> Result<[u8; 32]> {
        let bytes = norito::encode_canonical(self).map_err(|_| invalid("expiry-proof.body"))?;
        let mut hash = Sha256::new();
        hash.update(KAGEMUSHA_ENROLLMENT_EXPIRY_PROOF_MESSAGE_DOMAIN_V1);
        hash.update((bytes.len() as u64).to_le_bytes());
        hash.update(bytes);
        Ok(hash.finalize().into())
    }

    /// Structural validation without signer authority.
    ///
    /// # Errors
    /// Rejects an unsupported version or refusal code, a zero identity or deadline,
    /// or an observation before the expiry deadline.
    pub fn validate(&self) -> Result<()> {
        if self.version != 1
            || self.refusal_code != 10
            || self.request_id == [0; 32]
            || self.dispatch_sha256 == [0; 32]
            || self.permit_sha256 == [0; 32]
            || self.attempt_id == [0; 32]
            || self.challenge_digest == [0; 32]
            || self.expires_at_ms == 0
            || self.observed_at_ms < self.expires_at_ms
        {
            return Err(invalid("expiry-proof.body"));
        }
        Ok(())
    }
}

/// Issuer-signed proof used only to release an Accepted/no-Slot attempt after E1 expiry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(name = "iroha.kagemusha.enrollment.expiry-proof.v1")]
pub struct KagemushaEnrollmentExpiryProofV1 {
    /// Exact expiry statement.
    pub body: KagemushaEnrollmentExpiryProofBodyV1,
    /// Signature by the installed Enrollment-role signer.
    pub signature: KagemushaDeviceSignatureV1,
}

impl KagemushaEnrollmentExpiryProofV1 {
    /// Freeze a canonical DER issuer signature over the expiry statement.
    ///
    /// # Errors
    /// Rejects an invalid body or a malformed or noncanonical DER signature.
    pub fn from_issuer_der(
        body: KagemushaEnrollmentExpiryProofBodyV1,
        _certificate: &KagemushaWalletSignerCertificateV1,
        original_der: &[u8],
    ) -> Result<Self> {
        body.validate()?;
        let signature = KagemushaDeviceSignatureV1::from_der_normalizing_low_s(original_der)?;
        Ok(Self { body, signature })
    }

    /// Verify the proof under the installed Scheme and Enrollment certificate.
    ///
    /// # Errors
    /// Returns an error if body validation or encoding, Enrollment-certificate
    /// verification, or proof signature verification fails.
    pub fn verify(
        &self,
        scheme: &KagemushaWalletSchemeV1,
        certificate: &KagemushaWalletSignerCertificateV1,
    ) -> Result<()> {
        self.body.validate()?;
        certificate.verify_role(scheme, KagemushaWalletSignerRoleV1::Enrollment)?;
        self.signature
            .verify(&certificate.body.key, &self.body.signing_message()?)
    }

    /// Encode the bounded canonical proof original.
    ///
    /// # Errors
    /// Rejects an invalid body or signature, or a failure to encode the canonical frame.
    pub fn encode_canonical(&self) -> Result<Vec<u8>> {
        self.body.validate()?;
        self.signature.validate()?;
        norito::encode_canonical(self).map_err(|_| invalid("expiry-proof.frame"))
    }

    /// Decode a canonical proof original; signer verification remains explicit.
    ///
    /// # Errors
    /// Rejects an empty or oversized input, malformed or noncanonical framing,
    /// or an invalid body or signature.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > 4096 {
            return Err(invalid("expiry-proof.frame"));
        }
        let value: Self = norito::decode_canonical_with_limits(
            bytes,
            norito::canonical_decode_limits(bytes.len()),
        )
        .map_err(|_| invalid("expiry-proof.frame"))?;
        value.body.validate()?;
        value.signature.validate()?;
        Ok(value)
    }
}

impl KagemushaEnrollmentPermitBodyV1 {
    /// Structural validation only; real signer/current installation/nonce/elapsed checks follow.
    /// # Errors
    /// Rejects a version/zero identity or an observation outside the unchanged original window.
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err(invalid("permit.version"));
        }
        self.challenge.validate()?;
        for (field, value) in [
            ("permit.network_id", &self.network_id),
            ("permit.manifest", &self.manifest_digest),
            ("permit.release", &self.release_digest),
            ("permit.origin", &self.service_origin_digest),
            ("permit.fi", &self.fi_digest),
            ("permit.actor", &self.actor_digest),
            ("permit.attempt", &self.attempt_id),
            ("permit.client_nonce", &self.client_nonce),
            ("permit.dispatch_nonce", &self.native_dispatch_nonce),
            ("permit.originals", &self.originals_digest),
            ("permit.certificate", &self.enrollment_certificate),
        ] {
            nonzero(field, value)?;
        }
        if self.created_at_ms == 0
            || self.expires_at_ms <= self.created_at_ms
            || self.observed_at_ms < self.created_at_ms
            || self.observed_at_ms >= self.expires_at_ms
        {
            return Err(invalid("permit.original_window"));
        }
        Ok(())
    }

    /// New exact transcript: `LE16version`, platform/purpose tags,194-byte E1 transcript,
    /// eleven32-byte scope/nonce/original/certificate values in field order, then threeLE64times.
    /// # Errors
    /// Rejects invalid body before creating a signing message.
    pub fn transcript(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(KAGEMUSHA_ENROLLMENT_PERMIT_TRANSCRIPT_BYTES_V1);
        bytes.extend_from_slice(&self.version.to_le_bytes());
        bytes.extend_from_slice(&[self.platform.tag(), self.purpose.tag()]);
        bytes.extend_from_slice(&self.challenge.transcript());
        for value in [
            &self.network_id,
            &self.manifest_digest,
            &self.release_digest,
            &self.service_origin_digest,
            &self.fi_digest,
            &self.actor_digest,
            &self.attempt_id,
            &self.client_nonce,
            &self.native_dispatch_nonce,
            &self.originals_digest,
            &self.enrollment_certificate,
        ] {
            bytes.extend_from_slice(value);
        }
        for time in [self.created_at_ms, self.expires_at_ms, self.observed_at_ms] {
            bytes.extend_from_slice(&time.to_le_bytes());
        }
        debug_assert_eq!(bytes.len(), KAGEMUSHA_ENROLLMENT_PERMIT_TRANSCRIPT_BYTES_V1);
        Ok(bytes)
    }

    /// NEW nonmonetary message: SHA256(domain || LE64len(transcript) || transcript).
    /// The actual Enrollment signer signs these32 bytes with ECDSA-P256-SHA256.
    /// # Errors
    /// Rejects an invalid body. No preexisting monetary signature domain is involved.
    pub fn signing_message(&self) -> Result<[u8; 32]> {
        let transcript = self.transcript()?;
        let mut hash = Sha256::new();
        hash.update(KAGEMUSHA_ENROLLMENT_PERMIT_MESSAGE_DOMAIN_V1);
        hash.update((transcript.len() as u64).to_le_bytes());
        hash.update(transcript);
        Ok(hash.finalize().into())
    }
}

/// Signed canonical pre-key permit. Verification never creates a wallet or Native authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Decode, Encode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(name = "iroha.kagemusha.enrollment.permit.v1")]
pub struct KagemushaEnrollmentPermitV1 {
    /// Exact new signed body.
    pub body: KagemushaEnrollmentPermitBodyV1,
    /// Fixed-width low-S ECDSA-P256-SHA256 signature, received bytes never rewritten.
    pub signature: KagemushaDeviceSignatureV1,
}
impl KagemushaEnrollmentPermitV1 {
    /// Freeze a fresh actual issuer DER output. The service/HSM signer stays outside the model.
    /// # Errors
    /// Rejects a wrong rooted role/key/body or an invalid signer output; normalization is fresh-only.
    pub fn from_issuer_der(
        body: KagemushaEnrollmentPermitBodyV1,
        scheme: &KagemushaWalletSchemeV1,
        certificate: &KagemushaWalletSignerCertificateV1,
        original_der: &[u8],
    ) -> Result<Self> {
        let value = Self {
            body,
            signature: KagemushaDeviceSignatureV1::from_der_normalizing_low_s(original_der)?,
        };
        value.verify(scheme, certificate)?;
        Ok(value)
    }

    /// Authenticate the exact new domain/body under the actual rooted Enrollment-role key.
    /// # Errors
    /// Rejects another Scheme/network/certificate/role, noncanonical signature or changed body.
    pub fn verify(
        &self,
        scheme: &KagemushaWalletSchemeV1,
        certificate: &KagemushaWalletSignerCertificateV1,
    ) -> Result<()> {
        self.body.validate()?;
        scheme.validate()?;
        certificate.verify_role(scheme, KagemushaWalletSignerRoleV1::Enrollment)?;
        if self.body.challenge.scheme_id != scheme.scheme_id()
            || self.body.network_id != scheme.network_id
            || self.body.enrollment_certificate != certificate.certificate_digest()
        {
            return Err(invalid("permit.actual_issuer_scope"));
        }
        self.signature
            .verify(&certificate.body.key, &self.body.signing_message()?)
    }

    /// Encode one structurally canonical bounded original; signer verification remains required.
    /// # Errors
    /// Rejects malformed fields/signature or a frame exceeding the complete cap.
    pub fn encode_canonical(&self) -> Result<Vec<u8>> {
        self.body.validate()?;
        self.signature.validate()?;
        let bytes =
            norito::encode_canonical(self).map_err(|_| invalid("permit.canonical_frame"))?;
        if bytes.len() > KAGEMUSHA_ENROLLMENT_PERMIT_MAX_BYTES_V1 {
            return Err(invalid("permit.frame_bound"));
        }
        Ok(bytes)
    }

    /// Bound/canonical-decode then verify against the independently held actual issuer.
    /// # Errors
    /// Rejects an oversized/noncanonical/new-version/changed/wrong-role permit.
    pub fn decode_canonical(
        bytes: &[u8],
        scheme: &KagemushaWalletSchemeV1,
        certificate: &KagemushaWalletSignerCertificateV1,
    ) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > KAGEMUSHA_ENROLLMENT_PERMIT_MAX_BYTES_V1 {
            return Err(invalid("permit.frame_bound"));
        }
        let value: Self = norito::decode_canonical_with_limits(
            bytes,
            norito::canonical_decode_limits(bytes.len()),
        )
        .map_err(|_| invalid("permit.canonical_frame"))?;
        value.verify(scheme, certificate)?;
        Ok(value)
    }
}

#[cfg(test)]
#[path = "kagemusha_enrollment_permit_v1/tests.rs"]
mod tests;
