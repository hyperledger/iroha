//! Challenge-bound enrollment eligibility supplied by a bank or selected scheme operator.
//!
//! A policy is DATA until independently selected from current authenticated issuer configuration,
//! asset/scheme ownership and actual account/actor routing. Signatures attest an observation;
//! they do not replace platform evidence, the Enrollment-role credential signer, or monetary proofs.

use iroha_crypto::{Algorithm, PublicKey, ed25519_parse_public_key, ed25519_parse_signature};
use iroha_schema::IntoSchema;
use norito::{Decode, Encode};
use sha2::{Digest as _, Sha256};

use super::kagemusha_wallet_v1::{
    KagemushaWalletValidationErrorV1, decode_frame_v1, encode_frame_v1,
};

mod template;
pub use template::{KagemushaEligibilityObservationV1, KagemushaEligibilityPolicyTemplateV1};

/// Complete canonical Norito frame limit for each eligibility object, checked before decode.
pub const KAGEMUSHA_ELIGIBILITY_MAX_BYTES_V1: usize = 2048;
type Result<T> = core::result::Result<T, KagemushaWalletValidationErrorV1>;

fn invalid(field: &'static str) -> KagemushaWalletValidationErrorV1 {
    KagemushaWalletValidationErrorV1::InvalidField { field }
}
fn nonzero(value: &[u8; 32]) -> Result<()> {
    if *value == [0; 32] {
        return Err(invalid("eligibility.zero_identity"));
    }
    Ok(())
}
fn hash(domain: &[u8], original: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update((original.len() as u64).to_le_bytes());
    digest.update(original);
    digest.finalize().into()
}

/// Exact authority selected by the issuer; there is no fallback between these arms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(name = "iroha.kagemusha.eligibility.authority.v1")]
pub enum KagemushaEligibilityAuthorityV1 {
    /// The authenticated identity of the user's bank middleware; approval includes required KYC.
    #[codec(index = 1)]
    Bank {
        /// Existing FI scope digest, checked against authenticated account routing.
        fi_digest: [u8; 32],
    },
    /// An operator selected by the authenticated asset/scheme owner.
    /// Token issuers, community operators and Parliament may use this same arm; none is mandatory.
    #[codec(index = 2)]
    SchemeOperator {
        /// Exact operator identity; its current authorization is checked independently.
        operator_digest: [u8; 32],
    },
}

impl KagemushaEligibilityAuthorityV1 {
    /// Exact independently selected provider identity for account/actor routing.
    /// The native dispatch field remains named `fi_digest` for both authority arms.
    #[must_use]
    pub const fn scope_digest(&self) -> [u8; 32] {
        match self {
            Self::Bank { fi_digest } => *fi_digest,
            Self::SchemeOperator { operator_digest } => *operator_digest,
        }
    }
}

/// Current eligibility authority selection, separate from the platform enrollment policy.
///
/// Rotation, revocation and asset/scheme authorization belong to the authenticated issuer
/// owner. Validating or hashing this value does not establish any of those facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(name = "iroha.kagemusha.eligibility.policy.v1")]
pub struct KagemushaEligibilityPolicyV1 {
    /// Exactly one.
    pub version: u16,
    /// Independently authenticated genesis identity.
    pub network_id: [u8; 32],
    /// Exact wallet scheme identity.
    pub scheme_id: [u8; 32],
    /// Exact asset incarnation and scale digest.
    pub asset_digest: [u8; 32],
    /// Positive current authority revision; requests bind the complete policy digest.
    pub revision: u64,
    /// Independently selected bank or authorized scheme operator.
    pub authority: KagemushaEligibilityAuthorityV1,
    /// Canonical strong Ed25519 middleware key, separate from the Enrollment-role P-256 key.
    pub public_key: [u8; 32],
    /// Positive upper bound on one fresh request's lifetime; no cached eligibility lease.
    pub maximum_response_ms: u64,
}
impl KagemushaEligibilityPolicyV1 {
    /// Validate the explicit authority identity and strong signer key.
    /// # Errors
    /// Rejects unknown version, zero scope/revision/lifetime and weak keys.
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 || self.revision == 0 || self.maximum_response_ms == 0 {
            return Err(invalid("eligibility.policy"));
        }
        for value in [&self.network_id, &self.scheme_id, &self.asset_digest] {
            nonzero(value)?;
        }
        nonzero(&self.authority.scope_digest())?;
        ed25519_parse_public_key(&self.public_key)
            .map_err(|_| invalid("eligibility.public_key"))?;
        Ok(())
    }
    /// Encode a validated policy DATA frame.
    /// # Errors
    /// Rejects invalid fields or a frame exceeding the cap.
    pub fn encode_canonical(&self) -> Result<Vec<u8>> {
        self.validate()?;
        encode_frame_v1(self, KAGEMUSHA_ELIGIBILITY_MAX_BYTES_V1)
    }
    /// Decode one canonical policy; the caller must independently authenticate its selection.
    /// # Errors
    /// Rejects excessive, malformed, noncanonical or invalid input.
    pub fn decode_canonical(original: &[u8]) -> Result<Self> {
        let value: Self = decode_frame_v1(original, KAGEMUSHA_ELIGIBILITY_MAX_BYTES_V1)?;
        value.validate()?;
        Ok(value)
    }
    /// Domain-separated identity over the complete canonical policy frame.
    /// # Errors
    /// Rejects invalid policy fields.
    pub fn policy_digest(&self) -> Result<[u8; 32]> {
        Ok(hash(
            b"iroha:kagemusha:eligibility:policy:v1\0",
            &self.encode_canonical()?,
        ))
    }
}

/// Separate fresh observations are required at each of these issuer boundaries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(name = "iroha.kagemusha.eligibility.purpose.v1")]
pub enum KagemushaEligibilityPurposeV1 {
    /// Before releasing a pre-key permit, including a resumed permit.
    #[codec(index = 1)]
    PreKeyPermit,
    /// Before selecting platform verification for an account-signed E5.
    #[codec(index = 2)]
    VerifyEvidence,
    /// Before selecting the exact credential body for signing.
    #[codec(index = 3)]
    IssueCredential,
    /// Before delivering an original E6, including exact-byte recovery.
    #[codec(index = 4)]
    DeliverCredential,
}

/// Issuer-generated request, retained before dispatch over authenticated middleware transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(name = "iroha.kagemusha.eligibility.request.v1")]
pub struct KagemushaEligibilityRequestV1 {
    /// Exactly one.
    pub version: u16,
    /// Complete current authority policy identity, including network and asset scope.
    pub policy_digest: [u8; 32],
    /// Canonical domainless account digest.
    pub account_digest: [u8; 32],
    /// Existing authenticated actor scope digest; middleware must check its account binding.
    pub actor_digest: [u8; 32],
    /// Original enrollment attempt; checking eligibility never resets that attempt.
    pub attempt_id: [u8; 32],
    /// Fresh server CSPRNG nonce for this observation, not a mobile-selected retry identity.
    pub nonce: [u8; 32],
    /// Exact retained operation-original digest for the selected purpose.
    pub operation_digest: [u8; 32],
    /// The single mutation or delivery this observation covers.
    pub purpose: KagemushaEligibilityPurposeV1,
    /// Positive trusted issuer time when the nonce was retained.
    pub requested_at_ms: u64,
    /// Exclusive deadline bounded by current policy. The service also caps pre-key/verification
    /// requests at the original E1 deadline; already retained evidence/E6 recovery is separate.
    pub expires_at_ms: u64,
}
impl KagemushaEligibilityRequestV1 {
    fn validate_shape(&self) -> Result<()> {
        if self.version != 1
            || self.requested_at_ms == 0
            || self.expires_at_ms <= self.requested_at_ms
        {
            return Err(invalid("eligibility.request"));
        }
        for value in [
            &self.policy_digest,
            &self.account_digest,
            &self.actor_digest,
            &self.attempt_id,
            &self.nonce,
            &self.operation_digest,
        ] {
            nonzero(value)?;
        }
        Ok(())
    }
    /// Check exact selected policy and request lifetime before any middleware lookup.
    /// # Errors
    /// Rejects invalid or foreign requests and an interval exceeding the selected policy.
    pub fn validate(&self, policy: &KagemushaEligibilityPolicyV1) -> Result<()> {
        self.validate_shape()?;
        if self.policy_digest != policy.policy_digest()?
            || self.expires_at_ms - self.requested_at_ms > policy.maximum_response_ms
        {
            return Err(invalid("eligibility.request_policy"));
        }
        Ok(())
    }
    /// Encode the exact request under the independently selected policy.
    /// # Errors
    /// Rejects invalid scope, lifetime or an excessive frame.
    pub fn encode_canonical(&self, policy: &KagemushaEligibilityPolicyV1) -> Result<Vec<u8>> {
        self.validate(policy)?;
        encode_frame_v1(self, KAGEMUSHA_ELIGIBILITY_MAX_BYTES_V1)
    }
    /// Decode a canonical request and bind it to the independently selected policy.
    /// # Errors
    /// Rejects excessive, malformed, noncanonical or foreign input.
    pub fn decode_canonical(
        original: &[u8],
        policy: &KagemushaEligibilityPolicyV1,
    ) -> Result<Self> {
        let value: Self = decode_frame_v1(original, KAGEMUSHA_ELIGIBILITY_MAX_BYTES_V1)?;
        value.validate(policy)?;
        Ok(value)
    }
    /// Hash the complete request, including nonce, actor, operation, purpose and deadline.
    /// # Errors
    /// Rejects invalid or foreign request fields.
    pub fn request_digest(&self, policy: &KagemushaEligibilityPolicyV1) -> Result<[u8; 32]> {
        Ok(hash(
            b"iroha:kagemusha:eligibility:request:v1\0",
            &self.encode_canonical(policy)?,
        ))
    }
}

/// Definitive middleware observation; transport/read failures are errors, never an enum arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(name = "iroha.kagemusha.eligibility.decision.v1")]
pub enum KagemushaEligibilityDecisionV1 {
    /// Approved under the named authority's policy and currently unfrozen at observation time.
    /// Bank approval includes required KYC; a scheme operator makes no bank KYC assertion.
    #[codec(index = 1)]
    ApprovedUnfrozen,
    /// Current eligibility approval is absent or withdrawn.
    #[codec(index = 2)]
    NotApproved,
    /// The subject/account or scoped token is currently frozen.
    #[codec(index = 3)]
    Frozen,
}

/// Exact signed observation. Personal KYC documents and bank customer identifiers stay private.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(name = "iroha.kagemusha.eligibility.response_body.v1")]
pub struct KagemushaEligibilityResponseBodyV1 {
    /// Exactly one.
    pub version: u16,
    /// Digest of the complete original request.
    pub request_digest: [u8; 32],
    /// Current definitive observation from the selected middleware.
    pub decision: KagemushaEligibilityDecisionV1,
    /// Positive source revision, useful for durable audit; not a substitute for a fresh read.
    pub source_revision: u64,
    /// Trusted middleware time of its current eligibility/freeze read.
    pub observed_at_ms: u64,
    /// Exclusive response deadline, never later than the issuer request deadline.
    pub valid_until_ms: u64,
}
impl KagemushaEligibilityResponseBodyV1 {
    fn validate_shape(&self) -> Result<()> {
        if self.version != 1
            || self.source_revision == 0
            || self.observed_at_ms == 0
            || self.valid_until_ms <= self.observed_at_ms
        {
            return Err(invalid("eligibility.response_body"));
        }
        nonzero(&self.request_digest)
    }
    /// Fixed domain-separated SHA-256 message signed by the selected Ed25519 middleware key.
    /// # Errors
    /// Rejects invalid response fields or an excessive canonical frame.
    pub fn signing_message(&self) -> Result<[u8; 32]> {
        self.validate_shape()?;
        Ok(hash(
            b"iroha:kagemusha:eligibility:response:v1\0",
            &encode_frame_v1(self, KAGEMUSHA_ELIGIBILITY_MAX_BYTES_V1)?,
        ))
    }
}

/// Signed response with no caller-selectable signer key or certificate fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Encode, Decode, IntoSchema, norito::NoritoSchema)]
#[norito_schema(name = "iroha.kagemusha.eligibility.response.v1")]
pub struct KagemushaEligibilityResponseV1 {
    /// Exact signed observation.
    pub body: KagemushaEligibilityResponseBodyV1,
    /// Canonical Ed25519 signature over the body's signing message.
    pub signature: [u8; 64],
}
impl KagemushaEligibilityResponseV1 {
    /// Authenticate an observation for the exact retained request and current authority policy.
    ///
    /// The issuer must re-read current policy/routing, compare the retained operation and consume
    /// the nonce at its durable boundary. This result alone is not a reusable authorization token.
    /// # Errors
    /// Rejects foreign scope, stale/future observations, deadline extension and bad signatures.
    pub fn verify(
        &self,
        policy: &KagemushaEligibilityPolicyV1,
        request: &KagemushaEligibilityRequestV1,
        now_ms: u64,
    ) -> Result<KagemushaEligibilityDecisionV1> {
        self.body.validate_shape()?;
        if self.body.request_digest != request.request_digest(policy)?
            || self.body.observed_at_ms < request.requested_at_ms
            || self.body.observed_at_ms > now_ms
            || now_ms >= self.body.valid_until_ms
            || self.body.valid_until_ms > request.expires_at_ms
        {
            return Err(invalid("eligibility.response_binding"));
        }
        let key = PublicKey::from_bytes(Algorithm::Ed25519, &policy.public_key)
            .map_err(|_| invalid("eligibility.public_key"))?;
        ed25519_parse_signature(&self.signature)
            .and_then(|signature| {
                signature.verify(
                    &key,
                    &self
                        .body
                        .signing_message()
                        .map_err(|_| iroha_crypto::Error::BadSignature)?,
                )
            })
            .map_err(|_| invalid("eligibility.signature"))?;
        Ok(self.body.decision)
    }
    /// Encode structurally valid response DATA; admission additionally requires `verify`.
    /// # Errors
    /// Rejects malformed body/signature encodings or an excessive frame.
    pub fn encode_canonical(&self) -> Result<Vec<u8>> {
        self.body.validate_shape()?;
        ed25519_parse_signature(&self.signature).map_err(|_| invalid("eligibility.signature"))?;
        encode_frame_v1(self, KAGEMUSHA_ELIGIBILITY_MAX_BYTES_V1)
    }
    /// Decode and authenticate against the exact retained request and current policy.
    /// # Errors
    /// Rejects excessive, malformed, noncanonical, foreign, expired or forged input.
    pub fn decode_canonical(
        original: &[u8],
        policy: &KagemushaEligibilityPolicyV1,
        request: &KagemushaEligibilityRequestV1,
        now_ms: u64,
    ) -> Result<Self> {
        let value: Self = decode_frame_v1(original, KAGEMUSHA_ELIGIBILITY_MAX_BYTES_V1)?;
        value.verify(policy, request, now_ms)?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests;
