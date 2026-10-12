//! Provider-backed phone control: the number commitment, the provider key
//! identity and the provider signature rule.
//!
//! A verification provider checks control of a phone number with a fresh SMS
//! or carrier challenge and signs a short-lived credential. The credential
//! carries a hiding commitment to the canonical E.164 number, never the number.
//! This module owns that commitment, the commitment to a provider's public key
//! and the signature rule. The challenge, credential and provider policy
//! records name accounts and networks, so they live in
//! `iroha_data_model::phone_control`. The section "Provider-backed phone
//! control" of `specs/ram_lfe_execution_proof.md` is the specification.
//!
//! A credential is evidence of control at one instant. It is not a proof of
//! execution, decryption or identifier derivation and replaces none of them.
//! Nothing in Core, Torii or an SDK consumes these types yet:
//!
//! - TODO(R.2): the private relation takes
//!   [`PhoneNumberCommitmentV1::lane_words`] as public inputs and proves that
//!   the committed bytes are RAM-LFE input slots `1..=16` of the admitted
//!   canonical input and the preimage of the keyed nullifier.
//! - TODO(R.4): State registers the provider policy, consumes each challenge
//!   once, applies the expiry bounds and evicts bindings of a revoked key.
//! - TODO(R.5): the one-call claim runs the provider challenge and carries the
//!   credential; the SDK and JSON forms of these types arrive with it.

use super::{Hash, canonical::commitment_frame, clearing::ClearingArray};
use crate::{Algorithm, PrivateKey, PublicKey, Signature};
use fastpq_isi::{
    FASTPQ_CATALOG_V1, GOLDILOCKS_DIGEST384_BYTES_V1, GOLDILOCKS_DIGEST384_LANES_V1,
    GoldilocksDigest384V1, GoldilocksDigestDomainV1, hash_bytes_384_v1,
};
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};
use std::fmt;
use thiserror::Error;
use zeroize::Zeroize as _;

const PROVIDER_KEY_DOMAIN: &[u8] = b"iroha.ram_lfe.v1.phone_control.provider_key";

/// Blake2b domains owned by this crate for provider-backed phone control.
///
/// Together with `RAM_LFE_V1_PUBLIC_DOMAINS` and the data model's tables, no
/// domain is a prefix of another.
pub const PHONE_CONTROL_V1_CRYPTO_DOMAINS: [&[u8]; 1] = [PROVIDER_KEY_DOMAIN];

/// Protocol field of the typed Goldilocks domain of a number commitment.
pub const PHONE_CONTROL_V1_NUMBER_COMMITMENT_PROTOCOL: &str = "iroha.ram_lfe.v1.phone_control";
/// Role field of the typed Goldilocks domain of a number commitment.
pub const PHONE_CONTROL_V1_NUMBER_COMMITMENT_ROLE: &str = "number-commitment";
/// Length of the committed number field: the canonical E.164 bytes, zero-padded.
///
/// It equals RAM-LFE input slots `1..=16` of the canonical phone input.
pub const PHONE_CONTROL_V1_NUMBER_BYTES: usize = 16;
/// Length of the commitment blinding.
pub const PHONE_CONTROL_V1_BLINDING_BYTES: usize = 32;

/// Errors of the provider-backed phone-control contract.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum PhoneControlError {
    /// The number is not exact canonical E.164.
    #[error("phone number is not canonical E.164")]
    NonCanonicalNumber,
    /// The blinding is the all-zero value, which no random source produces.
    #[error("phone-number blinding must not be all zero")]
    ZeroBlinding,
    /// The operating-system random source failed.
    #[error("operating-system randomness is unavailable")]
    RandomnessUnavailable,
    /// A commitment word is not a canonical Goldilocks element.
    #[error("phone-number commitment holds a non-canonical Goldilocks word")]
    NonCanonicalCommitment,
    /// The commitment does not open to the supplied number and blinding.
    #[error("phone-number commitment does not open to the number and blinding")]
    CommitmentMismatch,
    /// A provider key is neither Ed25519 nor ML-DSA-65.
    #[error("provider keys must be Ed25519 or ML-DSA-65")]
    UnsupportedProviderKeyAlgorithm,
    /// A provider key cannot be read.
    #[error("provider key is malformed")]
    MalformedProviderKey,
    /// The provider could not sign the credential.
    #[error("provider signing failed")]
    ProviderSigningFailed,
    /// The provider signature is malformed or does not verify.
    #[error("provider signature does not verify")]
    BadProviderSignature,
    /// The provider policy record is malformed, or a change of its lifetimes
    /// is not allowed.
    #[error("invalid phone-control provider policy: {0}")]
    InvalidProviderPolicy(&'static str),
    /// The provider policy has no key with the credential's key identity.
    #[error("provider key is not registered in the provider policy")]
    UnknownProviderKey,
    /// The key identity is already registered, in any state.
    #[error("provider key is already registered")]
    DuplicateProviderKey,
    /// The provider policy holds its maximum number of keys.
    #[error("provider policy holds its maximum of {limit} keys")]
    ProviderKeyCapacity {
        /// Maximum number of keys of one provider policy.
        limit: usize,
    },
    /// The credential was issued before its key became active.
    #[error("provider key was not active when the credential was issued")]
    ProviderKeyNotActive,
    /// The credential was issued at or after the retirement of its key.
    #[error("provider key was retired when the credential was issued")]
    ProviderKeyRetired,
    /// The key is revoked. No credential under it is admissible.
    #[error("provider key is revoked")]
    ProviderKeyRevoked,
    /// A provider key lifecycle transition is not allowed.
    #[error("invalid provider key transition: {0}")]
    InvalidProviderKeyTransition(&'static str),
    /// The credential is bound to another authoritative value.
    #[error("credential is bound to another {0}")]
    ContextMismatch(&'static str),
    /// The credential does not answer the presented challenge record.
    #[error("credential does not answer the presented challenge: {0} differs")]
    ChallengeMismatch(&'static str),
    /// The credential's validity interval is empty.
    #[error("credential validity interval is empty")]
    EmptyValidity,
    /// The credential's lifetime exceeds the committed maximum.
    #[error("credential lifetime exceeds the committed maximum of {limit_ms} ms")]
    LifetimeExceeded {
        /// Committed maximum credential lifetime in milliseconds.
        limit_ms: u64,
    },
    /// The credential is presented before its issue time.
    #[error("credential is not valid yet")]
    NotYetValid,
    /// The credential is presented at or after its expiry.
    #[error("credential has expired")]
    Expired,
    /// The binding the evidence supports would end at or before its admission.
    #[error("the binding this evidence supports would expire at or before its admission")]
    BindingExpired,
    /// The challenge of the credential was already consumed on this network.
    #[error("phone-control challenge was already consumed")]
    ChallengeReplayed,
    /// Norito failed to encode a canonical frame.
    #[error("phone-control frame encoding failed: {0}")]
    Encoding(String),
}

/// Return whether `number` is exact canonical E.164: `+`, a nonzero leading
/// digit and 2 to 15 digits in total.
fn is_canonical_e164(number: &[u8]) -> bool {
    (PhoneNumberV1::MIN_BYTES..=PhoneNumberV1::MAX_BYTES).contains(&number.len())
        && number[0] == b'+'
        && matches!(number[1], b'1'..=b'9')
        && number[2..].iter().all(u8::is_ascii_digit)
}

/// Canonical E.164 phone number held as a private witness.
///
/// The value is the committed number field: the ASCII bytes `+` and 2 to 15
/// digits, zero-padded on the right to 16 bytes. Canonical E.164 has no zero
/// byte, so the padding is unambiguous, and the field equals RAM-LFE input
/// slots `1..=16` of the canonical phone input.
///
/// A phone number has little entropy. It lives in one heap allocation that is
/// cleared on drop, on an error return and during unwinding, has no wire
/// encoding and is never a ledger field. Copies the caller keeps are not
/// covered.
pub struct PhoneNumberV1(ClearingArray<u8, PHONE_CONTROL_V1_NUMBER_BYTES>);

impl PhoneNumberV1 {
    /// Shortest canonical E.164 value in bytes: `+` and two digits.
    pub const MIN_BYTES: usize = 3;
    /// Longest canonical E.164 value in bytes: `+` and fifteen digits.
    pub const MAX_BYTES: usize = PHONE_CONTROL_V1_NUMBER_BYTES;

    /// Take an exact canonical E.164 value.
    ///
    /// The input is not normalized here. Spaces, punctuation, a `00` prefix or
    /// a missing `+` are rejected, so two spellings of one number never give
    /// two witnesses.
    ///
    /// # Errors
    /// Returns [`PhoneControlError::NonCanonicalNumber`] for any other value.
    pub fn from_canonical(number: &[u8]) -> Result<Self, PhoneControlError> {
        if !is_canonical_e164(number) {
            return Err(PhoneControlError::NonCanonicalNumber);
        }
        let mut padded = ClearingArray::zeroed();
        padded[..number.len()].copy_from_slice(number);
        Ok(Self(padded))
    }

    /// Borrow the committed field: the canonical bytes, zero-padded to 16.
    #[must_use]
    pub fn expose_padded(&self) -> &[u8; PHONE_CONTROL_V1_NUMBER_BYTES] {
        &self.0
    }

    /// Borrow the canonical bytes without padding.
    ///
    /// The keyed nullifier is derived from exactly these bytes and never from
    /// the blinding, so two commitments to one number share one nullifier. The
    /// scan for the end of the number is not constant time in its length.
    #[must_use]
    pub fn expose_canonical(&self) -> &[u8] {
        let length = self
            .0
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(PHONE_CONTROL_V1_NUMBER_BYTES);
        &self.0[..length]
    }
}

impl fmt::Debug for PhoneNumberV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED phone number]")
    }
}

/// Fresh blinding of one number commitment.
///
/// The client generates 32 uniformly random bytes for every challenge and
/// never reuses them. It sends them with the number to the provider over the
/// provider's authenticated and confidential channel and keeps them as a
/// witness of the private relation. The blinding lives in one heap allocation
/// that is cleared on drop, on an error return and during unwinding. It has no
/// wire encoding in this crate.
pub struct PhoneNumberBlindingV1(ClearingArray<u8, PHONE_CONTROL_V1_BLINDING_BYTES>);

impl PhoneNumberBlindingV1 {
    /// Exact blinding length in bytes.
    pub const LENGTH: usize = PHONE_CONTROL_V1_BLINDING_BYTES;

    /// Generate a fresh blinding from the operating-system random source.
    ///
    /// The source writes directly into the blinding's heap allocation.
    ///
    /// # Errors
    /// Returns [`PhoneControlError::RandomnessUnavailable`] when the source fails.
    #[cfg(feature = "rand")]
    pub fn generate() -> Result<Self, PhoneControlError> {
        use rand_core::TryRngCore as _;
        let mut bytes = ClearingArray::zeroed();
        rand_core::OsRng
            .try_fill_bytes(bytes.as_mut_slice())
            .map_err(|_| PhoneControlError::RandomnessUnavailable)?;
        Self::checked(bytes)
    }

    /// Import a blinding, for example at the provider.
    ///
    /// The bytes are copied into the blinding's heap allocation and the
    /// argument is cleared. A copy the caller keeps is not covered. The import
    /// cannot establish the caller's entropy.
    ///
    /// # Errors
    /// Rejects the all-zero value, which no random source produces.
    pub fn from_bytes(
        mut bytes: [u8; PHONE_CONTROL_V1_BLINDING_BYTES],
    ) -> Result<Self, PhoneControlError> {
        let owner = ClearingArray::copy_of(&bytes);
        bytes.zeroize();
        Self::checked(owner)
    }

    fn checked(
        bytes: ClearingArray<u8, PHONE_CONTROL_V1_BLINDING_BYTES>,
    ) -> Result<Self, PhoneControlError> {
        if bytes.is_zero() {
            return Err(PhoneControlError::ZeroBlinding);
        }
        Ok(Self(bytes))
    }

    /// Borrow the blinding, to send it to the provider or to witness it.
    #[must_use]
    pub fn expose(&self) -> &[u8; PHONE_CONTROL_V1_BLINDING_BYTES] {
        &self.0
    }
}

impl fmt::Debug for PhoneNumberBlindingV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED phone-number blinding]")
    }
}

/// Typed identity of the digest a number commitment is computed with.
///
/// The private relation recomputes the commitment, so the digest is the
/// native-field hash of the proof backend. The identity is signed with the
/// commitment, and a decoder rejects every other tag.
///
/// Exactly one identity is implemented. It is not qualified: no collision,
/// preimage or hiding bound is established for the six-lane digest
/// (`specs/fastpq_compact_digest_security.md`). Task H.2 freezes the in-relation
/// digest of the shared backend. If it selects another digest, that digest
/// replaces this identity and every pinned vector together. Two identities are
/// never accepted side by side.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_crypto::ram_lfe::PhoneNumberCommitmentDigestV1")]
pub enum PhoneNumberCommitmentDigestV1 {
    /// Six-lane digest over the Goldilocks field
    /// (`fastpq_isi::GoldilocksDigest384V1`).
    GoldilocksDigest384V1,
}

impl PhoneNumberCommitmentDigestV1 {
    /// Label of this identity. It is the profile field of the typed domain the
    /// commitment is hashed under.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::GoldilocksDigest384V1 => "goldilocks-digest384-v1",
        }
    }

    /// Typed domain of a number commitment under this identity.
    fn domain(self) -> GoldilocksDigestDomainV1<'static> {
        GoldilocksDigestDomainV1 {
            catalog: FASTPQ_CATALOG_V1.as_bytes(),
            protocol: PHONE_CONTROL_V1_NUMBER_COMMITMENT_PROTOCOL.as_bytes(),
            profile: self.label().as_bytes(),
            role: PHONE_CONTROL_V1_NUMBER_COMMITMENT_ROLE.as_bytes(),
            phase: b"",
            level: 0,
            index: 0,
            counter: 0,
        }
    }
}

/// The 48 bytes of a number commitment: six canonical little-endian Goldilocks
/// words in lane order.
///
/// Construction and every decoder reject a word at or above the field modulus.
/// A non-canonical word is never reduced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, IntoSchema, norito::NoritoSchema)]
#[norito_schema(name = "iroha_crypto::ram_lfe::PhoneNumberCommitmentValueV1")]
pub struct PhoneNumberCommitmentValueV1([u8; GOLDILOCKS_DIGEST384_BYTES_V1]);

impl PhoneNumberCommitmentValueV1 {
    /// Encoded length in bytes.
    pub const BYTES: usize = GOLDILOCKS_DIGEST384_BYTES_V1;

    /// Decode six canonical little-endian Goldilocks words.
    ///
    /// # Errors
    /// Returns [`PhoneControlError::NonCanonicalCommitment`] when a word is at
    /// or above the field modulus.
    pub fn from_le_bytes(bytes: [u8; Self::BYTES]) -> Result<Self, PhoneControlError> {
        GoldilocksDigest384V1::from_le_bytes(bytes)
            .map(|_| Self(bytes))
            .ok_or(PhoneControlError::NonCanonicalCommitment)
    }

    /// Return the six words as canonical little-endian bytes.
    #[must_use]
    pub const fn to_le_bytes(self) -> [u8; Self::BYTES] {
        self.0
    }

    /// Return the six canonical Goldilocks words in lane order.
    #[must_use]
    pub fn words(self) -> [u64; GOLDILOCKS_DIGEST384_LANES_V1] {
        GoldilocksDigest384V1::from_le_bytes(self.0)
            .expect("construction and decoding admit canonical words only")
            .words()
    }

    fn decode_error() -> norito::core::Error {
        norito::core::Error::InvalidValue {
            context: "phone-number commitment word",
        }
    }
}

impl norito::core::SerializePayload for PhoneNumberCommitmentValueV1 {
    fn serialize(&self, writer: &mut norito::core::Encoder<'_>) -> Result<(), norito::core::Error> {
        writer.write_all(&self.0)?;
        Ok(())
    }

    fn encoded_len_hint(&self) -> Option<usize> {
        Some(Self::BYTES)
    }

    fn encoded_len_exact(&self) -> Option<usize> {
        Some(Self::BYTES)
    }
}

impl<'de> norito::core::DeserializePayload<'de> for PhoneNumberCommitmentValueV1 {
    fn deserialize(archived: &'de norito::core::Archived<Self>) -> Self {
        Self::try_deserialize(archived).expect("canonical phone-number commitment decode")
    }

    fn try_deserialize(
        archived: &'de norito::core::Archived<Self>,
    ) -> Result<Self, norito::core::Error> {
        // The payload is exactly 48 raw bytes, not Norito's element-framed array.
        let payload =
            norito::core::payload_slice_from_ptr(core::ptr::from_ref(archived).cast::<u8>())?;
        let (value, used) = <Self as norito::core::DecodeFromSlice>::decode_from_slice(payload)?;
        if used != payload.len() {
            return Err(norito::core::Error::LengthMismatch);
        }
        Ok(value)
    }
}

impl<'de> norito::core::DecodeFromSlice<'de> for PhoneNumberCommitmentValueV1 {
    fn decode_from_slice(bytes: &'de [u8]) -> Result<(Self, usize), norito::core::Error> {
        let prefix = bytes
            .get(..Self::BYTES)
            .ok_or(norito::core::Error::LengthMismatch)?;
        let mut encoded = [0_u8; Self::BYTES];
        encoded.copy_from_slice(prefix);
        let value = Self::from_le_bytes(encoded).map_err(|_| Self::decode_error())?;
        norito::core::note_payload_access(bytes, Self::BYTES);
        Ok((value, Self::BYTES))
    }
}

/// Hiding commitment to one canonical E.164 number.
///
/// The value is the digest named by `digest` of one typed frame: catalog
/// `FASTPQ_CATALOG_V1`, protocol
/// [`PHONE_CONTROL_V1_NUMBER_COMMITMENT_PROTOCOL`], profile
/// [`PhoneNumberCommitmentDigestV1::label`], role
/// [`PHONE_CONTROL_V1_NUMBER_COMMITMENT_ROLE`], an empty phase, level, index
/// and counter zero, over two byte fields: the 16-byte padded number and the
/// 32-byte blinding.
///
/// The provider signs the identity tag and all 48 bytes inside the credential
/// frame. A fresh blinding makes two commitments to one number unlinkable. The
/// commitment alone establishes nothing about who controls the number.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_crypto::ram_lfe::PhoneNumberCommitmentV1")]
pub struct PhoneNumberCommitmentV1 {
    digest: PhoneNumberCommitmentDigestV1,
    value: PhoneNumberCommitmentValueV1,
}

impl PhoneNumberCommitmentV1 {
    /// Commit a number under a fresh blinding.
    ///
    /// The number and the blinding are hashed from their clearing owners. The
    /// digest erases its lane, rate and byte-packing scratch on return and
    /// during unwinding. Scalars the compiler holds in registers are not
    /// covered.
    #[must_use]
    pub fn commit(
        digest: PhoneNumberCommitmentDigestV1,
        number: &PhoneNumberV1,
        blinding: &PhoneNumberBlindingV1,
    ) -> Self {
        let value = match digest {
            PhoneNumberCommitmentDigestV1::GoldilocksDigest384V1 => hash_bytes_384_v1(
                digest.domain(),
                &[number.expose_padded(), blinding.expose()],
            )
            .expect("two fixed-length fields fit the canonical frame"),
        };
        Self {
            digest,
            value: PhoneNumberCommitmentValueV1(value.to_le_bytes()),
        }
    }

    /// Rebuild a commitment from its identity and its 48 bytes.
    ///
    /// # Errors
    /// Returns [`PhoneControlError::NonCanonicalCommitment`] when a word is at
    /// or above the field modulus.
    pub fn from_le_bytes(
        digest: PhoneNumberCommitmentDigestV1,
        bytes: [u8; PhoneNumberCommitmentValueV1::BYTES],
    ) -> Result<Self, PhoneControlError> {
        Ok(Self {
            digest,
            value: PhoneNumberCommitmentValueV1::from_le_bytes(bytes)?,
        })
    }

    /// Check that a number and a blinding open this commitment.
    ///
    /// The provider runs this on the number it challenged before it signs.
    ///
    /// # Errors
    /// Returns [`PhoneControlError::CommitmentMismatch`] for any other number
    /// or blinding.
    pub fn verify_opening(
        &self,
        number: &PhoneNumberV1,
        blinding: &PhoneNumberBlindingV1,
    ) -> Result<(), PhoneControlError> {
        if Self::commit(self.digest, number, blinding) != *self {
            return Err(PhoneControlError::CommitmentMismatch);
        }
        Ok(())
    }

    /// Digest identity the commitment was computed with.
    #[must_use]
    pub const fn digest(self) -> PhoneNumberCommitmentDigestV1 {
        self.digest
    }

    /// The 48 commitment bytes.
    #[must_use]
    pub const fn to_le_bytes(self) -> [u8; PhoneNumberCommitmentValueV1::BYTES] {
        self.value.to_le_bytes()
    }

    // TODO(R.2): the private phone-control relation takes these six words as
    // public inputs and constrains the exact framed digest computation over the
    // padded number and the blinding.
    /// The six canonical Goldilocks words, in lane order.
    #[must_use]
    pub fn lane_words(self) -> [u64; GOLDILOCKS_DIGEST384_LANES_V1] {
        self.value.words()
    }
}

commitment_frame! {
    // The algorithm tag keeps equal key bytes of two algorithms apart.
    struct ProviderKeyInputV1<'a> as "iroha_crypto::ram_lfe::PhoneControlProviderKeyInputV1" {
        algorithm: Algorithm,
        public_key: &'a [u8],
    }
}

/// Field order of every borrowed commitment frame of this module.
#[cfg(test)]
pub(super) const COMMITMENT_FRAMES: [(&str, &[&str]); 1] =
    [(ProviderKeyInputV1::FRAME, ProviderKeyInputV1::FIELDS)];

/// Return the algorithm of a provider key when the contract admits it.
fn provider_key_algorithm(public_key: &PublicKey) -> Result<Algorithm, PhoneControlError> {
    match public_key.try_algorithm() {
        Ok(algorithm @ (Algorithm::Ed25519 | Algorithm::MlDsa)) => Ok(algorithm),
        Ok(_) => Err(PhoneControlError::UnsupportedProviderKeyAlgorithm),
        Err(_) => Err(PhoneControlError::MalformedProviderKey),
    }
}

/// Identity of one provider key: the commitment to its algorithm-tagged
/// public key.
///
/// A credential names its key by this identity, and revocation is terminal
/// for it.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_crypto::ram_lfe::PhoneControlProviderKeyIdV1")]
pub struct PhoneControlProviderKeyIdV1(Hash);

impl PhoneControlProviderKeyIdV1 {
    /// Commit a provider's public key.
    ///
    /// # Errors
    /// Returns [`PhoneControlError::UnsupportedProviderKeyAlgorithm`] unless
    /// the key is Ed25519 or ML-DSA-65, and reports a malformed key or a
    /// canonical encoding failure.
    pub fn commit(public_key: &PublicKey) -> Result<Self, PhoneControlError> {
        let algorithm = provider_key_algorithm(public_key)?;
        let (_, bytes) = public_key
            .try_to_bytes()
            .map_err(|_| PhoneControlError::MalformedProviderKey)?;
        let frame = norito::encode_canonical(&ProviderKeyInputV1 {
            algorithm,
            public_key: bytes,
        })
        .map_err(|error| PhoneControlError::Encoding(error.to_string()))?;
        Ok(Self(Hash::new_from_chunks(&[PROVIDER_KEY_DOMAIN, &frame])))
    }

    /// Borrow the marked Iroha Blake2b digest.
    #[must_use]
    pub const fn as_hash(&self) -> &Hash {
        &self.0
    }
}

/// Sign one provider message with a provider key.
///
/// `message` is a fixed domain followed by one canonical frame; the data model
/// builds it. This is the provider's operation and never a validator's.
///
/// # Errors
/// Returns [`PhoneControlError::UnsupportedProviderKeyAlgorithm`] unless the
/// key is Ed25519 or ML-DSA-65, and
/// [`PhoneControlError::ProviderSigningFailed`] when the backend refuses.
pub fn phone_control_provider_sign(
    private_key: &PrivateKey,
    message: &[u8],
) -> Result<Signature, PhoneControlError> {
    if !matches!(
        private_key.algorithm(),
        Algorithm::Ed25519 | Algorithm::MlDsa
    ) {
        return Err(PhoneControlError::UnsupportedProviderKeyAlgorithm);
    }
    Signature::try_new(private_key, message).map_err(|_| PhoneControlError::ProviderSigningFailed)
}

/// Verify one provider signature over a provider message.
///
/// The key must be of an admitted algorithm. [`Signature::verify`] is the one
/// verifier and it is strict for both: an Ed25519 signature must have a
/// canonical `R` in the prime-order subgroup and satisfy the cofactorless
/// equation, so a signature that only an unchecked verifier accepts is
/// refused; an ML-DSA-65 signature must have the exact detached length. This
/// function adds no parsing step of its own.
///
/// # Errors
/// Returns [`PhoneControlError::UnsupportedProviderKeyAlgorithm`] unless the
/// key is Ed25519 or ML-DSA-65, and
/// [`PhoneControlError::BadProviderSignature`] for a malformed signature and
/// for one that does not verify.
pub fn phone_control_provider_verify(
    public_key: &PublicKey,
    message: &[u8],
    signature: &Signature,
) -> Result<(), PhoneControlError> {
    provider_key_algorithm(public_key)?;
    signature
        .verify(public_key, message)
        .map_err(|_| PhoneControlError::BadProviderSignature)
}

#[cfg(test)]
#[path = "phone_control_tests.rs"]
mod tests;
