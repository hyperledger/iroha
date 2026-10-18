//! Fixed ML-DSA-65 and ML-KEM-768/XChaCha20-Poly1305 wire for PQ-MASP.
//!
//! The consensus statement carries only key digests and authenticated
//! ciphertext bytes. Wallets retain the large ML-KEM secret keys and decrypted
//! note plaintexts locally. There is exactly one byte layout for each object;
//! no suite identifiers, optional fields, or compatibility decoders exist.
use super::relation::{
    PqMaspNotePlaintextV1, derive_pq_masp_note_commitment_v1,
    derive_pq_masp_note_encryption_keys_digest_v1,
};
use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{Aead as _, KeyInit as _, Payload},
};
use iroha_data_model::privacy::{
    PqMaspStarkStatementV1, PrivacyAuthorizationKeyDigestV1, PrivacyCommitmentV1,
    PrivacyEncryptedOutputV1, PrivacyEncryptionKeyV1, PrivacyNativeConsensusBindingDigestV1,
    PrivacyRecipientIdV1, PrivacyStatementDigestV1, TAIRA_PRIVACY_MAX_PROOF_BYTES_PER_ACTION_V1,
};
use sha2::{Digest as _, Sha256};
#[cfg(test)]
use soranet_pq::decapsulate_mlkem;
use soranet_pq::{
    HedgedRngSeed, HkdfDomain, HkdfSuite, MlDsaSuite, MlKemSuite, derive_labeled_hkdf,
    deterministic_chacha20_rng, encapsulate_mlkem_from_seed, mldsa_public_key_from_secret_key,
    sign_mldsa, validate_mldsa_public_key, validate_mldsa_signature, validate_mlkem_ciphertext,
    verify_mldsa,
};
use thiserror::Error;
use zeroize::Zeroizing;
/// Exact canonical ML-DSA-65 public-key length.
pub const ML_DSA_65_PUBLIC_KEY_BYTES_V1: usize = 1_952;
/// Exact canonical ML-DSA-65 signature length.
pub const ML_DSA_65_SIGNATURE_BYTES_V1: usize = 3_309;
/// Exact canonical ML-KEM-768 public-key length.
pub const ML_KEM_768_PUBLIC_KEY_BYTES_V1: usize = 1_184;
/// Exact canonical ML-KEM-768 ciphertext length.
pub const ML_KEM_768_CIPHERTEXT_BYTES_V1: usize = 1_088;
/// Exact `XChaCha20` nonce length.
pub const XCHACHA20_NONCE_BYTES_V1: usize = 24;
const POLY1305_TAG_BYTES_V1: usize = 16;
const PQ_MASP_NOTE_PLAINTEXT_BYTES_V1: usize = 4 + 16 + 6 * 32;
const PQ_MASP_NOTE_AEAD_BYTES_V1: usize = PQ_MASP_NOTE_PLAINTEXT_BYTES_V1 + POLY1305_TAG_BYTES_V1;
/// Exact byte length of one canonical `PQE1` encrypted note payload.
pub const PQ_MASP_ENCRYPTED_OUTPUT_BYTES_V1: usize =
    4 + ML_KEM_768_CIPHERTEXT_BYTES_V1 + XCHACHA20_NONCE_BYTES_V1 + PQ_MASP_NOTE_AEAD_BYTES_V1;
/// Fixed bytes preceding the inner STARK in a canonical `PQA1` proof.
pub const PQ_MASP_AUTHORIZATION_HEADER_BYTES_V1: usize =
    4 + 4 + ML_DSA_65_PUBLIC_KEY_BYTES_V1 + ML_DSA_65_SIGNATURE_BYTES_V1;
/// Consensus maximum for the complete `PQA1` authorization proof.
pub const PQ_MASP_MAX_AUTHORIZATION_PROOF_BYTES_V1: usize =
    TAIRA_PRIVACY_MAX_PROOF_BYTES_PER_ACTION_V1 as usize;
/// Maximum inner STARK size after reserving the fixed authorization header.
pub const PQ_MASP_MAX_STARK_PROOF_BYTES_V1: usize =
    PQ_MASP_MAX_AUTHORIZATION_PROOF_BYTES_V1 - PQ_MASP_AUTHORIZATION_HEADER_BYTES_V1;
/// Exact wallet-visible encrypted-output, plaintext, and AAD schema.
///
/// Keep this descriptor beside the codec: the compiled governance profile commits to these bytes
/// and must not describe a stale or alternate wallet layout.
pub const PQ_MASP_WALLET_CIPHERTEXT_SCHEMA_V1: &[u8] = b"typed-output:recipient-id32+encapsulation-digest32+output-commitment32+ciphertext[PQE1+mlkem768-ciphertext1088+nonce24+xchacha20poly1305[PQN1+value-u128be+authorization-key-digest32+recipient-id32+nullifier-key-digest32+rho32+blinding32+memo-digest32]+tag16]|mlkem768-domain-kdf|aad:domain+asset-definition-id-u64be-length+norito+pool-id32+output-commitment32+recipient-id32+encapsulation-digest32";
pub const AUTHORIZATION_MAGIC_V1: &[u8; 4] = b"PQA1";
pub const ENCRYPTED_OUTPUT_MAGIC_V1: &[u8; 4] = b"PQE1";
const NOTE_PLAINTEXT_MAGIC_V1: &[u8; 4] = b"PQN1";
const AUTHORIZATION_CONTEXT_V1: &[u8] = b"pq-masp-stark-v1";
const AUTHORIZATION_MESSAGE_DOMAIN_V1: &[u8] = b"iroha:privacy:pq-masp:authorization-message:v1";
const AUTHORIZATION_KEY_DOMAIN_V1: &[u8] = b"iroha:privacy:pq-masp:authorization-key:v1";
const RECIPIENT_KEY_DOMAIN_V1: &[u8] = b"iroha:privacy:pq-masp:recipient-key:v1";
const ENCAPSULATION_DIGEST_DOMAIN_V1: &[u8] = b"iroha:privacy:pq-masp:mlkem-ciphertext:v1";
const NOTE_AAD_DOMAIN_V1: &[u8] = b"iroha:privacy:pq-masp:note-aad:v1";
const NOTE_NONCE_DOMAIN_V1: &[u8] = b"iroha:privacy:pq-masp:note-nonce:v1";
const NOTE_KDF_SALT_V1: &[u8] = b"iroha:privacy:pq-masp:note-kdf-salt:v1";
const NOTE_KDF_NAMESPACE_V1: &str = "pq-masp-stark-v1";
const NOTE_KDF_LABEL_V1: &str = "mlkem768-xchacha20poly1305-note-v1";
const NOTE_ENCAPSULATION_PERSONALIZATION_V1: &[u8] =
    b"iroha:privacy:pq-masp:mlkem768-encapsulation:v1";
/// SHA-256 of the encrypted-output KAT using the canonical `pq-masp-stark-v1` KDF namespace.
pub const PQ_MASP_ENCRYPTED_OUTPUT_KAT_SHA256_V1: [u8; 32] = [
    0xa4, 0xe1, 0xb4, 0xe6, 0x33, 0x4c, 0x08, 0xb7, 0xce, 0x95, 0x71, 0x37, 0x4d, 0xf2, 0x2f, 0xb3,
    0x9e, 0x31, 0xdd, 0x82, 0xe9, 0xc0, 0x23, 0x45, 0x1b, 0x0e, 0x46, 0xa6, 0xd9, 0x1c, 0xc2, 0xe2,
];
/// SHA-256 of the consensus-bound PQA1 KAT using the canonical `pq-masp-stark-v1` context.
pub const PQ_MASP_AUTHORIZATION_WIRE_KAT_SHA256_V1: [u8; 32] = [
    0x8d, 0x9d, 0x52, 0x81, 0x1f, 0xe7, 0xaf, 0x05, 0x56, 0xd2, 0x60, 0xa8, 0x53, 0xfc, 0xa5, 0x21,
    0x39, 0x82, 0xf6, 0x37, 0x18, 0x79, 0xba, 0x09, 0x47, 0x40, 0x9f, 0xb3, 0xfd, 0x27, 0x41, 0x77,
];
/// Exact decoded ML-DSA authorization wrapper.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PqMaspAuthorizationProofRefV1<'a> {
    /// Canonical ML-DSA-65 public key.
    pub(crate) public_key: &'a [u8],
    /// Canonical ML-DSA-65 detached signature.
    pub(crate) signature: &'a [u8],
    /// Inner transparent STARK proof.
    pub(crate) stark_proof: &'a [u8],
}
/// Failure of the fixed PQ-MASP authorization or note-encryption wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum PqMaspWireErrorV1 {
    /// A byte string did not have the one canonical size.
    #[error("PQ-MASP wire length is invalid")]
    InvalidLength,
    /// A version/domain magic did not match the sole first-release encoding.
    #[error("PQ-MASP wire magic is invalid")]
    InvalidMagic,
    /// A bounded length or canonical encoding operation failed.
    #[error("PQ-MASP wire encoding failed")]
    Encoding,
    /// A bounded allocation failed.
    #[error("PQ-MASP bounded allocation failed")]
    AllocationFailure,
    /// Caller-supplied randomness was the reserved all-zero seed.
    #[error("PQ-MASP randomness seed must be non-zero")]
    ZeroRandomness,
    /// The injected or operating-system cryptographic source failed.
    #[error("PQ-MASP wallet randomness is unavailable")]
    RandomnessUnavailable,
    /// The cryptographic source emitted a catastrophic repeated pattern.
    #[error("PQ-MASP wallet randomness failed its health check")]
    UnhealthyRandomness,
    /// ML-DSA-65 public-key material was malformed.
    #[error("PQ-MASP ML-DSA-65 public key is invalid")]
    InvalidAuthorizationPublicKey,
    /// ML-DSA-65 secret-key material was malformed.
    #[error("PQ-MASP ML-DSA-65 secret key is invalid")]
    InvalidAuthorizationSecretKey,
    /// ML-DSA-65 signature material was malformed.
    #[error("PQ-MASP ML-DSA-65 signature is invalid")]
    InvalidAuthorizationSignature,
    /// The ML-DSA-65 key did not match the statement key digest.
    #[error("PQ-MASP authorization key digest does not match")]
    AuthorizationKeyMismatch,
    /// The ML-DSA-65 authorization signature failed.
    #[error("PQ-MASP authorization signature verification failed")]
    AuthorizationFailed,
    /// ML-KEM-768 public-key material was malformed or non-canonical.
    #[error("PQ-MASP ML-KEM-768 public key is invalid")]
    InvalidRecipientPublicKey,
    /// ML-KEM-768 secret-key material was malformed or non-canonical.
    #[error("PQ-MASP ML-KEM-768 secret key is invalid")]
    InvalidRecipientSecretKey,
    /// ML-KEM-768 encapsulation material was malformed.
    #[error("PQ-MASP ML-KEM-768 ciphertext is invalid")]
    InvalidEncapsulation,
    /// Public recipient or encapsulation digest binding failed.
    #[error("PQ-MASP encrypted-output public binding is invalid")]
    EncryptedOutputBinding,
    /// The output ciphertext failed authenticated decryption.
    #[error("PQ-MASP encrypted-output authentication failed")]
    AuthenticationFailed,
    /// Decrypted note bytes were malformed or did not open the public commitment.
    #[error("PQ-MASP decrypted note commitment is invalid")]
    NoteCommitmentMismatch,
    /// Labeled HKDF could not produce the fixed key length.
    #[error("PQ-MASP note key derivation failed")]
    KeyDerivation,
}
fn is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}
fn checked_sha256_v1(domain: &[u8], value: &[u8]) -> Result<[u8; 32], PqMaspWireErrorV1> {
    let length = u64::try_from(value.len()).map_err(|_| PqMaspWireErrorV1::Encoding)?;
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(length.to_be_bytes());
    hash.update(value);
    Ok(hash.finalize().into())
}
/// Derive the committed digest for a canonical ML-DSA-65 authorization key.
pub fn derive_pq_masp_authorization_key_digest_v1(
    public_key: &[u8],
) -> Result<PrivacyAuthorizationKeyDigestV1, PqMaspWireErrorV1> {
    if public_key.len() != ML_DSA_65_PUBLIC_KEY_BYTES_V1
        || validate_mldsa_public_key(MlDsaSuite::MlDsa65, public_key).is_err()
    {
        return Err(PqMaspWireErrorV1::InvalidAuthorizationPublicKey);
    }
    Ok(PrivacyAuthorizationKeyDigestV1::new(checked_sha256_v1(
        AUTHORIZATION_KEY_DOMAIN_V1,
        public_key,
    )?))
}
/// Derive the committed ML-DSA-65 authorization-key digest from one canonical
/// secret key without returning or requiring a caller-supplied public key.
///
/// This is the wallet boundary used by native transaction builders. It makes
/// an inconsistent `(secret key, public key digest)` pair unrepresentable and
/// keeps public-key derivation inside the same pinned ML-DSA implementation
/// that authorizes the final PQ-MASP proof.
pub fn derive_pq_masp_authorization_key_digest_from_secret_v1(
    secret_key: &[u8],
) -> Result<PrivacyAuthorizationKeyDigestV1, PqMaspWireErrorV1> {
    let public_key = mldsa_public_key_from_secret_key(MlDsaSuite::MlDsa65, secret_key)
        .map_err(|_| PqMaspWireErrorV1::InvalidAuthorizationSecretKey)?;
    derive_pq_masp_authorization_key_digest_v1(&public_key)
}
/// Validate an ML-DSA-65 secret key and its exact statement key binding.
pub(super) fn validate_pq_masp_authorization_secret_key_v1(
    expected_key_digest: PrivacyAuthorizationKeyDigestV1,
    secret_key: &[u8],
) -> Result<(), PqMaspWireErrorV1> {
    let public_key = mldsa_public_key_from_secret_key(MlDsaSuite::MlDsa65, secret_key)
        .map_err(|_| PqMaspWireErrorV1::InvalidAuthorizationSecretKey)?;
    if derive_pq_masp_authorization_key_digest_v1(&public_key)? != expected_key_digest {
        return Err(PqMaspWireErrorV1::AuthorizationKeyMismatch);
    }
    Ok(())
}
/// Derive the public identifier for a canonical ML-KEM-768 recipient key.
pub fn derive_pq_masp_recipient_id_v1(
    public_key: &[u8],
) -> Result<PrivacyRecipientIdV1, PqMaspWireErrorV1> {
    if public_key.len() != ML_KEM_768_PUBLIC_KEY_BYTES_V1
        || MlKemSuite::MlKem768
            .validate_public_key(public_key)
            .is_err()
    {
        return Err(PqMaspWireErrorV1::InvalidRecipientPublicKey);
    }
    Ok(PrivacyRecipientIdV1::new(checked_sha256_v1(
        RECIPIENT_KEY_DOMAIN_V1,
        public_key,
    )?))
}
pub(super) fn derive_encapsulation_digest_v1(
    ml_kem_ciphertext: &[u8],
) -> Result<PrivacyEncryptionKeyV1, PqMaspWireErrorV1> {
    if ml_kem_ciphertext.len() != ML_KEM_768_CIPHERTEXT_BYTES_V1
        || validate_mlkem_ciphertext(MlKemSuite::MlKem768, ml_kem_ciphertext).is_err()
    {
        return Err(PqMaspWireErrorV1::InvalidEncapsulation);
    }
    Ok(PrivacyEncryptionKeyV1::new(checked_sha256_v1(
        ENCAPSULATION_DIGEST_DOMAIN_V1,
        ml_kem_ciphertext,
    )?))
}
fn authorization_message_v1(
    statement_digest: PrivacyStatementDigestV1,
    consensus_binding_digest: PrivacyNativeConsensusBindingDigestV1,
    stark_proof: &[u8],
) -> Result<[u8; 32], PqMaspWireErrorV1> {
    let proof_length = u64::try_from(stark_proof.len()).map_err(|_| PqMaspWireErrorV1::Encoding)?;
    let proof_digest = Sha256::digest(stark_proof);
    let mut hash = Sha256::new();
    hash.update(AUTHORIZATION_MESSAGE_DOMAIN_V1);
    hash.update(statement_digest.as_bytes());
    hash.update(consensus_binding_digest.as_bytes());
    hash.update(proof_length.to_be_bytes());
    hash.update(proof_digest);
    Ok(hash.finalize().into())
}
fn validate_stark_proof_size_v1(stark_proof: &[u8]) -> Result<(), PqMaspWireErrorV1> {
    if stark_proof.is_empty() || stark_proof.len() > PQ_MASP_MAX_STARK_PROOF_BYTES_V1 {
        return Err(PqMaspWireErrorV1::InvalidLength);
    }
    Ok(())
}
/// Decode exactly one ML-DSA-65 authorization and inner STARK proof.
pub fn decode_pq_masp_authorization_proof_v1(
    bytes: &[u8],
) -> Result<PqMaspAuthorizationProofRefV1<'_>, PqMaspWireErrorV1> {
    if bytes.len() < PQ_MASP_AUTHORIZATION_HEADER_BYTES_V1
        || bytes.len() > PQ_MASP_MAX_AUTHORIZATION_PROOF_BYTES_V1
    {
        return Err(PqMaspWireErrorV1::InvalidLength);
    }
    if bytes.get(..4) != Some(AUTHORIZATION_MAGIC_V1.as_slice()) {
        return Err(PqMaspWireErrorV1::InvalidMagic);
    }
    let declared = bytes
        .get(4..8)
        .and_then(|value| <[u8; 4]>::try_from(value).ok())
        .map(u32::from_be_bytes)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or(PqMaspWireErrorV1::Encoding)?;
    if declared == 0 || declared > PQ_MASP_MAX_STARK_PROOF_BYTES_V1 {
        return Err(PqMaspWireErrorV1::InvalidLength);
    }
    let expected = PQ_MASP_AUTHORIZATION_HEADER_BYTES_V1
        .checked_add(declared)
        .ok_or(PqMaspWireErrorV1::Encoding)?;
    if bytes.len() != expected {
        return Err(PqMaspWireErrorV1::InvalidLength);
    }
    let public_key_start = 8;
    let signature_start = public_key_start + ML_DSA_65_PUBLIC_KEY_BYTES_V1;
    let stark_start = signature_start + ML_DSA_65_SIGNATURE_BYTES_V1;
    let public_key = &bytes[public_key_start..signature_start];
    let signature = &bytes[signature_start..stark_start];
    let stark_proof = &bytes[stark_start..];
    derive_pq_masp_authorization_key_digest_v1(public_key)?;
    if validate_mldsa_signature(MlDsaSuite::MlDsa65, signature).is_err() {
        return Err(PqMaspWireErrorV1::InvalidAuthorizationSignature);
    }
    Ok(PqMaspAuthorizationProofRefV1 {
        public_key,
        signature,
        stark_proof,
    })
}
fn encode_authorization_proof_v1(
    public_key: &[u8],
    signature: &[u8],
    stark_proof: &[u8],
) -> Result<Vec<u8>, PqMaspWireErrorV1> {
    derive_pq_masp_authorization_key_digest_v1(public_key)?;
    if signature.len() != ML_DSA_65_SIGNATURE_BYTES_V1
        || validate_mldsa_signature(MlDsaSuite::MlDsa65, signature).is_err()
    {
        return Err(PqMaspWireErrorV1::InvalidAuthorizationSignature);
    }
    validate_stark_proof_size_v1(stark_proof)?;
    let stark_length = u32::try_from(stark_proof.len()).map_err(|_| PqMaspWireErrorV1::Encoding)?;
    let capacity = PQ_MASP_AUTHORIZATION_HEADER_BYTES_V1
        .checked_add(stark_proof.len())
        .ok_or(PqMaspWireErrorV1::Encoding)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| PqMaspWireErrorV1::AllocationFailure)?;
    bytes.extend_from_slice(AUTHORIZATION_MAGIC_V1);
    bytes.extend_from_slice(&stark_length.to_be_bytes());
    bytes.extend_from_slice(public_key);
    bytes.extend_from_slice(signature);
    bytes.extend_from_slice(stark_proof);
    Ok(bytes)
}
/// Sign a statement, consensus binding, and exact inner STARK with ML-DSA-65.
pub fn authorize_pq_masp_stark_proof_v1(
    statement_digest: PrivacyStatementDigestV1,
    consensus_binding_digest: PrivacyNativeConsensusBindingDigestV1,
    expected_key_digest: PrivacyAuthorizationKeyDigestV1,
    secret_key: &[u8],
    stark_proof: &[u8],
    seed: HedgedRngSeed,
) -> Result<Vec<u8>, PqMaspWireErrorV1> {
    if seed.is_all_zero() {
        return Err(PqMaspWireErrorV1::ZeroRandomness);
    }
    validate_stark_proof_size_v1(stark_proof)?;
    let public_key = mldsa_public_key_from_secret_key(MlDsaSuite::MlDsa65, secret_key)
        .map_err(|_| PqMaspWireErrorV1::InvalidAuthorizationSecretKey)?;
    if derive_pq_masp_authorization_key_digest_v1(&public_key)? != expected_key_digest {
        return Err(PqMaspWireErrorV1::AuthorizationKeyMismatch);
    }
    let message =
        authorization_message_v1(statement_digest, consensus_binding_digest, stark_proof)?;
    let mut rng = deterministic_chacha20_rng(seed, AUTHORIZATION_MESSAGE_DOMAIN_V1);
    let signature = sign_mldsa(
        MlDsaSuite::MlDsa65,
        secret_key,
        AUTHORIZATION_CONTEXT_V1,
        &message,
        &mut rng,
    )
    .map_err(|_| PqMaspWireErrorV1::InvalidAuthorizationSecretKey)?;
    encode_authorization_proof_v1(&public_key, signature.as_bytes(), stark_proof)
}
/// Verify the ML-DSA-65 wrapper and return the exact inner STARK proof.
pub fn verify_pq_masp_authorization_v1<'a>(
    statement_digest: PrivacyStatementDigestV1,
    consensus_binding_digest: PrivacyNativeConsensusBindingDigestV1,
    expected_key_digest: PrivacyAuthorizationKeyDigestV1,
    bytes: &'a [u8],
) -> Result<PqMaspAuthorizationProofRefV1<'a>, PqMaspWireErrorV1> {
    let decoded = decode_pq_masp_authorization_proof_v1(bytes)?;
    if derive_pq_masp_authorization_key_digest_v1(decoded.public_key)? != expected_key_digest {
        return Err(PqMaspWireErrorV1::AuthorizationKeyMismatch);
    }
    let message = authorization_message_v1(
        statement_digest,
        consensus_binding_digest,
        decoded.stark_proof,
    )?;
    verify_mldsa(
        MlDsaSuite::MlDsa65,
        decoded.public_key,
        AUTHORIZATION_CONTEXT_V1,
        &message,
        decoded.signature,
    )
    .map_err(|_| PqMaspWireErrorV1::AuthorizationFailed)?;
    Ok(decoded)
}
fn note_plaintext_bytes_v1(note: &PqMaspNotePlaintextV1) -> Zeroizing<Vec<u8>> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(PQ_MASP_NOTE_PLAINTEXT_BYTES_V1));
    bytes.extend_from_slice(NOTE_PLAINTEXT_MAGIC_V1);
    bytes.extend_from_slice(&note.value.to_be_bytes());
    bytes.extend_from_slice(note.authorization_key_digest.as_bytes());
    bytes.extend_from_slice(note.recipient_key_digest.as_bytes());
    bytes.extend_from_slice(&note.nullifier_key_digest);
    bytes.extend_from_slice(&note.rho);
    bytes.extend_from_slice(&note.blinding);
    bytes.extend_from_slice(&note.memo_digest);
    bytes
}
#[cfg(test)]
fn take_32_v1(bytes: &[u8], start: usize) -> Result<[u8; 32], PqMaspWireErrorV1> {
    bytes
        .get(start..start + 32)
        .and_then(|value| value.try_into().ok())
        .ok_or(PqMaspWireErrorV1::InvalidLength)
}
#[cfg(test)]
fn decode_note_plaintext_v1(bytes: &[u8]) -> Result<PqMaspNotePlaintextV1, PqMaspWireErrorV1> {
    if bytes.len() != PQ_MASP_NOTE_PLAINTEXT_BYTES_V1 {
        return Err(PqMaspWireErrorV1::InvalidLength);
    }
    if bytes.get(..4) != Some(NOTE_PLAINTEXT_MAGIC_V1.as_slice()) {
        return Err(PqMaspWireErrorV1::InvalidMagic);
    }
    let value = bytes
        .get(4..20)
        .and_then(|value| <[u8; 16]>::try_from(value).ok())
        .map(u128::from_be_bytes)
        .ok_or(PqMaspWireErrorV1::InvalidLength)?;
    Ok(PqMaspNotePlaintextV1 {
        value,
        authorization_key_digest: PrivacyAuthorizationKeyDigestV1::new(take_32_v1(bytes, 20)?),
        recipient_key_digest: PrivacyRecipientIdV1::new(take_32_v1(bytes, 52)?),
        nullifier_key_digest: take_32_v1(bytes, 84)?,
        rho: take_32_v1(bytes, 116)?,
        blinding: take_32_v1(bytes, 148)?,
        memo_digest: take_32_v1(bytes, 180)?,
    })
}
fn note_aad_v1(
    statement: &PqMaspStarkStatementV1,
    commitment: PrivacyCommitmentV1,
    recipient: PrivacyRecipientIdV1,
    encapsulation_digest: PrivacyEncryptionKeyV1,
) -> Result<Vec<u8>, PqMaspWireErrorV1> {
    let asset = norito::to_bytes(&statement.asset_definition_id)
        .map_err(|_| PqMaspWireErrorV1::Encoding)?;
    let capacity = NOTE_AAD_DOMAIN_V1
        .len()
        .checked_add(8)
        .and_then(|value| value.checked_add(asset.len()))
        .and_then(|value| value.checked_add(32 * 4))
        .ok_or(PqMaspWireErrorV1::Encoding)?;
    let mut aad = Vec::new();
    aad.try_reserve_exact(capacity)
        .map_err(|_| PqMaspWireErrorV1::AllocationFailure)?;
    aad.extend_from_slice(NOTE_AAD_DOMAIN_V1);
    aad.extend_from_slice(
        &u64::try_from(asset.len())
            .map_err(|_| PqMaspWireErrorV1::Encoding)?
            .to_be_bytes(),
    );
    aad.extend_from_slice(&asset);
    aad.extend_from_slice(statement.pool_id.as_bytes());
    aad.extend_from_slice(commitment.as_bytes());
    aad.extend_from_slice(recipient.as_bytes());
    aad.extend_from_slice(encapsulation_digest.as_bytes());
    Ok(aad)
}
fn derive_note_key_v1(
    shared_secret: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<[u8; 32]>, PqMaspWireErrorV1> {
    let context: [u8; 32] = Sha256::digest(aad).into();
    let derived = derive_labeled_hkdf(
        HkdfSuite::Sha3_256,
        Some(NOTE_KDF_SALT_V1),
        shared_secret,
        HkdfDomain::new(NOTE_KDF_NAMESPACE_V1, NOTE_KDF_LABEL_V1),
        &context,
        32,
    )
    .map_err(|_| PqMaspWireErrorV1::KeyDerivation)?;
    let mut key = Zeroizing::new([0_u8; 32]);
    key.copy_from_slice(&derived);
    Ok(key)
}
fn derive_nonce_v1(
    seed: &HedgedRngSeed,
    commitment: PrivacyCommitmentV1,
    ml_kem_ciphertext: &[u8],
) -> Result<[u8; XCHACHA20_NONCE_BYTES_V1], PqMaspWireErrorV1> {
    if seed.is_all_zero() {
        return Err(PqMaspWireErrorV1::ZeroRandomness);
    }
    let mut hash = Sha256::new();
    hash.update(NOTE_NONCE_DOMAIN_V1);
    hash.update(seed.as_bytes());
    hash.update(commitment.as_bytes());
    hash.update(
        u64::try_from(ml_kem_ciphertext.len())
            .map_err(|_| PqMaspWireErrorV1::Encoding)?
            .to_be_bytes(),
    );
    hash.update(ml_kem_ciphertext);
    let digest: [u8; 32] = hash.finalize().into();
    let mut nonce = [0_u8; XCHACHA20_NONCE_BYTES_V1];
    nonce.copy_from_slice(&digest[..XCHACHA20_NONCE_BYTES_V1]);
    if is_zero(&nonce) {
        return Err(PqMaspWireErrorV1::ZeroRandomness);
    }
    Ok(nonce)
}
fn parse_encrypted_output_v1(
    output: &PrivacyEncryptedOutputV1,
) -> Result<(&[u8], &[u8], &[u8]), PqMaspWireErrorV1> {
    if output.recipient.is_zero()
        || output.ephemeral_public_key.is_zero()
        || output.commitment.is_zero()
        || output.ciphertext.len() != PQ_MASP_ENCRYPTED_OUTPUT_BYTES_V1
    {
        return Err(PqMaspWireErrorV1::InvalidLength);
    }
    if output.ciphertext.get(..4) != Some(ENCRYPTED_OUTPUT_MAGIC_V1.as_slice()) {
        return Err(PqMaspWireErrorV1::InvalidMagic);
    }
    let kem_start = 4;
    let nonce_start = kem_start + ML_KEM_768_CIPHERTEXT_BYTES_V1;
    let aead_start = nonce_start + XCHACHA20_NONCE_BYTES_V1;
    let ml_kem_ciphertext = &output.ciphertext[kem_start..nonce_start];
    let nonce = &output.ciphertext[nonce_start..aead_start];
    let aead_ciphertext = &output.ciphertext[aead_start..];
    if is_zero(nonce) || is_zero(aead_ciphertext) {
        return Err(PqMaspWireErrorV1::InvalidEncapsulation);
    }
    let expected_digest = derive_encapsulation_digest_v1(ml_kem_ciphertext)?;
    if expected_digest != output.ephemeral_public_key {
        return Err(PqMaspWireErrorV1::EncryptedOutputBinding);
    }
    Ok((ml_kem_ciphertext, nonce, aead_ciphertext))
}
/// Validate the exact public ML-KEM/XChaCha encrypted-output shape.
pub fn validate_pq_masp_encrypted_output_v1(
    output: &PrivacyEncryptedOutputV1,
) -> Result<(), PqMaspWireErrorV1> {
    parse_encrypted_output_v1(output).map(|_| ())
}
/// Encrypt one fixed-width PQ-MASP note for an ML-KEM-768 recipient.
pub fn encrypt_pq_masp_note_v1(
    statement: &PqMaspStarkStatementV1,
    note: &PqMaspNotePlaintextV1,
    recipient_public_key: &[u8],
    seed: HedgedRngSeed,
) -> Result<(PrivacyCommitmentV1, PrivacyEncryptedOutputV1), PqMaspWireErrorV1> {
    if seed.is_all_zero() {
        return Err(PqMaspWireErrorV1::ZeroRandomness);
    }
    let recipient = derive_pq_masp_recipient_id_v1(recipient_public_key)?;
    if recipient != note.recipient_key_digest {
        return Err(PqMaspWireErrorV1::EncryptedOutputBinding);
    }
    let commitment = derive_pq_masp_note_commitment_v1(statement, note)
        .map_err(|_| PqMaspWireErrorV1::NoteCommitmentMismatch)?;
    let mut personalization = Vec::new();
    personalization
        .try_reserve_exact(NOTE_ENCAPSULATION_PERSONALIZATION_V1.len() + 32)
        .map_err(|_| PqMaspWireErrorV1::AllocationFailure)?;
    personalization.extend_from_slice(NOTE_ENCAPSULATION_PERSONALIZATION_V1);
    personalization.extend_from_slice(commitment.as_bytes());
    let (shared_secret, ml_kem_ciphertext) = encapsulate_mlkem_from_seed(
        MlKemSuite::MlKem768,
        recipient_public_key,
        seed.clone(),
        &personalization,
    )
    .map_err(|_| PqMaspWireErrorV1::InvalidRecipientPublicKey)?;
    let encapsulation_digest = derive_encapsulation_digest_v1(ml_kem_ciphertext.as_bytes())?;
    let aad = note_aad_v1(statement, commitment, recipient, encapsulation_digest)?;
    let key_bytes = derive_note_key_v1(shared_secret.as_bytes(), &aad)?;
    let nonce_bytes = derive_nonce_v1(&seed, commitment, ml_kem_ciphertext.as_bytes())?;
    let key: chacha20poly1305::Key = (*key_bytes).into();
    let nonce: chacha20poly1305::XNonce = nonce_bytes.into();
    let cipher = XChaCha20Poly1305::new(&key);
    let plaintext = note_plaintext_bytes_v1(note);
    let aead_ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: &plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| PqMaspWireErrorV1::AuthenticationFailed)?;
    if aead_ciphertext.len() != PQ_MASP_NOTE_AEAD_BYTES_V1 {
        return Err(PqMaspWireErrorV1::Encoding);
    }
    let mut ciphertext = Vec::new();
    ciphertext
        .try_reserve_exact(PQ_MASP_ENCRYPTED_OUTPUT_BYTES_V1)
        .map_err(|_| PqMaspWireErrorV1::AllocationFailure)?;
    ciphertext.extend_from_slice(ENCRYPTED_OUTPUT_MAGIC_V1);
    ciphertext.extend_from_slice(ml_kem_ciphertext.as_bytes());
    ciphertext.extend_from_slice(&nonce_bytes);
    ciphertext.extend_from_slice(&aead_ciphertext);
    let output = PrivacyEncryptedOutputV1 {
        recipient,
        ephemeral_public_key: encapsulation_digest,
        commitment,
        ciphertext,
    };
    validate_pq_masp_encrypted_output_v1(&output)?;
    Ok((commitment, output))
}
#[cfg(test)]
/// Decrypt and authenticate one PQ-MASP note with an ML-KEM-768 secret key.
pub fn decrypt_pq_masp_note_v1(
    statement: &PqMaspStarkStatementV1,
    output: &PrivacyEncryptedOutputV1,
    recipient_secret_key: &[u8],
) -> Result<PqMaspNotePlaintextV1, PqMaspWireErrorV1> {
    let (ml_kem_ciphertext, nonce, aead_ciphertext) = parse_encrypted_output_v1(output)?;
    let recipient_public_key = MlKemSuite::MlKem768
        .public_key_from_secret_key(recipient_secret_key)
        .map_err(|_| PqMaspWireErrorV1::InvalidRecipientSecretKey)?;
    if derive_pq_masp_recipient_id_v1(recipient_public_key)? != output.recipient {
        return Err(PqMaspWireErrorV1::EncryptedOutputBinding);
    }
    let shared_secret = decapsulate_mlkem(
        MlKemSuite::MlKem768,
        recipient_secret_key,
        ml_kem_ciphertext,
    )
    .map_err(|_| PqMaspWireErrorV1::InvalidRecipientSecretKey)?;
    let aad = note_aad_v1(
        statement,
        output.commitment,
        output.recipient,
        output.ephemeral_public_key,
    )?;
    let key_bytes = derive_note_key_v1(shared_secret.as_bytes(), &aad)?;
    let nonce_bytes: [u8; XCHACHA20_NONCE_BYTES_V1] = nonce
        .try_into()
        .map_err(|_| PqMaspWireErrorV1::InvalidLength)?;
    let key: chacha20poly1305::Key = (*key_bytes).into();
    let nonce: chacha20poly1305::XNonce = nonce_bytes.into();
    let cipher = XChaCha20Poly1305::new(&key);
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: aead_ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| PqMaspWireErrorV1::AuthenticationFailed)?,
    );
    let note = decode_note_plaintext_v1(&plaintext)?;
    if note.recipient_key_digest != output.recipient
        || derive_pq_masp_note_commitment_v1(statement, &note)
            .map_err(|_| PqMaspWireErrorV1::NoteCommitmentMismatch)?
            != output.commitment
    {
        return Err(PqMaspWireErrorV1::NoteCommitmentMismatch);
    }
    Ok(note)
}
/// Recompute and check the ordered output-key digest after wallet encryption.
pub fn validate_pq_masp_note_encryption_key_digest_v1(
    statement: &PqMaspStarkStatementV1,
) -> Result<(), PqMaspWireErrorV1> {
    for output in &statement.encrypted_outputs {
        validate_pq_masp_encrypted_output_v1(output)?;
    }
    if derive_pq_masp_note_encryption_keys_digest_v1(statement)
        .map_err(|_| PqMaspWireErrorV1::Encoding)?
        != statement.note_encryption_key_digest
    {
        return Err(PqMaspWireErrorV1::EncryptedOutputBinding);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy_engines::pq_masp::relation::derive_pq_masp_nullifier_key_digest_v1;
    use iroha_data_model::{
        asset::AssetDefinitionId,
        privacy::{
            PrivacyEngineManifestDigestV1, PrivacyNoteEncryptionKeyDigestV1,
            PrivacyParameterDigestV1, PrivacyParameterIdV1, PrivacyPoolIdV1,
            PrivacyPqAuthorizationProfileV1, PrivacyPqNoteEncryptionProfileV1, PrivacyProtocolIdV1,
            PrivacyRootV1, PrivacyStatementContextV1, PrivacyStatementSchemaDigestV1,
            PrivacyTransactionIntentDigestV1, PrivacyVerifierDigestV1,
        },
    };
    use iroha_model_base::domain::DomainId;
    use iroha_model_base::name::Name;
    use rand::{SeedableRng as _, TryCryptoRng, TryRngCore, rngs::StdRng};
    use soranet_pq::{generate_mldsa_keypair_from_seed, generate_mlkem_keypair_from_seed};
    use std::str::FromStr as _;
    fn raw(byte: u8) -> [u8; 32] {
        [byte; 32]
    }
    #[derive(Debug)]
    struct InjectedWalletEntropyError;
    impl core::fmt::Display for InjectedWalletEntropyError {
        fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            formatter.write_str("injected PQ-MASP wallet entropy failure")
        }
    }
    struct AdversarialWalletRng {
        fail: bool,
    }
    impl TryRngCore for AdversarialWalletRng {
        type Error = InjectedWalletEntropyError;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Err(InjectedWalletEntropyError)
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Err(InjectedWalletEntropyError)
        }
        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
            if self.fail {
                let midpoint = destination.len() / 2;
                destination[..midpoint].fill(0x51);
                return Err(InjectedWalletEntropyError);
            }
            destination.fill(0x61);
            Ok(())
        }
    }
    impl TryCryptoRng for AdversarialWalletRng {}
    fn statement_shell() -> PqMaspStarkStatementV1 {
        PqMaspStarkStatementV1 {
            context: PrivacyStatementContextV1 {
                network_id: iroha_data_model::NetworkId::from_genesis_hash(iroha_crypto::HashOf::<
                    iroha_data_model::block::BlockHeader,
                >::from_untyped_unchecked(
                    iroha_crypto::Hash::prehashed([0xC2; 32]),
                )),
                action_index: 0,
                transaction_intent_digest: PrivacyTransactionIntentDigestV1::new(raw(1)),
                parameter_id: PrivacyParameterIdV1::new(raw(2)),
                parameter_digest: PrivacyParameterDigestV1::new(raw(3)),
                verifier_digest: PrivacyVerifierDigestV1::new(raw(4)),
                statement_schema_digest: PrivacyStatementSchemaDigestV1::new(raw(5)),
                engine_manifest_digest: PrivacyEngineManifestDigestV1::new(raw(6)),
            },
            asset_definition_id: AssetDefinitionId::derive_from_components(
                DomainId::try_new("privacy", "universal").expect("domain"),
                Name::from_str("pq_note").expect("asset name"),
            ),
            pool_id: PrivacyPoolIdV1::new(raw(7)),
            anchor: PrivacyRootV1::new(raw(8)),
            anchor_epoch: 1,
            nullifiers: vec![iroha_data_model::privacy::PrivacyNullifierV1::new(raw(9))],
            output_commitments: Vec::new(),
            encrypted_outputs: Vec::new(),
            authorization_profile: PrivacyPqAuthorizationProfileV1::MlDsa65,
            authorization_key_digest: PrivacyAuthorizationKeyDigestV1::new(raw(10)),
            note_encryption_profile: PrivacyPqNoteEncryptionProfileV1::MlKem768XChaCha20Poly1305,
            note_encryption_key_digest: PrivacyNoteEncryptionKeyDigestV1::new(raw(11)),
            authorization_epoch: 1,
        }
    }
    #[test]
    fn protocol_domains_use_the_one_canonical_external_identifier() {
        let label = PrivacyProtocolIdV1::PqMaspStarkV1.canonical_label();
        assert_eq!(AUTHORIZATION_CONTEXT_V1, label.as_bytes());
        assert_eq!(NOTE_KDF_NAMESPACE_V1, label);
        assert_ne!(AUTHORIZATION_CONTEXT_V1, b"iroha-pq-masp-stark-v1");
        assert_ne!(NOTE_KDF_NAMESPACE_V1, "iroha/privacy/pq-masp-stark-v1");
    }
    #[test]
    fn dependency_parameter_sizes_match_the_pinned_wire() {
        assert_eq!(
            MlDsaSuite::MlDsa65.public_key_len(),
            ML_DSA_65_PUBLIC_KEY_BYTES_V1
        );
        assert_eq!(
            MlDsaSuite::MlDsa65.signature_len(),
            ML_DSA_65_SIGNATURE_BYTES_V1
        );
        assert_eq!(
            MlKemSuite::MlKem768.public_key_len(),
            ML_KEM_768_PUBLIC_KEY_BYTES_V1
        );
        assert_eq!(
            MlKemSuite::MlKem768.ciphertext_len(),
            ML_KEM_768_CIPHERTEXT_BYTES_V1
        );
    }
    #[test]
    fn wallet_schema_matches_the_exact_plaintext_and_aad_layout() {
        assert_eq!(
            PQ_MASP_WALLET_CIPHERTEXT_SCHEMA_V1,
            b"typed-output:recipient-id32+encapsulation-digest32+output-commitment32+ciphertext[PQE1+mlkem768-ciphertext1088+nonce24+xchacha20poly1305[PQN1+value-u128be+authorization-key-digest32+recipient-id32+nullifier-key-digest32+rho32+blinding32+memo-digest32]+tag16]|mlkem768-domain-kdf|aad:domain+asset-definition-id-u64be-length+norito+pool-id32+output-commitment32+recipient-id32+encapsulation-digest32"
        );
        let statement = statement_shell();
        let value = u128::from_be_bytes([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10,
        ]);
        let note = PqMaspNotePlaintextV1 {
            value,
            authorization_key_digest: PrivacyAuthorizationKeyDigestV1::new(raw(0x21)),
            recipient_key_digest: PrivacyRecipientIdV1::new(raw(0x32)),
            nullifier_key_digest: raw(0x43),
            rho: raw(0x54),
            blinding: raw(0x65),
            memo_digest: raw(0x76),
        };
        let plaintext = note_plaintext_bytes_v1(&note);
        assert_eq!(plaintext.len(), PQ_MASP_NOTE_PLAINTEXT_BYTES_V1);
        assert_eq!(&plaintext[0..4], NOTE_PLAINTEXT_MAGIC_V1);
        assert_eq!(&plaintext[4..20], &value.to_be_bytes());
        assert_eq!(&plaintext[20..52], note.authorization_key_digest.as_bytes());
        assert_eq!(&plaintext[52..84], note.recipient_key_digest.as_bytes());
        assert_eq!(&plaintext[84..116], &note.nullifier_key_digest);
        assert_eq!(&plaintext[116..148], &note.rho);
        assert_eq!(&plaintext[148..180], &note.blinding);
        assert_eq!(&plaintext[180..212], &note.memo_digest);
        assert_eq!(
            decode_note_plaintext_v1(&plaintext).expect("canonical plaintext"),
            note
        );
        let mut stale_little_endian = plaintext.to_vec();
        stale_little_endian[4..20].copy_from_slice(&value.to_le_bytes());
        let stale_note = decode_note_plaintext_v1(&stale_little_endian)
            .expect("the byte string canonically denotes a different value");
        assert_ne!(stale_note, note);
        assert_ne!(
            derive_pq_masp_note_commitment_v1(&statement, &stale_note)
                .expect("stale layout still forms a distinct note"),
            derive_pq_masp_note_commitment_v1(&statement, &note)
                .expect("canonical note commitment"),
            "a stale little-endian wallet layout must not alias the canonical note"
        );
        let commitment = PrivacyCommitmentV1::new(raw(0x87));
        let recipient = PrivacyRecipientIdV1::new(raw(0x98));
        let encapsulation_digest = PrivacyEncryptionKeyV1::new(raw(0xa9));
        let aad = note_aad_v1(&statement, commitment, recipient, encapsulation_digest)
            .expect("canonical note AAD");
        let asset = norito::to_bytes(&statement.asset_definition_id).expect("canonical asset");
        let mut expected_aad = Vec::new();
        expected_aad.extend_from_slice(NOTE_AAD_DOMAIN_V1);
        expected_aad.extend_from_slice(
            &u64::try_from(asset.len())
                .expect("asset length fits u64")
                .to_be_bytes(),
        );
        expected_aad.extend_from_slice(&asset);
        expected_aad.extend_from_slice(statement.pool_id.as_bytes());
        expected_aad.extend_from_slice(commitment.as_bytes());
        expected_aad.extend_from_slice(recipient.as_bytes());
        expected_aad.extend_from_slice(encapsulation_digest.as_bytes());
        assert_eq!(aad, expected_aad);
        let reordered = note_aad_v1(
            &statement,
            commitment,
            PrivacyRecipientIdV1::new(raw(0xa9)),
            PrivacyEncryptionKeyV1::new(raw(0x98)),
        )
        .expect("structurally valid but substituted AAD");
        assert_ne!(
            aad, reordered,
            "recipient and encapsulation roles must not alias"
        );
    }
    #[test]
    fn mlkem_xchacha_note_roundtrip_and_mutations_fail_closed() {
        let recipient_keys = generate_mlkem_keypair_from_seed(
            MlKemSuite::MlKem768,
            HedgedRngSeed::from_entropy(raw(21)),
            b"pq-masp-wire-recipient",
        )
        .expect("ML-KEM recipient");
        let mut statement = statement_shell();
        let note = PqMaspNotePlaintextV1 {
            value: 42,
            authorization_key_digest: statement.authorization_key_digest,
            recipient_key_digest: derive_pq_masp_recipient_id_v1(recipient_keys.public_key())
                .expect("recipient digest"),
            nullifier_key_digest: derive_pq_masp_nullifier_key_digest_v1(&raw(22))
                .expect("nullifier key"),
            rho: raw(23),
            blinding: raw(24),
            memo_digest: raw(25),
        };
        assert_eq!(
            super::super::encrypt_pq_masp_note_v1_with_rng(
                &statement,
                &note,
                recipient_keys.public_key(),
                &mut AdversarialWalletRng { fail: true },
            ),
            Err(PqMaspWireErrorV1::RandomnessUnavailable)
        );
        assert_eq!(
            super::super::encrypt_pq_masp_note_v1_with_rng(
                &statement,
                &note,
                recipient_keys.public_key(),
                &mut AdversarialWalletRng { fail: false },
            ),
            Err(PqMaspWireErrorV1::UnhealthyRandomness)
        );
        let (facade_commitment, facade_output) = super::super::encrypt_pq_masp_note_v1_with_rng(
            &statement,
            &note,
            recipient_keys.public_key(),
            &mut StdRng::from_seed([0x27; 32]),
        )
        .expect("public wallet facade encrypts");
        assert_eq!(
            decrypt_pq_masp_note_v1(&statement, &facade_output, recipient_keys.secret_key(),)
                .expect("public wallet facade decrypts"),
            note
        );
        let (commitment, output) = encrypt_pq_masp_note_v1(
            &statement,
            &note,
            recipient_keys.public_key(),
            HedgedRngSeed::from_entropy(raw(26)),
        )
        .expect("encrypt");
        assert_eq!(facade_commitment, commitment);
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(&output.ciphertext)),
            PQ_MASP_ENCRYPTED_OUTPUT_KAT_SHA256_V1,
            "canonical PQ-MASP encrypted-output wire changed"
        );
        statement.output_commitments.push(commitment);
        statement.encrypted_outputs.push(output.clone());
        statement.note_encryption_key_digest =
            derive_pq_masp_note_encryption_keys_digest_v1(&statement).expect("key-set digest");
        validate_pq_masp_note_encryption_key_digest_v1(&statement).expect("public wire");
        assert_eq!(
            decrypt_pq_masp_note_v1(&statement, &output, recipient_keys.secret_key())
                .expect("decrypt"),
            note
        );
        let mut cross_pool = statement.clone();
        cross_pool.pool_id = PrivacyPoolIdV1::new(raw(80));
        assert_eq!(
            decrypt_pq_masp_note_v1(&cross_pool, &output, recipient_keys.secret_key()),
            Err(PqMaspWireErrorV1::AuthenticationFailed)
        );
        let mut cross_asset = statement.clone();
        cross_asset.asset_definition_id = AssetDefinitionId::derive_from_components(
            DomainId::try_new("privacy", "universal").expect("domain"),
            Name::from_str("other_pq_note").expect("asset name"),
        );
        assert_eq!(
            decrypt_pq_masp_note_v1(&cross_asset, &output, recipient_keys.secret_key()),
            Err(PqMaspWireErrorV1::AuthenticationFailed)
        );
        let mut mutations = Vec::new();
        let mut truncated = output.clone();
        truncated.ciphertext.pop();
        mutations.push(truncated);
        let mut trailing = output.clone();
        trailing.ciphertext.push(0);
        mutations.push(trailing);
        for index in [
            0,
            4,
            4 + ML_KEM_768_CIPHERTEXT_BYTES_V1,
            PQ_MASP_ENCRYPTED_OUTPUT_BYTES_V1 - 1,
        ] {
            let mut mutated = output.clone();
            mutated.ciphertext[index] ^= 1;
            mutations.push(mutated);
        }
        let mut recipient = output.clone();
        recipient.recipient = PrivacyRecipientIdV1::new(raw(90));
        mutations.push(recipient);
        let mut ephemeral = output.clone();
        ephemeral.ephemeral_public_key = PrivacyEncryptionKeyV1::new(raw(91));
        mutations.push(ephemeral);
        let mut commitment = output.clone();
        commitment.commitment = PrivacyCommitmentV1::new(raw(92));
        mutations.push(commitment);
        let mut zero_nonce = output.clone();
        let nonce_start = 4 + ML_KEM_768_CIPHERTEXT_BYTES_V1;
        zero_nonce.ciphertext[nonce_start..nonce_start + XCHACHA20_NONCE_BYTES_V1].fill(0);
        mutations.push(zero_nonce);
        let mut zero_aead = output.clone();
        zero_aead.ciphertext[nonce_start + XCHACHA20_NONCE_BYTES_V1..].fill(0);
        mutations.push(zero_aead);
        for mutated in mutations {
            assert!(
                validate_pq_masp_encrypted_output_v1(&mutated).is_err()
                    || decrypt_pq_masp_note_v1(&statement, &mutated, recipient_keys.secret_key())
                        .is_err()
            );
        }
        let mut self_consistent_encapsulation_substitution = output.clone();
        self_consistent_encapsulation_substitution.ciphertext[4] ^= 1;
        let kem_end = 4 + ML_KEM_768_CIPHERTEXT_BYTES_V1;
        self_consistent_encapsulation_substitution.ephemeral_public_key =
            derive_encapsulation_digest_v1(
                &self_consistent_encapsulation_substitution.ciphertext[4..kem_end],
            )
            .expect("mutated encapsulation remains structurally encoded");
        let mut substituted_statement = statement.clone();
        substituted_statement.encrypted_outputs[0] =
            self_consistent_encapsulation_substitution.clone();
        assert_eq!(
            validate_pq_masp_note_encryption_key_digest_v1(&substituted_statement),
            Err(PqMaspWireErrorV1::EncryptedOutputBinding)
        );
        assert_eq!(
            decrypt_pq_masp_note_v1(
                &substituted_statement,
                &self_consistent_encapsulation_substitution,
                recipient_keys.secret_key(),
            ),
            Err(PqMaspWireErrorV1::AuthenticationFailed)
        );
        let wrong_keys = generate_mlkem_keypair_from_seed(
            MlKemSuite::MlKem768,
            HedgedRngSeed::from_entropy(raw(27)),
            b"pq-masp-wire-wrong-recipient",
        )
        .expect("wrong ML-KEM recipient");
        assert_eq!(
            decrypt_pq_masp_note_v1(&statement, &output, wrong_keys.secret_key()),
            Err(PqMaspWireErrorV1::EncryptedOutputBinding)
        );
    }
    #[test]
    fn mldsa_authorization_binds_statement_consensus_key_and_inner_proof_bytes() {
        let authorization_keys = generate_mldsa_keypair_from_seed(
            MlDsaSuite::MlDsa65,
            HedgedRngSeed::from_entropy(raw(31)),
            b"pq-masp-wire-authorization",
        )
        .expect("ML-DSA authorization key");
        let key_digest =
            derive_pq_masp_authorization_key_digest_v1(authorization_keys.public_key())
                .expect("key digest");
        let statement_digest = PrivacyStatementDigestV1::new(raw(32));
        let consensus_binding_digest = PrivacyNativeConsensusBindingDigestV1::new(raw(36));
        let stark_proof = b"deterministic-inner-transparent-stark-proof";
        let encoded = authorize_pq_masp_stark_proof_v1(
            statement_digest,
            consensus_binding_digest,
            key_digest,
            authorization_keys.secret_key(),
            stark_proof,
            HedgedRngSeed::from_entropy(raw(33)),
        )
        .expect("authorize");
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(&encoded)),
            PQ_MASP_AUTHORIZATION_WIRE_KAT_SHA256_V1,
            "canonical PQ-MASP PQA1 authorization wire changed"
        );
        let verified = verify_pq_masp_authorization_v1(
            statement_digest,
            consensus_binding_digest,
            key_digest,
            &encoded,
        )
        .expect("verify authorization");
        assert_eq!(verified.stark_proof, stark_proof);
        let mut mutations = Vec::new();
        let mut bad_magic = encoded.clone();
        bad_magic[0] ^= 1;
        mutations.push(bad_magic);
        mutations.push(encoded[..encoded.len() - 1].to_vec());
        let mut trailing = encoded.clone();
        trailing.push(0);
        mutations.push(trailing);
        for index in [
            8,
            8 + ML_DSA_65_PUBLIC_KEY_BYTES_V1,
            PQ_MASP_AUTHORIZATION_HEADER_BYTES_V1,
        ] {
            let mut mutated = encoded.clone();
            mutated[index] ^= 1;
            mutations.push(mutated);
        }
        for mutated in mutations {
            assert!(
                verify_pq_masp_authorization_v1(
                    statement_digest,
                    consensus_binding_digest,
                    key_digest,
                    &mutated,
                )
                .is_err()
            );
        }
        assert_eq!(
            verify_pq_masp_authorization_v1(
                PrivacyStatementDigestV1::new(raw(34)),
                consensus_binding_digest,
                key_digest,
                &encoded,
            ),
            Err(PqMaspWireErrorV1::AuthorizationFailed)
        );
        assert_eq!(
            verify_pq_masp_authorization_v1(
                statement_digest,
                PrivacyNativeConsensusBindingDigestV1::new(raw(37)),
                key_digest,
                &encoded,
            ),
            Err(PqMaspWireErrorV1::AuthorizationFailed)
        );
        assert_eq!(
            verify_pq_masp_authorization_v1(
                statement_digest,
                consensus_binding_digest,
                PrivacyAuthorizationKeyDigestV1::new(raw(35)),
                &encoded,
            ),
            Err(PqMaspWireErrorV1::AuthorizationKeyMismatch)
        );
        assert_eq!(
            authorize_pq_masp_stark_proof_v1(
                statement_digest,
                consensus_binding_digest,
                key_digest,
                authorization_keys.secret_key(),
                stark_proof,
                HedgedRngSeed::from_entropy([0; 32]),
            ),
            Err(PqMaspWireErrorV1::ZeroRandomness)
        );
        let mut zero_signature = encoded.clone();
        let signature_start = 8 + ML_DSA_65_PUBLIC_KEY_BYTES_V1;
        zero_signature[signature_start..signature_start + ML_DSA_65_SIGNATURE_BYTES_V1].fill(0);
        assert_eq!(
            decode_pq_masp_authorization_proof_v1(&zero_signature),
            Err(PqMaspWireErrorV1::InvalidAuthorizationSignature)
        );
        let mut zero_declared_length = encoded.clone();
        zero_declared_length[4..8].fill(0);
        assert_eq!(
            decode_pq_masp_authorization_proof_v1(&zero_declared_length),
            Err(PqMaspWireErrorV1::InvalidLength)
        );
        let mut oversized_declared_length = encoded.clone();
        oversized_declared_length[4..8].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(
            decode_pq_masp_authorization_proof_v1(&oversized_declared_length),
            Err(PqMaspWireErrorV1::InvalidLength)
        );
    }
    #[test]
    fn zero_seed_and_noncanonical_keys_are_rejected() {
        let statement = statement_shell();
        let note = PqMaspNotePlaintextV1 {
            value: 1,
            authorization_key_digest: statement.authorization_key_digest,
            recipient_key_digest: PrivacyRecipientIdV1::new(raw(1)),
            nullifier_key_digest: raw(2),
            rho: raw(3),
            blinding: raw(4),
            memo_digest: raw(5),
        };
        assert_eq!(
            derive_pq_masp_recipient_id_v1(&vec![0; ML_KEM_768_PUBLIC_KEY_BYTES_V1]),
            Err(PqMaspWireErrorV1::InvalidRecipientPublicKey)
        );
        let mut noncanonical = vec![1; ML_KEM_768_PUBLIC_KEY_BYTES_V1];
        noncanonical[0] = 0xFF;
        noncanonical[1] = (noncanonical[1] & 0xF0) | 0x0F;
        assert_eq!(
            derive_pq_masp_recipient_id_v1(&noncanonical),
            Err(PqMaspWireErrorV1::InvalidRecipientPublicKey)
        );
        assert_eq!(
            encrypt_pq_masp_note_v1(
                &statement,
                &note,
                &vec![0; ML_KEM_768_PUBLIC_KEY_BYTES_V1],
                HedgedRngSeed::from_entropy([0; 32]),
            ),
            Err(PqMaspWireErrorV1::ZeroRandomness)
        );
        assert_eq!(
            decode_pq_masp_authorization_proof_v1(&[]),
            Err(PqMaspWireErrorV1::InvalidLength)
        );
    }
}
