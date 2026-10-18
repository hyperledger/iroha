//! Fixed first-release private-note wallet encryption.
//!
//! There is exactly one codec: strict X25519 key agreement, a SHA-256 domain-separated key
//! derivation, and XChaCha20-Poly1305 over one fixed-width private note. Associated data
//! authenticates the pool, governed program, recipient, ephemeral key, and public note commitment.
//! The action digest cannot be included because it already commits the ciphertext.
use super::relation::{PrivateNotePlaintextV1, derive_note_commitment_v1};
use crate::privacy_engines::{
    prover_randomness::{HealthCheckedCryptoRngV1, ProverRandomnessErrorV1},
    x25519_wallet::{
        X25519WalletErrorV1, validate_x25519_public_key_v1, x25519_public_key_v1,
        x25519_shared_secret_v1,
    },
};
use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{Aead as _, KeyInit as _, Payload},
};
use iroha_data_model::privacy::{
    PRIVACY_IVM_PRIVATE_ENCRYPTED_OUTPUT_BYTES_V1, PRIVACY_IVM_PRIVATE_ENCRYPTED_OUTPUT_MAGIC_V1,
    PRIVACY_IVM_PRIVATE_ENCRYPTED_OUTPUT_NONCE_BYTES_V1,
    PRIVACY_IVM_PRIVATE_NOTE_PLAINTEXT_BYTES_V1, PrivacyCommitmentV1, PrivacyEncryptedOutputV1,
    PrivacyEncryptionKeyV1, PrivacyPoolIdV1, PrivacyProgramIdV1, PrivacyRecipientIdV1,
};
use rand_core_06::{CryptoRng, OsRng, RngCore};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;
const NOTE_MAGIC_V1: [u8; 4] = *b"IPW1";
const RECIPIENT_ID_DOMAIN_V1: &[u8] = b"iroha.privacy.ivm-private-note.recipient-id.v1";
const NOTE_AAD_DOMAIN_V1: &[u8] = b"iroha.privacy.ivm-private-note.note-aad.v1";
const NOTE_KEY_DOMAIN_V1: &[u8] = b"iroha.privacy.ivm-private-note.note-key.v1";
const WALLET_ENTROPY_BYTES_V1: usize = 64;
const EPHEMERAL_SECRET_BYTES_V1: usize = 32;
const POLY1305_TAG_BYTES_V1: usize = 16;
const AEAD_BYTES_V1: usize = PRIVACY_IVM_PRIVATE_NOTE_PLAINTEXT_BYTES_V1 + POLY1305_TAG_BYTES_V1;
/// Fixed wallet-codec failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum IvmPrivateNoteWalletErrorV1 {
    /// The public or secret X25519 key is invalid.
    #[error("private-note encryption key is invalid")]
    Key,
    /// Public ciphertext fields do not match the expected note.
    #[error("private-note encrypted output binding is invalid")]
    Binding,
    /// The outer ciphertext has a non-canonical byte length.
    #[error("private-note ciphertext length {actual} differs from {expected}")]
    Length {
        /// Observed byte length.
        actual: usize,
        /// Required byte length.
        expected: usize,
    },
    /// The sole first-release codec magic is absent.
    #[error("private-note ciphertext magic is invalid")]
    Magic,
    /// Required ephemeral secret, nonce, or ciphertext randomness is zero.
    #[error("private-note ciphertext randomness is invalid")]
    Randomness,
    /// The operating-system or injected cryptographic RNG failed or repeated
    /// an obviously unhealthy output pattern.
    #[error("private-note encryption randomness is unavailable")]
    RandomnessUnavailable,
    /// Authenticated decryption failed.
    #[error("private-note ciphertext authentication failed")]
    Authentication,
    /// The decrypted fixed-width note is malformed or does not open the expected commitment.
    #[error("private-note wallet plaintext is invalid")]
    Note,
}
impl From<X25519WalletErrorV1> for IvmPrivateNoteWalletErrorV1 {
    fn from(_: X25519WalletErrorV1) -> Self {
        Self::Key
    }
}
fn encode_note_material_v1(
    note: &PrivateNotePlaintextV1,
    commitment: PrivacyCommitmentV1,
) -> Zeroizing<[u8; PRIVACY_IVM_PRIVATE_NOTE_PLAINTEXT_BYTES_V1]> {
    let mut bytes = Zeroizing::new([0_u8; PRIVACY_IVM_PRIVATE_NOTE_PLAINTEXT_BYTES_V1]);
    let mut cursor = 0;
    bytes[cursor..cursor + 4].copy_from_slice(&NOTE_MAGIC_V1);
    cursor += 4;
    bytes[cursor..cursor + 32].copy_from_slice(commitment.as_bytes());
    cursor += 32;
    bytes[cursor..cursor + 16].copy_from_slice(&note.value.to_be_bytes());
    cursor += 16;
    bytes[cursor..cursor + 32].copy_from_slice(&note.spending_authority);
    cursor += 32;
    bytes[cursor..cursor + 32].copy_from_slice(&note.rho);
    cursor += 32;
    bytes[cursor..cursor + 32].copy_from_slice(&note.blinding);
    cursor += 32;
    bytes[cursor..cursor + 32].copy_from_slice(&note.memo_digest);
    debug_assert_eq!(cursor + 32, PRIVACY_IVM_PRIVATE_NOTE_PLAINTEXT_BYTES_V1);
    bytes
}
fn decode_note_material_v1(
    bytes: &[u8],
    expected_commitment: PrivacyCommitmentV1,
) -> Result<PrivateNotePlaintextV1, IvmPrivateNoteWalletErrorV1> {
    // Decode the shared fixed-width material only. The recipient checks the
    // canonical note commitment; the audit-opening caller compares every field
    // with a note already validated under its governed relation profile.
    if bytes.len() != PRIVACY_IVM_PRIVATE_NOTE_PLAINTEXT_BYTES_V1
        || bytes.get(..4) != Some(NOTE_MAGIC_V1.as_slice())
        || bytes.get(4..36) != Some(expected_commitment.as_bytes().as_slice())
    {
        return Err(IvmPrivateNoteWalletErrorV1::Note);
    }
    let value = u128::from_be_bytes(
        bytes[36..52]
            .try_into()
            .map_err(|_| IvmPrivateNoteWalletErrorV1::Note)?,
    );
    let mut spending_authority = [0_u8; 32];
    let mut rho = [0_u8; 32];
    let mut blinding = [0_u8; 32];
    let mut memo_digest = [0_u8; 32];
    spending_authority.copy_from_slice(&bytes[52..84]);
    rho.copy_from_slice(&bytes[84..116]);
    blinding.copy_from_slice(&bytes[116..148]);
    memo_digest.copy_from_slice(&bytes[148..180]);
    Ok(PrivateNotePlaintextV1 {
        value,
        spending_authority,
        rho,
        blinding,
        memo_digest,
    })
}
/// Derive the private-IVM recipient identity from a strict canonical X25519 public key.
pub fn derive_ivm_private_recipient_id_v1(
    recipient_public_key: [u8; 32],
) -> Result<PrivacyRecipientIdV1, IvmPrivateNoteWalletErrorV1> {
    validate_x25519_public_key_v1(recipient_public_key)?;
    let mut hash = Sha256::new();
    hash.update(RECIPIENT_ID_DOMAIN_V1);
    hash.update(recipient_public_key);
    Ok(PrivacyRecipientIdV1::new(hash.finalize().into()))
}
/// Derive a strict canonical X25519 public key from a wallet secret.
pub fn ivm_private_recipient_public_key_v1(
    recipient_secret_key: &[u8; 32],
) -> Result<[u8; 32], IvmPrivateNoteWalletErrorV1> {
    x25519_public_key_v1(recipient_secret_key).map_err(Into::into)
}
fn aad_v1(
    pool_id: PrivacyPoolIdV1,
    program_id: PrivacyProgramIdV1,
    recipient: PrivacyRecipientIdV1,
    ephemeral_public_key: PrivacyEncryptionKeyV1,
    commitment: PrivacyCommitmentV1,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(NOTE_AAD_DOMAIN_V1.len() + (5 * 32));
    aad.extend_from_slice(NOTE_AAD_DOMAIN_V1);
    aad.extend_from_slice(pool_id.as_bytes());
    aad.extend_from_slice(program_id.as_bytes());
    aad.extend_from_slice(recipient.as_bytes());
    aad.extend_from_slice(ephemeral_public_key.as_bytes());
    aad.extend_from_slice(commitment.as_bytes());
    aad
}
fn note_key_v1(shared_secret: &[u8; 32], aad: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut hash = Sha256::new();
    hash.update(NOTE_KEY_DOMAIN_V1);
    hash.update(shared_secret);
    hash.update(aad);
    let bytes: [u8; 32] = hash.finalize().into();
    Zeroizing::new(bytes)
}
fn encryption_entropy_is_healthy_v1(
    ephemeral_secret: &[u8; 32],
    nonce: &[u8; PRIVACY_IVM_PRIVATE_ENCRYPTED_OUTPUT_NONCE_BYTES_V1],
) -> bool {
    let secret_constant = ephemeral_secret
        .iter()
        .all(|byte| *byte == ephemeral_secret[0]);
    let nonce_constant = nonce.iter().all(|byte| *byte == nonce[0]);
    let repeated_prefix =
        ephemeral_secret[..PRIVACY_IVM_PRIVATE_ENCRYPTED_OUTPUT_NONCE_BYTES_V1] == nonce[..];
    !secret_constant && !nonce_constant && !repeated_prefix
}
fn map_curve_randomness_error_v1(_: ProverRandomnessErrorV1) -> IvmPrivateNoteWalletErrorV1 {
    IvmPrivateNoteWalletErrorV1::RandomnessUnavailable
}
fn parsed_ciphertext(
    output: &PrivacyEncryptedOutputV1,
) -> Result<
    (
        &[u8; PRIVACY_IVM_PRIVATE_ENCRYPTED_OUTPUT_NONCE_BYTES_V1],
        &[u8],
    ),
    IvmPrivateNoteWalletErrorV1,
> {
    if output.ciphertext.len() != PRIVACY_IVM_PRIVATE_ENCRYPTED_OUTPUT_BYTES_V1 {
        return Err(IvmPrivateNoteWalletErrorV1::Length {
            actual: output.ciphertext.len(),
            expected: PRIVACY_IVM_PRIVATE_ENCRYPTED_OUTPUT_BYTES_V1,
        });
    }
    if output.ciphertext.get(..4) != Some(PRIVACY_IVM_PRIVATE_ENCRYPTED_OUTPUT_MAGIC_V1.as_slice())
    {
        return Err(IvmPrivateNoteWalletErrorV1::Magic);
    }
    let nonce: &[u8; PRIVACY_IVM_PRIVATE_ENCRYPTED_OUTPUT_NONCE_BYTES_V1] = output
        .ciphertext
        .get(4..4 + PRIVACY_IVM_PRIVATE_ENCRYPTED_OUTPUT_NONCE_BYTES_V1)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(IvmPrivateNoteWalletErrorV1::Length {
            actual: output.ciphertext.len(),
            expected: PRIVACY_IVM_PRIVATE_ENCRYPTED_OUTPUT_BYTES_V1,
        })?;
    let authenticated = output
        .ciphertext
        .get(4 + PRIVACY_IVM_PRIVATE_ENCRYPTED_OUTPUT_NONCE_BYTES_V1..)
        .ok_or(IvmPrivateNoteWalletErrorV1::Length {
            actual: output.ciphertext.len(),
            expected: PRIVACY_IVM_PRIVATE_ENCRYPTED_OUTPUT_BYTES_V1,
        })?;
    if nonce.iter().all(|byte| *byte == 0)
        || authenticated.len() != AEAD_BYTES_V1
        || authenticated.iter().all(|byte| *byte == 0)
    {
        return Err(IvmPrivateNoteWalletErrorV1::Randomness);
    }
    Ok((nonce, authenticated))
}
/// Validate the exact public shape and bindings of one private-IVM wallet
/// ciphertext. Authentication remains recipient-local.
pub fn validate_ivm_private_encrypted_output_v1(
    _pool_id: PrivacyPoolIdV1,
    _program_id: PrivacyProgramIdV1,
    expected_commitment: PrivacyCommitmentV1,
    encrypted: &PrivacyEncryptedOutputV1,
) -> Result<(), IvmPrivateNoteWalletErrorV1> {
    if expected_commitment.is_zero()
        || encrypted.recipient.is_zero()
        || encrypted.ephemeral_public_key.is_zero()
        || encrypted.commitment != expected_commitment
    {
        return Err(IvmPrivateNoteWalletErrorV1::Binding);
    }
    validate_x25519_public_key_v1(encrypted.ephemeral_public_key.into_bytes())?;
    parsed_ciphertext(encrypted).map(|_| ())
}
fn encrypt_note_material_v1(
    pool_id: PrivacyPoolIdV1,
    program_id: PrivacyProgramIdV1,
    note: &PrivateNotePlaintextV1,
    commitment: PrivacyCommitmentV1,
    recipient_public_key: [u8; 32],
    ephemeral_secret: &[u8; EPHEMERAL_SECRET_BYTES_V1],
    nonce_bytes: &[u8; PRIVACY_IVM_PRIVATE_ENCRYPTED_OUTPUT_NONCE_BYTES_V1],
) -> Result<PrivacyEncryptedOutputV1, IvmPrivateNoteWalletErrorV1> {
    if commitment.is_zero() || !encryption_entropy_is_healthy_v1(ephemeral_secret, nonce_bytes) {
        return Err(IvmPrivateNoteWalletErrorV1::Randomness);
    }
    let recipient = derive_ivm_private_recipient_id_v1(recipient_public_key)?;
    let ephemeral_public = x25519_public_key_v1(ephemeral_secret)?;
    let shared = x25519_shared_secret_v1(ephemeral_secret, recipient_public_key)?;
    let ephemeral_public_key = PrivacyEncryptionKeyV1::new(ephemeral_public);
    let aad = aad_v1(
        pool_id,
        program_id,
        recipient,
        ephemeral_public_key,
        commitment,
    );
    let key = note_key_v1(&shared, &aad);
    let plaintext = encode_note_material_v1(note, commitment);
    let nonce: &chacha20poly1305::XNonce = nonce_bytes
        .as_slice()
        .try_into()
        .map_err(|_| IvmPrivateNoteWalletErrorV1::Note)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice())
        .map_err(|_| IvmPrivateNoteWalletErrorV1::Note)?;
    let authenticated = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext.as_slice(),
                aad: &aad,
            },
        )
        .map_err(|_| IvmPrivateNoteWalletErrorV1::Authentication)?;
    if authenticated.len() != AEAD_BYTES_V1 {
        return Err(IvmPrivateNoteWalletErrorV1::Note);
    }
    let mut ciphertext = Vec::with_capacity(PRIVACY_IVM_PRIVATE_ENCRYPTED_OUTPUT_BYTES_V1);
    ciphertext.extend_from_slice(&PRIVACY_IVM_PRIVATE_ENCRYPTED_OUTPUT_MAGIC_V1);
    ciphertext.extend_from_slice(nonce_bytes);
    ciphertext.extend_from_slice(&authenticated);
    let encrypted = PrivacyEncryptedOutputV1 {
        recipient,
        ephemeral_public_key,
        commitment,
        ciphertext,
    };
    validate_ivm_private_encrypted_output_v1(pool_id, program_id, commitment, &encrypted)?;
    Ok(encrypted)
}
/// Encrypt one fixed-width private note.
pub fn encrypt_ivm_private_wallet_note_v1(
    rng: &mut (impl RngCore + CryptoRng),
    pool_id: PrivacyPoolIdV1,
    program_id: PrivacyProgramIdV1,
    note: &PrivateNotePlaintextV1,
    recipient_public_key: [u8; 32],
) -> Result<PrivacyEncryptedOutputV1, IvmPrivateNoteWalletErrorV1> {
    let commitment =
        derive_note_commitment_v1(note).map_err(|_| IvmPrivateNoteWalletErrorV1::Note)?;
    derive_ivm_private_recipient_id_v1(recipient_public_key)?;
    let mut randomness_session =
        HealthCheckedCryptoRngV1::new(rng).map_err(map_curve_randomness_error_v1)?;
    let mut entropy = Zeroizing::new([0_u8; WALLET_ENTROPY_BYTES_V1]);
    randomness_session
        .try_fill_bytes(entropy.as_mut())
        .map_err(|_| IvmPrivateNoteWalletErrorV1::RandomnessUnavailable)?;
    let ephemeral_secret: &[u8; EPHEMERAL_SECRET_BYTES_V1] = entropy
        .get(..EPHEMERAL_SECRET_BYTES_V1)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(IvmPrivateNoteWalletErrorV1::RandomnessUnavailable)?;
    let nonce_bytes: &[u8; PRIVACY_IVM_PRIVATE_ENCRYPTED_OUTPUT_NONCE_BYTES_V1] = entropy
        .get(
            EPHEMERAL_SECRET_BYTES_V1
                ..EPHEMERAL_SECRET_BYTES_V1 + PRIVACY_IVM_PRIVATE_ENCRYPTED_OUTPUT_NONCE_BYTES_V1,
        )
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(IvmPrivateNoteWalletErrorV1::RandomnessUnavailable)?;
    if !encryption_entropy_is_healthy_v1(ephemeral_secret, nonce_bytes) {
        return Err(IvmPrivateNoteWalletErrorV1::RandomnessUnavailable);
    }
    encrypt_note_material_v1(
        pool_id,
        program_id,
        note,
        commitment,
        recipient_public_key,
        ephemeral_secret,
        nonce_bytes,
    )
}

/// Encrypt a pre-committed profiled note using a capsule-retained ephemeral opening.
///
/// The caller must already have derived `commitment` under its governed note
/// profile. The supplied ephemeral secret is retained only in restricted audit
/// material; a fresh authenticated nonce is obtained from `rng`.
pub(crate) fn encrypt_ivm_private_wallet_note_for_commitment_with_opening_v1(
    rng: &mut (impl RngCore + CryptoRng),
    pool_id: PrivacyPoolIdV1,
    program_id: PrivacyProgramIdV1,
    note: &PrivateNotePlaintextV1,
    commitment: PrivacyCommitmentV1,
    recipient_public_key: [u8; 32],
    ephemeral_secret: &[u8; EPHEMERAL_SECRET_BYTES_V1],
) -> Result<PrivacyEncryptedOutputV1, IvmPrivateNoteWalletErrorV1> {
    derive_ivm_private_recipient_id_v1(recipient_public_key)?;
    x25519_public_key_v1(ephemeral_secret)?;
    let mut randomness_session =
        HealthCheckedCryptoRngV1::new(rng).map_err(map_curve_randomness_error_v1)?;
    let mut nonce = Zeroizing::new([0_u8; PRIVACY_IVM_PRIVATE_ENCRYPTED_OUTPUT_NONCE_BYTES_V1]);
    randomness_session
        .try_fill_bytes(nonce.as_mut())
        .map_err(|_| IvmPrivateNoteWalletErrorV1::RandomnessUnavailable)?;
    encrypt_note_material_v1(
        pool_id,
        program_id,
        note,
        commitment,
        recipient_public_key,
        ephemeral_secret,
        &nonce,
    )
}
/// Encrypt one fixed-width private note with operating-system entropy.
///
/// # Errors
///
/// Returns the same closed typed failures as [`encrypt_ivm_private_wallet_note_v1`].
pub fn encrypt_ivm_private_wallet_note_with_os_rng_v1(
    pool_id: PrivacyPoolIdV1,
    program_id: PrivacyProgramIdV1,
    note: &PrivateNotePlaintextV1,
    recipient_public_key: [u8; 32],
) -> Result<PrivacyEncryptedOutputV1, IvmPrivateNoteWalletErrorV1> {
    encrypt_ivm_private_wallet_note_v1(&mut OsRng, pool_id, program_id, note, recipient_public_key)
}
fn decrypt_note_material_v1(
    pool_id: PrivacyPoolIdV1,
    program_id: PrivacyProgramIdV1,
    expected_commitment: PrivacyCommitmentV1,
    encrypted: &PrivacyEncryptedOutputV1,
    shared: &[u8; 32],
) -> Result<PrivateNotePlaintextV1, IvmPrivateNoteWalletErrorV1> {
    let aad = aad_v1(
        pool_id,
        program_id,
        encrypted.recipient,
        encrypted.ephemeral_public_key,
        expected_commitment,
    );
    let key = note_key_v1(shared, &aad);
    let (nonce_bytes, authenticated) = parsed_ciphertext(encrypted)?;
    let nonce: &chacha20poly1305::XNonce = nonce_bytes
        .as_slice()
        .try_into()
        .map_err(|_| IvmPrivateNoteWalletErrorV1::Note)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice())
        .map_err(|_| IvmPrivateNoteWalletErrorV1::Note)?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: authenticated,
                    aad: &aad,
                },
            )
            .map_err(|_| IvmPrivateNoteWalletErrorV1::Authentication)?,
    );
    decode_note_material_v1(plaintext.as_slice(), expected_commitment)
}

/// Authenticate a published ciphertext using a capsule-only ephemeral opening.
///
/// This path needs neither the role account's signing secret nor the note's
/// spending secret. The caller first derives `expected_commitment` under its
/// governed profile, then this function proves the envelope decrypts to the
/// exact expected note and one-time recipient key.
pub fn validate_ivm_private_wallet_encryption_opening_v1(
    pool_id: PrivacyPoolIdV1,
    program_id: PrivacyProgramIdV1,
    expected_note: &PrivateNotePlaintextV1,
    expected_commitment: PrivacyCommitmentV1,
    encrypted: &PrivacyEncryptedOutputV1,
    recipient_public_key: [u8; 32],
    ephemeral_secret: &[u8; EPHEMERAL_SECRET_BYTES_V1],
) -> Result<(), IvmPrivateNoteWalletErrorV1> {
    validate_ivm_private_encrypted_output_v1(pool_id, program_id, expected_commitment, encrypted)?;
    if derive_ivm_private_recipient_id_v1(recipient_public_key)? != encrypted.recipient
        || x25519_public_key_v1(ephemeral_secret)? != encrypted.ephemeral_public_key.into_bytes()
    {
        return Err(IvmPrivateNoteWalletErrorV1::Binding);
    }
    let shared = x25519_shared_secret_v1(ephemeral_secret, recipient_public_key)?;
    let decrypted =
        decrypt_note_material_v1(pool_id, program_id, expected_commitment, encrypted, &shared)?;
    if &decrypted != expected_note {
        return Err(IvmPrivateNoteWalletErrorV1::Note);
    }
    Ok(())
}
#[cfg(test)]
/// Decrypt, authenticate, and commitment-check one fixed-width private note.
pub fn decrypt_ivm_private_wallet_note_v1(
    pool_id: PrivacyPoolIdV1,
    program_id: PrivacyProgramIdV1,
    expected_commitment: PrivacyCommitmentV1,
    encrypted: &PrivacyEncryptedOutputV1,
    recipient_secret_key: &[u8; 32],
) -> Result<PrivateNotePlaintextV1, IvmPrivateNoteWalletErrorV1> {
    validate_ivm_private_encrypted_output_v1(pool_id, program_id, expected_commitment, encrypted)?;
    let recipient_public_key = ivm_private_recipient_public_key_v1(recipient_secret_key)?;
    if derive_ivm_private_recipient_id_v1(recipient_public_key)? != encrypted.recipient {
        return Err(IvmPrivateNoteWalletErrorV1::Binding);
    }
    let shared = x25519_shared_secret_v1(
        recipient_secret_key,
        encrypted.ephemeral_public_key.into_bytes(),
    )?;
    let note =
        decrypt_note_material_v1(pool_id, program_id, expected_commitment, encrypted, &shared)?;
    if derive_note_commitment_v1(&note).map_err(|_| IvmPrivateNoteWalletErrorV1::Note)?
        != expected_commitment
    {
        return Err(IvmPrivateNoteWalletErrorV1::Note);
    }
    Ok(note)
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy_engines::ivm_private_note::relation::derive_note_authority_v1;
    use rand_08::{SeedableRng as _, rngs::StdRng};
    use rand_core_06::{CryptoRng, Error as RngError, RngCore};
    #[derive(Clone, Copy)]
    enum AuditedEntropyMode {
        Healthy,
        Constant(u8),
        ConstantLeftHalf,
        ConstantRightHalf,
        Period(u8),
        ZeroNonce,
        RepeatedSecretPrefix,
        PartialFailure,
        Panic,
    }
    struct AuditedRng {
        mode: AuditedEntropyMode,
        requests: Vec<usize>,
    }
    impl AuditedRng {
        fn new(mode: AuditedEntropyMode) -> Self {
            Self {
                mode,
                requests: Vec::new(),
            }
        }
        fn healthy_byte(index: usize) -> u8 {
            (index as u8).wrapping_mul(41).wrapping_add(3)
        }
    }
    impl RngCore for AuditedRng {
        fn next_u32(&mut self) -> u32 {
            panic!("private-IVM wallet must use the fallible RNG interface")
        }
        fn next_u64(&mut self) -> u64 {
            panic!("private-IVM wallet must use the fallible RNG interface")
        }
        fn fill_bytes(&mut self, _destination: &mut [u8]) {
            panic!("private-IVM wallet must use the fallible RNG interface")
        }
        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RngError> {
            self.requests.push(destination.len());
            match self.mode {
                AuditedEntropyMode::Healthy
                | AuditedEntropyMode::ConstantLeftHalf
                | AuditedEntropyMode::ConstantRightHalf
                | AuditedEntropyMode::ZeroNonce
                | AuditedEntropyMode::RepeatedSecretPrefix => {
                    for (index, byte) in destination.iter_mut().enumerate() {
                        *byte = Self::healthy_byte(index);
                    }
                    if matches!(self.mode, AuditedEntropyMode::ConstantLeftHalf) {
                        destination[..WALLET_ENTROPY_BYTES_V1 / 2].fill(0x5a);
                    } else if matches!(self.mode, AuditedEntropyMode::ConstantRightHalf) {
                        destination[WALLET_ENTROPY_BYTES_V1 / 2..].fill(0xa5);
                    } else if matches!(self.mode, AuditedEntropyMode::ZeroNonce) {
                        destination[EPHEMERAL_SECRET_BYTES_V1
                            ..EPHEMERAL_SECRET_BYTES_V1
                                + PRIVACY_IVM_PRIVATE_ENCRYPTED_OUTPUT_NONCE_BYTES_V1]
                            .fill(0);
                    } else if matches!(self.mode, AuditedEntropyMode::RepeatedSecretPrefix) {
                        let repeated: [u8; PRIVACY_IVM_PRIVATE_ENCRYPTED_OUTPUT_NONCE_BYTES_V1] =
                            destination[..PRIVACY_IVM_PRIVATE_ENCRYPTED_OUTPUT_NONCE_BYTES_V1]
                                .try_into()
                                .expect("canonical source block has the repeated prefix");
                        destination[EPHEMERAL_SECRET_BYTES_V1
                            ..EPHEMERAL_SECRET_BYTES_V1
                                + PRIVACY_IVM_PRIVATE_ENCRYPTED_OUTPUT_NONCE_BYTES_V1]
                            .copy_from_slice(&repeated);
                    }
                }
                AuditedEntropyMode::Constant(byte) => destination.fill(byte),
                AuditedEntropyMode::Period(period) => {
                    for (index, byte) in destination.iter_mut().enumerate() {
                        *byte = ((index % usize::from(period)) as u8)
                            .wrapping_mul(41)
                            .wrapping_add(3);
                    }
                }
                AuditedEntropyMode::PartialFailure | AuditedEntropyMode::Panic => {
                    for (index, byte) in destination.iter_mut().take(17).enumerate() {
                        *byte = Self::healthy_byte(index);
                    }
                    if matches!(self.mode, AuditedEntropyMode::Panic) {
                        panic!("injected private-IVM wallet entropy panic");
                    }
                    return Err(RngError::new(
                        "injected partial private-IVM wallet RNG failure",
                    ));
                }
            }
            Ok(())
        }
    }
    impl CryptoRng for AuditedRng {}
    fn fixture() -> (
        PrivacyPoolIdV1,
        PrivacyProgramIdV1,
        PrivateNotePlaintextV1,
        [u8; 32],
    ) {
        let spending_secret = [0x31; 32];
        (
            PrivacyPoolIdV1::new([0x41; 32]),
            PrivacyProgramIdV1::new([0x51; 32]),
            PrivateNotePlaintextV1 {
                value: 19,
                spending_authority: derive_note_authority_v1(&spending_secret).unwrap(),
                rho: [0x61; 32],
                blinding: [0x71; 32],
                memo_digest: [0x81; 32],
            },
            [0x91; 32],
        )
    }
    #[test]
    fn fixed_codec_round_trips_and_every_outer_byte_is_authenticated() {
        let (pool, program, note, recipient_secret) = fixture();
        let recipient_public =
            ivm_private_recipient_public_key_v1(&recipient_secret).expect("recipient public key");
        let mut rng = StdRng::seed_from_u64(0x1_50_4e_45);
        let encrypted =
            encrypt_ivm_private_wallet_note_v1(&mut rng, pool, program, &note, recipient_public)
                .expect("encrypt canonical note");
        assert_eq!(
            encrypted.ciphertext.len(),
            PRIVACY_IVM_PRIVATE_ENCRYPTED_OUTPUT_BYTES_V1
        );
        assert_eq!(
            decrypt_ivm_private_wallet_note_v1(
                pool,
                program,
                encrypted.commitment,
                &encrypted,
                &recipient_secret,
            )
            .expect("decrypt canonical note"),
            note
        );
        for index in 0..encrypted.ciphertext.len() {
            let mut tampered = encrypted.clone();
            tampered.ciphertext[index] ^= 1;
            assert!(
                decrypt_ivm_private_wallet_note_v1(
                    pool,
                    program,
                    encrypted.commitment,
                    &tampered,
                    &recipient_secret,
                )
                .is_err(),
                "tampered ciphertext byte {index} was accepted"
            );
        }
    }
    #[test]
    fn fixed_codec_rejects_cross_context_and_public_field_substitution() {
        let (pool, program, note, recipient_secret) = fixture();
        let recipient_public = ivm_private_recipient_public_key_v1(&recipient_secret).unwrap();
        let mut rng = StdRng::seed_from_u64(0x2_50_4e_45);
        let encrypted =
            encrypt_ivm_private_wallet_note_v1(&mut rng, pool, program, &note, recipient_public)
                .unwrap();
        for (wrong_pool, wrong_program) in [
            (PrivacyPoolIdV1::new([0x42; 32]), program),
            (pool, PrivacyProgramIdV1::new([0x52; 32])),
        ] {
            assert_eq!(
                decrypt_ivm_private_wallet_note_v1(
                    wrong_pool,
                    wrong_program,
                    encrypted.commitment,
                    &encrypted,
                    &recipient_secret,
                ),
                Err(IvmPrivateNoteWalletErrorV1::Authentication)
            );
        }
        assert!(matches!(
            decrypt_ivm_private_wallet_note_v1(
                pool,
                program,
                encrypted.commitment,
                &encrypted,
                &[0x92; 32],
            ),
            Err(IvmPrivateNoteWalletErrorV1::Binding | IvmPrivateNoteWalletErrorV1::Authentication)
        ));
        let wrong_commitment = PrivacyCommitmentV1::new([0xa1; 32]);
        assert_eq!(
            decrypt_ivm_private_wallet_note_v1(
                pool,
                program,
                wrong_commitment,
                &encrypted,
                &recipient_secret,
            ),
            Err(IvmPrivateNoteWalletErrorV1::Binding)
        );
        let mut wrong_recipient = encrypted.clone();
        wrong_recipient.recipient = PrivacyRecipientIdV1::new([0xa2; 32]);
        assert_eq!(
            decrypt_ivm_private_wallet_note_v1(
                pool,
                program,
                encrypted.commitment,
                &wrong_recipient,
                &recipient_secret,
            ),
            Err(IvmPrivateNoteWalletErrorV1::Binding)
        );
        let mut wrong_ephemeral = encrypted.clone();
        wrong_ephemeral.ephemeral_public_key =
            PrivacyEncryptionKeyV1::new(ivm_private_recipient_public_key_v1(&[0xa3; 32]).unwrap());
        assert_eq!(
            decrypt_ivm_private_wallet_note_v1(
                pool,
                program,
                encrypted.commitment,
                &wrong_ephemeral,
                &recipient_secret,
            ),
            Err(IvmPrivateNoteWalletErrorV1::Authentication)
        );
    }
    #[test]
    fn fixed_codec_rejects_noncanonical_shapes_and_keys() {
        let (pool, program, note, recipient_secret) = fixture();
        let recipient_public = ivm_private_recipient_public_key_v1(&recipient_secret).unwrap();
        let mut rng = StdRng::seed_from_u64(0x3_50_4e_45);
        let encrypted =
            encrypt_ivm_private_wallet_note_v1(&mut rng, pool, program, &note, recipient_public)
                .unwrap();
        let mut truncated = encrypted.clone();
        truncated.ciphertext.pop();
        assert!(matches!(
            validate_ivm_private_encrypted_output_v1(
                pool,
                program,
                encrypted.commitment,
                &truncated,
            ),
            Err(IvmPrivateNoteWalletErrorV1::Length { .. })
        ));
        let mut suffixed = encrypted.clone();
        suffixed.ciphertext.push(0);
        assert!(matches!(
            validate_ivm_private_encrypted_output_v1(
                pool,
                program,
                encrypted.commitment,
                &suffixed,
            ),
            Err(IvmPrivateNoteWalletErrorV1::Length { .. })
        ));
        let mut zero_nonce = encrypted.clone();
        zero_nonce.ciphertext[4..4 + PRIVACY_IVM_PRIVATE_ENCRYPTED_OUTPUT_NONCE_BYTES_V1].fill(0);
        assert_eq!(
            validate_ivm_private_encrypted_output_v1(
                pool,
                program,
                encrypted.commitment,
                &zero_nonce,
            ),
            Err(IvmPrivateNoteWalletErrorV1::Randomness)
        );
        let mut zero_payload = encrypted.clone();
        zero_payload.ciphertext[4 + PRIVACY_IVM_PRIVATE_ENCRYPTED_OUTPUT_NONCE_BYTES_V1..].fill(0);
        assert_eq!(
            validate_ivm_private_encrypted_output_v1(
                pool,
                program,
                encrypted.commitment,
                &zero_payload,
            ),
            Err(IvmPrivateNoteWalletErrorV1::Randomness)
        );
        let mut low_order = encrypted.clone();
        let mut low_order_key = [0_u8; 32];
        low_order_key[0] = 1;
        low_order.ephemeral_public_key = PrivacyEncryptionKeyV1::new(low_order_key);
        assert_eq!(
            validate_ivm_private_encrypted_output_v1(
                pool,
                program,
                encrypted.commitment,
                &low_order,
            ),
            Err(IvmPrivateNoteWalletErrorV1::Key)
        );
        let mut noncanonical = encrypted.clone();
        noncanonical.ephemeral_public_key =
            PrivacyEncryptionKeyV1::new(FIELD_MODULUS_LITTLE_ENDIAN_FOR_TEST);
        assert_eq!(
            validate_ivm_private_encrypted_output_v1(
                pool,
                program,
                encrypted.commitment,
                &noncanonical,
            ),
            Err(IvmPrivateNoteWalletErrorV1::Key)
        );
        let mut low_order_recipient = [0_u8; 32];
        low_order_recipient[0] = 1;
        let mut low_order_source = AuditedRng::new(AuditedEntropyMode::Healthy);
        assert_eq!(
            encrypt_ivm_private_wallet_note_v1(
                &mut low_order_source,
                pool,
                program,
                &note,
                low_order_recipient,
            ),
            Err(IvmPrivateNoteWalletErrorV1::Key)
        );
        assert!(
            low_order_source.requests.is_empty(),
            "recipient preflight must reject before consuming wallet entropy"
        );
        let mut noncanonical_source = AuditedRng::new(AuditedEntropyMode::Healthy);
        assert_eq!(
            encrypt_ivm_private_wallet_note_v1(
                &mut noncanonical_source,
                pool,
                program,
                &note,
                FIELD_MODULUS_LITTLE_ENDIAN_FOR_TEST,
            ),
            Err(IvmPrivateNoteWalletErrorV1::Key)
        );
        assert!(
            noncanonical_source.requests.is_empty(),
            "recipient preflight must reject before consuming wallet entropy"
        );
        assert_eq!(
            ivm_private_recipient_public_key_v1(&[0; 32]),
            Err(IvmPrivateNoteWalletErrorV1::Key)
        );
    }
    #[test]
    fn wallet_entropy_uses_one_exact_canonical_block_and_fixed_partition() {
        let (pool, program, note, recipient_secret) = fixture();
        let recipient_public = ivm_private_recipient_public_key_v1(&recipient_secret).unwrap();
        let mut source = AuditedRng::new(AuditedEntropyMode::Healthy);
        let encrypted =
            encrypt_ivm_private_wallet_note_v1(&mut source, pool, program, &note, recipient_public)
                .expect("healthy canonical wallet entropy");
        assert_eq!(source.requests, [WALLET_ENTROPY_BYTES_V1]);
        let expected_secret: [u8; EPHEMERAL_SECRET_BYTES_V1] =
            core::array::from_fn(AuditedRng::healthy_byte);
        assert_eq!(
            encrypted.ephemeral_public_key.into_bytes(),
            x25519_public_key_v1(&expected_secret).expect("healthy ephemeral key")
        );
        let expected_nonce = (EPHEMERAL_SECRET_BYTES_V1
            ..EPHEMERAL_SECRET_BYTES_V1 + PRIVACY_IVM_PRIVATE_ENCRYPTED_OUTPUT_NONCE_BYTES_V1)
            .map(AuditedRng::healthy_byte)
            .collect::<Vec<_>>();
        assert_eq!(
            &encrypted.ciphertext[4..4 + PRIVACY_IVM_PRIVATE_ENCRYPTED_OUTPUT_NONCE_BYTES_V1],
            expected_nonce.as_slice()
        );
    }
    #[test]
    fn wallet_entropy_rejects_constant_and_every_prohibited_period_in_one_request() {
        let (pool, program, note, recipient_secret) = fixture();
        let recipient_public = ivm_private_recipient_public_key_v1(&recipient_secret).unwrap();
        for mode in [
            AuditedEntropyMode::Constant(0),
            AuditedEntropyMode::Constant(0x5a),
            AuditedEntropyMode::ConstantLeftHalf,
            AuditedEntropyMode::ConstantRightHalf,
            AuditedEntropyMode::Period(1),
            AuditedEntropyMode::Period(2),
            AuditedEntropyMode::Period(4),
            AuditedEntropyMode::Period(8),
            AuditedEntropyMode::Period(16),
            AuditedEntropyMode::Period(32),
            AuditedEntropyMode::ZeroNonce,
            AuditedEntropyMode::RepeatedSecretPrefix,
        ] {
            let mut source = AuditedRng::new(mode);
            assert_eq!(
                encrypt_ivm_private_wallet_note_v1(
                    &mut source,
                    pool,
                    program,
                    &note,
                    recipient_public,
                ),
                Err(IvmPrivateNoteWalletErrorV1::RandomnessUnavailable)
            );
            assert_eq!(
                source.requests,
                [WALLET_ENTROPY_BYTES_V1],
                "a rejected source must not be re-entered"
            );
        }
    }
    #[test]
    fn wallet_entropy_partial_error_and_unwind_never_reenter_the_source() {
        let (pool, program, note, recipient_secret) = fixture();
        let recipient_public = ivm_private_recipient_public_key_v1(&recipient_secret).unwrap();
        let mut partial = AuditedRng::new(AuditedEntropyMode::PartialFailure);
        assert_eq!(
            encrypt_ivm_private_wallet_note_v1(
                &mut partial,
                pool,
                program,
                &note,
                recipient_public,
            ),
            Err(IvmPrivateNoteWalletErrorV1::RandomnessUnavailable)
        );
        assert_eq!(partial.requests, [WALLET_ENTROPY_BYTES_V1]);
        let mut panicking = AuditedRng::new(AuditedEntropyMode::Panic);
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                encrypt_ivm_private_wallet_note_v1(
                    &mut panicking,
                    pool,
                    program,
                    &note,
                    recipient_public,
                )
                .ok();
            }))
            .is_err()
        );
        assert_eq!(panicking.requests, [WALLET_ENTROPY_BYTES_V1]);
    }
    const FIELD_MODULUS_LITTLE_ENDIAN_FOR_TEST: [u8; 32] = [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ];
    #[test]
    fn inner_note_codec_rejects_noncanonical_framing_and_embedded_commitment() {
        let (_, _, note, _) = fixture();
        let commitment = derive_note_commitment_v1(&note).unwrap();
        let encoded = encode_note_material_v1(&note, commitment);
        assert_eq!(
            decode_note_material_v1(encoded.as_slice(), commitment),
            Ok(note)
        );
        for index in 0..36 {
            let mut tampered = Zeroizing::new(*encoded);
            tampered[index] ^= 1;
            assert!(
                decode_note_material_v1(tampered.as_slice(), commitment).is_err(),
                "tampered plaintext byte {index} was accepted"
            );
        }
        for length in 0..encoded.len() {
            assert_eq!(
                decode_note_material_v1(&encoded[..length], commitment),
                Err(IvmPrivateNoteWalletErrorV1::Note)
            );
        }
        let mut trailing = Zeroizing::new(encoded.to_vec());
        trailing.push(0);
        assert_eq!(
            decode_note_material_v1(trailing.as_slice(), commitment),
            Err(IvmPrivateNoteWalletErrorV1::Note)
        );
    }

    #[test]
    fn authenticated_opening_corruption_fails_recipient_and_auditor_validation() {
        let (pool, program, note, recipient_secret) = fixture();
        let recipient_public = ivm_private_recipient_public_key_v1(&recipient_secret).unwrap();
        let commitment = derive_note_commitment_v1(&note).unwrap();
        let encoded = encode_note_material_v1(&note, commitment);
        let ephemeral_secret = core::array::from_fn(|index| (index as u8) * 7 + 3);
        let nonce = core::array::from_fn(|index| (index as u8) * 5 + 11);
        let encrypted = encrypt_note_material_v1(
            pool,
            program,
            &note,
            commitment,
            recipient_public,
            &ephemeral_secret,
            &nonce,
        )
        .unwrap();
        assert_eq!(
            validate_ivm_private_wallet_encryption_opening_v1(
                pool,
                program,
                &note,
                commitment,
                &encrypted,
                recipient_public,
                &ephemeral_secret,
            ),
            Ok(())
        );
        for index in 36..encoded.len() {
            let mut tampered = Zeroizing::new(*encoded);
            tampered[index] ^= 1;
            let changed_note = decode_note_material_v1(tampered.as_slice(), commitment).unwrap();
            // A malicious sender can authenticate arbitrary plaintext. Exercise
            // the commitment and exact-opening checks after successful AEAD,
            // rather than accepting an authentication failure as sufficient.
            let encrypted = encrypt_note_material_v1(
                pool,
                program,
                &changed_note,
                commitment,
                recipient_public,
                &ephemeral_secret,
                &nonce,
            )
            .unwrap();
            assert_eq!(
                decrypt_ivm_private_wallet_note_v1(
                    pool,
                    program,
                    commitment,
                    &encrypted,
                    &recipient_secret,
                ),
                Err(IvmPrivateNoteWalletErrorV1::Note),
                "recipient accepted authenticated opening byte {index}"
            );
            assert_eq!(
                validate_ivm_private_wallet_encryption_opening_v1(
                    pool,
                    program,
                    &note,
                    commitment,
                    &encrypted,
                    recipient_public,
                    &ephemeral_secret,
                ),
                Err(IvmPrivateNoteWalletErrorV1::Note),
                "auditor accepted authenticated opening byte {index}"
            );
        }
    }
}
