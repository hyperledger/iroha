//! Fixed first-release FCMP++ wallet note encryption.
//!
//! There is exactly one codec: X25519 key agreement, a SHA-256 domain-separated key derivation, and
//! XChaCha20-Poly1305 over one fixed-width note. The AEAD associated data binds the governed pool
//! (which transitively fixes its asset), recipient identity, ephemeral key, output identifier, and
//! complete `(O,I,C)` tuple. Consensus validates this exact public shape; recipient wallets
//! additionally authenticate and decode the note.
use super::{
    FCMP_OUTPUT_TUPLE_BYTES_V1, FcmpNativeErrorV1, FcmpOutputCommitmentOpeningV1,
    FcmpOutputTupleV1,
    field::{decode_edwards_point, validate_edwards_scalar},
    sal::generator_t,
};
use crate::privacy_engines::x25519_wallet::{
    validate_x25519_public_key_v1, x25519_public_key_v1, x25519_shared_secret_v1,
};
use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{Aead as _, KeyInit as _, Payload},
};
use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, scalar::Scalar};
use iroha_data_model::privacy::{
    PRIVACY_FCMP_ENCRYPTED_OUTPUT_BYTES_V1, PRIVACY_FCMP_ENCRYPTED_OUTPUT_MAGIC_V1,
    PRIVACY_FCMP_ENCRYPTED_OUTPUT_NONCE_BYTES_V1, PRIVACY_FCMP_NOTE_PLAINTEXT_BYTES_V1,
    PrivacyEncryptionKeyV1, PrivacyFcmpEncryptedOutputV1, PrivacyFcmpOutputTupleV1,
    PrivacyPoolIdV1, PrivacyRecipientIdV1,
};
use rand_core_06::{CryptoRng, RngCore};
use sha2::{Digest as _, Sha256, compress256, digest::generic_array::GenericArray};
use zeroize::{Zeroize, Zeroizing};
const NOTE_MAGIC_V1: [u8; 4] = *b"IFN1";
const RECIPIENT_ID_DOMAIN_V1: &[u8] = b"iroha.privacy.fcmp.wallet.recipient-id.v1";
const NOTE_AAD_DOMAIN_V1: &[u8] = b"iroha.privacy.fcmp.wallet.note-aad.v1";
const NOTE_KEY_DOMAIN_V1: &[u8] = b"iroha.privacy.fcmp.wallet.note-key.v1";
const POLY1305_TAG_BYTES_V1: usize = 16;
const AEAD_BYTES_V1: usize = PRIVACY_FCMP_NOTE_PLAINTEXT_BYTES_V1 + POLY1305_TAG_BYTES_V1;
pub(super) struct WalletSecretCopyValueV1<T: Copy + Zeroize>(T);
struct BorrowedWalletCopySlotV1<'a, T: Copy + Zeroize>(&'a mut T);
impl<T: Copy + Zeroize> BorrowedWalletCopySlotV1<'_, T> {
    fn expose_copy(&self) -> T {
        *self.0
    }
}
impl<T: Copy + Zeroize> Drop for BorrowedWalletCopySlotV1<'_, T> {
    fn drop(&mut self) {
        self.0.zeroize();
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        let _ = core::hint::black_box(&mut *self.0);
    }
}
impl<T: Copy + Zeroize> WalletSecretCopyValueV1<T> {
    fn copy_from_ref(value: &T) -> Self {
        Self::from_copy(*value)
    }
    fn from_copy(mut value: T) -> Self {
        Self::take(&mut value)
    }
    fn take(value: &mut T) -> Self {
        let incoming = BorrowedWalletCopySlotV1(value);
        let owned = Self(incoming.expose_copy());
        drop(incoming);
        owned
    }
    fn expose_copy(&self) -> T {
        self.0
    }
    pub(super) fn expose_ref(&self) -> &T {
        &self.0
    }
}
impl<T: Copy + Zeroize> Drop for WalletSecretCopyValueV1<T> {
    fn drop(&mut self) {
        self.0.zeroize();
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        let _ = core::hint::black_box(&mut self.0);
    }
}
struct WalletSecretSha256V1 {
    state: [u32; 8],
    block: [u8; 64],
    block_len: usize,
    byte_len: u64,
}
impl WalletSecretSha256V1 {
    fn new() -> Self {
        Self {
            state: [
                0x6a09_e667,
                0xbb67_ae85,
                0x3c6e_f372,
                0xa54f_f53a,
                0x510e_527f,
                0x9b05_688c,
                0x1f83_d9ab,
                0x5be0_cd19,
            ],
            block: [0; 64],
            block_len: 0,
            byte_len: 0,
        }
    }
    fn compress_block_v1(&mut self) {
        let block = GenericArray::from_slice(&self.block);
        compress256(&mut self.state, core::slice::from_ref(block));
        self.block.zeroize();
        self.block_len = 0;
    }
    fn update_v1(&mut self, mut input: &[u8]) {
        self.byte_len = self
            .byte_len
            .checked_add(u64::try_from(input.len()).expect("usize fits u64"))
            .expect("wallet note KDF input length fits u64");
        while !input.is_empty() {
            let take = core::cmp::min(64 - self.block_len, input.len());
            self.block[self.block_len..self.block_len + take].copy_from_slice(&input[..take]);
            self.block_len += take;
            input = &input[take..];
            if self.block_len == 64 {
                self.compress_block_v1();
            }
        }
    }
    fn finalize_v1(mut self) -> WalletSecretCopyValueV1<[u8; 32]> {
        let bit_len = self
            .byte_len
            .checked_mul(8)
            .expect("wallet note KDF bit length fits u64");
        self.block[self.block_len] = 0x80;
        self.block_len += 1;
        if self.block_len > 56 {
            self.block[self.block_len..].zeroize();
            self.compress_block_v1();
        }
        self.block[self.block_len..56].zeroize();
        self.block[56..].copy_from_slice(&bit_len.to_be_bytes());
        self.compress_block_v1();
        let mut output = WalletSecretCopyValueV1([0_u8; 32]);
        for index in 0..32 {
            output.0[index] = (self.state[index / 4] >> (24 - (8 * (index % 4)))) as u8;
        }
        output
    }
}
impl Drop for WalletSecretSha256V1 {
    fn drop(&mut self) {
        self.state.zeroize();
        self.block.zeroize();
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        let _ = core::hint::black_box(&mut self.state);
        let _ = core::hint::black_box(&mut self.block);
    }
}
/// Hash borrowed secret-bearing slices while owning and erasing all SHA-256
/// state, block scratch, and digest output.
pub(super) fn secret_sha256_v1(inputs: &[&[u8]]) -> WalletSecretCopyValueV1<[u8; 32]> {
    let mut hash = WalletSecretSha256V1::new();
    for input in inputs {
        hash.update_v1(input);
    }
    hash.finalize_v1()
}
/// Decrypted fixed-width FCMP++ wallet note.
///
/// The output tuple is public; the amount, amount-commitment mask, `spend_x`,
/// and `output_y` are secret output openings and are zeroized on drop.
pub struct FcmpWalletNoteV1 {
    output: FcmpOutputTupleV1,
    amount: u64,
    commitment_mask: [u8; 32],
    spend_x: [u8; 32],
    output_y: [u8; 32],
}
impl core::fmt::Debug for FcmpWalletNoteV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("FcmpWalletNoteV1")
            .field("output", &self.output)
            .finish_non_exhaustive()
    }
}
impl PartialEq for FcmpWalletNoteV1 {
    fn eq(&self, other: &Self) -> bool {
        self.output == other.output
            && self.amount == other.amount
            && self.commitment_mask == other.commitment_mask
            && self.spend_x == other.spend_x
            && self.output_y == other.output_y
    }
}
impl Eq for FcmpWalletNoteV1 {}
impl Zeroize for FcmpWalletNoteV1 {
    fn zeroize(&mut self) {
        self.amount.zeroize();
        self.commitment_mask.zeroize();
        self.spend_x.zeroize();
        self.output_y.zeroize();
    }
}
impl Drop for FcmpWalletNoteV1 {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl FcmpWalletNoteV1 {
    /// Construct and validate a spendable note opening.
    pub fn new(
        output: FcmpOutputTupleV1,
        mut spend_x: [u8; 32],
        mut output_y: [u8; 32],
        mut amount: u64,
        mut commitment_mask: [u8; 32],
    ) -> Result<Self, FcmpNativeErrorV1> {
        let spend_x_bytes = WalletSecretCopyValueV1::take(&mut spend_x);
        let output_y_bytes = WalletSecretCopyValueV1::take(&mut output_y);
        let amount = WalletSecretCopyValueV1::take(&mut amount);
        let commitment_mask = WalletSecretCopyValueV1::take(&mut commitment_mask);
        Self::from_secret_owners_v1(
            output,
            spend_x_bytes,
            output_y_bytes,
            amount,
            commitment_mask,
        )
    }
    /// Construct a note from borrowed secret openings without creating raw
    /// by-value copies in the caller.
    pub fn new_borrowed(
        output: FcmpOutputTupleV1,
        spend_x: &[u8; 32],
        output_y: &[u8; 32],
        amount: &u64,
        commitment_mask: &[u8; 32],
    ) -> Result<Self, FcmpNativeErrorV1> {
        let spend_x_bytes = WalletSecretCopyValueV1::copy_from_ref(spend_x);
        let output_y_bytes = WalletSecretCopyValueV1::copy_from_ref(output_y);
        let amount = WalletSecretCopyValueV1::copy_from_ref(amount);
        let commitment_mask = WalletSecretCopyValueV1::copy_from_ref(commitment_mask);
        Self::from_secret_owners_v1(
            output,
            spend_x_bytes,
            output_y_bytes,
            amount,
            commitment_mask,
        )
    }
    fn from_secret_owners_v1(
        output: FcmpOutputTupleV1,
        spend_x_bytes: WalletSecretCopyValueV1<[u8; 32]>,
        output_y_bytes: WalletSecretCopyValueV1<[u8; 32]>,
        amount: WalletSecretCopyValueV1<u64>,
        commitment_mask: WalletSecretCopyValueV1<[u8; 32]>,
    ) -> Result<Self, FcmpNativeErrorV1> {
        validate_edwards_scalar(*spend_x_bytes.expose_ref())?;
        validate_edwards_scalar(*output_y_bytes.expose_ref())?;
        let mut decoded_spend_x =
            Option::<Scalar>::from(Scalar::from_canonical_bytes(*spend_x_bytes.expose_ref()))
                .ok_or(FcmpNativeErrorV1::WalletNoteEncoding)?;
        let spend_x = WalletSecretCopyValueV1::take(&mut decoded_spend_x);
        let mut decoded_output_y =
            Option::<Scalar>::from(Scalar::from_canonical_bytes(*output_y_bytes.expose_ref()))
                .ok_or(FcmpNativeErrorV1::WalletNoteEncoding)?;
        let output_y = WalletSecretCopyValueV1::take(&mut decoded_output_y);
        if spend_x.expose_ref() == &Scalar::ZERO {
            return Err(FcmpNativeErrorV1::WalletNoteEncoding);
        }
        let output_key = decode_edwards_point(output.components().0, false)?;
        let spend_component = Zeroizing::new(&ED25519_BASEPOINT_POINT * spend_x.expose_ref());
        let output_component = Zeroizing::new(&generator_t() * output_y.expose_ref());
        let expected_output = Zeroizing::new(&*spend_component + &*output_component);
        if &*expected_output != &output_key {
            return Err(FcmpNativeErrorV1::WalletNoteEncoding);
        }
        FcmpOutputCommitmentOpeningV1::new_borrowed(
            output,
            amount.expose_ref(),
            commitment_mask.expose_ref(),
        )?;
        Ok(Self {
            output,
            amount: amount.expose_copy(),
            commitment_mask: commitment_mask.expose_copy(),
            spend_x: spend_x_bytes.expose_copy(),
            output_y: output_y_bytes.expose_copy(),
        })
    }
    /// Complete public output tuple recovered from the note.
    #[must_use]
    pub const fn output(&self) -> FcmpOutputTupleV1 {
        self.output
    }
    /// Canonical secret spend scalar.
    #[must_use]
    pub const fn spend_x(&self) -> &[u8; 32] {
        &self.spend_x
    }
    /// Canonical secret output blinding scalar.
    #[must_use]
    pub const fn output_y(&self) -> &[u8; 32] {
        &self.output_y
    }
    /// Hidden strict-positive `u64` amount.
    #[must_use]
    pub const fn amount(&self) -> &u64 {
        &self.amount
    }
    /// Canonical secret amount-commitment mask.
    #[must_use]
    pub const fn commitment_mask(&self) -> &[u8; 32] {
        &self.commitment_mask
    }
    /// Reconstruct the validated range-proof witness carried by this note.
    pub fn commitment_opening(&self) -> Result<FcmpOutputCommitmentOpeningV1, FcmpNativeErrorV1> {
        FcmpOutputCommitmentOpeningV1::new_borrowed(
            self.output,
            &self.amount,
            &self.commitment_mask,
        )
    }
    fn encode(&self, output_id: [u8; 32]) -> Zeroizing<[u8; PRIVACY_FCMP_NOTE_PLAINTEXT_BYTES_V1]> {
        let mut bytes = Zeroizing::new([0_u8; PRIVACY_FCMP_NOTE_PLAINTEXT_BYTES_V1]);
        let mut cursor = 0;
        bytes[cursor..cursor + 4].copy_from_slice(&NOTE_MAGIC_V1);
        cursor += 4;
        bytes[cursor..cursor + 32].copy_from_slice(&output_id);
        cursor += 32;
        bytes[cursor..cursor + FCMP_OUTPUT_TUPLE_BYTES_V1].copy_from_slice(&self.output.encode());
        cursor += FCMP_OUTPUT_TUPLE_BYTES_V1;
        let amount_bytes = Zeroizing::new(self.amount.to_le_bytes());
        bytes[cursor..cursor + 8].copy_from_slice(amount_bytes.as_ref());
        cursor += 8;
        bytes[cursor..cursor + 32].copy_from_slice(&self.commitment_mask);
        cursor += 32;
        bytes[cursor..cursor + 32].copy_from_slice(&self.spend_x);
        cursor += 32;
        bytes[cursor..cursor + 32].copy_from_slice(&self.output_y);
        bytes
    }
    #[cfg(test)]
    fn decode(
        bytes: &[u8],
        expected_output_id: [u8; 32],
        expected_output: FcmpOutputTupleV1,
    ) -> Result<Self, FcmpNativeErrorV1> {
        if bytes.len() != PRIVACY_FCMP_NOTE_PLAINTEXT_BYTES_V1
            || bytes.get(..4) != Some(NOTE_MAGIC_V1.as_slice())
            || bytes.get(4..36) != Some(expected_output_id.as_slice())
            || bytes.get(36..36 + FCMP_OUTPUT_TUPLE_BYTES_V1)
                != Some(expected_output.encode().as_slice())
        {
            return Err(FcmpNativeErrorV1::WalletNoteEncoding);
        }
        let amount_start = 36 + FCMP_OUTPUT_TUPLE_BYTES_V1;
        let amount = Zeroizing::new(u64::from_le_bytes(
            bytes
                .get(amount_start..amount_start + 8)
                .ok_or(FcmpNativeErrorV1::WalletNoteEncoding)?
                .try_into()
                .map_err(|_| FcmpNativeErrorV1::WalletNoteEncoding)?,
        ));
        let mut commitment_mask = Zeroizing::new([0_u8; 32]);
        commitment_mask.copy_from_slice(
            bytes
                .get(amount_start + 8..amount_start + 40)
                .ok_or(FcmpNativeErrorV1::WalletNoteEncoding)?,
        );
        let mut spend_x = Zeroizing::new([0_u8; 32]);
        let mut output_y = Zeroizing::new([0_u8; 32]);
        let secret_start = amount_start + 40;
        spend_x.copy_from_slice(
            bytes
                .get(secret_start..secret_start + 32)
                .ok_or(FcmpNativeErrorV1::WalletNoteEncoding)?,
        );
        output_y.copy_from_slice(
            bytes
                .get(secret_start + 32..secret_start + 64)
                .ok_or(FcmpNativeErrorV1::WalletNoteEncoding)?,
        );
        Self::new(
            expected_output,
            *spend_x,
            *output_y,
            *amount,
            *commitment_mask,
        )
    }
}
fn model_output(output: PrivacyFcmpOutputTupleV1) -> Result<FcmpOutputTupleV1, FcmpNativeErrorV1> {
    FcmpOutputTupleV1::new(
        output.output_key,
        output.linking_tag_generator,
        output.amount_commitment,
    )
}
/// Derive the sole first-release recipient identity from a canonical X25519 public key.
pub fn derive_fcmp_recipient_id_v1(
    recipient_public_key: [u8; 32],
) -> Result<PrivacyRecipientIdV1, FcmpNativeErrorV1> {
    validate_x25519_public_key_v1(recipient_public_key)
        .map_err(|_| FcmpNativeErrorV1::EncryptedOutputKey)?;
    let mut hash = Sha256::new();
    hash.update(RECIPIENT_ID_DOMAIN_V1);
    hash.update(recipient_public_key);
    Ok(PrivacyRecipientIdV1::new(hash.finalize().into()))
}
/// Derive a canonical X25519 public key from a non-zero wallet secret.
pub fn fcmp_recipient_public_key_v1(
    mut recipient_secret_key: [u8; 32],
) -> Result<[u8; 32], FcmpNativeErrorV1> {
    let recipient_secret_key = WalletSecretCopyValueV1::take(&mut recipient_secret_key);
    x25519_public_key_v1(recipient_secret_key.expose_ref())
        .map_err(|_| FcmpNativeErrorV1::EncryptedOutputKey)
}
fn aad_v1(
    pool_id: PrivacyPoolIdV1,
    recipient: PrivacyRecipientIdV1,
    ephemeral_public_key: PrivacyEncryptionKeyV1,
    output: PrivacyFcmpOutputTupleV1,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(NOTE_AAD_DOMAIN_V1.len() + (7 * 32));
    aad.extend_from_slice(NOTE_AAD_DOMAIN_V1);
    aad.extend_from_slice(pool_id.as_bytes());
    aad.extend_from_slice(recipient.as_bytes());
    aad.extend_from_slice(ephemeral_public_key.as_bytes());
    aad.extend_from_slice(output.output_id().as_bytes());
    aad.extend_from_slice(&output.output_key);
    aad.extend_from_slice(&output.linking_tag_generator);
    aad.extend_from_slice(&output.amount_commitment);
    aad
}
fn note_key_v1(shared_secret: &[u8; 32], aad: &[u8]) -> WalletSecretCopyValueV1<[u8; 32]> {
    let mut hash = WalletSecretSha256V1::new();
    hash.update_v1(NOTE_KEY_DOMAIN_V1);
    hash.update_v1(shared_secret);
    hash.update_v1(aad);
    hash.finalize_v1()
}
fn parsed_ciphertext(
    output: &PrivacyFcmpEncryptedOutputV1,
) -> Result<([u8; 24], &[u8]), FcmpNativeErrorV1> {
    if output.ciphertext.len() != PRIVACY_FCMP_ENCRYPTED_OUTPUT_BYTES_V1 {
        return Err(FcmpNativeErrorV1::EncryptedOutputLength {
            actual: output.ciphertext.len(),
            expected: PRIVACY_FCMP_ENCRYPTED_OUTPUT_BYTES_V1,
        });
    }
    if output.ciphertext.get(..4) != Some(PRIVACY_FCMP_ENCRYPTED_OUTPUT_MAGIC_V1.as_slice()) {
        return Err(FcmpNativeErrorV1::EncryptedOutputMagic);
    }
    let mut nonce = [0_u8; 24];
    nonce.copy_from_slice(
        output
            .ciphertext
            .get(4..4 + PRIVACY_FCMP_ENCRYPTED_OUTPUT_NONCE_BYTES_V1)
            .ok_or(FcmpNativeErrorV1::EncryptedOutputLength {
                actual: output.ciphertext.len(),
                expected: PRIVACY_FCMP_ENCRYPTED_OUTPUT_BYTES_V1,
            })?,
    );
    let encrypted = output
        .ciphertext
        .get(4 + PRIVACY_FCMP_ENCRYPTED_OUTPUT_NONCE_BYTES_V1..)
        .ok_or(FcmpNativeErrorV1::EncryptedOutputLength {
            actual: output.ciphertext.len(),
            expected: PRIVACY_FCMP_ENCRYPTED_OUTPUT_BYTES_V1,
        })?;
    if nonce.iter().all(|byte| *byte == 0)
        || encrypted.len() != AEAD_BYTES_V1
        || encrypted.iter().all(|byte| *byte == 0)
    {
        return Err(FcmpNativeErrorV1::EncryptedOutputRandomness);
    }
    Ok((nonce, encrypted))
}
/// Validate the exact public FCMP++ wallet ciphertext shape and all public
/// bindings available to consensus.
pub fn validate_fcmp_encrypted_output_v1(
    _pool_id: PrivacyPoolIdV1,
    expected_output: PrivacyFcmpOutputTupleV1,
    encrypted: &PrivacyFcmpEncryptedOutputV1,
) -> Result<(), FcmpNativeErrorV1> {
    model_output(expected_output)?;
    if encrypted.recipient.is_zero()
        || encrypted.output_id != expected_output.output_id()
        || encrypted.ephemeral_public_key.is_zero()
    {
        return Err(FcmpNativeErrorV1::EncryptedOutputBinding);
    }
    validate_x25519_public_key_v1(encrypted.ephemeral_public_key.into_bytes())
        .map_err(|_| FcmpNativeErrorV1::EncryptedOutputKey)?;
    parsed_ciphertext(encrypted).map(|_| ())
}
/// Encrypt one fixed-width spendable FCMP++ wallet note.
pub fn encrypt_fcmp_wallet_note_v1(
    rng: &mut (impl RngCore + CryptoRng),
    pool_id: PrivacyPoolIdV1,
    output: PrivacyFcmpOutputTupleV1,
    note: &FcmpWalletNoteV1,
    recipient_public_key: [u8; 32],
) -> Result<PrivacyFcmpEncryptedOutputV1, FcmpNativeErrorV1> {
    let native_output = model_output(output)?;
    if native_output != note.output() {
        return Err(FcmpNativeErrorV1::EncryptedOutputBinding);
    }
    let recipient = derive_fcmp_recipient_id_v1(recipient_public_key)?;
    let mut checked_rng = super::health_checked_fcmp_rng_v1(rng)?;
    let mut ephemeral_secret = Zeroizing::new([0_u8; 32]);
    checked_rng
        .try_fill_bytes(ephemeral_secret.as_mut())
        .map_err(|_| FcmpNativeErrorV1::RandomnessUnavailable)?;
    if ephemeral_secret.iter().all(|byte| *byte == 0) {
        return Err(FcmpNativeErrorV1::EncryptedOutputRandomness);
    }
    let ephemeral_public = x25519_public_key_v1(&*ephemeral_secret)
        .map_err(|_| FcmpNativeErrorV1::EncryptedOutputKey)?;
    let shared = x25519_shared_secret_v1(&*ephemeral_secret, recipient_public_key)
        .map_err(|_| FcmpNativeErrorV1::EncryptedOutputKey)?;
    let ephemeral_public_key = PrivacyEncryptionKeyV1::new(ephemeral_public);
    let aad = aad_v1(pool_id, recipient, ephemeral_public_key, output);
    let key = note_key_v1(&shared, &aad);
    let mut nonce_bytes = [0_u8; 24];
    if checked_rng.try_fill_bytes(&mut nonce_bytes).is_err() {
        nonce_bytes.zeroize();
        return Err(FcmpNativeErrorV1::RandomnessUnavailable);
    }
    if nonce_bytes.iter().all(|byte| *byte == 0) {
        return Err(FcmpNativeErrorV1::EncryptedOutputRandomness);
    }
    let nonce: chacha20poly1305::XNonce = nonce_bytes.into();
    let cipher = XChaCha20Poly1305::new_from_slice(key.expose_ref())
        .map_err(|_| FcmpNativeErrorV1::WalletNoteEncoding)?;
    let plaintext = note.encode(output.output_id().into_bytes());
    let authenticated = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext.as_slice(),
                aad: &aad,
            },
        )
        .map_err(|_| FcmpNativeErrorV1::EncryptedOutputAuthentication)?;
    if authenticated.len() != AEAD_BYTES_V1 {
        return Err(FcmpNativeErrorV1::WalletNoteEncoding);
    }
    let mut ciphertext = Vec::with_capacity(PRIVACY_FCMP_ENCRYPTED_OUTPUT_BYTES_V1);
    ciphertext.extend_from_slice(&PRIVACY_FCMP_ENCRYPTED_OUTPUT_MAGIC_V1);
    ciphertext.extend_from_slice(&nonce_bytes);
    ciphertext.extend_from_slice(&authenticated);
    let encrypted = PrivacyFcmpEncryptedOutputV1 {
        recipient,
        ephemeral_public_key,
        output_id: output.output_id(),
        ciphertext,
    };
    validate_fcmp_encrypted_output_v1(pool_id, output, &encrypted)?;
    Ok(encrypted)
}
#[cfg(test)]
/// Decrypt and authenticate one fixed-width FCMP++ wallet note.
pub fn decrypt_fcmp_wallet_note_v1(
    pool_id: PrivacyPoolIdV1,
    expected_output: PrivacyFcmpOutputTupleV1,
    encrypted: &PrivacyFcmpEncryptedOutputV1,
    mut recipient_secret_key: [u8; 32],
) -> Result<FcmpWalletNoteV1, FcmpNativeErrorV1> {
    let recipient_secret_key = WalletSecretCopyValueV1::take(&mut recipient_secret_key);
    validate_fcmp_encrypted_output_v1(pool_id, expected_output, encrypted)?;
    let recipient_public_key = x25519_public_key_v1(recipient_secret_key.expose_ref())
        .map_err(|_| FcmpNativeErrorV1::EncryptedOutputKey)?;
    if derive_fcmp_recipient_id_v1(recipient_public_key)? != encrypted.recipient {
        return Err(FcmpNativeErrorV1::EncryptedOutputBinding);
    }
    let shared = x25519_shared_secret_v1(
        recipient_secret_key.expose_ref(),
        encrypted.ephemeral_public_key.into_bytes(),
    )
    .map_err(|_| FcmpNativeErrorV1::EncryptedOutputKey)?;
    let aad = aad_v1(
        pool_id,
        encrypted.recipient,
        encrypted.ephemeral_public_key,
        expected_output,
    );
    let key = note_key_v1(&shared, &aad);
    let (nonce_bytes, authenticated) = parsed_ciphertext(encrypted)?;
    let nonce: chacha20poly1305::XNonce = nonce_bytes.into();
    let cipher = XChaCha20Poly1305::new_from_slice(key.expose_ref())
        .map_err(|_| FcmpNativeErrorV1::WalletNoteEncoding)?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: authenticated,
                    aad: &aad,
                },
            )
            .map_err(|_| FcmpNativeErrorV1::EncryptedOutputAuthentication)?,
    );
    FcmpWalletNoteV1::decode(
        plaintext.as_slice(),
        expected_output.output_id().into_bytes(),
        model_output(expected_output)?,
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy_engines::fcmp_plus_plus::{FailingRngV1, range::amount_generator};
    use core::cell::Cell;
    use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, scalar::Scalar};
    use rand_08::{SeedableRng, rngs::StdRng};
    thread_local! {
        static WALLET_COPY_CLEARS: Cell<usize> = const { Cell::new(0) };
    }
    #[derive(Clone, Copy)]
    struct TrackingCopy(u64);
    impl Zeroize for TrackingCopy {
        fn zeroize(&mut self) {
            self.0 = 0;
            WALLET_COPY_CLEARS.with(|calls| calls.set(calls.get() + 1));
        }
    }
    #[test]
    fn wallet_copy_owner_clears_taken_and_borrowed_retained_slots() {
        WALLET_COPY_CLEARS.with(|calls| calls.set(0));
        let mut source = TrackingCopy(7);
        let owner = WalletSecretCopyValueV1::take(&mut source);
        assert_eq!(source.0, 0);
        assert_eq!(owner.expose_ref().0, 7);
        assert_eq!(WALLET_COPY_CLEARS.with(Cell::get), 1);
        drop(owner);
        assert_eq!(WALLET_COPY_CLEARS.with(Cell::get), 2);
        WALLET_COPY_CLEARS.with(|calls| calls.set(0));
        let borrowed = TrackingCopy(11);
        let owner = WalletSecretCopyValueV1::copy_from_ref(&borrowed);
        assert_eq!(borrowed.0, 11);
        assert_eq!(owner.expose_ref().0, 11);
        assert_eq!(WALLET_COPY_CLEARS.with(Cell::get), 1);
        drop(owner);
        assert_eq!(WALLET_COPY_CLEARS.with(Cell::get), 2);
    }
    #[test]
    fn wallet_secret_sha256_matches_the_frozen_note_kdf() {
        let shared_secret = [0x31; 32];
        let aad = [0xa7; 224];
        let actual = note_key_v1(&shared_secret, &aad);
        let mut expected = Sha256::new();
        expected.update(NOTE_KEY_DOMAIN_V1);
        expected.update(shared_secret);
        expected.update(aad);
        let expected: [u8; 32] = expected.finalize().into();
        assert_eq!(actual.expose_ref(), &expected);
        let frozen: [u8; 32] =
            hex::decode("69e939fa1441f1353609cf5a5df72e60782976a166884df190e9093b6af54333")
                .expect("literal SHA-256")
                .try_into()
                .expect("32-byte SHA-256");
        assert_eq!(expected, frozen);
    }
    #[test]
    fn wallet_note_constructor_takes_inputs_before_validation_and_owns_products() {
        let source = include_str!("wallet.rs");
        let constructor = source
            .split_once("impl FcmpWalletNoteV1 {")
            .expect("wallet note impl")
            .1
            .split_once("/// Complete public output tuple recovered from the note")
            .expect("constructor boundary")
            .0;
        assert_eq!(
            constructor
                .matches("WalletSecretCopyValueV1::take(&mut")
                .count(),
            6
        );
        let input_last_take = constructor
            .find("WalletSecretCopyValueV1::take(&mut commitment_mask)")
            .expect("last input take");
        let first_validation = constructor
            .find("validate_edwards_scalar(")
            .expect("first scalar validation");
        assert!(input_last_take < first_validation);
        let spend_decode_take = constructor
            .find("WalletSecretCopyValueV1::take(&mut decoded_spend_x)")
            .expect("spend scalar take");
        let output_decode_take = constructor
            .find("WalletSecretCopyValueV1::take(&mut decoded_output_y)")
            .expect("output scalar take");
        let output_decode = constructor
            .find("let mut decoded_output_y")
            .expect("output scalar decode");
        assert!(first_validation < spend_decode_take);
        assert!(output_decode < output_decode_take);
        assert!(constructor.contains("&ED25519_BASEPOINT_POINT * spend_x.expose_ref()"));
        assert!(constructor.contains("&generator_t() * output_y.expose_ref()"));
        assert!(constructor.contains("Zeroizing::new(&*spend_component + &*output_component)"));
        assert!(!constructor.contains("Zeroizing::new(spend_x)"));
        assert!(!constructor.contains("ED25519_BASEPOINT_POINT * *spend_x"));
        let borrowed_constructor = constructor
            .find("pub fn new_borrowed(")
            .expect("borrowed wallet-note constructor");
        let first_borrowed_owner = constructor
            .find("WalletSecretCopyValueV1::copy_from_ref(spend_x)")
            .expect("borrowed spend owner");
        let borrowed_validation = constructor[borrowed_constructor..]
            .find("Self::from_secret_owners_v1(")
            .expect("borrowed constructor validation");
        assert!(borrowed_constructor < first_borrowed_owner);
        assert!(first_borrowed_owner - borrowed_constructor < borrowed_validation);
        let range_validation = constructor
            .find("FcmpOutputCommitmentOpeningV1::new_borrowed(")
            .expect("range opening validation");
        let publish_relative = constructor[range_validation..]
            .find("Ok(Self {")
            .expect("final publication");
        let publish = range_validation + publish_relative;
        assert!(output_decode_take < range_validation && range_validation < publish);
        assert!(constructor.contains("amount.expose_ref(),"));
        assert!(constructor.contains("commitment_mask.expose_ref(),"));
        assert!(!constructor.contains(
            "amount.expose_copy(),\n            commitment_mask.expose_copy(),\n        )?"
        ));
        let accessors = source
            .split_once("/// Complete public output tuple recovered from the note")
            .expect("wallet-note accessors")
            .1
            .split_once("    fn encode(")
            .expect("wallet-note accessor boundary")
            .0;
        assert!(accessors.contains("pub const fn spend_x(&self) -> &[u8; 32]"));
        assert!(accessors.contains("pub const fn output_y(&self) -> &[u8; 32]"));
        assert!(accessors.contains("pub const fn amount(&self) -> &u64"));
        assert!(accessors.contains("pub const fn commitment_mask(&self) -> &[u8; 32]"));
        let opening = accessors
            .split_once("pub fn commitment_opening(&self)")
            .expect("wallet-note opening helper")
            .1;
        assert!(opening.contains("FcmpOutputCommitmentOpeningV1::new_borrowed("));
        assert!(!opening.contains("FcmpOutputCommitmentOpeningV1::new(self.output"));
        let encoder = source
            .split_once("    fn encode(&self,")
            .expect("wallet-note encoder")
            .1
            .split_once("    fn decode(")
            .expect("encoder boundary")
            .0;
        assert!(encoder.contains(") -> Zeroizing<[u8; PRIVACY_FCMP_NOTE_PLAINTEXT_BYTES_V1]>"));
        let owner = encoder
            .find("Zeroizing::new([0_u8; PRIVACY_FCMP_NOTE_PLAINTEXT_BYTES_V1])")
            .expect("plaintext owner");
        let first_write = encoder
            .find("copy_from_slice")
            .expect("first plaintext write");
        assert!(owner < first_write);
        let amount_owner = encoder
            .find("let amount_bytes = Zeroizing::new(self.amount.to_le_bytes())")
            .expect("amount encoding owner");
        let amount_write = encoder
            .find("copy_from_slice(amount_bytes.as_ref())")
            .expect("owned amount write");
        assert!(amount_owner < amount_write);
        assert!(!encoder.contains("copy_from_slice(&self.amount.to_le_bytes())"));
        assert!(!encoder.contains(") -> [u8; PRIVACY_FCMP_NOTE_PLAINTEXT_BYTES_V1]"));
    }
    #[test]
    fn wallet_note_accessors_borrow_exact_storage_and_opening_preserves_it() {
        let (_, _, note, _) = fixture();
        assert!(core::ptr::eq(note.spend_x(), &raw const note.spend_x));
        assert!(core::ptr::eq(note.output_y(), &raw const note.output_y));
        assert!(core::ptr::eq(note.amount(), &raw const note.amount));
        assert!(core::ptr::eq(
            note.commitment_mask(),
            &raw const note.commitment_mask
        ));
        let opening = note.commitment_opening().expect("borrowed note opening");
        assert_eq!(opening.amount(), note.amount());
        let opening_mask = opening.commitment_mask();
        assert_eq!(&*opening_mask, note.commitment_mask());
        assert_eq!(opening.output(), note.output());
    }
    #[test]
    fn wallet_x25519_secrets_are_taken_or_borrowed_across_helper_boundaries() {
        let source = include_str!("wallet.rs");
        let secret_sha = source
            .split_once("struct WalletSecretSha256V1 {")
            .expect("secret SHA-256 owner")
            .1
            .split_once("/// Decrypted fixed-width FCMP++ wallet note.")
            .expect("secret SHA-256 boundary")
            .0;
        assert!(secret_sha.contains("state: [u32; 8]"));
        assert!(secret_sha.contains("block: [u8; 64]"));
        assert!(secret_sha.contains("GenericArray::from_slice(&self.block)"));
        assert!(secret_sha.contains("compress256(&mut self.state"));
        let compress = secret_sha
            .find("compress256(&mut self.state")
            .expect("secret compression");
        let block_clear = secret_sha[compress..]
            .find("self.block.zeroize()")
            .expect("post-compression block clear");
        assert!(block_clear > 0);
        let drop = secret_sha
            .split_once("impl Drop for WalletSecretSha256V1")
            .expect("secret SHA-256 drop")
            .1;
        assert!(drop.contains("self.state.zeroize()"));
        assert!(drop.contains("self.block.zeroize()"));
        assert!(drop.contains("compiler_fence"));
        assert!(drop.matches("black_box").count() >= 2);
        let note_key = source
            .split_once("fn note_key_v1(")
            .expect("note-key helper")
            .1
            .split_once("fn parsed_ciphertext(")
            .expect("note-key boundary")
            .0;
        assert!(note_key.contains(") -> WalletSecretCopyValueV1<[u8; 32]>"));
        let owner = note_key
            .find("let mut hash = WalletSecretSha256V1::new()")
            .expect("secret SHA-256 owner");
        let secret_update = note_key
            .find("hash.update_v1(shared_secret)")
            .expect("borrowed shared-secret update");
        let finalize = note_key
            .find("hash.finalize_v1()")
            .expect("owned SHA-256 finalization");
        assert!(owner < secret_update && secret_update < finalize);
        assert!(!note_key.contains("Sha256::new()"));
        assert!(!note_key.contains(".finalize()"));
        let public_key = source
            .split_once("pub fn fcmp_recipient_public_key_v1(")
            .expect("recipient public-key helper")
            .1
            .split_once("fn aad_v1(")
            .expect("public-key boundary")
            .0;
        let public_take = public_key
            .find("WalletSecretCopyValueV1::take(&mut recipient_secret_key)")
            .expect("recipient secret take");
        let public_derive = public_key
            .find("x25519_public_key_v1(recipient_secret_key.expose_ref())")
            .expect("borrowed public-key derivation");
        assert!(public_take < public_derive);
        assert!(!public_key.contains("Zeroizing::new(recipient_secret_key)"));
        let encrypt = source
            .split_once("pub fn encrypt_fcmp_wallet_note_v1(")
            .expect("encrypt helper")
            .1
            .split_once("/// Decrypt and authenticate")
            .expect("encrypt boundary")
            .0;
        assert!(encrypt.contains("x25519_public_key_v1(&*ephemeral_secret)"));
        assert!(encrypt.contains("x25519_shared_secret_v1(&*ephemeral_secret,"));
        assert!(encrypt.contains("let plaintext = note.encode("));
        assert!(encrypt.contains("XChaCha20Poly1305::new_from_slice(key.expose_ref())"));
        assert!(!encrypt.contains("x25519_public_key_v1(*ephemeral_secret)"));
        assert!(!encrypt.contains("Zeroizing::new(\n        x25519_shared_secret_v1"));
        assert!(!encrypt.contains("Zeroizing::new(note.encode("));
        let decrypt = source
            .split_once("pub fn decrypt_fcmp_wallet_note_v1(")
            .expect("decrypt helper")
            .1
            .split_once("#[cfg(test)]\nmod tests")
            .expect("decrypt boundary")
            .0;
        let decrypt_take = decrypt
            .find("WalletSecretCopyValueV1::take(&mut recipient_secret_key)")
            .expect("decrypt secret take");
        let validation = decrypt
            .find("validate_fcmp_encrypted_output_v1")
            .expect("ciphertext validation");
        assert!(decrypt_take < validation);
        assert!(decrypt.contains("x25519_public_key_v1(recipient_secret_key.expose_ref())"));
        assert!(decrypt.contains("recipient_secret_key.expose_ref(),"));
        assert!(decrypt.contains("XChaCha20Poly1305::new_from_slice(key.expose_ref())"));
        assert!(!decrypt.contains("fcmp_recipient_public_key_v1(*recipient_secret_key)"));
        assert!(!decrypt.contains("Zeroizing::new(recipient_secret_key)"));
    }
    struct PeriodicRng {
        period: usize,
        cursor: usize,
    }
    impl RngCore for PeriodicRng {
        fn next_u32(&mut self) -> u32 {
            panic!("FCMP++ wallet must reject the periodic prefix")
        }
        fn next_u64(&mut self) -> u64 {
            panic!("FCMP++ wallet must reject the periodic prefix")
        }
        fn fill_bytes(&mut self, _destination: &mut [u8]) {
            panic!("FCMP++ wallet must use fallible entropy")
        }
        fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), rand_core_06::Error> {
            for byte in destination {
                *byte = ((self.cursor % self.period) as u8)
                    .wrapping_mul(31)
                    .wrapping_add(7);
                self.cursor += 1;
            }
            Ok(())
        }
    }
    impl CryptoRng for PeriodicRng {}
    fn fixture() -> (
        PrivacyPoolIdV1,
        PrivacyFcmpOutputTupleV1,
        FcmpWalletNoteV1,
        [u8; 32],
    ) {
        let x = Scalar::from(17_u64);
        let y = Scalar::from(23_u64);
        let amount = 7_u64;
        let commitment_mask = Scalar::from(37_u64);
        let model = PrivacyFcmpOutputTupleV1 {
            output_key: ((ED25519_BASEPOINT_POINT * x) + (generator_t() * y))
                .compress()
                .to_bytes(),
            linking_tag_generator: (ED25519_BASEPOINT_POINT * Scalar::from(31_u64))
                .compress()
                .to_bytes(),
            amount_commitment: (amount_generator().expect("amount generator")
                * Scalar::from(amount)
                + ED25519_BASEPOINT_POINT * commitment_mask)
                .compress()
                .to_bytes(),
        };
        let note = FcmpWalletNoteV1::new(
            model_output(model).unwrap(),
            x.to_bytes(),
            y.to_bytes(),
            amount,
            commitment_mask.to_bytes(),
        )
        .unwrap();
        (PrivacyPoolIdV1::new([0x61; 32]), model, note, [0x42; 32])
    }
    fn authenticated_plaintext_for_test(
        pool: PrivacyPoolIdV1,
        output: PrivacyFcmpOutputTupleV1,
        encrypted: &PrivacyFcmpEncryptedOutputV1,
        recipient_secret: [u8; 32],
        plaintext: &[u8],
    ) -> PrivacyFcmpEncryptedOutputV1 {
        let shared = Zeroizing::new(
            x25519_shared_secret_v1(
                recipient_secret,
                encrypted.ephemeral_public_key.into_bytes(),
            )
            .expect("recipient shared secret"),
        );
        let aad = aad_v1(
            pool,
            encrypted.recipient,
            encrypted.ephemeral_public_key,
            output,
        );
        let key = note_key_v1(&shared, &aad);
        let (nonce_bytes, _) = parsed_ciphertext(encrypted).expect("canonical ciphertext");
        let nonce: chacha20poly1305::XNonce = nonce_bytes.into();
        let authenticated = XChaCha20Poly1305::new_from_slice(key.expose_ref())
            .expect("fixed key length")
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .expect("authenticate adversarial plaintext");
        let mut replacement = encrypted.clone();
        replacement
            .ciphertext
            .truncate(4 + PRIVACY_FCMP_ENCRYPTED_OUTPUT_NONCE_BYTES_V1);
        replacement.ciphertext.extend_from_slice(&authenticated);
        replacement
    }
    #[test]
    fn wallet_note_debug_is_redacted_and_explicit_zeroize_covers_every_secret() {
        let (_pool, _output, mut note, _secret) = fixture();
        let debug = format!("{note:?}");
        assert_eq!(
            debug,
            format!("FcmpWalletNoteV1 {{ output: {:?}, .. }}", note.output()),
            "wallet debug must contain exactly the public output tuple and a redaction marker"
        );
        note.zeroize();
        assert_eq!(note.amount, 0);
        assert_eq!(note.commitment_mask, [0; 32]);
        assert_eq!(note.spend_x, [0; 32]);
        assert_eq!(note.output_y, [0; 32]);
    }
    #[test]
    fn wallet_rng_unavailability_fails_without_calling_infallible_rng_methods() {
        let (pool, output, note, secret) = fixture();
        let public = fcmp_recipient_public_key_v1(secret).expect("recipient public key");
        assert_eq!(
            encrypt_fcmp_wallet_note_v1(&mut FailingRngV1, pool, output, &note, public),
            Err(FcmpNativeErrorV1::RandomnessUnavailable)
        );
    }
    #[test]
    fn wallet_binding_preflight_precedes_entropy_failure() {
        let (pool, mut output, note, secret) = fixture();
        output.output_key = (ED25519_BASEPOINT_POINT * Scalar::from(101_u64))
            .compress()
            .to_bytes();
        let public = fcmp_recipient_public_key_v1(secret).expect("recipient public key");
        assert_eq!(
            encrypt_fcmp_wallet_note_v1(&mut FailingRngV1, pool, output, &note, public),
            Err(FcmpNativeErrorV1::EncryptedOutputBinding)
        );
    }
    #[test]
    fn wallet_rejects_every_prohibited_short_period_entropy_prefix() {
        let (pool, output, note, secret) = fixture();
        let public = fcmp_recipient_public_key_v1(secret).expect("recipient public key");
        for period in [1, 2, 4, 8, 16, 32] {
            assert_eq!(
                encrypt_fcmp_wallet_note_v1(
                    &mut PeriodicRng { period, cursor: 0 },
                    pool,
                    output,
                    &note,
                    public,
                ),
                Err(FcmpNativeErrorV1::RandomnessHealthCheckFailed),
                "period-{period} wallet entropy was not rejected"
            );
        }
    }
    #[test]
    fn fixed_codec_round_trips_and_rejects_all_required_adversaries() {
        let (pool, output, note, secret) = fixture();
        let public = fcmp_recipient_public_key_v1(secret).unwrap();
        let mut rng = StdRng::seed_from_u64(0xfc_e001);
        let encrypted = encrypt_fcmp_wallet_note_v1(&mut rng, pool, output, &note, public).unwrap();
        assert_eq!(
            encrypted.ciphertext.len(),
            PRIVACY_FCMP_ENCRYPTED_OUTPUT_BYTES_V1
        );
        assert_eq!(
            decrypt_fcmp_wallet_note_v1(pool, output, &encrypted, secret).unwrap(),
            note
        );
        // A malicious sender can authenticate arbitrary plaintext. Recipient
        // decoding must still reject an amount/mask that does not open the
        // public C, instead of treating AEAD authentication as proof of the
        // commitment relation.
        let shared = x25519_shared_secret_v1(secret, encrypted.ephemeral_public_key.into_bytes())
            .expect("recipient shared secret");
        let aad = aad_v1(
            pool,
            encrypted.recipient,
            encrypted.ephemeral_public_key,
            output,
        );
        let key = note_key_v1(&shared, &aad);
        let (nonce_bytes, _) = parsed_ciphertext(&encrypted).expect("canonical ciphertext");
        let nonce: chacha20poly1305::XNonce = nonce_bytes.into();
        let mut mismatching_plaintext = note.encode(output.output_id().into_bytes());
        let amount_offset = 36 + FCMP_OUTPUT_TUPLE_BYTES_V1;
        mismatching_plaintext[amount_offset] ^= 1;
        let authenticated = XChaCha20Poly1305::new_from_slice(key.expose_ref())
            .expect("fixed key length")
            .encrypt(
                &nonce,
                Payload {
                    msg: mismatching_plaintext.as_ref(),
                    aad: &aad,
                },
            )
            .expect("authenticate adversarial plaintext");
        mismatching_plaintext.zeroize();
        let mut mismatching_opening = encrypted.clone();
        mismatching_opening
            .ciphertext
            .truncate(4 + PRIVACY_FCMP_ENCRYPTED_OUTPUT_NONCE_BYTES_V1);
        mismatching_opening
            .ciphertext
            .extend_from_slice(&authenticated);
        assert_eq!(
            decrypt_fcmp_wallet_note_v1(pool, output, &mismatching_opening, secret,),
            Err(FcmpNativeErrorV1::RangeCommitmentOpeningMismatch)
        );
        for index in [
            0,
            4,
            4 + PRIVACY_FCMP_ENCRYPTED_OUTPUT_NONCE_BYTES_V1,
            encrypted.ciphertext.len() - 1,
        ] {
            let mut tampered = encrypted.clone();
            tampered.ciphertext[index] ^= 1;
            assert!(
                decrypt_fcmp_wallet_note_v1(pool, output, &tampered, secret).is_err(),
                "tampered byte {index} was accepted"
            );
        }
        assert!(matches!(
            decrypt_fcmp_wallet_note_v1(pool, output, &encrypted, [0x43; 32]),
            Err(FcmpNativeErrorV1::EncryptedOutputBinding
                | FcmpNativeErrorV1::EncryptedOutputAuthentication)
        ));
        assert!(matches!(
            decrypt_fcmp_wallet_note_v1(
                PrivacyPoolIdV1::new([0x62; 32]),
                output,
                &encrypted,
                secret
            ),
            Err(FcmpNativeErrorV1::EncryptedOutputAuthentication)
        ));
        let mut substituted = output;
        substituted.amount_commitment = (ED25519_BASEPOINT_POINT * Scalar::from(41_u64))
            .compress()
            .to_bytes();
        assert!(decrypt_fcmp_wallet_note_v1(pool, substituted, &encrypted, secret).is_err());
        let mut wrong_output_id = encrypted.clone();
        wrong_output_id.output_id = substituted.output_id();
        assert!(decrypt_fcmp_wallet_note_v1(pool, output, &wrong_output_id, secret).is_err());
        let mut wrong_ephemeral = encrypted.clone();
        wrong_ephemeral.ephemeral_public_key =
            PrivacyEncryptionKeyV1::new(fcmp_recipient_public_key_v1([0x44; 32]).unwrap());
        assert!(matches!(
            decrypt_fcmp_wallet_note_v1(pool, output, &wrong_ephemeral, secret),
            Err(FcmpNativeErrorV1::EncryptedOutputAuthentication)
        ));
    }
    #[test]
    fn fixed_codec_rejects_noncanonical_shapes_and_unspendable_notes() {
        let (pool, output, note, secret) = fixture();
        let public = fcmp_recipient_public_key_v1(secret).unwrap();
        let mut rng = StdRng::seed_from_u64(0xfc_e002);
        let encrypted = encrypt_fcmp_wallet_note_v1(&mut rng, pool, output, &note, public).unwrap();
        let mut truncated = encrypted.clone();
        truncated.ciphertext.pop();
        assert!(matches!(
            validate_fcmp_encrypted_output_v1(pool, output, &truncated),
            Err(FcmpNativeErrorV1::EncryptedOutputLength { .. })
        ));
        let mut zero_nonce = encrypted.clone();
        zero_nonce.ciphertext[4..28].fill(0);
        assert!(matches!(
            validate_fcmp_encrypted_output_v1(pool, output, &zero_nonce),
            Err(FcmpNativeErrorV1::EncryptedOutputRandomness)
        ));
        let mut low_order = encrypted;
        low_order.ephemeral_public_key = PrivacyEncryptionKeyV1::new([0_u8; 32]);
        assert!(validate_fcmp_encrypted_output_v1(pool, output, &low_order).is_err());
        let native = model_output(output).unwrap();
        assert!(
            FcmpWalletNoteV1::new_borrowed(
                native,
                &Scalar::from(18_u64).to_bytes(),
                note.output_y(),
                note.amount(),
                note.commitment_mask(),
            )
            .is_err()
        );
        assert!(matches!(
            FcmpWalletNoteV1::new_borrowed(
                native,
                note.spend_x(),
                note.output_y(),
                note.amount(),
                &Scalar::from(41_u64).to_bytes(),
            ),
            Err(FcmpNativeErrorV1::RangeCommitmentOpeningMismatch)
        ));
    }
    #[test]
    fn authenticated_malformed_plaintext_fields_fail_closed() {
        let (pool, output, note, secret) = fixture();
        let public = fcmp_recipient_public_key_v1(secret).expect("recipient public key");
        let mut rng = StdRng::seed_from_u64(0xfc_e003);
        let encrypted = encrypt_fcmp_wallet_note_v1(&mut rng, pool, output, &note, public)
            .expect("canonical encrypted note");
        for (label, offset) in [
            ("note magic", 0),
            ("note version", 3),
            ("inner output id", 4),
            ("inner output key", 36),
            ("inner linking-tag generator", 36 + 32),
            ("inner amount commitment", 36 + 64),
        ] {
            let mut plaintext = note.encode(output.output_id().into_bytes());
            plaintext[offset] ^= 1;
            let adversarial = authenticated_plaintext_for_test(
                pool,
                output,
                &encrypted,
                secret,
                plaintext.as_slice(),
            );
            assert_eq!(
                decrypt_fcmp_wallet_note_v1(pool, output, &adversarial, secret),
                Err(FcmpNativeErrorV1::WalletNoteEncoding),
                "authenticated {label} substitution was accepted"
            );
        }
        let amount_start = 36 + FCMP_OUTPUT_TUPLE_BYTES_V1;
        for (label, start) in [
            ("commitment mask", amount_start + 8),
            ("spend scalar", amount_start + 40),
            ("output blinding scalar", amount_start + 72),
        ] {
            let mut plaintext = note.encode(output.output_id().into_bytes());
            plaintext[start..start + 32].fill(u8::MAX);
            let adversarial = authenticated_plaintext_for_test(
                pool,
                output,
                &encrypted,
                secret,
                plaintext.as_slice(),
            );
            assert_eq!(
                decrypt_fcmp_wallet_note_v1(pool, output, &adversarial, secret),
                Err(FcmpNativeErrorV1::ScalarEncoding),
                "authenticated noncanonical {label} was accepted"
            );
        }
    }
}
