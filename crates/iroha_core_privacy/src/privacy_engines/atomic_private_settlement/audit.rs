//! Auditor-only encryption for atomic private-settlement leg capsules.
//!
//! One canonical plaintext is padded and encrypted exactly once with a fresh
//! 256-bit data-encryption key (DEK). The DEK is then independently wrapped for
//! every auditor in the exact governed policy order. Capsule and wrap AAD bind
//! the complete public settlement context, while only auditor-held hybrid
//! secret keys can recover plaintext business data.

use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{Aead as _, KeyInit as _, Payload},
};
use iroha_crypto::HybridError;
use iroha_crypto::hybrid_encapsulate;
use iroha_crypto::{Hash, HybridKemCiphertext, HybridSecretKey, HybridSuite, hybrid_decapsulate};
use iroha_data_model::nexus::{
    ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1, PrivateSettlementWrappedDekV1,
};
use iroha_data_model::{
    account::AccountId,
    nexus::{
        PRIVATE_SETTLEMENT_WRAPPED_DEK_BYTES_V1, PrivateSettlementAuditAadV1,
        PrivateSettlementAuditCapsuleV1, PrivateSettlementAuditPolicyV1,
        PrivateSettlementCapsulePaddingV1, PrivateSettlementValidationError,
        private_settlement_audit_plaintext_commitment_v1 as data_model_plaintext_commitment_v1,
    },
};
use rand::rand_core::TryCryptoRng;
use thiserror::Error;
use zeroize::Zeroizing;

const AUDIT_CAPSULE_AAD_DOMAIN_V1: &[u8] = b"iroha:private-settlement:audit-capsule-aad:v1\0";
const AUDIT_DEK_WRAP_AAD_DOMAIN_V1: &[u8] = b"iroha:private-settlement:audit-dek-wrap-aad:v1\0";
const AUDIT_PLAINTEXT_MAGIC_V1: [u8; 4] = *b"APC1";
const AUDIT_PLAINTEXT_HEADER_BYTES_V1: usize = 8;
const AUDIT_DEK_BYTES_V1: usize = 32;
const AUDIT_AEAD_TAG_BYTES_V1: usize = 16;
const HYBRID_SUITE_V1: HybridSuite = HybridSuite::X25519MlKem768ChaCha20Poly1305;

/// Failure sealing or opening one auditor-only private-settlement capsule.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum PrivateSettlementAuditCryptoErrorV1 {
    /// The governed policy or public capsule wire is invalid.
    #[error("private-settlement audit policy or capsule is invalid: {0}")]
    InvalidWire(PrivateSettlementValidationError),
    /// Canonical Norito encoding failed or a platform length did not fit the wire.
    #[error("private-settlement audit canonical encoding failed")]
    CanonicalEncoding,
    /// The canonical plaintext is empty or does not fit the selected padding class.
    #[error("private-settlement audit plaintext does not fit the selected padding class")]
    InvalidPlaintextSize,
    /// The supplied AAD commitment does not authenticate the canonical plaintext.
    #[error("private-settlement audit plaintext commitment mismatch")]
    PlaintextCommitmentMismatch,
    /// The injected or operating-system cryptographic RNG failed or returned inert material.
    #[error("private-settlement audit randomness is unavailable")]
    RandomnessUnavailable,
    /// Hybrid encapsulation, decapsulation, or authenticated encryption failed.
    #[error("private-settlement audit cryptographic operation failed")]
    CryptographicFailure,
    /// The selected auditor is not present in the governed policy.
    #[error("private-settlement audit recipient is not governed by this policy")]
    UnknownAuditor,
    /// The supplied hybrid secret key is not the selected auditor's governed key.
    #[error("private-settlement audit recipient key does not match the governed policy")]
    RecipientKeyMismatch,
    /// Authenticated plaintext did not contain the sole canonical padded frame.
    #[error("private-settlement audit plaintext frame is invalid")]
    InvalidPlaintextFrame,
}

impl From<PrivateSettlementValidationError> for PrivateSettlementAuditCryptoErrorV1 {
    fn from(error: PrivateSettlementValidationError) -> Self {
        Self::InvalidWire(error)
    }
}

/// Compute the commitment placed in [`PrivateSettlementAuditAadV1::plaintext_commitment`].
///
/// `canonical_plaintext` must be the exact canonical Norito bytes of the private
/// leg payload. The same bytes are returned by a successful capsule open.
///
/// # Errors
///
/// Returns [`PrivateSettlementAuditCryptoErrorV1::CanonicalEncoding`] only on
/// platforms whose slice length cannot be represented as `u64`.
pub fn private_settlement_audit_plaintext_commitment_v1(
    canonical_plaintext: &[u8],
) -> Result<Hash, PrivateSettlementAuditCryptoErrorV1> {
    data_model_plaintext_commitment_v1(canonical_plaintext)
        .map_err(|_| PrivateSettlementAuditCryptoErrorV1::CanonicalEncoding)
}

/// Seal one canonical private leg plaintext using injected cryptographic entropy.
///
/// The plaintext is encrypted once. Each governed auditor receives an
/// independently authenticated hybrid-KEM wrapping of the same random DEK.
///
/// # Errors
///
/// Returns a typed failure for invalid policy/AAD, plaintext size or commitment
/// mismatch, unavailable entropy, or a cryptographic failure.
pub fn seal_private_settlement_audit_capsule_v1_with_rng<R: TryCryptoRng>(
    canonical_plaintext: &[u8],
    aad: PrivateSettlementAuditAadV1,
    padding: PrivateSettlementCapsulePaddingV1,
    policy: &PrivateSettlementAuditPolicyV1,
    rng: &mut R,
) -> Result<PrivateSettlementAuditCapsuleV1, PrivateSettlementAuditCryptoErrorV1> {
    policy.validate()?;
    validate_aad_against_policy(&aad, policy)?;
    let maximum = maximum_plaintext_bytes(padding);
    if canonical_plaintext.is_empty() || canonical_plaintext.len() > maximum {
        return Err(PrivateSettlementAuditCryptoErrorV1::InvalidPlaintextSize);
    }
    if private_settlement_audit_plaintext_commitment_v1(canonical_plaintext)?
        != aad.plaintext_commitment
    {
        return Err(PrivateSettlementAuditCryptoErrorV1::PlaintextCommitmentMismatch);
    }

    let capsule_aad = capsule_aad_bytes(&aad)?;
    let mut padded_plaintext = Zeroizing::new(vec![0_u8; padding.plaintext_bytes()]);
    fill_nonzero_random(rng, padded_plaintext.as_mut_slice())?;
    padded_plaintext[..AUDIT_PLAINTEXT_MAGIC_V1.len()].copy_from_slice(&AUDIT_PLAINTEXT_MAGIC_V1);
    let plaintext_length = u32::try_from(canonical_plaintext.len())
        .map_err(|_| PrivateSettlementAuditCryptoErrorV1::CanonicalEncoding)?;
    padded_plaintext[4..AUDIT_PLAINTEXT_HEADER_BYTES_V1]
        .copy_from_slice(&plaintext_length.to_le_bytes());
    padded_plaintext[AUDIT_PLAINTEXT_HEADER_BYTES_V1
        ..AUDIT_PLAINTEXT_HEADER_BYTES_V1 + canonical_plaintext.len()]
        .copy_from_slice(canonical_plaintext);

    let mut dek = Zeroizing::new([0_u8; AUDIT_DEK_BYTES_V1]);
    fill_nonzero_random(rng, dek.as_mut())?;
    let mut nonce = [0_u8; 24];
    fill_nonzero_random(rng, &mut nonce)?;
    let ciphertext = aead_encrypt(&dek, &nonce, padded_plaintext.as_slice(), &capsule_aad)?;
    if ciphertext.len() != padding.ciphertext_bytes() {
        return Err(PrivateSettlementAuditCryptoErrorV1::CryptographicFailure);
    }

    let mut wrapped_deks = Vec::with_capacity(policy.body.auditors.len());
    for auditor in &policy.body.auditors {
        let recipient = auditor.encryption_key.to_hybrid()?;
        let (kem, derived) =
            hybrid_encapsulate(HYBRID_SUITE_V1, &recipient, rng).map_err(map_hybrid_seal_error)?;
        let mut wrap_nonce = [0_u8; 24];
        fill_nonzero_random(rng, &mut wrap_nonce)?;
        let wrap_aad = dek_wrap_aad_bytes(&aad, auditor.auditor_id.clone(), &recipient, &kem)?;
        let wrap_key = Zeroizing::new(derived.encryption_key());
        let wrapped_dek = aead_encrypt(&wrap_key, &wrap_nonce, dek.as_slice(), &wrap_aad)?;
        if wrapped_dek.len() != PRIVATE_SETTLEMENT_WRAPPED_DEK_BYTES_V1 {
            return Err(PrivateSettlementAuditCryptoErrorV1::CryptographicFailure);
        }
        wrapped_deks.push(PrivateSettlementWrappedDekV1 {
            auditor_id: auditor.auditor_id.clone(),
            ephemeral_x25519: *kem.ephemeral_public(),
            ml_kem_ciphertext: kem.kyber_ciphertext().to_vec(),
            nonce: wrap_nonce,
            wrapped_dek,
        });
    }

    let capsule = PrivateSettlementAuditCapsuleV1 {
        version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
        aad,
        padding,
        nonce,
        ciphertext,
        wrapped_deks,
    };
    capsule.validate_against(policy)?;
    Ok(capsule)
}

/// Open one auditor-only private-settlement capsule.
///
/// The returned buffer zeroizes its allocation on drop. It contains exactly the
/// canonical bytes supplied to the sealing function, without the private frame
/// header or random padding.
///
/// # Errors
///
/// Returns a typed failure for invalid policy/wire, an unknown auditor, a key
/// mismatch, failed KEM/AEAD authentication, or a malformed plaintext frame.
pub fn open_private_settlement_audit_capsule_v1(
    capsule: &PrivateSettlementAuditCapsuleV1,
    policy: &PrivateSettlementAuditPolicyV1,
    auditor_id: &AccountId,
    recipient_secret: &HybridSecretKey,
) -> Result<Zeroizing<Vec<u8>>, PrivateSettlementAuditCryptoErrorV1> {
    policy.validate()?;
    capsule.validate_against(policy)?;
    let auditor_index = policy
        .body
        .auditors
        .binary_search_by(|auditor| auditor.auditor_id.cmp(auditor_id))
        .map_err(|_| PrivateSettlementAuditCryptoErrorV1::UnknownAuditor)?;
    let auditor = policy
        .body
        .auditors
        .get(auditor_index)
        .ok_or(PrivateSettlementAuditCryptoErrorV1::UnknownAuditor)?;
    let wrapped = capsule
        .wrapped_deks
        .get(auditor_index)
        .ok_or(PrivateSettlementAuditCryptoErrorV1::UnknownAuditor)?;
    let expected_recipient = auditor.encryption_key.to_hybrid()?;
    if !hybrid_public_keys_equal(recipient_secret.public(), &expected_recipient) {
        return Err(PrivateSettlementAuditCryptoErrorV1::RecipientKeyMismatch);
    }
    let kem = HybridKemCiphertext::from_parts(
        wrapped.ephemeral_x25519,
        wrapped.ml_kem_ciphertext.as_slice(),
    )
    .map_err(|_| PrivateSettlementAuditCryptoErrorV1::CryptographicFailure)?;
    let derived = hybrid_decapsulate(HYBRID_SUITE_V1, &kem, recipient_secret)
        .map_err(|_| PrivateSettlementAuditCryptoErrorV1::CryptographicFailure)?;
    let wrap_aad = dek_wrap_aad_bytes(
        &capsule.aad,
        auditor.auditor_id.clone(),
        &expected_recipient,
        &kem,
    )?;
    let wrap_key = Zeroizing::new(derived.encryption_key());
    let opened_dek = Zeroizing::new(aead_decrypt(
        &wrap_key,
        &wrapped.nonce,
        wrapped.wrapped_dek.as_slice(),
        &wrap_aad,
    )?);
    if opened_dek.len() != AUDIT_DEK_BYTES_V1 || opened_dek.iter().all(|byte| *byte == 0) {
        return Err(PrivateSettlementAuditCryptoErrorV1::CryptographicFailure);
    }
    let mut dek = Zeroizing::new([0_u8; AUDIT_DEK_BYTES_V1]);
    dek.copy_from_slice(opened_dek.as_slice());

    let capsule_aad = capsule_aad_bytes(&capsule.aad)?;
    let padded_plaintext = Zeroizing::new(aead_decrypt(
        &dek,
        &capsule.nonce,
        capsule.ciphertext.as_slice(),
        &capsule_aad,
    )?);
    decode_padded_plaintext(&padded_plaintext, capsule)
}

fn maximum_plaintext_bytes(padding: PrivateSettlementCapsulePaddingV1) -> usize {
    padding
        .plaintext_bytes()
        .saturating_sub(AUDIT_PLAINTEXT_HEADER_BYTES_V1)
}

fn validate_aad_against_policy(
    aad: &PrivateSettlementAuditAadV1,
    policy: &PrivateSettlementAuditPolicyV1,
) -> Result<(), PrivateSettlementAuditCryptoErrorV1> {
    if aad.route.dataspace_id != policy.body.dataspace_id
        || aad.audit_policy_digest != policy.policy_digest
        || aad.audit_key_epoch != policy.body.key_epoch
        || aad.network_id.as_bytes().iter().all(|byte| *byte == 0)
        || aad.bundle_id.as_ref().iter().all(|byte| *byte == 0)
        || aad
            .route
            .lane_incarnation
            .as_ref()
            .iter()
            .all(|byte| *byte == 0)
        || aad.authority_digest.as_ref().iter().all(|byte| *byte == 0)
        || aad.authority_context_height == 0
        || aad
            .plaintext_commitment
            .as_ref()
            .iter()
            .all(|byte| *byte == 0)
    {
        return Err(PrivateSettlementValidationError::AuditCapsuleBindingMismatch.into());
    }
    Ok(())
}

fn fill_nonzero_random<R: TryCryptoRng + ?Sized>(
    rng: &mut R,
    destination: &mut [u8],
) -> Result<(), PrivateSettlementAuditCryptoErrorV1> {
    rng.try_fill_bytes(destination)
        .map_err(|_| PrivateSettlementAuditCryptoErrorV1::RandomnessUnavailable)?;
    if !destination.is_empty() && destination.iter().all(|byte| *byte == 0) {
        return Err(PrivateSettlementAuditCryptoErrorV1::RandomnessUnavailable);
    }
    Ok(())
}

fn capsule_aad_bytes(
    aad: &PrivateSettlementAuditAadV1,
) -> Result<Vec<u8>, PrivateSettlementAuditCryptoErrorV1> {
    let encoded = norito::encode_canonical(aad)
        .map_err(|_| PrivateSettlementAuditCryptoErrorV1::CanonicalEncoding)?;
    frame_public_aad(AUDIT_CAPSULE_AAD_DOMAIN_V1, &encoded)
}

fn dek_wrap_aad_bytes(
    capsule_aad: &PrivateSettlementAuditAadV1,
    auditor_id: AccountId,
    recipient: &iroha_crypto::HybridPublicKey,
    kem: &HybridKemCiphertext,
) -> Result<Vec<u8>, PrivateSettlementAuditCryptoErrorV1> {
    let encoded = norito::encode_canonical(&(
        *capsule_aad,
        auditor_id,
        capsule_aad.audit_key_epoch,
        recipient.x25519_bytes(),
        recipient.kyber_bytes().to_vec(),
        *kem.ephemeral_public(),
        kem.kyber_ciphertext().to_vec(),
    ))
    .map_err(|_| PrivateSettlementAuditCryptoErrorV1::CanonicalEncoding)?;
    frame_public_aad(AUDIT_DEK_WRAP_AAD_DOMAIN_V1, &encoded)
}

fn frame_public_aad(
    domain: &[u8],
    encoded: &[u8],
) -> Result<Vec<u8>, PrivateSettlementAuditCryptoErrorV1> {
    let encoded_len = u64::try_from(encoded.len())
        .map_err(|_| PrivateSettlementAuditCryptoErrorV1::CanonicalEncoding)?;
    let mut framed = Vec::with_capacity(domain.len() + 8 + encoded.len());
    framed.extend_from_slice(domain);
    framed.extend_from_slice(&encoded_len.to_le_bytes());
    framed.extend_from_slice(encoded);
    Ok(framed)
}

fn aead_encrypt(
    key: &[u8; AUDIT_DEK_BYTES_V1],
    nonce: &[u8; 24],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, PrivateSettlementAuditCryptoErrorV1> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| PrivateSettlementAuditCryptoErrorV1::CryptographicFailure)?;
    let nonce: &chacha20poly1305::XNonce = nonce
        .as_slice()
        .try_into()
        .map_err(|_| PrivateSettlementAuditCryptoErrorV1::CryptographicFailure)?;
    cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| PrivateSettlementAuditCryptoErrorV1::CryptographicFailure)
}

fn aead_decrypt(
    key: &[u8; AUDIT_DEK_BYTES_V1],
    nonce: &[u8; 24],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, PrivateSettlementAuditCryptoErrorV1> {
    let cipher = XChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| PrivateSettlementAuditCryptoErrorV1::CryptographicFailure)?;
    let nonce: &chacha20poly1305::XNonce = nonce
        .as_slice()
        .try_into()
        .map_err(|_| PrivateSettlementAuditCryptoErrorV1::CryptographicFailure)?;
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| PrivateSettlementAuditCryptoErrorV1::CryptographicFailure)
}

fn map_hybrid_seal_error(error: HybridError) -> PrivateSettlementAuditCryptoErrorV1 {
    match error {
        HybridError::RandomBytes { .. } => {
            PrivateSettlementAuditCryptoErrorV1::RandomnessUnavailable
        }
        _ => PrivateSettlementAuditCryptoErrorV1::CryptographicFailure,
    }
}

fn hybrid_public_keys_equal(
    left: &iroha_crypto::HybridPublicKey,
    right: &iroha_crypto::HybridPublicKey,
) -> bool {
    left.x25519_bytes() == right.x25519_bytes() && left.kyber_bytes() == right.kyber_bytes()
}

fn decode_padded_plaintext(
    padded_plaintext: &[u8],
    capsule: &PrivateSettlementAuditCapsuleV1,
) -> Result<Zeroizing<Vec<u8>>, PrivateSettlementAuditCryptoErrorV1> {
    if padded_plaintext.len() != capsule.padding.plaintext_bytes()
        || padded_plaintext.get(..4) != Some(AUDIT_PLAINTEXT_MAGIC_V1.as_slice())
    {
        return Err(PrivateSettlementAuditCryptoErrorV1::InvalidPlaintextFrame);
    }
    let length_bytes: [u8; 4] = padded_plaintext
        .get(4..AUDIT_PLAINTEXT_HEADER_BYTES_V1)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(PrivateSettlementAuditCryptoErrorV1::InvalidPlaintextFrame)?;
    let plaintext_length = usize::try_from(u32::from_le_bytes(length_bytes))
        .map_err(|_| PrivateSettlementAuditCryptoErrorV1::InvalidPlaintextFrame)?;
    if plaintext_length == 0 || plaintext_length > maximum_plaintext_bytes(capsule.padding) {
        return Err(PrivateSettlementAuditCryptoErrorV1::InvalidPlaintextFrame);
    }
    let plaintext_end = AUDIT_PLAINTEXT_HEADER_BYTES_V1
        .checked_add(plaintext_length)
        .ok_or(PrivateSettlementAuditCryptoErrorV1::InvalidPlaintextFrame)?;
    let plaintext = padded_plaintext
        .get(AUDIT_PLAINTEXT_HEADER_BYTES_V1..plaintext_end)
        .ok_or(PrivateSettlementAuditCryptoErrorV1::InvalidPlaintextFrame)?;
    if private_settlement_audit_plaintext_commitment_v1(plaintext)?
        != capsule.aad.plaintext_commitment
    {
        return Err(PrivateSettlementAuditCryptoErrorV1::PlaintextCommitmentMismatch);
    }
    Ok(Zeroizing::new(plaintext.to_vec()))
}

const _: () = assert!(
    PRIVATE_SETTLEMENT_WRAPPED_DEK_BYTES_V1 == AUDIT_DEK_BYTES_V1 + AUDIT_AEAD_TAG_BYTES_V1
);

#[cfg(test)]
mod tests {
    use super::super::test_fixtures::aps_sidecar_material_fixture_v1 as sidecar_fixture;
    use super::*;
    use iroha_crypto::{Algorithm, HybridKeyPair, KeyPair};
    use iroha_data_model::nexus::private_settlement_capsule_canonical_upper_bound_v1;
    use iroha_data_model::nexus::{
        PrivateSettlementAuditPolicyBodyV1, PrivateSettlementAuditorV1,
        PrivateSettlementHybridPublicKeyV1,
    };
    use rand::rand_core::{TryCryptoRng, TryRngCore};

    struct Fixture {
        policy: PrivateSettlementAuditPolicyV1,
        recipients: Vec<(AccountId, HybridKeyPair)>,
        aad: PrivateSettlementAuditAadV1,
        plaintext: Vec<u8>,
    }

    fn hash(seed: u8) -> Hash {
        Hash::new([seed])
    }

    fn fixture() -> Fixture {
        let typed_plaintext = sidecar_fixture().plaintext;
        let mut rows = Vec::new();
        for index in 0_u8..2 {
            let signing = KeyPair::from_seed(vec![0x51 + index; 32], Algorithm::Ed25519);
            let auditor_id = AccountId::new(signing.public_key().clone());
            let mut key_rng = iroha_crypto::rng_from_seed_slice(&[0x71 + index]);
            let encryption = HybridKeyPair::generate(&mut key_rng).expect("hybrid auditor key");
            let auditor = PrivateSettlementAuditorV1 {
                auditor_id: auditor_id.clone(),
                signing_key: signing.public_key().clone(),
                encryption_key: PrivateSettlementHybridPublicKeyV1::from_hybrid(
                    encryption.public(),
                ),
            };
            rows.push((auditor, encryption));
        }
        rows.sort_by(|left, right| left.0.auditor_id.cmp(&right.0.auditor_id));
        let recipients = rows
            .iter()
            .map(|(auditor, key)| (auditor.auditor_id.clone(), key.clone()))
            .collect();
        let policy = PrivateSettlementAuditPolicyV1::new(PrivateSettlementAuditPolicyBodyV1 {
            version: ATOMIC_PRIVATE_SETTLEMENT_VERSION_V1,
            dataspace_id: typed_plaintext.route.dataspace_id,
            policy_id: hash(3),
            revision: 2,
            key_epoch: 9,
            activation_height: 10,
            retirement_height: Some(1_000),
            min_approvals: 1,
            auditors: rows.into_iter().map(|(auditor, _)| auditor).collect(),
        })
        .expect("valid auditor policy");
        let plaintext = norito::encode_canonical(&typed_plaintext).expect("canonical private leg");
        let plaintext_commitment =
            private_settlement_audit_plaintext_commitment_v1(&plaintext).expect("commitment");
        let aad = PrivateSettlementAuditAadV1 {
            network_id: typed_plaintext.network_id,
            bundle_id: typed_plaintext.bundle_id,
            leg_ordinal: typed_plaintext.leg_ordinal,
            route: typed_plaintext.route,
            authority_digest: hash(0xA4),
            authority_context_height: 10,
            audit_policy_digest: policy.policy_digest,
            audit_key_epoch: policy.body.key_epoch,
            plaintext_commitment,
        };
        Fixture {
            policy,
            recipients,
            aad,
            plaintext,
        }
    }

    #[test]
    fn one_ciphertext_roundtrips_for_every_governed_auditor() {
        let fixture = fixture();
        let mut rng = iroha_crypto::rng_from_seed_slice(b"private settlement audit capsule");
        let capsule = seal_private_settlement_audit_capsule_v1_with_rng(
            &fixture.plaintext,
            fixture.aad,
            PrivateSettlementCapsulePaddingV1::KiB16,
            &fixture.policy,
            &mut rng,
        )
        .expect("capsule seals");
        assert_eq!(
            capsule.ciphertext.len(),
            PrivateSettlementCapsulePaddingV1::KiB16.ciphertext_bytes()
        );
        assert_eq!(capsule.wrapped_deks.len(), fixture.recipients.len());
        assert!(
            u64::try_from(
                norito::encode_canonical(&capsule)
                    .expect("capsule encodes")
                    .len()
            )
            .expect("capsule length fits u64")
                <= private_settlement_capsule_canonical_upper_bound_v1(
                    u64::try_from(PrivateSettlementCapsulePaddingV1::KiB16.plaintext_bytes())
                        .expect("padding fits u64"),
                    u64::try_from(fixture.recipients.len()).expect("auditor count fits u64"),
                )
        );
        capsule
            .validate_against(&fixture.policy)
            .expect("wire remains valid");
        for (auditor_id, recipient) in &fixture.recipients {
            let opened = open_private_settlement_audit_capsule_v1(
                &capsule,
                &fixture.policy,
                auditor_id,
                recipient.secret(),
            )
            .expect("governed auditor opens capsule");
            assert_eq!(opened.as_slice(), fixture.plaintext.as_slice());
        }
    }

    #[test]
    fn wrong_recipient_key_is_rejected_before_decryption() {
        let fixture = fixture();
        let mut rng = iroha_crypto::rng_from_seed_slice(b"private settlement wrong key capsule");
        let capsule = seal_private_settlement_audit_capsule_v1_with_rng(
            &fixture.plaintext,
            fixture.aad,
            PrivateSettlementCapsulePaddingV1::KiB16,
            &fixture.policy,
            &mut rng,
        )
        .expect("capsule seals");
        let mut wrong_rng = iroha_crypto::rng_from_seed_slice(b"unrelated recipient key");
        let wrong = HybridKeyPair::generate(&mut wrong_rng).expect("wrong key");
        let error = open_private_settlement_audit_capsule_v1(
            &capsule,
            &fixture.policy,
            &fixture.recipients[0].0,
            wrong.secret(),
        )
        .expect_err("wrong key must fail");
        assert_eq!(
            error,
            PrivateSettlementAuditCryptoErrorV1::RecipientKeyMismatch
        );
    }

    #[test]
    fn aad_and_ciphertext_tampering_are_rejected() {
        let fixture = fixture();
        let mut rng = iroha_crypto::rng_from_seed_slice(b"private settlement tamper capsule");
        let capsule = seal_private_settlement_audit_capsule_v1_with_rng(
            &fixture.plaintext,
            fixture.aad,
            PrivateSettlementCapsulePaddingV1::KiB16,
            &fixture.policy,
            &mut rng,
        )
        .expect("capsule seals");
        let (auditor_id, recipient) = &fixture.recipients[0];

        let mut aad_tampered = capsule.clone();
        aad_tampered.aad.bundle_id = hash(0xA1);
        assert!(
            open_private_settlement_audit_capsule_v1(
                &aad_tampered,
                &fixture.policy,
                auditor_id,
                recipient.secret(),
            )
            .is_err()
        );

        let mut authority_tampered = capsule.clone();
        authority_tampered.aad.authority_digest = hash(0xA2);
        assert!(
            open_private_settlement_audit_capsule_v1(
                &authority_tampered,
                &fixture.policy,
                auditor_id,
                recipient.secret(),
            )
            .is_err()
        );

        let mut context_tampered = capsule.clone();
        context_tampered.aad.authority_context_height += 1;
        assert!(
            open_private_settlement_audit_capsule_v1(
                &context_tampered,
                &fixture.policy,
                auditor_id,
                recipient.secret(),
            )
            .is_err()
        );

        let mut ciphertext_tampered = capsule.clone();
        ciphertext_tampered.ciphertext[0] ^= 1;
        assert!(
            open_private_settlement_audit_capsule_v1(
                &ciphertext_tampered,
                &fixture.policy,
                auditor_id,
                recipient.secret(),
            )
            .is_err()
        );

        let mut wrap_tampered = capsule;
        wrap_tampered.wrapped_deks[0].wrapped_dek[0] ^= 1;
        assert!(
            open_private_settlement_audit_capsule_v1(
                &wrap_tampered,
                &fixture.policy,
                auditor_id,
                recipient.secret(),
            )
            .is_err()
        );
    }

    #[test]
    fn padding_classes_enforce_exact_plaintext_bounds() {
        let fixture = fixture();
        for (index, padding) in [
            PrivateSettlementCapsulePaddingV1::KiB4,
            PrivateSettlementCapsulePaddingV1::KiB16,
            PrivateSettlementCapsulePaddingV1::KiB64,
            PrivateSettlementCapsulePaddingV1::KiB256,
        ]
        .into_iter()
        .enumerate()
        {
            let maximum = maximum_plaintext_bytes(padding);
            let mut rng = iroha_crypto::rng_from_seed_slice(&[0x91 + index as u8]);
            let typed_result = seal_private_settlement_audit_capsule_v1_with_rng(
                &fixture.plaintext,
                fixture.aad,
                padding,
                &fixture.policy,
                &mut rng,
            );
            if fixture.plaintext.len() <= maximum {
                let capsule = typed_result.expect("fitting typed plaintext seals");
                assert_eq!(capsule.ciphertext.len(), padding.ciphertext_bytes());
            } else {
                assert_eq!(
                    typed_result.expect_err("undersized padding class must fail"),
                    PrivateSettlementAuditCryptoErrorV1::InvalidPlaintextSize
                );
            }

            let too_large = vec![0xA5; maximum + 1];
            let error = seal_private_settlement_audit_capsule_v1_with_rng(
                &too_large,
                fixture.aad,
                padding,
                &fixture.policy,
                &mut rng,
            )
            .expect_err("oversized plaintext must fail");
            assert_eq!(
                error,
                PrivateSettlementAuditCryptoErrorV1::InvalidPlaintextSize
            );
            let display = error.to_string();
            assert!(!display.contains(&(maximum + 1).to_string()));
            assert!(!display.contains(&maximum.to_string()));
        }

        let mut rng = iroha_crypto::rng_from_seed_slice(b"empty private settlement capsule");
        let error = seal_private_settlement_audit_capsule_v1_with_rng(
            &[],
            fixture.aad,
            PrivateSettlementCapsulePaddingV1::KiB4,
            &fixture.policy,
            &mut rng,
        )
        .expect_err("empty plaintext must fail");
        assert_eq!(
            error,
            PrivateSettlementAuditCryptoErrorV1::InvalidPlaintextSize
        );
        assert_eq!(
            error.to_string(),
            "private-settlement audit plaintext does not fit the selected padding class"
        );
    }

    #[derive(Debug)]
    struct InjectedRngError;

    impl core::fmt::Display for InjectedRngError {
        fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            formatter.write_str("injected private-settlement audit RNG failure")
        }
    }

    struct FailingRng;

    impl TryRngCore for FailingRng {
        type Error = InjectedRngError;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Err(InjectedRngError)
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Err(InjectedRngError)
        }

        fn try_fill_bytes(&mut self, _destination: &mut [u8]) -> Result<(), Self::Error> {
            Err(InjectedRngError)
        }
    }

    impl TryCryptoRng for FailingRng {}

    #[test]
    fn rng_failure_is_reported_without_a_partial_capsule() {
        let fixture = fixture();
        let error = seal_private_settlement_audit_capsule_v1_with_rng(
            &fixture.plaintext,
            fixture.aad,
            PrivateSettlementCapsulePaddingV1::KiB16,
            &fixture.policy,
            &mut FailingRng,
        )
        .expect_err("RNG failure must be reported");
        assert_eq!(
            error,
            PrivateSettlementAuditCryptoErrorV1::RandomnessUnavailable
        );
    }
}
