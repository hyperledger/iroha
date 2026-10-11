//! Exact W3f ordinary-signature SHA-256 XMD and BLS12-381 hash-to-field.
//!
//! The native owner is `w3f-bls 0.1.9` with `ark-ff 0.4.2`: the ciphersuite
//! and Iroha context below prefix the actual signed message, the hash-to-field
//! DST is `[1]`, and four 64-byte big-endian integers reduce modulo the BLS
//! base prime in order `u0.c0, u0.c1, u1.c0, u1.c1`. The SHA compression is
//! the existing constrained chip; every message byte, digest byte, XOR bit,
//! padding byte, length word and modular reduction remains linked in circuit.
//!
//! The complete wrapper uses a public circuit-fixed message length. Streaming
//! owners can instead prove the exact b0 transcript externally and call
//! [`expand_from_b0`]. Neither interface authenticates a free message or proves
//! signature verification; the caller must bind its original signing bytes.

use iroha_pasta::PastaField;
use iroha_plonk::frontend::{Error, Region};

use super::{extension::Fp2Value, field::Bls381Chip};
use crate::{
    Bit, GlueChip, Word,
    sha256::{Sha256Chip, Sha256Digest, Sha256State, Sha256Word},
};

/// Exact ciphersuite followed by the ordinary Iroha signing context.
pub const W3F_SIGNING_PREFIX: &[u8] =
    b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_for signing messages";

#[derive(Clone)]
enum Byte<F: PastaField> {
    Constant(u8),
    Assigned(Word<F>),
}

/// Hash the exact W3f ordinary-signature transcript to two Fp2 elements.
///
/// Inputs are original message bytes, without a ciphersuite/context prefix.
/// They are range-checked here. The public length controls the SHA padding;
/// callers needing one key for different lengths must supply their own
/// constrained stream and use [`expand_from_b0`] plus [`reduce_uniform`].
///
/// # Errors
/// Layout/bounds errors; non-byte inputs make the circuit unsatisfied.
pub fn hash_to_field<F: PastaField>(
    field: &mut Bls381Chip<'_, F>,
    sha: &mut Sha256Chip<F>,
    region: &mut Region<'_, F>,
    message: &[Word<F>],
) -> Result<[Fp2Value<F>; 2], Error> {
    let uniform = expand_message(field, sha, region, message)?;
    reduce_uniform(field, region, &uniform)
}

/// Expand the exact W3f ordinary-signature message to 256 constrained bytes.
///
/// Uses `b0 = SHA256(0^64 || prefix || message || [1,0,0,1,1])`.
/// The first two trailing bytes encode 256, the third is XMD's zero separator,
/// and the last two are `DST || len(DST)`. The SHA chip's table must already
/// be loaded by the caller.
///
/// # Errors
/// Layout/bounds errors; non-byte inputs make the circuit unsatisfied.
pub fn expand_message<F: PastaField>(
    field: &mut Bls381Chip<'_, F>,
    sha: &mut Sha256Chip<F>,
    region: &mut Region<'_, F>,
    message: &[Word<F>],
) -> Result<[Word<F>; 256], Error> {
    let mut framed = vec![Byte::Constant(0); 64];
    framed.extend(W3F_SIGNING_PREFIX.iter().copied().map(Byte::Constant));
    for byte in message {
        field.range().range_check(region, byte, 8)?;
        framed.push(Byte::Assigned(byte.clone()));
    }
    framed.extend([1, 0, 0, 1, 1].map(Byte::Constant));
    let b0 = hash_bytes(field, sha, region, &framed)?;
    expand_from_b0(field, sha, region, &b0)
}

/// Continue XMD from a constrained SHA-256 b0 digest, always producing 256
/// bytes with the exact ordinary W3f DST `[1]` and counters 1 through 8.
///
/// A streaming caller must prove that b0 hashes the exact transcript stated
/// in [`expand_message`], including its original message length and padding.
/// An arbitrary b0 is not an authenticated message. This function does not
/// accept a host digest verdict or silently perform that missing relation.
///
/// # Errors
/// SHA, range or glue layout errors.
pub fn expand_from_b0<F: PastaField>(
    field: &mut Bls381Chip<'_, F>,
    sha: &mut Sha256Chip<F>,
    region: &mut Region<'_, F>,
    b0: &Sha256Digest<F>,
) -> Result<[Word<F>; 256], Error> {
    let b0 = digest_bytes(field, region, b0)?;
    let b0_bits = b0
        .iter()
        .map(|byte| byte_bits(field, region, byte))
        .collect::<Result<Vec<_>, _>>()?;
    let mut frame: Vec<_> = b0.iter().cloned().map(Byte::Assigned).collect();
    frame.extend([1, 1, 1].map(Byte::Constant));
    let first = hash_bytes(field, sha, region, &frame)?;
    let mut previous = digest_bytes(field, region, &first)?;
    let mut uniform = previous.to_vec();
    for counter in 2..=8 {
        let mut frame = Vec::with_capacity(35);
        for (bits, byte) in b0_bits.iter().zip(&previous) {
            let other = byte_bits(field, region, byte)?;
            let result = xor_byte(field, region, bits, &other)?;
            frame.push(Byte::Assigned(result));
        }
        frame.extend([counter, 1, 1].map(Byte::Constant));
        let digest = hash_bytes(field, sha, region, &frame)?;
        previous = digest_bytes(field, region, &digest)?;
        uniform.extend_from_slice(&previous);
    }
    uniform.try_into().map_err(|_| Error::Synthesis)
}

/// Reduce four 64-byte big-endian integers, preserving the Fp2 coefficient
/// and element order used by arkworks' `HashToField<Fq2>`.
///
/// Every supplied byte is range-checked; the base chip proves the integer
/// quotient/remainder relation and canonical result, never a native verdict.
///
/// # Errors
/// Range, glue or integer-reduction layout errors.
pub fn reduce_uniform<F: PastaField>(
    field: &mut Bls381Chip<'_, F>,
    region: &mut Region<'_, F>,
    uniform: &[Word<F>; 256],
) -> Result<[Fp2Value<F>; 2], Error> {
    let mut coefficients = Vec::with_capacity(4);
    for bytes in uniform.chunks_exact(64) {
        for byte in bytes {
            field.range().range_check(region, byte, 8)?;
        }
        let limbs = (0..8)
            .map(|limb| {
                // Each word is BE8, but the array of eight words is LE64.
                let bytes = &bytes[(7 - limb) * 8..(8 - limb) * 8];
                pack_be(field.glue(), region, bytes)
            })
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| Error::Synthesis)?;
        coefficients.push(field.reduce_words(region, &limbs)?);
    }
    let [a, b, c, d] = coefficients.try_into().map_err(|_| Error::Synthesis)?;
    Ok([
        Fp2Value::from_coefficients([a, b]),
        Fp2Value::from_coefficients([c, d]),
    ])
}

fn pack_be<F: PastaField>(
    glue: &mut GlueChip<F>,
    region: &mut Region<'_, F>,
    bytes: &[Word<F>],
) -> Result<Word<F>, Error> {
    if bytes.is_empty() || bytes.len() > 8 {
        return Err(Error::BoundsFailure);
    }
    let mut packed = glue.constant(region, F::ZERO)?;
    for byte in bytes {
        packed = glue.linear(region, &[(F::from(256), &packed), (F::ONE, byte)], F::ZERO)?;
    }
    Ok(packed)
}

fn linear_terms<F: PastaField>(
    glue: &mut GlueChip<F>,
    region: &mut Region<'_, F>,
    terms: &[(F, &Word<F>)],
    constant: F,
) -> Result<Word<F>, Error> {
    let mut sum = glue.constant(region, constant)?;
    for pair in terms.chunks(2) {
        let mut step = vec![(F::ONE, &sum)];
        step.extend_from_slice(pair);
        sum = glue.linear(region, &step, F::ZERO)?;
    }
    Ok(sum)
}

fn hash_bytes<F: PastaField>(
    field: &mut Bls381Chip<'_, F>,
    sha: &mut Sha256Chip<F>,
    region: &mut Region<'_, F>,
    message: &[Byte<F>],
) -> Result<Sha256Digest<F>, Error> {
    let bit_len = u64::try_from(message.len())
        .map_err(|_| Error::BoundsFailure)?
        .checked_mul(8)
        .ok_or(Error::BoundsFailure)?;
    let mut bytes = message.to_vec();
    bytes.push(Byte::Constant(0x80));
    while bytes.len() % 64 != 56 {
        bytes.push(Byte::Constant(0));
    }
    bytes.extend(bit_len.to_be_bytes().map(Byte::Constant));
    let mut state = Sha256State::iv();
    let mut output = None;
    for block in bytes.chunks_exact(64) {
        let words = block
            .chunks_exact(4)
            .map(|chunk| {
                let mut constant = 0_u32;
                let mut terms = Vec::new();
                for (i, byte) in chunk.iter().enumerate() {
                    let shift = 8 * (3 - i);
                    match byte {
                        Byte::Constant(byte) => constant += u32::from(*byte) << shift,
                        Byte::Assigned(word) => terms.push((F::from(1_u64 << shift), word)),
                    }
                }
                if terms.is_empty() {
                    return Ok(Sha256Word::Constant(constant));
                }
                let packed =
                    linear_terms(field.glue(), region, &terms, F::from(u64::from(constant)))?;
                Ok(Sha256Word::Assigned(sha.range_check_u32(region, &packed)?))
            })
            .collect::<Result<Vec<_>, Error>>()?
            .try_into()
            .map_err(|_| Error::Synthesis)?;
        let digest = sha.compress(region, &state, &words)?;
        state = digest.state();
        output = Some(digest);
    }
    output.ok_or(Error::Synthesis)
}

fn digest_bytes<F: PastaField>(
    field: &mut Bls381Chip<'_, F>,
    region: &mut Region<'_, F>,
    digest: &Sha256Digest<F>,
) -> Result<[Word<F>; 32], Error> {
    let mut bytes = Vec::with_capacity(32);
    for word in digest.words() {
        let start = bytes.len();
        for i in 0..4 {
            let byte = field.range().witness_range_checked(
                region,
                word.value()
                    .map(|value| F::from(((value >> (8 * (3 - i))) & 255) as u64)),
                8,
            )?;
            bytes.push(byte);
        }
        let packed = pack_be(field.glue(), region, &bytes[start..])?;
        GlueChip::assert_equal(region, &packed, word.word())?;
    }
    bytes.try_into().map_err(|_| Error::Synthesis)
}

fn byte_bits<F: PastaField>(
    field: &mut Bls381Chip<'_, F>,
    region: &mut Region<'_, F>,
    byte: &Word<F>,
) -> Result<[Bit<F>; 8], Error> {
    let value = byte.value().map(|value| value.to_canonical_limbs()[0]);
    let bits = (0..8)
        .map(|i| {
            field
                .glue()
                .boolean(region, value.map(|byte| ((byte >> i) & 1) != 0))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let terms: Vec<_> = bits
        .iter()
        .enumerate()
        .map(|(i, bit)| (F::from(1_u64 << i), bit.word()))
        .collect();
    let packed = linear_terms(field.glue(), region, &terms, F::ZERO)?;
    GlueChip::assert_equal(region, &packed, byte)?;
    bits.try_into().map_err(|_| Error::Synthesis)
}

fn xor_byte<F: PastaField>(
    field: &mut Bls381Chip<'_, F>,
    region: &mut Region<'_, F>,
    a: &[Bit<F>; 8],
    b: &[Bit<F>; 8],
) -> Result<Word<F>, Error> {
    let mut bits = Vec::with_capacity(8);
    for (a, b) in a.iter().zip(b) {
        let product = field.glue().mul(region, a.word(), b.word())?;
        let bit = field.glue().linear(
            region,
            &[
                (F::ONE, a.word()),
                (F::ONE, b.word()),
                (-F::from(2), &product),
            ],
            F::ZERO,
        )?;
        bits.push(bit);
    }
    let terms: Vec<_> = bits
        .iter()
        .enumerate()
        .map(|(i, bit)| (F::from(1_u64 << i), bit))
        .collect();
    linear_terms(field.glue(), region, &terms, F::ZERO)
}

#[cfg(test)]
mod tests;
