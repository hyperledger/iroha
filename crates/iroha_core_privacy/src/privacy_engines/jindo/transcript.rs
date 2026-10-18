//! Canonically framed Fiat--Shamir transcript for revised Jindo.
use super::{
    JINDO_RING_DEGREE_V1,
    field::JindoFieldElementV1,
    ring::{
        JINDO_INNER_MODULI_V1, JINDO_OUTER_MODULI_V1, JindoPrimeModulusV1, JindoRnsPolynomialV1,
    },
};
use crate::privacy_engines::p256::{P256EngineError, TranscriptBindingV1};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
use thiserror::Error;
const TRANSCRIPT_DOMAIN_V1: &[u8] = b"iroha.privacy.jindo.current.transcript.v1";
const CHALLENGE_DOMAIN_V1: &[u8] = b"iroha.privacy.jindo.current.challenge.v1";
const TRANSCRIPT_VERSION_V1: u8 = 3;
const MAX_DERIVATION_RETRIES_V1: u32 = 1 << 16;
const MAX_RANGE_REJECTIONS_V1: usize = 4096;
/// Cardinality of the complete signed-monomial challenge set.
pub const JINDO_SIGNED_MONOMIAL_CHALLENGE_CARDINALITY_V1: u16 = 2048;
/// One uniformly sampled challenge in `{+X^i, -X^i | 0 <= i < 1024}`.
///
/// The canonical exponent is in `Z / 2048 Z`: exponents `0..1024` encode
/// `+X^i`, while exponents `1024..2048` encode `-X^(i - 1024)` because
/// `X^1024 = -1` in the application ring.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JindoSignedMonomialChallengeV1 {
    exponent_mod_2d: u16,
}
impl JindoSignedMonomialChallengeV1 {
    /// Construct a challenge from its canonical exponent modulo `2048`.
    #[must_use]
    pub const fn from_canonical_exponent(exponent_mod_2d: u16) -> Option<Self> {
        if exponent_mod_2d < JINDO_SIGNED_MONOMIAL_CHALLENGE_CARDINALITY_V1 {
            Some(Self { exponent_mod_2d })
        } else {
            None
        }
    }
    #[cfg(test)]
    /// Return the canonical exponent in `Z / 2048 Z`.
    #[must_use]
    pub const fn canonical_exponent(self) -> u16 {
        self.exponent_mod_2d
    }
    /// Return the monomial coefficient index in `0..1024`.
    #[must_use]
    pub const fn coefficient_index(self) -> u16 {
        self.exponent_mod_2d & 1023
    }
    /// Return whether the canonical representative is negative.
    #[must_use]
    pub const fn is_negative(self) -> bool {
        self.exponent_mod_2d >= 1024
    }
    pub(crate) fn polynomial(&self, moduli: [JindoPrimeModulusV1; 2]) -> JindoRnsPolynomialV1 {
        let mut coefficients = [0_i128; JINDO_RING_DEGREE_V1];
        coefficients[usize::from(self.coefficient_index())] =
            if self.is_negative() { -1 } else { 1 };
        JindoRnsPolynomialV1::from_balanced_coefficients(coefficients, moduli)
    }
    pub(crate) fn inner_polynomial(&self) -> JindoRnsPolynomialV1 {
        self.polynomial(JINDO_INNER_MODULI_V1)
    }
    pub(crate) fn outer_polynomial(&self) -> JindoRnsPolynomialV1 {
        self.polynomial(JINDO_OUTER_MODULI_V1)
    }
    pub(crate) const fn encoded(&self) -> [u8; 2] {
        self.exponent_mod_2d.to_be_bytes()
    }
}
/// Append-only Jindo transcript state.
#[derive(Clone, Debug)]
pub struct JindoTranscriptV1 {
    state: Vec<u8>,
}
impl JindoTranscriptV1 {
    pub(crate) fn new(
        binding: &TranscriptBindingV1<'_>,
        expected_crs_digest: [u8; 32],
    ) -> Result<Self, JindoTranscriptErrorV1> {
        binding
            .validate()
            .map_err(JindoTranscriptErrorV1::Binding)?;
        if binding.generator_digest != expected_crs_digest {
            return Err(JindoTranscriptErrorV1::CrsDigestMismatch);
        }
        let mut transcript = Self {
            state: Vec::with_capacity(4096),
        };
        transcript.append_message(b"domain", TRANSCRIPT_DOMAIN_V1)?;
        transcript.append_message(b"version", &[TRANSCRIPT_VERSION_V1])?;
        transcript.append_message(b"network_id", binding.network_id)?;
        transcript.append_message(b"genesis_hash", &binding.genesis_hash)?;
        transcript.append_message(b"action_index", &binding.action_index.to_be_bytes())?;
        transcript.append_message(b"statement_digest", &binding.statement_digest)?;
        transcript.append_message(b"parameter_id", &binding.parameter_id)?;
        transcript.append_message(b"parameter_digest", &binding.parameter_digest)?;
        transcript.append_message(b"verifier_digest", &binding.verifier_digest)?;
        transcript.append_message(b"statement_schema_digest", &binding.statement_schema_digest)?;
        transcript.append_message(b"engine_manifest_digest", &binding.engine_manifest_digest)?;
        transcript.append_message(b"crs_digest", &binding.generator_digest)?;
        Ok(transcript)
    }
    pub(crate) fn append_message(
        &mut self,
        label: &[u8],
        value: &[u8],
    ) -> Result<(), JindoTranscriptErrorV1> {
        let label_len =
            u16::try_from(label.len()).map_err(|_| JindoTranscriptErrorV1::FieldTooLarge)?;
        let value_len =
            u32::try_from(value.len()).map_err(|_| JindoTranscriptErrorV1::FieldTooLarge)?;
        self.state.extend_from_slice(&label_len.to_be_bytes());
        self.state.extend_from_slice(label);
        self.state.extend_from_slice(&value_len.to_be_bytes());
        self.state.extend_from_slice(value);
        Ok(())
    }
    /// Derive the paper's uniform coefficient-field challenge
    /// `x* <- F_p^x` for `ΠSplit`.
    pub(crate) fn field_challenge(
        &mut self,
        label: &[u8],
        ordinal: u32,
    ) -> Result<JindoFieldElementV1, JindoTranscriptErrorV1> {
        for retry in 0..MAX_DERIVATION_RETRIES_V1 {
            let mut reader = self.challenge_reader(label, ordinal, retry)?;
            for _ in 0..MAX_RANGE_REJECTIONS_V1 {
                let mut bytes = [0_u8; 32];
                reader.read(&mut bytes);
                if let Some(value) = decode_nonzero_field_challenge(bytes) {
                    drop(reader);
                    self.bind_challenge(label, ordinal, retry, &bytes)?;
                    return Ok(value);
                }
            }
        }
        Err(JindoTranscriptErrorV1::ChallengeExhausted)
    }
    /// Derive one uniform signed monomial.
    ///
    /// The low eleven bits of a uniform 16-bit XOF word are exactly uniform
    /// over the 2048 canonical exponents; no modulo bias or retry path exists.
    pub(crate) fn monomial_challenge(
        &mut self,
        label: &[u8],
        ordinal: u32,
    ) -> Result<JindoSignedMonomialChallengeV1, JindoTranscriptErrorV1> {
        let mut reader = self.challenge_reader(label, ordinal, 0)?;
        let mut bytes = [0_u8; 2];
        reader.read(&mut bytes);
        let exponent_mod_2d = signed_monomial_exponent_from_word_v1(bytes);
        let challenge = JindoSignedMonomialChallengeV1::from_canonical_exponent(exponent_mod_2d)
            .expect("eleven-bit mask is a canonical signed-monomial exponent");
        let encoded = challenge.encoded();
        drop(reader);
        self.bind_challenge(label, ordinal, 0, &encoded)?;
        Ok(challenge)
    }
    fn challenge_reader(
        &self,
        label: &[u8],
        ordinal: u32,
        retry: u32,
    ) -> Result<impl XofReader, JindoTranscriptErrorV1> {
        let mut hash = Shake256::default();
        absorb(&mut hash, CHALLENGE_DOMAIN_V1)?;
        absorb(&mut hash, &self.state)?;
        absorb(&mut hash, label)?;
        hash.update(&ordinal.to_be_bytes());
        hash.update(&retry.to_be_bytes());
        Ok(hash.finalize_xof())
    }
    fn bind_challenge(
        &mut self,
        label: &[u8],
        ordinal: u32,
        retry: u32,
        encoded: &[u8],
    ) -> Result<(), JindoTranscriptErrorV1> {
        self.append_message(b"challenge_label", label)?;
        self.append_message(b"challenge_ordinal", &ordinal.to_be_bytes())?;
        self.append_message(b"challenge_retry", &retry.to_be_bytes())?;
        self.append_message(b"challenge_value", encoded)
    }
}
fn signed_monomial_exponent_from_word_v1(bytes: [u8; 2]) -> u16 {
    u16::from_be_bytes(bytes) & (JINDO_SIGNED_MONOMIAL_CHALLENGE_CARDINALITY_V1 - 1)
}
fn decode_nonzero_field_challenge(bytes: [u8; 32]) -> Option<JindoFieldElementV1> {
    let value = JindoFieldElementV1::from_canonical_bytes(bytes)?;
    (!value.is_zero()).then_some(value)
}
fn absorb(hash: &mut Shake256, value: &[u8]) -> Result<(), JindoTranscriptErrorV1> {
    let len = u64::try_from(value.len()).map_err(|_| JindoTranscriptErrorV1::FieldTooLarge)?;
    hash.update(&len.to_be_bytes());
    hash.update(value);
    Ok(())
}
/// Jindo transcript failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum JindoTranscriptErrorV1 {
    /// The consensus transcript binding is structurally invalid.
    #[error("invalid Jindo consensus transcript binding: {0}")]
    Binding(P256EngineError),
    /// The bound CRS digest differs from the compiled transparent key.
    #[error("Jindo transcript CRS digest differs from the compiled transparent key")]
    CrsDigestMismatch,
    /// A framed transcript field exceeds the canonical length limit.
    #[error("Jindo transcript field is too large")]
    FieldTooLarge,
    /// Challenge derivation exhausted its fixed retry budget.
    #[error("Jindo challenge derivation exhausted its fixed retry budget")]
    ChallengeExhausted,
}
#[cfg(test)]
mod tests {
    use super::*;
    fn binding() -> TranscriptBindingV1<'static> {
        TranscriptBindingV1 {
            network_id: &[1; 32],
            genesis_hash: [1; 32],
            action_index: 0,
            statement_digest: [2; 32],
            parameter_id: [3; 32],
            parameter_digest: [4; 32],
            verifier_digest: [5; 32],
            statement_schema_digest: [6; 32],
            engine_manifest_digest: [7; 32],
            generator_digest: [8; 32],
        }
    }
    #[test]
    fn monomial_challenge_is_canonical_and_has_exactly_one_signed_coefficient() {
        let mut transcript = JindoTranscriptV1::new(&binding(), [8; 32]).unwrap();
        let challenge = transcript.monomial_challenge(b"alpha", 0).unwrap();
        assert!(challenge.canonical_exponent() < 2048);
        let polynomial = challenge.inner_polynomial();
        let nonzero = polynomial.residues()[0]
            .iter()
            .filter(|value| **value != 0)
            .count();
        assert_eq!(nonzero, 1);
    }
    #[test]
    fn signed_monomial_transcript_kat_is_frozen() {
        let mut transcript = JindoTranscriptV1::new(&binding(), [8; 32]).unwrap();
        let exponents = core::array::from_fn::<_, 4, _>(|ordinal| {
            transcript
                .monomial_challenge(b"alpha", ordinal as u32)
                .unwrap()
                .canonical_exponent()
        });
        assert_eq!(exponents, [1631, 1367, 1928, 1267]);
    }
    #[test]
    fn eleven_bit_projection_is_exactly_uniform_over_the_complete_set() {
        let mut preimages = [0_u8; 2048];
        for word in 0..=u16::MAX {
            let exponent = usize::from(signed_monomial_exponent_from_word_v1(word.to_be_bytes()));
            preimages[exponent] += 1;
        }
        assert!(preimages.into_iter().all(|count| count == 32));
    }
    #[test]
    fn challenge_is_replayable_and_binds_prior_messages() {
        let mut a = JindoTranscriptV1::new(&binding(), [8; 32]).unwrap();
        a.append_message(b"phase", b"one").unwrap();
        let ca = a.monomial_challenge(b"alpha", 0).unwrap();
        let mut b = JindoTranscriptV1::new(&binding(), [8; 32]).unwrap();
        b.append_message(b"phase", b"one").unwrap();
        assert_eq!(ca, b.monomial_challenge(b"alpha", 0).unwrap());
        let mut c = JindoTranscriptV1::new(&binding(), [8; 32]).unwrap();
        c.append_message(b"phase", b"two").unwrap();
        assert_ne!(ca, c.monomial_challenge(b"alpha", 0).unwrap());
    }
    #[test]
    fn field_challenge_is_nonzero_and_bound() {
        let mut a = JindoTranscriptV1::new(&binding(), [8; 32]).unwrap();
        let x = a.field_challenge(b"split-x-star", 0).unwrap();
        assert!(!x.is_zero());
        let mut b = JindoTranscriptV1::new(&binding(), [8; 32]).unwrap();
        assert_eq!(x, b.field_challenge(b"split-x-star", 0).unwrap());
    }
    #[test]
    fn split_challenge_boundary_is_exactly_the_nonzero_canonical_field() {
        let zero = [0_u8; 32];
        let one = {
            let mut bytes = [0_u8; 32];
            bytes[0] = 1;
            bytes
        };
        let modulus_minus_two = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xa0, 0xf9, 0x0e, 0x57, 0x64, 0x77, 0xbe, 0x54,
            0xe8, 0x17, 0xec, 0xae, 0x55, 0x03, 0x13, 0x70, 0xde, 0xc1, 0x7c, 0x27, 0x71, 0xb8,
            0x69, 0x09, 0x00, 0x40,
        ];
        let modulus_minus_one = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa1, 0xf9, 0x0e, 0x57, 0x64, 0x77, 0xbe, 0x54,
            0xe8, 0x17, 0xec, 0xae, 0x55, 0x03, 0x13, 0x70, 0xde, 0xc1, 0x7c, 0x27, 0x71, 0xb8,
            0x69, 0x09, 0x00, 0x40,
        ];
        let modulus = [
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa1, 0xf9, 0x0e, 0x57, 0x64, 0x77, 0xbe, 0x54,
            0xe8, 0x17, 0xec, 0xae, 0x55, 0x03, 0x13, 0x70, 0xde, 0xc1, 0x7c, 0x27, 0x71, 0xb8,
            0x69, 0x09, 0x00, 0x40,
        ];
        assert_eq!(decode_nonzero_field_challenge(zero), None);
        assert_eq!(
            decode_nonzero_field_challenge(one),
            Some(JindoFieldElementV1::ONE)
        );
        assert!(decode_nonzero_field_challenge(modulus_minus_two).is_some());
        assert_eq!(
            decode_nonzero_field_challenge(modulus_minus_one),
            Some(-JindoFieldElementV1::ONE),
            "unlike the Go digit sampler, the paper-canonical sampler admits -1"
        );
        assert_eq!(decode_nonzero_field_challenge(modulus), None);
    }
}
