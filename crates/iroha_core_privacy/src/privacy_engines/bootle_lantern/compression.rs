//! Canonical ABDLOP decomposition and reconciliation hints.
//!
//! The fixed parameters satisfy `q = gamma * m + 1`. The exceptional residue
//! `q - 1` therefore needs the explicit `(high, low) = (0, -1)` branch from
//! the Lantern construction; ordinary integer division would emit the
//! non-canonical high part `m`.
use super::params::{
    COMPRESSION_GAMMA_V1, COMPRESSION_MODULUS_V1, DECOMPOSITION_BITS_V1, PROOF_MODULUS_V1,
};
use thiserror::Error;
const POWER_OF_TWO_V1: u64 = 1_u64 << DECOMPOSITION_BITS_V1;
const POWER_OF_TWO_HALF_V1: i64 = u64::cast_signed(POWER_OF_TWO_V1 / 2);
const GAMMA_HALF_V1: i64 = u64::cast_signed(COMPRESSION_GAMMA_V1 / 2);
const COMPRESSION_MODULUS_HALF_V1: i64 = u64::cast_signed(COMPRESSION_MODULUS_V1 / 2);
const PROOF_MODULUS_HALF_V1: i64 = u64::cast_signed(PROOF_MODULUS_V1 / 2);
/// Rounded high part and signed low part of one proof-ring residue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Power2RoundV1 {
    /// Canonical high part, strictly below `2^36`.
    pub high: u64,
    /// Centered low part in `(-2^14, 2^14]`.
    pub low: i64,
}
/// `gamma`-decomposition of one proof-ring residue.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GammaDecompositionV1 {
    /// Canonical high part in `[0,m)`.
    pub high: u64,
    /// Centered low part in `(-gamma/2, gamma/2]`, with the exceptional
    /// `q-1` residue represented as `-1`.
    pub low: i64,
}
/// Compute the unique `2^15` rounding used for compressed `tA1`.
///
/// # Errors
///
/// Rejects a non-canonical proof-ring residue.
pub fn power2round_v1(residue: u64) -> Result<Power2RoundV1, CompressionErrorV1> {
    require_canonical(residue)?;
    let mut low =
        i64::try_from(residue % POWER_OF_TWO_V1).expect("power-of-two remainder fits i64");
    if low > POWER_OF_TWO_HALF_V1 {
        low -= i64::try_from(POWER_OF_TWO_V1).expect("power of two fits i64");
    }
    let adjusted = i128::from(residue) - i128::from(low);
    let high = u64::try_from(adjusted / i128::from(POWER_OF_TWO_V1))
        .expect("non-negative rounded high part fits u64");
    debug_assert!(high < (1_u64 << 36));
    Ok(Power2RoundV1 { high, low })
}
/// Compute the unique `gamma`-decomposition used by reconciliation.
///
/// # Errors
///
/// Rejects a non-canonical proof-ring residue.
pub fn gamma_decompose_v1(residue: u64) -> Result<GammaDecompositionV1, CompressionErrorV1> {
    require_canonical(residue)?;
    let mut low = i64::try_from(residue % COMPRESSION_GAMMA_V1).expect("gamma remainder fits i64");
    if low > GAMMA_HALF_V1 {
        low -= i64::try_from(COMPRESSION_GAMMA_V1).expect("gamma fits i64");
    }
    let adjusted = i128::from(residue) - i128::from(low);
    if adjusted == i128::from(PROOF_MODULUS_V1 - 1) {
        return Ok(GammaDecompositionV1 {
            high: 0,
            low: low - 1,
        });
    }
    let high = u64::try_from(adjusted / i128::from(COMPRESSION_GAMMA_V1))
        .expect("non-negative gamma high part fits u64");
    if high >= COMPRESSION_MODULUS_V1 {
        return Err(CompressionErrorV1::InternalInvariant);
    }
    Ok(GammaDecompositionV1 { high, low })
}
#[cfg(test)]
/// Reconstruct the proof-ring residue represented by a gamma decomposition.
///
/// # Errors
///
/// Rejects a high or low part outside the canonical decomposition domains.
pub fn recompose_gamma_v1(decomposition: GammaDecompositionV1) -> Result<u64, CompressionErrorV1> {
    if decomposition.high >= COMPRESSION_MODULUS_V1 {
        return Err(CompressionErrorV1::InvalidGammaHigh);
    }
    if !(-GAMMA_HALF_V1..=GAMMA_HALF_V1).contains(&decomposition.low)
        || decomposition.low == -GAMMA_HALF_V1
    {
        return Err(CompressionErrorV1::InvalidGammaLow);
    }
    Ok(canonicalize_i128(
        i128::from(decomposition.high) * i128::from(COMPRESSION_GAMMA_V1)
            + i128::from(decomposition.low),
    ))
}
/// Compute the centered reconciliation hint for `r + z` relative to `r`.
///
/// # Errors
///
/// Rejects non-canonical `r` or a correction outside the unique centered
/// proof-ring lift `[-floor(q/2), floor(q/2)]`.
pub fn make_gamma_hint_v1(residue: u64, correction: i64) -> Result<i64, CompressionErrorV1> {
    require_canonical(residue)?;
    if !(-PROOF_MODULUS_HALF_V1..=PROOF_MODULUS_HALF_V1).contains(&correction) {
        return Err(CompressionErrorV1::CorrectionOutOfRange);
    }
    let base = gamma_decompose_v1(residue)?;
    let corrected_residue = canonicalize_i128(i128::from(residue) + i128::from(correction));
    let corrected = gamma_decompose_v1(corrected_residue)?;
    Ok(center_modulus_even(
        i128::from(corrected.high) - i128::from(base.high),
    ))
}
/// Recover the reconciled high part from a centered hint and base residue.
///
/// # Errors
///
/// Rejects non-canonical `r` or a hint outside `(-m/2,m/2]`.
pub fn use_gamma_hint_v1(residue: u64, hint: i64) -> Result<u64, CompressionErrorV1> {
    require_canonical(residue)?;
    if !(-COMPRESSION_MODULUS_HALF_V1..=COMPRESSION_MODULUS_HALF_V1).contains(&hint)
        || hint == -COMPRESSION_MODULUS_HALF_V1
    {
        return Err(CompressionErrorV1::HintOutOfRange);
    }
    let base = gamma_decompose_v1(residue)?;
    Ok(mod_i128(
        i128::from(base.high) + i128::from(hint),
        COMPRESSION_MODULUS_V1,
    ))
}
/// Convert one canonical proof residue to its centered lift.
///
/// # Errors
///
/// Rejects a residue at least `q`.
pub fn center_proof_residue_v1(residue: u64) -> Result<i64, CompressionErrorV1> {
    require_canonical(residue)?;
    if residue <= PROOF_MODULUS_V1 / 2 {
        Ok(i64::try_from(residue).expect("proof residue fits i64"))
    } else {
        Ok(i64::try_from(residue).expect("proof residue fits i64")
            - i64::try_from(PROOF_MODULUS_V1).expect("proof modulus fits i64"))
    }
}
#[cfg(test)]
/// Convert a signed lift to its unique proof-ring residue.
#[must_use]
pub fn proof_residue_from_centered_v1(value: i64) -> u64 {
    canonicalize_i128(i128::from(value))
}
fn center_modulus_even(value: i128) -> i64 {
    let mut centered = i128::from(mod_i128(value, COMPRESSION_MODULUS_V1));
    let half = i128::from(COMPRESSION_MODULUS_HALF_V1);
    if centered > half {
        centered -= i128::from(COMPRESSION_MODULUS_V1);
    }
    i64::try_from(centered).expect("centered hint fits i64")
}
fn mod_i128(value: i128, modulus: u64) -> u64 {
    let modulus = i128::from(modulus);
    let mut reduced = value % modulus;
    if reduced < 0 {
        reduced += modulus;
    }
    u64::try_from(reduced).expect("canonical non-negative residue fits u64")
}
fn canonicalize_i128(value: i128) -> u64 {
    mod_i128(value, PROOF_MODULUS_V1)
}
fn require_canonical(residue: u64) -> Result<(), CompressionErrorV1> {
    if residue >= PROOF_MODULUS_V1 {
        return Err(CompressionErrorV1::NonCanonicalResidue);
    }
    Ok(())
}
/// Fixed decomposition failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum CompressionErrorV1 {
    /// Input residue was not in `[0,q)`.
    #[error("Bootle/Lantern compression input is not a canonical proof residue")]
    NonCanonicalResidue,
    /// A gamma high part was not in `[0,m)`.
    #[error("Bootle/Lantern gamma high part is outside its canonical range")]
    InvalidGammaHigh,
    /// A gamma low part was not in `(-gamma/2,gamma/2]`.
    #[error("Bootle/Lantern gamma low part is outside its canonical range")]
    InvalidGammaLow,
    /// A correction was not the unique centered proof-ring lift.
    #[error("Bootle/Lantern gamma correction is not a canonical centered proof-ring lift")]
    CorrectionOutOfRange,
    /// A hint was outside `(-m/2,m/2]`.
    #[error("Bootle/Lantern reconciliation hint is outside its canonical range")]
    HintOutOfRange,
    /// A fixed arithmetic invariant failed.
    #[error("Bootle/Lantern compression arithmetic invariant failed")]
    InternalInvariant,
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixed_parameters_have_the_required_exact_factorization() {
        assert_eq!(
            COMPRESSION_GAMMA_V1 * COMPRESSION_MODULUS_V1 + 1,
            PROOF_MODULUS_V1
        );
        assert_eq!(POWER_OF_TWO_V1, 32_768);
    }
    #[test]
    fn power2round_boundaries_are_unique_and_recompose_exactly() {
        for residue in [
            0,
            1,
            16_384,
            16_385,
            32_767,
            32_768,
            PROOF_MODULUS_V1 / 2,
            PROOF_MODULUS_V1 - 2,
            PROOF_MODULUS_V1 - 1,
        ] {
            let rounded = power2round_v1(residue).expect("canonical");
            assert!((-16_383..=16_384).contains(&rounded.low));
            assert!(rounded.high < (1_u64 << 36));
            assert_eq!(
                canonicalize_i128(
                    i128::from(rounded.high) * i128::from(POWER_OF_TWO_V1)
                        + i128::from(rounded.low)
                ),
                residue
            );
        }
        assert_eq!(
            power2round_v1(PROOF_MODULUS_V1),
            Err(CompressionErrorV1::NonCanonicalResidue)
        );
    }
    #[test]
    fn gamma_decomposition_handles_q_minus_one_exception_exactly() {
        assert_eq!(
            gamma_decompose_v1(PROOF_MODULUS_V1 - 1).expect("canonical"),
            GammaDecompositionV1 { high: 0, low: -1 }
        );
        for residue in [
            0,
            1,
            COMPRESSION_GAMMA_V1 / 2,
            COMPRESSION_GAMMA_V1 / 2 + 1,
            COMPRESSION_GAMMA_V1 - 1,
            COMPRESSION_GAMMA_V1,
            PROOF_MODULUS_V1 / 2,
            PROOF_MODULUS_V1 - 2,
            PROOF_MODULUS_V1 - 1,
        ] {
            let decomposition = gamma_decompose_v1(residue).expect("canonical");
            assert!(decomposition.high < COMPRESSION_MODULUS_V1);
            assert!((-GAMMA_HALF_V1 + 1..=GAMMA_HALF_V1).contains(&decomposition.low));
            assert_eq!(
                recompose_gamma_v1(decomposition).expect("canonical decomposition"),
                residue
            );
        }
    }
    #[test]
    fn hint_recovers_corrected_high_part_across_all_boundary_classes() {
        for residue in [
            0,
            1,
            COMPRESSION_GAMMA_V1 / 2,
            COMPRESSION_GAMMA_V1 / 2 + 1,
            COMPRESSION_GAMMA_V1,
            PROOF_MODULUS_V1 / 2,
            PROOF_MODULUS_V1 - 2,
            PROOF_MODULUS_V1 - 1,
        ] {
            for correction in [
                -PROOF_MODULUS_HALF_V1,
                -(GAMMA_HALF_V1 + 1),
                -GAMMA_HALF_V1,
                -GAMMA_HALF_V1 + 1,
                -1,
                0,
                1,
                GAMMA_HALF_V1 - 1,
                GAMMA_HALF_V1,
                GAMMA_HALF_V1 + 1,
                PROOF_MODULUS_HALF_V1,
            ] {
                let hint = make_gamma_hint_v1(residue, correction).expect("hint");
                let recovered = use_gamma_hint_v1(residue, hint).expect("reconcile");
                let corrected = gamma_decompose_v1(canonicalize_i128(
                    i128::from(residue) + i128::from(correction),
                ))
                .expect("corrected decomposition");
                assert_eq!(recovered, corrected.high);
            }
        }
    }
    #[test]
    fn hint_recovers_the_full_centered_response_domain_on_an_adversarial_corpus() {
        let mut state = 0xC6BC_2796_92B5_CC83_u64;
        for _ in 0..100_000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let residue = state % PROOF_MODULUS_V1;
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let correction_residue = state % PROOF_MODULUS_V1;
            let correction =
                center_proof_residue_v1(correction_residue).expect("canonical correction");
            let hint = make_gamma_hint_v1(residue, correction).expect("full-domain hint");
            let recovered = use_gamma_hint_v1(residue, hint).expect("full-domain reconciliation");
            let corrected = gamma_decompose_v1(canonicalize_i128(
                i128::from(residue) + i128::from(correction),
            ))
            .expect("corrected decomposition");
            assert_eq!(recovered, corrected.high);
        }
    }
    #[test]
    fn decomposition_roundtrips_a_large_deterministic_adversarial_corpus() {
        let mut state = 0xD1B5_4A32_D192_ED03_u64;
        for _ in 0..100_000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let residue = state % PROOF_MODULUS_V1;
            let decomposition = gamma_decompose_v1(residue).expect("canonical");
            assert_eq!(
                recompose_gamma_v1(decomposition).expect("canonical decomposition"),
                residue
            );
            let centered = center_proof_residue_v1(residue).expect("canonical");
            assert_eq!(proof_residue_from_centered_v1(centered), residue);
        }
    }
    #[test]
    fn malformed_decompositions_corrections_hints_and_residues_fail_closed() {
        assert_eq!(
            recompose_gamma_v1(GammaDecompositionV1 {
                high: COMPRESSION_MODULUS_V1,
                low: 0
            }),
            Err(CompressionErrorV1::InvalidGammaHigh)
        );
        for low in [-GAMMA_HALF_V1, GAMMA_HALF_V1 + 1, i64::MIN, i64::MAX] {
            assert_eq!(
                recompose_gamma_v1(GammaDecompositionV1 { high: 0, low }),
                Err(CompressionErrorV1::InvalidGammaLow)
            );
        }
        for correction in [
            -(PROOF_MODULUS_HALF_V1 + 1),
            PROOF_MODULUS_HALF_V1 + 1,
            i64::MIN,
            i64::MAX,
        ] {
            assert_eq!(
                make_gamma_hint_v1(0, correction),
                Err(CompressionErrorV1::CorrectionOutOfRange)
            );
        }
        for hint in [
            -COMPRESSION_MODULUS_HALF_V1,
            COMPRESSION_MODULUS_HALF_V1 + 1,
        ] {
            assert_eq!(
                use_gamma_hint_v1(0, hint),
                Err(CompressionErrorV1::HintOutOfRange)
            );
        }
        for residue in [PROOF_MODULUS_V1, PROOF_MODULUS_V1 + 1, u64::MAX] {
            assert_eq!(
                gamma_decompose_v1(residue),
                Err(CompressionErrorV1::NonCanonicalResidue)
            );
            assert_eq!(
                center_proof_residue_v1(residue),
                Err(CompressionErrorV1::NonCanonicalResidue)
            );
        }
    }
}
