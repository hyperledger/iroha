//! Bounded portable Falcon-512 recursive GPV/ffSampling.
//!
//! Arithmetic is adapted from `fn-dsa-sign` 0.3.0 at commit
//! `daf14859b5aa3f8d75c42966ba7de83e6eb59997` (Unlicense).  The semantic
//! delta is an arbitrary canonical `R_512` target, returning both preimage
//! halves, portable emulated floating-point arithmetic, explicit proposal
//! exhaustion, and no signature/message codec.
mod flr;
mod poly;
mod sampler;
use super::{DEGREE, LOG_DEGREE, Preimage, Trapdoor, comm};
use zeroize::Zeroizing;
pub(super) const PREIMAGE_COEFFICIENT_SAMPLES: u32 = {
    assert!(DEGREE == (1_usize << LOG_DEGREE));
    2_u32 << LOG_DEGREE
};
pub(super) const MAX_PROPOSALS_PER_COEFFICIENT: u32 = sampler::MAX_PROPOSALS_PER_COEFFICIENT;
pub(super) const TOTAL_GAUSSIAN_PROPOSAL_BUDGET: u32 =
    PREIMAGE_COEFFICIENT_SAMPLES * MAX_PROPOSALS_PER_COEFFICIENT;
// 1 / 12289, rounded exactly as in the pinned Falcon implementation.
const INV_Q: flr::Flr = flr::Flr::scaled(6_004_310_871_091_074, -66);
pub(super) fn sample_preimage_from_seed(
    trapdoor: &Trapdoor,
    target: &[u16; DEGREE],
    seed: &[u8; 56],
) -> Option<Preimage> {
    if [
        trapdoor.f.len(),
        trapdoor.g.len(),
        trapdoor.capital_f.len(),
        trapdoor.capital_g.len(),
        trapdoor.h.len(),
    ]
    .into_iter()
    .any(|length| length != DEGREE)
    {
        return None;
    }
    if target
        .iter()
        .any(|coefficient| *coefficient >= super::MODULUS)
    {
        return None;
    }
    let mut basis = Zeroizing::new(vec![flr::Flr::ZERO; 4 * DEGREE]);
    compute_basis(
        &trapdoor.f,
        &trapdoor.g,
        &trapdoor.capital_f,
        &trapdoor.capital_g,
        &mut basis,
    );
    let mut work = Zeroizing::new(vec![flr::Flr::ZERO; 9 * DEGREE]);
    // Compute the Gram matrix G = B*adj(B), keeping b11 and b01 for the
    // target transformation. Layout: g00 | g01 | g11 | b11 | b01.
    {
        let (b00, rest) = basis.split_at(DEGREE);
        let (b01, rest) = rest.split_at(DEGREE);
        let (b10, rest) = rest.split_at(DEGREE);
        let (b11, _) = rest.split_at(DEGREE);
        let (g00, rest) = work.split_at_mut(DEGREE);
        let (g01, rest) = rest.split_at_mut(DEGREE);
        let (g11, rest) = rest.split_at_mut(DEGREE);
        let (temporary_zero, rest) = rest.split_at_mut(DEGREE);
        let (temporary_one, _) = rest.split_at_mut(DEGREE);
        g00.copy_from_slice(b00);
        poly::poly_mulownadj_fft(LOG_DEGREE, g00);
        temporary_zero.copy_from_slice(b01);
        poly::poly_mulownadj_fft(LOG_DEGREE, temporary_zero);
        poly::poly_add(LOG_DEGREE, g00, temporary_zero);
        g01.copy_from_slice(b00);
        poly::poly_muladj_fft(LOG_DEGREE, g01, b10);
        temporary_zero.copy_from_slice(b01);
        poly::poly_muladj_fft(LOG_DEGREE, temporary_zero, b11);
        poly::poly_add(LOG_DEGREE, g01, temporary_zero);
        g11.copy_from_slice(b10);
        poly::poly_mulownadj_fft(LOG_DEGREE, g11);
        temporary_zero.copy_from_slice(b11);
        poly::poly_mulownadj_fft(LOG_DEGREE, temporary_zero);
        poly::poly_add(LOG_DEGREE, g11, temporary_zero);
        temporary_zero.copy_from_slice(b11);
        temporary_one.copy_from_slice(b01);
    }
    // Convert [target, 0] to coordinates in the lattice basis.
    {
        let (_, rest) = work.split_at_mut(3 * DEGREE);
        let (b11, rest) = rest.split_at_mut(DEGREE);
        let (b01, rest) = rest.split_at_mut(DEGREE);
        let (target_zero, rest) = rest.split_at_mut(DEGREE);
        let (target_one, _) = rest.split_at_mut(DEGREE);
        for (destination, source) in target_zero.iter_mut().zip(target.iter().copied()) {
            *destination = flr::Flr::from_i32(i32::from(source));
        }
        poly::FFT(LOG_DEGREE, target_zero);
        target_one.copy_from_slice(target_zero);
        poly::poly_mul_fft(LOG_DEGREE, target_one, b01);
        poly::poly_mulconst(LOG_DEGREE, target_one, -INV_Q);
        poly::poly_mul_fft(LOG_DEGREE, target_zero, b11);
        poly::poly_mulconst(LOG_DEGREE, target_zero, INV_Q);
    }
    work.copy_within(5 * DEGREE..7 * DEGREE, 3 * DEGREE);
    let mut gaussian = sampler::Sampler::<comm::chacha::ChaCha20Prng>::new(
        LOG_DEGREE,
        seed,
        TOTAL_GAUSSIAN_PROPOSAL_BUDGET,
    );
    {
        let (g00, rest) = work.split_at_mut(DEGREE);
        let (g01, rest) = rest.split_at_mut(DEGREE);
        let (g11, rest) = rest.split_at_mut(DEGREE);
        let (target_zero, rest) = rest.split_at_mut(DEGREE);
        let (target_one, temporary) = rest.split_at_mut(DEGREE);
        if !gaussian.ffsamp_fft(target_zero, target_one, g00, g01, g11, temporary) {
            return None;
        }
    }
    // Map the sampled coordinates back to a lattice point.
    work.copy_within(3 * DEGREE..5 * DEGREE, 4 * DEGREE);
    work[..4 * DEGREE].copy_from_slice(&basis[..4 * DEGREE]);
    {
        let (b00, rest) = work.split_at_mut(DEGREE);
        let (b01, rest) = rest.split_at_mut(DEGREE);
        let (b10, rest) = rest.split_at_mut(DEGREE);
        let (b11, rest) = rest.split_at_mut(DEGREE);
        let (target_zero, rest) = rest.split_at_mut(DEGREE);
        let (target_one, rest) = rest.split_at_mut(DEGREE);
        let (temporary_x, rest) = rest.split_at_mut(DEGREE);
        let (temporary_y, _) = rest.split_at_mut(DEGREE);
        temporary_x.copy_from_slice(target_zero);
        temporary_y.copy_from_slice(target_one);
        poly::poly_mul_fft(LOG_DEGREE, temporary_x, b00);
        poly::poly_mul_fft(LOG_DEGREE, temporary_y, b10);
        poly::poly_add(LOG_DEGREE, temporary_x, temporary_y);
        temporary_y.copy_from_slice(target_zero);
        poly::poly_mul_fft(LOG_DEGREE, temporary_y, b01);
        target_zero.copy_from_slice(temporary_x);
        poly::poly_mul_fft(LOG_DEGREE, target_one, b11);
        poly::poly_add(LOG_DEGREE, target_one, temporary_y);
        poly::iFFT(LOG_DEGREE, target_zero);
        poly::iFFT(LOG_DEGREE, target_one);
    }
    let mut first = Zeroizing::new(vec![0_i16; DEGREE].into_boxed_slice());
    let mut second = Zeroizing::new(vec![0_i16; DEGREE].into_boxed_slice());
    let target_zero = &work[4 * DEGREE..5 * DEGREE];
    let target_one = &work[5 * DEGREE..6 * DEGREE];
    let mut norm_squared = 0_u64;
    for index in 0..DEGREE {
        let first_coefficient = i64::from(target[index]) - target_zero[index].rint();
        let second_coefficient = -target_one[index].rint();
        let first_coefficient = i16::try_from(first_coefficient).ok()?;
        let second_coefficient = i16::try_from(second_coefficient).ok()?;
        first[index] = first_coefficient;
        second[index] = second_coefficient;
        for coefficient in [first_coefficient, second_coefficient] {
            let coefficient = i64::from(coefficient);
            norm_squared = norm_squared.checked_add((coefficient * coefficient).cast_unsigned())?;
        }
    }
    let norm_squared = u32::try_from(norm_squared).ok()?;
    if norm_squared > super::SIGNATURE_NORM_SQUARED_BOUND {
        return None;
    }
    if !preimage_equation_holds(target, &trapdoor.h, &first, &second) {
        return None;
    }
    Some(Preimage {
        first,
        second,
        #[cfg(test)]
        norm_squared,
    })
}
pub(super) fn preimage_equation_holds(
    target: &[u16; DEGREE],
    public_key: &[u16],
    first: &[i16],
    second: &[i16],
) -> bool {
    if public_key.len() != DEGREE || first.len() != DEGREE || second.len() != DEGREE {
        return false;
    }
    let modulus = i64::from(super::MODULUS);
    let mut product = Zeroizing::new(vec![0_i64; DEGREE].into_boxed_slice());
    for (index, coefficient) in first.iter().copied().enumerate() {
        product[index] = i64::from(coefficient);
    }
    for (left_index, left) in public_key.iter().copied().enumerate() {
        for (right_index, right) in second.iter().copied().enumerate() {
            let degree = left_index + right_index;
            let (destination, sign) = if degree < DEGREE {
                (degree, 1_i64)
            } else {
                (degree - DEGREE, -1_i64)
            };
            product[destination] += sign * i64::from(left) * i64::from(right);
        }
    }
    product
        .iter()
        .copied()
        .zip(target.iter().copied())
        .all(|(actual, expected)| actual.rem_euclid(modulus) == i64::from(expected))
}
fn compute_basis(f: &[i8], g: &[i8], capital_f: &[i8], capital_g: &[i8], basis: &mut [flr::Flr]) {
    let (b00, rest) = basis.split_at_mut(DEGREE);
    let (b01, rest) = rest.split_at_mut(DEGREE);
    let (b10, rest) = rest.split_at_mut(DEGREE);
    let (b11, _) = rest.split_at_mut(DEGREE);
    poly::poly_set_small(LOG_DEGREE, b01, f);
    poly::poly_set_small(LOG_DEGREE, b00, g);
    poly::poly_set_small(LOG_DEGREE, b11, capital_f);
    poly::poly_set_small(LOG_DEGREE, b10, capital_g);
    poly::FFT(LOG_DEGREE, b01);
    poly::FFT(LOG_DEGREE, b00);
    poly::FFT(LOG_DEGREE, b11);
    poly::FFT(LOG_DEGREE, b10);
    poly::poly_neg(LOG_DEGREE, b01);
    poly::poly_neg(LOG_DEGREE, b11);
}
#[cfg(test)]
pub(super) fn sampler_exhausts_with_zero_budget_for_test(
    trapdoor: &Trapdoor,
    target: &[u16; DEGREE],
    seed: &[u8; 56],
) -> bool {
    let mut basis = Zeroizing::new(vec![flr::Flr::ZERO; 4 * DEGREE]);
    compute_basis(
        &trapdoor.f,
        &trapdoor.g,
        &trapdoor.capital_f,
        &trapdoor.capital_g,
        &mut basis,
    );
    let mut sampler = sampler::Sampler::<comm::chacha::ChaCha20Prng>::new(LOG_DEGREE, seed, 0);
    let mut t0 = vec![flr::Flr::ZERO; DEGREE];
    let mut t1 = vec![flr::Flr::ZERO; DEGREE];
    let mut g00 = vec![flr::Flr::ONE; DEGREE];
    let mut g01 = vec![flr::Flr::ZERO; DEGREE];
    let mut g11 = vec![flr::Flr::ONE; DEGREE];
    let mut temporary = vec![flr::Flr::ZERO; 4 * DEGREE];
    for (destination, source) in t0.iter_mut().zip(target.iter().copied()) {
        *destination = flr::Flr::from_i32(i32::from(source));
    }
    !sampler.ffsamp_fft(
        &mut t0,
        &mut t1,
        &mut g00,
        &mut g01,
        &mut g11,
        &mut temporary,
    )
}
