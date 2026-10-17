//! Bounded portable Falcon-512 NTRU key generation.
//!
//! Arithmetic is adapted from `fn-dsa-kgen` 0.3.0 at commit
//! `daf14859b5aa3f8d75c42966ba7de83e6eb59997` (Unlicense).  The semantic
//! delta is an explicit candidate cap, a bounded parity sampler, raw secret
//! polynomial output, and mandatory NTRU/public-key self-checks.
mod fxp;
mod gauss;
mod mp31;
mod ntru;
mod poly;
mod vect;
mod zint31;
use super::{DEGREE, LOG_DEGREE, MODULUS, Trapdoor, comm};
use comm::PRNG as _;
use zeroize::{Zeroize, Zeroizing};
pub(super) const MAX_PARITY_ATTEMPTS_PER_POLYNOMIAL: u32 = 128;
struct Workspace {
    residues: Vec<u16>,
    integers: Vec<u32>,
    fixed_points: Vec<fxp::Fxr>,
}
impl Workspace {
    fn new() -> Self {
        Self {
            residues: vec![0; 2 * DEGREE],
            integers: vec![0; 6 * DEGREE],
            fixed_points: vec![fxp::Fxr::ZERO; 5 * DEGREE / 2],
        }
    }
}
impl Drop for Workspace {
    fn drop(&mut self) {
        self.residues.zeroize();
        self.integers.zeroize();
        self.fixed_points.zeroize();
    }
}
pub(super) fn generate_from_seed(seed: &[u8], max_candidates: u32) -> Option<Trapdoor> {
    if max_candidates == 0 {
        return None;
    }
    let mut workspace = Workspace::new();
    let mut f = Zeroizing::new(vec![0_i8; DEGREE].into_boxed_slice());
    let mut g = Zeroizing::new(vec![0_i8; DEGREE].into_boxed_slice());
    let mut capital_f = Zeroizing::new(vec![0_i8; DEGREE].into_boxed_slice());
    let mut capital_g = Zeroizing::new(vec![0_i8; DEGREE].into_boxed_slice());
    let mut h = Zeroizing::new(vec![0_u16; DEGREE].into_boxed_slice());
    let mut generator = comm::shake::SHAKE256_PRNG::new(seed);
    for _ in 0..max_candidates {
        if !gauss::sample_f_bounded(
            LOG_DEGREE,
            &mut generator,
            &mut f,
            MAX_PARITY_ATTEMPTS_PER_POLYNOMIAL,
        ) || !gauss::sample_f_bounded(
            LOG_DEGREE,
            &mut generator,
            &mut g,
            MAX_PARITY_ATTEMPTS_PER_POLYNOMIAL,
        ) {
            continue;
        }
        let squared_norm = f
            .iter()
            .copied()
            .zip(g.iter().copied())
            .map(|(left, right)| {
                let left = i32::from(left);
                let right = i32::from(right);
                left * left + right * right
            })
            .sum::<i32>();
        if squared_norm >= 16_823 {
            continue;
        }
        if !comm::mq::mqpoly_small_is_invertible(LOG_DEGREE, &f, &mut workspace.residues[..DEGREE])
        {
            continue;
        }
        if !ntru::check_ortho_norm(LOG_DEGREE, &f, &g, &mut workspace.fixed_points) {
            continue;
        }
        if !ntru::solve_NTRU(
            LOG_DEGREE,
            &f,
            &g,
            &mut capital_f,
            &mut capital_g,
            &mut workspace.integers,
            &mut workspace.fixed_points,
        ) {
            continue;
        }
        let (division_temporary, _) = workspace.residues.split_at_mut(DEGREE);
        comm::mq::mqpoly_div_small(LOG_DEGREE, &f, &g, &mut h, division_temporary);
        if ntru_equation_holds(
            f.as_ref(),
            g.as_ref(),
            capital_f.as_ref(),
            capital_g.as_ref(),
        ) && public_key_equation_holds(f.as_ref(), g.as_ref(), h.as_ref())
        {
            return Some(Trapdoor {
                f,
                g,
                capital_f,
                capital_g,
                h,
            });
        }
    }
    None
}
fn ntru_equation_holds(f: &[i8], g: &[i8], capital_f: &[i8], capital_g: &[i8]) -> bool {
    let mut equation = Zeroizing::new(vec![0_i64; DEGREE].into_boxed_slice());
    negacyclic_accumulate_i8(equation.as_mut(), f, capital_g, 1);
    negacyclic_accumulate_i8(equation.as_mut(), g, capital_f, -1);
    equation[0] == i64::from(MODULUS) && equation[1..].iter().all(|value| *value == 0)
}
fn public_key_equation_holds(f: &[i8], g: &[i8], h: &[u16]) -> bool {
    let modulus = i64::from(MODULUS);
    let mut product = Zeroizing::new(vec![0_i64; DEGREE].into_boxed_slice());
    for (left_index, left) in f.iter().copied().enumerate() {
        for (right_index, right) in h.iter().copied().enumerate() {
            let degree = left_index + right_index;
            let (destination, sign) = if degree < DEGREE {
                (degree, 1_i64)
            } else {
                (degree - DEGREE, -1_i64)
            };
            product[destination] += sign * i64::from(left) * i64::from(right);
        }
    }
    for destination in 0..DEGREE {
        if product[destination].rem_euclid(modulus) != i64::from(g[destination]).rem_euclid(modulus)
        {
            return false;
        }
    }
    true
}
fn negacyclic_accumulate_i8(output: &mut [i64], left: &[i8], right: &[i8], outer_sign: i64) {
    for (left_index, left) in left.iter().copied().enumerate() {
        for (right_index, right) in right.iter().copied().enumerate() {
            let degree = left_index + right_index;
            let (destination, wrap_sign) = if degree < DEGREE {
                (degree, 1_i64)
            } else {
                (degree - DEGREE, -1_i64)
            };
            output[destination] += outer_sign * wrap_sign * i64::from(left) * i64::from(right);
        }
    }
}
