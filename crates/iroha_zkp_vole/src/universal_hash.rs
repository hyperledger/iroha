//! The linear universal hashes of FAEST v3.0: `VOLEHash` and `ZKHash` (section 4.2,
//! Figure 4.4) and the leaf hash `LeafHash` (section 5, Figure 5.3).
//!
//! # `VOLEHash`
//!
//! The seed is `r_0 || r_1 || r_2 || r_3 || s_0 || s_1 || s_2 || s_3 || t`: eight
//! `lambda`-bit field elements and a 64-bit value, `8 * lambda + 64` bits. With
//! `s_4 = ToField(t || 0^{lambda - 64})` and the first input `x_0` read as the
//! coefficients of a polynomial, highest degree first,
//! `y_j = sum_i s_j^{n - 1 - i} * x_0[i]` for `j` in `[0..5)` and the output is
//! `h_j = r_j * y_0 + y_{j + 1} + x_1[j]` for `j` in `[0..4)`.
//!
//! # `ZKHash`
//!
//! The seed is `r_0 || r_1 || s || t`, `3 * lambda + 64` bits. With `t` embedded as
//! above, `h_0` and `h_1` are the evaluations of the input polynomial at `s` and `t`
//! and the output is `r_0 * h_0 + r_1 * h_1 + x_1`.
//!
//! # `LeafHash`
//!
//! `LeafHash(uhash, (x_0, x_1)) = x_0 * uhash + x_1` in `GF(2^{3 lambda})`, where
//! the `lambda`-bit `x_0` is zero-extended.
//!
//! All three are evaluated with a fixed sequence of field operations, and the
//! incremental states are erased on drop.

use core::fmt;

use thiserror::Error;
use zeroize::Zeroize;

use crate::field::{BinaryField, FieldError, LambdaField};

/// Bytes of the 64-bit evaluation point `t` at the end of both seeds.
const POINT_BYTES: usize = 8;

/// Errors of the universal hashes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum UniversalHashError {
    /// A seed does not have the length its hash defines.
    #[error("the seed must be {expected} bytes long, got {actual}")]
    InvalidSeedLength {
        /// Defined seed length in bytes.
        expected: usize,
        /// Supplied seed length in bytes.
        actual: usize,
    },
    /// An input or output byte string does not have the length the hash defines.
    #[error("expected {expected} bytes, got {actual}")]
    InvalidLength {
        /// Defined length in bytes.
        expected: usize,
        /// Supplied length in bytes.
        actual: usize,
    },
    /// A field element could not be decoded.
    #[error(transparent)]
    Field(#[from] FieldError),
}

/// `Err(InvalidLength)` unless `actual == expected`.
fn check_length(expected: usize, actual: usize) -> Result<(), UniversalHashError> {
    if actual == expected {
        Ok(())
    } else {
        Err(UniversalHashError::InvalidLength { expected, actual })
    }
}

/// Split a seed into `count` field elements followed by the 64-bit point `t`.
fn parse_seed<F: LambdaField, const N: usize>(
    seed: &[u8],
) -> Result<([F; N], u64), UniversalHashError> {
    let expected = N * F::BYTES + POINT_BYTES;
    if seed.len() != expected {
        return Err(UniversalHashError::InvalidSeedLength {
            expected,
            actual: seed.len(),
        });
    }
    let (elements, point) = seed.split_at(N * F::BYTES);
    let mut parsed = [F::ZERO; N];
    for (slot, chunk) in parsed.iter_mut().zip(elements.chunks_exact(F::BYTES)) {
        *slot = F::from_bytes(chunk)?;
    }
    let mut word = [0u8; POINT_BYTES];
    word.copy_from_slice(point);
    let t = u64::from_le_bytes(word);
    word.zeroize();
    Ok((parsed, t))
}

/// Incremental `VOLEHash` over `GF(2^lambda)`.
///
/// Feed the elements of the first input `x_0` in order with [`Self::update`] or
/// [`Self::update_bit`], then pass the second input `x_1` to [`Self::finalize`].
/// The caller is responsible for feeding exactly `ell + d_zk - 1` elements.
#[derive(Clone)]
pub struct VoleHasher<F: LambdaField> {
    r: [F; 4],
    s: [F; 4],
    t: u64,
    y: [F; 5],
}

impl<F: LambdaField> fmt::Debug for VoleHasher<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VoleHasher").finish_non_exhaustive()
    }
}

impl<F: LambdaField> VoleHasher<F> {
    /// Seed length in bytes: `(8 * lambda + 64) / 8`.
    pub const SEED_BYTES: usize = 8 * F::BYTES + POINT_BYTES;

    /// Parse the seed `chall_1`.
    ///
    /// # Errors
    /// Returns [`UniversalHashError::InvalidSeedLength`] unless `seed` is exactly
    /// [`Self::SEED_BYTES`] long.
    pub fn new(seed: &[u8]) -> Result<Self, UniversalHashError> {
        let (mut elements, t) = parse_seed::<F, 8>(seed)?;
        let mut r = [F::ZERO; 4];
        let mut s = [F::ZERO; 4];
        r.copy_from_slice(&elements[..4]);
        s.copy_from_slice(&elements[4..]);
        elements.zeroize();
        Ok(Self {
            r,
            s,
            t,
            y: [F::ZERO; 5],
        })
    }

    /// Absorb the next element of `x_0`.
    pub fn update(&mut self, x: F) {
        let [y0, y1, y2, y3, y4] = &mut self.y;
        for (y, s) in [y0, y1, y2, y3].into_iter().zip(self.s) {
            *y = *y * s + x;
        }
        *y4 = y4.mul_u64(self.t) + x;
    }

    /// Absorb the next element of `x_0` when it is the bit `bit & 1` embedded in the
    /// field.
    pub fn update_bit(&mut self, bit: u8) {
        self.update(F::from_bit(bit));
    }

    /// Finish with the second input `x_1` and return `h_0 .. h_3`.
    pub fn finalize(&self, x1: &[F; 4]) -> [F; 4] {
        let mut h = [F::ZERO; 4];
        for (j, slot) in h.iter_mut().enumerate() {
            *slot = self.r[j] * self.y[0] + self.y[j + 1] + x1[j];
        }
        h
    }
}

impl<F: LambdaField> Drop for VoleHasher<F> {
    fn drop(&mut self) {
        self.r.zeroize();
        self.s.zeroize();
        self.t.zeroize();
        self.y.zeroize();
    }
}

/// One-shot `VOLEHash(seed, (x0, x1))`.
///
/// # Errors
/// As [`VoleHasher::new`].
pub fn vole_hash<F: LambdaField>(
    seed: &[u8],
    x0: &[F],
    x1: &[F; 4],
) -> Result<[F; 4], UniversalHashError> {
    let mut hasher = VoleHasher::<F>::new(seed)?;
    for x in x0 {
        hasher.update(*x);
    }
    Ok(hasher.finalize(x1))
}

/// Incremental `ZKHash` over `GF(2^lambda)`.
///
/// Feed the `C` elements of the first input in order with [`Self::update`], then
/// pass the masking element `x_1` to [`Self::finalize`].
#[derive(Clone)]
pub struct ZkHasher<F: LambdaField> {
    r: [F; 2],
    s: F,
    t: u64,
    h: [F; 2],
}

impl<F: LambdaField> fmt::Debug for ZkHasher<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ZkHasher").finish_non_exhaustive()
    }
}

impl<F: LambdaField> ZkHasher<F> {
    /// Seed length in bytes: `(3 * lambda + 64) / 8`.
    pub const SEED_BYTES: usize = 3 * F::BYTES + POINT_BYTES;

    /// Parse the seed `chall_2`.
    ///
    /// # Errors
    /// Returns [`UniversalHashError::InvalidSeedLength`] unless `seed` is exactly
    /// [`Self::SEED_BYTES`] long.
    pub fn new(seed: &[u8]) -> Result<Self, UniversalHashError> {
        let ([r0, r1, s], t) = parse_seed::<F, 3>(seed)?;
        Ok(Self {
            r: [r0, r1],
            s,
            t,
            h: [F::ZERO; 2],
        })
    }

    /// Absorb the next element of `x_0`.
    pub fn update(&mut self, x: F) {
        self.h[0] = self.h[0] * self.s + x;
        self.h[1] = self.h[1].mul_u64(self.t) + x;
    }

    /// Finish with the masking element `x_1` and return the hash.
    pub fn finalize(&self, x1: F) -> F {
        self.r[0] * self.h[0] + self.r[1] * self.h[1] + x1
    }
}

impl<F: LambdaField> Drop for ZkHasher<F> {
    fn drop(&mut self) {
        self.r.zeroize();
        self.s.zeroize();
        self.t.zeroize();
        self.h.zeroize();
    }
}

/// One-shot `ZKHash(seed, (x0, x1))`.
///
/// # Errors
/// As [`ZkHasher::new`].
pub fn zk_hash<F: LambdaField>(seed: &[u8], x0: &[F], x1: F) -> Result<F, UniversalHashError> {
    let mut hasher = ZkHasher::<F>::new(seed)?;
    for x in x0 {
        hasher.update(*x);
    }
    Ok(hasher.finalize(x1))
}

/// `LeafHash(uhash, (x0, x1)) = x0 * uhash + x1` in `GF(2^{3 lambda})`.
pub fn leaf_hash<F: LambdaField>(uhash: F::Tripled, x0: F, x1: F::Tripled) -> F::Tripled {
    x0.mul_tripled(uhash) + x1
}

/// `LeafHash` on byte strings: `uhash` is `3 * lambda / 8` bytes, `x` is the
/// `4 * lambda / 8` bytes `x_0 || x_1`, and `out` receives `3 * lambda / 8` bytes.
///
/// # Errors
/// Returns [`UniversalHashError::InvalidLength`] unless all three buffers have
/// exactly those lengths.
pub fn leaf_hash_bytes<F: LambdaField>(
    uhash: &[u8],
    x: &[u8],
    out: &mut [u8],
) -> Result<(), UniversalHashError> {
    let tripled = <F::Tripled as BinaryField>::BYTES;
    check_length(tripled, uhash.len())?;
    check_length(F::BYTES + tripled, x.len())?;
    check_length(tripled, out.len())?;
    let (x0, x1) = x.split_at(F::BYTES);
    let mut key = F::Tripled::from_bytes(uhash)?;
    let mut x0 = F::from_bytes(x0)?;
    let mut x1 = F::Tripled::from_bytes(x1)?;
    let mut h = leaf_hash::<F>(key, x0, x1);
    let written = h.write_bytes(out);
    key.zeroize();
    x0.zeroize();
    x1.zeroize();
    h.zeroize();
    written?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::{Gf128, Gf192, Gf256};

    struct Counter(u8);

    impl Counter {
        fn bytes(&mut self, len: usize) -> Vec<u8> {
            (0..len)
                .map(|_| {
                    self.0 = self.0.wrapping_mul(73).wrapping_add(41);
                    self.0
                })
                .collect()
        }

        fn element<F: BinaryField>(&mut self) -> F {
            F::from_bytes(&self.bytes(F::BYTES)).expect("exact length")
        }
    }

    fn pow<F: BinaryField>(base: F, exponent: usize) -> F {
        (0..exponent).fold(F::ONE, |acc, _| acc * base)
    }

    fn check_parse_seed<F: LambdaField>() {
        let mut rng = Counter(1);
        let seed = rng.bytes(3 * F::BYTES + 8);
        let (elements, t) = parse_seed::<F, 3>(&seed).expect("exact length");
        for (i, element) in elements.iter().enumerate() {
            assert_eq!(
                element.to_bytes().as_ref(),
                &seed[i * F::BYTES..(i + 1) * F::BYTES]
            );
        }
        assert_eq!(t.to_le_bytes(), seed[3 * F::BYTES..]);
        assert_eq!(
            parse_seed::<F, 3>(&seed[1..]).map(|_| ()),
            Err(UniversalHashError::InvalidSeedLength {
                expected: seed.len(),
                actual: seed.len() - 1
            })
        );
    }

    #[test]
    fn seeds_split_into_elements_then_the_64_bit_point() {
        check_parse_seed::<Gf128>();
        check_parse_seed::<Gf192>();
        check_parse_seed::<Gf256>();
    }

    fn check_vole_hash<F: LambdaField>() {
        let mut rng = Counter(2);
        assert_eq!(VoleHasher::<F>::SEED_BYTES, 8 * F::BYTES + 8);
        let seed = rng.bytes(VoleHasher::<F>::SEED_BYTES);
        let x0: Vec<F> = (0..11).map(|_| rng.element()).collect();
        let x1: [F; 4] = [rng.element(), rng.element(), rng.element(), rng.element()];

        // Direct evaluation of the definition.
        let field = |i: usize| F::from_bytes(&seed[i * F::BYTES..(i + 1) * F::BYTES]).unwrap();
        let mut point = [0u8; 8];
        point.copy_from_slice(&seed[8 * F::BYTES..]);
        let s = [
            field(4),
            field(5),
            field(6),
            field(7),
            F::from_u64(u64::from_le_bytes(point)),
        ];
        let y: Vec<F> = s
            .iter()
            .map(|s| {
                x0.iter()
                    .enumerate()
                    .fold(F::ZERO, |acc, (i, x)| acc + pow(*s, x0.len() - 1 - i) * *x)
            })
            .collect();
        let expected: Vec<F> = (0..4).map(|j| field(j) * y[0] + y[j + 1] + x1[j]).collect();

        let h = vole_hash(&seed, &x0, &x1).expect("valid seed");
        assert_eq!(h.to_vec(), expected);

        // Incremental use and linearity: H(a + b) = H(a) + H(b).
        let other0: Vec<F> = (0..11).map(|_| rng.element()).collect();
        let other1: [F; 4] = [rng.element(), rng.element(), rng.element(), rng.element()];
        let sum0: Vec<F> = x0.iter().zip(&other0).map(|(a, b)| *a + *b).collect();
        let mut sum1 = x1;
        for (a, b) in sum1.iter_mut().zip(other1) {
            *a += b;
        }
        let other = vole_hash(&seed, &other0, &other1).expect("valid seed");
        let sum = vole_hash(&seed, &sum0, &sum1).expect("valid seed");
        for j in 0..4 {
            assert_eq!(sum[j], h[j] + other[j]);
        }

        // Bits are the embedded elements 0 and 1.
        let bits = [1u8, 0, 1, 1, 0];
        let mut by_bit = VoleHasher::<F>::new(&seed).expect("valid seed");
        let mut by_element = by_bit.clone();
        for bit in bits {
            by_bit.update_bit(bit);
            by_element.update(F::from_bit(bit));
        }
        assert_eq!(by_bit.finalize(&x1), by_element.finalize(&x1));

        assert_eq!(
            VoleHasher::<F>::new(&seed[1..]).map(|_| ()),
            Err(UniversalHashError::InvalidSeedLength {
                expected: seed.len(),
                actual: seed.len() - 1
            })
        );
        assert_eq!(
            vole_hash::<F>(&[], &x0, &x1),
            Err(UniversalHashError::InvalidSeedLength {
                expected: seed.len(),
                actual: 0
            })
        );
    }

    #[test]
    fn vole_hash_follows_its_definition() {
        check_vole_hash::<Gf128>();
        check_vole_hash::<Gf192>();
        check_vole_hash::<Gf256>();
    }

    fn check_zk_hash<F: LambdaField>() {
        let mut rng = Counter(3);
        assert_eq!(ZkHasher::<F>::SEED_BYTES, 3 * F::BYTES + 8);
        let seed = rng.bytes(ZkHasher::<F>::SEED_BYTES);
        let x0: Vec<F> = (0..9).map(|_| rng.element()).collect();
        let x1: F = rng.element();

        let field = |i: usize| F::from_bytes(&seed[i * F::BYTES..(i + 1) * F::BYTES]).unwrap();
        let mut point = [0u8; 8];
        point.copy_from_slice(&seed[3 * F::BYTES..]);
        let t = F::from_u64(u64::from_le_bytes(point));
        let evaluate = |at: F| {
            x0.iter()
                .enumerate()
                .fold(F::ZERO, |acc, (i, x)| acc + pow(at, x0.len() - 1 - i) * *x)
        };
        let expected = field(0) * evaluate(field(2)) + field(1) * evaluate(t) + x1;
        assert_eq!(zk_hash(&seed, &x0, x1), Ok(expected));

        let mut hasher = ZkHasher::<F>::new(&seed).expect("valid seed");
        for x in &x0 {
            hasher.update(*x);
        }
        assert_eq!(hasher.finalize(x1), expected);
        // The mask enters additively.
        assert_eq!(hasher.finalize(F::ZERO) + x1, expected);

        assert_eq!(
            ZkHasher::<F>::new(&seed[..seed.len() - 8]).map(|_| ()),
            Err(UniversalHashError::InvalidSeedLength {
                expected: seed.len(),
                actual: seed.len() - 8
            })
        );
        assert_eq!(
            zk_hash::<F>(&[0; 7], &x0, x1),
            Err(UniversalHashError::InvalidSeedLength {
                expected: seed.len(),
                actual: 7
            })
        );
    }

    #[test]
    fn zk_hash_follows_its_definition() {
        check_zk_hash::<Gf128>();
        check_zk_hash::<Gf192>();
        check_zk_hash::<Gf256>();
    }

    fn check_leaf_hash<F: LambdaField>() {
        let mut rng = Counter(4);
        let tripled = <F::Tripled as BinaryField>::BYTES;
        let uhash = rng.bytes(tripled);
        let x = rng.bytes(F::BYTES + tripled);
        let mut out = vec![0u8; tripled];
        leaf_hash_bytes::<F>(&uhash, &x, &mut out).expect("exact lengths");

        let key = F::Tripled::from_bytes(&uhash).unwrap();
        let x0 = F::from_bytes(&x[..F::BYTES]).unwrap();
        let x1 = F::Tripled::from_bytes(&x[F::BYTES..]).unwrap();
        let expected = x0.widen() * key + x1;
        assert_eq!(leaf_hash::<F>(key, x0, x1), expected);
        assert_eq!(out, expected.to_bytes().as_ref());
        // A zero x_0 leaves x_1.
        assert_eq!(leaf_hash::<F>(key, F::ZERO, x1), x1);

        let invalid =
            |expected, actual| Err(UniversalHashError::InvalidLength { expected, actual });
        assert_eq!(
            leaf_hash_bytes::<F>(&uhash[1..], &x, &mut out),
            invalid(tripled, tripled - 1)
        );
        assert_eq!(
            leaf_hash_bytes::<F>(&uhash, &x[1..], &mut out),
            invalid(F::BYTES + tripled, F::BYTES + tripled - 1)
        );
        let mut short = vec![0u8; tripled - 1];
        assert_eq!(
            leaf_hash_bytes::<F>(&uhash, &x, &mut short),
            invalid(tripled, tripled - 1)
        );
    }

    #[test]
    fn leaf_hash_follows_its_definition() {
        check_leaf_hash::<Gf128>();
        check_leaf_hash::<Gf192>();
        check_leaf_hash::<Gf256>();
    }

    #[test]
    fn length_checks_and_error_wrapping() {
        assert_eq!(check_length(3, 3), Ok(()));
        assert_eq!(
            check_length(3, 4),
            Err(UniversalHashError::InvalidLength {
                expected: 3,
                actual: 4
            })
        );
        assert_eq!(
            UniversalHashError::from(FieldError::InvalidModulus),
            UniversalHashError::Field(FieldError::InvalidModulus)
        );
        let seed = [0u8; 136];
        let vole = VoleHasher::<Gf128>::new(&seed).expect("valid seed");
        assert_eq!(format!("{vole:?}"), "VoleHasher { .. }");
        let zk = ZkHasher::<Gf128>::new(&seed[..56]).expect("valid seed");
        assert_eq!(format!("{zk:?}"), "ZkHasher { .. }");
    }
}
