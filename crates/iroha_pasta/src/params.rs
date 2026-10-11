//! Inner-product-argument commitment parameters compatible with the vendored
//! `halo2_proofs::poly::ipa::commitment::ParamsIPA`.
//!
//! # Derivation (transparent setup)
//!
//! For `n = 2^k`:
//!
//! - `g[i] = hash_to_curve("Halo2-Parameters", [0, i as u32 little-endian])`
//!   for `i < n` (a 5-byte message);
//! - `w = hash_to_curve("Halo2-Parameters", [1])`, the blinding base;
//! - `u = hash_to_curve("Halo2-Parameters", [2])`;
//! - `g_lagrange = n^-1 * IFFT(g)`, the commitment key for evaluation-form
//!   polynomials: `g_lagrange[j] = n^-1 * sum_i omega^(-ij) * g[i]`.
//!
//! The generators come from a random oracle, so nobody knows discrete-log
//! relations between them. Verifiers must not accept generator bytes from an
//! untrusted source without checking them against this derivation or a pinned
//! digest of it; [`ParamsIpa::matches_derivation`] performs the full check.
//!
//! # Byte format
//!
//! Identical to the vendored `ParamsIPA::write`:
//! `k (u32 little-endian) || g[0..n] || g_lagrange[0..n] || w || u`, every
//! point a 32-byte compressed encoding. [`ParamsIpa::from_bytes`] is stricter
//! than the vendored reader: it rejects trailing bytes, identity points and
//! `k > MAX_K`. [`ParamsIpa::new`] enforces the same rule on the points it
//! derives (an identity generator would make commitments non-binding), so
//! every value it returns round-trips through the codec. Both report the first
//! invalid point in encoding order, at every Rayon pool size.
//!
//! # Performance
//!
//! Generator hashing runs in parallel chunks on the caller's Rayon pool. The
//! group IFFT is a decimation-in-frequency transform whose twiddle
//! multiplications run through [`crate::curve::batch_mul_vartime`] (lockstep
//! batch-affine GLV); `n^-1` is folded into the first stage. All of it is exact
//! group arithmetic, so the output is identical at any thread count.
#![allow(clippy::many_single_char_names)]

use ff::Field;
use group::{GroupEncoding, prime::PrimeCurveAffine};
use rayon::prelude::*;
use std::sync::Arc;

use crate::curve::PastaCurve;
use crate::fft::FftDomain;

/// Hash-to-curve domain prefix of the vendored parameter generation.
pub const PARAMS_DOMAIN: &str = "Halo2-Parameters";

/// Largest supported `k` (2^28 generators, about 16 GiB of affine points).
pub const MAX_K: u32 = 28;

/// Parameter generation or decoding failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParamsError {
    /// `k` is larger than [`MAX_K`].
    UnsupportedK {
        /// The requested or encoded `k`.
        k: u64,
    },
    /// The byte string has the wrong length for its `k`.
    WrongLength {
        /// The length implied by `k`.
        expected: usize,
        /// The actual length.
        actual: usize,
    },
    /// A point encoding is not canonical, not on the curve, or the identity;
    /// or the derivation produced the identity or failed to hash to the curve.
    InvalidPoint {
        /// Index of the point in encoding order (`g`, `g_lagrange`, `w`, `u`).
        index: usize,
    },
}

impl core::fmt::Display for ParamsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedK { k } => write!(f, "unsupported params size k = {k}"),
            Self::WrongLength { expected, actual } => {
                write!(f, "params encoding has {actual} bytes, expected {expected}")
            }
            Self::InvalidPoint { index } => write!(f, "invalid params point at index {index}"),
        }
    }
}

impl std::error::Error for ParamsError {}

/// IPA commitment parameters for vectors of length `2^k`.
///
/// Clones share immutable public generator tables. Derivation and decoding
/// each allocate their own tables; there is no process-wide parameter cache.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParamsIpa<C: PastaCurve> {
    k: u32,
    g: Arc<[C::AffineExt]>,
    g_lagrange: Arc<[C::AffineExt]>,
    w: C::AffineExt,
    u: C::AffineExt,
}

/// Number of bytes of the encoding for a given `k`, if it fits `usize`.
pub fn encoded_len(k: u32) -> Option<usize> {
    if k >= usize::BITS {
        return None;
    }
    let n = 1usize << k;
    n.checked_mul(64)?.checked_add(4 + 64)
}

/// The 5-byte hash-to-curve message of generator `i`.
fn generator_message(i: u32) -> [u8; 5] {
    let mut message = [0u8; 5];
    message[1..5].copy_from_slice(&i.to_le_bytes());
    message
}

/// Generator `i` (`None` if `i` does not fit `u32`, hashing fails, or the
/// result is the identity).
fn derive_generator<C: PastaCurve>(i: usize) -> Option<C> {
    let i = u32::try_from(i).ok()?;
    C::hash_to_curve(PARAMS_DOMAIN, &generator_message(i))
        .ok()
        .filter(|p| !bool::from(p.is_identity()))
}

/// Returns the values of `slots`, or the index of the first empty slot.
fn first_missing<T>(slots: Vec<Option<T>>) -> Result<Vec<T>, ParamsError> {
    if let Some(index) = slots.iter().position(Option::is_none) {
        return Err(ParamsError::InvalidPoint { index });
    }
    Ok(slots.into_iter().flatten().collect())
}

/// Index of the first identity point of `points`, if any.
fn first_identity<'a, A: PrimeCurveAffine + 'a>(
    points: impl IntoIterator<Item = &'a A>,
) -> Option<usize> {
    points.into_iter().position(|p| bool::from(p.is_identity()))
}

/// Derives `g[0..n]` in projective form, hashing in parallel chunks.
///
/// # Errors
///
/// [`ParamsError::InvalidPoint`] with the smallest failing index (independent
/// of the pool size) when a generator cannot be derived or is the identity.
fn derive_generators<C: PastaCurve>(k: u32) -> Result<Vec<C>, ParamsError> {
    let n = 1usize << k;
    let mut g: Vec<Option<C>> = vec![None; n];
    g.par_chunks_mut(1024).enumerate().for_each(|(chunk, out)| {
        for (offset, slot) in out.iter_mut().enumerate() {
            *slot = derive_generator::<C>(chunk * 1024 + offset);
        }
    });
    first_missing(g)
}

/// Computes `n^-1 * IFFT(g)` over the group (decimation in frequency).
///
/// Returns affine points in natural order.
///
/// # Errors
///
/// [`ParamsError::UnsupportedK`] when `k > MAX_K`, [`ParamsError::WrongLength`]
/// unless `g.len() == 2^k`.
pub fn lagrange_basis<C: PastaCurve>(g: &[C], k: u32) -> Result<Vec<C::AffineExt>, ParamsError> {
    let n = g.len();
    if k > MAX_K {
        return Err(ParamsError::UnsupportedK { k: u64::from(k) });
    }
    if n != 1usize << k {
        return Err(ParamsError::WrongLength {
            expected: 1usize << k,
            actual: n,
        });
    }
    let domain = FftDomain::<C::ScalarExt>::new(k)
        .map_err(|_| ParamsError::UnsupportedK { k: u64::from(k) })?;
    let n_inv = domain.n_inv();
    let omega_inv = domain.omega_inv();
    let mut a: Vec<C> = g.to_vec();
    if n == 1 {
        return Ok(vec![a[0].to_affine()]);
    }
    let mut half = n / 2;
    let mut first = true;
    while half >= 1 {
        // w_{2h} for this stage: omega_inv^(n / 2h).
        let w = omega_inv.pow_vartime([(n / (2 * half)) as u64]);
        // Butterflies: lo <- lo + hi, hi <- lo - hi.
        a.par_chunks_mut(2 * half).for_each(|blk| {
            let (lo, hi) = blk.split_at_mut(half);
            for (x, y) in lo.iter_mut().zip(hi.iter_mut()) {
                let sum = *x + *y;
                let diff = *x - *y;
                *x = sum;
                *y = diff;
            }
        });
        // Twiddles: hi[j] *= w^j (and every element *= n^-1 in the first stage).
        let mut positions = Vec::new();
        let mut scalars = Vec::new();
        let twiddles: Vec<C::ScalarExt> = {
            let mut t = Vec::with_capacity(half);
            let mut cur = C::ScalarExt::ONE;
            for _ in 0..half {
                t.push(cur);
                cur *= w;
            }
            t
        };
        for blk in 0..n / (2 * half) {
            let base = blk * 2 * half;
            for (j, tw) in twiddles.iter().enumerate() {
                if first {
                    positions.push(base + j);
                    scalars.push(n_inv);
                    positions.push(base + half + j);
                    scalars.push(*tw * n_inv);
                } else if j != 0 {
                    positions.push(base + half + j);
                    scalars.push(*tw);
                }
            }
        }
        if !positions.is_empty() {
            let gathered: Vec<C> = positions.iter().map(|&p| a[p]).collect();
            let affine = crate::curve::batch_normalize_vartime(&gathered);
            let products =
                crate::curve::batch_mul_vartime::<C>(&affine, &scalars).map_err(|e| {
                    ParamsError::WrongLength {
                        expected: e.left,
                        actual: e.right,
                    }
                })?;
            for (&p, r) in positions.iter().zip(products.iter()) {
                a[p] = r.to_curve();
            }
        }
        first = false;
        half /= 2;
    }
    // Undo the bit-reversed order of the DIF output.
    let shift = usize::BITS - k;
    for i in 0..n {
        let r = i.reverse_bits() >> shift;
        if i < r {
            a.swap(i, r);
        }
    }
    Ok(crate::curve::batch_normalize_vartime(&a))
}

impl<C: PastaCurve> ParamsIpa<C> {
    /// Derives the parameters for `2^k` generators on the caller's Rayon pool.
    ///
    /// # Errors
    ///
    /// [`ParamsError::UnsupportedK`] when `k > MAX_K`.
    pub fn new(k: u32) -> Result<Self, ParamsError> {
        if k > MAX_K {
            return Err(ParamsError::UnsupportedK { k: u64::from(k) });
        }
        let n = 1usize << k;
        let g_projective = derive_generators::<C>(k)?;
        let g = crate::curve::batch_normalize_vartime(&g_projective);
        let g_lagrange = lagrange_basis(&g_projective, k)?;
        let hash = |m: &[u8], index: usize| {
            C::hash_to_curve(PARAMS_DOMAIN, m)
                .map(|p| p.to_affine())
                .map_err(|_| ParamsError::InvalidPoint { index })
        };
        let w = hash(&[1], 2 * n)?;
        let u = hash(&[2], 2 * n + 1)?;
        // `from_bytes` rejects identity points; so does derivation.
        if let Some(index) = first_identity(g.iter().chain(&g_lagrange).chain([&w, &u])) {
            return Err(ParamsError::InvalidPoint { index });
        }
        Ok(Self {
            k,
            g: g.into(),
            g_lagrange: g_lagrange.into(),
            w,
            u,
        })
    }

    /// `log2` of the number of generators.
    pub fn k(&self) -> u32 {
        self.k
    }

    /// The number of generators `n = 2^k`.
    pub fn n(&self) -> usize {
        self.g.len()
    }

    /// Commitment key for coefficient-form polynomials.
    pub fn g(&self) -> &[C::AffineExt] {
        &self.g
    }

    /// Commitment key for evaluation-form polynomials.
    pub fn g_lagrange(&self) -> &[C::AffineExt] {
        &self.g_lagrange
    }

    /// The blinding base `w`.
    pub fn w(&self) -> C::AffineExt {
        self.w
    }

    /// The inner-product base `u`.
    pub fn u(&self) -> C::AffineExt {
        self.u
    }

    /// Writes the vendored byte format to `writer`.
    ///
    /// # Errors
    ///
    /// Propagates I/O errors of `writer`.
    pub fn write<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.k.to_le_bytes())?;
        for p in self.g.iter().chain(self.g_lagrange.iter()) {
            writer.write_all(&p.to_bytes())?;
        }
        writer.write_all(&self.w.to_bytes())?;
        writer.write_all(&self.u.to_bytes())
    }

    /// Returns the vendored byte format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(encoded_len(self.k).unwrap_or(0));
        // Writing to a Vec cannot fail.
        let _ = self.write(&mut out);
        out
    }

    /// Decodes parameters strictly: exact length, `k <= MAX_K`, canonical
    /// non-identity points.
    ///
    /// Decoding does not prove the points were derived honestly; see
    /// [`Self::matches_derivation`].
    ///
    /// # Errors
    ///
    /// See [`ParamsError`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ParamsError> {
        let Some(k_bytes) = bytes.get(..4) else {
            return Err(ParamsError::WrongLength {
                expected: 4,
                actual: bytes.len(),
            });
        };
        let mut kb = [0u8; 4];
        kb.copy_from_slice(k_bytes);
        let k = u32::from_le_bytes(kb);
        if k > MAX_K {
            return Err(ParamsError::UnsupportedK { k: u64::from(k) });
        }
        let expected =
            encoded_len(k).ok_or_else(|| ParamsError::UnsupportedK { k: u64::from(k) })?;
        if bytes.len() != expected {
            return Err(ParamsError::WrongLength {
                expected,
                actual: bytes.len(),
            });
        }
        let n = 1usize << k;
        // Decode in parallel, then report the first invalid point sequentially:
        // a parallel `collect::<Result<_, _>>` may return any of several
        // errors, which would make the reported index depend on scheduling.
        let decoded: Vec<Option<C::AffineExt>> = bytes[4..]
            .par_chunks_exact(32)
            .map(|chunk| {
                let mut repr = [0u8; 32];
                repr.copy_from_slice(chunk);
                Option::<C::AffineExt>::from(C::AffineExt::from_bytes(&repr))
                    .filter(|p| !bool::from(p.is_identity()))
            })
            .collect();
        let mut points = first_missing(decoded)?.into_iter();
        let g: Vec<_> = points.by_ref().take(n).collect();
        let g_lagrange: Vec<_> = points.by_ref().take(n).collect();
        let w = points
            .next()
            .ok_or(ParamsError::InvalidPoint { index: 2 * n })?;
        let u = points
            .next()
            .ok_or(ParamsError::InvalidPoint { index: 2 * n + 1 })?;
        Ok(Self {
            k,
            g: g.into(),
            g_lagrange: g_lagrange.into(),
            w,
            u,
        })
    }

    /// Recomputes every point from the transparent derivation and compares.
    ///
    /// Costs as much as [`Self::new`].
    pub fn matches_derivation(&self) -> bool {
        Self::new(self.k).is_ok_and(|fresh| fresh == *self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::{Ep, Eq};
    use ff::PrimeField;
    use group::{Curve, Group};

    /// Returns the vendored-compatible omega for `k` (the generator of the
    /// order-`2^k` subgroup used by the group IFFT).
    fn omega_for<C: PastaCurve>(k: u32) -> Option<C::ScalarExt> {
        if k > <C::ScalarExt as PrimeField>::S {
            return None;
        }
        let mut omega = C::ScalarExt::ROOT_OF_UNITY;
        for _ in k..<C::ScalarExt as PrimeField>::S {
            omega = omega.square();
        }
        Some(omega)
    }

    #[test]
    fn lagrange_basis_matches_naive_group_dft() {
        for k in 0..=4u32 {
            let g = derive_generators::<Eq>(k).unwrap();
            let fast = lagrange_basis(&g, k).unwrap();
            let n = 1usize << k;
            let omega_inv = omega_for::<Eq>(k).unwrap().invert().unwrap();
            let n_inv = crate::Fp::from(n as u64).invert().unwrap();
            for (j, got) in fast.iter().enumerate() {
                let mut acc = Eq::identity();
                for (i, gi) in g.iter().enumerate() {
                    acc += gi.mul_vartime(&omega_inv.pow_vartime([(i * j) as u64]));
                }
                assert_eq!(*got, (acc * n_inv).to_affine(), "k = {k}, j = {j}");
            }
        }
    }

    #[test]
    fn codec_round_trip_and_strictness() {
        let p = ParamsIpa::<Ep>::new(3).unwrap();
        assert_eq!(p.k(), 3);
        assert_eq!(p.n(), 8);
        assert!(
            p.g()
                .iter()
                .chain(p.g_lagrange())
                .all(|q| !bool::from(q.is_identity()))
        );
        let bytes = p.to_bytes();
        assert_eq!(bytes.len(), encoded_len(3).unwrap());
        assert_eq!(ParamsIpa::<Ep>::from_bytes(&bytes).unwrap(), p);
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(matches!(
            ParamsIpa::<Ep>::from_bytes(&longer),
            Err(ParamsError::WrongLength { .. })
        ));
        let mut bad = bytes.clone();
        bad[4..36].copy_from_slice(&[0u8; 32]);
        assert_eq!(
            ParamsIpa::<Ep>::from_bytes(&bad),
            Err(ParamsError::InvalidPoint { index: 0 })
        );
        let mut big_k = bytes.clone();
        big_k[..4].copy_from_slice(&40u32.to_le_bytes());
        assert_eq!(
            ParamsIpa::<Ep>::from_bytes(&big_k),
            Err(ParamsError::UnsupportedK { k: 40 })
        );
        assert!(ParamsIpa::<Ep>::from_bytes(&[1, 2]).is_err());
        assert!(p.matches_derivation());
        assert_eq!(
            ParamsIpa::<Ep>::new(MAX_K + 1).unwrap_err(),
            ParamsError::UnsupportedK {
                k: u64::from(MAX_K + 1)
            }
        );
        assert_eq!(
            ParamsError::InvalidPoint { index: 3 }.to_string(),
            "invalid params point at index 3"
        );
        assert_eq!(generator_message(0x0102_0304), [0, 4, 3, 2, 1]);
        assert_ne!(p.w(), p.u());
    }

    fn shared_tables_preserve_codec<C: PastaCurve>() {
        let original = ParamsIpa::<C>::new(3).unwrap();
        let encoded = original.to_bytes();
        let clone = original.clone();
        assert!(Arc::ptr_eq(&original.g, &clone.g));
        assert!(Arc::ptr_eq(&original.g_lagrange, &clone.g_lagrange));
        assert_eq!(Arc::strong_count(&original.g), 2);
        assert_eq!(Arc::strong_count(&original.g_lagrange), 2);
        assert_eq!(clone.to_bytes(), encoded);
        drop(original);
        assert_eq!(Arc::strong_count(&clone.g), 1);
        assert_eq!(Arc::strong_count(&clone.g_lagrange), 1);
        assert_eq!(clone.to_bytes(), encoded);

        // Decoding remains independent of existing owners and does not intern
        // attacker-supplied points. Only an explicit clone shares its tables.
        let decoded = ParamsIpa::<C>::from_bytes(&encoded).unwrap();
        assert_eq!(decoded, clone);
        assert!(!Arc::ptr_eq(&decoded.g, &clone.g));
        assert!(!Arc::ptr_eq(&decoded.g_lagrange, &clone.g_lagrange));
        let decoded_clone = decoded.clone();
        assert!(Arc::ptr_eq(&decoded.g, &decoded_clone.g));
        assert!(Arc::ptr_eq(&decoded.g_lagrange, &decoded_clone.g_lagrange));
        drop(decoded);
        assert_eq!(decoded_clone.to_bytes(), encoded);

        for index in 0..2 * clone.n() + 2 {
            for point in [[0; 32], [0xff; 32]] {
                let mut malformed = encoded.clone();
                let offset = 4 + 32 * index;
                malformed[offset..offset + 32].copy_from_slice(&point);
                assert_eq!(
                    ParamsIpa::<C>::from_bytes(&malformed),
                    Err(ParamsError::InvalidPoint { index })
                );
            }
        }
        for length in [0, 3, encoded.len() - 1, encoded.len() + 1] {
            let mut malformed = encoded.clone();
            malformed.resize(length, 0);
            assert_eq!(
                ParamsIpa::<C>::from_bytes(&malformed),
                Err(ParamsError::WrongLength {
                    expected: if length < 4 { 4 } else { encoded.len() },
                    actual: length,
                })
            );
        }
        let mut malformed = encoded.clone();
        malformed[..4].copy_from_slice(&(MAX_K + 1).to_le_bytes());
        assert_eq!(
            ParamsIpa::<C>::from_bytes(&malformed),
            Err(ParamsError::UnsupportedK {
                k: u64::from(MAX_K + 1)
            })
        );
        // Failed decodes cannot mutate either retained table or its encoding.
        assert_eq!(clone.to_bytes(), encoded);
        assert_eq!(decoded_clone.to_bytes(), encoded);
    }

    #[test]
    fn pallas_clones_share_immutable_tables_and_preserve_strict_codec() {
        shared_tables_preserve_codec::<Ep>();
    }

    #[test]
    fn vesta_clones_share_immutable_tables_and_preserve_strict_codec() {
        shared_tables_preserve_codec::<Eq>();
    }

    #[test]
    fn decoding_reports_the_first_invalid_point_on_every_pool() {
        let p = ParamsIpa::<Eq>::new(6).unwrap();
        let mut bad = p.to_bytes();
        let n = p.n();
        // Corrupt points 5, n + 1 and u: an identity, an off-curve x and a
        // non-canonical x.
        let at = |index: usize| 4 + 32 * index;
        bad[at(5)..at(5) + 32].copy_from_slice(&[0u8; 32]);
        // The smallest x >= 1 without a curve point.
        let mut x = [0u8; 32];
        x[0] = 1;
        while bool::from(<Eq as GroupEncoding>::from_bytes(&x).is_some()) {
            x[0] += 1;
        }
        bad[at(n + 1)..at(n + 1) + 32].copy_from_slice(&x);
        bad[at(2 * n + 1)..at(2 * n + 1) + 32].copy_from_slice(&[0xFF; 32]);
        for threads in [1usize, 2, 4, 7] {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .unwrap();
            assert_eq!(
                pool.install(|| ParamsIpa::<Eq>::from_bytes(&bad)),
                Err(ParamsError::InvalidPoint { index: 5 }),
                "threads = {threads}"
            );
        }
        bad[at(5)..at(5) + 32].copy_from_slice(&p.g()[5].to_bytes());
        assert_eq!(
            ParamsIpa::<Eq>::from_bytes(&bad),
            Err(ParamsError::InvalidPoint { index: n + 1 })
        );
    }

    #[test]
    fn derivation_rejects_identity_and_reports_indices() {
        let g = Ep::generator().to_affine();
        let id = crate::EpAffine::default();
        assert_eq!(first_identity([&g, &g, &id, &id]), Some(2));
        assert_eq!(first_identity([&g]), None);
        assert_eq!(
            first_missing(vec![Some(1), None, Some(3), None]),
            Err(ParamsError::InvalidPoint { index: 1 })
        );
        assert_eq!(first_missing(vec![Some(1), Some(2)]), Ok(vec![1, 2]));
        let derived = derive_generators::<Ep>(2).unwrap();
        for (i, p) in derived.iter().enumerate() {
            assert_eq!(Some(*p), derive_generator::<Ep>(i));
            assert!(!bool::from(p.is_identity()));
        }
        if let Ok(beyond_u32) = usize::try_from(1u64 << 32) {
            assert!(derive_generator::<Ep>(beyond_u32).is_none());
        }
        // Every derived parameter set round-trips through the strict codec.
        let p = ParamsIpa::<Ep>::new(4).unwrap();
        assert_eq!(ParamsIpa::<Ep>::from_bytes(&p.to_bytes()), Ok(p));
    }

    #[test]
    fn encoded_len_bounds() {
        assert_eq!(encoded_len(0), Some(4 + 64 + 64));
        assert_eq!(encoded_len(64), None);
        assert!(omega_for::<Eq>(40).is_none());
    }
}
