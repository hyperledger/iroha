//! Bounded immutable generator-prefix sums for one trusted parameter owner.
//!
//! Entries are computed only from this owner's public monomial generators.
//! No point, digest, key, proof or source seal can populate this memo. Clones
//! share completed values; independently admitted parameters remain separate.

use std::sync::OnceLock;

use group::prime::PrimeCurveAffine;
use iroha_pasta::{PastaCurve, params::MAX_K};

use super::{IpaError, PinnedParams};

// ParamsIpa's constructors admit only k <= MAX_K. One cell per supported
// prefix bounds storage independently of callers, keys and catalogue size.
const PREFIX_COUNT: usize = MAX_K as usize + 1;

#[derive(Debug)]
pub(super) struct GeneratorPrefixSums<C: PastaCurve> {
    points: [OnceLock<C::AffineExt>; PREFIX_COUNT],
    #[cfg(test)]
    computations: [std::sync::atomic::AtomicUsize; PREFIX_COUNT],
}

impl<C: PastaCurve> Default for GeneratorPrefixSums<C> {
    fn default() -> Self {
        Self {
            points: std::array::from_fn(|_| OnceLock::new()),
            #[cfg(test)]
            computations: std::array::from_fn(|_| std::sync::atomic::AtomicUsize::new(0)),
        }
    }
}

impl<C: PastaCurve> PinnedParams<C> {
    /// Sum the first `2^source_k` monomial generators in their original order.
    ///
    /// The immutable parameter owner retains at most one computed affine point
    /// per supported prefix. Clones share this bounded memo; independently
    /// derived or decoded owners do not. Parameter identity and encoding exclude
    /// memo state. The result is public arithmetic, not a proof or source grant.
    /// Callers retain their own profile and nonidentity checks.
    ///
    /// # Errors
    /// [`IpaError::ParamsTooSmall`] if this owner lacks the requested prefix.
    pub fn generator_prefix_sum(&self, source_k: u32) -> Result<C::AffineExt, IpaError> {
        self.require_k(source_k)?;
        // Both indices are bounded by this privately constructed ParamsIpa's
        // k <= MAX_K (28), including on the supported 32-bit mobile target.
        let cell = &self.generator_prefix_sums.points[source_k as usize];
        Ok(*cell.get_or_init(|| {
            #[cfg(test)]
            self.generator_prefix_sums.computations[source_k as usize]
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.params().g()[..1_usize << source_k]
                .iter()
                .fold(C::identity(), |sum, point| sum + point.to_curve())
                .to_affine()
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Barrier, atomic::Ordering};

    use group::GroupEncoding;
    use iroha_pasta::{Ep, Eq};

    use super::*;

    fn serial<C: PastaCurve>(params: &PinnedParams<C>, source_k: u32) -> C::AffineExt {
        params.params().g()[..1_usize << source_k]
            .iter()
            .fold(C::identity(), |sum, point| sum + point.to_curve())
            .to_affine()
    }

    fn parity<C: PastaCurve>(params: PinnedParams<C>, prefixes: &[u32]) {
        let bytes = params.params().to_bytes();
        let digest = params.digest();
        let independent = PinnedParams::<C>::from_bytes(&bytes).unwrap();
        assert!(!Arc::ptr_eq(
            &params.generator_prefix_sums,
            &independent.generator_prefix_sums
        ));
        let clone = params.clone();
        assert!(Arc::ptr_eq(
            &params.generator_prefix_sums,
            &clone.generator_prefix_sums
        ));
        for &k in prefixes {
            let expected = serial(&params, k);
            let actual = params.generator_prefix_sum(k).unwrap();
            assert_eq!(actual, expected);
            assert_eq!(actual.to_bytes(), expected.to_bytes());
            assert_eq!(clone.generator_prefix_sum(k).unwrap(), actual);
            assert_eq!(
                params.generator_prefix_sums.computations[k as usize].load(Ordering::Relaxed),
                1
            );
            assert_eq!(
                independent.generator_prefix_sums.computations[k as usize].load(Ordering::Relaxed),
                0
            );
        }
        assert_eq!(
            params, independent,
            "runtime memo is not parameter identity"
        );
        assert_eq!(params.params().to_bytes(), bytes);
        assert_eq!(clone.params().to_bytes(), bytes);
        assert_eq!(params.digest(), digest);
        assert_eq!(params.generator_prefix_sums.points.len(), PREFIX_COUNT);
    }

    #[test]
    fn all_small_prefixes_match_original_serial_sum_and_encoding_on_both_curves() {
        // These domains have native pinned representations, so independent
        // decode above also checks that memo population does not alter bytes.
        let prefixes: Vec<_> = (0..=6).collect();
        parity(PinnedParams::<Ep>::derive(6).unwrap(), &prefixes);
        parity(PinnedParams::<Eq>::derive(6).unwrap(), &prefixes);
    }

    #[test]
    fn wallet_prefixes_match_original_serial_sum_and_encoding_on_both_curves() {
        parity(PinnedParams::<Ep>::for_domain(16).unwrap(), &[12, 14, 16]);
        parity(PinnedParams::<Eq>::for_domain(16).unwrap(), &[12, 14, 16]);
    }

    fn bounds<C: PastaCurve>() {
        let params = PinnedParams::<C>::derive(3).unwrap();
        for k in [4, 16, MAX_K + 1, u32::MAX] {
            assert_eq!(
                params.generator_prefix_sum(k),
                Err(IpaError::ParamsTooSmall {
                    needed: k,
                    available: 3
                })
            );
        }
        assert!(
            params
                .generator_prefix_sums
                .points
                .iter()
                .all(|point| point.get().is_none())
        );
        assert_eq!(
            params.generator_prefix_sum(0).unwrap(),
            params.params().g()[0]
        );
        assert_eq!(params.generator_prefix_sum(3).unwrap(), serial(&params, 3));
    }

    #[test]
    fn out_of_range_prefixes_fail_before_indexing_or_populating_on_both_curves() {
        bounds::<Ep>();
        bounds::<Eq>();
    }

    fn concurrent<C: PastaCurve>() {
        let params = PinnedParams::<C>::derive(6).unwrap();
        let barrier = Arc::new(Barrier::new(8));
        std::thread::scope(|scope| {
            let workers: Vec<_> = (0..8)
                .map(|_| {
                    let cloned = params.clone();
                    let barrier = Arc::clone(&barrier);
                    scope.spawn(move || {
                        barrier.wait();
                        (
                            cloned.generator_prefix_sum(6).unwrap(),
                            cloned.generator_prefix_sum(3).unwrap(),
                        )
                    })
                })
                .collect();
            let expected = (serial(&params, 6), serial(&params, 3));
            for worker in workers {
                assert_eq!(worker.join().unwrap(), expected);
            }
        });
        for k in [3_usize, 6] {
            assert_eq!(
                params.generator_prefix_sums.computations[k].load(Ordering::Relaxed),
                1,
                "each shared cell performs the actual sum once across concurrent clones"
            );
        }
        let independent = PinnedParams::<C>::derive(6).unwrap();
        assert!(
            independent
                .generator_prefix_sums
                .points
                .iter()
                .all(|point| point.get().is_none())
        );
        assert_eq!(
            independent.generator_prefix_sum(6).unwrap(),
            params.generator_prefix_sum(6).unwrap()
        );
        assert_eq!(
            independent.generator_prefix_sums.computations[6].load(Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn concurrent_clones_share_only_computed_owner_bound_prefixes() {
        concurrent::<Ep>();
        concurrent::<Eq>();
    }
}
