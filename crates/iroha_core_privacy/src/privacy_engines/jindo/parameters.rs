//! Frozen integer-only parameters for the revised Jindo first-release profile.
//!
//! The upstream search was run only as an external oracle. Consensus never reruns its
//! floating-point search: every prime, dimension and integer bound is compiled below.
use super::JINDO_MAX_BATCH_SIZE_V1;
use iroha_data_model::privacy::IROHA_JINDO_OUTER_COMMITMENT_RANK_V1;
/// Exact rounded-discrete-Gaussian width for `ΠAgg`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JindoGaussianWidthV1 {
    /// Aggregation mask sampled before the signed-monomial `alpha` challenge.
    AggregateMask,
}
impl JindoGaussianWidthV1 {
    /// Exact standard deviation multiplied by `2^64`.
    pub(crate) const fn sigma_q64(self) -> u128 {
        match self {
            Self::AggregateMask => 76_012_773_386_902_651_841_814_477_513_162_752,
        }
    }
    /// Integer proposal radius `ceil(14 sigma)`.
    pub(crate) const fn tail_radius(self) -> u64 {
        match self {
            Self::AggregateMask => 57_689_249_829_909_733,
        }
    }
}
/// Exact compiled Jindo parameter tuple.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct JindoParametersV1 {
    pub(crate) batch_size: usize,
    pub(crate) split: usize,
    pub(crate) rows: usize,
    pub(crate) columns: usize,
    pub(crate) slots: usize,
    pub(crate) inner_msis_rank: usize,
    pub(crate) outer_msis_rank: usize,
    pub(crate) mlwe_rank: usize,
    pub(crate) log_inner_cutoff: u32,
    pub(crate) log_outer_cutoff: u32,
    pub(crate) response_two_norm_bound: u128,
    pub(crate) decomposed_commitment_two_norm_bound: u128,
    pub(crate) challenge_l1_bound: usize,
    pub(crate) parallel_repetitions: usize,
    pub(crate) max_rejection_attempts: usize,
}
/// The only native Jindo parameter profile compiled for the first release.
pub const JINDO_PARAMETERS_V1: JindoParametersV1 = JindoParametersV1 {
    batch_size: JINDO_MAX_BATCH_SIZE_V1,
    split: 1,
    rows: 2,
    columns: 1,
    slots: 128,
    inner_msis_rank: 4,
    outer_msis_rank: IROHA_JINDO_OUTER_COMMITMENT_RANK_V1,
    mlwe_rank: 4,
    log_inner_cutoff: 43,
    log_outer_cutoff: 48,
    // Exact integers represented by the reference search's binary64 output.
    response_two_norm_bound: 26_726_985_705_641_897_984,
    decomposed_commitment_two_norm_bound: 4_811_910_842_327_350_272,
    challenge_l1_bound: 1,
    parallel_repetitions: 32,
    max_rejection_attempts: 256,
};
/// Exact number of independent signed-monomial repetitions in the hard-cut wire.
pub const JINDO_PARALLEL_REPETITIONS_V1: usize = JINDO_PARAMETERS_V1.parallel_repetitions;
/// PDF and reference-oracle provenance pinned by the closed profile.
pub const JINDO_SOURCE_PROVENANCE_V1: &[u8] = b"paper=eprint-2026-044-revision-2026-06-02;pdf-sha256=ebf0f9634b2d6a5c42e8f4810a7b9da07c3edd760cfca3d5a8159838d2bdc70e;oracle=ringo-snark@805eab27a4bc5daa01e26eee79a7e20a9394fc76;tree=9b326a6d7ca3421493a7373f7a2cf3382627b1f5;oracle-profile-sha256=88a885219c79f72cfb6a36edc7a32c4a19e81b9032c1c34a4be7e78a0a90004b;oracle-crs-kat-sha256=65921b820fda1ea47d1a75b97e216e6255cb0fa0691ce27eda0f4286a2107ca7";
/// Domain-separated, reviewable parameter manifest input.
///
/// This profile is exactly the univariate coefficient-encoding specialization. It makes no claim to
/// implement slot encoding, a general multilinear API, or dynamic parameter selection. The
/// signed-monomial set now has a complete unit-difference proof. The
/// non-interactive profile nevertheless remains unavailable until a pinned
/// qROM theorem proves that its 32 Fiat--Shamir repetitions amplify knowledge
/// soundness with a concrete loss at or above the release target.
pub const JINDO_PARAMETER_MANIFEST_V1: &[u8] = b"iroha-jindo-current-v1|paper=eprint-2026-044-current-figures-2-7|specialization=univariate-coefficient-encoding-only;no-slot-encoding;no-general-multilinear-api|field=p=3611623616^8+1,le32|split-challenge=uniform-nonzero-Fp;paper-correct-Fp-star;oracle-digit-sampler-zero-and-minus-one-boundary-corrected|ring=Zq[X]/(X^1024+1)|target-coefficients=256|batch=4-exact|split=1|rows=2|columns=1|slots=128|inner-msis-rank=4|outer-msis-rank=3|mlwe-rank=4|inner-primes=70368744067073,70368744183809|outer-primes=48591984641,48592009217|ambient-prime-oracle=7223242753|exact-split-evaluation=i128-ambient-equivalent;partial-wire=unique-balanced-inner-lift|inner-cutoff=2^43|outer-cutoff=2^48|response-two-norm-lt=26726985705641897984|decomposed-two-norm-lt=4811910842327350272|challenge=32-independent-parallel-repetitions-of-uniform-signed-monomial-from-Zmod2048;per-coordinate-cardinality=2048;l1-bound=1;all-distinct-differences-unit-in-every-compiled-RNS-factor|mask-sigma=8241321404272819/2;conservative-overprovisioned-for-l1-bound1|mask-sigma-q64=76012773386902651841814477513162752|mask-tail=14sigma|rejection-rate=6/5;integer-q256;max-attempts-per-repetition=256|rng-health=distinct-256bit-blocks|crs=shake256-domain-separated-iroha|wire=IJP3-32-round-fixed-phases-rns-packed-le;reject-IJP1-IJP2|assurance=unavailable-pending-pinned-qrom-parallel-fiat-shamir-extractor-loss-theorem";
#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy_engines::jindo::JINDO_RING_DEGREE_V1;
    #[test]
    fn frozen_shape_is_the_current_reference_profile() {
        let p = JINDO_PARAMETERS_V1;
        assert_eq!(
            (p.split, JINDO_RING_DEGREE_V1, p.rows, p.columns),
            (1, 1024, 2, 1)
        );
        assert_eq!(
            (p.slots, p.inner_msis_rank, p.outer_msis_rank, p.mlwe_rank),
            (128, 4, 3, 4)
        );
        assert_eq!((p.log_inner_cutoff, p.log_outer_cutoff), (43, 48));
        assert_eq!(p.challenge_l1_bound, 1);
        assert_eq!(p.parallel_repetitions, 32);
        assert_eq!(p.batch_size, 4);
        assert_eq!(p.split * p.rows * p.columns * p.slots, 256);
    }
    #[test]
    fn integer_gaussian_width_is_exact() {
        let width = JindoGaussianWidthV1::AggregateMask;
        assert_eq!(width.sigma_q64(), 8_241_321_404_272_819_u128 << 63);
        assert_eq!(width.tail_radius(), 57_689_249_829_909_733);
        assert!((u128::from(width.tail_radius()) << 64) >= width.sigma_q64() * 14);
    }
    #[test]
    fn source_profile_explicitly_denies_unimplemented_surfaces() {
        let manifest = core::str::from_utf8(JINDO_PARAMETER_MANIFEST_V1).unwrap();
        assert!(manifest.contains("no-slot-encoding"));
        assert!(manifest.contains("no-general-multilinear-api"));
        assert!(manifest.contains("per-coordinate-cardinality=2048"));
        assert!(manifest.contains("split-challenge=uniform-nonzero-Fp"));
        assert!(manifest.contains("exact-split-evaluation=i128-ambient-equivalent"));
        assert!(manifest.contains("partial-wire=unique-balanced-inner-lift"));
        assert!(manifest.contains("32-independent-parallel-repetitions"));
        assert!(manifest.contains("all-distinct-differences-unit"));
        assert!(manifest.contains("reject-IJP1-IJP2"));
        assert!(manifest.contains("unavailable-pending-pinned-qrom"));
        assert!(!manifest.contains("S_35"));
    }
}
