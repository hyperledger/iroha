//! Typed parameter sets, their canonical identity and the pinned evaluation context.
//!
//! [`BgvParameters`] is plain public data. [`BgvProfile::new`] validates it and
//! pins everything derived from it: the transforms of every prime, the exact
//! conversion and scale-down constants of every level and digit, and the
//! public noise constants. A profile is immutable and holds no secret.
//!
//! # Parameter rules
//!
//! In validation order: `log_degree` in `2..=17`; the plaintext modulus an odd
//! prime below `2^31`; at least one main and one special prime and at most
//! [`MAX_BASIS_PRIMES`] primes in total; one root per prime; every prime an
//! odd prime below `2^62`, congruent to one modulo `2 * N * t`, distinct from
//! every earlier one, with its root a primitive `2N`-th root of unity; a digit
//! size in `1..=main primes`; and an error parameter `eta` in `1..=24`.
//!
//! # Identity
//!
//! The identity is the 32-byte BLAKE3 `derive_key` output, under the context
//! [`PROFILE_IDENTITY_CONTEXT`], of this byte string (integers little-endian):
//! scheme version `1u8`; `log_degree` as `u32`; `t` as `u64`; the main prime
//! count as `u32` followed by each prime and its root as `u64`; the same for
//! the special primes; the key-switching method tag `1u8` (hybrid RNS with
//! exact centered digit extension and congruence-preserving division) and the
//! digit size as `u32`; the secret distribution tag `1u8` (uniform ternary);
//! the encryption mask distribution tag `1u8` (uniform ternary); the error
//! distribution tag `1u8` (centered binomial) and `eta` as `u32`; and the coin
//! derivation tag `1u8` ([`super::coins`]). Keys, ciphertexts and coin streams
//! bind this identity.
use super::{BgvError, coins::MAX_ERROR_ETA, noise};
use crate::{
    constant_time::FixedModulus,
    modular,
    natural::Natural,
    ntt_plan::{NegacyclicPlan, NttPlanError},
    rns_chain::{CongruentScaleDown, ConversionTarget, MAX_BASIS_PRIMES, RnsBasis},
};
use thiserror::Error;

/// BLAKE3 `derive_key` context of a profile identity.
pub const PROFILE_IDENTITY_CONTEXT: &str = "iroha_fhe bgv v1 profile identity";

/// Smallest supported `log2` of the ring degree.
pub const MIN_LOG_DEGREE: u32 = 2;
/// Largest supported `log2` of the ring degree.
pub const MAX_LOG_DEGREE: u32 = 17;
/// Exclusive upper bound of a plaintext modulus.
pub const PLAINTEXT_MODULUS_BOUND: u64 = 1 << 31;
/// Largest generator tried when a root is derived by rule.
const ROOT_CANDIDATE_LIMIT: u64 = 1 << 16;

/// A defect of a parameter set; the first one in validation order is reported.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum ParameterDefect {
    /// `log_degree` is outside `2..=17`.
    #[error("log2 of the ring degree must be in 2..=17")]
    DegreeOutOfRange,
    /// The plaintext modulus is not an odd prime below `2^31`.
    #[error("plaintext modulus must be an odd prime below 2^31")]
    PlaintextModulus,
    /// There is no main prime.
    #[error("the main chain is empty")]
    NoMainPrime,
    /// There is no special prime.
    #[error("the special basis is empty")]
    NoSpecialPrime,
    /// Main and special primes together exceed the supported count.
    #[error("too many primes")]
    TooManyPrimes,
    /// The number of roots differs from the number of primes.
    #[error("each prime needs exactly one root")]
    RootCountMismatch,
    /// A prime is even, below three or not below `2^62`.
    #[error("prime {index} is not an odd value in [3, 2^62)")]
    PrimeOutOfRange {
        /// Index over main then special primes.
        index: usize,
    },
    /// A prime is composite.
    #[error("prime {index} is composite")]
    PrimeComposite {
        /// Index over main then special primes.
        index: usize,
    },
    /// A prime is not congruent to one modulo `2 * N * t`.
    #[error("prime {index} is not 1 modulo 2*N*t")]
    PrimeNotOneModOrder {
        /// Index over main then special primes.
        index: usize,
    },
    /// A prime repeats an earlier one.
    #[error("prime {index} repeats an earlier prime")]
    PrimeDuplicate {
        /// Index over main then special primes.
        index: usize,
    },
    /// A root is not a primitive `2N`-th root of unity modulo its prime.
    #[error("root {index} is not a primitive 2N-th root of unity")]
    RootNotPrimitive {
        /// Index over main then special primes.
        index: usize,
    },
    /// The digit size is zero or exceeds the number of main primes.
    #[error("key-switching digit size must be in 1..=main primes")]
    DigitSize,
    /// The error parameter is outside `1..=24`.
    #[error("centered binomial eta must be in 1..=24")]
    ErrorEta,
    /// Rule-based derivation found too few primes of the requested size.
    #[error("no prime of the requested size satisfies the congruence")]
    NoPrimeOfRequestedSize,
}

/// A candidate parameter set for one RAM-LFE class shape over the field of 257 elements.
///
/// A candidate is a starting point for measurement. No candidate is qualified,
/// none has a reviewed security estimate, and membership in this list
/// qualifies nothing.
///
/// # Security estimate (unreviewed)
///
/// The Lattice Estimator was run on every candidate by
/// `scripts/fhe_bgv_lattice_estimator.sage`, which checks its moduli against
/// the primes pinned in this file before it estimates. The raw output is
/// `specs/fhe_bgv_lattice_estimator_output.txt`, and
/// `specs/fhe_bgv_cost_summary.json` restates it with the attacks that did
/// not return a cost. The estimate is for plain LWE of dimension `N` with a
/// uniform ternary secret and the centered binomial error. The cheapest
/// attack that returned a cost, in bits, on the largest modulus `Q * P`:
///
/// | Candidate | BDGL16 classical | ADPS16 classical | ADPS16 quantum |
/// | --- | ---: | ---: | ---: |
/// | [`Self::AffineF257`] | 136.9 | 102.5 | 93.0 |
/// | [`Self::BoundedF257`] | 197.9 | 161.5 | 146.8 |
/// | [`Self::RefreshF257`] | 135.3 | 99.0 | 89.8 |
///
/// The design target is 128 bits classically under BDGL16. Every candidate
/// meets it under that cost model on the attacks that returned a cost; under
/// the core-SVP count of ADPS16 only the bounded candidate does. Some attacks
/// returned none: the summary lists them with their reasons, and an attack
/// without a cost is not evidence that it is expensive.
///
/// The estimate does not cover the ring structure, the circular-security
/// assumption of the published relinearization and Galois keys, keys that
/// were not sampled honestly, or side channels. It also does not change that
/// no candidate holds the maximum shape of its class when a tape is lowered
/// instruction by instruction.
// TODO(C.3): have the parameters and the estimator record reviewed before any candidate
// is selected, and decide the proposals the summary records for the candidates that fall
// short under ADPS16 (`security_estimate.lattice_estimator.proposals`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BgvCandidate {
    /// `N = 2^14`, `t = 257`, six 50-bit main primes, two 60-bit special primes.
    AffineF257,
    /// `N = 2^16`, `t = 257`, twenty-two 50-bit main primes, two 60-bit special primes.
    BoundedF257,
    /// `N = 2^16`, `t = 257`, thirty-two 50-bit main primes, two 60-bit special primes.
    ///
    /// No refresh algorithm exists for this chain; it is a size candidate only.
    // TODO(C.8, R.9): a genuine noise-reducing refresh and its chain. Until then this
    // candidate has sizes and work units but no workload it is known to support.
    RefreshF257,
}

const F257_N14_MAIN_PRIMES: [u64; 6] = [
    562_950_180_667_393,
    562_950_189_088_769,
    562_950_256_459_777,
    562_950_542_786_561,
    562_950_610_157_569,
    562_950_635_421_697,
];
const F257_N14_MAIN_ROOTS: [u64; 6] = [
    523_942_584_495_627,
    256_843_195_152_613,
    352_338_768_887_496,
    332_641_283_479_067,
    366_769_483_877_183,
    530_504_891_961_457,
];
const F257_N14_SPECIAL_PRIMES: [u64; 2] = [576_460_752_320_790_529, 576_460_752_472_375_297];
const F257_N14_SPECIAL_ROOTS: [u64; 2] = [576_160_070_421_974_625, 99_952_779_311_123_764];
const F257_N16_MAIN_PRIMES: [u64; 32] = [
    562_950_189_088_769,
    562_950_256_459_777,
    562_951_469_137_921,
    562_952_075_476_993,
    562_953_389_211_649,
    562_953_726_066_689,
    562_954_736_631_809,
    562_954_804_002_817,
    562_955_612_454_913,
    562_956_117_737_473,
    562_957_835_698_177,
    562_958_947_319_809,
    562_958_981_005_313,
    562_959_452_602_369,
    562_960_901_079_041,
    562_961_574_789_121,
    562_962_080_071_681,
    562_962_517_983_233,
    562_962_585_354_241,
    562_963_326_435_329,
    562_963_528_548_353,
    562_963_696_975_873,
    562_964_235_943_937,
    562_964_337_000_449,
    562_965_751_791_617,
    562_966_526_558_209,
    562_967_031_840_769,
    562_967_436_066_817,
    562_967_941_349_377,
    562_968_446_631_937,
    562_968_648_744_961,
    562_969_052_971_009,
];
const F257_N16_MAIN_ROOTS: [u64; 32] = [
    385_893_405_205_932,
    350_275_667_331_060,
    439_714_477_701_790,
    39_507_986_569_924,
    276_941_941_677_677,
    345_697_119_622_936,
    227_937_140_902_190,
    349_078_217_448_246,
    534_073_667_999_702,
    110_656_982_151_237,
    275_077_308_269_654,
    468_467_268_621_673,
    444_947_294_116_924,
    100_674_010_362_669,
    493_276_687_125_251,
    316_676_029_053_776,
    92_201_513_703_887,
    478_990_346_657_226,
    304_951_947_706_799,
    71_328_820_792_678,
    497_339_524_155_467,
    531_817_990_159_480,
    201_260_045_606_688,
    482_906_202_252_142,
    270_374_685_636_300,
    108_831_672_723_441,
    144_102_182_175_396,
    222_464_393_845_610,
    407_849_608_990_993,
    92_442_527_827_733,
    168_710_833_885_157,
    11_500_286_790_533,
];
const F257_N16_SPECIAL_PRIMES: [u64; 2] = [576_460_752_472_375_297, 576_460_752_573_431_809];
const F257_N16_SPECIAL_ROOTS: [u64; 2] = [295_068_110_847_664_049, 531_503_295_167_113_429];

/// Number of main primes of the bounded candidate within the shared `N = 2^16` table.
const BOUNDED_MAIN_PRIMES: usize = 22;

impl BgvCandidate {
    /// Every candidate, smallest first.
    pub const ALL: [Self; 3] = [Self::AffineF257, Self::BoundedF257, Self::RefreshF257];

    /// Stable candidate name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::AffineF257 => "bgv.f257.n14.q6x50.p2x60",
            Self::BoundedF257 => "bgv.f257.n16.q22x50.p2x60",
            Self::RefreshF257 => "bgv.f257.n16.q32x50.p2x60",
        }
    }

    /// The pinned parameter set.
    ///
    /// The primes are the first primes of their bit length congruent to one
    /// modulo `2 * N * t`, ascending, and each root is `g^((q - 1) / 2N)` for
    /// the smallest `g >= 2` that makes it primitive; a test re-derives the
    /// tables with [`BgvParameters::derive`].
    #[must_use]
    pub fn parameters(self) -> BgvParameters {
        let (log_degree, main_primes, main_roots, special_primes, special_roots) = match self {
            Self::AffineF257 => (
                14,
                F257_N14_MAIN_PRIMES.to_vec(),
                F257_N14_MAIN_ROOTS.to_vec(),
                F257_N14_SPECIAL_PRIMES.to_vec(),
                F257_N14_SPECIAL_ROOTS.to_vec(),
            ),
            Self::BoundedF257 => (
                16,
                F257_N16_MAIN_PRIMES[..BOUNDED_MAIN_PRIMES].to_vec(),
                F257_N16_MAIN_ROOTS[..BOUNDED_MAIN_PRIMES].to_vec(),
                F257_N16_SPECIAL_PRIMES.to_vec(),
                F257_N16_SPECIAL_ROOTS.to_vec(),
            ),
            Self::RefreshF257 => (
                16,
                F257_N16_MAIN_PRIMES.to_vec(),
                F257_N16_MAIN_ROOTS.to_vec(),
                F257_N16_SPECIAL_PRIMES.to_vec(),
                F257_N16_SPECIAL_ROOTS.to_vec(),
            ),
        };
        BgvParameters {
            log_degree,
            plaintext_modulus: 257,
            main_primes,
            main_roots,
            special_primes,
            special_roots,
            digit_primes: 2,
            error_eta: super::coins::ERROR_ETA,
        }
    }
}

/// A complete public parameter set.
///
/// The secret and the encryption mask are uniform ternary and the errors are
/// centered binomial with parameter [`Self::error_eta`]; key switching is
/// hybrid RNS with digits of [`Self::digit_primes`] consecutive main primes.
/// Scheme version one has no other choice for these, and each is part of the
/// identity.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BgvParameters {
    /// `log2` of the ring degree `N`.
    pub log_degree: u32,
    /// The plaintext modulus `t`.
    pub plaintext_modulus: u64,
    /// Main primes `q_0, ..., q_L`; level `l` uses the first `l + 1`.
    pub main_primes: Vec<u64>,
    /// One primitive `2N`-th root of unity per main prime.
    pub main_roots: Vec<u64>,
    /// Special primes of hybrid key switching.
    pub special_primes: Vec<u64>,
    /// One primitive `2N`-th root of unity per special prime.
    pub special_roots: Vec<u64>,
    /// Consecutive main primes per key-switching digit.
    pub digit_primes: usize,
    /// Parameter of the centered binomial error; errors lie in `[-eta, eta]`.
    pub error_eta: u32,
}

/// First `count` primes of exactly `bits` bits congruent to one modulo `step`, skipping `skip`.
fn first_primes(
    bits: u32,
    step: u64,
    count: usize,
    skip: &[u64],
) -> Result<Vec<u64>, ParameterDefect> {
    if !(3..=62).contains(&bits) || step == 0 {
        return Err(ParameterDefect::NoPrimeOfRequestedSize);
    }
    let floor = 1_u64 << (bits - 1);
    let ceiling = 1_u64 << bits;
    let mut primes = Vec::with_capacity(count);
    let mut candidate = (floor / step)
        .checked_add(1)
        .and_then(|multiple| multiple.checked_mul(step))
        .and_then(|value| value.checked_add(1))
        .ok_or(ParameterDefect::NoPrimeOfRequestedSize)?;
    while primes.len() < count {
        if candidate >= ceiling {
            return Err(ParameterDefect::NoPrimeOfRequestedSize);
        }
        if modular::is_prime_u64(candidate) && !skip.contains(&candidate) {
            primes.push(candidate);
        }
        candidate = candidate
            .checked_add(step)
            .ok_or(ParameterDefect::NoPrimeOfRequestedSize)?;
    }
    Ok(primes)
}

impl BgvParameters {
    /// Derive a parameter set by rule.
    ///
    /// Main primes are the first `main_count` primes of exactly `main_bits`
    /// bits congruent to one modulo `2 * N * t`, ascending. Special primes
    /// are the first `special_count` such primes of `special_bits` bits that
    /// are not main primes. Each root is `g^((q - 1) / 2N)` for the smallest
    /// `g >= 2` that makes it a primitive `2N`-th root. The error parameter is
    /// [`super::coins::ERROR_ETA`].
    ///
    /// # Errors
    /// [`ParameterDefect::DegreeOutOfRange`],
    /// [`ParameterDefect::PlaintextModulus`] or
    /// [`ParameterDefect::NoPrimeOfRequestedSize`]. The result is not yet
    /// validated as a profile.
    pub fn derive(
        log_degree: u32,
        plaintext_modulus: u64,
        (main_bits, main_count): (u32, usize),
        (special_bits, special_count): (u32, usize),
        digit_primes: usize,
    ) -> Result<Self, ParameterDefect> {
        if !(MIN_LOG_DEGREE..=MAX_LOG_DEGREE).contains(&log_degree) {
            return Err(ParameterDefect::DegreeOutOfRange);
        }
        if plaintext_modulus >= PLAINTEXT_MODULUS_BOUND {
            return Err(ParameterDefect::PlaintextModulus);
        }
        let order = 2_u64 << log_degree;
        let step = order
            .checked_mul(plaintext_modulus)
            .ok_or(ParameterDefect::PlaintextModulus)?;
        let main_primes = first_primes(main_bits, step, main_count, &[])?;
        let special_primes = first_primes(special_bits, step, special_count, &main_primes)?;
        let root = |prime: &u64| {
            modular::primitive_root_of_order_with_candidate_limit(
                *prime,
                order,
                ROOT_CANDIDATE_LIMIT,
            )
            .ok_or(ParameterDefect::NoPrimeOfRequestedSize)
        };
        Ok(Self {
            log_degree,
            plaintext_modulus,
            main_roots: main_primes.iter().map(root).collect::<Result<_, _>>()?,
            special_roots: special_primes.iter().map(root).collect::<Result<_, _>>()?,
            main_primes,
            special_primes,
            digit_primes,
            error_eta: super::coins::ERROR_ETA,
        })
    }

    /// The ring degree `N`; meaningful for a `log_degree` within the supported range.
    #[must_use]
    pub const fn degree(&self) -> usize {
        1_usize << self.log_degree
    }

    /// The canonical byte string the identity is derived from.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(1_u8);
        bytes.extend_from_slice(&self.log_degree.to_le_bytes());
        bytes.extend_from_slice(&self.plaintext_modulus.to_le_bytes());
        for (primes, roots) in [
            (&self.main_primes, &self.main_roots),
            (&self.special_primes, &self.special_roots),
        ] {
            // A validated parameter set has at most 64 primes; a larger count saturates.
            bytes.extend_from_slice(
                &u32::try_from(primes.len())
                    .unwrap_or(u32::MAX)
                    .to_le_bytes(),
            );
            for (index, prime) in primes.iter().enumerate() {
                bytes.extend_from_slice(&prime.to_le_bytes());
                bytes.extend_from_slice(&roots.get(index).copied().unwrap_or(0).to_le_bytes());
            }
        }
        bytes.push(1_u8);
        bytes.extend_from_slice(
            &u32::try_from(self.digit_primes)
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        bytes.push(1_u8);
        bytes.push(1_u8);
        bytes.push(1_u8);
        bytes.extend_from_slice(&self.error_eta.to_le_bytes());
        bytes.push(1_u8);
        bytes
    }

    /// Decode the canonical byte string of a parameter set.
    ///
    /// Accepts exactly the output of [`Self::canonical_bytes`]: scheme version
    /// one, every method and distribution tag one, at most
    /// [`MAX_BASIS_PRIMES`] primes in total and no trailing byte. The result
    /// is not yet validated as a profile; [`BgvProfile::new`] does that.
    ///
    /// # Errors
    /// [`BgvError::MalformedFrame`].
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, BgvError> {
        /// Take the next `N` bytes.
        fn take<const N: usize>(rest: &mut &[u8]) -> Result<[u8; N], BgvError> {
            let (head, tail) = rest
                .split_first_chunk::<N>()
                .ok_or(BgvError::MalformedFrame)?;
            *rest = tail;
            Ok(*head)
        }
        /// Take one tag byte, which must be one.
        fn tag(rest: &mut &[u8]) -> Result<(), BgvError> {
            if take::<1>(rest)? == [1] {
                Ok(())
            } else {
                Err(BgvError::MalformedFrame)
            }
        }
        /// Take a count and that many `(prime, root)` pairs; `limit` bounds the count.
        fn pairs(rest: &mut &[u8], limit: usize) -> Result<(Vec<u64>, Vec<u64>), BgvError> {
            let count = usize::try_from(u32::from_le_bytes(take(rest)?))
                .map_err(|_| BgvError::MalformedFrame)?;
            if count > limit {
                return Err(BgvError::MalformedFrame);
            }
            let mut primes = Vec::with_capacity(count);
            let mut roots = Vec::with_capacity(count);
            for _ in 0..count {
                primes.push(u64::from_le_bytes(take(rest)?));
                roots.push(u64::from_le_bytes(take(rest)?));
            }
            Ok((primes, roots))
        }
        let mut rest = bytes;
        tag(&mut rest)?;
        let log_degree = u32::from_le_bytes(take(&mut rest)?);
        let plaintext_modulus = u64::from_le_bytes(take(&mut rest)?);
        let (main_primes, main_roots) = pairs(&mut rest, MAX_BASIS_PRIMES)?;
        let (special_primes, special_roots) =
            pairs(&mut rest, MAX_BASIS_PRIMES - main_primes.len())?;
        tag(&mut rest)?;
        let digit_primes = usize::try_from(u32::from_le_bytes(take(&mut rest)?))
            .map_err(|_| BgvError::MalformedFrame)?;
        tag(&mut rest)?;
        tag(&mut rest)?;
        tag(&mut rest)?;
        let error_eta = u32::from_le_bytes(take(&mut rest)?);
        tag(&mut rest)?;
        if !rest.is_empty() {
            return Err(BgvError::MalformedFrame);
        }
        Ok(Self {
            log_degree,
            plaintext_modulus,
            main_primes,
            main_roots,
            special_primes,
            special_roots,
            digit_primes,
            error_eta,
        })
    }

    /// The canonical 32-byte identity of the parameter set.
    #[must_use]
    pub fn identity(&self) -> [u8; 32] {
        blake3::derive_key(PROFILE_IDENTITY_CONTEXT, &self.canonical_bytes())
    }

    /// Check every parameter rule and return the first defect.
    ///
    /// # Errors
    /// The first [`ParameterDefect`] in the order of the module documentation.
    pub fn validate(&self) -> Result<(), ParameterDefect> {
        if !(MIN_LOG_DEGREE..=MAX_LOG_DEGREE).contains(&self.log_degree) {
            return Err(ParameterDefect::DegreeOutOfRange);
        }
        let plaintext = self.plaintext_modulus;
        if !(3..PLAINTEXT_MODULUS_BOUND).contains(&plaintext) || !modular::is_prime_u64(plaintext) {
            return Err(ParameterDefect::PlaintextModulus);
        }
        if self.main_primes.is_empty() {
            return Err(ParameterDefect::NoMainPrime);
        }
        if self.special_primes.is_empty() {
            return Err(ParameterDefect::NoSpecialPrime);
        }
        if self.main_primes.len() + self.special_primes.len() > MAX_BASIS_PRIMES {
            return Err(ParameterDefect::TooManyPrimes);
        }
        if self.main_roots.len() != self.main_primes.len()
            || self.special_roots.len() != self.special_primes.len()
        {
            return Err(ParameterDefect::RootCountMismatch);
        }
        let order = 2_u64 << self.log_degree;
        // `order <= 2^18` and `plaintext < 2^31`, so the product fits.
        let congruence = order * plaintext;
        let primes: Vec<u64> = self.all_primes().collect();
        for (index, (&prime, root)) in primes.iter().zip(self.all_roots()).enumerate() {
            if prime < 3 || prime.is_multiple_of(2) || prime >= crate::rns_chain::BASIS_PRIME_BOUND
            {
                return Err(ParameterDefect::PrimeOutOfRange { index });
            }
            if !modular::is_prime_u64(prime) {
                return Err(ParameterDefect::PrimeComposite { index });
            }
            if !(prime - 1).is_multiple_of(congruence) {
                return Err(ParameterDefect::PrimeNotOneModOrder { index });
            }
            if primes[..index].contains(&prime) {
                return Err(ParameterDefect::PrimeDuplicate { index });
            }
            if !modular::is_primitive_root_of_order(prime, root, order) {
                return Err(ParameterDefect::RootNotPrimitive { index });
            }
        }
        if self.digit_primes == 0 || self.digit_primes > self.main_primes.len() {
            return Err(ParameterDefect::DigitSize);
        }
        if self.error_eta == 0 || self.error_eta > MAX_ERROR_ETA {
            return Err(ParameterDefect::ErrorEta);
        }
        Ok(())
    }

    fn all_primes(&self) -> impl Iterator<Item = u64> + '_ {
        self.main_primes.iter().chain(&self.special_primes).copied()
    }

    fn all_roots(&self) -> impl Iterator<Item = u64> + '_ {
        self.main_roots.iter().chain(&self.special_roots).copied()
    }
}

/// Exact extension of one key-switching digit at one level.
#[derive(Clone, Debug)]
pub(super) struct DigitContext {
    /// Index of the first main prime of the digit.
    pub(super) first: usize,
    /// Main primes of the digit that are present at this level.
    pub(super) len: usize,
    /// The basis of those primes.
    pub(super) basis: RnsBasis,
    /// Limb indices of the extended polynomial that receive converted residues.
    pub(super) target_limbs: Vec<usize>,
    /// One conversion target per entry of `target_limbs`.
    pub(super) targets: Vec<ConversionTarget>,
}

/// Everything pinned for one level.
#[derive(Clone, Debug)]
pub(super) struct LevelContext {
    /// `(Q_l - 1) / 2`.
    pub(super) capacity: Natural,
    /// Drops `q_l`; absent at level zero.
    pub(super) drop_last: Option<CongruentScaleDown>,
    /// Divides by the special modulus.
    pub(super) drop_special: CongruentScaleDown,
    /// The basis `q_0, ..., q_l`.
    pub(super) basis: RnsBasis,
    /// Carries that basis into the plaintext modulus.
    pub(super) plaintext_target: ConversionTarget,
    /// The key-switching digits present at this level.
    pub(super) digits: Vec<DigitContext>,
    /// Public bound of the noise one key switch adds at this level.
    pub(super) key_switch_noise: Natural,
}

/// A validated parameter set with its pinned evaluation context.
#[derive(Clone, Debug)]
pub struct BgvProfile {
    parameters: BgvParameters,
    identity: [u8; 32],
    /// Transforms of the main primes followed by those of the special primes.
    plans: Vec<NegacyclicPlan>,
    plaintext: FixedModulus,
    levels: Vec<LevelContext>,
    /// `P mod q_i` for every main prime.
    special_product_mod_main: Vec<u64>,
    fresh_noise: Natural,
}

fn plan_defect(error: NttPlanError, index: usize) -> ParameterDefect {
    match error {
        NttPlanError::UnsupportedDegree => ParameterDefect::DegreeOutOfRange,
        NttPlanError::CompositeModulus => ParameterDefect::PrimeComposite { index },
        NttPlanError::RootNotPrimitive => ParameterDefect::RootNotPrimitive { index },
        NttPlanError::ModulusOutOfRange | NttPlanError::LengthMismatch { .. } => {
            ParameterDefect::PrimeOutOfRange { index }
        }
    }
}

impl BgvProfile {
    /// Validate a parameter set and pin its evaluation context.
    ///
    /// # Errors
    /// [`BgvError::InvalidParameters`] with the first defect.
    pub fn new(parameters: BgvParameters) -> Result<Self, BgvError> {
        parameters.validate()?;
        let degree = parameters.degree();
        let plaintext_modulus = parameters.plaintext_modulus;
        let plaintext =
            FixedModulus::derive(plaintext_modulus).ok_or(ParameterDefect::PlaintextModulus)?;
        let mut plans = Vec::with_capacity(parameters.main_primes.len());
        for (index, (prime, root)) in parameters
            .all_primes()
            .zip(parameters.all_roots())
            .enumerate()
        {
            plans.push(
                NegacyclicPlan::new(degree, prime, root)
                    .map_err(|error| plan_defect(error, index))?,
            );
        }
        let main = &parameters.main_primes;
        let special = &parameters.special_primes;
        let digit_primes = parameters.digit_primes;
        let error_bound = u64::from(parameters.error_eta);
        let mut levels = Vec::with_capacity(main.len());
        for level in 0..main.len() {
            let level_primes = &main[..=level];
            let basis = RnsBasis::new(level_primes)?;
            let mut digits = Vec::new();
            let mut digit_products = Vec::new();
            let mut first = 0_usize;
            while first <= level {
                let len = digit_primes.min(level + 1 - first);
                let digit_basis = RnsBasis::new(&main[first..first + len])?;
                let mut target_limbs = Vec::new();
                let mut targets = Vec::new();
                for (limb, &prime) in level_primes.iter().chain(special).enumerate() {
                    if limb <= level && (first..first + len).contains(&limb) {
                        continue;
                    }
                    target_limbs.push(limb);
                    targets.push(digit_basis.conversion_target(prime)?);
                }
                digit_products.push(digit_basis.product());
                digits.push(DigitContext {
                    first,
                    len,
                    basis: digit_basis,
                    target_limbs,
                    targets,
                });
                first += digit_primes;
            }
            let drop_last = if level == 0 {
                None
            } else {
                Some(CongruentScaleDown::new(
                    &main[..level],
                    &main[level..=level],
                    plaintext_modulus,
                )?)
            };
            levels.push(LevelContext {
                capacity: basis.half_product(),
                drop_last,
                drop_special: CongruentScaleDown::new(level_primes, special, plaintext_modulus)?,
                plaintext_target: basis.conversion_target(plaintext_modulus)?,
                basis,
                digits,
                key_switch_noise: noise::key_switch_noise(
                    degree,
                    plaintext_modulus,
                    error_bound,
                    &digit_products,
                    special,
                ),
            });
        }
        let special_product_mod_main = main
            .iter()
            .map(|&prime| {
                special.iter().fold(1_u64, |product, &factor| {
                    modular::mul_mod_u64(product, factor % prime, prime)
                })
            })
            .collect();
        Ok(Self {
            identity: parameters.identity(),
            fresh_noise: noise::fresh_noise(degree, plaintext_modulus, error_bound),
            parameters,
            plans,
            plaintext,
            levels,
            special_product_mod_main,
        })
    }

    /// Build the profile of a pinned candidate.
    ///
    /// # Errors
    /// [`BgvError::InvalidParameters`]; the pinned tables are tested to be valid.
    pub fn candidate(candidate: BgvCandidate) -> Result<Self, BgvError> {
        Self::new(candidate.parameters())
    }

    /// The parameter set.
    #[must_use]
    pub const fn parameters(&self) -> &BgvParameters {
        &self.parameters
    }

    /// The canonical identity of the parameter set.
    #[must_use]
    pub const fn identity(&self) -> &[u8; 32] {
        &self.identity
    }

    /// The ring degree `N`.
    #[must_use]
    pub const fn degree(&self) -> usize {
        self.parameters.degree()
    }

    /// The plaintext modulus `t`.
    #[must_use]
    pub const fn plaintext_modulus(&self) -> u64 {
        self.parameters.plaintext_modulus
    }

    /// The top level `L`: the index of the last main prime.
    #[must_use]
    pub fn top_level(&self) -> usize {
        self.parameters.main_primes.len() - 1
    }

    /// Number of special primes `K`.
    #[must_use]
    pub fn special_count(&self) -> usize {
        self.parameters.special_primes.len()
    }

    /// Number of key-switching digits at the top level.
    #[must_use]
    pub fn digit_count(&self) -> usize {
        self.parameters
            .main_primes
            .len()
            .div_ceil(self.parameters.digit_primes)
    }

    /// Largest magnitude of one sampled error coefficient.
    #[must_use]
    pub fn error_bound(&self) -> u64 {
        u64::from(self.parameters.error_eta)
    }

    /// The exact modulus `Q_level`.
    ///
    /// # Errors
    /// [`BgvError::LevelOutOfRange`].
    pub fn level_modulus(&self, level: usize) -> Result<Natural, BgvError> {
        Ok(self.level(level)?.basis.product())
    }

    /// The exact special modulus `P`.
    #[must_use]
    pub fn special_modulus(&self) -> Natural {
        Natural::product_of(&self.parameters.special_primes)
    }

    /// The decryption capacity `(Q_level - 1) / 2`.
    ///
    /// # Errors
    /// [`BgvError::LevelOutOfRange`].
    pub fn capacity(&self, level: usize) -> Result<&Natural, BgvError> {
        Ok(&self.level(level)?.capacity)
    }

    /// Public bound of the noise of a fresh public-key encryption.
    #[must_use]
    pub const fn fresh_noise(&self) -> &Natural {
        &self.fresh_noise
    }

    /// Public bound of the noise one key switch adds at `level`.
    ///
    /// # Errors
    /// [`BgvError::LevelOutOfRange`].
    pub fn key_switch_noise(&self, level: usize) -> Result<&Natural, BgvError> {
        Ok(&self.level(level)?.key_switch_noise)
    }

    pub(super) fn level(&self, level: usize) -> Result<&LevelContext, BgvError> {
        self.levels
            .get(level)
            .ok_or_else(|| BgvError::LevelOutOfRange {
                level,
                top: self.top_level(),
            })
    }

    /// Words of the noise bound in a canonical ciphertext frame: enough for the top capacity.
    #[must_use]
    pub fn noise_bound_words(&self) -> usize {
        self.levels
            .last()
            .map_or(0, |level| level.capacity.bit_len().div_ceil(64))
    }

    /// The transform of main prime `index`.
    pub(super) fn main_plan(&self, index: usize) -> &NegacyclicPlan {
        &self.plans[index]
    }

    /// The transform of limb `limb` over the main primes followed by the special primes.
    pub(super) fn full_plan(&self, limb: usize) -> &NegacyclicPlan {
        &self.plans[limb]
    }

    /// The transform of special prime `index`.
    pub(super) fn special_plan(&self, index: usize) -> &NegacyclicPlan {
        &self.plans[self.parameters.main_primes.len() + index]
    }

    /// The transform behind limb `limb` of a polynomial extended at `level`:
    /// main primes `0..=level`, then the special primes.
    pub(super) fn extended_plan(&self, level: usize, limb: usize) -> &NegacyclicPlan {
        if limb <= level {
            self.main_plan(limb)
        } else {
            self.special_plan(limb - level - 1)
        }
    }

    /// Branch-free arithmetic modulo the plaintext modulus.
    pub(super) const fn plaintext_fixed(&self) -> FixedModulus {
        self.plaintext
    }

    /// `P mod q_index` for a main prime.
    pub(super) fn special_product_mod_main(&self, index: usize) -> u64 {
        self.special_product_mod_main[index]
    }

    /// Number of limbs of a polynomial over every main and special prime.
    pub(super) fn full_limbs(&self) -> usize {
        self.plans.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn toy_parameters() -> BgvParameters {
        BgvParameters::derive(4, 257, (30, 3), (31, 2), 2).expect("toy parameters")
    }

    #[test]
    fn pinned_candidates_follow_the_derivation_rule_and_validate() {
        for candidate in BgvCandidate::ALL {
            let pinned = candidate.parameters();
            let derived = BgvParameters::derive(
                pinned.log_degree,
                257,
                (50, pinned.main_primes.len()),
                (60, 2),
                2,
            )
            .expect("derived");
            assert_eq!(pinned, derived, "{}", candidate.name());
            assert_eq!(pinned.validate(), Ok(()));
            assert_eq!(pinned.error_eta, 21);
        }
        assert_eq!(BgvCandidate::AffineF257.parameters().degree(), 1 << 14);
        assert_eq!(BgvCandidate::BoundedF257.parameters().main_primes.len(), 22);
        assert_eq!(BgvCandidate::RefreshF257.parameters().main_primes.len(), 32);
        let names: Vec<&str> = BgvCandidate::ALL.iter().map(|c| c.name()).collect();
        assert_eq!(
            names,
            [
                "bgv.f257.n14.q6x50.p2x60",
                "bgv.f257.n16.q22x50.p2x60",
                "bgv.f257.n16.q32x50.p2x60"
            ]
        );
    }

    #[test]
    fn identity_binds_every_parameter() {
        let base = toy_parameters();
        let identity = base.identity();
        assert_eq!(identity, toy_parameters().identity());
        let mut variants = Vec::new();
        let mut changed = base.clone();
        changed.log_degree += 1;
        variants.push(changed);
        let mut changed = base.clone();
        changed.plaintext_modulus = 769;
        variants.push(changed);
        let mut changed = base.clone();
        changed.main_primes[1] += 2;
        variants.push(changed);
        let mut changed = base.clone();
        changed.main_roots[0] += 1;
        variants.push(changed);
        let mut changed = base.clone();
        changed.special_primes.swap(0, 1);
        variants.push(changed);
        let mut changed = base.clone();
        changed.special_roots[1] += 1;
        variants.push(changed);
        let mut changed = base.clone();
        changed.digit_primes = 1;
        variants.push(changed);
        let mut changed = base.clone();
        changed.error_eta = 20;
        variants.push(changed);
        // Moving a prime from the main chain to the special basis changes the identity.
        let mut changed = base.clone();
        let prime = changed.main_primes.pop().expect("prime");
        let root = changed.main_roots.pop().expect("root");
        changed.special_primes.insert(0, prime);
        changed.special_roots.insert(0, root);
        variants.push(changed);
        for variant in variants {
            assert_ne!(variant.identity(), identity, "{variant:?}");
        }
        // The byte layout is pinned: version, log N, t, counts and pairs, tags.
        let bytes = base.canonical_bytes();
        assert_eq!(
            bytes.len(),
            1 + 4 + 8 + 4 + 3 * 16 + 4 + 2 * 16 + 1 + 4 + 3 + 4 + 1
        );
        assert_eq!(bytes[0], 1);
        assert_eq!(&bytes[1..5], &4_u32.to_le_bytes());
        assert_eq!(&bytes[5..13], &257_u64.to_le_bytes());
        assert_eq!(&bytes[13..17], &3_u32.to_le_bytes());
        assert_eq!(&bytes[17..25], &base.main_primes[0].to_le_bytes());
        assert_eq!(&bytes[25..33], &base.main_roots[0].to_le_bytes());
    }

    #[test]
    fn canonical_bytes_decode_to_the_same_parameters_and_reject_malformed_input() {
        let base = toy_parameters();
        let bytes = base.canonical_bytes();
        assert_eq!(
            BgvParameters::from_canonical_bytes(&bytes),
            Ok(base.clone())
        );
        for candidate in BgvCandidate::ALL {
            let parameters = candidate.parameters();
            let decoded = BgvParameters::from_canonical_bytes(&parameters.canonical_bytes())
                .expect("decoded");
            assert_eq!(decoded, parameters);
            assert_eq!(decoded.identity(), parameters.identity());
        }
        let malformed = Err(BgvError::MalformedFrame);
        // Every strict prefix, and one trailing byte.
        for length in 0..bytes.len() {
            assert_eq!(
                BgvParameters::from_canonical_bytes(&bytes[..length]),
                malformed,
                "length {length}"
            );
        }
        let mut longer = bytes.clone();
        longer.push(1);
        assert_eq!(BgvParameters::from_canonical_bytes(&longer), malformed);
        // The version and each of the five tags: offsets follow the documented layout.
        let after_primes = 1 + 4 + 8 + 4 + 3 * 16 + 4 + 2 * 16;
        for offset in [
            0,
            after_primes,
            after_primes + 5,
            after_primes + 6,
            after_primes + 7,
            after_primes + 12,
        ] {
            for value in [0_u8, 2] {
                let mut changed = bytes.clone();
                changed[offset] = value;
                assert_eq!(
                    BgvParameters::from_canonical_bytes(&changed),
                    malformed,
                    "offset {offset}"
                );
            }
        }
        // A count above the supported number of primes is refused before anything is read.
        let mut many = bytes.clone();
        many[13..17].copy_from_slice(&65_u32.to_le_bytes());
        assert_eq!(BgvParameters::from_canonical_bytes(&many), malformed);
        let mut many = bytes.clone();
        many[13 + 4 + 3 * 16..13 + 8 + 3 * 16].copy_from_slice(&62_u32.to_le_bytes());
        assert_eq!(BgvParameters::from_canonical_bytes(&many), malformed);
        // Decoding is structural: a changed field decodes and is then judged by validation.
        let mut changed = bytes.clone();
        changed[1..5].copy_from_slice(&1_u32.to_le_bytes());
        let decoded = BgvParameters::from_canonical_bytes(&changed).expect("decoded");
        assert_eq!(decoded.validate(), Err(ParameterDefect::DegreeOutOfRange));
    }

    #[test]
    fn validation_reports_the_first_defect() {
        let base = toy_parameters();
        let check = |mutate: &dyn Fn(&mut BgvParameters), expected: ParameterDefect| {
            let mut parameters = base.clone();
            mutate(&mut parameters);
            assert_eq!(parameters.validate(), Err(expected));
            assert_eq!(
                BgvProfile::new(parameters).err(),
                Some(BgvError::InvalidParameters(expected))
            );
        };
        check(&|p| p.log_degree = 1, ParameterDefect::DegreeOutOfRange);
        check(&|p| p.log_degree = 18, ParameterDefect::DegreeOutOfRange);
        check(
            &|p| p.plaintext_modulus = 2,
            ParameterDefect::PlaintextModulus,
        );
        check(
            &|p| p.plaintext_modulus = 255,
            ParameterDefect::PlaintextModulus,
        );
        check(
            &|p| p.plaintext_modulus = (1 << 31) + 11,
            ParameterDefect::PlaintextModulus,
        );
        check(&|p| p.main_primes.clear(), ParameterDefect::NoMainPrime);
        check(
            &|p| p.special_primes.clear(),
            ParameterDefect::NoSpecialPrime,
        );
        check(
            &|p| p.main_primes = vec![p.main_primes[0]; MAX_BASIS_PRIMES],
            ParameterDefect::TooManyPrimes,
        );
        check(
            &|p| {
                p.main_roots.pop();
            },
            ParameterDefect::RootCountMismatch,
        );
        check(
            &|p| p.special_roots.push(3),
            ParameterDefect::RootCountMismatch,
        );
        check(
            &|p| p.main_primes[1] = 1 << 62,
            ParameterDefect::PrimeOutOfRange { index: 1 },
        );
        check(
            &|p| {
                // The next composite that keeps the congruence.
                p.main_primes[0] += 2 * 16 * 257;
                while modular::is_prime_u64(p.main_primes[0]) {
                    p.main_primes[0] += 2 * 16 * 257;
                }
            },
            ParameterDefect::PrimeComposite { index: 0 },
        );
        // 12289 is prime and 1 mod 2N, but not 1 mod t.
        check(
            &|p| p.main_primes[2] = 12_289,
            ParameterDefect::PrimeNotOneModOrder { index: 2 },
        );
        check(
            &|p| {
                p.special_primes[1] = p.main_primes[0];
                p.special_roots[1] = p.main_roots[0];
            },
            ParameterDefect::PrimeDuplicate { index: 4 },
        );
        check(
            &|p| p.special_roots[0] = 1,
            ParameterDefect::RootNotPrimitive { index: 3 },
        );
        check(&|p| p.digit_primes = 0, ParameterDefect::DigitSize);
        check(&|p| p.digit_primes = 4, ParameterDefect::DigitSize);
        check(&|p| p.error_eta = 0, ParameterDefect::ErrorEta);
        check(&|p| p.error_eta = 25, ParameterDefect::ErrorEta);
    }

    #[test]
    fn derivation_follows_the_first_prime_rule() {
        let parameters = toy_parameters();
        let step = 2 * 16 * 257_u64;
        for &prime in parameters
            .main_primes
            .iter()
            .chain(&parameters.special_primes)
        {
            assert!(modular::is_prime_u64(prime));
            assert_eq!(prime % step, 1);
        }
        assert!(
            parameters
                .main_primes
                .windows(2)
                .all(|pair| pair[0] < pair[1])
        );
        assert!(parameters.main_primes.iter().all(|p| p.ilog2() == 29));
        assert!(parameters.special_primes.iter().all(|p| p.ilog2() == 30));
        // Nothing smaller of the same size satisfies the rule.
        let first = parameters.main_primes[0];
        let mut candidate = first - step;
        while candidate >= 1 << 29 {
            assert!(!modular::is_prime_u64(candidate));
            candidate -= step;
        }
        // Same-size special primes skip the main primes.
        let same = BgvParameters::derive(4, 257, (30, 2), (30, 2), 1).expect("same size");
        assert_eq!(same.special_primes[0], parameters.main_primes[2]);
        assert_eq!(same.validate(), Ok(()));
        assert_eq!(
            BgvParameters::derive(1, 257, (30, 1), (30, 1), 1),
            Err(ParameterDefect::DegreeOutOfRange)
        );
        assert_eq!(
            BgvParameters::derive(4, 1 << 31, (30, 1), (30, 1), 1),
            Err(ParameterDefect::PlaintextModulus)
        );
        assert_eq!(
            BgvParameters::derive(4, 257, (63, 1), (30, 1), 1),
            Err(ParameterDefect::NoPrimeOfRequestedSize)
        );
        // No 14-bit prime is 1 modulo 2 * 16 * 257 = 8224 (8225 = 5^2 * 7 * 47).
        assert_eq!(
            BgvParameters::derive(4, 257, (14, 1), (30, 1), 1),
            Err(ParameterDefect::NoPrimeOfRequestedSize)
        );
        assert_eq!(
            first_primes(30, 0, 1, &[]),
            Err(ParameterDefect::NoPrimeOfRequestedSize)
        );
    }

    #[test]
    fn profile_pins_levels_digits_and_public_constants() {
        let parameters = toy_parameters();
        let profile = BgvProfile::new(parameters.clone()).expect("profile");
        assert_eq!(profile.parameters(), &parameters);
        assert_eq!(profile.identity(), &parameters.identity());
        assert_eq!(profile.degree(), 16);
        assert_eq!(profile.plaintext_modulus(), 257);
        assert_eq!(profile.top_level(), 2);
        assert_eq!(profile.special_count(), 2);
        assert_eq!(profile.digit_count(), 2);
        assert_eq!(profile.error_bound(), 21);
        assert_eq!(profile.full_limbs(), 5);
        assert_eq!(profile.plaintext_fixed().modulus, 257);
        assert_eq!(
            profile.special_modulus(),
            Natural::product_of(&parameters.special_primes)
        );
        for level in 0..=2 {
            let primes = &parameters.main_primes[..=level];
            let modulus = Natural::product_of(primes);
            assert_eq!(profile.level_modulus(level), Ok(modulus.clone()));
            assert_eq!(profile.capacity(level), Ok(&modulus.half_floor()));
            let context = profile.level(level).expect("level");
            assert_eq!(context.basis.primes(), primes);
            assert_eq!(context.drop_last.is_some(), level > 0);
            assert_eq!(context.drop_special.kept_len(), level + 1);
            assert_eq!(context.drop_special.dropped_len(), 2);
            assert_eq!(context.plaintext_target.target_modulus(), 257);
            // Digits of two primes: {q0, q1}, {q2}; a partial digit shrinks with the level.
            let shapes: Vec<(usize, usize)> = context
                .digits
                .iter()
                .map(|digit| (digit.first, digit.len))
                .collect();
            let expected: &[(usize, usize)] = match level {
                0 => &[(0, 1)],
                1 => &[(0, 2)],
                _ => &[(0, 2), (2, 1)],
            };
            assert_eq!(shapes, expected);
            for digit in &context.digits {
                assert_eq!(digit.basis.len(), digit.len);
                // Every limb outside the digit receives a converted residue.
                assert_eq!(digit.target_limbs.len(), level + 1 + 2 - digit.len);
                assert_eq!(digit.targets.len(), digit.target_limbs.len());
                for (&limb, target) in digit.target_limbs.iter().zip(&digit.targets) {
                    assert!(!(digit.first..digit.first + digit.len).contains(&limb));
                    assert_eq!(
                        target.target_modulus(),
                        profile.extended_plan(level, limb).prime()
                    );
                }
            }
            assert_eq!(
                profile.special_product_mod_main(level),
                modulus_of_product(&parameters.special_primes, parameters.main_primes[level])
            );
            assert!(profile.key_switch_noise(level).is_ok());
        }
        assert_eq!(profile.main_plan(1).prime(), parameters.main_primes[1]);
        assert_eq!(
            profile.special_plan(1).prime(),
            parameters.special_primes[1]
        );
        assert_eq!(
            profile.extended_plan(0, 1).prime(),
            parameters.special_primes[0]
        );
        let out_of_range = BgvError::LevelOutOfRange { level: 3, top: 2 };
        assert_eq!(profile.level_modulus(3), Err(out_of_range));
        assert_eq!(profile.capacity(3).err(), Some(out_of_range));
        assert_eq!(profile.key_switch_noise(3).err(), Some(out_of_range));
        assert_eq!(profile.level(3).err(), Some(out_of_range));
        assert_eq!(
            profile.fresh_noise(),
            &Natural::from_u64(128 + 257 * 21 * 33)
        );
    }

    fn modulus_of_product(factors: &[u64], modulus: u64) -> u64 {
        Natural::product_of(factors)
            .rem_u64(modulus)
            .expect("modulus")
    }

    #[test]
    fn plan_defects_keep_their_prime_index() {
        assert_eq!(
            plan_defect(NttPlanError::UnsupportedDegree, 3),
            ParameterDefect::DegreeOutOfRange
        );
        assert_eq!(
            plan_defect(NttPlanError::CompositeModulus, 3),
            ParameterDefect::PrimeComposite { index: 3 }
        );
        assert_eq!(
            plan_defect(NttPlanError::RootNotPrimitive, 3),
            ParameterDefect::RootNotPrimitive { index: 3 }
        );
        assert_eq!(
            plan_defect(NttPlanError::ModulusOutOfRange, 3),
            ParameterDefect::PrimeOutOfRange { index: 3 }
        );
        assert_eq!(
            plan_defect(
                NttPlanError::LengthMismatch {
                    expected: 1,
                    found: 2
                },
                3
            ),
            ParameterDefect::PrimeOutOfRange { index: 3 }
        );
    }

    #[test]
    fn the_candidate_constructor_builds_the_affine_profile() {
        let profile = BgvProfile::candidate(BgvCandidate::AffineF257).expect("profile");
        assert_eq!(profile.degree(), 1 << 14);
        assert_eq!(profile.top_level(), 5);
        assert_eq!(profile.digit_count(), 3);
        assert_eq!(profile.level_modulus(5).expect("modulus").bit_len(), 295);
        assert_eq!(profile.special_modulus().bit_len(), 119);
    }
}
