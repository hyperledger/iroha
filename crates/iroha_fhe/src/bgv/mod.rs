//! Exact modular RNS-BGV: the leveled scheme of Brakerski, Gentry and Vaikuntanathan.
//!
//! This is the shared starting candidate for RAM-LFE and `SoraCloud`. It is a
//! genuine BGV: the plaintext sits in the low bits, `c0 + c1*s = m + t*e
//! (mod Q_l)`, with `gcd(Q_l, t) = 1`. It is not BFV scaling and not the
//! retained exact-lift construction of `iroha_crypto`, whose ciphertext
//! modulus is a multiple of the plaintext modulus.
//!
//! Nothing here is wired into a consumer, and no profile is qualified: the
//! candidates of [`BgvCandidate`] have no reviewed security estimate, no
//! circuit-privacy construction, no client well-formedness proof and no
//! verifiable opening. Those belong to the tasks that consume this module.
//!
//! # Ring, chain and levels
//!
//! `R = Z[X] / (X^N + 1)` with `N` a power of two. A profile pins main primes
//! `q_0, ..., q_L` and special primes `p_0, ..., p_(K-1)`, all congruent to
//! one modulo `2 * N * t`. A ciphertext at level `l` lives modulo
//! `Q_l = q_0 * ... * q_l`. Polynomials are limb-major canonical residues in
//! coefficient form; that is also the canonical encoding.
//!
//! # Equations
//!
//! - Secret key `s`: uniform ternary coefficients.
//! - Public key: `a` uniform modulo `Q_L`, `e` an error; `b = -a*s + t*e`.
//! - Encryption of `m` (centered modulo `t`): `u` uniform ternary, errors
//!   `e0, e1`; `c0 = b*u + t*e0 + m`, `c1 = a*u + t*e1`.
//! - Decryption: `v = [c0 + c1*s]` centered modulo `Q_l`; `m = v mod t`.
//! - Addition and plaintext operations act component-wise; multiplication
//!   forms the tensor `(a0*b0, a0*b1 + a1*b0, a1*b1)` and relinearizes it.
//! - Modulus switching drops `q_l` with the congruence-preserving rule of
//!   [`crate::rns_chain::CongruentScaleDown`]; because `q_l = 1 (mod t)` the
//!   plaintext is unchanged and no correction factor is carried.
//! - Key switching is hybrid RNS: the switched component is split into the
//!   digit groups of the profile, each digit is extended exactly (centered)
//!   to the level and special primes, multiplied by the key, and the sum is
//!   divided by `P = p_0 * ... * p_(K-1)` with the same congruence-preserving
//!   rule. Relinearization keys encrypt `P * s^2` digit by digit and Galois
//!   keys encrypt `P * s(X^k)`; publishing either relies on a circular
//!   security (key-dependent message) assumption that the profile review
//!   must state.
//!
//! No approximation occurs anywhere: basis extension is exact, every division
//! is exact, and no floating point is used.
//!
//! # Randomness
//!
//! Every key generation and encryption draws 64 bytes from the operating
//! system and fails closed when that fails. The seed is expanded by BLAKE3
//! `derive_key` and its extendable output, with the profile identity and a
//! purpose tag in the key material, so every sampled object has its own
//! stream. The samplers are specified in [`coins`]: uniform ternary secrets
//! and masks, centered binomial errors with `eta = 21`, and uniform residues
//! by rejection. Entry points that take a seed or explicit coins exist only
//! under `cfg(any(test, feature = "bgv-test-fixtures"))`.
//!
//! # Noise accounting and the failure bound
//!
//! Each ciphertext carries a [`NoiseBound`]: an exact upper bound of the
//! infinity norm of `v`, computed from profile constants and the public
//! operation history only. It never depends on a key, a plaintext or a
//! measured noise. An operation whose result would exceed the capacity
//! `(Q_l - 1) / 2` is refused with [`BgvError::NoiseBudgetExceeded`]. The
//! formulas are in [`noise`]; [`plan`] applies them to the public shape of a
//! ciphertext, and every operation takes the shape of its result from there,
//! so a sequence of operations can be planned without a key or a ciphertext
//! and is admitted on ciphertexts exactly when its plan is. Decryption fails
//! exactly when the infinity norm
//! of the true `v` exceeds the capacity; because every sampled error has
//! magnitude at most 21 with certainty, a ciphertext produced from honest
//! coins by admitted operations never fails. The bound is worst case and
//! therefore pessimistic by many bits; that cost is part of the candidate.
//!
//! # Encodings
//!
//! Parameter sets, ciphertexts, public keys, switching keys and evaluation
//! keys have canonical words and fixed byte frames, and decoders that reject
//! another profile, any other length and a non-canonical residue. The secret
//! key has a custody frame in a clearing buffer. Decoding establishes that an
//! encoding is well formed and nothing else: a decoded key or ciphertext is
//! not authenticated, and the Norito wire types that carry these frames
//! belong to the consumers.
//!
//! # Secrets
//!
//! Secret keys, sampled coins, the decryption scratch and plaintexts live in
//! owners that clear on drop, on an error return and on unwind. The seed of
//! an operation and the hash and stream state derived from it live in one
//! heap block that is overwritten whole before it is released ([`coins`]).
//! Arithmetic on secrets uses the branch-free kernels of
//! [`crate::constant_time`], [`crate::ntt_plan`] and [`crate::rns_chain`].
//! Rejection sampling leaks only how many candidates were rejected, which is
//! independent of the accepted values.
mod cipher;
pub mod coins;
pub mod cost;
mod encoding;
mod eval;
mod fault;
#[cfg(any(test, feature = "bgv-test-fixtures"))]
pub mod fixtures;
mod keys;
pub mod noise;
pub mod plan;
mod poly;
mod profile;

pub use cipher::{Ciphertext, Plaintext, PlaintextBound};
pub use coins::{COIN_SEED_BYTES, ERROR_BOUND, ERROR_ETA};
pub use encoding::SlotEncoding;
pub use keys::{EvaluationKeys, KeySet, PublicKey, SecretKey, SwitchingKey, SwitchingKeyKind};
pub use noise::NoiseBound;
pub use plan::CiphertextShape;
pub use profile::{BgvCandidate, BgvParameters, BgvProfile, ParameterDefect};

use crate::{automorphism::AutomorphismError, ntt_plan::NttPlanError, rns_chain::RnsChainError};
use thiserror::Error;

/// Failure of a BGV operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum BgvError {
    /// The parameter set is not a valid profile.
    #[error("invalid BGV parameters: {0}")]
    InvalidParameters(#[from] ParameterDefect),
    /// The operating system returned no entropy, or returned a stuck value.
    #[error("operating-system entropy is unavailable")]
    EntropyUnavailable,
    /// An object belongs to another profile.
    #[error("object belongs to another BGV profile")]
    ProfileMismatch,
    /// A level is above the top level of the profile.
    #[error("level {level} exceeds the top level {top}")]
    LevelOutOfRange {
        /// The requested level.
        level: usize,
        /// The top level of the profile.
        top: usize,
    },
    /// The operation needs a lower level than the lowest one.
    #[error("no modulus is left to switch to")]
    NoLevelLeft,
    /// The operands are at different levels where equal levels are required.
    #[error("operands are at levels {lhs} and {rhs}")]
    LevelMismatch {
        /// Level of the first operand.
        lhs: usize,
        /// Level of the second operand.
        rhs: usize,
    },
    /// A ciphertext has a number of components the operation does not accept.
    #[error("operation does not accept a ciphertext of {found} components")]
    ComponentCount {
        /// Components of the offending ciphertext.
        found: usize,
    },
    /// A slice or frame has the wrong length.
    #[error("expected {expected} elements, found {found}")]
    LengthMismatch {
        /// Required length.
        expected: usize,
        /// Supplied length.
        found: usize,
    },
    /// A coefficient or residue is not canonical.
    #[error("value at index {index} is not canonical")]
    NonCanonical {
        /// Index of the offending value.
        index: usize,
    },
    /// A plaintext exceeds the bound it was declared with.
    #[error("plaintext exceeds its declared norm bound")]
    PlaintextBoundExceeded,
    /// The public noise bound of the result exceeds the level capacity.
    #[error("public noise bound exceeds the capacity of level {level}")]
    NoiseBudgetExceeded {
        /// Level at which the capacity was exceeded.
        level: usize,
    },
    /// The switching key is not the one the operation needs.
    #[error("switching key does not match the requested operation")]
    WrongSwitchingKey,
    /// The Galois element is not an odd unit other than one.
    #[error("Galois element is not a usable automorphism power")]
    InvalidGaloisElement,
    /// A slot index or slot count is outside the encoding.
    #[error("slot {index} is outside the {slots} slots of the encoding")]
    SlotOutOfRange {
        /// The offending index or count.
        index: usize,
        /// Number of slots.
        slots: usize,
    },
    /// A plaintext is not in the scalar subalgebra of the encoding.
    #[error("plaintext coefficient {index} is outside the scalar subalgebra")]
    OutsideScalarSubalgebra {
        /// Index of the first offending coefficient.
        index: usize,
    },
    /// The plaintext modulus admits no slot encoding in this ring.
    #[error("plaintext modulus admits no scalar slot encoding in this ring")]
    EncodingUnavailable,
    /// A canonical frame is malformed.
    #[error("malformed canonical frame")]
    MalformedFrame,
    /// An arithmetic kernel rejected its input; this indicates an internal shape error.
    #[error("arithmetic kernel rejected its input")]
    Kernel,
}

impl From<RnsChainError> for BgvError {
    fn from(_: RnsChainError) -> Self {
        Self::Kernel
    }
}

impl From<NttPlanError> for BgvError {
    fn from(_: NttPlanError) -> Self {
        Self::Kernel
    }
}

impl From<AutomorphismError> for BgvError {
    fn from(_: AutomorphismError) -> Self {
        Self::Kernel
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_errors_map_to_the_kernel_variant() {
        assert_eq!(BgvError::from(RnsChainError::EmptyBasis), BgvError::Kernel);
        assert_eq!(
            BgvError::from(NttPlanError::UnsupportedDegree),
            BgvError::Kernel
        );
        assert_eq!(
            BgvError::from(AutomorphismError::PowerNotCoprime),
            BgvError::Kernel
        );
        assert_eq!(
            BgvError::from(ParameterDefect::DegreeOutOfRange),
            BgvError::InvalidParameters(ParameterDefect::DegreeOutOfRange)
        );
    }
}
