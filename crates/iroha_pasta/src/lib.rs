//! Iroha-native Pasta arithmetic and prover kernels.
//!
//! `iroha_pasta` is the lowest layer of the native PLONK/IPA stack. Node
//! verifiers, wallet provers and native state hashing use it without linking
//! any PLONK, gadget or recursion code.
//!
//! # Contents
//!
//! - [`field`]: the Pasta fields [`Fp`] and [`Fq`] (portable 4x64-bit
//!   Montgomery arithmetic specialised to the Pasta moduli) with the `ff` 0.13
//!   traits, constant-time and `*_vartime` inversion, batch inversion and
//!   table-based square roots.
//! - [`curve`]: Pallas ([`Ep`]) and Vesta ([`Eq`](struct@Eq)) with complete
//!   projective formulas, compressed encodings, the GLV endomorphism,
//!   hash-to-curve and batch kernels, implementing the `group` 0.13 traits.
//! - [`msm`]: batch-affine signed-digit Pippenger ([`msm::msm_public`],
//!   [`msm::msm_secret`]) and fixed-base commitment-key tables, planned against
//!   an explicit [`msm::MemoryBudget`] and a process-wide 64 MiB shared scratch
//!   ceiling ([`msm::SharedMemoryBudget`]).
//! - [`fold`]: the lockstep batch-affine GLV generator fold of the IPA prover.
//! - [`fft`]: radix-4 (fused radix-2) transforms with cached twiddles and coset
//!   transforms.
//! - [`params`]: the pinned IPA generator derivation and parameter byte codec.
//! - [`poseidon`]: the KAGEMUSHA V1 RP57 Poseidon permutation and sponge with
//!   pinned, regenerable constant tables.
//!
//! # Pinned representations and independent tests
//!
//! `tests/field_oracle.rs` and `tests/curve_oracle.rs` compare field and curve
//! behavior with the retained `pasta_curves` 0.5.2 dev oracle;
//! `tests/cross_impl_encoding.rs` also uses the separate `halo2curves` dev
//! oracle. Parameter and Poseidon KATs retain digests and vectors captured
//! before the vendored prover and `iroha_plonk_oracle` were deleted.
//! `tests/params_parity.rs` and `tests/poseidon_kat.rs` check those captures;
//! native parameter tests compare the group IFFT with a naive group DFT, and
//! Poseidon tests regenerate the constant tables. No live external prover is
//! required by these checks.
//!
//! # Determinism and timing
//!
//! Every result is a pure function of its inputs: exact integer arithmetic
//! only, identical on every architecture and at every Rayon pool size, with no
//! behaviour sourced from environment variables. Kernels run on the caller's
//! Rayon pool with no global locks. Routines named `*_vartime` take time that
//! depends on their inputs and accept public data only; each module documents
//! its timing posture.
//!
//! TODO: later milestones add the optional aarch64 `asm` multiplication
//! (bit-identical to the portable path), a GLV MSM, deferred IPA folds, the
//! Kaigi RP56 (`P128Pow5T3`) Poseidon tables, and allocation accounting
//! through `iroha_allocation`. The fold and `batch_mul_vartime` already use
//! GLV, the confidential V3 note hash uses the RP57 sponge of [`poseidon`], and
//! `tests/cross_impl_encoding.rs` holds the `halo2curves` 0.9 encoding KATs.
#![forbid(unsafe_code)]

pub mod cancellation;
pub use cancellation::{CancellationToken, Cancelled};

pub mod curve;
pub mod fft;
pub mod field;
pub mod fold;
pub mod msm;
pub mod params;
pub mod poseidon;

pub use curve::{Ep, EpAffine, Eq, EqAffine, PastaAffine, PastaCurve, pallas, vesta};
pub use field::{Fp, Fq, PastaField};

/// Two inputs that must have equal lengths did not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LengthMismatch {
    /// Length of the first input.
    pub left: usize,
    /// Length of the second input.
    pub right: usize,
}

impl core::fmt::Display for LengthMismatch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "length mismatch: {} != {}", self.left, self.right)
    }
}

impl std::error::Error for LengthMismatch {}

#[cfg(test)]
mod cancellation_tests;
