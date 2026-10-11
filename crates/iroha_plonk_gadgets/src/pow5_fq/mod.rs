//! The Pow5 Poseidon lane over Fq: `P_Fq`, RP57 Poseidon over the Pallas
//! scalar field (the Vesta base field), for Fq circuits.
//!
//! # Role
//!
//! In the Λ/Ω split-lineage design (`specs/kagemusha_lambda_omega_v1.md`)
//! the Fq circuits (the Q leaves and the Ω wrap, proved on Pallas) hash in
//! their own field:
//!
//! - the key-binding digests `P_Fq(VK)` that Q compares one-hot with the
//!   allowlisted σ keys and Ω with the A-variant keys (`hash_with_domain`
//!   over the key's elements, about 32 and 56 permutations);
//! - the base-field PIPA-R transcript (`plonk_ipa_v1.md` 6.2b) of every
//!   Vesta proof an Fq circuit verifies, whose squeezes carry the sponge
//!   state on ([`duplex`]).
//!
//! # Construction
//!
//! The lane is the generic [`crate::poseidon`] chip instantiated at
//! [`Fq`]: its gates and witnesses take the round constants and the MDS
//! matrix from [`iroha_pasta::poseidon::PoseidonField::rp57`], which for Fq
//! is the pinned `RP57_FQ` table of [`iroha_pasta::poseidon`] (regenerated
//! from the Grain procedure by `iroha_pasta` and anchored to the vendored
//! `halo2-base` constants of `fixtures/native_prover/kats_v1.json`). Nothing
//! in the layout depends on the field, so the Fq lane has the Fp lane's
//! shape:
//!
//! | item | value |
//! | --- | --- |
//! | advice columns per lane | 4 (`s0, s1, s2` and the equality-enabled `x`) |
//! | rows per permutation | 37 ([`ROWS_PER_PERMUTATION`]) |
//! | cells per permutation | 148 ([`CELLS_PER_PERMUTATION`]) |
//! | round-constant fixed columns | 6, shareable between lanes |
//! | selectors | 5 round selectors, one per start state, one [`duplex`] tap |
//! | gate degree | 6 (start gates and the tap gate: 2) |
//! | rotations | 0 and +1 |
//!
//! At `k = 16` (65,530 usable rows with the five blinding rows of a
//! rotation-+1 lane) one lane holds 1,771 permutations in 65,527 rows.
//!
//! # Native references and vectors
//!
//! [`permute_fq`] and [`hash_fq`] are the native `P_Fq` references
//! ([`iroha_pasta::poseidon::permute`] and `hash_with_domain` at `Fq`).
//! [`vectors`] pins nine full-state permutation known answers computed by
//! an independent implementation over the vendored constants. The native
//! permutation and the lane (with its whole output state exposed) are tested
//! against them, the domain sponge against the shared
//! `kagemusha_v1_poseidon.fq` vectors and the duplex mode against the Pallas
//! `poseidon_transcript` scripts of the same fixture
//! (`tests/pow5_fq_lane.rs`).

pub mod duplex;
pub mod vectors;

pub use duplex::{DuplexChip, DuplexConfig, duplex_native, squeeze_permutations};
use iroha_pasta::{
    Fq,
    poseidon::{WIDTH, hash_with_domain},
};
pub use vectors::{RP57_FQ_PERMUTATION_VECTORS, RP57_FQ_ZERO_CHAIN8, Rp57FqVector};

pub use crate::poseidon::{CELLS_PER_PERMUTATION, ROWS_PER_PERMUTATION};
use crate::poseidon::{Pow5Chip, Pow5Config, SpongeChip, SpongeConfig, permute_native};

/// A Pow5 lane configuration over Fq.
pub type Pow5FqConfig = Pow5Config<Fq>;
/// A Pow5 lane over Fq.
pub type Pow5FqChip = Pow5Chip<Fq>;
/// A KAGEMUSHA sponge lane configuration over Fq.
pub type SpongeFqConfig = SpongeConfig<Fq>;
/// The KAGEMUSHA domain sponge over Fq (`P_Fq`).
pub type SpongeFqChip = SpongeChip<Fq>;
/// A transcript-mode lane configuration over Fq.
pub type DuplexFqConfig = DuplexConfig<Fq>;
/// The transcript-mode sponge over Fq.
pub type DuplexFqChip = DuplexChip<Fq>;

/// Native reference: the RP57 Fq permutation of `state` after absorbing
/// `absorbed` into words 1 and 2.
#[must_use]
pub fn permute_fq(state: [Fq; WIDTH], absorbed: [Fq; 2]) -> [Fq; WIDTH] {
    permute_native(state, absorbed)
}

/// Native reference: `P_Fq(domain, inputs)`, the KAGEMUSHA domain hash over
/// Fq (`hash([domain, len, inputs...])`).
#[must_use]
pub fn hash_fq(domain: u64, inputs: &[Fq]) -> Fq {
    hash_with_domain(domain, inputs)
}

#[cfg(test)]
mod tests {
    use ff::Field as _;
    use iroha_pasta::poseidon::{PoseidonField as _, TABLE_BYTES, hash, permute};

    use super::*;

    #[test]
    fn native_references_are_the_rp57_fq_permutation_and_domain_hash() {
        let state = [Fq::from(3u64), -Fq::ONE, Fq::from(5u64)];
        let absorbed = [Fq::from(7u64), Fq::from(11u64)];
        let mut expected = [state[0], state[1] + absorbed[0], state[2] + absorbed[1]];
        permute(&mut expected);
        assert_eq!(permute_fq(state, absorbed), expected);
        let inputs = [Fq::from(9u64), Fq::ZERO];
        assert_eq!(
            hash_fq(42, &inputs),
            hash(&[Fq::from(42u64), Fq::from(2u64), inputs[0], inputs[1]])
        );
        assert_ne!(hash_fq(42, &inputs), hash_fq(43, &inputs));
    }

    #[test]
    fn the_lane_shape_is_the_m8_shape() {
        assert_eq!(ROWS_PER_PERMUTATION, 37);
        assert_eq!(CELLS_PER_PERMUTATION, 148);
        // The lane instantiated at Fq cannot silently run the Fp table.
        assert_ne!(Fq::rp57().to_table(), iroha_pasta::Fp::rp57().to_table());
        assert_eq!(Fq::rp57().to_table().len(), TABLE_BYTES);
    }
}
