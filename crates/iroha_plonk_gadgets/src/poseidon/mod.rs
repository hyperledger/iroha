//! Poseidon chips: the RP57 Pow5 permutation lane ([`pow5`]) and the
//! KAGEMUSHA sponge on it ([`sponge`]).
//!
//! Both reproduce [`iroha_pasta::poseidon`] bit for bit (width 3, rate 2,
//! `x^5`, `R_F = 8`, `R_P = 57`, the pinned RP57 tables of each Pasta
//! field), so in-circuit digests equal the native domain hash and the shared
//! `kagemusha_v1_poseidon` vectors of `fixtures/native_prover/kats_v1.json`.
//!
//! The transcript mode (intermediate squeezes with the state carried on,
//! `floor(len / 2) + 1` permutations per squeeze) is
//! [`crate::pow5_fq::duplex`], generic over both fields.
//!
//! TODO(T17 follow-up): the measured 6-column variant (two full rounds and
//! four partial rounds per row).

pub mod pow5;
pub mod sponge;

pub use pow5::{
    Absorb, AbsorbInput, CELLS_PER_PERMUTATION, LANE_COLUMNS, Pow5Chip, Pow5Columns, Pow5Config,
    Pow5State, ROWS_PER_PERMUTATION, RoundConstantColumns, SharedRoundSelectors, permute_native,
};
pub use sponge::{
    SpongeChip, SpongeConfig, domain_permutations, folded_state, raw_initial_state,
    raw_permutations,
};
