//! Chips for the Iroha-native PIPA-v1 `PLONKish` engine ([`iroha_plonk`],
//! `specs/plonk_ipa_v1.md`) on the Pasta fields of [`iroha_pasta`].
//!
//! # Contents
//!
//! Stage GADGETS (task T17):
//!
//! - [`poseidon`]: the RP57 width-3 Pow5 permutation lane (37 rows and 148
//!   cells per permutation, the M8 layout) and the KAGEMUSHA
//!   domain/arity-prefixed sponge on it, bit for bit
//!   [`iroha_pasta::poseidon`] and the `kagemusha_v1_poseidon` vectors of
//!   `fixtures/native_prover/kats_v1.json`;
//! - [`pow5_fq`] (M3): the lane instantiated over Fq (`P_Fq`, the pinned
//!   `RP57_FQ` table) with pinned full-state permutation vectors, and the
//!   transcript (duplex) mode whose squeezes carry the state on, as the
//!   native `Sponge` and the PIPA-R base-field transcript do;
//! - [`range`]: running-sum range checks against a `2^b`-row table, and
//!   checked `u128`/`u64` add, subtract and compare whose overflow or
//!   underflow has no satisfying assignment;
//! - [`arith`]: the glue gate (add, multiply, linear combinations,
//!   constants, booleans, select, is-zero, equality);
//! - [`bytes`] (M3): byte linking: the `P_bytes` packing on a one-row-per-byte
//!   tape, 32-byte proof messages linked to compressed points `(x, y
//!   parity)` and canonical scalars, and descriptor-sized sigma exports;
//! - [`ecc`] (M3): Pasta native ECC (Pallas in `Fp`, Vesta in `Fq`):
//!   complete addition, GLV variable-base multiplication with the lattice
//!   bound and a complete tail, identity-guarded Horner chains, fixed-base
//!   windows and on-curve checks;
//! - [`ff`] (M3): FF-CRT foreign-field arithmetic (Pasta `q` in `Fp`, Pasta
//!   `p` in `Fq`, P-256 `p` and `n`): three 87-bit limbs, a fused
//!   multiply-reduce gate proving `a b = c + q m` (70 cells per
//!   multiplication, range-checked against one 15-bit table column),
//!   division and inversion, canonical comparison;
//! - [`p256`] (M3): P-256 ECDSA verification (`SHA256withECDSA` over a
//!   Poseidon digest, low-S) in hard and soft modes, for witness and fixed
//!   keys: window lookups, incomplete chains proven exception-free and
//!   complete joins;
//! - [`sha256`] (M3): one SHA-256 compression per block on spread-table
//!   units (degree 5, one lookup), and the codec of a Poseidon digest as the
//!   32-byte canonical message of one padded block;
//! - [`blake2b`]: constrained BLAKE2b-256, Iroha hash marking, and streaming
//!   compression with linked state, counters and final flag;
//! - [`merkle`]: ordinary counted application-tree inclusion, with exact
//!   leaf/internal domains and constrained ragged-edge promotion;
//! - [`bls12_381`]: canonical 381-bit arithmetic, extension fields, curve
//!   and pairing components, and the native W3f hash-to-field transcript.
//!   These components alone do not establish signatures or finality;
//! - [`table`] (M3b): the shared lookup table of the Q leaf, through which
//!   the SHA-256 and P-256 window lookups ride on foreign-field range
//!   arguments, and its soundness conditions;
//! - [`q_leaf`] (M3b): the 17-column Q-leaf layout of the P-256 and SHA-256
//!   chips (ten lookup arguments, twelve equality columns), its row plan and
//!   the audit of the shared-table conditions;
//! - [`imt`]: authenticated indexed-map membership, soft gap checks,
//!   empty-slot insertion and predecessor relinking with slot clearing;
//! - [`statement`]: the G1 step statement encoding (26 elements under
//!   `kgwstmt1`) of the split-lineage step relations, the canonical
//!   cross-field limb encoding of spec S6, and the canonical limb
//!   decomposition of an own-field word, used by the native step proofs.
//! - [`cells`]: the typed cells chips exchange ([`cells::Word`],
//!   [`cells::Bit`], [`cells::Uint`]) and row cursors;
//! - [`tamper`]: the per-cell tamper harness every chip test runs. It shows
//!   that every assigned cell is pinned (by a gate, a lookup or a copy), not
//!   that a composed relation is semantically complete: a witness that is
//!   only copied into a hash is pinned by that copy whatever it claims.
//!
//! # Discipline
//!
//! Every chip has typed assigned cells, a native reference, shared vectors,
//! a per-cell tamper suite (each assigned advice cell, changed alone, must
//! make the strict constraint checker fail) and an inventory test pinning
//! its rows and cells per operation (`tests/`). Ordinary layouts have gate
//! degree at most [`MAX_GATE_DEGREE`]. Explicit compact phase layouts use at
//! most [`phase::MAX_COMPACT_GATE_DEGREE`] to share fixed columns; with exact
//! cosets the quotient cost scales with `d - 1`. The format cap remains nine.
//!
//! # Layout
//!
//! The `iroha_plonk` floor planner starts every region at row 0, so chips
//! address absolute rows: each chip owns its columns and a row cursor, and
//! chips on disjoint columns share rows freely. Pow5 lanes place
//! permutations at multiples of 37 rows, so lanes may share their
//! round-constant columns.
//!
//! # Determinism
//!
//! Layouts and witnesses are pure functions of the inputs: ordered
//! containers only, checked row arithmetic, no environment variables, no
//! `unsafe`. Witness generation that depends on secret values (inverses,
//! zero tests) is constant time.
#![forbid(unsafe_code)]

pub mod arith;
pub mod blake2b;
pub mod bls12_381;
pub mod bytes;
pub mod cells;
pub mod ecc;
pub mod ff;
pub mod imt;
pub mod merkle;
pub mod p256;
pub mod phase;
pub mod poseidon;
pub mod pow5_fq;
pub mod q_leaf;
pub mod range;
pub mod sha256;

pub mod crc64;
pub mod statement;
pub mod table;
pub mod tamper;

pub use arith::{GlueChip, GlueConfig};
pub use cells::{Bit, RowCursor, U64, U128, Uint, Word};
pub use poseidon::{
    AbsorbInput, Pow5Chip, Pow5Columns, Pow5Config, RoundConstantColumns, SpongeChip, SpongeConfig,
};
pub use range::{LimbBits, RunningSumChip, RunningSumConfig, UintChip};

/// The largest gate degree any chip of this crate uses.
pub const MAX_GATE_DEGREE: usize = 6;

pub mod word_hash;
pub use word_hash::WordHasher;
