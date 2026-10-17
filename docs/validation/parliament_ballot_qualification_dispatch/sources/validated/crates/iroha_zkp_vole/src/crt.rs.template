//! CRT encoding of the verifier challenge `Delta` and the VOLE-multiplication tables
//! (FAEST v3.0 section 5.2 and Appendix B).
//!
//! * [`generated`] holds the eight standard table sets as embedded statics, and
//!   the lookup from a parameter row to its set. Signing and verification read only
//!   these statics: nothing is computed at start-up or cached at first use.
//! * [`generator`] is the deterministic construction of a table set from
//!   `(lambda, tau, w_grind)`: integer and bit arithmetic only, no floating point,
//!   no randomness, no hashing, and no state outside the call. It produced the
//!   embedded sets and stays public for explicit use with other parameters.
//! * [`tables`] holds a table set, the eight standard profiles and the checked
//!   accessors.
//! * [`matrix`] is the `GF(2)` bit matrix the tables are made of, with the
//!   products the VOLE layer needs. The matrices are public; the operands they are
//!   applied to may be secret and never drive a branch or an index.
//! * [`codec`] serialises a table set to `u64` words and renders it as Rust source.
//!
//! Everything else in this directory is private support for the generator: big bit
//! vectors, `GF(2)[x]`, linear algebra over `GF(2)`, the field `F_4`, the cost
//! search and the bilinear multiplication algorithms. The byte-oriented polynomial
//! helpers and the enumeration of irreducible polynomials are those of
//! [`crate::field::poly`].
//!
//! # Attribution
//!
//! The construction follows the table generator of the FAEST v3.0.2 reference
//! implementation (`tables/vole_mult_tables.cpp` of `faest-ref`), which is
//! distributed under the MIT licence. The code here is an independent Rust
//! implementation of that construction, and the embedded tables are its output. The
//! upstream licence text is kept beside the generated tables in
//! `src/crt/generated/LICENSE.faest-ref`.
//!
//! # Conformance
//!
//! `tests/conformance_crt.rs` reproduces every entry of
//! `tests/fixtures/faest_v3_0_2/crt_vole_commit_tvs.txt`, regenerates the eight
//! sets and compares them with the embedded statics word for word, and pins the
//! SHAKE256 digest of every table.

mod algo;
mod bits;
pub mod codec;
mod cost;
mod error;
mod f4;
pub mod generated;
pub mod generator;
mod gf2poly;
mod linalg;
pub mod matrix;
pub mod tables;

pub use cost::{Place, PlaceKind};
pub use error::CrtError;
pub use generated::tables_for;
pub use tables::{CrtTables, Profile, TableWords};
