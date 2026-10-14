//! State-free **experimental** Parliament anonymous-ballot proofs: the
//! registration and vote relations of the construction frozen for investigation
//! in `specs/parliament_ballot_proof_profile.md` section 6, over the
//! VOLE-in-the-head backend [`iroha_zkp_vole`].
//!
//! # Status
//!
//! **No proof profile is selected or qualified.** The construction is frozen so
//! that it can be implemented, measured and reviewed; it is not the normative
//! profile, its `profile_id` is not allocated, and its security arguments
//! (`specs/parliament_ballot_proof_arguments.md`) await independent review.
//! Binding governance does not use this crate: it is not a dependency of Core or
//! of any node crate, it validates no on-chain ballot, and nothing it accepts or
//! rejects has governance effect. The parameter rows are the fast row
//! ([`profile::Row::Candidate`], the sole integration candidate) and the small
//! row ([`profile::Row::Comparator`], a measurement comparator); neither is
//! selected.
//!
//! Proofs produced here are *FAEST-derived*: they reuse the FAEST v3.0 proof
//! machinery with custom relations, a literal role prefix on every hash call and
//! a caller-supplied proving tape. They are not FAEST signatures and inherit no
//! FAEST theorem by construction.
//!
//! # What is here
//!
//! * [`profile`]: the two rows, the descriptor `DESC`, its digest `D`, the CRT
//!   table digest `T_crt`, the role namespaces and 77-byte prefixes, the proof
//!   lengths.
//! * [`framing`]: `Frame` and the bounded opaque public inputs.
//! * [`credential`]: the 48-byte secret, `B`, `C`, `D_reg`, `auth`, `nf` and the
//!   digest helpers.
//! * [`sealed_list`]: the sealed list and its digest `R`.
//! * [`keccak_relation`], [`selector`], [`layout`]: the constraint gadgets and
//!   the frozen witness and constraint tables.
//! * [`registration`], [`vote`]: statements, witness generation, the relations,
//!   `prove` and `verify`.
//! * [`proving`]: the 112-byte proving tape and the error types.
//! * [`test_codec`]: a **test-only** statement and record codec; not a
//!   production schema.
//!
//! # What a caller must supply and check
//!
//! The public inputs are bounded opaque byte strings. This crate neither parses
//! them nor knows the typed node values behind them: canonical encodings,
//! authentication of the body, of the sealed list and of the registration
//! authority, eligibility, freshness and nullifier uniqueness are the caller's.
//! The prover takes its 112 random bytes from the caller; there is no fallback.
//!
//! # Determinism and secrets
//!
//! The crate holds no state, performs no I/O and reads no configuration or
//! environment. Outputs are byte-identical on every platform; the `accel`
//! feature only forwards hardware acceleration to the backend and changes no
//! byte. Secret-dependent data drives no branch, table index or early exit in
//! this crate's own code: that covers the credential secret, the tape and the
//! voter's list position, which [`sealed_list::SealedList::position`] finds by a
//! full masked scan and [`vote::prove`] takes as a `u16` without comparing it
//! with anything. Owned tape, pad, witness and secret scratch buffers are
//! zeroized on drop. This does not establish erasure of register, spill or
//! compiler-generated copies, or cleanup after process abort. The prover is
//! synchronous and provides no cooperative cancellation API. Complete-proof
//! constant-time and erasure properties also depend on the backend and have
//! not been independently audited.

#![forbid(unsafe_code)]

pub mod credential;
pub mod framing;
pub mod keccak_relation;
pub mod layout;
pub mod profile;
pub mod proving;
pub mod registration;
pub mod sealed_list;
pub mod selector;
pub mod test_codec;
pub mod vote;

/// Whether any ballot proof profile in this crate is selected or qualified for
/// binding use. It is not.
pub const PROFILE_QUALIFIED: bool = false;

#[cfg(test)]
mod tests {
    use super::PROFILE_QUALIFIED;

    #[test]
    fn no_profile_is_qualified() {
        const { assert!(!PROFILE_QUALIFIED) };
        assert_eq!(iroha_zkp_vole::FAEST_SPECIFICATION_VERSION, "3.0");
    }
}
