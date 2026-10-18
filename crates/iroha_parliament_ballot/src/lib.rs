//! Typed protocol layer of the SORA Parliament anonymous ballot.
//!
//! The ballot is specified in `specs/parliament_private_ballot_design.md` §3 and §6, its
//! byte-level construction in `specs/parliament_ballot_proof_profile.md` §6, and the
//! production integration decisions of 2026-10-18 fix the envelope, the admission order,
//! the corpus, the stamp, the encodings and the full-verification interface. This crate is
//! the one implementation of those rules that Core, Torii, the CLI, the Rust client and the
//! native bridge share. It sits between the data-model wire types
//! ([`iroha_data_model::governance::anonymous_ballot`]) and the state-free proof relations
//! ([`iroha_parliament_ballot_proof`]):
//!
//! - [`inputs`]: the canonical `Enc` proof inputs of the typed values and the `P16`-bound
//!   digests `B`, `R`, `scope` and `policy_hash`, always computed by the proof crate;
//! - [`context`]: building and checking the authenticated ballot context, and the immutable
//!   scoped verification context that every verifier uses;
//! - [`registration`]: the registration statement and its verification;
//! - [`ballot`]: the vote statement, proof verification, the seven ordered admission
//!   checks and the block-execution decision shared by Core and the full verifier;
//! - [`stamp`]: the admission-stamp nonce search;
//! - [`corpus`]: the incremental accepted corpus and the closure-record builder;
//! - [`replay`]: the streaming core of independent full verification;
//! - [`wallet`]: native credential handling, disclosure, the choice lock, proving and
//!   relaying.
//!
//! # Status
//!
//! **Nothing here is qualified.** The data-model launch gate
//! [`PARLIAMENT_BALLOT_QUALIFICATION_V1`] is `None`, so binding production use stays
//! disabled; Core enforces that gate at its dispatch and state boundaries. This crate
//! neither reads nor changes the gate and claims nothing about it: engineering completion
//! and the tests here are not qualification evidence. The proof relations are the real
//! candidate relations; no verification step is a placeholder.
//!
//! # One row
//!
//! Production code compiles only the candidate row [`PROOF_ROW_V1`]; there is no row
//! argument, detection or fallback, and this crate never names the comparator row. Every
//! scoped context checks that the compiled descriptor digest is
//! [`ProofProfileIdV1::V1`].
//!
//! TODO: integration decision 6 keeps the comparator row behind the proof crate's test and
//! diagnostic support, excluded from node, wallet and bridge dependency features; the proof
//! crate still compiles both rows unconditionally, so that split is outstanding there.
//!
//! # Determinism and secrets
//!
//! Every verification and decision is a pure function of its inputs and gives the same
//! result on every platform; hardware parallelism is used only by the stamp search, whose
//! result any valid nonce satisfies. Secrets (credential secrets and proving tapes) live in
//! the proof crate's erasing owners; this crate draws them from the operating system's
//! random source and has no deterministic fallback.
//!
//! [`PARLIAMENT_BALLOT_QUALIFICATION_V1`]:
//!     iroha_data_model::governance::anonymous_ballot::PARLIAMENT_BALLOT_QUALIFICATION_V1
//! [`ProofProfileIdV1::V1`]: iroha_data_model::governance::anonymous_ballot::ProofProfileIdV1::V1

#![forbid(unsafe_code)]

pub mod ballot;
pub mod context;
pub mod corpus;
mod entropy;
pub mod inputs;
pub mod registration;
pub mod replay;
pub mod stamp;
pub mod wallet;

#[cfg(test)]
mod test_support;

use iroha_parliament_ballot_proof::profile::Row;

pub use self::entropy::EntropyUnavailableV1;

/// The proof-crate parameter row of the V1 profile: the candidate row
/// `(lambda, tau, w_grind, T_open, d_zk, n_mult) = (256, 33, 8, 229, 7, 704)`.
pub const PROOF_ROW_V1: Row = Row::Candidate;

#[cfg(test)]
mod tests {
    use iroha_data_model::governance::anonymous_ballot::{
        BallotProofBytesV1, PARLIAMENT_BALLOT_QUALIFICATION_V1, ProofProfileIdV1,
        RegistrationProofBytesV1, parliament_ballot_qualified_v1,
    };
    use iroha_parliament_ballot_proof::profile::{Profile, Role};

    use super::*;

    #[test]
    fn the_compiled_row_is_the_v1_profile_and_the_gate_stays_closed() {
        let profile = Profile::new(PROOF_ROW_V1).expect("embedded tables");
        assert_eq!(
            profile.descriptor_digest().as_bytes(),
            ProofProfileIdV1::V1.as_bytes()
        );
        assert_eq!(
            PROOF_ROW_V1.proof_bytes(Role::Vote),
            BallotProofBytesV1::LENGTH
        );
        assert_eq!(
            PROOF_ROW_V1.proof_bytes(Role::Registration),
            RegistrationProofBytesV1::LENGTH
        );
        // This crate never opens the launch gate.
        assert_eq!(PARLIAMENT_BALLOT_QUALIFICATION_V1, None);
        assert!(!parliament_ballot_qualified_v1());
        assert!(!iroha_parliament_ballot_proof::PROFILE_QUALIFIED);
    }
}
