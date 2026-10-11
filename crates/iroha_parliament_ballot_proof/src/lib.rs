//! State-free experimental Parliament anonymous-ballot relations (registration and
//! vote) over the VOLE-in-the-head backend [`iroha_zkp_vole`].
//!
//! **No proof profile is selected or qualified.** This crate exists to implement and
//! measure candidate relations; the evaluation record is
//! `specs/parliament_ballot_proof_profile.md`. Binding governance does not use this
//! crate: it is not a dependency of Core, it validates no on-chain ballot, and
//! nothing it accepts or rejects has governance effect.
//!
//! Proofs produced here are *FAEST-derived*: they reuse the FAEST v3.0 proof
//! machinery with custom relations and are not standard FAEST signatures.
//!
//! The crate holds no state, performs no I/O and reads no configuration or
//! environment. Outputs are byte-identical across hardware; the `accel` feature only
//! forwards hardware acceleration to the backend.

#![forbid(unsafe_code)]

pub mod credential;
pub mod framing;
pub mod keccak_relation;
pub mod profile;
pub mod registration;
pub mod sealed_list;
pub mod selector;
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
