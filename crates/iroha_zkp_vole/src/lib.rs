//! State-free, FAEST v3.0-derived VOLE-in-the-head proof backend.
//!
//! **Experimental and unqualified.** No proof profile built on this crate is selected
//! or qualified, nothing here is wired into Core, and no binding protocol decision
//! depends on it. Passing the official component vectors establishes conformance of
//! the individual building blocks only; it is not a security qualification.
//!
//! # Specification
//!
//! The backend follows "FAEST v3: Algorithm Specifications, Version 3.0" of
//! 1 September 2026: batch all-but-one vector commitments over a GGM tree, small-VOLE
//! conversion, the CRT-encoded challenge, VOLE-hash consistency checks and the
//! `QuickSilver` polynomial constraint check, bound together by the Fiat-Shamir
//! transcript of that specification.
//!
//! The layers, bottom up: [`field`], [`prg`], [`hash`] and [`universal_hash`];
//! [`bavc`] and [`crt`]; [`vole`]; [`quicksilver`] (the constraint check for a
//! relation written once against a small algebra trait), [`transcript`], [`codec`]
//! and [`randomness`]; and [`proof`], the generic prove and verify entry points for
//! any relation on any supported row. Every random-oracle call can be evaluated
//! inside a caller-chosen [`hash::Namespace`]; the empty prefix is plain FAEST.
//!
//! The [`faest`] module instantiates the backend with the plain FAEST AES
//! one-way-function relation so that every layer can be checked against the official
//! FAEST v3.0.2 reference test vectors (`tests/fixtures/faest_v3_0_2`). When the
//! backend is used with any other relation the result is *FAEST-derived*: it reuses
//! the FAEST proof machinery but is not a standard FAEST signature and must not be
//! described as one.
//!
//! # Determinism and acceleration
//!
//! Every output is a function of the inputs and the caller-supplied randomness only,
//! and is byte-identical across hardware. The default build uses portable code. The
//! `accel` feature enables hardware AES through the patched `aes` crate's `hardware`
//! feature; it changes speed, never bytes.
//!
//! # State
//!
//! The crate holds no state, performs no I/O and reads no configuration or
//! environment. Callers own randomness, persistence and policy.
//!
//! # Safety
//!
//! `unsafe` is forbidden crate-wide.
// TODO: when carry-less-multiply field arithmetic lands behind `accel`, relax the
// crate-wide `forbid` to `deny` and scope `unsafe` to that one intrinsics module.

#![forbid(unsafe_code)]

pub mod bavc;
pub mod codec;
pub mod crt;
pub mod faest;
pub mod field;
pub mod hash;
pub mod params;
pub mod prg;
pub mod proof;
pub mod quicksilver;
pub mod randomness;
pub mod transcript;
pub mod universal_hash;
pub mod vole;

/// Version of the FAEST specification this backend follows.
pub const FAEST_SPECIFICATION_VERSION: &str = "3.0";

#[cfg(test)]
mod tests {
    use super::FAEST_SPECIFICATION_VERSION;

    #[test]
    fn specification_version_is_pinned() {
        assert_eq!(FAEST_SPECIFICATION_VERSION, "3.0");
    }
}
