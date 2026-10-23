//! Post-quantum cryptography helpers for the `SoraNet` networking stack.
//!
//! This crate exposes ML-KEM and ML-DSA helpers plus the hedged RNG and HKDF
//! utilities needed by the `SoraNet` handshake.
#![allow(unsafe_code)]
#![deny(missing_docs)]
#[cfg(feature = "pqc")]
pub mod ffi;
mod hkdf;
#[cfg(feature = "pqc")]
mod mldsa;
#[cfg(feature = "pqc")]
mod mlkem;
#[cfg(all(test, feature = "pqc"))]
mod acvp_tests;
#[cfg(all(test, feature = "pqc"))]
mod nistkat_sha256;
mod rng;
#[cfg(not(feature = "pqc"))]
mod wire;
#[cfg(feature = "pqc")]
pub use crate::mldsa::{
    MlDsaError, MlDsaKeyPair, MlDsaSignature, MlDsaSuite, generate_mldsa_keypair,
    generate_mldsa_keypair_from_fips_seed, generate_mldsa_keypair_from_os,
    generate_mldsa_keypair_from_rng, generate_mldsa_keypair_from_seed,
    mldsa_public_key_from_secret_key, sign_mldsa, sign_mldsa_from_os, sign_mldsa_from_rng,
    sign_mldsa65_detached, validate_mldsa_public_key, validate_mldsa_secret_key,
    validate_mldsa_signature, verify_mldsa, verify_mldsa65_detached,
};
#[cfg(feature = "pqc")]
pub use crate::mlkem::{
    MlKemCiphertext, MlKemError, MlKemKeyPair, MlKemMetadata, MlKemParameters, MlKemSharedSecret,
    MlKemSuite, SuiteParseError, decapsulate_mlkem, decapsulate_mlkem_into, encapsulate_mlkem,
    encapsulate_mlkem_from_os, encapsulate_mlkem_from_rng, encapsulate_mlkem_from_seed,
    encapsulate_mlkem_into, generate_mlkem_keypair, generate_mlkem_keypair_from_os,
    generate_mlkem_keypair_from_rng, generate_mlkem_keypair_from_seed, generate_mlkem_keypair_into,
    mlkem_metadata, mlkem_parameters, validate_mlkem_ciphertext, validate_mlkem_key_pair,
    validate_mlkem_public_key, validate_mlkem_secret_key,
};
#[cfg(not(feature = "pqc"))]
pub use crate::wire::{MlDsaSuite, UnsupportedPqcError};
pub use crate::{
    hkdf::{HkdfDomain, HkdfSuite, derive_labeled_hkdf},
    rng::{
        HedgedChaCha20Rng, HedgedEntropyStatus, HedgedRngSeed, RngError,
        deterministic_chacha20_rng, hedged_chacha20_rng, hedged_chacha20_rng_from_os,
        hedged_chacha20_rng_from_rng,
    },
};
