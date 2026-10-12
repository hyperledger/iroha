//! Network-free native SCCP proof preflight and destination encodings (§5, §7, §8).
//!
//! Bundles are verified against an independently observed committee and checkpoint state.
//! Native exact quorums, signed generation continuity and full control leaves share the
//! destination verifier. EVM/TON encoders consume immutable verified originals; transaction
//! signing/export and owner-only key files remain separate from certificate authority.

pub mod bundle;
pub mod control;
pub mod evm;
pub mod rotation;
pub mod ton;

#[cfg(test)]
mod test_support;
