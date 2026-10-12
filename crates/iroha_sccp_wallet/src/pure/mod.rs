//! Network-free SCCP wallet primitives (spec §7, §8).
//!
//! Everything here is deterministic and free of I/O, so SDK bridges can export it over FFI:
//!
//! - [`bundle`]: native certificate and block/history proofs against the selected destination's
//!   original current committee, stored checkpoints and clock;
//! - [`rotation`]: signed committee handoffs with exact quorum, Live, latch and trust-deadline
//!   checks, split into current `submitCheckpoints` batches;
//! - [`control`]: two-track pause proofs and required newest-control ordering;
//! - [`evm`]: EVM calldata, EIP-1559 transactions and signing, unsigned export and owner-only key
//!   files; [`ton`] holds the TON destination encodings.

pub mod bundle;
pub mod control;
pub mod evm;
pub mod rotation;
pub mod ton;

#[cfg(test)]
#[path = "../../tests/support/current.rs"]
mod test_support;
