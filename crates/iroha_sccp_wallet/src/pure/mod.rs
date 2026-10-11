//! Network-free SCCP wallet primitives (spec §7, §8).
//!
//! Everything here is deterministic and free of I/O, so SDK bridges can export it over FFI:
//!
//! - [`bundle`]: message proof bundles verified against a destination's roster state, with the
//!   signature set trimmed to exactly `t`;
//! - [`rotation`]: roster rotation chains verified against every §5.1.5 bound and split into
//!   `rotateRosters` batches;
//! - [`control`]: Parliament control bundles and the §7.1 control decisions;
//! - [`evm`]: EVM calldata, EIP-1559 transactions and signing, unsigned export and owner-only key
//!   files; [`ton`] holds the TON destination encodings.

pub mod bundle;
pub mod control;
pub mod evm;
pub mod rotation;
pub mod ton;
