//! Fraud detection, assessment envelopes and committed admission policy.
//!
//! These first-release V1 types carry exact ledger-facing assessment evidence.
//! The committed admission policy is distinct from external scoring and local
//! transport; neither a decoded assessment nor a service response grants authority.
pub mod admission_policy;
pub use admission_policy::*;
pub mod types;
pub use types::*;
