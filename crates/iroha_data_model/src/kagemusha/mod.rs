//! KAGEMUSHA wallet wire data model.
//!
//! The sole KAGEMUSHA family is the split-lineage wallet wire in [`kagemusha_wallet_v1`]
//! (`specs/kagemusha_wallet_wire_v1.md`). Decoding a wallet object grants no money.

pub mod kagemusha_wallet_v1;
pub use kagemusha_wallet_v1::*;

/// Issuer-authenticated pre-key authorization, separate from monetary wallet objects.
pub mod kagemusha_enrollment_permit_v1;
pub use kagemusha_enrollment_permit_v1::*;

/// Bank or scheme-operator enrollment eligibility observations.
pub mod enrollment_eligibility_v1;
pub use enrollment_eligibility_v1::*;
