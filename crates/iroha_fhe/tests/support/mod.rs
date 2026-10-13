//! Shared support of the BGV integration tests: the independent oracle, the
//! vector reader and the costing harness.
//!
//! The oracle and the reader never call the implementation under test. The
//! oracle works on arbitrary-precision integers modulo the full modulus and
//! takes only plain numbers (degree, primes, seeds, words) from a test. The
//! costing harness of [`machine`] is the opposite: it lowers the V1 tape
//! instructions onto the implementation, once over public shapes and once
//! over ciphertexts.
#![allow(
    dead_code,
    reason = "each integration test binary uses its own part of the shared support"
)]

pub mod kat;
pub mod machine;
pub mod oracle;
