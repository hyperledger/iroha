//! Verifier-owned strict-DER resource limits.
//!
//! These limits define fixed admission and numeric-verifier topology and
//! therefore remain present in every node build. The native reference parser
//! and witness construction that consume them are release-evidence tooling.
/// Maximum bytes in one certificate or CRL DER document.
pub const ZK_X509_DER_MAX_DOCUMENT_BYTES_V1: usize = 16 * 1024;
/// Maximum content bytes in one DER value.
#[cfg(any(test, feature = "privacy-release-evidence"))]
pub const ZK_X509_DER_MAX_VALUE_BYTES_V1: usize = 16 * 1024;
/// Maximum constructed-value nesting depth, counting the top-level value.
pub const ZK_X509_DER_MAX_NESTING_DEPTH_V1: usize = 16;
/// Maximum number of DER values in one recursively validated document.
pub const ZK_X509_DER_MAX_VALUES_V1: usize = 2_048;
