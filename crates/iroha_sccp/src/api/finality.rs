//! Verification of native read-API certificates against independent caller authority.

use crate::v1::finality::{
    CertificateError, SccpFinalityHeaderV1, VerifiedCertificateV1, verify_certificate,
};
use iroha_data_model::sccp::{committee::SccpCommitteeGenerationV1, finality::SccpCertificateV1};

/// Why an untrusted API certificate does not match the caller's authenticated generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiCertificateError {
    /// The encoded header or exact-quorum native signature is invalid.
    Certificate(CertificateError),
    /// The certificate's outer height does not match the signed height.
    Height,
    /// The native header does not activate SCCP.
    Inactive,
    /// The signed network is not the caller's pinned network.
    Network,
    /// The header names another generation or committee root.
    Generation,
    /// Supplied keys differ from the independently authenticated ordered committee.
    Committee,
    /// Height or time is outside that retained generation's original tenure.
    Tenure,
    /// A rotation does not match the authenticated generation's exact end.
    Rotation,
}

impl core::fmt::Display for ApiCertificateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Certificate(error) => write!(f, "native certificate: {error}"),
            Self::Height => f.write_str("certificate height differs from signed height"),
            Self::Inactive => f.write_str("certificate does not activate SCCP"),
            Self::Network => f.write_str("certificate belongs to another network"),
            Self::Generation => f.write_str("certificate belongs to another generation"),
            Self::Committee => f.write_str("certificate keys differ from authenticated committee"),
            Self::Tenure => f.write_str("certificate is outside its generation tenure"),
            Self::Rotation => f.write_str("rotation differs from authenticated generation end"),
        }
    }
}

impl std::error::Error for ApiCertificateError {}

/// Verify a certificate with the caller's independent native authority.
///
/// `generation` must come from the caller's authenticated committed state, never from another
/// field in the same untrusted response. Decoding a
/// generation DTO does not authenticate it. The consensus instance is likewise pinned by the
/// caller. This establishes finality; message inclusion, destination state and expiry still
/// require their separate checks before submission.
///
/// # Errors
/// Rejects mismatched claims, inactive headers, out-of-tenure coordinates and invalid CommitQCs.
pub fn verify_native_certificate(
    certificate: &SccpCertificateV1,
    network_id: &[u8; 32],
    consensus_instance: &[u8; 32],
    generation: &SccpCommitteeGenerationV1,
) -> Result<VerifiedCertificateV1, ApiCertificateError> {
    let header = SccpFinalityHeaderV1::parse(&certificate.header)
        .map_err(|error| ApiCertificateError::Certificate(error.into()))?;
    if certificate.height != header.height() {
        return Err(ApiCertificateError::Height);
    }
    if !header.is_active() {
        return Err(ApiCertificateError::Inactive);
    }
    if header.network_id() != *network_id {
        return Err(ApiCertificateError::Network);
    }
    if header.generation() != generation.generation
        || header.committee_root() != generation.committee_root
    {
        return Err(ApiCertificateError::Generation);
    }
    if certificate.committee != generation.keys {
        return Err(ApiCertificateError::Committee);
    }
    if header.height() < generation.start_height
        || header.timestamp_ms() < generation.start_timestamp_ms
        || generation.end.is_some_and(|end| {
            header.height() > end.end_height || header.timestamp_ms() > end.end_timestamp_ms
        })
    {
        return Err(ApiCertificateError::Tenure);
    }
    if header.is_rotation()
        && !generation.end.is_some_and(|end| {
            header.height() == end.end_height
                && header.timestamp_ms() == end.end_timestamp_ms
                && header.next_committee_root() == end.next_committee_root
                && header.validity_ms() == end.successor_validity_ms
        })
    {
        return Err(ApiCertificateError::Rotation);
    }
    verify_certificate(
        consensus_instance,
        &certificate.qc,
        &certificate.header,
        &certificate.aggregate_signature,
        &generation.keys,
    )
    .map_err(ApiCertificateError::Certificate)
}

#[cfg(test)]
mod tests;
