//! Immutable representations of the same transparent, natively pinned parameters.

use super::{CurveV1, ParamsTrustError, PastaCurve, PinnedParams};

fn bytes(curve: CurveV1, k: u32) -> Option<&'static [u8]> {
    match (curve, k) {
        (CurveV1::Vesta, 12) => Some(include_bytes!("parameters/vesta-k12.params")),
        (CurveV1::Vesta, 14) => Some(include_bytes!("parameters/vesta-k14.params")),
        (CurveV1::Vesta, 16) => Some(include_bytes!("parameters/vesta-k16.params")),
        (CurveV1::Pallas, 16) => Some(include_bytes!("parameters/pallas-k16.params")),
        _ => None,
    }
}

fn decode_selected<C: PastaCurve>(
    expected: u32,
    bytes: &[u8],
) -> Result<PinnedParams<C>, ParamsTrustError> {
    let header: [u8; 4] = bytes
        .get(..4)
        .and_then(|head| head.try_into().ok())
        .ok_or(ParamsTrustError::MissingHeader)?;
    let actual = u32::from_le_bytes(header);
    if actual != expected {
        return Err(ParamsTrustError::DomainMismatch { expected, actual });
    }
    // Native pins, exact canonical extent and every point remain mandatory.
    // A selected-but-invalid representation never triggers transparent derivation.
    PinnedParams::from_bytes(bytes)
}

impl<C: PastaCurve> PinnedParams<C> {
    /// Obtain exact transparent parameters for the requested domain.
    ///
    /// The finite embedded Vesta k12/k14/k16 and Pallas k16 representations pass
    /// the same native-pinned digest and canonical point decoder as
    /// [`Self::from_bytes`]. Domains without an embedded representation use
    /// [`Self::derive`]. This choice introduces no runtime configuration, file
    /// cache or alternative parameter authority; explicit derivation remains
    /// available for independent generation and parity checks.
    ///
    /// # Errors
    /// An embedded header for another domain, any native pin or decoding failure,
    /// unknown curve, or transparent derivation failure for an unbundled domain.
    /// A selected embedded representation's failure propagates without a retry.
    pub fn for_domain(k: u32) -> Result<Self, ParamsTrustError> {
        let curve = super::super::curve_v1::<C>().ok_or(ParamsTrustError::UnknownCurve)?;
        match bytes(curve, k) {
            Some(bytes) => decode_selected(k, bytes),
            None => Self::derive(k),
        }
    }
}

#[cfg(test)]
mod tests;
