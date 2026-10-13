//! Canonical fixed-capacity native control codecs, separate from transaction payload bytes.

use iroha_data_model::consensus::{
    FinalizedGlobalThresholdBeaconPulseV1 as Pulse,
    GlobalThresholdBeaconPartialSignatureV1 as Partial,
};
use iroha_sumeragi::types::{ControlWitness, MAX_CONTROL_WITNESS_BYTES};

/// Malformed canonical control data or an exact signed-header/result mismatch.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ControlCodecError {
    /// A schema, codec, canonical framing or bounded encoding check failed.
    #[error("invalid canonical native control frame: {0}")]
    Encoding(#[from] norito::Error),
    /// The executed result did not consume the exact signed header witness.
    #[error("native header control witness differs from the executed result")]
    ResultMismatch,
}

fn limits() -> norito::DecodeLimits {
    norito::DecodeLimits::new(
        MAX_CONTROL_WITNESS_BYTES,
        MAX_CONTROL_WITNESS_BYTES,
        MAX_CONTROL_WITNESS_BYTES * 2,
        MAX_CONTROL_WITNESS_BYTES * 2,
        16,
    )
}

/// Stream the exact Pulse frame into inline header storage. No heap Vec is constructed.
pub(crate) fn encode(pulse: Option<&Pulse>) -> Result<ControlWitness, ControlCodecError> {
    let mut witness = ControlWitness::empty();
    if let Some(pulse) = pulse {
        norito::core::write_canonical_to_writer(pulse, &mut witness)?;
    }
    Ok(witness)
}

/// Decode only the single current canonical Pulse frame. Empty bytes carry no witness;
/// the pristine source verifier must independently require or prohibit that absence.
pub(crate) fn decode(witness: &ControlWitness) -> Result<Option<Pulse>, ControlCodecError> {
    if witness.is_empty() {
        return Ok(None);
    }
    norito::decode_canonical_with_limits(witness.as_slice(), limits())
        .map(Some)
        .map_err(Into::into)
}

/// Bind historical/follower R to exactly the bytes signed in its native header.
pub(crate) fn verify_result(
    witness: &ControlWitness,
    pulse: Option<&Pulse>,
) -> Result<(), ControlCodecError> {
    if decode(witness)?.as_ref() != pulse {
        return Err(ControlCodecError::ResultMismatch);
    }
    Ok(())
}

/// Canonical sideframe for an actual proof-carrying share; never a finalized header witness.
pub(crate) fn encode_partial(partial: &Partial) -> Result<ControlWitness, ControlCodecError> {
    let mut bytes = ControlWitness::empty();
    norito::core::write_canonical_to_writer(partial, &mut bytes)?;
    Ok(bytes)
}

/// Bounded exact decoder for the sole native producer's application-control sideframe.
pub(crate) fn decode_partial(bytes: &ControlWitness) -> Result<Partial, ControlCodecError> {
    norito::decode_canonical_with_limits(bytes.as_slice(), limits()).map_err(Into::into)
}
