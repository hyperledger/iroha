//! Three source-owned canonical DKG input banks, prepared before a private attempt.
//!
//! TODO: wire these complete phase banks into the source-owned daemon attempt.
//! Native finality journal/index preparation remains a separate open boundary.
//! There is no owned DTO fallback: generated field walks fill existing backing,
//! and extraction follows complete framed canonical comparison only.

use super::*;
use iroha_crypto::{PreparedCryptoDecodeError, PreparedPublicKeyDecode, PreparedSignatureDecode};
use iroha_data_model::consensus::GlobalThresholdBeaconDkgConstantProofV1;
use norito::core::{
    CanonicalField, DecodeField, DecodeIntoError, DecodeRecordFields, Encoder, FieldDestination,
    PayloadRef, PreparedRecordDestination, SequenceDestinationError, SequenceSpan,
    SerializePayload, decode_raw_byte_sequence_into, prepare_element_sequence,
};

mod common;
mod finish;
mod inline;
mod owner;
mod rows;
mod sequence;
mod session;
mod snapshot;
pub use common::GlobalThresholdBeaconInputDestinationErrorV1;
pub use owner::{
    GlobalThresholdBeaconInputErrorV1, PreparedGlobalThresholdBeaconDkgInputsV1,
    PreparedGlobalThresholdBeaconDkgPublicationV1,
    PreparedGlobalThresholdBeaconFinalSessionInputV1,
};

#[cfg(test)]
mod tests;
