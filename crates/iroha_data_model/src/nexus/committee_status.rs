//! Public committee preparation observations with explicit finality attachments.
//!
//! Finality artifacts require an independently trusted signed-genesis network and configured chain.
//! Transcript and readiness fields are progress observations, not standalone finality proofs.

use super::ValidatorCommitteeTransitionV1;
use crate::{
    NetworkId, consensus::GlobalThresholdBeaconKeySessionV1,
    sumeragi::finality::NativeFinalityArtifact,
};
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

/// One selected attempt and the incumbent boundary that froze it.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::nexus::ValidatorCommitteeSelectionStatusV1")]
#[norito(deny_unknown_fields)]
pub struct ValidatorCommitteeSelectionStatusV1 {
    /// Observed preparation, credentials, readiness proofs and optional terminal body.
    pub transition: ValidatorCommitteeTransitionV1,
    /// Exact selecting boundary; its native result must carry the identical preparation.
    pub selecting_finality: NativeFinalityArtifact,
}

/// Exact public inputs for inspecting and preparing a validator committee operation.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Encode,
    Decode,
    IntoSchema,
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito_schema(name = "iroha_data_model::nexus::ValidatorCommitteeStatusV1")]
#[norito(deny_unknown_fields)]
pub struct ValidatorCommitteeStatusV1 {
    /// Exact genesis-derived deployment identity.
    pub network_id: NetworkId,
    /// Explicit requested target, or the current scheduling epoch plus one.
    pub target_epoch: u64,
    /// Latest finalized artifact observed by this server, verified against its Kura block.
    pub latest_finality: NativeFinalityArtifact,
    /// Absence means no frozen attempt exists for the selected target; never readiness.
    #[norito(required)]
    pub selected: Option<ValidatorCommitteeSelectionStatusV1>,
    /// Complete public transcript for the attempt's exact session, when finalized.
    #[norito(required)]
    pub pending_beacon_session: Option<GlobalThresholdBeaconKeySessionV1>,
}
