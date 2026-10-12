//! Native SCCP committee generation records (`specs/sccp.md` §4.2 and §4.8).
//!
//! These are structural snapshot claims, not finality authority. Decoding does not authenticate
//! a generation. Writers and restorers must validate the records and independently establish
//! their original signed-genesis or certified-epoch provenance. Runtime owners retain that
//! provenance and fund the stored graph; this module defines no fallback attestation format.

use super::params::{
    SCCP_MAX_DESTINATION_PROGRESS_CAP_MS_V1, SCCP_MAX_FORGERY_EVIDENCE_GRACE_MS_V1,
    SCCP_MAX_VALIDITY_MS_V1, SCCP_MIN_FORGERY_EVIDENCE_GRACE_MS_V1, SccpParametersError,
    SccpParametersV1,
};
use crate::{
    DeriveJsonDeserialize, DeriveJsonSerialize, account::AccountId,
    block::consensus::is_valid_committee_size, sumeragi::epoch::ValidatorEpochContextV1,
    sumeragi_finality::certified_result::committee_root,
};
use iroha_crypto::Algorithm;
use iroha_model_base::topology::LaneId;
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

macro_rules! record {
    ($(#[$meta:meta])* pub struct $name:ident { $($fields:tt)* }) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Decode, Encode,
            IntoSchema, DeriveJsonSerialize, DeriveJsonDeserialize, norito::NoritoSchema)]
        #[norito(no_fast_from_json)]
        #[norito(decode_from_slice)]
        #[norito(deny_unknown_fields)]
        $(#[$meta])*
        pub struct $name { $($fields)* }
    };
}

/// The only causes of a native SCCP generation (§4.2.2 G1–G3/G7).
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Decode,
    Encode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(no_fast_from_json)]
#[norito(decode_from_slice)]
#[norito(deny_unknown_fields)]
#[norito(tag = "cause", content = "detail")]
#[norito_schema(name = "iroha_data_model::sccp::committee::SccpGenerationCauseV1")]
pub enum SccpGenerationCauseV1 {
    /// Original signed genesis committee.
    #[codec(index = 0)]
    Genesis,
    /// An incumbent-certified epoch boundary changes the keys.
    #[codec(index = 1)]
    KeyChange,
    /// The heartbeat renews the same keys with a new immutable deadline.
    #[codec(index = 2)]
    Heartbeat,
    /// Authenticated current keys recover a boundary missed while SCCP was degraded.
    #[codec(index = 3)]
    Resync,
}

record! {
    /// Exact validator tenure resolved when a generation is created; never looked up again.
    #[norito_schema(name = "iroha_data_model::sccp::committee::SccpGenerationMemberV1")]
    pub struct SccpGenerationMemberV1 {
        /// Staking-storage lane of the selected validator.
        pub lane_id: LaneId,
        /// Canonical domainless validator account.
        pub validator: AccountId,
        /// First height of the exact retained registration.
        pub activation_height: u64,
    }
}

record! {
    /// Immutable end of a generation; a resync has no predecessor handoff certificate.
    #[derive(Copy)]
    #[norito_schema(name = "iroha_data_model::sccp::committee::SccpGenerationEndV1")]
    pub struct SccpGenerationEndV1 {
        /// Last height belonging to this generation.
        pub end_height: u64,
        /// Time of that height, from its original execution.
        pub end_timestamp_ms: u64,
        /// Root of the successor's exact ordered keys.
        pub next_committee_root: [u8; 32],
        /// Creation-time validity of the successor.
        pub successor_validity_ms: u64,
    }
}

record! {
    /// One destination trust window over an immutable ordered native committee.
    #[norito_schema(name = "iroha_data_model::sccp::committee::SccpCommitteeGenerationV1")]
    pub struct SccpCommitteeGenerationV1 {
        /// Monotonic SCCP generation, starting at one (distinct from native epoch numbering).
        pub generation: u64,
        /// Canonical Keccak committee root over `keys`.
        pub committee_root: [u8; 32],
        /// Strictly ascending compressed subgroup BLS-normal keys, exactly `3f + 1`.
        pub keys: Vec<[u8; 48]>,
        /// Tenure at each key's bitmap index; unresolved keys remain explicitly `None`.
        pub members: Vec<Option<SccpGenerationMemberV1>>,
        /// Creation trigger.
        pub cause: SccpGenerationCauseV1,
        /// First height signed by this generation.
        pub start_height: u64,
        /// Genesis/handoff/resync time that starts its destination trust window.
        pub start_timestamp_ms: u64,
        /// Liability clock at creation.
        pub start_lc: u64,
        /// Creation-time validity; later parameter changes cannot renew it.
        pub validity_ms: u64,
        /// Exactly `start_timestamp_ms + validity_ms`.
        pub deadline_ms: u64,
        /// Creation-time evidence grace.
        pub grace_ms: u64,
        /// Creation-time maximum additional destination-progress wait.
        pub progress_cap_ms: u64,
        /// Exactly `start_lc + validity_ms + grace_ms`.
        pub liable_until_lc: u64,
        /// Liability clock when all relevant destination chains passed this deadline.
        pub dest_cleared_lc: Option<u64>,
        /// Absent for the current generation until it ends.
        pub end: Option<SccpGenerationEndV1>,
    }
}

record! {
    /// Original native parent execution identity, recorded by A1; decoding grants no authority.
    #[derive(Copy)]
    #[norito_schema(name = "iroha_data_model::sccp::committee::SccpAnchorV1")]
    pub struct SccpAnchorV1 {
        /// Sumeragi core block hash, not the Iroha block-header hash.
        pub core_hash: [u8; 32],
        /// Exact raw certified result bytes.
        pub result: [u8; 32],
    }
}

/// Creation coordinates supplied by the original generation transition; not a wire authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SccpGenerationStartV1 {
    /// Monotonic SCCP generation.
    pub generation: u64,
    /// Normative transition cause.
    pub cause: SccpGenerationCauseV1,
    /// First height of the generation.
    pub height: u64,
    /// Handoff/genesis/resync time.
    pub timestamp_ms: u64,
    /// Liability clock of that transition.
    pub liability_clock: u64,
}

/// Structural generation refusal; it says nothing about certificate provenance.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SccpGenerationError {
    /// A stored field or relation violates the canonical shape.
    #[error("invalid SCCP generation field: {0}")]
    Field(&'static str),
    /// Creation arithmetic cannot fit the canonical unsigned fields.
    #[error("SCCP generation time arithmetic overflows")]
    Overflow,
    /// The supplied epoch does not validate its own structure and original PoPs.
    #[error("invalid native epoch for SCCP generation: {0}")]
    Epoch(String),
    /// The supplied creation parameters violate their self-contained consensus rules.
    #[error("invalid SCCP creation parameters: {0}")]
    Parameters(SccpParametersError),
}

impl SccpCommitteeGenerationV1 {
    /// Copy creation facts from the exact original epoch and already resolved tenure bindings.
    ///
    /// Epoch validation includes its original ordered PoPs, but is not finality authentication.
    /// The caller must retain signed-genesis or incumbent-certificate authority independently.
    /// The returned value is a DTO; a runtime store must fund and retain its complete graph.
    ///
    /// # Errors
    /// Rejects malformed epoch credentials, out-of-epoch start, invalid fields and overflow.
    pub fn from_epoch(
        start: SccpGenerationStartV1,
        parameters: &SccpParametersV1,
        epoch: &ValidatorEpochContextV1,
        members: Vec<Option<SccpGenerationMemberV1>>,
    ) -> Result<Self, SccpGenerationError> {
        let keys = epoch
            .committee
            .iter()
            .map(|member| {
                let (algorithm, bytes) = member
                    .validator
                    .public_key()
                    .try_to_bytes()
                    .map_err(|_| SccpGenerationError::Field("keys"))?;
                if algorithm != Algorithm::BlsNormal {
                    return Err(SccpGenerationError::Field("keys"));
                }
                bytes
                    .try_into()
                    .map_err(|_| SccpGenerationError::Field("keys"))
            })
            .collect::<Result<Vec<[u8; 48]>, _>>()?;
        Self::from_owned_parts(start, parameters, epoch, keys, members)
    }

    /// Move already funded key/member buffers into the canonical creation record.
    ///
    /// The keys must exactly match the supplied original epoch in order. This seam neither
    /// allocates nor clones those buffers; epoch validation does not authenticate finality,
    /// and the caller remains responsible for original authority and allocation custody.
    ///
    /// # Errors
    /// Rejects invalid epoch/parameters, substituted keys, out-of-epoch start and bad fields.
    pub fn from_owned_parts(
        start: SccpGenerationStartV1,
        parameters: &SccpParametersV1,
        epoch: &ValidatorEpochContextV1,
        keys: Vec<[u8; 48]>,
        members: Vec<Option<SccpGenerationMemberV1>>,
    ) -> Result<Self, SccpGenerationError> {
        parameters
            .validate()
            .map_err(SccpGenerationError::Parameters)?;
        epoch.validate().map_err(SccpGenerationError::Epoch)?;
        if start.height < epoch.authorization.first_height
            || start.height > epoch.authorization.last_height
        {
            return Err(SccpGenerationError::Field("start_height"));
        }
        if keys.len() != epoch.committee.len()
            || keys.iter().zip(&epoch.committee).any(|(key, member)| {
                member
                    .validator
                    .public_key()
                    .try_to_bytes()
                    .map_or(true, |(algorithm, bytes)| {
                        algorithm != Algorithm::BlsNormal || bytes != key.as_slice()
                    })
            })
        {
            return Err(SccpGenerationError::Field("original_epoch_keys"));
        }
        let deadline_ms = start
            .timestamp_ms
            .checked_add(parameters.committee_validity_ms)
            .ok_or(SccpGenerationError::Overflow)?;
        let liable_until_lc = start
            .liability_clock
            .checked_add(parameters.committee_validity_ms)
            .and_then(|value| value.checked_add(parameters.forgery_evidence_grace_ms))
            .ok_or(SccpGenerationError::Overflow)?;
        let value = Self {
            generation: start.generation,
            committee_root: committee_root(&keys).ok_or(SccpGenerationError::Field("keys"))?,
            keys,
            members,
            cause: start.cause,
            start_height: start.height,
            start_timestamp_ms: start.timestamp_ms,
            start_lc: start.liability_clock,
            validity_ms: parameters.committee_validity_ms,
            deadline_ms,
            grace_ms: parameters.forgery_evidence_grace_ms,
            progress_cap_ms: parameters.destination_progress_cap_ms,
            liable_until_lc,
            dest_cleared_lc: None,
            end: None,
        };
        value.validate()?;
        Ok(value)
    }

    /// Validate a decoded record before storage; this does not authenticate its provenance.
    ///
    /// # Errors
    /// Rejects invalid geometry/order/points, root/member mismatch and inconsistent time facts.
    pub fn validate(&self) -> Result<(), SccpGenerationError> {
        let field = |name| SccpGenerationError::Field(name);
        if self.generation == 0
            || self.start_height == 0
            || (self.cause == SccpGenerationCauseV1::Genesis) != (self.generation == 1)
            || (self.generation > 1 && self.start_height == 1)
            || (self.cause == SccpGenerationCauseV1::Genesis
                && (self.start_height != 1 || self.start_lc != self.start_timestamp_ms))
        {
            return Err(field("generation"));
        }
        if !is_valid_committee_size(self.keys.len())
            || self.keys.windows(2).any(|pair| pair[0] >= pair[1])
            || self
                .keys
                .iter()
                .any(|key| !iroha_crypto::bls::consensus::key_validate(key))
        {
            return Err(field("keys"));
        }
        if committee_root(&self.keys) != Some(self.committee_root) {
            return Err(field("committee_root"));
        }
        if self.members.len() != self.keys.len() {
            return Err(field("members"));
        }
        for (index, member) in self.members.iter().enumerate() {
            if let Some(member) = member {
                if member.lane_id != LaneId::SINGLE
                    || member.activation_height > self.start_height
                    || self.members[..index]
                        .iter()
                        .flatten()
                        .any(|prior| prior.validator == member.validator)
                {
                    return Err(field("members"));
                }
            }
        }
        if self.start_lc > self.start_timestamp_ms
            || self.validity_ms == 0
            || self.validity_ms > SCCP_MAX_VALIDITY_MS_V1
            || !(SCCP_MIN_FORGERY_EVIDENCE_GRACE_MS_V1..=SCCP_MAX_FORGERY_EVIDENCE_GRACE_MS_V1)
                .contains(&self.grace_ms)
            || self.progress_cap_ms > SCCP_MAX_DESTINATION_PROGRESS_CAP_MS_V1
            || self.start_timestamp_ms.checked_add(self.validity_ms) != Some(self.deadline_ms)
            || self
                .start_lc
                .checked_add(self.validity_ms)
                .and_then(|v| v.checked_add(self.grace_ms))
                != Some(self.liable_until_lc)
        {
            return Err(field("time"));
        }
        if let Some(end) = self.end {
            if end.end_height < self.start_height
                || end.end_timestamp_ms < self.start_timestamp_ms
                || end.next_committee_root == [0; 32]
                || end.successor_validity_ms == 0
                || end.successor_validity_ms > SCCP_MAX_VALIDITY_MS_V1
            {
                return Err(field("end"));
            }
        }
        if self
            .dest_cleared_lc
            .is_some_and(|clock| self.end.is_none() || clock < self.start_lc)
        {
            return Err(field("dest_cleared_lc"));
        }
        Ok(())
    }

    /// Inclusive §4.8 liability predicate for an already validated record.
    ///
    /// Wider arithmetic preserves the exact predicate even when a window exceeds `u64::MAX`.
    /// The original caller supplies one frozen current-generation/clock cut for the block.
    #[must_use]
    pub fn liable_at(&self, current_generation: u64, liability_clock: u64) -> bool {
        let clock = u128::from(liability_clock);
        self.generation == current_generation
            || liability_clock <= self.liable_until_lc
            || match self.dest_cleared_lc {
                None => {
                    clock <= u128::from(self.liable_until_lc) + u128::from(self.progress_cap_ms)
                }
                Some(cleared) => clock <= u128::from(cleared) + u128::from(self.grace_ms),
            }
    }
}

#[cfg(test)]
#[path = "committee/tests.rs"]
mod tests;
