//! Native SCCP committee pins and forgery evidence DATA (`specs/sccp.md` §§4.9–4.14).
//!
//! These records carry exact original bytes and immutable generation attribution. Decoding or
//! passing a shape check never authenticates a committee, certificate, anchor or offender.
//! Core must join the retained generation, verify the exact native CommitQC relation, select
//! the first E1–E4 mismatch and apply deduplication before recording any evidence or hold.

use crate::{DeriveJsonDeserialize, DeriveJsonSerialize, account::AccountId};
use iroha_model_base::topology::LaneId;
use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

/// Depth of the fixed 4096-height closed anchor chunk.
pub const SCCP_ANCHOR_PATH_DEPTH_V1: usize = 12;

/// Deployment's independently authenticated initial native committee (§4.14.1).
///
/// Registration must match all four fields to the retained generation and check every
/// intervening deadline, member attribution and destination deployment. This is DATA, not
/// a constructor for authenticated authority.
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
#[norito(no_fast_from_json, decode_from_slice, deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::sccp::native::SccpCommitteePinV1")]
pub struct SccpCommitteePinV1 {
    /// Retained generation, starting at one.
    pub generation: u64,
    /// Exact native committee root of that generation.
    pub committee_root: [u8; 32],
    /// Generation's first certified height.
    pub start_height: u64,
    /// Generation's pinned wall-clock deadline, in milliseconds.
    pub until_ms: u64,
}

impl SccpCommitteePinV1 {
    /// Check the state-independent shape only; no signature or retained-state join is made.
    pub fn validate_shape(&self) -> Result<(), SccpNativeDataError> {
        if self.generation == 0 || self.start_height == 0 || self.until_ms == 0 {
            return Err(SccpNativeDataError::ZeroPinCoordinate);
        }
        if self.committee_root == [0; 32] {
            return Err(SccpNativeDataError::ZeroCommitteeRoot);
        }
        Ok(())
    }
}

/// Original block anchor and fixed-depth membership path for a completed chunk (§4.9).
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
#[norito(no_fast_from_json, decode_from_slice, deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::sccp::native::SccpAnchorWitnessV1")]
pub struct SccpAnchorWitnessV1 {
    /// Original committed block's native core hash.
    pub core_hash: [u8; 32],
    /// Exact raw certified result `R`, without Iroha Hash normalization.
    pub result: [u8; 32],
    /// Bottom-up siblings for the 4096-height chunk containing the signed height.
    #[norito(
        with = "anchor_path_json",
        bounded_with = "anchor_path_json::serialize_bounded"
    )]
    pub path: [[u8; 32]; SCCP_ANCHOR_PATH_DEPTH_V1],
}

/// JSON projection of the fixed-depth path, retaining the binary fixed-array layout.
mod anchor_path_json {
    use super::SCCP_ANCHOR_PATH_DEPTH_V1;
    use norito::json::{
        self, BoundedJsonError, JsonDeserialize, JsonSerialize, JsonWriteSink, Parser,
    };

    /// Write exactly twelve canonical hexadecimal siblings.
    pub fn serialize(path: &[[u8; 32]; SCCP_ANCHOR_PATH_DEPTH_V1], out: &mut String) {
        out.push('[');
        for (index, sibling) in path.iter().enumerate() {
            if index != 0 {
                out.push(',');
            }
            sibling.json_serialize(out);
        }
        out.push(']');
    }

    /// Write the fixed path through the caller's byte and nesting budget.
    pub fn serialize_bounded(
        path: &[[u8; 32]; SCCP_ANCHOR_PATH_DEPTH_V1],
        out: &mut dyn JsonWriteSink,
    ) -> Result<(), BoundedJsonError> {
        out.begin_container()?;
        let result = (|| {
            out.push('[')?;
            for (index, sibling) in path.iter().enumerate() {
                if index != 0 {
                    out.push(',')?;
                }
                sibling.json_serialize_to(out)?;
            }
            out.push(']')
        })();
        out.end_container();
        result
    }

    /// Decode directly into fixed storage, rejecting missing or additional siblings.
    pub fn deserialize(
        parser: &mut Parser<'_>,
    ) -> Result<[[u8; 32]; SCCP_ANCHOR_PATH_DEPTH_V1], json::Error> {
        parser.expect(b'[')?;
        let mut path = [[0; 32]; SCCP_ANCHOR_PATH_DEPTH_V1];
        for (index, sibling) in path.iter_mut().enumerate() {
            if index != 0 {
                parser.expect(b',')?;
            }
            *sibling = <[u8; 32]>::json_deserialize(parser)?;
        }
        parser.expect(b']')?;
        Ok(path)
    }
}

/// First satisfied forgery mismatch rule; precedence is E1, E2, E3, E4 (§4.9 step 5).
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
#[norito(no_fast_from_json, decode_from_slice, deny_unknown_fields)]
#[norito(tag = "rule", content = "detail")]
#[norito_schema(name = "iroha_data_model::sccp::native::SccpForgeryRuleV1")]
pub enum SccpForgeryRuleV1 {
    /// Signed height lies outside the retained generation's tenure.
    #[codec(index = 0)]
    E1,
    /// Signed height is at or beyond the executing block's height.
    #[codec(index = 1)]
    E2,
    /// Signature names a different block from the original height anchor.
    #[codec(index = 2)]
    E3,
    /// Original block hash matches, but the raw certified result differs.
    #[codec(index = 3)]
    E4,
}

/// One new slashable signer, attributed through the immutable generation membership (§4.9).
#[derive(
    Debug,
    Clone,
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
#[norito(no_fast_from_json, decode_from_slice, deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::sccp::native::SccpForgeryOffenderV1")]
pub struct SccpForgeryOffenderV1 {
    /// Index in the generation's ordered key and member arrays.
    pub signer: u32,
    /// Staking lane of the original registration.
    pub lane_id: LaneId,
    /// Canonical validator account of the original registration.
    pub validator: AccountId,
    /// Exact activation height of that registration; never a later peer-key lookup.
    pub activation_height: u64,
}

/// Permanent committed SCCP evidence and immutable attribution (§4.9 step 8).
///
/// The signed height is deliberately not the penalty-liability height. The latter is
/// `start_height`, pinned from the retained generation, and the penalty delay begins at the
/// enclosing evidence record's `recorded_at_height`. Offenders are only newly deduplicated
/// members, so their count need not equal the certificate's exact voting quorum.
#[derive(
    Debug,
    Clone,
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
#[norito(no_fast_from_json, decode_from_slice, deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::sccp::native::SccpForgeryRecordV1")]
pub struct SccpForgeryRecordV1 {
    /// Exact submitted certificate and optional original anchor witness.
    pub evidence: crate::isi::sccp::SubmitSccpForgeryEvidenceV1,
    /// First mismatch established by admission.
    pub rule: SccpForgeryRuleV1,
    /// Independently authenticated retained generation.
    pub generation: u64,
    /// Original generation's first height, used for penalty liability.
    pub start_height: u64,
    /// Newly deduplicated slashable members, in increasing signer order.
    pub offenders: Vec<SccpForgeryOffenderV1>,
}

impl SccpForgeryRecordV1 {
    /// Check structural invariants without accepting a signature or inventing attribution.
    pub fn validate_shape(&self) -> Result<(), SccpNativeDataError> {
        if self.generation == 0 || self.start_height == 0 {
            return Err(SccpNativeDataError::ZeroGenerationCoordinate);
        }
        let maximum = crate::block::consensus::MAX_VALIDATORS_PER_HEIGHT;
        if self.offenders.is_empty() || self.offenders.len() > maximum {
            return Err(SccpNativeDataError::OffenderCount);
        }
        for (index, offender) in self.offenders.iter().enumerate() {
            if !usize::try_from(offender.signer).is_ok_and(|signer| signer < maximum) {
                return Err(SccpNativeDataError::SignerOutOfRange);
            }
            if index > 0 && self.offenders[index - 1].signer >= offender.signer {
                return Err(SccpNativeDataError::OffenderOrder);
            }
            if offender.activation_height == 0 || offender.activation_height > self.start_height {
                return Err(SccpNativeDataError::ActivationHeight);
            }
            if self.offenders[..index].iter().any(|previous| {
                previous.lane_id == offender.lane_id && previous.validator == offender.validator
            }) {
                return Err(SccpNativeDataError::DuplicateOffender);
            }
        }
        Ok(())
    }
}

/// Permanent Parliament quarantine; neither a higher floor nor reconciliation removes it.
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
#[norito(no_fast_from_json, decode_from_slice, deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::sccp::native::SccpQuarantineV1")]
pub struct SccpQuarantineV1 {
    /// Exact enacted Parliament certificate.
    pub certificate_id: [u8; 32],
    /// Canonical enactment height.
    pub since_height: u64,
}

/// A state-independent native SCCP DATA invariant failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SccpNativeDataError {
    /// Deployment pins cannot name generation, height or deadline zero.
    #[error("SCCP committee pin contains a zero generation, height or deadline")]
    ZeroPinCoordinate,
    /// Native committee roots cannot be zero.
    #[error("SCCP committee pin contains a zero committee root")]
    ZeroCommitteeRoot,
    /// Evidence must name a real generation and its first height.
    #[error("SCCP forgery record contains a zero generation or start height")]
    ZeroGenerationCoordinate,
    /// A committed report has one to 31 newly slashable members.
    #[error("SCCP forgery offender count is outside 1..=31")]
    OffenderCount,
    /// Signer index is outside every admitted committee.
    #[error("SCCP forgery signer index is outside 0..31")]
    SignerOutOfRange,
    /// Signers are duplicated or not in increasing order.
    #[error("SCCP forgery offenders are not in strictly increasing signer order")]
    OffenderOrder,
    /// Attribution predates no registration or names a registration activated after the generation.
    #[error("SCCP forgery activation height must lie in 1..=start_height")]
    ActivationHeight,
    /// Deduplication must not repeat a lane/validator within a record.
    #[error("SCCP forgery record repeats a lane and validator")]
    DuplicateOffender,
}

#[cfg(test)]
mod tests;
