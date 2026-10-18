//! Committed block-start outputs of the anonymous ballot (integration decisions 3 and 9).
//!
//! Each is to be committed as one `BlockResult.outputs` entry, so that the block's output
//! commitment authenticates it; websocket events only project these records. No output
//! names an account or session.
//!
//! TODO: the Core integration adds `ExecutionOutputV1::GovernanceBlockStart` carrying
//! [`GovernanceBlockStartOutputV1`], reserves result capacity before sealing, and fixes the
//! anchor of the casting-clock prelude, which runs outside the pass positions.

use iroha_schema::IntoSchema;
use norito::codec::{Decode, Encode};

use super::{
    BallotBodyContextV1, BallotClosureRecordV1, BallotScopeV1, Digest512,
    SealedCredentialListBytesV1,
};
use crate::{
    DeriveJsonDeserialize, DeriveJsonSerialize,
    governance::{GovernanceAnchorV1, types::BodyInstanceId},
};

/// The G2a sealing transition published the canonical sealed list.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(
    name = "iroha_data_model::governance::anonymous_ballot::SealedCredentialListPublishedV1"
)]
pub struct SealedCredentialListPublishedV1 {
    /// Authoritative body context of the sealed body.
    pub body_context: BallotBodyContextV1,
    /// Sealed body instance, derived from the 64-byte roster root.
    pub body_instance_id: BodyInstanceId,
    /// 64-byte roster root of the extended preimage.
    pub roster_root: Digest512,
    /// Sealed-list digest `R`.
    pub list_digest: Digest512,
    /// Registration-mapping digest of the sealed `(assignment_id, C)` pairs.
    pub registration_mapping_digest: Digest512,
    /// The exact canonical list bytes stored at seal.
    pub sealed_list_bytes: SealedCredentialListBytesV1,
}

/// The G2c opening transition opened casting; the output's anchor is `s0`.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::governance::anonymous_ballot::CastingOpenedV1")]
pub struct CastingOpenedV1 {
    /// Authoritative body context.
    pub body_context: BallotBodyContextV1,
    /// Sealed body instance.
    pub body_instance_id: BodyInstanceId,
    /// Ballot scope.
    pub scope: BallotScopeV1,
    /// `policy_hash` of the frozen policy snapshot.
    pub policy_hash: Digest512,
    /// `opening_at = max(reflection_timestamp_ms, sealed_timestamp_ms + vote_notice_ms)`,
    /// computed once at Reflection; the actual opening may be later.
    pub opening_at_ms: u64,
}

/// The `EstablishCastingClock` prelude at `h_open + 1` froze the closing time; the
/// output's anchor carries that block's height and time.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::governance::anonymous_ballot::CastingClockEstablishedV1")]
pub struct CastingClockEstablishedV1 {
    /// Ballot scope.
    pub scope: BallotScopeV1,
    /// Frozen casting window.
    pub casting_window_ms: u64,
    /// `current_block_timestamp_ms + casting_window_ms`.
    pub closing_ms: u64,
}

/// One committed anonymous-ballot block-start event.
#[expect(
    clippy::large_enum_variant,
    reason = "the committed closure record stays inline in the canonical V1 output; boxing changes Norito and schema"
)]
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(
    tag = "kind",
    content = "detail",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[norito_schema(
    name = "iroha_data_model::governance::anonymous_ballot::GovernanceBlockStartEventV1"
)]
pub enum GovernanceBlockStartEventV1 {
    /// The sealed list was published at seal (G2a).
    #[codec(index = 0)]
    SealedCredentialListPublished(SealedCredentialListPublishedV1),
    /// Casting opened (G2c).
    #[codec(index = 1)]
    CastingOpened(CastingOpenedV1),
    /// The successor-block casting clock was established (prelude).
    #[codec(index = 2)]
    CastingClockEstablished(CastingClockEstablishedV1),
    /// The ballot closed (G2b) with this record.
    #[codec(index = 3)]
    BallotClosed(BallotClosureRecordV1),
}

/// One committed governance block-start output: where in the block-start pass it
/// happened and what happened.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Encode,
    Decode,
    IntoSchema,
    DeriveJsonSerialize,
    DeriveJsonDeserialize,
    norito::NoritoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(
    name = "iroha_data_model::governance::anonymous_ballot::GovernanceBlockStartOutputV1"
)]
pub struct GovernanceBlockStartOutputV1 {
    /// Height, pass position and block time of the transition.
    pub anchor: GovernanceAnchorV1,
    /// The transition's event.
    pub event: GovernanceBlockStartEventV1,
}

#[cfg(test)]
mod tests {
    use norito::codec::{Decode as _, Encode as _};

    use super::*;
    use crate::governance::anonymous_ballot::{
        framing::{decode_enc, enc},
        test_fixtures::{anchor, body_context, closure, sealed_list},
    };

    fn outputs() -> Vec<GovernanceBlockStartOutputV1> {
        let published = SealedCredentialListPublishedV1 {
            body_context: body_context(),
            body_instance_id: BodyInstanceId::new([0x03; 32]),
            roster_root: Digest512::new([0x0a; 64]),
            list_digest: Digest512::new([0x99; 64]),
            registration_mapping_digest: Digest512::new([0x04; 64]),
            sealed_list_bytes: SealedCredentialListBytesV1::from_list(&sealed_list(5))
                .expect("publish"),
        };
        let opened = CastingOpenedV1 {
            body_context: body_context(),
            body_instance_id: BodyInstanceId::new([0x03; 32]),
            scope: BallotScopeV1::new([0x44; 64]),
            policy_hash: Digest512::new([0xaa; 64]),
            opening_at_ms: 999_000,
        };
        let clock = CastingClockEstablishedV1 {
            scope: BallotScopeV1::new([0x44; 64]),
            casting_window_ms: 86_400_000,
            closing_ms: 87_401_000,
        };
        vec![
            GovernanceBlockStartOutputV1 {
                anchor: anchor(90, 1, 900_000),
                event: GovernanceBlockStartEventV1::SealedCredentialListPublished(published),
            },
            GovernanceBlockStartOutputV1 {
                anchor: anchor(100, 2, 1_000_000),
                event: GovernanceBlockStartEventV1::CastingOpened(opened),
            },
            GovernanceBlockStartOutputV1 {
                anchor: anchor(101, 0, 1_001_000),
                event: GovernanceBlockStartEventV1::CastingClockEstablished(clock),
            },
            GovernanceBlockStartOutputV1 {
                anchor: anchor(90_000, 0, 87_401_500),
                event: GovernanceBlockStartEventV1::BallotClosed(closure(9, 6, 2, 1)),
            },
        ]
    }

    #[test]
    fn every_block_start_output_round_trips() {
        for (index, output) in outputs().into_iter().enumerate() {
            let bytes = enc(&output).expect("enc");
            assert_eq!(
                decode_enc::<GovernanceBlockStartOutputV1>(&bytes),
                Ok(output.clone())
            );
            let bare = output.encode();
            assert_eq!(
                GovernanceBlockStartOutputV1::decode(&mut &bare[..]).expect("decode"),
                output
            );
            // The event discriminant is the variant index.
            let event = output.event.encode();
            assert_eq!(
                event[..4],
                u32::try_from(index).expect("small").to_le_bytes()
            );
            let json = norito::json::to_json(&output).expect("json");
            assert_eq!(
                norito::json::from_str::<GovernanceBlockStartOutputV1>(&json).expect("json"),
                output
            );
        }
    }

    #[test]
    fn a_published_list_must_decode_to_a_valid_list() {
        let output = &outputs()[0];
        let GovernanceBlockStartEventV1::SealedCredentialListPublished(published) = &output.event
        else {
            panic!("first output publishes the list");
        };
        assert_eq!(
            published.sealed_list_bytes.decode_list(),
            Ok(sealed_list(5))
        );
        let json = norito::json::to_json(&output.event).expect("json");
        assert!(json.starts_with(r#"{"kind":"sealed_credential_list_published","detail":{"#));
    }
}
