//! Committed governance block-start outputs (integration decisions 3 and 9, lifecycle
//! decisions D and H).
//!
//! Each output is to be committed as one `BlockResult.outputs` row, so that the block's
//! output commitment authenticates it; websocket events only project these records. No
//! output names an account or session.
//!
//! A row's anchor is where it happened ([`GovernanceOutputAnchorV1`]): a positioned item of
//! the shared G1–G3 pass carries its [`GovernanceAnchorV1`]; the mandatory
//! `EstablishCastingClock` prelude, which runs after S0 outside the pass positions, carries a
//! typed height and time instead of a fabricated position. Only
//! [`GovernanceBlockStartEventV1::CastingClockEstablished`] uses the prelude anchor, and it
//! always does ([`GovernanceBlockStartOutputV1::validate`]).
//!
//! The governance-start output partition of one block reserves
//! [`GOVERNANCE_START_OUTPUT_BYTES_V1`] complete encoded row bytes in at most
//! [`GOVERNANCE_START_OUTPUT_ROWS_V1`] rows, independently of the work budget. A positioned
//! Parliament item emits at most [`GOVERNANCE_START_ROWS_PER_ITEM_V1`] rows: a compact
//! lifecycle receipt of at most [`LIFECYCLE_RECEIPT_ROW_MAX_BYTES_V1`] bytes first, then one
//! richer ballot output of at most [`GOVERNANCE_START_ROW_MAX_BYTES_V1`] bytes; a prelude
//! clock row is at most [`CASTING_CLOCK_ROW_MAX_BYTES_V1`] bytes. Even all sixteen mandatory
//! prelude rows leave room for one maximal item.
//!
//! TODO: the Core integration adds `ExecutionOutputV1::GovernanceBlockStart` carrying
//! [`GovernanceBlockStartOutputV1`] and `ExecutionOutputPhase::GovernanceStart`, ordered
//! before the Network, Pipeline and Time rows, reserves the partition before mutation
//! (mandatory prelude capacity included) so that state mutation and publication commit or
//! roll back together, validates the genesis output and executed-wire envelopes against the
//! partition in addition to the existing mandatory capacities, and measures each limit on the
//! complete `ExecutionOutputV1` row frame.
//!
//! TODO: the compact `LifecycleApplied` and `NativeSlotAdvanced` receipt events of every
//! positioned Parliament item (the item, the affected entities, their resulting statuses and
//! the relevant state and evidence digests, never candidate snapshots; one receipt covering
//! all atomic effects of a composite item) are defined with Core's pass item types in the
//! next integration phase, as further [`GovernanceBlockStartEventV1`] variants.

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

/// Complete encoded row bytes of the governance-start output partition of one block.
pub const GOVERNANCE_START_OUTPUT_BYTES_V1: u64 = 1_048_576;

/// Rows of the governance-start output partition of one block.
pub const GOVERNANCE_START_OUTPUT_ROWS_V1: u32 = 256;

/// Largest complete governance-start row.
pub const GOVERNANCE_START_ROW_MAX_BYTES_V1: u64 = 262_144;

/// Largest complete [`GovernanceBlockStartEventV1::CastingClockEstablished`] row.
pub const CASTING_CLOCK_ROW_MAX_BYTES_V1: u64 = 1_024;

/// Largest compact lifecycle receipt row of one positioned Parliament item.
pub const LIFECYCLE_RECEIPT_ROW_MAX_BYTES_V1: u64 = 16_384;

/// Rows one positioned Parliament item may emit: one lifecycle receipt, then one richer
/// ballot output.
pub const GOVERNANCE_START_ROWS_PER_ITEM_V1: u32 = 2;

/// Where a governance block-start output happened.
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
#[norito(
    tag = "kind",
    content = "detail",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[norito_schema(name = "iroha_data_model::governance::anonymous_ballot::GovernanceOutputAnchorV1")]
pub enum GovernanceOutputAnchorV1 {
    /// The mandatory `EstablishCastingClock` prelude of a block, which has no pass position.
    #[codec(index = 0)]
    CastingClockPrelude {
        /// Height of the block (`h_open + 1` of the clocked ballot).
        height: u64,
        /// Time of that block in milliseconds.
        timestamp_ms: u64,
    },
    /// A positioned item of the shared G1–G3 pass.
    #[codec(index = 1)]
    Pass(GovernanceAnchorV1),
}

impl GovernanceOutputAnchorV1 {
    /// Height of the block that emitted the output.
    #[must_use]
    pub const fn height(&self) -> u64 {
        match self {
            Self::CastingClockPrelude { height, .. } => *height,
            Self::Pass(anchor) => anchor.height,
        }
    }

    /// Time of the block that emitted the output.
    #[must_use]
    pub const fn timestamp_ms(&self) -> u64 {
        match self {
            Self::CastingClockPrelude { timestamp_ms, .. } => *timestamp_ms,
            Self::Pass(anchor) => anchor.timestamp_ms,
        }
    }

    /// The pass anchor of a positioned item; `None` for the prelude.
    #[must_use]
    pub const fn pass_anchor(&self) -> Option<&GovernanceAnchorV1> {
        match self {
            Self::CastingClockPrelude { .. } => None,
            Self::Pass(anchor) => Some(anchor),
        }
    }
}

/// Why a governance block-start output pairs an event with the wrong kind of anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum GovernanceBlockStartOutputErrorV1 {
    /// A casting clock is always established by the prelude, never by a pass item.
    #[error("CastingClockEstablished must carry the casting-clock prelude anchor")]
    CastingClockWithPassAnchor,
    /// Only a casting-clock establishment may carry the prelude anchor.
    #[error("only CastingClockEstablished may carry the casting-clock prelude anchor")]
    PreludeAnchorForPassEvent,
}

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
/// output's [`GovernanceOutputAnchorV1::CastingClockPrelude`] anchor carries that block's
/// height and time.
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

/// One committed governance block-start output: where it happened and what happened.
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
    /// The prelude's height and time, or the pass item's height, position and time.
    pub anchor: GovernanceOutputAnchorV1,
    /// The transition's event.
    pub event: GovernanceBlockStartEventV1,
}

impl GovernanceBlockStartOutputV1 {
    /// Check the anchor kind: a casting-clock establishment carries the prelude anchor, and
    /// every other event a pass anchor.
    ///
    /// # Errors
    /// The [`GovernanceBlockStartOutputErrorV1`] of the mismatch.
    pub fn validate(&self) -> Result<(), GovernanceBlockStartOutputErrorV1> {
        let clock = matches!(
            self.event,
            GovernanceBlockStartEventV1::CastingClockEstablished(_)
        );
        match (clock, &self.anchor) {
            (true, GovernanceOutputAnchorV1::Pass(_)) => {
                Err(GovernanceBlockStartOutputErrorV1::CastingClockWithPassAnchor)
            }
            (false, GovernanceOutputAnchorV1::CastingClockPrelude { .. }) => {
                Err(GovernanceBlockStartOutputErrorV1::PreludeAnchorForPassEvent)
            }
            _ => Ok(()),
        }
    }

    /// The largest complete row this output's event may occupy:
    /// [`CASTING_CLOCK_ROW_MAX_BYTES_V1`] for a casting clock and
    /// [`GOVERNANCE_START_ROW_MAX_BYTES_V1`] for every other event.
    #[must_use]
    pub const fn row_cap_bytes(&self) -> u64 {
        match self.event {
            GovernanceBlockStartEventV1::CastingClockEstablished(_) => {
                CASTING_CLOCK_ROW_MAX_BYTES_V1
            }
            _ => GOVERNANCE_START_ROW_MAX_BYTES_V1,
        }
    }
}

#[cfg(test)]
mod tests {
    use norito::codec::{Decode as _, Encode as _};

    use super::*;
    use crate::governance::anonymous_ballot::{
        BALLOT_CONTEXT_MAX_BYTES_V1, MAX_SEALED_SEATS_V1, ParliamentBallotParametersV1,
        framing::{decode_enc, enc},
        test_fixtures::{anchor, body_context, closure, sealed_list},
    };

    /// Room left in every cap for the enum discriminant and the field length prefix that the
    /// future `ExecutionOutputV1::GovernanceBlockStart` row adds around an output.
    const ROW_FRAMING_MARGIN: u64 = 64;

    fn prelude(height: u64, timestamp_ms: u64) -> GovernanceOutputAnchorV1 {
        GovernanceOutputAnchorV1::CastingClockPrelude {
            height,
            timestamp_ms,
        }
    }

    fn pass(height: u64, position: u32, timestamp_ms: u64) -> GovernanceOutputAnchorV1 {
        GovernanceOutputAnchorV1::Pass(anchor(height, position, timestamp_ms))
    }

    fn published(seats: u16) -> SealedCredentialListPublishedV1 {
        SealedCredentialListPublishedV1 {
            body_context: body_context(),
            body_instance_id: BodyInstanceId::new([0x03; 32]),
            roster_root: Digest512::new([0x0a; 64]),
            list_digest: Digest512::new([0x99; 64]),
            registration_mapping_digest: Digest512::new([0x04; 64]),
            sealed_list_bytes: SealedCredentialListBytesV1::from_list(&sealed_list(seats))
                .expect("publish"),
        }
    }

    fn outputs() -> Vec<GovernanceBlockStartOutputV1> {
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
                anchor: pass(90, 1, 900_000),
                event: GovernanceBlockStartEventV1::SealedCredentialListPublished(published(5)),
            },
            GovernanceBlockStartOutputV1 {
                anchor: pass(100, 2, 1_000_000),
                event: GovernanceBlockStartEventV1::CastingOpened(opened),
            },
            GovernanceBlockStartOutputV1 {
                anchor: prelude(101, 1_001_000),
                event: GovernanceBlockStartEventV1::CastingClockEstablished(clock),
            },
            GovernanceBlockStartOutputV1 {
                anchor: pass(90_000, 0, 87_401_500),
                event: GovernanceBlockStartEventV1::BallotClosed(closure(9, 6, 2, 1)),
            },
        ]
    }

    #[test]
    fn every_block_start_output_round_trips_and_validates() {
        for (index, output) in outputs().into_iter().enumerate() {
            assert_eq!(output.validate(), Ok(()));
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
    fn only_the_casting_clock_uses_the_prelude_anchor() {
        let outputs = outputs();
        for output in &outputs {
            let swapped = GovernanceBlockStartOutputV1 {
                anchor: match output.anchor {
                    GovernanceOutputAnchorV1::Pass(anchor) => {
                        prelude(anchor.height, anchor.timestamp_ms)
                    }
                    GovernanceOutputAnchorV1::CastingClockPrelude {
                        height,
                        timestamp_ms,
                    } => pass(height, 0, timestamp_ms),
                },
                event: output.event.clone(),
            };
            let expected = if matches!(
                output.event,
                GovernanceBlockStartEventV1::CastingClockEstablished(_)
            ) {
                GovernanceBlockStartOutputErrorV1::CastingClockWithPassAnchor
            } else {
                GovernanceBlockStartOutputErrorV1::PreludeAnchorForPassEvent
            };
            assert_eq!(swapped.validate(), Err(expected));
        }
        // The anchor accessors read either kind; only a pass item has a position.
        let clocked = prelude(101, 1_001_000);
        assert_eq!((clocked.height(), clocked.timestamp_ms()), (101, 1_001_000));
        assert_eq!(clocked.pass_anchor(), None);
        let positioned = pass(100, 2, 1_000_000);
        assert_eq!(
            (positioned.height(), positioned.timestamp_ms()),
            (100, 1_000_000)
        );
        assert_eq!(positioned.pass_anchor(), Some(&anchor(100, 2, 1_000_000)));
        for value in [clocked, positioned] {
            assert_eq!(
                decode_enc::<GovernanceOutputAnchorV1>(&enc(&value).expect("enc")),
                Ok(value)
            );
            let json = norito::json::to_json(&value).expect("json");
            assert_eq!(
                norito::json::from_str::<GovernanceOutputAnchorV1>(&json).expect("json"),
                value
            );
        }
        assert_eq!(
            norito::json::to_json(&clocked).expect("json"),
            r#"{"kind":"casting_clock_prelude","detail":{"height":101,"timestamp_ms":1001000}}"#
        );
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

    /// Complete canonical frame length of `output`, as the output budget measures a row.
    fn frame_len(output: &GovernanceBlockStartOutputV1) -> u64 {
        u64::try_from(norito::canonical_frame_len(output).expect("frame")).expect("small")
    }

    #[test]
    fn the_largest_encoding_of_each_ballot_output_fits_its_row_cap() {
        // The largest published list has 1,000 commitments; the closure record, the opening
        // and the clock have fixed sizes, and every anchor kind has a fixed size.
        let largest = [
            GovernanceBlockStartOutputV1 {
                anchor: pass(u64::MAX, u32::MAX, u64::MAX),
                event: GovernanceBlockStartEventV1::SealedCredentialListPublished(published(
                    MAX_SEALED_SEATS_V1,
                )),
            },
            outputs()[1].clone(),
            GovernanceBlockStartOutputV1 {
                anchor: prelude(u64::MAX, u64::MAX),
                event: outputs()[2].event.clone(),
            },
            GovernanceBlockStartOutputV1 {
                anchor: pass(u64::MAX, u32::MAX, u64::MAX),
                event: GovernanceBlockStartEventV1::BallotClosed(closure(1_000, 400, 267, 0)),
            },
        ];
        for output in &largest {
            let bytes = frame_len(output);
            assert!(
                bytes + ROW_FRAMING_MARGIN <= output.row_cap_bytes(),
                "{bytes} bytes against {}",
                output.row_cap_bytes()
            );
            assert!(bytes + ROW_FRAMING_MARGIN <= GOVERNANCE_START_ROW_MAX_BYTES_V1);
        }
        assert_eq!(largest[2].row_cap_bytes(), CASTING_CLOCK_ROW_MAX_BYTES_V1);
        // Even a list frame at the full context cap would fit a governance row.
        let list_bytes = u64::try_from(
            published(MAX_SEALED_SEATS_V1)
                .sealed_list_bytes
                .as_bytes()
                .len(),
        )
        .expect("small");
        let fixed = frame_len(&largest[0]) - list_bytes;
        assert!(
            fixed + u64::try_from(BALLOT_CONTEXT_MAX_BYTES_V1).expect("small") + ROW_FRAMING_MARGIN
                <= GOVERNANCE_START_ROW_MAX_BYTES_V1
        );
    }

    #[test]
    fn the_partition_holds_every_prelude_row_and_one_maximal_item() {
        // At most K <= 16 casting clocks are established per block; one maximal positioned
        // item adds a receipt and a full governance row.
        const PRELUDE_ROWS: u64 = ParliamentBallotParametersV1::MAX_NONTERMINAL_ATTEMPTS as u64;
        const {
            assert!(
                PRELUDE_ROWS * CASTING_CLOCK_ROW_MAX_BYTES_V1
                    + LIFECYCLE_RECEIPT_ROW_MAX_BYTES_V1
                    + GOVERNANCE_START_ROW_MAX_BYTES_V1
                    <= GOVERNANCE_START_OUTPUT_BYTES_V1
            );
            assert!(
                PRELUDE_ROWS + GOVERNANCE_START_ROWS_PER_ITEM_V1 as u64
                    <= GOVERNANCE_START_OUTPUT_ROWS_V1 as u64
            );
        };
        assert_eq!(
            (
                GOVERNANCE_START_OUTPUT_BYTES_V1,
                GOVERNANCE_START_OUTPUT_ROWS_V1,
                GOVERNANCE_START_ROW_MAX_BYTES_V1,
                CASTING_CLOCK_ROW_MAX_BYTES_V1,
                LIFECYCLE_RECEIPT_ROW_MAX_BYTES_V1,
                GOVERNANCE_START_ROWS_PER_ITEM_V1,
            ),
            (1_048_576, 256, 262_144, 1_024, 16_384, 2)
        );
    }
}
