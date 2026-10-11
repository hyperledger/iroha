//! Block-start anchors of governance transitions, shared by the Parliament ballot and SCCP.
//!
//! The governance block-start pass processes its due items in one deterministic order
//! (`specs/sccp.md` §4.7.2). An anchor names one processed item: the block, the item's
//! position in that block's pass and the block's time. It authenticates nothing by itself;
//! the record that stores an anchor owns its authority.

use norito::codec::{Decode, Encode};

/// Where the block-start pass processed one governance transition.
///
/// The casting-open anchor `s0` of a binding ballot is a value of this type. SCCP receives it
/// with the certificate at enactment and compares it with the anchor of a fast-pause
/// enactment (`specs/sccp.md` §4.14.3 item 4, §4.14.7 and §10.1).
///
/// Ordering is lexicographic in field order, so `(height, position)` decides first. A height
/// has one block time on a chain, so `timestamp_ms` never decides between two of its anchors.
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
    crate::DeriveJsonSerialize,
    crate::DeriveJsonDeserialize,
    norito::NoritoSchema,
    iroha_schema::IntoSchema,
)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha_data_model::governance::anchor::GovernanceAnchorV1")]
pub struct GovernanceAnchorV1 {
    /// Height of the block whose block-start pass processed the transition.
    pub height: u64,
    /// 0-based index of the transition among the items that pass processed, in processing
    /// order.
    pub position: u32,
    /// Time of that block, in milliseconds.
    pub timestamp_ms: u64,
}

#[cfg(test)]
mod tests {
    use core::cmp::Ordering;

    use super::GovernanceAnchorV1;

    const fn anchor(height: u64, position: u32, timestamp_ms: u64) -> GovernanceAnchorV1 {
        GovernanceAnchorV1 {
            height,
            position,
            timestamp_ms,
        }
    }

    #[test]
    fn governance_anchor_round_trips_norito_and_json() {
        for value in [
            anchor(7200, 3, 1_790_000_000_000),
            anchor(1, 0, 0),
            anchor(u64::MAX, u32::MAX, u64::MAX),
        ] {
            let bytes = norito::encode_canonical(&value).unwrap();
            let decoded: GovernanceAnchorV1 = norito::decode_canonical(&bytes).unwrap();
            assert_eq!(decoded, value);
            assert_eq!(norito::encode_canonical(&decoded).unwrap(), bytes);
            // One canonical frame: neither a shorter nor a longer input decodes.
            assert!(
                norito::decode_canonical::<GovernanceAnchorV1>(&bytes[..bytes.len() - 1]).is_err()
            );
            let mut extended = bytes.clone();
            extended.push(0);
            assert!(norito::decode_canonical::<GovernanceAnchorV1>(&extended).is_err());

            let json = norito::json::to_json(&value).unwrap();
            assert_eq!(
                norito::json::from_str::<GovernanceAnchorV1>(&json).unwrap(),
                value
            );
        }

        // The JSON form names the three fields in declaration order and admits no other.
        assert_eq!(
            norito::json::to_json(&anchor(7200, 3, 1_790_000_000_000)).unwrap(),
            r#"{"height":7200,"position":3,"timestamp_ms":1790000000000}"#
        );
        assert!(
            norito::json::from_str::<GovernanceAnchorV1>(
                r#"{"height":7200,"position":3,"timestamp_ms":1790000000000,"extra":0}"#
            )
            .is_err()
        );
        assert!(
            norito::json::from_str::<GovernanceAnchorV1>(r#"{"height":7200,"position":3}"#)
                .is_err()
        );
    }

    #[test]
    fn governance_anchor_orders_by_height_then_position() {
        // The height decides first, whatever the position and the time are.
        assert!(anchor(7, u32::MAX, u64::MAX) < anchor(8, 0, 0));
        // Within a block, the position in the pass decides, whatever the time is.
        assert!(anchor(8, 0, u64::MAX) < anchor(8, 1, 0));
        // The time is the last key only.
        assert!(anchor(8, 1, 100) < anchor(8, 1, 101));
        assert_eq!(anchor(8, 1, 100).cmp(&anchor(8, 1, 100)), Ordering::Equal);
        assert_eq!(
            anchor(8, 1, 100).partial_cmp(&anchor(8, 0, 900)),
            Some(Ordering::Greater)
        );

        // The derived order agrees with the `(height, position)` pairs the lift rule compares.
        let mut anchors = [
            anchor(9, 0, 9000),
            anchor(8, 2, 8000),
            anchor(7, 5, 7000),
            anchor(8, 0, 8000),
            anchor(8, 1, 8000),
        ];
        anchors.sort();
        assert_eq!(
            anchors.map(|anchor| (anchor.height, anchor.position)),
            [(7, 5), (8, 0), (8, 1), (8, 2), (9, 0)]
        );
        for pair in anchors.windows(2) {
            assert!((pair[0].height, pair[0].position) < (pair[1].height, pair[1].position));
        }
    }
}
