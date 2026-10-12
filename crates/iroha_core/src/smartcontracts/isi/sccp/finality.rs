//! Fixed native SCCP finality header from the exact completed execution cut.
//!
//! The caller supplies G5's signing generation before G2 advances the current row.
//! This projection does not authenticate decoded records or consult another State view.

use iroha_data_model::sumeragi_finality::certified_result::{FLAG_ACTIVE, FLAG_ROTATION};
use iroha_data_model::{
    NetworkId,
    sccp::{
        commitment::{SccpBlockCommitmentV1, SccpHistoryStateV1},
        committee::SccpCommitteeGenerationV1,
        events::SccpFinalityDegradedReasonV1,
    },
    sumeragi_finality::{SccpFinalityHeaderFieldsV1, SccpFinalityHeaderV1},
};
use std::num::NonZeroU64;

type Degraded = SccpFinalityDegradedReasonV1;

/// Produce X after the original generation, anchor and pruning transitions.
/// `None` is the G4 degraded result; all SCCP fields then have the inactive zero shape.
/// The supplied record must be the retained G5 row of this same execution transaction.
pub(crate) fn produce(
    network: NetworkId,
    height: NonZeroU64,
    timestamp_ms: u64,
    signing: Option<&SccpCommitteeGenerationV1>,
    block: Option<&SccpBlockCommitmentV1>,
    history: &SccpHistoryStateV1,
) -> Result<SccpFinalityHeaderV1, Degraded> {
    let Some(signing) = signing else {
        return Ok(inactive(network, height, timestamp_ms));
    };
    if signing.start_height > height.get()
        || signing
            .end
            .is_some_and(|end| end.end_height != height.get())
        || history.size > iroha_sccp::v1::constants::MAX_HISTORY_SIZE
        || history.peaks.len() != history.size.count_ones() as usize
    {
        return Err(Degraded::InconsistentGenerationState);
    }
    // Right-bag the borrowed, structurally checked peaks without cloning their allocation.
    let mut peaks = history.peaks.iter().rev();
    let history_root = peaks.next().map_or([0; 32], |last| {
        peaks.fold(*last, |right, left| {
            iroha_sccp::v1::hashes::node(left, &right)
        })
    });
    let (message_count, sccp_root) =
        block.map_or((0, [0; 32]), |block| (block.message_count, block.root));
    let (flags, validity_ms, next_committee_root) =
        signing.end.map_or((FLAG_ACTIVE, 0, [0; 32]), |end| {
            (
                FLAG_ACTIVE | FLAG_ROTATION,
                end.successor_validity_ms,
                end.next_committee_root,
            )
        });
    SccpFinalityHeaderV1::from_fields(&SccpFinalityHeaderFieldsV1 {
        network_id: *network.as_bytes(),
        height: height.get(),
        timestamp_ms,
        flags,
        message_count,
        sccp_root,
        history_size: history.size,
        history_root,
        generation: signing.generation,
        committee_root: signing.committee_root,
        validity_ms,
        next_committee_root,
    })
    .map_err(|_| Degraded::InconsistentGenerationState)
}

/// Canonical inactive form; a block header supplies the nonzero height invariant.
pub(crate) fn inactive(
    network: NetworkId,
    height: NonZeroU64,
    timestamp_ms: u64,
) -> SccpFinalityHeaderV1 {
    SccpFinalityHeaderV1::inactive(*network.as_bytes(), height.get(), timestamp_ms)
        .expect("nonzero original block height is a valid inactive header")
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_data_model::sccp::committee::{SccpGenerationCauseV1, SccpGenerationEndV1};

    // Projection tests exercise only fixed fields. Original key/PoP authority is established
    // by the separate retained generation owner and native result C2/C3 checks.
    fn row() -> SccpCommitteeGenerationV1 {
        SccpCommitteeGenerationV1 {
            generation: 4,
            committee_root: [1; 32],
            keys: vec![],
            members: vec![],
            cause: SccpGenerationCauseV1::Heartbeat,
            start_height: 2,
            start_timestamp_ms: 10,
            start_lc: 10,
            validity_ms: 100,
            deadline_ms: 110,
            grace_ms: 100,
            progress_cap_ms: 100,
            liable_until_lc: 210,
            dest_cleared_lc: None,
            end: None,
        }
    }
    fn height() -> NonZeroU64 {
        NonZeroU64::new(9).unwrap()
    }
    fn network() -> NetworkId {
        NetworkId::from_genesis_hash(iroha_crypto::HashOf::from_untyped_unchecked(
            iroha_crypto::Hash::prehashed([4; 32]),
        ))
    }

    #[test]
    fn inactive_preserves_only_original_instance_height_and_time() {
        let header = produce(
            network(),
            height(),
            123,
            None,
            None,
            &SccpHistoryStateV1 {
                size: 1,
                peaks: vec![],
            },
        )
        .unwrap();
        assert!(!header.is_active());
        assert_eq!(header.network_id(), *network().as_bytes());
        assert_eq!(header.height(), 9);
        assert_eq!(header.timestamp_ms(), 123);
        assert_eq!(header.history_size(), 0);
        assert_eq!(header.generation(), 0);
        assert_eq!(header, inactive(network(), height(), 123));
    }

    #[test]
    fn original_signing_row_and_end_drive_active_rotation_not_current_successor() {
        let mut signing = row();
        let history = SccpHistoryStateV1 {
            size: 3,
            peaks: vec![[2; 32], [3; 32]],
        };
        let block = SccpBlockCommitmentV1 {
            message_count: 1,
            root: [7; 32],
            history_index: 2,
        };
        let ordinary = produce(
            network(),
            height(),
            123,
            Some(&signing),
            Some(&block),
            &history,
        )
        .unwrap();
        assert!(ordinary.is_active());
        assert!(!ordinary.is_rotation());
        assert_eq!(
            ordinary.history_root(),
            iroha_sccp::v1::hashes::node(&[2; 32], &[3; 32])
        );
        assert_eq!(ordinary.sccp_root(), [7; 32]);
        assert_eq!(ordinary.generation(), 4);
        signing.end = Some(SccpGenerationEndV1 {
            end_height: 9,
            end_timestamp_ms: 123,
            next_committee_root: [8; 32],
            successor_validity_ms: 100,
        });
        let rotation = produce(network(), height(), 123, Some(&signing), None, &history).unwrap();
        assert!(rotation.is_rotation());
        assert_eq!(rotation.generation(), 4);
        assert_eq!(rotation.committee_root(), [1; 32]);
        assert_eq!(rotation.next_committee_root(), [8; 32]);
        assert_eq!(rotation.validity_ms(), 100);
        assert_eq!(rotation.message_count(), 0);
    }

    #[test]
    fn malformed_history_or_foreign_tenure_cannot_produce_active_header() {
        let mut signing = row();
        let empty = SccpHistoryStateV1 {
            size: 0,
            peaks: vec![],
        };
        assert!(
            produce(
                network(),
                height(),
                123,
                Some(&signing),
                None,
                &SccpHistoryStateV1 {
                    size: 1,
                    peaks: vec![]
                }
            )
            .is_err()
        );
        signing.start_height = 10;
        assert!(produce(network(), height(), 123, Some(&signing), None, &empty).is_err());
        signing.start_height = 2;
        signing.end = Some(SccpGenerationEndV1 {
            end_height: 8,
            end_timestamp_ms: 123,
            next_committee_root: [8; 32],
            successor_validity_ms: 100,
        });
        assert!(produce(network(), height(), 123, Some(&signing), None, &empty).is_err());
    }
}
