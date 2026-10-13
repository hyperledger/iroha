//! Compact selection inside an already authenticated chronological prefix.
//!
//! The original creation bytes own the selected graph elsewhere. This selector retains only
//! immutable authority identity and activation scalars; it never clones a lane record.
use iroha_data_model::sumeragi_lanes::{SumeragiLaneRecord, SumeragiLaneState};
use iroha_model_base::topology::LaneId;
use std::io;

pub(super) struct LaneSelection {
    lane: LaneId,
    incarnation: [u8; 32],
    original: Option<(iroha_crypto::Hash, u64)>,
    disappeared: bool,
}
fn immutable_identity(record: &SumeragiLaneRecord) -> io::Result<iroha_crypto::Hash> {
    iroha_crypto::Hash::new_from_writer(|mut writer| {
        writer.write_all(b"iroha/native-lane-authority-selection/v1")?;
        norito::codec::encode_adaptive_into(
            &(
                record.lane,
                record.dataspace,
                record.incarnation,
                record.da_layout,
                record.created_at,
                record.active_from,
                record.anchor_freshness,
            ),
            &mut writer,
        )
        .map_err(io::Error::other)?;
        norito::codec::encode_adaptive_into(&record.params, &mut writer)
            .map_err(io::Error::other)?;
        norito::codec::encode_adaptive_into(&record.committee, &mut writer)
            .map_err(io::Error::other)?;
        Ok(())
    })
}
impl LaneSelection {
    pub(super) fn new(lane: LaneId, incarnation: [u8; 32]) -> Self {
        Self {
            lane,
            incarnation,
            original: None,
            disappeared: false,
        }
    }
    // Returns true exactly when this original creation carrier must acquire byte custody.
    // The provider grants no authority until its complete prefix reaches the captured State tip.
    pub(super) fn observe(&mut self, height: u64, state: &SumeragiLaneState) -> io::Result<bool> {
        let record = state
            .lane(self.lane)
            .filter(|record| record.incarnation == self.incarnation);
        let Some(record) = record else {
            self.disappeared |= self.original.is_some();
            return Ok(false);
        };
        if self.disappeared
            || record.created_at > height
            || record.created_at.checked_add(2) != Some(record.active_from)
        {
            return Err(super::invalid(
                "historical incarnation reappears or has invalid activation",
            ));
        }
        let identity = immutable_identity(record)?;
        if let Some((original, _)) = self.original {
            if original != identity {
                return Err(super::invalid(
                    "historical incarnation changes its immutable authority",
                ));
            }
            Ok(false)
        } else {
            // A later snapshot cannot substitute for the actual creation carrier. Genesis
            // reaches this selector only after its actual H2 successor authenticates its R.
            if record.created_at != height {
                return Err(super::invalid("original lane creation carrier is missing"));
            }
            self.original = Some((identity, record.active_from));
            Ok(true)
        }
    }
    pub(super) fn is_active(&self, tip: u64) -> bool {
        self.original.is_some_and(|(_, active)| active <= tip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_data_model::{
        parameter::system::SumeragiParameters, sumeragi_lanes::SumeragiLaneFrontier,
    };
    use iroha_model_base::topology::DataSpaceId;

    // Predicate-only fixtures. These do not purport to authenticate a carrier or its committee;
    // the production caller obtains those facts solely from NativeExecutionEvidenceVerifier.
    fn record() -> SumeragiLaneRecord {
        SumeragiLaneRecord {
            da_layout: iroha_sumeragi::availability::recommended_data_availability_layout(),
            lane: LaneId::new(7),
            dataspace: DataSpaceId::new(3),
            incarnation: [0x21; 32],
            params: SumeragiParameters::default(),
            committee: vec![],
            created_at: 10,
            active_from: 12,
            closing: None,
            anchor_freshness: 16,
            merged: SumeragiLaneFrontier::default(),
            merged_at: 12,
            rescued: 0,
        }
    }
    fn state(record: SumeragiLaneRecord) -> SumeragiLaneState {
        SumeragiLaneState {
            lanes: vec![record],
            ..SumeragiLaneState::default()
        }
    }
    #[test]
    fn activation_is_required_and_retirement_keeps_the_exact_original_authority() {
        let original = record();
        let mut selection = LaneSelection::new(original.lane, original.incarnation);
        selection.observe(10, &state(original.clone())).unwrap();
        assert!(!selection.is_active(11));
        let mut selection = LaneSelection::new(original.lane, original.incarnation);
        selection.observe(10, &state(original.clone())).unwrap();
        let mut progressed = original.clone();
        progressed.closing = Some(20);
        progressed.rescued = 999;
        progressed.merged.height = 6;
        progressed.merged_at = 19;
        selection.observe(20, &state(progressed)).unwrap();
        selection
            .observe(40, &SumeragiLaneState::default())
            .unwrap();
        let mut replacement = original.clone();
        replacement.incarnation = [0x22; 32];
        selection.observe(41, &state(replacement)).unwrap();
        assert!(selection.is_active(41));
    }
    #[test]
    fn another_incarnation_or_lane_is_never_substituted_for_the_request() {
        let original = record();
        for (lane, incarnation) in [
            (LaneId::new(8), original.incarnation),
            (original.lane, [0x22; 32]),
        ] {
            let mut selected = LaneSelection::new(lane, incarnation);
            selected.observe(10, &state(original.clone())).unwrap();
            assert!(!selected.is_active(12));
        }
    }
    #[test]
    fn immutable_authority_changes_and_reappearance_are_rejected() {
        let original = record();
        let mut changes = vec![];
        let mut tampered_value = original.clone();
        tampered_value.da_layout.chunk_size_bytes *= 2;
        changes.push(tampered_value);
        let mut tampered_value = original.clone();
        tampered_value.anchor_freshness += 1;
        changes.push(tampered_value);
        let mut tampered_value = original.clone();
        tampered_value.dataspace = DataSpaceId::new(8);
        changes.push(tampered_value);
        let mut tampered_value = original.clone();
        tampered_value.created_at += 1;
        tampered_value.active_from += 1;
        changes.push(tampered_value);
        for tampered_value in changes {
            let mut selected = LaneSelection::new(original.lane, original.incarnation);
            selected.observe(10, &state(original.clone())).unwrap();
            assert_eq!(
                selected
                    .observe(15, &state(tampered_value))
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
        }
        let mut selected = LaneSelection::new(original.lane, original.incarnation);
        selected.observe(10, &state(original.clone())).unwrap();
        selected.observe(40, &SumeragiLaneState::default()).unwrap();
        assert!(selected.observe(41, &state(original)).is_err());
    }
    #[test]
    fn malformed_future_activation_and_overflow_never_grant_authority() {
        for (created, active, height) in [
            (10, 11, 10),
            (10, 12, 9),
            (10, 12, 11),
            (u64::MAX, 1, u64::MAX),
        ] {
            let mut record = record();
            record.created_at = created;
            record.active_from = active;
            let mut selected = LaneSelection::new(record.lane, record.incarnation);
            assert!(selected.observe(height, &state(record)).is_err());
            assert!(!selected.is_active(height));
        }
    }
}
