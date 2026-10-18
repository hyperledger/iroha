//! Exact borrowed canonical lane semantics, sharing the original metadata selector.

use super::{LaneConfig, LaneConsensusProjectionV1, is_consensus_lane_metadata_key};
use norito::core::{Encoder, Error, SerializePayload, write_len_prefixed};

pub(super) struct Projection<'a>(pub(super) &'a LaneConfig);
impl SerializePayload for Projection<'_> {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        let lane = self.0;
        write_len_prefixed(writer, &LaneConsensusProjectionV1::VERSION)?;
        write_len_prefixed(writer, &lane.id)?;
        write_len_prefixed(writer, &lane.alias)?;
        write_len_prefixed(writer, &lane.effective_shard_id())?;
        write_len_prefixed(writer, &lane.dataspace_id)?;
        write_len_prefixed(writer, &lane.visibility)?;
        write_len_prefixed(writer, &lane.lane_type)?;
        write_len_prefixed(writer, &lane.governance)?;
        write_len_prefixed(writer, &lane.settlement)?;
        write_len_prefixed(writer, &lane.storage)?;
        write_len_prefixed(writer, &lane.proof_scheme)?;
        write_len_prefixed(writer, &lane.manifest_policy)?;
        write_len_prefixed(writer, &lane.confidential_compute)?;
        write_len_prefixed(writer, &lane.scheduler)?;
        write_len_prefixed(writer, &lane.settlement_buffer)?;
        write_len_prefixed(writer, &Metadata(lane))
    }
}

struct Metadata<'a>(&'a LaneConfig);
impl SerializePayload for Metadata<'_> {
    fn serialize(&self, writer: &mut Encoder<'_>) -> Result<(), Error> {
        let entries = self
            .0
            .metadata
            .iter()
            .filter(|(key, _)| is_consensus_lane_metadata_key(key));
        norito::core::write_ordered_map_entries(writer, entries.clone().count(), entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use norito::codec::Encode;

    #[test]
    fn borrowed_lane_matches_owned_for_optional_labels_and_reserved_metadata() {
        let mut lane = LaneConfig::default();
        lane.alias = "borrowed-independent-root".into();
        lane.lane_type = Some("bank".into());
        lane.governance = Some("governed".into());
        lane.settlement = Some("settle".into());
        lane.metadata
            .insert(super::super::AUTOSCALE_META_MANAGED.into(), "true".into());
        lane.metadata
            .insert("operator.presentation".into(), "excluded".into());
        assert_eq!(
            lane.borrowed_consensus_projection().encode(),
            lane.consensus_projection().encode()
        );
        lane.lane_type = None;
        lane.governance = None;
        lane.settlement = None;
        assert_eq!(
            lane.borrowed_consensus_projection().encode(),
            lane.consensus_projection().encode()
        );
    }
}
