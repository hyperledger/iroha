//! Canonical lane behavior projected from one effective State runtime catalog.
//!
//! The runtime lane vector comes from an already validated lane catalog.
//! Alias bytes are functional: autoscale ownership and lifecycle admission
//! inspect them. Descriptions and unreserved instrumentation metadata are
//! intentionally excluded by `LaneConfig::consensus_projection`.

use iroha_data_model::nexus::{LaneConfig, LaneConsensusProjectionV1, MAX_ACTIVE_EXECUTION_LANES};
use norito::{Decode, Encode, NoritoSchema};

/// Refusal to project a malformed or locally unallocatable runtime lane set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(super) enum RuntimeLaneProjectionError {
    /// The effective catalog has no primary lane or exceeds the protocol cap.
    #[error("effective runtime lane count is outside V1 bounds")]
    LaneCount,
    /// The effective catalog is not strictly ordered by lane identifier.
    #[error("effective runtime lanes must be strictly ordered")]
    LaneOrder,
    /// The local projection buffer could not be reserved.
    #[error("effective runtime lane projection allocation failed")]
    Allocation,
}

/// Explicit V1 semantic value for `runtime.lanes` in the future State root.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, NoritoSchema)]
#[norito(deny_unknown_fields)]
#[norito_schema(name = "iroha:state:runtime-lane-catalog:v1")]
pub(super) struct RuntimeLaneCatalogAuthorityV1 {
    version: u16,
    lanes: Vec<LaneConsensusProjectionV1>,
}

impl RuntimeLaneCatalogAuthorityV1 {
    /// Capture the exact ordered effective lanes after catalog validation.
    ///
    /// # Errors
    /// Rejects absent/excessive lanes, noncanonical ordering, or a local
    /// allocation refusal. The complete State root and retention reservation
    /// are separate publication obligations.
    pub(super) fn from_lanes(lanes: &[LaneConfig]) -> Result<Self, RuntimeLaneProjectionError> {
        if lanes.is_empty() || lanes.len() > MAX_ACTIVE_EXECUTION_LANES {
            return Err(RuntimeLaneProjectionError::LaneCount);
        }
        if lanes.windows(2).any(|pair| pair[0].id >= pair[1].id) {
            return Err(RuntimeLaneProjectionError::LaneOrder);
        }
        let mut projected = Vec::new();
        projected
            .try_reserve_exact(lanes.len())
            .map_err(|_| RuntimeLaneProjectionError::Allocation)?;
        for lane in lanes {
            // TODO: fund the strings cloned by this existing model projection
            // before activating the complete State commitment owner.
            projected.push(lane.consensus_projection());
        }
        Ok(Self {
            version: LaneConsensusProjectionV1::VERSION,
            lanes: projected,
        })
    }
}

/// Stream the validated original lane catalog without a cloned projection vector.
pub(super) fn borrowed(
    lanes: &[LaneConfig],
) -> Result<impl norito::SerializePayload + '_, RuntimeLaneProjectionError> {
    use super::policy_borrowed::{Seq, record};
    if lanes.is_empty() || lanes.len() > MAX_ACTIVE_EXECUTION_LANES {
        return Err(RuntimeLaneProjectionError::LaneCount);
    }
    if lanes.windows(2).any(|pair| pair[0].id >= pair[1].id) {
        return Err(RuntimeLaneProjectionError::LaneOrder);
    }
    Ok(record!(
        LaneConsensusProjectionV1::VERSION,
        Seq(lanes.iter().map(LaneConfig::borrowed_consensus_projection))
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroha_data_model::nexus::AUTOSCALE_META_MANAGED;
    use iroha_model_base::topology::LaneId;

    fn lanes() -> Vec<LaneConfig> {
        vec![
            LaneConfig::default(),
            LaneConfig {
                id: LaneId::new(3),
                alias: "elastic-lane-3".into(),
                ..LaneConfig::default()
            },
        ]
    }

    #[test]
    fn borrowed_runtime_catalog_matches_owned_and_rejects_order_substitution() {
        let original = lanes();
        super::super::policy_borrowed::assert_same_payload(
            &borrowed(&original).unwrap(),
            &RuntimeLaneCatalogAuthorityV1::from_lanes(&original).unwrap(),
        );
        let mut swapped = original;
        swapped.reverse();
        assert!(matches!(
            borrowed(&swapped),
            Err(RuntimeLaneProjectionError::LaneOrder)
        ));
        assert!(matches!(
            borrowed(&[]),
            Err(RuntimeLaneProjectionError::LaneCount)
        ));
    }

    #[test]
    fn runtime_lane_authority_roundtrips_with_one_v1_identity() {
        let projection = RuntimeLaneCatalogAuthorityV1::from_lanes(&lanes()).unwrap();
        assert_eq!(
            RuntimeLaneCatalogAuthorityV1::nominal_name(),
            "iroha:state:runtime-lane-catalog:v1"
        );
        let encoded = norito::encode_canonical(&projection).unwrap();
        assert_eq!(
            norito::decode_canonical::<RuntimeLaneCatalogAuthorityV1>(&encoded).unwrap(),
            projection
        );
        let _ambient = norito::core::DecodeFlagsGuard::enter(0);
        assert_eq!(norito::encode_canonical(&projection).unwrap(), encoded);
    }

    #[test]
    fn runtime_lane_authority_binds_alias_and_reserved_policy_not_presentation() {
        let baseline = lanes();
        let expected = RuntimeLaneCatalogAuthorityV1::from_lanes(&baseline).unwrap();
        let mut renamed = baseline.clone();
        renamed[1].alias = "manual-lane-3".into();
        assert_ne!(
            RuntimeLaneCatalogAuthorityV1::from_lanes(&renamed).unwrap(),
            expected
        );
        let mut reserved = baseline.clone();
        reserved[1]
            .metadata
            .insert(AUTOSCALE_META_MANAGED.into(), "true".into());
        assert_ne!(
            RuntimeLaneCatalogAuthorityV1::from_lanes(&reserved).unwrap(),
            expected
        );
        let mut presentation = baseline;
        presentation[1].description = Some("new description".into());
        presentation[1]
            .metadata
            .insert("operator.color".into(), "blue".into());
        assert_eq!(
            RuntimeLaneCatalogAuthorityV1::from_lanes(&presentation).unwrap(),
            expected
        );
    }

    #[test]
    fn runtime_lane_authority_rejects_empty_duplicate_reordered_and_excess_lanes() {
        assert_eq!(
            RuntimeLaneCatalogAuthorityV1::from_lanes(&[]),
            Err(RuntimeLaneProjectionError::LaneCount)
        );
        let mut duplicate = lanes();
        duplicate[1].id = duplicate[0].id;
        assert_eq!(
            RuntimeLaneCatalogAuthorityV1::from_lanes(&duplicate),
            Err(RuntimeLaneProjectionError::LaneOrder)
        );
        let mut reversed = lanes();
        reversed.reverse();
        assert_eq!(
            RuntimeLaneCatalogAuthorityV1::from_lanes(&reversed),
            Err(RuntimeLaneProjectionError::LaneOrder)
        );
        let excessive = (0..=MAX_ACTIVE_EXECUTION_LANES)
            .map(|id| LaneConfig {
                id: LaneId::new(u32::try_from(id).unwrap()),
                alias: format!("lane-{id}"),
                ..LaneConfig::default()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            RuntimeLaneCatalogAuthorityV1::from_lanes(&excessive),
            Err(RuntimeLaneProjectionError::LaneCount)
        );
    }
}
