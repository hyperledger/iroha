//! Synthetic Nexus/AMX context preimages and lane policies for genesis dataspace tests.
//!
//! The preimage uses the canonical writer and the complete tag grammar; opaque fields carry
//! synthetic values. It is never a real node configuration or deployment input.

use crate::{
    isi::{InstructionBox, SetParameter},
    nexus::{LaneCatalog, LaneConfig, LaneVisibility, NexusAmxContextWriterV1, tag},
    parameter::{Parameter, system::SumeragiParameters},
    sns::dataspace_id_for_alias,
    sumeragi_lanes::{SumeragiFixedLane, SumeragiLaneMember, SumeragiLanePolicy},
};
use iroha_crypto::{Hash, KeyPair, bls_normal_pop_prove};
use iroha_model_base::{
    peer::PeerId,
    topology::{DataSpaceId, LaneId},
};
use std::num::NonZeroU32;

/// One synthetic physical routing rule: lane, dataspace override, account, instruction.
pub type NexusRuleFixture = (u32, Option<DataSpaceId>, Option<String>, Option<String>);

/// A synthetic physical Nexus catalog rendered as an exact context preimage.
#[derive(Debug, Clone)]
pub struct NexusAmxContextFixture {
    /// Exclusive lane-id bound.
    pub lane_count: u32,
    /// Lane catalog entries.
    pub lanes: Vec<LaneConfig>,
    /// Dataspace catalog entries (identity, alias).
    pub dataspaces: Vec<(DataSpaceId, String)>,
    /// Ordered routing rules.
    pub rules: Vec<NexusRuleFixture>,
    /// Autoscale `(enabled, min_lane_id, max_lane_id_exclusive)`.
    pub autoscale: (bool, u32, u32),
}

/// SNS identity of a static fixture alias.
///
/// # Panics
/// Panics if the alias is not a canonical SNS label.
#[must_use]
pub fn fixture_dataspace_id(alias: &str) -> DataSpaceId {
    dataspace_id_for_alias(alias).expect("canonical fixture dataspace alias")
}

/// Fresh Taira participants in lane order: (lane, alias, visibility).
pub const TAIRA_FIXTURE_PARTICIPANTS: [(u32, &str, LaneVisibility); 5] = [
    (3, "dpn", LaneVisibility::Restricted),
    (4, "is2", LaneVisibility::Restricted),
    (5, "bpng", LaneVisibility::Public),
    (6, "cbsi", LaneVisibility::Restricted),
    (7, "is", LaneVisibility::Restricted),
];

impl NexusAmxContextFixture {
    /// The fresh eight-lane Taira shape: universal core/governance/zk lanes, Restricted
    /// participant lanes routed by account, and the Public `bpng` lane 5 with no account route.
    #[must_use]
    pub fn taira() -> Self {
        let lane = |id: u32, alias: &str, dataspace, visibility| LaneConfig {
            id: LaneId::new(id),
            dataspace_id: dataspace,
            alias: alias.to_owned(),
            visibility,
            governance: (visibility == LaneVisibility::Restricted).then(|| "parliament".to_owned()),
            ..LaneConfig::default()
        };
        let mut lanes = ["core", "governance", "zk"]
            .into_iter()
            .zip(0..)
            .map(|(alias, id)| lane(id, alias, DataSpaceId::UNIVERSAL, LaneVisibility::Public))
            .collect::<Vec<_>>();
        let mut dataspaces = vec![(DataSpaceId::UNIVERSAL, "universal".to_owned())];
        let mut rules = vec![
            (
                1,
                Some(DataSpaceId::UNIVERSAL),
                None,
                Some("governance".to_owned()),
            ),
            (
                2,
                Some(DataSpaceId::UNIVERSAL),
                None,
                Some("smartcontract::deploy".to_owned()),
            ),
        ];
        for (index, alias, visibility) in TAIRA_FIXTURE_PARTICIPANTS {
            let id = fixture_dataspace_id(alias);
            lanes.push(lane(index, alias, id, visibility));
            dataspaces.push((id, alias.to_owned()));
            if visibility == LaneVisibility::Restricted {
                rules.push((index, Some(id), Some(format!("*@{alias}")), None));
            }
        }
        dataspaces.sort();
        Self {
            lane_count: 8,
            lanes,
            dataspaces,
            rules,
            autoscale: (false, 1, 8),
        }
    }

    /// Render the exact context preimage.
    ///
    /// # Panics
    /// Panics if the lanes do not form a valid lane catalog.
    #[must_use]
    pub fn preimage(&self) -> Vec<u8> {
        let catalog = LaneCatalog::new(
            NonZeroU32::new(self.lane_count).expect("non-zero fixture lane count"),
            self.lanes.clone(),
        )
        .expect("valid fixture lane catalog");
        let (count, projected) = catalog.consensus_projection();
        let mut writer = NexusAmxContextWriterV1::new();
        writer.field(tag::LANE_COUNT, &count);
        writer.field(tag::LANES, &projected);
        writer.field(tag::LANE_LIFECYCLE_COUNT, &1_u64);
        writer.field(tag::LANE_LIFECYCLE_LANE_ID, &LaneId::new(0));
        writer.field(tag::LANE_LIFECYCLE_GENERATION, &0_u64);
        writer.field(tag::LANE_LIFECYCLE_INCARNATION, &Hash::new(b"fixture lane"));
        writer.field(tag::LANE_LIFECYCLE_ACTIVATION_HEIGHT, &1_u64);
        writer.field(tag::DATASPACE_COUNT, &(self.dataspaces.len() as u64));
        for (id, alias) in &self.dataspaces {
            writer.field(tag::DATASPACE_ID, id);
            writer.field(tag::DATASPACE_ALIAS, alias);
            writer.field(tag::DATASPACE_FAULT_TOLERANCE, &1_u32);
        }
        writer.field(tag::ROUTING_DEFAULT_LANE, &LaneId::new(0));
        writer.field(tag::ROUTING_DEFAULT_DATASPACE, &DataSpaceId::UNIVERSAL);
        writer.field(tag::ROUTING_RULE_COUNT, &(self.rules.len() as u64));
        for (lane, dataspace, account, instruction) in &self.rules {
            writer.field(tag::ROUTING_RULE_LANE, &LaneId::new(*lane));
            writer.field(tag::ROUTING_RULE_DATASPACE, dataspace);
            writer.field(tag::ROUTING_RULE_ACCOUNT, account);
            writer.field(tag::ROUTING_RULE_INSTRUCTION, instruction);
        }
        for field in tag::TAIL {
            match field {
                tag::AUTOSCALE_ENABLED => writer.field(field, &self.autoscale.0),
                tag::AUTOSCALE_MIN_LANE_ID => writer.field(field, &self.autoscale.1),
                tag::AUTOSCALE_MAX_LANE_ID_EXCLUSIVE => writer.field(field, &self.autoscale.2),
                _ => writer.field(field, &7_u64),
            }
        }
        writer.finish()
    }

    /// The signed context commitment of [`Self::preimage`].
    #[must_use]
    pub fn context_hash(&self) -> [u8; 32] {
        Hash::new(self.preimage()).into()
    }
}

/// A valid lane policy whose fixed lanes are the Taira participants, each pinned to the
/// given committee.
///
/// # Panics
/// Panics if a committee key cannot produce its proof of possession.
#[must_use]
pub fn taira_fixture_lane_policy(committee: &[KeyPair]) -> SumeragiLanePolicy {
    let members = committee
        .iter()
        .map(|key| SumeragiLaneMember {
            peer: PeerId::new(key.public_key().clone()),
            pop: bls_normal_pop_prove(key.private_key()).expect("fixture proof of possession"),
        })
        .collect::<Vec<_>>();
    let mut policy = SumeragiLanePolicy::for_chain(
        SumeragiParameters::default(),
        iroha_sumeragi::availability::recommended_data_availability_layout(),
    );
    policy.fixed = TAIRA_FIXTURE_PARTICIPANTS
        .iter()
        .map(|(lane, alias, _)| SumeragiFixedLane {
            lane: LaneId::new(*lane),
            dataspace: fixture_dataspace_id(alias),
            committee: members.clone(),
        })
        .collect();
    policy.validate().expect("valid fixture lane policy");
    policy
}

/// The policy as a signed genesis instruction.
#[must_use]
pub fn lane_policy_instruction(policy: SumeragiLanePolicy) -> InstructionBox {
    SetParameter::new(Parameter::Custom(policy.into_custom_parameter())).into()
}
