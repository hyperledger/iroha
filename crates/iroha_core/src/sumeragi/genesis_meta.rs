//! Genesis-bound consensus metadata: the hashes a node derives from a validated, uncommitted
//! genesis state block and compares with the values signed into genesis.

use crate::{
    smartcontracts::isi::staking::validator_election_eligible_at_height,
    state::{StateBlock, WorldReadOnly, public_lane_validator_record_matches_key},
};
use iroha_config::parameters::actual::{
    NexusConsensusPolicyDigestError, SumeragiLaneLifecycleEntry,
    sumeragi_nexus_amx_context_preimage,
};
use iroha_crypto::Hash;
use mv::storage::StorageReadOnly;

/// Build the canonical Nexus/AMX context preimage from a validated genesis state
/// block without committing that block. The projection binds every Nexus and
/// deterministic AMX input used by proposal assembly or validation, plus the
/// canonically ordered public-lane validator records whose retained tenure
/// contains height one, and the complete retained lane-incarnation lineage,
/// including retired lane identifiers. Signed genesis commits its hash; light
/// clients decode the exact bytes with `iroha_data_model::nexus::decode_nexus_amx_context_v1`.
#[must_use]
pub fn staged_genesis_nexus_amx_context_preimage(staged: &StateBlock<'_>) -> Vec<u8> {
    const GENESIS_CONTEXT_HEIGHT: u64 = 1;
    let eligible_validators = staged
        .world()
        .public_lane_validators()
        .iter()
        .filter(|(key, record)| public_lane_validator_record_matches_key(key, record))
        .filter(|(_, record)| validator_election_eligible_at_height(record, GENESIS_CONTEXT_HEIGHT))
        .map(|(key, record)| (key.clone(), record.clone()))
        .collect::<Vec<_>>();
    let retained_lane_lineage = staged
        .lane_incarnation_lineage_for_snapshot()
        .iter()
        .map(|(&lane_id, lineage)| SumeragiLaneLifecycleEntry {
            lane_id,
            generation: lineage.generation,
            incarnation: lineage.incarnation,
            activation_height: lineage.activation_height,
        })
        .collect::<Vec<_>>();
    sumeragi_nexus_amx_context_preimage(
        &staged.nexus,
        &staged.pipeline,
        &eligible_validators,
        &retained_lane_lineage,
    )
}

/// Compute the canonical Nexus/AMX commitment from a validated genesis state
/// block without committing that block: the hash of
/// [`staged_genesis_nexus_amx_context_preimage`].
#[must_use]
pub fn staged_genesis_nexus_amx_context_hash(staged: &StateBlock<'_>) -> Hash {
    Hash::new(staged_genesis_nexus_amx_context_preimage(staged))
}

/// Compute the canonical V1 execution policy from a validated, uncommitted genesis block.
///
/// # Errors
///
/// Returns an error if the Nexus policy has no authenticated runtime policy set.
pub fn staged_genesis_execution_policy_hash(
    staged: &StateBlock<'_>,
) -> Result<Hash, NexusConsensusPolicyDigestError> {
    staged.execution_policy_digest_v1().map(Hash::prehashed)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        kura::Kura,
        query::store::LiveQueryStore,
        state::{State, World},
    };
    use iroha_crypto::{Algorithm, KeyPair};
    use iroha_data_model::{
        account::AccountId,
        block::BlockHeader,
        nexus::{
            DataSpaceCatalog, DataSpaceMetadata, PublicLaneStakeShare, PublicLaneValidatorRecord,
            PublicLaneValidatorStatus,
        },
    };
    use iroha_model_base::{
        metadata::Metadata,
        peer::PeerId,
        topology::{DataSpaceId, LaneId},
    };
    use iroha_primitives::numeric::Quantity;
    use std::num::NonZeroU64;

    pub(crate) fn lane_record(
        peer: &PeerId,
        lane: LaneId,
        stake: u64,
    ) -> PublicLaneValidatorRecord {
        let validator = AccountId::new(peer.public_key().clone());
        PublicLaneValidatorRecord {
            lane_id: lane,
            validator: validator.clone(),
            peer_id: peer.clone(),
            stake_account: validator,
            total_stake: Quantity::from(stake),
            self_stake: Quantity::from(stake),
            metadata: Metadata::default(),
            status: PublicLaneValidatorStatus::Active,
            activation_height: 1,
            election_exit_height: None,
            deactivation_height: None,
        }
    }

    pub(crate) fn lane_hash_world(records: &[(LaneId, PeerId, u64)]) -> State {
        let world = World::default();
        {
            let mut block = world.block();
            for (lane, peer, stake) in records {
                let record = lane_record(peer, *lane, *stake);
                let validator = record.validator.clone();
                block
                    .public_lane_validators
                    .insert((*lane, validator.clone()), record);
                block.public_lane_stake_shares.insert(
                    (*lane, validator.clone(), validator.clone()),
                    PublicLaneStakeShare {
                        lane_id: *lane,
                        validator: validator.clone(),
                        staker: validator,
                        bonded: Quantity::from(*stake),
                        pending_unbonds: Default::default(),
                        metadata: Metadata::default(),
                    },
                );
            }
            block.commit();
        }
        State::new_for_testing(
            world,
            Kura::blank_kura_for_testing(),
            LiveQueryStore::start_test(),
        )
    }

    pub(crate) fn genesis_header() -> BlockHeader {
        BlockHeader::new(
            NonZeroU64::new(1).expect("non-zero test height"),
            None,
            None,
            0,
            0,
        )
    }

    fn staged_context_hash(state: &State) -> Hash {
        let block = state.block(genesis_header());
        staged_genesis_nexus_amx_context_hash(&block)
    }

    fn staged_context_hash_with_record(record: PublicLaneValidatorRecord) -> Hash {
        let state = lane_hash_world(&[]);
        let mut block = state.block(genesis_header());
        block
            .world
            .public_lane_validators
            .insert((record.lane_id, record.validator.clone()), record);
        staged_genesis_nexus_amx_context_hash(&block)
    }

    fn peer(seed: u8) -> PeerId {
        PeerId::new(
            KeyPair::try_from_seed(vec![seed; 32], Algorithm::BlsNormal)
                .expect("deterministic BLS peer")
                .public_key()
                .clone(),
        )
    }

    #[test]
    fn staged_lane_hash_is_order_independent_and_change_sensitive() {
        let peer_a = peer(0x61);
        let peer_b = peer(0x62);
        let state_ab = lane_hash_world(&[
            (LaneId::new(1), peer_a.clone(), 7),
            (LaneId::new(2), peer_b.clone(), 5),
        ]);
        let state_ba = lane_hash_world(&[
            (LaneId::new(2), peer_b.clone(), 5),
            (LaneId::new(1), peer_a.clone(), 7),
        ]);
        let changed = lane_hash_world(&[(LaneId::new(1), peer_a, 8), (LaneId::new(2), peer_b, 5)]);
        let hash = staged_context_hash(&state_ab);
        assert_eq!(hash, staged_context_hash(&state_ba));
        assert_ne!(hash, staged_context_hash(&changed));
    }

    #[test]
    fn staged_genesis_hash_uses_height_one_half_open_validator_tenure() {
        let peer = peer(0x64);
        let lane = LaneId::new(3);
        let empty_hash = staged_context_hash(&lane_hash_world(&[]));
        let mut record = lane_record(&peer, lane, 7);

        record.status = PublicLaneValidatorStatus::PendingActivation(1);
        assert_ne!(
            staged_context_hash_with_record(record.clone()),
            empty_hash,
            "a due pending label cannot suppress height-one tenure"
        );

        record.status = PublicLaneValidatorStatus::Exiting(u64::MAX);
        record.deactivation_height = Some(2);
        assert_ne!(
            staged_context_hash_with_record(record.clone()),
            empty_hash,
            "an exiting label cannot suppress retained height-one tenure"
        );

        record.status = PublicLaneValidatorStatus::Slashed(Hash::new(b"height-one slash"));
        assert_ne!(
            staged_context_hash_with_record(record.clone()),
            empty_hash,
            "a slashed label cannot suppress retained height-one tenure"
        );

        record.status = PublicLaneValidatorStatus::Exiting(u64::MAX);
        record.deactivation_height = Some(1);
        assert_eq!(
            staged_context_hash_with_record(record),
            empty_hash,
            "the deactivation boundary is exclusive"
        );
    }

    #[test]
    fn staged_lane_hash_binds_catalog_routing_and_amx_policy() {
        let records = [(LaneId::SINGLE, peer(0x63), 9)];
        let baseline = lane_hash_world(&records);
        let mut changed_catalog = lane_hash_world(&records);
        let catalog = DataSpaceCatalog::new(vec![
            DataSpaceMetadata::default(),
            DataSpaceMetadata {
                id: DataSpaceId::new(7),
                alias: "runtime-only-extra".to_owned(),
                description: None,
                fault_tolerance: 1,
            },
        ])
        .expect("valid runtime catalog");
        changed_catalog.set_dataspace_catalog_for_testing(catalog);
        assert_ne!(
            baseline.view().world().dataspace_catalog(),
            changed_catalog.view().world().dataspace_catalog(),
        );
        assert_ne!(
            staged_context_hash(&baseline),
            staged_context_hash(&changed_catalog),
            "dataspace catalog changes must alter the signed height context",
        );
        let mut changed_amx = lane_hash_world(&records);
        let mut pipeline = changed_amx.pipeline_snapshot();
        pipeline.amx_group_budget_ms = pipeline.amx_group_budget_ms.saturating_add(1);
        changed_amx.set_pipeline(pipeline);
        assert_ne!(
            staged_context_hash(&baseline),
            staged_context_hash(&changed_amx),
            "AMX policy changes must alter the signed height context",
        );
    }

    #[test]
    fn staged_preimage_hashes_to_the_staged_context_and_decodes() {
        let state = lane_hash_world(&[(LaneId::SINGLE, peer(0x65), 4)]);
        let block = state.block(genesis_header());
        let preimage = staged_genesis_nexus_amx_context_preimage(&block);
        assert_eq!(
            Hash::new(&preimage),
            staged_genesis_nexus_amx_context_hash(&block)
        );
        let catalog = iroha_data_model::nexus::decode_nexus_amx_context_v1(&preimage)
            .expect("the staged preimage is a canonical context");
        assert_eq!(
            catalog.lanes(),
            block.nexus.lane_catalog.consensus_projection().1.as_slice()
        );
    }

    #[test]
    fn staged_execution_policy_hash_is_deterministic_and_binds_the_pipeline() {
        let baseline = lane_hash_world(&[]);
        let expected = {
            let staged = baseline.block(genesis_header());
            let first = staged_genesis_execution_policy_hash(&staged).expect("derive policy");
            let second = staged_genesis_execution_policy_hash(&staged).expect("derive policy");
            assert_eq!(first, second);
            first
        };
        let mut drifted = baseline;
        let mut pipeline = drifted.pipeline_snapshot();
        pipeline.overlay_max_bytes = pipeline.overlay_max_bytes.saturating_add(1);
        drifted.set_pipeline(pipeline);
        let staged = drifted.block(genesis_header());
        assert_ne!(
            staged_genesis_execution_policy_hash(&staged).expect("derive drifted policy"),
            expected,
            "a pipeline change must alter the execution policy hash"
        );
    }
}
