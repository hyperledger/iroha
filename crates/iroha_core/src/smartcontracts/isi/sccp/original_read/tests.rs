//! Original consensus facts survive applied siblings and replacement overlays.

use super::*;
use crate::{
    smartcontracts::isi::sccp::{
        anchor_record::RetainedSccpAnchors, committee_storage::CommitteeFixtureStorage as _,
        test_support::sample_generation,
    },
    state::World,
};
use iroha_data_model::sccp::params::SccpParametersV1;

#[test]
fn replacement_parent_keeps_original_generations_clock_anchors_and_finality() {
    let world = World::new();
    let budget = world.sccp_committee_generations.allocation_budget();
    let anchor = SccpAnchorV1 {
        core_hash: [1; 32],
        result: [2; 32],
    };
    {
        let mut block = world.block();
        *block.sccp_parameters.get_mut() = Some(SccpParametersV1::taira_default());
        *block.sccp_committee_current.get_mut() = 3;
        *block.sccp_liability_clock.get_mut() = 11;
        *block.sccp_degraded_run.get_mut() = 1;
        *block.sccp_anchor_open.get_mut() = RetainedSccpAnchors::admit(&[anchor], budget).unwrap();
        block
            .sccp_anchor_chunks
            .try_insert_admitted(0, [3; 32])
            .unwrap();
        block
            .sccp_committee_generations
            .insert(1, sample_generation(1));
        block
            .sccp_committee_generations
            .insert(3, sample_generation(3));
        block.commit();
    }
    {
        let mut successor = world.block();
        successor
            .sccp_parameters
            .get_mut()
            .as_mut()
            .unwrap()
            .enabled = false;
        *successor.sccp_committee_current.get_mut() = 4;
        *successor.sccp_liability_clock.get_mut() = 22;
        *successor.sccp_degraded_run.get_mut() = 0;
        *successor.sccp_anchor_open.get_mut() = RetainedSccpAnchors::default();
        successor.sccp_anchor_chunks.try_remove_admitted(0).unwrap();
        successor.sccp_committee_generations.remove(1);
        successor
            .sccp_committee_generations
            .insert(2, sample_generation(2));
        successor.commit();
    }
    let published = world.view();
    assert!(!Current(&published).parameters().unwrap().enabled);
    assert_eq!(Current(&published).committee_current(), 4);
    assert_eq!(Current(&published).liability_clock(), 22);
    assert_eq!(Current(&published).degraded_run(), 0);
    assert!(Current(&published).generation(1).is_none());
    assert!(Current(&published).anchor_open().is_empty());
    assert!(Current(&published).anchor_chunk(0).is_none());
    let mut replacement = world.block_and_revert();
    for apply in [true, false] {
        let mut tx = replacement.transaction_without_telemetry(
            iroha_config::parameters::actual::LaneConfig::default(),
            0,
        );
        tx.sccp_parameters.get_mut().as_mut().unwrap().enabled = false;
        *tx.sccp_committee_current.get_mut() = 8;
        *tx.sccp_liability_clock.get_mut() = 99;
        *tx.sccp_degraded_run.get_mut() = 9;
        *tx.sccp_anchor_open.get_mut() = RetainedSccpAnchors::default();
        tx.sccp_anchor_chunks
            .try_insert_admitted(0, [9; 32])
            .unwrap();
        tx.sccp_committee_generations.remove(1);
        tx.sccp_committee_generations
            .insert(2, sample_generation(2));
        tx.sccp_committee_generations
            .insert(3, sample_generation(4));
        let parent = TransactionParent(&tx);
        assert!(parent.parameters().unwrap().enabled);
        assert_eq!(parent.committee_current(), 3);
        assert_eq!(parent.liability_clock(), 11);
        assert_eq!(parent.degraded_run(), 1);
        assert_eq!(parent.generation(1).unwrap().generation, 1);
        assert!(parent.generation(2).is_none());
        assert_eq!(parent.generation(3).unwrap().generation, 3);
        assert_eq!(parent.anchor_open(), &[anchor]);
        assert_eq!(parent.anchor_chunk(0), Some(&[3; 32]));
        assert_eq!(
            parent
                .generations()
                .map(|(key, value)| (*key, value.generation))
                .collect::<Vec<_>>(),
            vec![(1, 1), (3, 3)],
        );
        if apply {
            tx.apply();
        }
    }
    drop(replacement);
    let after = world.view();
    assert_eq!(Current(&after).committee_current(), 4);
    assert_eq!(Current(&after).liability_clock(), 22);
    assert_eq!(Current(&after).degraded_run(), 0);
    assert!(Current(&after).generation(1).is_none());
    assert_eq!(Current(&after).generation(2).unwrap().generation, 2);
}
