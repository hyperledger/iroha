//! Actual prepaid native-generation table current/undo and aborted transaction custody.

use super::*;
use iroha_allocation::AllocationBudget;
use iroha_crypto::{Algorithm, Hash, HashOf, KeyPair};
use iroha_data_model::{
    NetworkId,
    block::BlockHeader,
    parameter::system::ConsensusMode,
    sccp::{
        committee::{SccpGenerationCauseV1, SccpGenerationEndV1, SccpGenerationStartV1},
        params::SccpParametersV1,
    },
    sumeragi::epoch::{
        ValidatorCommitteeMemberV1, ValidatorEpochAuthorizationV1, ValidatorEpochContextV1,
        ValidatorGenerationV1,
    },
};
use iroha_model_base::peer::PeerId;

fn original(pool: &AllocationBudget) -> RetainedSccpCommitteeGeneration {
    let mut keys = (1..=4)
        .map(|seed| KeyPair::from_seed(vec![seed; 32], Algorithm::BlsNormal))
        .collect::<Vec<_>>();
    keys.sort_by_key(|key| PeerId::new(key.public_key().clone()));
    let committee = keys
        .iter()
        .map(|key| ValidatorCommitteeMemberV1 {
            validator: PeerId::new(key.public_key().clone()),
            proof_of_possession: iroha_crypto::bls_normal_pop_prove(key.private_key()).unwrap(),
        })
        .collect::<Vec<_>>();
    let network_id = NetworkId::from_genesis_hash(HashOf::<BlockHeader>::from_untyped_unchecked(
        Hash::new(b"native table custody"),
    ));
    let generation = ValidatorGenerationV1::from_committee(network_id, 0, &committee);
    let epoch = ValidatorEpochContextV1 {
        version: 1,
        network_id,
        mode: ConsensusMode::Npos,
        authorization: ValidatorEpochAuthorizationV1::genesis(&generation, 10).unwrap(),
        committee,
        leader_seed: [1; 32],
        da_layout: iroha_sumeragi::availability::recommended_data_availability_layout(),
    };
    RetainedSccpCommitteeGeneration::admit_new(
        SccpGenerationStartV1 {
            generation: 1,
            cause: SccpGenerationCauseV1::Genesis,
            height: 1,
            timestamp_ms: 100,
            liability_clock: 100,
        },
        &SccpParametersV1::taira_default(),
        &epoch,
        &[None; 4],
        pool,
    )
    .unwrap()
}

#[test]
fn actual_table_shares_original_current_undo_and_abandons_refused_child() {
    let pool = AllocationBudget::new(1 << 20);
    let original = original(&pool);
    let ended = original
        .with_lifecycle(
            Some(SccpGenerationEndV1 {
                end_height: 10,
                end_timestamp_ms: 200,
                next_committee_root: original.committee_root,
                successor_validity_ms: original.validity_ms,
            }),
            None,
            &pool,
        )
        .unwrap();
    let table = CommitteeStorage::try_new_admitted(pool.clone()).unwrap();
    table
        .try_with_admitted_block(|block| {
            block
                .try_insert_admitted(1, original.clone())
                .map_err(|(_, error)| error)?;
            Ok::<_, mv::storage::AdmittedStorageError>(())
        })
        .unwrap();
    assert!(std::ptr::eq(
        table.view().get(&1).unwrap().record(),
        original.record()
    ));
    table
        .try_with_admitted_block(|block| {
            let mut transaction = block.try_transaction_admitted()?;
            transaction
                .try_insert_admitted(1, ended.clone())
                .map_err(|(_, error)| error)?;
            transaction.apply();
            Ok::<_, mv::storage::AdmittedStorageError>(())
        })
        .unwrap();
    let snapshot = table.snapshot();
    assert!(std::ptr::eq(
        snapshot.current().get(&1).unwrap().record(),
        ended.record()
    ));
    assert!(std::ptr::eq(
        snapshot
            .revert_map()
            .get(&1)
            .unwrap()
            .as_ref()
            .unwrap()
            .record(),
        original.record()
    ));
    drop(snapshot);
    let before = pool.reserved_bytes();
    let refused = table.try_with_admitted_block(|block| {
        let mut transaction = block.try_transaction_admitted()?;
        pool.set_limit_bytes(pool.reserved_bytes());
        let (_, refusal) = transaction
            .try_insert_admitted(2, original.clone())
            .expect_err("the same original pool is full");
        assert!(matches!(
            &refusal,
            mv::storage::AdmittedStorageError::Allocation(
                iroha_allocation::AllocationRefusal::Capacity { .. }
            )
        ));
        // Even a handled refusal followed by dropping this child cannot publish its prefix.
        drop(transaction);
        Err::<(), _>(refusal)
    });
    assert!(refused.is_err());
    assert_eq!(pool.reserved_bytes(), before);
    assert!(table.view().get(&2).is_none());
    let snapshot = table.snapshot();
    assert!(std::ptr::eq(
        snapshot.current().get(&1).unwrap().record(),
        ended.record()
    ));
    assert!(std::ptr::eq(
        snapshot
            .revert_map()
            .get(&1)
            .unwrap()
            .as_ref()
            .unwrap()
            .record(),
        original.record()
    ));
    drop(snapshot);
    drop(table);
    assert_eq!(
        pool.reserved_bytes(),
        original.allocation_bytes().unwrap() + ended.allocation_bytes().unwrap()
    );
    drop((original, ended));
    assert_eq!(pool.reserved_bytes(), 0);
}
