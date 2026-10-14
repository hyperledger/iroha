//! Tests for batched transfer transcripts.

use iroha_core::{
    fastpq,
    kura::Kura,
    query::store::LiveQueryStore,
    smartcontracts::Execute,
    state::{State, World, WorldReadOnly},
};
use iroha_data_model::prelude::*;
use iroha_model_base::domain::DomainId;
use iroha_test_samples::{ALICE_ID, gen_account_in};
use nonzero_ext::nonzero;
#[test]
fn single_transfer_finalizes_canonical_poseidon_digest_on_block_drain() {
    // Direct execution and transcript draining share the block witness recorder.
    let _witness_guard = iroha_core::exec_witness::exec_witness_guard();
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
    let domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
    let (bob_id, _) = gen_account_in("wonderland");
    let alice_account = Account::new(ALICE_ID.clone()).build(&ALICE_ID);
    let bob_account = Account::new(bob_id.clone()).build(&ALICE_ID);
    let asset_def_id: AssetDefinitionId = AssetDefinitionId::derive_from_components(
        DomainId::try_new("wonderland", "universal").expect("domain id"),
        "rose".parse().expect("asset name"),
    );
    let asset_def = AssetDefinition::numeric(
        asset_def_id.clone(),
        "rose".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&ALICE_ID);
    let alice_asset = Asset::new(
        AssetId::new(asset_def_id.clone(), ALICE_ID.clone()),
        Quantity::from(100_u32),
    );
    let world = World::with_assets(
        [domain],
        [alice_account, bob_account],
        [asset_def],
        [alice_asset],
        [],
    );
    let kura = Kura::blank_kura_for_testing();
    let query_store = LiveQueryStore::start_test();
    let state = State::new_for_testing(world, kura, query_store);
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut tx = block.transaction();
    tx.tx_call_hash = Some(Hash::prehashed([0xCD; Hash::LENGTH]));
    Transfer::asset_quantity(AssetId::new(asset_def_id, ALICE_ID.clone()), 10_u32, bob_id)
        .execute(&ALICE_ID, &mut tx)
        .expect("transfer executes successfully");
    tx.apply();
    let transcripts = block.drain_transfer_transcripts();
    let entry = transcripts
        .values()
        .next()
        .expect("transcript recorded for transfer");
    assert_eq!(entry.len(), 1, "single transfer transcript recorded");
    assert_eq!(entry[0].deltas.len(), 1, "single delta recorded");
    assert_eq!(
        entry[0].poseidon_preimage_digest,
        Some(fastpq::poseidon_preimage_digest(
            &entry[0].deltas[0],
            &entry[0].batch_hash,
        ))
    );
}
#[test]
fn transfer_asset_batch_records_multi_delta_transcript() {
    // Direct execution and transcript draining share the block witness recorder.
    let _witness_guard = iroha_core::exec_witness::exec_witness_guard();
    let domain_id: DomainId = DomainId::try_new("wonderland", "universal").expect("domain id");
    let domain = Domain::new(domain_id.clone()).build(&ALICE_ID);
    let (bob_id, _) = gen_account_in("wonderland");
    let (carol_id, _) = gen_account_in("wonderland");
    let alice_account = Account::new(ALICE_ID.clone()).build(&ALICE_ID);
    let bob_account = Account::new(bob_id.clone()).build(&ALICE_ID);
    let carol_account = Account::new(carol_id.clone()).build(&ALICE_ID);
    let asset_def_id: AssetDefinitionId =
        iroha_data_model::asset::AssetDefinitionId::derive_from_components(
            DomainId::try_new("wonderland", "universal").unwrap(),
            "rose".parse().unwrap(),
        );
    let asset_def = AssetDefinition::numeric(
        asset_def_id.clone(),
        "rose".to_owned(),
        iroha_data_model::asset::AssetBalancePolicy::Global,
        None,
    )
    .build(&ALICE_ID);
    let alice_asset = Asset::new(
        AssetId::new(asset_def_id.clone(), ALICE_ID.clone()),
        Quantity::from(100_u32),
    );
    let world = World::with_assets(
        [domain],
        [alice_account, bob_account, carol_account],
        [asset_def],
        [alice_asset],
        [],
    );
    let kura = Kura::blank_kura_for_testing();
    let query_store = LiveQueryStore::start_test();
    let state = State::new_for_testing(world, kura, query_store);
    let header = BlockHeader::new(nonzero!(1_u64), None, None, 0, 0);
    let mut block = state.block(header);
    let mut tx = block.transaction();
    tx.tx_call_hash = Some(Hash::prehashed([0xAB; Hash::LENGTH]));
    let batch = TransferAssetBatch::new(vec![
        TransferAssetBatchEntry::new(
            ALICE_ID.clone(),
            bob_id.clone(),
            asset_def_id.clone(),
            10_u32,
        ),
        TransferAssetBatchEntry::new(
            ALICE_ID.clone(),
            carol_id.clone(),
            asset_def_id.clone(),
            5_u32,
        ),
    ]);
    batch
        .execute(&ALICE_ID, &mut tx)
        .expect("batch executes successfully");
    tx.apply();
    let transcripts = block.drain_transfer_transcripts();
    assert_eq!(transcripts.len(), 1);
    let entry = transcripts
        .values()
        .next()
        .expect("transcript recorded for batch");
    assert_eq!(entry.len(), 1, "single transcript for batch");
    assert_eq!(entry[0].deltas.len(), 2, "two deltas recorded");
    assert!(entry[0].poseidon_preimage_digest.is_none());
    let world = &block.world;
    let alice_asset_id = AssetId::new(asset_def_id.clone(), ALICE_ID.clone());
    let bob_asset_id = AssetId::new(asset_def_id.clone(), bob_id);
    let carol_asset_id = AssetId::new(asset_def_id, carol_id);
    let alice_balance = world.asset(&alice_asset_id).expect("alice asset");
    assert_eq!(**alice_balance, Quantity::from(85_u32));
    let bob_balance = world.asset(&bob_asset_id).expect("bob asset");
    assert_eq!(**bob_balance, Quantity::from(10_u32));
    let carol_balance = world.asset(&carol_asset_id).expect("carol asset");
    assert_eq!(**carol_balance, Quantity::from(5_u32));
}
