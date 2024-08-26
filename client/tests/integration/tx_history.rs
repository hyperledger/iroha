use std::{str::FromStr as _, thread};

use eyre::Result;
use iroha::{
    client::transaction,
    data_model::{prelude::*, query::parameters::Pagination},
};
use iroha_config::parameters::actual::Root as Config;
use nonzero_ext::nonzero;
use test_network::*;
use test_samples::ALICE_ID;

#[ignore = "ignore, more in #2851"]
#[test]
fn client_has_rejected_and_acepted_txs_should_return_tx_history() -> Result<()> {
    let (_rt, _peer, client) = <PeerBuilder>::new().with_port(10_715).start_with_runtime();
    wait_for_genesis_committed(&vec![client.clone()], 0);

    let pipeline_time = Config::pipeline_time();

    // Given
    let account_id = ALICE_ID.clone();
    let asset_definition_id = AssetDefinitionId::from_str("xor#wonderland")?;
    let create_asset =
        Register::asset_definition(AssetDefinition::numeric(asset_definition_id.clone()));
    client.submit_blocking(create_asset)?;

    //When
    let quantity = numeric!(200);
    let asset_id = AssetId::new(asset_definition_id, account_id.clone());
    let mint_existed_asset = Mint::asset_numeric(quantity, asset_id);
    let mint_not_existed_asset = Mint::asset_numeric(
        quantity,
        AssetId::new(
            AssetDefinitionId::from_str("foo#wonderland")?,
            account_id.clone(),
        ),
    );

    let transactions_count = 100;

    for i in 0..transactions_count {
        let mint_asset = if i % 2 == 0 {
            &mint_existed_asset
        } else {
            &mint_not_existed_asset
        };
        let instructions: Vec<InstructionBox> = vec![mint_asset.clone().into()];
        let transaction = client.build_transaction(instructions, Metadata::default());
        client.submit_transaction(&transaction)?;
    }
    thread::sleep(pipeline_time * 5);

    let transactions = client
        .query(transaction::by_account_id(account_id.clone()))
        .with_pagination(Pagination {
            limit: Some(nonzero!(50_u64)),
            offset: 1,
        })
        .execute_all()?;
    assert_eq!(transactions.len(), 50);

    let mut prev_creation_time = core::time::Duration::from_millis(0);
    transactions
        .iter()
        .map(AsRef::as_ref)
        .map(AsRef::as_ref)
        .for_each(|tx| {
            assert_eq!(tx.authority(), &account_id);
            //check sorted
            assert!(tx.creation_time() >= prev_creation_time);
            prev_creation_time = tx.creation_time();
        });
    Ok(())
}
