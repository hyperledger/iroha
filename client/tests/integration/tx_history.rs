#![allow(clippy::restriction)]

use std::{str::FromStr as _, thread};

use eyre::Result;
use iroha_client::client::transaction;
use iroha_data_model::prelude::*;
use test_network::*;

use super::Configuration;

#[ignore = "ignore, more in #2851"]
#[test]
fn client_has_rejected_and_acepted_txs_should_return_tx_history() -> Result<()> {
    let (_rt, _peer, client) = <PeerBuilder>::new().with_port(10_715).start_with_runtime();
    wait_for_genesis_committed(&vec![client.clone()], 0);

    let pipeline_time = Configuration::pipeline_time();

    // Given
    let account_id = AccountId::from_str("alice@wonderland")?;
    let asset_definition_id = AssetDefinitionId::from_str("xor#wonderland")?;
    let create_asset = RegisterBox::new(AssetDefinition::quantity(asset_definition_id.clone()));
    client.submit_blocking(create_asset)?;

    //When
    let quantity: u32 = 200;
    let asset_id = AssetId::new(asset_definition_id, account_id.clone());
    let mint_existed_asset = MintBox::new(quantity.to_value(), IdBox::AssetId(asset_id));
    let mint_not_existed_asset = MintBox::new(
        quantity.to_value(),
        IdBox::AssetId(AssetId::new(
            AssetDefinitionId::from_str("foo#wonderland")?,
            account_id.clone(),
        )),
    );

    let transactions_count = 100;

    for i in 0..transactions_count {
        let mint_asset = if i % 2 == 0 {
            &mint_existed_asset
        } else {
            &mint_not_existed_asset
        };
        let instructions: Vec<InstructionBox> = vec![mint_asset.clone().into()];
        let transaction = client.build_transaction(instructions, UnlimitedMetadata::new())?;
        client.submit_transaction(&transaction)?;
    }
    thread::sleep(pipeline_time * 5);

    let transactions = client
        .request_with_pagination(
            transaction::by_account_id(account_id.clone()),
            Pagination::new(Some(1), Some(50)),
        )?
        .only_output();
    assert_eq!(transactions.len(), 50);

    let mut prev_creation_time = core::time::Duration::from_millis(0);
    for tx in &transactions {
        assert_eq!(tx.payload().authority(), &account_id);
        //check sorted
        assert!(tx.payload().creation_time() >= prev_creation_time);
        prev_creation_time = tx.payload().creation_time();
    }
    Ok(())
}
