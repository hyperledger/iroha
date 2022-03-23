#![allow(clippy::restriction)]

use std::{str::FromStr as _, thread};

use iroha_client::client::transaction;
use iroha_data_model::prelude::*;
use test_network::{Peer as TestPeer, *};

use super::Configuration;

#[test]
fn client_has_rejected_and_acepted_txs_should_return_tx_history() {
    let (_rt, _peer, mut iroha_client) = <TestPeer>::start_test_with_runtime();
    wait_for_genesis_committed(&vec![iroha_client.clone()], 0);

    let pipeline_time = Configuration::pipeline_time();

    // Given
    let account_id = AccountId::from_str("alice@wonderland").expect("Valid");
    let asset_definition_id = AssetDefinitionId::from_str("xor#wonderland").expect("Valid");
    let create_asset = RegisterBox::new(AssetDefinition::new_quantity(asset_definition_id.clone()));
    iroha_client
        .submit(create_asset)
        .expect("Failed to prepare state.");

    thread::sleep(pipeline_time * 2);

    //When
    let quantity: u32 = 200;
    let asset_id = AssetId::new(asset_definition_id, account_id.clone());
    let mint_existed_asset = MintBox::new(Value::U32(quantity), IdBox::AssetId(asset_id));
    let mint_not_existed_asset = MintBox::new(
        Value::U32(quantity),
        IdBox::AssetId(AssetId::new(
            AssetDefinitionId::from_str("foo#wonderland").expect("Valid"),
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
        let instructions: Vec<Instruction> = vec![mint_asset.clone().into()];
        let transaction = iroha_client
            .build_transaction(instructions.into(), UnlimitedMetadata::new())
            .expect("Failed to create transaction");
        iroha_client
            .submit_transaction(transaction)
            .expect("Failed to submit transaction");
    }
    thread::sleep(pipeline_time * 5);

    let transactions = iroha_client
        .request_with_pagination(
            transaction::by_account_id(account_id.clone()),
            Pagination {
                start: Some(1),
                limit: Some(50),
            },
        )
        .expect("Failed to get transaction history");
    assert_eq!(transactions.len(), 50);

    let mut prev_creation_time = 0;
    for tx in &transactions {
        assert_eq!(&tx.payload().account_id, &account_id);
        //check sorted
        assert!(tx.payload().creation_time >= prev_creation_time);
        prev_creation_time = tx.payload().creation_time;
    }
}
