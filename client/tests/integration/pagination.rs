#![allow(clippy::restriction)]

use std::thread;

use iroha_client::client::asset;
use iroha_data_model::prelude::*;
use test_network::{Peer as TestPeer, *};

use super::Configuration;

#[test]
fn client_add_asset_quantity_to_existing_asset_should_increase_asset_amount() {
    let (_rt, _peer, mut iroha_client) = <TestPeer>::start_test_with_runtime();
    wait_for_genesis_committed(&vec![iroha_client.clone()], 0);
    let pipeline_time = Configuration::pipeline_time();

    let register: Vec<Instruction> = ('a'..'z')
        .map(|c| c.to_string())
        .map(|name| (name + "#wonderland").parse().expect("Valid"))
        .map(|asset_definition_id| {
            Instruction::Register(RegisterBox::new(
                AssetDefinition::quantity(asset_definition_id).build(),
            ))
        })
        .collect();
    iroha_client
        .submit_all(register)
        .expect("Failed to prepare state.");

    thread::sleep(pipeline_time);
    //When

    let vec = iroha_client
        .request_with_pagination(
            asset::all_definitions(),
            Pagination {
                start: Some(5),
                limit: Some(5),
            },
        )
        .expect("Failed to get assets")
        .only_output();
    assert_eq!(vec.len(), 5);
}
