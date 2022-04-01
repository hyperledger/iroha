#![allow(missing_docs, clippy::pedantic, clippy::restriction)]

use iroha::samples::get_config;
use iroha_core::{
    genesis::{GenesisNetwork, GenesisNetworkTrait, GenesisTransaction, RawGenesisBlock},
    prelude::*,
};
use iroha_data_model::prelude::*;
use test_network::{get_key_pair, Peer as TestPeer, TestRuntime};
use tokio::runtime::Runtime;

fn main() {
    fn generate_accounts(num: u32) -> small::SmallVec<[GenesisTransaction; 2]> {
        use iroha_data_model::*;

        let mut ret = small::SmallVec::new();
        for i in 0_u32..num {
            ret.push(GenesisTransaction::new(
                format!("Alice-{}", i).parse().expect("Valid"),
                format!("wonderland-{}", i).parse().expect("Valid"),
                PublicKey::default(),
            ));
            let asset_definition_id = AssetDefinitionId::new(
                format!("xor-{}", num).parse().expect("Valid"),
                format!("wonderland-{}", num).parse().expect("Valid"),
            );
            let create_asset =
                RegisterBox::new(AssetDefinition::new_quantity(asset_definition_id.clone()));
            ret.push(GenesisTransaction {
                isi: small::SmallVec(smallvec::smallvec![create_asset.into()]),
            });
        }
        ret
    }

    fn generate_genesis(num: u32) -> RawGenesisBlock {
        let transactions = generate_accounts(num);
        RawGenesisBlock { transactions }
    }
    let mut peer = <TestPeer>::new().expect("Failed to create peer");
    let configuration = get_config(
        std::iter::once(peer.id.clone()).collect(),
        Some(get_key_pair()),
    );
    let rt = Runtime::test();
    let genesis = GenesisNetwork::from_configuration(
        true,
        generate_genesis(1_000_000_u32),
        &configuration.genesis,
        &configuration.sumeragi.transaction_limits,
    )
    .expect("genesis creation failed");

    // This only submits the genesis. It doesn't check if the accounts
    // are created, because that check is 1) not needed for what the
    // test is actually for, 2) incredibly slow, making this sort of
    // test impractical, 3) very likely to overflow memory on systems
    // with less than 16GiB of free memory.
    rt.block_on(peer.start_with_config(genesis, configuration));
}
