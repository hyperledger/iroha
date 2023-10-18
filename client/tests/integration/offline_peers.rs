use eyre::Result;
use iroha_client::client::{self, QueryResult};
use iroha_data_model::{
    parameter::{default::MAX_TRANSACTIONS_IN_BLOCK, ParametersBuilder},
    prelude::*,
};
use test_network::*;
use tokio::runtime::Runtime;

#[test]
fn genesis_block_is_committed_with_some_offline_peers() -> Result<()> {
    // Given
    let rt = Runtime::test();

    let (network, client) = rt.block_on(<Network>::start_test_with_offline_and_set_n_shifts(
        4,
        1,
        Some(10_560),
    ));
    wait_for_genesis_committed(&network.clients(), 1);

    client.submit_blocking(
        ParametersBuilder::new()
            .add_parameter(MAX_TRANSACTIONS_IN_BLOCK, 1u32)?
            .into_set_parameters(),
    )?;

    //When
    let alice_id: AccountId = "alice@wonderland".parse()?;
    let roses = "rose#wonderland".parse()?;
    let alice_has_roses = 13;

    //Then
    let assets = client
        .seek(client.request(client::asset::by_account_id(alice_id))?)
        .collect::<QueryResult<Vec<_>>>()?;
    let asset = assets
        .iter()
        .find(|asset| asset.id().definition_id == roses)
        .unwrap();
    assert_eq!(AssetValue::Quantity(alice_has_roses), *asset.value());
    Ok(())
}
