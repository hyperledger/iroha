use eyre::Result;
use iroha::{
    client::{self},
    data_model::prelude::*,
};
use iroha_test_network::*;
use iroha_test_samples::ALICE_ID;
use tokio::{task::spawn_blocking, time::timeout};

#[tokio::test]
async fn restarted_peer_should_restore_its_state() -> Result<()> {
    let asset_definition_id = "xor#wonderland".parse::<AssetDefinitionId>()?;
    let quantity = numeric!(200);

    let network = NetworkBuilder::new().with_peers(4).start().await?;
    let peers = network.peers();

    // create state on the first peer
    let peer_a = &peers[0];
    let client = peer_a.client();
    let asset_definition_clone = asset_definition_id.clone();
    spawn_blocking(move || {
        client
            .submit_all_blocking::<InstructionBox>([
                Register::asset_definition(AssetDefinition::numeric(
                    asset_definition_clone.clone(),
                ))
                .into(),
                Mint::asset_numeric(
                    quantity,
                    AssetId::new(asset_definition_clone, ALICE_ID.clone()),
                )
                .into(),
            ])
            .unwrap();
    })
    .await?;
    network.ensure_blocks(2).await?;

    // shutdown all
    network.shutdown().await;

    // restart another one, **without a genesis** even
    let peer_b = &peers[1];
    let config = network.config();
    assert_ne!(peer_a, peer_b);
    timeout(network.peer_startup_timeout(), async move {
        peer_b.start(config, None).await;
        peer_b.once_block(2).await;
    })
    .await?;

    // ensure it has the state
    let client = peer_b.client();
    let asset = spawn_blocking(move || {
        client
            .query(client::asset::all())
            .filter_with(|asset| asset.id.account.eq(ALICE_ID.clone()))
            .execute_all()
    })
    .await??
    .into_iter()
    .find(|asset| *asset.id().definition() == asset_definition_id)
    .expect("Asset not found");
    assert_eq!(AssetValue::Numeric(quantity), *asset.value());

    Ok(())
}
