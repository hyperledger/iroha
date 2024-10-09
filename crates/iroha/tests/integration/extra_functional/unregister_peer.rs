use std::time::Duration;

use assert_matches::assert_matches;
use eyre::Result;
use iroha::{
    client,
    client::Client,
    data_model::{parameter::BlockParameter, prelude::*},
};
use iroha_test_network::{NetworkBuilder, NetworkPeer};
use iroha_test_samples::gen_account_in;
use nonzero_ext::nonzero;
use tokio::{task::spawn_blocking, time::sleep};

#[tokio::test]
async fn network_stable_after_add_and_after_remove_peer() -> Result<()> {
    const PIPELINE_TIME: Duration = Duration::from_millis(300);

    // Given a network
    let mut network = NetworkBuilder::new()
        .with_pipeline_time(PIPELINE_TIME)
        .with_peers(4)
        .with_genesis_instruction(SetParameter::new(Parameter::Block(
            BlockParameter::MaxTransactions(nonzero!(1_u64)),
        )))
        .start()
        .await?;
    let client = network.client();

    let (account, _account_keypair) = gen_account_in("domain");
    let asset_def: AssetDefinitionId = "xor#domain".parse()?;
    {
        let client = client.clone();
        let account = account.clone();
        let asset_def = asset_def.clone();
        spawn_blocking(move || {
            client.submit_all_blocking::<InstructionBox>([
                Register::domain(Domain::new("domain".parse()?)).into(),
                Register::account(Account::new(account)).into(),
                Register::asset_definition(AssetDefinition::numeric(asset_def)).into(),
            ])
        })
        .await??; // blocks=2
    }

    // When assets are minted
    mint(&client, &asset_def, &account, numeric!(100)).await?;
    network.ensure_blocks(3).await?;
    // and a new peer is registered
    let new_peer = NetworkPeer::generate();
    let new_peer_id = new_peer.id();
    let new_peer_client = new_peer.client();
    network.add_peer(&new_peer);
    new_peer.start(network.config(), None).await;
    {
        let client = client.clone();
        let id = new_peer_id.clone();
        spawn_blocking(move || client.submit_blocking(Register::peer(Peer::new(id)))).await??;
    }
    network.ensure_blocks(4).await?;
    // Then the new peer should already have the mint result.
    assert_eq!(
        find_asset(&new_peer_client, &account, &asset_def).await?,
        numeric!(100)
    );

    // When a peer is unregistered
    {
        let client = client.clone();
        spawn_blocking(move || client.submit_blocking(Unregister::peer(new_peer_id))).await??;
        // blocks=6
    }
    network.remove_peer(&new_peer);
    // We can mint without an error.
    mint(&client, &asset_def, &account, numeric!(200)).await?;
    // Assets are increased on the main network.
    network.ensure_blocks(6).await?;
    assert_eq!(
        find_asset(&client, &account, &asset_def).await?,
        numeric!(300)
    );
    // But not on the unregistered peer's network.
    sleep(PIPELINE_TIME * 5).await;
    assert_eq!(
        find_asset(&new_peer_client, &account, &asset_def).await?,
        numeric!(100)
    );

    Ok(())
}

async fn find_asset(
    client: &Client,
    account: &AccountId,
    asset_definition: &AssetDefinitionId,
) -> Result<Numeric> {
    let account_id = account.clone();
    let client = client.clone();
    let asset = spawn_blocking(move || {
        client
            .query(client::asset::all())
            .filter_with(|asset| asset.id.account.eq(account_id.clone()))
            .execute_all()
    })
    .await??
    .into_iter()
    .find(|asset| asset.id().definition() == asset_definition)
    .expect("asset should be there");

    assert_matches!(asset.value(), AssetValue::Numeric(quantity) => Ok(*quantity))
}

async fn mint(
    client: &Client,
    asset_definition_id: &AssetDefinitionId,
    account_id: &AccountId,
    quantity: Numeric,
) -> Result<()> {
    let mint_asset = Mint::asset_numeric(
        quantity,
        AssetId::new(asset_definition_id.clone(), account_id.clone()),
    );
    let client = client.clone();
    spawn_blocking(move || client.submit_blocking(mint_asset)).await??;
    Ok(())
}
