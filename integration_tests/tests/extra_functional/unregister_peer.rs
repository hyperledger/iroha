//! Peer unregister flows under churn.
use eyre::{Report, Result, WrapErr, eyre};
use integration_tests::sandbox;
use iroha::{
    blocking::Client,
    data_model::{isi::register::RegisterPeerWithPop, parameter::BlockParameter, prelude::*},
};
use iroha_model_base::domain::DomainId;
use iroha_test_network::{NetworkBuilder, NetworkPeer, domain_setup_instruction};
use iroha_test_samples::gen_account_in;
use nonzero_ext::nonzero;
use std::time::{Duration, Instant};
use tokio::{
    task::spawn_blocking,
    time::{sleep, timeout},
};
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn network_stable_after_add_and_after_remove_peer() -> Result<()> {
    const PIPELINE_TIME: Duration = Duration::from_secs(2);
    // Given a network
    let builder = NetworkBuilder::new()
        .with_block_cadence(PIPELINE_TIME)
        .with_peers(4)
        .with_max_validator_capacity(5)
        .with_genesis_instruction(SetParameter::new(Parameter::Block(
            BlockParameter::MaxTransactions(nonzero!(1_u64)),
        )));
    let Some(network) = sandbox::start_network_async_or_skip(
        builder,
        stringify!(network_stable_after_add_and_after_remove_peer),
    )
    .await?
    else {
        return Ok(());
    };
    // Late-join and removal flows replay DA/RBC history while the validator set is changing, so
    // give them a wider budget than steady-state block waits.
    let sync_timeout = network.sync_timeout().saturating_mul(3);
    let tx_timeout = sync_timeout;
    let client = network.client();
    let (account, _account_keypair) = gen_account_in("domain");
    let domain_id: DomainId = DomainId::try_new("domain", "universal")?;
    let asset_def: AssetDefinitionId = AssetDefinitionId::derive_from_components(
        DomainId::try_new("domain", "universal")?,
        "xor".parse()?,
    );
    // Register a new peer early to keep the pre-join block history short.
    let new_peer = NetworkPeer::builder().build(network.env());
    let new_peer_id = new_peer.id();
    let new_peer_client = new_peer.client();
    let register_peer = RegisterPeerWithPop::new(
        new_peer_id.clone(),
        new_peer
            .bls_pop()
            .expect("network peer should have BLS PoP")
            .to_vec(),
    );
    submit_or_skip(
        client.clone(),
        register_peer,
        tx_timeout,
        "network_stable_after_add_and_after_remove_peer register_peer",
    )
    .await?;
    if sandbox::handle_result(
        wait_for_peer_count(&client, 5, sync_timeout).await,
        stringify!(network_stable_after_add_and_after_remove_peer),
    )?
    .is_none()
    {
        return Ok(());
    }
    let mut expected_height = timeout(tx_timeout, client.client().status().get())
        .await
        .map_err(|_| {
            eyre!("network_stable_after_add_and_after_remove_peer fetch status timed out")
        })??
        .blocks;
    let genesis = network.genesis();
    if let Err(err) = new_peer
        .start(
            network.config_layers_with_additional_peers([&new_peer]),
            Some(&genesis),
        )
        .await
    {
        if let Some(reason) = sandbox::sandbox_reason(&err) {
            return Err(err.wrap_err(format!(
                "sandboxed network restriction detected while starting new peer: {reason}"
            )));
        }
        return Err(err);
    }
    if sandbox::handle_result(
        timeout(sync_timeout, new_peer.once_block(expected_height))
            .await
            .wrap_err_with(|| {
                format!("new peer did not sync to height {expected_height} before timeout")
            }),
        stringify!(network_stable_after_add_and_after_remove_peer),
    )?
    .is_none()
    {
        return Ok(());
    }
    let setup_domain = domain_setup_instruction(&domain_id, client.client().account())?;
    run_blocking_with_timeout(
        {
            let client = client.clone();
            let account = account.clone();
            let asset_def = asset_def.clone();
            let setup_domain = setup_domain.clone();
            move || {
                client
                    .submit_all::<InstructionBox>(
                        [
                            setup_domain,
                            Register::account(Account::new(account.clone())).into(),
                            Register::asset_definition({
                                let __asset_definition_id = asset_def;
                                AssetDefinition::numeric(
                                    __asset_definition_id.clone(),
                                    "xor".to_owned(),
                                    iroha_data_model::asset::AssetBalancePolicy::Global,
                                    None,
                                )
                            })
                            .into(),
                        ],
                        iroha::data_model::transaction::FeePaymentIntent::authority(
                            Vec::new(),
                            None,
                        ),
                    )
                    .map(|_| ())
            }
        },
        tx_timeout,
        "network_stable_after_add_and_after_remove_peer register bootstrap",
    )
    .await?;
    expected_height = expected_height.saturating_add(1);
    if sandbox::handle_result(
        network.ensure_blocks(expected_height).await,
        stringify!(network_stable_after_add_and_after_remove_peer),
    )?
    .is_none()
    {
        return Ok(());
    }
    // When assets are minted
    mint(&client, &asset_def, &account, 100_u32.into(), tx_timeout).await?;
    expected_height = expected_height.saturating_add(1);
    if sandbox::handle_result(
        network.ensure_blocks(expected_height).await,
        stringify!(network_stable_after_add_and_after_remove_peer),
    )?
    .is_none()
    {
        return Ok(());
    }
    let main_bootstrap_asset = match sandbox::handle_result(
        wait_for_asset(
            &client,
            &account,
            &asset_def,
            sync_timeout,
            Some(100_u32.into()),
        )
        .await,
        stringify!(network_stable_after_add_and_after_remove_peer),
    )? {
        Some(value) => value,
        None => return Ok(()),
    };
    assert_eq!(main_bootstrap_asset, Quantity::from(100_u32));
    // The new peer should already have the mint result.
    let new_peer_asset = match sandbox::handle_result(
        wait_for_asset(
            &new_peer_client,
            &account,
            &asset_def,
            sync_timeout,
            Some(100_u32.into()),
        )
        .await,
        stringify!(network_stable_after_add_and_after_remove_peer),
    )? {
        Some(value) => value,
        None => return Ok(()),
    };
    assert_eq!(new_peer_asset, Quantity::from(100_u32));
    // When a peer is unregistered
    submit_or_skip(
        client.clone(),
        Unregister::peer(new_peer_id),
        tx_timeout,
        "network_stable_after_add_and_after_remove_peer unregister_peer",
    )
    .await?;
    if sandbox::handle_result(
        wait_for_peer_count(&client, 4, sync_timeout).await,
        stringify!(network_stable_after_add_and_after_remove_peer),
    )?
    .is_none()
    {
        return Ok(());
    }
    expected_height = timeout(tx_timeout, client.client().status().get())
        .await
        .map_err(|_| eyre!("network_stable_after_add_and_after_remove_peer refresh status after unregister timed out"))??
        .blocks;
    // We can mint without an error.
    mint(&client, &asset_def, &account, 200_u32.into(), tx_timeout).await?;
    expected_height = expected_height.saturating_add(1);
    if sandbox::handle_result(
        network.ensure_blocks(expected_height).await,
        stringify!(network_stable_after_add_and_after_remove_peer),
    )?
    .is_none()
    {
        return Ok(());
    }
    // Assets are increased on the main network.
    let main_asset = match sandbox::handle_result(
        wait_for_asset(
            &client,
            &account,
            &asset_def,
            sync_timeout,
            Some(300_u32.into()),
        )
        .await,
        stringify!(network_stable_after_add_and_after_remove_peer),
    )? {
        Some(value) => value,
        None => return Ok(()),
    };
    assert_eq!(main_asset, Quantity::from(300_u32));
    // Removed peers should not observe new mints after unregister.
    sleep(PIPELINE_TIME * 5).await;
    let unregistered_asset = match sandbox::handle_result(
        wait_for_asset(
            &new_peer_client,
            &account,
            &asset_def,
            sync_timeout,
            Some(100_u32.into()),
        )
        .await,
        stringify!(network_stable_after_add_and_after_remove_peer),
    )? {
        Some(value) => value,
        None => return Ok(()),
    };
    assert_eq!(unregistered_asset, Quantity::from(100_u32));
    Ok(())
}
async fn find_asset(
    client: &Client,
    account: &AccountId,
    asset_definition: &AssetDefinitionId,
) -> Result<Option<Quantity>> {
    let account_id = account.clone();
    let client = client.clone();
    let asset = spawn_blocking(move || client.client().query(FindAssets::new()).execute_all())
        .await??
        .into_iter()
        .filter(|asset| asset.id().account() == &account_id)
        .find(|asset| asset.id().definition() == asset_definition);
    Ok(asset.map(|asset| asset.value().clone()))
}
async fn wait_for_asset(
    client: &Client,
    account: &AccountId,
    asset_definition: &AssetDefinitionId,
    timeout_duration: Duration,
    expected: Option<Quantity>,
) -> Result<Quantity> {
    let deadline = Instant::now() + timeout_duration;
    let mut last_err: Option<Report> = None;
    loop {
        match find_asset(client, account, asset_definition).await {
            Ok(Some(value)) if expected.as_ref().is_none_or(|expected| value == *expected) => {
                return Ok(value);
            }
            Ok(_) => {}
            Err(err) => {
                last_err = Some(err);
            }
        }
        if Instant::now() >= deadline {
            if expected.is_some() {
                return Err(eyre!(
                    "timed out waiting for asset to reach expected value; last_err={last_err:?}"
                ));
            }
            return Err(eyre!(
                "timed out waiting for asset to appear; last_err={last_err:?}"
            ));
        }
        sleep(Duration::from_millis(200)).await;
    }
}
async fn mint(
    client: &Client,
    asset_definition_id: &AssetDefinitionId,
    account_id: &AccountId,
    quantity: Quantity,
    timeout_duration: Duration,
) -> Result<()> {
    let mint_asset = Mint::asset_quantity(
        quantity,
        AssetId::new(asset_definition_id.clone(), account_id.clone()),
    );
    let client = client.clone();
    submit_or_skip(
        client,
        mint_asset,
        timeout_duration,
        "network_stable_after_add_and_after_remove_peer mint",
    )
    .await
}
async fn submit_or_skip<I>(
    client: Client,
    instruction: I,
    timeout_duration: Duration,
    context: &str,
) -> Result<()>
where
    I: Into<InstructionBox> + Send + 'static,
{
    let context_owned = context.to_string();
    run_blocking_with_timeout(
        move || {
            client
                .submit(
                    instruction,
                    iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
                )
                .map(|_| ())
                .wrap_err_with(|| context_owned.clone())
        },
        timeout_duration,
        context,
    )
    .await
}
async fn run_blocking_with_timeout<T, F>(
    task: F,
    timeout_duration: Duration,
    context: &str,
) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    let join = spawn_blocking(task);
    let result = timeout(timeout_duration, join)
        .await
        .map_err(|_| eyre!("{context} timed out"))?;
    result.map_err(Report::new)?
}
async fn wait_for_peer_count(
    client: &Client,
    expected: usize,
    timeout_duration: Duration,
) -> Result<()> {
    let deadline = Instant::now() + timeout_duration;
    loop {
        let count = spawn_blocking({
            let client = client.clone();
            move || {
                client
                    .client()
                    .query(FindPeers)
                    .execute_all()
                    .map(|peers| peers.len())
            }
        })
        .await??;
        if count == expected {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(eyre!(
                "timed out waiting for peer count {expected}, last seen {count}"
            ));
        }
        sleep(Duration::from_millis(200)).await;
    }
}
