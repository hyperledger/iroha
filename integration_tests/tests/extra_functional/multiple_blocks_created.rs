//! Stress block production with randomized mint bursts.
use eyre::{Result, eyre};
use integration_tests::{sandbox, sync::get_status_with_retry_async};
use iroha::data_model::{parameter::BlockParameter, prelude::*};
use iroha_model_base::domain::DomainId;
use iroha_test_network::*;
use iroha_test_samples::gen_account_in;
use rand::{SeedableRng, prelude::IteratorRandom};
use rand_chacha::ChaCha8Rng;
use std::{
    num::NonZero,
    time::{Duration, Instant},
};
use tokio::{task::spawn_blocking, time::sleep};
/// Bombard random peers with random mints in multiple rounds, ensuring they all have
/// a consistent total amount in the end.
#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn multiple_blocks_created() -> Result<()> {
    const N_ROUNDS: u64 = 5;
    const N_MAX_TXS_PER_BLOCK: u64 = 10;
    // Given
    let builder = NetworkBuilder::new()
        .with_peers(4)
        .with_block_cadence(std::time::Duration::from_secs(2))
        .with_genesis_instruction(SetParameter::new(Parameter::Block(
            BlockParameter::MaxTransactions(NonZero::new(N_MAX_TXS_PER_BLOCK).expect("valid")),
        )));
    let Some(network) =
        sandbox::start_network_async_or_skip(builder, stringify!(multiple_blocks_created)).await?
    else {
        return Ok(());
    };
    let sync_timeout = network.sync_timeout().max(Duration::from_secs(600));
    let leader = network
        .peers()
        .iter()
        .min_by_key(|peer| peer.public_key().to_string())
        .expect("at least one peer");
    let submit_client =
        integration_tests::sync::rebind_blocking_client(&leader.client(), |client| {
            client.transaction_status_timeout = sync_timeout;
            client.transaction_ttl = Some(sync_timeout + Duration::from_secs(5));
        });
    let domain_id: DomainId = DomainId::try_new("domain", "universal")?;
    let create_domain = domain_setup_instruction(&domain_id, submit_client.client().account())?;
    let (account_id, _account_keypair) = gen_account_in("domain");
    let create_account = Register::account(Account::new(account_id.clone()));
    let asset_definition_id: AssetDefinitionId = AssetDefinitionId::derive_from_components(
        DomainId::try_new("domain", "universal")?,
        "xor".parse()?,
    );
    let create_asset = Register::asset_definition({
        let __asset_definition_id = asset_definition_id.clone();
        AssetDefinition::numeric(
            __asset_definition_id.clone(),
            "xor".to_owned(),
            iroha_data_model::asset::AssetBalancePolicy::Global,
            None,
        )
    });
    {
        let client = submit_client.clone();
        let tx = {
            let account = client.account_client();
            account
                .prepare_transaction(iroha::client::AccountTransactionDraft::new(
                    [
                        create_domain,
                        InstructionBox::from(create_account),
                        InstructionBox::from(create_asset),
                    ],
                    iroha_data_model::transaction::FeePaymentIntent::authority(Vec::new(), None),
                    <_>::default(),
                ))
                .and_then(|payload| account.sign_transaction(payload))
        }
        .expect("build integration-test transaction");
        let submit_res: eyre::Result<()> =
            spawn_blocking(move || client.submit_transaction_and_wait(&tx).map(|_| ()))
                .await
                .map_err(eyre::Report::from)?;
        if sandbox::handle_result(submit_res, stringify!(multiple_blocks_created))?.is_none() {
            return Ok(());
        }
    }
    if sandbox::handle_result(
        network.ensure_blocks(2).await,
        stringify!(multiple_blocks_created),
    )?
    .is_none()
    {
        return Ok(());
    }
    let mut last_non_empty = match sandbox::handle_result(
        get_status_with_retry_async(&submit_client).await,
        stringify!(multiple_blocks_created),
    )? {
        Some(status) => status.blocks_non_empty,
        None => return Ok(()),
    };
    // When
    let mut rng = ChaCha8Rng::seed_from_u64(0x4d55_4c54);
    let mut total: u128 = 0;
    for _ in 1..=N_ROUNDS {
        let txs = (1..=N_MAX_TXS_PER_BLOCK)
            .choose(&mut rng)
            .expect("there is a room to choose from");
        println!("submitting {txs} transactions to random peers");
        let mut submit_handles = Vec::new();
        for _ in 0..txs {
            let value = (0..999_999)
                .choose(&mut rng)
                .expect("there is quite a room to choose from");
            total += value;
            let client = submit_client.clone();
            let tx = {
                let account = client.account_client();
                account
                    .prepare_transaction(iroha::client::AccountTransactionDraft::new(
                        [Mint::asset_quantity(
                            u64::try_from(value).expect("generated quantity fits u64"),
                            AssetId::new(asset_definition_id.clone(), account_id.clone()),
                        )],
                        iroha_data_model::transaction::FeePaymentIntent::authority(
                            Vec::new(),
                            None,
                        ),
                        <_>::default(),
                    ))
                    .and_then(|payload| account.sign_transaction(payload))
            }
            .expect("build integration-test transaction");
            submit_handles.push(spawn_blocking(move || {
                client.submit_transaction_and_wait(&tx).map(|_| ())
            }));
        }
        for handle in submit_handles {
            let submit_res: eyre::Result<()> = handle.await.map_err(eyre::Report::from)?;
            if sandbox::handle_result(submit_res, stringify!(multiple_blocks_created))?.is_none() {
                return Ok(());
            }
        }
        if sandbox::handle_result(
            network
                .ensure_blocks_with(|height| height.non_empty > last_non_empty)
                .await,
            stringify!(multiple_blocks_created),
        )?
        .is_none()
        {
            return Ok(());
        }
        match sandbox::handle_result(
            get_status_with_retry_async(&submit_client).await,
            stringify!(multiple_blocks_created),
        )? {
            Some(status) => last_non_empty = status.blocks_non_empty,
            None => return Ok(()),
        }
    }
    // ensuring all have the same total
    println!("all peers should have total={total}");
    let expected_value = Quantity::from(total);
    // Give the network a chance to flush any straggling transactions before asserting.
    let deadline = Instant::now() + sync_timeout;
    loop {
        let mut all_ok = true;
        for peer in network.peers() {
            let client = peer.client();
            let account_id = account_id.clone();
            let definition = asset_definition_id.clone();
            let assets: Vec<Asset> = match sandbox::handle_result(
                spawn_blocking(move || client.client().query(FindAssets::new()).execute_all())
                    .await?
                    .map_err(eyre::Report::from),
                stringify!(multiple_blocks_created),
            )? {
                Some(v) => v,
                None => return Ok(()),
            };
            let asset = assets.into_iter().find(|asset| {
                *asset.id().account() == account_id && *asset.id().definition() == definition
            });
            if let Some(asset) = asset {
                if *asset.value() != expected_value {
                    all_ok = false;
                    break;
                }
            } else {
                all_ok = false;
                break;
            }
        }
        if all_ok {
            break;
        }
        if Instant::now() >= deadline {
            return Err(eyre!(
                "asset totals did not converge to expected value {expected_value}"
            ));
        }
        sleep(Duration::from_millis(200)).await;
    }
    Ok(())
}
