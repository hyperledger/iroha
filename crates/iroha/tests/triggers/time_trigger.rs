use std::time::Duration;

use eyre::Result;
use iroha::{
    client::{self, Client},
    data_model::{
        asset::AssetId,
        events::pipeline::{BlockEventFilter, BlockStatus},
        prelude::*,
        Level,
    },
};
use iroha_test_network::*;
use iroha_test_samples::ALICE_ID;

fn curr_time() -> Duration {
    use std::time::SystemTime;

    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
}

#[test]
fn mint_asset_after_3_sec() -> Result<()> {
    const GAP: Duration = Duration::from_secs(3);

    let (network, _rt) = NetworkBuilder::new()
        .with_default_pipeline_time()
        .start_blocking()?;
    let test_client = network.client();
    // Sleep to certainly bypass time interval analyzed by genesis
    std::thread::sleep(network.pipeline_time());

    let asset_definition_id = "rose#wonderland"
        .parse::<AssetDefinitionId>()
        .expect("Valid");
    let account_id = ALICE_ID.clone();
    let asset_id = AssetId::new(asset_definition_id.clone(), account_id.clone());

    let init_quantity = test_client.query_single(FindAssetQuantityById {
        id: asset_id.clone(),
    })?;

    let start_time = curr_time();
    assert!(
        GAP < network.pipeline_time(),
        "Schedule should be in the future but within block estimation"
    );
    let schedule = TimeSchedule::starting_at(start_time + GAP);
    let instruction = Mint::asset_numeric(1_u32, asset_id.clone());
    let register_trigger = Register::trigger(Trigger::new(
        "mint_rose".parse().expect("Valid"),
        Action::new(
            vec![instruction],
            Repeats::from(1_u32),
            account_id.clone(),
            TimeEventFilter::new(ExecutionTime::Schedule(schedule)),
        ),
    ));
    test_client.submit_blocking(register_trigger)?;

    // Schedule start is in the future so trigger isn't executed after creating a new block
    test_client.submit_blocking(Log::new(Level::DEBUG, "Just to create block".to_string()))?;
    let after_registration_quantity = test_client.query_single(FindAssetQuantityById {
        id: asset_id.clone(),
    })?;
    assert_eq!(init_quantity, after_registration_quantity);

    // Sleep long enough that trigger start is in the past
    std::thread::sleep(network.pipeline_time());
    test_client.submit_blocking(Log::new(Level::DEBUG, "Just to create block".to_string()))?;

    let after_wait_quantity = test_client.query_single(FindAssetQuantityById {
        id: asset_id.clone(),
    })?;
    // Schedule is in the past now so trigger is executed
    assert_eq!(
        init_quantity.checked_add(1u32.into()).unwrap(),
        after_wait_quantity
    );

    Ok(())
}

#[test]
fn pre_commit_trigger_should_be_executed() -> Result<()> {
    const CHECKS_COUNT: usize = 5;

    let (network, _rt) = NetworkBuilder::new().start_blocking()?;
    let test_client = network.client();

    let asset_definition_id = "rose#wonderland".parse().expect("Valid");
    let account_id = ALICE_ID.clone();
    let asset_id = AssetId::new(asset_definition_id, account_id.clone());

    let mut prev_value = get_asset_value(&test_client, asset_id.clone());

    // Start listening BEFORE submitting any transaction not to miss any block committed event
    let event_listener = get_block_committed_event_listener(&test_client)?;

    let instruction = Mint::asset_numeric(1u32, asset_id.clone());
    let register_trigger = Register::trigger(Trigger::new(
        "mint_rose".parse()?,
        Action::new(
            vec![instruction],
            Repeats::Indefinitely,
            account_id.clone(),
            TimeEventFilter::new(ExecutionTime::PreCommit),
        ),
    ));
    test_client.submit(register_trigger)?;

    for _ in event_listener.take(CHECKS_COUNT) {
        let new_value = get_asset_value(&test_client, asset_id.clone());
        assert_eq!(new_value, prev_value.checked_add(Numeric::ONE).unwrap());
        prev_value = new_value;

        // ISI just to create a new block
        let sample_isi = SetKeyValue::account(
            account_id.clone(),
            "key".parse::<Name>()?,
            "value".parse::<Json>()?,
        );
        test_client.submit(sample_isi)?;
    }

    Ok(())
}

/// Get block committed event listener
fn get_block_committed_event_listener(
    client: &Client,
) -> Result<impl Iterator<Item = Result<EventBox>>> {
    let block_filter = BlockEventFilter::default().for_status(BlockStatus::Applied);
    client.listen_for_events([block_filter])
}

/// Get asset numeric value
fn get_asset_value(client: &Client, asset_id: AssetId) -> Numeric {
    let asset = client
        .query(client::asset::all())
        .filter_with(|asset| asset.id.eq(asset_id))
        .execute_single()
        .unwrap();
    *asset.value()
}
