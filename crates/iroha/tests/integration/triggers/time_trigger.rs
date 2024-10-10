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
use iroha_test_samples::{gen_account_in, load_sample_wasm, ALICE_ID};

use crate::integration::triggers::get_asset_value;

fn curr_time() -> Duration {
    use std::time::SystemTime;

    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
}

#[test]
fn mint_asset_after_3_sec() -> Result<()> {
    let (network, _rt) = NetworkBuilder::new()
        .with_default_pipeline_time()
        .start_blocking()?;
    let test_client = network.client();
    // Sleep to certainly bypass time interval analyzed by genesis
    std::thread::sleep(network.consensus_estimation());

    let asset_definition_id = "rose#wonderland"
        .parse::<AssetDefinitionId>()
        .expect("Valid");
    let account_id = ALICE_ID.clone();
    let asset_id = AssetId::new(asset_definition_id.clone(), account_id.clone());

    let init_quantity = test_client.query_single(FindAssetQuantityById {
        id: asset_id.clone(),
    })?;

    let start_time = curr_time();
    const GAP: Duration = Duration::from_secs(3);
    assert!(
        GAP < network.consensus_estimation(),
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
    std::thread::sleep(network.consensus_estimation());
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
            "value".parse::<JsonString>()?,
        );
        test_client.submit(sample_isi)?;
    }

    Ok(())
}

#[test]
fn mint_nft_for_every_user_every_1_sec() -> Result<()> {
    const TRIGGER_PERIOD: Duration = Duration::from_millis(1000);
    const EXPECTED_COUNT: u64 = 4;

    let (network, _rt) = NetworkBuilder::new()
        .with_default_pipeline_time()
        .start_blocking()?;
    let test_client = network.client();

    let alice_id = ALICE_ID.clone();

    let accounts: Vec<AccountId> = vec![
        alice_id.clone(),
        gen_account_in("wonderland").0,
        gen_account_in("wonderland").0,
        gen_account_in("wonderland").0,
        gen_account_in("wonderland").0,
    ];

    // Registering accounts
    let register_accounts = accounts
        .iter()
        .skip(1) // Alice has already been registered in genesis
        .cloned()
        .map(|account_id| Register::account(Account::new(account_id)))
        .collect::<Vec<_>>();
    test_client.submit_all_blocking(register_accounts)?;

    // Start listening BEFORE submitting any transaction not to miss any block committed event
    let event_listener = get_block_committed_event_listener(&test_client)?;

    // Registering trigger
    // Offset into the future to be able to register trigger
    let offset = Duration::from_secs(10);
    let start_time = curr_time() + offset;
    let schedule = TimeSchedule::starting_at(start_time).with_period(TRIGGER_PERIOD);

    let filter = TimeEventFilter(ExecutionTime::Schedule(schedule));
    let register_trigger = Register::trigger(Trigger::new(
        "mint_nft_for_all".parse()?,
        Action::new(
            load_sample_wasm("create_nft_for_every_user_trigger"),
            Repeats::Indefinitely,
            alice_id.clone(),
            filter,
        ),
    ));
    test_client.submit_blocking(register_trigger)?;
    std::thread::sleep(offset);

    // Time trigger will be executed on block commits, so we have to produce some transactions
    submit_sample_isi_on_every_block_commit(
        event_listener,
        &test_client,
        &alice_id,
        TRIGGER_PERIOD,
        usize::try_from(EXPECTED_COUNT)?,
    )?;

    // Checking results
    for account_id in accounts {
        let start_pattern = "nft_number_";
        let end_pattern = format!("_for_{}#{}", account_id.signatory(), account_id.domain());
        let assets = test_client
            .query(client::asset::all())
            .filter_with(|asset| asset.id.account.eq(account_id.clone()))
            .execute_all()?;
        let count: u64 = assets
            .into_iter()
            .filter(|asset| {
                let s = asset.id().definition().to_string();
                s.starts_with(start_pattern) && s.ends_with(&end_pattern)
            })
            .count()
            .try_into()
            .expect("`usize` should always fit in `u64`");

        assert!(
            count >= EXPECTED_COUNT,
            "{account_id} has {count} NFTs, but at least {EXPECTED_COUNT} expected",
        );
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

/// Submit some sample ISIs to create new blocks
fn submit_sample_isi_on_every_block_commit(
    block_committed_event_listener: impl Iterator<Item = Result<EventBox>>,
    test_client: &Client,
    account_id: &AccountId,
    timeout: Duration,
    times: usize,
) -> Result<()> {
    for _ in block_committed_event_listener.take(times) {
        std::thread::sleep(timeout);
        // ISI just to create a new block
        let sample_isi = SetKeyValue::account(
            account_id.clone(),
            "key".parse::<Name>()?,
            JsonString::new("value"),
        );
        test_client.submit(sample_isi)?;
    }

    Ok(())
}
